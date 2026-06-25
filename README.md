# YamAmit-MCP-auth

A mapper for **authentication / authorization gaps in MCP servers**. Point it at an MCP
server and it runs one independent detector per known auth gap, concluding for each:
**`HAS_GAP` · `NO_GAP` · `NOT_APPLICABLE` · `INCONCLUSIVE` · `ERROR`** — with the
request/response evidence behind each verdict.

It fills the hole left by the sibling `MCP-Scanner` (whose `sample_output.json` advertises
a `security_findings` block its code never actually produces) and stays out of `MSB`'s lane
(LLM-agent attack resistance). See [`OUTLINE.md`](./OUTLINE.md) for the full design, the
21-gap catalog, and the increasing-difficulty roadmap.

## Status

- **Tier 1 (easy) — done & verified.** 5 detectors, validated HAS-vs-NO against 3 live
  sandbox postures (14 passing tests).
- **Tier 2 (medium, gaps 6–12) — done & verified.** 7 detectors, validated against 2 new
  OAuth sandbox postures + broken_auth (19 passing tests). Adds `oauth.py` — a shared
  PRM → Authorization-Server-Metadata fetch (RFC 9728 → RFC 8414) run once per scan.
- **Tier 1 run against 88 real public servers** (87 reachable across two batches): big-name
  servers mostly hardened; the lesser-known long tail has ~24 wide-open servers. Full results
  in `reports/real_world_scan*.md`.
- **Tier 2 run against the same 88** (6 read-only detectors; `open-dcr` excluded as a write).
  Headline: 27 skip `Origin` validation, 14 have missing/mismatched AS metadata (incl. vercel,
  prisma), no predictable session ids among those assessable. Caveats + table in
  `reports/real_world_scan_tier2.md`.
- **Known limitation:** the prober doesn't yet replay the `Mcp-Session-Id` from `initialize`
  or do the legacy SSE handshake, so session-using servers can return false `INCONCLUSIVE`
  (also caps `predictable-session-id` reach). This is the next fix (no-regret, precedes any
  bulk scan).
- Tier 3 (hard, gaps 13–21) — designed in `OUTLINE.md`, not yet implemented.

| Gap | Verdict logic |
|-----|---------------|
| `no-authentication-remote` | `tools/list` with no token → 200 = HAS |
| `no-tls-transport` | cleartext http on non-loopback host = HAS (loopback exempt) |
| `missing-www-authenticate` | 401 without RFC 9728 `resource_metadata` pointer = HAS |
| `missing-protected-resource-metadata` | no `/.well-known/oauth-protected-resource` = HAS |
| `session-id-in-url` | session id in URL/query instead of `Mcp-Session-Id` header = HAS |
| `predictable-session-id` | session ids deterministic / sequential / <16 chars = HAS |
| `origin-not-validated` | forged `Origin` still gets a 200 result = HAS |
| `cors-misconfiguration` | reflects arbitrary Origin + `Allow-Credentials: true` = HAS *(heuristic, not MCP spec)* |
| `auth-endpoints-not-https` | a discovered OAuth endpoint uses cleartext http on non-loopback = HAS |
| `missing-as-metadata` | no RFC 8414 AS metadata (or issuer mismatch) = HAS |
| `implicit-flow-enabled` | AS metadata advertises `token` response-type / `implicit` grant = HAS |
| `open-dcr` | `/register` issues a `client_id` with no initial access token = HAS *(performs a write)* |

## Setup

```bash
cd YamAmit-MCP-auth
uv sync && uv pip install -e .
```

## Scan a server

```bash
uv run mcpauth scan http://your-mcp-host:port/mcp        # human-readable
uv run mcpauth scan http://your-mcp-host:port/mcp --json # machine-readable report
uv run mcpauth scan <url> --tier 1                       # only Tier-1 detectors
uv run mcpauth scan <url> --safe                         # skip write detectors (open-dcr)
uv run mcpauth scan <url> --exclude open-dcr             # skip a detector by gap id
```

> **`--safe` matters for real servers.** Every detector is read-only **except `open-dcr`**,
> which sends a real OAuth client-registration request (a write — see the note under "Try it
> on the sandbox"). Use `--safe` to drop all write-performing detectors when scanning servers
> you don't own.

## Try it on the sandbox

Reference targets demonstrate every verdict path. Tier 1 uses `vulnerable`/`hardened`
(+ `broken_auth` for coverage); Tier 2 adds an OAuth-capable `vulnerable_oauth`/`hardened_oauth`:

```bash
# Tier 1
uv run python sandbox/vulnerable_server.py --port 9100 &   # HAS_GAP target
uv run python sandbox/hardened_server.py   --port 9101 &   # NO_GAP target
uv run mcpauth scan http://127.0.0.1:9100/mcp
uv run mcpauth scan http://127.0.0.1:9101/mcp

# Tier 2 (OAuth/transport gaps)
uv run python sandbox/vulnerable_oauth_server.py --port 9110 &   # HAS_GAP target
uv run python sandbox/hardened_oauth_server.py   --port 9111 &   # NO_GAP target
uv run mcpauth scan http://127.0.0.1:9110/mcp --tier 2
uv run mcpauth scan http://127.0.0.1:9111/mcp --tier 2
```

> **Note — `open-dcr` performs a write.** That detector sends a real OAuth Dynamic Client
> Registration request (RFC 7591) to any discovered `registration_endpoint` with no token.
> On a server with open registration this creates a throwaway public client — so it then
> **deletes that client again via RFC 7592** (HTTP DELETE → 204). RFC 7592 support is optional,
> so if the server returns no management fields (or refuses the delete), the Finding's notes
> say **`MANUAL CLEANUP NEEDED`** and name the leftover `client_id`. Use `--safe` to skip it.

### Running `open-dcr` against real servers (the polite wrapper)

Because it writes, drive `open-dcr` through `reports/run_dcr.py` rather than a bulk scan:

```bash
uv run python reports/run_dcr.py --dry-run            # READ-ONLY: list servers offering
                                                      #   registration (the candidate shortlist)
uv run python reports/run_dcr.py --live --only dock,switch   # WRITES: sequential, self-cleaning
```

`--dry-run` (default) performs no writes — it only does OAuth discovery and reports which
endpoints advertise a `registration_endpoint`. `--live` runs **only** `open-dcr`, one server
at a time with a delay, single attempt, and surfaces any client it could not delete in a
prominent "MANUAL CLEANUP NEEDED" section of `reports/dcr_scan.md`.

## Test

```bash
uv run pytest -q

# scan all servers in reports/endpoints.txt
uv run mcpauth scan "$url" --json > "reports/raw/$name.json" 2>"reports/raw/$name.err"
```

Each detector is only considered done when it returns `HAS_GAP` against the vulnerable
sandbox and `NO_GAP` against the hardened one.

## Design notes

- **Independence.** Every detector is a self-contained `detect(ctx) -> Finding`; the runner
  executes them concurrently and none reads another's result. Detectors that need the OAuth
  metadata chain set `needs_oauth = True`; the runner fetches it **once** into `ctx.oauth`
  (shared read-only context), so the four OAuth detectors stay independent without each
  re-fetching — and a Tier-1-only scan never pays for it.
- **Transport gating.** HTTP/OAuth gaps return `NOT_APPLICABLE` for stdio servers (which
  pull credentials from the environment per spec).
- **Version gating.** RFC 9728 / audience MUSTs are graded strictly only when the server
  negotiates `2025-06-18`; older revisions are reported as weaker posture, not failures.
- **Loopback exemption.** Missing TLS is only flagged on non-loopback hosts.
