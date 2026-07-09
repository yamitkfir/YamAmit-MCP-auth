# YamAmit-MCP-auth

A mapper for **authentication / authorization gaps in MCP servers** (MCP = Model Context Protocol, the standard way an AI assistant connects to outside tools; "authentication" = proving who you are, "authorization" = what you're allowed to do once known).
Point it at an MCP server and it runs one independent detector (a small self-contained check, one per gap) per known auth gap, concluding for each with a **verdict** (the check's answer): **`HAS_GAP` (weakness present) · `NO_GAP` (handled correctly) · `NOT_APPLICABLE` (check doesn't apply to this server) · `INCONCLUSIVE` (couldn't tell) · `ERROR`** — with the request/response evidence (the actual message we sent and the server's reply) behind each verdict.

It fills the hole left by the sibling `MCP-Scanner` (whose `sample_output.json` advertises a `security_findings` block its code never actually produces) and stays out of `MSB`'s lane (LLM-agent attack resistance — whether the AI itself can be tricked, a different layer). See [`OUTLINE.md`](./OUTLINE.md) for the full design, the 21-gap catalog, and the increasing-difficulty roadmap.

## Status

- **Tier 1 (easy) — done & verified.** 5 detectors, validated HAS-vs-NO against 3 live sandbox postures (sandbox = small test servers we run locally; a "posture" is one server set up to be either vulnerable or secure) (14 passing tests).
- **Tier 2 (medium, gaps 6–12) — done & verified.** 7 detectors, validated against 2 new OAuth (the standard login system MCP uses) sandbox postures + broken_auth (19 passing tests). Adds `oauth.py` — a shared PRM → Authorization-Server-Metadata fetch (PRM = protected resource metadata, the server's published "how to log in here" info; AS metadata = the matching info about the login server itself) (RFC 9728 → RFC 8414, the internet standards defining those two documents) run once per scan.
- **Tier 1 run against 88 real public servers** (87 reachable across two batches): big-name servers mostly hardened; the lesser-known long tail has ~24 wide-open servers. Full results in `reports/real_world_scan*.md`.
- **Tier 2 run against the same 88** (6 read-only detectors; `open-dcr` excluded as a write). Headline: 27 skip `Origin` validation, 14 have missing/mismatched AS metadata (incl. vercel, prisma), no predictable session ids among those assessable. Caveats + table in `reports/real_world_scan_tier2.md`.
- **Known limitation:** the prober doesn't yet replay the `Mcp-Session-Id` (the temporary conversation tag the server hands back — not a password) from `initialize` (the opening "let's start" message of an MCP conversation) or do the legacy SSE handshake (SSE = Server-Sent Events, an older one-way "the server keeps talking to you" connection style), so session-using servers can return false `INCONCLUSIVE` (also caps `predictable-session-id` reach). This is the next fix (no-regret, precedes any bulk scan).
- Tier 3 (hard, gaps 13–21) — designed in `OUTLINE.md`, not yet implemented.

Terms used in the table: `tools/list` = the request asking a server to list its tools; `token` = a digital "ticket" proving you logged in; `200` = OK/allowed, `401` = "log in first" (the HTTP status codes a server replies with); TLS = encryption on the connection (the browser padlock); loopback = the local-only address `127.0.0.1`/`localhost`, reachable only from the same machine; `Origin` = the header naming which website is calling; issuer = the server's claimed identity in its login metadata.

| Gap | Verdict logic |
|-----|---------------|
| `no-authentication-remote` | `tools/list` (list-your-tools request) with no token → 200 = HAS |
| `no-tls-transport` | cleartext http (no encryption) on non-loopback host = HAS (loopback exempt) |
| `missing-www-authenticate` | 401 without RFC 9728 `resource_metadata` pointer (the "where to log in" hint) = HAS |
| `missing-protected-resource-metadata` | no `/.well-known/oauth-protected-resource` (standard "how to log in here" page) = HAS |
| `session-id-in-url` | session id (conversation tag) in URL/query instead of `Mcp-Session-Id` header = HAS |
| `predictable-session-id` | session ids deterministic / sequential / <16 chars (easy to guess) = HAS |
| `origin-not-validated` | forged `Origin` (faked calling-website header) still gets a 200 result = HAS |
| `cors-misconfiguration` | reflects arbitrary Origin + `Allow-Credentials: true` (lets any website make logged-in requests) = HAS *(heuristic = rule of thumb, not MCP spec)* |
| `auth-endpoints-not-https` | a discovered OAuth endpoint uses cleartext http on non-loopback = HAS |
| `missing-as-metadata` | no RFC 8414 AS metadata (login-server info), or issuer mismatch = HAS |
| `implicit-flow-enabled` | AS metadata advertises `token` response-type / `implicit` grant (an old, unsafe login style that puts the token in the web address) = HAS |
| `open-dcr` | `/register` issues a `client_id` with no initial access token, i.e. anyone can register = HAS *(performs a write)* |

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

> **`--safe` matters for real servers.** Every detector is read-only (only looks, never changes anything) **except `open-dcr`**, which sends a real OAuth client-registration request (a write — it can create something on the server; see the note under "Try it on the sandbox"). Use `--safe` to drop all write-performing detectors when scanning servers you don't own.

## Try it on the sandbox

Reference targets (small test servers we ship, so you can see each verdict without a real server) demonstrate every verdict path. Tier 1 uses `vulnerable` (gaps left open) / `hardened` (gaps closed) (+ `broken_auth`, which requires login but does it wrongly, for coverage); Tier 2 adds an OAuth-capable `vulnerable_oauth`/`hardened_oauth`:

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

> **Note — `open-dcr` performs a write.** That detector sends a real OAuth Dynamic Client Registration request (DCR = letting an app sign itself up as a client automatically; RFC 7591 is the standard for it) to any discovered `registration_endpoint` with no token. On a server with open registration this creates a throwaway public client — so it then **deletes that client again via RFC 7592** (the matching "delete my registration" standard; HTTP DELETE → 204, the "done, nothing to return" status). RFC 7592 support is optional, so if the server returns no management fields (or refuses the delete), the Finding's notes say **`MANUAL CLEANUP NEEDED`** and name the leftover `client_id`. Use `--safe` to skip it.

### Running `open-dcr` against real servers (the polite wrapper)

Because it writes, drive `open-dcr` through `reports/run_dcr.py` rather than a bulk scan:

```bash
uv run python reports/run_dcr.py --dry-run            # READ-ONLY: list servers offering
                                                      #   registration (the candidate shortlist)
uv run python reports/run_dcr.py --live --only dock,switch   # WRITES: sequential, self-cleaning
```

`--dry-run` (default) performs no writes — it only does OAuth discovery (fetching the server's login-info pages) and reports which endpoints (server web addresses) advertise a `registration_endpoint`. `--live` runs **only** `open-dcr`, one server at a time with a delay, single attempt, and surfaces any client it could not delete in a prominent "MANUAL CLEANUP NEEDED" section of `reports/dcr_scan.md`.

## Test

```bash
uv run pytest -q

# scan all servers in reports/endpoints.txt
uv run mcpauth scan "$url" --json > "reports/raw/$name.json" 2>"reports/raw/$name.err"
```

Each detector is only considered done when it returns `HAS_GAP` against the vulnerable sandbox and `NO_GAP` against the hardened one.

## Design notes

- **Independence.** Every detector is a self-contained `detect(ctx) -> Finding`; the runner executes them concurrently and none reads another's result. Detectors that need the OAuth metadata chain (the linked login-info documents) set `needs_oauth = True`; the runner fetches it **once** into `ctx.oauth` (shared read-only context), so the four OAuth detectors stay independent without each re-fetching — and a Tier-1-only scan never pays for it.
- **Transport gating.** HTTP/OAuth gaps return `NOT_APPLICABLE` for stdio servers (transport = *how* the AI and server talk; stdio = a server that runs locally on your own machine with no internet address, so it can't be scanned remotely and pulls credentials from the environment per spec).
- **Version gating.** RFC 9728 / audience (which service a token was issued *for*) MUSTs are graded strictly only when the server negotiates the `2025-06-18` spec version; older revisions are reported as weaker posture, not failures.
- **Loopback exemption.** Missing TLS (the connection encryption / browser padlock) is only flagged on non-loopback hosts (i.e. not the local-only `127.0.0.1`).
