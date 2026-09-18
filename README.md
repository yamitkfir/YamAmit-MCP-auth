# YamAmit-MCP-auth — MCP server authentication-gap mapper

Point this tool at an MCP server and it runs one independent check ("detector") per known authentication/authorization weakness ("gap"), and concludes for each one:

**`HAS_GAP`** (weakness present) · **`NO_GAP`** (handled correctly) ·
**`NOT_APPLICABLE`** (check can't apply here) · **`INCONCLUSIVE`** (couldn't tell) ·
**`ERROR`** (probe failed)

— each backed by the actual request sent and the server's reply (the *evidence*).

MCP = Model Context Protocol, the standard way an AI assistant connects to outside tools.
*Authentication* = proving who you are.
*Authorization* = what you're allowed to do once known.

This is the only project document. It is kept current with the code.

---

## Glossary (plain language)

| Term | Meaning |
|---|---|
| **token** | a digital "ticket" proving you logged in (like a wristband at an event) |
| **endpoint** | a specific web address a server answers on, e.g. `https://x.com/mcp` |
| **transport** | *how* the AI and server talk. Main kinds: HTTP, SSE, stdio |
| **stdio** | a server that runs locally on your own machine, no internet address — can't be scanned remotely |
| **SSE** | Server-Sent Events: an older one-way "the server keeps talking to you" connection |
| **status codes** | the server's short numeric reply: `200` OK · `400` your request was malformed · `401` log in first · `403` forbidden · `404` nothing here · `429` slow down |
| **TLS / HTTPS** | encryption on the connection (the padlock in a browser). "Cleartext http" = no encryption |
| **loopback** | the local-only address `127.0.0.1` / `localhost`, reachable only from the same machine |
| **`.well-known/…`** | a standard, predictable web address where a server publishes its "how to log in here" information |
| **session / session ID** | a temporary tag tying your back-and-forth messages together (a conversation ticket — *not* a password) |
| **the spec** | the official MCP rules document we measure servers against |
| **PRM** | Protected Resource Metadata — the server's published "how to log in here" page (RFC 9728) |
| **AS metadata** | Authorization Server Metadata — the matching information about the login server itself (RFC 8414) |
| **OAuth** | the standard login system MCP uses |
| **DCR** | Dynamic Client Registration — a self-service form letting an app sign itself up as a client (RFC 7591) |
| **PKCE** | proof that the app finishing a login is the one that started it |
| **audience** | which service a token was issued *for* (RFC 8707) |

---

## Where this sits

Two unrelated projects share the parent folder:

- **`MCP-Scanner/`** (Knostic) — *discovers* MCP servers on the internet via Shodan (a search engine that scans the whole internet; needs a paid key). Its `examples/sample_output.json` advertises a `security_findings` block (`authentication`, `ssl_enabled`, `cors_enabled`, `rate_limiting`) and a `risk_level` — **but its code never produces those fields** (verified: the string appears only in that sample file). This project is the engine that would fill them.
- **`MSB/`** (ICLR 2026 benchmark) — measures whether the *AI itself* can be tricked by booby-trapped tool descriptions ("tool poisoning") or hidden instructions ("prompt injection"). That's the AI's *behaviour*. We test the server's *plumbing*. Different layer, out of scope. Its stdio servers are usable as local targets.

**In scope:** what an *unauthenticated* client can observe about a server's authentication posture — no-auth servers, missing or broken TLS, OAuth discovery/metadata compliance (RFC 9728 / 8414), advertised grant types, open client registration, session identifier handling, DNS-rebinding/`Origin`, CORS.

**Out of scope, deliberately:**

- **Anything requiring a real token or a completed login.** See "Tier 3 is dropped" below.
- **Prompt injection / tool poisoning / malicious tool *content*** — that is the AI's behaviour, and `MSB/`'s lane.

---

## The gap catalog (12 gaps)

Grounded in the MCP Authorization spec, Security Best Practices, Transports, OAuth 2.1, RFCs 9728 / 8414 / 7591 / 8707, and research (Invariant Labs, Equixly, OWASP MCP Top-10).

### Tier 1 — easy: one unauthenticated request ✅ built

| # | id | What it checks | Sev |
|---|----|---|---|
| 1 | `no-authentication-remote` | Ask for the tool list with no login. Answered `200`? Wide open. | critical |
| 2 | `no-tls-transport` | Cleartext `http://` on a public host — **or** an https endpoint whose certificate doesn't validate | high |
| 3 | `missing-www-authenticate` | A `401` should also point to *where* to log in (`WWW-Authenticate` with `resource_metadata`) | medium |
| 4 | `missing-protected-resource-metadata` | The PRM page is absent or missing `authorization_servers` | medium |
| 5 | `session-id-in-url` | Session ID exposed in the web address instead of a header — addresses leak into logs | medium |

### Tier 2 — medium: crafted requests / follow-up lookups ✅ built

| # | id | What it checks | Sev |
|---|----|---|---|
| 6 | `predictable-session-id` | Session IDs guessable — sequential, deterministic, or too little entropy | medium |
| 7 | `origin-not-validated` | A forged `Origin` header is still accepted (enables DNS-rebinding) | high |
| 8 | `cors-misconfiguration` | Reflects any website's origin *and* allows credentials | medium |
| 9 | `auth-endpoints-not-https` | A published OAuth address uses cleartext `http` on a public host | high |
| 10 | `missing-as-metadata` | No RFC 8414 AS metadata, or its declared issuer doesn't match | medium |
| 11 | `implicit-flow-enabled` | Advertises the old unsafe login style that puts the token in the web address | high |
| 12 | `open-dcr` | Anyone can self-register as a client with no checks — **performs a write** | high |

### Tier 3 — dropped

Nine further gaps were designed but **never built, and the project no longer intends to build them**: `no-pkce`, `missing-token-audience-validation`, `token-passthrough`,  `confused-deputy-proxy-consent`, `improper-redirect-uri-validation`, `session-used-for-auth`, `self-asserted-capabilities`, `credential-harvesting-tool-desc`, `missing-session-isolation`.

%% **Why they are out.** Every one needs something this project does not have: a valid access token, a completed multi-step login against a server we do not own, several concurrent authenticated sessions, or a downstream back-end to watch a token being forwarded to.
Obtaining those against third-party production servers is not something an unauthenticated scanner can do, and two of them (`token-passthrough`, `missing-session-isolation`) could only ever have been graded best-effort even with credentials, because the evidence lives on a system we cannot observe.

The honest consequence: **this tool measures whether a server *advertises and enforces* login correctly, not whether its login is *sound*.** A server can score `NO_GAP` on all twelve gaps here and still mishandle token audience, skip PKCE, or leak between users. That limit is stated wherever results are reported rather than left implied. %%

### Research angle

Only **angle 3 — Discovery/PRM** remains: does the server correctly advertise and enforce its login process, as observed with no credentials? That covers gaps 1–12 and needs no login, so it is testable today against any public endpoint.

The two angles that depended on Tier 3 are closed: *token passthrough* (gaps 14, 15) and *identity isolation / confused deputy* (16, 19, 21). Gap #12 `open-dcr` survives  on its own terms — open registration is observable without a token, and it is the prerequisite an identity-confusion attack would build on.

---

## Gating rules every detector honours

- **Transport gating.** HTTP/OAuth gaps return `NOT_APPLICABLE` for **stdio** servers — the spec says they take credentials from the environment, not OAuth.
- **Version gating.** Gaps 3, 4, 10, 11, 14, 15 are firm requirements ("MUSTs") only from spec revision **2025-06-18 onward**. The comparison is chronological (`>=`), not equality: every later revision keeps the RFC 9728 requirement, so an equality test would let exactly the servers that keep up with the spec off the hook. Below that bar, weaker posture is reported as a risk note, not `HAS_GAP`.
- **Loopback exemption.** Cleartext `http://` is acceptable on `localhost`/`127.0.0.1`.

---

## Safety rules (this tool is pointed at other people's live servers)

1. **Nothing is modified by default.** Every detector only reads, **except `open-dcr`**, which is **off unless you pass `--unsafe-writes`**.
2. **Destination containment.** Almost every URL fetched after the first one is chosen by *the server being scanned* (its `authorization_servers`, endpoint URLs, `registration_endpoint`, `registration_client_uri`, `resource_metadata` pointer).
   Each one is checked before use: loopback / private / link-local addresses are refused (including the `169.254.169.254` cloud-metadata service), non-http(s) schemes are refused, and the *write* may only go to the scan target or a sibling host under the same domain.
   A refused destination is reported, never silently skipped.
3. **Redirects are not followed.** They would let a server attribute another host's document to itself — and RFC 9728 is entirely about *which* host published a document.
4. **Certificates are verified.** A TLS failure becomes a finding rather than being tolerated.
   `--insecure-tls` exists for self-signed local sandboxes and makes the TLS verdicts meaningless.
5. **Sessions are released.** A scan opens an MCP session where the server uses one and hands it back with the `DELETE` the spec prescribes, so no state outlives the scan.

> **Why rules 1–2 exist.** They were added after the write detector, run live, created an OAuth client on `api.llow.io` while the endpoint being scanned was `api.serff.ai` — a different domain that was never in the endpoint list. See "Outstanding obligation" below.

---

## Architecture

```
YamAmit-MCP-auth/
  README.md              # this file — the only project doc
  pyproject.toml         # uv-managed, isolated env
  mcpauth/
    models.py            # Verdict, Finding, ProbeContext, TargetSpec, version gate
    netguard.py          # destination classification: loopback/private/same-site (SSRF guard)
    probe.py             # HTTP/JSON-RPC client — full-body reads, SSE framing, evidence
    oauth.py             # PRM -> AS-metadata discovery (RFC 9728/8414), fetched once
    runner.py            # handshake, discovery, concurrent detectors, report aggregation
    detectors/
      base.py            # Detector contract + is_auth_challenge()
      tier1.py           # gaps 1-5
      tier2.py           # gaps 6-12
    cli.py               # `mcpauth scan <url>`
  sandbox/               # 7 local test servers (see Validation)
  tests/                 # 169 tests
  reports/               # raw scan evidence + per-batch result tables
```

**Independence requirement.** Each detector is a self-contained
`async detect(ctx) -> Finding`. None reads another's `Finding`, so the runner executes them concurrently in any order. Detectors needing the OAuth metadata chain set `needs_oauth = True`; the runner fetches it **once** into `ctx.oauth`, which is also why gaps #4 and #10 can never contradict each other about the same document.

Each `Finding` carries `gap_id`, `verdict`, `severity`, `evidence` (the request *and* the response), `spec_reference`, and `notes`.

---

## Usage

```bash
uv sync && uv pip install -e .

uv run mcpauth scan https://host/mcp                 # human-readable
uv run mcpauth scan https://host/mcp --json          # machine-readable
uv run mcpauth scan https://host/mcp --tier 1        # one tier only
uv run mcpauth scan --list-detectors                 # no target needed
uv run mcpauth scan https://host/mcp --unsafe-writes # OPT IN to open-dcr (a real write)
```

Exit codes, so a bulk run can branch: **0** clean · **1** gap found · **2** scan
failed/unreachable · **3** usage error. A mistyped `--tier`, `--exclude`, flag, or URL is
rejected rather than silently selecting nothing, and exits **3** — deliberately not the
argparse default of 2, because `run_scans.sh` *retries* on 2 and would otherwise report one bad command line as every endpoint failing twice.

**Bulk scanning:** `bash reports/run_scans.sh [--tier 1]` — read-only, writes to a fresh timestamped directory so it cannot overwrite published evidence.

**Driving `open-dcr` against real servers:** `reports/run_dcr.py`.
`--dry-run` (default) is read-only and lists which servers advertise a registration endpoint, flagging any that advertise it on a *different* host. `--live` writes: sequential, one attempt, self-cleaning via RFC 7592, and refuses an unrestricted run without `--yes`. Any client it could not delete is surfaced under a **`MANUAL CLEANUP NEEDED`** heading.

### Try it on the sandbox

```bash
uv run python sandbox/vulnerable_server.py --port 9100 &   # gaps open
uv run python sandbox/hardened_server.py   --port 9101 &   # gaps closed
uv run mcpauth scan http://127.0.0.1:9100/mcp

uv run python sandbox/vulnerable_oauth_server.py --port 9110 &
uv run python sandbox/hardened_oauth_server.py   --port 9111 &
uv run mcpauth scan http://127.0.0.1:9110/mcp --tier 2
```

---

## Validation

`uv run pytest -q` → **169 tests pass.**

Detectors are validated against local sandbox servers we control, because no single server exercises every verdict path (a no-auth server can never demonstrate a malformed `401`):

| Sandbox | Posture |
|---|---|
| `vulnerable_server.py` | no auth at all; claims the strict spec but violates its MUSTs |
| `hardened_server.py` | every Tier-1 gap closed |
| `broken_auth_server.py` | *does* require a token but challenges non-compliantly (the `HAS_GAP` anchor for #3 and #10) |
| `vulnerable_oauth_server.py` | predictable sessions, no `Origin` check, reflecting CORS, http OAuth endpoints, implicit grant, open DCR — but serves valid AS metadata, so it anchors `NO_GAP` for #10 |
| `hardened_oauth_server.py` | every Tier-2 gap closed |
| `stateful_open_server.py` | **wide open yet stateful** — requires a session ID like the spec says. Catches a prober that skips the handshake and grades a wide-open server `INCONCLUSIVE` |
| `subpath_prm_server.py` | **fully compliant at a subpath** — publishes its PRM at the RFC 9728 §3.1 path-inserted location. Catches a prober that only probes the bare origin |

Test layers: 35 verdict-matrix cases against the live sandboxes (`test_tier1.py` 14, `test_tier2.py` 21), 96 unit tests of the decision helpers (entropy, sequence detection, URL construction, SSRF guard, auth-challenge classification, SSE framing, version gating), and 38 regression tests pinning verdicts, CLI contracts, and error paths that were previously wrong.

A detector is "done" only when it returns `HAS_GAP` against the vulnerable posture and `NO_GAP` against the hardened one.

---

## Real-world results — 88 public endpoints

One read-only scan per endpoint, all 11 non-write detectors, 2026-09-18. Raw JSON in
`reports/raw-rescan-final/`; endpoint list in `reports/endpoints.txt`. Every count below was
recomputed from that JSON, not carried over from an earlier write-up.

| Gap | HAS_GAP | NO_GAP | N/A | INCONCLUSIVE | ERROR |
|---|--:|--:|--:|--:|--:|
| `no-authentication-remote` | **30** | 42 | 0 | 12 | 4 |
| `no-tls-transport` | 0 | 83 | 0 | 5 | 0 |
| `missing-www-authenticate` | 0 | 32 | 42 | 10 | 4 |
| `missing-protected-resource-metadata` | 22 | 41 | 0 | 25 | 0 |
| `session-id-in-url` | 0 | 10 | 0 | 74 | 4 |
| `predictable-session-id` | 0 | 10 | 20 | 58 | 0 |
| `origin-not-validated` | 26 | 10 | 0 | 48 | 4 |
| `cors-misconfiguration` | 2 | 68 | 0 | 14 | 4 |
| `auth-endpoints-not-https` | 0 | 52 | 36 | 0 | 0 |
| `missing-as-metadata` | 13 | 53 | 0 | 22 | 0 |
| `implicit-flow-enabled` | 0 | 52 | 35 | 1 | 0 |

All eleven rows cover all 88 endpoints — Tier 1 and Tier 2 ran in one pass, so there is no
longer a 87-vs-88 discrepancy between them. `open-dcr` is absent because it writes and was not
run in bulk; see the obligation below for the four servers it did reach.

**30 servers answer `tools/list` to an anonymous caller — 456 callable tools in total.** The
largest are `dock` (70 tools), `switch` (61), `gondola` (39) and `nullary` (35). They cluster
in the lesser-known registry long tail; the recognisable vendor servers (Stripe, Notion,
Sentry, Linear, GitHub, PayPal, Square, Wix, Zapier, Intercom, Atlassian, Cloudflare's
authenticated set, Neon, Grafana, Prisma, Vercel, Webflow, Semgrep) all demand login. DeepWiki
and EdgeOne are open *by design*; EdgeOne remains the most interesting single case, because its
anonymous tool `deploy-html` **changes state** rather than only reading.

`origin-not-validated` (26) is a real spec-MUST miss but overlaps the same wide-open servers,
and the DNS-rebinding threat it guards against is weak for a remote HTTPS server.
`cors-misconfiguration` is a general web-security heuristic — **CORS is not in the MCP spec**
and is never reported as a spec violation.

### What changed against the previously published numbers, and why

The earlier table **understated the headline finding**: it reported 24 open servers where there
are 30. Two bugs in the prober, both fixed and both now pinned by regression tests, were
responsible for most of the movement:

- **Response bodies were silently clipped.** The probe called `StreamReader.read(cap)` once,
  which returns *up to* `cap` bytes rather than `cap` bytes. Any response larger than one
  buffered chunk arrived as a fragment, flagged `truncated=False` — data loss presenting itself
  as complete data. `dock`'s 91,703-byte tool listing came back as 8,183 bytes of unparseable
  JSON, so a server that had just enumerated 70 tools to an unauthenticated caller was graded
  `INCONCLUSIVE`. Six servers were hidden this way.
- **A bare `403` counted as authentication.** Any `403` was read as "the server requires
  login", so a WAF block, geo-fence or bot filter earned a clean `NO_GAP`. A `403` now needs
  corroboration — a `WWW-Authenticate` header, or a genuine RFC 6750 error code in the body —
  which is why `NO_GAP` fell from 46 to 42 while `INCONCLUSIVE` stayed honest.

Two further shifts are the tool becoming honest rather than the internet changing:

- `predictable-session-id` moved from **76 `NOT_APPLICABLE` to 58 `INCONCLUSIVE`**. It used to
  claim "this server has no sessions" whenever it saw no session id — including when the server
  had refused to open one because we were not logged in. It now distinguishes "stateless" from
  "could not observe", so the honest answer is *unknown* for most targets.
- `no-tls-transport` moved from **88 `NO_GAP` to 83 + 5 `INCONCLUSIVE`**. It previously passed
  every `https://` URL without testing anything; it now makes a live request, and says so when
  a host cannot be reached to have its certificate checked.

`missing-protected-resource-metadata` rose from 17 to 22 `HAS_GAP` even though RFC 9728 §3.1
path insertion is now implemented — path insertion moved some servers *out* of the gap, but
removing the 4 `ERROR`s and sharpening `INCONCLUSIVE` moved more in.

**Still limiting these numbers:**

- **58 of 88 servers negotiated no protocol version at all** (22 reported 2025-06-18, 4 on
  2025-03-26, 4 on 2024-11-05), because a protected server answers `401` before negotiating. The
  strict-spec bar therefore only ever applied to 22 targets, and version-gated gaps return
  `INCONCLUSIVE` elsewhere.
- **The legacy two-channel SSE handshake is still unimplemented**, which is why
  `session-id-in-url` is 74/88 `INCONCLUSIVE`.
- **88 endpoints is a thin sample.** The registry holds 75,000+ records (see below), so these
  are rates within one host-deduped slice, not population rates.

**Honest framing:** "hardened" here means only that the server enforces auth on the first
unauthenticated call. It says nothing about whether its OAuth flow, token audience, PKCE, or
session isolation are sound — those were the dropped Tier-3 gaps, and this tool will never
report on them. A spec-MUST miss is also not automatically an exploit.

### Discovery: Shodan is not needed

Shodan's free tier returns 403 on `search`/`search_cursor` with 0 query credits, so the sibling scanner discovers **0 servers** — evidence in `reports/shodan_discovery.md`.

The **official MCP Registry** (`registry.modelcontextprotocol.io/v0/servers`) is free, needs no key, is paginated by `metadata.nextCursor`, and gives a URL plus transport type per remote entry — ready to feed straight into `mcpauth scan`.

**It is now far larger than the endpoint list reflects.** A re-pull stopped at **750 pages / 75,000 server records without reaching the end**, so the true total is unknown and at least that. Counting remote endpoints over the first 12,030 records alone: **10,669 remote endpoint URLs, 4,425 distinct, on 3,680 distinct hosts** (10,244 `streamable-http`, 425 `sse`). The 88 endpoints scanned so far are a host-deduped sample of a small fraction of that — they are not a census, and the result rates above must not be read as population rates.

Free complements for undeclared servers: CT-log mining for `mcp.<vendor>` subdomains, and GitHub code search over `mcp.json` configs. Honest limit: registries find *declared* servers;
fully anonymous exposed hosts still need paid Shodan/Censys or authorized self-scanning.

---

## ⚠ Outstanding obligation — 4 OAuth clients on servers we don't own

A live `open-dcr` run created real client registrations that could not be auto-deleted (none of the four returned RFC 7592 management fields). They are inert entries — no password, no data access, nobody logged in through them — but they are litter on someone else's system that we cannot remove ourselves.

| Server scanned | Host actually written to | client_id left behind |
|---|---|---|
| `trydock.ai` | `trydock.ai` | `dock_client_147f8c0e34e94b2c19c2e730c6d5aeec` |
| `api.serff.ai` | **`api.llow.io`** | `4b4e081b-bcea-43c0-8cec-4af0a5160695` |
| `mcp.gondola.ai` | `www.gondola.ai` | `gond_mcp_do7tStvN3QTKtjJfHzBEVhtUCsg8YWsV` |
| `mcp.switchapp.ai` | `mcp.switchapp.ai` | `mcpc_NI68KEmQ_i6x49tvj3J_cA` |

Row 2 is why the containment rules exist. Current decision: leave them, keep this record, no outreach. Also recorded in `reports/dcr_scan.md`.

---

## The spec has moved ahead of this tool

The current MCP revision is **`2026-07-28`**; `2025-11-25` also exists. The tool speaks `2025-06-18`. This matters more than a version bump:

- **Protocol-level sessions were removed in 2026-07-28** — no `Mcp-Session-Id`, no GET stream, no `DELETE` termination. Those existed only in `2025-03-26` … `2025-11-25`. So gaps **#5 and #6 are scoped to a transport generation the spec has dropped** and need explicit version scoping rather than being presented as timeless. (#18 and #21 were the other session-era gaps; they are dropped with Tier 3.)
- **The 2024-11-05 HTTP+SSE transport is deprecated** and eligible for removal — so building the legacy two-channel handshake is investing in a dying transport. Worth a scope decision.
- **New per-request requirements** the prober doesn't meet: `Mcp-Method` and `Mcp-Name `headers are REQUIRED for compliance, and header values must match the body. A strict current-revision server *must* reject our requests with `400 HeaderMismatch`.
- **`server/discover` is now a mandatory RPC** — a better probe than `initialize`, and the spec now defines the exact old-vs-new detection algorithm to implement.
- RFC 9728 PRM is now an **unconditional MUST**, which strengthens #4 — the one gap here the newest revision made stricter rather than weaker. (Token audience validation and the token-passthrough ban are also still MUSTs, but they were #14/#15 and are dropped with Tier 3, so this tool does not check them.)
- **Two framings need updating:** RFC 8414 is now *"at least one of RFC 8414 **or** OpenID Connect Discovery"*, so #10 must not treat a missing 8414 document as a violation when OIDC discovery is present (the code already tries both). And **DCR is now deprecated**, retained only for backwards compatibility, with Client ID Metadata Documents as the replacement — so #12's framing is dated.

---

## Known limitations and open work

**Correctness**

- Legacy two-channel SSE handshake unimplemented → caps gaps #5 and #6 (see the note above about whether this is worth building).
- Duplicate response headers collapse to the last value (`probe.py`), so a compliant multi-challenge `401` can be misgraded.
- No `429` / rate-limit handling. All detectors fire as one uncapped burst (~15 requests); a throttling target's `429`s flow into "header absent" branches and become confident `NO_GAP`/`NOT_APPLICABLE`. Needs a per-target request budget and 429 awareness.
- Only the first authorization server that answers is examined. The rest are listed in the report as unresolved, but they are not checked.
- `jsonrpc_result` doesn't correlate the JSON-RPC `id`, so on a shared SSE stream it can return another request's result.
- The SSE read now keeps what arrived when a held-open stream goes quiet (`_read_body`'s
  `stop_when_stalled`), but that path has **no live coverage** — see the sandbox blind spot
  below. It is exercised only against bodies that end.

**Test/sandbox blind spots** — each conceals a real defect class:

- No sandbox holds an SSE stream open; every real server does. So the stall handling in `_read_body` is only unit-tested, never driven by a stream that stays connected.
- No sandbox negotiates a revision *newer* than 2025-06-18.
- `hardened_server`'s PRM sits only at the bare origin with a `resource` value that doesn't match itself, and its `resource_metadata` pointer is an unreachable port-less URL — so the `NO_GAP` anchors for #3/#4 are not themselves compliant.
- `hardened_oauth_server`, the Tier-2 "hardened" anchor, leaves its **MCP endpoint wide open** — `/mcp` answers `initialize` and `tools/list` with no `Authorization` check, so gap #1 would call it critical. Only `/register` is protected (401 without an initial access token). It anchors `NO_GAP` for the six Tier-2 gaps while failing Tier 1, which is never exercised because the Tier-2 tests only run tier 2 against it.
- `broken_auth_server` and `hardened_server` accept `GET /mcp` but unconditionally parse a JSON body, returning `500`.
- `test_tier1`/`test_tier2` discard sandbox output and never poll the child, so a sandbox crash is invisible (`test_regressions` does this correctly — copy that `_boot`).
- `NoTlsTransport` has no live coverage at all.

**Not yet built**

- `discovery.py` with pluggable free sources (MCP Registry primary), to drop the Shodan dependency entirely and feed a bulk run.

---

## Working agreement

- Use simple language; when a technical term appears, define it briefly in parentheses.
- Reassess scope at each tier boundary; within a tier, work autonomously.
- Keep this document current. It is the single source of truth — no per-session status docs.
