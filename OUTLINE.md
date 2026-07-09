# MCP Server Authentication-Gap Mapper — Project Outline

> Goal: given a target MCP server (MCP = Model Context Protocol, the standard way an AI assistant connects to outside tools), run a set of **independent detectors** (small self-contained checks, one per gap), one per known authentication/authorization gap (authentication = proving who you are; authorization = what you're allowed to do once known), and conclude for each:
> **HAS gap / HAS NOT gap / N-A / INCONCLUSIVE** — with the evidence (the actual request we sent and the server's reply) that led to the verdict (the check's answer).

This is the home of `YamAmit-MCP-auth`. It sits alongside two sibling projects in
`MCProject/`:

- **`MCP-Scanner/`** (Knostic) — *discovers* MCP servers on the internet via Shodan (a search
  engine that scans the whole internet for exposed servers; needs a paid API key) and verifies they speak MCP. Its `examples/sample_output.json` advertises a `security_findings` block (`authentication`, `ssl_enabled`, `cors_enabled`, `rate_limiting`) and a `risk_level` — **but the scanner code never actually produces
  those fields.** They are aspirational. *This project fills that gap*: it is the engine that would populate `security_findings` for real.
- **`MSB/`** (ICLR 2026 benchmark) — measures how LLM *agents* resist 12 MCP **attack** categories (tool poisoning = malicious instructions hidden in a tool's description;
  prompt injection = sneaking secret commands into text the AI reads; etc.). That is the *content/behavioral* attack surface (about the AI's behavior) and is **out of scope** here.
  We focus on the **transport + protocol auth layer** (transport = *how* the AI and server talk): who is allowed to talk to the server at all, and whether tokens (digital "tickets" proving you logged in) / sessions (the back-and-forth tied together) are handled correctly.
  MSB's runnable servers under `data/tools/` are useful as local targets, though they are stdio (servers that run locally with no internet address; see "Transport gating").

---

## Scope: what counts as an "authentication gap"

In scope — authentication, authorization, token handling, and transport-level identity:
no-auth servers, missing TLS (connection encryption — the browser padlock), OAuth (the standard login system MCP uses) discovery/metadata non-compliance, missing token audience validation (checking a token was issued *for this* server, not another), token passthrough (blindly forwarding a user's token to a back-end), confused-deputy (a trusted program tricked into misusing its powers), session handling, PKCE (a proof that the same app which started a login is the one finishing it), redirect validation, DNS-rebinding (fooling a local server about which website is calling it) / Origin (the header naming the calling website), CORS (cross-site request rules; an auth-bypass enabler).

Out of scope — prompt injection / tool poisoning / malicious tool *content* (that is MSB's domain). One bridge check is noted (#20) but kept optional.

---

## The gap catalog (21 gaps, ordered by detection difficulty — our build order)

Grounded in the official MCP Authorization spec (the spec = the official MCP rules document we measure servers against; [2025-06-18][a], [2025-03-26][b] are two dated versions of it), [Security Best Practices][c], [Transports][d], OAuth 2.1 (the current version of the OAuth login standard), RFC 9728/8414/7591/8707 (numbered internet standards — for the login-info page, the login-server-info page, self-service client sign-up, and tying a token to one service, respectively), and research (Invariant Labs, Equixly, OWASP MCP Top-10). This catalog is kept in sync with the status doc at `MCP workshop/MCP-auth-gaps-status.md`.
"Plan ref" = section of our project plan ("Playbook A–E" / "Angle 1–3"; see the angle map below).

Verdict vocabulary used by every detector (the answer each check can give):
`HAS_GAP` (weakness present) · `NO_GAP` (handled correctly) · `NOT_APPLICABLE` (check doesn't apply here) · `INCONCLUSIVE` (couldn't tell) · `ERROR`.

### Tier 1 — Easy (single unauthenticated request / well-known GET / header read) — ✅ BUILT

Terms in the tables below: `tools/list` = the request asking a server to list its tools;
`Authorization` = the header that carries your login token; HTTP status codes are the server's short numeric reply — `200` = OK/allowed, `401` = "log in first", `403` = "known but not allowed", `404` = "nothing here"; `.well-known/...` = a standard, predictable web address where a server publishes its login info; `WWW-Authenticate` = the header pointing to *where* to log in; `Mcp-Session-Id` = the header carrying the conversation tag; SSE = Server-Sent Events, an older one-way "the server keeps talking to you" connection style;
"Sev" = severity (how serious the gap is).

| # | id | Gap | One-line detection | Sev | Plan ref |
|---|----|-----|--------------------|-----|----------|
| 1 | `no-authentication-remote` | Remote server invokes tools with no credentials (no login) | `tools/list` with no `Authorization` → 200 = HAS | critical | Playbook A |
| 2 | `no-tls-transport` | Cleartext HTTP (unencrypted) on non-loopback host (not the local-only `127.0.0.1`) | endpoint answers over `http://`, no →https redirect = HAS | high | — |
| 3 | `missing-www-authenticate` | 401 lacks RFC 9728 `WWW-Authenticate` discovery pointer (the "where to log in" hint) | 401 with no `WWW-Authenticate: ... resource_metadata=` = HAS (2025-06-18) | medium | Playbook A |
| 4 | `missing-protected-resource-metadata` | No `/.well-known/oauth-protected-resource` (the published "how to log in here" page, PRM) w/ `authorization_servers` | 404 / missing field = HAS (2025-06-18) | medium | Playbook A, Angle 3 |
| 5 | `session-id-in-url` | Session id (conversation tag) carried in URL/query (legacy SSE), where it can leak into logs | handshake uses `?sessionId=` instead of `Mcp-Session-Id` header = HAS | medium | — |

### Tier 2 — Medium (crafted headers / chained metadata fetch / multi-sample) — ✅ BUILT

| # | id | Gap | One-line detection | Sev | Plan ref |
|---|----|-----|--------------------|-----|----------|
| 6 | `predictable-session-id` | Low-entropy / sequential session ids (easy to guess, so hijackable) | open N sessions, ids correlated/short = HAS | medium | — |
| 7 | `origin-not-validated` | No `Origin` validation (enables DNS-rebinding, fooling a local server about who's calling) | forged `Origin: https://evil` still 200 = HAS | high | — |
| 8 | `cors-misconfiguration` | Reflects arbitrary origin + creds (lets any website make logged-in requests) | `OPTIONS` w/ evil Origin reflected in ACAO (+ACAC true) = HAS | medium | — |
| 9 | `auth-endpoints-not-https` | AS/redirect endpoints not HTTPS (login addresses unencrypted) | AS metadata lists non-loopback `http://` endpoint = HAS | high | Playbook A |
| 10 | `missing-as-metadata` | No `/.well-known/oauth-authorization-server` (the login-server-info page, AS metadata; RFC 8414) — AS-discovery complement to #4 | 404 / missing = HAS (2025-06-18) | medium | Playbook A, Angle 3 |
| 11 | `implicit-flow-enabled` | OAuth 2.1 forbids implicit grant (an old, unsafe login style that puts the token in the web address) | AS metadata: `response_types_supported` includes `token`, or `grant_types_supported` includes `implicit` = HAS | high | Playbook E |
| 12 | `open-dcr` | Unrestricted Dynamic Client Registration (anyone can self-sign-up as a client; RFC 7591) | `/register` accepts arbitrary client w/ no pre-shared token / origin check / allowlist = HAS | high | Playbook B, Angle 2 |

**Tier-2 implementation notes (spec-grounded; verbatim spec wording drove these):**
- **Shared OAuth fetch.** Gaps 9–12 all reason about the same PRM → AS-metadata chain (PRM = protected resource metadata, the server's "how to log in here" page; AS metadata = the matching info about the login server itself). The runner fetches it **once** into
  `ctx.oauth` (a `mcpauth/oauth.py:OAuthDiscovery`) iff a selected detector sets `needs_oauth = True`. Detectors stay independent — they read shared context, never each other's `Finding`.
- **RFC 8414 path construction (#9/#10/#11/#12).** The well-known URL (the standard login-info address) is built by **insertion** between host and path (`https://as/.well-known/oauth-authorization-server/tenant`), *not* OIDC-style appending. We try insertion first, then fall back to the OIDC-appended form (RFC 8414 §5), and check the returned `issuer` (the server's claimed identity) matches (§3.3). If the target has no PRM we also try the target's own origin (the server's own base address — many MCP servers are their own AS, i.e. they run their own login server).
- **#7 Origin & #6 session-id are spec MUSTs** (firm requirements) (Transports §Security: "MUST validate the `Origin` header"; Security Best Practices: "MUST use secure, non-deterministic session IDs").
- **#8 CORS is NOT in the MCP spec** — graded as a general web-security heuristic (a rule of thumb, not an official requirement) and labelled as such in every Finding; never cited as a spec violation.
- **#11 false-positive guard.** Only flags implicit (the old unsafe login style) on an *explicit* `token` / `implicit` signal. RFC 8414 says a *missing* `grant_types_supported` defaults to include `implicit`, but we treat that as a note, not HAS_GAP (too noisy to flag as a real finding).
- **#12 has a side effect, with self-cleanup.** `open-dcr` issues a real RFC 7591 registration POST (a write — it can create something on the server) with no initial access token; a successful probe creates a throwaway public client on the target, then immediately deletes it via RFC 7592 (the matching "delete my registration" standard; DELETE to `registration_client_uri` with the `registration_access_token`; success = 204, the "done,
  nothing to return" status). RFC 7592 is OPTIONAL, so cleanup can fail — when it does, the Finding's notes carry the literal marker `MANUAL CLEANUP NEEDED` plus the leftover `client_id`, never hidden. RFC 7591 *permits* open registration, so we report it as the confused-deputy (#16) prerequisite, not a spec violation. Drive it against real servers via `reports/run_dcr.py` (read-only `--dry-run` shortlist; sequential self-cleaning `--live`), and via `mcpauth scan --safe` to skip all write detectors.

### Tier 3 — Hard (valid/crafted creds, multi-step OAuth, behavioral) — designed, not built

| # | id | Gap | One-line detection | Sev | Plan ref |
|---|----|-----|--------------------|-----|----------|
| 13 | `no-pkce` | AS issues code without PKCE (the proof that the app finishing a login is the one that started it) | token granted with no `code_challenge` = HAS | high | Playbook E |
| 14 | `missing-token-audience-validation` | Accepts foreign-audience tokens — tokens minted for a *different* service (audience / `aud` = which service a token is meant for; RFC 8707) | token with wrong/absent `aud` accepted = HAS | critical | Playbook C, Angle 1 |
| 15 | `token-passthrough` | Forwards client token straight to upstream API instead of using its own credentials (a banned shortcut) | behavioral; foreign-audience token grants downstream = HAS | critical | Playbook D, Angle 1 |
| 16 | `confused-deputy-proxy-consent` | Proxy skips per-client consent (shared client_id) — a middleman reusing one identity for everyone, so users can be impersonated | DCR new redirect_uri → authorize w/o consent screen = HAS | high | Angle 2 |
| 17 | `improper-redirect-uri-validation` | Non-exact redirect_uri match (redirect_uri = where login sends you back; loose matching lets an attacker steal the login code) | mutated redirect_uri honored = HAS | high | Playbook E |
| 18 | `session-used-for-auth` | Session id alone authorizes (the conversation tag wrongly treated as proof of login) | replay session id w/o token still 200 = HAS | high | — |
| 19 | `self-asserted-capabilities` | Server claims capabilities/sampling without proof (sampling = the server asking the AI to generate text; it can disguise these as if a human typed them) | unauthenticated sampling indistinguishable from user input = HAS | high | Plan §"Blindly Trusting the Server" |
| 20 | `credential-harvesting-tool-desc` *(optional bridge)* | Tool descriptions reference credential paths (e.g. SSH keys) / cross-server token relay | `tools/list` description scan | high | MSB-adjacent |
| 21 | `missing-session-isolation` | Cross-agent state pollution — one user's session can read or affect another's on the same server | Agent A's context/state readable by Agent B on same server = HAS | high | Angle 2 |

[a]: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
[b]: https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
[c]: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
[d]: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports

### How the 3 project-plan angles map onto these gaps

| Angle | Focus | Gaps |
|-------|-------|------|
| **3 — Discovery/PRM** | OAuth handshake + metadata compliance (does the server correctly advertise its login process); credential-free, testable on public servers today | 1–5, 9–12 |
| **1 — Token passthrough** | MCP server → downstream API boundary (the line between the server and the back-end behind it); needs valid tokens + downstream observability | 14, 15 |
| **2 — Identity isolation / Confused deputy** | Multi-session, shared-identity, cross-user state pollution (keeping different users apart); needs concurrent authenticated sessions | 12, 16, 19, 21 |

---

## Gating rules (every detector must honor)

- **Transport gating.** HTTP/auth gaps apply only to HTTP / Streamable-HTTP (the current web-request connection style) / SSE (the older one-way streaming style) servers.
  For **stdio** servers (run locally, no internet address; all MSB targets), the spec says NOT to use the OAuth flow — creds come from the environment — so gaps 1–4, 9–21 return `NOT_APPLICABLE`. (Local-listener DNS-rebinding/Origin can still apply if a stdio server also opens an HTTP port.)
- **Version gating.** Gaps 3, 4, 10, 11, 14, 15 are *MUSTs* (firm requirements) only under the **2025-06-18** spec version. Read the negotiated `MCP-Protocol-Version` (the spec version the two sides agreed on; server assumes `2025-03-26` if the header is absent).
  A server merely on the older revision is **not** non-compliant — report weaker posture as
  a *risk note*, not `HAS_GAP`, unless it targets 2025-06-18.
- **Loopback exemption.** Cleartext `http://` (unencrypted) and missing TLS are acceptable on `localhost`/`127.0.0.1` (loopback = reachable only from the same machine). Only flag on non-loopback hosts.

---

## Architecture

```
YamAmit-MCP-auth/
  OUTLINE.md            # this file
  README.md            # quickstart
  pyproject.toml        # uv-managed, isolated env
  mcpauth/
    __init__.py
    models.py           # Verdict enum, Finding, ProbeContext, TargetSpec
    probe.py            # low-level HTTP/JSON-RPC client (one shared transport)
    oauth.py            # PRM -> AS-metadata discovery (RFC 9728/8414), fetched once
    runner.py           # discovers + runs detectors independently, aggregates report
    detectors/
      __init__.py       # registry: id -> detector callable, tier, severity
      base.py           # Detector protocol + helpers (gating, safe verdicts, needs_oauth)
      tier1.py          # the 5 Tier-1 detectors (one class each)
      tier2.py          # the 7 Tier-2 detectors (one class each)
      # tier3.py — to be added as that tier is built
    cli.py              # `mcpauth scan <url>` -> JSON report
  sandbox/
    vulnerable_server.py        # Tier-1 HAS_GAP target (easy gaps on)
    hardened_server.py          # Tier-1 NO_GAP target (easy gaps closed)
    broken_auth_server.py       # gates on a token but non-compliantly (HAS paths that
                                #   need a server which DOES gate access; also #10 anchor)
    vulnerable_oauth_server.py  # Tier-2 HAS_GAP target (predictable sessions, no Origin
                                #   check, reflecting CORS, http OAuth eps, implicit, open DCR)
    hardened_oauth_server.py    # Tier-2 NO_GAP target (every Tier-2 gap closed)
  tests/
    test_tier1.py        # each Tier-1 detector vs each sandbox posture (14 cases)
    test_tier2.py        # each Tier-2 detector vs each sandbox posture (19 cases)
  reports/               # real-world scan outputs (see "Real-world results" below)
```

**Independence requirement (from the mission):** each detector (one gap-check) is a self-contained callable `detect(ctx: ProbeContext) -> Finding`. It must not depend on another detector's result. The runner can execute them in any order / in parallel. This is what lets us "create and run separate independent tasks, each mapping one gap."

Each `Finding` (one detector's result) carries: `gap_id`, `verdict` (the answer:
HAS_GAP/NO_GAP/etc.), `severity`, `evidence` (the raw request/response snippet that justifies the verdict), `spec_reference` (which rule it checks), and `notes`.

---

## Validation strategy (how we know a detector works)

Because we can't promise the user owns any real exposed server, every detector is validated against **local sandbox servers we control** (sandbox = small test servers we run on our own machine). Three postures (each server set up a different way) are needed because no single server exercises every verdict path (a no-auth server can never demonstrate a malformed 401 = a wrongly-formed "log in first" reply):

- `sandbox/vulnerable_server.py` — exhibits the gap → detector must return `HAS_GAP`.
- `sandbox/hardened_server.py` — closes the gap → detector must return `NO_GAP`.
- `sandbox/broken_auth_server.py` — DOES require a token but challenges non-compliantly → exercises HAS paths for detectors (like #3) that only fire when a server gates access.

Tier 2 adds two more (the OAuth/transport gaps need an OAuth-metadata surface no Tier-1 server has):

- `sandbox/vulnerable_oauth_server.py` — predictable sessions, no Origin check, reflecting CORS, http OAuth endpoints, implicit grant, open DCR → `HAS_GAP` for #6–#9, #11, #12 (it *does* serve valid AS metadata, so it is the `NO_GAP` anchor for #10).
- `sandbox/hardened_oauth_server.py` — every Tier-2 gap closed → `NO_GAP`.
- `broken_auth_server.py` is reused as the `HAS_GAP` anchor for #10 (claims strict spec yet exposes no AS metadata).

A detector is only "done" when it gives the right verdict across these. Real-world targets are then opt-in via the CLI. **33 tests pass** (14 Tier-1 + 19 Tier-2).

---

## Real-world results (88 public servers)

**Tier 1 — 88 servers across two batches (87 reachable).** Famous remote servers are overwhelmingly hardened (they demand login); only DeepWiki + EdgeOne are open (no login) in batch 1 (both public by design), while the lesser-known registry long tail (batch 2) has ~22 wide-open servers. DeepWiki is the cleanest spec-claim-vs-reality case (claims the 2025-06-18 spec version but its `.well-known` metadata, the login-info page, 404s = is missing). Full per-gap tables in `reports/real_world_scan.md` (batch 1) + `real_world_scan_batch2.md`.

**Tier 2 — same 88, 6 read-only detectors** (`open-dcr` excluded — it writes, i.e. could change something on the server; see below). Headline HAS_GAP counts: `origin-not-validated` 27, `missing-as-metadata` 14 (incl. vercel & prisma with RFC 8414 §3.3 issuer mismatches — their published identity field doesn't match), `cors-misconfiguration` 4, `implicit-flow-enabled` 1, `predictable-session-id` 0 (of 11 assessable). No new clearly-exploitable holes beyond the Tier-1 batches — the Tier-2 value so far is compliance signal (rule-following, not break-ins), framed honestly (a spec MUST miss is not automatically an exploit; CORS isn't even in the MCP spec). Table + caveats in
`reports/real_world_scan_tier2.md`; raw JSON in `reports/raw_tier2/`. This run also caught and fixed a false positive in our own `oauth.py` (origin-fallback issuer "mismatch").

**Known limitation surfaced by these runs (must fix before bulk-scanning):** the prober does not yet replay the `Mcp-Session-Id` (the conversation tag the server handed back) from `initialize` (the opening "let's start" message) or perform the legacy two-channel SSE handshake (the older streaming connection setup), so session-using servers return `400` ("bad/incomplete request") / `404` → false `INCONCLUSIVE` (8 servers on gap #1; 32 on gap #5; also caps `predictable-session-id` reach — 76 N/A). See status doc §"How we handle the tool's blind spot".

---

## Execution roadmap (increasing difficulty — stop/reassess after each tier)

1. ✅ **Tier 0 — harness.** `models.py`, `probe.py`, `runner.py`, detector registry, CLI, + sandbox servers. Proven end-to-end.
2. ✅ **Tier 1 — 5 easy detectors.** Validated against the 3 sandbox postures (14 tests) and run against 36 real servers.
3. ✅ **Tier 2 — 7 medium detectors** (gaps 6–12). Built and validated against the two new OAuth sandbox postures + broken_auth (19 tests). Adds `oauth.py` (shared PRM → AS-metadata fetch) and the `needs_oauth` runner hook.
4. **Transport fix (no-regret, still pending).** Session-id replay (re-sending the conversation tag) + SSE handshake (the older streaming-connection setup), so Tier-1 verdicts (and Tier-2 #6, which also reads the session header) stop coming back INCONCLUSIVE on real servers. Must precede any bulk scan.
5. **Tier 3 — 9 hard detectors** (gaps 13–21). Requires an OAuth-capable mock AS (a fake login server) in the sandbox; the behavioral ones (15 token-passthrough, 21 isolation) may stay best-effort/INCONCLUSIVE without a downstream (a back-end system behind the server) — documented honestly, never silently skipped.

Reassess scope with the user at each tier boundary; within a tier, run autonomously.
