# Real-World MCP Server Auth-Posture Scan

**Date:** 2026-06-13
**Tool:** `mcpauth scan <URL> --json` (Tier-1 detectors only, 5 gaps)
**Scope:** 36 public remote MCP endpoints (HTTP / SSE / streamable-HTTP). One scan per endpoint, single retry on transient failure. No detector logic modified.

The five Tier-1 gaps scanned per endpoint:

1. `no-authentication-remote` (critical) — privileged `tools/list` with no `Authorization` returns 200 → HAS_GAP.
2. `no-tls-transport` (high) — cleartext HTTP on a non-loopback host.
3. `missing-www-authenticate` (medium) — 401 without RFC 9728 `WWW-Authenticate: ... resource_metadata=` (MUST only under 2025-06-18).
4. `missing-protected-resource-metadata` (medium) — no `/.well-known/oauth-protected-resource` with `authorization_servers` (MUST only under 2025-06-18).
5. `session-id-in-url` (medium) — session id carried in URL/query instead of `Mcp-Session-Id` header.

---

## Headline numbers

- **36 endpoints tested**, **34 reachable** (2 unreachable: DNS NXDOMAIN).
- **Posture by `no-authentication-remote` verdict:**
  - **Hardened (auth-gated, NO_GAP):** 24
  - **Open (HAS_GAP):** 2 — `deepwiki`, `edgeone` (both intentional public utility servers)
  - **Inconclusive:** 8 (tool limitations — see below)
  - **Unreachable (ERROR):** 2 — `fetch-mcp`, `sequentialthinking` (host does not resolve)

No genuine misconfiguration found. The two HAS_GAP servers are deliberately public, anonymous-access utility servers. Most production SaaS MCP servers correctly answer **HTTP 401** to an unauthenticated `initialize`/`tools/list`.

---

## Results table

Verdict abbreviations: `HAS_GAP` / `NO_GAP` / `N/A` (not applicable) / `INCONC` (inconclusive) / `ERROR`.
`proto` = protocol version negotiated on `initialize` (`unneg.` = server returned 401/404/405 before negotiating, so no version was exchanged).

| name | endpoint URL | transport | proto | no-auth | no-tls | www-auth | prm | sid-url | posture |
|---|---|---|---|---|---|---|---|---|---|
| asana | https://mcp.asana.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| atlassian-sse | https://mcp.atlassian.com/v1/sse | SSE | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC | hardened |
| cloudflare-bbrowser | https://browser.mcp.cloudflare.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| cloudflare-bindings | https://bindings.mcp.cloudflare.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| cloudflare-docs | https://docs.mcp.cloudflare.com/sse | SSE | unneg. | INCONC | NO_GAP | N/A | INCONC | INCONC | inconclusive |
| cloudflare-observability | https://observability.mcp.cloudflare.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| cloudflare-radar | https://radar.mcp.cloudflare.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| context7 | https://mcp.context7.com/mcp | streamable-HTTP | 2025-06-18 | INCONC | NO_GAP | N/A | NO_GAP | NO_GAP | inconclusive |
| context7-sse | https://mcp.context7.com/sse | SSE | unneg. | INCONC | NO_GAP | N/A | NO_GAP | INCONC | inconclusive |
| **deepwiki** | https://mcp.deepwiki.com/mcp | streamable-HTTP | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | **HAS_GAP** | INCONC | **open** |
| deepwiki-sse | https://mcp.deepwiki.com/sse | SSE | unneg. | INCONC | NO_GAP | N/A | INCONC | INCONC | inconclusive |
| **edgeone** | https://mcp-on-edge.edgeone.app/mcp-server | streamable-HTTP | 2024-11-05 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC | **open** |
| fetch-mcp | https://remote.mcpservers.org/fetch/mcp | streamable-HTTP | unneg. | ERROR | NO_GAP | ERROR | ERROR | ERROR | unreachable |
| github | https://api.githubcopilot.com/mcp/ | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | INCONC | INCONC | hardened |
| globalping | https://mcp.globalping.dev/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| grafana | https://mcp.grafana.com/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| hf-sse | https://hf.co/mcp/sse | SSE | unneg. | INCONC | NO_GAP | N/A | NO_GAP | INCONC | inconclusive |
| huggingface | https://hf.co/mcp | streamable-HTTP | 2025-06-18 | INCONC | NO_GAP | N/A | NO_GAP | NO_GAP | inconclusive |
| intercom | https://mcp.intercom.com/sse | SSE | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC | hardened |
| linear-mcp | https://mcp.linear.app/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| linear-sse | https://mcp.linear.app/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| neon | https://mcp.neon.tech/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| neon-mcp | https://mcp.neon.tech/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| notion | https://mcp.notion.com/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| paypal | https://mcp.paypal.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| prisma | https://mcp.prisma.io/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | INCONC | NO_GAP | INCONC | hardened |
| semgrep | https://mcp.semgrep.ai/sse | SSE | unneg. | INCONC | NO_GAP | N/A | NO_GAP | INCONC | inconclusive |
| sentry | https://mcp.sentry.dev/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | INCONC | INCONC | hardened |
| sentry-sse | https://mcp.sentry.dev/sse | SSE | unneg. | INCONC | NO_GAP | N/A | INCONC | INCONC | inconclusive |
| sequentialthinking | https://remote.mcpservers.org/sequentialthinking/mcp | streamable-HTTP | unneg. | ERROR | NO_GAP | ERROR | ERROR | ERROR | unreachable |
| square | https://mcp.squareup.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| stripe | https://mcp.stripe.com | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| vercel | https://mcp.vercel.com | streamable-HTTP | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| webflow | https://mcp.webflow.com/sse | SSE | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC | hardened |
| wix | https://mcp.wix.com/sse | SSE | unneg. | NO_GAP | NO_GAP | INCONC | NO_GAP | INCONC | hardened |
| zapier | https://mcp.zapier.com/api/mcp/mcp | streamable-HTTP | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC | hardened |

> Note on `no-tls-transport`: every endpoint scored NO_GAP simply because all candidate URLs are `https://`. This detector only fires on cleartext non-loopback hosts; none were found (expected for production servers).

---

## Servers with a real HAS_GAP

Two endpoints returned `no-authentication-remote = HAS_GAP` (tools listed/usable with zero credentials). **Both are intentionally-public utility servers, not misconfigurations:**

### 1. DeepWiki — `https://mcp.deepwiki.com/mcp` (INTENTIONALLY PUBLIC)
- Server: `DeepWiki 2.14.3`, protocol **2025-06-18**.
- `no-authentication-remote = HAS_GAP`: `tools/list` returned 3 read-only tools (`read_wiki_structure`, `read_wiki_contents`, `ask_question`) with no credential. This is by design — DeepWiki is a free, anonymous, read-only documentation Q&A service over public GitHub repos. No write/state-changing surface; no user data exposed.
- `missing-protected-resource-metadata = HAS_GAP`: **legitimate spec-claim-vs-reality mismatch.** The server negotiates `2025-06-18`, under which RFC 9728 protected-resource-metadata is a MUST, yet `/.well-known/oauth-protected-resource` returns **404**. Because the server is anonymous-by-design it never intends to use OAuth, so the practical risk is low — but it is a genuine non-compliance with the version it advertises. Worth flagging as the cleanest example of "claims 2025-06-18 but missing RFC 9728 metadata."

### 2. EdgeOne Pages Deploy — `https://mcp-on-edge.edgeone.app/mcp-server` (INTENTIONALLY PUBLIC, higher-impact surface)
- Server: `edgeone-pages-deploy-mcp-server 1.0.0`, protocol **2024-11-05**.
- `no-authentication-remote = HAS_GAP`: `tools/list` returned a `deploy-html` tool (deploys HTML content to Tencent EdgeOne edge) with no credential. This is the documented public demo behavior of EdgeOne Pages MCP — anonymous users can publish ephemeral HTML pages. It is intentional, but unlike DeepWiki it exposes a **state-changing/deploy action** anonymously, so it is a more interesting abuse surface (resource consumption, hosting arbitrary content).
- `missing-protected-resource-metadata = INCONCLUSIVE` (not HAS_GAP): correct — the server negotiated **2024-11-05**, under which RFC 9728 metadata is **not** a MUST, so the detector correctly downgrades the 404 to INCONCLUSIVE rather than flagging it. Good demonstration of the version-gating logic working.

**No genuine misconfig (a server that intended auth but failed to enforce it) was observed in this sample.**

---

## Spec-claim-vs-reality notes

- **DeepWiki**: advertises `2025-06-18` but does not serve RFC 9728 metadata (404) — see above. The only server in the sample that triggers the strict 2025-06-18 MUST and fails it.
- **context7 / huggingface**: both negotiate `2025-06-18` and **do** serve `/.well-known/oauth-protected-resource` with `authorization_servers` (NO_GAP on `missing-protected-resource-metadata`) — compliant. Their `no-auth` verdict is INCONCLUSIVE only due to the session limitation below, not a server fault.
- All other production servers reject the unauthenticated `initialize` with **401 before negotiating a version** (`proto = unneg.`). This means the version-gated detectors (`missing-www-authenticate`, `missing-protected-resource-metadata`) evaluate against `ctx.targets_strict_spec = False`, so a missing pointer/metadata yields INCONCLUSIVE rather than HAS_GAP. That is correct behavior, but it also means we cannot assess RFC 9728 compliance for any auth-gated server without a token.

---

## Tool limitations surfaced (feeds Tier-2 work)

Ranked by number of endpoints affected:

### 1. Streamable-HTTP / SSE session not replayed → `tools/list` rejected (8 endpoints → `no-authentication-remote = INCONCLUSIVE`)
The detector issues a bare `tools/list` without replaying the `Mcp-Session-Id` returned by `initialize`. Servers that require a session reject it:
- **HTTP 400 "Session ID required"** — `huggingface` (`hf.co/mcp`), `context7` (`mcp.context7.com/mcp`). These negotiated `2025-06-18` on `initialize` (so they ARE reachable and open-ish), but the second call fails session validation. **This is the known tool gap, not a server finding.**
- **HTTP 404 on SSE GET-style endpoints** — `cloudflare-docs`, `context7-sse`, `hf-sse`, `semgrep`, `sentry-sse`, `deepwiki-sse`. The `/sse` endpoints expect the legacy two-channel SSE handshake (GET to open stream, POST to a separate message URL); the detector POSTs JSON-RPC directly to the `/sse` path and gets 404/405.
- **Impact:** 8 endpoints could not get a clean open-vs-hardened verdict. **Highest-priority Tier-2 fix:** capture `Mcp-Session-Id` from `initialize` and replay it on subsequent calls; and implement the legacy SSE endpoint-event handshake for `/sse` targets.

### 2. SSE handshake not implemented → `session-id-in-url = INCONCLUSIVE` (32 of 34 reachable endpoints)
`session-id-in-url` is INCONCLUSIVE almost everywhere because, for auth-gated servers, `initialize` returns 401 (no `Mcp-Session-Id` header to inspect and the follow-up SSE GET also requires auth), and for the open SSE servers the detector does not complete the legacy SSE handshake to observe whether the message URL carries `?sessionId=`. Only `context7` and `huggingface` (open, header-based session) reached NO_GAP. **Tier-2 fix:** same SSE-handshake support as #1 would let this detector actually observe the message-channel URL.

### 3. Auth-gated 401-before-negotiation hides version-gated checks (most hardened servers → INCONCLUSIVE on www-auth/prm where applicable)
Because protected servers 401 the `initialize`, no `MCP-Protocol-Version` is negotiated, so `targets_strict_spec` is False and gaps #3/#4 cannot be asserted as HAS even if metadata were missing. Several servers (`atlassian-sse`, `intercom`, `wix`, `zapier`, `prisma`) returned INCONCLUSIVE on `missing-www-authenticate` — their 401 lacked a `resource_metadata` pointer, but the tool won't flag it without a confirmed 2025-06-18 negotiation. **Tier-2 consideration:** read the protocol version the server *would* use (e.g. from a successful unauthenticated `initialize` that some servers allow, or from the 401's own headers) to decide strictness; and treat a 401 WITHOUT any `WWW-Authenticate` header as a weaker finding regardless of version.

### 4. DNS / unreachable host (2 endpoints → ERROR)
- `remote.mcpservers.org` (`fetch-mcp`, `sequentialthinking`) — **NXDOMAIN** from the sandbox resolver (`ClientConnectorDNSError`, confirmed via `nslookup`). Host genuinely does not resolve here; could be a defunct directory entry or sandbox DNS restriction. Not a tool bug. These two are the only fully unreachable endpoints.

No TLS errors, redirects, or timeouts were encountered.

---

## Reproducible endpoint list

The exact endpoints scanned are in `reports/endpoints.txt` (format `name|url`), and the scan was driven by `reports/run_scans.sh` (one `uv run mcpauth scan <URL> --json` per line, single retry on empty/non-JSON output, polite 1s spacing). Raw per-endpoint JSON reports are under `reports/raw/<name>.json` (with `<name>.err` capturing any stderr).

To reproduce:
```
cd "/Users/yamitkfi/Documents/CS deg/MCProject/YamAmit-MCP-auth"
bash reports/run_scans.sh
```

Endpoints (36):
```
deepwiki                  https://mcp.deepwiki.com/mcp
deepwiki-sse              https://mcp.deepwiki.com/sse
huggingface               https://hf.co/mcp
hf-sse                    https://hf.co/mcp/sse
linear-sse                https://mcp.linear.app/sse
linear-mcp                https://mcp.linear.app/mcp
notion                    https://mcp.notion.com/mcp
sentry                    https://mcp.sentry.dev/mcp
sentry-sse                https://mcp.sentry.dev/sse
atlassian-sse             https://mcp.atlassian.com/v1/sse
github                    https://api.githubcopilot.com/mcp/
stripe                    https://mcp.stripe.com
cloudflare-docs           https://docs.mcp.cloudflare.com/sse
cloudflare-bindings       https://bindings.mcp.cloudflare.com/sse
cloudflare-observability  https://observability.mcp.cloudflare.com/sse
cloudflare-radar          https://radar.mcp.cloudflare.com/sse
cloudflare-bbrowser       https://browser.mcp.cloudflare.com/sse
asana                     https://mcp.asana.com/sse
globalping                https://mcp.globalping.dev/sse
grafana                   https://mcp.grafana.com/mcp
webflow                   https://mcp.webflow.com/sse
wix                       https://mcp.wix.com/sse
paypal                    https://mcp.paypal.com/sse
square                    https://mcp.squareup.com/sse
intercom                  https://mcp.intercom.com/sse
neon                      https://mcp.neon.tech/sse
neon-mcp                  https://mcp.neon.tech/mcp
prisma                    https://mcp.prisma.io/mcp
vercel                    https://mcp.vercel.com
zapier                    https://mcp.zapier.com/api/mcp/mcp
context7                  https://mcp.context7.com/mcp
context7-sse              https://mcp.context7.com/sse
semgrep                   https://mcp.semgrep.ai/sse
edgeone                   https://mcp-on-edge.edgeone.app/mcp-server
fetch-mcp                 https://remote.mcpservers.org/fetch/mcp        (unreachable: NXDOMAIN)
sequentialthinking        https://remote.mcpservers.org/sequentialthinking/mcp  (unreachable: NXDOMAIN)
```

---

## Honesty / caveats

- "Hardened" here means only that the server **enforces auth on the first unauthenticated call** (401). It does NOT mean the server's OAuth flow, token-audience validation, PKCE, CORS, or session handling are correct — those are Tier-2/Tier-3 gaps not exercised here, and most require a valid token we do not hold.
- For the 8 INCONCLUSIVE-on-no-auth servers, we genuinely cannot say open-vs-hardened from this pass; the session-replay limitation (#1) blocked it. `huggingface` and `context7` are likely at least partially open (they negotiated `2025-06-18` and answered `initialize` anonymously) but the `tools/list` rejection prevents confirmation.
- One scan per endpoint was performed (plus the built-in single retry on transient/empty output). Third-party production servers were not hammered.
