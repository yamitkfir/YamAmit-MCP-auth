# Real-World MCP Server Auth-Posture Scan — Batch 2

**Date:** 2026-06-20
**Tool:** `mcpauth scan <URL> --json` (Tier-1 detectors only, 5 gaps)
**Source:** Official MCP Registry (`registry.modelcontextprotocol.io/v0/servers`), 12 pages (~1,200 server records) paginated via `metadata.nextCursor`. Remote (`http(s)`) endpoints from each entry's `remotes[]` were extracted; stdio-only servers skipped.
**Scope:** 52 NEW remote endpoints appended to `reports/endpoints.txt` (the original 36 were NOT re-scanned). One scan per endpoint, single retry on empty/non-JSON output, ~1.2s spacing. No detector logic modified.

The selection mixes recognizable vendor servers (Exa, Parallel, Reka, Waystation connectors, Smithery-hosted Brave/Browserbase/Docfork/GitHub) with a diverse host-deduped sample of registry entries (one URL per host).

---

## Headline numbers

- **52 new endpoints** found in the registry and appended to `reports/endpoints.txt` (total list is now **88**).
- **50 reachable**, **2 unreachable** (see below).
- **Open (no-authentication-remote = HAS_GAP):** 22 servers — see standouts.
- **Spec-claim-vs-reality (negotiates 2025-06-18 but no RFC 9728 protected-resource-metadata):** 14 servers.

---

## Per-gap tally (new batch of 52)

| gap | HAS_GAP | NO_GAP | NOT_APPLICABLE | INCONCLUSIVE | ERROR |
|---|---|---|---|---|---|
| `no-authentication-remote` | 22 | 22 | 0 | 6 | 2 |
| `no-tls-transport` | 0 | 52 | 0 | 0 | 0 |
| `missing-www-authenticate` | 0 | 12 | 28 | 10 | 2 |
| `missing-protected-resource-metadata` | 16 | 15 | 0 | 19 | 2 |
| `session-id-in-url` | 0 | 9 | 0 | 41 | 2 |

> `no-tls-transport` is NO_GAP for all 52 — every candidate URL is `https://`. The detector only fires on cleartext non-loopback hosts.
> The high `session-id-in-url` INCONCLUSIVE count (41) and `missing-www-authenticate` N/A count (28) reflect the same Tier-1 tool limitations documented in batch 1 (no SSE/session-replay handshake; servers that answer 200 anonymously never emit a 401 so the WWW-Authenticate MUST is N/A).

---

## Results table

Verdicts: `HAS_GAP` / `NO_GAP` / `N/A` / `INCONC` / `ERROR`. `proto` = version negotiated on `initialize` (`unneg.` = server rejected before negotiating).

| name | url | proto | no-auth | no-tls | www-auth | prm | sid-url |
|---|---|---|---|---|---|---|---|
| h-index | https://h-index.xr-utilities.ai/mcp | 2025-03-26 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC |
| library | https://childpsychiatry.ai/api/mcp/v1 | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | NO_GAP |
| getperspective | https://getperspective.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | INCONC | INCONC |
| atars-mcp | https://mcp.aarna.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| dock | https://trydock.ai/api/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | NO_GAP | INCONC |
| stompy | https://mcp.stompy.ai | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| ca-rate-filings | https://api.serff.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | NO_GAP | INCONC |
| company-search | https://trycanonical.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| krtr | https://www.krtr.ai/api/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| library-2 | https://teenadhd.ai/api/mcp/v1 | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | NO_GAP |
| mcp-mailjunky | https://mcp.mailjunky.ai/sse | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| crane-ledger | https://api.craneledger.ai/mcp | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| web-agent | https://agent.tinyfish.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | INCONC | INCONC |
| hostprofit-mcp-production-up-railway-app | https://hostprofit-mcp-production.up.railway.app/mcp | unneg. | ERROR | NO_GAP | ERROR | ERROR | ERROR |
| just-publish | https://mcp.justpublish.ai/ | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | NO_GAP |
| directory | https://directory.boolsai.ai/mcp | unneg. | INCONC | NO_GAP | N/A | INCONC | INCONC |
| gondola | https://mcp.gondola.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | NO_GAP | INCONC |
| mcp-server | https://mcp-server.walterwrites.ai/mcp | unneg. | NO_GAP | NO_GAP | INCONC | NO_GAP | INCONC |
| buron | https://app.buron.ai/api/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| mcp-server-2 | https://tensorfeed.ai/api/mcp | 2024-11-05 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC |
| catalog-api | https://mcp.buywhere.ai/mcp | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| qr-manager | https://qr-manager.ai/api/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | INCONC | INCONC |
| weftly | https://api.weftly.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| docs | https://auteng.ai/mcp/docs | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| mcp-fiber | https://mcp.fiber.ai/mcp/v2/ | unneg. | INCONC | NO_GAP | N/A | INCONC | INCONC |
| scry | https://mcp.tunnelmind.ai/mcp | 2025-03-26 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC |
| figlime | https://figlime.rise2.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| quantifyme | https://mcp.quantifyme.ai/mcp | 2025-06-18 | INCONC | NO_GAP | N/A | HAS_GAP | NO_GAP |
| xmp4 | https://mcp.example4.ai/mcp | 2025-03-26 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC |
| shopify-admin-mcp | https://mcp.gossiper.io/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| salesforce-mcp | https://mcp.cirra.ai/sfdc/mcp | unneg. | NO_GAP | NO_GAP | INCONC | NO_GAP | INCONC |
| hi | https://mcp.hirey.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| api-openmandate | https://api.openmandate.ai/mcp | 2025-03-26 | **HAS_GAP** | NO_GAP | N/A | INCONC | NO_GAP |
| mcp-explorium | https://mcp-github-registry.explorium.ai/sse | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| travel | https://mcp.autonomad.ai/mcp | 2025-06-18 | INCONC | NO_GAP | N/A | HAS_GAP | NO_GAP |
| document-processing | https://api.filegraph.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| mcp-gavelin | https://mcp.gavelin.ai/mcp | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| strata | https://strata.klavis.ai/mcp/ | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| nullary | https://mcp.nullary.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| lawyer-search | https://mcp.law.ai | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| bowmark | https://api.bowmark.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| connect | https://mcp.raisonn.ai/mcp | unneg. | NO_GAP | NO_GAP | NO_GAP | NO_GAP | INCONC |
| anzenna | https://mcp.anzenna.ai/sse | unneg. | NO_GAP | NO_GAP | NO_GAP | HAS_GAP | INCONC |
| financial-data | https://mcp.rockmoon.ai/mcp | 2025-06-18 | INCONC | NO_GAP | N/A | HAS_GAP | NO_GAP |
| google-trends | https://google-trends.api.trendsmcp.ai/mcp | 2025-03-26 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | INCONC |
| mcp-server-3 | https://mcp.tensorfeed.ai/mcp | 2024-11-05 | **HAS_GAP** | NO_GAP | N/A | INCONC | INCONC |
| library-3 | https://teenanxiety.ai/api/mcp/v1 | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | HAS_GAP | NO_GAP |
| robomart | https://mcp.robomart.ai/mcp | unneg. | ERROR | NO_GAP | ERROR | ERROR | ERROR |
| code | https://mcp.paperlantern.ai/chat/mcp | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| notes | https://nebula.cosmonote.ai/mcp | unneg. | INCONC | NO_GAP | N/A | NO_GAP | INCONC |
| filtrix-ai | https://mcp.filtrix.ai/ | unneg. | NO_GAP | NO_GAP | INCONC | INCONC | INCONC |
| switch | https://mcp.switchapp.ai/mcp | 2025-06-18 | **HAS_GAP** | NO_GAP | N/A | NO_GAP | NO_GAP |

---

## Standout findings

### Open servers — no-authentication-remote = HAS_GAP (22)

These returned a usable `tools/list` with **no credential**. Many are small `.ai` startups; several expose read/search tools, a few expose state-changing actions (e.g. `just-publish`, `dock`, `switch`). Whether each is an intentional public utility vs. a misconfiguration was not individually verified — flagged for review.

| name | url | proto |
|---|---|---|
| h-index | https://h-index.xr-utilities.ai/mcp | 2025-03-26 |
| library | https://childpsychiatry.ai/api/mcp/v1 | 2025-06-18 |
| atars-mcp | https://mcp.aarna.ai/mcp | 2025-06-18 |
| dock | https://trydock.ai/api/mcp | 2025-06-18 |
| ca-rate-filings | https://api.serff.ai/mcp | 2025-06-18 |
| library-2 | https://teenadhd.ai/api/mcp/v1 | 2025-06-18 |
| just-publish | https://mcp.justpublish.ai/ | 2025-06-18 |
| gondola | https://mcp.gondola.ai/mcp | 2025-06-18 |
| mcp-server-2 | https://tensorfeed.ai/api/mcp | 2024-11-05 |
| weftly | https://api.weftly.ai/mcp | 2025-06-18 |
| docs | https://auteng.ai/mcp/docs | 2025-06-18 |
| scry | https://mcp.tunnelmind.ai/mcp | 2025-03-26 |
| xmp4 | https://mcp.example4.ai/mcp | 2025-03-26 |
| api-openmandate | https://api.openmandate.ai/mcp | 2025-03-26 |
| document-processing | https://api.filegraph.ai/mcp | 2025-06-18 |
| nullary | https://mcp.nullary.ai/mcp | 2025-06-18 |
| lawyer-search | https://mcp.law.ai | 2025-06-18 |
| bowmark | https://api.bowmark.ai/mcp | 2025-06-18 |
| google-trends | https://google-trends.api.trendsmcp.ai/mcp | 2025-03-26 |
| mcp-server-3 | https://mcp.tensorfeed.ai/mcp | 2024-11-05 |
| library-3 | https://teenanxiety.ai/api/mcp/v1 | 2025-06-18 |
| switch | https://mcp.switchapp.ai/mcp | 2025-06-18 |

### Spec-claim-vs-reality — negotiates `2025-06-18` but missing RFC 9728 protected-resource-metadata (14)

Each of these negotiated protocol `2025-06-18` on an anonymous `initialize` (so `targets_strict_spec` is true), yet `/.well-known/oauth-protected-resource` returned 404 / no `authorization_servers` → `missing-protected-resource-metadata = HAS_GAP`. This is the clean class of "claims the strict version but doesn't serve the mandated metadata." Note several of these are also OPEN (no auth at all), so the missing metadata is consistent with never intending OAuth; but a few (`quantifyme`, `travel`, `financial-data`) answered `initialize` anonymously with 2025-06-18 yet returned INCONCLUSIVE on no-auth (session-gated `tools/list`), so they appear to *intend* auth while still failing the RFC 9728 MUST.

| name | url |
|---|---|
| library | https://childpsychiatry.ai/api/mcp/v1 |
| atars-mcp | https://mcp.aarna.ai/mcp |
| library-2 | https://teenadhd.ai/api/mcp/v1 |
| just-publish | https://mcp.justpublish.ai/ |
| weftly | https://api.weftly.ai/mcp |
| docs | https://auteng.ai/mcp/docs |
| quantifyme | https://mcp.quantifyme.ai/mcp |
| travel | https://mcp.autonomad.ai/mcp |
| document-processing | https://api.filegraph.ai/mcp |
| nullary | https://mcp.nullary.ai/mcp |
| lawyer-search | https://mcp.law.ai |
| bowmark | https://api.bowmark.ai/mcp |
| financial-data | https://mcp.rockmoon.ai/mcp |
| library-3 | https://teenanxiety.ai/api/mcp/v1 |

---

## Unreachable / error endpoints

| name | url | reason |
|---|---|---|
| hostprofit-mcp-production-up-railway-app | https://hostprofit-mcp-production.up.railway.app/mcp | `initialize` transport TimeoutError — host accepted connection but never responded (likely a sleeping Railway free-tier dyno). |
| robomart | https://mcp.robomart.ai/mcp | `ClientConnectorDNSError` — `mcp.robomart.ai` does not resolve (NXDOMAIN). |

No TLS errors or redirects were encountered. All other 50 endpoints completed at least the `initialize` probe.

---

## Honesty / caveats

- "Open" means only that an unauthenticated `tools/list` succeeded. It does not establish intent — many small public-utility servers are anonymous by design. None were probed beyond listing tools (no tool *calls* were made).
- The 6 `no-authentication-remote = INCONCLUSIVE` cases are the known Tier-1 streamable-HTTP/SSE session limitation (server returns HTTP 400 "session required" or the `/sse` two-channel handshake isn't replayed) — a tool gap, not a server finding. Affected: any row showing INCONC on no-auth (e.g. `quantifyme`, `travel`, `financial-data`, plus SSE endpoints).
- `session-id-in-url` is INCONCLUSIVE for 41/52 for the same handshake reason carried over from batch 1.
- One scan per endpoint (plus the single built-in retry). Third-party servers were not hammered.
- Raw per-endpoint output is under `reports/raw/<name>.json` (+ `<name>.err`). New endpoints are in `reports/endpoints.txt` under the `# --- batch 2 (added 2026-06-20) ---` marker.
