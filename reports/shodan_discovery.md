# Shodan Free-Tier Capability Probe + MCP-Scanner Feasibility

**Date:** 2026-06-13
**Goal:** Determine what a FREE-TIER Shodan API key can do for wild MCP-server discovery, and whether it can drive `MCP-Scanner/mcp_scanner.py` to feed discovered endpoints into the auth-gap prober (`mcpauth scan`).

**Key handling:** The Shodan key was used only via inline env var / CLI argument. It was NOT written to any file. Verified with `grep -rl <key>` across the scanner repo (no matches). All transient scanner artifacts (logs, result dirs) were deleted after the run.

---

## 1. The key's plan and credits (`api.info()`)

| Field | Value |
|-------|-------|
| `plan` | **`oss`** (the free / open-source registration tier) |
| `query_credits` | **0** |
| `scan_credits` | **0** |
| `monitored_ips` | 0 |
| `unlocked` | **false** |
| `https` | false |
| `telnet` | false |

Raw output captured at `reports/shodan_raw/shodan_info.json`.

This is a bare free account with **zero query credits**. On Shodan, the `oss` plan does not grant API search access at all — search requires at least a Membership (one-time paid) or a `.edu`-upgraded account, and query credits are only granted to paid/membership tiers.

## 2. Precise CAN / CANNOT boundary (tested empirically)

Each call below was issued against the live API. "CAN" = returned data; "CANNOT" = `403 Forbidden / Access denied`.

| API call | Result | Consumes credit? |
|----------|--------|------------------|
| `api.info()` | **CAN** | no |
| `api.count("MCP")` -> `total: 228140` | **CAN** | no |
| `api.count("mcp", facets=[("port",5)])` -> returns port histogram (443, 80, 161, 3000, 8000) | **CAN** | no |
| `api.host("8.8.8.8")` -> ip/ports/org | **CAN** | no (host lookup is allowed on free) |
| `api.ports()` (list of crawled ports) | **CAN** | no |
| `api.protocols()` | **CAN** | no |
| `api.search_facets()` | **CAN** | no |
| **`api.search("mcp jsonrpc")`** | **CANNOT — 403 Access denied** | (blocked) |
| **`api.search_cursor("mcp")`** (streaming) | **CANNOT — 403 Access denied** | (blocked) |

**Bottom line for the boundary:** the free key can do *metadata/aggregate* operations (`count` — including faceted port/country breakdowns — `host` lookups, `ports`, `protocols`, `info`) but **cannot retrieve any actual search result list** (`search` / `search_cursor` are hard-403'd). You can learn *how many* MCP-ish banners exist and *which ports* they cluster on, but you cannot get a single concrete `ip:port` from a search.

> Side note: `count("MCP")` returning ~228k is a banner keyword match across all of Shodan, NOT 228k MCP servers — "MCP" matches many unrelated things. It's only useful as an aggregate, and crucially it never yields host addresses on this tier.

## 3. Could the scanner run?

**No — it produces zero discoveries on this key.**

`mcp_scanner.py` discovery (`search_shodan`, line ~303) calls `self.shodan_api.search(filter_query, ...)` for each of **111 hardcoded filters**. (The `shodan_filters.json` file is a reference catalog only; the live list is hardcoded in the `MCPServerScanner.__init__` class body.)

Controlled run:
```
.venv/bin/python mcp_scanner.py --api-key <key> --max-results 5 --max-concurrent 5
```
Observed behavior (run killed after ~12 filters to avoid pointless churn):
- PHASE 0 reports `Query credits: 0 / Scan credits: 0` but still proceeds (it only checks `info()` succeeds, not that credits > 0).
- PHASE 1: every filter logs `Shodan API error for filter '...': Access denied (403 Forbidden)`. Filters 1 through 12+ all 403 identically.
- The 403 is not classified by the code as quota/connection, so it neither breaks the loop nor retries — it just logs and walks all 111 filters, discovering nothing.
- **Discovered servers: 0. Verified servers: 0.**

No credits were burned (there are none to burn; 403s don't deduct, and the scanner never reached a successful search).

## 4. Step 3 (feed discoveries into the auth-gap prober)

**Not performed — there were zero discovered host:port pairs to feed.** Step 3 is gated on Step 2 finding servers; it found none. The prober (`mcpauth scan <URL> --json`) was therefore not invoked against any third-party host. No external probing was done.

## 5. Posture summary

N/A — no servers discovered, so no HAS_GAP / hardened / unreachable verdicts to report.

## 6. Bottom line

**The free `oss` key is NOT sufficient for wild-scale MCP discovery.** The single hard limiting factor is:

> **`search()` / `search_cursor()` return `403 Access denied` on the `oss` plan, and the account has 0 query credits.**

Everything the scanner needs (a list of `ip:port` from search results) lives behind that blocked endpoint. The only data the free tier exposes — `count` aggregates, faceted port histograms, and per-IP `host()` lookups — never yields a target list, so it cannot seed the prober.

To pursue this you need one of:
- A **Shodan Membership** (one-time paid, ~$49 historically) which unlocks `search` and grants monthly query credits, OR
- A **`.edu` academic upgrade** (Shodan grants upgraded accounts with search access to verified academic emails) — the cheapest legitimate path for a CS project, OR
- A paid **API plan** for higher query-credit volume.

With search unlocked, the existing scanner would work as-is and could feed `ip:port` candidates into `mcpauth scan` for the full discovery -> auth-gap pipeline. As it stands, this key gets you nothing beyond aggregate counts.

## 7. Reproduction notes

- Env: `MCP-Scanner/.venv` (uv-managed), `shodan` + `requests` + `aiohttp` installed.
- Probe method: direct `shodan.Shodan(key)` Python calls (gives precise per-endpoint success/failure and credit control) plus one capped run of `mcp_scanner.py`.
- Raw `info()` output: `reports/shodan_raw/shodan_info.json`.
