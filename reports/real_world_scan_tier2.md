# Tier-2 real-world scan (6 read-only detectors, 88 endpoints)

Run 2026-06-20. Detectors: the 6 **read-only** Tier-2 checks. `open-dcr` (#12) was
**excluded** because it performs a write (a real OAuth client registration) — not run
against third-party servers without explicit approval. Command per endpoint:

```
uv run mcpauth scan <url> --tier 2 --safe        # --safe drops write detectors
```

Raw JSON in `reports/raw_tier2/`; machine summary in `reports/raw_tier2/_summary.json`.
87 of 88 reachable (1 transport error).

## Tally

| Gap | HAS_GAP | NO_GAP | N/A | Inconclusive | Error |
|-----|--------:|-------:|----:|-------------:|------:|
| `predictable-session-id` | 0 | 11 | 76 | 0 | 1 |
| `origin-not-validated` | 27 | 5 | 0 | 52 | 4 |
| `cors-misconfiguration` | 4 | 64 | 0 | 16 | 4 |
| `auth-endpoints-not-https` | 0 | 53 | 34 | 0 | 1 |
| `missing-as-metadata` | 14 | 51 | 0 | 22 | 1 |
| `implicit-flow-enabled` | 1 | 52 | 33 | 1 | 1 |

## HAS_GAP hits

- **origin-not-validated (27):** api-openmandate, atars-mcp, bowmark, ca-rate-filings,
  context7, deepwiki, dock, document-processing, edgeone, financial-data, gondola,
  google-trends, h-index, huggingface, just-publish, lawyer-search, library, library-2,
  library-3, mcp-server-2, mcp-server-3, nullary, scry, switch, travel, weftly, xmp4
- **missing-as-metadata (14):** atars-mcp, bowmark, deepwiki, docs, document-processing,
  financial-data, hi, just-publish, nullary, prisma, quantifyme, travel, vercel, weftly
- **cors-misconfiguration (4):** document-processing, hf-sse, huggingface, switch
- **implicit-flow-enabled (1):** ca-rate-filings

## Honest caveats (read before trusting the counts)

1. **`origin-not-validated` (27) over-reads for remote servers.** The probe sends a forged
   `Origin` (the header naming which website is calling) on `initialize` and flags HAS if it
   gets a 200. That is a true spec MUST violation, **but** the rule exists chiefly to stop
   *DNS-rebinding* (a trick where a malicious webpage fools a *locally-running* server) — the
   threat is far weaker for these remote HTTPS servers. Also, several of the 27 are the same
   wide-open (no-auth) servers from the Tier-1 batches, so this overlaps with #1 rather than
   being a distinct new exposure. Treat as a compliance gap, not a fresh hole. The 52
   INCONCLUSIVE are auth-gated (401) servers where the Origin decision wasn't observable.

2. **`missing-as-metadata` (14) mixes two cases.** Some genuinely publish no RFC 8414
   "how-to-log-in" document; others (e.g. **vercel, prisma**) *do* publish it but its
   declared `issuer` doesn't match what their resource-metadata pointed to — a real but
   narrower RFC 8414 §3.3 violation. **Calibration fix applied during this run:** an earlier
   pass wrongly flagged atlassian — when a server has no resource-metadata we probe its own
   origin as a guess, and that guess naturally differs from the real issuer; we no longer
   treat that as a mismatch. Atlassian correctly dropped out (15 → 14).

3. **`predictable-session-id` reach is limited (76 N/A).** Most servers returned no session
   header on our single `initialize`, so there was nothing to assess. This is the **same
   transport blind spot** that limits Tier-1 #5 — the session-replay/SSE fix would widen
   coverage here too. Of the 11 we *could* assess, none were predictable (good).

4. **`cors-misconfiguration` is a heuristic, not an MCP-spec rule** (CORS isn't in the spec).
   The 4 hits reflect an arbitrary Origin + allow credentials — relevant only to
   browser-based callers, which MCP clients usually are not. Low real-world severity.

5. **`open-dcr` (#12) — run live against 4 approved servers (2026-06-20).** Targets were the
   4 servers that are both wide-open (no-auth) AND advertise a `registration_endpoint`:
   `ca-rate-filings`, `dock`, `gondola`, `switch`. **All 4 accepted an unauthenticated client
   registration (HAS_GAP)** — a real open-DCR finding, corroborating their loose posture.
   **Cleanup caveat:** none of the 4 returned RFC 7592 management fields, so the throwaway
   clients we created **could not be auto-deleted** and remain on those servers (client ids
   recorded in `reports/dcr_scan.md`). They are inert public client registrations; deprovision
   manually if contact is possible. A read-only dry-run found 50/88 servers advertise
   registration, but most are major vendors where open DCR is intentional — not run.

## Bottom line

No new clearly-exploitable holes beyond what the Tier-1 batches already surfaced. The
Tier-2 value so far is **compliance signal**: a real cluster of servers that skip Origin
validation and a handful with malformed/missing AS metadata (incl. two big names with
issuer mismatches). All require the same honesty framing we apply throughout: a spec MUST
miss is not automatically an exploit.
