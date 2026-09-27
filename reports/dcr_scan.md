# open-dcr LIVE run (writes performed, with RFC 7592 cleanup)

Part of the canonical full re-scan on **2026-09-27** (all 14 checks; raw output in `reports/raw-rescan-2026-09-27/`, write journal alongside).

Ran open-dcr against 83 servers. **38 have open registration** (anyone can register a client with no approval).

Verdicts: 38 HAS_GAP, 35 NOT_APPLICABLE (no registration endpoint advertised), 10 INCONCLUSIVE.

## ⚠️ 38 client(s) could NOT be auto-deleted — MANUAL CLEANUP NEEDED

No server returned the RFC 7592 management fields needed to delete a registration, so every client created is permanent until the server expires it.

| server (target) | host written to | client_id |
|---|---|---|
| https://agent.tinyfish.ai/mcp | clerk.tinyfish.ai | `EnSw693XDoWUWPAI` |
| https://api.bowmark.ai/mcp | api.bowmark.ai | `Z7VoOimtw3lZlxEUg5IBOA` |
| https://api.craneledger.ai/mcp | auth.craneledger.ai | `cl_6b52e9a6e24244bb9c860340facff001` |
| https://app.buron.ai/api/mcp | app.buron.ai | `vESvYouxCScVnOaeRpigMGQpCKfVafpV` |
| https://bindings.mcp.cloudflare.com/sse | bindings.mcp.cloudflare.com | `UZj-p8Tr34Nv-g5w` |
| https://browser.mcp.cloudflare.com/sse | browser.mcp.cloudflare.com | `dTLtrb1XJ2XDNb8d` |
| https://getperspective.ai/mcp | getperspective.ai | `persp_cid_5bf92cc0d0847be2a0e252c3703e319a` |
| https://mcp-github-registry.explorium.ai/sse | mcp-github-registry.explorium.ai | `zKxSteokJ7OFBqhR` |
| https://mcp-server.walterwrites.ai/mcp | mcp-server.walterwrites.ai | `mcp_7c1e56a2f1af7146e9f5b350f59c8bde8c90373e` |
| https://mcp.atlassian.com/v1/sse | mcp.atlassian.com | `9dBJu6sWVABkNdrD` |
| https://mcp.cirra.ai/sfdc/mcp | mcp.cirra.ai | `RL4s1x_I3BXmhjB-` |
| https://mcp.context7.com/mcp | clerk.context7.com | `VKHkuiIzAdKOBmrl` |
| https://mcp.context7.com/sse | clerk.context7.com | `xLKuwYxPED0332sU` |
| https://mcp.gavelin.ai/mcp | mcp.gavelin.ai | `dyn_d804925486356af9e6079e578d039129` |
| https://mcp.globalping.dev/sse | mcp.globalping.dev | `ik0YGL_jbc7YSPHv` |
| https://mcp.gondola.ai/mcp | www.gondola.ai | `gond_mcp_xRRRCNx-KB0oJNBnN105y9neuA9pCQjU` |
| https://mcp.gossiper.io/mcp | mcp.gossiper.io | `cmuk9xhrm000004l8so1hrfrj` |
| https://mcp.grafana.com/mcp | mcp.grafana.com | `eyJhbGciOiJFUzI1NiIsImtpZCI6ImM0OTI4ZTUyOWIzMWFmNDQiLCJ0eXAi` |
| https://mcp.linear.app/mcp | mcp.linear.app | `rWHyAPi5aP7w0Un4` |
| https://mcp.linear.app/sse | mcp.linear.app | `FuWC3Ozg22xUq-x0` |
| https://mcp.neon.tech/mcp | mcp.neon.tech | `IW9hgCDA` |
| https://mcp.neon.tech/sse | mcp.neon.tech | `Wt7SurtV` |
| https://mcp.notion.com/mcp | mcp.notion.com | `PqVqDpdSzafA4P-n` |
| https://mcp.paypal.com/sse | mcp.paypal.com | `bq85MoO0OQIMcawV` |
| https://mcp.prisma.io/mcp | auth.prisma.io | `eyJhbGciOiJSUzI1NiIsInR5cCI6ImRjcitqd3QiLCJraWQiOiJUa0hEN1lt` |
| https://mcp.sentry.dev/mcp | mcp.sentry.dev | `HsQfoHWFDtN5b06h` |
| https://mcp.sentry.dev/sse | mcp.sentry.dev | `8WRh2M2l4DtJYoHI` |
| https://mcp.stompy.ai | mcp.stompy.ai | `stompy_QUh1wN_FBT4dvO954yR12A` |
| https://mcp.stripe.com | access.stripe.com | `oacli_VL4tXadORC220H` |
| https://mcp.switchapp.ai/mcp | mcp.switchapp.ai | `mcpc_FaJ6yRCz3gr3o1vSVDPZsw` |
| https://mcp.webflow.com/sse | mcp.webflow.com | `c430j-QPGFrikgLQ` |
| https://mcp.wix.com/sse | mcp.wix.com | `1UTJwDw2SZ1rYL0q` |
| https://mcp.zapier.com/api/mcp/mcp | mcp.zapier.com | `KNH976u7-qKBLg5TmSj_gEuFQ--R0YXOImyETZsE9Mc` |
| https://nebula.cosmonote.ai/mcp | nebula.cosmonote.ai | `mcp_4e6d7b7686b8e8b5f91649c22e84e11d257087efed1c396a604ffe06` |
| https://observability.mcp.cloudflare.com/sse | observability.mcp.cloudflare.com | `7LVScgZeXpm3ObCe` |
| https://qr-manager.ai/api/mcp | qr-manager.ai | `3615d25e-8676-488f-9224-254e357ad59b` |
| https://radar.mcp.cloudflare.com/sse | radar.mcp.cloudflare.com | `ZRyH8d8cd7JilYcq` |
| https://trydock.ai/api/mcp | trydock.ai | `dock_client_77ee4d9beebdc6dfdefbde7b1e477c5b` |
