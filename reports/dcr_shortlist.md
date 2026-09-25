# open-dcr candidate shortlist (DRY RUN — read-only, no writes performed)

Scanned 88 endpoints. **48 advertise a registration_endpoint** (only these would be touched by a live run).

| server | registration_endpoint |
|---|---|
| asana | https://mcp.asana.com/register |
| atlassian-sse | https://mcp.atlassian.com/v1/register |
| bowmark | https://api.bowmark.ai/oauth/register |
| buron | https://app.buron.ai/api/auth/oauth2/register |
| catalog-api | https://api.buywhere.ai/v1/oauth/register |
| cloudflare-bbrowser | https://browser.mcp.cloudflare.com/register |
| cloudflare-bindings | https://bindings.mcp.cloudflare.com/register |
| cloudflare-observability | https://observability.mcp.cloudflare.com/register |
| cloudflare-radar | https://radar.mcp.cloudflare.com/register |
| company-search | https://trycanonical.ai/mcp/register |
| connect | https://mcp.raisonn.ai/oauth/register |
| context7 | https://clerk.context7.com/oauth/register |
| context7-sse | https://clerk.context7.com/oauth/register |
| crane-ledger | https://auth.craneledger.ai/register |
| dock | https://trydock.ai/oauth/register |
| getperspective | https://getperspective.ai/api/oauth/register |
| globalping | https://mcp.globalping.dev/register |
| gondola | https://www.gondola.ai/api/oauth/register |
| grafana | https://mcp.grafana.com/mcp/oauth/register |
| hi | https://hi.hirey.ai/oauth/register |
| intercom | https://mcp.intercom.com/register |
| linear-mcp | https://mcp.linear.app/register |
| linear-sse | https://mcp.linear.app/register |
| mcp-explorium | https://mcp-github-registry.explorium.ai/register |
| mcp-fiber | https://mcp.fiber.ai/register |
| mcp-gavelin | https://mcp.gavelin.ai/register |
| mcp-server | https://mcp-server.walterwrites.ai/oauth/register |
| neon | https://mcp.neon.tech/api/register |
| neon-mcp | https://mcp.neon.tech/api/register |
| notes | https://nebula.cosmonote.ai/oauth/register |
| notion | https://mcp.notion.com/register |
| paypal | https://mcp.paypal.com/register |
| prisma | https://auth.prisma.io/register |
| qr-manager | https://qr-manager.ai/api/oauth/register |
| salesforce-mcp | https://mcp.cirra.ai/register |
| semgrep | https://login.semgrep.dev/oauth2/register |
| sentry | https://mcp.sentry.dev/oauth/register |
| sentry-sse | https://mcp.sentry.dev/oauth/register |
| shopify-admin-mcp | https://mcp.gossiper.io/oauth2/register |
| square | https://mcp.squareup.com/register |
| stompy | https://mcp.stompy.ai/oauth/register |
| stripe | https://access.stripe.com/mcp/oauth2/register |
| switch | https://mcp.switchapp.ai/api/oauth/register |
| vercel | https://api.vercel.com/login/oauth/register |
| web-agent | https://clerk.tinyfish.ai/oauth/register |
| webflow | https://mcp.webflow.com/oauth/register |
| wix | https://mcp.wix.com/register |
| zapier | https://mcp.zapier.com/api/v1/oauth/register |

> ⚠️ `catalog-api` advertises registration on **api.buywhere.ai**, which is not the host scanned (`mcp.buywhere.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `context7` advertises registration on **clerk.context7.com**, which is not the host scanned (`mcp.context7.com`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `context7-sse` advertises registration on **clerk.context7.com**, which is not the host scanned (`mcp.context7.com`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `crane-ledger` advertises registration on **auth.craneledger.ai**, which is not the host scanned (`api.craneledger.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `gondola` advertises registration on **www.gondola.ai**, which is not the host scanned (`mcp.gondola.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `hi` advertises registration on **hi.hirey.ai**, which is not the host scanned (`mcp.hirey.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `prisma` advertises registration on **auth.prisma.io**, which is not the host scanned (`mcp.prisma.io`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `semgrep` advertises registration on **login.semgrep.dev**, which is not the host scanned (`mcp.semgrep.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `stripe` advertises registration on **access.stripe.com**, which is not the host scanned (`mcp.stripe.com`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `vercel` advertises registration on **api.vercel.com**, which is not the host scanned (`mcp.vercel.com`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

> ⚠️ `web-agent` advertises registration on **clerk.tinyfish.ai**, which is not the host scanned (`agent.tinyfish.ai`). A live run would write to a different party; the scanner now refuses that unless it is a sibling domain.

_Unreachable during discovery: hostprofit-mcp-production-up-railway-app._
