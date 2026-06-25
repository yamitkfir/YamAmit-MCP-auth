# MCP Server Auth-Gap Mapper — Status

## Goal
Point a tool at a real MCP server and decide, **for each known auth gap** (a specific way a server's login/permission handling can fall short of the rules), which of these it is:
- `HAS_GAP` — the weakness is present
- `NO_GAP` — the server handles it correctly
- `NOT_APPLICABLE` — this check doesn't apply to this kind of server
- `INCONCLUSIVE` — we couldn't tell (e.g. our tool hit a limitation)

...always backed by the actual request we sent and the server's response (the evidence).
The purpose is **mapping real servers on the public internet** ("in the wild").

Important requirement for AI agents (Claude): Aim to use simple language, as we have no background on these network subjects. When mentioning a technical term, add a short, direct definition in parentheses next to it.

## Quick glossary (plain-language)
- **Authentication** — proving *who* you are (like showing ID). **Authorization** — what you're *allowed* to do once known (your permissions).
- **token** — a digital "ticket" proving you logged in and may do something (think: a wristband at an event).
- **endpoint** — a specific web address the server answers on (e.g. `https://x.com/mcp`).
- **transport** — *how* the AI and server talk (plain web requests, or a streaming connection). Main types: HTTP, SSE, stdio (below).
- **stdio** — a server that runs *locally* on your own machine (no internet address); can't be scanned remotely.
- **HTTP status codes** — the server's short numeric reply: `200` = OK/allowed, `401` = "log in first", `400` = "your request was malformed", `404` = "nothing here".
- **TLS / HTTPS** — encryption on the connection (the padlock in a browser). "Cleartext http" = no encryption.
- **`.well-known/...`** — a standard, predictable web address where a server publishes its "how to log in here" info.
- **session / session ID** — a temporary tag tying your back-and-forth messages together (a conversation ticket; *not* a password).
- **the spec** — the official MCP rules document we measure servers against.

## The 3 codebases (in `MCProject/`)
- **MCP-Scanner** (by Knostic) — finds MCP servers on the internet using **Shodan** (a search engine that scans the whole internet and lets you look up exposed servers; needs a paid API key). It also tries to inspect servers but **fails to talk to both standard MCP connection styles** (it speaks the protocol incorrectly).
  Update: we likely can't use it without paying Shodan a one-time fee. See the doc's end.
- **MSB** (a 2026 research benchmark) — tests whether *the AI itself* can be tricked by booby-trapped tool descriptions or responses (e.g. "prompt injection" = hiding secret commands in text the AI reads; "tool poisoning" = malicious instructions inside a tool's description).
  That's about the *AI's behavior*. We instead test the *server's plumbing* (does it require login? does it follow the OAuth rules?). So it's a different layer — not our focus.
- **YamAmit-MCP-auth** — **our tool.** It connects to an MCP server the same way a normal AI client would and checks whether the server correctly enforces login and permissions according to the official rules (the spec).

## Gap catalog (21 gaps, ordered by how hard they are to detect)
These are the 21 weaknesses our tool looks for. They come from the official MCP rules )the spec, 2025 versions), the OAuth rulebook, several internet-standard documents, and published security research. 
"Plan ref" links each gap to our project plan: "Playbook A–E" and "Angle 1–3" are sections of that plan (the angle table at the bottom explains them).

Difficulty tiers = how much effort the check needs:
- **Tier 1 (Easy)** — one simple request, no login needed.
- **Tier 2 (Medium)** — a few crafted requests or follow-up lookups.
- **Tier 3 (Hard)** — needs a real login/token, a multi-step login dance, or watching behavior over time.

### Tier 1 — Easy (one unauthenticated request) — ✅ DONE, 5 detectors built
| # | Gap (short name) | What the check means, plainly | Plan ref |
|---|---|---|---|
| 1 | `no-authentication-remote` | Ask the server to list its tools **without logging in**. If it answers (status `200` = OK) instead of demanding login, the server is wide open. | Playbook A |
| 2 | `no-tls-transport` | Server reachable over **unencrypted** `http://` (no padlock) on a public address — data can be eavesdropped. | — |
| 3 | `missing-www-authenticate` | When the server says "log in first" (`401`), it should also point to *where* to log in (a header called `WWW-Authenticate`). This checks that pointer is missing. | Playbook A |
| 4 | `missing-protected-resource-metadata` | The server should publish its "how to log in here" info at a standard address (`.well-known/oauth-protected-resource`). This checks it's absent or incomplete. | Playbook A, Angle 3 |
| 5 | `session-id-in-url` | The conversation tag (session ID) is exposed inside the web address instead of in a header — addresses leak into logs/history, so this is unsafe. | — |

### Tier 2 — Medium (crafted requests / follow-up lookups) — designed, not built yet
| # | Gap (short name) | What the check means, plainly | Plan ref |
|---|---|---|---|
| 6 | `predictable-session-id` | Open several conversations; if their session tags are sequential or easy to guess, an attacker could hijack someone else's. | — |
| 7 | `origin-not-validated` | Send a request pretending to come from a malicious website (a fake `Origin`). If the server still accepts it, a bad webpage could secretly drive it (a "DNS-rebinding" trick — fooling a server about who's calling). | — |
| 8 | `cors-misconfiguration` | Server lets *any* website make logged-in requests to it (overly permissive cross-site rules) — a bad page could act as you. | — |
| 9 | `auth-endpoints-not-https` | The server's published login addresses use unencrypted `http://` on a public host. | Playbook A |
| 10 | `missing-as-metadata` | A second standard "how to log in" document (`.well-known/oauth-authorization-server`) is missing. Companion to #4. | Playbook A, Angle 3 |
| 11 | `implicit-flow-enabled` | The login setup still allows an old, unsafe style that puts the token directly in the web address. The current rules (OAuth 2.1, which MCP requires) forbid this. | Playbook E |
| 12 | `open-dcr` | The server lets *anyone* register as a client automatically (via a `/register` address) with no checks — a large opening for abuse. | Playbook B, Angle 2 |

### Tier 3 — Hard (needs a real login, a multi-step login flow, or behavior watching) — designed, not built yet
| # | Gap (short name) | What the check means, plainly | Plan ref |
|---|---|---|---|
| 13 | `no-pkce` | The login flow doesn't require **PKCE** (a proof that the same app which started the login is the one finishing it — stops a thief from stealing the login code mid-way). | Playbook E |
| 14 | `missing-token-audience-validation` | Server accepts a ticket that was issued for *a different service*. It should only accept tickets minted specifically for itself. | Playbook C, Angle 1 |
| 15 | `token-passthrough` | Server takes your ticket and just hands it straight to a back-end system instead of using its own credentials — a banned shortcut that breaks the security boundary. | Playbook D, Angle 1 |
| 16 | `confused-deputy-proxy-consent` | A middleman server reuses one shared identity for everyone and skips per-user consent, so users can be impersonated. ("Confused deputy" = a trusted program tricked into misusing its powers.) | Angle 2 |
| 17 | `improper-redirect-uri-validation` | After login, the server isn't strict about *where* it sends you back, so an attacker can redirect the login code to themselves. | Playbook E |
| 18 | `session-used-for-auth` | Reusing just the conversation tag (no ticket) still gets you in — meaning the tag is wrongly treated as proof of login. | — |
| 19 | `self-asserted-capabilities` | The server can *claim* abilities it never proved, and can send the AI requests disguised as if a human typed them — letting a bad server hijack the AI's reasoning. | Plan §"Blindly Trusting the Server" |
| 20 | `credential-harvesting-tool-desc` | A tool's description text secretly points at private files (like SSH keys) or tells the AI to leak another server's ticket. | MSB-adjacent bridge |
| 21 | `missing-session-isolation` | Two different users' sessions aren't kept separate — one user can read or affect another's data on the same server. | Angle 2 |

### How our 3 project-plan "angles" map onto these gaps
The project plan proposed three possible research directions ("angles"). Here's which gaps each covers:
| Angle | What it focuses on | Gaps |
|---|---|---|
| **3 — Discovery/login-info** | Whether the server correctly advertises and enforces its login process. **No login needed**, so testable on public servers today. | 1–5, 9–12 |
| **1 — Token passthrough** | The boundary between the MCP server and the back-end systems behind it. Needs a real token and visibility into the back-end. | 14, 15 |
| **2 — Identity isolation / Confused deputy** | Keeping different users apart. Needs several logged-in sessions at once. | 12, 16, 19, 21 |

Full technical design: `MCProject/YamAmit-MCP-auth/OUTLINE.md` (to be synced with this list).

## Status
- **Tier 1 built & verified** — 5 detectors, **14 test cases** passing. (The count isn't 1-per-detector on purpose: each detector is tested against *several* fake servers we built — one deliberately vulnerable, one secure ("hardened"), one with broken login — to confirm it gives the right answer in each situation. That's 11 of the cases; the other 3 test the no-encryption check directly. "Sandbox servers" = small test servers we run locally, not real ones.)
- **Real-world scan: 36 public MCP servers tested, 34 reachable.** ("Endpoint" = a server's web address.)

  **(a) Headline view — sorted only by gap #1 (does the server require login at all?):**
  | Posture | Count | Examples |
  |---|---|---|
  | **Hardened** (demands login — replies `401`) | 24 | Linear, Notion, Sentry, GitHub, Stripe, Atlassian, Cloudflare (all), Asana, Grafana, Webflow, Wix, PayPal, Square, Intercom, Neon, Prisma, Vercel, Zapier, Globalping |
  | **Open** (no login — HAS_GAP) | 2 | DeepWiki, EdgeOne — but both are *meant* to be public, so not actually mistakes |
  | **Inconclusive** (couldn't tell) | 8 | blocked by our tool's own limitations, not server faults |
  | **Unreachable / ERROR** | 2 | dead web address (fetch-mcp, sequentialthinking; "NXDOMAIN" = the address doesn't exist) |

  **(b) Full view — all 5 Tier-1 gaps across the 36 servers** (HAS_GAP = weakness actually found):
  | Gap | HAS_GAP | NO_GAP | N/A | Inconclusive | Error | Notes |
  |---|---|---|---|---|---|---|
  | `no-authentication-remote` | 2 | 24 | 0 | 8 | 2 | The 2 = DeepWiki, EdgeOne (public on purpose) |
  | `no-tls-transport` | 0 | 36 | 0 | 0 | 0 | every server is encrypted (HTTPS) — all clean |
  | `missing-www-authenticate` | 0 | 19 | 10 | 5 | 2 | N/A = servers that never asked for login; the 19 correctly include the "where to log in" pointer |
  | `missing-protected-resource-metadata` | 1 | 24 | 0 | 9 | 2 | **Only DeepWiki** — it claims to follow the newest rules (2025-06-18) but its login-info page is missing (returns `404`) |
  | `session-id-in-url` | 0 | 2 | 0 | 32 | 2 | Only context7 & huggingface could be judged; the 32 "couldn't tell" are due to our tool's connection limitation (see below) |

  Reports: `MCProject/YamAmit-MCP-auth/reports/real_world_scan.md` + 36 raw result files
  (`reports/raw/`), re-runnable via `reports/endpoints.txt` + `run_scans.sh`.

## Key findings
1. The tool **works against real, live servers** and gives clear answers backed by evidence — our core idea is proven.
2. **No real mistakes found** in this sample — every server that meant to require login did so.
   The 2 "open" servers are public on purpose:
   - **DeepWiki** — its 3 (read-only) tools are usable without login. It's our clearest "**rules say one thing, server does another**" example: it claims to follow the newest rules (which *require* publishing a login-info page) yet that page is missing (`404`).
   - **EdgeOne** — lets anyone use a tool that *changes things* (`deploy-html`, which publishes a web page) without login — a bigger risk than read-only. It runs on an older rules version (2024-11-05), so our tool correctly says "can't judge" its missing login-info page instead of flagging it — proof our "which rules version applies" logic works.
3. **Most "official" MCP servers run locally (stdio)** — they have no internet address, so they can't be scanned remotely. The real mistakes are expected to be among the many lesser-known, exposed servers (the "long tail"), which needs an internet-wide search to find (see Shodan, below).
4. **Real weaknesses on *famous* servers are rare** — big-name servers are mostly secure.
   So the project's value is in (a) the rule-compliance slip-ups even secure servers have (missing info pages, version mismatches), and (b) the long tail of lesser-known servers once we can discover them.

## Our tool's current limitations (these guide the next work; ranked by how many servers they affected)
1. **Doesn't reuse the conversation tag (8 servers)** — our check asks for the tool list without the session ID the server expects, so the server replies "incomplete request" (`400`) and we can't decide. *Fix: save and reuse the session ID.* (Explained in plain terms in the next section.)
2. **Doesn't handle the older two-step connection style (32 of 34)** — this leaves gap #5 ("session in URL") as "couldn't tell" almost everywhere. *Fix: support that older connection style.*
3. **Servers that demand login up front** — secure servers refuse our very first message, so checks #3/#4 can't fully run even when something's missing. (A sequencing limitation, not a server fault.)
4. **Dead addresses** — 2 servers no longer exist (environmental, not a bug in our tool).

## How we handle the tool's blind spot (plain-language)

**What the blind spot is.** Many MCP servers are *stateful* (the server expects an ongoing back-and-forth conversation, not one isolated question). The proper conversation is:
1. Our tool says **"hello / let's start"** (a message called `initialize`).
2. The server replies and hands back a **session ID** (a temporary ticket number tagging "this is our ongoing conversation" — it is **not** a password, just a tag tying messages together).
3. Our tool says **"ready"** and includes that ticket on every later message.

Today our tool does step 1 but **throws the ticket away** and never says "ready." So when it later asks "list your tools," the server says *"you didn't bring your ticket"* and returns an error (an HTTP `400` = "bad/incomplete request"). The tool can't tell whether that means "you forgot the ticket" or "this server is genuinely broken," so it reports **INCONCLUSIVE** (can't decide). That's why 8 servers couldn't be judged on gap #1 and 32 on gap #5.

**The fix has two parts:**
- **Part 1 — keep the ticket (fixes most cases).** Teach the tool to save the session ID, send the "ready" message, and attach the ticket to every later message — exactly like a real MCP client. *Important catch:* the ticket is plumbing, **not** a credential (login proof). So the no-authentication check must still send **no login token** but **do** carry the ticket — otherwise a server letting us in would look "secured" when it isn't, and the tool would lie.
- **Part 2 — handle older "two-channel" servers (fixes gap #5).** Some older servers use a different style: you open a long-lived listening connection (**SSE** = Server-Sent Events, a one-way "the server keeps talking to you" channel) and the server tells you a *second* web address to send questions to. Our tool currently waits for that connection to *finish*, but it never finishes (it stays open) — so the tool **freezes until timeout** (the same bug the Knostic scanner has). Fix: read that channel a little at a time and grab the address as soon as it appears, instead of waiting for the end.

**One rule for honesty.** A `400` could still mean a truly broken server. So after the fix, if a server errors, the tool should **retry once with the full proper handshake**, and only report INCONCLUSIVE if it *still* fails — recording exactly what happened as evidence. This avoids trading one wrong answer for another.

**Order & effort.** Part 1 is small (~1–2 hrs) and recovers most unjudged servers — do it first, and before scanning the 1,000+ registry servers (or most come back INCONCLUSIVE too). Part 2 is ~half a day and only matters for gap #5. Each fix gets its own sandbox test server so we can prove it works (gap-found vs. not-found), like the other detectors.
















-----------------
<!--

(copmletely deferring this part for now)

## Next for the MCP Scanner (in priority order)
1. **Fix the prober's transport handling** (session-id replay + SSE handshake) — highest
   leverage: converts ~8 INCONCLUSIVE verdicts to real ones and unblocks `session-id-in-url`
   across the board. Must come before bulk-scanning, or the 1,086 mostly return INCONCLUSIVE.
2. **Build a `discovery.py`** with pluggable free sources (MCP Registry primary; CT-log +
   GitHub for the long tail) emitting URLs into `mcpauth scan`. Drops the Shodan dependency.
3. **Run the bulk posture scan** across the 1,000+ registry endpoints → first real wild-scale
   report.
4. **Build Tier 2 detectors** (session entropy, Origin/DNS-rebinding, CORS, non-HTTPS auth eps).

## Discovery: Shodan NOT needed — free path found (verified live)
- **Shodan free tier is useless for this**: `search`/`search_cursor` return 403, 0 query credits → the Knostic scanner yields 0 servers, always. (Paid ~$49 / `.edu` upgrade would unlock it, but we don't need to.)
- **Winner — the official MCP Registry** (`registry.modelcontextprotocol.io/v0/servers`):
  free, no API key, paginated. One pull returned **1,086 real remote endpoint URLs** (with transport type) — 30× our curated list — ready to feed straight into `mcpauth scan`.
- **Complements** (also free) for servers the registry doesn't declare: CT-log mining (certspotter / Censys CT) for `mcp.<vendor>` subdomains, and GitHub code search for endpoint URLs in `mcp.json` configs. Netlas.io is the only free *scan* engine returning host lists if we want one.
- **Coupling note:** the Knostic scanner's Shodan dependency is shallow (one `search()` call → `ip:port` list; everything downstream is source-agnostic). Swapping in the Registry API is a few hours' work — and the Registry returns full URLs, so the prober  needs *no* change.
- **Honest limit:** registries/CT/GitHub find *declared/discoverable* servers; they don't see fully anonymous, unannounced exposed hosts — that slice still needs paid Shodan/Censys or authorized self-scanning. Minority of the population; not a blocker for the bulk of the work.

---

-->