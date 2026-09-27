# Slide-build guide — MCP authorization scanner

**Purpose.** A self-contained plan for building the presentation slides. For each slide it gives:
the **title**, the **on-slide content** (what the audience sees), **Say** (speaker notes — the
narration, and enough background that you can defend it), a **Visual** suggestion, and **If asked**
(anticipated follow-ups with answers). Build the deck straight from this file.

**Audience.** The course director. Has a networking background but **not** the MCP / OAuth
specifics — so define MCP, OAuth roles, tokens, sessions, PRM/AS-metadata, but move quickly
through general networking (HTTP status codes, TLS, DNS). Target **~30 minutes, ~30 slides**.

**Rule for yourself:** you must be able to answer a follow-up on *anything* on a slide. The
**Say** and **If asked** notes are written for that. For per-check depth beyond this file, use
the appendix in [`PRESENTATION-GUIDE.md`](PRESENTATION-GUIDE.md) (the deep reference — the
fourteen checks, one at a time). This file is the source of truth for the *story and the numbers*;
that file is the source of truth for *each check's exact mechanism*.

**All numbers here come from the canonical run:** one scan per server on **2026-09-27**, **83
servers**, **all 14 checks**, one consistent pass, **no ERROR verdicts**. Raw output:
`reports/raw-rescan-2026-09-27/`.

---

## How to build it — the overall arc

Tell one story in five movements, then defend it:

1. **Setup (slides 1–4):** what MCP is, why it has an auth problem, and the one question we answer.
2. **Method (5–10):** how the scanner works — one honest idea (measure from outside, never log in) and the machinery that makes it trustworthy.
3. **Results (11–18):** the 14 checks and what 83 real servers actually did — with the two findings that matter most.
4. **Trust & honesty (19–24):** how we know the checks are right, what it cost us ethically, and the hard limit of the whole approach.
5. **Close (25–30):** takeaways, what's next, and a Q&A back-pocket.

**Design tips.**
- One idea per slide. On-slide text is *headlines and evidence*, never paragraphs — the detail lives in your mouth (the **Say** notes).
- Show **evidence** (a real request/response) at least twice — it is the project's whole ethos and it pre-empts "how do you know?".
- Put the honest limits *on the slides*, not buried — with this examiner, volunteering a limit is worth more than hiding it.
- Keep a **numbers cheat-sheet** (end of this file) open while presenting.

---

## SECTION 1 — Setup

### Slide 1 — Title
- **On slide:** Project title ("Mapping the gap between what MCP servers *say* about login and what they *do*"), your names, course, date. One-line subtitle: *"A scanner that checks how well MCP servers protect their tools — without ever logging in."*
- **Say:** One sentence of what's coming: "I'll show what MCP is, the security question we chose, the tool we built, what it found across 83 real servers, and — importantly — the limits of what it can prove."
- **Visual:** clean title; maybe the 60-second headline as a teaser ("28 of 83 servers hand their tool list to a stranger").

### Slide 2 — What an MCP server is (and that the protocol ships with no security)
- **On slide:**
  - MCP (Model Context Protocol) = the standard that lets an AI assistant use outside **tools** ("search the docs", "run this query") over the internet. Published by Anthropic.
  - A tool call is just an HTTP request carrying a JSON-RPC message.
  - **The protocol itself ships with no security** — adding a login layer is the server author's job.
- **Say:** The professor knows HTTP but not MCP. Frame it: "Think of an MCP server as a small web API that exposes a *menu of actions* to an AI. The protocol standardises the menu and the messages, but deliberately leaves authentication to the implementer — which is exactly where things go wrong." Name a couple of real ones they'd recognise: Stripe, Notion, GitHub all run MCP servers.
- **Visual:** AI assistant ⇄ MCP server ⇄ (tools). Label the arrow "HTTP + JSON-RPC".
- **If asked — "what's JSON-RPC?"** A simple convention for calling a named method with parameters over HTTP and getting a result or an error back; MCP uses methods like `initialize`, `tools/list`, `tools/call`.

### Slide 3 — Authentication, authorization, and OAuth (the vocabulary)
- **On slide:**
  - **Authentication** = proving *who you are* (showing your ticket).
  - **Authorization** = deciding *what you may do* once known.
  - **OAuth 2.1** = the login system MCP adopted. You log in at a separate **authorization server**, which hands the app a **token** (a digital ticket; whoever holds it gets in).
  - Four actors: **User**, **Client** (the app, e.g. Claude Desktop), **MCP server** (holds the tools), **Authorization server** (runs the login, issues tokens).
- **Say:** "MCP didn't invent a login scheme — it adopted OAuth 2.1 and wrote rules for how servers must use it. That adoption, and how servers get it wrong, is our subject." Stress the split: the MCP server and the login server are often **different companies**, which matters later. A **token** is bearer — a stolen one is as good as the original.
- **Visual:** the four actors as boxes with labelled arrows (User→Client, Client→MCP server, Client→Auth server, Auth server issues token).
- **If asked — "why OAuth and not passwords?"** So the app never sees your password; the auth server does the login and hands back a scoped, revocable token.

### Slide 4 — The research question
- **On slide:**
  - Project goal: **map the gap between what the MCP spec requires and what real servers do.**
  - Supervisor's steer: *"focus on ONE angle — you can't cover everything."*
  - The angle we chose: **Does a server correctly *advertise and enforce* its login, as seen by a caller holding no credentials?**
  - Why this one: it needs **no login**, so it's testable **today** against any public server.
- **Say:** We considered three angles; this is the one that is both meaningful and actually runnable without accounts on 83 different services. Set expectations honestly here: "This measures advertisement and enforcement — *not* whether the login is sound. I'll return to that limit at the end; it's the single most important caveat."
- **Visual:** three candidate angles, the chosen one highlighted.
- **If asked — "what were the other two angles?"** Token-passthrough (a server forwarding your token to a third service) and identity confusion (one user mistaken for another) — both need a real logged-in session and evidence on a back-end we can't see. See slide 23.

---

## SECTION 2 — Method

### Slide 5 — What the scanner does, in one slide
- **On slide:**
  - Point it at one server address → it runs **14 independent checks**, one per known weakness ("gap").
  - **12 are read-only; 2 make a change** (register a client) and are **off unless you ask**.
  - Every check returns a verdict **plus the exact request we sent and the reply we got** (the evidence) — anyone can re-check.
  - `uv run mcpauth scan https://host/mcp`
- **Say:** The unit of output is a **compliance judgement with evidence**, not "an open port". Each check cites a specific clause of a specific standard. The evidence trail is deliberate: a claim like "this server answered a privileged call with no credential" is only trustworthy if we also show what we asked.
- **Visual:** a screenshot/mock of one finding: gap id, verdict, severity, request line, response, the rule it cites.
- **If asked — "what are the 14?"** Slide 11 lists them; the appendix in PRESENTATION-GUIDE.md has each in detail.

### Slide 6 — The three steps of login, and where we stop
- **On slide:**
  1. Ask the server with **no token** → a protected server replies `401` ("log in first") and points at its login-info page.
  2. **Get a token:** read the login-info page, read the auth server's page, send the user to log in, receive a token.
  3. Ask again **with the token** → the conversation opens.
  - **We do step 1, plus the *reading* half of step 2 — and nothing else.**
- **Say:** This is the honest core. We never send anyone to log in, never obtain a token, never reach step 3. Both description pages in step 2 are **public** and need no token — that's what makes half our checks possible. So every verdict describes **what a server does for a caller holding nothing.** Against a wide-open server, step 1 just succeeds — which is what check #1 reports.
- **Visual:** 3-step ladder with steps 1 + "read half of 2" highlighted, step 3 greyed out.
- **If asked — "isn't that a big limitation?"** Yes, and it's deliberate — slide 23 covers exactly what it can and cannot prove.

### Slide 7 — One scan, start to finish (the flow)
- **On slide (diagram):**
  1. **Validate** the target (must be http/https/stdio; a typo must not silently become 14 "not applicable"s).
  2. **Handshake** once (`initialize`): keep the session id, the negotiated protocol version, and any `401` challenge.
  3. **OAuth discovery** once: fetch the login-info page (PRM) → the auth server's page (AS metadata). Shared by checks #4, #9–#12, #14.
  4. **Run all checks concurrently.** Each reads only the shared context; none reads another's answer, so order can't change the result. A crash becomes an `ERROR` verdict, not a crashed scan.
  5. **Release** the session, **build the report** (findings + discovery trail + what ran/was skipped).
- **Say:** Define the two MCP-specific terms plainly:
  - **`initialize` / session id:** the opening handshake of MCP; the server may hand back a *session id*, a temporary label meaning "same conversation as before" — **not** a password. We replay it because a wide-open server that merely wants a session id would otherwise answer "400" to everything and look secured.
  - **PRM / AS metadata:** two public pages. **PRM** (Protected Resource Metadata) is where the MCP server says "here's where to log in for me". **AS metadata** is where that login server describes itself. Two pages because the MCP server and login server are often different companies.
  - A full read-only scan is **~19 requests**; ~24 with both write checks.
- **Visual:** the 5-box vertical flow (adapt the ASCII flow from PRESENTATION-GUIDE.md §4 into clean boxes).
- **If asked — "why fetch the pages only once?"** So all checks reason about the *same* copy — otherwise two checks could fetch the same page moments apart, get different answers, and the report would contradict itself.

### Slide 8 — Five possible answers (and why "I don't know" is a feature)
- **On slide:**
  - `HAS_GAP` — the weakness is really there.
  - `NO_GAP` — handled correctly.
  - `NOT_APPLICABLE` — the check can't apply here.
  - `INCONCLUSIVE` — we tried; the reply didn't let us decide. **A real answer, not a failure.**
  - `ERROR` — the check itself couldn't run.
- **Say:** A scanner that only ever says "vulnerable" or "fine" is lying about half its results. Two of our checks got *better* by saying "I don't know" more often — e.g. #1 used to treat a firewall's `403` as proof of a login and hand a clean bill of health to a blocked scan; that's the worst possible direction for a mistake. Now a bare `403` is `INCONCLUSIVE`.
- **Visual:** the five verdicts as a legend; highlight INCONCLUSIVE.
- **If asked — "doesn't that inflate 'unknown'?"** Yes, honestly — e.g. `session-id-in-url` is INCONCLUSIVE on 73 of 83 because we don't implement a deprecated transport. We report that plainly rather than guess.

### Slide 9 — The mechanisms that make it trustworthy (part 1: safety)
- **On slide:**
  - **We control where our own requests go (containment).** Almost every address after the first is chosen by the server we're scanning. Following blindly makes us a **confused deputy** — a trusted tool tricked into misusing its access.
  - Every such address is checked twice: as written, and again at the IP it **actually resolved to** (to catch a name that points at `127.0.0.1`, your office network, or a cloud metadata service — the DNS-rebinding trick).
  - The one **write** may only reach the scan target or a sibling under the same domain.
- **Say:** This is the most important safety slide, and it wasn't a precaution — it was a **fix**. An early run created a real OAuth client on `api.llow.io` while scanning `api.serff.ai` — a different company that was never on our list. The server's metadata named that address and the scanner obeyed. That incident is why containment exists, and it later fired for real (refused one write to `login.semgrep.dev`). See slide 22.
- **Visual:** confused-deputy cartoon: scanned server says "go register over there →" pointing at a third party; the guard blocks it.
- **If asked — "what's the residual hole?"** "Same domain" is judged by the last two labels only, so on shared hosting (`*.railway.app`) unrelated tenants look like siblings. A proper fix needs a public-suffix list. It's in the known-limitations list.

### Slide 10 — The mechanisms that make it trustworthy (part 2: honest reading)
- **On slide:**
  - **We never follow redirects.** The rule we test (RFC 9728) is about *which host* published a document; following a redirect would let a server credit someone else's document to itself.
  - **Certificates are actually checked** — a bad certificate is a *finding*, not shrugged off.
  - **Replies are read in a loop, with a cap.** One server sent 91,703 characters listing its tools; a single read kept 8,183 and the check gave up — so six servers were hidden until we fixed it. And an SSE stream never ends, so we keep what arrived instead of waiting forever.
  - **The control request (check #7).** A `403` alone proves nothing — the server may refuse *everything*. Only a server that accepts a no-Origin control **and** rejects a forged Origin is really validating it.
- **Say:** Pick 2 of these to actually narrate depending on time; the control-request idea and "length isn't entropy" (#6) are the most impressive. Each mechanism has a regression test named after the bug that motivated it.
- **Visual:** side-by-side "naïve read vs looped read" or the control-request truth table.
- **If asked — "length isn't entropy?"** (#6) A 15-char random token is strong; a 16-digit counter is weak. We estimate keyspace = length × alphabet size, not raw length.

---

## SECTION 3 — Results

### Slide 11 — The 14 checks at a glance
- **On slide (compact table, gap · what it asks · severity):**
  - Tier 1 (one request): #1 no-auth-remote (med), #2 no-TLS (high), #3 missing-WWW-Authenticate (med), #4 missing-PRM (med), #5 session-id-in-URL (med), **#13 unauthenticated-tool-invocation (high)**.
  - Tier 2 (crafted / follow-up): #6 predictable-session-id (med), #7 origin-not-validated (high), #8 CORS (med), #9 auth-endpoints-not-https (high), #10 missing-AS-metadata (med), #11 implicit-flow (high), #12 open-dcr (high, **write**), **#14 improper-redirect-uri-validation (high, write)**.
- **Say:** Don't read all 14 aloud. Say the grouping: five easy Tier-1 checks, seven Tier-2, plus the two we added (#13, #14) numbered after the original twelve. Two of the fourteen (#12, #14) write, and are off by default. #8 CORS is the only one not drawn from the MCP rules (general web security).
- **Visual:** the table, colour-coded by tier; mark the two write checks.
- **If asked — any single check:** go to the appendix in PRESENTATION-GUIDE.md; each has what-we-send / how-we-decide / why-it-matters / the-honest-limit.

### Slide 12 — Two or three checks worth explaining (pick your favourites)
- **On slide:** short cards for 2–3 checks. Recommended: **#4 path-inserted lookup**, **#7 the control request**, **#1↔#13 list-vs-call**.
- **Say:** These show engineering judgement. E.g. **#4:** RFC 9728 puts the login-info page at a path that *inserts* a well-known segment before the server's own path (`/.well-known/oauth-protected-resource/mcp`), not at the bare domain — we originally probed the bare domain and would have falsely accused nearly every real server. We now try the path-inserted form first and prefer the address the `401` itself named.
- **Visual:** one worked example (the #4 URL transformation).
- **If asked:** appendix.

### Slide 13 — The run
- **On slide:**
  - **83 public servers**, one consistent scan each, **2026-09-27**, **all 14 checks**, one pass, **0 errors**.
  - Servers from the official MCP Registry (free, no key). We paginated ~1,200 records and took 83.
  - Raw machine-readable output for every server is committed.
- **Say:** Emphasise *one consistent run* — every number on the next slide comes from the same scan on the same day, so they're directly comparable. We removed five endpoints that had gone dead since earlier runs, which is why there are no ERROR verdicts.
- **Visual:** "83 servers · 14 checks · 1 run · 0 errors · evidence committed".
- **If asked — "why only 83?"** It's a slice of the registry, not the whole internet — we say so on slide 18. The registry itself is far larger (a manual pull passed 75,000 entries without ending).

### Slide 14 — Results table (all 14 checks)
- **On slide:** the full table (HAS_GAP / NO_GAP / N/A / INCONCLUSIVE), 83 per row. Use the table from README §"Real-world results" / PRESENTATION-GUIDE §7. Bold the two headline rows (#1 = 28, open-dcr = 38).
- **Say:** Walk only the highlights; don't read every cell. Flag the honesty note out loud: the two metadata rows (#4 = 21, #10 = 12) are each **at least one too high** — `hf.co` answers `307` (a redirect) which we grade as "absent", but its redirect target is a compliant document. True values ≤20 and ≤11.
- **Visual:** the table; a callout box on the hf.co caveat.
- **If asked — "why not just follow the redirect?"** Because the rule is about which host *published* the document; following the redirect would let a server pass off another host's document as its own. The right fix is to grade a redirect as its own INCONCLUSIVE category — noted as future work.

### Slide 15 — Headline finding: capability disclosure
- **On slide:**
  - **28 of 83 servers answer `tools/list` with no login — 438 tools, reachable by a stranger.**
  - No rule broken (authenticating is only a SHOULD) — but nothing stops a stranger asking what a server can do.
  - Biggest: `dock` (71 tools), `switch` (69), `gondola` (44), `nullary` (35).
  - Concentrated among lesser-known entries; every recognisable vendor demanded a login (Stripe, Notion, Sentry, Linear, GitHub, PayPal, Square, Wix, Zapier, Atlassian, Neon, Grafana, Prisma, Vercel, Webflow).
- **Say:** Be precise: this proves the *catalogue* is readable without login — capability disclosure. It does **not** by itself prove you can *run* those tools. That distinction is the next slide and it's the strongest methodological point in the talk.
- **Visual:** 28/83 bar; logos of protected vendors vs a few open lesser-known ones.
- **If asked — "is disclosure actually harmful?"** It's the reconnaissance step — it tells an attacker exactly what a server can do. Whether it's *usable* is what #13 tests next.

### Slide 16 — The sharpener: listing ≠ running (check #13) ★ key slide
- **On slide:**
  - #1 tests *listing*; **#13 tests *invocation*** — an unauthenticated `tools/call` to a **nonexistent** tool (so nothing executes), reading only whether it hits a `401` or reaches the dispatch layer.
  - **6 of those 28 servers gate execution** — `dock`, `switch`, `gondola`, `api-openmandate`, `catalog-api`, `financial-data` list their tools to a stranger but answer `401` to `tools/call`.
  - So only **22** are open to *invocation* as well as listing.
- **Say:** This is the result to be proud of. #1's older wording ("anyone can use this server") was an **over-read on ~21% of the servers it flagged**. #13 replaces an inference with a measurement — and it's safe, because the tool name doesn't exist, so no real action runs. Show the evidence: `dock` → `tools/list` returns 71 tools (HTTP 200), `tools/call` → HTTP 401 `{"error":{"message":"Unauthorized"}}`.
- **Visual:** the 28 → split into 22 (list+call open) vs 6 (list-only); the dock request/response pair.
- **If asked — "why is 200 not proof for #14 but a reply is proof here?"** Different endpoints. For `tools/call`, *any* JSON-RPC reply means the request passed the transport auth gate. For #14's browser `/authorize` endpoint, a 200 is just a login page (slide 17-detail / appendix).
- **If asked — "could a real tool have side effects?"** We never call a real tool; the fake name is rejected before anything runs. That's the safety design.

### Slide 17 — Open self-registration (check #12)
- **On slide:**
  - **38 of 83 let anyone register an OAuth client with no approval** (open Dynamic Client Registration, RFC 7591).
  - Not a rule violation — RFC 7591 permits it — but it's **the foothold a bigger attack needs** (the surviving piece of the identity-confusion angle, visible without a token).
  - **This check writes** (it really registers), so it's off by default.
- **Say:** Define DCR plainly: normally a developer registers their app once by hand to get a client id; DCR automates that — the app sends a form and instantly gets a client id, no human. "Open" means *anyone* can. We report it as *posture*, not a breach. It's the stepping stone: register a legit-looking client, then phish a user into consenting.
- **Visual:** 38/83; a mock registration request → `client_id` returned.
- **If asked — "why does registering matter if you get no data?"** Alone it grabs nothing; it's step one of a confused-deputy / consent-phishing flow.

### Slide 18 — The write check that found nothing — and what it cost (check #14) ★ honesty slide
- **On slide:**
  - #14 tests whether a login server accepts a **redirect address the client never registered** (which would let an attacker steal the login code).
  - Of the 47 servers it could test: **23 correctly rejected it, 24 inconclusive, 0 accepted one.** No findings.
  - Half inconclusive because real auth servers show a **login page** before validating — the same "needs a completed login" wall.
  - **Cost:** running the two write checks left **76 client registrations we could not delete** (38 from #12 + 38 from #14).
- **Say:** This is a deliberately honest slide. #14 is correct (a sandbox demo catches a vulnerable server), but in the wild it's **low-yield and expensive** — zero findings for 76 registrations left on other people's servers. That's a concrete lesson in the cost of *write-class active probing* versus its yield. It also mirrors the Tier-3 boundary (slide 23) and the #12 incident (slide 22).
- **Visual:** 0 / 23 / 24 split; a "76 registrations left behind" cost tag.
- **If asked — "why does 200 not count as accepting the bad address?"** The `/authorize` endpoint is a browser page; a 200 is its own login/consent HTML at its own origin — the auth code is never in a 200 body. The dangerous event is a **redirect (3xx) to the attacker's address**. A 200 means we can't tell without logging in → inconclusive. (Front-desk analogy: 200 = "here's a sign-in form"; 3xx-to-attacker = "sent your guest+pass to the attacker, no check".)
- **If asked — "was leaving 76 registrations OK?"** They're inert (no password, no data, nobody logged in), most servers expire them, and we had the guiding professor's permission; every id is journalled before cleanup. Still, we present it as a real cost, not a footnote.

### Slide 19 — What limits these numbers (say it before you're asked)
- **On slide:**
  - **55 of 83 never told us their spec version** (a protected server refuses before agreeing one) — so the three version-gated checks answer "don't know" for most.
  - **`session-id-in-url` is inconclusive on 73 of 83** — we didn't implement a deprecated two-connection transport it needs.
  - **83 servers is a thin slice** — rates within one slice of the registry, **not** internet-wide rates.
  - **Breaking a MUST ≠ an exploitable hole.**
- **Say:** Volunteering these is the point. With this examiner, naming your own limits is worth more than a bigger headline number.
- **Visual:** four bullets, plain.
- **If asked — "so how many are truly wide open?"** The defensible claim: 28 disclose their catalogue; 22 also let a stranger invoke a tool. Beyond that we can't speak to soundness (slide 23).

---

## SECTION 4 — Trust & honesty

### Slide 20 — How we know the checks are right
- **On slide:**
  - **Seven purpose-built practice servers**, one per posture (wide-open, hardened, broken-auth, open-OAuth, hardened-OAuth, wide-open-but-session-based, correct-on-a-subpath).
  - A check counts as working only when it says **`HAS_GAP` against the broken server and `NO_GAP` against the correct one**.
  - **213 automated tests** (`uv run pytest -q`): **38 live** (boot a server and scan it), **111 unit** (individual judgement calls), **64 regression/behaviour** (55 pin ~33 real bugs we found & fixed; 9 pin the two new checks).
- **Say:** A suite of only broken servers can't catch a check that cries "gap!" at everything — hence the correct-reference servers. The regression tests are the engineering-quality story: each of the ~33 bugs is pinned by a test checked to *fail* against the old code, so it can't come back.
- **Visual:** the 7 practice servers as a grid; "213 tests, all green".
- **If asked — "which checks lack a live test?"** #2 (TLS) — every practice server is on loopback, which is exempt, so its logic is unit-tested instead; and #14 is verified against a local demo server + unit tests rather than a committed sandbox pair. We're upfront about both.

### Slide 21 — Evidence, end to end
- **On slide:** one real finding in full — request line (with "NO Authorization header"), response status, body — with secrets redacted (field name kept, value replaced).
- **Say:** Every one of the 83 servers' raw output is committed, so any claim in this talk is re-checkable. Credentials in replies are replaced with a placeholder before anything is written to disk — the field *name* stays, because "a secret was issued" is itself evidence.
- **Visual:** the annotated finding.
- **If asked — "how do you avoid leaking secrets in the committed data?"** A redaction pass replaces `client_secret`, tokens, etc. with `[REDACTED]` before writing.

### Slide 22 — Research ethics: the confused-deputy incident
- **On slide:**
  - Early run: the scanner **registered a client on `api.llow.io` while scanning `api.serff.ai`** — a different company, never on our list. Its metadata named that address; the scanner obeyed.
  - Fix: **containment** (a write may only reach the target or a sibling), destination checks at connect time, write-checks off by default, every id journalled before cleanup.
  - The guard later **fired for real**: refused a write to `login.semgrep.dev` — the only refusal across 83.
- **Say:** The framing that works: "This is the confused-deputy problem from our own literature review, realised by our own tool, against ourselves. We found it, contained it, and the containment is now demonstrably doing work." That's a stronger story than "we were careful from the start", because it's true and shows the failure mode is real.
- **Visual:** timeline: incident → fix → guard fires.
- **If asked — "what did you do about the 76 registrations?"** Leave them in place (inert, expiring), keep a committed record, don't contact anyone — a documented decision.

### Slide 23 — Scope: what we deliberately do NOT check ★ most important caveat
- **On slide:**
  - > This tool measures whether a server **advertises and enforces** login correctly. It does **not** measure whether that login is **sound**. A server can pass all 14 checks and still accept tokens meant for someone else, skip PKCE, or leak one user's data to another.
  - Out of scope: anything needing a real token / completed login (audience validation, token passthrough, session isolation…); prompt injection / tool poisoning (that's the AI's behaviour, a different project).
  - **PKCE** is the cleanest example we can't check — it needs a completed login.
- **Say:** This is the single most important sentence in the talk — say it slowly. Introduce the **two-hop** idea if asked: the MCP server is usually a middleman in front of a *true* backend; the dangerous auth mistakes live on that server→backend hop, which is invisible from outside even with a token. That's why those gaps are out of reach, not laziness.
- **Visual:** the two-hop diagram: Client → MCP server → true backend, with hop-2 shaded "invisible from outside".
- **If asked — "what is PKCE?"** A proof that the app finishing a login is the one that started it, so a stolen half-finished login is useless. Required by OAuth 2.1; we can't observe it without completing a login.

### Slide 24 — The rules have moved ahead of the tool
- **On slide:**
  - A newer MCP revision, **`2026-07-28`**, was published during our work; we speak `2025-06-18`.
  - **Sessions were removed entirely** — so #5 and #6 describe a generation the rules have dropped.
  - New per-request headers are now required; a strict server could reject every request we send.
  - **Publishing the login-info page is now unconditional** — which makes check #4 *stronger* (the only one the newest rules tightened).
  - Self-service registration is now **deprecated** — so #12's framing is dated.
- **Say:** Shows the field is live and we tracked it. Frame it as future work, not failure.
- **Visual:** a small timeline of MCP revisions with what changed.
- **If asked — "why not just support the new revision?"** It's the top of the future-work list (slide 25); the new mandatory `server/discover` request would also be a better opening move than our current handshake.

---

## SECTION 5 — Close

### Slide 25 — Limitations & future work
- **On slide:**
  - No `429` (rate-limit) handling yet — a throttled scan could mis-read a refusal.
  - Redirect-served metadata graded as "absent" (the hf.co false positive) — grade it INCONCLUSIVE instead.
  - Support the `2026-07-28` revision; build automatic server discovery to scale past 83.
  - Containment's "same domain" needs a public-suffix list.
- **Say:** Keep it crisp and owned. These are known and tracked, not surprises.
- **Visual:** a short roadmap list.

### Slide 26 — Takeaways
- **On slide:**
  - MCP ships with no security; enforcement is left to implementers, and many get it wrong in *observable* ways.
  - A no-login scanner can measure **advertisement and enforcement** across real servers, with evidence — but **not soundness**.
  - On 83 servers: **28 disclose their tools, 22 also let a stranger invoke one; 38 allow open registration; 0 redirect-URI findings.**
  - The honest result — "I don't know", 0-finding checks, the write cost — is part of the contribution.
- **Say:** End on the methodological point: the value is a *reproducible, evidence-first, honestly-scoped* instrument, not a sensational number.
- **Visual:** the three headline numbers + the one-line caveat.

### Slides 27–30 — Q&A back-pocket (hidden/backup slides)
Keep these ready to jump to. Content = the **Q&A bank** below, one topic per backup slide (e.g., "Isn't this just a port scanner?", "Did you attack anyone?", "Why so many INCONCLUSIVE?", "What's the biggest limitation?").

---

## Q&A bank (rehearse these)

| Question | Short answer |
|---|---|
| Isn't this just a port scanner? | No — every check cites a specific clause of a standard and returns the evidence for its verdict. The output is a compliance judgement, not an open port. |
| Did you attack anyone? | 12 of 14 checks create nothing durable (though #7 leaves one MCP session on session-based servers). The two write checks register a client and are off by default; see the ethics slide for what happened when we ran them and what we changed. |
| Why not read the servers' source code? | They're other people's production servers. The point is measuring observable behaviour from outside — the same position a real attacker is in. |
| How do you know your scanner is right and the server is wrong? | Seven practice servers (one per posture); a check counts as working only when it says HAS_GAP against the broken one and NO_GAP against the correct one. Plus 64 regression/behaviour tests, the bug ones checked to fail against the old code. |
| Why so many INCONCLUSIVE? | Because they're true — a refusal we can't attribute, or a reply we can't parse, is not evidence either way. Two checks got *better* by saying "unknown" more often. |
| 83 servers isn't many. | Agreed, and we say so. These are rates within one slice of the registry, not internet-wide rates. Scaling is a matter of running the same tool on a longer list (future work). |
| What's the single biggest limitation? | We never log in, so we measure advertisement and enforcement, not soundness. A server can pass all 14 checks and still mishandle tokens. |
| Which check is weakest, and why keep it? | CORS (#8) — not an MCP rule, only bites if a browser is involved. We keep it, clearly labelled as general web security, because it costs one request. #6 (predictable-session-id) is a close second: 0 findings and the feature was removed from the protocol. |
| #14 found nothing — why present it? | Because the honest result and its cost (76 registrations for 0 findings) is the clearest demonstration of what write-class probing costs vs. yields. |
| What did #13 add over #1? | It replaced an inference with a measurement and corrected #1 on 6 servers — proof that listing tools ≠ being able to run them. |
| What would you do next? | Support the 2026-07-28 revision (incl. the new required headers and `server/discover`); automatic registry-based discovery; `429` handling; a public-suffix list for containment. |

---

## Numbers cheat-sheet (canonical run, 2026-09-27, 83 servers, all 14 checks, 0 errors)

- **#1 no-authentication-remote:** 28 HAS_GAP · 42 NO_GAP · 13 INC. (438 tools; dock 71, switch 69, gondola 44, nullary 35.) Severity **medium** (disclosure).
- **#2 no-tls-transport:** 0 · 82 · 1 INC.
- **#3 missing-www-authenticate:** 0 · 32 · 41 N/A · 10 INC.
- **#4 missing-protected-resource-metadata:** 21 · 41 · 21 INC. (≤20 after the hf.co redirect false positive.)
- **#5 session-id-in-url:** 0 · 10 · 73 INC.
- **#6 predictable-session-id:** 0 · 10 · 18 N/A · 55 INC.
- **#7 origin-not-validated:** 24 · 10 · 49 INC.
- **#8 cors-misconfiguration:** 2 · 67 · 14 INC.
- **#9 auth-endpoints-not-https:** 0 · 52 · 31 N/A.
- **#10 missing-as-metadata:** 12 · 53 · 18 INC. (≤11 after the hf.co false positive.)
- **#11 implicit-flow-enabled:** 0 · 52 · 30 N/A · 1 INC.
- **#12 open-dcr:** 38 HAS_GAP · 35 N/A · 10 INC. (write; 38 registrations left.)
- **#13 unauthenticated-tool-invocation:** 22 HAS_GAP · 48 NO_GAP · 13 INC. (6 servers diverge from #1.)
- **#14 improper-redirect-uri-validation:** 0 HAS_GAP · 23 NO_GAP · 24 INC · 36 N/A. (write; 38 registrations left; 47 applicable.)
- **Version gate:** 28 negotiated a spec version (21 × 2025-06-18, 3 × 2025-03-26, 4 × 2024-11-05); 55 never did.
- **Write cost:** 76 registrations created, 0 auto-deletable.
- **Tests:** 213 pass (38 live · 111 unit · 64 regression/behaviour).
- **Requests per scan:** ~19 read-only; ~24 with both write checks.
- **Divergent servers (#1 HAS_GAP, #13 NO_GAP):** dock, switch, gondola, api-openmandate, catalog-api, financial-data.

---

*Deep per-check reference (what-we-send / how-we-decide / why-it-matters / honest-limit for all 14):*
[`PRESENTATION-GUIDE.md`](PRESENTATION-GUIDE.md) — Appendix. *Raw evidence:* `reports/raw-rescan-2026-09-27/`.
