# Presenting this project

## 1. The sixty-second version

> An **MCP server** (Model Context Protocol server — a program that offers *tools*, like "search the documents" or "run this query", to an AI assistant over the internet) is supposed to make a caller **log in** before it will hand over its tools. 
> The protocol's own rules say how: which refusal to send, where to publish the login instructions, which login styles are allowed.
>
> we built a scanner that asks one server 14 separate questions about its login setup — without ever logging in — and answers each one with the evidence attached. We ran it against 83 public servers.
>
> **28 of the 83 answer `tools/list` with no login.** They expose 438 tool descriptions to a stranger. Check #13 also found that 22 accept an unauthenticated `tools/call` far enough to return JSON-RPC; because the probe names a nonexistent tool, that does not prove a real tool can run.

---

## 2. The background your audience does not have

- **Authentication** = proving *who you are* (showing your ticket).
- **Authorization** = deciding *what you're allowed to do* once you're known.
- **MCP** is the current standard for connecting AI assistants to outside tools and data. Anthropic published it. **The protocol itself ships with no security** — it is the server author's job to add a login layer on top.
- **OAuth** is the login system that MCP chose. Instead of giving your password to the tool, you log in at a separate **authorization server**, which hands the tool a **token** (a digital ticket — whoever holds it gets in, so a stolen one is as good as the original).
- Anthropic did not invent a new login scheme; they adopted an existing one (OAuth 2.1) and wrote rules for how MCP servers must use it. **That adoption is where things go wrong**

### Terms this guide uses before it explains them

| Term | Meaning |
|---|---|
| **status code** | the short number a server replies with. The ones used here: `200` = fine, here you go · `400` = your request was malformed · `401` = **log in first** · `403` = refused, no reason given · `404` = nothing here · `429` = you're going too fast, slow down · `500` = the server broke. "`2xx`" means any number in the 200s = it worked |
| **RFC** | a numbered internet standard document. |
| **PRM** | Protected Resource Metadata — the page where the MCP server publishes "here is where you go to log in for me". Our check #4 (RFC 9728) |
| **AS metadata** | Authorization Server Metadata — the matching page where the *login* server describes itself: its addresses, which login styles it supports. Found by following the PRM. Our check #10 (RFC 8414) |
| **session ID / session tag** | a temporary label that links several MCP messages to the same conversation. It is not proof of identity and not a login credential. |
| **login token / access token** | the digital credential sent in `Authorization: Bearer ...` after login. It proves the caller was authorized; our scanner never obtains one. |
| **certificate** | the server identity document used by HTTPS. The browser/client checks who issued it, its dates, and whether it belongs to the hostname being contacted. |
| **Origin** | the website/address that started a browser request. A server can use it to decide whether the calling page is trusted. |
| **CORS** | browser rules, expressed through response headers, that decide which other websites may call a server and whether they may include credentials. |
| **SSE** | Server-Sent Events — an older MCP connection style that stays open. Our scanner keeps the reply once the connection goes quiet instead of waiting for the connection to close. |

---

## 3. The research question, and why this one

The overarching goal in our project plan was: **map the gap between what the protocol says and what implementations actually do.** Our supervisor's feedback was explicit — *"we should focus on ONE angle we want to check in MCP, you can't cover everything."* We wrote down three candidates:

...

3. Protected Resource Metadata scanner;
   Does the server correctly **advertise and enforce** its login, as seen by a caller holding nothing?
   Needs no token, so it is testable today against any public server.

**The question we actually answer:** does an MCP server correctly advertise and enforce its login process, as observed by someone with no credentials?

---

## 4. How the scanner works — the flow

Getting into a protected MCP server takes 3 steps:

1. Ask the server something **with no token**. A protected server answers `401` ("log in first") and points at its login-information page.
2. **Go and get a token**: read the login-information page, read the login server's own description page, send the user to manually log in, receive the token from AS.
3. Ask again, **carrying the token**. Only now does the conversation actually open.

**We do step 1, plus the reading half of step 2, and nothing else.** Both description pages are public and need no token — that is what makes checks #4, #9–#12 and #14 possible at all. We never send anyone to log in, never obtain a token, never reach step 3.

So every verdict in this project describes **what a server does for a caller holding nothing.** On a wide-open server, check #1 simply receives `tools/list` without login and reports catalog disclosure. That is noteworthy, but not automatically a protocol violation: authentication is a `SHOULD`, not a `MUST`.

### One scan, start to finish

```
  mcpauth scan https://host/mcp
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 1. VALIDATE the target                                      │
  │    Is it a URL? http / https / stdio only. A typo must not  │
  │    silently become fourteen confident "not applicable"s.    │
  └─────────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 2. HANDSHAKE — done once, shared by all checks               │
  │    POST initialize — say hello without a login token         │
  │      → save the protocol version the server chose            │
  │      → save any session tag needed for later requests        │
  │      → save any log-in-first challenge                       │
  │    POST notifications/initialized — say setup is complete    │
  │      → only if the server opened a session                    │
  └─────────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 3. OAUTH DISCOVERY — shared by checks #4 and #9–#12/#14     │
  │    GET PRM — the MCP server’s public login-information page  │
  │      → read the AS (login server) address                    │
  │    Derive the AS metadata address from it, then GET that page│
  │      → read the login, token, and registration endpoints     │
  │    Safety-check every address; never log in or request token │
  └─────────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 4. RUN THE CHECKS CONCURRENTLY                               │
  │    12 by default; 14 with --unsafe-writes.                   │
  │    Each reads only the shared context. None reads another's  │
  │    answer. So order cannot change the result.                │
  │    A check that crashes becomes an ERROR verdict, not a      │
  │    crashed scan.                                             │
  └─────────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ 5. RELEASE the session (DELETE), then BUILD THE REPORT       │
  │    (check #7's own session is left behind — see §5)          │
  │    12–14 findings + the discovery trail                      │
  │    + a record of what was run and what was skipped           │
  │    Exit code: 0 clean · 1 gap found · 2 scan failed · 3 typo │
  └─────────────────────────────────────────────────────────────┘
```

A full read-only scan is **19 requests** for a typical server (about 24 with both write checks enabled).

note: **we do nothing about being told to slow down.** All the checks fire at once, and if a server starts throttling us, those refusals land in branches that read them as "the header wasn't there" and produce a confident `NO_GAP` or `NOT_APPLICABLE`. It needs a request budget per server, and it does not have one.

### The 5 possible answers

| Answer | Plain meaning |
|---|---|
| `HAS_GAP` | The condition tested by this check was observed. Whether that is a protocol violation depends on the protocol-status column. |
| `NO_GAP` | The reply matched what this check currently treats as correct; known limitations still apply. |
| `NOT_APPLICABLE` | The check cannot apply to this server. |
| `INCONCLUSIVE` | We tried, the reply didn't let us decide. This is a real answer, not a failure. |
| `ERROR` | The check itself could not run. |

note: **`INCONCLUSIVE` is a feature.** A scanner that only ever says "vulnerable" or "fine" is lying about half its results. Several of our checks were *improved* by making them say "I don't know" more often — one went from **76** confident "not applicable" verdicts to **58** honest "unknown"s, because it used to announce "this server has no sessions" whenever it saw no session tag, including when the server had refused to start one *because we weren't logged in*. Those are two completely different facts.

A **session ID** (or **session tag**) is a temporary label that tells the server which MCP messages belong to the same conversation. It is not a password, identity proof, or login token.

---

## 5. The mechanisms behind every check

### We never send a login token — but we do replay the session tag

Every measurement probe goes out with **no login token** and no `Authorization` header, including the registration requests made by #12 and #14. That is the point of the project.

The only `Authorization` header is used during best-effort cleanup for #12 and #14: the scanner returns a `registration_access_token` that the server just issued, on a `DELETE`. That registration-management credential is not a user login token.

A **session tag** (`Mcp-Session-Id`) is carried when the server issued one. Anyone can obtain it through `initialize`; it only links messages to one conversation, so replaying it does not weaken the no-login test.

### Every answer carries its evidence

Each finding records **the request we sent as well as the reply we got** — the URL, the method, which headers we chose, whether an `Authorization` header was present (it never is), and the response body. A verdict saying "the server answered a privileged call with no credential" is only auditable if the report also shows what was asked. All 83 servers' raw output is committed to the repository.

Credentials in a reply (`client_secret`, `registration_access_token`, and similar) are **replaced with a placeholder before anything is written to disk** — the field *name* stays visible, because the fact that a secret was issued is itself evidence.

### We never follow redirects

A reply saying "go look over there instead" is not followed. This is deliberate and it is a subtle point worth making: the entire rule we are testing (RFC 9728) is about **which host published a document**. If we followed a redirect, a server could hand us another host's document and have us credit it to itself.

### We control where our own requests go

Almost every address fetched after the very first one **was chosen by the server being scanned** — it tells us where its login server is, where to register, where its pages live. Following that blindly turns the scanner into someone else's weapon. The classic name for this is a **confused deputy**: a trusted program tricked into misusing its access.

So every such address is checked before it is fetched: addresses in private networks are refused, anything that isn't `http`/`https` is refused, and **either write check** may only go to the server we are scanning or a sibling address under the same domain name. A refused address is always reported, never quietly skipped.

**The check runs in two places, and the second is the interesting half.** Reading the address as written only catches the obvious form (`http://10.0.0.5/`). A *name* like `intranet.example.com` looks like any ordinary public address until you actually look it up. So we check twice: once on the address as written, before fetching, and again on the address the name **really resolved to**, at the moment of connecting. That second check is the only thing that can catch a name the scanned server chose which points at your own machine, your office network, or the cloud service that hands out machine credentials. It has to happen at connect time rather than a moment earlier, because a name can be re-pointed in between. And if one name gives back several addresses, a single bad one refuses the lot — so the order they arrive in cannot decide it.

**The honest limit here, worth volunteering.** "A sibling under the same domain name" is judged by the **last two labels only**. On shared hosting — `*.railway.app`, `*.vercel.app` — every unrelated customer counts as a sibling, so either write check is allowed to reach them. Our own address list contains a `railway.app` server, so this is not hypothetical. A proper fix needs the published register of which name endings are shared, and we have not wired that in.

**This is the most important slide in the safety part of your talk**, because it was not a precaution — it was a fix. An early run created a real OAuth client on `api.llow.io` while the address being scanned was `api.serff.ai`, a completely different company that was never on our list. The server's own metadata named that address, and the scanner obeyed. See §8.

### Certificates are actually checked

A **certificate** is the identity document a server presents during HTTPS; the client checks its issuer, validity dates, and hostname. Verification is **on**. A failed certificate becomes a finding, not something we shrug off. This was also a fix: verification used to be disabled wholesale, which quietly broke our encryption grading — an expired or wrong-hostname certificate still scored no gap.

### Reading a reply is harder than it looks

Two mechanisms here, both of which changed our published numbers:

- **A reply must be read in a loop.** The function that reads from a connection returns *up to* the amount you ask for — whatever has arrived so far — not the amount you asked for. We called it once and assumed we had everything. One server sent 91,703 characters listing its tools; we kept 8,183, which no longer parsed as a document, so the check gave up and said "don't know" about a server that had just listed 70 tools to a stranger. **Six servers were hidden this way.**
- **An SSE stream never ends.** SSE (Server-Sent Events — an older style where the server holds the line open and keeps talking) has no end-of-reply to wait for. Waiting for one burns the whole timeout and then throws away the bytes that already contained the answer. So those reads are capped, and we keep what arrived.

### One shared lookup, not fourteen

Finding the login takes two hops: the MCP server's page names the login server, and the login server's own page describes itself. They are two pages rather than one because **the MCP server and the login server are often run by different companies**, and the MCP server cannot speak for someone else's login service.

Both are downloaded **once**, at the start, and every check reads that same copy. Without this, two checks could fetch the same page moments apart, get different results — the internet is unreliable — and one report would contradict itself about what the page said.

Note the limit of the sharing: it covers the *login-metadata lookup*, not every request. Checks #1 and #3 each send their own copy of the same unauthenticated `tools/list`, because detectors are forbidden from reading each other's responses.

### Three gating rules

- **Transport gating.** A **stdio** server (one running as a program on your own computer, talking through pipes, with no internet address at all) has nothing on the network to inspect. Login checks return `NOT_APPLICABLE`. Without this, every stdio entry in a registry list would be reported as "no authentication!" — a false alarm.
- **Version gating.** Three checks (#3, #4, #10) describe requirements that became mandatory only from protocol revision **2025-06-18**. Below that bar, the **absence** of a required document is reported as "don't know" rather than as a violation. A document that *is* published but is malformed is still graded a violation whatever revision the server claims — it got its own RFC wrong, and that judgement does not depend on the revision. We compare **"this revision or later"**, never "exactly this revision" — otherwise the servers that stay current would be the ones let off the hook.
- **Loopback exemption.** Unencrypted `http` is fine on `localhost` / `127.0.0.1`, because nothing leaves the machine.

### Nothing durable changes by default — with one leak to own

Twelve of the fourteen checks create nothing you would have to go and delete. The other two — #12 `open-dcr` and #14 `improper-redirect-uri-validation` — really create something that persists (each registers a client), and both are **off unless you explicitly pass `--unsafe-writes`**.

But do not say "read-only", because it is not quite true. Every `initialize` opens a short-lived MCP session, and the scan hands its own back with an HTTP `DELETE`. **Check #7 opens one more and never releases it** — so scanning a session-based server leaves exactly one session parked on it. In our own 2026-09-18 run, all 10 session-issuing servers took one. Check #6 does release the four it opens, but without the protocol-version header, so a server that insists on that header can refuse all four. A leftover session holds nothing but throwaway greeting data and expires on its own — but it is a bug, not a decision, and it is better volunteered than discovered.

### When a write check creates something, we record it before trying to undo it

The moment #12 or #14 creates a registration, its identifier is appended to a file on disk and forced out immediately — `mcpauth-writes.jsonl` from the command line, and a `write_journal.jsonl` beside the run’s raw output from the bulk runner (e.g. `reports/raw-rescan-2026-09-27/write_journal.jsonl`) — **before any attempt to delete it**.

That ordering is the whole point. The report is only produced once every server has been probed, and a run across 83 servers takes many minutes, so an interruption anywhere in between — Ctrl-C, a closed laptop, a timeout — used to discard every identifier gathered so far. Since **none** of the 76 cleanup attempts succeeded, those registrations remain on other people’s servers. The record has to survive whatever killed the run, so each line is pushed to disk immediately rather than held in memory.

---

## 6. How we know the checks work

**`uv run pytest -q` → 213 tests pass.**

The core idea: **no single server can exercise every possible answer.** A server with no login can never demonstrate what a *badly worded* "log in first" reply looks like. So we wrote one practice server per posture and run them locally:

| Practice server | What it pretends to be |
|---|---|
| `vulnerable_server.py` | No login at all; claims to follow the strict rules while breaking them |
| `hardened_server.py` | Scores `NO_GAP` on four of the five Tier-1 checks — the reference for what `NO_GAP` looks like. (#2, encryption, comes back `NOT_APPLICABLE` because it runs on loopback.) **Not actually a model server:** its own login-info page names an address with no port, so that address is unreachable and does not match the server itself |
| `broken_auth_server.py` | *Does* demand a token, but words its refusal wrongly — our proof that #3, #4 and #10 can spot a real failure |
| `vulnerable_oauth_server.py` | Guessable sessions, ignores `Origin`, permissive CORS, cleartext login addresses, implicit flow, open registration — yet publishes *valid* login-server info, which is how we prove #10 can also say `NO_GAP` |
| `hardened_oauth_server.py` | Passes the established Tier-2 sandbox checks (not #14) — the `NO_GAP` reference for those. **Also not a model server: its main endpoint answers both the greeting and list-tools with no login check at all**, so check #1 would rightly flag its unauthenticated catalog. That stays hidden only because it is never run against Tier 1 |
| `stateful_open_server.py` | **Wide open, yet session-based** (see below) |
| `subpath_prm_server.py` | **Correct on all the discovery checks, but hosted on a sub-path** (see below) |

**A check is considered finished only when it says `HAS_GAP` against a deliberately-broken server and `NO_GAP` against a deliberately-correct one** — a suite of only broken servers cannot catch a check that cries gap at everything. Twelve of the fourteen meet this against the practice servers; the exceptions are #2 `no-tls` (loopback makes a live pair impractical, so its logic is unit-tested) and #14 `improper-redirect-uri-validation` (covered by mocked behaviour tests for both `HAS_GAP` and `NO_GAP`, but no committed live sandbox pair).

**The exception is #2 (`no-tls-transport`)**, and you should volunteer it: every practice server runs on `http://127.0.0.1`, which the loopback exemption makes `NOT_APPLICABLE`, so building that pair would need a real certificate. Its decision logic is unit-tested instead.

**The two servers worth naming in the talk**, because each one exists to catch a specific class of bug we actually had:

- **`stateful_open_server.py`** — a server that wants a session tag and nothing else. This is a real shape: the transport rules require session handling but do not require authentication, so a developer can implement the transport carefully and still omit authorization. **10 of our 28 wide-open servers issue a session tag and require it on later requests; the other 18 are stateless.** This practice server exists because the scanner used to omit the tag, receive `400`, and say do not know about a completely open server.
- **`subpath_prm_server.py`** — correct on the discovery checks, but its address has a path after the domain (`/public/mcp`). The rule then puts its login-information page at `/.well-known/oauth-protected-resource/public/mcp`. A scanner that checks only the bare domain misses it and falsely accuses a correct server — **which would have hit nearly every real server, since almost all sit at `/mcp`.** Careful on stage: it is not correct on *every* check (it does not validate `Origin`), so don't call it a model server if someone might ask you to run it.

**The suite has three layers**, which is a good structure to show:

- **38 tests against the practice servers** (`test_tier1.py` 17, `test_tier2.py` 21) — 35 of them boot a real server and scan it, checking the verdict for each gap on each posture where that posture can produce a meaningful answer. The tables are deliberately sparse: a stateless server cannot demonstrate a session gap. The remaining 3 test the encryption classifier directly, since every practice server is loopback-exempt.
- **111 unit tests** of the individual judgement calls with no network involved: is this session tag guessable, is this address unencrypted, which addresses should we try, is this address safe to fetch, does a name that resolves into a private network get refused, was this reply really a login refusal, how do we read an SSE stream, does the version gate compare dates correctly.
- **64 regression / behaviour tests** — 55 covering the roughly **33** bugs we have actually found and fixed (each pinning the wrong answer so it cannot come back; not one test per bug — five cover the handshake bug alone, six the address guard), plus 9 pinning the two new checks (#13, #14) across their verdict branches. Each bug-regression test has been checked to **fail** against the code as it stood before its fix — one that passes either way pins nothing.

That third layer is the one to point at if asked about engineering quality. Most of the mechanisms in §5 have a test named after the bug that motivated them.

---

## 7. What we found

**83 public servers, one consistent scan each on 2026-09-27, all 14 checks (including the two write checks).** The raw machine-readable output for every server is committed in `reports/raw-rescan-2026-09-27/`, with the write journal alongside. Every number below was recalculated from that raw output. There are **no `ERROR` verdicts** — the five endpoints that had gone dead in earlier runs were removed from the list.

| Gap | HAS_GAP | NO_GAP | N/A | INCONCLUSIVE | ERROR | Protocol violation if `HAS_GAP`? |
|---|--:|--:|--:|--:|--:|---|
| `no-authentication-remote` | **28** | 42 | 0 | 13 | 0 | No — authentication is a `SHOULD` |
| `no-tls-transport` | 0 | 82 | 0 | 1 | 0 | Conditional — if OAuth is used |
| `missing-www-authenticate` | 0 | 32 | 41 | 10 | 0 | Yes — `2025-06-18` `MUST` |
| `missing-protected-resource-metadata` | 21 | 41 | 0 | 21 | 0 | Conditional — if OAuth is used |
| `session-id-in-url` | 0 | 10 | 0 | 73 | 0 | Not proven — a session ID is not an access token |
| `predictable-session-id` | 0 | 10 | 18 | 55 | 0 | Yes — MCP `MUST` |
| `origin-not-validated` | 24 | 10 | 0 | 49 | 0 | Yes — MCP `MUST` |
| `cors-misconfiguration` | 2 | 67 | 0 | 14 | 0 | No — outside MCP |
| `auth-endpoints-not-https` | 0 | 52 | 31 | 0 | 0 | Yes — OAuth endpoints `MUST` use HTTPS |
| `missing-as-metadata` | 12 | 53 | 0 | 18 | 0 | Conditional — if OAuth is used |
| `implicit-flow-enabled` | 0 | 52 | 30 | 1 | 0 | Not proven — legacy support may coexist |
| `open-dcr` | **38** | 0 | 35 | 10 | 0 | No — explicitly permitted |
| `unauthenticated-tool-invocation` | **22** | 48 | 0 | 13 | 0 | No — authentication is a `SHOULD`; real execution is not proven |
| `improper-redirect-uri-validation` | 0 | 23 | 36 | 24 | 0 | Yes — OAuth 2.1 `MUST` (none found) |

Here, **Yes** means the observation directly demonstrates a broken `MUST` or `MUST NOT`. **Conditional** means the requirement applies only when the optional OAuth authorization mechanism is being used. **Not proven** means the check found a security concern, but its evidence alone does not establish a protocol violation.

**One correction to carry with this table.** The two metadata rows are each at least one too high. We stopped following redirects — correct, because the whole rule is about *which* host published a document — but a redirect on a metadata address is still graded "the document is absent". `hf.co/mcp` answers `307` on the addresses we try, and what it redirects to is a **fully compliant** document; our own earlier scans graded it `NO_GAP` with that real document as the evidence. So `missing-protected-resource-metadata` (21) and `missing-as-metadata` (12) each contain at least this one false accusation (`huggingface`). Volunteer it — it is the kind of thing an examiner finds by clicking one link.

### The two findings to actually talk about

1. **28 of 83 answer `tools/list` with no login — 438 tools in total.** No rule is broken, since authenticating is only a SHOULD; what is notable is that nothing stops a stranger asking what a server can do. The biggest are `dock` (71 tools), `switch` (69), `gondola` (44), `nullary` (35). **They are concentrated among the lesser-known entries** — most recognisable vendors demanded a login: Stripe, Notion, Sentry, Linear, GitHub, PayPal, Square, Wix, Zapier, Atlassian, Neon, Grafana, Prisma, Vercel, Webflow.

   **Check #13 sharpens this.** Six of those 28 servers stop unauthenticated `tools/call` at the HTTP layer with `401`. The remaining 22 return a JSON-RPC reply without login, proving that the request reached MCP dispatch. Because the probe names a nonexistent tool, it does **not** prove that a real tool would execute. This still demonstrates why #1 catalog access and #13 dispatch access must be reported separately.

   **Own the exceptions, because they are checkable and they make the point sharper.** Cloudflare gated most of its servers but left `docs.mcp.cloudflare.com` open. HuggingFace’s `hf.co/mcp` is open — and it also carries the metadata false positive noted under the table, so name both facts. DeepWiki and EdgeOne are open on purpose. EdgeOne’s catalog advertises `deploy-html`, a state-changing tool; our safe #13 probe did not execute it and therefore does not prove that it is callable without login.
2. **24 of 83 accept a forged `Origin`** — a genuine MUST violation.
   An **Origin** tells a server which website started a browser request. Our scanner claimed to be a malicious website, but these MCP servers processed its request instead of rejecting it.
   This matters mainly for local MCP servers, which a malicious webpage could otherwise try to control through the user’s browser. For remote HTTPS servers the danger is much weaker, and all 24 were already among the 28 that need no login.

**And the two write checks, stated honestly.** `open-dcr` found 38 open registration endpoints. `improper-redirect-uri-validation` (#14) found **0 accepted bad redirects**, while the current implementation classified 23 replies as `NO_GAP` and 24 as inconclusive. Seven of those 23 clean verdicts came from generic rejection or login behaviour that does not prove exact redirect validation, so #14 needs reclassification before presenting 23 as confirmed-correct. Running both write checks left **76 client registrations** behind that we could not delete.

### What limits these numbers — say this yourself, before you're asked

- **55 of the 83 never told us which revision they follow** (21 said `2025-06-18`, 3 said `2025-03-26`, 4 said `2024-11-05` — that is all 28 that negotiated one) — because a properly protected server says "log in first" before it gets around to agreeing a version. So the strict standard only ever applied to 21 servers; for the rest, the version-gated checks answer "don't know".
- **83 servers is a thin sample.** These are rates within one small slice, **not** rates across the internet.
- **Breaking a MUST is not automatically an exploitable hole.**

### How we found the servers

Shodan's free tier refuses the searches we would need (it answers `403` once you have zero query credits), so it found **0 servers** — recorded in the repository. The **official MCP Registry** is free, needs no key, is read page by page, and gives an address plus connection type for each remote entry, ready to feed straight into the scanner. We paginated 12 pages of it — roughly 1,200 server records — and stopped there; that is the committed provenance of our 83. A separate pull by hand reached **750 pages, about 75,000 entries**, without reaching the end, so the registry's true size is unknown and at least that. **That pull is not committed**, so present it as an observation, not as evidence in the repo. Free ways to find servers that *don't* advertise themselves: mining certificate transparency logs (a public record of every certificate issued) for `mcp.<company>` names, and searching GitHub for committed `mcp.json` files. **The honest limit: directories only find servers that chose to be listed.**

---

## 8. Research ethics — have this answer ready

Do not let this come up as a surprise question. Volunteer it when you present check #12.

**The canonical 2026-09-27 run enabled both write checks and created 76 confirmed OAuth client registrations on servers we do not own — 38 from `open-dcr` and 38 from `improper-redirect-uri-validation` — and we could not delete a single one.** Not one server returned the RFC 7592 fields needed to remove a registration, so the checks' self-cleaning — the thing that made them feel safe to run — works only against our own practice server. They are inert (no password, no data access, nobody has logged in through them), and most servers expire an unused registration on their own, but until then they are our litter on other people's systems. Every identifier is journalled to `reports/raw-rescan-2026-09-27/write_journal.jsonl` **before** any delete is attempted, so even the ones we could not clean up are named.

**The precise point, in case an examiner opens the journal.** Earlier exploratory runs left more registrations on overlapping hosts — including the run where the scanner **wrote to `api.llow.io` while scanning `api.serff.ai`**, a different company that was never on our list. The server's own metadata named that address and the scanner obeyed it.

**That incident is why the containment rules in §5 exist**, and in the later run those rules correctly refused one write for exactly the same reason (`mcp.semgrep.ai` advertising registration on `login.semgrep.dev`) — the only refusal across all 83, and the one live demonstration that the guard is load-bearing.

**The framing that works:** this is the confused-deputy problem from our own literature review, realised by our own tool, against ourselves. We found it, we contained it, and the containment is now demonstrably doing work. That is a stronger story than "we were careful from the start" — because it is true, and because it shows the failure mode is real rather than theoretical.

If asked what we did about it, the answers are all small and all concrete:

- both write checks are off unless explicitly enabled, and either write may only reach the scan target or a sibling address;
- anything that cannot be cleaned up is printed under a loud `MANUAL CLEANUP NEEDED` heading rather than hidden;
- **every identifier is written to disk the instant it is created, before we try to delete it** (see §5), so an interruption can no longer lose the only record of a permanent registration;
- a request that reached the server but whose reply never came back now declares `MANUAL CLEANUP NEEDED`. It used to report success — printing "Every client created was deleted again" over a registration that was still sitting there;
- Ctrl-C genuinely stops a live run. Handled slightly differently, it would have swallowed the first Ctrl-C and carried on registering on every remaining server;
- each live run used to overwrite the machine-readable record of the one before it. That is exactly why the first run's four identifiers survive only in `dcr_scan.prev-1.md`. Reports are now preserved, never replaced.

---

## 9. Scope — what we deliberately do not check

Being crisp about the boundary is worth more than claiming coverage.

**Out of scope, with reasons:**

- **Anything needing a real token or a completed login.** Eight further gaps were designed and never built: `no-pkce`, `missing-token-audience-validation`, `token-passthrough`, `confused-deputy-proxy-consent`, `session-used-for-auth`, `self-asserted-capabilities`, `credential-harvesting-tool-desc`, `missing-session-isolation`. *(A ninth, `improper-redirect-uri-validation`, was later built as check #14 — see the appendix; its live run found it low-yield and expensive.)*
- **Prompt injection, tool poisoning, malicious tool *content*.** That is the AI's *behaviour*; we test the server's *plumbing*. Different layer. It is the subject of the `MSB/` benchmark sitting in the parent folder — a different project entirely, no shared code.
- **CORS is in scope only as general web security**, never as an MCP rule.

**The consequence, stated honestly — this is the single most important sentence in the talk:**

> This tool measures whether a server **advertises and enforces** login correctly. It does **not** measure whether that login is **sound**. A server can score `NO_GAP` on all fourteen of our checks and still accept tokens meant for someone else, skip PKCE, or leak one user's data to another.

**PKCE** is the cleanest example. It is a proof that the app finishing a login is the same app that started it, so a stolen half-finished login is useless. **We do not check it** — it needs a completed login. Naming it, unprompted, as something a clean report from us cannot rule out is the best possible demonstration that you understand your own instrument.

### The rules have moved ahead of the tool

Worth one slide, because it shows the field is live and that we tracked it:

- A new revision, **`2026-07-28`**, was published during our work. We speak `2025-06-18`.
- **Sessions were removed from the protocol entirely** in it — so checks #5 and #6 describe a generation of the protocol the rules have since dropped.
- **New per-request headers** (`Mcp-Method`, `Mcp-Name`) are now required. A server that strictly follows the current rules is **entitled to reject every request we send.**
- **Publishing the login-information page is now unconditional** — making check #4 *stronger*, the only one the newest rules tightened rather than loosened.
- **Self-service registration is now deprecated**, so check #12's framing is behind the times.

---

## 10. Questions to expect

| Question | Your answer, short |
|---|---|
| *Isn't this just a port scanner?* | No. Every check cites a specific clause of a specific standard and returns the evidence for its verdict. The unit of output is a compliance judgement, not an open port. |
| *Did you attack anyone?* | Twelve of the fourteen checks create nothing durable, though check #7 does leave one MCP session parked on a session-based server. The other two (#12, #14) each create a registration and are off by default. See §8 for what happened when we ran them, and what we changed. |
| *Why not just read the servers' source code?* | They are other people's production servers. The whole point is measuring observable behaviour from outside, which is also the position a real attacker is in. |
| *How do you know your scanner is right and the server is wrong?* | Seven purpose-built practice servers, one per posture, and a check only counts as working when it says `HAS_GAP` against the broken one **and** `NO_GAP` against the correct one. Plus 64 regression/behaviour tests — 55 covering the ~33 bugs we actually shipped and fixed (each checked to fail against the old code), and 9 pinning the two new checks. |
| *Why so many `INCONCLUSIVE`s?* | Because they are true. A refusal we cannot attribute, or a reply we cannot parse, is not evidence either way. Two of our checks got *better* by saying "unknown" more often. |
| *83 servers isn't many.* | Agreed, and we say so. These are rates within one slice of the official registry, not internet-wide rates. Scaling up is a matter of running the same tool on a longer list. |
| *What's the single biggest limitation?* | We never log in, so we measure advertisement and enforcement, not soundness. A server can pass all fourteen checks and still mishandle tokens. |
| *Which check is weakest, and why keep it?* | CORS (#8) — not an MCP rule at all, and only relevant if a browser is involved. We keep it, clearly labelled as general web security, because it costs one request. `predictable-session-id` (#6) is a close second: 0 findings in 83 servers, and the feature it tests was removed from the protocol. |
| *What would you do next?* | Pull candidate servers automatically from the official registry so a bulk run feeds itself; support the current `2026-07-28` revision, including the two new required headers. |

---

## 11. Structuring the talk

1. **What an MCP server is, and that the protocol ships with no security.** (1 min, 1 slide)
2. **Authentication vs authorization, and what OAuth does.** (1 min, 1 slide)
3. **The question: does the advertisement match the enforcement?** Mention the three candidate angles and why we chose this one. (1.5 min)
4. **The flow diagram** from §4, and the three-steps-and-we-stop-at-one framing. (2 min)
5. **Two or three mechanisms**, not fourteen checks. Pick from: `INCONCLUSIVE` as a real answer, the control request in #7, the path-inserted lookup in #4, length-is-not-entropy in #6, list-vs-call in #13. (2.5 min)
6. **The results table and the two findings that matter.** (2 min)
7. **Validation: seven practice servers, one per posture.** (1 min)
8. **The two write checks, and what they cost us** — 76 registrations we could not delete (38 from `open-dcr`, 38 from `improper-redirect-uri-validation`), and the containment that came out of it. §8 says to volunteer this rather than wait for the question, so it needs a slot. (1 min)
9. **Scope and the honest limit** — advertises-and-enforces, not sound. Name PKCE. (1 min)

---

## Appendix — the fourteen checks, one at a time

**This is reference material, not slide material.** It lives at the back on purpose: §11 tells you not to walk the audience through fourteen checks, so read §1–§11 to build the talk and come here only to answer a question about a specific check.

Each entry follows the same shape: **what we send · what we look at · how we decide · why it matters · the honest limit.** Tier 1 means one request and we can tell; Tier 2 means a crafted request, a follow-up lookup, or several samples.

---

### Tier 1 — one request, no login, and we can tell

#### #1 `no-authentication-remote` — severity **medium**

*Rule: MCP Transports §Security — servers SHOULD authenticate every connection, and a protected one MUST answer `401`.*

**What we send.** One `POST` of `tools/list` — "list your tools", a privileged operation — with **no `Authorization` header**, carrying the session tag if the server issued one.

**What we look at.** The status code and whether the body contains a genuine JSON-RPC `result`.

**How we decide.**

| Observation | Verdict |
|---|---|
| `200` with a parsed result | `HAS_GAP`, and we report the tool count |
| `200`, reply too long to parse, but the visible start already shows `"result":` | `HAS_GAP` — the call succeeded, we just couldn't read all of it |
| A real authentication refusal (see below) | `NO_GAP` |
| A bare `403` with nothing backing it up | `INCONCLUSIVE` |
| `200` whose body is a JSON-RPC *error* | `INCONCLUSIVE` — answered, but did not comply |
| Anything else | `INCONCLUSIVE`, with a hint about what the status usually means |

**What counts as a real refusal.** This is the sharpest judgement call in the project. A `401` is unambiguous. **A `403` is not** — it is also what a firewall, a country block, a bot filter, or an IP denylist returns. The tool used to credit any `403` as proof that the server enforces login, which turned *a blocked scan* into a clean bill of health on our most important check — the worst possible direction for a mistake. A `403` now counts only with corroboration: a `WWW-Authenticate` header, or a genuine OAuth error code in the body.

If asked what that fix changed in practice, the precise answer is **one verdict**: a server whose bare `403` body said `missing api key` had been credited as enforcing login, and is now `INCONCLUSIVE`. (`NO_GAP` on this check fell 46 → 42 between two *earlier* scans — not the run behind §7's table — but the other three moves had unrelated causes: a `308` redirect we no longer follow, a legacy SSE endpoint answering `404`, and one server that simply opened up.)

**The part of that fix still too generous, and you should say it before you are asked.** *Any* `WWW-Authenticate` header counts, including `Negotiate`, `NTLM` or `Basic realm="corp"` — those are Windows sign-on middleware sitting in front of the server. A request stopped there never reached the MCP server at all, so it tells us nothing about its login. And we read that header *before* the body, which defeats the body rule that exists to reject exactly this. No published number is affected — none of the 83 answered `403` with such a header, we checked — but the hole is real, and it is on our most important check.

**Why it matters.** This is the headline. A server here is not breaking a MUST — authenticating is only a SHOULD — but nothing stops a stranger asking what it can do.

**The honest limit.** "Protected" means only that the server demanded a login on the first unauthenticated request. It says nothing about whether that login is *sound*.

---

#### #2 `no-tls-transport` — severity **high**

*Rule: OAuth 2.1 §1.5 — traffic carrying a login MUST use `https` (loopback exempt).*

**What we send.** A plain `GET` to the endpoint.

**What we look at.** Two different things depending on the scheme.

**How we decide.**

- **Loopback** → `NOT_APPLICABLE`. Nothing leaves the machine.
- **`https`** → we actually connect. *"The URL says https"* is not the same as *"TLS works"*. If the handshake fails with a **certificate** problem (the ID card the server presents to prove it is who it claims) → `HAS_GAP`: an expired, self-signed or wrong-hostname certificate gives users no more protection than no encryption at all. If the host is simply unreachable → `INCONCLUSIVE`, because we could not inspect the certificate. Otherwise → `NO_GAP`.
- **`http` on a public host** → if it redirects to `https` (`301`/`302`/`307`/`308` with an `https` `Location`) → `NO_GAP`. Otherwise → `HAS_GAP`.

**Why it matters.** Without encryption, the token travels in the clear.

**The honest limit.** Distinguishing "the certificate is invalid" from "I couldn't reach the host" is genuinely hard — both arrive by the same path — so we match on the error text. And note that the redirect-to-https branch only works *because* we don't follow redirects; when we did, that branch was unreachable and a server that correctly upgraded to HTTPS was still flagged. **Also be ready for this: every practice server runs on loopback, so this is the one check with no live test** — see §6.

---

#### #3 `missing-www-authenticate` — severity **medium** · version-gated

*Rule: RFC 9728 §5.1 — the `401` MUST name the login-information page.*

**What we send.** An identical unauthenticated `tools/list` to the one check #1 sends — but a second, separate request. Detectors never read each other's responses, so each issues its own.

**What we look at.** The `WWW-Authenticate` header on the refusal, specifically whether it carries a `resource_metadata=` parameter pointing at an absolute `http(s)` address.

**How we decide.**

| Observation | Verdict |
|---|---|
| No authentication refusal at all | `NOT_APPLICABLE` — the requirement was never triggered |
| Challenge carries a usable `resource_metadata` URL | `NO_GAP` |
| Mentions `resource_metadata` but not as a usable absolute URL | `HAS_GAP` (strict revision) / `INCONCLUSIVE` |
| Challenge with no pointer at all | `HAS_GAP` (strict revision) / `INCONCLUSIVE` |

**Why it matters.** A server that correctly says "log in first" is also required to say **where**. Many just say "no" and leave the client stuck with nowhere to go.

**The honest limit.** A malformed pointer is not a compliant one — a plain substring test used to accept it, so we now require it to parse as an absolute address. Note the deliberate choice that a bare `403` lands in `NOT_APPLICABLE` rather than being graded a malformed challenge: charging a firewall block with an RFC 9728 violation would be a false accusation.

---

#### #4 `missing-protected-resource-metadata` — severity **medium** · version-gated

*Rule: RFC 9728 §3.1 — the page MUST exist, at the path-inserted address.*

**What we send.** Nothing of its own — it reads the shared discovery lookup. (It also carries its own `GET` fallback so the check works standalone, for instance in unit tests; in a real scan — even a Tier-1-only one — the shared lookup always runs, because this check is the one that asks for it.)

**What we look at.** Whether the **PRM** (Protected Resource Metadata — the page where the server publishes "here is where you go to log in for me") exists, and whether it names a login server in an `authorization_servers` field.

**How we decide.**

| Observation | Verdict |
|---|---|
| Document present, `authorization_servers` is a non-empty list of addresses | `NO_GAP` |
| Document present, `authorization_servers` is the wrong shape (e.g. a bare string) | `HAS_GAP` |
| Document present, field missing or empty | `HAS_GAP` — non-compliant on its own terms, whatever revision it claims |
| No document anywhere | `HAS_GAP` (strict revision) / `INCONCLUSIVE` |

**Where we look, and why this one is worth a slide.** Both RFC 9728 and RFC 8414 insert the well-known suffix **between the host and the path**. A resource at `https://ex.com/public/mcp` publishes its page at `https://ex.com/.well-known/oauth-protected-resource/public/mcp` — the server's own path appended. We originally probed only the bare domain. Since the standard MCP endpoint form is `https://host/mcp`, **that meant missing it on essentially every real server, and reporting fully compliant servers as missing their metadata.** We try the path-inserted form first, then the bare domain as a fallback, and we prefer the address the `401` itself named when there was one — because using that pointer is a client MUST, and guessing instead meant our scanner failed the very requirement it audits. (That pointer was the source for 33 of our 83 scans.)

**Why it matters.** This is the one check the *newest* revision made **stronger** — publishing the page is now required unconditionally.

---

#### #5 `session-id-in-url` — severity **medium**

*Rule: OAuth 2.1 §5 — MUST NOT put it in the web address.*

**What we send.** Up to three things, in order, stopping as soon as one answers:

1. Nothing — first we just inspect the target address we were given.
2. A repeat `initialize`, if the handshake saw no session tag.
3. A `GET` with `Accept: text/event-stream`, read with a **4 KB cap** because the stream never closes.

**What we look at.** Whether a session tag appears in a web address rather than in a header.

**How we decide.**

| Observation | Verdict |
|---|---|
| The target address itself carries `session_id=` / `sid=` in its query | `HAS_GAP` |
| The server returned the tag in the `Mcp-Session-Id` **header** | `NO_GAP` |
| The legacy SSE `endpoint` event advertises a POST address containing a session tag | `HAS_GAP` |
| Neither seen | `INCONCLUSIVE` — the server may be stateless, in which case the gap cannot apply |

**Why it matters.** Web addresses get written into server logs, browser history, and analytics, and are passed to other sites in the `Referer` header. A tag in the address leaks.

**The honest limit.** Be upfront about this one: **73 of our 83 servers answered "don't know".** We have not implemented the old two-connection SSE handshake that this check really needs. And the rules have moved on: protocol sessions were **removed entirely in revision `2026-07-28`** (see §9), so present this check as tied to revisions `2025-03-26` through `2025-11-25`, not as timeless.

---

### Tier 2 — crafted requests, follow-up lookups, several samples

#### #6 `predictable-session-id` — severity **medium**

*Rule: MCP Security Best Practices §Session Hijacking — session IDs MUST be non-deterministic.*

**What we send.** Up to **five session tags are sampled.** The handshake's tag counts as one when the server issued one, so the check then sends four more; when the handshake got no tag, the check sends five `initialize` requests of its own. Every session the check opened is then handed back with a `DELETE`, so we do not leave five parked on the target.

**What we look at.** The tags themselves, as strings.

**How we decide.** Four tests, ordered most-conclusive first:

1. **Deterministic** — the same tag handed out twice → `HAS_GAP`. Trivially forgeable.
2. **Sequential integers** — a constant-step progression over ≥4 samples, or a dense cluster whose whole span is no wider than the number of **distinct values** seen (which is what a `+1` counter looks like even when another client consumed a value in between) → `HAS_GAP`.
3. **Constant prefix + counter suffix** — `sess-1`, `sess-2`, `sess-3` → `HAS_GAP`. Checked *before* the entropy test on purpose, because `mcp-session-00000000000000000001` would otherwise score 192 bits of apparent keyspace while being a plain counter.
4. **Estimated keyspace below ~64 bits** → `HAS_GAP`.

If no tag was ever seen we distinguish four cases: could not reach the server, the server demanded a login before opening a session, the server answered with an odd status, or the server answered fine and simply issues no tags → only the last is `NOT_APPLICABLE`.

**The mechanism worth explaining: length is not entropy.** Our first rule was "shorter than 16 characters = weak". It got both directions wrong — it flagged a 15-character random token (**90 bits** if drawn from the 64-character base64url alphabet — perfectly strong) while passing a 16-digit numeric id (**53 bits**, brute-forceable). What matters is length **times how many characters each position could have held**. So we identify the smallest alphabet the tag fits (digits = 10 symbols, hex = 16, base64url = 64) and multiply.

We also guard the degenerate case: a tag longer than four characters built from only **one or two** distinct symbols is re-scored at one bit per character, so `aaaabbbb…` cannot claim a large keyspace however long it is. Tags with three or more distinct symbols are not penalised — short random tokens legitimately show few repeats.

**Why it matters.** A guessable tag is not a break-in on its own — you would still need a token. It matters because some servers wrongly treat the tag *as* the credential, and because a guessable tag lets someone continue an existing conversation.

**The honest limit.** Say this plainly: **0 failures in 83 servers, and protocol sessions were removed from MCP in `2026-07-28`.** This is our most marginal check. It is a good answer to "did every check find something?" — no, and that is a result too.

---

#### #7 `origin-not-validated` — severity **high**

*Rule: MCP Transports §Security Warning — servers MUST validate the `Origin` header.*

An **Origin** identifies the website/address that started a browser request. The server checks it to decide whether that calling page is trusted.

**What we send.** An `initialize` carrying a forged `Origin: https://evil.attacker.example`. Then, on one specific path only, **a second control request** with no `Origin` at all.

**What we look at.** Whether the forged request is accepted, and — critically — whether a refusal can actually be attributed to the `Origin`.

**How we decide.**

| Observation | Verdict |
|---|---|
| `200` with a valid result | `HAS_GAP` — the server accepted a request it should have rejected |
| `403`, **and** the control (no `Origin`) was accepted | `NO_GAP` — the server really is checking |
| `403`, **and** the control was also refused `403` | `INCONCLUSIVE` — the server refuses everything |
| `403`, and the control never completed | `INCONCLUSIVE` — the comparison never happened |
| An authentication refusal | `INCONCLUSIVE` — gated before `Origin` was ever considered |

**The mechanism worth explaining: the control request.** A `403` alone proves nothing — the server may refuse *everything*. Without the control, `403 {"error":"Missing API key"}` was being credited as "this server validates Origin". **Only a server that accepts the control and rejects the forged `Origin` is actually validating it.** This is the clearest example in the project of a comparison being necessary to make a single observation mean anything.

**Why it matters.** It blocks **DNS rebinding**, where a web page re-points its own domain name at `127.0.0.1` to reach a server on your machine.

**The honest limit.** Be ready for a sharp examiner here, and volunteer it first: that threat is aimed at *local* servers, so for a remote `https://` server the requirement is largely ceremonial. 24 of 83 breach it — a genuine MUST violation — **but all 24 are already among the 28 that need no login at all** (we checked the intersection: it is exact), so this check has never caught a server on its own.

---

#### #8 `cors-misconfiguration` — severity **medium**

*Rule: **none.** CORS is not in the MCP specification. Graded as general web security.*

**CORS** is the browser mechanism that uses response headers to decide which other websites may call a server and whether those requests may include credentials.

**What we send.** An `OPTIONS` preflight carrying `Origin: https://evil.attacker.example`, `Access-Control-Request-Method: POST` and `Access-Control-Request-Headers: authorization,content-type`. If that produces no CORS headers, we fall back to a `GET` carrying the same `Origin`.

**What we look at.** Two response headers: `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.

**How we decide.**

| Observation | Verdict |
|---|---|
| Reflects our forged origin **and** allows credentials | `HAS_GAP` — any website could make credentialed calls as you |
| Reflects our forged origin, but no credentials | `INCONCLUSIVE` — lower risk, worth noting, not a clear finding |
| `*` wildcard | `NO_GAP` — browsers refuse to send credentials to `*`, so no credentialed theft |
| A fixed origin that isn't ours | `NO_GAP` |
| No CORS header at all | `NO_GAP` — grants no cross-origin access |

**Why it matters — and the honest limit, which here are the same thing.** Own this proactively: **this is the weakest thing we report, and the only one of the fourteen not drawn from the MCP rules.** It only bites if a browser is involved, and MCP clients generally are not browsers. We report it as a general web-security observation and **never** cite it as a specification violation. Two servers out of 83.

One nuance worth keeping, because it shows care: on a wildcard we note that *if the server needs no login at all, any web page can still drive it directly* — the same exposure by a different route. Calling that simply "not exploitable" would have been misleading.

---

#### #9 `auth-endpoints-not-https` — severity **high**

*Rule: OAuth 2.1 §1.5 + MCP Authorization §2.8 — every OAuth address MUST use `https`.*

**What we send.** **Nothing.** This check makes no requests of its own; it reads the shared discovery lookup. Worth saying out loud — it illustrates the "fetch once, read many" design.

**What we look at.** Every address the server published: each `authorization_servers` entry — at most the first five, since a document listing hundreds would turn one scan into a flood against a third party — plus the endpoint fields inside the login server's description page (`issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint`, `device_authorization_endpoint`, `jwks_uri`).

**How we decide.** Any of them being cleartext `http` on a non-loopback host → `HAS_GAP`. Nothing discovered at all → `NOT_APPLICABLE`. Otherwise → `NO_GAP`.

**The mechanism worth explaining.** If the login server's description page is one the standard says must not be trusted (see #10), **we do not read its endpoints either** — and we say so in the note. Reading a document that another check has already declared unusable made one report contradict itself.

**Why it matters.** Tokens would travel in the clear.

---

#### #10 `missing-as-metadata` — severity **medium** · version-gated

*Rule: MCP Authorization §2.3.2 + RFC 8414 — the login server MUST publish its own description.*

**What we send.** Nothing of its own. The shared flow is: **PRM → AS address → derive the standard AS-metadata URLs → fetch them in order → keep the first valid metadata page → read its issuer and endpoints.** If the PRM gives no usable AS address, the scanner also tries the scanned server’s own origin as a fallback.

**What we look at.** Whether the **AS metadata** page (Authorization Server Metadata — where the login server describes its own addresses and supported login styles) exists, and whether it correctly names *itself*.

**How we decide.**

| Observation | Verdict |
|---|---|
| Page resolved, and its `issuer` is consistent with what we asked for | `NO_GAP` |
| Page served, but its `issuer` names **someone else** *and it was the PRM that told us which issuer to ask* | `HAS_GAP` — RFC 8414 §3.3 says such a document MUST NOT be used |
| No page anywhere | `HAS_GAP` (strict revision) / `INCONCLUSIVE` |

**Why the mismatch is qualified.** A mismatch only counts as a violation when the issuer was **authoritative** — named by the PRM. When we reached the page through the origin fallback, the issuer we asked for was our own *guess*, so a different value there is expected: we record it in the notes and do **not** call it a gap. Flagging it would fail every server whose issuer URL merely differs cosmetically from its origin.

**Where we look.** Up to three addresses: the RFC 8414 form with the well-known segment inserted before the issuer path, an inserted OpenID configuration form, and an appended OpenID configuration form. For the usual pathless AS address, the last two are the same URL, so only two distinct pages are fetched. The project’s compliance baseline remains MCP revision `2025-06-18`; the OpenID forms are compatibility fallbacks.

**Why #4 and #10 are two checks, not one.** This is a likely question. #4 asks *"is page 1 there, and does it name anyone?"*; #10 asks *"does page 2 exist, and is it self-consistent?"* You need the first to know where the second is — and they are separate for the reason given in §5: the two pages often belong to two different companies.

**The honest limit.** Only the *first* login server that answers is examined. Any others are listed in the report as unexamined rather than being silently treated as cleared.

---

#### #11 `implicit-flow-enabled` — severity **high**

*Rule: OAuth 2.1 §1.8 — the implicit grant was removed from the standard.*

**What we send.** Nothing of its own — it reads the login server's description page from the shared lookup.

**What we look at.** Two fields: `response_types_supported` and `grant_types_supported`.

**How we decide.** `response_types_supported` containing `token`, **or** `grant_types_supported` containing `implicit` → `HAS_GAP`. No usable description page → `NOT_APPLICABLE`. Field present and clean → `NO_GAP`. `response_types_supported` absent → `INCONCLUSIVE`.

**The mechanism worth explaining.** OAuth response types are **space-delimited sets**. A single entry `"id_token token"` advertises the hybrid flow and therefore *does* include `token`. Testing whole entries with a plain list membership check matched only a bare `"token"` entry, so every real-world advertisement of the implicit grant via a combined response type was missed. We split on spaces.

**A deliberate false-positive avoidance.** RFC 8414 says that when `grant_types_supported` is *absent*, the default technically includes `implicit`. We **do not** flag that — it is a frequent false positive. We note it instead. Being able to explain a choice like this is exactly what an examiner is looking for.

**Why it matters.** The implicit flow delivered the token **inside the web address**, where it leaks into browser history, server logs, and the `Referer` header. OAuth 2.1 removed it in favour of the authorization-code flow with PKCE.

---

#### #12 `open-dcr` — severity **high** · **this one writes** · off by default

*Rule: **none.** RFC 7591 §3 actually permits open registration. Reported as posture, not a breach.*

**What we send.** A real RFC 7591 client-registration `POST` with **no** initial access token:

```json
{
  "client_name": "mcpauth-probe (auth-gap scanner, safe to delete)",
  "redirect_uris": ["https://mcpauth.example/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Then, immediately, an attempt to **delete what we just created** — an RFC 7592 `DELETE` to the management address the server returned, carrying the registration token it returned.

**Before any of that: the containment check.** The registration address was chosen by the scanned server and what follows is a *write*. So it must be `http(s)`, must not be cleartext on a public host, and **must be the scan target itself or a sibling under the same domain name**. If not → the check returns `INCONCLUSIVE` and **no request is made at all**. The same gate applies to the deletion, because a `DELETE` carrying a credential is exactly the shape of request that must never be aimed at a host of someone else's choosing.

**How we decide.**

| Observation | Verdict |
|---|---|
| Any `2xx` with a `client_id` | `HAS_GAP` — anyone can mint a client. Cleanup attempted, outcome stated |
| Any `2xx` from which we could not read a `client_id` | `HAS_GAP` **+ `MANUAL CLEANUP NEEDED`**, naming the endpoint to inspect by hand — we cannot name the client we just created, which is exactly why the warning is loud |
| The request went out but **no reply came back** | `ERROR` **+ `MANUAL CLEANUP NEEDED`** — the server may well have created it, and we cannot know |
| The connection never opened (refused, name didn't resolve, certificate rejected) | `ERROR`, and **nothing is owed** — no request reached anyone |
| A real authentication refusal | `NO_GAP` — the endpoint requires a registration token |
| A bare `403` | `INCONCLUSIVE` — could be authorization, could be a firewall |
| Anything else | `INCONCLUSIVE` — could be input validation rather than an auth decision |
| No usable AS metadata, or metadata advertising no `registration_endpoint` | `NOT_APPLICABLE` — nothing to register against, and no request is sent |

**That last row is the most common outcome in practice**: **35** of the 83 servers advertise no registration address at all, so we never write to them — which appears in §7's table as 35 `NOT_APPLICABLE`. Turned round, this is the better number for a slide: **48 of 83 do advertise registration** (38 open + 10 inconclusive), and those 48 are the only ones a live run would ever touch.

**The mechanism worth explaining: success is decided by the status code, not by whether we could parse the reply.** Any `2xx` — including a `202 Accepted` — means the server created something. Inferring "nothing was created" from an unreadable body is precisely how a real client ended up abandoned on a third party's server with no record of it.

**And the harder version of the same mistake: a reply that never arrives is not a reply saying "no".** When our request reached the server and the answer got lost on the way back, the tool used to record it as "nothing was created" — and then printed **"Every client created was deleted again"** over a permanent registration on someone else's production server. It now separates the two cases by *why* the request failed: a connection that never opened created nothing and owes nothing, while a lost reply declares `MANUAL CLEANUP NEEDED`. Anything it cannot classify counts as possibly-created, because over-reporting one write you cannot verify is recoverable, and quietly abandoning one is not.

**Why it matters.** Open self-registration is not against the rules — but it is **the foothold a bigger attack needs**, and it is the one surviving piece of the identity-confusion angle we otherwise dropped, because it is visible without any token. **38 of 83 servers.**

**The honest limit, and you must state it.** Probing this means **really registering something**. See §8 — do not present this check without presenting what it cost.

---

#### #13 `unauthenticated-tool-invocation` — severity **high**

*Rule: MCP Authorization — a protected server MUST validate a token before processing a request and answer `401`. `tools/call` is a privileged operation.*

**What we send.** One `POST` of `tools/call` naming a **deliberately non-existent tool** (`__mcpauth_probe_nonexistent_tool__`) with empty arguments, **no `Authorization` header**, carrying the session tag if the server issued one. The fake name means a conformant server rejects it before running anything — nothing is executed.

**What we look at.** Not any tool output — *where the rejection came from*: an HTTP `401` (or a corroborated `403`) versus a JSON-RPC reply.

**How we decide.**

| Observation | Verdict |
|---|---|
| `401`, or a `403` corroborated by `WWW-Authenticate` / an OAuth error code | `NO_GAP` — the invocation path is gated |
| `2xx` with a JSON-RPC reply — a result, or an "unknown tool" error | `HAS_GAP` — the call reached the MCP dispatch layer, past any auth gate |
| A JSON-RPC error that itself reads as an auth decision | `INCONCLUSIVE` — a non-conformant server may be doing app-layer auth |
| bare `403` / `400` / `404` / `429` / other | `INCONCLUSIVE`, with a hint |

**The mechanism worth explaining: this is the check that closes #1's inference gap.** #1 proves only that the *catalog* is readable without a login (it sends `tools/list`), then *infers* "anyone can use this server" — but a server can gate listing and calling differently (a public catalog with gated execution is legitimate), and #1 never tests a call. #13 tests the **invocation path directly**: a JSON-RPC reply to an unauthenticated `tools/call` proves the request got past the transport auth gate; a `401` proves it did not. Nothing runs, because the tool does not exist.

**Why it matters.** Against 83 servers, #13 disagreed with #1 on six: `dock`, `switch`, `gondola`, `financial-data`, `api-openmandate`, and `catalog-api` expose `tools/list` but answer `401` to unauthenticated `tools/call`. The other 22 return JSON-RPC, which proves dispatch access without login — not successful real-tool execution.

**The honest limit.** A JSON-RPC reply proves the call reached the dispatch layer; it does not prove a *real* tool would run side effects (we never call one). A server that reports auth failure as a JSON-RPC error rather than `401` lands in `INCONCLUSIVE`, not mis-graded open.

---

#### #14 `improper-redirect-uri-validation` — severity **high** · **this one writes** · off by default

*Rule: OAuth 2.1 §7.5.4 + MCP — clients MUST pre-register redirect URIs; the authorization server MUST validate exact redirect URIs against pre-registered values, and MUST NOT redirect to an invalid one.*

**What a redirect URI is.** After a user logs in, the authorization server sends their browser back to a **redirect address** the client registered in advance, carrying the one-time authorization code. If the server will send that code to an address the client never registered, an attacker who lures a user to a crafted authorize link captures the code — and thus the token.

**What we send.** First a real RFC 7591 registration (a **write**) to obtain a client with one known redirect URI; then **one unauthenticated `GET`** to the `authorization_endpoint` carrying a **different, unregistered** redirect URI (`https://mcpauth-attacker.example/steal`); then an RFC 7592 `DELETE` to clean the client up. Both URIs are non-resolving `.example` hosts, so even a server that wrongly honoured one sends nothing anywhere real.

**Why it writes, and why it's off by default.** To test "an *unregistered* redirect URI for a *known* client" we must first **have** a known client — which means registering one, exactly like #12. So #14 runs only under `--unsafe-writes`, and only where self-service registration is open.

**What we look at — and the point that trips people up: HTTP `200` does NOT mean "accepted".** The `/authorize` endpoint is a **browser page**, not a JSON API. A `200` is the server serving its own **login/consent HTML** at its own origin — the authorization code is **never** delivered in a `200` body. The dangerous event — sending the code to the attacker's address — happens only as a **`3xx` redirect whose `Location` is the unregistered URI**.

**How we decide.**

| Observation | Verdict |
|---|---|
| `3xx` → `Location` host = the unregistered attacker URI | `HAS_GAP` — server honoured an address the client never registered |
| Any `4xx` | **Current code:** `NO_GAP`. This is strong evidence only when the body explicitly says the redirect URI mismatched; generic errors, missing PKCE, or a login page do not prove validation. |
| `3xx` → the authorization server’s own host, or `200` (login/consent page) | `INCONCLUSIVE` — validation may happen only after a login we cannot complete. |
| `3xx` → another non-attacker host | **Current code:** `NO_GAP`, but this may simply be an external login host and should be treated as inconclusive. |

Front-desk analogy: `200` means the desk hands you a sign-in form; `3xx` to the bad URI means it sends the guest and code to the attacker; an error that explicitly says the address is not registered proves rejection. A generic `4xx` only says something went wrong, not what was checked.

**Why it matters — and the fleet result you must present honestly.** Of 47 applicable servers, the current code reports **0 `HAS_GAP`, 23 `NO_GAP`, and 24 `INCONCLUSIVE`**. Sixteen of the 23 clean verdicts contain direct invalid-redirect evidence; the other seven are PKCE/malformed-request responses, generic errors or login redirects that do not prove exact redirect validation. The check therefore found no accepted bad redirect, but it did **not** confirm 23 correct implementations. It also registered 38 clients it could not delete. #14 is covered by mocked behaviour tests, with no committed live vulnerable/hardened sandbox pair.

**The honest limit.** Like #12, probing this means really registering something — here, for zero findings. The unauthenticated probe cannot see validation that happens only after login, and the current classifier is too generous with generic `4xx` replies and redirects to other login hosts.
