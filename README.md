# YamAmit-MCP-auth — a scanner that checks how well an MCP server protects its login

An **MCP server** is a program that offers *tools* (actions, like "search the documents" or "run this query") to an AI assistant over the internet. Before an AI is allowed to use those tools, the server is supposed to make it **log in**. This project checks whether servers actually do that, and whether they do it the way the official rules require.

You point the tool at one server address and it runs 14 separate checks — one per known weakness (twelve are read-only; two make a change on the server and stay off unless you ask). Each check is called a **detector**, and each weakness is called a **gap**. Every check answers on its own, and every answer comes with the actual message we sent and the server's actual reply (the **evidence**), so anyone can re-check our work.

```bash
uv run mcpauth scan https://some-server.com/mcp
```

Each of the 14 checks returns one of five answers:

| Answer | Plain meaning |
|---|---|
| **`HAS_GAP`** | The condition tested by this check was observed. It may be a protocol violation, an optional-security concern, or a general web issue; see the protocol-status column. |
| **`NO_GAP`** | The reply matched what this check currently treats as correct; known limitations still apply. |
| **`NOT_APPLICABLE`** | This check cannot apply to this server (for example, the check is about logins over the internet and this server doesn't use the internet). |
| **`INCONCLUSIVE`** | We tried, but the reply didn't let us decide. **This is a real answer, not a failure** — saying "I don't know" is the point. |
| **`ERROR`** | The check itself could not run (the server never replied, the connection broke). |

- **Authentication** = proving *who you are* (showing your ticket).
- **Authorization** = deciding *what you're allowed to do* once you're known.

This README is the primary project document. [PRESENTATION-GUIDE.md](PRESENTATION-GUIDE.md) is its presenter-facing companion; both should stay aligned with the code and saved evidence.

**Important requirement for AI agents (Claude):** Aim to use simple language, as we have no background on these network subjects. When mentioning a technical term, add a short, direct definition in parentheses next to it.

---

## Glossary

| Term | Meaning |
|---|---|
| **token** | a digital "ticket" proving you logged in. Whoever holds it gets in, so a stolen one is as good as the original |
| **endpoint** | one specific web address a server answers on, e.g. `https://example.com/mcp` |
| **header** | a labelled extra line attached to a web request or reply, carrying info about it (who's asking, what format, which version). The message body is the content; headers are the envelope |
| **status code** | the short number a server replies with: `200` = fine, here you go · `400` = your request was malformed · `401` = log in first · `403` = refused · `404` = nothing here · `429` = you're going too fast, slow down · `500` = the server broke |
| **transport** | *how* the AI and the server talk to each other. The kinds that matter here: plain HTTP, SSE, and stdio |
| **stdio** | a server running as a program on your own computer, with no internet address at all. It cannot be scanned from outside, so most of our checks don't apply to it |
| **SSE** | Server-Sent Events — an older style of connection where the server keeps the line open and keeps talking. Because the line never closes, you can't just "wait for the reply to end" |
| **TLS / HTTPS** | encryption on the connection — the padlock in a browser. "Cleartext `http`" (no `s`) means no encryption |
| **certificate** | the ID card a server presents to prove it really is the site it claims. If it doesn't check out, the padlock is worthless |
| **loopback** | `127.0.0.1` or `localhost`. Nothing leaves the machine, so no encryption is needed |
| **OAuth** | the standard login system MCP uses. Rather than giving your password to the tool, you log in at a separate **authorization server**, which hands the tool a token |
| **authorization server** | the separate service that runs the login and issues tokens. Often the same company as the MCP server |
| **`.well-known/…`** | a standardised, predictable web address where a server publishes information about itself, so software can find it without being told where to look. The next two rows — **PRM** and **AS metadata** — are both published at exactly this kind of address |
| **PRM** | Protected Resource Metadata — the page where the MCP server publishes "here is where you go to log in for me". Published at a `.well-known/…` address (the row above), so a client can find it unaided. Defined by **RFC 9728**. **Relevant to us because it is our check #4**, and because it is the *advertisement* half of the only thing we can still measure: does the server correctly advertise and enforce its login |
| **AS metadata** | Authorization Server Metadata — the matching page where the *login* server describes itself: its addresses, which login styles it supports. Also at a `.well-known/…` address, and reached by following the **PRM**: the PRM names the login server, this page describes it. Defined by **RFC 8414**; it is our check #10 |
| **RFC** | a numbered internet standard document |
| **MUST / SHOULD** | the standards' own strength words. **MUST** = required, breaking it is a violation. **SHOULD** = strongly recommended, but allowed to differ with good reason |
| **spec revision** | which dated version of the MCP rules a server follows, e.g. `2025-06-18`. Newer revisions demand more. The server declares it in reply to our greeting — but a protected one says "log in first" before it ever gets that far, so 55 of our 83 never did |
| **session / session ID** | a temporary tag tying your back-and-forth messages together — a conversation ticket, *not* a password. Still worth protecting: whoever has it can continue your conversation |
| **DCR** | Dynamic Client Registration — a self-service sign-up form letting an app register itself as a client with no human involved (**RFC 7591**). Our check #12. Open sign-up isn't against the rules — we report it because it's the foothold a bigger attack needs, and because probing it means really registering something |
| **PKCE** | a proof that the app finishing a login is the same app that started it, so a stolen half-finished login is useless. We do **not** check this — it needs a completed login. It's here as the clearest example of what a clean report from us still can't rule out |
| **audience** | which service a token was issued *for*. A token meant for service A must not be accepted by service B (**RFC 8707**) |
| **CORS** | a browser rule about which websites are allowed to call this server from a user's browser. Note: **not part of the MCP rules at all**. Our check #8 — the only one of the fourteen not drawn from the MCP rules. It only bites if a browser is involved, and MCP clients generally aren't browsers, so it's the weakest thing we report. |
| **Origin** | a header saying which website a browser request came from. A server that trusts it blindly can be tricked. Our check #7: 24 of our 83 servers accept a forged one — but all 24 are already among the 28 that need no login at all, so this check has never caught a server on its own |
| **WAF** | Web Application Firewall — a filter in front of a server that blocks traffic it finds suspicious. It also answers `403`, which is why a bare `403` will prove nothing to us |

---

## Where this project sits

The parent folder holds three projects. This one is ours; the other two are unrelated to it and to each other.

- **`MCP-Scanner/`** (by Knostic) *finds* MCP servers but never judges them: it advertises a `security_findings` block with fields for authentication, TLS, CORS and rate limiting, and its code never fills any of them in (verified — those names appear only in one sample output file, nowhere in the code). That empty promise is what this project exists to fill. **We share no code with it.**
- **`MSB/`** is an unrelated benchmark (published at the ICLR 2026 conference) about whether the **AI itself** can be tricked by booby-trapped tool descriptions or hidden instructions. That is the AI's *behaviour*; we test the server's *plumbing*. Different layer, deliberately out of scope, **no shared code**.

**What we check:** everything a visitor who has *not* logged in can observe about a server's login setup — servers with no login at all, missing or broken encryption, whether the server correctly publishes where to log in, which login styles it advertises, whether anyone can sign themselves up as a client, how it handles session tags, and two browser-related weaknesses.

**What we deliberately do not check:**

- **Anything that needs a real token or a completed login.** See "Tier 3 — dropped" below for why.
- **Prompt injection, tool poisoning, malicious tool *content*.** That's the AI's behaviour, and it's `MSB/`'s job.

---

## What it checks — the 14 gaps

These come from the official MCP rules (the Authorization, Security Best Practices and Transports documents), the OAuth 2.1 standard, RFCs 9728 / 8414 / 7591 / 8707, and published research.

### Tier 1 — the easy checks: one request with no login, and we can tell

| # | Name | What it does, in plain terms | Rule it breaks | Protocol violation if `HAS_GAP`? | Sev |
|---|---|---|---|---|---|
| 1 | `no-authentication-remote` | Ask the server "list your tools" without logging in. If it answers, **anyone on the internet can read its list of tools without logging in** (capability disclosure). Whether those tools can actually be *run* without logging in we do **not** test — we only ever ask for the list, never run one. | **MCP Transports §Security** — servers SHOULD authenticate every connection, and a protected one MUST answer `401` | No — authentication is a `SHOULD` | medium |
| 2 | `no-tls-transport` | Is the connection unencrypted (`http` instead of `https`) on a public address — or encrypted but with a **certificate** (ID card) that doesn't check out? Either way the traffic isn't really protected. | **OAuth 2.1 §1.5** — traffic carrying a login MUST use https (loopback exempt) | Conditional — if OAuth is used | high |
| 3 | `missing-www-authenticate` | When the server correctly says "log in first" (`401`), it is also required to say **where** to log in, via a `WWW-Authenticate` header pointing at its login-info page. Many just say "no" and leave you stuck. | **RFC 9728 §5.1** — the `401` MUST name the login-info page | Yes — `2025-06-18` `MUST` | medium |
| 4 | `missing-protected-resource-metadata` | Does the server publish its "here's where to log in" page (**PRM**) at all, and does that page actually name a login server? | **RFC 9728 §3.1** — the page MUST exist, at the path-inserted address | Conditional — if OAuth is used | medium |
| 5 | `session-id-in-url` | Is the session tag put in the web address instead of in a header? Web addresses get written into server logs, browser history and analytics, so the tag leaks. | **OAuth 2.1 §5** — MUST NOT put it in the web address | Not proven — a session ID is not an access token | medium |
| 13 | `unauthenticated-tool-invocation` | Send `tools/call` without logging in, using a deliberately non-existent tool so nothing executes. A JSON-RPC reply proves the request reached the MCP dispatch layer instead of being stopped by a `401`; it does **not** prove that a real tool would run. | **MCP Authorization** — a protected server MUST validate a token before processing a request, and answer `401` | No — authentication itself is a `SHOULD`; this measures the unauthenticated dispatch path | high |

*(Checks #13 and #14 were added after the original twelve, so they keep numbers 13–14 rather than renumbering everything. #13 is a Tier-1 mechanism — one unauthenticated request — and #14 is a Tier-2 write, listed with the Tier-2 checks below.)*

### Tier 2 — the medium checks: specially-crafted requests, or a follow-up lookup

| # | Name | What it does, in plain terms | Rule it breaks | Protocol violation if `HAS_GAP`? | Sev |
|---|---|---|---|---|---|
| 6 | `predictable-session-id` | Open several sessions and compare the tags. Are they guessable — counting up (1, 2, 3), identical every time, or simply too short to be safe? A guessable tag isn't a break-in on its own — you'd still need a token. It matters because some servers wrongly treat the tag *as* the credential, and because a guessable tag lets someone hijack an existing conversation. Found 0 failures in 83 servers, and protocol sessions were removed from MCP in `2026-07-28` — so this is our most marginal check. | **MCP Security Best Practices §Session Hijacking** — MUST be non-deterministic | Yes — MCP `MUST` | medium |
| 7 | `origin-not-validated` | Send a request claiming to come from `evil.attacker.example`. Does the server accept it? Required by the MCP rules themselves (Transports, "Security Warning"), not by any RFC — it blocks DNS rebinding, where a web page re-points its own domain name at `127.0.0.1` to reach a server on your machine. Note that this threat is aimed at *local* servers, so for a remote `https://` server the requirement is largely ceremonial. | **MCP Transports §Security Warning** — MUST validate `Origin` | Yes — MCP `MUST` | high |
| 8 | `cors-misconfiguration` | Does the server tell browsers "any website may call me" *and* "you may send credentials along"? Together those let any web page act as you. (A general web-security concern — **not an MCP rule.**) | **none** — CORS is not in the MCP spec; graded as general web security | No — outside MCP | medium |
| 9 | `auth-endpoints-not-https` | Among the login addresses the server publishes, is any of them unencrypted `http` on a public host? Tokens would travel in the clear. | **OAuth 2.1 §1.5** + **MCP Authorization §2.8** — every OAuth address MUST use https | Yes — OAuth endpoints `MUST` use HTTPS | high |
| 10 | `missing-as-metadata` | Does the login server publish its own description page (**AS metadata**) — and does that page correctly name itself? A page claiming to belong to someone else must not be trusted. | **MCP Authorization §2.3.2** + **RFC 8414** — the login server MUST publish it | Conditional — if OAuth is used | medium |
| 11 | `implicit-flow-enabled` | Does it still advertise the old "implicit" login style, which delivers the token inside the web address (where it leaks)? The current OAuth 2.1 standard removed it. | **OAuth 2.1 §1.8** — the implicit grant was removed from the standard | Not proven — legacy support may coexist | high |
| 12 | `open-dcr` | Can anyone sign themselves up as a client with no approval at all? **This check writes** — it really does create a registration — so it is switched off unless you explicitly ask for it. | **none** — **RFC 7591 §3** actually permits open sign-up; reported as posture, not a breach | No — explicitly permitted | high |
| 14 | `improper-redirect-uri-validation` | After a login, the server sends you back to a **redirect address** the app registered in advance. Does the login server accept an address that was **never registered**? If so, an attacker can steal the login code (and thus the token). **This check writes** — it must register a throwaway client first — so it is off unless you explicitly ask. | **OAuth 2.1 §7.5.4 + MCP** — the login server MUST reject a redirect_uri that isn't an exact pre-registered match, and MUST NOT redirect to it | Yes — OAuth 2.1 `MUST` / `MUST NOT` | high |

Here, **Yes** means the observation directly demonstrates a broken `MUST` or `MUST NOT`. **Conditional** means the requirement applies only when the optional OAuth authorization mechanism is being used. **Not proven** means the check found a security concern, but its evidence alone does not establish a protocol violation.

### Tier 3 — dropped

**Eight** more gaps were designed but **never built, and the project no longer intends to build them**: `no-pkce`, `missing-token-audience-validation`, `token-passthrough`, `confused-deputy-proxy-consent`, `session-used-for-auth`, `self-asserted-capabilities`, `credential-harvesting-tool-desc`, `missing-session-isolation`. *(A ninth, `improper-redirect-uri-validation`, was originally in this list but was later built after all — it is check #14 above. Its live run found it testable but low-yield; see the results section.)*

**Why they are out.** Every one of them needs something we do not have and cannot get: a valid token, a full multi-step login completed against a server we don't own, several logged-in sessions running at once, or the ability to watch a *different* back-end server receive a forwarded token. A scanner that never logs in cannot obtain any of that against strangers' production servers. Two of them (`token-passthrough`, `missing-session-isolation`) could only ever have been guessed at even *with* a login, because the evidence lives on a machine we can't see.

**The honest consequence, and it matters:** this tool measures whether a server **advertises and enforces** login correctly — *not* whether its login is **sound**. A server can score `NO_GAP` on all fourteen of our checks and still accept tokens meant for someone else, skip PKCE, or leak one user's data to another. That limit is repeated wherever results appear, rather than left for the reader to work out.

### The research angle that remains

One angle survives: **does the server correctly advertise and enforce its login process, as seen by someone with no credentials?** That covers all 14 gaps, needs no login for the twelve read-only ones (the two write checks, #12 and #14, need a self-service registration but still no human login), and is therefore testable today against any public server.

The two angles that depended on Tier 3 are closed: *token passthrough* (a server forwarding your token on to a third service that shouldn't get it) and *identity confusion* (one user's identity being mistaken for another's). Gap #12 `open-dcr` survives independently, because open sign-up is visible without any token — and it is the stepping stone an identity-confusion attack would need.

---

## Rules every check follows

- **Transport gating.** A **stdio** server is a program on your machine that the AI talks to through pipes — no address, no port, nothing on the network to inspect. Login checks return `NOT_APPLICABLE` for those, because such a server legitimately needs no OAuth (only someone already on the machine can reach it). Without this, every stdio entry in a registry list would be reported as "no authentication!" — a false alarm. Note this is *not* about `localhost` servers: those are ordinary HTTP servers and we scan them normally.
- **Version gating.** Gaps 3, 4 and 10 became firm requirements (**MUSTs**) only from spec revision **2025-06-18 onwards**, so those three are the only ones whose verdict depends on the server's version. We compare dates as "this revision or later", never "exactly this revision" — because every newer revision keeps the requirement, so an exact match would let precisely the servers that stay current off the hook. Below that bar, a weak result is reported as a note, not as `HAS_GAP`.
- **Loopback exemption.** Unencrypted `http` is perfectly fine on `localhost` / `127.0.0.1`, because nothing leaves the machine.

---

## Safety rules — we are pointing this at other people's live servers

1. **Nothing durable is changed by default.** Twelve checks make no persistent registration. The two write checks — #12 `open-dcr` and #14 `improper-redirect-uri-validation` — each register a client and are **off unless you pass `--unsafe-writes`**. Not quite read-only, though: check #7 opens a session it does not hand back (see rule 5).
   **Anything created by either write check is recorded immediately**, in `mcpauth-writes.jsonl` and on error output, before cleanup is attempted. Without that journal, an interrupted bulk run could leave a real registration with its identifier lost.
2. **We control where our own requests go.** Almost every address we fetch after the very first one was *chosen by the server we are scanning* — it tells us where its login server is, where to register, where its info pages live. Following that blindly would turn our scanner into someone else's weapon (the classic name for this is a **confused deputy**: a trusted program tricked into misusing its access). So every such address is checked first: addresses inside private networks are refused, anything that isn't `http`/`https` is refused, and either **write check** may only go to the server we're scanning or a sibling address under the same domain name. A refused address is always reported, never quietly skipped.
   **How that is enforced, in two places.** Checking the address as written catches only the obvious form (`http://10.0.0.5/`), because a *name* like `intranet.example.com` looks like any other public address until you look it up. So the check runs twice: once on the address as written, before we fetch it, and again on the address the name actually **resolved to**, at the moment of connecting. The second one is what catches a name the scanned server chose that points at your own machine, your office network, or the cloud service that hands out machine credentials. It has to happen at connect time rather than a moment earlier, because a name can be re-pointed in between (the trick is called **DNS rebinding**). What is still permitted is in "Known limitations" below.
3. **We never follow redirects** (a reply saying "go look over there instead"). Following one would let a server hand us another host's document and have us credit it to itself — and RFC 9728 is entirely about *which* host published a document.
4. **Certificates are checked.** A failed certificate becomes a *finding*, not something we shrug off. `--insecure-tls` turns the checking off for local practice servers with homemade certificates, and it makes all our encryption verdicts meaningless — that's the trade.
5. **Sessions are handed back, best effort — with one known leak.** A scan releases the session it opened with the `DELETE` request ("I'm done, discard this") that the rules prescribe. Check #6 opens up to four more so it can compare their tags, and releases those too — but without the `MCP-Protocol-Version` header, so a server that insists on that header can refuse those four and leave them sitting until they expire on their own. **Check #7 opens one more and never releases it at all**, so a scan of a session-based server leaves exactly one session parked on it. A leftover session holds nothing but throwaway greeting data, but the leak is a bug, not a decision — it is listed under "Known limitations" below.

> **Why rules 1 and 2 exist.** They were added after a live #12 run created a real OAuth client on `api.llow.io` while the address being scanned was `api.serff.ai` — a different domain that was never on our list. See What we left behind below.

---

## How the code is arranged

```
YamAmit-MCP-auth/
  README.md              # primary project document
  pyproject.toml         # dependency list, managed by `uv`
  mcpauth/
    models.py            # the shared vocabulary: verdicts, findings, the version gate
    netguard.py          # decides if an address is safe to fetch (private? same site?)
    probe.py             # sends the web requests, reads full replies, records evidence
    oauth.py             # finds the login-info pages (PRM -> AS metadata), once per scan
    runner.py            # does step 1 below (one request, no token), then runs all checks together
    detectors/
      base.py            # what every check must provide + was this a login refusal?
      tier1.py           # gaps 1–5 and 13
      tier2.py           # gaps 6–12 and 14
    cli.py               # the command line: `mcpauth scan <url>`
  sandbox/               # 7 practice servers we run locally (see Validation)
  tests/                 # 213 tests
  reports/               # raw scan evidence + result tables
```

**What a real client does, and where we stop.** Getting into a protected MCP server takes three steps:

1. Ask the server something with **no token**. A protected server answers `401` ("log in first") and points at its login-info page.
2. Go and get a token: read the login-info page, read the login server's own description page, send the user to log in, receive the token.
3. Ask again, now carrying the token. Only now does the conversation actually open.

**We only ever do step 1, plus the reading half of step 2.** The discovery flow is **MCP address → fetch PRM → read the AS address → derive and fetch the AS metadata page → read its login, token, and registration endpoints.** Those pages are public, so checks #4, #9–#12, and #14 need no human login. We never obtain a login token or reach step 3.

**Each check stands alone** — none of them reads another's answer, which is why all fourteen
can run at once, in any order, with the same result either way.

The only thing they share is **two web pages**, because finding the login takes two hops:

1. **The MCP server's own page** — "to log in for me, use this login server". Just a pointer.
2. **That login server's page** — its addresses, and which login styles it supports.

You need the first to know where the second is. They are two pages rather than one because the
MCP server and the login server are often run by **different companies**, and the MCP server
cannot speak for someone else's login service. That split is also why they are two separate
checks: **#4** asks "is page 1 there, and does it name anyone?", **#10** asks "does page 2
exist, and is it self-consistent?"

The scan downloads both **once** at the start, and every check reads that same copy. Without
that, two checks could fetch the same page moments apart, get different results — the internet
is unreliable — and the report would end up contradicting itself about what the page said.

Every answer carries: which gap, the verdict, the severity, the **evidence** (our request *and* the server's reply), which rule it cites, and a plain-language note.

---

## Using it

```bash
uv sync && uv pip install -e .

uv run mcpauth scan https://host/mcp                 # readable report
uv run mcpauth scan https://host/mcp --json          # machine-readable
uv run mcpauth scan https://host/mcp --tier 1        # only the easy checks
uv run mcpauth scan --list-detectors                 # just list the checks; no address needed
uv run mcpauth scan https://host/mcp --unsafe-writes # OPT IN to #12 and #14; both register clients
                                                     # (records what they create in ./mcpauth-writes.jsonl;
                                                     #  override with --write-journal PATH)
```

**Exit codes** (the number the command leaves behind, so a script can react): **0** nothing found · **1** at least one gap found · **2** the scan failed or the server never answered · **3** you typed the command wrong. 

**Scanning many servers:** `bash reports/run_scans.sh [--tier 1]`. Read-only, and it writes into a brand-new timestamped folder so it can never overwrite evidence a published table relies on.

**Running the DCR-focused write script against real servers:** `reports/run_dcr.py`.
`--dry-run` (the default) is read-only: it lists which servers *offer* self-registration, and flags any that offer it on a **different** host than the one being scanned. `--live` actually writes: one server at a time, one attempt each, deleting what it creates, and it refuses to run against everything unless you add `--yes`. Anything it could not delete is printed under a **`MANUAL CLEANUP NEEDED`** heading.

### Try it on the practice servers

```bash
uv run python sandbox/vulnerable_server.py --port 9100 &   # deliberately wide open
uv run python sandbox/hardened_server.py   --port 9101 &   # deliberately correct
uv run mcpauth scan http://127.0.0.1:9100/mcp

uv run python sandbox/vulnerable_oauth_server.py --port 9110 &
uv run python sandbox/hardened_oauth_server.py   --port 9111 &
uv run mcpauth scan http://127.0.0.1:9110/mcp --tier 2
```

---

## How we know the checks work

`uv run pytest -q` → **213 tests pass.**

The checks are tested against practice servers we wrote and run locally, because no single server can exercise every possible answer. (A server with no login at all can never demonstrate what a *badly worded* "log in first" reply looks like.) So we built one server per posture:

| Practice server | What it pretends to be |
|---|---|
| `vulnerable_server.py` | no login at all; claims to follow the strict rules while breaking them |
| `hardened_server.py` | scores `NO_GAP` on four Tier-1 checks; #2 is `NOT_APPLICABLE` because the server is loopback. **Not a model server, though:** its login-info page gives an address with no port, so that address is unreachable and does not match the server itself |
| `broken_auth_server.py` | it *does* demand a token, but words its refusal wrongly: the `401` carries no pointer to its login-info page, and that page is absent — breaking **RFC 9728 §5.1** and **§3.1**. Our proof that checks **#3, #4 and #10** can spot a real failure |
| `vulnerable_oauth_server.py` | guessable sessions, ignores `Origin`, over-permissive CORS, unencrypted login addresses, the old implicit login style, open self-registration — yet it publishes *valid* login-server info, which is how we prove #10 can also say `NO_GAP` |
| `hardened_oauth_server.py` | passes the established Tier-2 sandbox checks (not #14) — the `NO_GAP` reference for those. **Also not a model server:** its main endpoint answers both the greeting and "list your tools" with no login check at all, so check #1 would rightly flag it. It only ever gets run against Tier 2, which is how that stays hidden (see the blind spots below) |
| `stateful_open_server.py` | **wide open, yet session-based.** A session tag only says same conversation; any stranger gets one through `initialize`. **10 of our 28** wide-open servers issue a tag and require it later, while the other 18 are stateless. This server caught the scanner forgetting to replay that tag and incorrectly returning do not know |
| `subpath_prm_server.py` | correct on the discovery checks while hosted below `/public/mcp`. Its PRM therefore belongs at `/.well-known/oauth-protected-resource/public/mcp`. It is not correct on every check — for example, it does not validate `Origin` |

The 213 tests come in three layers:

- **38 live tests** that scan those practice servers and check the answer for every gap on every posture (`test_tier1.py` 17, `test_tier2.py` 21).
- **111 small tests** of the individual judgement calls with no network involved: is this session tag guessable, is this address unencrypted, which web addresses should we try, is this address safe to fetch, does a name that resolves into private space get refused, was this reply really a login refusal, how do we read an SSE stream, does the version gate compare dates correctly.
- **64 regression/behaviour tests** — 55 covering the roughly 33 bugs we have actually found and fixed (each pinning the wrong answer so it cannot come back; some take several — five cover the handshake bug alone, six the destination guard), plus 9 pinning the two new checks (#13, #14) across their verdict branches. The bug-regression tests have each been checked to **fail** against the code as it was before its fix — one that passes either way pins nothing.

A check is considered finished when both broken and correct behaviour are covered. Twelve checks have live practice-server coverage for both verdicts. #2 is unit-tested because loopback cannot exercise public TLS failure; #14 has mocked behaviour tests but no committed live vulnerable/hardened pair.

---

## Real-world results — 83 public servers

This table is **one consistent run**: a single scan per server on **2026-09-27** covering **all 14 checks** — the twelve read-only ones and the two write checks (`open-dcr` and `improper-redirect-uri-validation`, which really register a client). Raw per-server output is committed in `reports/raw-rescan-2026-09-27/`, with the write journal alongside it. The address list is `reports/endpoints.txt` (83 servers; five endpoints that had gone dead in earlier runs were removed, so there are **no `ERROR` verdicts** here). **Every number below was recalculated from that raw output.**

| Gap | HAS_GAP | NO_GAP | N/A | INCONCLUSIVE | ERROR | Protocol violation if `HAS_GAP`? |
|---|--:|--:|--:|--:|--:|---|
| `no-authentication-remote` | **28** | 42 | 0 | 13 | 0 | No — authentication is a `SHOULD` |
| `no-tls-transport` | 0 | 82 | 0 | 1 | 0 | Conditional — if OAuth is used |
| `missing-www-authenticate` | 0 | 32 | 41 | 10 | 0 | Yes — `2025-06-18` `MUST` |
| `missing-protected-resource-metadata` | 21 | 41 | 0 | 21 | 0 | Conditional — if OAuth is used |
| `session-id-in-url` | 0 | 10 | 0 | 73 | 0 | Not proven — session ID is not an access token |
| `predictable-session-id` | 0 | 10 | 18 | 55 | 0 | Yes — MCP `MUST` |
| `origin-not-validated` | 24 | 10 | 0 | 49 | 0 | Yes — MCP `MUST` |
| `cors-misconfiguration` | 2 | 67 | 0 | 14 | 0 | No — outside MCP |
| `auth-endpoints-not-https` | 0 | 52 | 31 | 0 | 0 | Yes — OAuth endpoints `MUST` use HTTPS |
| `missing-as-metadata` | 12 | 53 | 0 | 18 | 0 | Conditional — if OAuth is used |
| `implicit-flow-enabled` | 0 | 52 | 30 | 1 | 0 | Not proven — legacy support may coexist |
| `open-dcr` | **38** | 0 | 35 | 10 | 0 | No — explicitly permitted |
| `unauthenticated-tool-invocation` | **22** | 48 | 0 | 13 | 0 | No — authentication is a `SHOULD`; real execution is not proven |
| `improper-redirect-uri-validation` | 0 | 23 | 36 | 24 | 0 | Yes — OAuth 2.1 `MUST` / `MUST NOT` (none found) |

Here, **Yes** means a real `HAS_GAP` would directly demonstrate a broken `MUST` or `MUST NOT`. **Conditional** means the rule applies only when optional OAuth authorization is used. **Not proven** means the observation alone does not establish a protocol violation.

**One correction to carry with this table.** `missing-protected-resource-metadata` (21) and `missing-as-metadata` (12) are each at least one too high: we don't follow redirects (correct — RFC 9728 is about *which* host published a document), but a metadata address that answers `307` is currently graded "absent". `hf.co/mcp` does exactly that and its redirect target is a compliant document, so `huggingface` is a false `HAS_GAP` on both rows. True values are ≤20 and ≤11.

Every row covers all 83 servers, scanned in one pass on 2026-09-27.

`open-dcr` run: **38 servers let anyone register a client with no approval.** Of the 10 inconclusive ones, 8 answered `400` and 1 answered `500` (`catalog-api`) — they offer registration but rejected our request, so they are neither open nor proven closed. The 10th (`semgrep`) was never sent a request at all: it advertised registration on `login.semgrep.dev`, a third-party host, and safety rule 2 refused the write — the one time the containment rule has fired in a live run. This run left **76 registrations** behind (38 from `open-dcr`, 38 from `improper-redirect-uri-validation`); see "What we left behind" below.

`improper-redirect-uri-validation` (#14) run: of 47 applicable servers, the current code reports **23 `NO_GAP`, 24 `INCONCLUSIVE`, and 0 `HAS_GAP`**. Sixteen clean results explicitly say the redirect URI was invalid; seven came from PKCE or malformed-request errors, generic errors, or redirects to another login host, which do not prove exact redirect validation. So the run found no accepted bad redirect, but it did not confirm 23 correct implementations.

### The headline

**28 of the 83 servers answer `tools/list` with no login — 438 tools in total.** No rule is broken, since authenticating is only a SHOULD; what's notable is that nothing stops a stranger asking what a server can do. The biggest are `dock` (71 tools), `switch` (69), `gondola` (44) and `nullary` (35).

**Check #13 sharpens this.** Six of those 28 servers answer unauthenticated `tools/call` with HTTP `401`. The remaining 22 return a JSON-RPC reply, proving the request reached MCP dispatch without login. Because the probe names a nonexistent tool, this does **not** prove a real tool would execute; it proves only that catalog access and dispatch access differ on six servers.

They are concentrated among the lesser-known entries. Every recognisable vendor demanded a login: Stripe, Notion, Sentry, Linear, GitHub, PayPal, Square, Wix...
DeepWiki and EdgeOne are open on purpose. EdgeOne’s catalog advertises `deploy-html`, a state-changing tool; the safe #13 probe did not execute it, so this project does not prove it is callable without login.

Two results need context so they aren't over-read:

- `origin-not-validated` (24 servers) is a genuine breach of a MUST, but it mostly hits the same wide-open servers, and the attack it protects against is weak for a normal encrypted public server.
- `cors-misconfiguration` is a general web-security observation. **CORS is not mentioned in the MCP rules**, so we don't actually report it as a rule violation.

### What still limits these numbers

- **55 of the 83 servers never told us which rules version they follow** (21 said `2025-06-18`, 3 said `2025-03-26`, 4 said `2024-11-05`) — because a properly protected server says "log in first" before it gets around to agreeing a version. So the strict standard only ever applied to 21 servers; for the rest, version-dependent checks answer "don't know".
- **We have not implemented the old two-connection SSE greeting**, which is why `session-id-in-url` is "don't know" for 73 of 83.
- **83 servers is a thin sample.** The public directory is far larger — a manual pull stopped after 750 pages / 75,000 entries without reaching the end, so the true total is unknown and at least that. That pull was done by hand and is **not committed here**, so treat the figure as an observation, not as evidence in this repo. These are rates within one small slice, **not** rates across the internet.

**And the framing that matters:** "protected" here means only that the server demanded a login on the first unauthenticated request. It says nothing about whether its login process is sound — whether it checks that tokens were issued for *it*, whether it uses PKCE, whether it keeps users apart. Those were the dropped Tier-3 gaps, and this tool will never report on them. Also: breaking a MUST is not automatically an exploitable hole.

### Finding servers: we don't need Shodan

Shodan's free tier refuses the searches we'd need (it answers `403` once you have zero query credits), so the sibling scanner finds **0 servers** — recorded in `reports/shodan_discovery.md`.

The **official MCP Registry** (`registry.modelcontextprotocol.io/v0/servers`) is free, needs no key, is read page by page, and gives an address plus connection type for each remote entry — ready to feed straight into our scanner.

Free ways to find servers that *don't* advertise themselves: mining certificate transparency logs (a public record of every certificate issued) for `mcp.<company>` names, and searching GitHub for committed `mcp.json` config files. The honest limit: directories only find servers that *chose* to be listed. Genuinely hidden servers still need a paid service or permission to scan.

---

## ⚠ What we left behind — 76 OAuth clients on servers we don't own

The canonical 2026-09-27 run enabled **both** write checks, and each registers a client on every server that offers open registration. It created **76 real client registrations we could not remove** — **38 from `open-dcr` and 38 from `improper-redirect-uri-validation`** — on servers we don't own. They are inert (no password, no data access, nobody has logged in through them), and most such servers expire an unused registration on their own; but until then they are our litter on other people's systems. Every identifier was written to `reports/raw-rescan-2026-09-27/write_journal.jsonl` **before** any cleanup was attempted, so none can be lost.

**Cleanup succeeded 0 times out of 76.** Not one server returned the RFC 7592 fields needed to delete a registration, so the checks' self-cleaning — the thing that made them feel safe to run — works only against our own practice server. Anyone running these checks against real servers should expect every registration to persist until the server expires it. That is why both write checks stay off unless `--unsafe-writes` is passed.

Earlier exploratory runs left more registrations, on overlapping hosts — including the `api.llow.io` write described under safety rule 2 (a client created on a *different* company's server than the one being scanned, which is exactly why the containment rules now exist). Those are recorded in `reports/dcr_scan.prev-1.md`.

**Current decision: leave them in place, keep this record, do not contact anyone.**

---

## The official rules have moved ahead of this tool

During our work, a new MCP revision was published: **`2026-07-28`** (and `2025-11-25` also exists). Our tool speaks `2025-06-18`. Why it matters:

- **Sessions were removed from the protocol entirely in `2026-07-28`** — no session tag, no held-open stream, no "discard this session" request. They existed only in the revisions from `2025-03-26` to `2025-11-25`. So gaps **#5 and #6 describe a generation of the protocol that the rules have since dropped**, and should be presented as tied to those revisions rather than as timeless.
- **The oldest (`2024-11-05`) two-connection style is officially deprecated** and may be removed. So building support for it — which is what gap #5 needs — means investing in something on its way out. Worth a deliberate decision.
- **New per-request requirements we don't yet meet:** two new headers (`Mcp-Method` and `Mcp-Name`) are now required, and their values must agree with the message body. A server that strictly follows the current rules is *entitled to reject every request we send*.
- **A new "tell me about yourself" request (`server/discover`) is now mandatory**, and it is a better opening move than the greeting we currently use. The rules even spell out how to detect which generation a server belongs to.
- **Publishing the login-info page is now required unconditionally**, which makes gap #4 *stronger* — the only one of our checks that the newest rules tightened rather than loosened.
- **Two of our framings are now dated.** First, a login server may now satisfy the rules with *either* RFC 8414 metadata **or** OpenID Connect discovery, so gap #10 must not treat a missing RFC 8414 page as a violation when the other kind is present (the code already tries both). Second, **self-service registration is now deprecated**, kept only for backwards compatibility and replaced by a different mechanism — so gap #12's framing is behind the times.

---

## Known limitations and open work

**Containment** — what rule 2 still permits

- **"Same domain name" is judged by the last two labels only.** So on shared hosting (`*.railway.app`, `*.vercel.app`, `*.github.io`) every unrelated tenant counts as a sibling, and either **write check** is allowed to reach them. Our own address list contains a `railway.app` server, so this is not hypothetical. (A proper fix needs a *public suffix list* — the published register of which name endings are shared, so `railway.app` can be told apart from an ordinary company domain.)
- **Unrelated but public third parties are fetched, by design.** Following a login-info page that names someone else's login server is the normal case, so reads are not confined to the scanned company. Only the two **write checks** are.
- Resolving-to-private names, and the `localhost.` / `0x7f.0.0.1` spellings that used to slip past the loopback check, are now refused at connect time (see safety rule 2).
- **Check #7 leaves one session behind** on every session-based server and never sends the `DELETE` (see safety rule 5).

**Correctness**

- The old two-connection SSE greeting is not implemented, which limits gaps #5 and #6 (see the scope question above).
- When a server sends the same header twice, we keep only the last one — so a correctly-worded reply that offers two login options can be misjudged.
- **No handling of "slow down" (`429`) replies.** All checks fire at once: a measured read-only scan sends **19 requests** in a burst (about **24** with both write checks enabled — `open-dcr` adds a register+delete, `improper-redirect-uri-validation` a register+authorize+delete), and more when the login-info pages take several attempts to locate. If a server starts throttling us, those refusals flow into branches that read them as "the header wasn't there" and produce a confident `NO_GAP` or `NOT_APPLICABLE`. This needs a request budget per server and awareness of `429`.
- Only the *first* login server that answers is examined. Any others are listed in the report as unexamined, but they are not checked.
- **Check #14 over-credits some replies.** It treats every `4xx` and every redirect to a different non-attacker host as `NO_GAP`. Generic errors, missing PKCE, and redirects to an external login host do not prove exact redirect validation; those cases should be inconclusive.
- When reading a stream carrying several replies at once, we don't match a reply to the request that asked for it, so in principle we could return the wrong one.
- The stream-reading code now keeps whatever arrived when a held-open connection goes quiet, but **that path has no live test** (see the blind spot below). It is only exercised against replies that actually end.

**Gaps in our own testing** — each one hides a whole class of possible bug:

- **No practice server holds a connection open, and every real server does.** So the "connection went quiet" handling is only tested in isolation, never against a connection that genuinely stays up.
- No practice server claims a rules version *newer* than `2025-06-18`.
- `hardened_server`'s login-info page is published only at the bare domain, names an address that isn't itself, and points at an unreachable URL — so our "this is what correct looks like" reference for #3 and #4 is not, in fact, correct.
- `hardened_oauth_server`, our Tier-2 "correct" reference, **leaves its main endpoint wide open**: it answers both the greeting and "list your tools" with no login check at all, so gap #1 would rightly flag it. Only its registration address is protected. It serves as the `NO_GAP` reference for six Tier-2 gaps while failing Tier 1 — which never shows up, because those tests only ever run Tier 2 against it.
- `broken_auth_server` and `hardened_server` accept a plain `GET` but then try to read a message body that isn't there, and crash with `500`.
- The Tier-1 and Tier-2 test files throw away their practice servers' output and never check whether they are still alive, so a crashed practice server would be invisible. (The regression test file does this properly — copy its approach.)
- Check #2 (`no-tls-transport`) has **no live test at all**.
- Check #14 has mocked branch coverage but no committed live vulnerable/hardened practice-server pair.

**Not built yet**

- A `discovery.py` that pulls candidate servers from free sources (the official registry first), so a bulk run can feed itself and the Shodan dependency disappears completely.

---

## Working agreement

- **Use simple language. When a technical term appears, define it briefly in parentheses.** We have no background in these networking subjects.
- Reassess the scope at each tier boundary; inside a tier, work independently.
- Keep this document current. It is the single source of truth.
