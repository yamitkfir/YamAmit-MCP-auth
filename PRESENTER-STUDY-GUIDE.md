# Presenter Study Guide — mcpauth

Everything you need to present the deck confidently and answer follow-ups, built from the
actual code (not the slides). Section 1 = every gap #1–#14. Section 2 = terms. Section 3 =
codebase flow & methods. Section 4 = the test taxonomy vs the fleet scan.

File map for anything you want to open live:
- Detectors: [tier1.py](mcpauth/detectors/tier1.py), [tier2.py](mcpauth/detectors/tier2.py), [base.py](mcpauth/detectors/base.py)
- Flow: [runner.py](mcpauth/runner.py), [oauth.py](mcpauth/oauth.py), [probe.py](mcpauth/probe.py), [netguard.py](mcpauth/netguard.py), [models.py](mcpauth/models.py), [cli.py](mcpauth/cli.py)
- Validation: [sandbox/](sandbox/), [tests/](tests/)
- Fleet run: [reports/](reports/) (`endpoints.txt`, `run_scans.sh`, `run_dcr.py`, `raw-rescan-2026-09-27/`)

Fleet run = **83 public servers, one consistent scan on 2026-09-27, 0 ERROR verdicts.**
Verdict columns below are **HAS_GAP / NO_GAP / N/A / INCONCLUSIVE**.

---

## 0. The one-paragraph mental model

For each known auth weakness there is one **detector**. The **runner** does a light
**discovery** pass (an MCP `initialize` handshake, and — if any detector needs it — a fetch
of the OAuth metadata chain), then runs all detectors **concurrently and independently**
(none reads another's result), collects one **Finding** each (a verdict + the raw
request/response evidence + the spec clause), and builds a report. Everything is done from
**outside with no credentials**: the tool never logs in, never sends an `Authorization`
header, and (by default) never writes. Two detectors (#12, #14) do write and are off unless
`--unsafe-writes` is passed.

---

# SECTION 1 — THE 14 GAPS

Each entry: **Rule** (MUST/SHOULD + clause), tier, severity, read/write; what it checks; how
it works in code; the verdicts; the fleet result; and history/gotchas.

Grouping used in the deck: reach-the-tools (**#1, #13**), transport (**#2, #5**), discovery
of the login (**#3, #4, #10**), session & browser (**#6, #7, #8**), OAuth hygiene (**#9,
#11**), writes (**#12, #14**).

---

## #1 — `no-authentication-remote` — can a stranger LIST the tools?
**Rule: SHOULD** (Transports §Security) · Tier 1 · Severity MEDIUM · read-only
Fleet: **28 / 42 / 0 / 13**

**What it checks:** does the server return its tool catalogue to a caller with no
credential? This is **capability *disclosure*** — the menu is readable — **not** proof you
can run anything.

**How it works** ([tier1.py:28](mcpauth/detectors/tier1.py#L28)): send `tools/list` with no
`Authorization` header (but *do* carry the session id if the handshake got one — see
"session id is plumbing" below). Then:
- HTTP 200 + a JSON-RPC `result` with a `tools` array → **HAS_GAP** (reports the tool count).
- HTTP 200 truncated but the visible prefix already shows `"result":` → **HAS_GAP** (via
  `truncated_success`; see history).
- An auth challenge (401, or a *corroborated* 403) → **NO_GAP**.
- A **bare 403** (no `WWW-Authenticate`, no OAuth error code) → **INCONCLUSIVE** ("a blocked
  scan looks the same").
- 200 with a JSON-RPC *error*, or odd statuses (400/404/405/429) → **INCONCLUSIVE** with a
  targeted hint.

**Why only SHOULD / MEDIUM:** the MCP spec says servers *SHOULD* authenticate, so an open
catalogue is **posture, not a broken rule**. Every recognisable vendor (Stripe, Notion,
GitHub, PayPal, …) gated; the open ones cluster among newer/lesser-known servers.

**History/gotcha:** the honest limitation is baked into the docstring — "an ungated
tools/list *implies* an ungated tools/call on the common one-gate architecture, but a server
may gate the two differently," which is exactly why **#13** exists.

---

## #13 — `unauthenticated-tool-invocation` — can a stranger RUN a tool?
**Rule: MUST** (MCP Authorization) · Tier 1 · Severity HIGH · read-only
Fleet: **22 / 48 / 0 / 13**

**What it checks:** the *invocation path* directly — what #1 can only infer. It's the twin of
#1 (added after 1–12, so historical numbering stayed stable; it's a tier-1 mechanism = one
unauthenticated request).

**How it works** ([tier1.py:513](mcpauth/detectors/tier1.py#L513)): send `tools/call` for a
**deliberately non-existent tool** (`__mcpauth_probe_nonexistent_tool__`) with empty
arguments and no `Authorization`. Nothing can execute — a conformant server rejects "unknown
tool" *after* the request has cleared any transport auth gate. What it reads is **where the
rejection came from**:
- 401 / corroborated 403 → **NO_GAP** (gate stopped us before dispatch).
- Any 2xx JSON-RPC reply — `result` OR error — → **HAS_GAP** (the call reached the MCP
  dispatch layer, so invocation is ungated). For a non-existent tool the normal reply is an
  "unknown tool" error, which is exactly the proof.
- **Guard:** if that JSON-RPC error *reads like an auth decision* (`_is_auth_flavoured_error`:
  words like "unauthorized", "token", "403"…) → **INCONCLUSIVE**, because a non-conformant
  server may be reporting auth-failure as a JSON-RPC error instead of the HTTP 401 the spec
  requires. Biases toward INCONCLUSIVE, never toward HAS_GAP.
- bare 403 / odd status → **INCONCLUSIVE**.

**The headline story (slide 20):** of the 28 servers that disclose their catalogue (#1),
**#13 found 22 also let a stranger run a tool, and 6 gate execution** (list → 200, call →
401). So "anyone can use" would over-state by ~a fifth — #13 replaces that inference with a
measurement. The 6 that gate: dock, switch, gondola, api-openmandate, catalog-api,
financial-data.

---

## #2 — `no-tls-transport` — is the traffic actually encrypted?
**Rule: MUST** (OAuth 2.1 §1.5 / MCP Authorization) · Tier 1 · Severity HIGH · read-only
Fleet: **0 / 82 / 0 / 1**

**What it checks:** cleartext HTTP on a public host — **or** HTTPS whose certificate is
broken (expired, self-signed, wrong hostname). "The URL says https" ≠ "TLS works."

**How it works** ([tier1.py:146](mcpauth/detectors/tier1.py#L146)): loopback is
**NOT_APPLICABLE** (cleartext allowed locally). For `https://`: a GET with cert verification
**on** — a TLS handshake failure (`res.tls_failure`) → **HAS_GAP**; unreachable →
INCONCLUSIVE; validates → **NO_GAP**. For `http://` on a remote host: **HAS_GAP** unless it
**redirects to https** (301/302/307/308 with a `https:` Location) → NO_GAP.

**Gotchas/history:** (1) the probe **doesn't follow redirects**, which is what makes the
"redirects to HTTPS" branch reachable *and* keeps document attribution exact. (2) Certificate
verification used to be off wholesale, which silently broke this very check — a forged cert
scored NO_GAP. (3) On loopback there's no public cert to fail, so #2 is **unit-tested**, not
live-tested (a known blind spot).

---

## #5 — `session-id-in-url` — is the session tag leaking in the URL?
**Rule: MUST** (OAuth 2.1 §5; sessions moved to the `Mcp-Session-Id` header) · Tier 1 · MEDIUM · read-only
Fleet: **0 / 10 / 0 / 73**

**What it checks:** is a session identifier carried in the web address/query instead of a
header? URLs leak into logs, browser history, and the `Referer` header.

**How it works** ([tier1.py:412](mcpauth/detectors/tier1.py#L412)): (1) target URL already
has `?session_id=`/`?sid=` → **HAS_GAP**. (2) handshake handed the session back in the
`Mcp-Session-Id` header → **NO_GAP**. (3) fall back to a capped SSE GET: legacy two-channel
SSE servers advertise their POST endpoint (with `?sessionId=`) in an `endpoint` event; if
seen → **HAS_GAP**. Otherwise **INCONCLUSIVE** (server may be stateless — no session at all).

**Why 73 INCONCLUSIVE:** most modern servers are **stateless** (no session issued), so
there's nothing to place in a URL, and the honest answer is "not applicable / can't tell"
rather than a pass. Sessions existed in revisions 2025-03-26 … 2025-11-25 and were **removed
entirely in 2026-07-28**. The fully correct test needs the deprecated two-connection
transport we chose not to implement — say so if asked.

---

## #3 — `missing-www-authenticate` — does the 401 say WHERE to log in?
**Rule: MUST** (MCP Authorization 2025-06-18 → RFC 9728 §5.1) · Tier 1 · MEDIUM · read-only
Fleet: **0 / 32 / 41 / 10**

**What it checks:** when a server *correctly* refuses with 401, does it also point the client
at its login-info page via a `WWW-Authenticate: … resource_metadata="…"` header? This is the
**first step of discovery** (the deck moved it out of "transport" into the discovery group
for exactly this reason).

**How it works** ([tier1.py:219](mcpauth/detectors/tier1.py#L219)): send `tools/list`. If it
was **not** an auth challenge → **NOT_APPLICABLE** (the MUST isn't triggered; note a bare 403
lands here, *not* graded as a malformed challenge — charging a WAF block with an RFC 9728
violation would be a false positive → **41 N/A**). If challenged: parse the header. A usable
absolute `resource_metadata=` URL → **NO_GAP**. Token present but malformed/not absolute →
HAS_GAP (strict) / INCONCLUSIVE (older). No pointer at all → HAS_GAP (strict) / INCONCLUSIVE
(older). **Version-gated** via `targets_strict_spec`.

---

## #4 — `missing-protected-resource-metadata` (PRM) — is the login-info page published?
**Rule: MUST** (RFC 9728 §3.1) · Tier 1 · MEDIUM · read-only · `needs_oauth`
Fleet: **21 / 41 / 0 / 21**  *(this count is ≥1 too high — see hf.co caveat)*

**What it checks:** does the MCP server publish the **Protected Resource Metadata** document
that names its authorization (login) server? Without it, an honest client literally cannot
find where to authenticate.

**The engineering detail worth saying out loud:** RFC 9728 §3.1 locates the document by
**inserting** the well-known segment *before* the resource's path. For `https://host/mcp` the
PRM is at `https://host/.well-known/oauth-protected-resource/mcp` — **not** the bare
`https://host/.well-known/…`. Probing only the bare origin missed it on essentially every
real server (canonical MCP form is `host/mcp`). `prm_candidates()`
([oauth.py:114](mcpauth/oauth.py#L114)) tries the path-inserted form first, then the origin
form.

**How it works** ([tier1.py:304](mcpauth/detectors/tier1.py#L304)): reuses the runner's
**single** discovery fetch (`ctx.oauth`) so #4 and #10 can never disagree about one server;
falls back to its own fetch for a Tier-1-only scan. Grading: document present with a non-empty
`authorization_servers` **array** → NO_GAP; present but the field is the wrong type or
missing/empty → HAS_GAP (graded strictly — the server published RFC 9728 metadata and got it
wrong); document absent → HAS_GAP (strict rev) / INCONCLUSIVE (older). If the PRM's `resource`
field names a different host, a note flags possible mis-attribution (`resource_mismatch`).

**Known caveat (be first to concede it):** `huggingface.co` (hf.co) answers a **redirect** we
grade as "absent," but its target is a valid document — so #4 (and #10) are each at least one
too high. It's the kind of thing an examiner finds by clicking one link.

---

## #10 — `missing-as-metadata` — does the login server describe itself?
**Rule: MUST** (MCP Authorization §2.3.2 → RFC 8414) · Tier 2 · MEDIUM · read-only · `needs_oauth`
Fleet: **12 / 53 / 0 / 18**

**What it checks:** the *second* discovery hop — does the authorization server publish its own
**Authorization Server Metadata** (RFC 8414: grant types, endpoints, registration endpoint),
and does it correctly name itself? Two checks (#4 and #10) because the two pages are often run
by **different companies**.

**How it works** ([tier2.py:589](mcpauth/detectors/tier2.py#L589)): reads `ctx.oauth`. If AS
metadata resolved: **issuer match** check — RFC 8414 §3.3 says metadata whose `issuer` ≠ the
requested issuer **MUST NOT be used** → that's a **HAS_GAP** (`issuer_mismatch`); a clean match
→ NO_GAP. If no AS metadata: HAS_GAP (strict) / INCONCLUSIVE (older). The candidate URLs
(`as_metadata_candidates`, [oauth.py:127](mcpauth/oauth.py#L127)) cover RFC 8414's inserted
form **and** OpenID-Connect forms (since 2026-07-28 a server satisfies discovery with either).

---

## #6 — `predictable-session-id` — are session tags guessable?
**Rule: SHOULD** (Transports §Session Mgmt; Security Best Practices §Session Hijacking says MUST) · Tier 2 · MEDIUM · read-only
Fleet: **0 / 10 / 18 / 55**

**What it checks:** can an attacker guess a valid session id? (A session id is
bearer-equivalent for the life of a conversation.)

**How it works** ([tier2.py:51](mcpauth/detectors/tier2.py#L51)): open up to **5** sessions
(counting the one the handshake already opened), collect the ids, then **DELETE the extras it
opened** (so the check stays read-only in effect). `_assess_session_ids` checks, in order of
conclusiveness: identical id twice (deterministic → HAS_GAP), sequential integers
(counter → HAS_GAP), constant prefix + numeric suffix (→ HAS_GAP), then an **entropy floor**.

**The key idea to present — "length is not entropy":** the estimate is `length ×
log2(alphabet size)`, floored at **64 bits**. The old rule "shorter than 16 chars = weak" got
both directions wrong: it flagged a 15-char random base64url token (~89 bits, strong) and
passed a 16-digit numeric id (~53 bits, brute-forceable). Alphabets are ordered smallest-first
so `1234` is graded as 4 digits (10 symbols), not base64url. Conservative → a NO_GAP means "no
weakness of these four kinds found," not "provably strong." 55 INCONCLUSIVE largely because
most servers are stateless (no session to sample).

---

## #7 — `origin-not-validated` — is a forged Origin accepted? *(special attention)*
**Rule: MUST** (Transports §Security Warning — DNS-rebinding) · Tier 2 · Severity HIGH · read-only
Fleet: **24 / 10 / 0 / 49**

**What it checks:** does the server reject a request carrying a forged `Origin` header?
Origin validation is the defence against **DNS rebinding** (a malicious web page in the
victim's browser rebinding a name to a local address to reach a server that trusts
"localhost"). It is **mainly a threat to local/loopback servers**; for a remote HTTPS server
it's largely ceremonial — be ready to say that honestly.

**How it works** ([tier2.py:310](mcpauth/detectors/tier2.py#L310)): send `initialize` with
`Origin: https://evil.attacker.example`.
- 200 with a valid result → **HAS_GAP** (accepts cross-origin requests it should reject).
- **403 → the clever bit: a control request.** A 403 *alone proves nothing* — the server
  might refuse everything. So it sends a **second** `initialize` with **no Origin** header:
  - control **succeeds** and forged was 403 → **NO_GAP** (genuinely validating Origin).
  - control **also 403** → **INCONCLUSIVE** (server refuses everything; not attributable to
    Origin).
  - control **never completes** → **INCONCLUSIVE** (can't claim a comparison we didn't
    observe).
- auth-gated before any Origin decision → INCONCLUSIVE.

**The regression story (ties to slide 23):** before the control request, a
`403 {"error":"Missing API key"}` was credited as "server validates Origin" — asserting a
comparison that never happened. Test: `test_origin_detector_needs_a_completed_control_request`.

**Likely Q:** *"Why 24 HAS_GAP if it's mostly ceremonial for remote servers?"* — Because the
spec states it as an unconditional MUST ("validate Origin on **all** incoming connections"),
so a remote server that accepts a forged Origin is non-compliant even where the practical risk
is low. We report the rule violation and are honest about the real-world severity.

---

## #8 — `cors-misconfiguration` — may any website call it with credentials? *(special attention: CORS)*
**Rule: non-MCP** (general web security) · Tier 2 · MEDIUM · read-only
Fleet: **2 / 67 / 0 / 14**

**First thing to say:** **CORS is NOT in the MCP spec.** This is the **only** check graded as
a general web-security heuristic, never cited as an MCP violation. It's kept because it costs
one request and is clearly labelled. It's "our weakest check," and honesty about that is a
strength, not an embarrassment.

**What CORS actually is (for the audience):** browsers enforce the **same-origin policy** —
JavaScript on `site-a.com` can't read responses from `site-b.com` by default. **CORS**
(Cross-Origin Resource Sharing) is how a server *opts in* to being called cross-origin, via
response headers: `Access-Control-Allow-Origin` (who may call) and
`Access-Control-Allow-Credentials: true` (may they send cookies/credentials). The dangerous
combo is **reflecting an arbitrary Origin back *and* allowing credentials** — then *any*
website a victim visits can make authenticated calls to the server as that victim.

**How it works** ([tier2.py:416](mcpauth/detectors/tier2.py#L416)): send a preflight
`OPTIONS` (fall back to a GET) carrying `Origin: https://evil.attacker.example`.
- reflects the evil Origin **and** `Allow-Credentials: true` → **HAS_GAP**.
- reflects it but **no** credentials → INCONCLUSIVE (lower risk).
- `Access-Control-Allow-Origin: *` → **NO_GAP** (browsers refuse to send credentials to a
  wildcard, so no credentialed theft) — *but* the note adds: if the server needs no auth
  anyway (#1), any web page can still drive it directly.
- fixed/other origin, or no ACAO header at all → **NO_GAP** (MCP clients aren't browsers).

**Likely Q:** *"Why include a non-MCP check at all?"* — Because a browser-based MCP client is
a real deployment, and a credentialed-CORS misconfig is a genuine account-takeover vector; we
include it, label it clearly as non-spec, and only 2 servers tripped it.

**Likely Q:** *"How is #8 different from #7?"* — #7 (Origin) is the server rejecting a forged
Origin on the *request*; #8 (CORS) is the server *telling the browser* it's allowed to make
credentialed cross-origin calls in the *response*. Different direction, different mechanism;
#7 is an MCP MUST, #8 is not in the spec.

---

## #9 — `auth-endpoints-not-https` — any login address on plain http?
**Rule: MUST** (OAuth 2.1 §1.5 & MCP Authorization §2.8; RFC 8414) · Tier 2 · HIGH · read-only · `needs_oauth`
Fleet: **0 / 52 / 31 / 0**

**What it checks:** among the OAuth URLs the server *advertises* (the `authorization_servers`
list plus the endpoint fields inside AS metadata — issuer, token, registration, jwks_uri, …),
is any served over cleartext `http` on a public host? Tokens/codes would travel exposed.

**How it works** ([tier2.py:512](mcpauth/detectors/tier2.py#L512)): pure **read of the
already-fetched metadata** — makes no request of its own. Any insecure-http URL → HAS_GAP;
all https/loopback → NO_GAP; nothing discovered → N/A. Crucially, if the AS metadata is
**unusable** (issuer mismatch, per #10 / RFC 8414 §3.3) it is **not read here** — otherwise
one report would contradict itself.

---

## #11 — `implicit-flow-enabled` — still offering the removed implicit flow? *(special attention)*
**Rule: MUST NOT** (OAuth 2.1 §1.8 removed the implicit grant) · Tier 2 · HIGH · read-only · `needs_oauth`
Fleet: **0 / 52 / 30 / 1**

**What the implicit flow is (for the audience):** the old OAuth "implicit" grant returned the
**access token directly in the redirect URL fragment** (`#access_token=…`). That means the
token lands in browser history, `Referer` headers, and server logs — it leaks. OAuth 2.1
**removed** it in favour of the **authorization-code flow** (the server returns a short-lived
*code* in the URL, which the app then exchanges for a token over a back-channel POST — the
token never rides in a URL).

**How it works** ([tier2.py:670](mcpauth/detectors/tier2.py#L670)): read the AS metadata's
`response_types_supported` / `grant_types_supported`. Present a `token` response type or an
`implicit` grant → **HAS_GAP**. Neither → NO_GAP. Metadata unusable/absent → N/A /
INCONCLUSIVE.

**The subtlety to present (ties to slide 15):** OAuth response types are **space-delimited
sets** — a single advertised entry can be `"id_token token"` (the *hybrid* flow), which still
includes `token`. `_response_type_values` ([tier2.py:649](mcpauth/detectors/tier2.py#L649))
**splits each entry on spaces** and tests membership, so `"id_token token"` is correctly
flagged. A naive `"token" in [list]` matched only a *bare* `"token"` entry and missed every
combined advertisement. (We also deliberately do **not** flag a *missing*
`grant_types_supported` as HAS even though RFC 8414's default technically includes implicit —
that default is a frequent false positive.)

---

## #12 — `open-dcr` — can anyone register a client? *(WRITE)*
**Rule: SHOULD** (RFC 7591 §3 permits open registration) · Tier 2 · HIGH · `has_side_effects` · `needs_oauth`
Fleet: **38 / 0 / 35 / 10**

**What DCR is:** **Dynamic Client Registration** (RFC 7591) lets an app register itself with
the authorization server automatically — no human sign-up. "**Open**" means it accepts
registrations with **no initial access token** (no review/vetting): anyone can mint a client.

**Why it's reported as posture, not a violation:** RFC 7591 §3 actually *permits* open
registration (a SHOULD). But an unauthenticated registration endpoint is the **prerequisite
for the confused-deputy / consent-phishing attack** and for registration flooding, and it's
the one piece of the identity-confusion risk visible without a token — so we report "open" as
a security-relevant posture and say exactly that.

**How it works** ([tier2.py:872](mcpauth/detectors/tier2.py#L872)): needs usable AS metadata
with a `registration_endpoint`. **Containment first** (`_write_target_refusal`): the endpoint
was chosen by the scanned server, and this is a *write*, so it may only go to the target or a
**same-registrable-domain sibling** over https — otherwise INCONCLUSIVE, no request made. Then
POST a throwaway RFC 7591 registration with **no** auth. Grading by **HTTP status, not body
parseability**:
- any 2xx → a client was created → **HAS_GAP**; then attempt **RFC 7592 cleanup** (DELETE the
  returned `registration_client_uri` with the returned token). Cleanup is OPTIONAL, so it
  often fails — the note then shouts `MANUAL CLEANUP NEEDED` and names the client id.
- auth challenge → NO_GAP (registration requires a token).
- bare 403 → INCONCLUSIVE.

**The 3-step attack chain (slide 21):** register a legitimate-looking client → lure a user
into approving it → receive tokens issued for that user.

---

## #14 — `improper-redirect-uri-validation` — accepts an unregistered return address? *(WRITE, special attention)*
**Rule: MUST** (OAuth 2.1 §7.5.4 — AS MUST validate exact redirect URIs, MUST NOT redirect to an invalid one) · Tier 2 · HIGH · `has_side_effects` · `needs_oauth`
Fleet: **0 / 23 / 36 / 24**

**What it checks (the attack it models):** after login, the authorization server sends the
user back to a **redirect URI** carrying the authorization **code**. If the AS will send the
user to an address the client **never registered**, an attacker can craft an authorize link,
lure a user, and **capture the code (and thus the token)**. OAuth 2.1 requires **exact-match**
validation against pre-registered values.

**Why it must write (why it's off by default):** to test "an *unregistered* redirect URI for a
*known* client," you must first *have* a known client — which means a real RFC 7591
registration, exactly like #12. It only applies where **DCR is open** (otherwise there's no
way to get a client without human sign-up).

**How it works** ([tier2.py:1129](mcpauth/detectors/tier2.py#L1129)):
1. Needs usable AS metadata with **both** `authorization_endpoint` and
   `registration_endpoint`. Containment-check the registration endpoint (same rule as #12).
2. Register a throwaway client with **one** known redirect URI
   (`https://mcpauth-callback.example/cb` — `.example` is RFC 6761 reserved, non-resolving, so
   nothing could ever be sent anywhere real). Journal it before anything that can fail.
3. Send **one** unauthenticated GET to the authorization endpoint carrying a **different,
   unregistered** redirect URI (`https://mcpauth-attacker.example/steal`) — SSRF-guarded.
4. Read **only where the server tried to send the browser** (the `Location` header):
   - redirect to the **unregistered** host → **HAS_GAP** (didn't validate — the real gap).
   - redirect to its **own login page** → **INCONCLUSIVE** (defers redirect validation until
     after login, which this unauthenticated probe can't reach).
   - 4xx rejection → **NO_GAP** (consistent with validating).
   - redirect somewhere else / other → NO_GAP / INCONCLUSIVE.
5. **Always clean up** (RFC 7592 DELETE) in a `finally`, journalling the outcome.

**The finding & its meaning (slide 22):** **0 real findings.** Of **47 testable** servers,
**23 correctly rejected** the bad address and **24 were INCONCLUSIVE** — the "200 login page"
case, where the AS shows its login form before validating, and completing the flow would
require logging in, which we never do. **This is the strongest concrete example of why
INCONCLUSIVE is a real verdict** (slide 7).

**The insight (slide 22 / connects to conclusion):** only servers running a *working* OAuth
registration-and-authorize flow were even testable, and none mishandled the redirect address —
**secure behaviours cluster**: a server built well enough to run this flow also validates the
redirect URI.

**Why #12 shows 35 N/A but #14 shows 36 N/A** (a likely sharp question): #14 has a **stricter
applicability precondition**. #12 is testable wherever a *registration endpoint* is advertised
(48 applicable). #14 additionally needs a client to actually *register* **and** a reachable
`/authorize` endpoint (47 applicable). The single differing server is **`catalog-api`**: #12
could probe its registration (INCONCLUSIVE) but no usable client could be established, so #14
was NOT_APPLICABLE there.

**The cost (kept in your back pocket — dropped from the slide):** running the two write checks
across the fleet created **76 client registrations** (≈38 from #12, ≈38 from #14) that **could
not be deleted — 0 of 76 cleaned up**, because not one real server returned the RFC 7592
management fields. That's the honest cost of write-class probing: zero findings, real litter
left behind. It's why both write checks stay off unless `--unsafe-writes` is passed. (All are
inert public clients that expire on their own, and every id was journalled before any delete
attempt.)

---

# SECTION 2 — TERMS GLOSSARY

- **MCP (Model Context Protocol):** a protocol (published by Anthropic) that lets an AI
  assistant call outside **tools** over HTTP. A tool call is an HTTP request carrying a
  **JSON-RPC** message. The protocol standardises the messages; it leaves **security
  optional**.
- **JSON-RPC:** "call a named method with parameters, get a result or an error." MCP uses
  `initialize` (open the conversation), `tools/list` (read the catalogue), `tools/call`
  (invoke a tool). A **notification** is a JSON-RPC message with **no `id`** (so the server
  doesn't reply) — e.g. `notifications/initialized`.
- **Streamable HTTP:** the modern MCP transport (one HTTP endpoint). The older **SSE / two
  connection** transport (2024-11-05) used a separate GET stream + POST endpoint; we did not
  implement it (relevant to #5).
- **Authentication vs Authorization:** authentication = *proving who you are* (showing your
  ticket). Authorization = *what you're allowed to do* once known. MCP forces **neither**;
  both are the implementer's job to enforce.
- **OAuth 2.1:** the login framework MCP adopted. You log in at a separate **authorization
  server**, which issues the app a **token**. MCP wrote rules for how servers must use it.
- **Token:** a digital ticket — **bearer**, so whoever holds it gets in; a stolen token is as
  good as the original. Never belongs in a URL.
- **Session id (`Mcp-Session-Id`):** a temporary "same conversation" label the server may
  hand back on `initialize`. **Plumbing, not a credential** — that's why the scanner *replays*
  it while still sending no `Authorization` header (otherwise a wide-open stateful server that
  merely wants a session id would answer 400 and look secured). Removed from the spec in
  2026-07-28.
- **PRM — Protected Resource Metadata (RFC 9728):** a small JSON document the **MCP server**
  publishes that names its authorization server(s). Discovery hop 1. Located by **path
  insertion**: `https://host/.well-known/oauth-protected-resource/<path>`. (Checked by #4.)
- **AS Metadata — Authorization Server Metadata (RFC 8414):** the document the **login
  server** publishes describing itself (grant types, endpoints, registration endpoint, PKCE
  methods). Discovery hop 2. (Checked by #10.) Often OpenID-Connect-shaped
  (`/.well-known/openid-configuration`).
- **`WWW-Authenticate` header:** on a 401, the standard "here's how/where to log in" pointer;
  RFC 9728 §5.1 makes it carry the `resource_metadata="…"` URL (the authoritative PRM
  location). (Checked by #3; also used to seed discovery.)
- **DCR — Dynamic Client Registration (RFC 7591):** an app registering itself with the login
  server automatically. **RFC 7592** is the companion for *managing/deleting* a registered
  client (the cleanup path — OPTIONAL, which is why cleanup usually fails). (Checked by #12.)
- **`redirect_uri`:** where the login server sends the user back after login, carrying the
  authorization code. Must be exact-matched against pre-registered values. (Checked by #14.)
- **Authorization-code flow vs Implicit flow:** code flow returns a short-lived **code** in
  the URL, exchanged for a token over a back-channel (token never in a URL). **Implicit** put
  the **token** straight in the URL fragment — leaky, removed by OAuth 2.1. (Checked by #11.)
- **PKCE (Proof Key for Code Exchange):** an extension proving the app that *finishes* a login
  is the one that *started* it (defeats code interception). **We cannot verify PKCE** without
  completing a login, so it's out of scope — a good example of the boundary if asked.
- **Confused deputy:** a trusted program tricked into misusing its authority on someone else's
  behalf. Two senses here: (a) the *attack* open DCR enables (a malicious client riding a
  user's consent), and (b) the *scanner itself* becoming one if it blindly followed
  target-chosen URLs — which is what **containment** prevents.
- **SSRF (Server-Side Request Forgery):** making a server issue requests to
  attacker-chosen destinations (e.g. internal services, cloud metadata at `169.254.169.254`).
  The netguard layer exists to stop the scanner being used for SSRF.
- **DNS rebinding:** an attacker re-points a hostname to an internal address *after* a check
  passed, to reach a server that trusts local callers. Countered by validating **Origin** (#7)
  and by resolving/guarding at **connect time** (netguard layer 2).
- **Verdicts:** `HAS_GAP` (weakness present), `NO_GAP` (correctly defended), `NOT_APPLICABLE`
  (can't apply — wrong transport/spec rev/no feature), `INCONCLUSIVE` (probe ran, evidence
  ambiguous), `ERROR` (probe couldn't complete).
- **Version gating (`targets_strict_spec`):** MCP revisions are `YYYY-MM-DD` strings; the tool
  compares `>= 2025-06-18` (the first revision where RFC 9728/audience rules are MUSTs). Newer
  revisions keep the requirement, so it's `>=`, not `==`.
- **Two populations:** the **83 public servers** (from the official **MCP Registry**) we
  *measure*; the **7 local practice servers** (`sandbox/`) we built to *validate the scanner*.

---

# SECTION 3 — CODEBASE FLOW & METHODS

## 3.1 Entry point — the CLI ([cli.py](mcpauth/cli.py))
`mcpauth scan <url> [--tier N] [--exclude gap-id] [--unsafe-writes] [--insecure-tls]
[--write-journal PATH] [--json] [--list-detectors]`.
- Validates the URL (rejects a bare host or unknown scheme — a missing scheme used to produce
  12 confident false NOT_APPLICABLEs). Rejects mistyped `--tier` / `--exclude` (a mistyped
  exclude once left a write enabled).
- **Writes are off by default:** unless `--unsafe-writes`, the write detectors are added to
  the exclude set. With it, a **write journal** sink is created (append + `fsync` per record,
  plus a stderr line) and a loud warning is printed.
- **Exit codes** (so a bulk runner can branch): 0 clean, 1 gap found, 2 scan failed, 3 usage
  error.

## 3.2 One scan — `scan()` ([runner.py:121](mcpauth/runner.py#L121))
1. Build the `TargetSpec` and the detector list (`build_detectors` applies tier/exclude
   filters).
2. Open the shared **`Probe`** (an `async with`): one aiohttp session with TLS verification
   **on** and the **contained resolver** installed.
3. **Discovery** (`_discover`, only for HTTP transports):
   - **Handshake** (`_handshake`): POST `initialize` → capture the `Mcp-Session-Id`, the
     `WWW-Authenticate` challenge, `serverInfo`, and the negotiated **protocolVersion**
     (preferring the value in the body over the header). Set that version on the probe so
     every later request advertises it. If a session id came back, send
     `notifications/initialized` (a real notification — no `id`).
   - If **any** selected detector sets `needs_oauth`, fetch the OAuth chain once
     (`discover_oauth`) into `ctx.oauth`.
   - Failures are **non-fatal** — detectors still run and report ERROR/INCONCLUSIVE.
4. **Concurrent, independent execution:** `asyncio.gather(run_one(d) …)`. Each detector reads
   only `ctx` (never another's Finding), so order never changes a result. A detector that
   raises becomes an **ERROR Finding** (with evidence), not a crashed scan.
5. **Release** the handshake session (`_release_session`: DELETE with the negotiated version).
6. **Build the report** (`_build_report`): verdict counts, per-gap findings (`to_dict`),
   discovery notes, and an `oauth` summary (PRM/AS URLs, blocked URLs, external hosts). A full
   read-only scan is ~19 requests.

## 3.3 OAuth discovery — `discover_oauth()` ([oauth.py:241](mcpauth/oauth.py#L241))
Fetched **once** so the four OAuth detectors (#9–#12) and #4/#10 all reason about the *same*
documents and can't contradict each other.
- **PRM (RFC 9728):** try, in order, the `resource_metadata` URL from the 401 challenge
  (authoritative), then the **path-inserted** well-known URL, then the bare origin. Validate
  `authorization_servers` (must be an array; a bare JSON string used to be iterated
  *character by character*; capped at **5** to stop a hostile PRM amplifying into a flood).
  Flag `resource_mismatch` if the PRM's `resource` names a different host.
- **AS metadata (RFC 8414):** for each PRM-listed issuer, try the inserted OAuth form + two
  OpenID-Connect forms; first hit wins. Check the returned `issuer` matches (RFC 8414 §3.3 —
  mismatch ⇒ `MUST NOT use`, surfaced as `as_metadata_usable = False`). Record the servers not
  resolved. Fallback: try the target's **own origin** (many MCP servers are their own AS).
- **Every** post-first-hop URL passes the SSRF guard before it's fetched.

## 3.4 The probe — HTTP/JSON-RPC client ([probe.py](mcpauth/probe.py))
- Thin aiohttp wrapper; **never raises on status** (detectors interpret status themselves).
- **Does not follow redirects** — so document attribution stays exact (RFC 9728 is about
  *which host* published a document) and the #2 redirect-to-HTTPS branch is reachable.
- **Byte-capped incremental body read** (1 MB cap, read in a loop): a single `read(cap)`
  returned only the first buffered chunk while claiming complete — a 91,703-byte `tools/list`
  came back as 8 KB of clipped JSON, downgrading a real finding. `truncated_success` salvages
  a verdict from a clipped body that already shows `"result":`.
- **SSE parsing** (`_parse_sse`): joins multi-line `data:` fields (a pretty-printed JSON-RPC
  message spans several lines); flushes trailing data because of the byte cap.
- **`MCP-Protocol-Version`** sent on every POST (required since 2025-06-18), echoing the
  negotiated revision.
- **Secret redaction** (`redact_secrets`): `client_secret`, tokens, codes are replaced with
  `[REDACTED]` before anything is written — the field **name** stays (that a secret was issued
  is itself evidence), the value never reaches a saved report.
- **Timeouts:** a total budget *and* a separate `sock_connect` budget, so `connect_failed`
  can distinguish "the POST never reached the server" (nothing created) from "the reply was
  lost" (a client may exist) — the distinction #12/#14 need to avoid inventing or hiding a
  cleanup obligation.
- **`HttpResult`** records the **request as well as the response** (method, rpc method, chosen
  headers, final URL) — that's the unit of evidence.

## 3.5 Containment — two layers ([netguard.py](mcpauth/netguard.py))
Almost every URL fetched after the first is **chosen by the scanned server** (its
`authorization_servers`, endpoint URLs, `registration_endpoint`, the
`registration_client_uri` it returns, the 401 `resource_metadata` pointer). Following those
blindly makes the scanner a **confused deputy / SSRF vector**.
1. **String predicates** (before a fetch): `ssrf_reason` refuses non-http(s) schemes and
   internal destinations *written as IP literals* (loopback, RFC 1918, link-local incl. the
   `169.254.169.254` cloud-metadata address, CGNAT, etc.). `same_site` / `registrable_domain`
   confine the **one write** to the target or a same-domain sibling.
2. **Connect-time resolver** (`_ContainedResolver` → `resolved_address_reason`): judges what a
   hostname actually **resolved to**, at connect time — catching `intranet.example.com` that
   points into private space, and closing the **DNS-rebinding** window. Refuses if **any**
   resolved address is internal (split-horizon safety).

**The real incident to tell (slide 9):** scanning `api.serff.ai`, an early version followed
that server's own metadata to a registration endpoint on `api.llow.io` — a different company —
and registered a client there. Containment was added in response; it has since blocked one
cross-domain write (to `login.semgrep.dev`).

**Honest limits (say them):** `registrable_domain` is a two-label approximation with no
public-suffix list, so tenants of a shared suffix (`railway.app`, `vercel.app`) look like
siblings; and unrelated *public* third parties are allowed for **reads** by design (following
a PRM that names someone else's AS is normal).

## 3.6 Verdict-shaping helper — `is_auth_challenge` ([base.py:37](mcpauth/detectors/base.py#L37))
The single most important calibration in the tool. A **401** = unambiguous challenge. A
**403** counts as an auth challenge **only with corroboration** — a `WWW-Authenticate` header
or a real OAuth error code (`invalid_token`, `insufficient_scope`, `invalid_client`,
`unauthorized_client`) that appears as the body's `error` **field** (not just a substring).
Otherwise a bare 403 (WAF, geo-block, bot filter) is **not** evidence of auth — crediting it
was "the worst possible direction" for #1 to err. Deliberately excludes `invalid_request`
(means "malformed", the opposite of an auth decision) and `access_denied` (a consent refusal).

## 3.7 The write journal ([cli.py:103](mcpauth/cli.py#L103), [tier2.py:794](mcpauth/detectors/tier2.py#L794))
`_record_write` is called **at each moment the obligation changes** (created → cleanup
outcome), not once at the end, and **never raises**. The library never picks a path; the CLI
supplies the sink (append + `fsync`, plus stderr). Before this existed, a created `client_id`
lived only in the returned Finding, so a Ctrl-C/timeout during cleanup orphaned a real
registration on someone else's server with its id nowhere.

## 3.8 Fleet-run tooling ([reports/](reports/))
- `endpoints.txt` — the 83 targets (`shortname|url`; the `dock`/`gondola`/… aliases).
- `run_scans.sh` — drives the CLI (read-only) over every endpoint, branching on exit code
  (retries on transport failure, not on usage errors).
- `run_dcr.py` — the `--unsafe-writes` fleet driver for #12/#14, wiring the write journal;
  its per-server timeout spans POST + DELETE (why journalling-before-cleanup matters).
- `raw-rescan-2026-09-27/` — the canonical run: one JSON report per server + a
  `write_journal.jsonl`. Every headline number in the deck is re-derivable from here.
- `dcr_scan.md` — the write-run summary (open DCR + the 0/76 cleanup result).

---

# SECTION 4 — TESTS: THE AUTOMATED SUITE vs THE FLEET SCAN

Two different things people conflate; keep them straight.

## 4.1 Two server populations
- **83 public servers** (the **MCP Registry**): the *subjects of measurement*. The fleet scan
  (Section 3.8) points the finished tool at them and records verdicts. This is the **result**.
- **7 local practice servers** (`sandbox/`): the *instruments of validation*. We wrote them so
  we can prove each detector gives the right answer, because no single real server exercises
  every HAS *and* NO path (a no-auth server can never demonstrate a *badly worded* 401). This
  is how we trust the tool.

## 4.2 The 7 practice servers (`sandbox/`)
| Server | Posture it plays |
|---|---|
| `vulnerable_server.py` | no login at all; claims strict spec while breaking its MUSTs |
| `hardened_server.py` | correct on the Tier-1 checks (the NO_GAP reference); #2 is N/A on loopback |
| `broken_auth_server.py` | *does* demand a token but challenges non-compliantly — the HAS anchor for #3/#4/#10 |
| `vulnerable_oauth_server.py` | guessable sessions, no Origin check, reflecting CORS, http OAuth URLs, implicit grant, open DCR — but serves *valid* AS metadata (so #10 can say NO_GAP) |
| `hardened_oauth_server.py` | passes the established Tier-2 checks (the NO_GAP reference); only ever run against Tier 2 |
| `stateful_open_server.py` | wide open *and* session-based — caught the scanner forgetting to replay the session tag |
| `subpath_prm_server.py` | correct discovery while hosted under `/public/mcp` — proves the RFC 9728 §3.1 path-insertion |

## 4.3 The 213 automated tests come in three layers
- **38 live tests** ([test_tier1.py](tests/test_tier1.py) 17 + [test_tier2.py](tests/test_tier2.py) 21): boot the practice servers as real subprocesses, scan them, and assert the **verdict for every gap on every posture**. These are the **"scanner gap tests"** — a check is "done" only when it says **HAS_GAP against the broken server AND NO_GAP against the correct one** (catches both failure modes: missing a real gap, and crying wolf). Driven by an `EXPECTATIONS` table (`gap_id → {posture: expected verdict}`).
- **111 unit tests** ([test_units.py](tests/test_units.py)): pure judgement calls, **no network** — is this session id guessable, is this URL insecure http, which well-known URLs to try, is this destination safe to fetch, does a name resolving into private space get refused, was this reply really a login refusal, does the version gate compare dates correctly, SSE parsing.
- **64 regression/behaviour tests** ([test_regressions.py](tests/test_regressions.py)): **55** pin real bugs we found and fixed (each checked to **fail** against the pre-fix code — one that passes either way pins nothing; ~33 distinct bugs, some needing several tests — **5** for the handshake bug, **6** for the destination guard), plus **9** pinning the two new checks (#13, #14) across their verdict branches.

## 4.4 How the layers map to the flow (Section 3)
- **Discovery/handshake** (3.2) ← regression tests (`_handshake` bug: stateful servers, session replay, `notifications/initialized` has no id, protocol-version echo).
- **OAuth discovery / path insertion** (3.3) ← `subpath_prm_server` live tests + unit tests on `prm_candidates` / `as_metadata_candidates`.
- **Containment** (3.5) ← unit tests on `ssrf_reason`/`same_site`/`is_internal_host` + regression tests (public name → internal address refused; split-horizon; target may still resolve internally; blocked ≠ TLS failure — the "6 for the destination guard").
- **Probe evidence** (3.4) ← regression tests (oversized tool list still HAS_GAP; truncated error not read as success; large body read in full; secret redaction; connect-timeout not logged as a delivered POST) + SSE unit tests.
- **Write machinery** (3.7) ← regression tests (client id journalled before cleanup; journal failure doesn't break the scan; non-success reply naming a client id isn't journalled as created; CLI supplies a journal when writes enabled).

## 4.5 Honest blind spots (own them before you're asked)
- **#2 (TLS)** has no live test — every practice server is on loopback (TLS-exempt), so its
  logic is unit-tested only.
- **#14** has mocked behaviour tests but **no committed live vulnerable/hardened pair**.
- The **SSE "connection went quiet"** salvage path has no live test — no practice server holds
  a connection open (every real one does).
- **No practice server claims a revision newer than 2025-06-18.**
- The tier-1/tier-2 test files don't check whether their practice servers stayed alive, so a
  crashed practice server would be invisible (the regression file does this properly).

---

## Quick-reference cheat sheet (numbers you'll be asked)

- 14 checks = 12 read-only + 2 write. 5 verdicts. Scope = advertise + enforce, **not**
  soundness (no login → hop 2 invisible).
- Fleet: 83 servers, 2026-09-27, 0 ERROR. #1 = **28** disclose; #13 = **22** invocable (6
  gate); #12 = **38** open DCR; #14 = **0** findings (47 testable: 23 reject, 24 inc).
- 438 tools reachable across the 28; top servers dock 71, switch 69, gondola 44, nullary 35.
- Writes left **76** registrations, **0** cleaned (no server returned RFC 7592 fields).
- Tests: **213** = 38 live + 111 unit + 64 regression. **7** practice servers.
- Spec drift: sessions removed 2026-07-28; servers self-report their revision, installed base
  lags, so #5/#6 still describe real servers scanned.
