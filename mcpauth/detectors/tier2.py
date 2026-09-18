"""Tier 2 detectors — medium: crafted headers, chained metadata, multi-sample.

Each class maps exactly one gap (6–12) from the catalog in README.md and is independent of the
others. The four OAuth-metadata detectors (#9–#12) read the PRM -> AS-metadata chain
that the runner fetched once into `ctx.oauth`; they never re-derive it or read another
detector's Finding.

Honesty notes baked into the verdicts (see the constraints rules):
  * #8 cors-misconfiguration is NOT addressed by the MCP spec — it is graded as a
    general web-security heuristic, never cited as a spec violation.
  * #12 open-dcr: RFC 7591 §3 actually SAYS open registration SHOULD be supported.
    We report "open" as a security-relevant posture (it is the prerequisite for the
    confused-deputy attack, #16), not as a spec violation — the note says so, and the
    detector performs a real registration POST (a write) which the docs flag.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlsplit

from ..models import ProbeContext, Severity, Verdict
from ..netguard import is_loopback_host as _is_loopback_host
from ..netguard import same_site as _same_site
from ..probe import Probe, jsonrpc_result, truncated_success
from .base import Detector, is_auth_challenge

# Endpoint fields in RFC 8414 AS metadata that name a URL we can check / use.
_AS_ENDPOINT_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "userinfo_endpoint",
    "device_authorization_endpoint",
    "jwks_uri",
)


def _insecure_http(url: str) -> bool:
    """True if `url` is cleartext http on a non-loopback host (OAuth 2.1 §1.5 violation)."""
    p = urlsplit(url)
    return p.scheme.lower() == "http" and not _is_loopback_host(p.hostname or "")


# --------------------------------------------------------------------------- #6
class PredictableSessionId(Detector):
    """#6 — low-entropy / sequential / constant session ids."""

    gap_id = "predictable-session-id"
    name = "Predictable session identifier"
    tier = 2
    severity = Severity.MEDIUM
    spec_reference = (
        "MCP Transports §Session Management: session id SHOULD be globally unique and "
        "cryptographically secure. Security Best Practices §Session Hijacking: servers "
        "MUST use secure, non-deterministic session IDs; avoid predictable/sequential ones."
    )

    _SAMPLES = 5

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        ids: list[str] = []
        last = None
        # Count the session the runner already opened, so we take one fewer sample.
        if ctx.session_id:
            ids.append(ctx.session_id)
        opened: list[str] = []
        for _ in range(self._SAMPLES - len(ids)):
            res = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
            last = res
            if not res.ok:
                break
            sid = res.headers.get("mcp-session-id")
            if sid:
                ids.append(sid)
                opened.append(sid)

        # Hand the extra sessions back. Leaving five parked on every target is what made
        # "every detector is read-only except open-dcr" untrue.
        for sid in opened:
            await probe.request(
                "DELETE", ctx.target.url, headers={"Mcp-Session-Id": sid},
            )

        if not ids:
            # Distinguish "this server has no sessions" from "we never got to see one".
            if last is not None and not last.ok:
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=last.evidence(),
                    notes="Could not reach the server to open a session.",
                )
            if last is not None and is_auth_challenge(last)[0]:
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=last.evidence(),
                    notes=(
                        "The server requires authentication before it will open a session, "
                        "so no session identifier was observable. This is NOT evidence that "
                        "the server is stateless."
                    ),
                )
            if last is not None and last.status not in (200, None):
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=last.evidence(),
                    notes=(
                        f"initialize answered HTTP {last.status} and issued no session id, "
                        "so predictability could not be assessed."
                    ),
                )
            return self.na(
                "Server answered initialize but issued no Mcp-Session-Id header, so there is "
                "no stateful session identifier to assess. (Protocol-level sessions were "
                "removed in MCP 2026-07-28, so this is expected on current servers.)"
            )

        verdict, note = _assess_session_ids(ids)
        return self.finding(verdict, evidence=f"observed session ids: {ids}", notes=note)


def _trailing_int(s: str):
    """Return (prefix, int) if `s` ends in digits, else None. e.g. 'sess-12' -> ('sess-', 12)."""
    m = re.search(r"(\d+)$", s)
    if not m:
        return None
    return s[: m.start()], int(m.group(1))


def _is_arithmetic(nums: list[int]) -> bool:
    """True if the sorted ints form a constant-step progression (predictable).

    Needs at least 4 samples. Any 3 numbers with equal gaps are arithmetic by coincidence
    surprisingly often (1, 7, 13), so a 3-sample rule produced false positives on random
    data; a 4-in-a-row constant step is a real signal.
    """
    if len(nums) < 4:
        return False
    step = nums[1] - nums[0]
    return step != 0 and all(b - a == step for a, b in zip(nums, nums[1:]))


def _looks_sequential(nums: list[int]) -> bool:
    """True if integers look like a guessable counter.

    Two signals, robust to the fact that a counter's observed values may skip numbers that
    another client's in-flight request consumed:
      * a constant-step arithmetic progression over >=4 samples (e.g. 5, 10, 15, 20), or
      * a *dense cluster*: the whole span is no wider than the number of samples, which is
        what a `+1` counter looks like even with an occasional gap (100, 101, 103).

    The span test used to allow `3 * len(s)`, which let genuinely scattered values (2, 5, 9)
    read as a counter. Tightening it to `len(s)` keeps real counters — including ones with
    gaps — while random small integers fall out.
    """
    s = sorted(set(nums))
    if len(s) < 3:
        return False
    if _is_arithmetic(s):
        return True
    return (s[-1] - s[0]) <= len(s)


# Character classes a session id might be drawn from, ordered SMALLEST alphabet first so the
# first match is the most conservative one that fits: '1234' must be graded as 4 digits (10
# symbols), not as 4 base64url characters (64). Keyspace sizes are what an attacker must
# search per character.
_ALPHABETS = (
    (re.compile(r"^[0-9]+$"), 10, "digits"),
    (re.compile(r"^[a-f0-9]+$"), 16, "lowercase hex"),
    (re.compile(r"^[A-F0-9]+$"), 16, "uppercase hex"),
    (re.compile(r"^[a-f0-9-]+$"), 17, "lowercase hex with hyphens (UUID-like)"),
    (re.compile(r"^[a-z0-9]+$"), 36, "lowercase alphanumeric"),
    (re.compile(r"^[A-Za-z0-9]+$"), 62, "mixed-case alphanumeric"),
    (re.compile(r"^[A-Za-z0-9_-]+$"), 64, "base64url"),
)

# Below this, a session id is guessable by brute force. Session ids are bearer-equivalent
# for the lifetime of a conversation, so the bar is well above a password's.
_MIN_ENTROPY_BITS = 64


def _entropy_bits(sid: str) -> tuple[float, str]:
    """Estimate the search space of a session id, in bits, plus a plain-language reason.

    Length is *not* entropy, and the previous rule ("shorter than 16 characters = weak")
    got both directions wrong: it flagged a 15-character random base64url token (~89 bits,
    perfectly strong) while passing a 16-digit numeric id (~53 bits, brute-forceable). What
    matters is length times how many characters each position could have held.

    Distinct characters actually observed also cap the estimate, so a long string drawn from
    a tiny alphabet (`aaaabbbb…`) cannot claim a large keyspace.
    """
    if not sid:
        return 0.0, "empty"
    keyspace, label = 95, "printable ASCII"       # conservative default
    for pattern, size, name in _ALPHABETS:
        if pattern.match(sid):
            keyspace, label = size, name
            break

    # A string built from only one or two distinct symbols cannot carry the entropy its
    # alphabet suggests, however long it is ("aaaaaaaa…"). Short random tokens legitimately
    # show few repeats, so this only kicks in for genuinely degenerate ids.
    observed = len(set(sid))
    if observed <= 2 and len(sid) > 4:
        bits = len(sid) * math.log2(max(observed, 2))
        return bits, (
            f"{len(sid)} chars but only {observed} distinct symbol(s) ≈ {bits:.0f} bits"
        )

    bits = len(sid) * math.log2(keyspace)
    return bits, f"{len(sid)} chars of {label} ({keyspace} symbols) ≈ {bits:.0f} bits"


def _assess_session_ids(ids: list[str]):
    """Classify a list of observed session ids. Conservative: only flags clear weakness.

    Returns (Verdict, note). Checks run in order of how conclusive they are: determinism
    (same id twice), sequential integers, a constant prefix with a counter suffix, and only
    then an estimated-keyspace floor via `_entropy_bits`.

    The entropy step assumes each character was drawn independently at random, which is
    false for any structured id (a timestamp plus a short random tail scores high). It
    therefore errs toward NO_GAP, so a `NO_GAP` here means "no weakness of these four kinds
    was found", not "this id is strong".
    """
    uniq = list(dict.fromkeys(ids))

    # Deterministic: same id handed out for separate initialize calls.
    if len(ids) >= 2 and len(uniq) == 1:
        return Verdict.HAS_GAP, (
            f"Server returned the identical session id {ids[0]!r} for {len(ids)} separate "
            "initialize calls — deterministic, so trivially forgeable."
        )

    # Sequential integers (pure-digit ids).
    pure = [int(x) for x in ids if x.isdigit()]
    if len(pure) >= 3 and _looks_sequential(pure):
        return Verdict.HAS_GAP, (
            f"Session ids are sequential/counter-like integers ({sorted(pure)}) — an "
            "attacker can guess valid ids by counting."
        )

    # Shared prefix + guessable integer suffix, e.g. sess-1, sess-2, sess-3. A constant
    # multi-char prefix across distinct ids is itself a tell that the variable part is a
    # counter, not entropy — random tokens don't share a fixed prefix. This is checked
    # BEFORE the entropy test on purpose: `mcp-session-00000000000000000001` is 32
    # characters of apparent keyspace and still a plain counter.
    parsed = [_trailing_int(x) for x in ids]
    if len(ids) >= 3 and all(p is not None for p in parsed):
        prefixes = {p[0] for p in parsed}  # type: ignore[index]
        suffixes = [p[1] for p in parsed]  # type: ignore[index]
        if len(prefixes) == 1 and prefixes != {""}:
            prefix = next(iter(prefixes))
            if _looks_sequential(suffixes):
                return Verdict.HAS_GAP, (
                    f"Session ids share the fixed prefix {prefix!r} with a "
                    f"guessable numeric suffix ({sorted(suffixes)}) — predictable counter."
                )
            # A constant prefix means all the unpredictability lives in the digits, so that
            # is what must be measured. Otherwise a busy server whose counter skips values
            # irregularly (3, 8, 11, 17, 25 — because other clients consumed the gaps)
            # escapes both the arithmetic and the dense-cluster test, and a literal counter
            # is certified NO_GAP purely because the server has other traffic.
            digits = max(len(str(s)) for s in suffixes)
            bits = digits * math.log2(10)
            if bits < _MIN_ENTROPY_BITS:
                return Verdict.HAS_GAP, (
                    f"Session ids are the fixed prefix {prefix!r} followed by a "
                    f"{digits}-digit number ({sorted(suffixes)}); only those digits vary, "
                    f"so the real search space is ~{bits:.0f} bits — guessable."
                )

    # Weak ids are guessable regardless of pattern — judged on estimated keyspace, not on
    # character count. The old `len < 16` rule flagged strong compact tokens and passed weak
    # long ones; see `_entropy_bits`.
    weakest = min(ids, key=lambda s: _entropy_bits(s)[0])
    bits, how = _entropy_bits(weakest)
    if bits < _MIN_ENTROPY_BITS:
        return Verdict.HAS_GAP, (
            f"Weakest session id {weakest!r} has only ~{bits:.0f} bits of entropy "
            f"({how}) — under the ~{_MIN_ENTROPY_BITS}-bit floor needed to resist guessing "
            "(the spec wants a securely generated UUID/JWT/hash)."
        )

    if len(ids) == 1:
        return Verdict.INCONCLUSIVE, (
            f"Only one session id observed ({weakest!r}); it is strong on its own "
            f"({how}) but variability across sessions could not be assessed."
        )

    return Verdict.NO_GAP, (
        f"{len(uniq)} distinct session ids, weakest {how}, no constant/sequential pattern "
        "(checked determinism, counter sequences, shared-prefix counters, and entropy)."
    )


# --------------------------------------------------------------------------- #7
class OriginNotValidated(Detector):
    """#7 — server does not validate the Origin header (DNS-rebinding exposure)."""

    gap_id = "origin-not-validated"
    name = "Origin header not validated (DNS rebinding)"
    tier = 2
    severity = Severity.HIGH
    spec_reference = (
        "MCP Transports §Security Warning: servers MUST validate the Origin header on all "
        "incoming connections to prevent DNS rebinding attacks."
    )

    _FORGED_ORIGIN = "https://evil.attacker.example"

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        res = await probe.mcp_call(
            ctx.target.url, "initialize", probe.initialize_params(),
            headers={"Origin": self._FORGED_ORIGIN},
        )
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        if res.status == 200 and (
            jsonrpc_result(res) is not None or truncated_success(res)
        ):
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes=(
                    f"initialize from forged Origin {self._FORGED_ORIGIN!r} succeeded "
                    "(HTTP 200 with a valid result) — the server accepts cross-origin "
                    "requests it should reject."
                ),
            )
        if res.status == 403:
            # A 403 alone proves nothing: the server may refuse *everything*. Compare
            # against a control request with no Origin header. Only a server that accepts
            # the control and rejects the forged Origin is actually validating Origin.
            # Without this, `403 {"error":"Missing API key"}` was credited as
            # "server validates Origin".
            control = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
            if not control.ok:
                # Without a completed control we have not observed the comparison this
                # verdict rests on. Falling through used to emit NO_GAP with the note "the
                # same request without an Origin header was not [rejected]" — asserting an
                # observation that never happened, on servers whose body said "Missing API
                # key".
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=(
                        f"forged Origin: {res.evidence(200)}\n"
                        f"--- control (no Origin) ---\n{control.evidence(200)}"
                    ),
                    notes=(
                        "The forged Origin was refused with 403, but the control request "
                        "(same call, no Origin header) never completed, so the refusal "
                        "cannot be attributed to Origin validation."
                    ),
                )
            if control.status == 403:
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=(
                        f"forged Origin: {res.evidence(200)}\n"
                        f"--- control (no Origin) ---\n{control.evidence(200)}"
                    ),
                    notes=(
                        "The server answered 403 to the forged Origin AND to an identical "
                        "request with no Origin header at all, so the refusal is not "
                        "attributable to Origin validation."
                    ),
                )
            return self.finding(
                Verdict.NO_GAP,
                evidence=(
                    f"forged Origin: {res.evidence(200)}\n"
                    f"--- control (no Origin) -> HTTP {control.status} ---"
                ),
                notes=(
                    "Forged Origin rejected with 403 while the same request without an "
                    "Origin header was not — the server validates Origin, as MCP Transports "
                    "requires (2026-07-28 specifies 403 for an invalid Origin)."
                ),
            )
        if is_auth_challenge(res)[0]:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=res.evidence(),
                notes=(
                    "Request was auth-gated before any Origin decision was observable, "
                    "so Origin validation could not be confirmed either way."
                ),
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=res.evidence(),
            notes=f"Unexpected status {res.status} for forged-Origin initialize.",
        )


# --------------------------------------------------------------------------- #8
class CorsMisconfiguration(Detector):
    """#8 — reflects an arbitrary Origin with credentials (general web-security heuristic).

    NOTE: CORS is not addressed by the MCP specification. This is graded as a general
    browser-security heuristic, never as an MCP spec violation.
    """

    gap_id = "cors-misconfiguration"
    name = "CORS reflects arbitrary origin with credentials"
    tier = 2
    severity = Severity.MEDIUM
    spec_reference = (
        "Not in the MCP spec. General web security: reflecting an arbitrary Origin in "
        "Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true "
        "lets any website make credentialed cross-origin calls."
    )

    _EVIL = "https://evil.attacker.example"

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        # CORS headers usually appear on the preflight; fall back to a GET carrying Origin.
        preflight = await probe.request(
            "OPTIONS", ctx.target.url,
            headers={
                "Origin": self._EVIL,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        res = preflight
        if not (preflight.ok and "access-control-allow-origin" in preflight.headers):
            res = await probe.request("GET", ctx.target.url, headers={"Origin": self._EVIL})

        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        acao = res.headers.get("access-control-allow-origin", "")
        acac = res.headers.get("access-control-allow-credentials", "").lower() == "true"

        if not acao:
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"no Access-Control-Allow-Origin in response to Origin {self._EVIL}",
                notes="Server grants no cross-origin access (safe; MCP clients aren't browsers).",
            )
        reflected = acao == self._EVIL
        if reflected and acac:
            return self.finding(
                Verdict.HAS_GAP,
                evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: true",
                notes=(
                    "Server reflects an arbitrary Origin AND allows credentials — any website "
                    "could make credentialed cross-origin requests. (Heuristic, not MCP spec.)"
                ),
            )
        if reflected:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                notes=(
                    "Reflects an arbitrary Origin but without Allow-Credentials — lower risk "
                    "(no cookies/credentials shared). Worth noting, not a clear finding."
                ),
            )
        if acao.strip() == "*":
            # A wildcard cannot carry credentials (browsers refuse `*` with
            # Allow-Credentials), so it is not a credentialed-theft vector. But on a server
            # that needs no credentials in the first place, `*` means any web page can drive
            # it directly — which is the same exposure by a different route, and calling that
            # simply "not exploitable" was misleading.
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"{res.request_line()}\nAccess-Control-Allow-Origin: *; Allow-Credentials: {acac}",
                notes=(
                    "Wildcard Access-Control-Allow-Origin: browsers will not send "
                    "credentials to it, so no credentialed cross-origin theft is possible. "
                    "Note that if this server needs no authentication at all (see "
                    "no-authentication-remote), any web page can still call it directly."
                ),
            )
        return self.finding(
            Verdict.NO_GAP,
            evidence=f"{res.request_line()}\nAccess-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
            notes=(
                f"Does not reflect the forged Origin (fixed origin {acao!r}) — not "
                "exploitable for credentialed theft."
            ),
        )


# --------------------------------------------------------------------------- #9
class AuthEndpointsNotHttps(Detector):
    """#9 — an OAuth endpoint (AS, token, registration, …) uses cleartext http."""

    gap_id = "auth-endpoints-not-https"
    name = "OAuth endpoint not served over HTTPS"
    tier = 2
    severity = Severity.HIGH
    needs_oauth = True
    spec_reference = (
        "OAuth 2.1 §1.5 & MCP Authorization §2.8: all OAuth protocol URLs MUST use https "
        "(loopback exempt). RFC 8414 mandates https for issuer / jwks_uri / metadata path."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na
        oauth = ctx.oauth
        if oauth is None or not oauth.attempted:
            return self.na("OAuth discovery was not run for this scan.")

        checked: list[str] = []
        violations: list[str] = []

        # Authorization-server issuer URLs named in the PRM.
        for s in oauth.authorization_servers:
            checked.append(s)
            if _insecure_http(s):
                violations.append(f"authorization_servers entry: {s}")

        # Endpoint URLs inside the resolved AS metadata document — but only if it may be
        # relied on. RFC 8414 §3.3 forbids using metadata whose issuer does not match, and
        # #10 already reports that as a gap; reading it here anyway made one report
        # contradict itself.
        md = oauth.as_metadata if oauth.as_metadata_usable else {}
        # Kept out of `checked`: that list is counted and reported as "N discovered OAuth
        # URL(s)", so putting an explanatory sentence in it inflated the count by one and
        # described prose as a URL.
        skipped_note = ""
        if oauth.has_as_metadata and not oauth.as_metadata_usable:
            skipped_note = (
                " (AS-metadata endpoints were NOT checked: its issuer does not match, so "
                "RFC 8414 §3.3 forbids using the document — see missing-as-metadata.)"
            )
        md = md or {}
        for fld in _AS_ENDPOINT_FIELDS:
            val = md.get(fld)
            if isinstance(val, str) and val:
                checked.append(f"{fld}={val}")
                if _insecure_http(val):
                    violations.append(f"{fld}: {val}")

        if not checked:
            return self.na(
                "No authorization-server URLs or AS-metadata endpoints were discovered, so "
                "there is nothing to check for https." + skipped_note
            )
        if violations:
            return self.finding(
                Verdict.HAS_GAP,
                evidence="; ".join(violations),
                notes=(
                    f"{len(violations)} OAuth endpoint(s) use cleartext http on a non-loopback "
                    "host — tokens/codes in transit are exposed." + skipped_note
                ),
            )
        return self.finding(
            Verdict.NO_GAP,
            evidence="; ".join(checked)[:400],
            notes=(
                f"All {len(checked)} discovered OAuth URL(s) use https or loopback."
                + skipped_note
            ),
        )


# -------------------------------------------------------------------------- #10
class MissingAsMetadata(Detector):
    """#10 — no RFC 8414 Authorization Server Metadata (complements #4's PRM check)."""

    gap_id = "missing-as-metadata"
    name = "Missing OAuth Authorization Server Metadata (RFC 8414)"
    tier = 2
    severity = Severity.MEDIUM
    needs_oauth = True
    spec_reference = (
        "MCP Authorization §2.3.2: clients MUST follow RFC 8414 to obtain AS metadata; "
        "authorization servers MUST provide it. Distinct from RFC 9728 PRM (#4)."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na
        oauth = ctx.oauth
        if oauth is None or not oauth.attempted:
            return self.na("OAuth discovery was not run for this scan.")

        if oauth.has_as_metadata:
            if oauth.issuer_mismatch:
                return self.finding(
                    Verdict.HAS_GAP,
                    evidence=f"metadata at {oauth.as_metadata_url}",
                    notes=(
                        "AS metadata was served but its 'issuer' does not match the requested "
                        "issuer (RFC 8414 §3.3 says such metadata MUST NOT be used)."
                    ),
                )
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"AS metadata at {oauth.as_metadata_url} (source={oauth.as_metadata_source})",
                notes="RFC 8414 Authorization Server Metadata resolved successfully.",
            )

        strict = ctx.targets_strict_spec
        # Sharpen the evidence depending on whether an AS was even advertised.
        if oauth.authorization_servers:
            base = (
                f"PRM advertises authorization_servers {oauth.authorization_servers} but none "
                "expose a usable RFC 8414 metadata document"
            )
        else:
            base = (
                "No authorization server is advertised (no PRM authorization_servers) and the "
                "server's own origin exposes no RFC 8414 metadata (overlaps #4 missing-PRM)"
            )
        if strict:
            return self.finding(
                Verdict.HAS_GAP, evidence=base,
                notes=base + " — required under 2025-06-18.",
            )
        return self.finding(
            Verdict.INCONCLUSIVE, evidence=base,
            notes=base + "; server negotiated <2025-06-18 where RFC 8414 is not a MUST.",
        )


def _response_type_values(raw) -> set[str] | None:
    """Flatten an OAuth response-type / grant-type list into individual values.

    OAuth response types are **space-delimited sets**: a single entry `"id_token token"`
    advertises the hybrid flow and therefore does include `token`. Testing whole entries
    with `"token" in [...]` matched only a bare `"token"` entry, so every real-world
    advertisement of the implicit grant via a combined response type was missed.

    Returns None when the field is absent or not a list, which callers treat as
    "unknown" — distinct from an empty set, which means "advertised nothing".
    """
    if not isinstance(raw, list):
        return None
    values: set[str] = set()
    for entry in raw:
        if isinstance(entry, str):
            values.update(part for part in entry.lower().split() if part)
    return values


# -------------------------------------------------------------------------- #11
class ImplicitFlowEnabled(Detector):
    """#11 — AS advertises the OAuth implicit grant, which OAuth 2.1 removed."""

    gap_id = "implicit-flow-enabled"
    name = "Implicit grant advertised (forbidden by OAuth 2.1)"
    tier = 2
    severity = Severity.HIGH
    needs_oauth = True
    spec_reference = (
        "OAuth 2.1 §1.8 removes the implicit grant; MCP §2.3 mandates OAuth 2.1. RFC 8414: "
        "response_types_supported 'token' or grant_types_supported 'implicit' advertise it."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na
        oauth = ctx.oauth
        if oauth is None or not oauth.attempted:
            return self.na("OAuth discovery was not run for this scan.")
        if not oauth.as_metadata_usable:
            return self.na(
                "No usable AS metadata resolved, so advertised grant/response types are "
                "unknown (see missing-as-metadata; a document whose issuer does not match "
                "MUST NOT be used per RFC 8414 §3.3)."
            )

        md = oauth.as_metadata or {}
        rts = md.get("response_types_supported")
        gts = md.get("grant_types_supported")
        rts_list = _response_type_values(rts)
        gts_list = _response_type_values(gts)

        signals = []
        if rts_list is not None and "token" in rts_list:
            signals.append("response_types_supported contains 'token'")
        if gts_list is not None and "implicit" in gts_list:
            signals.append("grant_types_supported contains 'implicit'")

        if signals:
            return self.finding(
                Verdict.HAS_GAP,
                evidence=f"response_types_supported={rts}; grant_types_supported={gts}",
                notes="Implicit grant advertised: " + "; ".join(signals) + ".",
            )

        # No explicit implicit signal. We deliberately do NOT flag a *missing*
        # grant_types_supported as HAS even though RFC 8414's default includes 'implicit'
        # — that default is a frequent false positive. Note it instead.
        if rts_list is not None:
            note = (
                "response_types_supported has no 'token' and no 'implicit' grant advertised "
                "— implicit grant not usable."
            )
            if gts_list is None:
                note += (
                    " (grant_types_supported is absent; RFC 8414's default technically "
                    "includes 'implicit', but response_types lacks 'token' so it is moot.)"
                )
            return self.finding(Verdict.NO_GAP, evidence=f"response_types_supported={rts}", notes=note)

        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=f"grant_types_supported={gts}",
            notes="AS metadata omits response_types_supported; cannot confirm implicit support.",
        )


# -------------------------------------------------------------------------- #12
_CLEANUP_FAIL_MARKER = "MANUAL CLEANUP NEEDED"


def _write_target_refusal(url: str, target_url: str) -> str:
    """Why we must not send a write to `url`, or `""` if it is an acceptable destination.

    A write may go to the scan target itself or to a sibling host under the same
    registrable domain (many MCP servers put their authorization server on
    `auth.<same-domain>`), over https or explicit loopback. Anything else — a different
    organisation, private address space, a non-HTTP scheme — is refused.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        return f"{url!r} does not use http(s)."
    if not parts.hostname:
        return f"{url!r} has no host."
    if _insecure_http(url):
        return (
            f"{url!r} is cleartext http on a non-loopback host; sending a registration "
            "there would expose it in transit."
        )
    if not _same_site(url, target_url):
        return (
            f"{url!r} is not the scan target or a sibling of it "
            f"({urlsplit(target_url).hostname!r}) — writing there would touch a third "
            "party who never agreed to be scanned."
        )
    return ""


class OpenDcr(Detector):
    """#12 — Dynamic Client Registration accepts unauthenticated requests.

    SIDE EFFECT: this detector performs a real OAuth 2.0 client registration POST
    (RFC 7591) against the discovered registration_endpoint with no initial access
    token. A successful probe creates a throwaway public client on the target — so,
    immediately after, it tries to delete that client again via RFC 7592 (HTTP DELETE
    to the returned registration_client_uri, authenticated with the returned
    registration_access_token). RFC 7592 support is OPTIONAL, so cleanup can fail; when
    it does, the Finding says so loudly (notes contain "MANUAL CLEANUP NEEDED") and names
    the client id left behind, rather than hiding it.
    """

    gap_id = "open-dcr"
    name = "Open Dynamic Client Registration"
    tier = 2
    severity = Severity.HIGH
    needs_oauth = True
    has_side_effects = True  # performs a real RFC 7591 registration POST (a write)
    spec_reference = (
        "RFC 7591 §3: open registration is permitted (SHOULD), but an unauthenticated "
        "registration endpoint is the prerequisite for the confused-deputy attack (#16) "
        "and for registration flooding. Cleanup uses RFC 7592 §2.3 (DELETE -> 204)."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na
        oauth = ctx.oauth
        if oauth is None or not oauth.attempted:
            return self.na("OAuth discovery was not run for this scan.")
        if not oauth.as_metadata_usable:
            return self.na(
                "The AS metadata document declares an issuer that does not match the one "
                "the PRM named, so RFC 8414 §3.3 says it MUST NOT be used — and we will "
                "certainly not send a write to an endpoint it advertises."
            )
        md = oauth.as_metadata or {}
        endpoint = md.get("registration_endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            return self.na(
                "AS metadata advertises no registration_endpoint, so Dynamic Client "
                "Registration is not offered here."
            )

        # CONTAINMENT. The endpoint is a URL the *scanned server* chose, and what follows is
        # a write. Unchecked, that makes the scanner a confused deputy: it will create an
        # OAuth client on whatever host the target names — a cloud metadata service, a box
        # on the operator's LAN, or an unrelated third party who never agreed to be
        # scanned. This has already happened: scanning `api.serff.ai` registered a client on
        # `api.llow.io`, a different domain that was never in the endpoint list.
        blocked = _write_target_refusal(endpoint, ctx.target.url)
        if blocked:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=f"registration_endpoint = {endpoint}",
                notes=(
                    f"REFUSED to send the registration write: {blocked} No request was "
                    "made, so whether registration is open here is unknown. Re-run against "
                    "that host directly if you have permission to test it."
                ),
            )

        probe: Probe = ctx.probe
        payload = {
            "client_name": "mcpauth-probe (auth-gap scanner, safe to delete)",
            "redirect_uris": ["https://mcpauth.example/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        # No Authorization header == no RFC 7591 initial access token.
        res = await probe.request(
            "POST", endpoint,
            headers={"Content-Type": "application/json"},
            json_body=payload,
        )
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        reg = res.json if isinstance(res.json, dict) else {}
        client_id = reg.get("client_id")

        # Success is decided by the HTTP status, NOT by whether we could parse the body.
        # A 2xx means the server created something; if the body did not parse we still owe
        # the operator a loud warning naming what we cannot clean up. Inferring "nothing was
        # created" from an unparsed body is how a real client ended up abandoned on a third
        # party's server with no marker at all.
        # Any 2xx, not just 200/201: a 202 Accepted also means the server took the
        # registration, and treating it as "not created" is exactly the silent-orphan
        # outcome the paragraph above exists to prevent.
        created = res.status is not None and 200 <= res.status < 300
        if created and client_id:
            cleanup = await self._cleanup(probe, reg, ctx.target.url)
            return self.finding(
                Verdict.HAS_GAP,
                evidence=f"{res.request_line()}\n-> HTTP {res.status}, client_id={client_id!r}",
                notes=(
                    "Registration succeeded with no initial access token — anyone can mint a "
                    "client. RFC 7591 permits this, but it enables confused-deputy (#16); "
                    f"consider an allowlist or pre-shared registration token. {cleanup}"
                ),
            )
        if created:
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes=(
                    f"⚠ {_CLEANUP_FAIL_MARKER}: the registration POST returned HTTP "
                    f"{res.status} (success), so a client was almost certainly created, but "
                    "the response body could not be parsed as JSON so we cannot name its "
                    f"client_id or delete it. Inspect {endpoint} manually. Registration is "
                    "open here (no initial access token was required)."
                ),
            )
        if is_auth_challenge(res)[0]:
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Registration endpoint requires authorization (initial access token).",
            )
        if res.status == 403:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=res.evidence(),
                notes=(
                    "Registration was refused with a bare 403 (no WWW-Authenticate header, "
                    "no OAuth error code). That may be an authorization requirement or just "
                    "a WAF/bot filter, so it is not evidence either way."
                ),
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=res.evidence(),
            notes=(
                f"Registration POST returned HTTP {res.status} without a client_id; could be "
                "input validation rather than an auth decision."
            ),
        )

    async def _cleanup(self, probe: "Probe", reg: dict, target_url: str) -> str:
        """Best-effort RFC 7592 delete of the client we just created. Returns a note.

        The note always states the cleanup outcome. If the client could NOT be removed it
        contains the _CLEANUP_FAIL_MARKER and the client_id, so a caller (or a human
        reading the report) can deprovision it manually.
        """
        client_id = reg.get("client_id")
        mgmt_uri = reg.get("registration_client_uri")
        reg_token = reg.get("registration_access_token")

        # RFC 7592 is OPTIONAL: without both the management URL and its token there is no
        # spec-defined way to delete what we created.
        if not mgmt_uri or not reg_token:
            return (
                f"⚠ {_CLEANUP_FAIL_MARKER}: server returned no RFC 7592 management fields "
                f"(registration_client_uri / registration_access_token), so the client we "
                f"created (client_id={client_id!r}) cannot be deleted programmatically — "
                "deprovision it manually if the server is not yours."
            )

        # The management URI and the bearer token both come from the response body, i.e. the
        # target picked them. A DELETE carrying an Authorization header is exactly the shape
        # of request that must never be aimed at a host of someone else's choosing.
        refusal = _write_target_refusal(str(mgmt_uri), target_url)
        if refusal:
            return (
                f"⚠ {_CLEANUP_FAIL_MARKER}: the server pointed cleanup at "
                f"{str(mgmt_uri)!r}, which we refused to contact ({refusal}) — sending a "
                f"credential-bearing DELETE there could hit an unrelated host. "
                f"client_id={client_id!r} still exists; deprovision it manually."
            )

        delete = await probe.request(
            "DELETE", str(mgmt_uri),
            headers={"Authorization": f"Bearer {reg_token}"},
        )
        if not delete.ok:
            return (
                f"⚠ {_CLEANUP_FAIL_MARKER}: DELETE {mgmt_uri} failed at transport level "
                f"({delete.error}); client_id={client_id!r} may still exist."
            )
        if delete.status in (200, 204):
            return f"Cleanup: client_id={client_id!r} deleted via RFC 7592 (HTTP {delete.status})."
        return (
            f"⚠ {_CLEANUP_FAIL_MARKER}: DELETE {mgmt_uri} returned HTTP {delete.status} "
            f"(RFC 7592 delete unsupported?); client_id={client_id!r} may still exist."
        )
