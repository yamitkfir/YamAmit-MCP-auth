"""Tier 2 detectors — medium: crafted headers, chained metadata, multi-sample.

Each class maps exactly one gap (6–12) from OUTLINE.md and is independent of the
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

import re
from urllib.parse import urlsplit

from ..models import ProbeContext, Severity, Verdict
from ..probe import Probe, jsonrpc_result
from .base import Detector

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

_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _is_loopback_host(host: str) -> bool:
    h = (host or "").lower()
    return h in _LOOPBACK_HOSTS or h.endswith(".localhost")


def _insecure_http(url: str) -> bool:
    """True if `url` is cleartext http on a non-loopback host (OAuth 2.1 §1.5 violation)."""
    p = urlsplit(url)
    return p.scheme == "http" and not _is_loopback_host(p.hostname or "")


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
        for _ in range(self._SAMPLES):
            res = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
            if not res.ok:
                break
            sid = res.headers.get("mcp-session-id")
            if sid:
                ids.append(sid)

        if not ids:
            return self.na(
                "Server issues no Mcp-Session-Id header on initialize, so there is no "
                "stateful session identifier to assess (it may be stateless or legacy-SSE)."
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
    """True if the sorted ints form a constant-step progression (predictable)."""
    if len(nums) < 3:
        return False
    step = nums[1] - nums[0]
    return step != 0 and all(b - a == step for a, b in zip(nums, nums[1:]))


def _looks_sequential(nums: list[int]) -> bool:
    """True if integers look like a guessable counter.

    Two signals, robust to the fact that detectors run concurrently (so observed ids
    from a counter may skip values another in-flight request consumed):
      * a constant-step arithmetic progression (e.g. 5, 10, 15), or
      * a *dense cluster* of small integers (span small relative to how many we saw),
        which is what a `+1` counter looks like even with a few gaps.
    Requires >=3 distinct values so random data never trips it.
    """
    s = sorted(set(nums))
    if len(s) < 3:
        return False
    if _is_arithmetic(s):
        return True
    return (s[-1] - s[0]) <= 3 * len(s)


def _assess_session_ids(ids: list[str]):
    """Classify a list of observed session ids. Conservative: only flags clear weakness.

    Returns (Verdict, note). We rely on determinism / sequentiality / short-length
    signals rather than fragile single-sample entropy math, so real high-entropy
    servers are never falsely flagged.
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
    # counter, not entropy — random tokens don't share a fixed prefix.
    parsed = [_trailing_int(x) for x in ids]
    if len(ids) >= 3 and all(p is not None for p in parsed):
        prefixes = {p[0] for p in parsed}  # type: ignore[index]
        suffixes = [p[1] for p in parsed]  # type: ignore[index]
        if len(prefixes) == 1 and prefixes != {""} and _looks_sequential(suffixes):
            return Verdict.HAS_GAP, (
                f"Session ids share the fixed prefix {next(iter(prefixes))!r} with a "
                f"guessable numeric suffix ({sorted(suffixes)}) — predictable counter."
            )

    # Very short ids are guessable regardless of pattern.
    shortest = min(ids, key=len)
    if len(shortest) < 16:
        return Verdict.HAS_GAP, (
            f"Shortest session id {shortest!r} is only {len(shortest)} chars — too little "
            "entropy to resist guessing (spec wants a securely generated UUID/JWT/hash)."
        )

    if len(ids) == 1:
        return Verdict.INCONCLUSIVE, (
            f"Only one session id observed ({shortest!r}, {len(shortest)} chars); it is long "
            "enough but variability across sessions could not be assessed."
        )

    return Verdict.NO_GAP, (
        f"{len(uniq)} distinct session ids, all >=16 chars, no constant/sequential pattern "
        "(checked determinism, counter sequences, shared-prefix counters, and length)."
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

        if res.status == 200 and jsonrpc_result(res) is not None:
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
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Forged Origin rejected with 403 — server validates Origin.",
            )
        if res.status == 401:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=res.evidence(),
                notes=(
                    "Request was auth-gated (401) before any Origin decision was observable, "
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
        return self.finding(
            Verdict.NO_GAP,
            evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
            notes="Does not reflect the forged Origin (wildcard or fixed origin) — not exploitable for credentialed theft.",
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

        # Endpoint URLs inside the resolved AS metadata document.
        md = oauth.as_metadata or {}
        for fld in _AS_ENDPOINT_FIELDS:
            val = md.get(fld)
            if isinstance(val, str) and val:
                checked.append(f"{fld}={val}")
                if _insecure_http(val):
                    violations.append(f"{fld}: {val}")

        if not checked:
            return self.na(
                "No authorization-server URLs or AS-metadata endpoints were discovered, so "
                "there is nothing to check for https."
            )
        if violations:
            return self.finding(
                Verdict.HAS_GAP,
                evidence="; ".join(violations),
                notes=(
                    f"{len(violations)} OAuth endpoint(s) use cleartext http on a non-loopback "
                    "host — tokens/codes in transit are exposed."
                ),
            )
        return self.finding(
            Verdict.NO_GAP,
            evidence="; ".join(checked)[:400],
            notes=f"All {len(checked)} discovered OAuth URL(s) use https or loopback.",
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
        if not oauth.has_as_metadata:
            return self.na(
                "No AS metadata resolved, so advertised grant/response types are unknown "
                "(see missing-as-metadata)."
            )

        md = oauth.as_metadata or {}
        rts = md.get("response_types_supported")
        gts = md.get("grant_types_supported")
        rts_list = [str(x).lower() for x in rts] if isinstance(rts, list) else None
        gts_list = [str(x).lower() for x in gts] if isinstance(gts, list) else None

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
        md = oauth.as_metadata or {}
        endpoint = md.get("registration_endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            return self.na(
                "AS metadata advertises no registration_endpoint, so Dynamic Client "
                "Registration is not offered here."
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
        if res.status in (200, 201) and client_id:
            cleanup = await self._cleanup(probe, reg)
            note = (
                "Registration succeeded with no initial access token — anyone can mint a "
                "client. RFC 7591 permits this, but it enables confused-deputy (#16); "
                f"consider an allowlist or pre-shared registration token. {cleanup}"
            )
            return self.finding(
                Verdict.HAS_GAP,
                evidence=f"POST {endpoint} -> HTTP {res.status}, client_id={client_id!r}",
                notes=note,
            )
        if res.status in (401, 403):
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Registration endpoint requires authorization (initial access token).",
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=res.evidence(),
            notes=(
                f"Registration POST returned HTTP {res.status} without a client_id; could be "
                "input validation rather than an auth decision."
            ),
        )

    async def _cleanup(self, probe: "Probe", reg: dict) -> str:
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
