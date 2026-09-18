"""Tier 1 detectors — easy: single unauthenticated request, well-known GET, header read.

Each class maps exactly one gap from the catalog in README.md and is independent of the
others.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import ProbeContext, Severity, Verdict
from ..oauth import prm_candidates
from ..probe import Probe, _is_tls_failure, jsonrpc_error, jsonrpc_result, truncated_success
from .base import Detector, is_auth_challenge

__all__ = [
    "MissingProtectedResourceMetadata",
    "MissingWwwAuthenticate",
    "NoAuthenticationRemote",
    "NoTlsTransport",
    "SessionIdInUrl",
    "_is_tls_failure",
]


class NoAuthenticationRemote(Detector):
    """#1 — remote server invokes tools with no credentials at all."""

    gap_id = "no-authentication-remote"
    name = "No authentication on remote MCP server"
    tier = 1
    severity = Severity.CRITICAL
    spec_reference = (
        "Transports §Security: servers SHOULD authenticate all connections. "
        "A protected server MUST answer 401 when authorization is required."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        # Reach a privileged operation with NO Authorization header. The session id (if the
        # server issued one) IS carried: it is plumbing, not a credential, so withholding it
        # would make a wide-open server look secured.
        res = await probe.mcp_call(
            ctx.target.url, "tools/list", {}, headers=ctx.session_headers()
        )
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        result = jsonrpc_result(res)
        if res.status == 200 and isinstance(result, dict):
            tools = result.get("tools")
            tools = tools if isinstance(tools, list) else []
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes=f"tools/list returned {len(tools)} tool(s) without any credential.",
            )

        if res.status == 200 and truncated_success(res):
            # The reply was longer than the read cap, so it does not parse — but the visible
            # prefix already carries a JSON-RPC `result`, which means the privileged call
            # succeeded without a credential. Concluding "could not tell" here downgraded
            # real findings on exactly the servers that expose the most tools.
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes=(
                    "tools/list returned a result without any credential. The response "
                    "exceeded the read cap so it could not be parsed in full, and the tool "
                    "count is therefore not reported — but the server answered the "
                    "privileged call."
                ),
            )

        challenged, why = is_auth_challenge(res)
        if challenged:
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes=f"Server rejects unauthenticated privileged calls ({why}).",
            )

        if res.status == 403:
            # Refused, but not demonstrably by an authentication decision.
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=res.evidence(),
                notes=(
                    f"{why}. The server may well require authentication, but this response "
                    "does not prove it — a blocked scan looks the same."
                ),
            )

        err = jsonrpc_error(res)
        if res.status == 200 and err:
            return self.finding(
                Verdict.INCONCLUSIVE,
                evidence=res.evidence(),
                notes=(
                    f"HTTP 200 but the JSON-RPC body is an error ({err}); the call did not "
                    "succeed, and the error is not an HTTP authorization decision."
                ),
            )

        hint = ""
        if res.status == 400:
            hint = (
                " A 400 often means the request was incomplete for this server (e.g. it "
                "wanted a session id or protocol header) rather than that access was denied."
            )
        elif res.status in (404, 405):
            hint = (
                " A 404/405 on a POST often means this URL is a legacy two-channel SSE "
                "endpoint rather than a Streamable HTTP endpoint."
            )
        elif res.status == 429:
            hint = " A 429 means we were rate-limited; nothing about auth was observed."
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=res.evidence(),
            notes=f"Unexpected status {res.status}; could not confirm tool access.{hint}",
        )


class NoTlsTransport(Detector):
    """#2 — cleartext HTTP, or a broken certificate, on a non-loopback host."""

    gap_id = "no-tls-transport"
    name = "Cleartext HTTP transport (no TLS)"
    tier = 1
    severity = Severity.HIGH
    spec_reference = (
        "OAuth 2.1 §1.5 / MCP Authorization: auth-bearing traffic MUST use HTTPS "
        "(loopback exempt)."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na
        if ctx.target.is_loopback:
            return self.na("Loopback host — cleartext is permitted by spec.")

        probe: Probe = ctx.probe

        if ctx.target.scheme == "https":
            # "The URL says https" is not the same as "TLS actually works". With
            # certificate verification enabled, a failed handshake is a real finding: an
            # expired, self-signed, or wrong-hostname certificate gives users no more
            # protection than cleartext, and used to be graded NO_GAP.
            res = await probe.request("GET", ctx.target.url)
            if not res.ok and res.tls_failure:
                return self.finding(
                    Verdict.HAS_GAP,
                    evidence=res.evidence(),
                    notes=(
                        "Endpoint is https but its TLS certificate does not validate, so "
                        "the encryption cannot be trusted (an attacker in the middle can "
                        "impersonate this server)."
                    ),
                )
            if not res.ok:
                return self.finding(
                    Verdict.INCONCLUSIVE,
                    evidence=res.evidence(),
                    notes=(
                        "Endpoint scheme is https but the host could not be reached, so "
                        "the certificate could not be validated."
                    ),
                )
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Endpoint is https and its certificate validated.",
            )

        # http:// on a remote host. Check whether it redirects to https. This works only
        # because the probe no longer follows redirects itself; when it did, this branch
        # was unreachable and a server that correctly upgraded to HTTPS was still flagged.
        res = await probe.request("GET", ctx.target.url)
        location = res.headers.get("location", "") if res.ok else ""
        if res.ok and res.status in (301, 302, 307, 308) and location.lower().startswith("https:"):
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes=f"Cleartext endpoint redirects to HTTPS ({location}).",
            )
        return self.finding(
            Verdict.HAS_GAP,
            evidence=res.evidence() if res.ok else (
                f"endpoint scheme = http on non-loopback host {ctx.target.host}; "
                f"{res.evidence()}"
            ),
            notes="Remote MCP endpoint reachable over cleartext; tokens/sessions exposed.",
        )


class MissingWwwAuthenticate(Detector):
    """#3 — 401 lacks RFC 9728 WWW-Authenticate discovery pointer (2025-06-18 MUST)."""

    gap_id = "missing-www-authenticate"
    name = "401 without RFC 9728 WWW-Authenticate pointer"
    tier = 1
    severity = Severity.MEDIUM
    spec_reference = (
        "MCP Authorization 2025-06-18: on 401 the server MUST return WWW-Authenticate "
        "indicating the protected-resource-metadata URL (RFC 9728 §5.1)."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        res = await probe.mcp_call(
            ctx.target.url, "tools/list", {}, headers=ctx.session_headers()
        )
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        challenged, why = is_auth_challenge(res)
        if not challenged:
            # No authentication challenge was issued, so this MUST is not triggered. Note
            # that a bare 403 lands here rather than being graded as a malformed challenge:
            # charging a WAF block with an RFC 9728 violation would be a false positive.
            return self.finding(
                Verdict.NOT_APPLICABLE,
                evidence=res.evidence(),
                notes=(
                    f"No authentication challenge to inspect ({why}), so the "
                    "WWW-Authenticate MUST is not triggered (see no-authentication-remote "
                    "for the real risk)."
                ),
            )

        www = res.headers.get("www-authenticate", "")
        pointer = _resource_metadata_pointer(www)
        if pointer:
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"{res.request_line()}\nWWW-Authenticate: {www}",
                notes=f"Challenge points at its metadata document: {pointer}",
            )

        if "resource_metadata" in www.lower():
            # The token is present but not a usable absolute URL — a malformed pointer is
            # not a compliant one, and a plain substring test used to accept it.
            return self.finding(
                Verdict.HAS_GAP if ctx.targets_strict_spec else Verdict.INCONCLUSIVE,
                evidence=f"{res.request_line()}\nWWW-Authenticate: {www!r}",
                notes=(
                    "Challenge mentions resource_metadata but not as an absolute http(s) "
                    "URL, so a client cannot follow it."
                ),
            )

        verdict = Verdict.HAS_GAP if ctx.targets_strict_spec else Verdict.INCONCLUSIVE
        note = (
            f"{why}, but the challenge carries no resource_metadata pointer."
            if ctx.targets_strict_spec
            else (
                f"{why} with no resource_metadata pointer, but the server negotiated "
                f"{ctx.protocol_version or 'no version'}, before this became a MUST."
            )
        )
        return self.finding(
            verdict, evidence=f"{res.request_line()}\nWWW-Authenticate: {www!r}", notes=note
        )


def _resource_metadata_pointer(www_authenticate: str) -> str:
    """Return the `resource_metadata` URL from a challenge, if it is a usable one."""
    for chunk in www_authenticate.replace(",", " ").split():
        if chunk.lower().startswith("resource_metadata="):
            url = chunk.split("=", 1)[1].strip().strip('"\'')
            parts = urlsplit(url)
            if parts.scheme in ("http", "https") and parts.netloc:
                return url
    return ""


class MissingProtectedResourceMetadata(Detector):
    """#4 — no /.well-known/oauth-protected-resource with authorization_servers."""

    gap_id = "missing-protected-resource-metadata"
    name = "Missing OAuth Protected Resource Metadata (RFC 9728)"
    tier = 1
    severity = Severity.MEDIUM
    # Read the runner's single discovery pass rather than re-fetching. This is the same
    # document #10 reasons about, so sharing it means the two can never disagree about one
    # server, and every URL we tried is recorded once in the report's discovery notes.
    needs_oauth = True
    spec_reference = (
        "MCP Authorization: servers MUST expose RFC 9728 metadata at "
        "/.well-known/oauth-protected-resource including authorization_servers. "
        "RFC 9728 §3.1 locates it by inserting the well-known suffix before the "
        "resource path."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        # Reuse the runner's single discovery pass when it ran, so this detector and #10
        # can never disagree about the same document. Falls back to its own fetch so a
        # Tier-1-only scan stays self-contained.
        if ctx.oauth is not None and ctx.oauth.attempted:
            return self._from_discovery(ctx)
        return await self._fetch(ctx)

    def _from_discovery(self, ctx: ProbeContext):
        disc = ctx.oauth
        assert disc is not None
        if isinstance(disc.prm, dict):
            return self._grade_document(ctx, disc.prm, f"PRM at {disc.prm_url}", disc)
        return self._absent(
            ctx,
            "; ".join(disc.notes[:4]) or f"no PRM document (tried {disc.prm_url})",
        )

    async def _fetch(self, ctx: ProbeContext):
        probe: Probe = ctx.probe
        attempts: list[str] = []
        for url in prm_candidates(ctx.target.url):
            res = await probe.request("GET", url)
            if not res.ok:
                attempts.append(f"{url} -> transport error: {res.error}")
                continue
            attempts.append(f"{url} -> HTTP {res.status}")
            if res.status == 200 and isinstance(res.json, dict):
                return self._grade_document(ctx, res.json, res.evidence(), None)
        return self._absent(ctx, "; ".join(attempts))

    def _grade_document(self, ctx: ProbeContext, doc: dict, evidence: str, disc):
        servers = doc.get("authorization_servers")
        if isinstance(servers, list) and any(
            isinstance(s, str) and s.strip() for s in servers
        ):
            count = sum(1 for s in servers if isinstance(s, str) and s.strip())
            notes = f"authorization_servers present ({count} entr{'y' if count == 1 else 'ies'})."
            if disc is not None and disc.resource_mismatch:
                notes += (
                    " NOTE: the document's `resource` field names a different host than "
                    "the target, so it may describe another resource (RFC 9728 §3.3)."
                )
            return self.finding(Verdict.NO_GAP, evidence=evidence, notes=notes)

        if servers is not None and not isinstance(servers, list):
            # Previously a JSON string here counted as "present" and its character count
            # was reported as an entry count.
            return self.finding(
                Verdict.HAS_GAP,
                evidence=evidence,
                notes=(
                    f"Metadata document present but authorization_servers is "
                    f"{type(servers).__name__}, not the array RFC 9728 requires."
                ),
            )

        # A document that exists but omits the required field is non-compliant on its own
        # terms, whatever revision the server negotiated — it published RFC 9728 metadata
        # and got it wrong. Graded strictly on purpose; the version gate covers *absence*.
        return self.finding(
            Verdict.HAS_GAP,
            evidence=evidence,
            notes="Metadata document present but authorization_servers missing/empty.",
        )

    def _absent(self, ctx: ProbeContext, evidence: str):
        if ctx.targets_strict_spec:
            return self.finding(
                Verdict.HAS_GAP,
                evidence=evidence,
                notes=(
                    "No RFC 9728 metadata document at either the path-inserted or the "
                    "origin well-known location."
                ),
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=evidence,
            notes=(
                "No metadata document found; the server negotiated "
                f"{ctx.protocol_version or 'no version'}, before RFC 9728 became a MUST."
            ),
        )


class SessionIdInUrl(Detector):
    """#5 — session id carried in URL/query (legacy SSE) instead of header."""

    gap_id = "session-id-in-url"
    name = "Session identifier carried in URL/query string"
    tier = 1
    severity = Severity.MEDIUM
    spec_reference = (
        "OAuth 2.1 §5: tokens MUST NOT appear in URI query. MCP Streamable HTTP moved "
        "the session to the Mcp-Session-Id header."
    )

    _SESSION_QS = re.compile(r"[?&]?(session[_-]?id|sid)=", re.IGNORECASE)

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe

        # 1) target URL itself already carries a session id?
        if self._SESSION_QS.search(urlsplit(ctx.target.url).query or ""):
            return self.finding(
                Verdict.HAS_GAP,
                evidence=ctx.target.url,
                notes="Target URL contains a session id in its query string.",
            )

        # 2) Did the handshake hand the session back in the header, as it should?
        if ctx.session_id:
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"Mcp-Session-Id header present (len={len(ctx.session_id)})",
                notes="Session conveyed via header per Streamable HTTP.",
            )

        init = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
        if not init.ok:
            return self.finding(Verdict.ERROR, evidence=init.evidence())

        header_sid = init.headers.get("mcp-session-id")
        if header_sid:
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"Mcp-Session-Id header present (len={len(header_sid)})",
                notes="Session conveyed via header per Streamable HTTP.",
            )

        # 3) Legacy SSE servers advertise the POST endpoint (with ?sessionId=) in an
        #    `endpoint` event on the GET stream. That stream stays open by design, so the
        #    read is capped: waiting for the body to end used to burn the whole timeout and
        #    then discard the bytes that already contained the answer.
        sse = await probe.request(
            "GET", ctx.target.url,
            headers={"Accept": "text/event-stream"},
            read_bytes=4096,
        )
        body = sse.text if sse.ok else ""
        if self._SESSION_QS.search(body):
            return self.finding(
                Verdict.HAS_GAP,
                evidence=f"{sse.request_line()}\n{body[:300]}",
                notes="Legacy SSE endpoint event exposes session id in the message URL.",
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=f"{init.evidence()}\n--- SSE probe ---\n{sse.evidence(200)}",
            notes=(
                "No header session id and no URL-borne session id observed. The server may "
                "be stateless (no session at all), in which case this gap cannot apply."
            ),
        )
