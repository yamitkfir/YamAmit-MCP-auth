"""Tier 1 detectors — easy: single unauthenticated request, well-known GET, header read.

Each class maps exactly one gap from OUTLINE.md and is independent of the others.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ..models import ProbeContext, Severity, Verdict
from ..probe import Probe, jsonrpc_result
from .base import Detector


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
        # Reach a privileged operation with NO Authorization header.
        res = await probe.mcp_call(ctx.target.url, "tools/list", {})
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        if res.status == 200 and jsonrpc_result(res) is not None:
            tools = jsonrpc_result(res).get("tools", [])
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes=f"tools/list returned {len(tools)} tool(s) without any credential.",
            )
        if res.status in (401, 403):
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Server rejects unauthenticated privileged calls.",
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=res.evidence(),
            notes=f"Unexpected status {res.status}; could not confirm tool access.",
        )


class NoTlsTransport(Detector):
    """#2 — cleartext HTTP on a non-loopback host."""

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

        if ctx.target.scheme == "https":
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"endpoint scheme = https ({ctx.target.url})",
            )

        # http:// on a remote host. Check whether it redirects to https.
        probe: Probe = ctx.probe
        res = await probe.request("GET", ctx.target.url)
        location = res.headers.get("location", "") if res.ok else ""
        if res.ok and res.status in (301, 302, 307, 308) and location.startswith("https"):
            return self.finding(
                Verdict.NO_GAP,
                evidence=res.evidence(),
                notes="Cleartext endpoint redirects to HTTPS.",
            )
        return self.finding(
            Verdict.HAS_GAP,
            evidence=f"endpoint scheme = http on non-loopback host {ctx.target.host}",
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
        res = await probe.mcp_call(ctx.target.url, "tools/list", {})
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        if res.status not in (401, 403):
            # No challenge issued at all — this control simply isn't exercised here.
            return self.finding(
                Verdict.NOT_APPLICABLE,
                evidence=res.evidence(),
                notes=(
                    "Server did not issue a 401/403, so the WWW-Authenticate MUST is "
                    "not triggered (see no-authentication-remote for the real risk)."
                ),
            )

        www = res.headers.get("www-authenticate", "")
        has_pointer = "resource_metadata" in www.lower()
        if has_pointer:
            return self.finding(
                Verdict.NO_GAP,
                evidence=f"WWW-Authenticate: {www}",
            )
        verdict = Verdict.HAS_GAP if ctx.targets_strict_spec else Verdict.INCONCLUSIVE
        note = (
            "401 without resource_metadata pointer."
            if ctx.targets_strict_spec
            else "401 lacks pointer, but server negotiated <2025-06-18 where it is not a MUST."
        )
        return self.finding(verdict, evidence=f"WWW-Authenticate: {www!r}", notes=note)


class MissingProtectedResourceMetadata(Detector):
    """#4 — no /.well-known/oauth-protected-resource with authorization_servers."""

    gap_id = "missing-protected-resource-metadata"
    name = "Missing OAuth Protected Resource Metadata (RFC 9728)"
    tier = 1
    severity = Severity.MEDIUM
    spec_reference = (
        "MCP Authorization 2025-06-18: servers MUST expose RFC 9728 metadata at "
        "/.well-known/oauth-protected-resource including authorization_servers."
    )

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe
        parts = urlsplit(ctx.target.url)
        well_known = urlunsplit(
            (parts.scheme, parts.netloc, "/.well-known/oauth-protected-resource", "", "")
        )
        res = await probe.request("GET", well_known)
        if not res.ok:
            return self.finding(Verdict.ERROR, evidence=res.evidence())

        strict = ctx.targets_strict_spec
        if res.status == 200 and isinstance(res.json, dict):
            servers = res.json.get("authorization_servers")
            if servers:
                return self.finding(
                    Verdict.NO_GAP,
                    evidence=res.evidence(),
                    notes=f"authorization_servers present ({len(servers)} entry).",
                )
            return self.finding(
                Verdict.HAS_GAP,
                evidence=res.evidence(),
                notes="Metadata document present but authorization_servers missing/empty.",
            )
        # 404 / non-JSON
        verdict = Verdict.HAS_GAP if strict else Verdict.INCONCLUSIVE
        note = (
            "No RFC 9728 metadata document."
            if strict
            else "No metadata doc; server negotiated <2025-06-18 where 9728 is not a MUST."
        )
        return self.finding(verdict, evidence=res.evidence(), notes=note)


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

    _SESSION_QS = re.compile(r"[?&](session_?id|sid)=", re.IGNORECASE)

    async def detect(self, ctx: ProbeContext):
        na = self.require_http_transport(ctx)
        if na:
            return na

        probe: Probe = ctx.probe

        # 1) target URL itself already carries a session id?
        if self._SESSION_QS.search(ctx.target.url):
            return self.finding(
                Verdict.HAS_GAP,
                evidence=ctx.target.url,
                notes="Target URL contains a session id in its query string.",
            )

        # 2) Open a session and see how the server hands it back.
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

        # Legacy SSE servers advertise the POST endpoint (with ?sessionId=) in an
        # `endpoint` event on the GET stream.
        sse = await probe.request(
            "GET", ctx.target.url, headers={"Accept": "text/event-stream"}
        )
        body = sse.text if sse.ok else ""
        if self._SESSION_QS.search(body) or "sessionId=" in body:
            return self.finding(
                Verdict.HAS_GAP,
                evidence=body[:300],
                notes="Legacy SSE endpoint event exposes session id in the message URL.",
            )
        return self.finding(
            Verdict.INCONCLUSIVE,
            evidence=init.evidence(),
            notes="No header session id and no URL-borne session id observed.",
        )
