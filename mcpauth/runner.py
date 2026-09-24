"""Discovery + independent detector execution + report aggregation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from .detectors import build_detectors
from .models import Finding, ProbeContext, TargetSpec, Verdict
from .oauth import discover_oauth
from .probe import MCP_PROTOCOL_VERSION, Probe, jsonrpc_result

REPORT_VERSION = 2


async def _handshake(ctx: ProbeContext) -> None:
    """Complete the MCP opening conversation the way a real client does.

    `initialize` -> keep the `Mcp-Session-Id` the server hands back -> send
    `notifications/initialized`. Without this, every later request to a *stateful* server
    (one that expects an ongoing conversation) is rejected with HTTP 400, and the tool
    cannot tell "I forgot the session id" from "this server is broken" — so a server with no
    authentication at all came back INCONCLUSIVE on `no-authentication-remote`.

    The session id is plumbing, not a credential. It is replayed on later probes; no
    `Authorization` header ever is.
    """
    probe: Probe = ctx.probe
    res = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
    if not res.ok:
        kind = "TLS/certificate error" if res.tls_failure else "transport error"
        ctx.discovery_notes.append(f"initialize {kind}: {res.error}")
        return

    ctx.reachable = True
    ctx.session_id = res.headers.get("mcp-session-id")
    ctx.www_authenticate = res.headers.get("www-authenticate", "")

    # Prefer the version the server negotiated in the body: the header is advisory and a
    # server that emitted a weaker value there could otherwise talk its own audit down.
    result = jsonrpc_result(res)
    ver = None
    if isinstance(result, dict):
        ver = result.get("protocolVersion")
        info = result.get("serverInfo")
        ctx.server_info = info if isinstance(info, dict) else {}
        ctx.initialize_ok = res.status == 200
    if not ver:
        ver = res.headers.get("mcp-protocol-version")
    ctx.protocol_version = ver if isinstance(ver, str) else None
    # Every subsequent request must advertise the negotiated revision, not the one we
    # opened with. Setting it on the probe applies it to all detectors at once.
    probe.negotiated_version = ctx.protocol_version

    ctx.discovery_notes.append(
        f"initialize -> HTTP {res.status}, protocolVersion={ctx.protocol_version or 'unspecified'}, "
        f"session={'yes' if ctx.session_id else 'no'}"
    )

    if ctx.session_id:
        # A notification, so no `id` — that absence is what makes it one (JSON-RPC 2.0 §4.1)
        # and what tells the server not to reply.
        ack = await probe.mcp_call(
            ctx.target.url, "notifications/initialized", None,
            headers=ctx.session_headers(), notification=True,
        )
        ctx.discovery_notes.append(
            f"notifications/initialized -> HTTP {ack.status}" if ack.ok
            else f"notifications/initialized transport error: {ack.error}"
        )


async def _release_session(ctx: ProbeContext) -> None:
    """Tear down the session the *handshake* opened.

    Streamable HTTP (2025-03-26 … 2025-11-25) says clients SHOULD release a session with an
    HTTP DELETE. Skipping it is why "every detector is read-only" was not quite true: each
    scan left sessions parked on the target.

    This does NOT clear every session a scan creates, so "leaves no server-side state
    behind" is still not true. It releases `ctx.session_id` only; #6 releases the extra ones
    it opened; but #7 (`tier2.py`) obtains a session on its forged-Origin or control
    `initialize` and releases nothing, and #5's fallback `initialize` can do the same. On a
    stateful target a default scan therefore leaves one session parked.
    """
    if not ctx.session_id:
        return
    res = await ctx.probe.request(
        "DELETE", ctx.target.url,
        headers={
            "Mcp-Session-Id": ctx.session_id,
            # The negotiated revision, not the one we opened with — a server that enforces
            # the header can reject a mismatched DELETE, leaving the session parked.
            "MCP-Protocol-Version": ctx.protocol_version or MCP_PROTOCOL_VERSION,
        },
    )
    ctx.discovery_notes.append(
        f"DELETE session -> HTTP {res.status}" if res.ok
        else f"DELETE session transport error: {res.error}"
    )


async def _discover(ctx: ProbeContext, want_oauth: bool) -> None:
    """Learn protocol version / liveness / session, and optionally the OAuth chain.

    Failures are non-fatal: detectors still run and report ERROR/INCONCLUSIVE as needed.
    """
    if not ctx.target.is_http_transport:
        ctx.discovery_notes.append("Non-HTTP transport; HTTP auth detectors will be N/A.")
        return

    await _handshake(ctx)

    if want_oauth:
        # Hand over the 401 challenge, if we saw one: its `resource_metadata` parameter is
        # the authoritative location of the metadata document (RFC 9728 §5.1).
        ctx.oauth = await discover_oauth(ctx.probe, ctx.target.url, ctx.www_authenticate)
        ctx.discovery_notes.extend(ctx.oauth.notes)


async def scan(
    url: str,
    tiers: set[int] | None = None,
    exclude: set[str] | None = None,
    *,
    insecure_tls: bool = False,
    write_journal: "Callable[[dict], None] | None" = None,
) -> dict:
    """Run all (selected) detectors against one target and return a report dict.

    `write_journal`, if given, is called the moment a write-performing detector creates
    something on the target — before any cleanup is attempted — so the record survives an
    interruption. Only `open-dcr` writes, and it only runs when the caller included it.
    """
    target = TargetSpec(url=url)
    detectors = build_detectors(tiers, exclude)
    async with Probe(insecure_tls=insecure_tls, target_url=url) as probe:
        ctx = ProbeContext(target=target, probe=probe, write_journal=write_journal)
        await _discover(ctx, want_oauth=any(d.needs_oauth for d in detectors))

        # Independent → run concurrently. Any detector crash becomes an ERROR finding.
        async def run_one(d) -> Finding:
            try:
                return await d.detect(ctx)
            except Exception as e:  # noqa: BLE001
                return Finding(
                    gap_id=d.gap_id,
                    name=d.name,
                    verdict=Verdict.ERROR,
                    severity=d.severity,
                    # An ERROR finding still has to say what it was probing, or the report
                    # has a hole in it where a verdict should be.
                    evidence=(
                        f"detector {d.gap_id} raised while probing {target.url}: "
                        f"{type(e).__name__}: {e}"
                    ),
                    spec_reference=getattr(d, "spec_reference", ""),
                    notes=f"detector raised {type(e).__name__}: {e}",
                )

        findings = await asyncio.gather(*(run_one(d) for d in detectors))
        await _release_session(ctx)

    return _build_report(ctx, list(findings), detectors, tiers, exclude)


def _build_report(
    ctx: ProbeContext,
    findings: list[Finding],
    detectors: list,
    tiers: set[int] | None,
    exclude: set[str] | None,
) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.verdict.value] = counts.get(f.verdict.value, 0) + 1
    report = {
        "report_version": REPORT_VERSION,
        "target": ctx.target.url,
        "reachable": ctx.reachable,
        "protocol_version": ctx.protocol_version,
        "server_info": ctx.server_info,
        # Record the selection, so a consumer can tell a read-only or --tier 1 run from a full
        # one instead of guessing from which gap ids happen to be present.
        "detectors_run": [d.gap_id for d in detectors],
        "tiers_selected": sorted(tiers) if tiers else "all",
        "excluded": sorted(exclude) if exclude else [],
        "discovery": ctx.discovery_notes,
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }
    if ctx.oauth is not None:
        report["oauth"] = {
            "prm_url": ctx.oauth.prm_url,
            "prm_source": ctx.oauth.prm_source,
            "authorization_servers": ctx.oauth.authorization_servers,
            "as_metadata_url": ctx.oauth.as_metadata_url,
            "as_metadata_usable": ctx.oauth.as_metadata_usable,
            "unresolved_servers": ctx.oauth.unresolved_servers,
            "blocked_urls": ctx.oauth.blocked_urls,
            "external_hosts_contacted": ctx.oauth.external_hosts,
        }
    return report
