"""Discovery + independent detector execution + report aggregation."""

from __future__ import annotations

import asyncio

from .detectors import build_detectors
from .models import Finding, ProbeContext, TargetSpec, Verdict
from .oauth import discover_oauth
from .probe import Probe, jsonrpc_result


async def _discover(ctx: ProbeContext, want_oauth: bool) -> None:
    """One lightweight unauthenticated initialize to learn protocol version / liveness.

    If any selected detector reasons about OAuth metadata, also fetch the PRM -> AS
    metadata chain once here (into ctx.oauth) so those detectors stay independent.

    Failures are non-fatal: detectors still run and report ERROR/INCONCLUSIVE as needed.
    """
    if not ctx.target.is_http_transport:
        ctx.discovery_notes.append("Non-HTTP transport; HTTP auth detectors will be N/A.")
        return

    probe: Probe = ctx.probe  # type: ignore[assignment]
    res = await probe.mcp_call(ctx.target.url, "initialize", probe.initialize_params())
    if not res.ok:
        ctx.discovery_notes.append(f"initialize transport error: {res.error}")
    else:
        # The negotiated protocol version may arrive as a response header or in the result.
        ver = res.headers.get("mcp-protocol-version")
        result = jsonrpc_result(res)
        if not ver and isinstance(result, dict):
            ver = result.get("protocolVersion")
        ctx.protocol_version = ver
        if isinstance(result, dict):
            ctx.server_info = result.get("serverInfo", {})
            ctx.initialize_ok = res.status == 200
        ctx.discovery_notes.append(
            f"initialize -> HTTP {res.status}, protocolVersion={ver or 'unspecified'}"
        )

    if want_oauth:
        ctx.oauth = await discover_oauth(probe, ctx.target.url)
        ctx.discovery_notes.extend(ctx.oauth.notes)


async def scan(
    url: str, tiers: set[int] | None = None, exclude: set[str] | None = None
) -> dict:
    """Run all (selected) detectors against one target and return a report dict."""
    target = TargetSpec(url=url)
    detectors = build_detectors(tiers, exclude)
    async with Probe() as probe:
        ctx = ProbeContext(target=target, probe=probe)
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
                    notes=f"detector raised {type(e).__name__}: {e}",
                )

        findings = await asyncio.gather(*(run_one(d) for d in detectors))

    return _build_report(ctx, list(findings))


def _build_report(ctx: ProbeContext, findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.verdict.value] = counts.get(f.verdict.value, 0) + 1
    return {
        "target": ctx.target.url,
        "protocol_version": ctx.protocol_version,
        "server_info": ctx.server_info,
        "discovery": ctx.discovery_notes,
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }
