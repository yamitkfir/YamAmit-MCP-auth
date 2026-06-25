"""Detector contract + shared gating helpers.

A detector is any async callable `detect(ctx) -> Finding`. We express that as a small
class so each one carries its metadata (id, name, tier, severity, spec ref) and the
registry can list them. Detectors must be independent: read only `ctx`, never another
detector's Finding.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from ..models import Finding, ProbeContext, Severity, Verdict


class Detector:
    gap_id: str = ""
    name: str = ""
    tier: int = 0
    severity: Severity = Severity.MEDIUM
    spec_reference: str = ""
    # Detectors that reason about the OAuth metadata chain (PRM -> AS metadata) set
    # this so the runner fetches that chain once, into ctx.oauth, before running them.
    needs_oauth: bool = False
    # Detectors that mutate target state (e.g. a registration POST) set this so callers
    # can opt out via `mcpauth scan --safe`. Read-only detectors leave it False.
    has_side_effects: bool = False

    async def detect(self, ctx: ProbeContext) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError

    # --- helpers so subclasses produce consistent, well-formed Findings -----------

    def finding(
        self, verdict: Verdict, evidence: str = "", notes: str = ""
    ) -> Finding:
        return Finding(
            gap_id=self.gap_id,
            name=self.name,
            verdict=verdict,
            severity=self.severity,
            evidence=evidence,
            spec_reference=self.spec_reference,
            notes=notes,
        )

    def na(self, why: str) -> Finding:
        return self.finding(Verdict.NOT_APPLICABLE, notes=why)

    def require_http_transport(self, ctx: ProbeContext) -> Finding | None:
        """Return an N/A finding if the target isn't an HTTP-family transport."""
        if not ctx.target.is_http_transport:
            return self.na(
                "Target is not an HTTP-family transport (stdio servers pull "
                "credentials from the environment; OAuth flow does not apply)."
            )
        return None


DetectFn = Callable[[ProbeContext], Awaitable[Finding]]
