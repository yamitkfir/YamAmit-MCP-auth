"""Detector contract + shared gating helpers.

A detector is any async callable `detect(ctx) -> Finding`. We express that as a small
class so each one carries its metadata (id, name, tier, severity, spec ref) and the
registry can list them. Detectors must be independent: read only `ctx`, never another
detector's Finding.
"""

from __future__ import annotations

import json
import re
from typing import Awaitable, Callable

from ..models import Finding, ProbeContext, Severity, Verdict
from ..probe import HttpResult

# Error codes that genuinely mark a response as an *authentication/authorization* decision.
#
# Deliberately NOT included:
#   * `invalid_request` — RFC 6750 §3.1 defines it as "the request is malformed", which is
#     the opposite of an auth decision. Accepting it meant a 403 carrying
#     {"error":"invalid_request","message":"missing sessionId"} was credited as proof that
#     the server enforces authentication, handing `no-authentication-remote` a NO_GAP.
#   * `access_denied` — an RFC 6749 §4.1.2.1 *authorization endpoint* error (the user
#     refused consent), not something a protected resource returns to reject a token.
_OAUTH_ERROR_CODES = (
    "invalid_token",
    "insufficient_scope",
    "invalid_client",
    "unauthorized_client",
)

_ERROR_FIELD = re.compile(r'"error"\s*:\s*"([^"]+)"')


def is_auth_challenge(res: HttpResult) -> tuple[bool, str]:
    """Did the server *authenticate*-reject this request? Returns (yes, why).

    A `401` is unambiguous: it means "log in first".

    A `403` is not. It is what an edge proxy, a Web Application Firewall, a geo-fence, a
    bot filter, or an IP denylist returns — and the tool used to credit any `403` as proof
    that the server enforces authentication. That turned a *blocked scan* into a clean bill
    of health on the single most important check (`no-authentication-remote`), which is the
    worst possible direction for this error to run.

    So a `403` counts only with corroboration: a `WWW-Authenticate` header (the standard
    "here is how to log in" pointer) or an OAuth error code in the body. Under MCP
    2026-07-28 an insufficient-scope refusal is specified as exactly that — `403` plus
    `WWW-Authenticate: Bearer error="insufficient_scope"` — so real authorization
    decisions are corroborated, and bare denials stay uncounted.

    The code must appear as the body's `error` *field*, not merely somewhere in the text: a
    substring search matched prose and unrelated JSON, so an ordinary validation error was
    read as an authentication requirement.
    """
    if res.status == 401:
        return True, "HTTP 401 — an unambiguous authentication challenge"

    if res.status != 403:
        return False, f"HTTP {res.status} is not an authentication challenge"

    www = res.headers.get("www-authenticate", "")
    if www:
        return True, f"HTTP 403 corroborated by WWW-Authenticate: {www}"

    code = _body_error_code(res.text or "")
    if code in _OAUTH_ERROR_CODES:
        return True, f"HTTP 403 corroborated by OAuth error code {code!r} in the body"
    if code:
        return False, (
            f"HTTP 403 whose body reports error {code!r}, which is not an "
            "authentication/authorization decision (RFC 6750 §3.1) — so it is NOT evidence "
            "that the server requires authentication"
        )

    return False, (
        "HTTP 403 with no WWW-Authenticate header and no OAuth error code — this is a "
        "generic refusal (WAF, geo-block, IP denylist, bot filter all answer 403), so it "
        "is NOT evidence that the server requires authentication"
    )


def _body_error_code(text: str) -> str:
    """The lowercased `error` value from a JSON body, or "" if there isn't one.

    Falls back to a regex when the body is truncated at the read cap (and so no longer
    parses), because a clipped body still shows its `error` field near the front.
    """
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, str):
            return err.strip().lower()
        # OAuth-shaped nesting: {"error": {"code": "invalid_token"}}
        if isinstance(err, dict):
            for key in ("code", "error", "message"):
                val = err.get(key)
                if isinstance(val, str):
                    return val.strip().lower()
        return ""
    m = _ERROR_FIELD.search(text)
    return m.group(1).strip().lower() if m else ""


class Detector:
    gap_id: str = ""
    name: str = ""
    tier: int = 0
    severity: Severity = Severity.MEDIUM
    spec_reference: str = ""
    # Detectors that reason about the OAuth metadata chain (PRM -> AS metadata) set
    # this so the runner fetches that chain once, into ctx.oauth, before running them.
    needs_oauth: bool = False
    # Detectors that mutate target state (e.g. a registration POST) set this so they are
    # excluded unless the caller opts IN via `mcpauth scan --unsafe-writes`. Read-only
    # detectors leave it False.
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
