"""Core data types shared by every detector.

The whole tool revolves around one idea: for each known auth gap, a detector
inspects a target and returns a `Finding` with one of the verdicts below. Detectors
are independent — none reads another's result — so the runner may execute them in any
order or in parallel.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .netguard import is_loopback_host

if TYPE_CHECKING:
    from .oauth import OAuthDiscovery
    from .probe import Probe


class Verdict(str, enum.Enum):
    """The conclusion a detector reaches about one gap on one target."""

    HAS_GAP = "HAS_GAP"          # the vulnerability/gap is present
    NO_GAP = "NO_GAP"            # the server correctly defends against it
    NOT_APPLICABLE = "NOT_APPLICABLE"  # gap can't apply (e.g. stdio transport, wrong spec rev)
    INCONCLUSIVE = "INCONCLUSIVE"      # probe ran but evidence is ambiguous
    ERROR = "ERROR"              # probe could not be completed (network, etc.)


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """One detector's conclusion about one gap."""

    gap_id: str
    name: str
    verdict: Verdict
    severity: Severity
    evidence: str = ""           # raw request/response snippet justifying the verdict
    spec_reference: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "gap_id": self.gap_id,
            "name": self.name,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "spec_reference": self.spec_reference,
            "notes": self.notes,
        }


@dataclass
class TargetSpec:
    """What the user pointed us at."""

    url: str

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    @property
    def is_http_transport(self) -> bool:
        return self.scheme in ("http", "https")


@dataclass
class ProbeContext:
    """Shared, read-only context handed to every detector.

    Populated once by the runner during a lightweight discovery phase so individual
    detectors don't each re-run `initialize`. Detectors may still issue their own
    targeted probes via `probe`.
    """

    target: TargetSpec
    probe: "Probe"                        # TYPE_CHECKING import avoids the runtime cycle
    protocol_version: str | None = None   # negotiated MCP-Protocol-Version, if learned
    server_info: dict = field(default_factory=dict)
    initialize_ok: bool = False           # did unauthenticated initialize succeed?
    oauth: "OAuthDiscovery | None" = None  # PRM->AS metadata chain (fetched once, Tier-2+)
    discovery_notes: list[str] = field(default_factory=list)
    reachable: bool = False               # did ANY request to the target complete?
    # Session id the server handed back on `initialize`, for revisions 2025-03-26 through
    # 2025-11-25 that use one. It is plumbing, NOT a credential, so detectors carry it while
    # still sending no Authorization header — otherwise a wide-open server that merely wants
    # a session id answers 400 and gets graded "unknown" on the most important check.
    session_id: str | None = None
    www_authenticate: str = ""             # challenge seen during discovery, if any
    # Optional sink for durable records of anything this scan *created* on the target.
    # Only `open-dcr` writes, and only it uses this. The library never picks a path or
    # touches the filesystem; the caller supplies the sink. It exists because a created
    # `client_id` used to live solely in the returned Finding, so any interruption before
    # the report was written orphaned a real registration on someone else's server with no
    # record of its id. See `OpenDcr._journal`.
    write_journal: "Callable[[dict], None] | None" = None

    def session_headers(self) -> dict[str, str]:
        """Headers a detector should carry to look like a normal client mid-conversation.

        Deliberately contains no `Authorization`: the point of most of these checks is what
        the server does for a caller who has *not* logged in.
        """
        return {"Mcp-Session-Id": self.session_id} if self.session_id else {}

    # First spec revision that makes the RFC 9728 / 8707 audience rules MANDATORY.
    SPEC_STRICT = "2025-06-18"

    @property
    def targets_strict_spec(self) -> bool:
        """True if the server negotiated a revision where 9728/audience are MUSTs.

        MCP revisions are `YYYY-MM-DD` strings, so they sort chronologically and the test
        is **`>=`, not `==`**. That matters: every revision after 2025-06-18 keeps the RFC
        9728 requirement (under 2026-07-28 it is an unconditional MUST), so comparing
        against one hardcoded date would let precisely the servers that keep up with the
        spec off the hook, and print a note claiming they negotiated something older.

        When no version is negotiated the spec says assume 2025-03-26 (the weaker bar).
        An unparseable value is treated as not-strict rather than trusted.
        """
        return _spec_at_least(self.protocol_version, self.SPEC_STRICT)


_SPEC_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _spec_at_least(version: str | None, floor: str) -> bool:
    """Chronological comparison of two MCP revision strings, tolerant of junk."""
    if not version or not _SPEC_DATE.match(version):
        return False
    return version >= floor
