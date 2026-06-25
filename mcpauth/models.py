"""Core data types shared by every detector.

The whole tool revolves around one idea: for each known auth gap, a detector
inspects a target and returns a `Finding` with one of the verdicts below. Detectors
are independent — none reads another's result — so the runner may execute them in any
order or in parallel.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

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
        h = self.host.lower()
        return h in ("localhost", "127.0.0.1", "::1") or h.endswith(".localhost")

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

    # Spec revision that makes 9728/8707 audience rules MANDATORY.
    SPEC_STRICT = "2025-06-18"

    @property
    def targets_strict_spec(self) -> bool:
        """True if the server negotiated the revision where 9728/audience are MUSTs.

        When no version is negotiated the spec says assume 2025-03-26 (the weaker bar).
        """
        return self.protocol_version == self.SPEC_STRICT
