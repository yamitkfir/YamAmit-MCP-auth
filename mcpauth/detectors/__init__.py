"""Detector registry.

Add a detector class here and it is automatically available to the runner and CLI.
Detectors are independent and may be run in any order / concurrently.
"""

from __future__ import annotations

from .base import Detector
from .tier1 import (
    MissingProtectedResourceMetadata,
    MissingWwwAuthenticate,
    NoAuthenticationRemote,
    NoTlsTransport,
    SessionIdInUrl,
)
from .tier2 import (
    AuthEndpointsNotHttps,
    CorsMisconfiguration,
    ImplicitFlowEnabled,
    MissingAsMetadata,
    OpenDcr,
    OriginNotValidated,
    PredictableSessionId,
)

ALL_DETECTORS: list[type[Detector]] = [
    # Tier 1 — easy
    NoAuthenticationRemote,
    NoTlsTransport,
    MissingWwwAuthenticate,
    MissingProtectedResourceMetadata,
    SessionIdInUrl,
    # Tier 2 — medium
    PredictableSessionId,
    OriginNotValidated,
    CorsMisconfiguration,
    AuthEndpointsNotHttps,
    MissingAsMetadata,
    ImplicitFlowEnabled,
    OpenDcr,
]


# Gap ids of detectors that mutate target state — `mcpauth scan --safe` skips these.
WRITE_DETECTORS: set[str] = {cls.gap_id for cls in ALL_DETECTORS if cls.has_side_effects}


def build_detectors(
    tiers: set[int] | None = None, exclude: set[str] | None = None
) -> list[Detector]:
    instances = [cls() for cls in ALL_DETECTORS]
    if tiers is not None:
        instances = [d for d in instances if d.tier in tiers]
    if exclude:
        instances = [d for d in instances if d.gap_id not in exclude]
    return instances
