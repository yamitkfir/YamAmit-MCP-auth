"""Validate every Tier-2 detector against live sandbox servers.

Three postures, same rationale as Tier 1 (no single server exercises every HAS and NO
path — e.g. a server that serves valid AS metadata cannot also demonstrate *missing*
metadata):

  vuln_oauth    — predictable sessions, no Origin check, reflecting CORS, http OAuth
                  endpoints, implicit grant, open DCR; but DOES serve valid AS metadata
  hardened_oauth— every Tier-2 gap closed
  broken_auth   — claims strict spec yet exposes no AS metadata (the #10 HAS anchor)

Each gap lists its expected verdict per posture; a detector is "done" only when every
expectation holds.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpauth.runner import scan
from mcpauth.models import Verdict

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "sandbox"

H = Verdict.HAS_GAP.value
N = Verdict.NO_GAP.value
NA = Verdict.NOT_APPLICABLE.value

# gap_id -> {posture: expected_verdict}.  Missing posture = not asserted.
EXPECTATIONS = {
    "predictable-session-id": {"voauth": H, "hoauth": N},
    "origin-not-validated": {"voauth": H, "hoauth": N},
    "cors-misconfiguration": {"voauth": H, "hoauth": N},
    "auth-endpoints-not-https": {"voauth": H, "hoauth": N, "broken": NA},
    "missing-as-metadata": {"voauth": N, "hoauth": N, "broken": H},
    "implicit-flow-enabled": {"voauth": H, "hoauth": N, "broken": NA},
    "open-dcr": {"voauth": H, "hoauth": N, "broken": NA},
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _boot(script: str, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(SANDBOX / script), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return proc
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError(f"{script} did not start on :{port}")


@pytest.fixture(scope="module")
def urls():
    ports = {k: _free_port() for k in ("voauth", "hoauth", "broken")}
    procs = [
        _boot("vulnerable_oauth_server.py", ports["voauth"]),
        _boot("hardened_oauth_server.py", ports["hoauth"]),
        _boot("broken_auth_server.py", ports["broken"]),
    ]
    time.sleep(0.3)
    try:
        yield {k: f"http://127.0.0.1:{p}/mcp" for k, p in ports.items()}
    finally:
        for p in procs:
            p.terminate()


# Cache one Tier-2 scan per posture across all gap assertions.
_cache: dict[str, dict[str, str]] = {}


def _verdicts(url: str) -> dict[str, str]:
    if url not in _cache:
        report = asyncio.run(scan(url, tiers={2}))
        _cache[url] = {f["gap_id"]: f["verdict"] for f in report["findings"]}
    return _cache[url]


@pytest.mark.parametrize(
    "gap,posture,expected",
    [(g, p, v) for g, m in EXPECTATIONS.items() for p, v in m.items()],
)
def test_detector_verdict(urls, gap, posture, expected):
    verdicts = _verdicts(urls[posture])
    assert verdicts[gap] == expected, (
        f"{gap} on {posture}: expected {expected}, got {verdicts[gap]}"
    )


def test_full_registry_runs_clean_against_vuln_oauth(urls):
    """All detectors (every tier) run against the vuln-oauth server with no ERROR/crash."""
    report = asyncio.run(scan(urls["voauth"]))
    errors = [f["gap_id"] for f in report["findings"] if f["verdict"] == Verdict.ERROR.value]
    assert not errors, f"unexpected ERROR verdicts: {errors}"
    # Sanity: both tiers are present in a default (all-tier) scan.
    tiers_seen = {f["gap_id"] for f in report["findings"]}
    assert "no-authentication-remote" in tiers_seen  # tier 1
    assert "open-dcr" in tiers_seen                   # tier 2


def test_open_dcr_cleans_up_after_itself(urls):
    """open-dcr must delete the client it creates (RFC 7592) and say so in its notes."""
    report = asyncio.run(scan(urls["voauth"], tiers={2}))
    dcr = next(f for f in report["findings"] if f["gap_id"] == "open-dcr")
    assert dcr["verdict"] == Verdict.HAS_GAP.value
    # The vuln-oauth server supports RFC 7592 delete, so cleanup must succeed...
    assert "deleted via RFC 7592" in dcr["notes"], dcr["notes"]
    # ...and must NOT have left the failure marker behind.
    assert "MANUAL CLEANUP NEEDED" not in dcr["notes"], dcr["notes"]


def test_safe_flag_excludes_open_dcr(urls):
    """`--safe` (WRITE_DETECTORS exclusion) must drop the only write detector."""
    from mcpauth.detectors import WRITE_DETECTORS

    assert WRITE_DETECTORS == {"open-dcr"}
    report = asyncio.run(scan(urls["voauth"], tiers={2}, exclude=WRITE_DETECTORS))
    gap_ids = {f["gap_id"] for f in report["findings"]}
    assert "open-dcr" not in gap_ids
    assert "origin-not-validated" in gap_ids  # other tier-2 detectors still run
