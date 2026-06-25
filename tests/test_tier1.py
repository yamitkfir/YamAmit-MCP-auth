"""Validate every Tier-1 detector against live sandbox servers.

Three server postures, because no single server exercises every detector's HAS and NO
paths (e.g. a no-auth server can never demonstrate a malformed 401):

  vulnerable    — no auth at all; claims strict spec but violates its MUSTs
  hardened      — closes every Tier-1 gap correctly
  broken_auth   — DOES gate on a token, but challenges non-compliantly

Each gap below lists its expected verdict per posture. A detector is "done" only when
every expectation holds. Gap #2 (no-tls) is exempt on loopback, so it's unit-tested via
TargetSpec logic rather than a live cert.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpauth.models import TargetSpec, Verdict
from mcpauth.runner import scan

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "sandbox"

H = Verdict.HAS_GAP.value
N = Verdict.NO_GAP.value
NA = Verdict.NOT_APPLICABLE.value

# gap_id -> {posture: expected_verdict}.  Missing posture = not asserted.
EXPECTATIONS = {
    "no-authentication-remote": {"vuln": H, "hard": N, "broken": N},
    "missing-www-authenticate": {"vuln": NA, "hard": N, "broken": H},
    "missing-protected-resource-metadata": {"vuln": H, "hard": N, "broken": H},
    "session-id-in-url": {"vuln": H, "hard": N},
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
    ports = {k: _free_port() for k in ("vuln", "hard", "broken")}
    procs = [
        _boot("vulnerable_server.py", ports["vuln"]),
        _boot("hardened_server.py", ports["hard"]),
        _boot("broken_auth_server.py", ports["broken"]),
    ]
    time.sleep(0.3)
    try:
        yield {k: f"http://127.0.0.1:{p}/mcp" for k, p in ports.items()}
    finally:
        for p in procs:
            p.terminate()


# Cache one scan per posture across all gap assertions.
_cache: dict[str, dict[str, str]] = {}


def _verdicts(url: str) -> dict[str, str]:
    if url not in _cache:
        report = asyncio.run(scan(url, tiers={1}))
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


# ---- no-tls (#2): pure classification logic, no live cert needed ----------------

def test_no_tls_loopback_is_exempt():
    assert TargetSpec("http://127.0.0.1:9100/mcp").is_loopback is True


def test_no_tls_remote_http_classification():
    t = TargetSpec("http://mcp.example.com/mcp")
    assert t.is_http_transport and not t.is_loopback and t.scheme == "http"


def test_https_remote_classification():
    t = TargetSpec("https://mcp.example.com/mcp")
    assert t.scheme == "https" and not t.is_loopback
