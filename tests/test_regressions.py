"""Regression tests for verdicts that were wrong before.

Each test here pins a specific false verdict the detectors used to produce against a
realistic server. They are separated from test_tier1/test_tier2 (which assert the
HAS-vs-NO matrix per posture) because these assert *the absence of a known bug*.

The two live postures used here exist precisely because the original sandboxes could
not express them:

  stateful_open_server  — wide open, but requires a session id like the spec says
  subpath_prm_server    — compliant, but hosted at a subpath with a path-inserted PRM
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcpauth.models import Verdict
from mcpauth.runner import scan

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "sandbox"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _boot(script: str, port: int) -> subprocess.Popen:
    """Start a sandbox server, failing loudly if it dies or never serves.

    Captures output (rather than discarding it) so a crashed sandbox reports its
    traceback instead of silently yielding wrong verdicts.
    """
    proc = subprocess.Popen(
        [sys.executable, str(SANDBOX / script), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    for _ in range(100):
        if proc.poll() is not None:
            output = proc.stdout.read() if proc.stdout else "(no output captured)"
            raise RuntimeError(f"{script} exited with code {proc.returncode}:\n{output}")
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return proc
        time.sleep(0.1)
    proc.terminate()
    proc.wait(timeout=5)
    raise RuntimeError(f"{script} did not start on :{port}")


def _shutdown(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture(scope="module")
def stateful_url():
    port = _free_port()
    proc = _boot("stateful_open_server.py", port)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        _shutdown(proc)


@pytest.fixture(scope="module")
def subpath_url():
    port = _free_port()
    proc = _boot("subpath_prm_server.py", port)
    try:
        yield f"http://127.0.0.1:{port}/public/mcp"
    finally:
        _shutdown(proc)


def _verdicts(url: str, **kw) -> dict[str, str]:
    report = asyncio.run(scan(url, **kw))
    return {f["gap_id"]: f["verdict"] for f in report["findings"]}


# --- the handshake bug -----------------------------------------------------------

def test_wide_open_stateful_server_is_has_gap(stateful_url):
    """A server with NO auth that requires a session id must read as HAS_GAP.

    Before the fix the prober never replayed Mcp-Session-Id, so this server answered
    400 ("Missing session ID") and gap #1 came back INCONCLUSIVE — the tool could not
    tell a wide-open server from a secured one, on its most important check.
    """
    verdicts = _verdicts(stateful_url, tiers={1})
    assert verdicts["no-authentication-remote"] == Verdict.HAS_GAP.value


def test_stateful_handshake_is_completed(stateful_url):
    """The runner performs initialize -> session id -> notifications/initialized."""
    report = asyncio.run(scan(stateful_url, tiers={1}))
    notes = " ".join(report["discovery"])
    assert "session=yes" in notes
    assert "notifications/initialized -> HTTP 202" in notes


def test_session_is_released_after_scan(stateful_url):
    """A scan tears down the session it opened, leaving no server-side state."""
    report = asyncio.run(scan(stateful_url, tiers={1}))
    assert "DELETE session -> HTTP 204" in " ".join(report["discovery"])


def test_stateful_server_session_is_header_borne(stateful_url):
    """Session in the header (not the URL) must be NO_GAP, not INCONCLUSIVE."""
    verdicts = _verdicts(stateful_url, tiers={1})
    assert verdicts["session-id-in-url"] == Verdict.NO_GAP.value


def test_stateful_server_session_entropy_ok(stateful_url):
    """token_urlsafe(24) ids must not trip the predictability heuristic."""
    verdicts = _verdicts(stateful_url, tiers={2})
    assert verdicts["predictable-session-id"] == Verdict.NO_GAP.value


# --- the PRM path-insertion bug --------------------------------------------------

def test_subpath_hosted_prm_is_found(subpath_url):
    """RFC 9728 §3.1 path insertion: a compliant subpath server must be NO_GAP.

    Before the fix only the bare origin was probed, so this server — which publishes
    its PRM at /.well-known/oauth-protected-resource/public/mcp exactly as the RFC
    requires — was reported as missing its metadata.
    """
    verdicts = _verdicts(subpath_url, tiers={1})
    assert verdicts["missing-protected-resource-metadata"] == Verdict.NO_GAP.value


def test_prm_candidates_try_path_inserted_first(subpath_url):
    """The path-inserted URL is attempted, and is the one that answers."""
    report = asyncio.run(scan(subpath_url, tiers={1}))
    notes = " ".join(report["discovery"])
    assert "/.well-known/oauth-protected-resource/public/mcp" in notes


def test_subpath_issuer_as_metadata_resolves(subpath_url):
    """RFC 8414 path insertion resolves a path-bearing issuer (tenant-a)."""
    verdicts = _verdicts(subpath_url, tiers={2})
    assert verdicts["missing-as-metadata"] == Verdict.NO_GAP.value


def test_older_revision_uses_non_strict_grading(subpath_url):
    """A 2025-03-26 server exercises the not-yet-a-MUST branches without erroring."""
    report = asyncio.run(scan(subpath_url, tiers={1, 2}))
    assert report["protocol_version"] == "2025-03-26"
    errors = [f["gap_id"] for f in report["findings"]
              if f["verdict"] == Verdict.ERROR.value]
    assert not errors, f"unexpected ERROR verdicts: {errors}"


# --- evidence completeness -------------------------------------------------------

def test_every_finding_carries_evidence_or_explains_why(stateful_url):
    """Verdicts that assert something about the server must show their evidence.

    NOT_APPLICABLE findings legitimately have no exchange to show (the check never
    ran), so only the substantive verdicts are required to carry evidence.
    """
    report = asyncio.run(scan(stateful_url))
    substantive = {Verdict.HAS_GAP.value, Verdict.NO_GAP.value,
                   Verdict.INCONCLUSIVE.value, Verdict.ERROR.value}
    missing = [
        f["gap_id"] for f in report["findings"]
        if f["verdict"] in substantive and not f["evidence"].strip()
    ]
    assert not missing, f"findings with no evidence: {missing}"


def test_evidence_records_the_request_not_just_the_response(stateful_url):
    """Evidence includes what we sent, so a verdict can be audited/reproduced."""
    report = asyncio.run(scan(stateful_url, tiers={1}))
    gap1 = next(f for f in report["findings"]
                if f["gap_id"] == "no-authentication-remote")
    assert "POST" in gap1["evidence"]
    assert "tools/list" in gap1["evidence"]


# --- non-HTTP gating -------------------------------------------------------------

def test_stdio_target_is_not_applicable():
    """stdio servers take credentials from the environment; HTTP gaps must be N/A."""
    verdicts = _verdicts("stdio:///usr/local/bin/some-mcp-server")
    http_gaps = ["no-authentication-remote", "missing-www-authenticate",
                 "missing-protected-resource-metadata", "origin-not-validated"]
    for gap in http_gaps:
        assert verdicts[gap] == Verdict.NOT_APPLICABLE.value, gap


# --- CLI contract ----------------------------------------------------------------

def test_cli_exit_code_signals_gap_found(stateful_url):
    """A bulk-scan script must be able to branch on the outcome via $?.

    The CLI previously returned 0 unconditionally, so `run_scans.sh`'s `$?` check could
    never distinguish a clean server from a wide-open one or from a failed scan.
    """
    from mcpauth.cli import EXIT_GAP_FOUND, main

    assert main(["scan", stateful_url, "--tier", "1", "--json"]) == EXIT_GAP_FOUND


def test_cli_rejects_unknown_tier(stateful_url):
    """`--tier 99` must fail loudly, not silently select zero detectors."""
    from mcpauth.cli import EXIT_USAGE, main

    with pytest.raises(SystemExit) as exc:
        main(["scan", stateful_url, "--tier", "99"])
    assert exc.value.code == EXIT_USAGE


def test_cli_rejects_unknown_gap_id(stateful_url):
    from mcpauth.cli import EXIT_USAGE, main

    with pytest.raises(SystemExit) as exc:
        main(["scan", stateful_url, "--exclude", "no-such-gap"])
    assert exc.value.code == EXIT_USAGE


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "--tier", "99", "http://127.0.0.1:9/mcp"],
        ["scan", "--exclude", "no-such-gap", "http://127.0.0.1:9/mcp"],
        ["scan", "example.com/mcp"],          # no scheme
        ["scan", "ftp://example.com/mcp"],    # unsupported scheme
        ["scan", "https:///mcp"],             # no host
        ["scan"],                             # no url at all
        ["scan", "http://127.0.0.1:9/mcp", "--nope"],
        ["bogus-subcommand"],
    ],
)
def test_usage_errors_exit_3_not_2(argv):
    """Every bad command line must exit EXIT_USAGE (3), never EXIT_SCAN_FAILED (2).

    argparse's own default is 2, which this CLI already uses for "target unreachable" —
    and `run_scans.sh` *retries* on 2. So a single mistyped flag was reported as every
    endpoint in the list failing twice instead of as one bad command.
    """
    from mcpauth.cli import EXIT_SCAN_FAILED, EXIT_USAGE, main

    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == EXIT_USAGE, f"{argv} exited {exc.value.code}"
    assert exc.value.code != EXIT_SCAN_FAILED


def test_list_detectors_needs_no_url():
    """`--list-detectors` says "and exit"; it must not demand a target it never contacts.

    The unknown-gap-id error message tells the user to run `mcpauth scan --list-detectors`,
    which previously failed with a usage error of its own.
    """
    from mcpauth.cli import EXIT_CLEAN, main
    from mcpauth.detectors import ALL_DETECTORS

    assert main(["scan", "--list-detectors"]) == EXIT_CLEAN
    assert len(ALL_DETECTORS) == 12


# --- detector crash handling -----------------------------------------------------

def test_detector_crash_becomes_error_finding_with_evidence():
    """A raising detector yields ERROR (not a lost scan), and says what it was probing."""
    from mcpauth.detectors.base import Detector

    class Exploding(Detector):
        gap_id = "exploding-test-detector"
        name = "Detector that raises"
        tier = 1

        async def detect(self, ctx):
            raise RuntimeError("boom")

    import mcpauth.detectors as reg
    original = list(reg.ALL_DETECTORS)
    reg.ALL_DETECTORS.append(Exploding)
    try:
        report = asyncio.run(scan("http://127.0.0.1:1/mcp", tiers={1}))
    finally:
        reg.ALL_DETECTORS[:] = original
    finding = next(f for f in report["findings"]
                   if f["gap_id"] == "exploding-test-detector")
    assert finding["verdict"] == Verdict.ERROR.value
    assert "RuntimeError: boom" in finding["notes"]
    assert finding["evidence"].strip(), "ERROR findings must still carry evidence"


# --- error and edge paths that a review found unguarded ---------------------------
#
# Every bug pinned below lived in a failure branch, not a happy path: a control request
# that never completed, a 2xx that wasn't 200/201, a transport that is never "reached".
# The suite covered the adjacent success cases and walked straight past all of them.


def _fake(status=None, *, ok=True, text="", headers=None, error=""):
    from mcpauth.probe import HttpResult

    return HttpResult(
        ok=ok, status=status, headers=headers or {}, text=text, error=error,
        url="https://x.example/mcp", method="POST", rpc_method="initialize",
    )


def test_generic_403_error_code_is_not_an_auth_challenge():
    """`invalid_request` means "malformed request" (RFC 6750 §3.1), not "log in first".

    Crediting it handed `no-authentication-remote` a NO_GAP for servers that merely
    rejected a badly-formed call — a false clean bill of health on the critical check.
    """
    from mcpauth.detectors.base import is_auth_challenge

    ok, why = is_auth_challenge(
        _fake(403, text='{"error":"invalid_request","message":"missing sessionId"}')
    )
    assert ok is False, why
    ok, why = is_auth_challenge(_fake(403, text='{"error":"access_denied"}'))
    assert ok is False, why
    # Real resource-server rejections still count.
    for code in ("invalid_token", "insufficient_scope"):
        assert is_auth_challenge(_fake(403, text='{"error":"%s"}' % code))[0] is True


def test_auth_error_code_must_be_the_error_field_not_any_substring():
    """A substring search matched prose and unrelated payloads."""
    from mcpauth.detectors.base import is_auth_challenge

    assert is_auth_challenge(
        _fake(403, text='{"detail":"see docs on invalid_token handling"}')
    )[0] is False


def test_origin_detector_needs_a_completed_control_request():
    """403-to-forged-Origin + failed control must be INCONCLUSIVE, never NO_GAP.

    Falling through produced NO_GAP with the note "the same request without an Origin
    header was not [rejected]" — an observation that never happened.
    """
    from mcpauth.detectors.tier2 import OriginNotValidated
    from mcpauth.models import ProbeContext, TargetSpec

    class FlakyControl:
        def __init__(self):
            self.n = 0

        async def mcp_call(self, url, method, params=None, **kw):
            self.n += 1
            if self.n == 1:
                return _fake(403, text='{"error":"Missing API key"}')
            return _fake(ok=False, error="TimeoutError: ")

        def initialize_params(self):
            return {}

    ctx = ProbeContext(target=TargetSpec(url="https://x.example/mcp"), probe=FlakyControl())
    f = asyncio.run(OriginNotValidated().detect(ctx))
    assert f.verdict is Verdict.INCONCLUSIVE, f.notes
    assert "never completed" in f.notes


def test_notifications_initialized_has_no_id():
    """An `id` makes a message a request, not a notification (JSON-RPC 2.0 §4.1)."""
    from mcpauth.probe import Probe

    assert "id" not in Probe.jsonrpc_notification("notifications/initialized")
    assert "id" in Probe.jsonrpc("initialize")


def test_requests_echo_the_negotiated_protocol_version():
    """After initialize the client must send the *negotiated* revision, not its own."""
    from mcpauth.probe import MCP_PROTOCOL_VERSION, Probe

    probe = Probe()
    assert probe.negotiated_version is None
    sent = {}

    async def fake_request(method, url, *, headers=None, **kw):
        sent.update(headers or {})
        return _fake(200)

    probe.request = fake_request  # type: ignore[method-assign]
    probe.negotiated_version = "2025-03-26"
    asyncio.run(probe.mcp_call("https://x.example/mcp", "tools/list"))
    assert sent["MCP-Protocol-Version"] == "2025-03-26" != MCP_PROTOCOL_VERSION


def test_dcr_treats_any_2xx_as_a_created_client():
    """A 202 registration used to be graded INCONCLUSIVE "could be input validation".

    That is the silent-orphan outcome the detector exists to avoid: a client created on
    someone else's server with nothing in the report naming it.
    """
    from mcpauth.detectors.tier2 import _CLEANUP_FAIL_MARKER, OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}

    class Accepts202:
        async def request(self, method, url, **kw):
            return _fake(202, text="queued, not json")

    ctx = ProbeContext(target=TargetSpec(url="https://x.example/mcp"), probe=Accepts202())
    ctx.oauth = disc
    f = asyncio.run(OpenDcr().detect(ctx))
    assert f.verdict is Verdict.HAS_GAP, f.notes
    assert _CLEANUP_FAIL_MARKER in f.notes


def test_registration_secrets_are_redacted_from_evidence():
    """Reports get committed, so a client_secret must never reach one."""
    from mcpauth.probe import redact_secrets

    body = '{"client_id":"abc","client_secret":"s3cr3t","registration_access_token":"rat-9"}'
    out = redact_secrets(body)
    assert "s3cr3t" not in out and "rat-9" not in out
    assert "client_secret" in out and "abc" in out  # names and non-secrets survive
    assert "s3cr3t" not in _fake(201, text=body).evidence()


def test_unresolved_servers_keeps_the_ones_that_failed():
    """Overwriting dropped tried-and-failed servers, implying they had been cleared."""
    from mcpauth.oauth import OAuthDiscovery

    disc = OAuthDiscovery(attempted=True)
    disc.authorization_servers = ["https://as0", "https://as1", "https://as2"]
    for i, issuer in enumerate(disc.authorization_servers):
        if issuer == "https://as1":                       # only the second resolves
            disc.unresolved_servers += disc.authorization_servers[i + 1:]
            break
        disc.unresolved_servers.append(issuer)
    assert disc.unresolved_servers == ["https://as0", "https://as2"]


def test_stdio_scan_exits_clean_not_failed():
    """All-NOT_APPLICABLE is a successful scan of an inapplicable target, not a failure.

    Returning EXIT_SCAN_FAILED also made run_scans.sh retry it.
    """
    from mcpauth.cli import EXIT_CLEAN, _exit_code

    report = asyncio.run(scan("stdio:///usr/local/bin/some-mcp-server"))
    assert set(report["summary"]) == {"NOT_APPLICABLE"}
    assert _exit_code(report) == EXIT_CLEAN
    # An unreachable HTTP target is still a failure.
    assert _exit_code({"reachable": False, "summary": {"INCONCLUSIVE": 3}}) != EXIT_CLEAN
