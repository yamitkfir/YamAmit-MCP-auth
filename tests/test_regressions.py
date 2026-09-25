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
import json
import os
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


# --- containment: the address guard must see through a hostname (C1) --------------
#
# `netguard`'s string predicates cannot tell `https://intranet.example.com/register` from
# any other public URL, so a target-supplied name pointing at loopback, RFC 1918 space or
# 169.254.169.254 passed every check and was then connected to. The check now runs in the
# resolver, on the addresses actually about to be dialled.


class _StubResolver:
    """Stands in for aiohttp's resolver so these tests need no DNS and no network."""

    def __init__(self, mapping):
        self._mapping = mapping

    async def resolve(self, host, port=0, family=None):
        return [
            {"hostname": host, "host": a, "port": port, "family": family,
             "proto": 0, "flags": 0}
            for a in self._mapping[host]
        ]

    async def close(self):
        pass


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "169.254.169.254"])
def test_public_name_resolving_to_an_internal_address_is_refused(address):
    """The bypass was a name, not an IP literal: `is_internal_host` never resolved one."""
    from mcpauth.netguard import BlockedDestination
    from mcpauth.probe import _ContainedResolver

    r = _ContainedResolver(
        "mcp.example.com", _StubResolver({"sneaky.attacker.test": [address]})
    )
    with pytest.raises(BlockedDestination) as exc:
        asyncio.run(r.resolve("sneaky.attacker.test", 443))
    assert address in str(exc.value)


def test_split_horizon_name_is_refused_even_if_one_answer_is_public():
    """Otherwise the verdict is decided by resolver ordering — a coin flip."""
    from mcpauth.netguard import BlockedDestination
    from mcpauth.probe import _ContainedResolver

    r = _ContainedResolver(
        "mcp.example.com", _StubResolver({"both.test": ["93.184.216.34", "10.1.2.3"]})
    )
    with pytest.raises(BlockedDestination):
        asyncio.run(r.resolve("both.test", 443))


def test_the_scan_target_may_still_resolve_internally():
    """Scanning a local sandbox must keep working, by name as well as by literal.

    The exemption is scoped to that one host: `test_loopback_target_does_not_unlock_the_
    private_address_space` in test_units.py pins the other half.
    """
    from mcpauth.probe import _ContainedResolver

    stub = _StubResolver({"localhost": ["127.0.0.1"], "other.test": ["127.0.0.1"]})
    r = _ContainedResolver("localhost", stub)
    assert asyncio.run(r.resolve("localhost", 9100))          # allowed: it is the target
    with pytest.raises(Exception):                            # a different name is not
        asyncio.run(r.resolve("other.test", 9100))


def test_public_name_resolving_publicly_is_allowed():
    """Following a PRM that names a third party's authorization server is the normal case."""
    from mcpauth.probe import _ContainedResolver

    r = _ContainedResolver(
        "mcp.example.com", _StubResolver({"auth.elsewhere.test": ["93.184.216.34"]})
    )
    assert asyncio.run(r.resolve("auth.elsewhere.test", 443))


def test_blocked_destination_is_not_mistaken_for_a_tls_failure():
    """A refusal graded as a cert failure would become a `no-tls-transport` HAS_GAP."""
    from mcpauth.netguard import BlockedDestination
    from mcpauth.probe import _is_connect_failure, _is_tls_failure

    exc = BlockedDestination("'x.test' resolves to internal address 10.0.0.5 — aborting")
    assert _is_tls_failure(f"{type(exc).__name__}: {exc}") is False
    assert _is_connect_failure(exc) is True


# --- the one write must never be recorded as no write at all (C2, C3) --------------


def _registration_ok(**body):
    """A 201 whose body is already *parsed*, as `Probe.request` would return it.

    `_fake` deliberately leaves `json` unset — that is what makes it useful for the
    unparseable-body branch — so a test about the parsed path has to supply it.
    """
    from mcpauth.probe import HttpResult

    return HttpResult(
        ok=True, status=201, text=json.dumps(body), json=body,
        url="https://x.example/register", method="POST",
    )


def test_registration_that_times_out_declares_an_obligation():
    """A POST that reached the server and then lost its reply may have created a client.

    This returned ERROR with EMPTY notes, so `run_dcr.py` set `cleanup_failed=False` and
    the report printed "✅ Every client created was deleted again" over a permanent
    registration on someone else's production server.
    """
    from mcpauth.detectors.tier2 import _CLEANUP_FAIL_MARKER, OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}

    class ReplyLost:
        async def request(self, method, url, **kw):
            return _fake(ok=False, error="TimeoutError: ")

    journal = []
    ctx = ProbeContext(
        target=TargetSpec(url="https://x.example/mcp"), probe=ReplyLost(),
        write_journal=journal.append,
    )
    ctx.oauth = disc
    f = asyncio.run(OpenDcr().detect(ctx))
    assert f.verdict is Verdict.ERROR
    assert _CLEANUP_FAIL_MARKER in f.notes, f.notes
    assert [r["stage"] for r in journal] == ["attempted-outcome-unknown"]


def test_registration_that_never_connected_declares_nothing():
    """The mirror case: inventing an obligation leaves one that can never be discharged.

    `reports/dcr_scan.md` over-reports by exactly one row because of this.
    """
    import aiohttp

    from mcpauth.detectors.tier2 import _CLEANUP_FAIL_MARKER, OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery
    from mcpauth.probe import _is_connect_failure

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}

    class NeverConnected:
        async def request(self, method, url, **kw):
            res = _fake(ok=False, error="ClientConnectorDNSError: no such host")
            res.connect_failed = True
            return res

    journal = []
    ctx = ProbeContext(
        target=TargetSpec(url="https://x.example/mcp"), probe=NeverConnected(),
        write_journal=journal.append,
    )
    ctx.oauth = disc
    f = asyncio.run(OpenDcr().detect(ctx))
    assert f.verdict is Verdict.ERROR
    assert _CLEANUP_FAIL_MARKER not in f.notes, f.notes
    assert journal == [], "nothing was created, so nothing is owed"
    # The classification this branch rests on is by exception type, not message text.
    key = aiohttp.ClientConnectorDNSError.__new__(aiohttp.ClientConnectorDNSError)
    assert _is_connect_failure(key) is True
    assert _is_connect_failure(TimeoutError("read timed out")) is False


def test_created_client_id_is_journalled_before_cleanup_is_attempted():
    """The id lived only in the coroutine frame until the Finding was serialised.

    `run_dcr.py`'s 25 s per-server budget spans the POST *and* the RFC 7592 DELETE, so a
    cancellation during cleanup destroyed the only record of a client we had just created.
    """
    from mcpauth.detectors.tier2 import OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}
    order = []

    class RegistersThenCancels:
        async def request(self, method, url, **kw):
            order.append(method)
            if method == "POST":
                return _registration_ok(
                    client_id="abc123",
                    registration_client_uri="https://x.example/c/1",
                    registration_access_token="rat",
                )
            raise asyncio.CancelledError            # cleanup dies mid-flight

    journal = []
    ctx = ProbeContext(
        target=TargetSpec(url="https://x.example/mcp"), probe=RegistersThenCancels(),
        write_journal=journal.append,
    )
    ctx.oauth = disc
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(OpenDcr().detect(ctx))
    # The POST happened, cleanup was attempted, and the id is already durable.
    assert order == ["POST", "DELETE"]
    assert journal and journal[0]["stage"] == "created"
    assert journal[0]["client_id"] == "abc123"
    assert journal[0]["registration_endpoint"] == "https://x.example/register"


def test_journal_failure_does_not_break_the_scan():
    """The Finding is authoritative; a broken sink must not turn a real verdict into ERROR."""
    from mcpauth.detectors.tier2 import OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}

    class Registers:
        async def request(self, method, url, **kw):
            return _registration_ok(client_id="abc123")

    def explode(_record):
        raise OSError("disk full")

    ctx = ProbeContext(
        target=TargetSpec(url="https://x.example/mcp"), probe=Registers(),
        write_journal=explode,
    )
    ctx.oauth = disc
    f = asyncio.run(OpenDcr().detect(ctx))
    assert f.verdict is Verdict.HAS_GAP
    assert "abc123" in f.evidence
    assert any("write journal failed" in n for n in ctx.discovery_notes)


def test_non_success_reply_naming_a_client_id_is_not_journalled_as_created():
    """A 409 rejecting our metadata can echo a client_id we did not create.

    Journalling that as `created` both fabricates an obligation and leaves it unclosed,
    since the non-2xx branches never reach cleanup. The note must also stop saying
    "without a client_id" while printing one in the evidence directly beneath.
    """
    from mcpauth.detectors.tier2 import _CLEANUP_FAIL_MARKER, OpenDcr
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.oauth import OAuthDiscovery
    from mcpauth.probe import HttpResult

    disc = OAuthDiscovery(attempted=True)
    disc.as_metadata = {"registration_endpoint": "https://x.example/register"}
    body = {"error": "invalid_client_metadata", "client_id": "not-ours"}

    class Rejects409:
        async def request(self, method, url, **kw):
            return HttpResult(
                ok=True, status=409, text=json.dumps(body), json=body,
                url="https://x.example/register", method="POST",
            )

    journal = []
    ctx = ProbeContext(
        target=TargetSpec(url="https://x.example/mcp"), probe=Rejects409(),
        write_journal=journal.append,
    )
    ctx.oauth = disc
    f = asyncio.run(OpenDcr().detect(ctx))
    assert f.verdict is Verdict.INCONCLUSIVE
    stages = [r["stage"] for r in journal]
    assert "created" not in stages, stages
    assert stages == ["client-id-in-non-success-reply"], stages
    # The id is disclosed, and the note no longer contradicts the evidence.
    assert "not-ours" in f.notes
    assert "without a client_id" not in f.notes
    assert _CLEANUP_FAIL_MARKER in f.notes


def test_connect_timeout_is_not_reported_as_a_delivered_post():
    """With only a total budget, aiohttp raises a bare TimeoutError for every phase.

    That made `_is_connect_failure` unable to tell a dead TCP handshake from a lost reply,
    so `open-dcr` demanded manual cleanup for hosts it never reached. A separate
    `sock_connect` budget yields `ConnectionTimeoutError`, which is unambiguous.
    """
    import aiohttp

    from mcpauth.probe import Probe, _is_connect_failure

    timeout = Probe(timeout=12.0)._timeout
    assert timeout.sock_connect is not None, "connect phase needs its own budget"
    assert timeout.sock_connect < timeout.total, "else the total fires first"

    connect = aiohttp.ConnectionTimeoutError.__new__(aiohttp.ConnectionTimeoutError)
    assert _is_connect_failure(connect) is True
    # A read timeout is still "may have been delivered" — the conservative direction.
    assert _is_connect_failure(aiohttp.SocketTimeoutError()) is False
    assert _is_connect_failure(TimeoutError("read timed out")) is False


def test_cli_supplies_a_write_journal_when_writes_are_enabled(tmp_path, monkeypatch):
    """The durability fix was inert on the documented `--unsafe-writes` path.

    `scan()` grew a `write_journal` parameter, but the CLI — which is how README documents
    opting into the write, and what `run_scans.sh --unsafe-writes` runs — passed no sink, so
    an interrupt during RFC 7592 cleanup still left a client with its id nowhere on disk.
    """
    from mcpauth import cli

    captured = {}

    async def fake_scan(url, tiers=None, exclude=None, **kw):
        captured.update(kw)
        if kw.get("write_journal"):
            kw["write_journal"]({"stage": "created", "client_id": "abc123"})
        return {"target": url, "reachable": True, "discovery": [], "findings": [],
                "summary": {}, "protocol_version": None}

    monkeypatch.setattr(cli, "scan", fake_scan)
    path = tmp_path / "writes.jsonl"
    cli.main(["scan", "https://x.example/mcp", "--unsafe-writes",
              "--write-journal", str(path)])
    assert captured.get("write_journal") is not None, "no sink was passed"
    assert json.loads(path.read_text().strip())["client_id"] == "abc123"

    # Without --unsafe-writes nothing can be created, so no sink and no file.
    captured.clear()
    other = tmp_path / "unused.jsonl"
    cli.main(["scan", "https://x.example/mcp", "--write-journal", str(other)])
    assert captured.get("write_journal") is None
    assert not other.exists()


# --- Ctrl-C must stop a live run, not just annotate it -----------------------------


def _load_run_dcr(name, tmp_path):
    """Load `reports/run_dcr.py` with its on-disk paths redirected into a temp dir."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, ROOT / "reports" / "run_dcr.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.RAW_DIR = tmp_path
    mod.JOURNAL = tmp_path / "write_journal.jsonl"
    mod.DELAY_BETWEEN = 0
    return mod


def test_cancelling_a_live_run_stops_it_touching_further_servers(tmp_path):
    """Catching `CancelledError` alongside `Exception` in `dcr_one` consumed the first Ctrl-C.

    On Python 3.11+ the first SIGINT arrives as one `CancelledError`. Absorbing it into an
    ERROR row let `run_live` carry on and perform a real registration POST against every
    remaining third-party server, while the operator saw a run that looked complete.

    This goes through the real `dcr_one`, because the defect was in its except clause —
    stubbing `dcr_one` out would pass either way.
    """
    run_dcr = _load_run_dcr("run_dcr_cancel", tmp_path)
    detected = []

    async def fake_discover(probe, url, *a, **kw):
        from mcpauth.oauth import OAuthDiscovery

        d = OAuthDiscovery(attempted=True)
        d.as_metadata = {"registration_endpoint": f"{url.rsplit('/', 1)[0]}/register"}
        return d

    class CancelsMidProbe:
        gap_id = "open-dcr"

        async def detect(self, ctx):
            detected.append(ctx.target.url)
            raise asyncio.CancelledError      # as a first Ctrl-C would arrive

    run_dcr.discover_oauth = fake_discover
    run_dcr.OpenDcr = CancelsMidProbe
    endpoints = [("first", "https://a.example/mcp"), ("second", "https://b.example/mcp")]
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_dcr.run_live(endpoints))
    assert detected == ["https://a.example/mcp"], (
        f"the run continued to {detected[1:]} after the cancel"
    )
    # Stopping must not cost us the record: the journal line precedes the re-raise.
    written = [json.loads(x) for x in
               (tmp_path / "write_journal.jsonl").read_text().splitlines()]
    assert [w["stage"] for w in written] == ["aborted-outcome-unknown"]
    assert written[0]["registration_endpoint"] == "https://a.example/register"


def test_an_abort_before_any_endpoint_is_known_claims_nothing(tmp_path):
    """No registration endpoint means no POST was possible, so no obligation exists.

    Flagging cleanup anyway is what makes `reports/dcr_scan.md` over-report by one row.
    """
    run_dcr = _load_run_dcr("run_dcr_abort", tmp_path)

    async def dies_in_discovery(probe, url, *a, **kw):
        raise TimeoutError

    run_dcr.discover_oauth = dies_in_discovery
    row = asyncio.run(run_dcr.dcr_one("x", "https://a.example/mcp"))
    assert row["verdict"] == "ERROR"
    assert row["cleanup_failed"] is False, row["notes"]
    assert row["written_host"] is None
    assert "no cleanup is owed" in row["notes"]
    assert not (tmp_path / "write_journal.jsonl").exists()


# --- the record of what we left behind must not be overwritten (C4) ---------------


def test_json_report_backup_keeps_its_own_extension(tmp_path):
    """`with_suffix('.prev-1.md')` gave JSON content a Markdown name.

    That is why `_summary.json` was excluded from clobber protection and overwritten in
    place, leaving the first live run's four client_ids only in `dcr_scan.prev-1.md`.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_dcr", ROOT / "reports" / "run_dcr.py"
    )
    run_dcr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_dcr)

    target = tmp_path / "_summary.json"
    target.write_text('["first run"]')
    run_dcr._write_without_clobbering(target, '["second run"]')
    assert (tmp_path / "_summary.prev-1.json").read_text() == '["first run"]'
    assert target.read_text() == '["second run"]'
    # A third run keeps both earlier ones.
    run_dcr._write_without_clobbering(target, '["third run"]')
    assert (tmp_path / "_summary.prev-2.json").read_text() == '["second run"]'
    # The Markdown report's existing naming is unchanged.
    md = tmp_path / "dcr_scan.md"
    md.write_text("run one")
    run_dcr._write_without_clobbering(md, "run two")
    assert (tmp_path / "dcr_scan.prev-1.md").read_text() == "run one"


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


def test_run_scans_works_with_no_arguments(tmp_path):
    """The documented default `bash reports/run_scans.sh` must actually run.

    macOS ships bash 3.2, where expanding an EMPTY array as "${arr[@]}" under `set -u` is a
    fatal "unbound variable". The script collected extra CLI args into an array and expanded
    it that way, so invoking it with no arguments — the primary documented usage — aborted on
    the first endpoint and scanned nothing.
    """
    port = _free_port()
    proc = _boot("stateful_open_server.py", port)
    try:
        endpoints = tmp_path / "endpoints.txt"
        endpoints.write_text(f"local | http://127.0.0.1:{port}/mcp\n")
        out = tmp_path / "raw"
        env = {
            **os.environ,
            "EP": str(endpoints),
            "OUT": str(out),
        }
        run = subprocess.run(
            ["bash", str(ROOT / "reports" / "run_scans.sh")],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=180,
        )
        combined = run.stdout + run.stderr
        assert "unbound variable" not in combined, combined
        report = out / "local.json"
        assert report.exists(), f"no report written.\n{combined}"
        data = json.loads(report.read_text())
        assert data["findings"], combined
        # Read-only by default: the write detector must not have run.
        assert "open-dcr" not in data["detectors_run"]
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_oversized_tool_list_still_reports_wide_open():
    """A tools/list bigger than the read cap must not downgrade a critical finding.

    One scanned server answered `tools/list` with 91,703 bytes. The 64 KB cap clipped it
    mid-JSON, so the body would not parse, so `jsonrpc_result` returned None and the detector
    reported "Unexpected status 200; could not confirm tool access" — for a server that had
    just listed 64 tools to an unauthenticated caller. Thirteen endpoints were affected.
    """
    from mcpauth.detectors.tier1 import NoAuthenticationRemote
    from mcpauth.models import ProbeContext, TargetSpec
    from mcpauth.probe import HttpResult, truncated_success

    # A real result, clipped mid-array exactly as the cap would clip it.
    clipped = '{"jsonrpc":"2.0","id":"x","result":{"tools":[{"name":"a","description":"' + "y" * 200

    class Oversized:
        async def mcp_call(self, url, method, params=None, **kw):
            return HttpResult(
                ok=True, status=200, headers={"content-type": "application/json"},
                text=clipped, json=None, truncated=True,
                url=url, method="POST", rpc_method=method, request_headers={},
            )

        def initialize_params(self):
            return {}

    assert truncated_success(
        HttpResult(ok=True, status=200, text=clipped, json=None, truncated=True)
    ) is True

    ctx = ProbeContext(target=TargetSpec(url="https://x.example/mcp"), probe=Oversized())
    f = asyncio.run(NoAuthenticationRemote().detect(ctx))
    assert f.verdict is Verdict.HAS_GAP, f.notes


def test_truncated_error_response_is_not_read_as_success():
    """The salvage must stay conservative: a clipped JSON-RPC *error* is not a result."""
    from mcpauth.probe import HttpResult, truncated_success

    err = '{"jsonrpc":"2.0","id":"x","error":{"code":-32000,"message":"' + "z" * 200
    assert truncated_success(
        HttpResult(ok=True, status=200, text=err, json=None, truncated=True)
    ) is False
    # Not truncated at all -> nothing to salvage.
    assert truncated_success(
        HttpResult(ok=True, status=200, text='{"result":{}}', json=None, truncated=False)
    ) is False


def test_large_body_is_read_in_full():
    """`StreamReader.read(n)` returns *up to* n bytes, so one call clips a big body.

    The probe used a single `read(cap)` and set `truncated = len(raw) >= cap`. For any
    response larger than one buffered chunk that returned a fragment with truncated=False —
    data loss that presented itself as complete data. A 91,703-byte tools/list arrived as
    8,183 bytes of unparseable JSON, and the server that sent it was graded "could not tell"
    instead of wide open.
    """
    from mcpauth.probe import _read_body

    class FakeContent:
        """Mimics aiohttp: read(n) yields at most one chunk, then b'' at EOF."""

        def __init__(self, chunks):
            self._chunks = list(chunks)

        async def read(self, n):
            if not self._chunks:
                return b""
            head = self._chunks[0]
            if len(head) <= n:
                return self._chunks.pop(0)
            self._chunks[0] = head[n:]
            return head[:n]

    class FakeResp:
        def __init__(self, chunks):
            self.content = FakeContent(chunks)

    body = b'{"result":{"tools":[' + b'{"name":"x"},' * 5000 + b'{"name":"y"}]}}'
    chunks = [body[i:i + 8183] for i in range(0, len(body), 8183)]
    assert len(chunks) > 1, "test needs a multi-chunk body"

    raw, truncated = asyncio.run(_read_body(FakeResp(chunks), 1_000_000,
                                            stop_when_stalled=False))
    assert raw == body, f"read {len(raw)} of {len(body)} bytes"
    assert truncated is False
    assert json.loads(raw)["result"]["tools"]

    # And the cap is still honoured, and reported.
    raw, truncated = asyncio.run(_read_body(FakeResp(chunks), 100,
                                            stop_when_stalled=False))
    assert len(raw) == 100 and truncated is True
