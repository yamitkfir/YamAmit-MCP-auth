"""Pure unit tests for the decision helpers — no network, no sandbox.

These functions carry the detectors' judgement calls (is this id predictable? is this
URL cleartext? which well-known paths should we try? is this 403 an auth challenge?).
They were previously only exercised indirectly through live scans, so a heuristic could
be wrong in a way no test could see. Table-driven here, with the real-world formats that
used to be misjudged called out by name.
"""

from __future__ import annotations

import secrets
import uuid

import pytest

from mcpauth.detectors.base import is_auth_challenge
from mcpauth.detectors.tier1 import _is_tls_failure
from mcpauth.detectors.tier2 import (
    _assess_session_ids,
    _entropy_bits,
    _insecure_http,
    _looks_sequential,
    _response_type_values,
    _same_site,
)
from mcpauth.models import ProbeContext, TargetSpec, Verdict
from mcpauth.oauth import as_metadata_candidates, is_ssrf_risk, prm_candidates
from mcpauth.probe import HttpResult


# --- session id assessment (#6) ---------------------------------------------------

@pytest.mark.parametrize("ids,expected,why", [
    # HAS_GAP: genuinely predictable.
    (["sess-1", "sess-2", "sess-3"], Verdict.HAS_GAP, "shared prefix + counter"),
    (["1", "2", "3", "4", "5"], Verdict.HAS_GAP, "bare counter"),
    (["same"] * 5, Verdict.HAS_GAP, "deterministic"),
    ([f"mcp-session-{i:020d}" for i in range(1, 6)], Verdict.HAS_GAP,
     "long but a padded counter"),
    ([str(1000000000000000 + i) for i in range(5)], Verdict.HAS_GAP,
     "16 chars yet only ~53 bits: length is not entropy"),
    # NO_GAP: cryptographically random, various real formats.
    ([secrets.token_hex(16) for _ in range(5)], Verdict.NO_GAP, "32-char hex"),
    ([str(uuid.uuid4()) for _ in range(5)], Verdict.NO_GAP, "uuid4"),
    ([secrets.token_urlsafe(24) for _ in range(5)], Verdict.NO_GAP, "base64url"),
])
def test_assess_session_ids(ids, expected, why):
    verdict, note = _assess_session_ids(ids)
    assert verdict == expected, f"{why}: got {verdict.value} — {note}"


def test_short_but_high_entropy_id_is_judged_on_bits_not_length():
    """A random 15-char base64url id (~78 bits) is strong despite being under 16 chars.

    The old rule flagged every id shorter than 16 characters, so secure servers using
    compact random tokens were reported as predictable.
    """
    ids = [secrets.token_urlsafe(16)[:15] for _ in range(5)]
    verdict, note = _assess_session_ids(ids)
    assert verdict == Verdict.NO_GAP, note


def test_single_sample_is_inconclusive_not_no_gap():
    verdict, _ = _assess_session_ids([secrets.token_urlsafe(24)])
    assert verdict == Verdict.INCONCLUSIVE


@pytest.mark.parametrize("nums,expected", [
    ([1, 2, 3], True),                 # counter
    ([7, 8, 9, 10, 11], True),         # counter with all steps 1
    ([100, 101, 103], True),           # counter with one skipped value
    ([5, 10, 15, 20], True),           # constant step, enough samples
    ([1, 7, 13], False),               # 3 random values that happen to be arithmetic
    ([2, 5, 9], False),                # random, increasing gaps
    ([10, 50, 90], False),             # wide constant step, only 3 samples
    ([1, 2], False),                   # too few to judge
])
def test_looks_sequential(nums, expected):
    assert _looks_sequential(nums) is expected


def test_entropy_bits_reflects_alphabet():
    """Same length, different alphabet => different strength."""
    digits, _ = _entropy_bits("1234567890123456")
    hexish, _ = _entropy_bits("a1b2c3d4e5f60718")
    assert digits < hexish


# --- URL construction (RFC 9728 §3.1 / RFC 8414 §3.1, §5) -------------------------

def test_prm_candidates_inserts_resource_path():
    """RFC 9728 §3.1: the suffix goes between host and path, not at the origin."""
    got = prm_candidates("https://example.com/public/mcp")
    assert got[0] == "https://example.com/.well-known/oauth-protected-resource/public/mcp"
    assert got[1] == "https://example.com/.well-known/oauth-protected-resource"


def test_prm_candidates_collapse_for_bare_origin():
    got = prm_candidates("https://mcp.example.com")
    assert got == ["https://mcp.example.com/.well-known/oauth-protected-resource"]


def test_prm_candidates_strip_trailing_slash():
    """RFC 9728 §3.1: a terminating slash after the host is removed first."""
    got = prm_candidates("https://api.example.com/mcp/")
    assert got[0] == "https://api.example.com/.well-known/oauth-protected-resource/mcp"


def test_as_metadata_candidates_order():
    """RFC 8414 §3.1 insertion first, then the §5 OIDC fallbacks."""
    got = as_metadata_candidates("https://auth.example.com/tenant1")
    assert got == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_as_metadata_candidates_dedup_for_bare_issuer():
    got = as_metadata_candidates("https://auth.example.com")
    assert len(got) == len(set(got))
    assert got[0] == "https://auth.example.com/.well-known/oauth-authorization-server"


# --- cleartext classification (#9) ------------------------------------------------

@pytest.mark.parametrize("url,insecure", [
    ("http://auth.example.com/token", True),
    ("https://auth.example.com/token", False),
    ("http://localhost:8080/token", False),       # loopback exempt
    ("http://127.0.0.1/token", False),
    ("http://[::1]:9000/token", False),
    ("http://app.localhost/token", False),
])
def test_insecure_http(url, insecure):
    assert _insecure_http(url) is insecure


# --- implicit-grant signal parsing (#11) ------------------------------------------

@pytest.mark.parametrize("raw,contains_token", [
    (["code", "token"], True),
    (["code token"], True),          # space-delimited set in one entry
    (["code", "id_token token"], True),
    (["code"], False),
    (["code", "id_token"], False),
])
def test_response_type_values_flattens_space_delimited(raw, contains_token):
    """OAuth response types are space-delimited sets, so entries must be split."""
    values = _response_type_values(raw)
    assert values is not None
    assert ("token" in values) is contains_token


def test_response_type_values_none_for_missing_field():
    assert _response_type_values(None) is None


# --- write-target containment (#12 / SSRF) ----------------------------------------

@pytest.mark.parametrize("endpoint,target,same", [
    ("https://mcp.example.com/register", "https://mcp.example.com/mcp", True),
    ("https://auth.example.com/register", "https://mcp.example.com/mcp", True),
    ("https://evil.attacker.test/register", "https://mcp.example.com/mcp", False),
    ("http://169.254.169.254/register", "https://mcp.example.com/mcp", False),
    ("http://localhost:6379/register", "https://mcp.example.com/mcp", False),
    ("https://mcp.example.com.evil.test/register", "https://mcp.example.com/mcp", False),
])
def test_same_site_guards_the_only_write(endpoint, target, same):
    """open-dcr's registration POST must not follow target-supplied URLs off-site.

    The endpoint comes from metadata the target controls, so without this the scanner
    can be pointed at cloud-metadata services or an unrelated third party's server —
    and the write would land on someone who never agreed to be scanned.
    """
    assert _same_site(endpoint, target) is same


# --- SSRF guard on target-supplied discovery URLs ---------------------------------

PUBLIC_TARGET = "https://mcp.example.com/mcp"


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata service
    "http://127.0.0.1:6379/",                     # local Redis
    "http://localhost:8080/token",
    "http://10.1.2.3/authorize",                  # RFC 1918
    "http://192.168.0.5/authorize",
    "http://172.16.4.4/authorize",
    "http://[::1]:9000/authorize",
])
def test_ssrf_guard_blocks_internal_targets(url):
    """A malicious target must not be able to aim our fetches at internal hosts.

    These URLs arrive from server-controlled metadata (`authorization_servers`, the
    `resource_metadata` header), so fetching them blindly makes the scanner an SSRF
    vector — MCP Security Best Practices §SSRF names exactly these destinations.
    """
    assert is_ssrf_risk(url, PUBLIC_TARGET) != ""


@pytest.mark.parametrize("url", [
    "https://auth.example.com/authorize",
    "https://some-other-idp.test/token",
])
def test_ssrf_guard_allows_public_hosts(url):
    """Third-party but public authorization servers are legitimate and must be fetched."""
    assert is_ssrf_risk(url, PUBLIC_TARGET) == ""


def test_ssrf_guard_allows_the_scan_target_itself():
    """Scanning your own sandbox must keep working: the target's own host is always fine."""
    assert is_ssrf_risk(
        "http://127.0.0.1:9110/.well-known/oauth-authorization-server",
        "http://127.0.0.1:9110/mcp",
    ) == ""
    # localhost and 127.0.0.1 are the same host spelled two ways.
    assert is_ssrf_risk("http://localhost:9110/token", "http://127.0.0.1:9110/mcp") == ""


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.1.1/authorize",
    "http://10.0.0.1/token",
])
def test_loopback_target_does_not_unlock_the_private_address_space(url):
    """A local server must not be able to redirect us to *other* internal hosts.

    The exemption above is scoped to the target's own host only. Exempting everything
    private whenever the target was local would let a sandbox (or any localhost service)
    pivot the scanner into the cloud-metadata endpoint and the LAN.
    """
    assert is_ssrf_risk(url, "http://127.0.0.1:9110/mcp") != ""


# --- auth-challenge classification (#1, #7, #12) ----------------------------------

def _res(status: int, headers: dict | None = None, text: str = "") -> HttpResult:
    return HttpResult(ok=True, status=status, headers=headers or {}, text=text)


def test_401_is_always_a_challenge():
    assert is_auth_challenge(_res(401))[0] is True


def test_bare_403_is_not_a_challenge():
    """A WAF/geo-block also answers 403; crediting it as auth is a false NO_GAP."""
    assert is_auth_challenge(_res(403, text="<html>Access Denied</html>"))[0] is False


def test_403_with_www_authenticate_is_a_challenge():
    ok, why = is_auth_challenge(_res(403, headers={"www-authenticate": "Bearer"}))
    assert ok is True and "WWW-Authenticate" in why


def test_403_with_oauth_error_code_is_a_challenge():
    ok, why = is_auth_challenge(_res(403, text='{"error":"insufficient_scope"}'))
    assert ok is True and "insufficient_scope" in why


@pytest.mark.parametrize("status", [200, 400, 404, 429, 500, 503])
def test_other_statuses_are_not_challenges(status):
    assert is_auth_challenge(_res(status))[0] is False


# --- body parsing (RFC 9110 §8.3.1: media types are case-insensitive) -------------

@pytest.mark.parametrize("ctype", [
    "application/json",
    "Application/JSON",              # legal per RFC 9110; a case-sensitive test missed it
    "APPLICATION/JSON",
    "application/json; charset=utf-8",
    "application/json-rpc",
    "application/scim+json",
    "text/plain",                    # servers mislabel JSON; sniff the body instead
    "",                              # no content-type at all
])
def test_parse_body_reads_json_regardless_of_content_type_casing(ctype):
    """A missed parse used to strand a created OAuth client with no id to clean up.

    open-dcr derives the client_id it must DELETE from the parsed body, so a body the
    parser skipped meant the tool created a real client on a third-party server, could
    not name it, and reported INCONCLUSIVE with no cleanup warning.
    """
    from mcpauth.probe import _parse_body

    assert _parse_body('{"client_id":"abc"}', ctype) == {"client_id": "abc"}


def test_parse_body_returns_none_for_non_json():
    from mcpauth.probe import _parse_body

    assert _parse_body("<html>nope</html>", "text/html") is None


# --- SSE framing ------------------------------------------------------------------

def test_parse_sse_joins_multi_line_data_fields():
    """One SSE event may span several `data:` lines, joined with newlines.

    Decoding each line independently dropped every wrapped/pretty-printed JSON-RPC
    message, so a valid InitializeResult framed that way looked like no response.
    """
    from mcpauth.probe import _parse_sse

    body = 'event: message\ndata: {"jsonrpc":"2.0","id":1,\ndata: "result":{"tools":[]}}\n\n'
    assert _parse_sse(body) == [{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}]


def test_parse_sse_handles_multiple_events_and_keepalives():
    from mcpauth.probe import _parse_sse

    body = ': keep-alive\ndata: {"a":1}\n\ndata: {"b":2}\n\n'
    assert _parse_sse(body) == [{"a": 1}, {"b": 2}]


def test_parse_sse_recovers_event_from_truncated_stream():
    """We read SSE bodies with a byte cap, so the final blank line may be missing."""
    from mcpauth.probe import _parse_sse

    assert _parse_sse('data: {"d":4}') == [{"d": 4}]


def test_parse_sse_ignores_non_json_endpoint_event():
    """The legacy `endpoint` event is a URL, not JSON; it must not raise."""
    from mcpauth.probe import _parse_sse

    assert _parse_sse("event: endpoint\ndata: /messages/?sessionId=42\n\n") == []


# --- version gating --------------------------------------------------------------

@pytest.mark.parametrize("version,strict", [
    ("2024-11-05", False),
    ("2025-03-26", False),
    ("2025-06-18", True),
    ("2025-11-25", True),   # newer revisions keep the RFC 9728 MUST
    ("2026-07-28", True),   # current revision at time of writing
    (None, False),          # unnegotiated => spec says assume 2025-03-26
    ("not-a-date", False),
])
def test_targets_strict_spec(version, strict):
    """Revisions sort chronologically, so gating is >=, not == one hardcoded date."""
    ctx = ProbeContext(
        target=TargetSpec("https://mcp.example.com/mcp"),
        probe=None,  # type: ignore[arg-type] — property under test never touches it
        protocol_version=version,
    )
    assert ctx.targets_strict_spec is strict


# --- TLS failure classification (#2) ---------------------------------------------

@pytest.mark.parametrize("error,is_tls", [
    ("ClientConnectorCertificateError: certificate verify failed", True),
    ("SSLCertVerificationError: self-signed certificate", True),
    ("ClientConnectorError: Cannot connect to host (Connection refused)", False),
    ("TimeoutError: ", False),
])
def test_is_tls_failure(error, is_tls):
    assert _is_tls_failure(error) is is_tls


# --- target classification -------------------------------------------------------

@pytest.mark.parametrize("url,loopback", [
    ("http://127.0.0.1:9100/mcp", True),
    ("http://localhost:9100/mcp", True),
    ("http://app.localhost/mcp", True),
    ("https://mcp.example.com/mcp", False),
])
def test_target_is_loopback(url, loopback):
    assert TargetSpec(url).is_loopback is loopback


@pytest.mark.parametrize("url,http_transport", [
    ("https://mcp.example.com/mcp", True),
    ("http://mcp.example.com/mcp", True),
    ("stdio:///usr/bin/server", False),
])
def test_target_is_http_transport(url, http_transport):
    assert TargetSpec(url).is_http_transport is http_transport
