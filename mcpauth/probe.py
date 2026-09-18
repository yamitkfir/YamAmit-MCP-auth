"""Low-level HTTP / JSON-RPC probe client used by all detectors.

Thin wrapper over aiohttp that:
  * speaks MCP JSON-RPC over Streamable HTTP / SSE,
  * never raises on HTTP status (detectors interpret status themselves),
  * captures a compact, evidence-friendly record of each exchange.

Kept deliberately small: detectors compose these primitives rather than the probe
encoding any gap-specific logic.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp

MCP_PROTOCOL_VERSION = "2025-06-18"
USER_AGENT = "mcpauth-prober/0.1"


@dataclass
class HttpResult:
    """Outcome of one HTTP exchange — the unit of evidence.

    Records the **request as well as the response**. A verdict that says "the server
    answered 200 to a privileged call with no credential" is only auditable if the report
    also shows what we sent, so `method`, `rpc_method`, the headers we chose, and the URL
    we actually ended up at are all kept.
    """

    ok: bool                       # did the request complete (not a transport error)?
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    json: Any = None
    error: str = ""
    url: str = ""                  # the URL we requested
    method: str = ""               # HTTP verb we sent
    rpc_method: str = ""           # JSON-RPC method, when this was an MCP call
    request_headers: dict[str, str] = field(default_factory=dict)
    final_url: str = ""            # where we ended up, if redirected
    truncated: bool = False        # body hit the read cap
    tls_failure: bool = False      # transport error was a certificate/TLS problem

    def request_line(self) -> str:
        """One-line description of what we sent, for the evidence trail."""
        bits = [f"{self.method or 'GET'} {self.url}"]
        if self.rpc_method:
            bits.append(f"(JSON-RPC {self.rpc_method})")
        auth = "Authorization" in {k.title() for k in self.request_headers}
        bits.append("with Authorization" if auth else "with NO Authorization header")
        for h in ("Origin", "Mcp-Session-Id"):
            val = _get_ci(self.request_headers, h)
            if val:
                bits.append(f"{h}: {val}")
        return " ".join(bits)

    def evidence(self, max_body: int = 400) -> str:
        head = f"REQUEST: {self.request_line()}"
        if not self.ok:
            return f"{head}\nRESPONSE: transport error: {self.error}"
        where = ""
        if self.final_url and self.final_url != self.url:
            where = f" (redirected to {self.final_url})"
        body = redact_secrets(self.text)[:max_body]
        if len(self.text) > max_body or self.truncated:
            body += " …[truncated]"
        return f"{head}\nRESPONSE: HTTP {self.status}{where}\n{body}"


# Response fields that are credentials. `open-dcr` POSTs a real client registration, and
# RFC 7591 §3.2.1 replies may carry a `client_secret` and an RFC 7592
# `registration_access_token` — which would otherwise be echoed verbatim into a report that
# gets committed to git.
_SECRET_FIELDS = (
    "client_secret",
    "registration_access_token",
    "access_token",
    "refresh_token",
    "id_token",
    "authorization_code",
)

_SECRET_JSON = re.compile(
    r'("(?:' + "|".join(_SECRET_FIELDS) + r')"\s*:\s*)"[^"]*"', re.IGNORECASE
)


def redact_secrets(text: str) -> str:
    """Replace credential values in a response body with a placeholder.

    Keeps the field *name* visible — that a `client_secret` was issued is itself evidence —
    while ensuring the value never reaches a saved report.
    """
    if not text:
        return text
    return _SECRET_JSON.sub(r'\1"[REDACTED]"', text)


def _get_ci(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup (RFC 9110: field names are case-insensitive)."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return ""


class Probe:
    """Shared HTTP client.

    Certificate verification is **on** by default. It used to be disabled wholesale, which
    quietly broke the tool's own TLS grading: an expired, self-signed, or wrong-hostname
    certificate still scored `no-tls-transport = NO_GAP`, and an on-path attacker could
    forge every verdict. A certificate failure is now surfaced as a *finding* (see
    `_is_tls_failure`) instead of being silently tolerated. `insecure_tls=True` restores
    the old behaviour for deliberately self-signed local sandboxes.
    """

    def __init__(
        self,
        timeout: float = 12.0,
        *,
        insecure_tls: bool = False,
        max_body_bytes: int = 64_000,
    ):
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None
        self._insecure_tls = insecure_tls
        self._max_body_bytes = max_body_bytes
        # Set by the runner once `initialize` tells us what the server settled on. Every
        # later request must advertise the *negotiated* revision, not the one we opened
        # with; keeping it here means each detector gets it right without threading the
        # value through every call site (and forgetting at one of them).
        self.negotiated_version: str | None = None

    async def __aenter__(self) -> "Probe":
        self._session = aiohttp.ClientSession(
            timeout=self._timeout,
            connector=aiohttp.TCPConnector(ssl=not self._insecure_tls),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    @staticmethod
    def jsonrpc(method: str, params: dict | None = None) -> dict:
        req: dict[str, Any] = {
            "jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method
        }
        if params is not None:
            req["params"] = params
        return req

    @staticmethod
    def jsonrpc_notification(method: str, params: dict | None = None) -> dict:
        """A JSON-RPC *notification*: same shape, but with NO `id`.

        The absence of `id` is the only thing that makes a message a notification (JSON-RPC
        2.0 §4.1), and it is what tells the server not to reply. Sending
        `notifications/initialized` with an id made it a request — so the tool broke the
        very handshake rule it audits, and a strict server is entitled to error on it.
        """
        req: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        return req

    @staticmethod
    def initialize_params() -> dict:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpauth", "version": "0.1"},
        }

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        json_body: Any = None,
        rpc_method: str = "",
        allow_redirects: bool = False,
        read_bytes: int | None = None,
    ) -> HttpResult:
        """Issue one HTTP request, never raising on status or transport error.

        Two deliberate departures from aiohttp's defaults:

        * **Redirects are not followed.** They used to be, silently, which made the
          `no-tls-transport` redirect-to-HTTPS branch dead code and — worse — attributed a
          document fetched from another origin to the URL we asked for. RFC 9728's whole
          point is *which* host published a document, so that attribution has to be exact.
        * **The body is read with a byte cap, incrementally.** A Server-Sent Events stream
          stays open by design, so `await resp.text()` waited for the full timeout and then
          threw away everything it had already received. Reading up to a cap returns the
          bytes that are already on the wire, which is what the SSE-based checks need.
        """
        assert self._session is not None, "use 'async with Probe()'"
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        cap = self._max_body_bytes if read_bytes is None else read_bytes
        try:
            async with self._session.request(
                method, url, headers=hdrs, json=json_body,
                allow_redirects=allow_redirects,
            ) as resp:
                raw = await resp.content.read(cap)
                truncated = len(raw) >= cap
                # A non-UTF-8 body is still a successful exchange; don't call it a
                # transport error just because we cannot decode every byte.
                text = raw.decode("utf-8", errors="replace")
                ctype = resp.headers.get("content-type", "")
                if "text/event-stream" in ctype.lower():
                    parsed: Any = _parse_sse(text)
                else:
                    parsed = _parse_body(text, ctype)
                return HttpResult(
                    ok=True,
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=text,
                    json=parsed,
                    url=url,
                    method=method,
                    rpc_method=rpc_method,
                    request_headers=dict(hdrs),
                    final_url=str(resp.url),
                    truncated=truncated,
                )
        except Exception as e:  # noqa: BLE001 — detectors want the message, not a raise
            err = f"{type(e).__name__}: {e}"
            return HttpResult(
                ok=False, error=err, url=url, method=method, rpc_method=rpc_method,
                request_headers=dict(hdrs), tls_failure=_is_tls_failure(err),
            )

    async def mcp_call(
        self,
        url: str,
        method: str,
        params: dict | None = None,
        *,
        headers: dict | None = None,
        protocol_version: str | None = None,
        notification: bool = False,
    ) -> HttpResult:
        """POST a JSON-RPC call with the headers MCP Streamable HTTP expects.

        `MCP-Protocol-Version` is sent on every request, not just `initialize`: it has been
        required on each POST since 2025-06-18, and a server that enforces it rejects an
        unversioned client outright — which would look like a server fault rather than ours.

        Pass `protocol_version` to echo what the server actually negotiated. The spec
        requires the client to send the *negotiated* revision after initialization; the
        default is only the version we open with.

        `notification=True` omits the JSON-RPC `id`, which is what distinguishes a
        notification from a request.
        """
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": (
                protocol_version or self.negotiated_version or MCP_PROTOCOL_VERSION
            ),
        }
        if headers:
            h.update(headers)
        body = (
            self.jsonrpc_notification(method, params) if notification
            else self.jsonrpc(method, params)
        )
        return await self.request(
            "POST", url, headers=h, json_body=body, rpc_method=method,
        )


_TLS_ERROR_MARKERS = (
    "certificateerror",
    "sslcertverificationerror",
    "certificate verify failed",
    "sslerror",
    "ssl:",
    "self-signed certificate",
    "hostname mismatch",
)


def _is_tls_failure(error: str) -> bool:
    """True if a transport error was a certificate/TLS problem, not a plain connect failure.

    With certificate verification enabled, "could not connect" and "the certificate is
    invalid" arrive by the same path but mean very different things: the first is an
    unreachable host, the second is a real TLS finding we must report rather than swallow.
    """
    e = (error or "").lower()
    if "connection refused" in e or "cannot connect to host" in e:
        # aiohttp wraps cert failures in ClientConnectorCertificateError, whose message
        # also mentions the host; the explicit markers below still win.
        return any(m in e for m in _TLS_ERROR_MARKERS if m != "ssl:")
    return any(m in e for m in _TLS_ERROR_MARKERS)


def _parse_body(text: str, ctype: str) -> Any:
    """Parse a response body as JSON when it plausibly is JSON, else None.

    The old test was `"application/json" in ctype`, a case-*sensitive* substring match.
    RFC 9110 §8.3.1 makes media types case-insensitive and RFC 6839 makes any `+json`
    suffix JSON, so `Application/JSON`, `application/scim+json` and `application/json-rpc`
    were all skipped — and every `isinstance(res.json, dict)` branch above then took its
    negative path, turning present metadata documents into "missing" ones. Servers also
    mislabel JSON as `text/plain` or send no content-type at all, so as a last resort we
    sniff the body: if it starts with `{` or `[` and parses, it is JSON.
    """
    c = (ctype or "").lower()
    looks_json = "json" in c
    if not looks_json:
        stripped = text.lstrip()
        # Only sniff when the label is absent or generic — never override an explicit
        # non-JSON type like text/html, where a leading '{' would be a coincidence.
        generic = (not c) or c.startswith("text/plain") or c.startswith(
            "application/octet-stream"
        )
        if not (generic and stripped[:1] in ("{", "[")):
            return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_sse(content: str) -> list:
    """Extract JSON payloads from an SSE body.

    Per the SSE specification a single event's `data` field may be split across several
    `data:` lines, which are joined with newlines to form one payload — exactly what a
    pretty-printed JSON-RPC message looks like on the wire. Decoding each line
    independently (the previous behaviour) dropped every such event, so a valid
    `InitializeResult` framed that way looked like no response at all.

    Lines beginning with `:` are comments (keep-alives) and carry no data. Because we read
    bodies with a byte cap, the final event may lack its terminating blank line, so any
    pending data is flushed at the end.
    """
    events: list = []
    pending: list[str] = []

    def flush() -> None:
        if not pending:
            return
        raw = "\n".join(pending)
        pending.clear()
        try:
            events.append(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            pass  # e.g. the legacy `endpoint` event, whose data is a URL, not JSON

    for line in content.splitlines():
        if line.startswith(":"):        # SSE comment / keep-alive
            continue
        if not line.strip():            # blank line terminates the event
            flush()
            continue
        if line.startswith("data:"):
            # One optional leading space after the colon is part of the framing.
            chunk = line[5:]
            pending.append(chunk[1:] if chunk.startswith(" ") else chunk)
    flush()
    return events


def jsonrpc_result(result: HttpResult) -> Any:
    """Pull the JSON-RPC `result` out of either a JSON or SSE response, else None.

    A JSON-RPC *error* response is not a result: returning None for it keeps "the server
    answered" from being mistaken for "the server complied".
    """
    payload = result.json
    if isinstance(payload, dict):
        if "error" in payload:
            return None
        return payload.get("result")
    if isinstance(payload, list):  # SSE events
        for ev in payload:
            if isinstance(ev, dict) and "result" in ev and "error" not in ev:
                return ev["result"]
    return None


def jsonrpc_error(result: HttpResult) -> Any:
    """The JSON-RPC `error` object, if the response carried one."""
    payload = result.json
    if isinstance(payload, dict):
        return payload.get("error")
    if isinstance(payload, list):
        for ev in payload:
            if isinstance(ev, dict) and "error" in ev:
                return ev["error"]
    return None
