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
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp

MCP_PROTOCOL_VERSION = "2025-06-18"
USER_AGENT = "mcpauth-prober/0.1"


@dataclass
class HttpResult:
    """Outcome of one HTTP exchange — the unit of evidence."""

    ok: bool                       # did the request complete (not a transport error)?
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    json: Any = None
    error: str = ""
    url: str = ""

    def evidence(self, max_body: int = 400) -> str:
        if not self.ok:
            return f"{self.url} -> transport error: {self.error}"
        body = self.text[:max_body]
        return f"{self.url} -> HTTP {self.status}\n{body}"


class Probe:
    def __init__(self, timeout: float = 12.0):
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "Probe":
        # ssl=False: we are auditing security posture, not trusting the cert chain.
        self._session = aiohttp.ClientSession(
            timeout=self._timeout,
            connector=aiohttp.TCPConnector(ssl=False),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    @staticmethod
    def jsonrpc(method: str, params: dict | None = None) -> dict:
        req = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
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
    ) -> HttpResult:
        """Issue one HTTP request, never raising on status or transport error."""
        assert self._session is not None, "use 'async with Probe()'"
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        try:
            async with self._session.request(
                method, url, headers=hdrs, json=json_body
            ) as resp:
                text = await resp.text()
                parsed: Any = None
                ctype = resp.headers.get("content-type", "")
                if "application/json" in ctype:
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        parsed = None
                elif "text/event-stream" in ctype:
                    parsed = _parse_sse(text)
                return HttpResult(
                    ok=True,
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=text,
                    json=parsed,
                    url=url,
                )
        except Exception as e:  # noqa: BLE001 — detectors want the message, not a raise
            return HttpResult(ok=False, error=f"{type(e).__name__}: {e}", url=url)

    async def mcp_call(
        self,
        url: str,
        method: str,
        params: dict | None = None,
        *,
        headers: dict | None = None,
    ) -> HttpResult:
        """POST a JSON-RPC call. Adds the Accept header MCP Streamable HTTP expects."""
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if headers:
            h.update(headers)
        return await self.request(
            "POST", url, headers=h, json_body=self.jsonrpc(method, params)
        )


def _parse_sse(content: str) -> list:
    """Extract JSON payloads from `data:` lines of an SSE body."""
    events = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            data = line[5:].strip()
            try:
                events.append(json.loads(data))
            except json.JSONDecodeError:
                continue
    return events


def jsonrpc_result(result: HttpResult) -> Any:
    """Pull the JSON-RPC `result` out of either a JSON or SSE response, else None."""
    payload = result.json
    if isinstance(payload, dict):
        return payload.get("result")
    if isinstance(payload, list):  # SSE events
        for ev in payload:
            if isinstance(ev, dict) and "result" in ev:
                return ev["result"]
    return None
