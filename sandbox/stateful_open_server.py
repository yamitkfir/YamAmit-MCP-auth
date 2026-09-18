"""WIDE-OPEN but STATEFUL MCP server — the posture the prober used to misjudge.

This server requires **no authentication whatsoever**, yet it implements the real
Streamable HTTP session lifecycle: it issues an `Mcp-Session-Id` on `initialize` and
answers HTTP 400 to any later request that omits it, exactly as the spec prescribes
(Transports §Session Management: "Servers that require a session ID SHOULD respond to
requests without an Mcp-Session-Id header (other than initialization) with HTTP 400").

Why this posture exists in the suite: a prober that skips the handshake sees that 400
and cannot tell "I forgot the session id" from "this server is broken", so it reports
INCONCLUSIVE on gap #1 — a wide-open server graded as unknown. Every other sandbox is
stateless, so none of them can catch that regression. Here the only correct verdict for
`no-authentication-remote` is HAS_GAP.

Run:
    uv run python sandbox/stateful_open_server.py --port 9120

Behavior:
  #1 no-authentication-remote : HAS_GAP (tools/list needs no credential, only a session)
  #5 session-id-in-url        : NO_GAP  (session travels in the header, never the URL)
  #6 predictable-session-id   : NO_GAP  (fresh high-entropy id per session)
"""

from __future__ import annotations

import argparse
import json
import secrets

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

SPEC = "2025-06-18"

TOOLS = [
    {"name": "read_internal_docs", "description": "Read the internal document store.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "delete_record", "description": "Delete a database record.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
]

# Live sessions: id -> whether notifications/initialized has arrived.
_sessions: dict[str, bool] = {}


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message, status):
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}},
        status_code=status,
    )


async def mcp(request: Request) -> Response:
    if request.method == "DELETE":
        # Spec: clients SHOULD release sessions with DELETE; we honor it.
        sid = request.headers.get("mcp-session-id")
        if sid and sid in _sessions:
            del _sessions[sid]
            return Response(status_code=204)
        return Response(status_code=404)

    if request.method == "GET":
        # A server-to-client stream, only for an established session.
        if request.headers.get("mcp-session-id") not in _sessions:
            return _error(None, -32600, "Missing or unknown session", 400)
        return Response("", media_type="text/event-stream")

    body = await request.json()
    method, req_id = body.get("method"), body.get("id")

    if method == "initialize":
        sid = secrets.token_urlsafe(24)
        _sessions[sid] = False
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "stateful-open-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": SPEC},
        )

    # Everything after initialize MUST carry the session id (spec: else HTTP 400).
    sid = request.headers.get("mcp-session-id")
    if not sid or sid not in _sessions:
        return _error(req_id, -32600, "Missing session ID", 400)

    if method == "notifications/initialized":
        _sessions[sid] = True
        return Response(status_code=202)  # spec: notifications get 202 Accepted

    # NOTE: no Authorization check anywhere — that is the gap this server exhibits.
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": TOOLS}))
    if method == "tools/call":
        return JSONResponse(_result(req_id, {"content": [{"type": "text", "text": "ok"}]}))
    return _error(req_id, -32601, "method not found", 200)


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET", "DELETE"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9120)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"stateful_open_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
