"""Deliberately INSECURE MCP server — exhibits every Tier-1 auth gap.

Used only to validate detectors. Run:
    uv run python sandbox/vulnerable_server.py --port 9100

Gaps present:
  #1 no-authentication-remote           : tools/list & tools/call need no credential
  #2 no-tls-transport                   : plain http (gap only counts on non-loopback)
  #3 missing-www-authenticate           : never issues a 401 challenge
  #4 missing-protected-resource-metadata: /.well-known/... returns 404
  #5 session-id-in-url                  : exposes ?sessionId= in a legacy SSE endpoint event
"""

from __future__ import annotations

import argparse
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

TOOLS = [
    {"name": "search_documents", "description": "Search the document database.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "run_sql", "description": "Execute a SQL query.",
     "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}}},
]


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


async def mcp(request: Request) -> Response:
    """JSON-RPC endpoint. No auth check whatsoever (gap #1, #3).

    A GET (SSE handshake) leaks the session id in the message URL (gap #5), mimicking
    legacy combined endpoints.
    """
    if request.method == "GET":
        return PlainTextResponse(
            "event: endpoint\ndata: /messages/?sessionId=42\n\n",
            media_type="text/event-stream",
        )
    body = await request.json()
    method, req_id = body.get("method"), body.get("id")
    if method == "initialize":
        # Claims current-spec (2025-06-18) compliance — a realistic posture: the server
        # advertises support for the strict revision yet violates its MUSTs (#3/#4).
        # No Mcp-Session-Id header is set, pushing the session detector to the SSE path.
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "vulnerable-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": "2025-06-18",
            }),
            headers={"MCP-Protocol-Version": "2025-06-18"},
        )
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": TOOLS}))
    if method == "tools/call":
        return JSONResponse(_result(req_id, {"content": [{"type": "text", "text": "ok"}]}))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def sse(request: Request) -> Response:
    """Legacy SSE handshake that leaks the session id in the message URL (gap #5)."""
    endpoint_event = "event: endpoint\ndata: /messages/?sessionId=42\n\n"
    return PlainTextResponse(endpoint_event, media_type="text/event-stream")


async def well_known(request: Request) -> Response:
    """No protected-resource metadata (gap #4)."""
    return PlainTextResponse("not found", status_code=404)


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET"]),
    Route("/sse", sse, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", well_known, methods=["GET"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"vulnerable_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
