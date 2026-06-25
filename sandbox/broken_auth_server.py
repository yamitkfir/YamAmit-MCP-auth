"""BROKEN-AUTH MCP server — requires a token but implements the challenge wrong.

This posture exists to exercise the HAS_GAP path of detectors that only trigger when a
server *does* gate access but does so non-compliantly:

  #1 no-authentication-remote : NO_GAP  (it does require a token)
  #3 missing-www-authenticate : HAS_GAP (401 carries no RFC 9728 resource_metadata pointer)
  #4 missing-protected-resource-metadata : HAS_GAP (well-known 404, strict spec claimed)

Run:
    uv run python sandbox/broken_auth_server.py --port 9102
"""

from __future__ import annotations

import argparse
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

SPEC = "2025-06-18"
VALID_TOKEN = "broken-valid-token"


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


async def mcp(request: Request) -> Response:
    body = await request.json()
    method, req_id = body.get("method"), body.get("id")

    if method == "initialize":
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "broken-auth-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            headers={"MCP-Protocol-Version": SPEC},
        )

    if request.headers.get("authorization") != f"Bearer {VALID_TOKEN}":
        # 401 WITHOUT a resource_metadata pointer → gap #3.
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": 401, "message": "unauthorized"}},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer", "MCP-Protocol-Version": SPEC},
        )
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": []}))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def well_known(request: Request) -> Response:
    return PlainTextResponse("not found", status_code=404)


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET"]),
    Route("/.well-known/oauth-protected-resource", well_known, methods=["GET"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9102)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"broken_auth_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
