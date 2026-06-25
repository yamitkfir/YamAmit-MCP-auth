"""HARDENED MCP server — closes every Tier-1 auth gap. Detectors must return NO_GAP.

Run:
    uv run python sandbox/hardened_server.py --port 9101

Behavior:
  #1 requires a Bearer token on privileged calls (else 401)
  #3 the 401 carries WWW-Authenticate with a resource_metadata pointer
  #4 /.well-known/oauth-protected-resource returns authorization_servers
  #5 hands the session back via the Mcp-Session-Id header (never in a URL)
  negotiates protocolVersion 2025-06-18 so strict-spec MUSTs are graded.

(#2 no-tls is validated separately: both sandbox servers are http on loopback, which
is exempt; the http-vs-https logic is unit-tested via TargetSpec without a live cert.)
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

VALID_TOKEN = "sandbox-valid-token"
SPEC = "2025-06-18"

TOOLS = [
    {"name": "search_documents", "description": "Search the document database.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _challenge() -> Response:
    base = "http://127.0.0.1/.well-known/oauth-protected-resource"
    return JSONResponse(
        {"jsonrpc": "2.0", "error": {"code": 401, "message": "unauthorized"}},
        status_code=401,
        headers={"WWW-Authenticate": f'Bearer resource_metadata="{base}"',
                 "MCP-Protocol-Version": SPEC},
    )


def _authorized(request: Request) -> bool:
    auth = request.headers.get("authorization", "")
    return auth == f"Bearer {VALID_TOKEN}"


async def mcp(request: Request) -> Response:
    body = await request.json()
    method, req_id = body.get("method"), body.get("id")

    if method == "initialize":
        # initialize is allowed unauthenticated, but returns a header session id (#5)
        # and negotiates the strict spec version (#3/#4 graded as MUST).
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "hardened-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            headers={"Mcp-Session-Id": secrets.token_urlsafe(24),
                     "MCP-Protocol-Version": SPEC},
        )

    # Privileged methods require a valid bearer token (#1).
    if not _authorized(request):
        return _challenge()

    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": TOOLS}))
    if method == "tools/call":
        return JSONResponse(_result(req_id, {"content": [{"type": "text", "text": "ok"}]}))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def well_known(request: Request) -> Response:
    return JSONResponse({
        "resource": "http://127.0.0.1/mcp",
        "authorization_servers": ["https://auth.example.com"],
    }, headers={"MCP-Protocol-Version": SPEC})


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET"]),
    Route("/.well-known/oauth-protected-resource", well_known, methods=["GET"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9101)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"hardened_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
