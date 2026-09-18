"""COMPLIANT subpath-hosted MCP server — publishes its PRM exactly where RFC 9728 says.

The MCP endpoint lives at `/public/mcp`, so RFC 9728 §3.1 puts its Protected Resource
Metadata at the *path-inserted* location:

    /.well-known/oauth-protected-resource/public/mcp

and NOT at the bare origin. This server serves it only at the correct place (the root
location 404s, as it legitimately may — that path belongs to a different resource).

Why this posture exists in the suite: a prober that only probes the bare origin reports
this fully compliant server as `missing-protected-resource-metadata = HAS_GAP`. Since
real MCP servers are routinely hosted at a subpath, that false positive would be common.
The only correct verdict here is NO_GAP.

Also negotiates the older 2025-03-26 revision, which exercises the non-strict grading
branches (where RFC 9728 is not yet a MUST) that no other sandbox reaches.

Run:
    uv run python sandbox/subpath_prm_server.py --port 9121

Behavior:
  #1 no-authentication-remote           : NO_GAP  (401 + WWW-Authenticate on privileged calls)
  #3 missing-www-authenticate           : NO_GAP  (401 carries the resource_metadata pointer)
  #4 missing-protected-resource-metadata: NO_GAP  (PRM at the RFC 9728 path-inserted URL)
"""

from __future__ import annotations

import argparse
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

# Deliberately the OLDER revision: exercises the "not yet a MUST" grading paths.
SPEC = "2025-03-26"
VALID_TOKEN = "subpath-valid-token"
RESOURCE_PATH = "/public/mcp"


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _prm_url(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/.well-known/oauth-protected-resource{RESOURCE_PATH}"


async def mcp(request: Request) -> Response:
    if request.method == "GET":
        return Response("", media_type="text/event-stream")

    body = await request.json()
    method, req_id = body.get("method"), body.get("id")

    if method == "initialize":
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "subpath-prm-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            headers={"MCP-Protocol-Version": SPEC},
        )
    if method == "notifications/initialized":
        return Response(status_code=202)

    if request.headers.get("authorization") != f"Bearer {VALID_TOKEN}":
        # 401 pointing at the path-inserted PRM location (RFC 9728 §5.1).
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": 401, "message": "unauthorized"}},
            status_code=401,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{_prm_url(request)}"',
                "MCP-Protocol-Version": SPEC,
            },
        )
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": []}))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def prm_subpath(request: Request) -> Response:
    """The RFC 9728 §3.1 correct location for a resource hosted at /public/mcp."""
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "resource": f"{base}{RESOURCE_PATH}",
        "authorization_servers": [f"{base}/tenant-a"],
    }, headers={"MCP-Protocol-Version": SPEC})


async def prm_root_absent(request: Request) -> Response:
    """The bare-origin PRM legitimately does not exist for a subpath resource."""
    return PlainTextResponse("not found", status_code=404)


async def as_metadata(request: Request) -> Response:
    """AS metadata for the path-bearing issuer, also via RFC 8414 path insertion."""
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": f"{base}/tenant-a",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
    })


app = Starlette(routes=[
    Route(RESOURCE_PATH, mcp, methods=["POST", "GET"]),
    Route(f"/.well-known/oauth-protected-resource{RESOURCE_PATH}", prm_subpath,
          methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", prm_root_absent, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server/tenant-a", as_metadata,
          methods=["GET"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9121)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"subpath_prm_server": f"http://{a.host}:{a.port}{RESOURCE_PATH}"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
