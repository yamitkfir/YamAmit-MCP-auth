"""HARDENED MCP + OAuth server — closes every Tier-2 gap. Detectors must return NO_GAP.

Run:
    uv run python sandbox/hardened_oauth_server.py --port 9111

Behavior (NO_GAP expected):
  #6  predictable-session-id   : Mcp-Session-Id is a fresh cryptographically-random token
  #7  origin-not-validated     : forged Origin -> 403 (absent Origin is allowed, as a
                                 non-browser MCP client legitimately sends none)
  #8  cors-misconfiguration    : emits no Access-Control-Allow-Origin for foreign origins
  #9  auth-endpoints-not-https : every AS-metadata endpoint uses https (or loopback)
  #10 missing-as-metadata      : RFC 8414 metadata served, issuer matches
  #11 implicit-flow-enabled    : code grant only, S256 PKCE — no implicit
  #12 open-dcr                 : /register requires an initial access token (else 401)
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
REGISTRATION_TOKEN = "sandbox-initial-access-token"


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _issuer(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _origin_ok(request: Request) -> bool:
    """Allow same-origin or an absent Origin; reject any foreign Origin (#7)."""
    origin = request.headers.get("origin")
    if not origin:
        return True  # non-browser clients send no Origin; nothing to rebind.
    return origin.rstrip("/") == _issuer(request)


async def mcp(request: Request) -> Response:
    if request.method == "OPTIONS":
        # Preflight from a foreign origin gets no ACAO header at all (#8).
        return Response(status_code=204)

    # Enforce Origin on every data request, GET stream included (#7).
    if not _origin_ok(request):
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": 403, "message": "forbidden origin"}},
            status_code=403,
        )
    if request.method == "GET":
        return Response("", media_type="text/event-stream")

    body = await request.json()
    method, req_id = body.get("method"), body.get("id")
    if method == "initialize":
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "hardened-oauth-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            # Fresh, high-entropy session id every call (#6).
            headers={"Mcp-Session-Id": secrets.token_urlsafe(24),
                     "MCP-Protocol-Version": SPEC},
        )
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": []}))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def prm(request: Request) -> Response:
    issuer = _issuer(request)
    return JSONResponse({
        "resource": f"{issuer}/mcp",
        "authorization_servers": [issuer],
    }, headers={"MCP-Protocol-Version": SPEC})


async def as_metadata(request: Request) -> Response:
    """RFC 8414 metadata: https endpoints, code-only grant, S256, issuer matches (#9/#10/#11)."""
    issuer = _issuer(request)
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "registration_endpoint": f"{issuer}/register",
        "jwks_uri": "https://auth.example.com/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
    })


async def register(request: Request) -> Response:
    """Protected DCR: requires an initial access token, else 401 (#12)."""
    if request.headers.get("authorization") != f"Bearer {REGISTRATION_TOKEN}":
        return JSONResponse(
            {"error": "invalid_token", "error_description": "initial access token required"},
            status_code=401,
        )
    return JSONResponse({"client_id": "registered-client-1"}, status_code=201)


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET", "OPTIONS"]),
    Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", as_metadata, methods=["GET"]),
    Route("/register", register, methods=["POST"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9111)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"hardened_oauth_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
