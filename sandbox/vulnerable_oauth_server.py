"""Deliberately INSECURE MCP + OAuth server — exhibits the Tier-2 OAuth/transport gaps.

Validates the Tier-2 detectors' HAS_GAP paths. Run:
    uv run python sandbox/vulnerable_oauth_server.py --port 9110

Gaps present (HAS_GAP expected):
  #6  predictable-session-id   : Mcp-Session-Id is a sequential counter
  #7  origin-not-validated     : ignores the Origin header entirely
  #8  cors-misconfiguration    : reflects any Origin + Allow-Credentials: true
  #9  auth-endpoints-not-https : AS metadata lists cleartext http endpoints
  #11 implicit-flow-enabled    : AS metadata advertises response_type 'token' / implicit
  #12 open-dcr                 : /register issues a client_id with no initial access token

Intentionally NOT a gap here (so the matrix has a NO_GAP anchor for it):
  #10 missing-as-metadata      : valid PRM + AS metadata ARE served (issuer matches)
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

# Sequential session counter — deterministic and guessable (#6). Long, to prove the
# detector catches predictability independent of length (not just "too short").
_session_counter = 0

TOOLS = [
    {"name": "search_documents", "description": "Search the document database.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
]


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _issuer(request: Request) -> str:
    """This server is its own authorization server; issuer = its own origin."""
    return str(request.base_url).rstrip("/")


def _cors_headers(request: Request) -> dict:
    """Reflect whatever Origin the caller sent, and allow credentials (#8)."""
    origin = request.headers.get("origin", "*")
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "authorization, content-type",
    }


async def mcp(request: Request) -> Response:
    global _session_counter
    if request.method == "OPTIONS":  # CORS preflight (#8)
        return Response(status_code=204, headers=_cors_headers(request))
    if request.method == "GET":
        return PlainTextResponse("", media_type="text/event-stream",
                                 headers=_cors_headers(request))

    body = await request.json()
    method, req_id = body.get("method"), body.get("id")
    # No Origin check anywhere (#7): the forged Origin is simply ignored.
    if method == "initialize":
        _session_counter += 1
        sid = f"mcp-session-{_session_counter:020d}"  # 32 chars, but sequential (#6)
        return JSONResponse(
            _result(req_id, {
                "serverInfo": {"name": "vulnerable-oauth-sandbox", "version": "0.1"},
                "capabilities": {"tools": {}},
                "protocolVersion": SPEC,
            }),
            headers={"Mcp-Session-Id": sid, "MCP-Protocol-Version": SPEC,
                     **_cors_headers(request)},
        )
    if method == "tools/list":
        return JSONResponse(_result(req_id, {"tools": TOOLS}),
                            headers=_cors_headers(request))
    if method == "tools/call":
        return JSONResponse(_result(req_id, {"content": [{"type": "text", "text": "ok"}]}),
                            headers=_cors_headers(request))
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "method not found"}})


async def prm(request: Request) -> Response:
    """Valid Protected Resource Metadata pointing at this server as its own AS."""
    issuer = _issuer(request)
    return JSONResponse({
        "resource": f"{issuer}/mcp",
        "authorization_servers": [issuer],
    }, headers={"MCP-Protocol-Version": SPEC})


async def as_metadata(request: Request) -> Response:
    """RFC 8414 metadata with insecure http endpoints (#9) and implicit grant (#11)."""
    issuer = _issuer(request)
    return JSONResponse({
        "issuer": issuer,
        # Cleartext, non-loopback endpoints — exposed tokens/codes in transit (#9).
        "authorization_endpoint": "http://insecure-auth.example/authorize",
        "token_endpoint": "http://insecure-auth.example/token",
        # Open dynamic registration on this very server (#12).
        "registration_endpoint": f"{issuer}/register",
        # Advertises the removed implicit grant (#11), via both signals.
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "implicit"],
        "code_challenge_methods_supported": [],
    })


# In-memory client registry so the create -> delete round trip is real (#12 cleanup).
_clients: dict[str, dict] = {}
_register_counter = 0


async def register(request: Request) -> Response:
    """Open Dynamic Client Registration — issues a client_id with no auth (#12).

    Returns the RFC 7592 management fields (registration_client_uri + access token) so a
    well-behaved scanner can delete the client it just created.
    """
    global _register_counter
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — tolerate empty/invalid bodies
        pass
    _register_counter += 1
    client_id = f"dyn-client-{_register_counter:06d}"
    reg_token = f"reg-token-{client_id}"
    issuer = _issuer(request)
    _clients[client_id] = {"registration_access_token": reg_token}
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": 0,
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "none"),
        # RFC 7592 management fields.
        "registration_client_uri": f"{issuer}/register/{client_id}",
        "registration_access_token": reg_token,
    }, status_code=201)


async def manage_client(request: Request) -> Response:
    """RFC 7592 client-configuration endpoint — supports DELETE (cleanup) here."""
    client_id = request.path_params["client_id"]
    record = _clients.get(client_id)
    if record is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    # Must present the registration access token issued at registration (RFC 7592 §2.3).
    if request.headers.get("authorization") != f"Bearer {record['registration_access_token']}":
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    if request.method == "DELETE":
        _clients.pop(client_id, None)
        return Response(status_code=204)  # RFC 7592 §2.3: success = 204 No Content
    return JSONResponse({"client_id": client_id})


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST", "GET", "OPTIONS"]),
    Route("/.well-known/oauth-protected-resource", prm, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", as_metadata, methods=["GET"]),
    Route("/register", register, methods=["POST"]),
    Route("/register/{client_id}", manage_client, methods=["GET", "DELETE"]),
])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9110)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    print(json.dumps({"vulnerable_oauth_server": f"http://{a.host}:{a.port}/mcp"}))
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
