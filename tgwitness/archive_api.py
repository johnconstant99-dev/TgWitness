"""Panel-managed archive credentials; read-only integration endpoints."""
import asyncio
import json
from types import SimpleNamespace
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, ValidationError

from .access import Refused
from .archive import ArchiveQuery, ArchiveReader, Connections, ConnectionSettings, MAX_RESPONSE, RateLimited, TOOLS
from .workers import limited_in_thread

QUERY_TIMEOUT = 8

async def startup(app):
    app.state.archive_mcp = None
    from .mcp_server import build_server, runtime_status
    if not runtime_status()["available"]:
        return
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import TransportSecuritySettings

    async def request(token, query=None, address=None):
        try:
            who = connections(app).resolve(token, count=False)
            if query is None:
                return identity_view(who)
            return await read(app, token, ArchiveQuery.model_validate(query), address)
        except (Refused, ValidationError) as exc:
            raise ValueError(str(exc)) from None

    server = build_server(SimpleNamespace(request=request))
    # Endpoint validates the listening address, configured public host and Origin.
    manager = StreamableHTTPSessionManager(server._lowlevel_server, json_response=True, stateless=True,
        max_request_body_size=65536, security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    context = manager.run()
    await context.__aenter__()
    app.state.archive_mcp = {"server": server, "manager": manager, "context": context,
                             "connections": connections(app)}


async def shutdown(app):
    runtime = getattr(app.state, "archive_mcp", None)
    app.state.archive_mcp = None
    if runtime is not None:
        await runtime["context"].__aexit__(None, None, None)
    manager = getattr(getattr(app.state, "access", None), "archive_connections", None)
    if manager is not None:
        manager.save()


def connections(app):
    access = app.state.access
    if not hasattr(access, "archive_connections"):
        access.archive_connections = Connections(access.vault)
    return access.archive_connections


def identity_view(who):
    return {"connection_id": who.owner, "tools": who.grant["tools"], "scope": who.grant["workspaces"],
            "expires_at": who.grant["expires_at"]}


async def read(app, token, body, address=None):
    manager = connections(app)
    who = manager.resolve(token, count=False, tool=body.tool)
    async with asyncio.timeout(QUERY_TIMEOUT):
        result = await limited_in_thread(app.state.archive_slots, ArchiveReader(app.state.profiles, who).read, body)
    manager.resolve(token, count=False, tool=body.tool)
    if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_RESPONSE:
        raise ValueError("Archive response is too large. Narrow the query.")
    return result


class ProtocolCheck(BaseModel):
    token: SecretStr
    transport: Literal["stdio", "http"]
    url: str | None = Field(default=None, max_length=2048)


def register(app, authenticate):
    app.state.archive_slots = asyncio.Semaphore(2)

    def credential(request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(401, "Archive credential required.", headers={"WWW-Authenticate": "Bearer"})
        return token

    def principal(request, *, count=True):
        try:
            return connections(app).resolve(credential(request), count=count,
                                            address=request.client.host if request.client else None)
        except RateLimited as exc:
            raise HTTPException(429, str(exc), headers={"Retry-After": "60"}) from None
        except Refused as exc:
            raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from None

    @app.get("/api/mcp", dependencies=[Depends(authenticate)])
    @app.get("/api/integrations/mcp", dependencies=[Depends(authenticate)])
    async def overview(request: Request):
        from .mcp_server import runtime_status
        from .mcp_transport import remember_panel_origin
        remember_panel_origin(app, request)
        manager, status = connections(app), runtime_status()
        if status["available"] and getattr(app.state, "archive_mcp", None) is None:
            status.update(available=False, problem="MCP support is installed. Restart TgWitness to activate the endpoint.")
        return {**status, "connections": [manager.public(e) for e in manager.entries], "tools": list(TOOLS),
                "endpoint": "/mcp", "max_days": 90,
                "tool_groups": {"navigation": list(TOOLS[:2]), "messages": list(TOOLS[2:6]), "capture": [TOOLS[6]]}}

    @app.post("/api/mcp/connections", dependencies=[Depends(authenticate)])
    @app.post("/api/integrations/mcp", dependencies=[Depends(authenticate)])
    async def issue(body: ConnectionSettings):
        if set(body.workspaces) - app.state.profiles.entries.keys():
            raise HTTPException(422, "Unknown workspace.")
        try:
            token, entry = connections(app).issue(body)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"token": token, "connection": entry}

    @app.post("/api/mcp/connections/{connection_id}/rotate", dependencies=[Depends(authenticate)])
    @app.post("/api/integrations/mcp/{connection_id}/rotate", dependencies=[Depends(authenticate)])
    async def rotate(connection_id: str):
        try:
            token, entry = connections(app).rotate(connection_id)
        except KeyError:
            raise HTTPException(404, "Archive connection not found.") from None
        except Refused as exc:
            raise HTTPException(422, str(exc)) from None
        return {"token": token, "connection": entry}

    @app.delete("/api/mcp/connections/{connection_id}", dependencies=[Depends(authenticate)])
    @app.delete("/api/integrations/mcp/{connection_id}", dependencies=[Depends(authenticate)])
    async def revoke(connection_id: str):
        try:
            connections(app).revoke(connection_id)
        except KeyError:
            raise HTTPException(404, "Archive connection not found.") from None
        return {"revoked": True}

    @app.post("/api/mcp/check", dependencies=[Depends(authenticate)])
    @app.post("/api/integrations/mcp/check", dependencies=[Depends(authenticate)])
    async def protocol_check(request: Request, body: ProtocolCheck):
        from .mcp_server import check_protocol
        token = body.token.get_secret_value()
        try:
            connections(app).resolve(token)
            host, port = request.scope.get("server") or ("127.0.0.1", 8787)
            if host in ("0.0.0.0", "::"):
                host = "127.0.0.1"
            address = f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"
            result = await check_protocol(address, token, (body.url or address + "/mcp") if body.transport == "http" else None,
                                          stdio_url=body.url if body.transport == "stdio" else None)
            connections(app).resolve(token, count=False)
            return result
        except ImportError:
            raise HTTPException(503, "Install TgWitness with the mcp extra to check the protocol.") from None
        except (ValueError, Refused) as exc:
            raise HTTPException(400, str(exc)) from None
        except Exception:
            raise HTTPException(502, "MCP protocol or authorization check failed. Check the endpoint and credential.") from None

    @app.get("/api/archive/identity")
    async def identity(request: Request):
        who = principal(request)
        return identity_view(who)

    @app.post("/api/archive/query")
    async def query(request: Request, body: ArchiveQuery):
        principal(request)
        try:
            return await read(app, credential(request), body, request.client.host if request.client else None)
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError:
            raise HTTPException(503, "Archive query timed out. Narrow the query.") from None

    from .mcp_transport import Endpoint
    app.add_route("/mcp", Endpoint(app), methods=["GET", "POST", "DELETE"])
