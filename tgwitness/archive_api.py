"""Panel-managed archive credentials; read-only integration endpoints."""
import asyncio
import json
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr

from .access import Refused
from .archive import ArchiveQuery, ArchiveReader, Connections, ConnectionSettings, MAX_RESPONSE, RateLimited, TOOLS


class ProtocolCheck(BaseModel):
    token: SecretStr
    transport: Literal["stdio", "http"]
    url: str | None = Field(default=None, max_length=2048)


def register(app, authenticate):
    slots = asyncio.Semaphore(2)

    def connections():
        access = app.state.access
        if not hasattr(access, "archive_connections"):
            access.archive_connections = Connections(access.vault)
        return access.archive_connections

    def credential(request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(401, "Archive credential required.", headers={"WWW-Authenticate": "Bearer"})
        return token

    def principal(request, *, count=True):
        try:
            return connections().resolve(credential(request), count=count)
        except RateLimited as exc:
            raise HTTPException(429, str(exc), headers={"Retry-After": "60"}) from None
        except Refused as exc:
            raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from None

    @app.get("/api/integrations/mcp", dependencies=[Depends(authenticate)])
    async def overview():
        manager = connections()
        return {"connections": [manager.public(e) for e in manager.entries], "tools": list(TOOLS)}

    @app.post("/api/integrations/mcp", dependencies=[Depends(authenticate)])
    async def issue(body: ConnectionSettings):
        if set(body.workspaces) - app.state.profiles.entries.keys():
            raise HTTPException(422, "Unknown workspace.")
        try:
            token, entry = connections().issue(body)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"token": token, "connection": entry}

    @app.delete("/api/integrations/mcp/{connection_id}", dependencies=[Depends(authenticate)])
    async def revoke(connection_id: str):
        try:
            connections().revoke(connection_id)
        except KeyError:
            raise HTTPException(404, "Archive connection not found.") from None
        return {"revoked": True}

    @app.post("/api/integrations/mcp/check", dependencies=[Depends(authenticate)])
    async def protocol_check(request: Request, body: ProtocolCheck):
        from .mcp_server import check_protocol
        token = body.token.get_secret_value()
        try:
            connections().resolve(token)
            if body.transport == "http" and not body.url:
                raise ValueError("Enter the MCP server URL.")
            host, port = request.scope.get("server") or ("127.0.0.1", 8787)
            if host in ("0.0.0.0", "::"):
                host = "127.0.0.1"
            address = f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"
            tools = await check_protocol(address, token, body.url if body.transport == "http" else None)
            connections().resolve(token, count=False)
            return {"tools": tools, "messages_read": 0}
        except ImportError:
            raise HTTPException(503, "Install TgWitness with the mcp extra to check the protocol.") from None
        except (ValueError, Refused) as exc:
            raise HTTPException(400, str(exc)) from None
        except Exception:
            raise HTTPException(502, "MCP protocol or authorization check failed. Check the endpoint and credential.") from None

    @app.get("/api/archive/identity")
    async def identity(request: Request):
        who = principal(request)
        return {"connection_id": who.owner, "tools": list(TOOLS), "scope": who.grant["workspaces"],
                "expires_at": who.grant["expires_at"]}

    @app.post("/api/archive/query")
    async def query(request: Request, body: ArchiveQuery):
        who = principal(request)
        try:
            async with asyncio.timeout(8):
                async with slots:
                    result = await asyncio.to_thread(ArchiveReader(app.state.profiles, who).read, body)
            principal(request, count=False)
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError:
            raise HTTPException(503, "Archive query timed out. Narrow the query.") from None
        if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_RESPONSE:
            raise HTTPException(413, "Archive response is too large. Narrow the query.")
        return result
