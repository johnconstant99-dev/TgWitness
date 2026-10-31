"""Authenticated, stateless MCP transport hosted by the panel."""
import asyncio
import json
import os
from urllib.parse import urlsplit

from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response

from .access import Refused
from .archive import RateLimited


def remember_panel_origin(app, request):
    """Called only after administrator authentication on the MCP settings page."""
    scheme, host = request.scope.get("scheme", "http"), request.headers.get("host", "").lower()
    origin = scheme + "://" + host
    try:
        parsed = urlsplit(origin)
        if (scheme not in ("http", "https") or not parsed.hostname or parsed.netloc != host
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            return
        parsed.port  # Validate the port before remembering it.
    except ValueError:
        return
    supplied = request.headers.get("origin")
    if supplied and supplied.lower() != origin:
        return
    origins = getattr(app.state, "archive_mcp_origins", {})
    origins[origin] = None
    if len(origins) > 16:
        origins.pop(next(iter(origins)))
    app.state.archive_mcp_origins = origins


def trusted_request(request, registered=()):
    """Trust the listening address or the operator's public URL, never an arbitrary Host."""
    try:
        server, port = request.scope.get("server") or ("127.0.0.1", 8787)
        hosts = set()
        if server not in ("0.0.0.0", "::"):
            hosts.add(server.lower())
        hosts.update(("127.0.0.1", "localhost", "::1"))
        authorities = {("[" + host + "]" if ":" in host else host) +
                       (":" + str(port) if port not in (80, 443) else "") for host in hosts}
        origins = {request.scope.get("scheme", "http") + "://" + host for host in authorities}
        for origin in registered:
            authorities.add(urlsplit(origin).netloc)
            origins.add(origin)
        public = os.environ.get("TGWITNESS_PUBLIC_URL", "").strip()
        if public:
            parsed = urlsplit(public)
            if parsed.scheme == "https" and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment):
                authorities.add(parsed.netloc.lower())
                origins.add("https://" + parsed.netloc.lower())
        host = request.headers.get("host", "").lower()
        origin = request.headers.get("origin")
        return host in authorities and (not origin or origin.lower() in origins)
    except ValueError:
        return False


class Endpoint:
    def __init__(self, app):
        self.app, self.active = app, 0

    async def __call__(self, scope, receive, send):
        runtime = getattr(self.app.state, "archive_mcp", None)
        headers = {"Cache-Control": "no-store"}

        async def error(status, detail, extra=None):
            await JSONResponse({"error": detail}, status, headers={**headers, **(extra or {})})(scope, receive, send)

        if runtime is None:
            return await error(503, "MCP is unavailable. Check Integrations in the panel.")
        request = Request(scope, receive)
        if not trusted_request(request, getattr(self.app.state, "archive_mcp_origins", ())):
            return await error(403, "Untrusted MCP host or origin. Open MCP settings at this panel address, "
                               "or set TGWITNESS_PUBLIC_URL for a public endpoint.")
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            return await error(401, "MCP connection credential required.", {"WWW-Authenticate": "Bearer"})
        try:
            who = runtime["connections"].resolve(token, address=request.client.host if request.client else None)
        except RateLimited as exc:
            return await error(429, str(exc), {"Retry-After": "60"})
        except Refused as exc:
            return await error(401, str(exc), {"WWW-Authenticate": "Bearer"})
        if request.method != "POST":
            return await Response(status_code=405, headers={**headers, "Allow": "POST"})(scope, receive, send)
        if self.active >= 32:
            return await error(429, "Too many MCP requests in progress.", {"Retry-After": "1"})
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
        from mcp.server.auth.provider import AccessToken
        from starlette.authentication import AuthCredentials
        scoped = {**scope, "state": {**scope.get("state", {})},
                  "user": AuthenticatedUser(AccessToken(token=who.owner, client_id=who.owner, scopes=who.grant["tools"])),
                  "auth": AuthCredentials(who.grant["tools"])}
        started = False

        async def private_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message.get("headers", []), (b"cache-control", b"no-store")]}
            await send(message)

        self.active += 1
        try:
            async with asyncio.timeout(12):
                body = bytearray()
                async with asyncio.timeout(8):
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > 65536:
                            return await error(413, "MCP request is too large.")
                try:
                    message = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    message = None  # The SDK returns the protocol's parse error.
                if isinstance(message, dict) and message.get("method") == "tools/call":
                    params = message.get("params")
                    name = params.get("name") if isinstance(params, dict) else None
                    # Revalidate after receiving the body, before any SDK call.
                    try:
                        runtime["connections"].resolve(token, count=False, tool=name if isinstance(name, str) else None)
                    except Refused as exc:
                        return await error(403, str(exc))
                first = True

                async def replay():
                    nonlocal first
                    if first:
                        first = False
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await receive()

                await runtime["manager"].handle_request(scoped, replay, private_send)
        except ClientDisconnect:
            return
        except TimeoutError:
            if not started:
                await error(408, "MCP request timed out.")
        finally:
            self.active -= 1
