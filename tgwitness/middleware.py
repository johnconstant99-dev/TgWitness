import asyncio

from starlette.responses import JSONResponse

KEEP_ALIVE_SECONDS = 150

MCP_BODY_TIMEOUT = 8
BODY_TIMEOUT = 60
PUBLIC_BODY_TIMEOUT = 10
MAX_PENDING_BODIES = 32
MAX_PENDING_BODY_BYTES = 64 * 1024 * 1024
MAX_PENDING_BODIES_PER_CLIENT = 4


def request_limit(path, default=16384):
    if "/api/account-export" in path:
        return 512 * 1024
    if "/api/analysis/reports/" in path:
        return 65536
    if path.endswith(("/api/auth/import", "/api/auth/import/preview", "/api/profiles/import", "/api/profiles/check")):
        from .account_import import IMPORT_REQUEST_LIMIT
        return IMPORT_REQUEST_LIMIT
    if path.endswith('/api/storage/recovery'):
        return 8 * 1024 * 1024
    if path.endswith('/api/storage'):
        return 128 * 1024
    if path.endswith("/api/network/sources/list"):
        return 1536 * 1024
    if path.endswith("/api/account/avatar"):
        return 7 * 1024 * 1024
    return default


def body_expected(scope):
    headers = scope.get("headers", [])
    if any(key.lower() == b"transfer-encoding" for key, _ in headers):
        return True
    lengths = [value.strip() for key, value in headers if key.lower() == b"content-length"]
    if lengths:
        return len(lengths) != 1 or lengths[0] != b"0"
    return scope.get("method") not in ("GET", "HEAD", "OPTIONS")


def mcp_body(route):
    return route.endswith("/mcp") and not route.endswith(("/api/mcp", "/api/integrations/mcp"))


def body_timeout(route):
    if mcp_body(route):
        return MCP_BODY_TIMEOUT
    if route.endswith(("/api/access/login", "/api/demo-access", "/api/witness/head")) or "/api/archive/" in route:
        return PUBLIC_BODY_TIMEOUT
    return BODY_TIMEOUT


class RequestLimit:
    def __init__(self, app, max_body=16384, path_limits=True):
        self.app, self.max_body, self.path_limits = app, max_body, path_limits
        self.pending_bodies = self.pending_bytes = 0
        self.pending_clients = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not body_expected(scope):
            return await self.app(scope, receive, send)
        body = bytearray()
        limit = request_limit(scope.get("path", ""), self.max_body) if self.path_limits else self.max_body
        route = scope.get("path", "").removeprefix(scope.get("root_path", "")).rstrip("/")
        timeout = body_timeout(route)
        address = (scope.get("client") or ("unknown", 0))[0]
        pending = self.pending_clients.get(address, 0)
        if pending >= MAX_PENDING_BODIES_PER_CLIENT:
            return await JSONResponse({"detail": "Too many pending request bodies from this address. Try again shortly."},
                status_code=429, headers={"Cache-Control": "no-store", "Retry-After": "1"})(scope, receive, send)
        if self.pending_bodies >= MAX_PENDING_BODIES or self.pending_bytes + limit > MAX_PENDING_BODY_BYTES:
            return await JSONResponse({"detail": "Too many pending request bodies. Try again shortly."},
                status_code=503, headers={"Cache-Control": "no-store", "Retry-After": "1"})(scope, receive, send)
        self.pending_bodies += 1
        self.pending_bytes += limit
        self.pending_clients[address] = pending + 1
        too_large = False
        try:
            async with asyncio.timeout(timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        continue
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > limit:
                        too_large = True
                        break
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            detail = "MCP request body timed out" if mcp_body(route) else "Request body timed out"
            return await JSONResponse({"detail": detail}, status_code=408,
                                      headers={"Cache-Control": "no-store"})(scope, receive, send)
        finally:
            self.pending_bodies -= 1
            self.pending_bytes -= limit
            remaining = self.pending_clients[address] - 1
            if remaining:
                self.pending_clients[address] = remaining
            else:
                del self.pending_clients[address]
        if too_large:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        await self.app(scope, replay, send)
