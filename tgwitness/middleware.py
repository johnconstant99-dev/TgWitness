import asyncio

from starlette.responses import JSONResponse

KEEP_ALIVE_SECONDS = 150

MCP_BODY_TIMEOUT = 8
BODY_TIMEOUT = 60
MAX_PENDING_BODIES = 32
MAX_PENDING_BODY_BYTES = 64 * 1024 * 1024


def request_limit(path, default=16384):
    if "/api/account-export" in path:
        return 512 * 1024
    if "/api/analysis/reports/" in path:
        return 65536
    if path.endswith(("/api/auth/import", "/api/auth/import/preview", "/api/profiles/import")):
        from .account_import import IMPORT_REQUEST_LIMIT
        return IMPORT_REQUEST_LIMIT
    if path.endswith('/api/storage/recovery'):
        return 8 * 1024 * 1024
    if path.endswith('/api/storage'):
        return 128 * 1024
    if path.endswith("/api/network/sources/list"):
        return 1536 * 1024
    return default


class RequestLimit:
    def __init__(self, app, max_body=16384, path_limits=True):
        self.app, self.max_body, self.path_limits = app, max_body, path_limits
        self.pending_bodies = self.pending_bytes = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        limit = request_limit(scope.get("path", ""), self.max_body) if self.path_limits else self.max_body
        route = scope.get("path", "").removeprefix(scope.get("root_path", "")).rstrip("/")
        timeout = MCP_BODY_TIMEOUT if route == "/mcp" else BODY_TIMEOUT
        if self.pending_bodies >= MAX_PENDING_BODIES or self.pending_bytes + limit > MAX_PENDING_BODY_BYTES:
            return await JSONResponse({"detail": "Too many pending request bodies. Try again shortly."},
                status_code=503, headers={"Cache-Control": "no-store", "Retry-After": "1"})(scope, receive, send)
        self.pending_bodies += 1
        self.pending_bytes += limit
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
            detail = "MCP request body timed out" if route == "/mcp" else "Request body timed out"
            return await JSONResponse({"detail": detail}, status_code=408,
                                      headers={"Cache-Control": "no-store"})(scope, receive, send)
        finally:
            self.pending_bodies -= 1
            self.pending_bytes -= limit
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
