from starlette.responses import JSONResponse


def request_limit(path, default=16384):
    if "/api/analysis/reports/" in path:
        return 65536
    if path.endswith(("/api/auth/import", "/api/profiles/import")):
        from .account_import import IMPORT_REQUEST_LIMIT
        return IMPORT_REQUEST_LIMIT
    if path.endswith("/api/network/sources/list"):
        return 1536 * 1024
    return default


class RequestLimit:
    """Enforce request size while receiving, including requests without Content-Length."""
    def __init__(self, app, max_body=16384, path_limits=True):
        self.app, self.max_body, self.path_limits = app, max_body, path_limits

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        limit = request_limit(scope.get("path", ""), self.max_body) if self.path_limits else self.max_body
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        sent = False
        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        await self.app(scope, replay, send)
