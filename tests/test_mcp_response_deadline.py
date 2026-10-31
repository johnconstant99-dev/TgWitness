"""A stalled SDK response must close, rather than masquerade as a finished response."""
import asyncio
from types import SimpleNamespace

import pytest

from tgwitness import mcp_transport

pytest.importorskip("mcp")


def test_started_mcp_response_timeout_reaches_asgi_and_releases_capacity(monkeypatch):
    monkeypatch.setattr(mcp_transport, "REQUEST_TIMEOUT", .03, raising=False)

    async def run():
        calls = 0

        async def handle(_scope, receive, send):
            nonlocal calls
            calls += 1
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            if calls == 1:
                await send({"type": "http.response.body", "body": b'{"result":', "more_body": True})
                await asyncio.Event().wait()
            await send({"type": "http.response.body", "body": b'{}', "more_body": False})

        who = SimpleNamespace(owner="synthetic", grant={"tools": ["list_chats"]})
        connections = SimpleNamespace(resolve=lambda *_args, **_kwargs: who)
        app = SimpleNamespace(state=SimpleNamespace(archive_mcp={
            "connections": connections, "manager": SimpleNamespace(handle_request=handle)}))
        endpoint = mcp_transport.Endpoint(app)
        scope = {"type": "http", "method": "POST", "path": "/mcp", "scheme": "http",
                 "server": ("127.0.0.1", 8787), "client": ("127.0.0.1", 50001),
                 "headers": [(b"host", b"127.0.0.1:8787"), (b"authorization", b"Bearer tgw_mcp_synthetic")]}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', "more_body": False}

        async def send(message):
            sent.append(message)

        # Raising lets the ASGI server close the incomplete connection. Returning
        # normally after response.start would leave a successful, truncated body.
        with pytest.raises(TimeoutError):
            await endpoint(scope, receive, send)
        assert endpoint.active == 0
        assert sent and sent[-1].get("more_body") is True
        sent.clear()
        await endpoint(scope, receive, send)
        assert endpoint.active == 0 and sent[-1]["body"] == b'{}'
        assert (b"cache-control", b"no-store") in sent[0]["headers"]

    asyncio.run(run())
