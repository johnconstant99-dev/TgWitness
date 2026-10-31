import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from test_access import HARBOR, panel as panel
from tgwitness import archive_api
from tgwitness.archive import ArchiveQuery, ArchiveReader, ConnectionSettings, Connections
from tgwitness.mcp_transport import trusted_request


def issue(admin, tools):
    response = admin.post("/api/mcp/connections", json={"name": "Boundary audit",
        "workspaces": {"default": [HARBOR]}, "expires_at": time.time() + 3600, "tools": tools})
    assert response.status_code == 200, response.text
    return response.json()


def rpc(client, token, method, params=None, *, headers=None):
    return client.post("/mcp", headers={"Authorization": "Bearer " + token,
        "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25", **(headers or {})},
        json={"jsonrpc": "2.0", "id": 1, "method": method, **({"params": params} if params is not None else {})})


@pytest.mark.parametrize("host,origin,expected", [
    ("127.0.0.1:8787", None, True),
    ("localhost:8787", "http://localhost:8787", True),
    ("[::1]:8787", "http://[::1]:8787", True),
    ("evil.example:8787", None, False),
    ("127.0.0.1:8787", "https://evil.example", False),
    ("127.0.0.1:8787", "null", False),
    ("evidence.example", "https://evidence.example", True),
    ("evidence.example", "http://evidence.example", False),
    ("evidence.example.evil.test", None, False),
])
def test_mcp_host_and_origin_use_configuration_not_forwarded_headers(monkeypatch, host, origin, expected):
    monkeypatch.setenv("TGWITNESS_PUBLIC_URL", "https://evidence.example")
    headers = [(b"host", host.encode()), (b"x-forwarded-host", b"evidence.example"),
               (b"x-forwarded-proto", b"https")]
    if origin is not None:
        headers.append((b"origin", origin.encode()))
    request = Request({"type": "http", "method": "POST", "path": "/mcp", "scheme": "http",
                       "server": ("127.0.0.1", 8787), "headers": headers})
    assert trusted_request(request) is expected


def test_mcp_tools_allowlist_applies_to_discovery_and_direct_calls(panel, monkeypatch):
    app, admin = panel
    issued = issue(admin, ["list_chats"])
    listing = rpc(admin, issued["token"], "tools/list")
    assert listing.status_code == 200, listing.text
    assert [tool["name"] for tool in listing.json()["result"]["tools"]] == ["list_chats"]
    entered = []
    original = ArchiveReader.read

    def recorded(reader, query):
        entered.append(query.tool)
        return original(reader, query)

    monkeypatch.setattr(ArchiveReader, "read", recorded)
    denied = rpc(admin, issued["token"], "tools/call", {"name": "search_messages", "arguments": {"query": ""}})
    assert denied.status_code == 403, denied.text
    assert not entered
    assert "Harbor text" not in denied.text
    allowed = rpc(admin, issued["token"], "tools/call", {"name": "list_chats", "arguments": {}})
    assert allowed.status_code == 200 and not allowed.json()["result"].get("isError"), allowed.text
    assert entered == ["list_chats"]
    assert allowed.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("change", ("revoke", "rotate"))
def test_mcp_discards_read_that_finishes_after_token_change(panel, monkeypatch, change):
    app, admin = panel
    issued = issue(admin, ["search_messages"])
    app.state.store.append("message.new", {"text": "REVOKED_REPLY_SECRET"}, HARBOR, 2)
    entered, release = threading.Event(), threading.Event()
    original = ArchiveReader.read

    def paused(reader, query):
        result = original(reader, query)
        entered.set()
        assert release.wait(10), "Synthetic archive read was not released"
        return result

    monkeypatch.setattr(ArchiveReader, "read", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(rpc, admin, issued["token"], "tools/call",
                              {"name": "search_messages", "arguments": {"query": "REVOKED_REPLY_SECRET"}})
        try:
            assert entered.wait(8), "MCP call did not reach the archive reader"
            getattr(app.state.access.archive_connections, change)(issued["connection"]["id"])
        finally:
            release.set()
        response = pending.result(timeout=8)
    assert response.status_code == 200 and response.json()["result"]["isError"], response.text
    assert "REVOKED_REPLY_SECRET" not in response.text


def test_cancelled_archive_call_retains_its_worker_slot(journal, monkeypatch):
    store, vault = journal
    manager = Connections(vault)
    token, _ = manager.issue(ConnectionSettings(name="Read", workspaces={"default": None}, expires_at=time.time() + 3600))

    async def run():
        app = SimpleNamespace(state=SimpleNamespace(access=SimpleNamespace(archive_connections=manager),
            archive_slots=asyncio.Semaphore(1), profiles=SimpleNamespace(entries={})))
        entered, finished = asyncio.Queue(), asyncio.Queue()
        release = threading.Event()
        loop = asyncio.get_running_loop()

        def paused(_reader, _query):
            loop.call_soon_threadsafe(entered.put_nowait, True)
            try:
                assert release.wait(10)
                return {"items": []}
            finally:
                loop.call_soon_threadsafe(finished.put_nowait, True)

        monkeypatch.setattr(ArchiveReader, "read", paused)
        query = ArchiveQuery(tool="list_workspaces")
        first = asyncio.create_task(archive_api.read(app, token, query))
        requests = [first]
        try:
            await asyncio.wait_for(entered.get(), 3)
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)
            second = asyncio.create_task(archive_api.read(app, token, query))
            requests.append(second)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(entered.get(), .05)
            assert app.state.archive_slots.locked()
            release.set()
            assert await asyncio.wait_for(second, 3) == {"items": []}
            for _ in requests:
                await asyncio.wait_for(finished.get(), 3)
        finally:
            release.set()
            await asyncio.gather(*requests, return_exceptions=True)
    asyncio.run(run())


def test_mcp_read_timeout_returns_a_tool_error_without_unfinished_data(panel, monkeypatch):
    app, admin = panel
    issued = issue(admin, ["search_messages"])
    entered, finished, release = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(archive_api, "QUERY_TIMEOUT", .05)

    def paused(_reader, _query):
        entered.set()
        try:
            assert release.wait(10)
            return {"items": [{"text": "UNFINISHED_READ_SECRET"}]}
        finally:
            finished.set()

    monkeypatch.setattr(ArchiveReader, "read", paused)
    try:
        response = rpc(admin, issued["token"], "tools/call", {"name": "search_messages", "arguments": {"query": ""}})
        assert entered.is_set()
        assert response.status_code == 200 and response.json()["result"]["isError"], response.text
        assert "timed out" in response.text and "UNFINISHED_READ_SECRET" not in response.text
        assert not finished.is_set()
    finally:
        release.set()
        assert finished.wait(3)


def test_only_authenticated_same_origin_panel_can_register_a_public_host(panel, monkeypatch):
    app, admin = panel
    monkeypatch.delenv("TGWITNESS_PUBLIC_URL", raising=False)
    issued = issue(admin, ["list_chats"])
    host = "operator-tunnel.example"
    assert rpc(admin, issued["token"], "tools/list", headers={"Host": host}).status_code == 403
    response = admin.get("/api/mcp", headers={"Host": host, "Authorization": ""})
    assert response.status_code in (401, 403)
    assert rpc(admin, issued["token"], "tools/list", headers={"Host": host}).status_code == 403
    admin.get("/api/mcp", headers={"Host": host, "Origin": "https://foreign.example"})
    assert rpc(admin, issued["token"], "tools/list", headers={"Host": host}).status_code == 403
    response = admin.get("/api/mcp", headers={"Host": host, "Origin": "http://" + host})
    assert response.status_code == 200, response.text
    accepted = rpc(admin, issued["token"], "tools/list", headers={"Host": host, "Origin": "http://" + host})
    assert accepted.status_code == 200, accepted.text
    assert [tool["name"] for tool in accepted.json()["result"]["tools"]] == ["list_chats"]
    assert rpc(admin, issued["token"], "tools/list", headers={"Host": host, "Origin": "https://foreign.example"}).status_code == 403


@pytest.mark.parametrize("mode,status", (("no_body", 408), ("partial", 408), ("too_large", 413), ("complete", 200)))
@pytest.mark.parametrize("prefix", ("", "/panel"))
def test_mcp_body_is_bounded_before_the_sdk_or_auth_runs(monkeypatch, mode, status, prefix):
    from tgwitness import middleware
    monkeypatch.setattr(middleware, "MCP_BODY_TIMEOUT", .05)

    async def run():
        sent, entered, reads = [], [], 0

        async def receive():
            nonlocal reads
            reads += 1
            if mode == "too_large":
                return {"type": "http.request", "body": b"x" * 4096, "more_body": True}
            if mode == "complete" or mode == "partial" and reads == 1:
                return {"type": "http.request", "body": b'{"jsonrpc":"2.0"}', "more_body": mode == "partial"}
            await asyncio.Event().wait()

        async def send(message):
            sent.append(message)

        async def inner(_scope, replay, send):
            entered.append(await replay())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        app = middleware.RequestLimit(inner)
        await asyncio.wait_for(app({"type": "http", "path": prefix + "/mcp", "root_path": prefix}, receive, send), 1)
        assert sent[0]["status"] == status
        assert len(entered) == (1 if mode == "complete" else 0)
        if mode == "complete":
            assert entered[0]["body"] == b'{"jsonrpc":"2.0"}'
        if status == 408:
            assert (b"cache-control", b"no-store") in sent[0]["headers"]
    asyncio.run(run())


def test_legacy_mcp_http_deadline_closes_stream_and_restores_capacity(monkeypatch):
    import httpx
    from tgwitness import mcp_server
    monkeypatch.setattr(mcp_server, "ARCHIVE_TIMEOUT", .05)
    clients, streams, closed = [], [], []

    class Response:
        status_code = 200

        def __init__(self, stuck):
            self.stuck = stuck

        async def __aenter__(self):
            streams.append(self)
            return self

        async def __aexit__(self, *_exc):
            closed.append(self)

        async def aiter_bytes(self, **_options):
            yield b'{"tools":'
            if self.stuck:
                await asyncio.Event().wait()
            yield b"[]}"

    class Client:
        def __init__(self, **options):
            assert options["trust_env"] is False and options["follow_redirects"] is False
            clients.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            closed.append(self)

        def stream(self, *_args, **_options):
            return Response(len(clients) == 1)

    monkeypatch.setattr(httpx, "AsyncClient", Client)

    async def run():
        api = mcp_server.ArchiveAPI("https://archive.example")
        with pytest.raises(TimeoutError):
            await api.request("tgw_mcp_synthetic")
        assert closed == [streams[0], clients[0]]
        assert not api.slots.locked()
        assert await api.request("tgw_mcp_synthetic") == {"tools": []}
        assert closed == [streams[0], clients[0], streams[1], clients[1]]
    asyncio.run(run())
