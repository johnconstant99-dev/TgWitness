import asyncio
import hashlib
import json

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import ClientDisconnect, Request

from tgwitness import live_stream
from tgwitness.access import Refused
from test_access import HARBOR, OTHER, issue, login, panel as panel


def test_batch_targets_validates_every_chat_before_writing(panel):
    app, client = panel
    store = app.state.store
    before = store.stats()["head"]
    result = client.post("/api/targets/batch", json={"chat_ids": [HARBOR, 999], "enabled": False})
    assert result.status_code == 400
    assert store.stats()["head"] == before
    assert all(t["enabled"] for t in store.targets())
    result = client.post("/api/targets/batch", json={"chat_ids": [HARBOR, HARBOR, OTHER], "enabled": False})
    assert result.status_code == 200 and result.json()["updated"] == 2
    assert not any(t["enabled"] for t in store.targets())
    assert store.verify(app.state.vault.public_key)


def test_batch_keeps_enabled_state_when_only_priority_changes(panel):
    app, client = panel
    client.post("/api/targets", json={"chat_id": HARBOR, "enabled": False})
    result = client.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER], "priority": False})
    assert result.status_code == 200
    states = {t["chat_id"]: t for t in app.state.store.targets()}
    assert not states[HARBOR]["enabled"] and states[OTHER]["enabled"]
    assert not any(t["priority"] for t in states.values())


def test_batch_and_media_scope_do_not_leak_other_chats(panel):
    app, client = panel
    token, _ = issue(client, permissions=["view", "sources"], workspaces={"default": [HARBOR]})
    viewer, _ = login(app, token)
    result = viewer.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER], "enabled": False})
    assert result.status_code == 403
    result = viewer.post("/api/targets/batch", json={"chat_ids": [HARBOR], "priority": False})
    assert [t["chat_id"] for t in result.json()["targets"]] == [HARBOR]
    data = b"\x89PNG\r\n\x1a\n" + b"not an actual picture"
    digest = hashlib.sha256(data).hexdigest()
    (app.state.store.root / "media").mkdir(exist_ok=True)
    (app.state.store.root / "media" / digest).write_bytes(data)
    app.state.store.append("media.saved", {"media_sha256": digest}, OTHER, 1)
    assert viewer.get("/api/media/" + digest + "?inline=1").status_code == 404


@pytest.mark.parametrize("data,expected", [
    (b"<svg onload=alert(1)></svg>", "application/octet-stream"),
    (b"<!DOCTYPE html><script>alert(1)</script>", "application/octet-stream"),
    (b"\xff\xd8\xff\xe0saved", "image/jpeg"),
    (b"OggSsaved", "audio/ogg"),
    (b"\x00\x00\x00\x18ftypmp42saved", "video/mp4"),
])
def test_inline_media_uses_bytes_and_keeps_download(panel, data, expected):
    app, client = panel
    digest = hashlib.sha256(data).hexdigest()
    directory = app.state.store.root / "media"
    directory.mkdir(exist_ok=True)
    (directory / digest).write_bytes(data)
    result = client.get("/api/media/" + digest + "?inline=1")
    assert result.status_code == 200 and result.content == data
    assert result.headers["content-type"] == expected
    assert result.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in result.headers["content-security-policy"]
    disposition = "attachment" if expected == "application/octet-stream" else "inline"
    assert result.headers["content-disposition"].startswith(disposition)
    assert client.get("/api/media/" + digest).headers["content-disposition"].startswith("attachment")


def test_stream_contains_only_committed_visible_metadata(journal):
    store, _ = journal
    visible = store.append("message.new", {"text": "private payload"}, HARBOR, 1)
    store.append("message.new", {"text": "other secret"}, OTHER, 1)
    with pytest.raises(RuntimeError), store.transaction():
        store.append("message.new", {"text": "rolled back"}, HARBOR, 2)
        raise RuntimeError()
    records = live_stream.notifications(store, 0, {HARBOR})
    assert [r["seq"] for r in records] == [visible["seq"]]
    assert set(records[0]) == {"seq", "kind", "chat_id", "message_id", "observed_at"}
    assert live_stream.notifications(store, visible["seq"], {HARBOR}) == []


def test_stream_revocation_stops_and_slow_client_has_no_queue(journal):
    store, _ = journal
    for i in range(105):
        store.append("message.new", {"text": str(i)}, HARBOR, i)

    async def run():
        revoked = False

        def authorize():
            if revoked:
                raise Refused("revoked")
            return {HARBOR}

        async def disconnected():
            return False

        updates = live_stream.stream(store, 0, authorize, disconnected, interval=0)
        first = await anext(updates)
        assert len(json.loads(first.split("data: ")[1])) == 100
        second = await anext(updates)
        assert len(json.loads(second.split("data: ")[1])) == 5
        revoked = True
        with pytest.raises(Refused):
            await anext(updates)
        await updates.aclose()

    asyncio.run(run())


def stream_scope(spec="2.4"):
    return {"type": "http", "asgi": {"spec_version": spec}, "method": "GET", "path": "/api/stream",
            "query_string": b"", "headers": [], "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 80), "scheme": "http"}


async def disconnected_receive():
    return {"type": "http.disconnect"}


def test_stream_route_header_failure_does_not_exhaust_slots(tmp_path):
    from tgwitness.app import create_app

    async def run():
        app = create_app(tmp_path)
        endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", None) == "/api/stream")
        scope = stream_scope()
        request = Request(scope)
        credential = HTTPAuthorizationCredentials(scheme="Bearer", credentials="synthetic")
        # These responses have not started: constructing them must reserve nothing.
        responses = [await endpoint(request, after=0, credential=credential) for _ in range(40)]

        async def broken_send(message):
            assert message["type"] == "http.response.start" and message["status"] == 200
            raise OSError("Synthetic disconnect before first body")

        for response in responses:
            with pytest.raises(ClientDisconnect):
                await response(scope, disconnected_receive, broken_send)
            assert response.slots.active == 0

    asyncio.run(run())


def test_stream_limit_counts_active_responses_and_releases_header_cancellation():
    async def run():
        slots = live_stream.StreamSlots()
        gate, started = asyncio.Event(), asyncio.Event()
        headers = 0

        async def body():
            yield ": connected\n\n"

        async def slow_send(message):
            nonlocal headers
            if message["type"] == "http.response.start":
                headers += 1
                if headers == 32:
                    started.set()
                await gate.wait()

        def connection():
            response = live_stream.LimitedStreamingResponse(body(), slots=slots, media_type="text/event-stream")
            return asyncio.create_task(response(stream_scope(), disconnected_receive, slow_send))

        tasks = [connection() for _ in range(32)]
        try:
            await asyncio.wait_for(started.wait(), 5)
            assert slots.active == 32
            rejected = []

            async def capture(message):
                rejected.append(message)

            response = live_stream.LimitedStreamingResponse(body(), slots=slots)
            await response(stream_scope(), disconnected_receive, capture)
            assert rejected[0]["status"] == 429
            assert dict(rejected[0]["headers"])[b"retry-after"] == b"10"
            assert json.loads(rejected[1]["body"]) == {"detail": "Too many live streams."}
            assert slots.active == 32
            tasks[0].cancel()
            with pytest.raises(asyncio.CancelledError):
                await tasks[0]
            assert slots.active == 31
            tasks[0].cancel()  # Repeated cancellation cannot release the same slot again.
            assert slots.active == 31
            tasks.append(connection())
            await asyncio.sleep(0)
            assert slots.active == 32
            gate.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            assert slots.active == 0
        finally:
            gate.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(run())


def test_stream_body_disconnect_closes_generator_and_releases_slot():
    async def run():
        slots, closed = live_stream.StreamSlots(), []

        async def body():
            try:
                yield ": connected\n\n"
                await asyncio.Event().wait()
            finally:
                closed.append(True)

        async def broken_send(message):
            if message["type"] == "http.response.body":
                raise OSError("Synthetic body disconnect")

        response = live_stream.LimitedStreamingResponse(body(), slots=slots)
        with pytest.raises(ClientDisconnect):
            await response(stream_scope(), disconnected_receive, broken_send)
        assert slots.active == 0 and closed == [True]

    asyncio.run(run())


def test_stream_old_asgi_disconnect_and_normal_expiry_release_slots(journal):
    async def run():
        store, _ = journal
        slots = live_stream.StreamSlots()

        async def blocked_send(message):
            await asyncio.Event().wait()

        async def connected():
            return False

        response = live_stream.LimitedStreamingResponse(
            live_stream.stream(store, 0, lambda: None, connected), slots=slots)
        await response(stream_scope("2.0"), disconnected_receive, blocked_send)
        assert slots.active == 0
        sent = []

        async def capture(message):
            sent.append(message)

        expired = live_stream.LimitedStreamingResponse(
            live_stream.stream(store, 0, lambda: None, connected, lifetime=0), slots=slots)
        await expired(stream_scope(), disconnected_receive, capture)
        assert slots.active == 0
        assert sent[0]["status"] == 200 and sent[-1]["more_body"] is False

    asyncio.run(run())


@pytest.mark.parametrize("error", [RuntimeError, asyncio.CancelledError])
def test_stream_slot_released_even_when_iterator_close_fails(error):
    class BrokenClose:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def aclose(self):
            raise error("Synthetic close failure")

    async def run():
        slots = live_stream.StreamSlots()

        async def send(message):
            pass

        response = live_stream.LimitedStreamingResponse(BrokenClose(), slots=slots)
        with pytest.raises(error):
            await response(stream_scope(), disconnected_receive, send)
        assert slots.active == 0

    asyncio.run(run())
