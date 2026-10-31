import asyncio
import json
import threading

import pytest

from tgwitness import live_stream
from tgwitness.access import Refused


def test_stream_has_finite_lifetime_for_graceful_server_shutdown(journal):
    store, _ = journal

    async def run():
        async def disconnected():
            return False

        updates = live_stream.stream(store, 0, lambda: None, disconnected, lifetime=0)
        with pytest.raises(StopAsyncIteration):
            await anext(updates)

    asyncio.run(run())


def test_scope_change_during_read_discards_old_batch(journal, monkeypatch):
    store, _ = journal
    store.append("message.new", {"text": "removed scope"}, 11, 1)
    visible = store.append("message.new", {"text": "retained scope"}, 22, 2)
    started, release = threading.Event(), threading.Event()
    original, calls = live_stream.notifications, []

    def delayed(*args):
        records = original(*args)
        calls.append(args[2])
        if len(calls) == 1:
            started.set()
            assert release.wait(4)
        return records

    monkeypatch.setattr(live_stream, "notifications", delayed)

    async def run():
        allowed = {11, 22}

        async def disconnected():
            return False

        events = live_stream.stream(store, 0, lambda: allowed, disconnected, interval=0)
        task = asyncio.create_task(anext(events))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            allowed = {22}
            release.set()
            frame = await asyncio.wait_for(task, 2)
            records = json.loads(frame.split("data: ")[1])
            assert [record["seq"] for record in records] == [visible["seq"]]
            assert calls == [{11, 22}, {22}]
        finally:
            release.set()
            await events.aclose()
    asyncio.run(run())


def test_revocation_during_read_yields_no_metadata(journal, monkeypatch):
    store, _ = journal
    store.append("message.new", {"text": "secret"}, 11, 1)
    started, release = threading.Event(), threading.Event()
    original = live_stream.notifications

    def delayed(*args):
        records = original(*args)
        started.set()
        assert release.wait(4)
        return records

    monkeypatch.setattr(live_stream, "notifications", delayed)

    async def run():
        revoked = False

        def authorize():
            if revoked:
                raise Refused("revoked")
            return {11}

        async def disconnected():
            return False

        events = live_stream.stream(store, 0, authorize, disconnected, interval=0)
        task = asyncio.create_task(anext(events))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            revoked = True
            release.set()
            with pytest.raises(Refused):
                await task
        finally:
            release.set()
            await events.aclose()
    asyncio.run(run())


def test_slow_consumer_does_not_read_ahead_and_disconnect_stops_queries(journal, monkeypatch):
    store, _ = journal
    for n in range(110):
        store.append("message.new", {"text": "not in notifications"}, 11, n)
    original, calls = live_stream.notifications, []

    def record(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(live_stream, "notifications", record)

    async def run():
        closed = False

        async def disconnected():
            return closed

        events = live_stream.stream(store, 0, lambda: {11}, disconnected, interval=0)
        frame = await anext(events)
        assert len(json.loads(frame.split("data: ")[1])) == 100
        await asyncio.sleep(.02)
        assert calls == [0]
        closed = True
        with pytest.raises(StopAsyncIteration):
            await anext(events)
        assert calls == [0]
        await events.aclose()
    asyncio.run(run())
