import asyncio
import json
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FloodWaitError
from telethon.tl import types

from tgwitness import distributed_export, settings_hub, telegram_client
from tgwitness.account_export import AccountExport
from tgwitness.collector import Collector, message_record
from tgwitness.message_selection import Selection, SelectionIndex, detect_language
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_chat_export

CHAT = -1000000000042


def message(mid, text="A sufficiently long English message for this investigation.", parent=None, day=5):
    return types.Message(id=mid, peer_id=types.PeerChannel(42), from_id=types.PeerUser(91),
                         date=datetime(2026, 10, day, tzinfo=timezone.utc), message=text,
                         reply_to=types.MessageReplyHeader(reply_to_msg_id=parent) if parent else None)


def workspace(path):
    path.mkdir()
    store, vault = Store(path), Vault(path)
    store.bind(vault)
    store.set_setting("account", {"id": 100 + sum(map(ord, path.name))})
    vault.save("credentials", {"session": "synthetic-session-presence"})
    collector = Collector(store, vault)
    return SimpleNamespace(state=SimpleNamespace(store=store, vault=vault, collector=collector))


def test_monitoring_rejects_all_export_claims_without_stopping(tmp_path):
    async def scenario():
        app = workspace(tmp_path / "monitor")
        c = app.state.collector
        try:
            c.running = True
            c.restore = AsyncMock()
            assert not c.reserve_export("other")
            with pytest.raises(ValueError, match="busy"):
                await c.start_export(CHAT)
            export = AccountExport(c, app.state.store, app.state.vault)
            with pytest.raises(ValueError, match="busy"):
                await export.start({"transport": "regular"})
            c._avatar = AsyncMock()
            assert await c.avatar(91) is None
            c._avatar.assert_not_awaited()
            assert c.running and c.export_claim is None
            c.restore.assert_not_awaited()
        finally:
            app.state.store.close()
    asyncio.run(scenario())


def test_start_race_reserves_monitoring_before_first_await(tmp_path, monkeypatch):
    async def scenario():
        app = workspace(tmp_path / "race")
        c = app.state.collector
        entered, release = asyncio.Event(), asyncio.Event()
        async def starting():
            entered.set()
            await release.wait()
        c.start_observation = starting
        monkeypatch.setattr(settings_hub, "validate_collection_scope", lambda _: None)
        task = asyncio.create_task(c.start())
        try:
            await entered.wait()
            assert not c.reserve_export("export")
            with pytest.raises(ValueError, match="busy"):
                await c.start()
            release.set()
            await task
            assert not c.observation_starting
            assert c.reserve_export("export")
            with pytest.raises(ValueError, match="busy"):
                await c.start()
        finally:
            release.set()
            await task
            app.state.store.close()
    asyncio.run(scenario())


def test_rpc_calls_and_batch_are_serial(monkeypatch):
    async def scenario():
        client = object.__new__(telegram_client.WitnessClient)
        active, peak, order = 0, 0, []
        async def request(self, sender, req, ordered=False, flood_sleep_threshold=None):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(.001)
            order.append(req)
            active -= 1
            return req
        monkeypatch.setattr(telegram_client.TelegramClient, "_call", request)
        assert await asyncio.gather(client._call(None, [1, 2]), client._call(None, 3)) == [[1, 2], 3]
        assert peak == 1 and order == [1, 2, 3]
    asyncio.run(scenario())


def test_floodwait_is_full_and_persisted_before_next_rpc(monkeypatch):
    async def scenario():
        client = object.__new__(telegram_client.WitnessClient)
        clock, saved, calls = [100.0], [], []
        async def request(self, sender, req, ordered=False, flood_sleep_threshold=None):
            calls.append((req, clock[0]))
            if req == 1:
                raise FloodWaitError(request=None, capture=7200)
            return req
        async def sleep(seconds):
            clock[0] += seconds
        monkeypatch.setattr(telegram_client.TelegramClient, "_call", request)
        monkeypatch.setattr(telegram_client.time, "time", lambda: clock[0])
        monkeypatch.setattr(telegram_client.asyncio, "sleep", sleep)
        client.rpc_backoff_setter = saved.append
        with pytest.raises(FloodWaitError):
            await client._call(None, 1)
        assert saved == [7301.0]
        assert await client._call(None, 2) == 2
        assert calls[1][1] >= 7301.0
    asyncio.run(scenario())


def test_cross_language_reply_and_outside_period_context(tmp_path):
    index = SelectionIndex(tmp_path / "selection.sqlite3", CHAT)
    try:
        index.add(message_record(message(1, "Original before the period", day=1)), "old")
        index.add(message_record(message(2, "English message", parent=1, day=5)), "a")
        index.add(message_record(message(3, "Русский ответ на английское сообщение", parent=2, day=6)), "b")
        options = Selection(from_utc="2026-10-05T00:00:00Z", to_utc="2026-10-07T00:00:00Z",
                            languages=["en"], reply_mode="answered", context_depth=1)
        def language(text):
            return {"status": "detected", "language": "ru" if "Русский" in text else "en"}
        index.classify(options, language)
        index.expand(options, 1)
        rows = {r["id"]: r for r, _ in index.output()}
        assert set(rows) == {1, 2, 3}
        assert rows[2]["selection"]["role"] == "match"
        assert rows[1]["selection"]["role"] == rows[3]["selection"]["role"] == "context"
        assert index.counts()["matched"] == 1
    finally:
        index.close()


def test_answer_scope_and_forum_topic_are_not_conflated(tmp_path):
    index = SelectionIndex(tmp_path / "selection.sqlite3", CHAT)
    try:
        root = message_record(message(1, day=5))
        reply = message_record(message(2, parent=1, day=8))
        post = message_record(message(3, parent=50, day=5))
        post["reply_to"] = {"forum_topic": True, "reply_to_msg_id": 50}
        for row in (root, reply, post):
            index.add(row, "a")
        options = Selection(to_utc="2026-10-07T00:00:00Z", reply_mode="answered")
        index.classify(options)
        assert not list(index.output())
        options.reply_scope = "through_start"
        index.classify(options)
        assert [r["id"] for r, _ in index.output()] == [1]
        index.classify(Selection(reply_mode="replies"))
        assert [r["id"] for r, _ in index.output()] == [2]
    finally:
        index.close()


def test_language_detection_keeps_short_text_unknown():
    assert detect_language("OK")["status"] == "unknown"
    assert detect_language("https://example.org/english-text")["status"] == "unknown"
    assert detect_language("The investigation concerns a large public discussion and the replies to these messages.")["language"] == "en"


class Client:
    def __init__(self, messages):
        self.messages = messages
        self.reads = []
        self.block = None
        self.blocked = asyncio.Event()

    async def get_messages(self, entity, limit=None, offset_date=None, ids=None):
        if ids is not None:
            return next((m for m in self.messages if m.id == ids), None)
        return sorted([m for m in self.messages if offset_date is None or m.date < offset_date],
                      key=lambda m: -m.id)[:limit]

    async def iter_messages(self, entity, offset_id=0, min_id=0):
        self.reads.append((min_id, offset_id))
        if self.block is not None and len(self.reads) > 1:
            self.blocked.set()
            await self.block.wait()
        for m in sorted(self.messages, key=lambda m: -m.id):
            if min_id < m.id < offset_id:
                yield m
        await asyncio.sleep(0)


def coordinator(tmp_path, messages, count=2):
    entries = {}
    peer = types.Channel(id=42, title="Synthetic group", photo=types.ChatPhotoEmpty(),
                         date=datetime.now(timezone.utc), megagroup=True, access_hash=1)
    for i in range(count):
        name = "account" + str(i)
        app = workspace(tmp_path / name)
        c = app.state.collector
        c.client = Client(messages)
        c.restore = AsyncMock()
        c.resolve_for_export = AsyncMock(return_value=peer)
        c.chat_profile = AsyncMock(return_value=({}, {"role": "member"}, []))
        c.dialog_cache = {CHAT: {"kind": "supergroup", "title": "Synthetic group", "entity": peer}}
        entries[name] = {"app": app, "label": name}
    registry = SimpleNamespace(entries=entries, app=entries["account0"]["app"])
    return distributed_export.DistributedExport(registry), entries


def close_entries(entries):
    for entry in entries.values():
        entry["app"].state.store.close()


def test_multi_start_is_atomic_when_one_account_monitors(tmp_path):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)])
        first = entries["account0"]["app"].state.collector
        second = entries["account1"]["app"].state.collector
        second.running = True
        try:
            with pytest.raises(ValueError, match="busy"):
                await manager.start(CHAT, list(entries), "account0")
            assert first.export_claim is None and second.export_claim is None and second.running
            first.resolve_for_export.assert_not_awaited()
        finally:
            close_entries(entries)
    asyncio.run(scenario())


def test_resume_reuses_signed_chunks_and_rejects_tampering(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 7)], count=1)
        c = entries["account0"]["app"].state.collector
        c.client.block = asyncio.Event()
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        try:
            state = await manager.start(CHAT, ["account0"], "account0")
            await asyncio.wait_for(c.client.blocked.wait(), 5)
            await manager.pause(state["id"])
            assert manager.state["phase"] == "paused" and c.export_claim is None
            directory = manager.directory(state["id"])
            receipts = list((directory / "receipts").glob("*.json"))
            assert len(receipts) == 1
            preserved = json.loads(receipts[0].read_text())["statement"]
            first_bounds = (preserved["low"] - 1, preserved["high"] + 1)
            restored = distributed_export.DistributedExport(manager.profiles)
            assert restored.public()["phase"] == "paused"
            c.client.block = None
            c.client.reads.clear()
            # Keep this recovery test independent of HTML/PDF rendering.
            async def finish(directory, options):
                assert first_bounds not in c.client.reads
                raise ValueError("Recovery reached selection")
            restored.finish_selection = finish
            await restored.resume(state["id"])
            await asyncio.wait_for(restored.task, 10)
            assert restored.state["error"] == "Recovery reached selection"
            assert len(list((directory / "receipts").glob("*.json"))) == 3
            chunk = directory / "chunks" / (str(preserved["low"]) + ".jsonl")
            chunk.write_text(chunk.read_text().replace("English", "tampered"))
            c.client.reads.clear()
            await restored.resume(state["id"])
            await asyncio.wait_for(restored.task, 5)
            assert "differs" in restored.state["error"]
            assert not c.client.reads and c.export_claim is None
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_filtered_archive_is_verifiable_and_contains_context(tmp_path, monkeypatch):
    async def scenario():
        rows = [message(1, day=1), message(2, parent=1, day=5),
                message(3, "Русский ответ на исходное сообщение.", parent=2, day=6)]
        manager, entries = coordinator(tmp_path, rows)
        monkeypatch.setattr(distributed_export, "CHUNK", 1)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0", selection={
                "from_utc": "2026-10-05T00:00:00Z", "to_utc": "2026-10-07T00:00:00Z",
                "reply_mode": "answered", "context_depth": 1})
            await asyncio.wait_for(manager.task, 60)
            assert manager.state["phase"] == "done", manager.state
            path = manager.result_path(state["id"])
            public = entries["account0"]["app"].state.vault.public_key
            checked = verify_chat_export(path, fingerprint(public))
            assert checked["message_count"] == 3
            with zipfile.ZipFile(path) as archive:
                result = json.loads(archive.read("chat.json"))
                assert json.loads(archive.read("message-ids.json"))["selection_applied"]
                assert b"Context message" in archive.read("chat.html")
                assert b"deleted before the export, or never visible" not in archive.read("chat.html")
            messages = {row["id"]: row for row in result["messages"]}
            assert messages[2]["selection"]["role"] == "match"
            assert messages[1]["selection"]["role"] == messages[3]["selection"]["role"] == "context"
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_cancelling_an_old_job_cannot_replace_active_state(tmp_path):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)], count=1)
        collector = entries["account0"]["app"].state.collector
        try:
            old = await manager.start(CHAT, ["account0"], "account0")
            await manager.pause(old["id"])
            new = await manager.start(CHAT, ["account0"], "account0")
            with pytest.raises(ValueError, match="current"):
                await manager.cancel(old["id"])
            assert manager.state["id"] == new["id"] and collector.export_claim == new["id"]
            await manager.pause(new["id"])
            assert manager.state["phase"] == "paused" and collector.export_claim is None
            assert len(manager.list_jobs()) == 2
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_preflight_cancellation_releases_every_account(tmp_path):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)])
        started = asyncio.Event()
        async def resolve(*args):
            started.set()
            await asyncio.Event().wait()
        first = entries["account0"]["app"].state.collector
        first.resolve_for_export = resolve
        task = asyncio.create_task(manager.start(CHAT, list(entries), "account0"))
        try:
            await asyncio.wait_for(started.wait(), 2)
            assert all(entry["app"].state.collector.export_claim for entry in entries.values())
            with pytest.raises(ValueError, match="current"):
                await manager.start(CHAT, list(entries), "account0")
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert not manager.busy()
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("interruption", ["failure", "pause", "repeated_pause", "failure_then_pause"])
def test_workers_finish_cleanup_before_accounts_are_released(tmp_path, interruption):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)])
        entered, draining, release, stopped = (asyncio.Event() for _ in range(4))
        workers = []

        async def work(worker):
            workers.append(asyncio.current_task())
            if worker["profile_id"] == "account0":
                await entered.wait()
                if interruption.startswith("failure"):
                    raise OSError("Synthetic chunk-index failure")
                await asyncio.Event().wait()
            else:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    draining.set()
                    await release.wait()
                    stopped.set()

        manager.work = work
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            await asyncio.wait_for(entered.wait(), 5)
            if interruption in ("pause", "repeated_pause"):
                manager.task.cancel()
            await asyncio.wait_for(draining.wait(), 5)
            assert manager.busy() and manager.db is not None and not stopped.is_set()
            for entry in entries.values():
                collector = entry["app"].state.collector
                assert collector.export_claim == state["id"]
                assert not collector.reserve_export("competing-task")
            if interruption in ("repeated_pause", "failure_then_pause"):
                manager.task.cancel()
                await asyncio.sleep(0)
                assert manager.busy() and not stopped.is_set()
            release.set()
            await asyncio.wait_for(asyncio.gather(manager.task, return_exceptions=True), 5)
            assert stopped.is_set() and all(task.done() for task in workers)
            assert manager.db is None and not manager.busy()
            assert manager.state["phase"] == ("failed" if interruption == "failure" else "paused")
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            release.set()
            for task in workers:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_context_cap_and_precise_half_open_dates(tmp_path):
    options = Selection(from_utc="2026-10-05T00:00:00Z", to_utc="2026-10-05T00:00:01Z",
                        text_contains=["root"], context_depth=1, max_context_messages=2)
    assert options.in_period({"date": "2026-10-05T00:00:00.500000Z"})
    assert not options.in_period({"date": "2026-10-05T00:00:01.000000Z"})
    with pytest.raises(ValueError, match="time zone"):
        Selection(from_utc="2026-10-05T00:00:00")
    index = SelectionIndex(tmp_path / "context.sqlite3", CHAT)
    try:
        index.add(message_record(message(1, "root")), "a")
        for mid in range(2, 102):
            index.add(message_record(message(mid, "answer", parent=1)), "a")
        index.classify(options)
        index.expand(options, 1)
        assert index.counts()["context"] == 2 and index.counts()["matched"] == 1
        assert len(list(index.output())) == 3
    finally:
        index.close()


def test_rpc_peer_resolution_reentrancy_and_cancelled_wait(monkeypatch):
    async def scenario():
        client = object.__new__(telegram_client.WitnessClient)
        calls = []
        async def request(self, sender, req, ordered=False, flood_sleep_threshold=None):
            calls.append(req)
            return await self._call(sender, 2) if req == 1 else req
        monkeypatch.setattr(telegram_client.TelegramClient, "_call", request)
        assert await asyncio.wait_for(client._call(None, 1), 2) == 2
        assert calls == [1, 2]
        deadline = telegram_client.time.time() + 7200
        client.rpc_backoff_getter = lambda: deadline
        waiting = asyncio.create_task(client._call(None, 3))
        await asyncio.sleep(.01)
        waiting.cancel()
        await asyncio.gather(waiting, return_exceptions=True)
        assert calls == [1, 2] and client.rpc_backoff_getter() == deadline
        assert not client._rpc_lock.locked()
    asyncio.run(scenario())


def test_ten_accounts_cover_chunks_once(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 21)], count=10)
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        async def finish(directory, options):
            assert manager.state["ranges_done"] == 10 and manager.state["captured"] == 20
            ranges = [bounds for entry in entries.values() for bounds in entry["app"].state.collector.client.reads]
            assert len(ranges) == len(set(ranges)) == 10
            assert all(entry["app"].state.collector.client.reads for entry in entries.values())
            raise ValueError("Ten-account acquisition checked")
        manager.finish_selection = finish
        try:
            await manager.start(CHAT, list(entries), "account0")
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["error"] == "Ten-account acquisition checked", manager.state
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
