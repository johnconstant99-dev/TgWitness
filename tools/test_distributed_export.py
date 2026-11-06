import asyncio
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FloodWaitError, FloodPremiumWaitError, RPCError, TypeNotFoundError
from telethon.tl import types
from telethon.tl.functions import account as account_functions

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tgwitness import chat_export, distributed_export, export_timing, settings_hub, telegram_client, verify
from tgwitness.account_export import AccountExport
from tgwitness.collector import Collector, UnreadableHistory, message_record
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


@pytest.mark.parametrize("error_type", [FloodWaitError, FloodPremiumWaitError])
def test_floodwait_is_full_and_persisted_before_next_rpc(monkeypatch, error_type):
    async def scenario():
        client = object.__new__(telegram_client.WitnessClient)
        clock, saved, calls = [100.0], [], []
        async def request(self, sender, req, ordered=False, flood_sleep_threshold=None):
            calls.append((req, clock[0]))
            if req == 1:
                raise error_type(request=None, capture=7200)
            return req
        async def sleep(seconds):
            clock[0] += seconds
        monkeypatch.setattr(telegram_client.TelegramClient, "_call", request)
        monkeypatch.setattr(telegram_client.time, "time", lambda: clock[0])
        monkeypatch.setattr(telegram_client.asyncio, "sleep", sleep)
        client.rpc_backoff_setter = lambda until, method: saved.append(until)
        with pytest.raises(error_type):
            await client._call(None, 1)
        assert saved == [7301.0]
        assert await client._call(None, 2) == 2
        assert calls[1][1] >= 7301.0
    asyncio.run(scenario())


def test_reconnect_does_not_shorten_persisted_flood_wait(tmp_path, monkeypatch):
    async def scenario():
        app = workspace(tmp_path / "reconnect")
        collector, store = app.state.collector, app.state.store
        clock = [100.0]
        monkeypatch.setattr(telegram_client.time, "time", lambda: clock[0])
        async def restore():
            clock[0] = 200.0
            store.set_setting("rpc_backoff_until", 500.0)
            raise FloodWaitError(None, capture=10)
        collector.restore = restore
        try:
            await collector.reconnect()
            assert store.get_setting("rpc_backoff_until") == 500.0
            assert collector.next_reconnect_at == 500.0
        finally:
            store.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("error_type", [FloodWaitError, FloodPremiumWaitError])
def test_export_retry_waits_without_changing_api_pair(monkeypatch, error_type):
    async def scenario():
        clock, calls, states = [100.0], [], []
        job = SimpleNamespace(current={}, persist=lambda: states.append(dict(job.current)))
        async def request():
            calls.append(clock[0])
            if len(calls) == 1:
                raise error_type(None, capture=60)
            return "page"
        async def sleep(seconds):
            clock[0] += seconds
        monkeypatch.setattr(telegram_client.time, "time", lambda: clock[0])
        monkeypatch.setattr(telegram_client.asyncio, "sleep", sleep)
        assert await AccountExport.retry(job, request) == "page"
        assert calls == [100.0, 161.0]
        assert states[0]["wait_reason"] == "rate_limit" and states[0]["wait_until"] == 160.0
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
        self.by_number = {}
        self.iter_options = []

    def lookup(self, mid):
        return next((m for m in self.messages if m.id == mid), None) or self.by_number.get(mid)

    async def __call__(self, request, ordered=False):
        raise RPCError(request, "TAKEOUT_UNAVAILABLE_IN_TEST", 400)

    async def get_messages(self, entity, limit=None, offset_date=None, ids=None):
        if ids is not None:
            return [self.lookup(mid) for mid in ids] if isinstance(ids, list) else self.lookup(ids)
        return sorted([m for m in self.messages if offset_date is None or m.date < offset_date],
                      key=lambda m: -m.id)[:limit]

    async def iter_messages(self, entity, offset_id=0, min_id=0, **options):
        self.reads.append((min_id, offset_id))
        self.iter_options.append(options)
        if self.block is not None and len(self.reads) > 1:
            self.blocked.set()
            await self.block.wait()
        for m in sorted(self.messages, key=lambda m: -m.id):
            if min_id < m.id < offset_id:
                yield m
        await asyncio.sleep(0)


class PoisonClient(Client):
    page = 3

    def __init__(self, messages, poison):
        super().__init__(messages)
        self.poison = set(poison)

    def fail(self):
        raise TypeNotFoundError(0xddb5ab75, b"undecoded remainder")

    async def get_messages(self, entity, limit=None, offset_date=None, ids=None, add_offset=0):
        if ids is not None:
            if self.poison & set(ids if isinstance(ids, list) else [ids]):
                self.fail()
            return await super().get_messages(entity, ids=ids)
        ordered = sorted([m for m in self.messages if offset_date is None or m.date < offset_date], key=lambda m: -m.id)
        window = ordered[add_offset:add_offset + (limit or len(ordered))]
        if any(m.id in self.poison for m in window):
            self.fail()
        return window

    async def iter_messages(self, entity, offset_id=0, min_id=0):
        self.reads.append((min_id, offset_id))
        ordered = [m for m in sorted(self.messages, key=lambda m: -m.id)
                   if min_id < m.id and (not offset_id or m.id < offset_id)]
        for start in range(0, len(ordered), self.page):
            page = ordered[start:start + self.page]
            if any(m.id in self.poison for m in page):
                self.fail()
            for m in page:
                yield m
            await asyncio.sleep(0)


def test_undecodable_message_is_recorded_and_history_continues(tmp_path):
    async def scenario():
        app = workspace(tmp_path / "reader")
        collector = app.state.collector
        collector.client = PoisonClient([message(i) for i in range(1, 11)], poison={7})
        peer = types.Channel(id=42, title="Synthetic group", photo=types.ChatPhotoEmpty(),
                             date=datetime.now(timezone.utc), megagroup=True, access_hash=1)
        try:
            count, _ = await collector.fetch_range(peer, 1, 10, tmp_path / "chunk.jsonl")
            rows = [json.loads(line) for line in (tmp_path / "chunk.jsonl").read_text(encoding="utf-8").splitlines()]
            assert count == 10 and [row["id"] for row in rows] == list(range(10, 0, -1))
            unparsed = [row for row in rows if row["type"] == "unparsed"]
            assert [row["id"] for row in unparsed] == [7] and unparsed[0]["unparsed"]["constructor"] == "ddb5ab75"
            event = next(e for e in app.state.store.events(limit=5) if e["kind"] == "history.unparsed")
            assert event["payload"]["numbers"] == [7]

            collector.client = PoisonClient([message(i) for i in range(1, 31)], poison=range(1, 31))
            with pytest.raises(UnreadableHistory, match="ddb5ab75"):
                await collector.fetch_range(peer, 1, 30, tmp_path / "broken.jsonl")
        finally:
            app.state.store.close()
    asyncio.run(scenario())


def test_undecodable_newest_message_does_not_block_the_start(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [])
        for entry in entries.values():
            entry["app"].state.collector.client = PoisonClient([message(i) for i in range(1, 8)], poison={7})
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            assert state["workers"][0]["high"] == 7, state
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            path = manager.result_path(state["id"])
            verify_chat_export(path, fingerprint(entries["account0"]["app"].state.vault.public_key))
            with zipfile.ZipFile(path) as archive:
                rows = {row["id"]: row for row in json.loads(archive.read("chat.json"))["messages"]}
                ids = json.loads(archive.read("message-ids.json"))
            assert set(rows) == set(range(1, 8)) and rows[7]["type"] == "unparsed", rows.get(7)
            assert ids["missing"] == 0
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


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


@pytest.mark.parametrize("download, capture_media, avatars, expected", [
    (False, True, True, False), (True, False, True, False),
    (True, True, False, False), (True, True, True, True),
])
def test_distributed_profile_photo_respects_export_and_capture_settings(
        tmp_path, monkeypatch, download, capture_media, avatars, expected):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)], count=1)
        c = entries["account0"]["app"].state.collector
        c.store.set_setting("capture", {"download_media": capture_media, "include_avatars": avatars})
        async def finish(self, directory, options):
            raise ValueError("Stop after acquisition for profile inspection")
        monkeypatch.setattr(distributed_export.Run, "finish_selection", finish)
        try:
            await manager.start(CHAT, ["account0"], "account0", selection={"download_media": download})
            await asyncio.wait_for(latest_run(manager).task, 10)
            c.chat_profile.assert_awaited_once()
            assert c.chat_profile.await_args.kwargs["include_photo"] is expected
            assert latest_run(manager).state["error"] == "Stop after acquisition for profile inspection"
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("terminal", ["done", "paused", "failed"])
def test_export_rate_includes_waits_but_excludes_reused_messages_and_packaging(monkeypatch, terminal):
    clock = [100.0]
    monkeypatch.setattr(export_timing, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    timer = export_timing.ExportTiming()
    assert timer.snapshot(200)["messages_per_second"] is None
    timer.baseline = 200
    clock[0] = 112.0
    timer.move("running")
    clock[0] = 132.0
    assert timer.snapshot(240)["messages_per_second"] == 2
    # A wait without new committed messages lowers the average.
    clock[0] = 142.0
    assert timer.snapshot(240)["messages_per_second"] == pytest.approx(40 / 30, abs=.001)
    timer.move("selecting")
    clock[0] = 150.0
    timer.move("packaging")
    clock[0] = 155.0
    timer.move(terminal)
    result = timer.snapshot(260)
    assert result["new_messages"] == 60 and result["reused_messages"] == 200
    assert result["messages_per_second"] == 2 and result["elapsed_seconds"] == 55
    assert result["phase_seconds"] == {"preparing": 12, "running": 30, "selecting": 8, "packaging": 5}
    clock[0] = 5000.0
    assert timer.snapshot(260) == result
    resumed = export_timing.ExportTiming()
    resumed.baseline = 260
    assert resumed.snapshot(260)["new_messages"] == resumed.snapshot(260)["elapsed_seconds"] == 0


def latest_run(manager):
    return manager.runs[next(reversed(manager.runs))]


def hold_launch(manager):
    manager.launch = lambda run: manager.runs.setdefault(run.state["id"], run)


def intercept_selection(manager, callback):
    launch = manager.launch
    def start(run):
        run.finish_selection = callback
        return launch(run)
    manager.launch = start


async def finished(manager, state, timeout=60):
    run = manager.runs[state["id"]]
    await asyncio.wait_for(run.task, timeout)
    return run.state


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
            assert latest_run(manager).state["phase"] == "paused" and c.export_claim is None
            paused_performance = manager.public()["performance"]
            await asyncio.sleep(.02)
            assert manager.public()["performance"] == paused_performance
            directory = manager.directory(state["id"])
            receipts = list((directory / "receipts").glob("*.json"))
            assert len(receipts) == 1
            preserved = json.loads(receipts[0].read_text())["statement"]
            first_bounds = (preserved["low"] - 1, preserved["high"] + 1)
            restored = distributed_export.DistributedExport(manager.profiles)
            assert restored.public()["phase"] == "paused"
            c.client.block = None
            c.client.reads.clear()
            async def finish(self, directory, options):
                assert first_bounds not in c.client.reads
                raise ValueError("Recovery reached selection")
            monkeypatch.setattr(distributed_export.Run, "finish_selection", finish)
            job = await finished(restored, await restored.resume(state["id"]), 10)
            assert job["error"] == "Recovery reached selection"
            performance = restored.public()["performance"]
            assert performance["reused_messages"] == 2 and performance["new_messages"] == 4
            assert len(list((directory / "receipts").glob("*.json"))) == 3
            chunk = directory / "chunks" / (str(preserved["low"]) + ".jsonl")
            chunk.write_text(chunk.read_text().replace("English", "tampered"))
            c.client.reads.clear()
            job = await finished(restored, await restored.resume(state["id"]), 5)
            assert "differs" in job["error"]
            assert restored.public()["performance"]["new_messages"] == 0
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
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            performance = manager.public()["performance"]
            assert performance["new_messages"] == 2 and performance["reused_messages"] == 0
            assert performance["phase_seconds"]["packaging"] > 0
            assert distributed_export.verified(manager.directory(state["id"]) / "status.json",
                                    entries["account0"]["app"].state.vault.public_key)["performance"] == performance
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


@pytest.mark.parametrize("inclusive", [False, True])
@pytest.mark.parametrize("microseconds", [0, 500000])
def test_date_selection_keeps_every_message_at_inclusive_start(tmp_path, inclusive, microseconds):
    async def scenario():
        boundary = datetime(2026, 10, 5, tzinfo=timezone.utc)
        rows = [message(i) for i in range(1, 8)]
        for row, seconds in zip(rows, (-2, -1, 0, 0, 0, 1, 2)):
            row.date = boundary + timedelta(seconds=seconds)

        class DateClient(Client):
            async def get_messages(self, entity, limit=None, offset_date=None, ids=None):
                if inclusive and offset_date is not None and ids is None:
                    return sorted([m for m in self.messages if m.date <= offset_date.replace(microsecond=0)],
                                  key=lambda m: -m.id)[:limit]
                return await super().get_messages(entity, limit, offset_date, ids)

        manager, entries = coordinator(tmp_path, rows, count=1)
        collector = entries["account0"]["app"].state.collector
        collector.client = DateClient(rows)
        # Exercise the signed plan, real chunk acquisition and local selection.
        # Bundle rendering and verification have their own integration check above.
        hold_launch(manager)
        options = Selection(from_utc=(boundary + timedelta(microseconds=microseconds)).isoformat(),
                            to_utc=(boundary + timedelta(seconds=2)).isoformat())
        try:
            state = await manager.start(CHAT, ["account0"], "account0", selection=options.model_dump())
            latest_run(manager).prepare_chunks()
            await latest_run(manager).work(latest_run(manager).state["workers"][0])
            scratch, _ = await latest_run(manager).finish_selection(manager.directory(state["id"]), options)
            selected = [json.loads(line)["id"] for line in scratch.read_text().splitlines()]
            assert selected == ([6, 5, 4, 3] if microseconds == 0 else [6])
        finally:
            if latest_run(manager).db:
                latest_run(manager).db.close()
                latest_run(manager).db = None
            if latest_run(manager).state:
                manager.release(latest_run(manager).state["id"])
            close_entries(entries)
    asyncio.run(scenario())


def test_cancelling_an_old_job_leaves_the_active_one_running(tmp_path):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)], count=1)
        collector = entries["account0"]["app"].state.collector
        try:
            old = await manager.start(CHAT, ["account0"], "account0")
            await manager.pause(old["id"])
            new = await manager.start(CHAT, ["account0"], "account0")
            old_performance = manager.public(old["id"])["performance"]
            assert (await manager.cancel(old["id"]))["phase"] == "cancelled"
            assert manager.runs[new["id"]].active() and collector.export_claim == new["id"]
            assert (await manager.pause(new["id"]))["phase"] == "paused" and collector.export_claim is None
            assert manager.public(old["id"])["phase"] == "cancelled" and len(manager.list_jobs()) == 2
            assert manager.public(old["id"])["performance"] == old_performance
            await asyncio.sleep(.02)
            assert manager.public(old["id"])["performance"] == old_performance
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
            with pytest.raises(ValueError, match="busy"):
                await manager.start(CHAT, list(entries), "account0")
            assert all(manager.uses(name) for name in entries)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert not manager.reserved and not manager.runs
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("interruption", ["failure", "pause", "repeated_pause", "failure_then_pause"])
def test_workers_finish_cleanup_before_accounts_are_released(tmp_path, monkeypatch, interruption):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(1)])
        entered, draining, release, stopped = (asyncio.Event() for _ in range(4))
        workers = []

        async def work(self, worker):
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

        monkeypatch.setattr(distributed_export.Run, "work", work)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            run = manager.runs[state["id"]]
            await asyncio.wait_for(entered.wait(), 5)
            if interruption in ("pause", "repeated_pause"):
                run.task.cancel()
            await asyncio.wait_for(draining.wait(), 5)
            assert run.active() and run.db is not None and not stopped.is_set()
            for entry in entries.values():
                collector = entry["app"].state.collector
                assert collector.export_claim == state["id"]
                assert not collector.reserve_export("competing-task")
            if interruption in ("repeated_pause", "failure_then_pause"):
                run.task.cancel()
                await asyncio.sleep(0)
                assert run.active() and not stopped.is_set()
            release.set()
            await asyncio.wait_for(asyncio.gather(run.task, return_exceptions=True), 5)
            assert stopped.is_set() and all(task.done() for task in workers)
            assert run.db is None and not run.active() and not manager.reserved
            assert run.state["phase"] == ("failed" if interruption == "failure" else "paused")
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


def test_unfiltered_archive_keeps_number_analysis_and_rechecks_gaps(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in (1, 2, 4, 6, 7)])
        for entry in entries.values():
            entry["app"].state.collector.client.by_number = {5: message(5)}
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            path = manager.result_path(state["id"])
            verify_chat_export(path, fingerprint(entries["account0"]["app"].state.vault.public_key))
            with zipfile.ZipFile(path) as archive:
                ids = json.loads(archive.read("message-ids.json"))
                result = json.loads(archive.read("chat.json"))
            assert not ids.get("selection_applied"), ids
            assert ids["recheck"]["asked"] == 2 and ids["recheck"]["returned"] == [5] and ids["recheck"]["empty"] == 1
            assert ids["missing"] == 1 and ids["missing_ranges"] == [[3, 3]], ids
            assert 5 in {row["id"] for row in result["messages"]}
            assert ids["recheck"]["unchecked"] == 0 and ids["recheck"]["accounts"] == 2
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_recheck_reads_below_the_oldest_listed_message_and_counts_unchecked(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in (4, 5, 7, 8)])
        for entry in entries.values():
            entry["app"].state.collector.client.by_number = {2: message(2)}
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export, "RECHECK_PER_ACCOUNT", 1)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            with zipfile.ZipFile(manager.result_path(state["id"])) as archive:
                recheck = json.loads(archive.read("message-ids.json"))["recheck"]
                ids = {row["id"] for row in json.loads(archive.read("chat.json"))["messages"]}
            assert recheck["edge"] == [1, 3] and recheck["edge_found"] == 1 and 2 in ids, recheck
            assert recheck["asked"] == 3 and recheck["unchecked"] == 1 and recheck["limit_reached"], recheck
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


class SilentClient(Client):
    def __init__(self, messages, silent):
        super().__init__(messages)
        self.silent = silent

    def is_connected(self):
        return True

    async def iter_messages(self, entity, offset_id=0, min_id=0):
        if self.silent:
            self.silent -= 1
            await asyncio.Event().wait()
        async for m in super().iter_messages(entity, offset_id=offset_id, min_id=min_id):
            yield m


class BrokenRangeClient(Client):
    def __init__(self, messages, broken):
        super().__init__(messages)
        self.broken = broken

    async def iter_messages(self, entity, offset_id=0, min_id=0):
        if min_id < self.broken < offset_id:
            raise ValueError("Telegram returned an unusable answer")
        async for m in super().iter_messages(entity, offset_id=offset_id, min_id=min_id):
            yield m


def test_silent_account_returns_its_range_and_comes_back(tmp_path, monkeypatch):
    async def scenario():
        rows = [message(i) for i in range(1, 9)]
        manager, entries = coordinator(tmp_path, rows)
        entries["account1"]["app"].state.collector.client = SilentClient(rows, silent=2)
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export, "PAGE_TIMEOUT", 0.2)
        monkeypatch.setattr(distributed_export, "OUTAGE_PAUSE", 0.05)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            assert all(w["state"] == "done" for w in job["workers"]), job["workers"]
            with zipfile.ZipFile(manager.result_path(state["id"])) as archive:
                assert {row["id"] for row in json.loads(archive.read("chat.json"))["messages"]} == set(range(1, 9))
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_range_failing_on_two_accounts_stops_without_losing_accounts(tmp_path, monkeypatch):
    async def scenario():
        rows = [message(i) for i in range(1, 9)]
        manager, entries = coordinator(tmp_path, rows, count=3)
        for entry in entries.values():
            entry["app"].state.collector.client = BrokenRangeClient(rows, broken=3)
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        try:
            job = await finished(manager, await manager.start(CHAT, list(entries), "account0"))
            assert job["phase"] == "failed", job
            assert "3–4" in job["error"] and "unusable answer" in job["error"], job["error"]
            assert all(w["state"] == "done" for w in job["workers"]), job["workers"]
            assert job["ranges_done"] == 3
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_export_names_deletions_kept_in_the_journal(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in (1, 2, 3)])
        store = entries["account0"]["app"].state.store
        store.append("message.deleted", {"message_id": 4, "text": "Removed after it was observed."}, CHAT)
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0")
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            with zipfile.ZipFile(manager.result_path(state["id"])) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                header = json.loads(archive.read("chat.json"))
            assert manifest["journal"]["deleted"] == 1 and header["journal"]["deleted"] == 1
            assert chat_export.JOURNAL_LIMIT in manifest["limitations"]
            assert not any("cannot be recovered and are not present" in line for line in manifest["limitations"])
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_compare_finds_removed_and_edited_messages(tmp_path, monkeypatch):
    async def export(path, rows, lead):
        path.mkdir()
        manager, entries = coordinator(path, rows)
        try:
            state = await manager.start(CHAT, [lead], lead)
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            return manager.result_path(state["id"]), entries[lead]["app"].state.vault.public_key
        finally:
            await manager.close()
            close_entries(entries)

    async def scenario():
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        before = [message(i) for i in range(1, 6)]
        after = [message(1), message(2), message(4, "Rewritten after the fact."), message(5)]
        first, key = await export(tmp_path / "t1", before, "account0")
        second, _ = await export(tmp_path / "t2", after, "account0")
        result = verify.compare_chat_exports(first, second, fingerprint(key))
        assert result["method"] == "number" and result["first"]["key_pinned"], result
        assert [row["id"] for row in result["only_first"]] == [3] and not result["only_second"]
        assert [(c["first"]["id"], c["second"]["text"]) for c in result["changed"]] == [(4, "Rewritten after the fact.")]
        assert result["unchanged"] == 3
        shifted = [message(1), message(2), message(4, "Rewritten after the fact."), message(5)]
        for row in shifted:
            row.date += timedelta(seconds=1)
        other_side = verify.compare_chat_exports(second, (await export(tmp_path / "t3", shifted, "account1"))[0])
        assert other_side["method"] == "content" and not other_side["only_first"] and not other_side["only_second"]
    asyncio.run(scenario())


def test_full_recheck_reads_every_absent_number(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in (1, 2, 5, 9)])
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export, "RECHECK_PER_ACCOUNT", 1)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0", selection={"recheck_all": True})
            job = await finished(manager, state)
            assert job["phase"] == "done", job
            with zipfile.ZipFile(manager.result_path(state["id"])) as archive:
                ids = json.loads(archive.read("message-ids.json"))
            assert ids["recheck"]["asked"] == 5 and ids["recheck"]["unchecked"] == 0, ids["recheck"]
            assert not ids.get("selection_applied")
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


class TakeoutClient(Client):
    def __init__(self, messages, account_id):
        super().__init__(messages)
        self.requests = []
        self.account_id = account_id

    async def get_input_entity(self, entity):
        return entity if isinstance(entity, types.InputUserSelf) else types.InputPeerChannel(entity.id, 1)

    async def __call__(self, request, ordered=False):
        self.requests.append(request)
        while hasattr(request, "query"):
            request = request.query
        if type(request).__name__ == "GetUsersRequest":
            return [types.User(self.account_id, is_self=True)]
        if type(request).__name__ == "GetSplitRangesRequest":
            return [types.MessageRange(0, 2147483647)]
        if isinstance(request, account_functions.InitTakeoutSessionRequest):
            return types.account.Takeout(id=77)
        return True


def test_ranges_are_read_through_a_takeout_session(tmp_path, monkeypatch):
    async def scenario():
        rows = [message(i) for i in range(1, 7)]
        manager, entries = coordinator(tmp_path, rows)
        for entry in entries.values():
            collector = entry["app"].state.collector
            collector.client = TakeoutClient(rows, collector.store.get_setting("account")["id"])
            collector.resolve_for_export.return_value.username = "synthetic"
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            job = await finished(manager, await manager.start(CHAT, list(entries), "account0", transport="takeout"))
            assert job["phase"] == "done", job
            for entry in entries.values():
                client = entry["app"].state.collector.client
                kinds = [type(r).__name__ for r in client.requests]
                assert kinds.count("InitTakeoutSessionRequest") == 1 and "InvokeWithTakeoutRequest" in kinds, kinds
                finish = [r for r in client.requests if type(r).__name__ == "InvokeWithTakeoutRequest"]
                assert finish[-1].takeout_id == 77 and type(finish[-1].query).__name__ == "FinishTakeoutSessionRequest"
                assert client.iter_options and all(o == {"wait_time": 0} for o in client.iter_options)
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_ten_accounts_cover_chunks_once(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 21)], count=10)
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        async def finish(self, directory, options):
            assert self.state["ranges_done"] == 10 and self.state["captured"] == 20
            ranges = [bounds for entry in entries.values() for bounds in entry["app"].state.collector.client.reads]
            assert len(ranges) == len(set(ranges)) == 10
            assert all(entry["app"].state.collector.client.reads for entry in entries.values())
            raise ValueError("Ten-account acquisition checked")
        monkeypatch.setattr(distributed_export.Run, "finish_selection", finish)
        try:
            job = await finished(manager, await manager.start(CHAT, list(entries), "account0"), 10)
            assert job["error"] == "Ten-account acquisition checked", job
            assert all(entry["app"].state.collector.export_claim is None for entry in entries.values())
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
