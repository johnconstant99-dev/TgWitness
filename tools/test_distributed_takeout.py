import asyncio
import copy
import json
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest
from telethon import TelegramClient, errors, utils
from telethon.sessions import MemorySession
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.test_distributed_export import CHAT, close_entries, coordinator, message
from tgwitness import distributed_export
from tgwitness.distributed_takeout import HistoryTakeout
from tgwitness.verify import fingerprint, verify_chat_export


class Client(TelegramClient):
    def __init__(self, rows, account_id):
        super().__init__(MemorySession(), 123456, "f" * 32)
        self.rows, self.account_id = rows, account_id
        self.requests, self.iterator_waits = [], []
        self.delay, self.invalid, self.inits = 0, False, 0
        self.block_after, self.history_requests = None, 0
        self.flood_type = None
        self.blocked = asyncio.Event()
        self.ranges = [t.MessageRange(0, 10), t.MessageRange(10, 2147483647)]
        self.handle = 424242424242
        self.peer = t.Channel(42, "Synthetic public group", t.ChatPhotoEmpty(),
                              datetime.now(timezone.utc), megagroup=True, access_hash=1, username="synthetic")

    async def get_input_entity(self, entity):
        return entity if isinstance(entity, (t.InputPeerChannel, t.InputUserSelf)) else utils.get_input_peer(entity)

    def iter_messages(self, *args, **kwargs):
        self.iterator_waits.append(kwargs.get("wait_time"))
        return TelegramClient.iter_messages(self, *args, **kwargs)

    async def __call__(self, request, *args, **kwargs):
        wrappers = []
        while isinstance(request, (f.InvokeWithTakeoutRequest, f.InvokeWithMessagesRangeRequest)):
            wrappers.append(request)
            request = request.query
        self.requests.append((copy.deepcopy(request), copy.deepcopy(wrappers)))
        if wrappers and self.invalid:
            raise errors.TakeoutInvalidError(request)
        if isinstance(request, f.users.GetUsersRequest):
            return [t.User(self.account_id, first_name="Fixture", is_self=True)]
        if isinstance(request, f.account.InitTakeoutSessionRequest):
            if self.delay:
                raise errors.TakeoutInitDelayError(request, capture=self.delay)
            self.inits += 1
            return t.account.Takeout(self.handle)
        if isinstance(request, f.messages.GetSplitRangesRequest):
            return self.ranges
        if isinstance(request, f.account.FinishTakeoutSessionRequest):
            return True
        if isinstance(request, f.updates.GetStateRequest):
            return t.updates.State(0, 0, datetime.now(timezone.utc), 0, 0)
        if isinstance(request, f.messages.GetHistoryRequest):
            if wrappers:
                self.history_requests += 1
                if self.history_requests == 2 and self.flood_type:
                    raise self.flood_type(request, capture=60)
                if self.block_after is not None and self.history_requests > self.block_after:
                    self.blocked.set()
                    await asyncio.Event().wait()
            rows = sorted([m for m in self.rows if (not request.offset_id or m.id < request.offset_id)
                and (request.offset_id or not request.offset_date or m.date < request.offset_date)
                and (not request.min_id or m.id > request.min_id)
                and (not request.max_id or m.id < request.max_id)], key=lambda m: -m.id)
            return t.messages.ChannelMessages(0, len(self.rows), rows[:request.limit], [], [self.peer], [])
        raise AssertionError(type(request).__name__)


def setup(tmp_path, rows, count=1):
    manager, entries = coordinator(tmp_path, rows, count=count)
    for entry in entries.values():
        collector = entry["app"].state.collector
        collector.client = Client(rows, collector.store.get_setting("account")["id"])
        collector.resolve_for_export.return_value = collector.client.peer
    return manager, entries


def transport(collector, name="a" * 32):
    return HistoryTakeout(collector, name, collector.store.get_setting("account")["id"], True)


def test_takeout_private_lifecycle_reuse_and_range_validation(tmp_path):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)])
        c = entries["account0"]["app"].state.collector
        try:
            first = transport(c)
            await first.open()
            init = next(r for r, _ in c.client.requests if isinstance(r, f.account.InitTakeoutSessionRequest))
            assert init.message_megagroups and not init.message_channels and not init.files and not init.contacts
            assert first.client._export_range == {"min_id": 10, "max_id": 2147483647}
            second = transport(c)
            await second.open()
            assert c.client.inits == 1
            assert second.public()["generations"][0]["last_reused_at"]
            assert str(c.client.handle) not in json.dumps(list(c.store.events()))
            c.store.verify(c.vault.public_key)
            c.client.ranges = [t.MessageRange(99, 2147483647)]
            with pytest.raises(ValueError, match="range changed"):
                await transport(c).open()
            c.client.ranges = [t.MessageRange(10, 2147483647)]
            await second.finish()
            assert "takeout_id" not in c.vault.read(second.name)
            assert second.public()["generations"][0]["closed_at"]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_invalid_takeout_requires_explicit_retry_and_account_binding(tmp_path):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)])
        c = entries["account0"]["app"].state.collector
        try:
            await transport(c).open()
            c.client.invalid = True
            with pytest.raises(errors.TakeoutInvalidError):
                await transport(c).open()
            assert c.client.inits == 1
            assert "takeout_id" not in c.vault.read(transport(c).name)
            c.client.invalid = False
            renewed = transport(c)
            await renewed.open()
            assert c.client.inits == 2 and len(renewed.public()["generations"]) == 2
            c.client.account_id += 1
            with pytest.raises(ValueError, match="signed account"):
                await transport(c).open()
            assert c.client.inits == 2
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_takeout_delay_pauses_without_regular_fallback(tmp_path):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)])
        c = entries["account0"]["app"].state.collector
        c.client.delay = 3600
        try:
            await manager.start(CHAT, ["account0"], "account0", transport="takeout")
            await manager.task
            assert manager.state["phase"] == "paused" and manager.state["captured"] == 0
            assert manager.state["wait_until"] and "approval" in manager.state["error"]
            assert c.export_claim is None
            # The only history read was the regular preflight upper boundary.
            assert sum(isinstance(r, f.messages.GetHistoryRequest) for r, _ in c.client.requests) == 1
            assert not list((manager.directory(manager.state["id"]) / "receipts").iterdir())
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_real_telethon_iterator_removes_only_takeout_sleep(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = setup(tmp_path, [message(i) for i in range(1, 202)])
        c = entries["account0"]["app"].state.collector
        pauses, ordinary, fast = [], [], []
        original_sleep = asyncio.sleep
        async def sleep(seconds):
            if seconds > 0:
                pauses.append(seconds)
            await original_sleep(0)
        async def save_ordinary(m):
            ordinary.append(m.id)
        async def save_fast(m):
            fast.append(m.id)
        monkeypatch.setattr(asyncio, "sleep", sleep)
        try:
            await c.iterate_history(c.client.peer, save_ordinary, offset_id=202)
            assert len(pauses) >= 2 and sum(pauses) > 1.8
            pauses.clear()
            network = transport(c)
            await network.open()
            await c.iterate_history(c.client.peer, save_fast, offset_id=202, history_client=network.client)
            assert fast == ordinary == list(range(201, 0, -1))
            assert not pauses and c.client.iterator_waits[-1] == 0
            history = [(r, w) for r, w in c.client.requests if isinstance(r, f.messages.GetHistoryRequest) and w]
            assert len(history) == 3
            assert all([type(x) for x in w] == [f.InvokeWithTakeoutRequest, f.InvokeWithMessagesRangeRequest] for _, w in history)
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("transport_kind", ["regular", "takeout"])
def test_sparse_plan_reduces_requests_without_omitting_ids(tmp_path, transport_kind):
    async def scenario():
        rows = [message(i) for i in (1, 200001, 400001, 500000)]
        manager, entries = setup(tmp_path, rows)
        manager.launch = lambda: None
        c = entries["account0"]["app"].state.collector
        try:
            state = await manager.start(CHAT, ["account0"], "account0", transport=transport_kind)
            assert state["ranges_total"] == 5  # Previously 250 fixed 2,000-ID tasks.
            assert manager.job["segments"] == [{"low": 1, "high": 500000, "profiles": ["account0"]}]
            manager.prepare_chunks()
            if transport_kind == "takeout":
                network = transport(c, state["id"])
                await network.open()
                manager.history_transports["account0"] = network
            await manager.work(state["workers"][0])
            assert manager.state["captured"] == 4 and manager.state["ranges_done"] == 5
            directory = manager.directory(state["id"])
            saved = [json.loads(line)["id"] for path in (directory / "chunks").glob("*.jsonl")
                     for line in path.read_text().splitlines()]
            assert sorted(saved) == [m.id for m in rows]
            receipts = list((directory / "receipts").glob("*.json"))
            for path in receipts:
                signed = manager.verified(path, c.vault.public_key)
                if transport_kind == "takeout":
                    assert signed["transport"] == "takeout" and signed["transport_generation"] == 1
                else:
                    assert "transport" not in signed
            history = [(r, w) for r, w in c.client.requests if isinstance(r, f.messages.GetHistoryRequest)]
            assert len(history) == 6  # One boundary lookup plus five complete ID ranges.
            assert all(bool(w) == (transport_kind == "takeout") for _, w in history[1:])
            assert str(c.client.handle) not in (directory / "status.json").read_text()
        finally:
            if manager.db:
                manager.db.close()
                manager.db = None
            if manager.state:
                manager.release(manager.state["id"])
            close_entries(entries)
    asyncio.run(scenario())


def test_takeout_archive_keeps_signatures_and_private_handles(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1), message(2)], count=2)
        monkeypatch.setattr(distributed_export, "CHUNK", 1)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *a: None)
        try:
            state = await manager.start(CHAT, list(entries), "account0", transport="takeout")
            await asyncio.wait_for(manager.task, 60)
            assert manager.state["phase"] == "done", manager.state
            path = manager.result_path(state["id"])
            key = entries["account0"]["app"].state.vault.public_key
            assert verify_chat_export(path, fingerprint(key))["message_count"] == 2
            with zipfile.ZipFile(path) as archive:
                result = json.loads(archive.read("manifest.json"))
                assert result["collection"]["history_transport"] == "takeout"
                assert json.loads(archive.read("chat.json"))["acquisition"]["history_transports"]
                for name in archive.namelist():
                    assert b"424242424242" not in archive.read(name)
            for entry in entries.values():
                c = entry["app"].state.collector
                assert c.export_claim is None
                assert "takeout_id" not in c.vault.read("distributed-takeout-" + state["id"])
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_takeout_pause_resume_reuses_signed_chunks_and_handle(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = setup(tmp_path, [message(i) for i in range(1, 7)])
        c = entries["account0"]["app"].state.collector
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        c.client.block_after = 1
        try:
            state = await manager.start(CHAT, ["account0"], "account0", transport="takeout")
            await asyncio.wait_for(c.client.blocked.wait(), 5)
            await manager.pause(state["id"])
            directory = manager.directory(state["id"])
            receipt = next((directory / "receipts").glob("*.json"))
            saved = receipt.read_bytes()
            assert manager.state["captured"] == 2 and c.export_claim is None
            c.client.block_after = None
            restored = distributed_export.DistributedExport(manager.profiles)
            async def finish(*args):
                assert restored.state["captured"] == 6
                raise ValueError("Acquisition recovery checked")
            restored.finish_selection = finish
            await restored.resume(state["id"])
            await asyncio.wait_for(restored.task, 5)
            assert restored.state["error"] == "Acquisition recovery checked"
            assert receipt.read_bytes() == saved and c.client.inits == 1
            assert restored.state["performance"]["reused_messages"] == 2
            assert restored.state["performance"]["new_messages"] == 4
            assert c.export_claim is None
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("public", [False, True])
def test_takeout_rejects_unsupported_source_or_transport(tmp_path, public):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)])
        c = entries["account0"]["app"].state.collector
        if not public:
            c.client.peer.username = None
        try:
            with pytest.raises(ValueError, match="Unknown|public channels"):
                await manager.start(CHAT, ["account0"], "account0", transport="unknown" if public else "takeout")
            assert not c.client.inits and c.export_claim is None
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("error_type", [errors.FloodWaitError, errors.FloodPremiumWaitError])
def test_takeout_flood_resume_keeps_cursor_and_transport(tmp_path, monkeypatch, error_type):
    async def scenario():
        manager, entries = setup(tmp_path, [message(i) for i in range(1, 202)])
        c = entries["account0"]["app"].state.collector
        c.client.flood_type = error_type
        saved, waits = [], []
        async def save(m):
            saved.append(m.id)
        original_sleep = asyncio.sleep
        async def sleep(seconds):
            waits.append(seconds)
            await original_sleep(0)
        monkeypatch.setattr(asyncio, "sleep", sleep)
        try:
            network = transport(c)
            await network.open()
            await c.iterate_history(c.client.peer, save, offset_id=202, history_client=network.client)
            assert saved == list(range(201, 0, -1))
            assert waits == [61] and c.store.get_setting("rpc_backoff_until") > 0
            assert c.client.iterator_waits == [0, 0]
            history = [(r, w) for r, w in c.client.requests if isinstance(r, f.messages.GetHistoryRequest)]
            assert all(w for _, w in history)
            assert history[1][0].offset_id == history[2][0].offset_id == 102
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_pending_rate_limit_rejects_export_before_any_preflight(tmp_path):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)], count=2)
        entries["account1"]["app"].state.store.set_setting("rpc_backoff_until", time.time() + 3600)
        try:
            with pytest.raises(ValueError, match="account1.*paused"):
                await manager.start(CHAT, list(entries), "account0", transport="takeout")
            for entry in entries.values():
                c = entry["app"].state.collector
                assert c.export_claim is None and not c.client.requests
                c.resolve_for_export.assert_not_awaited()
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
