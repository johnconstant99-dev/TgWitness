"""Synthetic backfill fault tests: no credentials, live Telegram or notifications."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest
from telethon import TelegramClient, errors
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.browser_fixtures import CHAT, media_message, telegram_message
from tgwitness import history, history_cursor
from tgwitness.collector import Collector
from tgwitness.history_options import HistoryOptions
from tgwitness.rpc_pacing import AccountPacer, bulk_request
from tgwitness.security import Vault
from tgwitness.store import Store, utcnow
from tgwitness.telegram_client import WitnessClient


class Client:
    def __init__(self, rows):
        self.rows, self.reads, self.rpc = rows, [], []
        self.hold, self.entered = asyncio.Event(), asyncio.Event()
        self.block_media = False
        self.block_offset = None
        self.failure = None
        self.ranges = []
        self.actions = []
        self.admin_error = None
        self.takeout_error = None

    async def get_me(self):
        return NS(id=44)

    async def get_input_entity(self, value):
        return t.InputPeerChannel(123, 456)

    async def iter_dialogs(self, **kwargs):
        yield NS(id=CHAT)

    async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
        split = getattr(self, "_export_range", None)
        self.reads.append((offset_id, split, getattr(self, "_export_takeout", None)))
        if self.block_offset is not None and offset_id >= self.block_offset:
            self.entered.set()
            await self.hold.wait()
        if self.failure:
            raise self.failure
        rows = [m for m in self.rows if not offset_id or m.id < offset_id]
        if split:
            rows = [m for m in rows if split["min_id"] <= m.id <= split["max_id"]]
        return rows[:limit]

    async def download_media(self, media, file, progress_callback, *, thumb=None):
        self.rpc.append(("media", getattr(self, "_export_takeout", None)))
        self.entered.set()
        if self.block_media:
            await self.hold.wait()
        await progress_callback(4, 4)
        file.write(b"data")
        return file

    async def __call__(self, request, **kwargs):
        self.rpc.append(request)
        if isinstance(request, f.InvokeWithTakeoutRequest):
            request = request.query
        if isinstance(request, f.account.InitTakeoutSessionRequest):
            if self.takeout_error:
                raise self.takeout_error
            return NS(id=999)
        if isinstance(request, f.messages.GetSplitRangesRequest):
            return [t.MessageRange(**r) for r in self.ranges]
        if isinstance(request, f.account.FinishTakeoutSessionRequest):
            return True
        if isinstance(request, f.channels.GetAdminLogRequest):
            if self.admin_error:
                raise self.admin_error
            rows = [e for e in self.actions if (not request.max_id or e.id < request.max_id) and e.id > request.min_id]
            return NS(events=rows[:1])  # Short pages still require a terminal empty response.
        raise AssertionError(type(request))


def make(root, rows=()):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    store.set_setting("account", {"id": 44})
    store.set_target(CHAT, "Synthetic group", "supergroup", True)
    collector = Collector(store, vault)
    collector.client = Client(list(rows))
    collector.restore = AsyncMock()
    collector.resolve_target = AsyncMock(return_value=t.Channel(id=123, title="Synthetic", photo=t.ChatPhotoEmpty(),
        date=datetime.now(timezone.utc), megagroup=True, access_hash=456))
    return collector, store


async def finished(h):
    await asyncio.wait_for(h.task, 10)
    return h.status()


def test_text_finishes_while_media_waits_then_resume_uses_durable_queue(tmp_path):
    async def run():
        c, store = make(tmp_path, [media_message(3), telegram_message(2), telegram_message(1)])
        c.client.block_media = True
        h = c.history
        try:
            await h.start(HistoryOptions(admin_log=False))
            await asyncio.wait_for(c.client.entered.wait(), 5)
            for _ in range(500):
                if h.status()["sources_by_phase"].get("complete"):
                    break
                await asyncio.sleep(.01)
            assert h.status()["captured"] == 3 and not h.task.done()
            assert store.media_stats().get("running") == 1
            await h.pause()
            assert store.media_stats().get("retry") == 1
            before = len(c.client.reads)
            store.append("independent.test", {"note": "unrelated global tail is valid"})
            # Projection deletion is repaired from signed observations on resume.
            store.db.execute("DELETE FROM history_items")
            c.client.hold.set()
            await h.resume()
            state = await finished(h)
            assert state["phase"] == "complete" and state["media"]["done"] == 1
            assert len(c.client.reads) == before
            assert len(store.events(kind="message.snapshot")) == 3
            history_cursor.verify(store, c.vault, h.current())
        finally:
            await h.pause()
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("mutation", ["offset_id=1", "metadata='{}'", "captured=800", "cursor_seq=1"])
def test_resume_rejects_mutable_cursor_tampering_before_network(tmp_path, mutation):
    async def run():
        c, store = make(tmp_path, [telegram_message(3), telegram_message(2)])
        c.client.block_offset = 1
        try:
            await c.history.start(HistoryOptions(admin_log=False))
            await asyncio.wait_for(c.client.entered.wait(), 5)
            await c.history.pause()
            store.db.execute("UPDATE history_sources SET " + mutation)
            c.restore.reset_mock()
            with pytest.raises(ValueError, match="cursor"):
                await c.history.resume()
            c.restore.assert_not_awaited()
            assert c.export_claim is None
        finally:
            store.close()
    asyncio.run(run())


def test_atomic_message_cursor_and_media_rollback(tmp_path, monkeypatch):
    async def run():
        c, store = make(tmp_path, [media_message(3)])
        real = history_cursor.seal
        def fail_after_message(store, run_id, cid):
            if store.events(kind="message.snapshot"):
                raise OSError("simulated storage interruption")
            return real(store, run_id, cid)
        monkeypatch.setattr(history_cursor, "seal", fail_after_message)
        try:
            await c.history.start(HistoryOptions(admin_log=False))
            assert (await finished(c.history))["phase"] == "paused"
            assert not store.events(kind="message.snapshot")
            assert not store.media_stats()
            assert c.history.source(c.history.current()["id"])["offset_id"] == 0
            monkeypatch.setattr(history_cursor, "seal", real)
            await c.history.resume()
            assert (await finished(c.history))["captured"] == 1
        finally:
            store.close()
    asyncio.run(run())


def test_changed_observation_is_not_a_fabricated_edit_or_deletion(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(8, "new")])
        try:
            await c.capture_message(telegram_message(8, "old"), "message.new", CHAT)
            await c.capture_message(telegram_message(7, "missing from new read"), "message.new", CHAT)
            await c.history.start(HistoryOptions(admin_log=False))
            assert (await finished(c.history))["phase"] == "complete"
            change = store.events(kind="history.content.changed")[0]
            assert change["message_id"] == 8
            assert not store.events(kind="message.edited") and not store.events(kind="message.deleted")
        finally:
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("takeout", [False, True])
def test_admin_log_retains_historical_versions_without_overwriting_chat(tmp_path, takeout):
    async def run():
        c, store = make(tmp_path, [telegram_message(4, "current")])
        now = datetime.now(timezone.utc)
        c.client.actions = [t.ChannelAdminLogEvent(20, now, 44, t.ChannelAdminLogEventActionEditMessage(
            media_message(4), telegram_message(4, "previous edit"))),
            t.ChannelAdminLogEvent(19, now, 44, t.ChannelAdminLogEventActionDeleteMessage(telegram_message(2, "deleted")))]
        try:
            await c.history.start(HistoryOptions(transport="takeout" if takeout else "standard"))
            state = await finished(c.history)
            assert state["phase"] == "complete", state
            assert state["captured"] == 1 and state["media"]["done"] == 1
            assert len(store.events(kind="history.admin_log.observed")) == 2
            assert store.message_state(CHAT, 4)["content"]["text"] == "current"
            assert not store.events(kind="message.deleted")
            meta = state["sources"][0]["metadata"]
            assert meta["admin_before"]["observed"] == 2 and meta["admin_after"]["observed"] == 0
            history_cursor.verify(store, c.vault, c.history.current())
        finally:
            store.close()
    asyncio.run(run())


def test_admin_rights_denied_is_reported_as_gap_not_empty_success(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(3)])
        c.client.admin_error = errors.ChatAdminRequiredError(None)
        try:
            await c.history.start()
            state = await finished(c.history)
            assert state["phase"] == "incomplete" and state["captured"] == 1
            assert state["sources"][0]["metadata"]["admin_before"]["status"] == "unavailable"
        finally:
            store.close()
    asyncio.run(run())


def test_takeout_ranges_wrap_files_and_finalize_only_after_drain(tmp_path):
    async def run():
        c, store = make(tmp_path, [media_message(5), telegram_message(4), telegram_message(2), telegram_message(1)])
        c.client.ranges = [{"min_id": 1, "max_id": 2}, {"min_id": 3, "max_id": 5}]
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "complete" and state["captured"] == 4, state
            assert [m["message_id"] for m in store.events(kind="message.snapshot")] == [4, 5, 1, 2]
            assert all(takeout == 999 for _, _, takeout in c.client.reads)
            assert ("media", 999) in c.client.rpc
            finish = [r.query for r in c.client.rpc if isinstance(r, f.InvokeWithTakeoutRequest)
                      and isinstance(r.query, f.account.FinishTakeoutSessionRequest)]
            assert len(finish) == 1 and finish[0].success
            assert "takeout_id" not in c.vault.read("account-export-history-" + state["id"])
        finally:
            store.close()
    asyncio.run(run())


def test_takeout_approval_does_not_destroy_login_or_start_history(tmp_path):
    async def run():
        c, store = make(tmp_path)
        c.vault.save("credentials", {"session": "synthetic-preserved"})
        c.client.takeout_error = errors.TakeoutInitDelayError(None, capture=3600)
        try:
            await c.history.start(HistoryOptions(transport="takeout"))
            state = await finished(c.history)
            assert state["phase"] == "paused" and state["reason"] == "takeout_approval_wait"
            assert not c.client.reads
            assert c.vault.read("credentials")["session"] == "synthetic-preserved"
            await c.history.cancel()
            assert c.history.status()["phase"] == "cancelled"
            assert not any(isinstance(r, f.InvokeWithTakeoutRequest) for r in c.client.rpc)
        finally:
            store.close()
    asyncio.run(run())


def test_expired_takeout_resumes_without_skipping_or_switching_account(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(3), telegram_message(2)])
        c.client.failure = errors.TakeoutInvalidError(None)
        c.vault.save("credentials", {"session": "preserved"})
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "paused", state
            assert "takeout_id" not in c.vault.read("account-export-history-" + state["id"])
            assert c.vault.read("credentials")["session"] == "preserved"
            c.client.failure = None
            await c.history.resume()
            state = await finished(c.history)
            assert state["phase"] == "complete" and state["captured"] == 2, state
        finally:
            store.close()
    asyncio.run(run())


def test_changed_takeout_ranges_fail_closed(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(3)])
        c.client.block_offset = 1
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            await asyncio.wait_for(c.client.entered.wait(), 5)
            await c.history.pause()
            before = len(c.client.reads)
            c.client.ranges = [{"min_id": 1, "max_id": 10}]
            await c.history.resume()
            assert (await finished(c.history))["phase"] == "paused"
            assert len(c.client.reads) == before
        finally:
            store.close()
    asyncio.run(run())


def test_pacer_floors_account_isolation_and_takeout_recognition(tmp_path):
    async def run():
        c, store = make(tmp_path)
        sleeps, now = [], [10.]
        async def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds
        p = AccountPacer(store, clock=lambda: now[0], sleep=sleep)
        try:
            await p.before()
            await p.before()
            assert sleeps == [1.]
            p.flooded(61)
            assert p.state()["delay_seconds"] == 6.
            for _ in range(1000):
                p.success()
            assert p.state()["delay_seconds"] == .5
            store.set_setting("account", {"id": 45})
            assert p.state()["delay_seconds"] == 1. and p.state()["floodwait_count"] == 0
            request = f.InvokeWithTakeoutRequest(99, f.InvokeWithMessagesRangeRequest(t.MessageRange(1, 9),
                f.messages.GetHistoryRequest(t.InputPeerSelf(), 0, None, 0, 100, 0, 0, 0)))
            assert bulk_request(request)
        finally:
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("rpc", [
    f.messages.GetMessagesRequest([t.InputMessageID(1)]),
    f.channels.GetMessagesRequest(t.InputChannel(42, 1), [t.InputMessageID(1)]),
    f.channels.GetParticipantsRequest(t.InputChannel(42, 1), t.ChannelParticipantsRecent(), 0, 200, 0),
])
def test_id_rechecks_and_participants_share_the_bulk_pacer(tmp_path, monkeypatch, rpc):
    async def run():
        c, store = make(tmp_path)
        now, sleeps, sent = [10.], [], []
        async def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds
        async def underlying(self, sender, query, *args):
            sent.append(now[0])
            return "ok"
        client = WitnessClient(None, 123, "a" * 32)
        client.bulk_pacer = AccountPacer(store, clock=lambda: now[0], sleep=sleep)
        monkeypatch.setattr(TelegramClient, "_call", underlying)
        try:
            wrapped = f.InvokeWithTakeoutRequest(99, rpc)
            assert bulk_request(rpc) and bulk_request(wrapped)
            await client._call(None, rpc)
            await client._call(None, wrapped)
            assert sent == [10., 11.] and sleeps == [1.]
            assert client.bulk_pacer.state()["success_streak"] == 2
        finally:
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("media", [False, True])
def test_concurrent_rpc_waiters_share_pacing_and_server_cooldown(tmp_path, monkeypatch, media):
    async def run():
        c, store = make(tmp_path)
        client = WitnessClient(None, 123, "a" * 32)
        client.bulk_pacer = AccountPacer(store)
        client.rpc_backoff_getter = lambda: store.get_setting("rpc_backoff_until", 0)
        client.rpc_backoff_setter = lambda value: store.set_setting("rpc_backoff_until", value)
        calls = []
        async def underlying(self, sender, request, *args):
            import time
            calls.append(time.time())
            if len(calls) == 1:
                raise errors.FloodWaitError(None, capture=0)
            return "ok"
        monkeypatch.setattr(TelegramClient, "_call", underlying)
        request = f.messages.GetHistoryRequest(t.InputPeerSelf(), 0, None, 0, 100, 0, 0, 0)
        following = f.upload.GetFileRequest(t.InputDocumentFileLocation(1, 2, b"synthetic", ""), 0, 4096) if media else request
        try:
            result = await asyncio.gather(client._call(None, request), client._call(None, following), return_exceptions=True)
            assert isinstance(result[0], errors.FloodWaitError) and result[1] == "ok"
            assert calls[1] - calls[0] >= 1.
            assert client.bulk_pacer.state()["floodwait_count"] == 1
            assert client.bulk_pacer.state()["success_streak"] == (0 if media else 1)
        finally:
            store.close()
    asyncio.run(run())


def test_network_retry_exhaustion_pauses_without_claiming_eof(tmp_path, monkeypatch):
    async def run():
        c, store = make(tmp_path)
        c.client.failure = OSError("synthetic network loss")
        real_sleep = asyncio.sleep
        async def no_backoff(seconds):
            await real_sleep(0)
        monkeypatch.setattr(history.asyncio, "sleep", no_backoff)
        try:
            await c.history.start(HistoryOptions(admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "paused" and len(c.client.reads) == 5
            assert state["sources_by_phase"] == {"queued": 1}
            assert not store.events(kind="history.source.complete")
            assert len(store.events(kind="history.retry")) == 5
        finally:
            store.close()
    asyncio.run(run())


def test_legacy_cursor_is_reconstructed_from_signed_observations(tmp_path):
    async def run():
        c, store = make(tmp_path)
        try:
            now = utcnow()
            store.db.execute("INSERT INTO history_runs(id,account_id,phase,created_at,updated_at) VALUES (?,?,?,?,?)",
                             ("legacy", 44, "paused", now, now))
            store.db.execute("INSERT INTO history_sources(run_id,chat_id,title,position,offset_id,captured) VALUES (?,?,?,?,?,?)",
                             ("legacy", CHAT, "Legacy source", 0, 1, 999))
            store.append("history.started", {"history_run_id": "legacy", "account_id": 44, "sources": [CHAT]})
            store.append("history.source.started", {"history_run_id": "legacy", "upper_message_id": 50}, CHAT)
            await c.capture_message(telegram_message(50), "message.snapshot", CHAT, history_run_id="legacy")
            await c.capture_message(telegram_message(47), "message.snapshot", CHAT, history_run_id="legacy")
            history_cursor.verify(store, c.vault, c.history.current())
            source = c.history.source("legacy")
            assert source["captured"] == 2 and source["offset_id"] == 47
            assert source["upper_id"] == 50 and source["cursor_hash"]
        finally:
            store.close()
    asyncio.run(run())


def test_cancel_closes_takeout_unsuccessfully_and_preserves_observations(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(3)])
        c.client.block_offset = 1
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            await asyncio.wait_for(c.client.entered.wait(), 5)
            await c.history.cancel()
            assert c.history.status()["phase"] == "cancelled"
            assert len(store.events(kind="message.snapshot")) == 1
            requests = [r.query for r in c.client.rpc if isinstance(r, f.InvokeWithTakeoutRequest)
                        and isinstance(r.query, f.account.FinishTakeoutSessionRequest)]
            assert len(requests) == 1 and not requests[0].success
        finally:
            store.close()
    asyncio.run(run())


def test_admin_final_pass_collects_new_actions_without_duplicates(tmp_path):
    async def run():
        c, store = make(tmp_path, [telegram_message(4)])
        now = datetime.now(timezone.utc)
        def action(eid):
            return t.ChannelAdminLogEvent(eid, now, 44, t.ChannelAdminLogEventActionDeleteMessage(telegram_message(2)))
        c.client.actions = [action(19)]
        original = c.client.get_messages
        async def read(*args, **kwargs):
            c.client.actions = [action(20), action(19)]
            return await original(*args, **kwargs)
        c.client.get_messages = read
        try:
            await c.history.start()
            state = await finished(c.history)
            assert state["phase"] == "complete", state
            meta = state["sources"][0]["metadata"]
            assert meta["admin_before"]["observed"] == 1 and meta["admin_after"]["observed"] == 1
            assert {e["payload"]["provider_event_id"] for e in store.events(kind="history.admin_log.observed")} == {19, 20}
        finally:
            store.close()
    asyncio.run(run())


def test_raw_page_preserves_empty_messages_and_does_not_hide_short_pages(monkeypatch):
    async def run():
        client = WitnessClient(None, 123, "a" * 32)
        requests = []
        async def receive(self, request, **kwargs):
            requests.append(request)
            return t.messages.Messages(messages=[t.MessageEmpty(20, peer_id=None), telegram_message(18)], users=[], chats=[], topics=[])
        monkeypatch.setattr(WitnessClient, "__call__", receive)
        rows = await client.history_page(t.InputPeerChannel(123, 456), limit=100, offset_id=21)
        assert [r.id for r in rows] == [20, 18] and isinstance(rows[0], t.MessageEmpty)
        assert len(requests) == 1 and requests[0].offset_id == 21 and requests[0].limit == 100
    asyncio.run(run())


@pytest.mark.parametrize("peer", [None, t.PeerChannel(123)])
def test_empty_message_advances_cursor_as_unavailable_without_losing_older_text(tmp_path, peer):
    async def run():
        c, store = make(tmp_path, [t.MessageEmpty(5, peer_id=peer), telegram_message(3)])
        try:
            await c.history.start(HistoryOptions(admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "incomplete" and state["captured"] == 1 and state["unavailable"] == 1
            assert store.events(kind="history.message.unavailable")[0]["message_id"] == 5
        finally:
            store.close()
    asyncio.run(run())


def test_takeout_media_authorization_loss_pauses_and_retains_queue(tmp_path):
    async def run():
        c, store = make(tmp_path, [media_message(3)])
        c.client.download_media = AsyncMock(side_effect=errors.SessionRevokedError(None))
        c.cleanup_rejected_authorization = AsyncMock()
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "paused" and state["reason"] == "authorization_required", state
            assert c.authorization_required and state["media_pending"] == 1
            assert store.claim_media(44) is None, "Ordinary workers must not bypass the chosen Takeout transport"
            c.cleanup_rejected_authorization.assert_awaited_once_with(c.client)
            assert not any(isinstance(r, f.InvokeWithTakeoutRequest) and
                isinstance(r.query, f.account.FinishTakeoutSessionRequest) for r in c.client.rpc)
        finally:
            await c.wait_authorization_cleanup()
            store.close()
    asyncio.run(run())


def test_cancelled_takeout_marks_pending_files_skipped(tmp_path):
    async def run():
        c, store = make(tmp_path, [media_message(3)])
        c.client.block_media = True
        try:
            await c.history.start(HistoryOptions(transport="takeout", admin_log=False))
            await asyncio.wait_for(c.client.entered.wait(), 5)
            await c.history.cancel()
            state = c.history.status()
            assert state["phase"] == "cancelled" and state["media_pending"] == 0
            assert state["media"]["skipped"] == 1
            assert len(store.events(kind="message.snapshot")) == 1
        finally:
            store.close()
    asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
