"""History acquisition: durable cursors, scope isolation and honest partial outcomes. No network."""
import asyncio
import base64
import json
from types import SimpleNamespace as NS

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
from telethon import types
from telethon.errors import ChannelPrivateError, FloodWaitError

from tgwitness import history
from tgwitness.app import create_app
from tgwitness.collector import Collector
from tgwitness.evidence import export_file
from tgwitness.store import canonical
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_bundle, verify_history_report, fingerprint
from test_access import issue, login
from test_collector import CHAT, FakeClient, media_message, telegram_message


async def prepared(journal, monkeypatch, size=5):
    monkeypatch.setattr(history, "PAGE_SIZE", 2)
    store, vault = journal
    store.set_setting("account", {"id": 44})
    store.set_target(CHAT, "Synthetic history", "supergroup", True)
    collector = Collector(store, vault, FakeClient)
    collector.running = True
    rows = [telegram_message(i, text=f"history-{i}") for i in range(size, 0, -1)]

    async def resolve(chat_id):
        return chat_id

    async def get_messages(entity, limit, offset_id):
        return [m for m in rows if not offset_id or m.id < offset_id][:limit]

    collector.resolve_target = resolve
    collector.client = NS(get_messages=get_messages)
    return collector, rows


def test_history_populates_journal_and_signed_export(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        h = collector.history
        started = await h.start()
        await h.task
        state = h.status()
        assert state["phase"] == "complete" and state["captured"] == 5
        assert state["sources"][0]["upper_id"] == 5 and state["sources"][0]["offset_id"] == 1
        rows = journal[0].events(kind="message.snapshot")
        assert {e["message_id"] for e in rows} == {1, 2, 3, 4, 5}
        assert all(e["payload"]["history_run_id"] == started["id"] for e in rows)
        assert all(e["payload"]["source"] == "history_acquisition" for e in rows)
        report = h.report()
        Ed25519PublicKey.from_public_bytes(base64.b64decode(journal[1].public_key)).verify(
            base64.b64decode(report["signature"]), canonical(report["statement"]))
        bundle = export_file(*journal, "zip")
        assert verify_bundle(bundle)["events"] >= 5
        report_path = journal[0].root / "progress.json"
        report_path.write_bytes(canonical(report))
        assert verify_history_report(report_path, fingerprint(journal[1].public_key), bundle)["evidence_counts_checked"]
        assert not verify_history_report(report_path)["evidence_counts_checked"]
        # A valid signature with fabricated counters must still conflict with the journal.
        report["statement"]["captured"] += 1
        report["statement"]["sources"][0]["captured"] += 1
        report["signature"] = journal[1].sign(canonical(report["statement"]))
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with pytest.raises(ValueError, match="differ from the journal"):
            verify_history_report(report_path, bundle=bundle)
        bundle.unlink()
    asyncio.run(run())


def test_pause_restart_resume_does_not_repeat_saved_messages(journal, monkeypatch):
    async def run():
        collector, rows = await prepared(journal, monkeypatch)
        entered, release = asyncio.Event(), asyncio.Event()
        original = collector.client.get_messages

        async def blocking(entity, limit, offset_id):
            if offset_id:
                entered.set()
                await release.wait()
            return await original(entity, limit, offset_id)
        collector.client.get_messages = blocking
        h = collector.history
        await h.start()
        await asyncio.wait_for(entered.wait(), 3)
        assert h.status()["captured"] == 2
        await h.pause("process_shutdown")
        # New messages after the upper boundary must not leak into the resumed run.
        rows.insert(0, telegram_message(99))
        collector.client.get_messages = original
        collector.history = history.History(collector)
        await collector.history.resume()
        await collector.history.task
        assert collector.history.status()["captured"] == 5
        events = journal[0].events(kind="message.snapshot")
        assert sorted(e["message_id"] for e in events) == [1, 2, 3, 4, 5]
    asyncio.run(run())


def test_crash_state_requires_explicit_resume(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        h = collector.history
        await h.start()
        h.task.cancel()
        await asyncio.gather(h.task, return_exceptions=True)
        restored = history.History(collector)
        assert restored.status()["phase"] == "paused"
        assert restored.status()["reason"] == "process_restart"
        assert not restored.busy
        await restored.resume()
        await restored.task
        assert restored.status()["captured"] == 5
    asyncio.run(run())


def test_failed_cursor_write_rolls_back_observation_and_media(journal, monkeypatch):
    async def run():
        collector, rows = await prepared(journal, monkeypatch, size=1)
        rows[:] = [media_message(1)]
        original = collector.capture_message

        async def broken(*args, **kwargs):
            await original(*args, **kwargs)
            raise OSError("Synthetic transaction failure")
        collector.capture_message = broken
        h = collector.history
        await h.start()
        await h.task
        assert h.status()["phase"] == "paused" and h.status()["captured"] == 0
        assert not journal[0].events(kind="message.snapshot")
        assert not journal[0].media_stats()
        collector.capture_message = original
        await h.resume()
        await h.task
        assert h.status()["captured"] == 1
        assert h.status()["media_pending"] == 1
    asyncio.run(run())


def test_one_forbidden_source_does_not_hide_success_or_report_full_completion(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        other = -1000000000456
        journal[0].set_target(other, "Forbidden", "supergroup", True)
        original = collector.client.get_messages

        async def partly_private(entity, **kwargs):
            if entity == other:
                raise ChannelPrivateError(None)
            return await original(entity, **kwargs)
        collector.client.get_messages = partly_private
        await collector.history.start()
        await collector.history.task
        state = collector.history.status()
        assert state["phase"] == "incomplete" and state["captured"] == 5
        assert state["sources_by_phase"] == {"complete": 1, "failed": 1}
        assert any(s["error"] == "ChannelPrivateError" for s in state["sources"])
    asyncio.run(run())


@pytest.mark.parametrize("problem", ["wrong_chat", "repeated_id", "wrong_order"])
def test_bad_history_page_is_not_accepted(journal, monkeypatch, problem):
    async def run():
        collector, rows = await prepared(journal, monkeypatch)
        if problem == "wrong_chat":
            rows[0].peer_id = types.PeerChannel(999)
        elif problem == "repeated_id":
            rows[1].id = rows[0].id
        else:
            rows[:] = list(reversed(rows))
        await collector.history.start()
        await collector.history.task
        assert collector.history.status()["phase"] == "paused"
        assert collector.history.status()["captured"] == 0
        assert not journal[0].events(kind="message.snapshot")
    asyncio.run(run())


def test_disabled_source_is_skipped_even_if_fetch_already_started(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        original = collector.client.get_messages

        async def disabled(entity, **kwargs):
            journal[0].set_target(CHAT, "Synthetic history", "supergroup", False)
            return await original(entity, **kwargs)
        collector.client.get_messages = disabled
        await collector.history.start()
        await collector.history.task
        assert collector.history.status()["phase"] == "incomplete"
        assert collector.history.status()["captured"] == 0
        assert collector.history.status()["sources"][0]["error"] == "source_disabled"
    asyncio.run(run())


def test_cancel_retains_records_and_next_run_is_explicit(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        await collector.history.start()
        with pytest.raises(ValueError, match="existing"):
            await collector.history.start()
        await collector.history.cancel()
        assert collector.history.status()["phase"] == "cancelled"
        with pytest.raises(ValueError, match="paused"):
            await collector.history.resume()
        await collector.history.start()
        await collector.history.task
        assert collector.history.status()["phase"] == "complete"
    asyncio.run(run())


def test_wrong_account_cannot_resume(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        await collector.history.start()
        await collector.history.pause()
        journal[0].set_setting("account", {"id": 999})
        with pytest.raises(ValueError, match="different"):
            await collector.history.resume()
    asyncio.run(run())


def test_floodwait_preserves_cursor_and_durable_account_backoff(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)

        async def wait(*args, **kwargs):
            raise FloodWaitError(None, capture=600)
        collector.client.get_messages = wait
        await collector.history.start()
        for _ in range(100):
            if journal[0].get_setting("rpc_backoff_until", 0):
                break
            await asyncio.sleep(.01)
        assert journal[0].get_setting("rpc_backoff_until", 0) > history.time.time() + 500
        await collector.history.pause()
        assert collector.history.status()["captured"] == 0
        assert collector.history.status()["sources"][0]["offset_id"] == 0
    asyncio.run(run())


def test_chat_limited_access_cannot_see_or_control_other_history(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as admin:
        admin.headers["Authorization"] = "Bearer " + app.state.vault.token
        token, _ = issue(admin, workspaces={"default": [CHAT]}, permissions=["sources", "export"])
        limited, _ = login(app, token)
        assert limited.get("/api/status").json()["history"] is None
        for route in ("/api/history", "/api/history/report"):
            assert limited.get(route).status_code == 403
        for action in ("start", "resume", "pause", "cancel"):
            assert limited.post("/api/history/" + action).status_code == 403
        assert admin.post("/api/history/start").status_code == 400
        assert admin.get("/api/history/report").status_code == 404


def test_low_disk_pauses_before_any_history_is_read(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        monkeypatch.setattr(history.shutil, "disk_usage", lambda root: NS(free=1))
        await collector.history.start()
        await collector.history.task
        assert collector.history.status()["reason"] == "insufficient_free_space"
        assert not journal[0].events(kind="message.snapshot")
    asyncio.run(run())


def test_stalled_page_times_out_without_losing_cursor(journal, monkeypatch):
    async def run():
        collector, _ = await prepared(journal, monkeypatch)
        original_param = collector.param
        collector.param = lambda key: (.02 if collector.history.status()["captured"] >= 2 else 3) \
            if key == "operation_timeout_seconds" else original_param(key)
        original_read = collector.client.get_messages

        async def stall(entity, **kwargs):
            if kwargs["offset_id"]:
                await asyncio.Event().wait()
            return await original_read(entity, **kwargs)
        collector.client.get_messages = stall
        await collector.history.start()
        await collector.history.task
        assert collector.history.status()["phase"] == "paused"
        assert collector.history.status()["reason"] == "TimeoutError"
        assert collector.history.status()["captured"] == 2
        collector.client.get_messages = original_read
        collector.param = original_param
        await collector.history.resume()
        await collector.history.task
        assert collector.history.status()["captured"] == 5
        assert len(journal[0].events(kind="message.snapshot")) == 5
    asyncio.run(run())


def test_cursor_survives_database_close_and_reopen(tmp_path, monkeypatch):
    async def run():
        vault = Vault(tmp_path)
        store = Store(tmp_path)
        store.bind(vault)
        collector, _ = await prepared((store, vault), monkeypatch)
        entered = asyncio.Event()
        original = collector.client.get_messages

        async def block(entity, **kwargs):
            if kwargs["offset_id"]:
                entered.set()
                await asyncio.Event().wait()
            return await original(entity, **kwargs)
        collector.client.get_messages = block
        await collector.history.start()
        await asyncio.wait_for(entered.wait(), 3)
        collector.history.task.cancel()
        await asyncio.gather(collector.history.task, return_exceptions=True)
        store.close()  # no history pause transition was saved
        store = Store(tmp_path)
        store.bind(vault)
        try:
            restored, _ = await prepared((store, vault), monkeypatch)
            assert restored.history.status()["phase"] == "paused"
            assert restored.history.status()["captured"] == 2
            await restored.history.resume()
            await restored.history.task
            assert restored.history.status()["captured"] == 5
            assert sorted(e["message_id"] for e in store.events(kind="message.snapshot")) == [1, 2, 3, 4, 5]
        finally:
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("size,missing,phase", [(0, False, "complete"), (5, True, "incomplete")])
def test_empty_history_and_unavailable_message_are_distinct(journal, monkeypatch, size, missing, phase):
    async def run():
        collector, rows = await prepared(journal, monkeypatch, size=size)
        if missing:
            rows[0] = types.MessageEmpty(id=rows[0].id, peer_id=None)
        await collector.history.start()
        await collector.history.task
        state = collector.history.status()
        assert state["phase"] == phase
        assert state["captured"] == size - int(missing)
        assert state["unavailable"] == int(missing)
        report = journal[0].root / "progress.json"
        report.write_bytes(canonical(collector.history.report()))
        bundle = export_file(*journal, "zip")
        try:
            assert verify_history_report(report, bundle=bundle)["evidence_counts_checked"]
        finally:
            bundle.unlink()
    asyncio.run(run())
