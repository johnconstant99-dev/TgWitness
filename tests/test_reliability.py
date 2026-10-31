import asyncio
import hashlib
import sqlite3
import time
import zipfile

import pytest
from telethon.errors import FloodWaitError

from tgwitness.collector import Collector
from tgwitness.evidence import export_file
from tgwitness.store import Store
from tgwitness.verify import verify_bundle
from test_collector import FakeClient, CHAT, media_message, saved_session, wait_media, telegram_message


async def prepared(journal):
    store, vault = journal
    collector = Collector(store, vault, FakeClient)
    await collector.configure(123, "a"*32, saved_session())
    store.set_target(CHAT, "Private group without username", "supergroup", True)
    store.set_setting("capture", {"download_media": True, "max_media_mb": 1})
    return collector


def test_pending_account_change_preserves_working_session(journal):
    async def run():
        store, vault = journal
        collector = await prepared(journal)
        saved = vault.read("credentials")
        await collector.configure(999, "b"*32)
        assert vault.read("credentials") == saved
        assert store.get_setting("account")["id"] == 44
        await collector.restore()
        assert collector.client.authorized
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_journal_cannot_be_reassigned_to_another_account(journal):
    async def run():
        store, vault = journal
        collector = await prepared(journal)
        saved = vault.read("credentials")
        with pytest.raises(ValueError, match="different Telegram account"):
            await collector.configure(999, "b"*32, saved_session())
        assert vault.read("credentials") == saved
        assert store.get_setting("account")["id"] == 44
        assert len(store.events(kind="account.authorized")) == 1
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_message_and_job_commit_atomically(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        before = store.stats()["total"]
        store.db.execute("CREATE TRIGGER reject_job BEFORE INSERT ON media_jobs "
                         "BEGIN SELECT RAISE(ABORT, 'test full disk'); END")
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError):
            await collector.capture_message(media_message(), "message.new", CHAT)
        assert store.stats()["total"] == before
        assert store.media_stats() == {}
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_jobs_survive_restart_and_preserve_original_media_versions(journal):
    async def run():
        store, vault = journal
        collector = await prepared(journal)
        first = await collector.capture_message(media_message(document_id=501), "message.new", CHAT)
        second = await collector.capture_message(media_message(document_id=502), "message.edited", CHAT)
        assert store.media_stats() == {"queued": 2}
        abandoned = store.claim_media(44)
        assert abandoned["message_event"] == first["seq"]
        await collector.stop(shutdown=True)

        reopened = Store(store.root)
        reopened.bind(vault)
        seen = []
        new = Collector(reopened, vault, FakeClient)
        await new.restore()
        async def download(media, file, progress_callback):
            seen.append(media.document.id)
            file.write(b"data")
            return file
        new.client.download_media = download
        try:
            await new.start()
            await wait_media(reopened)
            assert seen == [501, 502]
            assert reopened.media_stats() == {"done": 2}
            assert len(reopened.events(kind="media.recovered")) == 1
            assert {e["payload"]["message_event"] for e in reopened.events(kind="media.saved")} == {
                first["seq"], second["seq"]}
        finally:
            await new.stop()
            reopened.close()
    asyncio.run(run())


def test_queue_mutation_cannot_substitute_another_attachment(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        await collector.capture_message(media_message(), "message.new", CHAT)
        with store.transaction():
            store.db.execute("UPDATE media_jobs SET descriptor=?", (bytes(media_message(document_id=666)),))
        await collector.start()
        await wait_media(store)
        assert store.media_stats() == {"failed": 1}
        assert store.events(kind="media.failed")[0]["payload"]["reason"] == "queue_descriptor_differs_from_signed_observation"
        assert not store.events(kind="media.saved")
        await collector.stop()
    asyncio.run(run())


def test_flood_wait_persists_without_stopping_text_capture(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        async def download(*args, **kwargs):
            raise FloodWaitError(None, capture=90)
        collector.client.download_media = download
        await collector.capture_message(media_message(), "message.new", CHAT)
        await collector.start()
        await wait_media(store)
        assert store.media_stats() == {"retry": 1}
        assert store.get_setting("rpc_backoff_until") > time.time() + 80
        await collector.capture_message(telegram_message(10, "Still collecting"), "message.new", CHAT)
        assert store.events(kind="message.new")[0]["payload"]["text"] == "Still collecting"
        await collector.stop()
    asyncio.run(run())


def test_one_private_source_missing_does_not_stop_others(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_target(-1000000000999, "Unavailable private source", "supergroup", True)
        await collector.start()
        assert collector.running
        assert collector.source_status[str(CHAT)]["state"] == "visible_in_dialogs"
        assert collector.source_status["-1000000000999"]["state"] == "access_unconfirmed"
        assert len(store.events(kind="source.access_unconfirmed")) == 1
        await collector.stop()
    asyncio.run(run())


def test_corrupt_existing_media_is_not_marked_preserved(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        folder = store.root / "media"
        folder.mkdir()
        digest = hashlib.sha256(b"data").hexdigest()
        path = folder / digest
        path.write_bytes(b"corrupt")
        await collector.capture_message(media_message(), "message.new", CHAT)
        await collector.start()
        await wait_media(store)
        assert path.read_bytes() == b"corrupt"
        assert store.media_stats() == {"failed": 1}
        assert not store.events(kind="media.saved")
        await collector.stop()
    asyncio.run(run())


def test_export_uses_stable_streamed_prefix_while_writes_continue(journal, monkeypatch):
    import tgwitness.evidence as evidence
    store, vault = journal
    for i in range(100):
        store.append("message.new", {"text": str(i)}, CHAT, i)
    monkeypatch.setattr(store, "all_events", lambda: pytest.fail("Full journal loaded into memory"))
    original = evidence.html_chunks
    def interleaved(events, *rest):
        store.append("message.new", {"text": "Written during export"}, CHAT, 101)
        yield from original(events, *rest)
    monkeypatch.setattr(evidence, "html_chunks", interleaved)
    path = export_file(store, vault, "zip")
    try:
        assert verify_bundle(path)["events"] == 100
        assert store.verify(vault.public_key)["events"] == 101
        with zipfile.ZipFile(path) as z:
            assert b"Written during export" not in z.read("events.jsonl")
    finally:
        path.unlink()


def test_retained_local_checkpoint_detects_tail_truncation(journal):
    from tgwitness.evidence import retain_checkpoint
    store, vault = journal
    store.append("message.new", {"text":"first"})
    store.append("message.new", {"text":"second"})
    retain_checkpoint(store, vault)
    store.db.execute("DROP TRIGGER immutable_delete")
    store.db.execute("DELETE FROM events WHERE seq=2")
    store.db.commit()
    with pytest.raises(ValueError, match="shorter"):
        store.verify(vault.public_key)
    with pytest.raises(ValueError, match="shorter"):
        export_file(store, vault, "zip")


def test_reconnect_retries_and_authorization_loss_are_visible(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        collector.running = True
        await collector.client.disconnect()
        connect = collector.client.connect
        async def failed_connect():
            raise OSError("simulated offline")
        collector.client.connect = failed_connect
        await collector.reconnect()
        assert collector.next_reconnect_at > time.time()
        assert store.events(kind="connection.retry_failed")
        collector.next_reconnect_at = 0
        collector.client.connect = connect
        await collector.reconnect()
        assert collector.client.connected and collector.reconnect_attempts == 0
        collector.client.authorized = False
        collector.next_reconnect_at = 0
        await collector.reconnect()
        assert not collector.running and collector.phase == "authorization_required"
        assert store.events(kind="coverage.gap")[0]["payload"]["reason"] == "authorization_required"
        await collector.stop()
    asyncio.run(run())
