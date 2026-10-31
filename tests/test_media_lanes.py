import asyncio
import hashlib
import threading

import pytest
from telethon.errors import FileReferenceExpiredError
from telethon.tl import types

from test_collector import CHAT, media_message, wait_media
from test_reliability import prepared


async def until(predicate):
    async def poll():
        while not predicate():
            await asyncio.sleep(.01)
    await asyncio.wait_for(poll(), 2)


@pytest.mark.parametrize("ttl", [None, "media", "message"])
def test_urgent_media_finishes_while_large_download_is_blocked(journal, ttl):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_setting("capture", {"download_media": True, "max_media_mb": 8})
        blocked, release = asyncio.Event(), asyncio.Event()
        large_size = 3 * 1024**2

        async def download(media, file, progress_callback):
            if media.document.id == 501:
                blocked.set()
                await release.wait()
            data = b"x" * media.document.size
            file.write(data)
            return file

        collector.client.download_media = download
        await collector.capture_message(media_message(document_id=501, size=large_size), "message.new", CHAT)
        try:
            await collector.start()
            await asyncio.wait_for(blocked.wait(), 2)
            urgent = media_message(id=10, document_id=502, size=large_size if ttl else 4)
            if ttl == "media":
                urgent.media.ttl_seconds = 30
            elif ttl == "message":
                urgent.ttl_period = 30
            event = await collector.capture_message(urgent, "message.new", CHAT)
            await until(lambda: bool(store.events(kind="media.saved")))
            assert store.events(kind="media.saved")[0]["payload"]["message_event"] == event["seq"]
            assert store.media_stats() == {"done": 1, "running": 1}
            release.set()
            await wait_media(store)
        finally:
            release.set()
            await collector.stop(shutdown=True)
    asyncio.run(run())


@pytest.mark.parametrize("attachment", ["document", "photo"])
@pytest.mark.parametrize("change", ["same", "different", "missing", "expires_again", "other_type"])
def test_expired_reference_only_refetches_same_observed_attachment(journal, change, attachment):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        downloads, fetches = [], []

        def message_for(kind, identity=500):
            message = media_message(document_id=identity)
            if kind == "photo":
                photo = types.Photo(id=identity, access_hash=777, file_reference=b"original-reference",
                                    date=message.date, sizes=[types.PhotoSize(type="x", w=2, h=2, size=4)], dc_id=2)
                message.media = types.MessageMediaPhoto(photo=photo)
            return message

        async def download(media, file, progress_callback):
            item = getattr(media, "photo", None) or media.document
            downloads.append(item.file_reference)
            if len(downloads) == 1 or change == "expires_again":
                file.write(b"partial")
                raise FileReferenceExpiredError(None)
            file.write(b"data")
            return file

        async def get_messages(peer, *, ids):
            fetches.append((peer, ids))
            if change == "missing":
                return None
            kind = ("document" if attachment == "photo" else "photo") if change == "other_type" else attachment
            message = message_for(kind, 666 if change == "different" else 500)
            item = message.photo or message.document
            item.file_reference = b"renewed-reference"
            return message

        collector.client.download_media = download
        collector.client.get_messages = get_messages
        event = await collector.capture_message(message_for(attachment), "message.new", CHAT)
        try:
            await collector.start()
            await wait_media(store)
            assert fetches == [(CHAT, 9)]
            assert len(downloads) == (2 if change in ("same", "expires_again") else 1)
            assert not list((store.root / "media").glob("pending-*"))
            if change == "same":
                assert store.media_stats() == {"done": 1}
                saved = store.events(kind="media.saved")[0]
                assert saved["payload"]["message_event"] == event["seq"]
                assert saved["payload"]["media_sha256"] == hashlib.sha256(b"data").hexdigest()
                assert saved["payload"]["file_reference_refreshed"] is True
            else:
                assert store.media_stats() == {"failed": 1}
                assert not store.events(kind="media.saved")
            original = store.events(before=event["seq"] + 1, limit=1)[0]
            assert original == event
        finally:
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_bulk_lane_starts_and_both_jobs_survive_stop(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_setting("capture", {"download_media": True, "max_media_mb": 8})
        started, waiting = set(), asyncio.Event()

        async def download(media, file, progress_callback):
            started.add(media.document.id)
            file.write(b"part")
            await waiting.wait()

        collector.client.download_media = download
        await collector.capture_message(media_message(document_id=501), "message.new", CHAT)
        try:
            await collector.start()
            await until(lambda: 501 in started)
            await collector.capture_message(
                media_message(id=10, document_id=502, size=3 * 1024**2), "message.new", CHAT)
            await until(lambda: 502 in started)
            assert store.media_stats() == {"running": 2}
        finally:
            await collector.stop(shutdown=True)
        assert store.media_stats() == {"retry": 2}
        assert not collector.media_worker and not collector.urgent_media_worker
        assert not list((store.root / "media").glob("pending-*"))
        assert not collector.client.connected
    asyncio.run(run())


def test_large_file_hash_does_not_hold_up_urgent_download(journal, monkeypatch):
    import tgwitness.collector as module

    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_setting("capture", {"download_media": True, "max_media_mb": 8})
        hashing, release = threading.Event(), threading.Event()
        urgent_saved = asyncio.Event()
        original_digest = module.file_digest

        def digest(path):
            if path.stat().st_size > 2 * 1024**2:
                hashing.set()
                assert release.wait(5), "large hashing fixture was not released"
            return original_digest(path)

        async def download(media, file, progress_callback):
            file.write(b"x" * media.document.size)
            if media.document.id == 502:
                urgent_saved.set()
            return file

        monkeypatch.setattr(module, "file_digest", digest)
        collector.client.download_media = download
        await collector.capture_message(
            media_message(document_id=501, size=3 * 1024**2), "message.new", CHAT)
        try:
            await collector.start()
            await until(hashing.is_set)
            await collector.capture_message(media_message(id=10, document_id=502), "message.new", CHAT)
            await asyncio.wait_for(urgent_saved.wait(), 2)
        finally:
            release.set()
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_worker_failure_cancels_other_lane_and_keeps_job(journal, monkeypatch):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        blocked, fail_worker = asyncio.Event(), asyncio.Event()

        async def download(media, file, progress_callback):
            blocked.set()
            await asyncio.Event().wait()

        async def monitor():
            await fail_worker.wait()
            raise RuntimeError("synthetic worker failure")

        collector.client.download_media = download
        monkeypatch.setattr(collector, "monitor", monitor)
        await collector.capture_message(media_message(), "message.new", CHAT)
        try:
            await collector.start()
            await asyncio.wait_for(blocked.wait(), 2)
            fail_worker.set()
            await until(lambda: not collector.client.connected)
            assert not collector.running
            assert collector.phase == "collector_error"
            assert store.media_stats() == {"retry": 1}
            assert collector.media_worker.done() and collector.urgent_media_worker.done()
        finally:
            await collector.stop(shutdown=True)
    asyncio.run(run())
