"""Whole-tool review: failure paths outside the mini-client happy path."""
import asyncio
import hashlib
import threading

import pytest

from tgwitness import dossier, replica
from tgwitness import chat_export
from tgwitness.evidence import checkpoint, retain_checkpoint
from tgwitness.network import NetworkConfig
from tgwitness.store import canonical
from tests.test_collector import CHAT, media_message, wait_media
from tests.test_reliability import prepared
from tests.test_replica import AK, SK, configure, fake_s3
from tests.test_review_regressions import backup


@pytest.mark.parametrize("data", [b"", b"abc", b"abcde"])
def test_incomplete_or_oversized_download_is_not_preserved(journal, data):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        async def download(media, file, progress_callback):
            file.write(data)
            return file
        collector.client.download_media = download
        try:
            await collector.start()
            await collector.capture_message(media_message(size=4), "message.new", CHAT)
            await wait_media(store)
            assert not store.events(kind="media.saved")
            assert not list((store.root / "media").glob("pending-*"))
        finally:
            await collector.stop()
    asyncio.run(run())


@pytest.mark.parametrize("change", ["endpoint", "prefix", "bucket"])
def test_replica_destination_change_copies_the_whole_journal(journal, tmp_path, change):
    async def run():
        store, vault = journal
        first, endpoint, objects, _ = await fake_s3()
        second, new_endpoint, new_objects, _ = await fake_s3()
        try:
            configure(store, vault, endpoint)
            event = store.append("message.new", {"text": "must reach both backups"}, CHAT, 1)
            retain_checkpoint(store, vault)
            copied = await replica.sync(store, vault, NetworkConfig(kind="direct"))
            assert copied["error"] is None
            assert copied["objects"] >= 2
            settings = replica.replica_settings(store)
            settings[change] = {"endpoint": new_endpoint, "prefix": "another-copy", "bucket": "another-bucket"}[change]
            store.set_setting("replica", settings)
            if change == "bucket":
                # This minimal fake server has one active bucket; switch its backing map.
                objects.clear()
            copied = await replica.sync(store, vault, NetworkConfig(kind="direct"))
            assert copied["error"] is None and copied["objects"] >= 2
            # The second destination needs the beginning of the journal, not just its tail.
            target = new_objects if change == "endpoint" else objects
            prefix = replica.workspace_prefix(settings, vault.public_key)
            assert any(name.startswith(prefix + "/journal/000000000001-") for name in target)
            restored = await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "restored")
            assert restored["events"] >= event["seq"]
        finally:
            first.close()
            second.close()
            await first.wait_closed()
            await second.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize("local", [None, b"corrupt bytes"])
def test_replica_does_not_skip_missing_or_corrupt_media(journal, local):
    async def run():
        store, vault = journal
        server, endpoint, objects, _ = await fake_s3()
        try:
            configure(store, vault, endpoint)
            data = b"original bytes"
            digest = hashlib.sha256(data).hexdigest()
            store.append("media.saved", {"media_sha256": digest, "size": len(data)}, CHAT, 1)
            retain_checkpoint(store, vault)
            media = store.root / "media" / digest
            media.parent.mkdir(exist_ok=True)
            if local is not None:
                media.write_bytes(local)
            failed = await replica.sync(store, vault, NetworkConfig(kind="direct"))
            assert failed["error"]
            assert not any("/media/" in name for name in objects)
            media.write_bytes(data)
            assert (await replica.sync(store, vault, NetworkConfig(kind="direct")))["error"] is None
            assert sum("/media/" in name for name in objects) == 1
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize("media", [None, b"wrong bytes", b"original bytes"])
def test_restore_checks_media_referenced_by_signed_journal(journal, tmp_path, monkeypatch, media):
    store, vault = journal
    original = b"original bytes"
    digest = hashlib.sha256(original).hexdigest()
    event = store.append("media.saved", {"media_sha256": digest, "size": len(original)}, CHAT, 1)
    objects = {"audit/journal/000000000001-000000000001.jsonl.tgwr": canonical(event) + b"\n",
               "audit/checkpoints/checkpoint-000000000001.json.tgwr": canonical(checkpoint(store, vault))}
    if media is not None:
        objects["audit/media/hidden-name.tgwr"] = media
    info, _ = backup(monkeypatch, vault, objects)
    out = tmp_path / "restored"
    if media == original:
        result = asyncio.run(replica.restore(info, "fake", "fake", out))
        assert result["media_verified"] == 1
    else:
        with pytest.raises(ValueError, match="media"):
            asyncio.run(replica.restore(info, "fake", "fake", out))
        assert list(out.iterdir()) == []


def test_disabled_dossier_is_not_recreated_by_a_pending_build(journal, monkeypatch):
    store, vault = journal
    dossier.set_enabled(store, CHAT, True)
    original = dossier.build
    def disable_during_build(*args):
        statement = original(*args)
        dossier.set_enabled(store, CHAT, False)
        return statement
    monkeypatch.setattr(dossier, "build", disable_during_build)
    dossier.signed(store, vault, CHAT)
    assert dossier.enabled_chats(store) == []
    assert not dossier.cache_path(store, CHAT).exists()


@pytest.mark.parametrize("conflict", [False, True])
def test_restore_handles_replayed_journal_segments_after_interruption(journal, tmp_path, monkeypatch, conflict):
    store, vault = journal
    first = store.append("message.new", {"text": "first"}, CHAT, 1)
    second = store.append("message.new", {"text": "second"}, CHAT, 2)
    replay = {**first, "payload": {"text": "different"}} if conflict else first
    objects = {"audit/journal/000000000001-000000000001.jsonl.tgwr": canonical(first) + b"\n",
               "audit/journal/000000000001-000000000002.jsonl.tgwr": canonical(replay) + b"\n" + canonical(second) + b"\n",
               "audit/checkpoints/checkpoint-000000000002.json.tgwr": canonical(checkpoint(store, vault))}
    info, _ = backup(monkeypatch, vault, objects)
    if conflict:
        with pytest.raises(ValueError, match="Conflicting"):
            asyncio.run(replica.restore(info, "fake", "fake", tmp_path / "restored"))
    else:
        result = asyncio.run(replica.restore(info, "fake", "fake", tmp_path / "restored"))
        assert result["events"] == 2


def test_export_cancellation_waits_for_the_file_worker_before_cleanup(journal, monkeypatch):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        entered, release = threading.Event(), threading.Event()
        def building(scratch, meta, vault, output, limit):
            entered.set()
            assert release.wait(5)
            assert scratch.exists()  # Cancellation must not remove the worker's input.
            output.write_bytes(b"synthetic completed archive")
        monkeypatch.setattr(chat_export, "build_bundle", building)
        async def history(entity, scratch, record):
            scratch.write_text("{}\n")
            return 1
        collector.stream_history = history
        record = {"id": "cancellation-probe", "chat_id": CHAT, "phase": "running", "captured": 1}
        collector.export_state = record
        collector.export_task = asyncio.create_task(collector.run_export(None, {}, record))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            cancelling = asyncio.create_task(collector.cancel_export(record["id"]))
            await asyncio.sleep(.05)
            assert not cancelling.done()
            release.set()
            await cancelling
            assert record["phase"] == "cancelled"
            assert not list((store.root / "temporary-exports").iterdir())
        finally:
            release.set()
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_copy_does_not_publish_a_checkpoint_ahead_of_its_journal(journal, tmp_path, monkeypatch):
    async def run():
        store, vault = journal
        server, endpoint, objects, _ = await fake_s3()
        configure(store, vault, endpoint)
        data = b"preserved"
        digest = hashlib.sha256(data).hexdigest()
        path = store.root / "media" / digest
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        store.append("media.saved", {"media_sha256": digest, "size": len(data)}, CHAT, 1)
        retain_checkpoint(store, vault)
        upload = replica.upload
        async def append_during_media(*args, **kwargs):
            size = await upload(*args, **kwargs)
            if "/media/" in args[2]:
                store.append("message.new", {"text": "arrived during backup"}, CHAT, 2)
                retain_checkpoint(store, vault)
            return size
        monkeypatch.setattr(replica, "upload", append_during_media)
        try:
            copied = await replica.sync(store, vault, NetworkConfig(kind="direct"))
            assert copied["error"] is None and copied["journal_seq"] == 1
            assert not any("checkpoint-000000000002" in name for name in objects)
            restored = await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "first")
            assert restored["events"] == 1 and restored["media_verified"] == 1
            await replica.sync(store, vault, NetworkConfig(kind="direct"))
            restored = await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "second")
            assert restored["events"] >= 2
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())
