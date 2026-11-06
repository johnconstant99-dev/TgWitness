"""Downloads must match the observed photo variant and declared payload length."""
import asyncio
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

import pytest
from telethon import errors
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import file_hashes, telegram_client
from tgwitness.account_export import AccountExport, BoundedWriter
from tgwitness.account_export_transport import Transport, WrappedClient
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_account_export
from tools.demo_account_export import SyntheticCollector
from tools.test_file_hash_export import CONTENT, ExportTransport


def photo(progressive=False, animated=True):
    size = (t.PhotoSizeProgressive("y", 100, 100, [2, len(CONTENT)]) if progressive
            else t.PhotoSize("y", 100, 100, len(CONTENT)))
    return t.Photo(900, 2, b"synthetic-reference", datetime(2026, 11, 5, tzinfo=timezone.utc),
                   [size], 2, video_sizes=[t.VideoSize("u", 100, 100, len(CONTENT))] if animated else None)


@pytest.mark.parametrize("progressive", [False, True])
@pytest.mark.parametrize("takeout", [None, 999])
def test_photo_download_uses_the_hash_manifest_variant(monkeypatch, progressive, takeout):
    client = telegram_client.WitnessClient(None, 123, "a" * 32)
    client.session.set_dc(2, "127.0.0.1", 443)
    sent = []

    async def wire(self, sender, request, ordered=False, flood_sleep_threshold=None):
        if takeout:
            assert isinstance(request, f.InvokeWithTakeoutRequest) and request.takeout_id == takeout
            request = request.query
        assert isinstance(request, f.upload.GetFileRequest)
        sent.append(request.location.thumb_size)
        payload = CONTENT if request.location.thumb_size == "y" else b"v" * len(CONTENT)
        return t.upload.File(t.storage.FileJpeg(), 0, payload)

    monkeypatch.setattr(telegram_client.TelegramClient, "_call", wire)
    network = object.__new__(Transport)
    network.ranged = lambda task: WrappedClient(client, takeout)
    output = io.BytesIO()
    asyncio.run(network.download(photo(progressive), BoundedWriter(output, 1024), None, {}))
    assert sent == [file_hashes.representation(photo(progressive))["variant"]]
    assert output.getvalue() == CONTENT


@pytest.mark.parametrize("change", ["none", "variant", "size"])
def test_photo_reference_refresh_keeps_the_observed_representation(change):
    original, refreshed = photo(), photo()
    refreshed.file_reference = b"renewed-synthetic-reference"
    if change == "variant":
        refreshed.sizes[0].type = "x"
    elif change == "size":
        refreshed.sizes[0].size += 1
    calls = []

    async def download(media, *, file, progress_callback, **options):
        calls.append(options)
        if len(calls) == 1:
            file.write(b"interrupted")
            raise errors.FileReferenceExpiredError(None)
        file.write(CONTENT)
        return file

    async def refresh(media, task):
        return refreshed

    network = object.__new__(Transport)
    network.ranged = lambda task: SimpleNamespace(download_media=download)
    network.refresh_media = refresh
    output = io.BytesIO()
    task = network.download(original, BoundedWriter(output, 1024), None, {})
    if change == "none":
        asyncio.run(task)
        assert output.getvalue() == CONTENT
        assert calls == [{"thumb": "y"}, {"thumb": "y"}]
    else:
        with pytest.raises(ValueError, match="representation changed"):
            asyncio.run(task)
        assert len(calls) == 1


@pytest.mark.parametrize("payload", [b"", CONTENT[:-1], CONTENT])
def test_account_photo_length_controls_archive_coverage(tmp_path, payload):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)

        class Network(ExportTransport):
            async def page(self, task, cursor):
                rows, after, terminal = await super().page(task, cursor)
                return [(row, photo(animated=False)) for row, _ in rows], after, terminal

            async def download(self, media, stream, progress, task):
                stream.write(payload)
                return stream

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "include_profile": False, "include_contacts": False})
            await export.task
            path = export.result_path(job["id"])
            checked = verify_account_export(path, fingerprint(vault.public_key))
            complete = payload == CONTENT
            assert checked["complete_within_scope"] is complete
            assert checked["counts"]["messages"] == 2
            with zipfile.ZipFile(path) as archive:
                rows = [json.loads(line) for line in archive.read("data/00000001.jsonl").splitlines()]
                assert all(row["attachments"][0]["outcome"] == ("saved" if complete else "failed") for row in rows)
                if not complete:
                    assert not any(name.startswith("media/") for name in archive.namelist())
        finally:
            await export.close()
            store.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("claim", ["expected_bytes", "representation"])
def test_verifier_rejects_signed_payload_length_contradictions(tmp_path, claim):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        export.transport_factory = ExportTransport

        async def old_attachment(media, task, network, directory, options):
            payload = CONTENT[:-1]
            digest = hashlib.sha256(payload).hexdigest()
            (directory / "media" / digest).write_bytes(payload)
            return {"kind": "photo", "outcome": "saved", "file": "media/" + digest,
                    "sha256": digest, "bytes": len(payload),
                    "expected_bytes": len(CONTENT) if claim == "expected_bytes" else None,
                    "representation": file_hashes.representation(photo()) if claim == "representation" else None}

        export.attachment = old_attachment
        try:
            job = await export.start({"transport": "regular", "include_profile": False, "include_contacts": False})
            await export.task
            assert export.public()["ready"], export.public()
            with pytest.raises(ValueError, match="attachment size differs"):
                verify_account_export(export.result_path(job["id"]), fingerprint(vault.public_key))
        finally:
            await export.close()
            store.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("payload", [b"", CONTENT[:-1], CONTENT])
def test_chat_export_rejects_incomplete_payload(tmp_path, payload):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    collector = Collector(store, vault)
    item = t.Message(1, t.PeerUser(11), datetime(2026, 11, 5, tzinfo=timezone.utc),
                     "Photo", media=t.MessageMediaPhoto(photo=photo(animated=False)))

    async def download(media, *, file, progress_callback, **options):
        file.write(payload)
        return file

    collector.client = SimpleNamespace(download_media=download)
    directory = tmp_path / "downloads"
    directory.mkdir()
    try:
        result = asyncio.run(collector.export_attachment(item, directory, "download"))
        if payload == CONTENT:
            assert (tmp_path / "downloads" / result["file_sha256"]).read_bytes() == CONTENT
        else:
            assert result.get("file_status") == "unavailable", result
            assert result["file_error"] == "download_size_differs_from_observed_attachment"
            assert not list(directory.iterdir())
    finally:
        store.close()


def test_chat_export_rejects_corrupt_existing_content(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    collector = Collector(store, vault)
    item = t.Message(1, t.PeerUser(11), datetime(2026, 11, 5, tzinfo=timezone.utc),
                     "Photo", media=t.MessageMediaPhoto(photo=photo(animated=False)))

    async def download(media, *, file, progress_callback, **options):
        file.write(CONTENT)
        return file

    collector.client = SimpleNamespace(download_media=download)
    directory = tmp_path / "downloads"
    directory.mkdir()
    destination = directory / hashlib.sha256(CONTENT).hexdigest()
    destination.write_bytes(b"changed")
    try:
        with pytest.raises(ValueError, match="existing_content_addressed_file_is_corrupt"):
            asyncio.run(collector.export_attachment(item, directory, "download"))
        assert destination.read_bytes() == b"changed"
        assert not list(directory.glob("part-*"))
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
