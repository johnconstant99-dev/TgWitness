"""Deterministic preservation and read-receipt tests; no Telegram connections."""
import asyncio
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FileReferenceExpiredError
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import ephemeral, history, message_details, pdf_report, report, telegram_client
from tgwitness.collector import Collector, describe_message
from tgwitness.export_preflight import preview_capture
from tgwitness.monitoring import normalize_capture
from tgwitness.security import Vault
from tgwitness.store import Store, utcnow

CONTENT = b"synthetic ephemeral attachment"
WHEN = datetime(2026, 11, 5, tzinfo=timezone.utc)
CHAT = 77001


def message(kind="photo", ttl=10, *, empty=False, mid=1, size=None):
    size = len(CONTENT) if size is None else size
    if kind == "photo":
        media = t.MessageMediaPhoto(photo=None if empty else t.Photo(
            123, 456, b"ref", WHEN, [t.PhotoSize("x", 20, 20, size)], 2), ttl_seconds=ttl)
    else:
        attributes = [t.DocumentAttributeVideo(2, 20, 20)] if kind == "video" else []
        media = t.MessageMediaDocument(document=None if empty else t.Document(
            321, 654, b"ref", WHEN, "video/mp4" if kind == "video" else "application/octet-stream",
            size, 2, attributes), ttl_seconds=ttl)
    return t.Message(mid, t.PeerUser(CHAT), date=WHEN, message="", from_id=t.PeerUser(CHAT),
                     media=media, media_unread=True)


@pytest.fixture
def workspace(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.set_target(CHAT, "Synthetic private chat", "private", True)
    store.set_setting("account", {"id": 12345})
    collector = Collector(store, vault)
    collector.client = SimpleNamespace(get_messages=AsyncMock())

    async def download(media, file, progress_callback, *, thumb=None):
        if isinstance(media, t.MessageMediaPhoto):
            assert thumb == "x"
        file.write(CONTENT)
        await progress_callback(len(CONTENT), len(CONTENT))
        return file

    collector.client.download_media = AsyncMock(side_effect=download)
    collector.export_claim = "test"
    yield collector, store, vault
    store.close()


async def drain(collector, lane="all"):
    await collector.download_worker(lane, owner="test")


@pytest.mark.parametrize("kind", ["photo", "video", "document"])
@pytest.mark.parametrize("ttl", [10, ephemeral.VIEW_ONCE])
def test_saved_file_ttl_signature_and_viewing_label(workspace, kind, ttl):
    c, store, vault = workspace

    async def scenario():
        source = await c.capture_message(message(kind, ttl), "message.new", CHAT)
        await drain(c, "ephemeral")
        saved = store.events(kind="media.saved")[0]
        assert saved["payload"]["message_event"] == source["seq"]
        facts = saved["payload"]["ephemeral_media"]
        assert facts == {"ttl_seconds": ttl, "mode": "view_once" if ttl == ephemeral.VIEW_ONCE else "timer",
                         "availability": "available_at_observation", "human_viewing": "not_established", "outcome": "saved"}
        assert saved["payload"]["media_sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert (store.root / "media" / saved["payload"]["media_sha256"]).read_bytes() == CONTENT
        assert source["payload"]["raw"]["media_unread"] is True
        assert source["payload"]["raw"]["media"]["ttl_seconds"] == ttl
        assert store.verify(vault.public_key)["events"] >= 2
        c.client.get_messages.assert_not_awaited()
        assert "not establish" in report.record_html(saved, report.Words("en"), {}, {}, False)
        details = message_details.details(source["payload"]["raw"])
        text = " ".join(pdf_report.details_lines(report.Words("en"), details))
        assert "not establish" in text
        if ttl == ephemeral.VIEW_ONCE:
            assert "View-once" in text and str(ttl) not in text

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["photo", "video", "document"])
def test_empty_media_is_signed_unavailable_even_when_downloads_disabled(workspace, kind):
    c, store, _ = workspace
    store.set_setting("capture", {"download_media": False, "record_disabled_media": False})

    async def scenario():
        await c.capture_message(message(kind, empty=True), "message.new", CHAT)
        await drain(c)
        result = store.events(kind="media.skipped")[0]["payload"]
        assert result["reason"] == "ephemeral_attachment_unavailable_at_observation"
        assert result["ephemeral_media"]["outcome"] == "unavailable"
        assert result["ephemeral_media"]["human_viewing"] == "not_established"
        assert not store.media_stats()
        assert not store.events(kind="coverage.gap")
        c.client.download_media.assert_not_awaited()

    asyncio.run(scenario())


def test_bypasses_type_and_duration_rules_but_can_be_disabled(workspace):
    c, store, _ = workspace
    settings = {"types": {"video": {"enabled": False, "max_seconds": 1, "max_mb": 2}}}
    store.set_setting("capture", settings)

    async def scenario():
        await c.capture_message(message("video"), "message.new", CHAT)
        await drain(c)
        assert store.media_stats() == {"done": 1}
        override = store.events(kind="message.new")[0]["payload"]["media_capture"]["rule_override"]
        assert override["overridden"][0] == "type_not_collected" and "size ceiling" in override["still_applied"]
        store.set_setting("capture", {**settings, "preserve_ephemeral_media": False})
        await c.capture_message(message("video", mid=2), "message.new", CHAT)
        await drain(c)
        assert store.events(kind="media.skipped")[0]["payload"]["ephemeral_media"]["outcome"] == "not_saved"
        assert c.client.download_media.await_count == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("settings,size", [
    ({"download_media": False}, None), ({"media_action": "exclude"}, None),
    ({"max_media_mb": 1}, 2 * 1024**2), ({"media_action": "hashes_only"}, None),
])
def test_no_bytes_for_explicit_exclusions_or_size_limit(workspace, settings, size):
    c, store, _ = workspace
    store.set_setting("capture", settings)
    c.attachment_hashes = AsyncMock(return_value={"status": "complete"})

    async def scenario():
        await c.capture_message(message(size=size), "message.new", CHAT)
        await drain(c)
        c.client.download_media.assert_not_awaited()
        outcome = next(e for e in store.all_events() if e["kind"].startswith("media."))["payload"]
        assert outcome["ephemeral_media"]["outcome"] in ("not_saved", "hashed")
        assert outcome["retry_warning"] == ephemeral.RETRY_NOTE
        if size:
            assert outcome["reason"] == "above the size limit of the attachment settings"
            assert "settings changed" not in outcome.get("meaning", "")
        assert not store.events(kind="media.saved")

    asyncio.run(scenario())


def test_saved_observation_survives_expired_reference_and_missing_media(workspace):
    c, store, _ = workspace
    c.client.download_media.side_effect = FileReferenceExpiredError(None)
    c.client.get_messages.return_value = message(empty=True)

    async def scenario():
        original = await c.capture_message(message(), "message.new", CHAT)
        await drain(c)
        result = store.events(kind="media.failed")[0]["payload"]
        assert result["reason"] == "original_attachment_no_longer_available"
        assert result["ephemeral_media"]["availability"] == "available_at_observation"
        assert result["ephemeral_media"]["outcome"] == "not_saved"
        assert store.events(before=original["seq"] + 1, limit=1)[0] == original
        assert not list((store.root / "media").iterdir())

    asyncio.run(scenario())


def test_queue_cancellation_retains_ephemeral_outcome(workspace):
    c, store, _ = workspace
    original = asyncio.run(c.capture_message(message(), "message.new", CHAT))
    assert store.clear_media_queue(original["seq"]) == 1
    assert store.events(kind="media.skipped")[0]["payload"]["ephemeral_media"]["outcome"] == "not_saved"


def test_outcomes_for_old_signed_observations_derive_ttl_from_raw(workspace):
    _, store, _ = workspace
    source = store.append("message.snapshot", describe_message(message()), CHAT, 1)
    assert store.ephemeral_outcome(source["seq"], "not_saved")["ephemeral_media"]["ttl_seconds"] == 10


def test_immediate_lane_works_during_bulk_download_and_messages_first(workspace):
    c, store, _ = workspace

    async def scenario():
        bulk_started, release_bulk, saved = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def download(media, file, progress_callback, *, thumb=None):
            if getattr(media, "ttl_seconds", None) is None:
                bulk_started.set()
                await release_bulk.wait()
            else:
                file.write(CONTENT)
                saved.set()
                return file
        c.client.download_media.side_effect = download
        c.running = True
        await c.capture_message(message("document", None, size=3 * 1024**2), "message.new", CHAT)
        bulk = asyncio.create_task(c.download_worker("bulk"))
        urgent = None
        try:
            await asyncio.wait_for(bulk_started.wait(), 2)
            store.set_setting("capture", {"messages_first": True})
            urgent = asyncio.create_task(c.download_worker("ephemeral"))
            await c.capture_message(message(mid=2), "message.new", CHAT)
            await asyncio.wait_for(saved.wait(), 2)
            while not store.events(kind="media.saved"):
                await asyncio.sleep(.01)
            assert not bulk.done() and not release_bulk.is_set()
        finally:
            c.running = False
            for task in (bulk, urgent):
                if task:
                    task.cancel()
            await asyncio.gather(*(task for task in (bulk, urgent) if task), return_exceptions=True)
        assert store.events(kind="media.saved")[0]["message_id"] == 2

    asyncio.run(scenario())


def test_history_saves_ephemeral_before_next_page_without_waiting_for_ordinary_jobs(workspace, monkeypatch):
    c, store, vault = workspace
    store.set_setting("capture", {"messages_first": True})
    monkeypatch.setattr(history, "PAGE_SIZE", 2)
    c.resolve_target = AsyncMock(return_value=t.InputPeerUser(CHAT, 1))

    async def get_page(entity, limit, offset_id):
        if not offset_id:
            return [message(mid=4), message(ttl=None, mid=3)]
        assert len(store.events(kind="media.saved")) == 1
        assert store.events(kind="media.saved")[0]["message_id"] == 4
        assert store.media_stats() == {"done": 1, "queued": 1}
        return []

    c.client.get_messages.side_effect = get_page

    async def scenario():
        c.export_claim = "history:test"
        c.history.create_run("test", utcnow(), 12345, store.targets(True))
        await asyncio.wait_for(c.history.task, 3)
        assert c.history.status()["phase"] == "complete"
        assert store.media_stats() == {"done": 2}
        store.verify(vault.public_key)

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["photo", "document"])
def test_explicit_empty_constructors_are_unavailable(kind):
    item = message(kind)
    setattr(item.media, kind, t.PhotoEmpty(123) if kind == "photo" else t.DocumentEmpty(321))
    assert ephemeral.describe(item.media)["availability"] == "unavailable_at_observation"


@pytest.mark.parametrize("ttl", [None, 0, -1])
def test_disabled_or_absent_ttl_is_not_ephemeral(ttl):
    assert ephemeral.describe(message(ttl=ttl).media) is None
    ordinary = message(ttl=ttl)
    ordinary.ttl_period = 60
    assert "ephemeral_media" not in message_details.details(ordinary.to_dict())["media_info"]


@pytest.mark.parametrize("request_class", telegram_client._READ_RECEIPTS)
@pytest.mark.parametrize("wrapper", ["direct", "batch", "takeout", "nested", "generator"])
def test_no_read_receipt_reaches_transport_even_in_wrappers_or_batches(monkeypatch, request_class, wrapper):
    client = object.__new__(telegram_client.WitnessClient)
    transport = AsyncMock()
    monkeypatch.setattr(telegram_client.TelegramClient, "_call", transport)
    blocked = object.__new__(request_class)
    allowed = f.updates.GetStateRequest()
    request = {"direct": blocked, "batch": [allowed, blocked],
               "takeout": f.InvokeWithTakeoutRequest(1, blocked),
               "nested": f.InvokeWithoutUpdatesRequest(f.InvokeWithTakeoutRequest(1, blocked)),
               "generator": (x for x in [allowed, blocked])}[wrapper]
    with pytest.raises(telegram_client.ReadReceiptBlocked):
        asyncio.run(client._call(None, request))
    transport.assert_not_awaited()


def test_real_telethon_read_helper_is_blocked(monkeypatch):
    client = telegram_client.WitnessClient(None, 123, "a" * 32)
    transport = AsyncMock()
    monkeypatch.setattr(telegram_client.TelegramClient, "_call", transport)
    async def scenario():
        for contents in (False, True):
            with pytest.raises(telegram_client.ReadReceiptBlocked):
                await client.send_read_acknowledge(t.InputPeerUser(CHAT, 1), max_id=1, clear_mentions=contents)
    asyncio.run(scenario())
    transport.assert_not_awaited()


@pytest.mark.parametrize("kind", ["photo", "video", "document"])
def test_real_telethon_downloader_fetches_view_once_bytes_without_read_receipts(monkeypatch, kind):
    client = telegram_client.WitnessClient(None, 123, "a" * 32)
    client.session.set_dc(2, "127.0.0.1", 443)
    sent = []

    async def transport(self, sender, request, ordered=False, flood_sleep_threshold=None):
        sent.append(request)
        assert isinstance(request, f.upload.GetFileRequest)
        return t.upload.File(t.storage.FileJpeg(), 0, CONTENT)

    monkeypatch.setattr(telegram_client.TelegramClient, "_call", transport)

    async def scenario():
        output = io.BytesIO()
        await client.download_media(message(kind, ephemeral.VIEW_ONCE).media, file=output)
        assert output.getvalue() == CONTENT
        assert len(sent) == 1

    asyncio.run(scenario())


def test_normalization_retains_setting():
    assert normalize_capture(None)["preserve_ephemeral_media"] is True
    assert normalize_capture({"preserve_ephemeral_media": False})["preserve_ephemeral_media"] is False


def test_preflight_counts_ttl_bytes_with_excluded_type(workspace):
    c, store, _ = workspace
    c.resolve_target = AsyncMock(return_value=t.InputPeerUser(CHAT, 1))
    c.client.get_messages.return_value = [message()]
    settings = normalize_capture({"types": {"photo": {"enabled": False, "max_mb": 1}}})
    result = asyncio.run(preview_capture(c, CHAT, settings, 300))
    assert result["sample"]["known_download_bytes"] == len(CONTENT)
    c.client.download_media.assert_not_awaited()


@pytest.mark.parametrize("transport", ["standard", "takeout"])
def test_merged_backfill_preserves_ttl_using_the_selected_transport(tmp_path, transport):
    from tools.test_history_backfill import make, finished, media_message
    from tgwitness.history_options import HistoryOptions

    async def scenario():
        item = media_message(5)
        item.media.ttl_seconds = ephemeral.VIEW_ONCE
        c, store = make(tmp_path, [item])
        store.set_setting("capture", {"messages_first": True,
            "types": {"document": {"enabled": False, "max_mb": 1}}})
        try:
            await c.history.start(HistoryOptions(transport=transport, admin_log=False))
            state = await finished(c.history)
            assert state["phase"] == "complete" and state["media"] == {"done": 1}
            saved = store.events(kind="media.saved")[0]["payload"]
            assert saved["ephemeral_media"]["mode"] == "view_once"
            assert saved["ephemeral_media"]["outcome"] == "saved"
            assert (store.root / "media" / saved["media_sha256"]).read_bytes() == b"data"
            transfers = [call for call in c.client.rpc if isinstance(call, tuple)]
            assert transfers == [("media", 999 if transport == "takeout" else None)]
        finally:
            store.close()

    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
