"""Failure cases found by the 2026-10-29 review, using isolated synthetic data."""
import asyncio
import base64
import io
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS

import pytest
from cryptography.exceptions import InvalidSignature
from telethon.errors import RpcCallFailError
from telethon.sessions import StringSession
from telethon.tl import functions, types

from tgwitness import replica
from tgwitness.collector import Collector
from tgwitness.evidence import checkpoint
from tgwitness.store import canonical
from tgwitness.telegram_client import WitnessClient
from tgwitness.verify import fingerprint
from tests.test_collector import CHAT, media_message, telegram_message
from tests.test_investigation import offer
from tests.test_recheck import RecheckClient, observing
from tests.test_scope import SHOP_BOT, message


@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("change", ["attachment", "keyboard_removed", "entities", "file_reference",
                                    "link_preview_loaded"])
def test_observable_message_versions(journal, live, change):
    async def run():
        store, vault = journal
        collector = await observing(store, vault)
        store.set_setting("capture", {"download_media": False})
        old, new = media_message(9, document_id=500), media_message(9, document_id=500)
        if change == "link_preview_loaded":
            when = datetime(2026, 1, 1, tzinfo=timezone.utc)
            old = telegram_message(9, "https://example.org", types.MessageMediaWebPage(
                webpage=types.WebPagePending(id=1, date=when, url="https://example.org")))
            new = telegram_message(9, "https://example.org", types.MessageMediaWebPage(
                webpage=types.WebPage(id=1, url="https://example.org", display_url="example.org", hash=5,
                                      title="Example")))
        elif change == "attachment":
            new = media_message(9, document_id=501)
        elif change == "keyboard_removed":
            old.reply_markup = offer().reply_markup
        elif change == "entities":
            new.entities = [types.MessageEntityBold(offset=0, length=1)]
        else:
            new.media.document.file_reference = b"refreshed-file-reference"
            new.media.document.access_hash += 1
        await collector.capture_message(old, "message.new", CHAT)
        RecheckClient.server = {9: new}
        if live:
            await collector.on_edit(NS(chat_id=CHAT, message=new))
            await collector.on_edit(NS(chat_id=CHAT, message=new))
        else:
            settings = {"messages": False, "edits": True, "deletions": False}
            await collector.recheck_chat(CHAT, settings)
            assert (await collector.recheck_chat(CHAT, settings))["edited"] == 0
        edits = [e for e in store.all_events() if e["kind"] == "message.edited"]
        assert len(edits) == (0 if change in ("file_reference", "link_preview_loaded") else 1)
        versions = store.chat_messages(CHAT)["messages"][0]["versions"]
        assert len(versions) == 1 + len(edits)
        if change == "keyboard_removed":
            assert store.message_state(CHAT, 9)["content"]["buttons"] is None
        await collector.stop()
    asyncio.run(run())


def test_background_scope_excludes_outgoing_but_advances_recheck(journal):
    async def run():
        store, vault = journal
        collector = await observing(store, vault)
        store.set_setting("scope", {"mode": "selected", "own_actions": False})
        await collector.capture_message(message(CHAT, 10, "incoming"), "message.new", CHAT)
        outgoing = message(CHAT, 11, "excluded", out=True)
        RecheckClient.server = {11: outgoing}
        result = await collector.recheck_chat(CHAT, {"messages": True, "membership": True,
                                                    "edits": True, "deletions": False})
        assert result["recovered"] == 0
        assert not store.message_state(CHAT, 11)["content"]
        assert store.get_setting("recheck_floor", {})[str(CHAT)] == 11
        assert (await collector.snapshot(CHAT, 20, origin="new_chat"))["captured"] == 0

        assert (await collector.snapshot(CHAT, 20))["captured"] == 1
        outgoing.message = "changed but excluded"
        result = await collector.recheck_chat(CHAT, {"messages": False, "edits": True, "deletions": False})
        assert result["edited"] == 0
        assert store.message_state(CHAT, 11)["content"]["text"] == "excluded"
        await collector.stop()
    asyncio.run(run())


def test_callback_rpc_has_one_attempt_without_changing_concurrent_read_retries(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault)
        await collector.ensure_route()
        assert isinstance(collector.make_client(123, "a" * 32), WitnessClient)
        client = WitnessClient(StringSession(), 123, "a" * 32, request_retries=1, raise_last_call_error=True)
        entered, release = asyncio.Event(), asyncio.Event()

        class Sender:
            def __init__(self, block=False):
                self.attempts, self.block = 0, block

            def send(self, request, ordered=False):
                self.attempts += 1
                async def respond():
                    if self.block:
                        entered.set()
                        await release.wait()
                    if self.attempts == 1:
                        raise RpcCallFailError(request)
                    return types.messages.BotCallbackAnswer(cache_time=0, message="ok")
                return asyncio.create_task(respond())

        action, read = Sender(True), Sender()
        callback = asyncio.create_task(client._call(action, functions.messages.GetBotCallbackAnswerRequest(
            types.InputPeerUser(SHOP_BOT, 1), 10, data=b"action")))
        await entered.wait()
        assert client._request_retries == 1
        reading = asyncio.create_task(client._call(read, functions.help.GetConfigRequest()))
        release.set()
        with pytest.raises(RpcCallFailError):
            await callback
        await reading
        assert action.attempts == 1
        assert read.attempts == 2
        assert client._request_retries == 1
    asyncio.run(run())


class MemoryS3:
    def __init__(self, objects):
        self.objects, self.downloads = objects, []

    async def list(self, prefix):

        for name, data in sorted(self.objects.items()):
            yield name, len(data)

    async def get(self, name, sink):
        self.downloads.append(name)
        await sink(self.objects[name])


def backup(monkeypatch, vault, objects):
    key = os.urandom(32)
    info = {"endpoint": "https://synthetic.invalid", "region": "test", "bucket": "test",
            "path_style": True, "prefix": "audit", "key": base64.b64encode(key).decode(),
            "fingerprint": fingerprint(vault.public_key)}
    storage = MemoryS3({name: b"".join(replica.encrypt(key, name, io.BytesIO(data).read, os.urandom(8)))
                        for name, data in objects.items()})
    monkeypatch.setattr(replica, "S3", lambda *args: storage)
    return info, storage


@pytest.mark.parametrize("name", ["audit/../outside.bin.tgwr", "audit/exports/../../outside.tgwr",
    "audit//outside.tgwr", "audit/exports/C:/outside.tgwr", "audit/exports/a:stream.tgwr",
    "audit/exports/..\\outside.tgwr", "audit/exports/CON.tgwr", "audit/exports/bad. /file.tgwr",
    "other/exports/outside.tgwr", "audit/exports/\\\\host\\file.tgwr"])
def test_restore_rejects_paths_before_downloading(journal, tmp_path, monkeypatch, name):
    _, vault = journal
    info, storage = backup(monkeypatch, vault, {name: b"untrusted"})
    out = tmp_path / "restored"
    with pytest.raises(ValueError):
        asyncio.run(replica.restore(info, "fake", "fake", out))
    assert not storage.downloads
    assert list(out.iterdir()) == []
    assert not (tmp_path / "outside.bin.download").exists()


def test_restore_rejects_existing_output_and_link_escapes(journal, tmp_path, monkeypatch):
    _, vault = journal
    info, storage = backup(monkeypatch, vault, {})
    out = tmp_path / "restored"
    out.mkdir()
    (out / "keep").write_text("original")
    with pytest.raises(ValueError, match="empty"):
        asyncio.run(replica.restore(info, "fake", "fake", out))
    assert (out / "keep").read_text() == "original"
    assert not storage.downloads


    with TemporaryDirectory(prefix="tgwitness-restore-links-") as temporary:
        root = Path(temporary).resolve()
        linked, outside = root / "restore", root / "outside"
        linked.mkdir()
        outside.mkdir()
        try:
            (linked / "exports").symlink_to(outside, target_is_directory=True)
        except OSError:
            if os.name != "nt":
                raise
            subprocess.run(["cmd", "/c", "mklink", "/J", str(linked / "exports"), str(outside)],
                           check=True, capture_output=True)
        with pytest.raises(ValueError):
            replica.restore_path(linked, "audit", "audit/exports/keep.tgwr")


@pytest.mark.parametrize("defect", ["truncated", "range", "ciphertext", "signature", None])
def test_restore_authenticates_complete_archive_before_publishing(journal, tmp_path, monkeypatch, defect):
    store, vault = journal
    first = store.append("message.new", {"text": "first"}, CHAT, 1)
    second = store.append("message.new", {"text": "second"}, CHAT, 2)
    cp = checkpoint(store, vault)
    if defect == "signature":
        cp["statement"]["created_at"] = "tampered"
    journal_data = canonical(first) + b"\n"
    if defect not in ("truncated", "range"):
        journal_data += canonical(second) + b"\n"
    last = "1" if defect == "truncated" else "2"
    journal_name = "audit/journal/000000000001-" + last.zfill(12) + ".jsonl.tgwr"
    objects = {journal_name: journal_data, "audit/checkpoints/checkpoint-000000000002.json.tgwr": canonical(cp)}
    info, storage = backup(monkeypatch, vault, objects)
    if defect == "ciphertext":
        storage.objects[journal_name] = b"invalid encrypted object"
    out = tmp_path / "restored"
    if defect:
        with pytest.raises((ValueError, InvalidSignature)):
            asyncio.run(replica.restore(info, "fake", "fake", out))
        assert list(out.iterdir()) == []
    else:
        result = asyncio.run(replica.restore(info, "fake", "fake", out))
        assert result["events"] == 2 and result["checkpoints_verified"] == 1
        assert len((out / "events.jsonl").read_bytes().splitlines()) == 2


@pytest.mark.parametrize("offset,mode,valid", [(0, "COMPLIANCE", True), (60, "COMPLIANCE", True),
    (-1, "COMPLIANCE", True), (-60, "COMPLIANCE", False), (0, "GOVERNANCE", False),
    (None, "COMPLIANCE", False), ("invalid", "COMPLIANCE", False), ("expired", "COMPLIANCE", False),
    ("naive", "COMPLIANCE", False)])
def test_object_lock_must_cover_requested_deadline(offset, mode, valid):
    settings = {"retention_days": 365, "retention_mode": "COMPLIANCE"}
    headers = replica.lock_headers(settings)
    expected = datetime.fromisoformat(headers["x-amz-object-lock-retain-until-date"])
    if isinstance(offset, int):
        returned = (expected + timedelta(seconds=offset)).isoformat()
    else:
        returned = {None: None, "invalid": "not a date", "expired": "2000-01-01T00:00:00Z",
                    "naive": expected.replace(tzinfo=None).isoformat()}[offset]

    class Storage:
        async def object_lock(self):
            return {"enabled": True, "default_days": None}

        async def retention(self, name):
            return {"mode": mode, "retain_until": returned}

    result = asyncio.run(replica.lock_report(Storage(), "object", settings, headers))
    assert result["verified"] is valid
    assert datetime.fromisoformat(result["requested"]["retain_until"]) == expected


def test_bucket_default_retention_is_checked_from_upload_time():
    started = datetime.now(timezone.utc) - timedelta(minutes=20)
    class Storage:
        async def object_lock(self):
            return {"enabled": True, "default_days": 3, "default_mode": "COMPLIANCE"}

        async def retention(self, name):
            return {"mode": "COMPLIANCE", "retain_until": (started + timedelta(days=3)).isoformat()}
    result = asyncio.run(replica.lock_report(Storage(), "object", {"retention_days": 0}, {}, started))
    assert result["verified"] is True
