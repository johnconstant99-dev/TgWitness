"""History must survive slow attachments, process restart and queue tampering."""
import asyncio
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.account_export import AccountExport
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_account_export
from tools.demo_account_export import SyntheticCollector
from tools.test_file_hash_export import CONTENT, ExportTransport, HashClient
from tgwitness import file_hashes


@pytest.mark.parametrize("interruption", ["pause", "retry"])
def test_attachment_progress_is_live_uncommitted_and_resets(tmp_path, interruption):
    from unittest.mock import AsyncMock

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.restore = AsyncMock()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered, release = asyncio.Event(), asyncio.Event()
        attempts = []

        class Network(ExportTransport):
            async def download(self, media, stream, progress, task):
                attempts.append(export.public()["transfer"])
                if len(attempts) == 1:
                    stream.write(CONTENT[:2])
                    await progress(2, len(CONTENT))
                    entered.set()
                    await release.wait()
                    raise ConnectionError("Retry the interrupted transfer")
                stream.write(CONTENT)
                await progress(len(CONTENT), len(CONTENT))
                return stream

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(entered.wait(), 10)
            state = export.public()
            assert state["transfer"]["received_bytes"] == 2
            assert state["transfer"]["total_bytes"] == len(CONTENT)
            assert state["counts"]["bytes_saved"] == 0
            export.persist()
            assert "transfer" not in json.loads((export.directory(job["id"]) / "status.json").read_bytes())
            if interruption == "pause":
                await export.pause(job["id"])
                assert export.public()["transfer"] is None
                assert not list((export.directory(job["id"]) / "media").glob("pending-*"))
                await export.resume(job["id"])
            else:
                release.set()
            await asyncio.wait_for(export.task, 10)
            assert len(attempts) == 2
            assert attempts[1]["received_bytes"] == 0
            assert attempts[1]["attempt"] == (1 if interruption == "pause" else 2)
            assert collector.restore.await_count == (0 if interruption == "pause" else 1)
            assert export.public()["transfer"] is None
            assert verify_account_export(export.result_path(job["id"]), fingerprint(vault.public_key))["complete_within_scope"]
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


def test_finished_approval_wait_stays_partial_on_resume(tmp_path):
    from telethon.errors import TakeoutInitDelayError

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)

        class Waiting(ExportTransport):
            async def open(self):
                raise TakeoutInitDelayError(None, capture=86400)

        export.transport_factory = Waiting
        try:
            job = await export.start({"transport": "takeout"})
            await export.task
            saved = await export.finalize_partial(job["id"], "Approval did not fit the available time.")
            assert saved["phase"] == "partial" and not saved["coverage"]["inventory_complete"]
            original = export.result_path(job["id"]).read_bytes()
            resumed = await export.resume(job["id"])
            assert resumed["phase"] == "partial" and resumed["ready"]
            assert export.result_path(job["id"]).read_bytes() == original
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("transport", ["regular", "takeout"])
@pytest.mark.parametrize("action", ["download", "hashes_only"])
def test_all_history_is_durable_before_attachment_and_resume_never_refetches(tmp_path, transport, action):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered, hold = asyncio.Event(), asyncio.Event()
        fetched = []
        resumed = False

        class Network(ExportTransport):
            async def discover(self):
                chats, tasks, gaps = await super().discover()
                return [chats[0], {**chats[0], "id": 22}], [tasks[0], {**tasks[0], "id": "messages:22:0", "chat_id": 22}], gaps

            async def page(self, task, cursor):
                assert not resumed, "Resume must use frozen history, even if Telegram messages have changed"
                fetched.append(task["chat_id"])
                rows, after, terminal = await super().page(task, cursor)
                return [({**row, "chat_id": task["chat_id"]}, media) for row, media in rows], after, terminal

            async def download(self, media, stream, progress, task):
                entered.set()
                await hold.wait()
                stream.write(CONTENT)
                return stream

            async def hashes(self, media, task):
                entered.set()
                await hold.wait()
                return await file_hashes.collect(HashClient(), media)

        export.transport_factory = Network
        try:
            job = await export.start({"transport": transport, "media_action": action,
                "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(entered.wait(), 10)
            assert fetched == [11, 22]
            assert export.public()["acquisition"]["messages_preserved"] == 4
            directory = export.directory(job["id"])
            preserved = {p.name: p.read_bytes() for p in (directory / "history-pages").glob("*.json")}
            assert sum(len(json.loads(data)["statement"]["rows"]) for data in preserved.values()) == 4
            assert all(b"private-reference" not in data for data in preserved.values())
            await export.pause(job["id"])
            export = AccountExport(collector, store, vault)
            export.transport_factory = Network
            resumed = True
            hold.set()
            await export.resume(job["id"])
            await asyncio.wait_for(export.task, 10)
            assert export.public()["phase"] == "done", export.public()
            assert preserved == {p.name: p.read_bytes() for p in (directory / "history-pages").glob("*.json")}
            result = export.result_path(job["id"])
            assert verify_account_export(result, fingerprint(vault.public_key))["counts"]["messages"] == 4
            with zipfile.ZipFile(result) as archive:
                assert not any(name.startswith(("history-pages/", "attachment-queue/")) for name in archive.namelist())
                assert all(b"private-reference" not in archive.read(name) for name in archive.namelist())
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("action", ["download", "hashes_only"])
@pytest.mark.parametrize("custom_emoji", [False, True])
def test_finish_keeps_attachments_completed_before_the_page_was_sealed(tmp_path, action, custom_emoji):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered = asyncio.Event()
        calls = 0

        class Network(ExportTransport):
            async def page(self, task, cursor):
                rows, after, terminal = await super().page(task, cursor)
                for row, media in rows:
                    media.id = row["id"]
                    if custom_emoji:
                        row["entities"] = [{"_": "MessageEntityCustomEmoji", "document_id": row["id"]}]
                if custom_emoji:
                    rows = [(row, None) for row, media in rows]
                return rows, after, terminal

            async def extra_media(self, row, task):
                if not custom_emoji:
                    return []
                from telethon.tl import types
                from tools.test_file_hash_export import document
                media = document()
                media.id = row["id"]
                media.attributes = [types.DocumentAttributeCustomEmoji(alt="test", stickerset=types.InputStickerSetEmpty())]
                return [media]

            async def acquire(self):
                nonlocal calls
                calls += 1
                if calls == 2:
                    entered.set()
                    await asyncio.Event().wait()

            async def download(self, media, stream, progress, task):
                await self.acquire()
                stream.write(CONTENT)
                return stream

            async def hashes(self, media, task):
                await self.acquire()
                return await file_hashes.collect(HashClient(), media)

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "media_action": action,
                "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(entered.wait(), 10)
            assert not export.receipts
            await export.finalize_partial(job["id"], "runner_deadline")
            result = verify_account_export(export.result_path(job["id"]), fingerprint(vault.public_key))
            assert result["counts"]["messages"] == 2 and not result["complete_within_scope"]
            assert result["counts"]["media_saved" if action == "download" else "media_hashed"] == 1
            assert result["counts"]["media_skipped"] == 1
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


def test_enrichment_pages_are_bounded_and_resume_inside_a_frozen_network_page(tmp_path):
    from tools.test_file_hash_export import document

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered, resume = asyncio.Event(), asyncio.Event()
        calls, fetched = 0, 0

        class Network(ExportTransport):
            async def discover(self):
                chats, tasks, gaps = await super().discover()
                tasks[0].update(cursor_start=26, newest_message_id=25)
                return chats, tasks, gaps

            async def page(self, task, cursor):
                nonlocal fetched
                fetched += 1
                rows = []
                for identifier in range(25, 0, -1):
                    media = document()
                    media.id = identifier
                    rows.append(({"category": "messages", "id": identifier, "chat_id": 11, "from_id": 12,
                        "outgoing": False, "date": "2026-11-04T00:00:00+00:00", "text": "synthetic"}, media))
                return rows, 1, True

            async def hashes(self, media, task):
                nonlocal calls
                calls += 1
                if calls == 12:
                    entered.set()
                    await resume.wait()
                return await file_hashes.collect(HashClient(), media)

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "media_action": "hashes_only",
                "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(entered.wait(), 10)
            assert len(export.receipts) == 1
            await export.pause(job["id"])
            export = AccountExport(collector, store, vault)
            export.transport_factory = Network
            resume.set()
            await export.resume(job["id"])
            await asyncio.wait_for(export.task, 10)
            assert export.public()["ready"], export.public()
            assert fetched == 1 and calls == 26
            verified = verify_account_export(export.result_path(job["id"]))
            assert verified["counts"]["messages"] == 25 and verified["complete_within_scope"]
            assert [e["statement"]["count"] for e in export.receipts] == [10, 10, 5]
            assert export.public()["counts"]["messages_seen"] == 25
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


def test_packaging_reserve_stops_history_before_consuming_archive_space(tmp_path, monkeypatch):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        pressure = False

        class Network(ExportTransport):
            async def page(self, task, cursor):
                nonlocal pressure
                if cursor < task["cursor_start"]:
                    pressure = True
                    return [], cursor, True
                rows, after, terminal = await super().page(task, cursor)
                return rows, after, False

        monkeypatch.setattr(export, "storage_pressure", lambda *args, **kwargs: pressure)
        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "media_action": "exclude",
                "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(export.task, 10)
            assert export.public()["phase"] == "paused" and "disk" in export.public()["error"]
            assert export.public()["acquisition"]["messages_preserved"] == 2
            await export.finalize_partial(job["id"], "storage_limit")
            result = verify_account_export(export.result_path(job["id"]))
            assert result["counts"]["messages"] == 2 and not result["complete_within_scope"]
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("stop_at", ["attachment", "history", "approval"])
def test_deadline_finishes_with_all_preserved_messages_and_explicit_gaps(tmp_path, stop_at):
    from telethon import errors

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered = asyncio.Event()

        class Network(ExportTransport):
            async def open(self):
                if stop_at == "approval":
                    entered.set()
                    raise errors.TakeoutInitDelayError(None, capture=3600)

            async def page(self, task, cursor):
                if cursor < task["cursor_start"]:
                    entered.set()
                    await asyncio.Event().wait()
                rows, after, terminal = await super().page(task, cursor)
                return rows, after, stop_at != "history"

            async def hashes(self, media, task):
                entered.set()
                await asyncio.Event().wait()

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "takeout", "media_action": "hashes_only",
                "include_profile": False, "include_contacts": False, "export_format": "telegram_both"})
            await asyncio.wait_for(entered.wait(), 10)
            result = await export.finalize_partial(job["id"], "runner_deadline")
            assert result["ready"] and result["phase"] == "partial", result
            path = export.result_path(job["id"])
            verified = verify_account_export(path, fingerprint(vault.public_key))
            assert verified["counts"]["messages"] == (0 if stop_at == "approval" else 2)
            assert not verified["complete_within_scope"]
            with zipfile.ZipFile(path) as archive:
                native = json.loads(archive.read("result.json"))
                assert len(native["chats"]["list"]) == (0 if stop_at == "approval" else 1)
                assert "export_results.html" in archive.namelist()
                assert not any(n.startswith("attachment-queue/") for n in archive.namelist())
            before = path.read_bytes()
            await export.finalize_partial(job["id"], "duplicate_finish")
            assert path.read_bytes() == before
        finally:
            await export.close()
            store.close()
    asyncio.run(run())


@pytest.mark.parametrize("tamper", ["history", "queue", "rollback"])
def test_tampered_staged_pages_never_become_a_successful_export(tmp_path, tamper):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        entered = asyncio.Event()

        class Network(ExportTransport):
            async def hashes(self, media, task):
                entered.set()
                await asyncio.Event().wait()

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "media_action": "hashes_only",
                "include_profile": False, "include_contacts": False})
            await asyncio.wait_for(entered.wait(), 10)
            await export.pause(job["id"])
            directory = export.directory(job["id"])
            page = directory / "history-pages/00000001.json"
            if tamper == "history":
                value = json.loads(page.read_bytes())
                value["statement"]["rows"][0]["text"] = "Changed after acquisition"
                page.write_text(json.dumps(value))
            elif tamper == "rollback":
                page.unlink()
            else:
                queue = directory / "attachment-queue/00000001.enc"
                queue.write_bytes(b"corrupt" + queue.read_bytes()[7:])
            await export.resume(job["id"])
            await asyncio.wait_for(export.task, 10)
            assert export.public()["phase"] == "failed"
            assert not export.public()["ready"]
        finally:
            await export.close()
            store.close()
    asyncio.run(run())
