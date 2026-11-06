import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.tl import types

from tgwitness import chat_export, distributed_export, replica
from tgwitness import store as journal
from tgwitness.collector import Collector, message_record
from tgwitness.security import Vault
from tgwitness.store import Store
from test_distributed_export import CHAT, close_entries, coordinator, finished, message

OTHER = -1000000000043


def today():
    return datetime.now(timezone.utc).date().isoformat()


@pytest.fixture
def store(tmp_path):
    vault, events = Vault(tmp_path), Store(tmp_path)
    events.bind(vault)
    try:
        yield events
    finally:
        events.close()


def test_chat_titles_become_safe_file_names(store):
    day, override = today(), chr(0x202E)
    cases = {'../Scam: "Crypto" <VIP>' + override + "gpj.exe\n": "Scam_Crypto_VIP_gpj.exe",
             "Мошенники 2026": "Мошенники_2026", " Wallet\\drainer | support? ": "Wallet_drainer_support",
             "Ж" * 80: "Ж" * 50, None: "chat_" + str(CHAT), override + "..": "chat_" + str(CHAT)}
    for title, stem in cases.items():
        name = chat_export.archive_name(store, CHAT, title)
        assert name == stem + "_" + day + "_1.zip", (title, name)
        assert Path(name).name == name and len(name.encode()) < 255
        assert not any(c in name for c in '<>:"/\\|?*\n' + override)


def test_number_counts_todays_exports_of_the_same_chat(store, monkeypatch):
    store.append("chat_export.completed", {}, CHAT)
    store.append("chat_export.completed", {}, OTHER)
    with monkeypatch.context() as patch:
        patch.setattr(journal, "utcnow", lambda: (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(
            timespec="milliseconds"))
        store.append("chat_export.completed", {}, CHAT)
    assert chat_export.archive_name(store, CHAT, "Group") == "Group_" + today() + "_2.zip"
    assert chat_export.archive_name(store, OTHER, "Group") == "Group_" + today() + "_2.zip"
    assert chat_export.archive_name(store, -1000000000044, "Group") == "Group_" + today() + "_1.zip"


def test_distributed_exports_of_one_chat_are_numbered(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 5)])
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)
        try:
            names = []
            for _ in range(2):
                job = await finished(manager, await manager.start(CHAT, list(entries), "account0"))
                assert job["phase"] == "done", job
                names.append(job["filename"])
            assert names == ["Synthetic_group_" + today() + "_" + str(n) + ".zip" for n in (1, 2)]
            restarted = distributed_export.DistributedExport(manager.profiles)
            assert [job["filename"] for job in restarted.list_jobs()] == names[::-1]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_single_chat_export_names_its_archive(tmp_path, monkeypatch):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = Collector(store, vault)
        collector.client = SimpleNamespace(get_messages=AsyncMock(return_value=[]))
        collector.telegram_clock = AsyncMock(return_value={})
        collector.chat_profile = AsyncMock(return_value=({}, {}, {}))

        async def history(entity, scratch, record, media_dir, files):
            scratch.write_text("\n".join(json.dumps(message_record(message(i))) for i in (2, 1)), encoding="utf-8")
            return 2

        collector.stream_history = history
        monkeypatch.setattr(chat_export, "build_bundle", lambda scratch, meta, vault, output, *args: output.write_bytes(b"zip"))
        monkeypatch.setattr(replica, "outbox", lambda *args: None)
        try:
            for number in (1, 2):
                record = {"id": "single" + str(number), "chat_id": CHAT, "captured": 0}
                await collector.run_export(types.PeerChannel(42), {"title": "Scam / Support"}, record)
                assert record["phase"] == "done", record
                assert record["filename"] == "Scam_Support_" + today() + "_" + str(number) + ".zip", record
        finally:
            store.close()
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
