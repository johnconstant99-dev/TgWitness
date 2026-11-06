import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.tl import types

from tgwitness import distributed_export
from tgwitness.verify import fingerprint, verify_chat_export
from test_distributed_export import CHAT, Client, close_entries, finished, message, workspace

OTHER = -1000000000043


class CountedClient(Client):
    async def get_messages(self, entity, limit=None, offset_date=None, ids=None):
        if limit == 0:
            return SimpleNamespace(total=len(self.messages))
        return await super().get_messages(entity, limit=limit, offset_date=offset_date, ids=ids)


def channel(number, title):
    return types.Channel(id=number, title=title, photo=types.ChatPhotoEmpty(), date=datetime.now(timezone.utc),
                         megagroup=True, access_hash=1)


def other(mid):
    row = message(mid)
    row.peer_id = types.PeerChannel(43)
    return row


def registry(tmp_path, first=range(1, 9), second=range(1, 7), count=4):
    chats = {CHAT: (channel(42, "Synthetic group"), [message(i) for i in first]),
             OTHER: (channel(43, "Second group"), [other(i) for i in second])}
    entries = {}
    for i in range(count):
        name = "account" + str(i)
        chat = CHAT if i < count // 2 else OTHER
        peer, rows = chats[chat]
        app = workspace(tmp_path / name)
        c = app.state.collector
        c.client = CountedClient(rows)
        c.restore = AsyncMock()
        c.resolve_for_export = AsyncMock(return_value=peer)
        c.chat_profile = AsyncMock(return_value=({}, {"role": "member"}, []))
        c.dialog_cache = {chat: {"kind": "supergroup", "title": peer.title, "entity": peer}}
        entries[name] = {"app": app, "label": name}
    manager = distributed_export.DistributedExport(SimpleNamespace(entries=entries, app=entries["account0"]["app"]))
    return manager, entries


def collector(entries, name):
    return entries[name]["app"].state.collector


@pytest.fixture(autouse=True)
def small_chunks(monkeypatch):
    monkeypatch.setattr(distributed_export, "CHUNK", 2)
    monkeypatch.setattr(distributed_export.replica, "outbox", lambda *args: None)


def test_two_exports_on_different_accounts_run_at_the_same_time(tmp_path):
    async def scenario():
        manager, entries = registry(tmp_path)
        for name in ("account0", "account1"):
            collector(entries, name).client.block = asyncio.Event()
        try:
            first = await manager.start(CHAT, ["account0", "account1"], "account0")
            await asyncio.wait_for(collector(entries, "account0").client.blocked.wait(), 5)
            second = await manager.start(OTHER, ["account2", "account3"], "account2")
            assert manager.runs[first["id"]].active() and manager.runs[second["id"]].active()
            assert [collector(entries, "account" + str(i)).export_claim for i in range(4)] == \
                [first["id"], first["id"], second["id"], second["id"]]
            assert all(manager.uses("account" + str(i)) for i in range(4))
            assert manager.public(chat_id=CHAT)["id"] == first["id"]
            assert manager.public(chat_id=OTHER)["id"] == second["id"]

            done = await finished(manager, second)
            assert done["phase"] == "done", done
            assert manager.runs[first["id"]].active() and manager.public(first["id"])["phase"] == "running"
            assert collector(entries, "account2").export_claim is None
            assert collector(entries, "account0").export_claim == first["id"]

            for name in ("account0", "account1"):
                collector(entries, name).client.block.set()
            assert (await finished(manager, first))["phase"] == "done"
            for state, lead, count in ((first, "account0", 8), (second, "account2", 6)):
                key = entries[lead]["app"].state.vault.public_key
                checked = verify_chat_export(manager.result_path(state["id"]), fingerprint(key))
                assert checked["message_count"] == count, checked
            assert not manager.reserved
            assert all(collector(entries, "account" + str(i)).export_claim is None for i in range(4))
        finally:
            for name in ("account0", "account1"):
                collector(entries, name).client.block.set()
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_an_account_of_a_running_export_cannot_join_another(tmp_path):
    async def scenario():
        manager, entries = registry(tmp_path)
        collector(entries, "account1").client.block = asyncio.Event()
        try:
            first = await manager.start(CHAT, ["account0", "account1"], "account0")
            with pytest.raises(ValueError, match="account1: account is busy"):
                await manager.start(OTHER, ["account1", "account3"], "account2")
            assert collector(entries, "account2").export_claim is None
            assert collector(entries, "account3").export_claim is None
            assert not manager.uses("account2") and not manager.uses("account3")
            assert collector(entries, "account1").export_claim == first["id"]
            assert len(manager.runs) == 1 and len(manager.list_jobs()) == 1
        finally:
            collector(entries, "account1").client.block.set()
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_start_refuses_an_export_that_does_not_fit_on_disk(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = registry(tmp_path, first=(1, 2, 8))
        reserve = collector(entries, "account0").param("media_min_free_mb") * 1024**2
        needed = 3 * distributed_export.RECORD_BYTES * distributed_export.WORKING_COPIES + reserve
        free = [needed - 1]
        monkeypatch.setattr(distributed_export.shutil, "disk_usage", lambda path: SimpleNamespace(free=free[0]))
        try:
            with pytest.raises(ValueError, match="Not enough free disk space"):
                await manager.start(CHAT, ["account0", "account1"], "account0")
            assert not manager.reserved and not manager.runs and not list(manager.root.iterdir())
            assert collector(entries, "account0").export_claim is None
            free[0] = needed
            state = await manager.start(CHAT, ["account0", "account1"], "account0")
            assert state["disk"] == {"estimated_messages": 3, "needed_bytes": needed, "free_bytes": needed}, state
            assert (await finished(manager, state))["phase"] == "done"
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_working_files_stay_until_done_and_only_the_archive_remains(tmp_path):
    async def scenario():
        manager, entries = registry(tmp_path)
        client = collector(entries, "account0").client
        client.block = asyncio.Event()
        try:
            state = await manager.start(CHAT, ["account0"], "account0")
            directory = manager.directory(state["id"])
            await asyncio.wait_for(client.blocked.wait(), 5)
            assert (await manager.pause(state["id"]))["phase"] == "paused"
            assert list((directory / "chunks").glob("*.jsonl")) and (directory / "work.sqlite3").is_file()
            client.block = None
            done = await finished(manager, await manager.resume(state["id"]))
            assert done["phase"] == "done", done
            assert sorted(p.name for p in directory.iterdir()) == ["export.zip", "job.json", "status.json"]
            restarted = distributed_export.DistributedExport(manager.profiles)
            assert restarted.public(state["id"])["phase"] == "done"
            path = restarted.result_path(state["id"])
            key = entries["account0"]["app"].state.vault.public_key
            assert verify_chat_export(path, fingerprint(key))["message_count"] == 8
        finally:
            client.block = None
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
