"""Check the baseline snapshot taken when a person adds a chat to observation (T16)."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import patch

import httpx
from telethon.tl import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.app import create_app
from tgwitness.monitoring import monitoring_settings
from tgwitness.proxy_catalog import ProxyPool
from tools.browser_fixtures import CHAT, FakeClient, saved_session
from tools.check_session_reservations import idle, pinned, probe

OTHER, LATER = -1000000000456, -1000000000789
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class HistoryClient(FakeClient):
    history = {}

    async def iter_dialogs(self, limit):
        for chat_id in (CHAT, OTHER, LATER):
            number = -chat_id - 1000000000000
            yield NS(id=chat_id, name="Chat " + str(number), is_group=True, is_channel=True,
                     entity=NS(megagroup=True, id=number))

    def message(self, number, message_id):
        return types.Message(id=message_id, peer_id=types.PeerChannel(number), date=NOW,
                             message=self.history[number][message_id], from_id=types.PeerUser(55))

    async def iter_messages(self, entity, limit=None, min_id=0, reverse=False, **kwargs):
        ids = sorted((i for i in self.history[entity.id] if i > min_id), reverse=not reverse)
        for message_id in ids[:limit]:
            yield self.message(entity.id, message_id)

    async def get_messages(self, entity, limit=None, ids=None, **kwargs):
        if ids is not None:
            return [self.message(entity.id, i) if i in self.history[entity.id] else None for i in ids]
        return [self.message(entity.id, i) for i in sorted(self.history[entity.id], reverse=True)[:limit]]


@asynccontextmanager
async def workspace():
    HistoryClient.history = {number: {i: "Old message " + str(i) for i in range(1, 6)} for number in (123, 456, 789)}
    with tempfile.TemporaryDirectory(prefix="watch-baseline-") as scratch, \
            patch.object(ProxyPool, "run", idle), patch.object(ProxyPool, "pin", staticmethod(pinned)), \
            patch.object(ProxyPool, "probe", staticmethod(probe)):
        app = create_app(Path(scratch), client_factory=HistoryClient)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                         headers={"Authorization": "Bearer " + app.state.vault.token}) as http:
                await app.state.collector.configure(123, "a" * 32, saved_session())
                assert (await http.get("/api/dialogs")).status_code == 200
                yield app, http


async def settled(store, chat_ids):
    for _ in range(250):
        done = {e["chat_id"] for e in store.events(kind="snapshot.completed", limit=1000)}
        if not store.get_setting("baseline_pending", []) and set(chat_ids) <= done:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("The baseline snapshot was not taken: " + repr(store.get_setting("baseline_pending", [])))


def snapshots(store, chat_id):
    return [e for e in store.events(kind="message.snapshot", chat_id=chat_id, limit=1000)]


async def baseline_and_missing():
    async with workspace() as (app, http):
        collector, store = app.state.collector, app.state.store
        store.set_target(LATER, "Chat 789", "supergroup", True)
        response = await http.post("/api/targets", json={"chat_id": CHAT, "enabled": True})
        assert response.status_code == 200, response.text
        assert store.get_setting("baseline_pending") == [CHAT], "adding a chat queues its baseline"
        assert not snapshots(store, CHAT), "nothing is fetched before observation runs"

        response = await http.post("/api/collector/start")
        assert response.status_code == 200, response.text
        await settled(store, [CHAT])
        saved = snapshots(store, CHAT)
        assert sorted(e["message_id"] for e in saved) == [1, 2, 3, 4, 5]
        assert all(e["payload"]["source"] == "baseline_snapshot" for e in saved)
        started = store.events(kind="snapshot.started", chat_id=CHAT, limit=10)
        assert [e["payload"].get("origin") for e in started] == ["baseline"]
        assert not snapshots(store, LATER), "chats that were already observed get no baseline"

        response = await http.post("/api/targets", json={"chat_id": OTHER, "enabled": True})
        assert response.status_code == 200, response.text
        await settled(store, [CHAT, OTHER])
        assert sorted(e["message_id"] for e in snapshots(store, OTHER)) == [1, 2, 3, 4, 5], \
            "a chat added while observing gets its baseline right away"

        response = await http.post("/api/targets", json={"chat_id": CHAT, "enabled": True})
        assert response.status_code == 200 and store.get_setting("baseline_pending") == []
        assert len(store.events(kind="snapshot.started", chat_id=CHAT, limit=10)) == 1, \
            "saving an already observed chat again takes no new baseline"

        del HistoryClient.history[123][2]
        result = await collector.recheck_chat(CHAT, monitoring_settings(store))
        assert result["missing"] == 1, result
        missing = store.events(kind="message.missing_on_recheck", chat_id=CHAT, limit=10)
        assert [e["message_id"] for e in missing] == [2]
        reference = missing[0]["payload"]["last_saved_event"]
        original = next(e for e in saved if e["message_id"] == 2)
        assert reference == {"seq": original["seq"], "hash": original["hash"]}
        assert original["payload"]["text"] == "Old message 2"
        shown = next(m for m in store.chat_messages(CHAT)["messages"] if m["message_id"] == 2)
        assert shown["missing"] and shown["versions"][-1]["text"] == "Old message 2", shown
        await collector.stop()
    return "ok  baseline: queued on add, taken at start or right away, deleted old message reported with its text"


async def batch_and_restart():
    async with workspace() as (app, http):
        store = app.state.store
        response = await http.post("/api/targets/batch", json={"chat_ids": [CHAT, OTHER], "enabled": True})
        assert response.status_code == 200, response.text
        assert store.get_setting("baseline_pending") == [CHAT, OTHER]
        response = await http.post("/api/targets/batch", json={"chat_ids": [OTHER], "enabled": False})
        assert response.status_code == 200, response.text
        assert (await http.post("/api/collector/start")).status_code == 200
        await settled(store, [CHAT])
        assert len(snapshots(store, CHAT)) == 5
        assert not snapshots(store, OTHER), "a chat paused again before observation gets no baseline"
        await app.state.collector.stop()
        response = await http.post("/api/targets/batch", json={"chat_ids": [OTHER], "enabled": True})
        assert response.status_code == 200 and store.get_setting("baseline_pending") == [OTHER]
        assert (await http.post("/api/collector/start")).status_code == 200
        await settled(store, [CHAT, OTHER])
        assert len(snapshots(store, OTHER)) == 5 and len(snapshots(store, CHAT)) == 5
        await app.state.collector.stop()
    return "ok  batch: newly enabled chats queued, paused ones skipped, pending baselines survive a pause"


async def main():
    print(await asyncio.wait_for(baseline_and_missing(), 60))
    print(await asyncio.wait_for(batch_and_restart(), 60))
    print("watch baseline checks passed")


if __name__ == "__main__":
    asyncio.run(main())
