import asyncio
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import types

from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store

CHANNEL = -1000000000555


def deletion(ids):
    return SimpleNamespace(chat_id=CHANNEL, deleted_ids=ids, original_update=types.UpdateDeleteChannelMessages(
        channel_id=555, messages=ids, pts=1, pts_count=len(ids)))


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_target(CHANNEL, "Watched group", "supergroup", True)
        collector = Collector(store, vault)
        collector.running = True
        await collector.on_delete(deletion(list(range(100, 115))))
        await collector.on_delete(deletion([200]))
        events = list(store.all_events())
        batches = [e for e in events if e["kind"] == "deletion.batch"]
        deleted = [e for e in events if e["kind"] == "message.deleted"]
        assert len(batches) == 1 and batches[0]["payload"]["count"] == 15, batches
        assert not any(e["kind"] == "history.cleared" for e in events)
        assert len(deleted) == 16
        batched = [e for e in deleted if "batch" in e["payload"]]
        assert len(batched) == 15 and all(e["payload"]["batch"]["seq"] == batches[0]["seq"] for e in batched)
        assert all("raw" not in e["payload"] for e in batched)
        single = next(e for e in deleted if e["message_id"] == 200)
        assert "raw" in single["payload"] and "batch" not in single["payload"]
        largest = max(len(json.dumps(e["payload"])) for e in batched)
        assert largest < 600, largest
        await collector.on_raw(types.UpdatePinnedChannelMessages(channel_id=555, messages=[7], pts=2, pts_count=1, pinned=True))
        await collector.on_raw(types.UpdatePinnedChannelMessages(channel_id=555, messages=[7], pts=3, pts_count=1, pinned=False))
        unpinned = [e for e in store.all_events() if e["kind"] == "message.unpinned"]
        assert [(e["chat_id"], e["message_id"]) for e in unpinned] == [(CHANNEL, 7)], unpinned
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="bulk-deletion-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("A deletion update is journalled once; each deletion refers to it instead of repeating every ID.")
