"""Deletion notifications cannot identify an actor or prove a whole-history clear."""
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from telethon.tl import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store


@pytest.mark.parametrize("chat_id", [55123, -1000000000555])
@pytest.mark.parametrize("count", [2, 9, 10, 15])
def test_deletion_of_subset_keeps_actor_and_whole_history_unknown(tmp_path, chat_id, count):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_target(chat_id, "Synthetic evidence review", "private" if chat_id > 0 else "supergroup", True)
        collector = Collector(store, vault)
        collector.running = True
        ids = list(range(1, count + 1))
        try:
            for mid in [*ids, 100]:
                store.append("message.new", {"text": f"Synthetic message {mid}", "outgoing": mid == 1,
                             "sent_at": "2026-11-05T12:00:00+00:00", "edited_at": None}, chat_id, mid)
            raw = (types.UpdateDeleteMessages(messages=ids, pts=1, pts_count=count) if chat_id > 0 else
                   types.UpdateDeleteChannelMessages(channel_id=555, messages=ids, pts=1, pts_count=count))
            await collector.on_delete(SimpleNamespace(chat_id=None if chat_id > 0 else chat_id,
                                                      deleted_ids=ids, original_update=raw))
            assert store.message_state(chat_id, 100)["deleted"] is False
            events = list(store.all_events())
            summaries = [e for e in events if e["kind"] in ("deletion.batch", "history.cleared")]
            assert len(summaries) == 1
            summary = summaries[0]
            assert summary["kind"] == "deletion.batch", "A subset deletion is not a whole-history clear"
            assert summary["payload"]["outgoing_saved"] == 1
            assert summary["payload"]["raw"] == raw.to_dict()
            assert "other side cleared" not in summary["payload"]["meaning"]
            assert "does not identify who deleted them" in summary["payload"]["meaning"]
            deleted = [e for e in events if e["kind"] == "message.deleted"]
            assert len(deleted) == count
            assert all(e["payload"]["deleted_by"] is None for e in deleted)
            assert all(e["payload"]["deletion_time"] is None for e in deleted)
            assert all(e["payload"]["batch"]["hash"] == summary["hash"] for e in deleted)
            store.verify(vault.public_key)
        finally:
            store.close()
    asyncio.run(scenario())
