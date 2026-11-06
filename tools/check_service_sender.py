import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import types

from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store

GROUP = -1000000000888
WHEN = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def service(mid, sender, action):
    return types.MessageService(id=mid, peer_id=types.PeerChannel(888), date=WHEN, action=action,
                                from_id=types.PeerUser(sender))


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_target(GROUP, "Watched group", "supergroup", True)
        collector = Collector(store, vault)
        collector.running = True
        update = types.UpdateNewChannelMessage(service(1, 91, types.MessageActionPinMessage()), pts=5, pts_count=1)
        update._entities = {91: types.User(91, first_name="Pinning", last_name="Admin", username="pinner")}
        await collector.on_raw(update)
        await collector.avatar_history.close()
        pinned = next(e for e in store.all_events() if e["kind"] == "message.new" and e["message_id"] == 1)
        assert pinned["payload"]["sender_observation"]["display_name"] == "Pinning Admin", pinned["payload"]
        store.append("message.new", {"sender_id": 92, "text": "Earlier text", "sent_at": WHEN.isoformat(),
                                     "sender_observation": {"id": 92, "display_name": "Renaming Admin", "username": None}},
                     GROUP, 2, 92)
        store.append("message.new", {"sender_id": 92, "text": "", "sent_at": WHEN.isoformat(), "sender_observation": None,
                                     "service_action": "MessageActionChatEditTitle"}, GROUP, 3, 92)
        store.append("message.new", {"sender_id": 93, "text": "", "sent_at": WHEN.isoformat(), "sender_observation": None,
                                     "service_action": "MessageActionPinMessage"}, GROUP, 4, 93)
        shown = {m["message_id"]: m["sender"] for m in store.chat_messages(GROUP)["messages"]}
        assert shown[1] == {"id": 91, "name": "Pinning Admin", "username": "pinner"}, shown
        assert shown[3] == {"id": 92, "name": "Renaming Admin", "username": None}, shown
        assert shown[4] == {"id": 93, "name": None, "username": None}, shown
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="service-sender-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Service messages name their sender: from the update's users, or from the journal for older records.")
