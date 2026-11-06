import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.errors import ChannelPrivateError
from telethon.tl import types

from tgwitness import health
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store

CHANNEL = -1000000000777
GROUP = -4242
ME = 501


class Client:
    def __init__(self, answer):
        self.answer = answer

    async def get_input_entity(self, peer):
        return types.InputChannel(peer.channel_id, 1)

    async def __call__(self, request):
        if isinstance(self.answer, Exception):
            raise self.answer
        return types.messages.Chats(chats=[self.answer])


def service(chat, action):
    return types.UpdateNewMessage(types.MessageService(
        id=9, peer_id=types.PeerChat(-chat), date=datetime.now(timezone.utc), action=action,
        from_id=types.PeerUser(77)), pts=1, pts_count=1)


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_setting("account", {"id": ME})
        store.set_target(CHANNEL, "Watched supergroup", "supergroup", True)
        store.set_target(GROUP, "Watched group", "group", True)
        collector = Collector(store, vault)
        collector.running = True

        collector.client = Client(types.Channel(id=777, title="Watched supergroup", photo=types.ChatPhotoEmpty(),
                                                date=datetime.now(timezone.utc), megagroup=True, access_hash=1))
        await collector.on_raw(types.UpdateChannel(channel_id=777))
        assert not store.get_setting("lost_sources", {}), "Still a member: nothing is lost"

        collector.client = Client(ChannelPrivateError(request=None))
        await collector.on_raw(types.UpdateChannel(channel_id=777))
        await collector.on_raw(types.UpdateChannel(channel_id=777))
        events = list(store.events(limit=20))
        lost = [e for e in events if e["kind"] == "source.access_lost"]
        assert len(lost) == 1 and lost[0]["chat_id"] == CHANNEL and lost[0]["payload"]["reason"] == "no_access"
        assert any(e["kind"] == "coverage.gap" and e["payload"]["reason"] == "source_access_lost" for e in events)
        assert collector.source_visibility(CHANNEL, {CHANNEL: {"last_observed_at": "2999-01-01"}})["state"] == "access_lost"

        collector.client = Client(types.Chat(id=4242, title="Watched group", photo=types.ChatPhotoEmpty(),
                                             participants_count=2, date=datetime.now(timezone.utc), version=1))
        await collector.on_raw(service(GROUP, types.MessageActionChatDeleteUser(user_id=ME)))
        assert str(GROUP) not in store.get_setting("lost_sources"), "A replayed removal of a member is not a loss"

        collector.client = Client(types.ChatForbidden(id=4242, title="Watched group"))
        await collector.on_raw(service(GROUP, types.MessageActionChatDeleteUser(user_id=ME)))
        assert str(GROUP) in store.get_setting("lost_sources")

        part = health.sources({"source_status": collector.source_status, "scope": {"mode": "selected"}}, 2)
        assert part["state"] == "failed" and part["reason"] == "access_lost", part

        collector.dialog_cache[CHANNEL] = {"visibility": "public", "role": "member"}
        assert collector.source_visibility(CHANNEL, {})["state"] == "visible_in_dialogs"
        assert str(CHANNEL) not in store.get_setting("lost_sources")
        assert any(e["kind"] == "source.access_restored" for e in store.events(limit=5))
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="source-access-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Removal from a watched chat is journalled once, opens a coverage gap and shows as lost until access returns.")
