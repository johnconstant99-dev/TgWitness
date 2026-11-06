import asyncio
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.errors import RPCError
from telethon.tl import functions, types

from tgwitness import interactions
from tgwitness.collector import Collector
from tgwitness.scope import visibility
from tgwitness.security import Vault
from tgwitness.store import Store

WHEN = datetime(2026, 1, 1, tzinfo=timezone.utc)


def channel(number, username=None, usernames=(), megagroup=False):
    return types.Channel(id=number, title="Synthetic channel %d" % number, photo=types.ChatPhotoEmpty(), date=WHEN,
                         access_hash=1, megagroup=megagroup, username=username,
                         usernames=[types.Username(name, active=active) for name, active in usernames] or None)


COLLECTIBLE = channel(101, usernames=[("syntheticdurov", True), ("syntheticold", False)])
HIDDEN = channel(102, username="syntheticgroup", megagroup=True)
CLOSED = channel(103, username="syntheticclosed")
UNLISTED = channel(104, usernames=[("syntheticgone", False)])


class Telegram:
    def __init__(self):
        self.joined = []

    async def get_entity(self, username):
        return {"syntheticdurov": COLLECTIBLE, "syntheticgroup": HIDDEN, "syntheticclosed": CLOSED}[username]

    async def __call__(self, request):
        if isinstance(request, functions.messages.CheckChatInviteRequest):
            return types.ChatInvite(title="Synthetic invite", photo=types.PhotoEmpty(1), participants_count=9, color=0)
        if isinstance(request, functions.channels.GetFullChannelRequest):
            if request.channel is CLOSED:
                raise RPCError(request, "CHANNEL_PRIVATE", 400)
            full = types.ChannelFull(id=request.channel.id, about="Synthetic description", read_inbox_max_id=0,
                                     read_outbox_max_id=0, unread_count=0, chat_photo=types.PhotoEmpty(0),
                                     notify_settings=types.PeerNotifySettings(), bot_info=[], pts=1,
                                     participants_count=1234 if request.channel is COLLECTIBLE else 56,
                                     hidden_prehistory=request.channel is HIDDEN or None)
            return types.messages.ChatFull(full_chat=full, chats=[], users=[])
        assert isinstance(request, functions.channels.JoinChannelRequest)
        self.joined.append(request.channel.id)
        return SimpleNamespace(chats=[request.channel])


async def dialogs(store, vault):
    async def listed(limit):
        for entity in (COLLECTIBLE, UNLISTED, HIDDEN):
            yield SimpleNamespace(id=-1000000000000 - entity.id, name=entity.title, is_group=entity.megagroup,
                                  is_channel=True, entity=entity, folder_id=None)

    collector = Collector(store, vault)
    collector.restore, collector.load_folders = AsyncMock(), AsyncMock()
    collector.client = SimpleNamespace(iter_dialogs=listed)
    found = {d["chat_id"]: d["visibility"] for d in (await collector.dialogs())["dialogs"]}
    assert found == {-1000000000101: "public_username", -1000000000104: "private_or_unlisted",
                     -1000000000102: "public_username"}, found


async def previews_and_joins(store):
    collector = SimpleNamespace(store=store, running=False, restore=AsyncMock(), client=Telegram(), dialog_cache={},
                                selected=lambda chat: chat in {t["chat_id"] for t in store.targets()},
                                request_baseline=lambda chat_ids: None)

    async def preview(link):
        return await interactions.preview(collector, interactions.Preview(link=link))

    public = await preview("@syntheticdurov")
    assert (public["participants_count"], public["history_visible"], public["about"]) == (
        1234, True, "Synthetic description"), public
    hidden = await preview("https://t.me/syntheticgroup")
    assert (hidden["participants_count"], hidden["history_visible"]) == (56, False), hidden
    closed = await preview("@syntheticclosed")
    assert closed["participants_count"] is None and closed["history_visible"] is None
    assert closed["full_info_error"] == "RPCError", closed
    invite = await preview("https://t.me/+syntheticinvite")
    assert invite["participants_count"] == 9 and invite["history_visible"] is None, invite

    async def join(preview, observe, name):
        body = interactions.Action(request_id="join-preview-" + name, action="open", preview_id=preview["preview_id"],
                                   **({} if observe is None else {"observe": observe}))
        return await interactions.execute(collector, body)

    watched = await join(public, False, "unobserved-0001")
    assert watched["status"] == "succeeded" and watched["chat_id"] == -1000000000101, watched
    assert not store.targets() and not store.events(kind="source.added", limit=5)
    assert collector.dialog_cache[-1000000000101]["visibility"] == "public_username"
    observed = await join(hidden, None, "observed-default1")
    assert observed["status"] == "succeeded"
    assert [t["chat_id"] for t in store.targets()] == [-1000000000102]
    assert store.events(kind="source.added", limit=5)[0]["chat_id"] == -1000000000102
    assert collector.client.joined == [101, 102]
    requested = [e["payload"]["request"]["observe"] for e in store.all_events() if e["kind"] == "interaction.requested"]
    assert requested == [False, None], requested


def main():
    assert visibility(COLLECTIBLE) == visibility(HIDDEN) == "public_username"
    assert visibility(UNLISTED) == visibility(channel(105)) == "private_or_unlisted"
    with tempfile.TemporaryDirectory(prefix="join-preview-") as temporary:
        root = Path(temporary)
        store, vault = Store(root), Vault(root)
        store.bind(vault)
        try:
            store.set_setting("account", {"id": 9001, "key_origin": "created"})
            store.set_setting("parameters", {"action_join_seconds": 0})
            asyncio.run(dialogs(store, vault))
            asyncio.run(previews_and_joins(store))
            store.verify(vault.public_key)
        finally:
            store.close()
    print("Collectible-only usernames count as public; previews read members and history visibility from "
          "GetFullChannel; joining observes only when asked.")


if __name__ == "__main__":
    main()
