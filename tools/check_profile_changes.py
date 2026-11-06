import asyncio
import io
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PIL import Image
from telethon.tl import types

from tgwitness import people
from tgwitness.collector import PROFILE_REQUEST_SECONDS, Collector
from tgwitness.security import Vault
from tgwitness.store import Store

GROUP = -1000000000777
FRIEND = 4242
MEMBER = 5151
WHEN = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def picture(colour):
    data = io.BytesIO()
    Image.new("RGB", (8, 8), colour).save(data, "JPEG")
    return data.getvalue()


def user(uid, first, photo=None, **flags):
    return types.User(uid, first_name=first, access_hash=1,
                      photo=types.UserProfilePhoto(photo, dc_id=2) if photo else None, **flags)


def message(mid, peer, sender):
    return types.Message(mid, peer, date=WHEN, message="Synthetic message " + str(mid), from_id=types.PeerUser(sender))


def kinds(store, *names):
    return [e for e in store.all_events() if e["kind"] in names]


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_target(GROUP, "Watched group", "supergroup", True)
        store.set_target(FRIEND, "Private chat", "private", True)
        store.set_setting("account", {"id": 1})
        store.set_setting("monitoring", {"profiles": True})
        collector = Collector(store, vault)
        collector.running = True
        photos = {111: picture("red"), 222: picture("blue"), 333: picture("green"), 444: picture("white")}

        async def download(location, file, dc_id):
            file.write(photos[location.photo_id])
        collector.client = SimpleNamespace(is_connected=lambda: True, download_file=AsyncMock(side_effect=download),
                                           get_entity=AsyncMock())

        await collector.capture_message(message(1, types.PeerChannel(777), MEMBER), "message.new", GROUP,
                                        sender=user(MEMBER, "Member", 111))
        await collector.avatar_history.drain()
        await collector.capture_message(message(2, types.PeerChannel(777), MEMBER), "message.new", GROUP,
                                        sender=user(MEMBER, "Member Renamed", 222))
        await collector.avatar_history.drain()
        await collector.capture_message(message(3, types.PeerChannel(777), MEMBER), "message.new", GROUP,
                                        sender=user(MEMBER, "Member Renamed", 222))
        await collector.avatar_history.drain()
        changed = kinds(store, "actor.profile_changed")
        assert len(changed) == 1, changed
        assert changed[0]["chat_id"] == GROUP and changed[0]["payload"]["source"] == "message_sender"
        assert changed[0]["payload"]["changes"] == {"display_name": {"before": "Member", "after": "Member Renamed"}}
        avatars = [e["payload"] for e in kinds(store, "actor.avatar_saved") if e["chat_id"] == GROUP]
        assert [(a["photo_id"], a.get("previous_photo_id", "unknown")) for a in avatars] == [(111, "unknown"), (222, 111)]

        short = message(10, types.PeerUser(FRIEND), FRIEND)
        await collector.capture_message(short, "message.new", FRIEND)
        assert kinds(store, "message.new")[-1]["payload"]["sender_observation"] is None
        requested = kinds(store, "actor.refresh_requested")
        assert len(requested) == 1 and requested[0]["payload"]["source"] == "message_without_sender_profile"
        collector.client.get_entity.return_value = user(FRIEND, "Friend", 333, contact=True)
        await people.refresh_one(collector)
        await collector.avatar_history.drain()
        assert collector.client.get_entity.await_count == 1
        await collector.capture_message(message(11, types.PeerUser(FRIEND), FRIEND), "message.new", FRIEND)
        assert len(kinds(store, "actor.refresh_requested")) == 1
        collector.profile_requests[FRIEND] -= PROFILE_REQUEST_SECONDS + 1
        await collector.capture_message(message(12, types.PeerUser(FRIEND), FRIEND), "message.new", FRIEND)
        assert len(kinds(store, "actor.refresh_requested")) == 2
        collector.client.get_entity.return_value = user(FRIEND, "Friend Renamed", 444, contact=True)
        await people.refresh_one(collector)
        await collector.avatar_history.drain()
        private = [e for e in kinds(store, "actor.profile_changed", "actor.avatar_saved") if e["chat_id"] == FRIEND]
        assert [e["kind"] for e in private] == ["actor.avatar_saved", "actor.profile_changed", "actor.avatar_saved"], private
        assert private[1]["payload"]["changes"] == {"display_name": {"before": "Friend", "after": "Friend Renamed"}}
        assert private[1]["payload"]["source"] == "requested_profile_refresh"
        assert (private[0]["payload"]["photo_id"], private[2]["payload"]["photo_id"],
                private[2]["payload"]["previous_photo_id"]) == (333, 444, 333)

        await collector.on_raw(types.UpdateUserName(FRIEND, "Friend Again", "", [types.Username("friend", active=True)]))
        update = kinds(store, "actor.profile_changed")[-1]["payload"]
        assert update["source"] == "telegram_update"
        assert update["changes"]["display_name"] == {"before": "Friend Renamed", "after": "Friend Again"}
        assert people.timeline(store, FRIEND, FRIEND)["person"]["profile"]["display_name"] == "Friend Again"
        assert people.timeline(store, GROUP, MEMBER)["person"]["profile"]["display_name"] == "Member Renamed"
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="profile-changes-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Name and photo changes in a group and a private chat are recorded as separate events with before and after.")
