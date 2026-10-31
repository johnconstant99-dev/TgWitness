import asyncio
import hashlib
import io
import json
import zipfile

from PIL import Image
from telethon import types

from tgwitness import avatar_history, dossier
from tgwitness.evidence import export_file
from tgwitness.verify import verify_bundle, verify_dossier

CHAT, OTHER = -1000000000123, -1000000000456


def photo(seed=1):
    image = Image.new("RGB", (32, 32))
    image.putdata([((x * 3 + y * seed) % 256,) * 3 for y in range(32) for x in range(32)])
    out = io.BytesIO()
    image.save(out, "JPEG")
    return out.getvalue()


def actor(peer, photo_id):
    return types.User(id=peer, first_name="Synthetic", photo=types.UserProfilePhoto(photo_id=photo_id, dc_id=2))


def message(store, peer, photo_id, chat=CHAT):
    return store.append("message.new", {"sender_id": peer, "text": "Synthetic observation",
                        "sender_observation": {"id": peer, "photo_id": photo_id}},
                        chat_id=chat, message_id=store.stats()["total"] + 1, actor_id=peer)


class Photos:
    def __init__(self, images):
        self.images, self.calls = images, []

    def is_connected(self):
        return True

    async def download_profile_photo(self, entity, file, download_big):
        assert download_big is False
        self.calls.append((entity.id, entity.photo.photo_id))
        file.write(self.images[entity.photo.photo_id])
        return file


def test_avatar_changes_preserve_blobs_and_scoped_signed_history(journal, tmp_path):
    store, vault = journal
    first, second = photo(), photo(7)
    client = Photos({11: first, 12: second, 13: second})
    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        for photo_id in (11, 12, 13):
            message(store, 501, photo_id)
            assert history.observe(actor(501, photo_id), chat_id=CHAT)
            assert not history.observe(actor(501, photo_id), chat_id=CHAT)
            await history.drain()
        assert not history.observe(actor(501, 13), chat_id=CHAT)
        message(store, 502, 12)
        history.observe(actor(502, 12), chat_id=CHAT)
        await history.drain()
        message(store, 501, 13)
        await history.close()
        # One photo in another source needs a separately scoped capture record.
        message(store, 501, 12, OTHER)
        history.observe(actor(501, 12), chat_id=OTHER)
        await history.drain()
        await history.close()

    asyncio.run(run())
    records = store.events(kind="actor.avatar_saved", limit=20)
    assert len(records) == 5 and {event["chat_id"] for event in records} == {CHAT, OTHER}
    assert all(event["message_id"] is None and event["signature"] for event in records)
    assert len(list((store.root / "media").iterdir())) == 2
    for content in (first, second):
        assert (store.root / "media" / hashlib.sha256(content).hexdigest()).read_bytes() == content
    value = dossier.signed(store, vault, CHAT)
    alice = next(p for p in value["statement"]["people"] if p["id"] == 501)
    assert [p["photo_id"] for p in alice["avatar"]["history"]] == [11, 12, 13]
    assert alice["avatar"]["history"][2]["last_at"] > alice["avatar"]["history"][2]["first_at"]
    assert any(item["id"] == 502 and item["distance"] == 0 for item in alice["avatar"]["history_similar"])
    other_record = next(event for event in records if event["chat_id"] == OTHER)
    assert str(other_record["seq"]) not in value["statement"]["record_hashes"]
    bundle = export_file(store, vault, "zip")
    assert verify_bundle(bundle)["events"] == store.stats()["total"]
    with zipfile.ZipFile(bundle) as archive:
        assert all("media/" + hashlib.sha256(data).hexdigest() in archive.namelist() for data in (first, second))
    profile = tmp_path / "dossier-test.json"
    profile.write_text(json.dumps(value), encoding="utf-8")
    assert verify_dossier(profile, value["fingerprint"], bundle)["records_checked"] > 0


def test_avatar_history_restart_deduplicates_and_failure_does_not_block_next_photo(journal):
    store, _ = journal
    client = Photos({11: b"not an image", 12: photo(), 13: b"x" * (avatar_history.MAX_BYTES + 1)})
    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        for photo_id in (11, 12, 13):
            history.observe(actor(501, photo_id), chat_id=CHAT)
        await history.drain()
        await history.close()
        assert not history.observe(actor(501, 11), chat_id=CHAT)
        restored = avatar_history.AvatarHistory(store, lambda: client)
        restored.observe(actor(501, 12), chat_id=CHAT)
        await restored.drain()
        await restored.close()

    asyncio.run(run())
    assert client.calls == [(501, 11), (501, 12), (501, 13)]
    assert len(store.events(kind="actor.avatar_saved")) == 1
    assert len(store.events(kind="actor.avatar_failed")) == 2
    assert len(list((store.root / "media").iterdir())) == 1


def test_avatar_queue_and_shutdown_are_bounded_and_restartable(journal):
    store, _ = journal
    client = Photos({11: photo()})
    started = asyncio.Event()

    async def blocked(entity, file, download_big):
        started.set()
        await asyncio.Event().wait()

    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        original = client.download_profile_photo
        client.download_profile_photo = blocked
        assert not history.observe(actor(501, 11), chat_id=None)
        history.observe(types.User(id=501), chat_id=CHAT)
        await history.drain()
        for peer in range(avatar_history.MAX_PENDING + 20):
            history.observe(actor(peer + 1, 11), chat_id=CHAT)
        assert len(history.pending) == avatar_history.MAX_PENDING
        await started.wait()
        await history.close()
        assert not history.pending and history.worker is None
        client.download_profile_photo = original
        assert history.observe(actor(501, 11), chat_id=CHAT)
        await history.drain()
        await history.close()

    asyncio.run(run())
    assert len(store.events(kind="actor.avatar_saved")) == 1


def test_revisited_and_removed_photo_keep_changes_without_redownloading(journal):
    store, _ = journal
    client = Photos({11: photo(), 12: photo(7)})
    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        for photo_id in (11, 12, 11, None, 11):
            message(store, 501, photo_id)
            entity = actor(501, photo_id) if photo_id is not None else types.User(id=501)
            assert history.observe(entity, chat_id=CHAT)
        await history.drain()
        await history.close()

    asyncio.run(run())
    assert client.calls == [(501, 11), (501, 12)]
    events = avatar_history.history_events(store, CHAT)
    assert [event["payload"]["photo_id"] for event in events] == [11, 12, 11, None, 11]
    removed = next(event for event in events if event["kind"] == "actor.avatar_removed")
    assert removed["payload"]["previous_photo_id"] == 11 and removed["signature"]
    profile = dossier.build(store, CHAT)["people"][0]
    assert len(profile["avatar"]["history"]) == 2 and len(profile["avatar"]["changes"]) == 5
    assert profile["avatar"]["history"][0]["first_at"] < profile["avatar"]["history"][0]["last_at"]


def test_download_failure_can_retry_after_cooldown(journal):
    store, _ = journal
    client = Photos({11: b"bad photo"})
    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        history.observe(actor(501, 11), chat_id=CHAT)
        await history.drain()
        assert not history.observe(actor(501, 11), chat_id=CHAT)
        history.failed[(CHAT, 501, 11)] = 0
        client.images[11] = photo()
        assert history.observe(actor(501, 11), chat_id=CHAT)
        await history.drain()
        await history.close()

    asyncio.run(run())
    assert client.calls == [(501, 11), (501, 11)]
    assert len(store.events(kind="actor.avatar_saved")) == 1


def test_minimal_users_do_not_invent_avatar_changes(journal):
    store, _ = journal
    client = Photos({11: photo(), 12: photo(7)})
    history = avatar_history.AvatarHistory(store, lambda: client)

    async def run():
        history.observe(actor(501, 11), chat_id=CHAT)
        await history.drain()
        # A reduced User may omit or carry a non-authoritative photo field.
        partial = actor(501, 12)
        partial.min = True
        assert not history.observe(partial, chat_id=CHAT)
        assert not history.observe(types.User(id=501, min=True), chat_id=CHAT)
        assert not store.events(kind="actor.avatar_removed")
        assert history.observe(types.User(id=501, min=True, apply_min_photo=True), chat_id=CHAT)
        await history.drain()
        # Channel min constructors do carry authoritative photo information.
        channel = types.Channel(id=77, title="Synthetic", date=None, min=True,
                                photo=types.ChatPhoto(photo_id=11, dc_id=2))
        assert history.observe(channel, chat_id=CHAT)
        await history.drain()
        await history.close()

    asyncio.run(run())
    assert client.calls == [(501, 11), (77, 11)]
    assert len(store.events(kind="actor.avatar_removed")) == 1
