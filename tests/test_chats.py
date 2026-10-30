import asyncio

from fastapi.testclient import TestClient
from telethon.tl import types

from tgwitness.app import create_app
from tgwitness.collector import Collector
from test_collector import CHAT, FakeClient

OTHER = -1000000000999


def seed(store):
    alice = {"id": 44, "display_name": "Alice", "username": "alice"}
    store.append("message.new", {"text": "Original", "sender_id": 44, "sender_observation": alice,
                                 "sent_at": "2026-01-01T10:00:00+00:00"}, CHAT, 10, 44)
    store.append("message.edited", {"text": "Changed", "sender_id": 44, "sender_observation": alice,
                                    "edited_at": "2026-01-01T10:05:00+00:00"}, CHAT, 10)
    store.append("message.deleted", {"deleted_by": None}, CHAT, 10)
    for _ in range(2):  # a repeated history snapshot is not a new version
        store.append("message.snapshot", {"text": "From history", "sender_id": 45, "has_media": True,
                                          "reply_to_message_id": 10}, CHAT, 11)
    store.append("media.saved", {"media_sha256": "a" * 64, "mime_type": "image/png",
                                 "original_name": "shot.png", "size": 12}, CHAT, 11)
    store.append("message.deleted", {"deleted_by": None}, CHAT, 12)
    store.append("message.new", {"text": "Elsewhere", "sender_id": 46}, OTHER, 13)


def test_chat_view_aggregates_versions_deletions_and_media(journal):
    store, _ = journal
    seed(store)
    result = store.chat_messages(CHAT)
    assert [m["message_id"] for m in result["messages"]] == [10, 11, 12] and result["next_before"] is None
    edited, history, lost = result["messages"]
    assert [v["text"] for v in edited["versions"]] == ["Original", "Changed"]
    assert edited["text"] == "Changed" and edited["edited"] and edited["deleted"] and edited["captured"]
    assert edited["sender"] == {"id": 44, "name": "Alice", "username": "alice"}
    assert len(history["versions"]) == 1 and history["origins"] == ["history"] and not history["edited"]
    assert history["reply_to"] == 10 and history["media"][0]["name"] == "shot.png"
    assert lost["deleted"] and not lost["captured"] and lost["text"] is None

    first = store.chat_messages(CHAT, limit=2)
    assert [m["message_id"] for m in first["messages"]] == [11, 12] and first["next_before"] == 11
    older = store.chat_messages(CHAT, before_id=11, limit=2)
    assert [m["message_id"] for m in older["messages"]] == [10] and older["next_before"] is None

    overview = store.chat_overview()
    assert overview[CHAT]["messages"] == 3 and overview[CHAT]["edited"] == 1 and overview[CHAT]["deleted"] == 2
    assert overview[CHAT]["last_text"] == "From history"
    assert overview[OTHER]["messages"] == 1


class PhotoClient:
    def __init__(self):
        self.calls, self.connected = 0, True

    def is_connected(self):
        return self.connected

    async def download_profile_photo(self, entity, file=None, download_big=True):
        assert file is bytes and download_big is False
        self.calls += 1
        return b"\xff\xd8jpeg" if entity.photo else None


def test_avatars_are_cached_requested_once_and_never_journaled(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        client = collector.client = PhotoClient()
        collector.remember(types.User(id=501, photo=types.UserProfilePhoto(photo_id=1, dc_id=2)))
        collector.remember(types.User(id=502, photo=None))
        before = store.stats()["total"]
        path = await collector.avatar(501)
        assert path.read_bytes() == b"\xff\xd8jpeg"
        assert await collector.avatar(501) == path and client.calls == 1
        assert await collector.avatar(502) is None and (store.root / "avatars" / "502.none").exists()
        assert await collector.avatar(502) is None and client.calls == 2
        assert await collector.avatar(999) is None and client.calls == 2  # unseen user: no request
        client.connected = False
        collector.remember(types.User(id=503, photo=types.UserProfilePhoto(photo_id=2, dc_id=2)))
        assert await collector.avatar(503) is None and client.calls == 2  # offline: no reconnect for others
        assert store.stats()["total"] == before
    asyncio.run(run())


def test_chats_api(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        store = app.state.store
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        seed(store)
        chats = {c["chat_id"]: c for c in client.get("/api/chats").json()["chats"]}
        assert chats[CHAT]["title"] == "Synthetic" and chats[CHAT]["enabled"] is True
        assert chats[CHAT]["deleted"] == 2 and chats[CHAT]["edited"] == 1
        assert chats[OTHER]["enabled"] is False and chats[OTHER]["title"] is None
        messages = client.get("/api/chats/" + str(CHAT) + "/messages").json()["messages"]
        assert messages[0]["deleted"] and messages[0]["sender"]["username"] == "alice"
        assert client.get("/api/chats/" + str(CHAT) + "/messages?limit=0").status_code == 422
        assert client.get("/api/avatar/44").status_code == 404
        assert client.get("/api/chats", headers={"Authorization": ""}).status_code == 401
        policy = client.get("/api/status").headers["content-security-policy"]
        assert "img-src 'self' data: blob:" in policy and "script-src 'self';" in policy


def test_people_tab_counts_saved_deleted_and_edited(journal):
    store, _ = journal
    seed(store)
    result = store.chat_authors(CHAT)
    people = {p["id"]: p for p in result["authors"]}
    assert set(people) == {44, 45}
    assert (people[44]["messages"], people[44]["deleted"], people[44]["edited"]) == (1, 1, 1)
    assert people[44]["name"] == "Alice" and people[44]["username"] == "alice"
    assert (people[45]["messages"], people[45]["deleted"], people[45]["edited"]) == (1, 0, 0)
    assert result["authors"][0]["id"] == 44
    assert result["deleted_without_author"] == 1


def test_chat_scale_counts_missing_ids_and_estimates_time(journal):
    from telethon.helpers import TotalList
    from test_collector import saved_session, telegram_message

    class ScaleClient(FakeClient):
        async def get_messages(self, entity, limit):
            page = TotalList([telegram_message(5000)] if limit else [])
            page.total = 4000
            return page

    async def run():
        store, vault = journal
        collector = Collector(store, vault, ScaleClient)
        await collector.configure(123, "a" * 32, saved_session())
        await collector.dialogs()
        scale = await collector.chat_scale(CHAT)
        assert scale["total"] == 4000 and scale["last_message_id"] == 5000
        assert scale["ids_are_per_chat"] and scale["missing_ids"] == 1000
        assert scale["pages"] == 40 and scale["estimate_seconds"] == 40  # 1 s between pages above 3,000
        await collector.stop(shutdown=True)
    asyncio.run(run())
