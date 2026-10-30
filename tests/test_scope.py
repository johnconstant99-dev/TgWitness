import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from fastapi.testclient import TestClient
from telethon.tl import types

from tgwitness.app import create_app
from tgwitness.collector import Collector
from tests.test_collector import CHAT, FakeClient, media_message, saved_session

NEWS = -1000000000456     # broadcast channel, archived
ALICE, SHOP_BOT, STRANGER, NEW_BOT = 777, 888, 999, 4242
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def channel(number, **flags):
    return types.Channel(id=number, title="Channel " + str(number), photo=types.ChatPhotoEmpty(), date=NOW, **flags)


ENTITIES = {
    CHAT: channel(123, megagroup=True), NEWS: channel(456, broadcast=True),
    ALICE: types.User(id=ALICE, first_name="Alice", contact=True),
    SHOP_BOT: types.User(id=SHOP_BOT, first_name="Shop", bot=True),
    STRANGER: types.User(id=STRANGER, first_name="Stranger"),
    NEW_BOT: types.User(id=NEW_BOT, first_name="Fresh bot", bot=True),
}


class ScopeClient(FakeClient):
    async def iter_dialogs(self, limit):
        yield NS(id=CHAT, name="Synthetic group", is_group=True, is_channel=True, entity=ENTITIES[CHAT], folder_id=None)
        yield NS(id=ALICE, name="Alice", is_group=False, is_channel=False, entity=ENTITIES[ALICE], folder_id=None)
        yield NS(id=SHOP_BOT, name="Shop", is_group=False, is_channel=False, entity=ENTITIES[SHOP_BOT], folder_id=None)
        yield NS(id=NEWS, name="News", is_group=False, is_channel=True, entity=ENTITIES[NEWS], folder_id=1)

    async def get_entity(self, peer):
        return ENTITIES[peer]

    async def __call__(self, request):
        title = types.TextWithEntities("Work", [])
        return types.messages.DialogFilters(filters=[
            types.DialogFilterDefault(),
            types.DialogFilter(id=2, title=title, pinned_peers=[], include_peers=[types.InputPeerUser(ALICE, 1)],
                               exclude_peers=[], bots=True, exclude_archived=True)])

    async def get_messages(self, entity, limit=None, ids=None):
        return [] if ids is None else [None for _ in ids]

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0, reverse=False):
        return
        yield


def message(chat_id, id=1, text="hi", out=False):
    peer = types.PeerUser(chat_id) if chat_id > 0 else types.PeerChannel(-chat_id - 1000000000000)
    return types.Message(id=id, peer_id=peer, date=NOW, message=text, out=out,
                         from_id=types.PeerUser(44 if out else (chat_id if chat_id > 0 else 55)))


async def collector_with(store, vault, scope=None):
    collector = Collector(store, vault, ScopeClient)
    await collector.configure(123, "a" * 32, saved_session())
    if scope:
        store.set_setting("scope", scope)
    return collector


def kinds(store, kind):
    return [e for e in store.all_events() if e["kind"] == kind]


def test_whole_account_mode_adds_existing_and_new_chats_by_type(journal):
    store, vault = journal

    async def run():
        collector = await collector_with(store, vault, {"mode": "account", "types": {
            "channels": False, "groups": True, "private": True, "bots": True}})
        await collector.start()  # no chosen chats needed in whole-account mode
        added = {t["chat_id"]: t for t in store.targets()}
        assert set(added) == {CHAT, ALICE, SHOP_BOT}  # the broadcast channel type is off
        assert all(t["origin"] == "scope" and t["priority"] == 0 for t in added.values())
        assert kinds(store, "scope.applied")[0]["payload"]["mode"] == "account"
        # A chat that first appears while observing is added on the spot and recorded.
        await collector.on_new(NS(chat_id=NEW_BOT, message=message(NEW_BOT), chat=ENTITIES[NEW_BOT]))
        await collector.on_new(NS(chat_id=NEWS, message=message(NEWS)))  # channels are off: ignored
        discovered = kinds(store, "source.discovered")
        assert [(e["chat_id"], e["payload"]["kind"]) for e in discovered] == [(NEW_BOT, "bot")]
        assert [e["chat_id"] for e in kinds(store, "message.new")] == [NEW_BOT]
        # A chat Telegram could not describe yet is not declined for good: its next message decides.
        stranger, ENTITIES[STRANGER] = ENTITIES[STRANGER], None
        try:
            assert not await collector.covers(STRANGER)
        finally:
            ENTITIES[STRANGER] = stranger
        await collector.on_new(NS(chat_id=STRANGER, message=message(STRANGER), chat=stranger))
        assert [e["chat_id"] for e in kinds(store, "message.new")] == [NEW_BOT, STRANGER]
        await collector.stop()
    asyncio.run(run())


def test_folder_mode_follows_folder_rules_and_exclusions(journal):
    store, vault = journal

    async def run():
        collector = await collector_with(store, vault, {"mode": "folder", "folder_id": 2, "exclude": [SHOP_BOT]})
        result = await collector.dialogs()
        assert [f["title"] for f in result["folders"]] == ["Work"]
        await collector.start()
        # Alice is included by name; bots by category, but the shop bot is excluded; the group is not in the folder.
        assert [t["chat_id"] for t in store.targets(True)] == [ALICE]
        await collector.on_new(NS(chat_id=STRANGER, message=message(STRANGER)))  # not a contact, not in the folder
        await collector.on_new(NS(chat_id=NEW_BOT, message=message(NEW_BOT)))     # bots belong to the folder
        await collector.on_new(NS(chat_id=SHOP_BOT, message=message(SHOP_BOT)))   # excluded
        assert sorted(e["chat_id"] for e in kinds(store, "message.new")) == [NEW_BOT]
        # Paused when it left the folder, now beyond the dialogs read: its membership is unknown, it stays paused.
        store.set_target(STRANGER, "Stranger", "private", False, origin="scope", priority=0)
        assert (await collector.apply_scope())["resumed"] == 0
        assert sorted(t["chat_id"] for t in store.targets(True)) == [ALICE, NEW_BOT]
        # Back to chosen chats: automatically added sources are paused, nothing else is recorded.
        store.set_setting("scope", {"mode": "selected"})
        changed = await collector.apply_scope()
        assert changed["paused"] == 2 and not store.targets(True)
        await collector.on_new(NS(chat_id=ALICE, message=message(ALICE, 2)))
        assert len(kinds(store, "message.new")) == 1
        await collector.stop()
    asyncio.run(run())


def test_folder_mode_starts_with_the_folders_read_last_time_when_telegram_does_not_answer(journal):
    store, vault = journal

    class Silent(ScopeClient):
        async def __call__(self, request):
            raise TimeoutError()

    async def run():
        collector = await collector_with(store, vault, {"mode": "folder", "folder_id": 2})
        await collector.start()
        await collector.stop()
        restarted = Collector(store, vault, Silent)  # a new process: nothing in memory
        await restarted.configure(123, "a" * 32, saved_session())
        await restarted.start()
        assert restarted.running and restarted.folders[2]["title"] == "Work"
        await restarted.stop()
    asyncio.run(run())


def test_own_actions_deletions_in_private_chats_and_button_presses(journal):
    store, vault = journal

    async def run():
        collector = await collector_with(store, vault, {"mode": "account"})
        await collector.start()
        keyboard = types.ReplyKeyboardMarkup(rows=[types.KeyboardButtonRow(
            buttons=[types.KeyboardButton("Buy", types.ButtonTypeDefault()),
                     types.KeyboardButton("Help", types.ButtonTypeDefault())])])
        offer = message(SHOP_BOT, 10, "Choose")
        offer.reply_markup = keyboard
        await collector.on_new(NS(chat_id=SHOP_BOT, message=offer))
        await collector.on_new(NS(chat_id=SHOP_BOT, message=message(SHOP_BOT, 11, "Buy", out=True)))
        press = kinds(store, "message.new")[-1]["payload"]
        assert press["outgoing"] is True and press["button_press"]["text"] == "Buy"
        assert press["button_press"]["keyboard_event"] == kinds(store, "message.new")[0]["seq"]
        await collector.on_edit(NS(chat_id=SHOP_BOT, message=message(SHOP_BOT, 11, "Buy now", out=True)))
        assert "only its author" in kinds(store, "message.edited")[0]["payload"]["editor_visibility"]
        # Not presses: an edit to a button's text, a snapshot of it, an older message before the keyboard.
        await collector.on_edit(NS(chat_id=SHOP_BOT, message=message(SHOP_BOT, 11, "Help", out=True)))
        await collector.capture_message(message(SHOP_BOT, 12, "Help", out=True), "message.snapshot", SHOP_BOT)
        await collector.capture_message(message(SHOP_BOT, 9, "Buy", out=True), "message.new", SHOP_BOT)
        assert not any("button_press" in e["payload"] for e in store.all_events()
                       if e["message_id"] in (9, 12) or e["kind"] == "message.edited")
        # Private-chat deletions arrive without a chat; the saved message ID identifies it.
        await collector.on_delete(NS(chat_id=None, deleted_ids=[11, 5000], original_update={"_": "UpdateDeleteMessages"}))
        deleted = kinds(store, "message.deleted")
        assert [(e["chat_id"], e["message_id"]) for e in deleted] == [(SHOP_BOT, 11)]
        assert deleted[0]["payload"]["chat_resolution"]["method"].startswith("chat of the previously saved")
        assert deleted[0]["payload"]["deleted_message_was_outgoing"] is True
        assert kinds(store, "deletion.unscoped")[0]["payload"]["message_ids"] == [5000]
        # Leaving out own actions skips outgoing messages only.
        store.set_setting("scope", {"mode": "account", "own_actions": False})
        await collector.on_new(NS(chat_id=ALICE, message=message(ALICE, 20, "mine", out=True)))
        await collector.on_new(NS(chat_id=ALICE, message=message(ALICE, 21, "theirs")))
        assert [e["message_id"] for e in kinds(store, "message.new") if e["chat_id"] == ALICE] == [21]
        await collector.stop()
    asyncio.run(run())


def test_recheck_tiers_and_media_rules_by_type(journal, monkeypatch):
    import time
    store, vault = journal

    async def run():
        collector = await collector_with(store, vault)
        store.set_target(CHAT, "Priority", "supergroup", True)                     # chosen: priority
        store.set_target(ALICE, "Alice", "private", True, origin="scope", priority=0)  # added: other tier
        assert [t["chat_id"] for t in collector.due_targets()] == [CHAT, ALICE]  # never checked
        now = time.time()
        store.set_setting("recheck_last", {str(CHAT): now - 20 * 60, str(ALICE): now - 20 * 60})
        assert [t["chat_id"] for t in collector.due_targets()] == [CHAT]         # 15 min vs 6 h
        store.set_setting("recheck_last", {str(CHAT): now, str(ALICE): now})
        assert [t["chat_id"] for t in collector.due_targets(forced=True)] == [CHAT]  # reconnect: priority only
        store.set_setting("recheck_other_minutes", 0)
        store.set_setting("recheck_last", {})
        assert [t["chat_id"] for t in collector.due_targets()] == [CHAT]         # other tier switched off
        # Per-type attachment rules: documents off, photos kept.
        store.set_setting("account", {"id": 44})
        store.set_setting("capture", {"download_media": True, "max_media_mb": 20, "types": {
            "document": {"enabled": False, "max_mb": 20}, "photo": {"enabled": True, "max_mb": 5}}})
        await collector.capture_message(media_message(), "message.new", CHAT)
        assert "type not collected by policy: document" in kinds(store, "media.skipped")[0]["payload"]["reason"]
        store.set_setting("capture", {"download_media": True, "max_media_mb": 20, "types": {
            "document": {"enabled": True, "max_mb": 300}}})
        record = await collector.capture_message(media_message(12), "message.new", CHAT)
        assert record["payload"]["media_capture"]["media_type"] == "document"
        assert record["payload"]["media_capture"]["max_bytes"] == 300 * 1024**2
    asyncio.run(run())


def test_scope_api_requires_acknowledgement_and_removal_cleans_up(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert c.post("/api/scope", json={"mode": "account"}).status_code == 409  # warning not confirmed
        state = c.post("/api/scope", json={"mode": "account", "acknowledged": True}).json()
        assert state["settings"]["mode"] == "account" and "third parties" in state["warning"]
        change = app.state.store.events(kind="scope.changed")[0]["payload"]
        assert change["acknowledged"] is True and change["after"]["mode"] == "account"
        assert c.post("/api/scope", json={"mode": "folder", "acknowledged": True}).status_code == 422  # no folder
        assert c.post("/api/recheck", json={"recheck_minutes": 10, "recheck_other_minutes": 720}).status_code == 200
        assert c.get("/api/status").json()["recheck"] == {"recheck_minutes": 10, "recheck_other_minutes": 720}
        store = app.state.store
        store.set_target(CHAT, "Synthetic", "supergroup", True, origin="scope", priority=0)
        store.append("message.new", {"text": "file"}, CHAT, 7, media_job={"account_id": 1, "descriptor": b"x",
                                                                          "max_bytes": 10})
        assert c.post("/api/targets/priority", json={"chat_id": CHAT, "priority": True}).json()["targets"][0]["priority"] == 1
        assert c.post("/api/chats/" + str(CHAT) + "/dossier", json={"enabled": True}).status_code == 200
        assert c.delete("/api/targets/" + str(CHAT)).status_code == 200
        assert store.targets() == [] and c.get("/api/status").json()["dossiers"] == []
        assert CHAT in c.get("/api/scope").json()["settings"]["exclude"]  # account mode would add it back
        assert store.events(kind="target.removed")[0]["payload"]["dossier_removed"] is True
        # Its file still waiting is given up and recorded, not left pending for ever.
        assert store.media_stats() == {"failed": 1} and store.media_oldest() is None
        assert store.events(kind="media.failed")[0]["payload"]["error_type"] == "source_removed"
        # Chosen again by hand: the exclusion goes, so the scope does not pause it at its next refresh.
        app.state.collector.dialog_cache[CHAT] = {"chat_id": CHAT, "title": "Synthetic", "kind": "supergroup"}
        assert c.post("/api/targets", json={"chat_id": CHAT, "enabled": True}).status_code == 200
        assert CHAT not in c.get("/api/scope").json()["settings"]["exclude"]
        assert store.events(kind="target.changed")[-1]["payload"]["removed_from_scope_exclusions"] is True
        # A full exclusion list refuses the removal instead of breaking the scope settings.
        store.set_setting("scope", {**c.get("/api/scope").json()["settings"], "exclude": list(range(1, 5001))})
        assert c.delete("/api/targets/" + str(CHAT)).status_code == 409
        assert [t["chat_id"] for t in store.targets()] == [CHAT] and c.get("/api/status").status_code == 200
