import asyncio
from types import SimpleNamespace as NS

from fastapi.testclient import TestClient
from telethon.tl import functions, types

from tgwitness import keyboard
from tgwitness.app import create_app
from tgwitness.collector import Collector, plain
from tests.test_collector import saved_session
from tests.test_scope import ENTITIES, NEW_BOT, SHOP_BOT, ScopeClient, kinds, message


def button(text, kind):
    return types.KeyboardInlineButton(text=text, type=kind)


def offer(message_id=10, text="Choose a payment method", url="https://pay.example/a"):
    item = message(SHOP_BOT, message_id, text)
    item.reply_markup = types.ReplyInlineMarkup(rows=[
        types.KeyboardInlineButtonRow(buttons=[button("Pay", types.InlineButtonTypeUrl(url)),
                                               button("I paid", types.InlineButtonTypeCallback(b"paid:7"))]),
        types.KeyboardInlineButtonRow(buttons=[button("Open shop", types.InlineButtonTypeWebView("https://shop.example/app")),
                                               button("Copy code", types.InlineButtonTypeCopy("PROMO-7"))])])
    return item


class InvestigationClient(ScopeClient):
    """A bot with a profile and two earlier messages in its chat."""
    async def __call__(self, request):
        if isinstance(request, functions.users.GetFullUserRequest):
            return types.users.UserFull(full_user=types.UserFull(
                id=NEW_BOT, settings=types.PeerSettings(), notify_settings=types.PeerNotifySettings(),
                common_chats_count=0, about="Fast exchange 24/7",
                bot_info=types.BotInfo(description="Send /start to get your personal link",
                                       commands=[types.BotCommand("start", "Begin"), types.BotCommand("pay", "Payment link")])),
                chats=[], users=[])
        return await super().__call__(request)

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0, reverse=False):
        for item in (message(NEW_BOT, 2, "Welcome! Your link: https://evil.example/x"), message(NEW_BOT, 1, "/start", out=True)):
            yield item


def test_buttons_are_read_from_saved_objects():
    found = keyboard.keyboard(plain(offer().reply_markup))
    assert found["inline"] is True
    assert found["rows"][0] == [{"type": "url", "text": "Pay", "url": "https://pay.example/a"},
                                {"type": "callback", "text": "I paid", "data_base64": "cGFpZDo3"}]
    assert found["rows"][1] == [{"type": "web_app", "text": "Open shop", "url": "https://shop.example/app"},
                                {"type": "copy", "text": "Copy code", "copy_text": "PROMO-7"}]
    assert keyboard.keyboard(None) is None and keyboard.keyboard({"_": "ReplyKeyboardHide"}) is None

    old = {"_": "ReplyInlineMarkup", "rows": [{"_": "KeyboardButtonRow", "buttons": [
        {"_": "KeyboardButtonUrl", "text": "Pay", "url": "https://pay.example/old"},
        {"_": "KeyboardButtonCallback", "text": "Paid", "data": {"bytes_base64": "eA=="}}]}]}
    assert keyboard.keyboard(old)["rows"][0] == [{"type": "url", "text": "Pay", "url": "https://pay.example/old"},
                                                 {"type": "callback", "text": "Paid", "data_base64": "eA=="}]
    reply = keyboard.keyboard(plain(types.ReplyKeyboardMarkup(rows=[types.KeyboardButtonRow(buttons=[
        types.KeyboardButton("Share phone", types.ButtonTypeRequestPhone())])])))
    assert reply == {"inline": False, "rows": [[{"type": "request_phone", "text": "Share phone"}]]}


def test_bot_buttons_are_kept_and_button_only_edits_recorded(journal):
    store, vault = journal

    async def run():
        collector = Collector(store, vault, ScopeClient)
        await collector.configure(123, "a" * 32, saved_session())
        store.set_setting("scope", {"mode": "account"})
        await collector.start()
        await collector.on_new(NS(chat_id=SHOP_BOT, message=offer()))

        await collector.on_edit(NS(chat_id=SHOP_BOT, message=offer(url="https://pay.example/b")))
        await collector.on_edit(NS(chat_id=SHOP_BOT, message=offer(url="https://pay.example/b")))
        assert len(kinds(store, "message.edited")) == 1
        shown = store.chat_messages(SHOP_BOT)["messages"][0]
        assert [v["buttons"]["rows"][0][0]["url"] for v in shown["versions"]] == ["https://pay.example/a",
                                                                                 "https://pay.example/b"]
        assert shown["buttons"]["rows"][1][0]["type"] == "web_app" and shown["edited"] is True

        changed = offer(url="https://pay.example/c")
        changed.edit_date = None

        async def get_messages(entity, ids=None, limit=None):
            return [changed for _ in ids] if ids else []
        collector.client.get_messages = get_messages
        result = await collector.recheck_chat(SHOP_BOT, {"messages": False, "edits": True, "deletions": True,
                                                         "reactions": True, "membership": True})
        assert result["edited"] == 1
        assert store.chat_messages(SHOP_BOT)["messages"][0]["buttons"]["rows"][0][0]["url"] == "https://pay.example/c"
        await collector.stop()
    asyncio.run(run())


def test_a_new_bot_gets_its_profile_and_earlier_messages_saved(journal):
    store, vault = journal

    async def run():
        collector = Collector(store, vault, InvestigationClient)
        await collector.configure(123, "a" * 32, saved_session())
        store.set_setting("scope", {"mode": "account", "new_chats": {"profile": True, "history": 50}})
        await collector.start()
        await collector.on_new(NS(chat_id=NEW_BOT, message=message(NEW_BOT, 3, "Pay here"), chat=ENTITIES[NEW_BOT]))
        for _ in range(50):
            if kinds(store, "snapshot.completed"):
                break
            await asyncio.sleep(0.02)
        profile = kinds(store, "source.profile")[0]
        assert profile["chat_id"] == NEW_BOT and profile["payload"]["about"] == "Fast exchange 24/7"
        assert profile["payload"]["bot"]["description"].startswith("Send /start")
        assert [c["command"] for c in profile["payload"]["bot"]["commands"]] == ["start", "pay"]
        snapshot = kinds(store, "snapshot.started")[0]["payload"]
        assert snapshot["origin"] == "new_chat" and snapshot["limit"] == 50
        earlier = [e for e in kinds(store, "message.snapshot") if e["chat_id"] == NEW_BOT]
        assert sorted(e["message_id"] for e in earlier) == [1, 2]
        assert all(e["payload"]["source"] == "new_chat_snapshot" for e in earlier)
        assert kinds(store, "snapshot.completed")[0]["payload"]["captured"] == 2

        assert not [e for e in kinds(store, "snapshot.started") if e["chat_id"] != NEW_BOT]
        await collector.stop()
    asyncio.run(run())


def test_profile_and_scope_api(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=InvestigationClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        state = c.post("/api/scope", json={"mode": "account", "acknowledged": True,
                                           "new_chats": {"profile": True, "history": 200}}).json()
        assert state["settings"]["new_chats"] == {"profile": True, "history": 200}
        assert c.post("/api/scope", json={"mode": "account", "new_chats": {"history": 5000}}).status_code == 422
        assert c.get("/api/chats/" + str(NEW_BOT) + "/profile").json() == {"profile": None}
        c.post("/api/auth/configure", json={"api_id": 123, "api_hash": "a" * 32})
        c.post("/api/auth/phone", json={"phone": "+15551112222"})
        c.post("/api/auth/code", json={"code": "12345"})
        saved = c.post("/api/chats/" + str(NEW_BOT) + "/profile", json={}).json()
        assert saved["profile"]["bot"]["commands"][1]["command"] == "pay" and "raw" not in saved["profile"]
        assert c.get("/api/chats/" + str(NEW_BOT) + "/profile").json()["seq"] == saved["seq"]
