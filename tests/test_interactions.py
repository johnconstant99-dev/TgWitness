import asyncio
import time
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient
from telethon.errors import FloodWaitError, InviteRequestSentError, BotResponseTimeoutError
from telethon.tl import functions, types

from tgwitness.app import create_app
from tgwitness.collector import Collector
from tgwitness.interactions import Action, Preview, execute, parse_link, preview
from tests.test_collector import CHAT, saved_session
from tests.test_investigation import offer
from tests.test_scope import ENTITIES, SHOP_BOT, ScopeClient, message, kinds


class InteractionClient(ScopeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent, self.callbacks, self.joined = [], [], []
        self.failure = None
        self.current = offer()
        self.pending_join = False

    async def get_entity(self, peer):
        if isinstance(peer, str):
            return ENTITIES[SHOP_BOT] if peer == "shop_bot" else ENTITIES[CHAT]
        return await super().get_entity(peer)

    async def send_message(self, entity, text, **kwargs):
        self.sent.append((entity.id, text, kwargs))
        if self.failure:
            raise self.failure
        item = message(entity.id, 100 + len(self.sent), text, out=True)
        if kwargs.get("reply_to"):
            item.reply_to = types.MessageReplyHeader(reply_to_msg_id=kwargs["reply_to"])
        return item

    async def get_messages(self, entity, limit=None, ids=None):
        if isinstance(ids, int):
            return self.current
        return await super().get_messages(entity, limit=limit, ids=ids)

    async def __call__(self, request):
        if isinstance(request, functions.messages.GetBotCallbackAnswerRequest):
            self.callbacks.append(request)
            if self.failure:
                raise self.failure
            return types.messages.BotCallbackAnswer(cache_time=0, message="Recorded answer", alert=True,
                                                     url="https://example.test/receipt")
        if isinstance(request, functions.messages.CheckChatInviteRequest):
            return types.ChatInvite(title="Preview group", photo=types.PhotoEmpty(1), participants_count=9, color=0)
        if isinstance(request, (functions.messages.ImportChatInviteRequest, functions.channels.JoinChannelRequest)):
            self.joined.append(request)
            if self.pending_join:
                raise InviteRequestSentError(request)
            return NS(chats=[ENTITIES[CHAT]])
        return await super().__call__(request)


async def ready(store, vault):
    collector = Collector(store, vault, InteractionClient)
    await collector.configure(123, "a" * 32, saved_session())
    await collector.dialogs()
    store.set_target(SHOP_BOT, "Shop", "bot", True)
    return collector


def action(kind="send", **kwargs):
    return Action(request_id="request-0000000001", action=kind, **kwargs)


@pytest.mark.parametrize("link", ["https://evil.test/shop_bot", "https://t.me.evil.test/a", "tg://join?invite=abc",
                                   "https://t.me/shop_bot?startgroup=x", "https://t.me/shop_bot/123",
                                   "https://user@t.me/shop_bot", "https://t.me/+abc?x=1"])
def test_links_are_parsed_without_fetching_arbitrary_urls(link):
    with pytest.raises(ValueError):
        parse_link(link)


def test_send_audits_plain_text_and_deduplicates_after_collector_restart(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        body = action(chat_id=SHOP_BOT, text="**literal** <b>text</b>", reply_to=10)
        result = await execute(collector, body)
        assert result["status"] == "succeeded"
        assert collector.client.sent[0][2] == {"reply_to": 10, "parse_mode": None, "link_preview": False}
        assert kinds(store, "interaction.requested")[0]["seq"] < kinds(store, "message.new")[0]["seq"]
        assert kinds(store, "message.new")[0]["payload"]["source"] == "panel_action"
        assert kinds(store, "interaction.result")[0]["payload"]["message_id"] == 101
        restarted = Collector(store, vault, InteractionClient)
        assert await execute(restarted, body) == result
        assert restarted.client is None
        with pytest.raises(ValueError):
            await execute(collector, body.model_copy(update={"text": "changed"}))
        await collector.stop()
    asyncio.run(run())


def test_callback_receipt_contains_popup_url_and_original_button(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        saved = await collector.capture_message(offer(), "message.new", SHOP_BOT)
        body = action("press", chat_id=SHOP_BOT, message_id=10, keyboard_event=saved["seq"], row=0, column=1)
        result = await execute(collector, body)
        assert result["answer"]["message"] == "Recorded answer"
        assert result["answer"]["alert"] and result["answer"]["url"].endswith("/receipt")
        assert collector.client.callbacks[0].data == b"paid:7"
        assert kinds(store, "interaction.requested")[0]["payload"]["button"]["text"] == "I paid"
        assert await execute(collector, body) == result
        assert len(collector.client.callbacks) == 1
        await collector.stop()
    asyncio.run(run())


def test_changed_or_unsupported_button_never_executes(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        saved = await collector.capture_message(offer(), "message.new", SHOP_BOT)
        body = action("press", chat_id=SHOP_BOT, message_id=10, keyboard_event=saved["seq"], row=0, column=1)
        collector.client.current = offer(url="https://changed.test")
        with pytest.raises(ValueError, match="buttons changed"):
            await execute(collector, body)
        assert not collector.client.callbacks
        assert kinds(store, "message.edited")
        collector.client.current = offer()
        with pytest.raises(ValueError, match="button type"):
            await execute(collector, body.model_copy(update={"column": 0}))
        with pytest.raises(ValueError):
            await execute(collector, body.model_copy(update={"chat_id": CHAT}))
        await collector.stop()
    asyncio.run(run())


def test_reply_keyboard_sends_only_the_saved_button_text(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        item = message(SHOP_BOT, 12, "Choose")
        item.reply_markup = types.ReplyKeyboardMarkup(rows=[types.KeyboardButtonRow(buttons=[
            types.KeyboardButton("Details", types.ButtonTypeDefault())])])
        saved = await collector.capture_message(item, "message.new", SHOP_BOT)
        collector.client.current = item
        result = await execute(collector, action("press", chat_id=SHOP_BOT, message_id=12,
                               keyboard_event=saved["seq"], row=0, column=0))
        assert result["status"] == "succeeded"
        assert collector.client.sent[0][1] == "Details" and not collector.client.callbacks
        assert kinds(store, "interaction.requested")[0]["payload"]["button"]["type"] == "text"
        await collector.stop()
    asyncio.run(run())


@pytest.mark.parametrize("failure,status", [(TimeoutError(), "unknown"), (BotResponseTimeoutError(None), "unknown"),
                                           (FloodWaitError(None, capture=37), "rejected")])
def test_errors_preserve_uncertainty_and_respect_flood_wait(journal, failure, status):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        collector.client.failure = failure
        body = action(chat_id=SHOP_BOT, text="hello")
        result = await execute(collector, body)
        assert result["status"] == status
        assert await execute(collector, body) == result
        assert len(collector.client.sent) == 1
        if isinstance(failure, FloodWaitError):
            assert store.get_setting("rpc_backoff_until") > time.time()
            with pytest.raises(FloodWaitError):
                await execute(collector, body.model_copy(update={"request_id": "request-0000000002"}))
        await collector.stop()
    asyncio.run(run())


def test_cancelled_request_is_unknown_and_never_replayed(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        collector.client.failure = asyncio.CancelledError()
        body = action(chat_id=SHOP_BOT, text="hello")
        with pytest.raises(asyncio.CancelledError):
            await execute(collector, body)
        assert (await execute(collector, body))["status"] == "unknown"
        assert len(collector.client.sent) == 1
        await collector.stop()
    asyncio.run(run())


@pytest.mark.parametrize("pending", [False, True])
def test_invite_preview_precedes_join_and_pending_is_not_membership(journal, pending):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        p = await preview(collector, Preview(link="https://t.me/+invite_hash"))
        assert p["title"] == "Preview group" and not collector.client.joined
        collector.client.pending_join = pending
        result = await execute(collector, action("open", preview_id=p["preview_id"]))
        assert result["status"] == ("approval_pending" if pending else "succeeded")
        assert collector.selected(CHAT) is not pending
        assert kinds(store, "interaction.preview")[0]["payload"]["raw"]["participants_count"] == 9
        assert kinds(store, "interaction.requested")[0]["payload"]["preview_event"] == p["preview_event"]
        await collector.stop()
    asyncio.run(run())


def test_bot_deep_link_records_start_parameter_and_registers_chat(journal):
    store, vault = journal

    async def run():
        collector = await ready(store, vault)
        p = await preview(collector, Preview(link="https://t.me/shop_bot?start=case_7"))
        result = await execute(collector, action("open", preview_id=p["preview_id"]))
        assert result["chat_id"] == SHOP_BOT and collector.client.sent[0][1] == "/start case_7"
        p = await preview(collector, Preview(link="@shop_bot"))
        saved = store.get_setting("interaction.preview." + p["preview_id"])
        saved["expires_at"] = 0
        store.set_setting("interaction.preview." + p["preview_id"], saved)
        with pytest.raises(ValueError, match="expired"):
            await execute(collector, action("open", preview_id=p["preview_id"]).model_copy(update={"request_id": "request-0000000002"}))
        await collector.stop()
    asyncio.run(run())


def test_endpoints_require_auth_reject_demo_and_isolate_workspaces(tmp_path):
    app = create_app(tmp_path, client_factory=InteractionClient)
    with TestClient(app) as client:
        body = action(chat_id=SHOP_BOT, text="from main").model_dump()
        assert client.post("/api/interactions", json=body).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert client.post("/api/auth/configure", json={"api_id": 123, "api_hash": "a" * 32,
                                                        "session": saved_session()}).status_code == 200
        app.state.store.set_target(SHOP_BOT, "Shop", "bot", True)
        result = client.post("/api/interactions", json=body)
        assert result.status_code == 200 and result.json()["status"] == "succeeded"
        second = client.post("/api/profiles", json={"label": "Other"}).json()
        prefix = f"/profiles/{second['id']}/api/"
        assert client.post(prefix + "interactions", json=body).status_code == 400
        assert client.post(prefix + "auth/configure", json={"api_id": 124, "api_hash": "b" * 32,
                                                           "session": saved_session()}).status_code == 200
        child = app.state.profiles.entries[second["id"]]["app"]
        child.state.store.set_target(SHOP_BOT, "Shop", "bot", True)
        assert client.post(prefix + "interactions", json={**body, "text": "from other"}).json()["status"] == "succeeded"
        assert app.state.collector.client.sent[0][1] == "from main"
        assert child.state.collector.client.sent[0][1] == "from other"
        assert len(app.state.collector.client.sent) == len(child.state.collector.client.sent) == 1
        assert kinds(child.state.store, "interaction.requested")[0]["payload"]["account_id"] == 124
        assert client.post("/api/interactions", json={**body, "text": " "}).status_code == 422
    with TestClient(create_app(tmp_path / "demo", demo=True)) as client:
        client.headers["Authorization"] = "Bearer " + client.app.state.vault.token
        assert client.post("/api/interactions", json=body).status_code == 409
