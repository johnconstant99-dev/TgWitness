"""Explicit panel actions on the workspace's Telegram session, with durable receipts."""
import asyncio
import base64
import re
import secrets
import time
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator
from telethon import utils
from telethon.errors import FloodWaitError, InviteRequestSentError, RPCError, UserAlreadyParticipantError
from telethon.tl import functions, types

from . import keyboard
from .collector import buttons_of, plain
from .scope import kind_of, scope_settings, unexclude
from .store import canonical


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    link: str = Field(min_length=1, max_length=512)


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{16,80}$")
    action: Literal["open", "send", "press"]
    preview_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    chat_id: int | None = None
    text: str | None = Field(default=None, max_length=4096)
    reply_to: int | None = Field(default=None, gt=0)
    message_id: int | None = Field(default=None, gt=0)
    keyboard_event: int | None = Field(default=None, gt=0)
    row: int | None = Field(default=None, ge=0, le=99)
    column: int | None = Field(default=None, ge=0, le=99)

    @model_validator(mode="after")
    def complete(self):
        if self.action == "open" and not self.preview_id:
            raise ValueError("Preview the Telegram link first.")
        if self.action != "open" and self.chat_id is None:
            raise ValueError("Select a chat.")
        if self.action == "send" and (not self.text or not self.text.strip()
                                     or len(self.text.encode("utf-16-le")) // 2 > 4096):
            raise ValueError("Enter a message of up to 4096 characters.")
        if self.action == "press" and any(v is None for v in (
                self.message_id, self.keyboard_event, self.row, self.column)):
            raise ValueError("Select a saved message button.")
        return self


def parse_link(value):
    value = value.strip()
    if re.fullmatch(r"@[A-Za-z][A-Za-z0-9_]{3,31}", value):
        return {"username": value[1:], "start": None}
    if value.startswith(("t.me/", "telegram.me/")):
        value = "https://" + value
    url = urlsplit(value)
    if (url.scheme != "https" or url.netloc not in ("t.me", "telegram.me") or url.fragment):
        raise ValueError("Use a Telegram username or an https://t.me/ link.")
    path = url.path.strip("/")
    invite = re.fullmatch(r"(?:\+|joinchat/)([A-Za-z0-9_-]+)", path)
    if invite and not url.query:
        return {"invite": invite[1]}
    query = parse_qs(url.query, keep_blank_values=True)
    if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", path)
            or set(query) - {"start"} or len(query.get("start", [])) > 1):
        raise ValueError("Use a chat invite, username or bot start link.")
    start = query.get("start", [None])[0]
    if start is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", start):
        raise ValueError("Invalid bot start parameter.")
    return {"username": path, "start": start}


def check_pause(collector):
    until = collector.store.get_setting("rpc_backoff_until", 0)
    if time.time() < until:
        raise FloodWaitError(None, capture=max(1, int(until - time.time()) + 1))


async def preview(collector, body):
    check_pause(collector)
    target = parse_link(body.link)
    await collector.restore()
    if "invite" in target:
        entity = await collector.client(functions.messages.CheckChatInviteRequest(target["invite"]))
        chat = getattr(entity, "chat", None)
        title = getattr(entity, "title", None) or utils.get_display_name(chat)
        kind = kind_of(chat) if chat else "group"
        member = isinstance(entity, types.ChatInviteAlready)
    else:
        entity = await collector.client.get_entity(target["username"])
        title, kind, member = utils.get_display_name(entity), kind_of(entity), None
        if target["start"] is not None and not getattr(entity, "bot", False):
            raise ValueError("The start parameter requires a bot.")
    result = {"preview_id": secrets.token_hex(16), "link": body.link.strip(), "target": target,
              "title": title, "kind": kind, "already_member": member,
              "about": getattr(entity, "about", None),
              "participants_count": getattr(entity, "participants_count", None),
              "request_needed": bool(getattr(entity, "request_needed", False)),
              "expires_at": time.time() + 600,
              "account_id": (collector.store.get_setting("account", {}) or {}).get("id"),
              "raw": plain(entity)}
    with collector.store.transaction():
        event = collector.store.append("interaction.preview", result)
        result["preview_event"] = event["seq"]
        collector.store.set_setting("interaction.preview." + result["preview_id"], result)
    return {k: v for k, v in result.items() if k not in ("raw", "target")}


def observe(collector, entity):
    chat_id = utils.get_peer_id(entity)
    title, kind = utils.get_display_name(entity), kind_of(entity)
    collector.dialog_cache[chat_id] = {"chat_id": chat_id, "title": title, "kind": kind, "entity": entity}
    if not collector.selected(chat_id):
        with collector.store.transaction():
            collector.store.set_target(chat_id, title, kind, True, origin="manual")
            included = unexclude(collector.store, chat_id)
            collector.store.append("source.added", {"title": title, "kind": kind, "source": "panel_interaction",
                                                   **({"removed_from_scope_exclusions": True} if included else {})},
                                   chat_id)
        if collector.running:
            collector.intake.put_nowait((chat_id, entity))
    return chat_id


async def sent(collector, entity, text, reply_to=None):
    message = await collector.client.send_message(entity, text, reply_to=reply_to,
                                                  parse_mode=None, link_preview=False)
    chat_id = utils.get_peer_id(entity)
    event = await collector.capture_message(message, "message.new", chat_id, source="panel_action")
    return {"chat_id": chat_id, "message_id": message.id, "message_event": event["seq"]}


async def execute(collector, body):
    """Called under the workspace operation lock. A recorded request is never executed twice.

    A crash between the intent and receipt leaves an unknown outcome, including after restart.
    No retry of side effects is attempted here. Telegram/transport errors can be ambiguous.
    """
    store = collector.store
    key = "interaction.action." + body.request_id
    request = body.model_dump()
    prior = store.get_setting(key, None)
    if prior:
        if canonical(prior["request"]) != canonical(request):
            raise ValueError("This request ID belongs to another action.")
        return prior.get("result") or {"request_id": body.request_id, "status": "unknown",
                                       "request_event": prior["request_event"]}
    check_pause(collector)
    await collector.restore()
    account = (store.get_setting("account", {}) or {}).get("id")
    prepared, entity = None, None
    if body.action == "open":
        prepared = store.get_setting("interaction.preview." + body.preview_id, None)
        if not prepared or prepared["expires_at"] < time.time() or prepared["account_id"] != account:
            raise ValueError("The preview expired. Preview the Telegram link again.")
    else:
        entity = await collector.resolve_target(body.chat_id)
        if not collector.selected(body.chat_id):
            raise ValueError("Enable observation for this chat in Sources first.")
    selected = None
    if body.action == "press":
        events = store.events(chat_id=body.chat_id, message_id=body.message_id,
                              before=body.keyboard_event + 1, limit=1)
        if not events or events[0]["seq"] != body.keyboard_event:
            raise ValueError("Select a saved message button.")
        saved = keyboard.of_payload(events[0]["payload"])
        current = await collector.client.get_messages(entity, ids=body.message_id)
        live = buttons_of(current) if current else None
        if not live or live != saved:
            if current:
                await collector.capture_message(current, "message.edited", body.chat_id,
                                                source="panel_button_check")
            raise ValueError("The buttons changed or the message disappeared. Refresh the chat.")
        try:
            selected = live["rows"][body.row][body.column]
        except IndexError:
            raise ValueError("Select a saved message button.") from None
        if selected["type"] not in ("callback", "text"):
            raise ValueError("This button type must be opened in Telegram.")
    details = {"request": request, "account_id": account, "observation_running": collector.running,
               "own_actions": scope_settings(store)["own_actions"], "button": selected,
               "preview_event": prepared["preview_event"] if prepared else None}
    with store.transaction():
        event = store.append("interaction.requested", details, body.chat_id, body.message_id, account)
        pending = {"request": request, "request_event": event["seq"]}
        store.set_setting(key, pending)
    result = {"request_id": body.request_id, "request_event": event["seq"], "status": "succeeded"}
    cancelled, dispatched = False, False
    try:
        if body.action == "open":
            target = prepared["target"]
            if "invite" in target:
                checked = await collector.client(functions.messages.CheckChatInviteRequest(target["invite"]))
                if isinstance(checked, types.ChatInviteAlready):
                    entity = checked.chat
                else:
                    dispatched = True
                    joined = await collector.client(functions.messages.ImportChatInviteRequest(target["invite"]))
                    entity = joined.chats[0]
            else:
                entity = await collector.client.get_entity(target["username"])

                if entity.id != prepared["raw"]["id"]:
                    raise ValueError("The link destination changed. Preview it again.")
                if isinstance(entity, types.Channel):
                    try:
                        dispatched = True
                        await collector.client(functions.channels.JoinChannelRequest(entity))
                    except UserAlreadyParticipantError:
                        pass
            result["chat_id"] = observe(collector, entity)
            if getattr(entity, "bot", False):
                dispatched = True
                result.update(await sent(collector, entity, "/start" + (
                    " " + target["start"] if target.get("start") else "")))
        elif body.action == "send":
            dispatched = True
            result.update(await sent(collector, entity, body.text, body.reply_to))
        elif selected["type"] == "text":
            dispatched = True
            result.update(await sent(collector, entity, selected["text"]))
        else:
            dispatched = True
            answer = await collector.client(functions.messages.GetBotCallbackAnswerRequest(
                entity, body.message_id, data=base64.b64decode(selected.get("data_base64", ""))))
            result.update(chat_id=body.chat_id, message_id=body.message_id, answer=plain(answer))
    except InviteRequestSentError:
        result["status"] = "approval_pending"
    except FloodWaitError as exc:
        store.set_setting("rpc_backoff_until", max(time.time() + exc.seconds,
                                                   store.get_setting("rpc_backoff_until", 0)))
        result.update(status="rejected", error_type=type(exc).__name__, retry_after=exc.seconds)
    except (Exception, asyncio.CancelledError) as exc:
        cancelled = isinstance(exc, asyncio.CancelledError)
        definite = (isinstance(exc, ValueError) and not dispatched) or (isinstance(exc, RPCError) and exc.code < 500
                                                  and type(exc).__name__ != "BotResponseTimeoutError")
        result.update(status="rejected" if definite else "unknown", error_type=type(exc).__name__)
    with store.transaction():
        receipt = store.append("interaction.result", result, result.get("chat_id", body.chat_id),
                               result.get("message_id", body.message_id), account)
        result["result_event"] = receipt["seq"]
        store.set_setting(key, {**pending, "result": result})
    if cancelled:
        raise asyncio.CancelledError
    return result
