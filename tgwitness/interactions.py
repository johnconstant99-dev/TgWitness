import asyncio
import base64
import re
import secrets
import time
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from telethon import utils
from telethon.errors import FloodWaitError, InviteRequestSentError, RPCError, UserAlreadyParticipantError
from .telegram_client import FLOOD_ERRORS
from telethon.tl import functions, types

from . import keyboard, tuning
from .collector import buttons_of, plain
from .scope import kind_of, scope_settings, unexclude, visibility
from .store import canonical

ACTION = "interaction.action."
QUEUE = "interaction.queue"
PACE = {"join": ("action_join_seconds", "action_joins_per_hour"),
        "message": ("action_message_seconds", "action_messages_per_hour"),
        "bot": ("action_button_seconds", "action_buttons_per_hour")}
READ_ONLY = "This account is read-only. Turn off Read-only on the account page to send, join or press bot buttons."
READ_ONLY_STOP = "Read-only was turned on before this action's turn. It was not sent."
RESTART_STOP = "TgWitness stopped before this action's turn. It was not sent."


class Preview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    link: str = Field(min_length=1, max_length=512)


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{16,80}$")
    action: Literal["open", "send", "press"]
    preview_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    observe: StrictBool | None = None
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


class ReadOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


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


RESTRICTIONS = {"FrozenMethodInvalidError": ("frozen", None), "UserRestrictedError": ("spam_block", 24 * 3600),
                "PeerFloodError": ("peer_flood", 24 * 3600)}
RESTRICTION_TEXT = {
    "frozen": "Telegram has frozen this account. Sending, joining and pressing bot buttons are off; reading continues.",
    "spam_block": "Telegram limits this account (spam block). Sending, joining and pressing bot buttons are off "
                  "until {until}; reading continues.",
    "peer_flood": "Telegram reported too many actions from this account (PEER_FLOOD). Sending, joining and pressing "
                  "bot buttons are off until {until}; reading continues."}


def restriction(store):
    current = store.get_setting("account_restriction", None)
    if current and current.get("until") and current["until"] < time.time():
        store.set_setting("account_restriction", None)
        store.append("account.restriction_expired", {"kind": current["kind"]})
        return None
    return current


def check_restriction(store):
    current = restriction(store)
    if current:
        until = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(current["until"])) if current.get("until") else None
        raise AccountRestricted(RESTRICTION_TEXT[current["kind"]].format(until=until))


def note_restriction(store, exc):
    kind, hold = RESTRICTIONS.get(type(exc).__name__, (None, None))
    if not kind:
        return
    value = {"kind": kind, "since": time.time(), "until": time.time() + hold if hold else None,
             "telegram_error": type(exc).__name__}
    store.set_setting("account_restriction", value)
    store.append("account.restricted", {**value, "meaning": RESTRICTION_TEXT[kind].split(".")[0] + "."})


class AccountRestricted(ValueError):
    pass


def read_only(store):
    chosen = store.get_setting("read_only", None)
    if isinstance(chosen, bool):
        return chosen
    return (store.get_setting("account", None) or {}).get("key_origin") != "created"


def set_read_only(store, enabled):
    with store.transaction():
        store.set_setting("read_only", enabled)
        store.append("account.read_only", {"enabled": enabled})
    if enabled:
        abandon(store, READ_ONLY_STOP)
    return pace_status(store)


def pace_status(store):
    pending = [store.get_setting(ACTION + r, None) or {} for r in store.get_setting(QUEUE, None) or []]
    times = [p["queued_until"] for p in pending if p.get("queued_until") and not p.get("result")]
    return {"read_only": read_only(store), "queued": len(times), "next_at": min(times, default=None)}


def permitted(collector):
    store = collector.store
    check_pause(collector)
    check_restriction(store)
    goal = (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")
    if goal == "evidence":
        raise ValueError("Telegram actions from the panel are off for the Evidence for a case goal.")
    if read_only(store):
        raise AccountRestricted(READ_ONLY)


def reserve(store, category):
    gap, hourly = (tuning.value(store, key) for key in PACE[category])
    now = time.time()
    with store.transaction():
        pace = store.get_setting("action_pace", None) or {}
        taken = sorted(t for t in pace.get(category, []) if t > now - max(gap, 3600))
        slot = max(now, taken[-1] + gap) if taken else now
        if len(taken) >= hourly:
            slot = max(slot, taken[-hourly] + 3600)
        store.set_setting("action_pace", {**pace, category: taken + [slot]})
    return slot


def progress(pending):
    if pending.get("result"):
        return pending["result"]
    state = {"request_id": pending["request"]["request_id"], "request_event": pending["request_event"]}
    if pending.get("queued_until"):
        return {**state, "status": "queued", "run_at": pending["queued_until"]}
    return {**state, "status": "unknown"}


def requested(store, request_id):
    return store.get_setting(ACTION + request_id, None) if re.fullmatch(r"[a-zA-Z0-9_-]{16,80}", request_id) else None


def waiting(store, request_id):
    return request_id in (store.get_setting(QUEUE, None) or [])


def finish(store, pending, result):
    request = pending["request"]
    with store.transaction():
        receipt = store.append("interaction.result", result, result.get("chat_id", request.get("chat_id")),
                               result.get("message_id", request.get("message_id")), pending.get("account_id"))
        result["result_event"] = receipt["seq"]
        store.set_setting(ACTION + request["request_id"], {**pending, "result": result})
        queue = store.get_setting(QUEUE, None) or []
        if request["request_id"] in queue:
            store.set_setting(QUEUE, [r for r in queue if r != request["request_id"]])
    return result


def abandon(store, reason, request_id=None):
    for queued in store.get_setting(QUEUE, None) or []:
        pending = store.get_setting(ACTION + queued, None)
        if request_id in (None, queued) and pending and not pending.get("result"):
            finish(store, pending, {"request_id": queued, "request_event": pending["request_event"],
                                    "status": "rejected", "error": reason})


async def channel_facts(collector, chat):
    if not isinstance(chat, types.Channel):
        return {}
    try:
        full = (await collector.client(functions.channels.GetFullChannelRequest(chat))).full_chat
    except Exception as exc:
        return {"full_info_error": type(exc).__name__}
    return {key: value for key, value in {"participants_count": full.participants_count,
                                          "history_visible": not full.hidden_prehistory,
                                          "about": full.about or None}.items() if value is not None}


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
        entity = chat = await collector.client.get_entity(target["username"])
        title, kind, member = utils.get_display_name(entity), kind_of(entity), None
        if target["start"] is not None and not getattr(entity, "bot", False):
            raise ValueError("The start parameter requires a bot.")
    facts = await channel_facts(collector, chat)
    about = facts.pop("about", None)
    result = {"preview_id": secrets.token_hex(16), "link": body.link.strip(), "target": target,
              "title": title, "kind": kind, "already_member": member,
              "about": getattr(entity, "about", None) or about,
              "participants_count": getattr(entity, "participants_count", None)
                                    or getattr(chat, "participants_count", None),
              "history_visible": None,
              "request_needed": bool(getattr(entity, "request_needed", False)),
              "expires_at": time.time() + 600,
              "account_id": (collector.store.get_setting("account", {}) or {}).get("id"),
              "raw": plain(entity), **facts}
    with collector.store.transaction():
        event = collector.store.append("interaction.preview", result)
        result["preview_event"] = event["seq"]
        collector.store.set_setting("interaction.preview." + result["preview_id"], result)
    return {k: v for k, v in result.items() if k not in ("raw", "target")}


def observe(collector, entity, add=True):
    chat_id = utils.get_peer_id(entity)
    title, kind = utils.get_display_name(entity), kind_of(entity)
    collector.dialog_cache[chat_id] = {"chat_id": chat_id, "title": title, "kind": kind, "entity": entity,
                                       "visibility": visibility(entity)}
    if add and not collector.selected(chat_id):
        with collector.store.transaction():
            collector.store.set_target(chat_id, title, kind, True, origin="manual")
            included = unexclude(collector.store, chat_id)
            collector.store.append("source.added", {"title": title, "kind": kind, "source": "panel_interaction",
                                                   **({"removed_from_scope_exclusions": True} if included else {})},
                                   chat_id)
            collector.request_baseline([chat_id])
        if collector.running:
            collector.intake.put_nowait((chat_id, entity, False))
    return chat_id


async def sent(collector, entity, text, reply_to=None):
    message = await collector.client.send_message(entity, text, reply_to=reply_to,
                                                  parse_mode=None, link_preview=False)
    chat_id = utils.get_peer_id(entity)
    event = await collector.capture_message(message, "message.new", chat_id, source="panel_action")
    return {"chat_id": chat_id, "message_id": message.id, "message_event": event["seq"]}


def prepare(collector, body, account, fresh=True):
    store = collector.store
    if body.action == "open":
        prepared = store.get_setting("interaction.preview." + body.preview_id, None)
        if not prepared or fresh and prepared["expires_at"] < time.time() or prepared["account_id"] != account:
            raise ValueError("The preview expired. Preview the Telegram link again.")
        return prepared, None, None
    if not collector.selected(body.chat_id):
        raise ValueError("Enable observation for this chat in Sources first.")
    if body.action == "send":
        return None, None, None
    events = store.events(chat_id=body.chat_id, message_id=body.message_id,
                          before=body.keyboard_event + 1, limit=1)
    if not events or events[0]["seq"] != body.keyboard_event:
        raise ValueError("Select a saved message button.")
    saved = keyboard.of_payload(events[0]["payload"])
    try:
        selected = saved["rows"][body.row][body.column]
    except (IndexError, KeyError, TypeError):
        raise ValueError("Select a saved message button.") from None
    if selected["type"] not in ("callback", "text"):
        raise ValueError("This button type must be opened in Telegram.")
    return None, saved, selected


def record(collector, body, account, prepared, selected, run_at=None):
    store = collector.store
    request = body.model_dump()
    details = {"request": request, "account_id": account, "observation_running": collector.running,
               "own_actions": scope_settings(store)["own_actions"], "button": selected,
               "preview_event": prepared["preview_event"] if prepared else None}
    pending = {"request": request, "account_id": account}
    if run_at:
        details["queued_until"] = pending["queued_until"] = run_at
    with store.transaction():
        event = store.append("interaction.requested", details, body.chat_id, body.message_id, account)
        pending["request_event"] = event["seq"]
        store.set_setting(ACTION + body.request_id, pending)
        if run_at:
            store.set_setting(QUEUE, (store.get_setting(QUEUE, None) or []) + [body.request_id])
    return pending


async def execute(collector, body, queue=None):
    store = collector.store
    prior = store.get_setting(ACTION + body.request_id, None)
    if prior:
        if canonical(prior["request"]) != canonical(body.model_dump()):
            raise ValueError("This request ID belongs to another action.")
        return progress(prior)
    permitted(collector)
    account = (store.get_setting("account", {}) or {}).get("id")
    prepared, saved, selected = prepare(collector, body, account)
    category = ("bot" if body.action == "press" else "message" if body.action == "send" or prepared["kind"] == "bot"
                else "join")
    run_at = reserve(store, category)
    if run_at > time.time():
        if queue:
            pending = record(collector, body, account, prepared, selected, run_at)
            queue(run_at, body)
            return progress(pending)
        await asyncio.sleep(run_at - time.time())
    await collector.restore()
    return await perform(collector, body, account, prepared, saved, selected)


async def run_queued(collector, body):
    store = collector.store
    pending = store.get_setting(ACTION + body.request_id, None)
    if not pending or pending.get("result"):
        return None
    try:
        permitted(collector)
        prepared, saved, selected = prepare(collector, body, pending.get("account_id"), fresh=False)
        await collector.restore()
        return await perform(collector, body, pending.get("account_id"), prepared, saved, selected, pending)
    except (Exception, asyncio.CancelledError) as exc:
        if not (store.get_setting(ACTION + body.request_id, None) or {}).get("result"):
            finish(store, pending, {"request_id": body.request_id, "request_event": pending["request_event"],
                                    "status": "rejected", "error_type": type(exc).__name__,
                                    **({"error": str(exc)} if isinstance(exc, ValueError) else {})})
        if isinstance(exc, asyncio.CancelledError):
            raise
        return progress(store.get_setting(ACTION + body.request_id, None))


async def perform(collector, body, account, prepared, saved, selected, pending=None):
    store = collector.store
    entity = None
    if body.action != "open":
        entity = await collector.resolve_target(body.chat_id)
    if body.action == "press":
        current = await collector.client.get_messages(entity, ids=body.message_id)
        live = buttons_of(current) if current else None
        if not live or live != saved:
            if current:
                await collector.capture_message(current, "message.edited", body.chat_id,
                                                source="panel_button_check")
            raise ValueError("The buttons changed or the message disappeared. Refresh the chat.")
    if pending is None:
        pending = record(collector, body, account, prepared, selected)
    result = {"request_id": body.request_id, "request_event": pending["request_event"], "status": "succeeded"}
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
                    chats = getattr(joined, "chats", None) or []
                    if chats:
                        entity = chats[0]
                    else:
                        again = await collector.client(functions.messages.CheckChatInviteRequest(target["invite"]))
                        entity = getattr(again, "chat", None)
                        if entity is None:
                            raise ValueError("Joined, but Telegram has not returned the chat yet. Open the link again.")
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
            result["chat_id"] = observe(collector, entity, body.observe is not False)
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
    except FLOOD_ERRORS as exc:
        store.set_setting("rpc_backoff_until", max(time.time() + exc.seconds,
                                                   store.get_setting("rpc_backoff_until", 0)))
        result.update(status="rejected", error_type=type(exc).__name__, retry_after=exc.seconds)
    except (Exception, asyncio.CancelledError) as exc:
        note_restriction(store, exc)
        cancelled = isinstance(exc, asyncio.CancelledError)
        definite = (isinstance(exc, ValueError) and not dispatched) or (isinstance(exc, RPCError) and exc.code < 500
                                                  and type(exc).__name__ != "BotResponseTimeoutError")
        result.update(status="rejected" if definite else "unknown", error_type=type(exc).__name__)
    finish(store, pending, result)
    if cancelled:
        raise asyncio.CancelledError
    return result
