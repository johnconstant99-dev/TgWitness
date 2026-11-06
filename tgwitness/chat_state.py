"""Periodic chat-state snapshots: title, description, counts, pinned messages, administrators and gifts.

State that lives outside the message stream changes without a message: an unpin of every message leaves no
message-level trace, a gift can be converted or upgraded without a service message. Each snapshot is a
signed `chat.state` record of what Telegram returned to this account, with its differences from the
previous snapshot of the same chat. Telegram does not say who changed anything or when between snapshots."""
import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

from telethon import utils
from telethon.tl import functions, types

from .telegram_client import FLOOD_ERRORS

KIND = "chat.state"
PINNED_LIMIT = 100
ADMIN_LIMIT = 200
GIFT_LIMIT = 100
TIMEOUT = 30
SCALARS = ("title", "usernames", "about", "participants_count", "admins_count", "linked_chat_id",
           "slowmode_seconds", "photo_id", "pinned_total", "gifts_total")
# Counts change constantly; a record whose changes touch only these keeps the full state of an earlier record.
VOLATILE = {"participants_count", "admins_count", "pinned_total", "gifts_total"}
FULL_EVERY = timedelta(days=7)
MEANING = ("What Telegram returned to this account about the chat at this time, and the differences from the "
           "previous snapshot. Telegram does not say who changed anything or when it changed between snapshots. "
           "A part that could not be read is unknown, not empty.")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def stamp(value):
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
    return None


def peer_id(value):
    try:
        return utils.get_peer_id(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def admin_entry(part):
    rights = getattr(part, "admin_rights", None)
    flags = sorted(k for k, v in rights.to_dict().items() if v is True) if rights is not None else []
    role = "creator" if type(part).__name__.endswith("Creator") else "admin"
    return {"user_id": getattr(part, "user_id", None), "role": role, "rights": flags,
            "rank": getattr(part, "rank", None) or None}


def gift_entry(saved):
    gift = getattr(saved, "gift", None)
    key = getattr(saved, "saved_id", None) or getattr(saved, "msg_id", None)
    return {"key": str(key) if key is not None else None, "gift_id": getattr(gift, "id", None),
            "unique": isinstance(gift, types.StarGiftUnique), "slug": getattr(gift, "slug", None),
            "unsaved": bool(getattr(saved, "unsaved", False)), "refunded": bool(getattr(saved, "refunded", False)),
            "date": stamp(getattr(saved, "date", None)), "from_id": peer_id(getattr(saved, "from_id", None))}


async def read_state(client, entity, options, timeout=TIMEOUT):
    """(state, errors). A part that fails is left out of the state and named in errors."""
    errors, state = {}, {}

    async def ask(part, request):
        try:
            return await asyncio.wait_for(request(), timeout)
        except (asyncio.CancelledError, *FLOOD_ERRORS):
            raise
        except Exception as exc:
            errors[part] = type(exc).__name__
            return None
    def identity(answer):
        if answer is None:
            return
        candidates = list(getattr(answer, "chats", []) or []) + list(getattr(answer, "users", []) or [])
        current = next((item for item in candidates if peer_id(item) == peer_id(entity)), None)
        if current is None:
            errors["identity"] = "Unavailable"
            return
        state["title"] = utils.get_display_name(current) or None
        names = [getattr(current, "username", None)] + [getattr(u, "username", None)
                 for u in getattr(current, "usernames", None) or [] if getattr(u, "active", False)]
        state["usernames"] = sorted({name for name in names if name})
        state["photo_id"] = getattr(getattr(current, "photo", None), "photo_id", None)

    def completeness(part, complete):
        state.setdefault("parts_complete", {})[part] = bool(complete)
    if isinstance(entity, types.Channel):
        answer = await ask("full", lambda: client(functions.channels.GetFullChannelRequest(entity)))
        identity(answer)
        full = getattr(answer, "full_chat", None)
        if full is not None:
            state.update(about=full.about or None, participants_count=full.participants_count,
                         admins_count=full.admins_count, slowmode_seconds=full.slowmode_seconds,
                         linked_chat_id=-1000000000000 - full.linked_chat_id if full.linked_chat_id else None)
        if options["chat_state_admins"]:
            answer = await ask("admins", lambda: client(functions.channels.GetParticipantsRequest(
                entity, types.ChannelParticipantsAdmins(), 0, ADMIN_LIMIT, 0)))
            if answer is not None:
                state["admins"] = sorted((admin_entry(p) for p in answer.participants), key=lambda a: a["user_id"] or 0)
                count = getattr(answer, "count", None)
                completeness("admins", type(count) is int and count == len(state["admins"]))
    elif isinstance(entity, types.Chat):
        answer = await ask("full", lambda: client(functions.messages.GetFullChatRequest(entity.id)))
        identity(answer)
        full = getattr(answer, "full_chat", None)
        if full is not None:
            parts = getattr(getattr(full, "participants", None), "participants", None)
            state.update(about=full.about or None,
                         participants_count=len(parts) if parts is not None else getattr(entity, "participants_count", None))
            if options["chat_state_admins"] and parts is not None:
                state["admins"] = sorted(({"user_id": p.user_id, "role": "creator" if type(p).__name__.endswith("Creator")
                                           else "admin", "rights": [], "rank": None} for p in parts
                                          if type(p).__name__.endswith(("Admin", "Creator"))), key=lambda a: a["user_id"])
                completeness("admins", True)
    elif isinstance(entity, types.User):
        answer = await ask("full", lambda: client(functions.users.GetFullUserRequest(entity)))
        identity(answer)
        full = getattr(answer, "full_user", None)
        if full is not None:
            state["about"] = full.about or None
    if options["chat_state_pinned"]:
        found = await ask("pinned", lambda: client.get_messages(entity, limit=PINNED_LIMIT,
                                                                 filter=types.InputMessagesFilterPinned()))
        if found is not None:
            state["pinned"] = sorted(m.id for m in found if type(getattr(m, "id", None)) is int)
            state["pinned_total"] = getattr(found, "total", None)
            completeness("pinned", type(state["pinned_total"]) is int and state["pinned_total"] == len(state["pinned"]))
    gifted = isinstance(entity, types.User) or isinstance(entity, types.Channel) and not getattr(entity, "megagroup", False)
    if options["chat_state_gifts"] and gifted:
        answer = await ask("gifts", lambda: client(functions.payments.GetSavedStarGiftsRequest(
            peer=entity, offset="", limit=GIFT_LIMIT)))
        if answer is not None:
            state["gifts"] = sorted((gift_entry(g) for g in answer.gifts), key=lambda g: g["key"] or "")
            state["gifts_total"] = getattr(answer, "count", None)
            completeness("gifts", type(state["gifts_total"]) is int and state["gifts_total"] == len(state["gifts"])
                         and not getattr(answer, "next_offset", None))
    # Null descriptions/photos/linked chats are observed clearing; absent counts are unknown.
    return {k: v for k, v in state.items() if v is not None or k not in VOLATILE}, errors


def keyed(entries, key):
    return {entry[key]: entry for entry in entries or [] if entry.get(key) is not None}


def differences(before, after):
    """Changes between two states. Parts missing from either state were not read and are not compared."""
    changes = {}
    for key in SCALARS:
        if key in before and key in after and before[key] != after[key]:
            changes[key] = {"before": before.get(key), "after": after.get(key)}
    if "pinned" in before and "pinned" in after:
        added, removed = sorted(set(after["pinned"]) - set(before["pinned"])), sorted(set(before["pinned"]) - set(after["pinned"]))
        if not before.get("parts_complete", {}).get("pinned", True):
            added = []
        if not after.get("parts_complete", {}).get("pinned", True):
            removed = []
        if added or removed:
            changes["pinned"] = {"added": added, "removed": removed}
    for part, key in (("admins", "user_id"), ("gifts", "key")):
        if part not in before or part not in after:
            continue
        old, new = keyed(before[part], key), keyed(after[part], key)
        found = {"added": [new[k] for k in sorted(set(new) - set(old), key=str)],
                 "no_longer_listed": [old[k] for k in sorted(set(old) - set(new), key=str)],
                 "changed": [{"before": old[k], "after": new[k]} for k in sorted(set(old) & set(new), key=str)
                             if old[k] != new[k]]}
        if not before.get("parts_complete", {}).get(part, True):
            found["added"] = []
        if not after.get("parts_complete", {}).get(part, True):
            found["no_longer_listed"] = []
        if any(found.values()):
            changes[part] = found
    return changes


def latest(store, chat_id):
    """(record, full state, seq of the record holding it) of the newest snapshot, or (None, None, None)."""
    records = store.events(chat_id=chat_id, kind=KIND, limit=1)
    if not records:
        return None, None, None
    record = records[0]
    payload = record["payload"]
    if "state" in payload:
        return record, payload["state"], record["seq"]
    base = payload.get("state_seq")
    found = store.events(chat_id=chat_id, kind=KIND, before=base + 1, limit=1) if type(base) is int else []
    if not found or found[0]["seq"] != base or "state" not in found[0]["payload"]:
        return record, None, None
    state = json.loads(json.dumps(found[0]["payload"]["state"]))
    if "state_overrides" in payload:
        state.update(payload["state_overrides"])
    else:
        for key, change in (payload.get("changes") or {}).items():
            if key in SCALARS:
                state[key] = change["after"]
    return record, state, base


def record(store, chat_id, state, errors, *, unchanged=True, now=None):
    """Append a snapshot. Returns the record, or None when nothing changed and unchanged checks are not kept."""
    now = now or datetime.now(timezone.utc)
    previous, before, base = latest(store, chat_id)
    carried = []
    if before is not None:
        # A part that could not be read keeps its earlier value, named in carried_forward, so it is not
        # reported as removed and later snapshots compare with the last value actually read.
        carried = sorted(k for k in before if k not in state)
        if "parts_complete" in state:
            state = {**state, "parts_complete": {**before.get("parts_complete", {}), **state["parts_complete"]}}
        state = {**{k: before[k] for k in carried}, **state}
    changes = differences(before, state) if before is not None else {}
    digest = hashlib.sha256(canonical(state)).hexdigest()
    payload = {"changes": changes, "errors": errors, "carried_forward": carried, "state_sha256": digest,
               "previous_seq": previous["seq"] if previous else None, "meaning": MEANING}
    base_record = store.events(chat_id=chat_id, kind=KIND, before=base + 1, limit=1) if base else []
    stale = not base_record or now - datetime.fromisoformat(base_record[0]["observed_at"]) >= FULL_EVERY
    base_state = base_record[0]["payload"]["state"] if base_record else {}
    structural = {k: v for k, v in state.items() if k not in VOLATILE}
    base_structural = {k: v for k, v in base_state.items() if k not in VOLATILE}
    if before is None or stale or structural != base_structural:
        payload["state"] = state
    else:
        if state == before and not unchanged and not errors:
            return None
        payload["state_seq"] = base
        payload["state_overrides"] = {k: state[k] for k in VOLATILE if k in state
                                      and (k not in base_state or state[k] != base_state[k])}
    return store.append(KIND, payload, chat_id)


def options(collector):
    return {key: collector.param(key) for key in ("chat_state_pinned", "chat_state_admins", "chat_state_gifts")}


def due(store, minutes, limit=100):
    """Enabled sources without a snapshot in the last interval, the longest waiting first."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="milliseconds")
    with store.lock:
        rows = store.db.execute(
            "SELECT t.chat_id FROM targets t LEFT JOIN (SELECT chat_id, max(observed_at) AS last FROM events "
            "WHERE kind=? GROUP BY chat_id) s ON s.chat_id=t.chat_id WHERE t.enabled=1 AND (s.last IS NULL OR s.last<?) "
            "ORDER BY s.last IS NOT NULL, s.last LIMIT ?", (KIND, cutoff, limit if limit is not None else -1)).fetchall()
    return [row[0] for row in rows]


async def run_due(collector, attempted):
    """Snapshot the sources that are due. attempted remembers chats that could not be read this interval."""
    minutes = collector.param("chat_state_minutes")
    if minutes <= 0:
        return 0
    done = 0
    for chat_id in due(collector.store, minutes, limit=None):
        if not collector.running or done >= 100:
            break
        now = time.monotonic()
        if now - attempted.get(chat_id, -1e12) < minutes * 60:
            continue
        attempted[chat_id] = now
        while collector.running and time.time() < collector.store.get_setting("rpc_backoff_until", 0):
            await asyncio.sleep(1)
        if not collector.running:
            break
        entity = collector.dialog_cache.get(chat_id, {}).get("entity") or await collector.lookup_entity(chat_id)
        if entity is None:
            continue
        try:
            state, errors = await read_state(collector.client, entity, options(collector))
        except FLOOD_ERRORS as exc:
            until = max(time.time() + exc.seconds, collector.store.get_setting("rpc_backoff_until", 0))
            collector.store.set_setting("rpc_backoff_until", until)
            collector.store.append("telegram.backoff", {"operation": "chat state snapshot",
                                                        "retry_after_seconds": exc.seconds})
            attempted.pop(chat_id, None)
            break
        record(collector.store, chat_id, state, errors, unchanged=collector.param("chat_state_unchanged"))
        done += 1
        await asyncio.sleep(collector.param("chat_state_pause_seconds"))
    return done
