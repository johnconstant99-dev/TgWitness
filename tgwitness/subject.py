import asyncio
from pathlib import Path

from telethon import utils
from telethon.tl import functions, types

USER_FLAGS = ("bot", "verified", "scam", "fake", "premium", "deleted", "support", "restricted")
COMPARED = ("title", "usernames", "about", "bot_description", "commands", "photo_sha256", "flags", "participants")
MEANING = ("What Telegram returned to this account about the chat or account at this moment. Names, usernames, "
           "descriptions and photos can change later; each snapshot keeps its own time.")


def kind_of(entity):
    if isinstance(entity, types.User):
        return "bot" if entity.bot else "user"
    if isinstance(entity, types.Channel):
        return "group" if entity.megagroup or entity.gigagroup else "channel"
    return "group"


def compared(snapshot):
    return {key: value if value not in (None, "", [], {}) else None
            for key in COMPARED for value in (snapshot.get(key),)}


SKIPPED = {"photo": ("photo_sha256",), "full_info": ("about", "bot_description", "commands", "participants")}


def changes(previous, current):
    if not previous:
        return []
    before, after = compared(previous), compared(current)
    skipped = {key for snapshot in (previous, current)
               for error in snapshot.get("unavailable") or () for key in SKIPPED.get(error, ())}
    return [{"field": key, "before": before[key], "after": after[key]} for key in COMPARED
            if key not in skipped and before[key] != after[key]]


async def user_details(collector, entity):
    full = (await asyncio.wait_for(collector.client(functions.users.GetFullUserRequest(entity)), 30)).full_user
    bot = getattr(full, "bot_info", None)
    return {"about": getattr(full, "about", None) or None, "common_chats": getattr(full, "common_chats_count", None),
            "personal_channel_id": getattr(full, "personal_channel_id", None),
            "bot_description": getattr(bot, "description", None) or None if bot else None,
            "commands": [{"command": c.command, "description": c.description}
                         for c in getattr(bot, "commands", None) or []] if bot else []}


async def snapshot(collector, chat_id, media_dir=None):
    await collector.restore()
    entity = collector.dialog_cache.get(chat_id, {}).get("entity") or await collector.lookup_entity(chat_id)
    if entity is None:
        raise ValueError("Telegram did not return this chat. Load chats and try again.")
    if media_dir is not None:
        Path(media_dir).mkdir(parents=True, exist_ok=True)
    profile, observer, errors = await collector.chat_profile(entity, media_dir)
    flags = {name: True for name in USER_FLAGS if getattr(entity, name, False) is True}
    flags.update({name: True for name in ("scam", "fake", "verified", "restricted") if profile.get(name)})
    details = {}
    if isinstance(entity, types.User):
        try:
            details = await user_details(collector, entity)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            errors["full_info"] = type(exc).__name__
    names = profile.get("usernames") or ([entity.username] if getattr(entity, "username", None) else [])
    current = {
        "title": utils.get_display_name(entity) or None, "kind": kind_of(entity), "usernames": names,
        "user_id": entity.id if isinstance(entity, types.User) else None,
        "first_name": getattr(entity, "first_name", None), "last_name": getattr(entity, "last_name", None),
        "flags": sorted(flags), "about": details.get("about") or profile.get("about"),
        "bot_description": details.get("bot_description"), "commands": details.get("commands") or [],
        "common_chats": details.get("common_chats"), "personal_channel_id": details.get("personal_channel_id"),
        "participants": profile.get("participants_count"), "created_at": profile.get("created_at"),
        "restriction_reasons": profile.get("restriction_reasons"), "linked_chat_id": profile.get("linked_chat_id"),
        "photo_sha256": profile.get("photo_sha256"), "photo_id": profile.get("photo_id"),
        "observer": observer or None, "unavailable": sorted(errors) or None}
    previous = collector.store.events(chat_id=chat_id, kind="subject.snapshot", limit=1)
    current["changes"] = changes(previous[0]["payload"] if previous else None, current)
    current = {key: value for key, value in current.items() if value not in (None, "", [], {})}
    event = collector.store.append("subject.snapshot", {**current, "meaning": MEANING}, chat_id)
    collector.remember(entity, chat_id=chat_id)
    return {"event": event["seq"], "snapshot": current}


def register(app, authenticate, require_live, operation, media_dir):
    from fastapi import Depends

    @app.post("/api/subjects/{chat_id}/snapshot", dependencies=[Depends(authenticate)])
    async def subject_snapshot(chat_id: int):
        require_live()
        return await operation(snapshot, app.state.collector, chat_id, media_dir)
