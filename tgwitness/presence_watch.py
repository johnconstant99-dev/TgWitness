import asyncio
import re
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from .people import status_value
from .store import utcnow

WATCHES = "presence.watches"
SETTINGS = "presence.watch_settings"
MAX_WATCHES = 50
BATCH = 100
MIN_INTERVAL, MAX_INTERVAL, DEFAULT_INTERVAL = 60, 3600, 300
USERNAME = r"@?[A-Za-z][A-Za-z0-9_]{3,31}"
STATES = ("online", "offline", "recently", "last_week", "last_month", "unknown")
MEANING = ("Online status as Telegram reports it to this account. A person who hides last seen shows only a coarse "
           "state such as recently, and an exact time of going offline is only given when they allow it. Absence of a "
           "change between checks does not prove the person was offline.")
POLL_MEANING = ("The workspace asked Telegram for the current status of the watched accounts. Asking is an action by "
                "this account; it is recorded with every check.")


class Watch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: int | None = Field(default=None, gt=0)
    username: str | None = Field(default=None, max_length=33)
    label: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=1000)
    enabled: StrictBool = True

    @field_validator("username")
    @classmethod
    def handle(cls, value):
        if value is None or not value.strip():
            return None
        value = value.strip().lstrip("@")
        if not re.fullmatch(USERNAME, value):
            raise ValueError("Enter a Telegram username, for example @name.")
        return value.lower()

    @model_validator(mode="after")
    def identified(self):
        if self.user_id is None and self.username is None:
            raise ValueError("Add the account by numeric ID or by @username.")
        return self


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = False
    interval_seconds: int = Field(default=DEFAULT_INTERVAL, ge=MIN_INTERVAL, le=MAX_INTERVAL)
    record_unchanged: StrictBool = False


def settings(store):
    return {**Settings().model_dump(), **(store.get_setting(SETTINGS, None) or {})}


def save_settings(store, body):
    with store.transaction():
        store.set_setting(SETTINGS, body.model_dump())
        store.append("presence.watch_settings_changed", {
            **body.model_dump(),
            "meaning": "How often this account asks Telegram for the status of the watched accounts."})
    return settings(store)


def watches(store):
    return store.get_setting(WATCHES, None) or []


def available(store):
    goal = (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")
    if goal == "evidence":
        raise ValueError("Watching online status is off for the Evidence for a case goal.")


def add(store, body, actor):
    available(store)
    with store.transaction():
        current = watches(store)
        if len(current) >= MAX_WATCHES:
            raise ValueError("Remove a watched account before adding another.")
        if any(w.get("user_id") and w["user_id"] == body.user_id for w in current) or \
           any(body.username and w.get("username") == body.username for w in current):
            raise ValueError("This account is already watched.")
        entry = {"id": secrets.token_hex(8), **body.model_dump(), "added_at": utcnow(), "added_by": actor,
                 "resolved": body.user_id is not None, "last_state": None, "last_checked_at": None}
        store.set_setting(WATCHES, current + [entry])
        store.append("presence.watch_added", {"watch": entry, "actor": actor})
    return entry


def update(store, ident, body, actor):
    available(store)
    with store.transaction():
        current = watches(store)
        found = next((w for w in current if w["id"] == ident), None)
        if found is None:
            raise KeyError(ident)
        before = dict(found)
        found.update(body.model_dump(), resolved=found.get("resolved") and body.user_id == before.get("user_id"))
        store.set_setting(WATCHES, current)
        store.append("presence.watch_updated", {"before": before, "watch": found, "actor": actor})
    return found


def remove(store, ident, actor):
    with store.transaction():
        current = watches(store)
        found = next((w for w in current if w["id"] == ident), None)
        if found is None:
            raise KeyError(ident)
        store.set_setting(WATCHES, [w for w in current if w["id"] != ident])
        store.append("presence.watch_removed", {"watch": found, "actor": actor})
    return {"removed": ident}


def changed(previous, current):
    if not previous:
        return True
    if previous.get("state") != current.get("state"):
        return True
    return previous.get("was_online") != current.get("was_online")


def note(store, entry, status, checked_at):
    payload = {"watch_id": entry["id"], "user_id": entry.get("user_id"), "username": entry.get("username"),
               "label": entry.get("label") or None, "status": status, "previous": entry.get("last_state"),
               "checked_at": checked_at, "meaning": MEANING}
    return store.append("presence.changed", {k: v for k, v in payload.items() if v is not None},
                        actor_id=entry.get("user_id"))


async def resolve(client, entry):
    from telethon.tl import types
    target = entry["user_id"] if entry.get("user_id") else entry["username"]
    found = await asyncio.wait_for(client.get_input_entity(target), 20)
    if not isinstance(found, types.InputPeerUser):
        raise ValueError("not_a_user")
    return types.InputUser(found.user_id, found.access_hash), found.user_id


async def check(collector, now=None):
    from telethon.tl import functions
    store = collector.store
    available(store)
    config = settings(store)
    current = [w for w in watches(store) if w.get("enabled", True)]
    if not current:
        return {"checked": 0, "changes": 0, "unavailable": {}}
    await collector.restore()
    inputs, index, unavailable = [], {}, {}
    for entry in current:
        try:
            handle, uid = await resolve(collector.client, entry)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            unavailable[entry["id"]] = type(exc).__name__ if not isinstance(exc, ValueError) else str(exc)
            continue
        entry["user_id"], entry["resolved"] = uid, True
        inputs.append(handle)
        index[uid] = entry
    checked_at, changes = now or utcnow(), 0
    for start in range(0, len(inputs), BATCH):
        found = await asyncio.wait_for(collector.client(functions.users.GetUsersRequest(inputs[start:start + BATCH])), 30)
        for user in found:
            entry = index.get(getattr(user, "id", None))
            if entry is None:
                continue
            status = status_value(getattr(user, "status", None)) if getattr(user, "status", None) else {"state": "unknown"}
            if config["record_unchanged"] or changed(entry.get("last_state"), status):
                note(store, entry, status, checked_at)
                changes += 1
            entry["last_state"], entry["last_checked_at"] = status, checked_at
    with store.transaction():
        stored = watches(store)
        by_id = {entry["id"]: entry for entry in current}
        for entry in stored:
            fresh = by_id.get(entry["id"])
            if fresh:
                entry.update({key: fresh[key] for key in ("user_id", "resolved", "last_state", "last_checked_at")})
        store.set_setting(WATCHES, stored)
        store.append("presence.checked", {"watched": len(current), "answered": len(index), "changes": changes,
                                          "unavailable": unavailable, "at": checked_at, "meaning": POLL_MEANING})
    return {"checked": len(index), "changes": changes, "unavailable": unavailable}


def moment(value):
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def pattern(store, user_id=None, limit=5000, offset_minutes=0):
    zone = timezone(timedelta(minutes=offset_minutes))
    found = [event for event in store.events(kind="presence.changed", limit=limit)
             if user_id is None or (event.get("payload") or {}).get("user_id") == user_id]
    found.sort(key=lambda event: event["seq"])
    hours, weekdays, states = [0] * 24, [0] * 7, Counter()
    sessions, online_since, last = [], None, None
    for event in found:
        payload = event.get("payload") or {}
        state = (payload.get("status") or {}).get("state")
        at = moment(payload.get("checked_at") or event.get("observed_at"))
        states[state] += 1
        if at and state == "online":
            local = at.astimezone(zone)
            hours[local.hour] += 1
            weekdays[local.weekday()] += 1
            if online_since is None:
                online_since = at
        elif state != "online" and online_since is not None and at:
            seen = (payload.get("status") or {}).get("was_online")
            end = moment(seen) or at
            sessions.append({"from": online_since.isoformat(), "to": end.isoformat(),
                             "seconds": max(0, round((end - online_since).total_seconds()))})
            online_since = None
        last = payload if state else last
    return {"user_id": user_id, "checks": len(found), "states": dict(states.most_common()), "hours": hours,
            "weekdays": weekdays, "sessions": sessions[-50:], "offset_minutes": offset_minutes,
            "last": last, "meaning": MEANING}


async def loop(collector):
    store = collector.store
    while collector.running:
        config = settings(store)
        try:
            if config["enabled"] and watches(store):
                await check(collector)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            store.append("presence.check_failed", {"error_type": type(exc).__name__})
        await asyncio.sleep(max(MIN_INTERVAL, config["interval_seconds"]))


def owner_of(request):
    principal = request.state.principal
    return {"label": getattr(principal, "label", None) or ("Main administrator" if principal.admin else None),
            "owner": principal.owner}


def register(app, authenticate, require_live, operation):
    from fastapi import Depends, HTTPException, Request

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except KeyError:
            raise HTTPException(404, "Watch not found.") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/presence", dependencies=[Depends(authenticate)])
    async def overview():
        return {"watches": watches(app.state.store), "settings": settings(app.state.store),
                "limits": {"min_interval_seconds": MIN_INTERVAL, "max_interval_seconds": MAX_INTERVAL,
                           "max_watches": MAX_WATCHES}}

    @app.post("/api/presence/settings", dependencies=[Depends(authenticate)])
    async def configure(body: Settings):
        require_live()
        return await call(save_settings, app.state.store, body)

    @app.post("/api/presence/watches", dependencies=[Depends(authenticate)])
    async def watch_add(request: Request, body: Watch):
        require_live()
        return await call(add, app.state.store, body, owner_of(request))

    @app.put("/api/presence/watches/{ident}", dependencies=[Depends(authenticate)])
    async def watch_edit(request: Request, ident: str, body: Watch):
        require_live()
        return await call(update, app.state.store, ident, body, owner_of(request))

    @app.delete("/api/presence/watches/{ident}", dependencies=[Depends(authenticate)])
    async def watch_remove(request: Request, ident: str):
        require_live()
        return await call(remove, app.state.store, ident, owner_of(request))

    @app.post("/api/presence/check", dependencies=[Depends(authenticate)])
    async def check_now():
        require_live()
        return await operation(check, app.state.collector)

    @app.get("/api/presence/pattern", dependencies=[Depends(authenticate)])
    async def watch_pattern(user_id: int | None = None, offset_minutes: int = 0):
        if not -720 <= offset_minutes <= 840:
            raise HTTPException(422, "Choose a time zone between UTC-12 and UTC+14.")
        return await call(pattern, app.state.store, user_id, 5000, offset_minutes)
