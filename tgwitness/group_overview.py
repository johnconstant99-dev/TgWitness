import json
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException

from . import tuning
from .settings_hub import wizard_state
from .verify import LIVENESS_GAP_SECONDS, MESSAGE_KINDS, Coverage, parse_time

WINDOW_DAYS = 7
CHATS_SHOWN = 200
STATE_KINDS = ("observation.started", "observation.stopped", "process.started", "process.stopped",
               "coverage.gap", "connection.restored", "collector.heartbeat", "parameters.changed")
OPENING = ("observation.started", "observation.stopped", "process.started", "process.stopped")


def iso(moment):
    return moment.isoformat(timespec="milliseconds")


def allowed_silence(store):
    return max(LIVENESS_GAP_SECONDS, 3 * tuning.value(store, "heartbeat_seconds"))


def observed(store, since):
    coverage = Coverage()
    coverage.allowed = allowed_silence(store)
    with store.lock:
        before = store.db.execute(
            "SELECT kind FROM events WHERE observed_at<? AND kind IN (" + ",".join("?" * len(OPENING)) + ")"
            " ORDER BY seq DESC LIMIT 1", (since, *OPENING)).fetchone()
        rows = store.db.execute(
            "SELECT observed_at,kind,chat_id,message_id,payload FROM events WHERE observed_at>=? AND kind IN ("
            + ",".join("?" * len(STATE_KINDS)) + ") ORDER BY seq", (since, *STATE_KINDS)).fetchall()
    if before and before["kind"] == "observation.started":
        coverage.open(since)
    for row in rows:
        coverage.add({"observed_at": row["observed_at"], "kind": row["kind"], "chat_id": row["chat_id"],
                      "message_id": row["message_id"], "payload": json.loads(row["payload"])})
    return [(parse_time(p["from"]), parse_time(p["to"])) for p in coverage.result()["continuous"]]


def interruptions(periods, start, end, allowed):
    holes, cursor = [], start
    for low, high in sorted(p for p in periods if p[1] > start):
        if low - cursor > allowed:
            holes.append((cursor, low))
        cursor = max(cursor, high)
    if end - cursor > allowed:
        holes.append((cursor, end))
    return holes


def latest(store, kinds):
    with store.lock:
        seq = max((store.db.execute("SELECT max(seq) FROM events WHERE kind=?", (kind,)).fetchone()[0] or 0)
                  for kind in kinds)
        row = store.db.execute("SELECT observed_at,kind FROM events WHERE seq=?", (seq,)).fetchone() if seq else None
    return {"at": row["observed_at"], "kind": row["kind"]} if row else None


def member(entry, app):
    if app is None:
        return {"id": entry["id"], "label": entry["label"], "available": False}
    store = app.state.store
    account = store.get_setting("account", None) or {}
    current = app.state.connection.public()["current"]
    check = current.get("check") or {}
    measured = check.get("current") and check.get("telegram_connected")
    return {"id": entry["id"], "label": entry["label"], "available": True,
            "username": account.get("username"), "account_id": account.get("id"),
            "account_kind": wizard_state(app).get("account_kind"),
            "route": {"mode": current["mode"], "latency_ms": check.get("latency_ms") if measured else None},
            "last_message": latest(store, MESSAGE_KINDS)}


def overview(registry, group_id):
    group = registry._group(group_id)
    now = datetime.now(timezone.utc)
    since = iso(now - timedelta(days=WINDOW_DAYS))
    members, seen = [], {}
    for profile_id in registry.members(group_id):
        entry = registry.entries[profile_id]
        app = entry.get("app")
        members.append(member(entry, app))
        if app is None:
            continue
        for target in app.state.store.targets():
            chat = seen.setdefault(target["chat_id"], {"chat_id": target["chat_id"], "title": target["title"],
                                                       "kind": target["kind"], "seen_by": [], "recorded_by": []})
            chat["seen_by"].append(profile_id)
            if target["enabled"]:
                chat["recorded_by"].append(profile_id)
    shared = sorted((c for c in seen.values() if len(c["seen_by"]) > 1),
                    key=lambda c: (-len(c["seen_by"]), -len(c["recorded_by"]), c["title"] or ""))[:CHATS_SHOWN]
    stores = {p: registry.entries[p]["app"].state.store for c in shared for p in c["recorded_by"]}
    periods = {p: observed(store, since) for p, store in stores.items()}
    for chat in shared:
        recording = [periods[p] for p in chat["recorded_by"]]
        starts = [period[0][0] for period in recording if period]
        if not starts:
            chat["coverage"] = {"observed": False}
            continue
        start = max(parse_time(since), min(starts))
        allowed = timedelta(seconds=max(allowed_silence(stores[p]) for p in chat["recorded_by"]))
        holes = interruptions([p for period in recording for p in period], start, now, allowed)
        chat["coverage"] = {"observed": True, "interruptions": len(holes),
                            "seconds_unobserved": round(sum((b - a).total_seconds() for a, b in holes))}
    return {"group": {"id": group["id"], "label": group["label"], "goal": (group.get("values") or {}).get("goal")},
            "members": members, "chats": shared, "chats_total": sum(len(c["seen_by"]) > 1 for c in seen.values()),
            "window_days": WINDOW_DAYS}


def register(app, authenticate):
    @app.get("/api/profile-groups/{group_id}/overview", dependencies=[Depends(authenticate)])
    async def group_overview(group_id: str):
        try:
            return overview(app.state.profiles, group_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
