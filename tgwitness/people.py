import asyncio
import json
import time
from datetime import datetime, timezone

MESSAGE_KINDS = {"message.new", "message.snapshot", "message.recovered", "message.edited"}
PROFILE_KINDS = {"actor.profile", "actor.profile_changed"}
PROFILE_FIELDS = ("display_name", "username")
TABLES = ("people_state", "people_observations", "people_messages", "people_refresh_jobs")


def stamp(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).timestamp()
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, OverflowError, OSError):
        pass
    return None


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value is not None else None


def user_id(value):
    return value if type(value) is int and 0 < value < 2**63 else None


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def profile_changes(old, values):
    return {k: {"before": old[k], "after": values.get(k)} for k in PROFILE_FIELDS
            if k in values and old.get(k) not in (None, "") and old[k] != values[k]}


def unchanged(old, values):
    for key, value in values.items():
        if key == "flags":
            if any(old.get("flags", {}).get(k) != v for k, v in value.items()):
                return False
        elif key != "partial" and old.get(key) != value:
            return False
    return True


def membership(event):
    payload, results = event["payload"], []
    raw = payload.get("raw") or {}
    if event["kind"] == "membership.update":
        uid = user_id(payload.get("user_id", raw.get("user_id")))
        if not uid:
            return []
        before, after = raw.get("prev_participant"), raw.get("new_participant")
        name = (after or {}).get("_", "")
        actor = event.get("actor_id")
        if after is None or name.endswith("ParticipantLeft"):
            state = "left" if actor == uid else "removed" if actor else "absent"
        elif name == "ChannelParticipantBanned":
            state = "banned" if (after.get("banned_rights") or {}).get("view_messages") else "restricted"
        elif name.endswith("ParticipantAdmin") or name.endswith("ParticipantCreator"):
            state = "admin"
        else:
            state = "joined" if before is None else "member"
        results.append((uid, {"state": state, "actor_id": actor, "before": before, "after": after}))
    elif event["kind"] == "membership.service":
        action, actor = payload.get("action") or {}, event.get("actor_id")
        name = action.get("_", "")
        if name == "MessageActionChatAddUser":
            results = [(uid, {"state": "joined", "actor_id": actor})
                       for uid in action.get("users", []) if user_id(uid)]
        elif name == "MessageActionChatDeleteUser" and user_id(action.get("user_id")):
            uid = action["user_id"]
            results = [(uid, {"state": "left" if uid == actor else "removed", "actor_id": actor})]
        elif name in {"MessageActionChatJoinedByLink", "MessageActionChatJoinedByRequest"} and user_id(actor):
            results = [(actor, {"state": "joined", "actor_id": actor})]
    return results


class PeopleIndex:
    def __init__(self, db):
        self.db = db
        for sql in (
            "CREATE TABLE IF NOT EXISTS people_state(chat_id INTEGER,user_id INTEGER,first_seq INTEGER,last_seq INTEGER,"
            "profile TEXT NOT NULL DEFAULT '{}',status TEXT NOT NULL DEFAULT '{}',membership TEXT NOT NULL DEFAULT '{}',"
            "messages INTEGER NOT NULL DEFAULT 0,first_at REAL,last_at REAL,PRIMARY KEY(chat_id,user_id)) WITHOUT ROWID",
            "CREATE INDEX IF NOT EXISTS people_subject ON people_state(user_id,chat_id)",
            "CREATE INDEX IF NOT EXISTS people_recent ON people_state(chat_id,last_seq DESC,user_id)",
            "CREATE TABLE IF NOT EXISTS people_observations(chat_id INTEGER,user_id INTEGER,event_seq INTEGER,"
            "category TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(chat_id,user_id,event_seq)) WITHOUT ROWID",
            "CREATE TABLE IF NOT EXISTS people_messages(chat_id INTEGER,message_id INTEGER,user_id INTEGER,"
            "sent_at REAL,event_seq INTEGER,PRIMARY KEY(chat_id,message_id)) WITHOUT ROWID",
            "CREATE INDEX IF NOT EXISTS people_activity ON people_messages(chat_id,user_id,sent_at DESC)",
            "CREATE TABLE IF NOT EXISTS people_refresh_jobs(user_id INTEGER PRIMARY KEY,requested_seq INTEGER,"
            "attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL DEFAULT 0)",
        ):
            db.execute(sql)

    def state(self, chat, uid):
        row = self.db.execute("SELECT * FROM people_state WHERE chat_id=? AND user_id=?", (chat, uid)).fetchone()
        return dict(row) if row else None

    def known_chats(self, uid):
        return [row[0] for row in self.db.execute("SELECT p.chat_id FROM people_state p JOIN targets t "
                    "ON t.chat_id=p.chat_id WHERE p.user_id=? AND t.enabled=1", (uid,))]

    def record(self, event, uid, category, data, profile=None, status=None, member=None):
        chat, seq = event["chat_id"], event["seq"]
        self.db.execute("INSERT INTO people_state(chat_id,user_id,first_seq,last_seq) VALUES(?,?,?,?) "
                        "ON CONFLICT(chat_id,user_id) DO UPDATE SET last_seq=excluded.last_seq", (chat, uid, seq, seq))
        previous = self.state(chat, uid)
        if profile is not None:
            old = json.loads(previous["profile"])
            values = dict(profile)
            if values.pop("partial", False):
                values = {k: v for k, v in values.items() if v not in (None, "", [], {})}
            if values.get("source") == "message_profile_cache" and old.get("source") in {"telegram_update", "requested_profile_refresh", "full_profile_collection"}:
                for key in ("display_name", "username", "usernames"):
                    if key in old:
                        values[key] = old[key]
                values["source"], values["observed_at"] = old["source"], old.get("observed_at")
                if "flags" in old:
                    values["flags"] = {**values.get("flags", {}), **old["flags"]}
            if old.get("flags", {}).get("deleted") and values.get("source") == "message_profile_cache":
                values["flags"] = {**values.get("flags", {}), "deleted": True}
            if isinstance(values.get("flags"), dict):
                values["flags"] = {**old.get("flags", {}), **values["flags"]}
            data["profile_changes"] = {k: {"before": old.get(k), "after": v} for k, v in values.items()
                                       if k not in {"source", "observed_at"} and old.get(k) != v}
            merged = {**old, **values}
            self.db.execute("UPDATE people_state SET profile=? WHERE chat_id=? AND user_id=?",
                            (encode(merged), chat, uid))
        for column, value in (("status", status), ("membership", member)):
            if value is not None:
                self.db.execute("UPDATE people_state SET " + column + "=? WHERE chat_id=? AND user_id=?",
                                (encode({**value, "record": seq, "observed_at": event["observed_at"]}), chat, uid))
        self.db.execute("INSERT OR REPLACE INTO people_observations VALUES(?,?,?,?,?)",
                        (chat, uid, seq, category, encode(data)))

    def append(self, event):
        chat, payload, kind = event["chat_id"], event["payload"], event["kind"]
        if kind == "actor.refresh_completed":
            self.db.execute("DELETE FROM people_refresh_jobs WHERE user_id=? AND requested_seq<=?",
                            (payload["user_id"], payload["requested_seq"]))
            return
        if chat is None:
            return
        if kind in MESSAGE_KINDS:
            observed = payload.get("sender_observation") or {}
            uid = user_id(payload.get("sender_id", observed.get("id")))
            if not uid or type(event["message_id"]) is not int:
                return
            profile = {k: observed[k] for k in ("display_name", "username", "flags", "photo_id", "partial") if k in observed}
            profile["source"] = "message_profile_cache"
            profile["observed_at"] = event["observed_at"]
            self.record(event, uid, "message", {"message_id": event["message_id"], "edited": kind == "message.edited",
                        "source": payload.get("source"), "sent_at": payload.get("sent_at")}, profile=profile)
            sent = stamp(payload.get("sent_at") or (event.get("source_at") if kind != "message.edited" else None))
            inserted = self.db.execute("INSERT OR IGNORE INTO people_messages VALUES(?,?,?,?,?)",
                        (chat, event["message_id"], uid, sent, event["seq"])).rowcount
            if inserted:
                self.db.execute("UPDATE people_state SET messages=messages+1,"
                    "first_at=CASE WHEN first_at IS NULL THEN ? WHEN ? IS NULL THEN first_at ELSE min(first_at,?) END,"
                    "last_at=CASE WHEN last_at IS NULL THEN ? WHEN ? IS NULL THEN last_at ELSE max(last_at,?) END "
                    "WHERE chat_id=? AND user_id=?", (sent, sent, sent, sent, sent, sent, chat, uid))
        elif kind in PROFILE_KINDS | {"actor.status"} and user_id(payload.get("user_id")):
            uid = payload["user_id"]
            if kind in PROFILE_KINDS:
                profile = {**payload["profile"], "source": payload.get("source"), "observed_at": event["observed_at"]}
                self.record(event, uid, "profile", {"source": payload.get("source")}, profile=profile)
            else:
                self.record(event, uid, "status", payload["status"], status=payload["status"])
        elif kind == "actor.refresh_requested" and user_id(payload.get("user_id")):
            uid = payload["user_id"]
            self.record(event, uid, "refresh_requested", {"state": "pending"})
            self.db.execute("INSERT INTO people_refresh_jobs(user_id,requested_seq) VALUES(?,?) "
                            "ON CONFLICT(user_id) DO UPDATE SET requested_seq=excluded.requested_seq", (uid, event["seq"]))
        elif kind == "actor.profile_unavailable" and user_id(payload.get("user_id")):
            self.record(event, payload["user_id"], "profile_unavailable", {"error_type": payload.get("error_type"), "area": payload.get("area")})
        elif kind in {"actor.avatar_saved", "actor.avatar_observed", "actor.gift_observed", "actor.profile_link", "actor.profile_collected"}:
            uid = user_id(payload.get("user_id", payload.get("peer_id")))
            if uid:
                category = {"actor.avatar_saved": "avatar", "actor.avatar_observed": "avatar", "actor.gift_observed": "gift",
                    "actor.profile_link": "link", "actor.profile_collected": "collection"}[kind]
                self.record(event, uid, category, dict(payload))
        elif kind.startswith("membership."):
            for uid, member in membership(event):
                self.record(event, uid, "membership", member, member=member)


def profile_from_entity(entity):
    from telethon.tl import types
    if not isinstance(entity, types.User):
        return None
    usernames = [u.username for u in entity.usernames or [] if u.active]
    result = {"display_name": " ".join(s for s in (entity.first_name, entity.last_name) if s),
              "username": entity.username or (usernames[0] if usernames else None), "usernames": usernames,
              "partial": bool(entity.min)}
    flags = {k: bool(getattr(entity, k)) for k in ("deleted", "bot", "scam", "fake", "verified", "premium")
             if not entity.min or getattr(entity, k) is not None}
    if flags:
        result["flags"] = flags
    return result


def status_value(status):
    name = type(status).__name__
    state = {"UserStatusOnline": "online", "UserStatusOffline": "offline", "UserStatusRecently": "recently",
             "UserStatusLastWeek": "last_week", "UserStatusLastMonth": "last_month"}.get(name, "unknown")
    value = {"state": state}
    for key in ("expires", "was_online"):
        when = getattr(status, key, None)
        if isinstance(when, datetime):
            value[key] = when.astimezone(timezone.utc).isoformat()
    return value


def observe_update(store, update, *, profiles, presence, raw):
    from telethon.tl import types
    uid = user_id(getattr(update, "user_id", None))
    if not uid:
        return
    if isinstance(update, types.UpdateUserName) and profiles:
        values = {"display_name": " ".join(s for s in (update.first_name, update.last_name) if s),
                  "usernames": [u.username for u in update.usernames if u.active]}
        values["username"] = values["usernames"][0] if values["usernames"] else None
        category, value = "profile", values
    elif isinstance(update, types.UpdateUserStatus) and presence:
        category, value = "status", status_value(update.status)
    elif isinstance(update, types.UpdateUser) and profiles:
        request_refresh(store, uid, "telegram_update", raw=raw)
        return
    else:
        return
    with store.transaction():
        for chat in store.read_index.people.known_chats(uid):
            previous = json.loads(store.read_index.people.state(chat, uid)[category])
            if all(previous.get(k) == v for k, v in value.items()):
                continue
            changes = profile_changes(previous, value) if category == "profile" else None
            store.append("actor.profile_changed" if changes else "actor." + category, {"user_id": uid, category: value,
                **({"changes": changes} if changes else {}), "raw": raw,
                "source": "telegram_update", "collector_account_id": (store.get_setting("account", {}) or {}).get("id"),
                "association": "Previously observed in this chat; user presence is account-wide."}, chat, actor_id=uid)


def request_refresh(store, uid, source, **facts):
    with store.transaction():
        if store.db.execute("SELECT 1 FROM people_refresh_jobs WHERE user_id=?", (uid,)).fetchone():
            return
        if store.db.execute("SELECT count(*) FROM people_refresh_jobs").fetchone()[0] >= 128:
            for chat in store.read_index.people.known_chats(uid):
                store.append("actor.profile_unavailable", {"user_id": uid, "error_type": "RefreshQueueFull"}, chat, actor_id=uid)
            return
        for chat in store.read_index.people.known_chats(uid):
            store.append("actor.refresh_requested", {"user_id": uid, "source": source, **facts}, chat, actor_id=uid)


def sender_change(store, chat, entity):
    profile = profile_from_entity(entity)
    if profile is None or profile["partial"] or not user_id(entity.id):
        return None
    previous = store.read_index.people.state(chat, entity.id)
    if not previous:
        return None
    values = {k: profile[k] for k in PROFILE_FIELDS}
    changes = profile_changes(json.loads(previous["profile"]), values)
    return {"profile": values, "changes": changes} if changes else None


def observe_entity(store, entity, chat):
    profile = profile_from_entity(entity)
    if profile is None or not user_id(entity.id) or not getattr(entity, "deleted", False):
        return
    profile = {"flags": {"deleted": True}}
    with store.transaction():
        previous = store.read_index.people.state(chat, entity.id)
        if not previous:
            return
        old = json.loads(previous["profile"])
        if old.get("flags", {}).get("deleted") is True:
            return
        store.append("actor.profile", {"user_id": entity.id, "profile": profile, "source": "received_entity",
            "collector_account_id": (store.get_setting("account", {}) or {}).get("id")}, chat, actor_id=entity.id)


async def refresh_one(collector):
    from .monitoring import capture_settings, monitoring_settings
    from telethon.tl import types
    store, client, now = collector.store, collector.client, time.time()
    policy = monitoring_settings(store)
    if not collector.running or not policy["profiles"] or not client or not client.is_connected():
        return
    if store.get_setting("rpc_backoff_until", 0) > now or getattr(client, "_rpc_lock", None) and client._rpc_lock.locked():
        return
    with store.transaction():
        job = store.db.execute("SELECT * FROM people_refresh_jobs WHERE next_attempt<=? ORDER BY requested_seq LIMIT 1", (now,)).fetchone()
        if job is None:
            return
        uid, requested, attempts = job["user_id"], job["requested_seq"], job["attempts"] + 1
        store.db.execute("UPDATE people_refresh_jobs SET attempts=?,next_attempt=? WHERE user_id=?", (attempts, now + 300, uid))
        if not store.read_index.people.known_chats(uid):
            complete_refresh(store, uid, requested, "source_not_selected")
            return
    try:
        entity = await asyncio.wait_for(client.get_entity(uid), 15)
        if not isinstance(entity, types.User) or entity.id != uid or entity.min:
            raise ValueError("IncompleteProfile")
        profile = profile_from_entity(entity)
        with store.transaction():
            if not collector.running or not monitoring_settings(store)["profiles"]:
                return
            chats = store.read_index.people.known_chats(uid)
            for chat in chats:
                previous = json.loads(store.read_index.people.state(chat, uid)["profile"])
                changes = profile_changes(previous, profile)
                if changes or not unchanged(previous, profile):
                    store.append("actor.profile_changed" if changes else "actor.profile", {"user_id": uid, "profile": profile,
                        **({"changes": changes} if changes else {}), "source": "requested_profile_refresh",
                        "collector_account_id": (store.get_setting("account", {}) or {}).get("id")}, chat, actor_id=uid)
                if monitoring_settings(store)["presence"] and entity.status is not None:
                    store.append("actor.status", {"user_id": uid, "status": status_value(entity.status),
                        "source": "requested_profile_refresh"}, chat, actor_id=uid)
            complete_refresh(store, uid, requested, "received")
        if capture_settings(store)["include_avatars"]:
            for chat in chats:
                collector.avatar_history.observe(entity, chat_id=chat)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        with store.transaction():
            for chat in store.read_index.people.known_chats(uid):
                store.append("actor.profile_unavailable", {"user_id": uid, "error_type": type(exc).__name__}, chat, actor_id=uid)
            if attempts >= 3:
                complete_refresh(store, uid, requested, "attempt_limit")


def observed_names(db, chat, uids):
    found = {}
    for uid in uids:
        rows = db.execute("SELECT seq,hash,observed_at,kind,message_id,json_extract(payload,'$.source'),"
                          "json_extract(payload,'$.sender_observation') FROM events WHERE json_extract(payload,'$.sender_id')=? "
                          "AND chat_id=? AND kind IN (?,?,?,?)", (uid, chat, *sorted(MESSAGE_KINDS))).fetchall()
        rows += db.execute("SELECT seq,hash,observed_at,kind,message_id,json_extract(payload,'$.source'),"
                           "json_extract(payload,'$.profile') FROM events INDEXED BY event_kind WHERE kind IN (?,?) "
                           "AND chat_id=? AND json_extract(payload,'$.user_id')=?", (*sorted(PROFILE_KINDS), chat, uid)).fetchall()
        names = []
        for seq, digest, observed_at, kind, message_id, source, value in sorted(rows, key=lambda row: row[0]):
            value = json.loads(value) if value else None
            if not isinstance(value, dict) or not isinstance(value.get("display_name"), str) or not value["display_name"]:
                continue
            contact = value["flags"].get("contact") if isinstance(value.get("flags"), dict) else None
            names.append({"seq": seq, "hash": digest, "observed_at": observed_at, "name": value["display_name"],
                          "username": value.get("username"), "message_id": message_id,
                          "source": "contact" if contact else "profile" if contact is False else None,
                          "live": kind == "message.new" and source == "live_update"})
        if names:
            found[uid] = names
    return found


def complete_refresh(store, uid, requested, result):
    row = store.db.execute("SELECT chat_id FROM events WHERE seq=?", (requested,)).fetchone()
    store.append("actor.refresh_completed", {"user_id": uid, "requested_seq": requested, "result": result},
                 row[0] if row else None, actor_id=uid)


def coverage(db, chat, since, now):
    target = db.execute("SELECT enabled FROM targets WHERE chat_id=?", (chat,)).fetchone()
    if not target or not target[0]:
        return "unknown"
    rows = db.execute("SELECT kind,observed_at,payload FROM events WHERE observed_at>=? AND "
        "(chat_id=? OR chat_id IS NULL) AND (kind IN ('collector.heartbeat','monitoring.changed','collector.stopped',"
        "'process.stopped','target.changed','target.added','target.removed','scope.changed','scope.applied',"
        "'collector.error','observation.stopped','observation.started') OR kind='coverage.gap') ORDER BY seq LIMIT 20001", (iso(since), chat)).fetchall()
    if len(rows) > 20000:
        return "unknown"
    previous, seen = since, False
    for row in rows:
        when, payload = stamp(row["observed_at"]), json.loads(row["payload"])
        if row["kind"] != "collector.heartbeat":
            return "interrupted"
        allowed = max(120, min(float(payload.get("interval_seconds", 60)), 3600) * 2 + 15)
        if not when or not payload.get("connected") or when - previous > allowed:
            return "interrupted"
        previous, seen = when, True
    if not seen or now - previous > allowed:
        return "unknown"
    return "no_recorded_gap"


def public_person(row, now, quiet_days):
    value = dict(row)
    for key in ("profile", "status", "membership"):
        value[key] = json.loads(value[key])
    current = value["status"]
    if current.get("state") == "online" and (stamp(current.get("expires")) or 0) <= now:
        value["status"] = {**current, "state": "unknown", "last_observed_state": "online", "expired": True}
    last = value.pop("last_at")
    value["first_message_at"], value["last_message_at"] = iso(value.pop("first_at")), iso(last)
    value["silence_days"] = max(0, (now - last) / 86400) if last is not None else None
    value["activity"] = ("never_posted" if not value["messages"] else "unknown" if last is None
                         else "quiet" if now - last >= quiet_days * 86400 else "recent")
    return value


def listing(store, chat, *, quiet_days=7, offset=0, limit=100, mode="all", now=None):
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    clauses, args = ["chat_id=?"], [chat]
    if mode == "quiet":
        clauses.append("last_at<=?")
        args.append(now - quiet_days * 86400)
    elif mode == "deleted":
        clauses.append("json_extract(profile,'$.flags.deleted')=1")
    elif mode == "departed":
        clauses.append("json_extract(membership,'$.state') IN ('left','removed','banned')")
    elif mode == "never_posted":
        clauses.append("messages=0")
    where = " AND ".join(clauses)
    with store.snapshot() as snapshot:
        db = snapshot.connection
        total = db.execute("SELECT count(*) FROM people_state WHERE " + where, args).fetchone()[0]
        rows = db.execute("SELECT * FROM people_state WHERE " + where + " ORDER BY last_seq DESC,user_id LIMIT ? OFFSET ?",
                          [*args, limit, offset]).fetchall()
        return {"people": [public_person(row, now, quiet_days) for row in rows], "total": total,
                "offset": offset, "limit": limit, "quiet_days": quiet_days, "as_of": iso(now),
                "coverage": coverage(db, chat, now - quiet_days * 86400, now)}


def timeline(store, chat, uid, *, before=None, limit=100, quiet_days=7, now=None):
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    with store.snapshot() as snapshot:
        db = snapshot.connection
        row = db.execute("SELECT * FROM people_state WHERE chat_id=? AND user_id=?", (chat, uid)).fetchone()
        if row is None:
            raise ValueError("This user has no recorded observations in this chat.")
        rows = db.execute("SELECT p.*,e.observed_at,e.source_at,e.hash,e.kind FROM people_observations p "
            "JOIN events e ON e.seq=p.event_seq WHERE p.chat_id=? AND p.user_id=? AND p.event_seq<? "
            "ORDER BY p.event_seq DESC LIMIT ?", (chat, uid, before or 2**63 - 1, limit + 1)).fetchall()
        more = len(rows) > limit
        events = [{**dict(item), "data": json.loads(item["data"])} for item in rows[:limit]]
        activity = db.execute("SELECT sent_at,event_seq FROM people_messages WHERE chat_id=? AND user_id=? "
            "AND sent_at IS NOT NULL ORDER BY sent_at DESC LIMIT 2", (chat, uid)).fetchall()
        return {"person": public_person(row, now, quiet_days), "events": events,
                "next_before": events[-1]["event_seq"] if more else None, "as_of": iso(now),
                "last_message_gap_days": (activity[0][0] - activity[1][0]) / 86400 if len(activity) == 2 else None,
                "coverage": coverage(db, chat, now - quiet_days * 86400, now),
                "meaning": "Observed statuses and actions."}
