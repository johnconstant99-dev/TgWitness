import hashlib
import json
import sqlite3
import threading
import time
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import keyboard
from . import message_content

ZERO = "0" * 64
EVENT_FIELDS = ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id",
                "actor_id", "payload", "previous_hash")
# Journal records that make up the readable chat view.
TEXT_KINDS = ("message.new", "message.snapshot", "message.edited", "message.recovered")
# A deletion notice from Telegram and "not returned at a later recheck" are different facts.
GONE_KINDS = ("message.deleted", "message.missing_on_recheck")
CHAT_KINDS = TEXT_KINDS + GONE_KINDS + ("media.saved",)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def event_hash(event):
    return hashlib.sha256(canonical({k: event[k] for k in EVENT_FIELDS})).hexdigest()


def search_text(value):
    return unicodedata.normalize("NFC", value.casefold())


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.lock = threading.RLock()
        self.db = sqlite3.connect(root / "journal.sqlite3", check_same_thread=False)
        self.db.create_function("search_text", 1, search_text, deterministic=True)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, source_at TEXT,
              kind TEXT NOT NULL, chat_id INTEGER, message_id INTEGER, actor_id INTEGER,
              payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL,
              signature TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS event_chat ON events(chat_id, seq);
            CREATE INDEX IF NOT EXISTS event_message ON events(chat_id, message_id, seq);
            CREATE INDEX IF NOT EXISTS event_kind ON events(kind, seq);
            CREATE INDEX IF NOT EXISTS event_observed ON events(observed_at, seq);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS targets (
              chat_id INTEGER PRIMARY KEY, title TEXT NOT NULL, enabled INTEGER NOT NULL,
              kind TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS media_jobs (
              message_event INTEGER PRIMARY KEY REFERENCES events(seq),
              account_id INTEGER NOT NULL, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
              descriptor BLOB NOT NULL, descriptor_hash TEXT NOT NULL, max_bytes INTEGER NOT NULL,
              state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
              next_attempt REAL NOT NULL DEFAULT 0, last_error TEXT);
            CREATE INDEX IF NOT EXISTS media_ready ON media_jobs(state, next_attempt, message_event);
            CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON events
              BEGIN SELECT RAISE(ABORT, 'Journal is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON events
              BEGIN SELECT RAISE(ABORT, 'Journal is append-only'); END;
        """)
        # Sources added before 0.7 were all chosen by hand and rechecked at the priority interval.
        columns = {r[1] for r in self.db.execute("PRAGMA table_info(targets)")}
        if "origin" not in columns:
            self.db.execute("ALTER TABLE targets ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'")
        if "priority" not in columns:
            self.db.execute("ALTER TABLE targets ADD COLUMN priority INTEGER NOT NULL DEFAULT 1")
        # Private chats and ordinary groups share one account-wide message ID sequence; deletion
        # notices for them carry only IDs, so the chat is found by a saved message ID.
        self.db.execute("CREATE INDEX IF NOT EXISTS event_message_id ON events(message_id)")
        self.db.commit()
        self.signer = None
        self.targets_revision = 0

    @contextmanager
    def transaction(self):
        """Nested operations commit together, including a journal record and its durable job."""
        with self.lock:
            outer = not self.db.in_transaction
            if outer:
                self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                if outer:
                    self.db.commit()
            except BaseException:
                if outer:
                    self.db.rollback()
                raise

    def bind(self, vault):
        identity = self.get_setting("public_key", None)
        if identity is not None and identity != vault.public_key:
            raise RuntimeError("Signing key does not match this journal. Restore the original vault.")
        self.set_setting("public_key", vault.public_key)
        self.signer = vault

    def append(self, kind, payload, chat_id=None, message_id=None, actor_id=None, source_at=None,
               media_job=None):
        with self.transaction():
            tail = self.db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            event = dict(seq=tail["seq"] + 1 if tail else 1, observed_at=utcnow(),
                         source_at=source_at, kind=kind, chat_id=chat_id, message_id=message_id,
                         actor_id=actor_id, payload=payload, previous_hash=tail["hash"] if tail else ZERO)
            event["hash"] = event_hash(event)
            event["signature"] = self.signer.sign(bytes.fromhex(event["hash"]))
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            tuple(canonical(event[k]).decode() if k == "payload" else event[k]
                                  for k in (*EVENT_FIELDS, "hash", "signature")))
            if media_job:
                self.db.execute(
                    "INSERT INTO media_jobs(message_event,account_id,chat_id,message_id,"
                    "descriptor,descriptor_hash,max_bytes) VALUES (?,?,?,?,?,?,?)",
                    (event["seq"], media_job["account_id"], chat_id, message_id,
                     media_job["descriptor"], hashlib.sha256(media_job["descriptor"]).hexdigest(),
                     media_job["max_bytes"]))
            return event

    @staticmethod
    def decode(row):
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def chat_overview(self):
        """Per chat: saved messages, edited and deleted counts, and the newest saved text."""
        marks = ",".join("?" * len(CHAT_KINDS))
        text_marks = ",".join("?" * len(TEXT_KINDS))
        with self.lock:
            rows = self.db.execute(
                "SELECT chat_id, count(DISTINCT CASE WHEN kind!='media.saved' THEN message_id END) AS messages,"
                " count(DISTINCT CASE WHEN kind='message.edited' THEN message_id END) AS edited,"
                " count(DISTINCT CASE WHEN kind='message.deleted' THEN message_id END) AS deleted,"
                " count(DISTINCT CASE WHEN kind='message.missing_on_recheck' THEN message_id END) AS missing,"
                " max(observed_at) AS last_observed_at"
                " FROM events WHERE chat_id IS NOT NULL AND message_id IS NOT NULL AND kind IN (" + marks + ")"
                " GROUP BY chat_id", CHAT_KINDS).fetchall()
            result = {}
            for row in rows:
                newest = self.db.execute(
                    "SELECT payload FROM events WHERE chat_id=? AND kind IN (" + text_marks + ")"
                    " ORDER BY message_id DESC, seq DESC LIMIT 1", (row["chat_id"], *TEXT_KINDS)).fetchone()
                payload = json.loads(newest["payload"]) if newest else {}
                sender = payload.get("sender_observation") or {}
                result[row["chat_id"]] = {
                    "messages": row["messages"], "edited": row["edited"], "deleted": row["deleted"],
                    "missing": row["missing"],
                    "last_observed_at": row["last_observed_at"],
                    "last_text": payload.get("text") if newest else None,
                    "last_sender": sender.get("display_name"),
                }
        return result

    def chat_authors(self, chat_id):
        """Everyone with a saved message in this chat: counts of saved, edited and deleted messages."""
        text_marks = ",".join("?" * len(TEXT_KINDS))
        with self.lock:
            rows = self.db.execute(
                "SELECT message_id, kind, json_extract(payload,'$.sender_id') AS sender_id,"
                " json_extract(payload,'$.sender_observation.display_name') AS name,"
                " json_extract(payload,'$.sender_observation.username') AS username,"
                " coalesce(json_extract(payload,'$.sent_at'), source_at) AS sent_at"
                " FROM events WHERE chat_id=? AND message_id IS NOT NULL AND kind IN (" + text_marks + ")"
                " ORDER BY seq", (chat_id, *TEXT_KINDS)).fetchall()
            deleted = {r[0] for r in self.db.execute(
                "SELECT DISTINCT message_id FROM events WHERE chat_id=? AND kind='message.deleted'", (chat_id,))}
            missing = {r[0] for r in self.db.execute(
                "SELECT DISTINCT message_id FROM events WHERE chat_id=? AND kind='message.missing_on_recheck'",
                (chat_id,))} - deleted
        people, edited, owner = {}, set(), {}
        for row in rows:
            if row["kind"] == "message.edited":
                edited.add(row["message_id"])
            person = people.setdefault(row["sender_id"], {
                "id": row["sender_id"], "name": None, "username": None, "message_ids": set(),
                "first_message_at": None, "last_message_at": None})
            person["name"] = row["name"] or person["name"]
            person["username"] = row["username"] or person["username"]
            person["message_ids"].add(row["message_id"])
            owner.setdefault(row["message_id"], row["sender_id"])
            when = row["sent_at"]
            if when and (person["first_message_at"] is None or when < person["first_message_at"]):
                person["first_message_at"] = when
            if when and (person["last_message_at"] is None or when > person["last_message_at"]):
                person["last_message_at"] = when
        result = []
        for person in people.values():
            ids = person.pop("message_ids")
            person.update(messages=len(ids), deleted=len(ids & deleted), missing=len(ids & missing),
                          edited=sum(1 for i in ids & edited if owner.get(i) == person["id"]))
            result.append(person)
        result.sort(key=lambda p: (-p["messages"], -p["deleted"], str(p["id"])))
        return {"authors": result, "deleted_without_author": len(deleted - set(owner))}

    def last_message_id(self, chat_id):
        """Highest message ID with saved content in this chat, or None."""
        marks = ",".join("?" * len(TEXT_KINDS))
        with self.lock:
            row = self.db.execute("SELECT max(message_id) FROM events WHERE chat_id=? AND kind IN (" + marks + ")",
                                  (chat_id, *TEXT_KINDS)).fetchone()
        return row[0]

    def message_state(self, chat_id, message_id):
        """Latest saved content of one message and whether it is already recorded as gone."""
        marks = ",".join("?" * len(TEXT_KINDS))
        with self.lock:
            row = self.db.execute(
                "SELECT seq, hash, json_extract(payload,'$.text') AS text,"
                " json_extract(payload,'$.edited_at') AS edited_at,"
                " json_extract(payload,'$.outgoing') AS outgoing,"
                " payload FROM events"
                " WHERE chat_id=? AND message_id=? AND kind IN (" + marks + ") ORDER BY seq DESC LIMIT 1",
                (chat_id, message_id, *TEXT_KINDS)).fetchone()
            gone = {r[0] for r in self.db.execute(
                "SELECT DISTINCT kind FROM events WHERE chat_id=? AND message_id=? AND kind IN (?,?)",
                (chat_id, message_id, *GONE_KINDS))}
        content = dict(row) if row else None
        if content:
            content["observable"] = message_content.of_payload(json.loads(content.pop("payload")))
            content["buttons"] = content["observable"]["buttons"]
        return {"content": content,
                "deleted": "message.deleted" in gone, "missing": "message.missing_on_recheck" in gone}

    def alive_message_ids(self, chat_id, below=None, limit=200):
        """Saved message IDs not yet recorded as deleted or missing, newest first."""
        marks = ",".join("?" * len(TEXT_KINDS))
        where, params = "chat_id=? AND message_id IS NOT NULL AND kind IN (" + marks + ")", [chat_id, *TEXT_KINDS]
        if below is not None:
            where += " AND message_id<?"
            params.append(below)
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT DISTINCT message_id FROM events WHERE " + where +
                " AND message_id NOT IN (SELECT message_id FROM events WHERE chat_id=? AND message_id IS NOT NULL"
                " AND kind IN (?,?)) ORDER BY message_id DESC LIMIT ?", (*params, chat_id, *GONE_KINDS, limit))]

    def chat_messages(self, chat_id, before_id=None, limit=60):
        """Readable view of one chat: every saved version, deletion and attachment per message."""
        marks = ",".join("?" * len(CHAT_KINDS))
        where, params = "chat_id=? AND message_id IS NOT NULL AND kind IN (" + marks + ")", [chat_id, *CHAT_KINDS]
        if before_id is not None:
            where += " AND message_id<?"
            params.append(before_id)
        with self.lock:
            ids = [r[0] for r in self.db.execute(
                "SELECT DISTINCT message_id FROM events WHERE " + where + " ORDER BY message_id DESC LIMIT ?",
                (*params, limit))]
            if not ids:
                return {"messages": [], "next_before": None}
            rows = self.db.execute(
                "SELECT seq, observed_at, source_at, kind, message_id, payload FROM events"
                " WHERE chat_id=? AND message_id IN (" + ",".join("?" * len(ids)) + ") AND kind IN (" + marks + ")"
                " ORDER BY seq", (chat_id, *ids, *CHAT_KINDS)).fetchall()
        messages = {}
        for row in rows:
            payload = json.loads(row["payload"])
            item = messages.setdefault(row["message_id"], {
                "message_id": row["message_id"], "first_seq": row["seq"], "sender": None, "sent_at": None,
                "reply_to": None, "has_media": False, "service_action": None, "grouped_id": None,
                "versions": [], "media": [], "deleted": False, "deleted_observed_at": None,
                "missing": False, "missing_observed_at": None,
                "telegram_edited_at": None, "origins": []})
            kind = row["kind"]
            if kind in TEXT_KINDS:
                observed = payload.get("sender_observation") or {}
                if item["sender"] is None and (payload.get("sender_id") is not None or observed):
                    item["sender"] = {"id": payload.get("sender_id", observed.get("id")),
                                      "name": observed.get("display_name"), "username": observed.get("username")}
                item["sent_at"] = item["sent_at"] or payload.get("sent_at") or row["source_at"]
                item["reply_to"] = item["reply_to"] or payload.get("reply_to_message_id")
                item["has_media"] = item["has_media"] or bool(payload.get("has_media"))
                item["service_action"] = item["service_action"] or payload.get("service_action")
                item["grouped_id"] = item["grouped_id"] or payload.get("grouped_id")
                item["telegram_edited_at"] = payload.get("edited_at") or item["telegram_edited_at"]
                origin = {"message.new": "live", "message.snapshot": "history", "message.edited": "edit",
                          "message.recovered": "recheck"}[kind]
                if origin not in item["origins"]:
                    item["origins"].append(origin)
                text, buttons = payload.get("text") or "", keyboard.of_payload(payload)
                content_hash = hashlib.sha256(canonical(message_content.of_payload(payload))).hexdigest()
                if not item["versions"] or item["versions"][-1]["content_hash"] != content_hash:
                    item["versions"].append({"text": text, "buttons": buttons, "observed_at": row["observed_at"],
                                             "content_hash": content_hash,
                                             "edited_at": payload.get("edited_at"), "kind": kind, "seq": row["seq"]})
            elif kind == "message.deleted":
                item["deleted"] = True
                item["deleted_observed_at"] = item["deleted_observed_at"] or row["observed_at"]
            elif kind == "message.missing_on_recheck":
                item["missing"] = True
                item["missing_observed_at"] = item["missing_observed_at"] or row["observed_at"]
            elif payload.get("media_sha256"):
                item["media"].append({"sha256": payload["media_sha256"], "mime_type": payload.get("mime_type"),
                                      "name": payload.get("original_name"), "size": payload.get("size")})
        result = []
        for item in sorted(messages.values(), key=lambda m: m["message_id"]):
            item["captured"] = bool(item["versions"])
            item["text"] = item["versions"][-1]["text"] if item["versions"] else None
            item["buttons"] = item["versions"][-1]["buttons"] if item["versions"] else None
            item["edited"] = len(item["versions"]) > 1 or bool(item["telegram_edited_at"])
            result.append(item)
        return {"messages": result, "next_before": min(ids) if len(ids) == limit else None}

    def events_after(self, seq, limit):
        """Consecutive journal records after seq, as stored (for the off-site copy)."""
        with self.lock:
            return [self.decode(r) for r in self.db.execute(
                "SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?", (seq, limit))]

    def counts_since(self, observed_at, kinds):
        """{(chat_id, kind): records} observed at or after the given UTC time (for the daily summary)."""
        with self.lock:
            return {(r[0], r[1]): r[2] for r in self.db.execute(
                "SELECT chat_id, kind, count(*) FROM events WHERE observed_at>=? AND kind IN ("
                + ",".join("?" * len(kinds)) + ") GROUP BY chat_id, kind", (observed_at, *kinds))}

    def media_saved_after(self, seq):
        """(seq, SHA-256) of preserved files recorded after seq."""
        with self.lock:
            return [(r[0], r[1]) for r in self.db.execute(
                "SELECT seq, json_extract(payload,'$.media_sha256') FROM events WHERE kind='media.saved' AND seq>?"
                " ORDER BY seq", (seq,)) if r[1]]

    def events(self, chat_id=None, message_id=None, kind=None, before=None, limit=100, search=None):
        filters, params = [], []
        for key, value in (("chat_id", chat_id), ("message_id", message_id)):
            if value is not None:
                filters.append(key + "=?")
                params.append(value)
        if kind in ("membership", "coverage"):
            prefixes = ("membership.",) if kind == "membership" else (
                "coverage.", "connection.", "collector.", "process.", "observation.",
                "snapshot.", "target.", "capture.", "monitoring.", "source.", "scope.", "telegram.", "clock.", "media.failed",
                "media.retry", "media.recovered", "deletion.unscoped")
            filters.append("(" + " OR ".join("kind LIKE ?" for _ in prefixes) + ")")
            params.extend(p + "%" for p in prefixes)
        elif kind:
            filters.append("kind=?")
            params.append(kind)
        if before is not None:
            filters.append("seq<?")
            params.append(before)
        if search:
            filters.append("instr(search_text(payload), ?)>0")
            params.append(search_text(search))
        sql = "SELECT * FROM events"
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        sql += " ORDER BY seq DESC LIMIT ?"
        with self.lock:
            return [self.decode(r) for r in self.db.execute(sql, [*params, limit])]

    def all_events(self):
        with self.lock:
            return [self.decode(r) for r in self.db.execute("SELECT * FROM events ORDER BY seq")]

    @contextmanager
    def snapshot(self):
        """Separate read transaction: bounded-memory stable prefix without blocking WAL writers."""
        connection = sqlite3.connect(self.root / "journal.sqlite3")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        try:
            head = connection.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            yield JournalSnapshot(connection, dict(head) if head else None)
        finally:
            connection.rollback()
            connection.close()

    def verify(self, public_key):
        from .verify import verify_events, verify_checkpoint
        retained = self.retained_checkpoint()
        with self.snapshot() as snapshot:
            result = verify_events(snapshot.events(), public_key)
            if retained:
                verify_checkpoint(retained, public_key, result["events"], snapshot.hash_at)
            return result

    def retained_checkpoint(self):
        path = self.root / "checkpoints" / "latest.json"
        return json.loads(path.read_bytes()) if path.exists() else None

    def media_stats(self):
        with self.lock:
            return {r[0]: r[1] for r in self.db.execute(
                "SELECT state,count(*) FROM media_jobs GROUP BY state")}

    def media_oldest(self):
        with self.lock:
            row = self.db.execute(
                "SELECT min(e.observed_at) FROM media_jobs j JOIN events e ON e.seq=j.message_event "
                "WHERE j.state IN ('queued','retry','running')").fetchone()
        return row[0]

    def claim_media(self, account_id, now=None):
        with self.transaction():
            row = self.db.execute(
                "SELECT j.* FROM media_jobs j JOIN targets t USING(chat_id) "
                "WHERE j.account_id=? AND t.enabled=1 AND j.state IN ('queued','retry') "
                "AND j.next_attempt<=? ORDER BY j.message_event LIMIT 1",
                (account_id, time.time() if now is None else now)).fetchone()
            if not row:
                return None
            self.db.execute("UPDATE media_jobs SET state='running',attempts=attempts+1 WHERE message_event=?",
                            (row["message_event"],))
            job = dict(row)
            job["attempts"] += 1
            return job

    def recover_media(self):
        with self.transaction():
            count = self.db.execute("SELECT count(*) FROM media_jobs WHERE state='running'").fetchone()[0]
            if count:
                self.db.execute("UPDATE media_jobs SET state='retry',next_attempt=0,"
                                "last_error='interrupted' WHERE state='running'")
                self.append("media.recovered", {"jobs": count, "reason": "previous attempt interrupted",
                                               "content_recoverability": "not guaranteed"})
            return count

    def finish_media(self, job, state, payload, delay=0):
        if state not in ("done", "retry", "failed"):
            raise ValueError("Invalid media outcome")
        with self.transaction():
            self.append({"done": "media.saved", "retry": "media.retry", "failed": "media.failed"}[state],
                        {"message_event": job["message_event"], "attempt": job["attempts"], **payload},
                        job["chat_id"], job["message_id"])
            self.db.execute("UPDATE media_jobs SET state=?,next_attempt=?,last_error=? WHERE message_event=?",
                            (state, time.time() + delay, payload.get("error_type"), job["message_event"]))

    def stats(self):
        with self.lock:
            counts = {r[0]: r[1] for r in self.db.execute("SELECT kind,count(*) FROM events GROUP BY kind")}
            tail = self.db.execute("SELECT seq,hash,observed_at FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return {"counts": counts, "total": sum(counts.values()), "head": dict(tail) if tail else None}

    def get_setting(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        with self.transaction():
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))

    def targets(self, enabled_only=False):
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM targets" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY title")]

    def set_target(self, chat_id, title, kind, enabled, origin=None, priority=None):
        """Add or update a source. origin/priority keep their saved values unless given."""
        with self.transaction():
            self.db.execute(
                "INSERT INTO targets(chat_id,title,enabled,kind,origin,priority) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(chat_id) DO UPDATE SET title=excluded.title, enabled=excluded.enabled,"
                " kind=excluded.kind" + (", origin=excluded.origin" if origin else "")
                + (", priority=excluded.priority" if priority is not None else ""),
                (chat_id, title, int(enabled), kind, origin or "manual",
                 1 if priority is None else int(priority)))
            self.targets_revision += 1

    def remove_target(self, chat_id):
        """Forget a source; its journal records stay (the journal is append-only). Its files still
        waiting to download are recorded as failed: nothing fetches files of a removed source."""
        with self.transaction():
            removed = self.db.execute("DELETE FROM targets WHERE chat_id=?", (chat_id,)).rowcount
            waiting = self.db.execute("SELECT * FROM media_jobs WHERE chat_id=? AND state IN ('queued','retry')"
                                      " ORDER BY message_event", (chat_id,)).fetchall()
            for job in waiting:
                self.finish_media(dict(job), "failed", {
                    "error_type": "source_removed", "meaning": "the source was removed before this file was downloaded"})
            self.targets_revision += 1
        return bool(removed)

    def account_message_chat(self, message_id):
        """The private chat or ordinary group where this account-wide message ID was saved, or None.

        Channels and supergroups (IDs below -10^12) number messages per chat and are never matched.
        """
        marks = ",".join("?" * len(TEXT_KINDS))
        with self.lock:
            chats = [r[0] for r in self.db.execute(
                "SELECT DISTINCT chat_id FROM events WHERE message_id=? AND chat_id IS NOT NULL"
                " AND chat_id>-1000000000000 AND kind IN (" + marks + ")", (message_id, *TEXT_KINDS))]
        return chats[0] if len(chats) == 1 else None

    def latest_reply_keyboard(self, chat_id, window=500, before_message_id=None):
        """(seq, button labels) of the newest saved message in this chat with a reply keyboard,
        only among messages older than before_message_id when given."""
        with self.lock:
            row = self.db.execute(
                "SELECT seq, json_extract(payload,'$.raw.reply_markup') FROM (SELECT seq, message_id, payload FROM events"
                " WHERE chat_id=? ORDER BY seq DESC LIMIT ?) WHERE"
                " json_extract(payload,'$.raw.reply_markup._')='ReplyKeyboardMarkup'"
                " AND (? IS NULL OR message_id<?) ORDER BY seq DESC LIMIT 1",
                (chat_id, window, before_message_id, before_message_id)).fetchone()
        if not row:
            return None
        markup = json.loads(row[1])
        labels = [b.get("text") for r in markup.get("rows", []) for b in r.get("buttons", []) if b.get("text")]
        return row[0], labels

    def events_of(self, kinds, limit=50, after=None, before=None):
        """Newest records of the given kinds (for the panel's notification list)."""
        where, params = "kind IN (" + ",".join("?" * len(kinds)) + ")", list(kinds)
        if after is not None:
            where += " AND seq>?"
            params.append(after)
        if before is not None:
            where += " AND seq<?"
            params.append(before)
        with self.lock:
            return [self.decode(r) for r in self.db.execute(
                "SELECT * FROM events WHERE " + where + " ORDER BY seq DESC LIMIT ?", (*params, limit))]

    def chat_records(self, chat_id, kinds):
        """Every record of the given kinds in one chat, oldest first."""
        with self.lock:
            return [self.decode(r) for r in self.db.execute(
                "SELECT * FROM events WHERE chat_id=? AND kind IN (" + ",".join("?" * len(kinds)) + ")"
                " ORDER BY seq", (chat_id, *kinds))]

    def sender_chats(self, sender_ids):
        """{sender_id: {chat_id: distinct saved messages}} across every chat in this journal. Snapshots,
        edits and recoveries of one message are further records of the same message, not new ones."""
        if not sender_ids:
            return {}
        marks = ",".join("?" * len(TEXT_KINDS))
        wanted = set(sender_ids)
        result = {}
        with self.lock:
            for chat_id, sender, count in self.db.execute(
                    "SELECT chat_id, json_extract(payload,'$.sender_id') AS sender, count(DISTINCT message_id) FROM events"
                    " WHERE kind IN (" + marks + ") AND chat_id IS NOT NULL GROUP BY chat_id, sender", TEXT_KINDS):
                if sender in wanted:
                    result.setdefault(sender, {})[chat_id] = count
        return result

    def close(self):
        self.db.close()


class JournalSnapshot:
    def __init__(self, connection, head):
        self.connection, self.head = connection, head

    def events(self):
        for row in self.connection.execute("SELECT * FROM events ORDER BY seq"):
            yield Store.decode(row)

    def hash_at(self, seq):
        if seq == 0:
            return ZERO
        row = self.connection.execute("SELECT hash FROM events WHERE seq=?", (seq,)).fetchone()
        return row[0] if row else None
