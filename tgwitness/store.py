import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import keyboard
from . import message_content
from . import continuity
from .journal_index import CHAT_KINDS, MEDIA_KINDS, TEXT_KINDS, JournalIndex, migrate_media, search_text
from .journal_index import GONE_KINDS as GONE_KINDS

ZERO = "0" * 64
EVENT_FIELDS = ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id",
                "actor_id", "payload", "previous_hash")

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def event_hash(event):
    return hashlib.sha256(canonical({k: event[k] for k in EVENT_FIELDS})).hexdigest()


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

        columns = {r[1] for r in self.db.execute("PRAGMA table_info(targets)")}
        if "origin" not in columns:
            self.db.execute("ALTER TABLE targets ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'")
        if "priority" not in columns:
            self.db.execute("ALTER TABLE targets ADD COLUMN priority INTEGER NOT NULL DEFAULT 1")


        self.db.execute("CREATE INDEX IF NOT EXISTS event_message_id ON events(message_id)")
        self.db.commit()
        self.signer = None
        self.targets_revision = 0
        self.listeners = []
        with self.transaction():
            continuity.initialize(self.db)
            migrate_media(self.db)
            self.read_index = JournalIndex(self.db)

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
            continuity.index_event(self.db, event["seq"], event["hash"])
            self.read_index.append(event)
            if media_job:
                self.db.execute(
                    "INSERT INTO media_jobs(message_event,account_id,chat_id,message_id,"
                    "descriptor,descriptor_hash,max_bytes,priority,estimated_bytes) VALUES (?,?,?,?,?,?,?,?,?)",
                    (event["seq"], media_job["account_id"], chat_id, message_id,
                     media_job["descriptor"], hashlib.sha256(media_job["descriptor"]).hexdigest(),
                     media_job["max_bytes"], media_job.get("priority", 10), media_job.get("estimated_bytes")))
            for listen in self.listeners:
                try:
                    listen(event)
                except Exception:
                    pass
            return event

    @staticmethod
    def decode(row):
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def chat_overview(self):
        """Per chat: saved messages, edited and deleted counts, and the newest saved text."""
        with self.lock:
            rows = self.db.execute(
                "SELECT c.*,e.payload FROM chat_state_index c LEFT JOIN events e ON e.seq=c.text_seq "
                "WHERE c.last_observed_at IS NOT NULL").fetchall()
            result = {}
            for row in rows:
                payload = json.loads(row["payload"]) if row["payload"] is not None else {}
                sender = payload.get("sender_observation") or {}
                result[row["chat_id"]] = {
                    "messages": row["messages"], "edited": row["edited"], "deleted": row["deleted"],
                    "missing": row["missing"],
                    "last_observed_at": row["last_observed_at"],
                    "last_text": payload.get("text"),
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
        with self.lock:
            row = self.db.execute("SELECT message_id FROM message_state_index INDEXED BY message_text WHERE chat_id=? "
                                  "AND text_seq IS NOT NULL ORDER BY message_id DESC LIMIT 1", (chat_id,)).fetchone()
        return row[0] if row else None

    def message_state(self, chat_id, message_id):
        """Latest saved content of one message and whether it is already recorded as gone."""
        with self.lock:
            row = self.db.execute(
                "SELECT e.seq,e.hash,json_extract(e.payload,'$.text') AS text,"
                "json_extract(e.payload,'$.edited_at') AS edited_at,"
                "json_extract(e.payload,'$.outgoing') AS outgoing,e.payload,m.deleted,m.missing "
                "FROM message_state_index m LEFT JOIN events e ON e.seq=m.text_seq "
                "WHERE m.chat_id=? AND m.message_id=?", (chat_id, message_id)).fetchone()
        content = {key: row[key] for key in ("seq", "hash", "text", "edited_at", "outgoing", "payload")} \
            if row and row["seq"] is not None else None
        if content:
            content["observable"] = message_content.of_payload(json.loads(content.pop("payload")))
            content["buttons"] = content["observable"]["buttons"]
        return {"content": content,
                "deleted": bool(row and row["deleted"]), "missing": bool(row and row["missing"])}

    def alive_message_ids(self, chat_id, below=None, limit=200):
        """Saved message IDs not yet recorded as deleted or missing, newest first."""
        where, params = "chat_id=? AND text_seq IS NOT NULL AND deleted=0 AND missing=0", [chat_id]
        if below is not None:
            where += " AND message_id<?"
            params.append(below)
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT message_id FROM message_state_index INDEXED BY message_alive WHERE " + where +
                " ORDER BY message_id DESC LIMIT ?", (*params, limit))]

    def chat_messages(self, chat_id, before_id=None, limit=60):
        """Readable view of one chat: every saved version, deletion and attachment per message."""
        marks = ",".join("?" * len(CHAT_KINDS))
        where, params = "chat_id=?", [chat_id]
        if before_id is not None:
            where += " AND message_id<?"
            params.append(before_id)
        with self.lock:
            ids = [r[0] for r in self.db.execute(
                "SELECT message_id FROM message_state_index WHERE " + where + " ORDER BY message_id DESC LIMIT ?",
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
                observable = message_content.of_payload(payload)
                content_hash = hashlib.sha256(canonical(observable)).hexdigest()
                if not item["versions"] or item["versions"][-1]["content_hash"] != content_hash:
                    item["versions"].append({"text": text, "buttons": buttons, "observed_at": row["observed_at"],
                                             "entities": observable["entities"],
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
                "SELECT seq, json_extract(payload,'$.media_sha256') FROM events WHERE kind IN (?,?) AND seq>?"
                " ORDER BY seq", (*MEDIA_KINDS, seq)) if r[1]]

    def media_in_chats(self, sha256, chat_ids):
        """Whether a preserved file was saved from one of these chats."""
        marks = ",".join("?" * len(chat_ids))
        with self.lock:
            return self.db.execute(
                "SELECT 1 FROM events WHERE kind IN (?,?) AND chat_id IN (" + marks + ")"
                " AND json_extract(payload,'$.media_sha256')=? LIMIT 1",
                (*MEDIA_KINDS, *sorted(chat_ids), sha256)).fetchone() is not None

    def sender_in_chats(self, sender_id, chat_ids):
        """Whether someone wrote a saved message in one of these chats."""
        marks = ",".join("?" * len(chat_ids))
        with self.lock:
            return self.db.execute(
                "SELECT 1 FROM events WHERE chat_id IN (" + marks + ") AND message_id IS NOT NULL"
                " AND json_extract(payload,'$.sender_id')=? LIMIT 1", (*sorted(chat_ids), sender_id)).fetchone() is not None

    def events(self, chat_id=None, message_id=None, kind=None, before=None, limit=100, search=None, chat_ids=None,
               *, since=None, until=None, message_min=None, message_max=None, timeout_s=None,
               text_only=False, message_only=False):
        filters, params = [], []
        source, order = "events", "seq"
        if chat_ids is not None:
            filters.append("chat_id IN (" + ",".join("?" * len(chat_ids)) + ")")
            params.extend(sorted(chat_ids))
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
            candidate = self.read_index.candidate(search, text_only=text_only)
            if candidate is not None:
                table = "event_text_search" if text_only else "event_payload_search"
                source = table + " JOIN events ON events.seq=" + table + ".rowid"
                order = table + ".rowid"
                filters.append(table + " MATCH ?")
                params.append(candidate)
            value = "COALESCE(json_extract(payload,'$.text'),'')" if text_only else "payload"
            filters.append("instr(search_text(" + value + "), ?)>0")
            params.append(search_text(search))
        if message_only:
            filters.append("kind IN (" + ",".join("?" * len(CHAT_KINDS)) + ")")
            params.extend(CHAT_KINDS)
        for comparison, value in (("observed_at>=?", since), ("observed_at<=?", until)):
            if value is not None:
                filters.append(comparison)
                params.append(value.astimezone(timezone.utc).isoformat(timespec="milliseconds"))
        for comparison, value in (("message_id>=?", message_min), ("message_id<=?", message_max)):
            if value is not None:
                filters.append(comparison)
                params.append(value)
        sql = "SELECT events.* FROM " + source
        if filters:
            sql += " WHERE " + " AND ".join(filters)
        sql += " ORDER BY " + order + " DESC LIMIT ?"
        return [self.decode(r) for r in self.bounded_read(sql, [*params, limit], timeout_s)]

    def archive_chats(self, offset, limit, chat_ids):
        sql = ("WITH known AS (SELECT chat_id,title,kind,enabled FROM targets UNION ALL "
               "SELECT chat_id,NULL,NULL,0 FROM known_chat_index "
               "WHERE chat_id NOT IN (SELECT chat_id FROM targets)) SELECT * FROM known")
        params = []
        if chat_ids is not None:
            sql += " WHERE chat_id IN (" + ",".join("?" * len(chat_ids)) + ")"
            params.extend(sorted(chat_ids))
        sql += " ORDER BY chat_id LIMIT ? OFFSET ?"
        return [dict(r) for r in self.bounded_read(sql, [*params, limit, offset], 3)]

    def bounded_read(self, sql, params, timeout_s):
        if timeout_s is None:
            with self.lock:
                return self.db.execute(sql, params).fetchall()
        deadline = time.monotonic() + timeout_s
        if not self.lock.acquire(timeout=timeout_s):
            raise TimeoutError("Archive is busy. Retry shortly.")
        try:
            self.db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            return self.db.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError("Archive search timed out. Narrow the query.") from None
            raise exc
        finally:
            self.db.set_progress_handler(None, 0)
            self.lock.release()

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

    def claim_media(self, account_id, now=None, *, min_priority=None, max_priority=None):
        filters, params = [], [account_id, time.time() if now is None else now]
        for operator, value in ((">=", min_priority), ("<=", max_priority)):
            if value is not None:
                filters.append("j.priority" + operator + "?")
                params.append(value)
        with self.transaction():
            row = self.db.execute(
                "SELECT j.* FROM media_jobs j JOIN targets t USING(chat_id) "
                "WHERE j.account_id=? AND t.enabled=1 AND j.state IN ('queued','retry') "
                "AND j.next_attempt<=? " + ("AND " + " AND ".join(filters) if filters else "") +
                " ORDER BY j.priority,j.message_event LIMIT 1", params).fetchone()
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

    def stats(self, chat_ids=None):
        with self.lock:
            if chat_ids is None:
                rows = self.db.execute("SELECT kind,total FROM event_kind_counts")
            else:
                rows = self.db.execute("SELECT kind,sum(total) FROM chat_event_kind_counts "
                                       "WHERE chat_id IN (" + ",".join("?" * len(chat_ids)) + ") GROUP BY kind",
                                       sorted(chat_ids))
            counts = {r[0]: r[1] for r in rows}
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

    def target_counts(self):
        with self.lock:
            row = self.db.execute("SELECT count(*),coalesce(sum(enabled=1),0) FROM targets").fetchone()
        return {"total": row[0], "enabled": row[1]}

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
        with self.lock:
            chats = [r[0] for r in self.db.execute(
                "SELECT chat_id FROM message_state_index WHERE message_id=? AND text_seq IS NOT NULL"
                " AND chat_id>-1000000000000 LIMIT 2", (message_id,))]
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
        sender_filter = "json_extract(payload,'$.sender_id') IN (" + ",".join("?" * len(wanted)) + ")"
        if None in wanted:
            sender_filter = "(" + sender_filter + " OR json_extract(payload,'$.sender_id') IS NULL)"
        result = {}
        with self.lock:
            for chat_id, sender, count in self.db.execute(
                    "SELECT chat_id, json_extract(payload,'$.sender_id') AS sender, count(DISTINCT message_id) FROM events"
                    " WHERE kind IN (" + marks + ") AND chat_id IS NOT NULL"
                    " AND " + sender_filter +
                    " GROUP BY chat_id, sender", (*TEXT_KINDS, *wanted)):
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
