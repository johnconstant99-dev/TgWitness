"""Rebuildable read indexes. Signed journal records remain the source of truth."""
import json
import sqlite3
import unicodedata

TEXT_KINDS = ("message.new", "message.snapshot", "message.edited", "message.recovered")
GONE_KINDS = ("message.deleted", "message.missing_on_recheck")
CHAT_KINDS = TEXT_KINDS + GONE_KINDS + ("media.saved",)
MEDIA_KINDS = ("media.saved", "actor.avatar_saved")
NUL_PAYLOAD = "instr(payload,'\\u0000')>0"
READ_GROUPS = {
    "state": ("message_state_index", "chat_state_index", "known_chat_index"),
    "counts": ("event_kind_counts", "chat_event_kind_counts"),
    "search": ("event_text_search",),
    "payload_search": ("event_payload_search",),
}


def search_text(value):
    value = "" if value is None else value if isinstance(value, str) else str(value)
    return unicodedata.normalize("NFC", value.casefold())


def nul_text(payload):
    """Older JSON1 builds truncate decoded strings at NUL; Python preserves them."""
    value = json.loads(payload).get("text")
    return value if isinstance(value, str) else ""


class JournalIndex:
    def __init__(self, db):
        self.db = db
        self.repair_missing_tables()
        # Do not use executescript: migration must roll back with its caller.
        for sql in (
            "CREATE TABLE IF NOT EXISTS journal_read_index (name TEXT PRIMARY KEY, seq INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS message_state_index ("
            "chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL, text_seq INTEGER,"
            "has_message INTEGER NOT NULL, edited INTEGER NOT NULL, deleted INTEGER NOT NULL,"
            "missing INTEGER NOT NULL, PRIMARY KEY(chat_id,message_id)) WITHOUT ROWID",
            "CREATE INDEX IF NOT EXISTS message_alive ON message_state_index(chat_id,message_id DESC) "
            "WHERE text_seq IS NOT NULL AND deleted=0 AND missing=0",
            "CREATE INDEX IF NOT EXISTS message_text ON message_state_index(chat_id,message_id DESC) "
            "WHERE text_seq IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS message_account ON message_state_index(message_id,chat_id) "
            "WHERE text_seq IS NOT NULL AND chat_id>-1000000000000",
            "CREATE TABLE IF NOT EXISTS chat_state_index (chat_id INTEGER PRIMARY KEY,"
            "messages INTEGER NOT NULL DEFAULT 0, edited INTEGER NOT NULL DEFAULT 0,"
            "deleted INTEGER NOT NULL DEFAULT 0, missing INTEGER NOT NULL DEFAULT 0,"
            "last_observed_at TEXT, text_id INTEGER, text_seq INTEGER)",
            "CREATE TABLE IF NOT EXISTS known_chat_index (chat_id INTEGER PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS event_kind_counts (kind TEXT PRIMARY KEY, total INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS chat_event_kind_counts (chat_id INTEGER NOT NULL,kind TEXT NOT NULL,"
            "total INTEGER NOT NULL,PRIMARY KEY(chat_id,kind)) WITHOUT ROWID",
            "CREATE INDEX IF NOT EXISTS event_sender ON events("
            "json_extract(payload,'$.sender_id'),chat_id,message_id,kind)",
            "CREATE INDEX IF NOT EXISTS event_media ON events("
            "json_extract(payload,'$.media_sha256'),chat_id,kind)",
            "CREATE INDEX IF NOT EXISTS event_text_nul ON events(seq) WHERE " + NUL_PAYLOAD,
        ):
            db.execute(sql)
        self.search_enabled = self.create_search()
        self.payload_search_enabled = self.create_search("event_payload_search", "document")
        state_seq = self.position("state")
        search_seq = self.position("search") if self.search_enabled else state_seq
        payload_seq = self.position("payload_search") if self.payload_search_enabled else state_seq
        for row in db.execute("SELECT * FROM events WHERE seq>? ORDER BY seq",
                              (min(state_seq, search_seq, payload_seq),)):
            if row["seq"] > state_seq or self.search_enabled and row["seq"] > search_seq:
                event = dict(row)
                event["payload"] = json.loads(row["payload"])
            if row["seq"] > state_seq:
                self.state(event)
            if self.search_enabled and row["seq"] > search_seq:
                self.search(event)
            if self.payload_search_enabled and row["seq"] > payload_seq:
                self.search_payload(row["seq"], row["payload"])
        self.initialize_counts()

    def repair_missing_tables(self):
        """A watermark is usable only with every table it describes.

        The caller's transaction restores the previous state if replay fails.
        Reset a whole group so surviving counters/FTS rows cannot be replayed twice.
        """
        existing = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        has_positions = "journal_read_index" in existing
        positions = {row[0] for row in self.db.execute("SELECT name FROM journal_read_index")} if has_positions else set()
        for name, tables in READ_GROUPS.items():
            if name in positions and all(table in existing for table in tables):
                continue
            for table in tables:
                self.db.execute("DROP TABLE IF EXISTS " + table)
            if has_positions:
                self.db.execute("DELETE FROM journal_read_index WHERE name=?", (name,))

    def create_search(self, table="event_text_search", column="text"):
        try:
            self.db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS " + table + " USING "
                            "fts5(" + column + ",content='',tokenize='trigram case_sensitive 1')")
        except sqlite3.OperationalError as exc:
            # Older/system SQLite builds can lack FTS5 or the trigram tokenizer.
            if "no such module" not in str(exc) and "tokenizer" not in str(exc):
                raise
            return False
        return True

    def position(self, name):
        row = self.db.execute("SELECT seq FROM journal_read_index WHERE name=?", (name,)).fetchone()
        return row[0] if row else 0

    def advance(self, name, seq):
        self.db.execute("INSERT INTO journal_read_index VALUES (?,?) "
                        "ON CONFLICT(name) DO UPDATE SET seq=excluded.seq", (name, seq))

    def append(self, event):
        self.state(event)
        if self.search_enabled:
            self.search(event)
        if self.payload_search_enabled:
            payload = self.db.execute("SELECT payload FROM events WHERE seq=?", (event["seq"],)).fetchone()[0]
            self.search_payload(event["seq"], payload)
        self.count(event["chat_id"], event["kind"], 1)
        self.advance("counts", event["seq"])

    def count(self, chat, kind, total):
        self.db.execute("INSERT INTO event_kind_counts VALUES (?,?) "
                        "ON CONFLICT(kind) DO UPDATE SET total=total+excluded.total", (kind, total))
        if chat is not None:
            self.db.execute("INSERT INTO chat_event_kind_counts VALUES (?,?,?) "
                            "ON CONFLICT(chat_id,kind) DO UPDATE SET total=total+excluded.total", (chat, kind, total))

    def initialize_counts(self):
        indexed = self.position("counts")
        tail = self.db.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
        if indexed < tail:
            for row in self.db.execute("SELECT chat_id,kind,count(*) FROM events WHERE seq>? "
                                       "GROUP BY chat_id,kind", (indexed,)):
                self.count(*row)
            self.advance("counts", tail)

    def state(self, event):
        db = self.db
        chat, message, kind = event["chat_id"], event["message_id"], event["kind"]
        if chat is not None and message is not None:
            db.execute("INSERT OR IGNORE INTO known_chat_index VALUES (?)", (chat,))
        if chat is not None and kind in CHAT_KINDS:
            db.execute("INSERT OR IGNORE INTO chat_state_index(chat_id) VALUES (?)", (chat,))
            if message is not None:
                old = db.execute("SELECT * FROM message_state_index WHERE chat_id=? AND message_id=?",
                                 (chat, message)).fetchone()
                values = (int(kind != "media.saved"), int(kind == "message.edited"),
                          int(kind == "message.deleted"), int(kind == "message.missing_on_recheck"))
                previous = tuple(old[k] for k in ("has_message", "edited", "deleted", "missing")) if old else (0,)*4
                updated = tuple(max(a, b) for a, b in zip(previous, values))
                text_seq = event["seq"] if kind in TEXT_KINDS else old["text_seq"] if old else None
                db.execute("INSERT INTO message_state_index VALUES (?,?,?,?,?,?,?) "
                           "ON CONFLICT(chat_id,message_id) DO UPDATE SET text_seq=excluded.text_seq,"
                           "has_message=excluded.has_message,edited=excluded.edited,"
                           "deleted=excluded.deleted,missing=excluded.missing",
                           (chat, message, text_seq, *updated))
                db.execute("UPDATE chat_state_index SET messages=messages+?,edited=edited+?,"
                           "deleted=deleted+?,missing=missing+?,"
                           "last_observed_at=max(coalesce(last_observed_at,''),?) WHERE chat_id=?",
                           (*[b-a for a, b in zip(previous, updated)], event["observed_at"], chat))
            if kind in TEXT_KINDS:
                db.execute("UPDATE chat_state_index SET text_id=?,text_seq=? WHERE chat_id=? "
                           "AND (text_seq IS NULL OR text_id IS NULL OR ?>=text_id)",
                           (message, event["seq"], chat, message))
        self.advance("state", event["seq"])

    def search(self, event):
        value = event["payload"].get("text")
        if value is not None and not isinstance(value, str):
            # JSON objects/arrays are strings to SQLite's json_extract(), and
            # were searchable before FTS. Index that exact representation.
            value = self.db.execute("SELECT json_extract(payload,'$.text') FROM events WHERE seq=?",
                                    (event["seq"],)).fetchone()[0]
        if value is not None:
            self.db.execute("INSERT INTO event_text_search(rowid,text) VALUES (?,?)",
                            (event["seq"], search_text(value)))
        self.advance("search", event["seq"])

    def search_payload(self, seq, payload):
        self.db.execute("INSERT INTO event_payload_search(rowid,document) VALUES (?,?)",
                        (seq, search_text(payload)))
        self.advance("payload_search", seq)

    def candidate(self, query, *, text_only=True):
        # Exact instr() remains authoritative. Short queries use the
        # original scan; NUL is excluded because FTS query strings cannot carry it.
        value = search_text(query)
        enabled = self.search_enabled if text_only else self.payload_search_enabled
        if not enabled or len(value) < 3 or "\0" in value:
            return None
        return '"' + value.replace('"', '""') + '"'


def media_fields(payload):
    """Best-effort scheduling hints for old queues; never alter signed payloads."""
    capture = payload.get("media_capture") or {}
    raw = payload.get("raw") or {}
    media = raw.get("media") or {}
    document = media.get("document") or (media.get("webpage") or {}).get("document") or {}
    size = capture.get("estimated_bytes", document.get("size"))
    size = size if type(size) is int and size >= 0 else None
    ttl = raw.get("ttl_period") or media.get("ttl_seconds")
    priority = capture.get("priority")
    if type(priority) is not int:
        priority = 0 if isinstance(ttl, (int, float)) and ttl > 0 else 1 if size is not None and size <= 2*1024**2 else 10
    return priority, size


def migrate_media(db):
    columns = {r[1] for r in db.execute("PRAGMA table_info(media_jobs)")}
    added = "priority" not in columns
    if added:
        db.execute("ALTER TABLE media_jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 10")
    if "estimated_bytes" not in columns:
        db.execute("ALTER TABLE media_jobs ADD COLUMN estimated_bytes INTEGER")
    if added:
        for row in db.execute("SELECT j.message_event,e.payload FROM media_jobs j "
                              "JOIN events e ON e.seq=j.message_event"):
            priority, size = media_fields(json.loads(row["payload"]))
            db.execute("UPDATE media_jobs SET priority=?,estimated_bytes=? WHERE message_event=?",
                       (priority, size, row["message_event"]))
    db.execute("CREATE INDEX IF NOT EXISTS media_lane ON "
               "media_jobs(account_id,priority,message_event,next_attempt) WHERE state IN ('queued','retry')")
