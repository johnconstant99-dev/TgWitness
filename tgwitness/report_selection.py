"""Select report material from a stable journal without editing source records.

Observation dates are inclusive UTC calendar dates. Missing message-number
ranges are calculated independently of author and event-kind filters, using
every known positive message number in the snapshot. They are not deletion
claims. A separate disposable SQLite database bounds memory while preserving
exact counts for arbitrarily long journals; the snapshot remains read-only.
"""
from datetime import date
from pathlib import Path
import sqlite3
import tempfile
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from . import report_analytics


FORMAT = "tgwitness-report-selection-v1"
MAX_SELECTION_IDS = 1000
MAX_CATALOG_ROWS = 1000
MAX_PREVIEW_ROWS = 100
MAX_GAP_ROWS = 100
PREVIEW_CHARS = 240
TITLE_CHARS = 160
ID_GAP_BASIS = (
    "Message numbers absent from all records in this snapshot, between the lowest and highest known "
    "message numbers observed in each selected chat during the selected UTC dates. Sender and event-kind "
    "filters do not create gaps. Neighboring records are context and may fall outside those filters or dates. "
    "An absent message number is not proof that a message existed or was deleted."
)
Identifier = Annotated[int, Field(strict=True, gt=-(2**63), lt=2**63)]
EventKind = Literal["message.new", "message.snapshot", "message.recovered", "message.edited",
                    "message.deleted", "message.missing_on_recheck"]


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    enabled: StrictBool = False
    chats: list[Identifier] = Field(default_factory=list, max_length=MAX_SELECTION_IDS)
    senders: list[Identifier] = Field(default_factory=list, max_length=MAX_SELECTION_IDS)
    date_from: str = Field(default="", strict=True, max_length=10, pattern=r"^(?:\d{4}-\d{2}-\d{2})?$")
    date_to: str = Field(default="", strict=True, max_length=10, pattern=r"^(?:\d{4}-\d{2}-\d{2})?$")
    kinds: list[EventKind] = Field(default_factory=lambda: list(report_analytics.KINDS), max_length=6)
    id_gaps: StrictBool = True

    @field_validator("chats", "senders", "kinds")
    @classmethod
    def distinct(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Choose each item only once")
        if 0 in value:
            raise ValueError("Telegram identifiers must not be zero")
        return value

    @field_validator("date_from", "date_to")
    @classmethod
    def calendar_date(cls, value):
        if value:
            date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def chronological(self):
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("The end date must not be earlier than the start date")
        return self


def _selection(value):
    return value if isinstance(value, Selection) else Selection.model_validate(value or {})


def _text(value, limit=PREVIEW_CHARS):
    return value[:limit] if isinstance(value, str) else ""


def sender_id(event):
    """The recorded message sender, never the event's actor or an inferred user."""
    payload = event.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    observed = payload.get("sender_observation")
    observed = observed if isinstance(observed, dict) else {}
    return report_analytics._identifier(payload.get("sender_id", observed.get("id")))


class _Matcher:
    def __init__(self, selection):
        self.enabled = selection.enabled
        self.chats = frozenset(selection.chats)
        self.senders = frozenset(selection.senders)
        self.kinds = frozenset(selection.kinds)
        self.start = date.fromisoformat(selection.date_from) if selection.date_from else None
        self.end = date.fromisoformat(selection.date_to) if selection.date_to else None

    def chat(self, event):
        return not self.enabled or not self.chats or event.get("chat_id") in self.chats

    def time(self, event):
        if not self.enabled or not (self.start or self.end):
            return True
        moment = report_analytics._time(event.get("observed_at"))
        return moment is not None and (self.start is None or moment.date() >= self.start) \
            and (self.end is None or moment.date() <= self.end)

    def __call__(self, event):
        if not self.enabled:
            return True
        kind = event.get("kind")
        return isinstance(kind, str) and kind in self.kinds and self.chat(event) and self.time(event) \
            and (not self.senders or sender_id(event) in self.senders)


def compile_selection(selection):
    """Prepare a reusable predicate for long export streams."""
    return _Matcher(_selection(selection))


def matches(event, selection):
    return compile_selection(selection)(event)


def _preview(event):
    payload = event.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    return {"seq": report_analytics._sequence(event.get("seq")),
            "chat_id": report_analytics._identifier(event.get("chat_id")),
            "message_id": _message_id(event.get("message_id")),
            "kind": _text(event.get("kind"), 80), "observed_at": _text(event.get("observed_at"), 64),
            "sender_id": sender_id(event), "text": _text(payload.get("text"))}


def _message_id(value):
    # MTProto message IDs are positive signed 32-bit integers. Do not expand a
    # range or accept a boolean/float just because Python compares it as an int.
    return value if type(value) is int and 0 < value < 2**31 else None


def _prepare(connection):
    connection.executescript("""
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-2048;
        CREATE TABLE titles (id INTEGER PRIMARY KEY, title TEXT NOT NULL);
        CREATE TABLE catalog_chats (id INTEGER PRIMARY KEY, count INTEGER NOT NULL);
        CREATE TABLE catalog_senders (id INTEGER PRIMARY KEY, count INTEGER NOT NULL);
        CREATE TABLE selected_chats (id INTEGER PRIMARY KEY);
        CREATE TABLE selected_senders (id INTEGER PRIMARY KEY);
        CREATE TABLE selected_changed (chat INTEGER, message INTEGER, PRIMARY KEY(chat,message));
        CREATE TABLE bounds (chat INTEGER PRIMARY KEY, low INTEGER NOT NULL, high INTEGER NOT NULL);
        CREATE TABLE known (
            chat INTEGER NOT NULL, message INTEGER NOT NULL, seq INTEGER,
            kind TEXT NOT NULL, observed_at TEXT NOT NULL, sender INTEGER, text TEXT NOT NULL,
            priority INTEGER NOT NULL, PRIMARY KEY (chat, message)
        ) WITHOUT ROWID;
    """)
    connection.execute("BEGIN")


def _catalog(connection, table, *, titles=False):
    # Only fixed internal table names are allowed here, never user input.
    assert table in ("catalog_chats", "catalog_senders")
    total = connection.execute("SELECT count(*) FROM " + table).fetchone()[0]
    if total > MAX_CATALOG_ROWS:
        return [], total, "too_many_groups"
    if titles:
        rows = connection.execute("SELECT c.id, c.count, COALESCE(t.title, '') AS title FROM catalog_chats c "
                                  "LEFT JOIN titles t ON t.id=c.id ORDER BY c.count DESC, c.id")
    else:
        rows = connection.execute("SELECT id, count FROM catalog_senders ORDER BY count DESC, id")
    return [dict(row) for row in rows], total, "available"


def _save_title(connection, identity, title):
    identity = report_analytics._identifier(identity)
    if identity is not None and isinstance(title, str):
        connection.execute("INSERT INTO titles VALUES (?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title",
                           (identity, _text(title, TITLE_CHARS)))


def _titles(connection, event):
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return
    if event.get("kind") in ("target.changed", "source.discovered", "target.removed"):
        _save_title(connection, event.get("chat_id"), payload.get("title"))
    if event.get("kind") == "scope.applied":
        added = payload.get("added")
        for item in added if isinstance(added, list) else ():
            if isinstance(item, dict):
                _save_title(connection, item.get("chat_id"), item.get("title"))


def _known(connection, event, predicate):
    chat = report_analytics._identifier(event.get("chat_id"))
    message = _message_id(event.get("message_id"))
    if chat is None or message is None:
        return
    row = _preview(event)
    kind = row["kind"]
    priority = 0 if kind in ("message.new", "message.snapshot", "message.recovered", "message.edited") else \
        1 if kind in report_analytics.KINDS else 2
    connection.execute("""
        INSERT INTO known VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(chat,message) DO UPDATE SET seq=excluded.seq, kind=excluded.kind,
            observed_at=excluded.observed_at, sender=excluded.sender, text=excluded.text, priority=excluded.priority
        WHERE excluded.priority < known.priority OR
              (excluded.priority = known.priority AND excluded.seq < known.seq)
    """, (chat, message, row["seq"], kind, row["observed_at"], row["sender_id"], row["text"], priority))
    if predicate.chat(event) and predicate.time(event):
        connection.execute("INSERT INTO bounds VALUES (?,?,?) ON CONFLICT(chat) "
                           "DO UPDATE SET low=min(low,excluded.low), high=max(high,excluded.high)", (chat, message, message))


def _neighbor(row, predicate):
    result = {"seq": row["seq"], "chat_id": row["chat"], "message_id": row["message"],
              "kind": row["kind"], "observed_at": row["observed_at"], "sender_id": row["sender"], "text": row["text"]}
    result.update(context_only=True, matches_selection=predicate({**result, "payload": {"sender_id": row["sender"]}}))
    return result


def _gaps(connection, predicate, enabled):
    result = {"enabled": enabled, "status": "available" if enabled else "disabled", "basis": ID_GAP_BASIS,
              "rows": [], "ranges_total": 0, "ids_total": 0, "truncated": False}
    if not enabled:
        return result
    previous = None
    # Every known ID participates, including IDs seen outside selected dates and
    # IDs only referenced by a deletion, recheck or attachment. The date range
    # chooses boundaries; it does not erase known IDs between those boundaries.
    rows = connection.execute("SELECT k.* FROM known k JOIN bounds b ON b.chat=k.chat "
                              "WHERE k.message BETWEEN b.low AND b.high ORDER BY k.chat,k.message")
    for row in rows:
        if previous is not None and row["chat"] == previous["chat"] and row["message"] > previous["message"] + 1:
            count = row["message"] - previous["message"] - 1
            result["ranges_total"] += 1
            result["ids_total"] += count
            if len(result["rows"]) < MAX_GAP_ROWS:
                result["rows"].append({"chat_id": row["chat"], "start": previous["message"]+1,
                    "end": row["message"]-1, "count": count,
                    "before": _neighbor(previous, predicate), "after": _neighbor(row, predicate)})
        previous = row
    result["truncated"] = result["ranges_total"] > len(result["rows"])
    return result


def analyze(snapshot, selection=None, preview_limit=40, *, scratch_root=None):
    """Analyze every record in one stable snapshot with bounded returned previews.

    All counts are exact. Catalog overflow is explicit, not a silently partial
    top list. Selection controls report presentation; it is not a redaction
    policy for the signed original archive. Gap-neighbor context may contain a
    sender or message excluded by the report's filters.
    """
    selection = _selection(selection)
    predicate = compile_selection(selection)
    preview_limit = max(0, min(MAX_PREVIEW_ROWS, preview_limit)) if type(preview_limit) is int else 40
    aggregate = report_analytics.Analytics()
    messages = {"rows": [], "total": 0, "truncated": False}
    records = selected_records = invalid_time_excluded = unknown_catalog_senders = 0
    last_seq, journal_head = None, None
    if scratch_root is not None:
        Path(scratch_root).mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tgwitness-report-selection-", dir=scratch_root) as scratch:
        connection = sqlite3.connect(Path(scratch) / "selection.sqlite3")
        connection.row_factory = sqlite3.Row
        try:
            _prepare(connection)
            for event in snapshot.events():
                records += 1
                seq = report_analytics._sequence(event.get("seq"))
                if seq is not None and (last_seq is None or seq > last_seq):
                    last_seq = seq
                    journal_head = _text(event.get("hash"), 64) or None
                _titles(connection, event)
                if selection.id_gaps:
                    _known(connection, event, predicate)
                kind = event.get("kind")
                message_kind = isinstance(kind, str) and kind in report_analytics.KINDS
                chat = report_analytics._identifier(event.get("chat_id"))
                sender = sender_id(event)
                if message_kind:
                    if chat is not None:
                        connection.execute("INSERT INTO catalog_chats VALUES (?,1) ON CONFLICT(id) DO UPDATE SET count=count+1", (chat,))
                    if predicate.chat(event):
                        if predicate.time(event):
                            if sender is None:
                                unknown_catalog_senders += 1
                            else:
                                connection.execute("INSERT INTO catalog_senders VALUES (?,1) ON CONFLICT(id) DO UPDATE SET count=count+1", (sender,))
                        elif report_analytics._time(event.get("observed_at")) is None:
                            invalid_time_excluded += 1
                if not predicate(event):
                    continue
                selected_records += 1
                aggregate.add(event)
                if kind in ("message.edited", "message.deleted", "message.missing_on_recheck") and chat is not None \
                        and type(event.get("message_id")) is int:
                    connection.execute("INSERT OR IGNORE INTO selected_changed VALUES (?,?)", (chat, event["message_id"]))
                if not message_kind:
                    continue
                messages["total"] += 1
                if len(messages["rows"]) < preview_limit:
                    messages["rows"].append(_preview(event))
                if chat is not None:
                    connection.execute("INSERT OR IGNORE INTO selected_chats VALUES (?)", (chat,))
                if sender is not None:
                    connection.execute("INSERT OR IGNORE INTO selected_senders VALUES (?)", (sender,))
            raw = aggregate.result()
            chats, chats_total, chats_status = _catalog(connection, "catalog_chats", titles=True)
            senders, senders_total, senders_status = _catalog(connection, "catalog_senders")
            counts = {"selected_records": selected_records, "selected_message_records": messages["total"],
                      "message_observations": raw["message_observations"],
                      "participants": connection.execute("SELECT count(*) FROM selected_senders").fetchone()[0],
                      "chats": connection.execute("SELECT count(*) FROM selected_chats").fetchone()[0],
                      "invalid_time_excluded": invalid_time_excluded}
            gaps = _gaps(connection, predicate, selection.id_gaps)
            changed_total = connection.execute("SELECT count(*) FROM selected_changed").fetchone()[0]
            changed_keys = [tuple(row) for row in connection.execute("SELECT chat,message FROM selected_changed ORDER BY chat,message LIMIT 20")]
        finally:
            connection.close()
    head = getattr(snapshot, "head", None)
    if isinstance(head, dict):
        last_seq = report_analytics._sequence(head.get("seq")) or last_seq
        journal_head = _text(head.get("hash"), 64) or journal_head
    messages["truncated"] = messages["total"] > len(messages["rows"])
    return {"format": FORMAT, "selection": selection.model_dump(),
            "source": {"records": records, "last_seq": last_seq, "journal_head": journal_head},
            "counts": counts, "analytics": raw,
            "catalog": {"chats": chats, "chats_total": chats_total, "chats_status": chats_status,
                        "senders": senders, "senders_total": senders_total, "senders_status": senders_status,
                        "unknown_sender_records": unknown_catalog_senders,
                        "sender_basis": "Message records in selected chats and UTC dates, before sender and event-kind filters"},
            "messages": messages, "id_gaps": gaps,
            "changed_keys": changed_keys, "changed_total": changed_total}
