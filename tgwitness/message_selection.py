"""Reproducible selection over a disk-backed acquisition, before media retrieval."""
import json
import re
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache
from importlib.metadata import version
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .store import canonical


def utc(value):
    if not value:
        return None
    stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Export dates must include a time zone.")
    return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_utc: str | None = None
    to_utc: str | None = None
    languages: list[str] = Field(default_factory=list, max_length=75)
    uncertain_language: Literal["exclude", "include"] = "exclude"
    reply_mode: Literal["all", "replies", "answered"] = "all"
    reply_scope: Literal["period", "through_start"] = "period"
    context_depth: int = Field(default=0, ge=0, le=10)
    max_context_messages: int = Field(default=1000, ge=0, le=100000)
    sender_ids: list[int] = Field(default_factory=list, max_length=10000)
    text_contains: list[str] = Field(default_factory=list, max_length=100)
    download_media: bool = False
    recheck_all: bool = False

    @field_validator("from_utc", "to_utc", mode="before")
    @classmethod
    def dates(cls, value):
        return utc(value)

    @field_validator("languages")
    @classmethod
    def codes(cls, values):
        values = sorted(set(v.lower().strip() for v in values))
        if any(not re.fullmatch("[a-z]{2}", v) for v in values):
            raise ValueError("Use two-letter message language codes.")
        if values:
            from lingua import Language
            supported = {lang.iso_code_639_1.name.lower() for lang in Language.all()}
            if not set(values) <= supported:
                raise ValueError("Unsupported message language.")
        return values

    @field_validator("sender_ids")
    @classmethod
    def senders(cls, values):
        if any(not value or not -(2**63) < value < 2**63 for value in values):
            raise ValueError("Invalid sender ID.")
        return sorted(set(values))

    @field_validator("text_contains")
    @classmethod
    def terms(cls, values):
        if any(not value.strip() or len(value) > 200 for value in values):
            raise ValueError("Text filters must contain 1 to 200 characters.")
        return list(dict.fromkeys(value.casefold() for value in values))

    @model_validator(mode="after")
    def bounds(self):
        if self.from_utc and self.to_utc and self.from_utc >= self.to_utc:
            raise ValueError("The period must end after it starts.")
        return self

    def in_period(self, row):
        date = utc(row.get("date"))
        return not ((self.from_utc and (not date or date < self.from_utc))
                    or (self.to_utc and (not date or date >= self.to_utc)))

    def excludes_messages(self):
        return bool(self.from_utc or self.to_utc or self.languages or self.reply_mode != "all"
                    or self.sender_ids or self.text_contains)


@lru_cache(maxsize=1)
def detector():
    from lingua import LanguageDetectorBuilder
    return LanguageDetectorBuilder.from_all_spoken_languages().build()


def detect_language(text):
    sample = re.sub(r"```[\s\S]*?```|`[^`]*`|https?://\S+|www\.\S+", " ", text or "")[:20000]
    result = {"detector": "lingua", "version": version("lingua-language-detector"),
              "policy": "letters>=12; score>=0.70; margin>=0.10; mixed spans>=2 words", "language": None,
              "status": "unknown"}
    if sum(c.isalpha() for c in sample) < 12:
        return result
    engine = detector()
    scores = engine.compute_language_confidence_values(sample)
    if not scores:
        return result
    top = scores[0]
    result["score"] = round(top.value, 6)
    result["candidate"] = top.language.iso_code_639_1.name.lower()
    if len(sample.split()) >= 6:
        spans = engine.detect_multiple_languages_of(sample)
        langs = sorted({s.language.iso_code_639_1.name.lower() for s in spans if s.word_count >= 2})
        if len(langs) > 1:
            return {**result, "status": "mixed", "languages": langs}
    margin = top.value - (scores[1].value if len(scores) > 1 else 0)
    if top.value >= .70 and margin >= .10:
        result.update(status="detected", language=result["candidate"])
    return result


def reply_link(row, chat_id):
    header = row.get("reply_to") or {}
    parent = header.get("reply_to_msg_id") or row.get("reply_to_message_id")
    peer = header.get("reply_to_peer_id") or {}
    peer_id = (-1000000000000 - peer["channel_id"] if "channel_id" in peer else
               -peer["chat_id"] if "chat_id" in peer else peer.get("user_id", chat_id))
    topic = header.get("reply_to_top_id")
    direct = type(parent) is int and parent > 0
    if header.get("forum_topic") and (not topic or parent == topic):
        direct = False
    return parent, peer_id, topic, direct


class SelectionIndex:
    def __init__(self, path, chat_id):
        self.chat_id = chat_id
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY, profile TEXT NOT NULL, record TEXT NOT NULL,
                parent INTEGER, parent_chat INTEGER, topic INTEGER, direct INTEGER NOT NULL,
                in_period INTEGER NOT NULL DEFAULT 0, matched INTEGER NOT NULL DEFAULT 0,
                selected INTEGER NOT NULL DEFAULT 0, depth INTEGER, language TEXT,
                missing_parent TEXT
            );
            CREATE INDEX IF NOT EXISTS replies ON messages(parent_chat,parent,direct);
            CREATE INDEX IF NOT EXISTS context_layer ON messages(selected,depth);
        """)

    def close(self):
        self.db.close()

    def add(self, row, profile):
        parent, peer, topic, direct = reply_link(row, self.chat_id)
        self.db.execute("INSERT OR IGNORE INTO messages(id,profile,record,parent,parent_chat,topic,direct) "
                        "VALUES(?,?,?,?,?,?,?)", (row["id"], profile, canonical(row).decode(), parent, peer, topic, direct))

    def classify(self, options, language_detector=detect_language):
        return list(self.classify_batches(options, language_detector))[-1]

    def classify_batches(self, options, language_detector=detect_language):
        uncertain = 0
        self.db.execute("UPDATE messages SET matched=0,selected=0,depth=NULL,in_period=0,language=NULL")
        for number, row in enumerate(self.db.execute("SELECT id,record FROM messages")):
            if number and number % 200 == 0:
                yield uncertain
            item = json.loads(row["record"])
            self.db.execute("UPDATE messages SET in_period=? WHERE id=?", (options.in_period(item), row["id"]))
        self.db.commit()
        for number, row in enumerate(self.db.execute("SELECT * FROM messages WHERE in_period=1 ORDER BY id")):
            if number and number % 50 == 0:
                yield uncertain
            item = json.loads(row["record"])
            if options.sender_ids and item.get("from_id") not in options.sender_ids:
                continue
            if options.text_contains and not any(t in (item.get("text") or "").casefold() for t in options.text_contains):
                continue
            if options.reply_mode == "replies" and not row["direct"]:
                continue
            if options.reply_mode == "answered":
                period = " AND in_period=1" if options.reply_scope == "period" else ""
                if not self.db.execute("SELECT 1 FROM messages WHERE direct=1 AND parent_chat=? AND parent=?" +
                                       period + " LIMIT 1", (self.chat_id, row["id"])).fetchone():
                    continue
            language = language_detector(item.get("text", "")) if options.languages else None
            if language:
                self.db.execute("UPDATE messages SET language=? WHERE id=?", (json.dumps(language), row["id"]))
                if language["status"] != "detected":
                    uncertain += 1
                    if options.uncertain_language == "exclude":
                        continue
                elif language["language"] not in options.languages:
                    continue
            self.db.execute("UPDATE messages SET matched=1,selected=1,depth=0 WHERE id=?", (row["id"],))
        self.db.commit()
        yield uncertain

    def expand(self, options, depth):
        remaining = options.max_context_messages - self.db.execute(
            "SELECT count(*) FROM messages WHERE selected=1 AND matched=0").fetchone()[0]
        if remaining <= 0:
            return []
        rows = self.db.execute("SELECT p.id FROM messages s JOIN messages p ON p.id=s.parent "
            "WHERE s.selected=1 AND s.depth=? AND s.direct=1 AND s.parent_chat=? AND p.selected=0 "
            "UNION SELECT c.id FROM messages s JOIN messages c ON c.parent=s.id AND c.parent_chat=? AND c.direct=1 "
            "WHERE s.selected=1 AND s.depth=? AND c.selected=0 ORDER BY 1 LIMIT ?",
            (depth - 1, self.chat_id, self.chat_id, depth - 1, remaining)).fetchall()
        self.db.executemany("UPDATE messages SET selected=1,depth=? WHERE id=?", [(depth, r["id"]) for r in rows])
        self.db.commit()
        remaining -= len(rows)
        return self.db.execute("SELECT min(s.id) AS id,s.profile,s.parent,s.parent_chat FROM messages s "
            "WHERE s.selected=1 AND s.depth=? AND s.direct=1 AND s.parent IS NOT NULL "
            "AND s.missing_parent IS NULL AND NOT EXISTS(SELECT 1 FROM messages p WHERE p.id=s.parent "
            "AND s.parent_chat=?) GROUP BY s.parent_chat,s.parent ORDER BY min(s.id) LIMIT ?",
            (depth - 1, self.chat_id, remaining)).fetchall()

    def output(self):
        for row in self.db.execute("SELECT * FROM messages WHERE selected=1 ORDER BY id DESC"):
            item = json.loads(row["record"])
            replies = [r[0] for r in self.db.execute("SELECT id FROM messages WHERE direct=1 AND parent_chat=? "
                       "AND parent=? ORDER BY id LIMIT 100", (self.chat_id, row["id"]))]
            item["selection"] = {"role": "match" if row["matched"] else "context", "depth": row["depth"],
                                 "language": json.loads(row["language"]) if row["language"] else None,
                                 "observed_reply_ids_sample": replies, "missing_parent": row["missing_parent"]}
            yield item, row["profile"]

    def counts(self):
        row = self.db.execute("SELECT count(*),coalesce(sum(matched),0),coalesce(sum(selected),0),"
                              "count(missing_parent) FROM messages").fetchone()
        return {"examined": row[0], "matched": row[1], "context": row[2] - row[1],
                "selected": row[2], "missing_context": row[3]}
