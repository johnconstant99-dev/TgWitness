"""The data behind the report's viewer: the records or messages of an export, beside report.html.

report.html is the viewer: search, filters, people, indicators, selection and a check of the whole
archive, all in the browser with nothing sent anywhere. It reads viewer/*.html documents in sandboxed
frames without same-origin privileges. Each frame passes one JSON text via postMessage; the signed
seal lists the SHA-256 of that text, and the viewer checks it before display. Unverified frame code
cannot access the report DOM. A report saved on its own carries the
same JSON texts inside the page.

Journal records are shown by the fields a reader needs (text, sender, details, files, hashes); the
journal files in the archive stay authoritative. Chat messages are the records of chat.json as they
are, so a selection of them can be compared with chat.json by verify.py.
"""
import base64
import hashlib
import json
import re

from . import report

FORMAT = "tgwitness-viewer-v1"
CHUNK = 2000            # items per data file
CHUNK_BYTES = 16 * 1024 * 1024  # split large raw records before a browser needs excessive memory
INLINE_LIMIT = 20000    # items a report saved on its own carries inside the page
INLINE_BYTES = 32 * 1024 * 1024
LONE = re.compile("[\ud800-\udfff]")
DETAIL_KEYS = ("text_entities", "reply_to_message_id", "forwarded_from", "via_bot_id", "author", "views", "forwards", "replies", "reactions",
               "buttons", "auto_delete_seconds", "protected", "media_info", "album_id")


def json_text(value):
    """JSON as the viewer reads it: compact, UTF-8, with lone surrogates written as escapes."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return LONE.sub(lambda m: "\\u%04x" % ord(m.group()), text)


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def document(name, text):
    """A data document for an opaque-origin sandbox; no unverified code runs in the report."""
    loader = 'parent.postMessage(JSON.parse(document.getElementById("data").textContent),"*");'
    digest = base64.b64encode(hashlib.sha256(loader.encode()).digest()).decode()
    payload = json.dumps({"file": name, "text": text}, ensure_ascii=True).replace("<", "\\u003c")
    return ('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; script-src \'sha256-' + digest + '\'; base-uri \'none\'">'
            '<title>TgWitness viewer data</title><script type="application/json" id="data">' + payload
            + '</script><script>' + loader + '</script>').encode("utf-8")


def journal_item(event, raw_records=False):
    """One journal record as the viewer shows it."""
    payload, kind = event["payload"] if isinstance(event["payload"], dict) else {}, event["kind"]
    item = {"s": event["seq"], "k": kind, "c": report.category(kind), "t": event["observed_at"], "h": event["hash"]}
    if event["chat_id"] is not None:
        item["ch"] = event["chat_id"]
    if event["message_id"] is not None:
        item["m"] = event["message_id"]
    sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
    sender_id = payload.get("sender_id", sender.get("id"))
    for key, value in (("a", sender.get("display_name")), ("u", sender.get("username")), ("id", sender_id),
                       ("tt", payload.get("date") if isinstance(payload.get("date"), str) else None)):
        if value not in (None, ""):
            item[key] = value
    if isinstance(payload.get("text"), str) and payload["text"]:
        item["x"] = payload["text"]
    if payload.get("text_withheld"):
        item["xw"] = True
    if event.get("minimised"):
        item["w"] = event["minimised"]
    if item["c"] in ("message", "edited"):
        details = {k: v for k, v in report.shown_details(payload).items() if k in DETAIL_KEYS}
        if isinstance(payload.get("reply_to_message_id"), int):
            details["reply_to_message_id"] = payload["reply_to_message_id"]
        if details:
            item["d"] = details
    if kind == "media.saved" and isinstance(payload.get("media_sha256"), str):
        item["f"] = {k: v for k, v in (("sha", payload["media_sha256"]), ("mime", payload.get("mime_type")),
                                       ("size", payload.get("size")), ("name", payload.get("original_name")))
                     if v not in (None, "")}
    if item["c"] not in ("message", "edited", "media"):
        # Operational records: their facts without the saved Telegram object.
        facts = {k: v for k, v in payload.items() if k != "raw"}
        text = json.dumps(facts, ensure_ascii=False, separators=(",", ":"))
        item["p"] = text if len(text) <= 4000 else text[:4000] + "…"
    if raw_records:
        item["r"] = event
    return item


class Writer:
    """Collects items into data files, bounded by the configured count and byte budget."""

    def __init__(self, write_member, kind, role="items", prefix=None, chunk_size=CHUNK):
        self.write_member, self.kind, self.files, self.batch, self.role = write_member, kind, [], [], role
        self.prefix = prefix or ("messages" if kind == "chat" else "records")
        self.count = 0
        self.chunk_size, self.batch_bytes = max(1, int(chunk_size)), 0

    def add(self, item):
        size = len(json_text(item).encode("utf-8"))
        if self.batch and self.batch_bytes + size > CHUNK_BYTES:
            self.flush()
        self.batch.append(item)
        self.batch_bytes += size
        self.count += 1
        if len(self.batch) >= self.chunk_size:
            self.flush()

    def flush(self):
        if self.batch:
            self.file(self.prefix + "-" + str(len([f for f in self.files if f["role"] == self.role]) + 1).zfill(4),
                      self.batch, self.role)
            self.batch = []
            self.batch_bytes = 0

    def file(self, stem, value, role):
        name = "viewer/" + stem + ".html"
        text = json_text(value)
        self.write_member(name, [document(name, text)])
        self.files.append({"file": name, "role": role, "count": len(value), "sha256": sha256(text)})

    def descriptor(self, people=None, indicators=None):
        self.flush()
        if people:
            self.file("people", people, "people")
        if indicators and indicators.get("items"):
            self.file("indicators", indicators["items"], "indicators")
        return {"format": FORMAT, "kind": self.kind, "items": self.count, "files": self.files}


class Inline:
    """The same data inside a report saved on its own: JSON texts in the page, listed in its seal."""

    def __init__(self, kind, chunk_size=CHUNK):
        self.kind, self.items, self.files, self.blocks = kind, [], [], []
        self.chunk_size = max(1, int(chunk_size))
        self.total_bytes = 0

    def add(self, item):
        if self.items is None:
            return
        self.total_bytes += len(json_text(item).encode("utf-8"))
        if len(self.items) >= INLINE_LIMIT or self.total_bytes > INLINE_BYTES:
            self.items = None
            return
        self.items.append(item)

    def block(self, name, value, role):
        text = json_text(value).replace("<", "\\u003c")
        self.files.append({"file": name, "role": role, "count": len(value), "sha256": sha256(text)})
        self.blocks.append('<script type="application/json" class="tgw-file" data-file="' + name + '">' + text
                           + "</script>")

    def html(self, people=None, indicators=None):
        """The data blocks for the end of the page; the descriptor is then complete."""
        if self.items is None:
            return ""
        prefix = "messages" if self.kind == "chat" else "records"
        for index in range(0, len(self.items), self.chunk_size):
            self.block("viewer/" + prefix + "-" + str(index // self.chunk_size + 1).zfill(4) + ".html",
                       self.items[index:index + self.chunk_size], "items")
        if people:
            self.block("viewer/people.html", people, "people")
        if indicators and indicators.get("items"):
            self.block("viewer/indicators.html", indicators["items"], "indicators")
        return "".join(self.blocks)

    def descriptor(self):
        if self.items is None:
            return {"format": FORMAT, "kind": self.kind, "items": 0, "files": [], "omitted": True}
        return {"format": FORMAT, "kind": self.kind, "items": len(self.items), "files": self.files}
