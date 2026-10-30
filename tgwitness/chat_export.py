"""Full chat history export in a Telegram-style, signed bundle.

The collector streams one JSON record per message into a scratch JSONL file
(memory-safe for very large chats). This module turns that scratch file into a
downloadable ZIP that contains:

  chat.json      Telegram-export-style array of messages.
  chat.html      Readable rendering of the same messages.
  authors.csv    Everyone who posted: ID, name, username, message count, first/last.
  authors.json   The same list as JSON.
  manifest.json  Metadata plus a SHA-256 for every file in the bundle.
  manifest.sig   Ed25519 signature over manifest.json by the profile key.
  verify.py      A copy of the journal verifier (shares the signature scheme).
  README.txt     Scope and the verification command.

The signature proves the bundle was not changed after export relative to a
trusted key fingerprint. It does not prove Telegram origin, and the export is a
current snapshot: messages deleted before export or past edits are not
reconstructed.
"""
import csv
import hashlib
import html
import io
import json
import zipfile
from pathlib import Path

from .evidence import producer
from .store import canonical, utcnow
from .verify import fingerprint

EXPORT_LIMITS = [
    "This export is a current history snapshot taken by a Telegram client, not Telegram-signed evidence.",
    "Messages deleted before export, and past edits, cannot be recovered and are not present.",
    "Message times come from Telegram; the export time uses the collector's system clock.",
    "Sender names are the cached Telegram profile at export; names and usernames are mutable.",
    "The signature detects changes relative to a trusted key. Retain the fingerprint elsewhere.",
]
MAX_BUNDLE_BYTES = 4 * 1024**3


def records(scratch_path):
    """Yield message records previously written one-per-line as canonical JSON."""
    with Path(scratch_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def authors(scratch_path):
    """Everyone who posted in the exported history, most active first."""
    people = {}
    for record in records(scratch_path):
        if record.get("type") == "service":
            continue
        key = record.get("from_id")
        person = people.setdefault(key, {"user_id": key, "name": None, "username": None, "messages": 0,
                                         "first_message_at": None, "last_message_at": None,
                                         "first_message_id": None, "last_message_id": None})
        person["name"] = person["name"] or record.get("from")
        person["username"] = person["username"] or record.get("from_username")
        person["messages"] += 1
        date, message_id = record.get("date"), record.get("id")
        if date and (person["first_message_at"] is None or date < person["first_message_at"]):
            person["first_message_at"], person["first_message_id"] = date, message_id
        if date and (person["last_message_at"] is None or date > person["last_message_at"]):
            person["last_message_at"], person["last_message_id"] = date, message_id
    return sorted(people.values(), key=lambda p: (-p["messages"], str(p["user_id"])))


def authors_csv(people):
    from .evidence import safe_cell
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    columns = ("user_id", "name", "username", "messages", "first_message_at", "last_message_at",
               "first_message_id", "last_message_id")
    writer.writerow(columns)
    for person in people:
        writer.writerow([safe_cell(person[c]) for c in columns])
    return b"\xef\xbb\xbf" + out.getvalue().encode("utf-8")


def json_chunks(meta, scratch_path):
    header = {k: meta[k] for k in ("format", "chat", "account", "exported_at", "message_count",
                                   "author_count", "source", "limitations") if k in meta}
    prefix = json.dumps(header, ensure_ascii=False, indent=1)[:-2]  # drop closing "\n}"
    yield (prefix + ',\n "messages": [').encode("utf-8")
    first = True
    for record in records(scratch_path):
        yield (("" if first else ",") + "\n  "
               + json.dumps(record, ensure_ascii=False)).encode("utf-8")
        first = False
    yield b"\n ]\n}\n"


def _bubble(record):
    escape = lambda v: html.escape("" if v is None else str(v))
    who = escape(record.get("from") or ("Service" if record.get("type") == "service" else "Unknown"))
    when = escape(record.get("date") or "")
    body = []
    if record.get("reply_to_message_id"):
        body.append('<div class="reply">In reply to #' + escape(record["reply_to_message_id"]) + "</div>")
    if record.get("type") == "service":
        body.append('<div class="service">' + escape(record.get("action") or "Service event") + "</div>")
    text = record.get("text") or ""
    if text:
        body.append('<div class="text">' + escape(text).replace("\n", "<br>") + "</div>")
    if record.get("media_type"):
        body.append('<div class="media">[' + escape(record["media_type"])
                    + (" · not included in this export]" if not record.get("file") else "]") + "</div>")
    edited = (' · edited ' + escape(record["edited"])) if record.get("edited") else ""
    return ('<article id="m' + escape(record.get("id")) + '" class="'
            + ("service-row" if record.get("type") == "service" else "msg") + '">'
            + '<header><span class="from">' + who + '</span>'
            + '<span class="meta">#' + escape(record.get("id")) + ' · ' + when + edited + '</span></header>'
            + "".join(body) + "</article>")


def html_chunks(meta, scratch_path):
    escape = lambda v: html.escape("" if v is None else str(v))
    chat = meta.get("chat", {})
    yield ('<!doctype html><html lang="en"><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           '<title>TgWitness chat export · ' + escape(chat.get("title")) + '</title>'
           '<style>body{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;max-width:820px;'
           'margin:0 auto;padding:24px 16px 80px;background:#e7ebf0;color:#17212b}'
           'h1{font-size:20px;margin:0 0 4px}.sub{color:#5b6b7b;margin:0 0 8px}'
           '.limits{background:#fff;border:1px solid #d7dee6;border-radius:12px;padding:12px 18px;'
           'margin:12px 0 20px;font-size:13px;color:#5b6b7b}'
           'article.msg{background:#fff;border-radius:12px;padding:8px 14px;margin:8px 0;'
           'box-shadow:0 1px 2px rgba(0,0,0,.06)}'
           'article.service-row{text-align:center;margin:14px 0;color:#5b6b7b;font-size:13px}'
           'header{display:flex;justify-content:space-between;gap:12px;align-items:baseline}'
           '.from{font-weight:600;color:#3a73b8}.meta{color:#8a99a8;font-size:12px;font-family:monospace}'
           '.text{margin-top:4px;white-space:normal;overflow-wrap:anywhere}'
           '.reply{border-left:3px solid #3a73b8;padding-left:8px;color:#5b6b7b;font-size:13px;margin-top:4px}'
           '.media{margin-top:4px;color:#5b6b7b;font-size:13px}.service{font-style:italic}</style>'
           '<h1>' + escape(chat.get("title")) + '</h1>'
           '<p class="sub">Chat ' + escape(chat.get("id")) + ' · ' + escape(chat.get("kind"))
           + ' · ' + escape(chat.get("visibility")) + ' · ' + escape(meta.get("message_count"))
           + ' messages · exported ' + escape(meta.get("exported_at")) + '</p>'
           '<div class="limits"><ul><li>'
           + "</li><li>".join(escape(x) for x in meta.get("limitations", []))
           + "</li></ul></div>").encode("utf-8")
    for record in records(scratch_path):
        yield _bubble(record).encode("utf-8")
    yield b"</html>"


def build_bundle(scratch_path, meta, vault, out_path, max_bytes=MAX_BUNDLE_BYTES):
    meta = {"format": "tgwitness-chat-export-v1", "exported_at": utcnow(),
            "public_key": vault.public_key, "fingerprint": fingerprint(vault.public_key),
            "source": "Telegram history read by the account; a current snapshot, "
                      "not reconstruction of deleted or past-edited messages.",
            "producer": producer(), "limitations": EXPORT_LIMITS, **meta}
    path = Path(out_path)
    hashes, total = {}, 0
    try:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            def write_member(name, values):
                nonlocal total
                digest = hashlib.sha256()
                with archive.open(name, "w", force_zip64=True) as outgoing:
                    for chunk in values:
                        total += len(chunk)
                        if total > max_bytes - 4 * 1024**2:
                            raise ValueError("Export exceeds the uncompressed size limit set in Parameters")
                        outgoing.write(chunk)
                        digest.update(chunk)
                hashes[name] = digest.hexdigest()

            people = authors(scratch_path)
            meta["author_count"] = len(people)
            write_member("chat.json", json_chunks(meta, scratch_path))
            write_member("chat.html", html_chunks(meta, scratch_path))
            write_member("authors.json", [json.dumps(people, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.csv", [authors_csv(people)])
            write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
            write_member("README.txt", [("\n".join(EXPORT_LIMITS)
                + "\n\nchat.json is authoritative; chat.html is a readable derivative.\n"
                "authors.csv / authors.json list everyone who posted in the exported history,\n"
                "with message counts and first/last message; names are the profile at export time.\n"
                "manifest.json lists a SHA-256 for every file; manifest.sig is the Ed25519 signature.\n"
                "Verify authenticity with a trusted key fingerprint, using a verifier from a trusted checkout:\n"
                "  python verify.py chat-export.zip --fingerprint TRUSTED_SHA256\n"
                "Exports above 4 GiB uncompressed also need --max-gib with their size in GiB.\n"
                "Requires Python 3.11+ and cryptography. chat.json is authoritative.\n").encode()])
            manifest = {**meta, "files": hashes}
            manifest_bytes = canonical(manifest)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise
