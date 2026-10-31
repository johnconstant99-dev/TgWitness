"""Full chat history export in a Telegram-style, signed bundle.

The collector streams one JSON record per message into a scratch JSONL file
(memory-safe for very large chats). This module turns that scratch file into a
downloadable ZIP that contains:

  chat.json      Telegram-export-style array of messages.
  chat.html      Readable rendering of the same messages, oldest first, sealed (report.py).
  authors.csv    Everyone who posted: ID, name, username, message count, first/last.
  authors.json   The same list as JSON.
  custody.json   How the history was acquired and exported, with the standards followed.
  SHA256SUMS     Every file's SHA-256 for sha256sum -c.
  manifest.json  Metadata plus a SHA-256 for every file in the bundle.
  manifest.sig   Ed25519 signature over manifest.json by the profile key.
  verify.py      A copy of the journal verifier (shares the signature scheme).
  README.txt     Scope and verification, in the report language and in English.

The signature proves the bundle was not changed after export relative to a
trusted key fingerprint. It does not prove Telegram origin, and the export is a
current snapshot: messages deleted before export or past edits are not
reconstructed.
"""
import csv
import hashlib
import io
import json
import uuid
import zipfile
from pathlib import Path

from . import report
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
    prefix = json.dumps(header, ensure_ascii=False, indent=1)[:-2]
    yield (prefix + ',\n "messages": [').encode("utf-8")
    first = True
    for record in records(scratch_path):
        yield (("" if first else ",") + "\n  "
               + json.dumps(record, ensure_ascii=False)).encode("utf-8")
        first = False
    yield b"\n ]\n}\n"


def records_backwards(scratch_path, block=1 << 16):
    """Records from the last line to the first, reading the file from its end in blocks."""
    with Path(scratch_path).open("rb") as handle:
        handle.seek(0, 2)
        position, rest = handle.tell(), b""
        while position > 0:
            step = min(block, position)
            position -= step
            handle.seek(position)
            lines = (handle.read(step) + rest).split(b"\n")
            rest = lines.pop(0)
            for line in reversed(lines):
                if line.strip():
                    yield json.loads(line)
        if rest.strip():
            yield json.loads(rest)


def chat_stats(scratch_path):
    """Counts, first and last dates, and whether Telegram returned the history newest first."""
    stats = {"text": 0, "media": 0, "edited": 0, "service": 0, "first_at": None, "last_at": None,
             "first_id": None, "last_id": None}
    for record in records(scratch_path):
        if record.get("type") == "service":
            stats["service"] += 1
        elif record.get("media_type"):
            stats["media"] += 1
        else:
            stats["text"] += 1
        stats["edited"] += bool(record.get("edited"))
        date = record.get("date")
        if date and (stats["first_at"] is None or date < stats["first_at"]):
            stats["first_at"] = date
        if date and (stats["last_at"] is None or date > stats["last_at"]):
            stats["last_at"] = date
        stats["first_id"] = record.get("id") if stats["first_id"] is None else stats["first_id"]
        stats["last_id"] = record.get("id")
    stats["newest_first"] = isinstance(stats["first_id"], int) and isinstance(stats["last_id"], int) \
        and stats["first_id"] > stats["last_id"]
    return stats


def html_chunks(meta, scratch_path, context=None):
    """The readable chat, oldest message first (see report.py); sealed when the context can sign."""
    context = context or {}
    stats = context.get("stats") or chat_stats(scratch_path)
    context = {"producer": producer(), "limits": EXPORT_LIMITS, "people": authors(scratch_path), "files": {},
               "report_id": "unsealed", "created_at": utcnow(), "fingerprint": "", **context, "stats": stats}
    ordered = (lambda: records_backwards(scratch_path)) if stats["newest_first"] else (lambda: records(scratch_path))
    return report.chat_chunks(meta, ordered, context)


def build_bundle(scratch_path, meta, vault, out_path, max_bytes=MAX_BUNDLE_BYTES, options=None):
    options = options or report.resolved()
    meta = {"format": "tgwitness-chat-export-v1", "exported_at": utcnow(),
            "public_key": vault.public_key, "fingerprint": fingerprint(vault.public_key),
            "source": "Telegram history read by the account; a current snapshot, "
                      "not reconstruction of deleted or past-edited messages.",
            "producer": producer(), "limitations": EXPORT_LIMITS, "case": report.case_of(options), **meta}
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
            write_member("authors.json", [json.dumps(people, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.csv", [authors_csv(people)])
            write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
            context = {"kind": "chat", "options": options, "report_id": str(uuid.uuid4()), "created_at": meta["exported_at"],
                       "producer": meta["producer"], "limits": EXPORT_LIMITS, "public_key": vault.public_key,
                       "fingerprint": meta["fingerprint"], "meta": meta, "people": people,
                       "stats": chat_stats(scratch_path), "chat_json_sha256": hashes["chat.json"],
                       "account": meta.get("account"), "sign": vault.sign}
            write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                     indent=1).encode("utf-8")])
            context["files"] = dict(hashes)
            write_member("chat.html", html_chunks(meta, scratch_path, context))
            listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
            write_member("README.txt", [report.readme(context, listed, "\n".join(EXPORT_LIMITS)
                + "\n\nchat.json is authoritative; chat.html is a readable derivative sealed with the same key.\n"
                "authors.csv / authors.json list everyone who posted in the exported history,\n"
                "with message counts and first/last message; names are the profile at export time.\n"
                "custody.json records how the history was acquired and exported.\n"
                "manifest.json lists a SHA-256 for every file; manifest.sig is the Ed25519 signature.\n"
                "SHA256SUMS repeats those hashes for sha256sum -c.\n"
                "Verify authenticity with a trusted key fingerprint, using a verifier from a trusted checkout:\n"
                "  python verify.py chat-export.zip --fingerprint TRUSTED_SHA256\n"
                "Exports above 4 GiB uncompressed also need --max-gib with their size in GiB.\n"
                "Requires Python 3.11+ and cryptography. chat.json is authoritative.\n")])
            write_member("SHA256SUMS", [report.sha256sums(hashes)])
            manifest = {**meta, "report": {"id": context["report_id"], "file": "chat.html",
                                           "language": options["language"], "sealed": True, "custody": "custody.json"},
                        "files": hashes}
            manifest_bytes = canonical(manifest)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise
