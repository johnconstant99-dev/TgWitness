"""Full chat history export in a Telegram-style, signed bundle.

The collector streams one JSON record per message into a scratch JSONL file
(memory-safe for very large chats). This module turns that scratch file into a
downloadable ZIP that contains:

  chat.json      Telegram-export-style array of messages.
  chat.html      The sealed report and its viewer (report.py): search, filters, people, indicators,
                 selection; the messages are viewer/*.js beside it, listed by SHA-256 in its seal.
  message-ids.json  How the message numbers run: present, absent and every absent run.
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

from . import indicators, pdf_report, report
from .evidence import producer, report_entry, write_indicators, write_pdf, write_viewer
from .store import canonical, utcnow
from .verify import fingerprint, message_id_summary

ID_MEANING = ("Channels and supergroups number their messages 1, 2, 3... per chat, service messages included. A "
              "number absent between the first and the last exported message belongs to a message Telegram did not "
              "return: deleted before the export, or not visible to this account. If only part of the chat was "
              "exported, numbers outside that part are absent too. In private chats and basic groups the numbers "
              "are shared by all of the account's chats, so absent numbers say nothing there.")

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
        signed = record.get("author")  # an admin's signature under a channel post
        if isinstance(signed, str) and signed and signed not in person.setdefault("signatures", []) \
                and len(person["signatures"]) < 50:
            person["signatures"].append(signed)
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


def message_ids(scratch_path, chat_id):
    """How the exported messages' numbers run; verify.py recounts this from chat.json."""
    ids = sorted({r["id"] for r in records(scratch_path) if type(r.get("id")) is int})
    return {**message_id_summary(chat_id, ids), "meaning": ID_MEANING}


def chat_indicators(scratch_path, meta=None, media_dir=None):
    """Links, domains, wallets, accounts, phone numbers and e-mail addresses in the exported messages and in
    the chat's description."""
    found = indicators.Indicators()
    profile = ((meta or {}).get("chat") or {}).get("profile") or {}
    found.text(profile.get("about"), "chat description", None, (meta or {}).get("exported_at"))
    for record in records(scratch_path):
        if record.get("type") != "service":
            found.message(record.get("text"), record, {"message": record.get("id")}, record.get("date"))
            saved = record.get("file_sha256")
            if media_dir is not None and isinstance(saved, str) and record.get("file_kind") in ("photo", "sticker", "document") \
                    and (Path(media_dir) / saved).is_file():
                found.image(saved, Path(media_dir) / saved, {"message": record.get("id")}, record.get("date"))
    return found.result()


def chat_category(record):
    """The filter a message falls under in chat.html (as report.chat_rows marks it)."""
    return "service" if record.get("type") == "service" else "media" if record.get("media_type") \
        else "edited" if record.get("edited") else "text"


def json_chunks(meta, scratch_path):
    header = {k: meta[k] for k in ("format", "chat", "account", "observer", "exported_at", "acquisition",
                                   "message_count", "author_count", "message_ids", "recheck", "admin_log", "source",
                                   "limitations") if meta.get(k) is not None}
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


RENAMES = ("MessageActionChannelCreate", "MessageActionChatCreate", "MessageActionChatEditTitle")


def chat_stats(scratch_path):
    """Counts, first and last dates, and whether Telegram returned the history newest first."""
    stats = {"text": 0, "media": 0, "edited": 0, "service": 0, "first_at": None, "last_at": None,
             "first_id": None, "last_id": None, "renames": [], "found_on_recheck": 0}
    for record in records(scratch_path):
        if record.get("action") in RENAMES and isinstance(record.get("action_title"), str) and len(stats["renames"]) < 100:
            stats["renames"].append({"id": record.get("id"), "date": record.get("date"), "title": record["action_title"]})
        stats["found_on_recheck"] += bool(record.get("found_on_recheck"))
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


def attachment_files(media_dir):
    """Attachments saved by the export, each named by its SHA-256."""
    if media_dir is None or not Path(media_dir).is_dir():
        return []
    return sorted(p for p in Path(media_dir).iterdir() if p.is_file() and len(p.name) == 64
                  and all(c in "0123456789abcdef" for c in p.name))


def build_bundle(scratch_path, meta, vault, out_path, max_bytes=MAX_BUNDLE_BYTES, options=None, media_dir=None):
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
            ids = message_ids(scratch_path, (meta.get("chat") or {}).get("id"))
            if meta.get("recheck"):
                ids["recheck"] = meta["recheck"]
            log = meta.get("admin_log")
            if isinstance(log, dict) and log.get("events") is not None:
                # The events go into a file of their own; chat.json and the report name what it holds.
                write_member("admin-log.json", [json.dumps(log, ensure_ascii=False, indent=1).encode("utf-8")])
                meta["admin_log"] = {"file": "admin-log.json", "read_at": log.get("read_at"),
                                     "events": len(log["events"]), "complete": log.get("complete"),
                                     "error_type": log.get("error_type"), "meaning": log.get("meaning")}
                admin_events = log["events"]
            else:
                admin_events = None
            meta["message_ids"] = {**{k: ids[k] for k in ("numbered_per_chat", "first_id", "last_id", "present", "missing")},
                                   "missing_runs": len(ids["missing_ranges"]), "file": "message-ids.json"}
            attachments = attachment_files(media_dir)
            if attachments:
                meta["attachments"] = len(attachments)
            write_member("chat.json", json_chunks(meta, scratch_path))
            write_member("message-ids.json", [json.dumps(ids, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.json", [json.dumps(people, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.csv", [authors_csv(people)])
            found = chat_indicators(scratch_path, meta, media_dir)
            write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
            for source in attachments:
                with source.open("rb") as incoming:
                    write_member("media/" + source.name, iter(lambda: incoming.read(1024 * 1024), b""))
                if hashes["media/" + source.name] != source.name:
                    raise ValueError("Attachment changed while the export was written: " + source.name)
            stats = chat_stats(scratch_path)
            context = {"kind": "chat", "options": options, "report_id": str(uuid.uuid4()), "created_at": meta["exported_at"],
                       "producer": meta["producer"], "limits": EXPORT_LIMITS, "public_key": vault.public_key,
                       "fingerprint": meta["fingerprint"], "meta": meta, "people": people,
                       "stats": stats, "chat_json_sha256": hashes["chat.json"], "message_ids": ids,
                       "account": meta.get("account"), "sign": vault.sign, "indicators": found,
                       "admin_events": admin_events}
            write_indicators(write_member, found, context)
            write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                     indent=1).encode("utf-8")])
            # The viewer's data, oldest message first.
            ordered = (lambda: records_backwards(scratch_path)) if stats["newest_first"] else (lambda: records(scratch_path))
            context["viewer"] = write_viewer(write_member, "chat", ordered(), people, found, options)
            context["files"] = dict(hashes)
            write_pdf(write_member, "chat.pdf", lambda: pdf_report.chat_report_pdf(meta, context, vault, ordered()))
            context["files"] = dict(hashes)
            write_member("chat.html", html_chunks(meta, scratch_path, context))
            listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
            write_member("README.txt", [report.readme(context, listed, "\n".join(EXPORT_LIMITS)
                + "\n\nchat.json is authoritative; chat.html is a readable derivative sealed with the same key.\n"
                "authors.csv / authors.json list everyone who posted in the exported history,\n"
                "with message counts and first/last message; names are the profile at export time.\n"
                "custody.json records how the history was acquired and exported.\n"
                "media/ holds the attachments saved with the export, each named by its SHA-256; a message\n"
                "without a file names the reason in file_status.\n"
                "Exports above 4 GiB uncompressed also need --max-gib with their size in GiB.\n"
                "Requires Python 3.11+ and cryptography. chat.json is authoritative.\n")])
            write_member("SHA256SUMS", [report.sha256sums(hashes)])
            manifest = {**meta, "report": report_entry(context, options, "chat.html"), "files": hashes}
            manifest_bytes = canonical(manifest)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise
