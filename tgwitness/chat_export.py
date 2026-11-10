import base64
import bisect
import csv
import hashlib
import io
import json
import os
import re
import shutil
import unicodedata
import uuid
import zipfile
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import indicators, pdf_report, people, report, verification_kit
from .evidence import producer, report_entry, write_indicators, write_pdf, write_viewer
from .media_jobs import forget_files
from .message_selection import Selection
from .security import private_write
from .store import canonical, utcnow
from .verify import fingerprint, message_id_summary

ID_MEANING = ("Channels and supergroups number their messages 1, 2, 3... per chat, service messages included. A "
              "number absent between the first and the last exported message belongs to a message Telegram did not "
              "return: deleted before the export, or not visible to this account. If only part of the chat was "
              "exported, numbers outside that part are absent too. In private chats and basic groups the numbers "
              "are shared by all of the account's chats, so absent numbers say nothing there.")

EXPORT_LIMITS = [
    "This export is the chat history Telegram returned to this workspace's client at export time, signed with the "
    "collector key in the manifest.",
    "Each message appears in its current version; the evidence journal of the workspace holds earlier versions and "
    "deletion notices observed live.",
    "Message times come from Telegram; the export time uses the collector's system clock.",
    "chat.json gives each sender's name at export and its source: the account's contacts or the Telegram profile. "
    "Where the journal recorded the name at the time of a message, sender-names.json and the readable copies use it; "
    "names and usernames are mutable.",
    "Verify with the collector fingerprint you retained; any change to the export breaks its signature.",
]
JOURNAL_LIMIT = ("This snapshot holds only what Telegram returned at export. The journal of this workspace also "
                 "holds deletions or earlier versions observed in this chat; export the evidence journal to include them.")
NAMES_MEANING = ("Sender names as the journal of this workspace recorded them: delivered with the message when it was "
                 "received live, otherwise the last name recorded before the message was sent. Messages not listed show "
                 "the name at export: from in chat.json, with its source in from_source.")
MAX_BUNDLE_BYTES = 4 * 1024**3
PARTIAL_FORMAT = "tgwitness-chat-partial-v1"
CHECKPOINT_MESSAGES = 5000
HISTORY_FILE = re.compile(r"history-[A-Za-z0-9_-]{1,64}\.jsonl")
FILE_FIELDS = ("file", "file_sha256", "file_size", "file_kind", "file_status", "file_error", "server_hashes",
               "file_hash_sha256", "file_reused")
PARTIAL_MEANING = ("Messages read before this export stopped. They stay in the workspace under a statement signed with "
                   "the collector key; the next export of this chat by the same account checks them and continues.")
SET_ASIDE_MEANING = ("Messages kept from an earlier stopped export could not be continued and were moved aside unchanged; "
                     "this export starts from the newest message.")
PARTIAL_SCOPE = ("Only messages numbered {low}-{high} were read before the export stopped. Numbers outside that range "
                 "were not read, so their absence says nothing about deletion.")
SESSIONS_LIMIT = ("This export continued an earlier stopped export of the same chat by the same account; "
                  "acquisition.sessions lists each session. Messages kept from an earlier session show the version "
                  "Telegram returned during that session.")
PARTIAL_LIMIT = ("This export stopped before it finished and holds only the messages read until then; partial names "
                 "the range read and the reason it stopped.")
REUSED_MEANING = ("file_reused marks an attachment whose bytes were not downloaded again: Telegram serves a file under a "
                  "fixed identifier, and the bytes saved earlier for the same identifier and size, in this export or in "
                  "the workspace journal (media_event), were hashed again before reuse.")


def journal_changes(store, chat_id):
    deleted = store.count_events(chat_id=chat_id, kind="message.deleted,message.missing_on_recheck")
    edited = store.count_events(chat_id=chat_id, kind="message.edited")
    if not deleted and not edited:
        return None
    return {"deleted": deleted, "edited": edited, "meaning": JOURNAL_LIMIT}


def archive_name(store, chat_id, title):
    now = datetime.now(timezone.utc)
    number = store.count_events(chat_id=chat_id, kind="chat_export.completed",
                                since=now.replace(hour=0, minute=0, second=0, microsecond=0)) + 1
    name = "".join("_" if unicodedata.category(c)[0] in "CZ" or c in '<>:"/\\|?*' else c for c in title or "")
    name = re.sub("_+", "_", name).encode()[:100].decode(errors="ignore").strip("._- ")
    return (name or "chat_" + str(chat_id)) + "_" + now.date().isoformat() + "_" + str(number) + ".zip"


def export_limits(meta):
    meta = meta or {}
    limits = [EXPORT_LIMITS[0], JOURNAL_LIMIT, *EXPORT_LIMITS[2:]] if meta.get("journal") else list(EXPORT_LIMITS)
    if len((meta.get("acquisition") or {}).get("sessions") or []) > 1:
        limits.append(SESSIONS_LIMIT)
    if meta.get("partial"):
        limits.append(PARTIAL_LIMIT)
    return limits


def records(scratch_path):
    with Path(scratch_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def journal_names(store, chat_id, scratch_path):
    senders = {r["from_id"] for r in records(scratch_path) if type(r.get("from_id")) is int and r["from_id"] != chat_id}
    with store.snapshot() as snapshot:
        found = people.observed_names(snapshot.connection, chat_id, senders)
    return {uid: {"live": {n["message_id"]: n for n in names if n["live"]},
                  "seen": sorted(((people.stamp(n["observed_at"]), n) for n in names
                                  if people.stamp(n["observed_at"]) is not None), key=lambda item: item[0])}
            for uid, names in found.items()}


def sender_name(record, names, chat_id):
    uid = record.get("from_id")
    if type(uid) is not int or uid == chat_id or record.get("type") == "unparsed":
        return None
    known = names.get(uid) or {}
    found, basis = known.get("live", {}).get(record.get("id")), "received_with_message"
    if found is None:
        sent, seen = people.stamp(record.get("date")), known.get("seen") or []
        index = bisect.bisect_right(seen, sent, key=lambda item: item[0]) if sent is not None else 0
        found, basis = (seen[index - 1][1] if index else None), "recorded_before_message"
    if found is None:
        return {"basis": "export_time"}
    return {"name": found["name"], "username": found["username"], "basis": basis, "source": found["source"],
            "observed_at": found["observed_at"], "record": {"seq": found["seq"], "hash": found["hash"]}}


def named(record, names, chat_id):
    found = sender_name(record, names, chat_id)
    if found is None:
        return record
    if found["basis"] == "export_time":
        return {**record, "from_basis": "export_time"}
    return {**record, "from": found["name"], "from_username": found["username"], "from_basis": found["basis"],
            "from_source": found["source"]}


def sender_names(scratch_path, names, chat_id):
    listed, at_export = [], 0
    for record in records(scratch_path):
        found = sender_name(record, names, chat_id)
        if found and found["basis"] == "export_time":
            at_export += 1
        elif found:
            listed.append({"id": record.get("id"), "from_id": record["from_id"], **found})
    return listed, at_export


def authors(scratch_path):
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
        signed = record.get("author")
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
    ids = sorted({r["id"] for r in records(scratch_path) if type(r.get("id")) is int})
    return {**message_id_summary(chat_id, ids), "meaning": ID_MEANING}


def chat_indicators(scratch_path, meta=None, media_dir=None):
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


def json_chunks(meta, scratch_path):
    header = {k: meta[k] for k in ("format", "chat", "account", "observer", "exported_at", "acquisition",
                                   "message_count", "author_count", "message_ids", "sender_names", "recheck", "admin_log",
                                   "source", "journal", "partial", "limitations") if meta.get(k) is not None}
    prefix = json.dumps(header, ensure_ascii=False, indent=1)[:-2]
    yield (prefix + ',\n "messages": [').encode("utf-8")
    first = True
    for record in records(scratch_path):
        yield (("" if first else ",") + "\n  "
               + json.dumps(record, ensure_ascii=False)).encode("utf-8")
        first = False
    yield b"\n ]\n}\n"


def records_backwards(scratch_path, block=1 << 16):
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
    stats = {"text": 0, "media": 0, "edited": 0, "service": 0, "first_at": None, "last_at": None,
             "first_id": None, "last_id": None, "renames": [], "found_on_recheck": 0, "files_reused": 0}
    for record in records(scratch_path):
        if record.get("action") in RENAMES and isinstance(record.get("action_title"), str) and len(stats["renames"]) < 100:
            stats["renames"].append({"id": record.get("id"), "date": record.get("date"), "title": record["action_title"]})
        stats["found_on_recheck"] += bool(record.get("found_on_recheck"))
        stats["files_reused"] += bool(record.get("file_reused"))
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
    context = context or {}
    stats = context.get("stats") or chat_stats(scratch_path)
    context = {"producer": producer(), "limits": export_limits(meta), "people": authors(scratch_path), "files": {},
               "report_id": "unsealed", "created_at": utcnow(), "fingerprint": "", **context, "stats": stats}
    names, chat_id = context.get("names") or {}, ((meta or {}).get("chat") or {}).get("id")
    source = (lambda: records_backwards(scratch_path)) if stats["newest_first"] else (lambda: records(scratch_path))
    return report.chat_chunks(meta, lambda: (named(r, names, chat_id) for r in source()), context)


def attachment_files(media_dir):
    if media_dir is None or not Path(media_dir).is_dir():
        return []
    return sorted(p for p in Path(media_dir).iterdir() if p.is_file() and len(p.name) == 64
                  and all(c in "0123456789abcdef" for c in p.name))


def build_bundle(scratch_path, meta, vault, out_path, max_bytes=MAX_BUNDLE_BYTES, options=None, media_dir=None,
                 names=None):
    options, names = options or report.resolved(), names or {}
    meta = {"format": "tgwitness-chat-export-v1", "exported_at": utcnow(),
            "public_key": vault.public_key, "fingerprint": fingerprint(vault.public_key),
            "source": "Telegram history read by the account; a current snapshot, "
                      "not reconstruction of deleted or past-edited messages.",
            "producer": producer(), "limitations": export_limits(meta), "case": report.case_of(options), **meta}
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
            collection = meta.get("collection") or {}
            if collection.get("mode") == "distributed_selection" and Selection.model_validate(
                    collection.get("selection") or {}).excludes_messages():
                ids["selection_applied"] = True
                ids["meaning"] = ("Numbers absent from this selected export may have been excluded by filters; deletions are recorded as separate notices.")
            if meta.get("recheck"):
                ids["recheck"] = meta["recheck"]
            log = meta.get("admin_log")
            if isinstance(log, dict) and log.get("events") is not None:
                write_member("admin-log.json", [json.dumps(log, ensure_ascii=False, indent=1).encode("utf-8")])
                meta["admin_log"] = {"file": "admin-log.json", "read_at": log.get("read_at"),
                                     "events": len(log["events"]), "complete": log.get("complete"),
                                     "error_type": log.get("error_type"), "meaning": log.get("meaning")}
                admin_events = log["events"]
            else:
                admin_events = None
            meta["message_ids"] = {**{k: ids[k] for k in ("numbered_per_chat", "first_id", "last_id", "present", "missing")},
                                   "missing_runs": len(ids["missing_ranges"]), "file": "message-ids.json"}
            if ids.get("selection_applied"):
                meta["message_ids"].update(selection_applied=True, meaning=ids["meaning"])
            attachments = attachment_files(media_dir)
            if attachments:
                meta["attachments"] = len(attachments)
            chat_id = (meta.get("chat") or {}).get("id")
            attributed, at_export = sender_names(scratch_path, names, chat_id)
            meta["sender_names"] = {"file": "sender-names.json", "from_journal": len(attributed), "at_export": at_export,
                                    "meaning": NAMES_MEANING}
            write_member("chat.json", json_chunks(meta, scratch_path))
            write_member("message-ids.json", [json.dumps(ids, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("sender-names.json", [json.dumps({"meaning": NAMES_MEANING, "messages": attributed},
                                                          ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.json", [json.dumps(people, ensure_ascii=False, indent=1).encode("utf-8")])
            write_member("authors.csv", [authors_csv(people)])
            found = chat_indicators(scratch_path, meta, media_dir)
            write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
            verification_kit.write(write_member, options.get("language", "en"))
            for record in records(scratch_path):
                if record.get("server_hashes") is not None:
                    data = canonical(record["server_hashes"])
                    digest = hashlib.sha256(data).hexdigest()
                    if record.get("file_hash_sha256") != digest:
                        raise ValueError("File-hash record differs from its manifest")
                    name = "hashes/" + digest + ".json"
                    if name not in hashes:
                        write_member(name, [data])
            for source in attachments:
                with source.open("rb") as incoming:
                    write_member("media/" + source.name, iter(lambda: incoming.read(1024 * 1024), b""))
                if hashes["media/" + source.name] != source.name:
                    raise ValueError("Attachment changed while the export was written: " + source.name)
            stats = chat_stats(scratch_path)
            if stats["files_reused"]:
                meta["attachments_reused"] = {"messages": stats["files_reused"], "meaning": REUSED_MEANING}
            analytics = report.snapshot_analytics.collect(records(scratch_path), "snapshot", meta.get("chat"))
            analytics = report.snapshot_analytics.project(analytics, options)
            write_member("analytics.json", [canonical(analytics)])
            context = {"kind": "chat", "options": options, "report_id": str(uuid.uuid4()), "created_at": meta["exported_at"],
                       "producer": meta["producer"], "limits": meta["limitations"], "public_key": vault.public_key,
                       "fingerprint": meta["fingerprint"], "meta": meta, "people": people,
                       "stats": stats, "analytics": analytics, "chat_json_sha256": hashes["chat.json"], "message_ids": ids,
                       "account": meta.get("account"), "sign": vault.sign, "indicators": found,
                       "admin_events": admin_events}
            write_indicators(write_member, found, context)
            write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                     indent=1).encode("utf-8")])
            source = (lambda: records_backwards(scratch_path)) if stats["newest_first"] else (lambda: records(scratch_path))

            def ordered():
                return (named(r, names, chat_id) for r in source())
            context["viewer"] = write_viewer(write_member, "chat", ordered(), people, found, options)
            context["files"] = dict(hashes)
            write_pdf(write_member, "chat.pdf", lambda: pdf_report.chat_report_pdf(meta, context, vault, ordered()))
            context["files"] = dict(hashes)
            write_member("chat.html", html_chunks(meta, scratch_path, {**context, "names": names}))
            listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
            write_member("README.txt", [verification_kit.quickstart(options.get("language", "en")), b"\n",
                report.readme(context, listed, "\n".join(meta["limitations"])
                + "\n\nchat.json is authoritative; chat.html is a readable derivative sealed with the same key.\n"
                "authors.csv / authors.json list everyone who posted in the exported history,\n"
                "with message counts and first/last message; names are the profile at export time.\n"
                "sender-names.json gives the sender name the journal recorded at the time of each listed message.\n"
                "custody.json records how the history was acquired and exported.\n"
                "media/ holds the attachments saved with the export, each named by its SHA-256; a message\n"
                "without a file names the reason in file_status.\n"
                "Exports above 4 GiB uncompressed also need --max-gib with their size in GiB.\n"
                "Requires Python 3.11+ and cryptography. chat.json is authoritative.\n")])
            write_member("SHA256SUMS", [report.sha256sums(hashes)])
            manifest = {**meta, "report": report_entry(context, options, "chat.html"), "files": hashes,
                        "case_assessment": report.case_assessment.snapshot(context, "chat", meta)}
            manifest_bytes = canonical(manifest)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def linked(path):
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def awaits_file(entry):
    return bool(entry.get("media_type")) and entry.get("type") != "unparsed" and not any(k in entry for k in FILE_FIELDS)


def scan_history(path):
    digest, size, count, high, low = hashlib.sha256(), 0, 0, None, None
    with Path(path).open("rb") as stream:
        for line in stream:
            digest.update(line)
            size += len(line)
            if line.strip():
                count += 1
                number = json.loads(line).get("id")
                if type(number) is int:
                    high = number if high is None else max(high, number)
                    low = number if low is None else min(low, number)
    return size, digest.hexdigest(), count, high, low


class HistoryWriter:
    def __init__(self, partial):
        self.partial = partial
        self.stream = partial.file.open("w", encoding="utf-8", newline="\n")
        self.digest, self.size, self.count, self.checked = hashlib.sha256(), 0, 0, 0
        self.first = self.last = None

    def __enter__(self):
        return self

    def __exit__(self, *failure):
        self.stream.close()

    def write(self, text):
        data = text.encode("utf-8")
        self.stream.write(text)
        self.digest.update(data)
        self.size, self.count, self.last = self.size + len(data), self.count + 1, text
        self.first = self.first or text

    def flush(self):
        self.stream.flush()
        if self.partial.carried and self.count - self.checked >= CHECKPOINT_MESSAGES:
            os.fsync(self.stream.fileno())
            self.partial.save(self.partial.file, self.size, self.digest.hexdigest(), self.count,
                              json.loads(self.first)["id"], json.loads(self.last)["id"])
            self.checked = self.count

    def carry(self):
        yield from self.partial.retained()
        self.partial.carried = True


class PartialExport:
    def __init__(self, store, vault, chat_id, account_id):
        self.store, self.vault, self.chat_id, self.account_id = store, vault, chat_id, account_id
        self.root = store.root / "partial-exports"
        self.directory = self.root / str(chat_id)
        self.media = self.directory / "media"
        if linked(self.root) or linked(self.directory) or linked(self.media):
            raise ValueError("Partial-export storage must not be a link.")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.file = self.session = self.previous = self.statement = self.set_aside = None
        if self.directory.is_dir():
            try:
                self.previous = self.load()
            except (ValueError, OSError, KeyError, TypeError) as exc:
                self.set_aside = str(exc) if type(exc) is ValueError else type(exc).__name__
                forget_files(self.media)
                self.directory.replace(self.root / (str(chat_id) + ".set-aside-"
                                                    + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")))
        self.statement, self.carried = self.previous, self.previous is None
        self.earlier = list((self.previous or {}).get("sessions") or [])
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.media.mkdir(mode=0o700, exist_ok=True)
        if self.previous is None:
            forget_files(self.media)

    def load(self):
        path = self.directory / "partial.json"
        if not path.exists():
            if any(self.directory.glob("history-*.jsonl")):
                raise ValueError("Saved messages have no signed statement.")
            return None
        if linked(path) or path.stat().st_size > 16 * 1024**2:
            raise ValueError("Invalid partial-export statement.")
        envelope = json.loads(path.read_bytes())
        if envelope["public_key"] != self.vault.public_key:
            raise ValueError("Saved messages were signed with a different collector key.")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(envelope["public_key"], validate=True)).verify(
                base64.b64decode(envelope["signature"], validate=True), canonical(envelope["statement"]))
        except Exception:
            raise ValueError("The partial-export statement signature is invalid.") from None
        statement = envelope["statement"]
        if statement["format"] != PARTIAL_FORMAT or statement["chat_id"] != self.chat_id:
            raise ValueError("Saved messages belong to another chat or format.")
        if statement["account_id"] != self.account_id:
            raise ValueError("Saved messages were read by another account.")
        if not isinstance(statement["file"], str) or not HISTORY_FILE.fullmatch(statement["file"]) \
                or any(type(statement[k]) is not int for k in ("bytes", "messages", "low", "high")) \
                or not isinstance(statement["sessions"], list) or not isinstance(statement["sha256"], str):
            raise ValueError("Invalid partial-export statement.")
        data = self.directory / statement["file"]
        if linked(data) or data.stat().st_size < statement["bytes"]:
            raise ValueError("Saved messages are shorter than their signed statement.")
        digest, left = hashlib.sha256(), statement["bytes"]
        with data.open("rb") as stream:
            while left:
                chunk = stream.read(min(left, 1024 * 1024))
                if not chunk:
                    raise ValueError("Saved messages are shorter than their signed statement.")
                digest.update(chunk)
                left -= len(chunk)
        if digest.hexdigest() != statement["sha256"]:
            raise ValueError("Saved messages differ from their signed statement.")
        if data.stat().st_size > statement["bytes"]:
            with data.open("r+b") as stream:
                stream.truncate(statement["bytes"])
        for stale in self.directory.glob("history-*.jsonl"):
            if stale.name != statement["file"]:
                with suppress(OSError):
                    stale.unlink()
        return statement

    def start(self, export_id, started_at, files=None):
        self.session = {"export_id": export_id, "started_at": started_at, "files": files or "workspace_settings"}
        self.file = self.directory / ("history-" + export_id + ".jsonl")
        if not HISTORY_FILE.fullmatch(self.file.name) or linked(self.file):
            raise ValueError("Invalid export identifier.")
        return self.file

    def public(self):
        found = {}
        if self.previous:
            found["resumed"] = self.summary(self.previous)
        if self.set_aside:
            found["set_aside"] = {"reason": self.set_aside, "meaning": SET_ASIDE_MEANING}
        return found

    @staticmethod
    def summary(statement):
        return {"retained": True, "messages": statement["messages"], "low": statement["low"], "high": statement["high"],
                "sha256": statement["sha256"], "sessions": len(statement["sessions"]), "meaning": PARTIAL_MEANING,
                **({"account_loss": statement["account_loss"]} if statement.get("account_loss") else {})}

    def writer(self):
        return HistoryWriter(self)

    def retained(self):
        with (self.directory / self.previous["file"]).open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    entry = json.loads(line)
                    if entry.get("file") is not None and not self.has_file(entry):
                        entry = {k: v for k, v in entry.items() if k not in FILE_FIELDS}
                    yield entry

    def has_file(self, entry):
        digest = entry.get("file_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or entry["file"] != "media/" + digest:
            return False
        path = self.media / digest
        return not linked(path) and path.is_file() and path.stat().st_size == entry.get("file_size")

    def save(self, file, size, digest, count, high, low, stop=None, loss=None):
        session = {**(self.session or {}), **({"stopped_at": utcnow(), "stop": stop} if stop else {})}
        statement = {"format": PARTIAL_FORMAT, "chat_id": self.chat_id, "account_id": self.account_id,
                     "file": file.name, "bytes": size, "sha256": digest, "messages": count, "high": high, "low": low,
                     "saved_at": utcnow(), "sessions": [*self.earlier, session]}
        if loss:
            statement["account_loss"] = loss
        private_write(self.directory / "partial.json", canonical({"statement": statement, "public_key": self.vault.public_key,
                                                                  "signature": self.vault.sign(canonical(statement))}))
        if self.previous and self.previous["file"] != file.name:
            (self.directory / self.previous["file"]).unlink(missing_ok=True)
        self.statement = statement
        return statement

    def retain(self, stop, loss=None):
        try:
            if not self.carried and self.file is not None:
                self.file.unlink(missing_ok=True)
            source = self.file if self.carried else self.directory / self.previous["file"]
            found = scan_history(source) if source is not None and source.is_file() else (0, None, 0, None, None)
            if not found[2] or found[3] is None:
                if self.previous is None:
                    self.discard()
                    return None
                raise ValueError("Saved messages could not be read back.")
            return self.summary(self.save(source, *found, stop=stop, loss=loss))
        except Exception as exc:
            return {"retained": False, "error_type": type(exc).__name__}

    def sessions(self, finished_at):
        return [*self.earlier, {**self.session, "finished_at": finished_at}]

    def discard(self):
        forget_files(self.media)
        shutil.rmtree(self.directory, ignore_errors=True)

    def bundle(self, out_path, meta, max_bytes=MAX_BUNDLE_BYTES, options=None):
        statement = self.statement
        path = self.directory / statement["file"]
        meta = {**meta, "message_count": statement["messages"],
                "partial": {**self.summary(statement), "complete": False,
                            "stop": statement["sessions"][-1].get("stop"),
                            "scope": PARTIAL_SCOPE.format(low=statement["low"], high=statement["high"])},
                "acquisition": {**(meta.get("acquisition") or {}), "sessions": statement["sessions"]}}
        return build_bundle(path, meta, self.vault, out_path, max_bytes, options, self.media,
                            journal_names(self.store, self.chat_id, path))
