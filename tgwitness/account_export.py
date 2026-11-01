"""Durable, resumable account acquisition with signed pages and a portable ZIP64 bundle.

Only sealed pages advance a cursor. Cached progress is rebuilt from their signatures
and bytes before resuming or packaging. Message/metadata JSONL is authoritative;
HTML is an escaped readable derivative. No new Telegram authorization is created.
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from telethon import errors
from telethon.tl import types

from . import account_export_transport as transport, account_report
from .evidence import producer
from .security import private_write
from .store import ZERO, canonical, utcnow
from .verify import fingerprint
from .workers import complete_in_thread

KINDS = ("private", "bot", "group", "supergroup", "channel")
MEDIA = ("photo", "video", "video_message", "voice", "audio", "document", "sticker", "animation")
JOB_ID = re.compile(r"[a-f0-9]{32}")
LIMITATIONS = [
    "A snapshot of data visible to this account during the recorded acquisition intervals; not Telegram-signed evidence.",
    "Deleted data, inaccessible history, previous edits and secret chats may be unavailable.",
    "Capture times are the collector's clock, not an independent timestamp. Pin the signing fingerprint independently.",
    "Options and inventory are frozen. Resume retains earlier observations; it does not make an atomic account snapshot.",
    "Media exclusions and acquisition failures are recorded. A valid signature does not establish completeness.",
]


class AccountExportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: Literal["takeout", "regular"] = "takeout"
    chat_kinds: list[Literal[KINDS]] = Field(default_factory=lambda: list(KINDS), max_length=len(KINDS))
    chat_ids: list[int] = Field(default_factory=list, max_length=10000)
    sender_ids: list[int] = Field(default_factory=list, max_length=10000)
    text_contains: list[str] = Field(default_factory=list, max_length=100)
    purpose: str = Field(default="", max_length=1000)
    report_language: str = "en"
    from_utc: str | None = None
    to_utc: str | None = None
    own_messages_only: bool = False
    include_archived: bool = True
    media_types: list[Literal[MEDIA]] = Field(default_factory=lambda: list(MEDIA), max_length=len(MEDIA))
    max_media_file_mib: int = Field(default=512, ge=1, le=4096)
    max_total_gib: int = Field(default=16, ge=1, le=1024)
    include_profile: bool = True
    include_contacts: bool = True
    include_profile_photos: bool = False
    include_stories: bool = False
    include_session_metadata: bool = False
    include_other_data: bool = False

    @field_validator("report_language")
    @classmethod
    def report_language_supported(cls, value):
        return account_report.validate_language(value)

    @field_validator("chat_ids", "sender_ids", mode="before")
    @classmethod
    def ids(cls, values):
        if not isinstance(values, list) or any(type(v) is not int or not -(2**63) < v < 2**63 or v == 0 for v in values):
            raise ValueError("IDs must be nonzero 64-bit integers.")
        return values

    @field_validator("text_contains")
    @classmethod
    def terms(cls, values):
        if any(not v.strip() or len(v) > 200 for v in values):
            raise ValueError("Use nonempty literal text filters of at most 200 characters.")
        return list(dict.fromkeys(v.casefold() for v in values))

    @field_validator("from_utc", "to_utc")
    @classmethod
    def date_bound(cls, value):
        if value is None or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
        except ValueError:
            raise ValueError("Use an ISO date or timestamp for the export period.") from None

    @model_validator(mode="after")
    def options(self):
        if self.from_utc and self.to_utc and self.from_utc >= self.to_utc:
            raise ValueError("The export period must end after it starts.")
        self.chat_ids = sorted(set(self.chat_ids))
        self.sender_ids = sorted(set(self.sender_ids))
        self.chat_kinds = [k for k in KINDS if k in self.chat_kinds]
        self.media_types = [k for k in MEDIA if k in self.media_types]
        return self


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for piece in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(piece)
    return digest.hexdigest()


def sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def durable_write(path, data):
    if linked(path) or linked(path.with_suffix(path.suffix + ".tmp")):
        raise ValueError("Refusing to overwrite a linked account-export file.")
    private_write(path, data)
    sync_directory(path.parent)


def linked(path):
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def read_json(path, limit=64 * 1024**2):
    if linked(path) or path.stat().st_size > limit:
        raise ValueError("Invalid or oversized account-export state file.")
    return json.loads(path.read_bytes())


class BoundedWriter:
    def __init__(self, stream, limit):
        self.stream, self.limit, self.total, self.digest = stream, limit, 0, hashlib.sha256()

    def write(self, data):
        if self.total + len(data) > self.limit:
            raise ValueError("attachment_size_limit")
        self.total += len(data)
        self.digest.update(data)
        return self.stream.write(data)

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def reset(self):
        self.stream.seek(0)
        self.stream.truncate()
        self.total, self.digest = 0, hashlib.sha256()


def media_info(media):
    item = getattr(media, "document", None) or getattr(media, "photo", None) or media
    kind, size = "document", getattr(item, "size", None)
    if isinstance(item, types.Photo):
        kind = "photo"
        sizes = [getattr(p, "size", None) or max(getattr(p, "sizes", None) or [0]) for p in item.sizes]
        size = max(sizes or [0]) or None
    for attribute in getattr(item, "attributes", []):
        if isinstance(attribute, types.DocumentAttributeVideo):
            kind = "video_message" if attribute.round_message else "video"
        elif isinstance(attribute, types.DocumentAttributeAudio):
            kind = "voice" if attribute.voice else "audio"
        elif isinstance(attribute, types.DocumentAttributeAnimated):
            kind = "animation"
        elif isinstance(attribute, (types.DocumentAttributeSticker, types.DocumentAttributeCustomEmoji)):
            kind = "sticker"
    return {"kind": kind, "media_id": getattr(item, "id", None), "expected_bytes": size}


class AccountExport:
    def __init__(self, collector, store, vault):
        self.collector, self.store, self.vault = collector, store, vault
        self.root = store.root / "account-exports"
        if linked(self.root):
            raise ValueError("Account-export storage must not be a filesystem link.")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.task, self.current, self.index = None, None, None
        self.transport_factory = transport.Transport  # replaced by deterministic fake transports in tests

    def directory(self, job_id):
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ValueError("Unknown account export.")
        path = self.root / job_id
        if linked(self.root) or linked(path) or path.resolve().parent != self.root.resolve():
            raise ValueError("Account-export path is outside its storage directory.")
        for name in ("data", "receipts", "media"):
            child = path / name
            if linked(child) or child.resolve().parent != path.resolve():
                raise ValueError("Account-export working directories must not be filesystem links.")
        return path

    def busy(self):
        return bool(self.task and not self.task.done())

    def signed(self, statement):
        return {"statement": statement, "signature": self.vault.sign(canonical(statement))}

    def verify_signed(self, envelope):
        statement = envelope["statement"]
        if statement["public_key"] != self.vault.public_key:
            raise ValueError("Account export belongs to a different signing identity.")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.vault.public_key)).verify(
                base64.b64decode(envelope["signature"], validate=True), canonical(statement))
        except (InvalidSignature, ValueError):
            raise ValueError("Account-export signature verification failed.") from None
        return statement

    def public(self, job_id=None):
        job_id = job_id or (self.current or {}).get("id")
        if not job_id:
            return {"phase": "none", "active": False}
        claimed = getattr(self.collector, "export_claim", None) == job_id
        if self.current and self.current["id"] == job_id:
            return {**json.loads(json.dumps(self.current)), "active": self.busy() or claimed}
        directory = self.directory(job_id)
        if not directory.is_dir():
            return {"id": job_id, "phase": "unknown"}
        state = read_json(directory / "status.json")
        if not claimed and state["phase"] in ("preparing", "running", "packaging"):
            state.update(phase="paused", error="The process stopped. Resume verifies the saved pages first.")
        state["ready"] = state.get("ready", False) and (directory / "export.zip").is_file()
        state["active"] = claimed
        return state

    def list_jobs(self):
        jobs = []
        for path in self.root.iterdir():
            if JOB_ID.fullmatch(path.name) and path.is_dir() and not path.is_symlink():
                try:
                    jobs.append(self.public(path.name))
                except (ValueError, OSError, KeyError):
                    jobs.append({"id": path.name, "phase": "failed", "ready": False,
                                 "error": "Saved export state is unavailable; preserve it for inspection."})
        return sorted(jobs, key=lambda s: s.get("created_at", ""), reverse=True)

    def persist(self):
        self.current["updated_at"] = utcnow()
        durable_write(self.directory(self.current["id"]) / "status.json", canonical(self.current))

    async def start(self, options):
        options = AccountExportOptions.model_validate(options).model_dump()
        if self.busy():
            raise ValueError("An account export is already running. Pause it first.")
        if options["transport"] == "takeout":
            for job in self.list_jobs():
                if not self.vault.read("account-export-" + job["id"]).get("takeout_id"):
                    continue
                if job.get("ready"):
                    await self.resume(job["id"])  # Retry finalization while preserving the published archive.
                else:
                    raise ValueError("Resume or remove the unfinished Takeout export before starting another Takeout session.")
        account = (self.store.get_setting("account", {}) or {}).get("id")
        if not account:
            raise ValueError("Connect a Telegram account before exporting it.")
        job_id = secrets.token_hex(16)
        if not self.collector.reserve_export(job_id):
            raise ValueError("Another export is already using this account.")
        try:
            directory = self.directory(job_id)
            directory.mkdir(mode=0o700)
            for name in ("data", "receipts", "media"):
                (directory / name).mkdir(mode=0o700)
            job = {"format": "tgwitness-account-export-job-v1", "job_id": job_id, "account_id": account,
                   "public_key": self.vault.public_key, "created_at": utcnow(), "options": options,
                   "options_sha256": sha(canonical(options))}
            durable_write(directory / "job.json", canonical(self.signed(job)))
            self.current = {"id": job_id, "account_id": account, "phase": "preparing", "options": options,
                "created_at": job["created_at"], "ready": False, "current_chat": None, "wait_until": None,
                "error": None, "omissions": [], "counts": {}, "coverage": {}}
            self.persist()
            self.store.append("account_export.started", {"job_id": job_id, "options_sha256": job["options_sha256"],
                "account_id": account, "meaning": "selected visible account data; resumable acquisition"})
            self.task = asyncio.create_task(self.run(job))
            self.task.add_done_callback(lambda _: self.collector.release_export(job_id))
        except BaseException:
            self.collector.release_export(job_id)
            raise
        return self.public()

    async def pause(self, job_id):
        self.directory(job_id)
        if self.busy() and self.current["id"] == job_id:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        return self.public(job_id)

    async def resume(self, job_id):
        if self.busy():
            raise ValueError("An account export is already running. Pause it first.")
        directory = self.directory(job_id)
        if not (directory / "job.json").is_file():
            raise ValueError("The saved account export is unavailable.")
        job = self.verify_signed(read_json(directory / "job.json"))
        if job["account_id"] != (self.store.get_setting("account", {}) or {}).get("id"):
            raise ValueError("This export belongs to a different Telegram account.")
        if sha(canonical(job["options"])) != job["options_sha256"]:
            raise ValueError("The saved export options have changed.")
        if not self.collector.reserve_export(job_id):
            raise ValueError("Another export is already using this account.")
        recovering = False
        try:
            self.current = self.public(job_id)
            if self.current.get("ready"):
                if self.vault.read("account-export-" + job_id).get("takeout_id"):
                    network = self.transport_factory(self.collector, self.vault, job_id, job["options"])
                    try:
                        await network.open()
                        if network.account_id != job["account_id"]:
                            raise ValueError("The connected account differs from this export's signed account.")
                        await network.finish(True)
                    except (errors.RPCError, OSError, ConnectionError, TimeoutError):
                        raise ValueError("The saved archive is retained, but Telegram Takeout finalization failed. Reconnect and retry.") from None
                    self.current["error"] = None
                self.current.update(phase="partial" if self.current.get("coverage", {}).get("failures") else "done",
                                    wait_until=None, delay_seconds=None)
                self.persist()
                self.collector.release_export(job_id)
                return self.public()  # published archives stay byte-for-byte stable for range downloads
            recovering = True
            self.current.update(phase="preparing", ready=False, error=None, wait_until=None, options=job["options"])
            # Validate before returning success to the resume request, not only in its background task.
            await complete_in_thread(self.recover, job)
            self.persist()
            self.task = asyncio.create_task(self.run(job))
            self.task.add_done_callback(lambda _: self.collector.release_export(job_id))
        except BaseException as exc:
            try:
                if recovering:
                    interrupted = isinstance(exc, (asyncio.CancelledError, OSError, TimeoutError))
                    self.current.update(phase="paused" if interrupted else "failed", current_chat=None,
                        error="Verification interrupted. Resume verifies the saved pages again." if interrupted else
                              str(exc) if isinstance(exc, ValueError) else "Verification failed: " + type(exc).__name__)
                    try:
                        self.persist()
                    except (OSError, ValueError):
                        pass  # Keep retryable in-memory state and preserve the original verification error.
            finally:
                try:
                    if self.index:
                        self.index.close()
                finally:
                    self.index = None
                    self.collector.release_export(job_id)
            raise
        return self.public()

    def recover(self, job):
        directory = self.directory(job["job_id"])
        if self.index:
            self.index.close()
        index_path = directory / "index.sqlite3"
        if index_path.is_symlink():
            raise ValueError("Invalid account-export index path.")
        self.index = sqlite3.connect(index_path, check_same_thread=False)
        self.index.execute("DROP TABLE IF EXISTS seen")
        self.index.execute("CREATE TABLE seen (chat INTEGER, message INTEGER, PRIMARY KEY(chat,message))")
        self.progress, self.receipts, self.head = {}, [], ZERO
        self.counts = dict(records=0, messages=0, messages_exported=0, messages_seen=0,
                           media_saved=0, media_skipped=0, bytes_saved=0)
        self.failures = 0
        inventory_path = directory / "inventory.json"
        if not inventory_path.exists():
            if any((directory / "receipts").iterdir()):
                raise ValueError("Captured pages have no signed inventory.")
            self.inventory, self.inventory_hash = None, None
            return
        envelope = read_json(inventory_path)
        inventory = self.verify_signed(envelope)
        for key in ("job_id", "account_id", "options_sha256"):
            if inventory[key] != job[key]:
                raise ValueError("The inventory belongs to a different export.")
        self.inventory, self.inventory_hash = inventory, sha(canonical(envelope))
        tasks = {task["id"]: task for task in inventory["tasks"]}
        for number, path in enumerate(sorted((directory / "receipts").glob("*.json")), 1):
            envelope = read_json(path)
            receipt = self.verify_signed(envelope)
            if (path.name != f"{number:08d}.json" or receipt["seq"] != number
                    or receipt["previous_receipt_sha256"] != self.head
                    or receipt["inventory_sha256"] != self.inventory_hash):
                raise ValueError("The saved receipt chain is incomplete or changed.")
            for key in ("job_id", "account_id", "options_sha256"):
                if receipt[key] != job[key]:
                    raise ValueError("A page belongs to a different export.")
            task = tasks.get(receipt["task_id"])
            previous = self.progress.get(receipt["task_id"])
            if (task is None or previous and previous["terminal"] or receipt["category"] != task["category"]
                    or receipt["chat_id"] != task["chat_id"]
                    or receipt["cursor_before"] != (previous["cursor_after"] if previous else task["cursor_start"])):
                raise ValueError("Saved page cursor or task changed.")
            if receipt["data_file"] != f"data/{number:08d}.jsonl":
                raise ValueError("Invalid captured page path.")
            data_path = directory / receipt["data_file"]
            if data_path.is_symlink() or file_sha(data_path) != receipt["data_sha256"]:
                raise ValueError("A captured page changed after it was signed.")
            count = 0
            with data_path.open("rb") as stream:
                for raw in stream:
                    row = json.loads(raw)
                    if raw != canonical(row) + b"\n":
                        raise ValueError("A captured page is not canonical JSONL.")
                    self.count_row(row, directory, verify=True)
                    count += 1
            if count != receipt["count"]:
                raise ValueError("Captured page count differs from its receipt.")
            self.accept(envelope)
        self.index.commit()
        with self.store.lock:
            committed = self.store.db.execute("SELECT payload FROM events WHERE kind='account_export.page' "
                "AND json_extract(payload,'$.job_id')=? ORDER BY seq DESC LIMIT 1", (job["job_id"],)).fetchone()
        if committed:
            boundary = json.loads(committed[0])
            if (boundary["seq"] > len(self.receipts)
                    or sha(canonical(self.receipts[boundary["seq"] - 1])) != boundary["receipt_sha256"]):
                raise ValueError("Saved pages were rolled back before their journal commitment.")
        self.update_counts()

    def count_row(self, row, directory, verify=False):
        self.counts["records"] += 1
        if row["category"] == "messages":
            try:
                self.index.execute("INSERT INTO seen VALUES (?,?)", (row["chat_id"], row["id"]))
            except sqlite3.IntegrityError:
                raise ValueError("Duplicate message in sealed account-export pages.") from None
            self.counts["messages"] += 1
            self.counts["messages_exported"] += 1
        for attachment in row.get("attachments", []):
            if attachment["outcome"] == "saved":
                digest = attachment["sha256"]
                if not re.fullmatch(r"[a-f0-9]{64}", digest) or attachment["file"] != "media/" + digest:
                    raise ValueError("Invalid attachment content path.")
                path = directory / attachment["file"]
                if verify and (path.is_symlink() or path.stat().st_size != attachment["bytes"] or file_sha(path) != digest):
                    raise ValueError("A captured attachment changed after it was signed.")
                self.counts["media_saved"] += 1
                self.counts["bytes_saved"] += attachment["bytes"]
            else:
                self.counts["media_skipped"] += 1
                self.failures += attachment["outcome"] == "failed"

    def accept(self, envelope):
        receipt = envelope["statement"]
        self.receipts.append(envelope)
        self.progress[receipt["task_id"]] = receipt
        self.head = sha(canonical(envelope))
        self.counts["messages_seen"] += receipt.get("seen_count", 0) if receipt["category"] == "messages" else 0
        self.failures += receipt["outcome"] == "failed"

    def update_counts(self):
        if not self.inventory:
            return
        tasks = self.inventory["tasks"]
        chats = self.inventory["chats"]
        selected = [c for c in chats if c["selected"]]
        discovered = self.inventory.get("discovery_counts", {}).get("chats_discovered", len(chats))
        # A page can be sealed for each slice of a large chat history. Rechecking
        # every task for every chat after each page made progress O(chats * tasks * pages).
        chat_tasks = {chat["id"]: [0, 0] for chat in selected}
        for task in tasks:
            status = chat_tasks.get(task["chat_id"])
            if status is not None:
                status[0] += 1
                page = self.progress.get(task["id"])
                status[1] += bool(page and page["terminal"] and page["outcome"] == "ok")
        self.current["counts"] = {**self.counts, "chats_discovered": discovered, "chats_selected": len(selected),
            "chats_done": sum(total == done for total, done in chat_tasks.values())}
        self.current["coverage"] = {"inventory_complete": self.inventory["discovery_complete"],
            "tasks_total": len(tasks), "tasks_done": sum(bool(p["terminal"]) and p["outcome"] == "ok"
                                                          for p in self.progress.values()),
            "failures": self.failures + len(self.inventory["gaps"]),
            "scope": "visible to this account during the recorded acquisition intervals"}
        self.current["omissions"] = self.inventory["gaps"][:100]

    async def retry(self, call):
        for attempt in range(6):
            try:
                return await call()
            except errors.FloodWaitError as exc:
                self.current.update(phase="waiting", wait_until=time.time() + exc.seconds, delay_seconds=exc.seconds)
                self.persist()
                await asyncio.sleep(exc.seconds + 1)
                self.current.update(phase="running", wait_until=None, delay_seconds=None)
            except (OSError, ConnectionError, TimeoutError, errors.ServerError):
                if attempt == 5:
                    raise
                await asyncio.sleep(min(30, 2 ** attempt))
                await self.collector.restore()
        raise ConnectionError("Telegram remains rate limited; resume later.")

    async def attachment(self, media, task, network, directory, options):
        info = media_info(media)
        limit = options["max_media_file_mib"] * 1024**2
        category = task["category"]
        if category in ("messages", "stories") and info["kind"] not in options["media_types"]:
            return {**info, "outcome": "excluded", "reason": "media_type_not_selected"}
        if info["expected_bytes"] is not None and info["expected_bytes"] > limit:
            return {**info, "outcome": "excluded", "reason": "per_file_limit"}
        remaining = options["max_total_gib"] * 1024**3 - self.counts["bytes_saved"] - self.pending_bytes
        if remaining <= 0 or info["expected_bytes"] and info["expected_bytes"] > remaining:
            return {**info, "outcome": "failed", "reason": "total_budget"}
        temporary = directory / "media" / ("pending-" + secrets.token_hex(8))
        try:
            async def progress(current, total):
                if max(current, total) > min(limit, remaining):
                    raise ValueError("attachment_size_limit")
            async def download_once():
                if shutil.disk_usage(directory).free < min(limit, remaining, info["expected_bytes"] or 1024**2) + 64 * 1024**2:
                    raise OSError("Insufficient free space for the next attachment.")
                with temporary.open("wb") as stream:
                    writer = BoundedWriter(stream, min(limit, remaining))
                    result = await network.download(media, writer, progress, task)
                    if result is None:
                        raise ValueError("attachment_unavailable")
                    stream.flush()
                    os.fsync(stream.fileno())
                if info["expected_bytes"] is not None and info["kind"] != "photo" and writer.total != info["expected_bytes"]:
                    raise ValueError("attachment_size_differs_from_observation")
                return writer
            writer = await self.retry(download_once)
            digest, size = writer.digest.hexdigest(), writer.total
            # Additional Takeout JSON can contain new authorization fields: sanitize before export.
            if isinstance(media, types.InputTakeoutFileLocation):
                if size > 64 * 1024**2:
                    raise ValueError("additional_json_exceeds_sanitizer_limit")
                sanitized = canonical(transport.safe(json.loads(temporary.read_bytes())))
                durable_write(temporary, sanitized)
                digest, size = sha(sanitized), len(sanitized)
            target = directory / "media" / digest
            if target.exists():
                if target.is_symlink() or file_sha(target) != digest:
                    raise ValueError("existing_attachment_is_corrupt")
                temporary.unlink()
            else:
                temporary.replace(target)
                sync_directory(target.parent)
            self.pending_bytes += size
            return {**info, "outcome": "saved", "file": "media/" + digest, "sha256": digest, "bytes": size}
        except errors.TakeoutFileEmptyError:
            return {**info, "outcome": "excluded", "reason": "no_additional_data"}
        except errors.TakeoutInvalidError:
            raise  # Resume must renew the transport, not sign an expired session as an attachment failure.
        except (errors.RPCError, ValueError) as exc:
            return {**info, "outcome": "failed", "reason": type(exc).__name__ if isinstance(exc, errors.RPCError) else str(exc)}
        finally:
            temporary.unlink(missing_ok=True)

    def selected(self, row, options):
        if row["category"] != "messages":
            return True
        date = row.get("date")
        if date:
            date = datetime.fromisoformat(date).astimezone(timezone.utc).isoformat()
        if options["from_utc"] and (not date or date < options["from_utc"]):
            return False
        if options["to_utc"] and (not date or date >= options["to_utc"]):
            return False
        if options["sender_ids"] and row.get("from_id") not in options["sender_ids"]:
            return False
        if options["text_contains"] and not any(term in (row.get("text") or "").casefold()
                                                for term in options["text_contains"]):
            return False
        return not options["own_messages_only"] or row.get("outgoing")

    def seal(self, job, task, cursor, next_cursor, terminal, rows, seen_count, started, outcome="ok", error=None):
        directory = self.directory(job["job_id"])
        number = len(self.receipts) + 1
        data = b"".join(canonical(row) + b"\n" for row in rows)
        name = f"data/{number:08d}.jsonl"
        receipt = {"format": "tgwitness-account-export-page-v1", "public_key": self.vault.public_key,
            "job_id": job["job_id"], "account_id": job["account_id"], "options_sha256": job["options_sha256"],
            "inventory_sha256": self.inventory_hash, "seq": number, "previous_receipt_sha256": self.head,
            "task_id": task["id"], "category": task["category"], "chat_id": task["chat_id"],
            "cursor_before": cursor, "cursor_after": next_cursor, "terminal": terminal, "outcome": outcome,
            "error": error, "captured_from": started, "captured_until": utcnow(), "seen_count": seen_count,
            "count": len(rows), "data_file": name, "data_sha256": sha(data)}
        receipt["transport_generation"] = getattr(self, "transport_generation", 0)
        envelope = self.signed(receipt)
        durable_write(directory / name, data)
        durable_write(directory / "receipts" / f"{number:08d}.json", canonical(envelope))
        for row in rows:
            self.count_row(row, directory)
        self.index.commit()
        self.accept(envelope)
        self.store.append("account_export.page", {"job_id": job["job_id"], "seq": number,
            "receipt_sha256": self.head, "category": task["category"], "count": len(rows)}, task["chat_id"])
        self.update_counts()
        self.persist()

    async def run(self, job):
        directory, options = self.directory(job["job_id"]), job["options"]
        network = self.transport_factory(self.collector, self.vault, job["job_id"], options)
        try:
            await complete_in_thread(self.recover, job)
            await self.retry(network.open)
            self.transport_generation = getattr(network, "secret", {}).get("generation", 0)
            if network.account_id != job["account_id"]:
                raise ValueError("The connected account differs from this export's signed account.")
            if self.inventory is None:
                chats, tasks, gaps = await self.retry(network.discover)
                inventory = {"format": "tgwitness-account-export-inventory-v1", "public_key": self.vault.public_key,
                    "job_id": job["job_id"], "account_id": job["account_id"], "options_sha256": job["options_sha256"],
                    "observed_at": utcnow(), "chats": chats, "tasks": tasks, "discovery_complete": True, "gaps": gaps,
                    "discovery_counts": getattr(network, "discovery_counts", {"chats_discovered": len(chats), "chats_excluded": 0})}
                durable_write(directory / "inventory.json", canonical(self.signed(inventory)))
                await complete_in_thread(self.recover, job)
            elif hasattr(network, "validate_inventory"):
                await self.retry(lambda: network.validate_inventory(self.inventory))
            self.current.update(phase="running", error=None, wait_until=None)
            self.persist()
            for task in self.inventory["tasks"]:
                previous = self.progress.get(task["id"])
                if previous and previous["terminal"]:
                    continue
                cursor = previous["cursor_after"] if previous else task["cursor_start"]
                self.current["current_chat"] = task["chat_id"]
                if task.get("discovery_error"):
                    self.seal(job, task, cursor, cursor, True, [], 0, utcnow(), "failed", task["discovery_error"])
                    continue
                while True:
                    started, self.pending_bytes = utcnow(), 0
                    try:
                        page, after, terminal = await self.retry(lambda: network.page(task, cursor))
                        if not terminal and after == cursor:
                            raise ValueError("Telegram pagination made no progress.")
                        if task["category"] == "messages" and after > cursor:
                            raise ValueError("Telegram history cursor moved forward.")
                        rows, page_ids = [], set()
                        for row, media in page:
                            if not self.selected(row, options):
                                continue
                            if row["category"] == "messages":
                                key = (row["chat_id"], row["id"])
                                if (key in page_ids or self.index.execute("SELECT 1 FROM seen WHERE chat=? AND message=?", key).fetchone()):
                                    continue
                                if not 0 < row["id"] < cursor or row["id"] > task["newest_message_id"]:
                                    raise ValueError("Telegram returned a message outside the frozen page boundary.")
                                page_ids.add(key)
                            media = media if isinstance(media, list) else [media] if media is not None else []
                            if hasattr(network, "extra_media"):
                                media += await self.retry(lambda: network.extra_media(row, task))
                            if media:
                                row.setdefault("attachments", []).extend([await self.attachment(item, {**task, "message_id": row.get("id")},
                                    network, directory, options) for item in media])
                            rows.append(row)
                        self.seal(job, task, cursor, after, terminal, rows, len(page), started)
                    except errors.TakeoutInvalidError:
                        raise
                    except errors.RPCError as exc:
                        self.seal(job, task, cursor, cursor, True, [], 0, started, "failed", type(exc).__name__)
                        terminal = True
                    except ValueError as exc:
                        # Explicitly record unavailable selected categories, never silently omit them.
                        if task["category"] == "other_data" and options["transport"] == "regular":
                            self.seal(job, task, cursor, cursor, True, [], 0, started, "failed", str(exc))
                            terminal = True
                        else:
                            raise
                    if terminal:
                        break
                    cursor = after
                    await asyncio.sleep(0)
            await complete_in_thread(self.recover, job)  # reject changes without blocking the HTTP event loop
            self.current.update(phase="packaging", current_chat=None)
            self.persist()
            await complete_in_thread(self.package, job)
            self.current.update(phase="partial" if self.current["coverage"]["failures"] else "done", ready=True)
            self.persist()
            try:
                await self.retry(lambda: network.finish(True))
            except (errors.RPCError, OSError, ConnectionError, TimeoutError):
                self.current["error"] = "Export saved; Telegram Takeout finalization could not be confirmed."
            self.current.update(phase="partial" if self.current["coverage"]["failures"] else "done", wait_until=None)
            self.persist()
            self.store.append("account_export.completed", {"job_id": job["job_id"], "receipt_head_sha256": self.head,
                "counts": self.counts, "complete_within_scope": self.current["phase"] == "done"})
        except errors.TakeoutInvalidError:
            if hasattr(network, "invalidate"):
                network.invalidate()
            self.current.update(phase="paused", error="Telegram ended the Takeout session. Resume creates a new "
                "Takeout session with the same options and checks that the saved pagination ranges still apply.")
            self.persist()
        except errors.TakeoutInitDelayError as exc:
            self.current.update(phase="waiting", wait_until=time.time() + exc.seconds,
                                delay_seconds=exc.seconds, error="Telegram requires a Takeout waiting period. Resume after it ends.")
            self.persist()
        except asyncio.CancelledError:
            if self.current.get("ready"):
                self.current.update(phase="partial" if self.current["coverage"]["failures"] else "done",
                                    error="Archive saved; Telegram Takeout finalization may still be pending.")
            else:
                self.current.update(phase="paused", error=None)
            self.persist()
            raise
        except (OSError, ConnectionError, TimeoutError) as exc:
            self.current.update(phase="paused", error=type(exc).__name__ + ": resume from the last sealed page.")
            self.persist()
        except Exception as exc:
            self.current.update(phase="failed", error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
            self.persist()
        finally:
            if self.index:
                self.index.close()
                self.index = None

    def package(self, job):
        directory = self.directory(job["job_id"])
        out, final = directory / "export.zip.part", directory / "export.zip"
        hashes = {}
        try:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                def write(name, chunks):
                    digest = hashlib.sha256()
                    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_STORED if name.startswith("media/") else zipfile.ZIP_DEFLATED
                    with archive.open(entry, "w", force_zip64=True) as target:
                        for chunk in chunks:
                            target.write(chunk)
                            digest.update(chunk)
                    hashes[name] = digest.hexdigest()

                def chunks(path):
                    if path.is_symlink():
                        raise ValueError("Export content must not be a filesystem link.")
                    with path.open("rb") as source:
                        yield from iter(lambda: source.read(1024 * 1024), b"")

                write("job.json", chunks(directory / "job.json"))
                write("inventory.json", chunks(directory / "inventory.json"))
                media = set()
                message_pages = {}
                chat_counts = {}
                captured_from = captured_until = None
                for envelope in self.receipts:
                    receipt = envelope["statement"]
                    first, last = receipt.get("captured_from"), receipt.get("captured_until")
                    if first:
                        captured_from = min(captured_from, first) if captured_from else first
                    if last:
                        captured_until = max(captured_until, last) if captured_until else last
                    write(f"receipts/{receipt['seq']:08d}.json", [canonical(envelope)])
                    write(receipt["data_file"], chunks(directory / receipt["data_file"]))
                    if hashes[receipt["data_file"]] != receipt["data_sha256"]:
                        raise ValueError("A captured page changed while packaging.")
                    if receipt["category"] == "messages":
                        message_pages.setdefault(receipt["chat_id"], []).append(receipt["data_file"])
                        chat_counts[receipt["chat_id"]] = chat_counts.get(receipt["chat_id"], 0) + receipt["count"]
                    with (directory / receipt["data_file"]).open("rb") as stream:
                        for raw in stream:
                            for attachment in json.loads(raw).get("attachments", []):
                                if attachment["outcome"] == "saved":
                                    media.add(attachment["file"])
                for name in sorted(media):
                    write(name, chunks(directory / name))
                    if hashes[name] != name.removeprefix("media/"):
                        raise ValueError("An attachment changed while packaging.")
                selected = [c for c in self.inventory["chats"] if c["selected"]]
                report_context = {"report_language": job["options"].get("report_language", "en"),
                    "archive_reference": job["job_id"], "requested_at": job["created_at"],
                    "captured_from": captured_from, "captured_until": captured_until,
                    "options": job["options"], "counts": self.current["counts"], "coverage": self.current["coverage"],
                    "complete_within_scope": not self.current["coverage"]["failures"],
                    "omissions": [*self.inventory.get("gaps", []), *self.current.get("omissions", [])],
                    "fingerprint": fingerprint(self.vault.public_key), "limitations": LIMITATIONS}
                for chat in selected:
                    name = "chats/" + str(chat["id"]) + ".html"
                    def message_rows(chat=chat):
                        for data_file in message_pages.get(chat["id"], ()):
                            with (directory / data_file).open("rb") as stream:
                                for raw in stream:
                                    yield json.loads(raw)
                    write(name, account_report.account_chat(report_context, chat, message_rows()))
                write("index.html", account_report.account_index(report_context,
                    ({**chat, "message_count": chat_counts.get(chat["id"], 0)} for chat in selected)))
                write("README.txt", [("TgWitness account export\n\n" + "\n".join(LIMITATIONS)
                    + "\n\nVerify using verify.py from a trusted checkout, with --fingerprint TRUSTED_SHA256.\n"
                    + "data/*.jsonl are authoritative; receipts bind each page to frozen options and inventory.\n"
                    + "HTML is a readable derivative. Media names are content hashes.\n").encode()])
                write("verify.py", chunks(Path(__file__).with_name("verify.py")))
                write("SHA256SUMS", ["".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())).encode()])
                manifest = {"format": "tgwitness-account-export-v1", "public_key": self.vault.public_key,
                    "report_language": report_context["report_language"],
                    "fingerprint": fingerprint(self.vault.public_key), "job_id": job["job_id"], "account_id": job["account_id"],
                    "options": job["options"], "options_sha256": job["options_sha256"], "inventory_sha256": self.inventory_hash,
                    "created_at": job["created_at"], "completed_at": utcnow(), "status": "partial" if self.current["coverage"]["failures"] else "done",
                    "complete_within_scope": not self.current["coverage"]["failures"], "coverage": self.current["coverage"],
                    "counts": self.current["counts"], "receipt_count": len(self.receipts), "receipt_head_sha256": self.head,
                    "files": hashes, "limitations": LIMITATIONS, "producer": producer()}
                archive.writestr(zipfile.ZipInfo("manifest.json"), canonical(manifest))
                archive.writestr(zipfile.ZipInfo("manifest.sig"), self.vault.sign(canonical(manifest)))
            with out.open("r+b") as stream:
                os.fsync(stream.fileno())
            out.replace(final)
            sync_directory(directory)
            self.current.update(archive_sha256=file_sha(final), archive_bytes=final.stat().st_size)
        finally:
            out.unlink(missing_ok=True)

    def result_path(self, job_id):
        directory = self.directory(job_id)
        return directory / "export.zip" if self.public(job_id).get("ready") and not (directory / "export.zip").is_symlink() else None

    async def remove(self, job_id):
        directory = self.directory(job_id)
        if self.busy() and self.current["id"] == job_id:
            raise ValueError("Pause the account export before removing it.")
        saved = self.vault.read("account-export-" + job_id)
        if saved.get("takeout_id"):
            await self.collector.restore()
            try:
                await transport.WrappedClient(self.collector.client, saved["takeout_id"])(
                    transport.f.account.FinishTakeoutSessionRequest(success=False))
            except errors.TakeoutInvalidError:
                pass  # Telegram has already terminated this session.
            except (errors.RPCError, OSError, ConnectionError, TimeoutError):
                raise ValueError("Could not close the Telegram Takeout session. Reconnect and retry removing this export.") from None
        if directory.exists():
            # All generated job paths must remain inside the verified job root.
            if any(linked(p) or not p.resolve().is_relative_to(directory.resolve()) for p in directory.rglob("*")):
                raise ValueError("Refusing to remove an export containing filesystem links.")
            identities = {path.stem for path in (directory / "disclosures").glob("*") if JOB_ID.fullmatch(path.stem)}
            for path in self.vault.root.glob("disclosure-*.enc"):
                identity = path.stem.removeprefix("disclosure-")
                if JOB_ID.fullmatch(identity) and self.vault.read(path.stem).get("source_job") == job_id:
                    identities.add(identity)
            for identity in identities:
                self.vault.save("disclosure-" + identity, {})
            shutil.rmtree(directory)
        self.vault.save("account-export-" + job_id, {})
        if self.current and self.current["id"] == job_id:
            self.current = None
        return {"id": job_id, "deleted": True}

    async def close(self):
        if self.busy():
            await self.pause(self.current["id"])
