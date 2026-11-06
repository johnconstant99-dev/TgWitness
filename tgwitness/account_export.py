"""Durable, resumable account acquisition with signed pages and a portable ZIP64 bundle.

Only sealed pages advance a cursor. Cached progress is rebuilt from their signatures
and bytes before resuming or packaging. Message/metadata JSONL is authoritative;
HTML is an escaped readable derivative. No new Telegram authorization is created.
"""
import asyncio
import base64
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
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

from . import account_export_transport as transport, account_report, file_hashes, account_attachment_cache
from .evidence import producer
from .monitoring import MediaRule
from .security import private_write
from .store import ZERO, canonical, utcnow
from .verify import fingerprint, validate_server_hashes
from .workers import complete_in_thread
from .telegram_client import FLOOD_ERRORS

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
    messages_first: bool = True
    export_format: Literal["tgwitness", "telegram_json", "telegram_html", "telegram_both"] = "tgwitness"
    chat_kinds: list[Literal[KINDS]] = Field(default_factory=lambda: list(KINDS), max_length=len(KINDS))
    chat_ids: list[int] = Field(default_factory=list, max_length=10000)
    sender_ids: list[int] = Field(default_factory=list, max_length=10000)
    text_contains: list[str] = Field(default_factory=list, max_length=100)
    purpose: str = Field(default="", max_length=1000)
    report_language: str = "en"
    report_presentation: account_report.Presentation = Field(default_factory=account_report.Presentation)
    from_utc: str | None = None
    to_utc: str | None = None
    own_messages_only: bool = False
    include_archived: bool = True
    media_types: list[Literal[MEDIA]] = Field(default_factory=lambda: list(MEDIA), max_length=len(MEDIA))
    media_action: Literal["download", "hashes_only", "exclude"] = "download"
    media_actions: dict[Literal[MEDIA], Literal["download", "hashes_only", "exclude"]] = Field(default_factory=dict)
    oversized_media: Literal["exclude", "hashes_only"] = "exclude"
    max_media_file_mib: int = Field(default=512, ge=1, le=4096)
    media_rules: dict[Literal[MEDIA], MediaRule] = Field(default_factory=dict)
    max_total_gib: int = Field(default=16, ge=1, le=1024)
    budget_exhausted: Literal["stop_files", "hashes_only"] = "hashes_only"
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
    # Attributes are an unordered set of capabilities. Animated MP4s and video
    # stickers also carry a video attribute; its position must not change which
    # exclusion or byte limit applies. Match the Capture engine's precedence.
    attributes = getattr(item, "attributes", [])
    if any(isinstance(a, types.DocumentAttributeVideo) and a.round_message for a in attributes):
        kind = "video_message"
    elif any(isinstance(a, types.DocumentAttributeAudio) and a.voice for a in attributes):
        kind = "voice"
    elif any(isinstance(a, (types.DocumentAttributeSticker, types.DocumentAttributeCustomEmoji)) for a in attributes):
        kind = "sticker"
    elif any(isinstance(a, types.DocumentAttributeAnimated) for a in attributes):
        kind = "animation"
    elif any(isinstance(a, types.DocumentAttributeVideo) for a in attributes):
        kind = "video"
    elif any(isinstance(a, types.DocumentAttributeAudio) for a in attributes):
        kind = "audio"
    return {"kind": kind, "media_id": getattr(item, "id", None), "expected_bytes": size}


def attachment_policy(media, task, options):
    """Decide from observed metadata; this performs no Telegram requests."""
    info = media_info(media)
    representation = file_hashes.representation(media)
    if representation:
        info["representation"] = representation
    limit = options["max_media_file_mib"] * 1024**2
    category = task["category"]

    def excluded(reason):
        return {**info, "outcome": "excluded", "reason": reason}, "exclude", limit

    if category in ("messages", "stories") and info["kind"] not in options["media_types"]:
        return excluded("media_type_not_selected")
    rule = options.get("media_rules", {}).get(info["kind"], {}) if category in ("messages", "stories") else {}
    action = options.get("media_actions", {}).get(info["kind"], rule.get("action") or options.get("media_action", "download"))
    if category == "other_data":
        action = "download"
    if action == "exclude":
        return excluded("media_policy")
    if rule:
        if not rule.get("enabled", True):
            return excluded("media_type_not_selected")
        limit = min(limit, rule["max_mb"] * 1024**2)
        if rule.get("max_seconds"):
            item = getattr(media, "document", None) or media
            duration = next((a.duration for a in getattr(item, "attributes", []) if hasattr(a, "duration")), None)
            if duration is None or not 0 <= duration <= rule["max_seconds"]:
                return excluded("duration_limit")
    if action == "download" and info["expected_bytes"] is not None and info["expected_bytes"] > limit:
        if options.get("oversized_media") == "hashes_only" and category != "other_data":
            action = "hashes_only"
        else:
            return excluded("per_file_limit")
    return info, action, limit


class AccountExport:
    def __init__(self, collector, store, vault):
        self.collector, self.store, self.vault = collector, store, vault
        self.root = store.root / "account-exports"
        if linked(self.root):
            raise ValueError("Account-export storage must not be a filesystem link.")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.task, self.current, self.index = None, None, None
        self.transfer = None
        self.packaging_copies, self.record_bytes = 1, 0
        self.transport_factory = transport.Transport  # replaced by deterministic fake transports in tests

    def directory(self, job_id):
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ValueError("Unknown account export.")
        path = self.root / job_id
        if linked(self.root) or linked(path) or path.resolve().parent != self.root.resolve():
            raise ValueError("Account-export path is outside its storage directory.")
        for name in ("data", "receipts", "media", "history-pages", "attachment-queue", "attachment-results"):
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
            active = self.busy() or claimed
            return {**json.loads(json.dumps(self.current)), "active": active,
                    "transfer": dict(self.transfer) if active and self.transfer else None}
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
        durable_write(self.directory(self.current["id"]) / "status.json",
                      canonical({k: v for k, v in self.current.items() if k != "transfer"}))

    async def start(self, options):
        options = AccountExportOptions.model_validate(options).model_dump()
        from .export_preflight import assess
        assessment = assess(options, shutil.disk_usage(self.root).free)
        if not assessment["can_start"]:
            raise ValueError(" ".join(item["message"] for item in assessment["issues"] if item["severity"] == "error"))
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
            raise ValueError("This account is busy. Pause observation or its current task before exporting.")
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
            self.task.add_done_callback(lambda done: self.collector.release_export(job_id) if self.task is done else None)
        except BaseException:
            self.collector.release_export(job_id)
            raise
        return self.public()

    async def pause(self, job_id):
        self.directory(job_id)
        if self.task and self.current and self.current["id"] == job_id:
            if not self.task.done():
                self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None
            self.collector.release_export(job_id)
        return self.public(job_id)

    async def finish(self, job_id, reason="Stopped before acquisition completed."):
        """Start offline finalization without holding an HTTP request for a large ZIP."""
        from .account_finalization import finalize
        await self.pause(job_id)
        if self.busy():
            raise ValueError("Another account export is running.")
        directory = self.directory(job_id)
        job = self.verify_signed(read_json(directory / "job.json"))
        if sha(canonical(job["options"])) != job["options_sha256"]:
            raise ValueError("The saved export options have changed.")
        self.current = self.public(job_id)
        if self.current.get("ready"):
            return self.current
        if not self.collector.reserve_export(job_id):
            raise ValueError("The account is busy. Pause its current task first.")
        self.current.update(phase="packaging", options=job["options"], account_id=job["account_id"], error=None)
        try:
            self.persist()
        except BaseException:
            self.collector.release_export(job_id)
            raise

        async def finish_saved():
            try:
                await complete_in_thread(finalize, self, job, reason)
            except asyncio.CancelledError:
                if not self.current.get("ready"):
                    self.current.update(phase="paused", error="Finalization interrupted. Saved pages are retained.")
                    self.persist()
                raise
            except Exception as exc:
                self.current.update(phase="failed", error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
                self.persist()
            finally:
                if self.index:
                    self.index.close()
                    self.index = None
                self.collector.release_export(job_id)
        self.task = asyncio.create_task(finish_saved())
        self.task.add_done_callback(lambda done: self.collector.release_export(job_id) if self.task is done else None)
        return self.public()

    async def finalize_partial(self, job_id, reason="Stopped before acquisition completed."):
        """Wait for offline finalization before a disposable runner revokes the login."""
        state = await self.finish(job_id, reason)
        if not state.get("ready"):
            await asyncio.shield(self.task)
            state = self.public(job_id)
        if not state.get("ready"):
            raise ValueError(state.get("error") or "The preserved export could not be finalized.")
        return state

    def complete(self):
        coverage = self.current.get("coverage", {})
        return bool(coverage.get("inventory_complete") and not coverage.get("failures")
                    and coverage.get("tasks_done") == coverage.get("tasks_total"))

    def packaging_reserve(self, extra_records=0, extra_media=0):
        acquisition = (self.current or {}).get("acquisition", {})
        records = max(acquisition.get("bytes_preserved", 0), getattr(self, "record_bytes", 0)) + extra_records
        media = getattr(self, "counts", {}).get("unique_media_bytes", 0) + getattr(self, "pending_bytes", 0) + extra_media
        # Includes escaped HTML, JSON views and an additional outer encrypted copy
        # on disposable runners. This is a reserve, not a final-size prediction.
        return 256 * 1024**2 + getattr(self, "packaging_copies", 1) * (16 * records + media)

    def storage_pressure(self, extra_records=0, extra_media=0):
        return shutil.disk_usage(self.root).free < self.packaging_reserve(extra_records, extra_media)

    def ensure_storage(self, extra_records=0):
        if self.storage_pressure(extra_records):
            raise OSError(errno.ENOSPC, "Free disk is reserved for finishing the archive.")

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
            raise ValueError("This account is busy. Pause observation or its current task before resuming the export.")
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
                        await network.finish(self.complete())
                    except (errors.RPCError, OSError, ConnectionError, TimeoutError):
                        raise ValueError("The saved archive is retained, but Telegram Takeout finalization failed. Reconnect and retry.") from None
                    self.current["error"] = None
                self.current.update(phase="done" if self.complete() else "partial",
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
            self.task.add_done_callback(lambda done: self.collector.release_export(job_id) if self.task is done else None)
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
        self.index.execute("DROP TABLE IF EXISTS stored_media")
        self.index.execute("CREATE TABLE stored_media (sha256 TEXT PRIMARY KEY, bytes INTEGER NOT NULL)")
        self.progress, self.receipts, self.head = {}, [], ZERO
        self.counts = dict(records=0, messages=0, messages_exported=0, messages_seen=0,
                           media_saved=0, media_hashed=0, media_skipped=0, bytes_saved=0, unique_media_bytes=0)
        self.attachment_cache = {}
        self.attachment_cache_bytes = 0
        self.record_bytes = 0
        self.pending_bytes, self.pending_media = 0, set()
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
        self.record_bytes += len(canonical(row)) + 1
        self.counts["records"] += 1
        if row["category"] == "messages":
            try:
                self.index.execute("INSERT INTO seen VALUES (?,?)", (row["chat_id"], row["id"]))
            except sqlite3.IntegrityError:
                raise ValueError("Duplicate message in sealed account-export pages.") from None
            self.counts["messages"] += 1
            self.counts["messages_exported"] += 1
        for attachment in row.get("attachments", []):
            if attachment.get("server_hashes") is not None:
                validate_server_hashes(attachment["server_hashes"])
            if attachment["outcome"] == "saved":
                digest = attachment["sha256"]
                if not re.fullmatch(r"[a-f0-9]{64}", digest) or attachment["file"] != "media/" + digest:
                    raise ValueError("Invalid attachment content path.")
                path = directory / attachment["file"]
                recorded = self.index.execute("SELECT 1 FROM stored_media WHERE sha256=?", (digest,)).fetchone()
                if verify and (path.is_symlink() or path.stat().st_size != attachment["bytes"] or not recorded and file_sha(path) != digest):
                    raise ValueError("A captured attachment changed after it was signed.")
                self.counts["media_saved"] += 1
                self.counts["bytes_saved"] += attachment["bytes"]
                inserted = self.index.execute("INSERT OR IGNORE INTO stored_media VALUES (?,?)", (digest, attachment["bytes"]))
                if inserted.rowcount:
                    self.counts["unique_media_bytes"] += attachment["bytes"]
            elif attachment["outcome"] == "hashed":
                if attachment.get("server_hashes", {}).get("status") != "complete":
                    raise ValueError("Hash-only attachment has incomplete coverage.")
                self.counts["media_hashed"] += 1
            else:
                self.counts["media_skipped"] += 1
                self.failures += attachment["outcome"] == "failed"
            if attachment.get("representation") and attachment["outcome"] in ("saved", "hashed"):
                self.cache_attachment(attachment)

    def cache_attachment(self, attachment):
        key = (canonical(attachment["representation"]), attachment["outcome"])
        size = len(canonical(attachment))
        if size > 8 * 1024**2:
            return
        previous = self.attachment_cache.pop(key, None)
        self.attachment_cache_bytes = getattr(self, "attachment_cache_bytes", 0) - (len(canonical(previous)) if previous else 0)
        while self.attachment_cache and (len(self.attachment_cache) >= 512 or self.attachment_cache_bytes + size > 8 * 1024**2):
            removed = self.attachment_cache.pop(next(iter(self.attachment_cache)))
            self.attachment_cache_bytes -= len(canonical(removed))
        self.attachment_cache[key] = attachment
        self.attachment_cache_bytes += size

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
            except FLOOD_ERRORS as exc:
                self.current.update(phase="waiting", wait_until=time.time() + exc.seconds, delay_seconds=exc.seconds,
                                    wait_reason="rate_limit")
                self.persist()
                await asyncio.sleep(exc.seconds + 1)
                self.current.update(phase="running", wait_until=None, delay_seconds=None, wait_reason=None)
            except (OSError, ConnectionError, TimeoutError, errors.ServerError):
                if attempt == 5:
                    raise
                await asyncio.sleep(min(30, 2 ** attempt))
                await self.collector.restore()
        raise ConnectionError("Telegram remains rate limited; resume later.")

    async def attachment(self, media, task, network, directory, options):
        info, action, limit = attachment_policy(media, task, options)
        representation = info.get("representation")
        if action == "exclude":
            return info
        cached = self.attachment_cache.get((canonical(representation), "hashed" if action == "hashes_only" else "saved")) if representation else None
        if cached is None:
            cached = account_attachment_cache.read(self, representation, "hashed" if action == "hashes_only" else "saved")
        if cached:
            if cached["outcome"] == "saved":
                path = directory / cached["file"]
                if path.is_symlink() or not path.is_file() or path.stat().st_size != cached["bytes"]:
                    raise ValueError("Cached attachment changed after capture.")
                recorded = self.index and self.index.execute("SELECT 1 FROM stored_media WHERE sha256=?", (cached["sha256"],)).fetchone()
                if not hasattr(self, "pending_media"):
                    self.pending_media = set()
                if not recorded and cached["sha256"] not in self.pending_media:
                    self.pending_bytes += cached["bytes"]
                    self.pending_media.add(cached["sha256"])
            return {**cached, "reused": True}
        remaining = options["max_total_gib"] * 1024**3 - self.counts.get("unique_media_bytes", self.counts["bytes_saved"]) - self.pending_bytes
        budget_full = remaining <= 0 or info["expected_bytes"] and info["expected_bytes"] > remaining
        disk_full = (hasattr(self, "root") and self.storage_pressure(extra_media=min(limit, remaining, info["expected_bytes"] or limit)))
        if action == "download" and (budget_full or disk_full):
            if options.get("budget_exhausted") == "hashes_only" and task["category"] != "other_data":
                action = "hashes_only"
                info["download_skipped_reason"] = "total_budget" if budget_full else "packaging_reserve"
                cached = account_attachment_cache.read(self, representation, "hashed")
                if cached:
                    return {**cached, "reused": True, "download_skipped_reason": info["download_skipped_reason"]}
            else:
                return {**info, "outcome": "failed", "reason": "total_budget" if budget_full else "packaging_reserve"}
        if action == "hashes_only":
            try:
                hashes = await self.retry(lambda: network.hashes(media, task))
                validate_server_hashes(hashes)
                result = {**info, "outcome": "hashed" if hashes["status"] == "complete" else "failed",
                          "reason": "hashes_only" if hashes["status"] == "complete" else hashes.get("reason", "hashes_unavailable"),
                          "server_hashes": hashes}
                if result["outcome"] == "hashed" and representation:
                    account_attachment_cache.save(self, result)
                    self.cache_attachment(result)
                return result
            except errors.TakeoutInvalidError:
                raise
            except (errors.RPCError, ValueError) as exc:
                return {**info, "outcome": "failed", "reason": "hashes_unavailable", "error": type(exc).__name__}
        temporary = directory / "media" / ("pending-" + secrets.token_hex(8))
        try:
            async def progress(current, total):
                if max(current, total if total is not None else current) > min(limit, remaining):
                    raise ValueError("attachment_size_limit")
                self.transfer = {"received_bytes": current, "total_bytes": total,
                                 "kind": info["kind"], "attempt": attempt}
            attempt = 0
            async def download_once():
                nonlocal attempt
                attempt += 1
                # Live transfer counters are not signed or counted as preserved bytes.
                # A retry starts this file again; do not retain the previous attempt's progress.
                await progress(0, info["expected_bytes"])
                if shutil.disk_usage(directory).free < min(limit, remaining, info["expected_bytes"] or 1024**2) + 64 * 1024**2:
                    raise OSError("Insufficient free space for the next attachment.")
                with temporary.open("wb") as stream:
                    writer = BoundedWriter(stream, min(limit, remaining))
                    result = await network.download(media, writer, progress, task)
                    if result is None:
                        raise ValueError("attachment_unavailable")
                    stream.flush()
                    os.fsync(stream.fileno())
                if info["expected_bytes"] is not None and writer.total != info["expected_bytes"]:
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
            if not hasattr(self, "pending_media"):
                self.pending_media = set()
            recorded = self.index and self.index.execute("SELECT 1 FROM stored_media WHERE sha256=?", (digest,)).fetchone()
            if not recorded and digest not in self.pending_media:
                self.pending_bytes += size
                self.pending_media.add(digest)
            result = {**info, "outcome": "saved", "file": "media/" + digest, "sha256": digest, "bytes": size}
            if representation:
                account_attachment_cache.save(self, result)
                self.cache_attachment(result)
            return result
        except errors.TakeoutInvalidError:
            raise  # Resume must renew the transport, not sign an expired session as an attachment failure.
        except (errors.RPCError, ValueError) as exc:
            if isinstance(exc, errors.RPCError) and getattr(exc, "message", None) == "TAKEOUT_FILE_EMPTY":
                return {**info, "outcome": "excluded", "reason": "no_additional_data"}
            return {**info, "outcome": "failed", "reason": type(exc).__name__ if isinstance(exc, errors.RPCError) else str(exc)}
        finally:
            self.transfer = None
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
            self.current.update(phase="running", error=None, wait_until=None, delay_seconds=None, wait_reason=None)
            self.persist()
            if options.get("messages_first", False):
                from .account_acquisition import StagedTransport
                network = StagedTransport(network, self, job)
                await network.prepare()
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
                    self.ensure_storage()
                    started, self.pending_bytes, self.pending_media = utcnow(), 0, set()
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
                        self.seal(job, task, cursor, after, terminal, rows, getattr(page, "seen_count", len(page)),
                                  getattr(page, "started", started))
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
            self.current.update(phase="done" if self.complete() else "partial", ready=True)
            self.persist()
            try:
                await self.retry(lambda: network.finish(self.complete()))
            except (errors.RPCError, OSError, ConnectionError, TimeoutError):
                self.current["error"] = "Export saved; Telegram Takeout finalization could not be confirmed."
            self.current.update(phase="done" if self.complete() else "partial", wait_until=None)
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
                                delay_seconds=exc.seconds, wait_reason="takeout_approval",
                                error=None)
            self.persist()
        except asyncio.CancelledError:
            if self.current.get("ready"):
                self.current.update(phase="done" if self.complete() else "partial",
                                    error="Archive saved; Telegram Takeout finalization may still be pending.")
            else:
                self.current.update(phase="paused", error=None)
            self.persist()
            raise
        except (OSError, ConnectionError, TimeoutError) as exc:
            space = isinstance(exc, OSError) and exc.errno == errno.ENOSPC
            self.current.update(phase="paused", error="Free disk is reserved for finishing the archive. Free space to resume, "
                "or finish with saved data." if space else type(exc).__name__ + ": resume from the last sealed page.")
            self.persist()
        except Exception as exc:
            self.current.update(phase="failed", error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
            self.persist()
        finally:
            if self.index:
                self.index.close()
                self.index = None
            self.collector.release_export(job["job_id"])

    def package(self, job):
        directory = self.directory(job["job_id"])
        out, final = directory / "export.zip.part", directory / "export.zip"
        hashes = {}
        try:
            with tempfile.SpooledTemporaryFile(max_size=1024**2, dir=directory) as hash_index, \
                    zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
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
                hash_manifests = set()
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
                            row = json.loads(raw)
                            for index, attachment in enumerate(row.get("attachments", [])):
                                if attachment["outcome"] == "saved":
                                    media.add(attachment["file"])
                                if attachment.get("server_hashes"):
                                    body = canonical(attachment["server_hashes"])
                                    name = "hashes/" + sha(body) + ".json"
                                    if name not in hash_manifests:
                                        write(name, [body])
                                        hash_manifests.add(name)
                                    hash_index.write(canonical({"category": row["category"], "chat_id": row.get("chat_id"),
                                        "message_id": row.get("id"), "attachment_index": index, "manifest": name}) + b"\n")
                if hash_manifests:
                    hash_index.seek(0)
                    write("hashes/index.jsonl", iter(lambda: hash_index.read(1024**2), b""))
                for name in sorted(media):
                    write(name, chunks(directory / name))
                    if hashes[name] != name.removeprefix("media/"):
                        raise ValueError("An attachment changed while packaging.")
                selected = [c for c in self.inventory["chats"] if c["selected"]]
                report_context = {"report_language": job["options"].get("report_language", "en"), "archive": True,
                    "presentation": job["options"].get("report_presentation", {}),
                    "archive_reference": job["job_id"], "requested_at": job["created_at"],
                    "captured_from": captured_from, "captured_until": captured_until,
                    "options": job["options"], "counts": self.current["counts"], "coverage": self.current["coverage"],
                    "complete_within_scope": self.complete(),
                    "omissions": [*self.inventory.get("gaps", []), *self.current.get("omissions", [])],
                    "fingerprint": fingerprint(self.vault.public_key), "limitations": LIMITATIONS}
                analytics = account_report.snapshot_analytics.Analytics("snapshot")
                for chat in selected:
                    def message_rows(chat=chat):
                        for data_file in message_pages.get(chat["id"], ()):
                            with (directory / data_file).open("rb") as stream:
                                for raw in stream:
                                    yield json.loads(raw)
                    chat_analytics = account_report.snapshot_analytics.Analytics("snapshot")
                    for row in message_rows():
                        analytics.snapshot(row, chat)
                        chat_analytics.snapshot(row, chat)
                    context = {**report_context, "analytics": account_report.snapshot_analytics.project(chat_analytics.result(), report_context["presentation"])}
                    display_chat = {**chat, "message_count": chat_counts.get(chat["id"], 0)}
                    for name, content in account_report.account_chat_pages(context, display_chat, message_rows):
                        write(name, content)
                report_context["analytics"] = account_report.snapshot_analytics.project(analytics.result(), report_context["presentation"])
                write("analytics.json", [canonical(report_context["analytics"])])
                write("index.html", account_report.account_index(report_context,
                    ({**chat, "message_count": chat_counts.get(chat["id"], 0)} for chat in selected)))
                if job["options"].get("export_format", "tgwitness") != "tgwitness":
                    from .telegram_export import DesktopExport
                    desktop = DesktopExport(directory, self.inventory, self.receipts, job, self.current["coverage"])
                    try:
                        if job["options"]["export_format"] in ("telegram_json", "telegram_both"):
                            write("result.json", desktop.json())
                        if job["options"]["export_format"] in ("telegram_html", "telegram_both"):
                            for name, content in desktop.html():
                                write(name, content)
                    finally:
                        desktop.close()
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
                    "created_at": job["created_at"], "completed_at": utcnow(), "status": "done" if self.complete() else "partial",
                    "complete_within_scope": self.complete(), "coverage": self.current["coverage"],
                    "counts": self.current["counts"], "receipt_count": len(self.receipts), "receipt_head_sha256": self.head,
                    "files": hashes, "limitations": LIMITATIONS, "producer": producer(),
                    "case_assessment": account_report.case_assessment.snapshot(report_context)}
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
