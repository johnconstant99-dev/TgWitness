"""Concurrent chat exports with per-account reservations and signed checkpoints."""
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
import time
from contextlib import suppress
from datetime import datetime, timedelta
from collections import deque
from itertools import chain, islice

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from telethon import errors as telegram_errors, utils
from telethon.errors import TypeNotFoundError
from telethon.tl import types

from . import chat_export, replica, report, tuning
from .account_export import durable_write, linked, read_json
from .collector import AUTHORIZATION_ERRORS, message_record, unparsed_record
from .export_timing import ExportTiming
from .distributed_takeout import HistoryTakeout
from .distributed_pages import FORMAT as PAGE_FORMAT, RangePages
from .message_selection import Selection, SelectionIndex, utc
from .message_numbers import MissingNumbers
from .monitoring import capture_settings
from .store import canonical, utcnow
from .verify import fingerprint, verify_chat_export
from .workers import complete_in_thread

CHUNK = 2000
PAGE_TIMEOUT = 60
OUTAGE_RETRIES = 4
OUTAGE_PAUSE = 30
POISON_ACCOUNTS = 2
ACCOUNT_ERRORS = 3
RECHECK_EDGE = 1000
RECHECK_PER_ACCOUNT = 1000
RECORD_BYTES = 1024
WORKING_COPIES = 5
ACTIVE = ("preparing", "running", "selecting", "packaging")
JOB_ID = re.compile(r"[a-f0-9]{32}")


def verified(path, public):
    envelope = read_json(path)
    if envelope["public_key"] != public:
        raise ValueError("Export signing identity changed.")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(envelope["statement"]))
    return envelope["statement"]


class DistributedExport:
    def __init__(self, profiles):
        self.profiles = profiles
        self.root = profiles.app.state.store.root / "distributed-exports"
        if linked(self.root):
            raise ValueError("Distributed-export storage must not be a link.")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.runs = {}
        self.reserved = {}

    def app_for(self, profile):
        entry = self.profiles.entries.get(profile)
        if not entry or entry.get("app") is None:
            raise ValueError("Unknown or unavailable account workspace.")
        return entry["app"]

    def directory(self, job_id):
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise ValueError("Unknown distributed export.")
        path = self.root / job_id
        if linked(path) or path.resolve().parent != self.root.resolve():
            raise ValueError("Export directory must remain inside its workspace.")
        if any(linked(path / name) for name in ("chunks", "receipts", "media", "pages")):
            raise ValueError("Export working directories must not be links.")
        return path

    def uses(self, profile):
        return profile in self.reserved

    def public(self, job_id=None, chat_id=None):
        if job_id is None:
            jobs = [state for state in self.list_jobs() if chat_id in (None, state["chat_id"])]
            return next((state for state in jobs if state["phase"] in ACTIVE), jobs[0] if jobs else {"phase": "none"})
        if job_id in self.runs:
            self.runs[job_id].update_timing()
            return json.loads(json.dumps(self.runs[job_id].state))
        path = self.directory(job_id) / "status.json"
        if not path.is_file():
            return {"phase": "unknown"}
        envelope = read_json(path)
        state = envelope["statement"]
        public = self.app_for(state["lead"]).state.vault.public_key
        state = verified(path, public)
        if state["phase"] in ACTIVE:
            state.update(phase="paused", error="The process stopped. Resume verifies saved chunks first.")
        return state

    def list_jobs(self):
        items = []
        for path in self.root.iterdir():
            if path.is_dir() and JOB_ID.fullmatch(path.name):
                try:
                    state = self.public(path.name)
                    if state.get("id"):
                        items.append(state)
                except (ValueError, OSError, KeyError, InvalidSignature):
                    continue
        return sorted(items, key=lambda s: s["started_at"], reverse=True)

    def reserve(self, profiles, owner):
        try:
            for profile in profiles:
                app = self.app_for(profile)
                collector = app.state.collector
                if not app.state.vault.read("credentials").get("session"):
                    raise ValueError("Connect every selected Telegram account before exporting.")
                if collector.store.get_setting("rpc_backoff_until", 0) > time.time():
                    label = self.profiles.entries[profile].get("label", profile)
                    raise ValueError(label + ": Telegram requests are paused. Check the saved rate-limit deadline in connection details.")
                if not collector.reserve_export(owner):
                    label = self.profiles.entries[profile].get("label", profile)
                    raise ValueError(label + ": account is busy. Pause its current task explicitly or deselect it.")
                self.reserved[profile] = (owner, collector)
        except BaseException:
            self.release(owner)
            raise

    def release(self, owner):
        for profile, (claim, collector) in list(self.reserved.items()):
            if claim == owner:
                collector.release_export(owner)
                del self.reserved[profile]

    async def start(self, chat_id, profile_ids, lead_id, language="en", selection=None, transport="regular"):
        if transport not in ("regular", "takeout"):
            raise ValueError("Unknown export transport.")
        options = Selection.model_validate(selection or {})
        chosen = list(dict.fromkeys([lead_id, *profile_ids]))
        export_id = secrets.token_hex(16)
        self.reserve(chosen, export_id)
        timing = ExportTiming()
        try:
            lead_app = self.app_for(lead_id)
            lead = lead_app.state.collector
            entity = await lead.resolve_for_export(chat_id)
            if transport == "takeout" and (not isinstance(entity, types.Channel) or not getattr(entity, "username", None)):
                raise ValueError("Distributed Takeout currently supports public channels and supergroups only.")
            if len(chosen) > 1 and not isinstance(entity, types.Channel):
                raise ValueError("Only one account can export an ordinary group or private chat.")
            now = utc(utcnow())
            scan_end = options.to_utc if options.reply_scope == "period" else None
            scan_end = min(scan_end, now) if scan_end else now
            username = getattr(entity, "username", None)
            workers, bounds, densities, entities = [], [], [], {}
            for profile in chosen:
                app = self.app_for(profile)
                collector = app.state.collector
                worker = {"profile_id": profile, "label": self.profiles.entries[profile].get("label", profile),
                          "account_id": (app.state.store.get_setting("account", {}) or {}).get("id"),
                          "public_key": app.state.vault.public_key, "state": "pending", "captured": 0,
                          "ranges": 0, "wait_until": None, "error": None}
                try:
                    peer = entity if profile == lead_id else await collector.resolve_for_export(chat_id, username)
                    try:
                        latest = await collector.client.get_messages(peer, limit=1,
                            offset_date=datetime.fromisoformat(scan_end))
                        upper = latest[0].id if latest else 0
                        count = getattr(latest, "total", None)
                    except TypeNotFoundError:
                        upper = await collector.number_before(peer, datetime.fromisoformat(scan_end))
                        count = None
                    if type(count) is int and count > 0:
                        # Planning only: this is not a count for the selected dates,
                        # nor evidence of deletion. Keep every ID in the plan.
                        densities.append(max(1, upper // count))
                        worker.update(planning_count=count, planning_count_scope="visible history estimate; precision unknown")
                    lower = 1
                    if upper and options.from_utc:
                        # Telegram can include messages exactly at offset_date.
                        # Read past the boundary; local selection applies [from, until).
                        lower = await collector.number_before(peer,
                            datetime.fromisoformat(options.from_utc) - timedelta(seconds=1)) + 1
                    if upper >= lower:
                        bounds.append((lower, upper, profile))
                    worker.update(low=lower, high=upper)
                    entities[profile] = peer
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    worker.update(state="skipped", error=type(exc).__name__,
                                  reason=str(exc) if isinstance(exc, ValueError) else None)
                workers.append(worker)
            if lead_id not in entities:
                lead_worker = next(w for w in workers if w["profile_id"] == lead_id)
                raise ValueError("The starting account cannot read this chat: "
                                 + (lead_worker.get("reason") or lead_worker.get("error") or "unknown reason") + ".")
            cuts = sorted({edge for low, high, _ in bounds for edge in (low, high + 1)})
            segments = []
            for low, end in zip(cuts, cuts[1:]):
                eligible = [p for left, right, p in bounds if left <= low and end - 1 <= right]
                if eligible:
                    segments.append({"low": low, "high": end - 1, "profiles": eligible})
            total = next((worker.get("planning_count") for worker in workers
                          if worker["profile_id"] == lead_id), None)
            if total is None and segments:
                try:
                    total = (await lead.client.get_messages(entity, limit=0)).total
                except Exception:
                    total = None
            if type(total) is not int or total < 0:
                total = None
            messages = sum(s["high"] - s["low"] + 1 for s in segments)
            messages = min(messages, total) if total is not None else messages
            needed = messages * RECORD_BYTES * WORKING_COPIES + lead.param("media_min_free_mb") * 1024**2
            free = shutil.disk_usage(self.root).free
            if free < needed:
                raise ValueError("Not enough free disk space for this export. Free up space or choose a shorter period.")
            info = lead.dialog_cache.get(chat_id, {})
            chunk_size = CHUNK * min(50, min(densities, default=1))
            state = {"id": export_id, "chat_id": chat_id, "title": info.get("title"), "lead": lead_id,
                          "phase": "preparing", "started_at": now, "workers": workers,
                          "captured": 0, "ranges_done": 0, "ranges_total": sum(
                              (s["high"] - s["low"]) // chunk_size + 1 for s in segments),
                          "total": None, "eta_seconds": None, "ready": False, "error": None,
                          "selection": options.model_dump(), "counts": {}, "transport": transport}
            job = {"format": "tgwitness-distributed-job-v1", "id": export_id, "chat_id": chat_id,
                        "lead": lead_id, "started_at": now, "scan_end": scan_end, "username": username,
                        "chunk_size": chunk_size, "segments": segments, "workers": [dict(w) for w in workers],
                        "transport": transport, "megagroup": bool(getattr(entity, "megagroup", False)),
                        "checkpoint_format": PAGE_FORMAT,
                        "selection": options.model_dump(), "report": report.resolved(lead.store, language),
                        "chat": {"id": chat_id, "title": info.get("title"), "kind": info.get("kind")}}
            state["disk"] = {"estimated_messages": messages, "needed_bytes": needed, "free_bytes": free}
            run = Run(self, state, job, timing=timing)
            run.entities = entities
            directory = self.directory(export_id)
            directory.mkdir(mode=0o700)
            for folder in ("chunks", "receipts", "media", "pages"):
                (directory / folder).mkdir(mode=0o700)
            durable_write(directory / "job.json", canonical(run.signed(job)))
            run.persist()
            self.launch(run)
            return self.public(export_id)
        except BaseException:
            self.release(export_id)
            raise

    def launch(self, run):
        owner = run.state["id"]
        self.runs[owner] = run
        run.task = asyncio.create_task(run.run())
        run.task.add_done_callback(lambda _: self.release(owner))

    async def resume(self, job_id):
        state = self.public(job_id)
        if state.get("phase") not in ("paused", "failed", "cancelled"):
            raise ValueError("This export is not available to resume.")
        public = self.app_for(state["lead"]).state.vault.public_key
        job = verified(self.directory(job_id) / "job.json", public)
        active = [w for w in job["workers"] if w["state"] != "skipped"]
        for worker in active:
            app = self.app_for(worker["profile_id"])
            if (app.state.vault.public_key != worker["public_key"] or
                    (app.state.store.get_setting("account", {}) or {}).get("id") != worker["account_id"]):
                raise ValueError("A participating account or signing identity has changed.")
        self.reserve([w["profile_id"] for w in active], job_id)
        try:
            state.update(phase="preparing", ready=False, error=None, wait_until=None, approval_profile=None)
            state["workers"] = [{**w, "state": "pending" if w["state"] != "skipped" else "skipped",
                                 "wait_until": None} for w in job["workers"]]
            run = Run(self, state, job)
            run.persist()
            self.launch(run)
            return self.public(job_id)
        except BaseException:
            self.release(job_id)
            raise

    def poll(self, job_id):
        return self.public(job_id)

    async def pause(self, job_id):
        run = self.runs.get(job_id)
        if run and run.active():
            run.task.cancel()
            await asyncio.gather(run.task, return_exceptions=True)
            if run.state["phase"] not in ("done", "failed", "paused"):
                run.state.update(phase="paused", ready=False, error="Paused; committed chunks are retained.")
                run.set_phase("paused")
                run.persist()
        return self.public(job_id)

    async def cancel(self, job_id):
        state = await self.pause(job_id)
        if state.get("phase") not in ("done", "unknown", *ACTIVE):
            run = Run(self, {**state, "phase": "cancelled"})
            run.persist()
            self.runs[job_id] = run
        return self.public(job_id)

    def result_path(self, job_id):
        state = self.public(job_id)
        path = self.directory(job_id) / "export.zip"
        return path if state.get("ready") and path.is_file() and not path.is_symlink() else None

    async def close(self):
        for job_id in list(self.runs):
            await self.pause(job_id)


class Run:
    """Keep one export's workers, progress and recovery state together."""

    def __init__(self, exports, state, job=None, *, timing=None):
        self.app_for, self.directory = exports.app_for, exports.directory
        self.state, self.job = state, job
        self.task = self.db = self.recheck = None
        self.chunk_failures, self.entities = {}, {}
        self.history_transports, self.page_states = {}, {}
        self.timing = (timing or ExportTiming()) if job is not None else None

    def update_timing(self):
        if self.timing is not None and self.state is not None:
            self.state["performance"] = self.timing.snapshot(self.state["captured"])

    def set_phase(self, phase):
        self.state["phase"] = phase
        if self.timing is not None:
            self.timing.move(phase)
        self.update_timing()

    def active(self):
        return bool(self.task and not self.task.done())

    def signed(self, value, vault=None):
        vault = vault or self.app_for(self.state["lead"]).state.vault
        return {"statement": value, "public_key": vault.public_key, "signature": vault.sign(canonical(value))}

    def persist(self):
        self.update_timing()
        self.state["updated_at"] = utcnow()
        durable_write(self.directory(self.state["id"]) / "status.json", canonical(self.signed(self.state)))

    def prepare_chunks(self):
        directory = self.directory(self.state["id"])
        retained_count = self.state["captured"]
        if self.job.get("checkpoint_format") not in (None, PAGE_FORMAT):
            raise ValueError("Unsupported distributed checkpoint format.")
        self.page_states = {}
        path = directory / "work.sqlite3"
        if linked(path):
            raise ValueError("Export index must not be a link.")
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("DROP TABLE IF EXISTS tasks; DROP TABLE IF EXISTS eligible; "
            "CREATE TABLE tasks(low INTEGER PRIMARY KEY, high INTEGER, phase TEXT, profile TEXT, count INTEGER, sha256 TEXT);"
            "CREATE TABLE eligible(low INTEGER,profile TEXT,PRIMARY KEY(profile,low));")
        for segment in self.job["segments"]:
            for low in range(segment["low"], segment["high"] + 1, self.job["chunk_size"]):
                high = min(segment["high"], low + self.job["chunk_size"] - 1)
                self.db.execute("INSERT INTO tasks VALUES(?,?,'pending',NULL,0,NULL)", (low, high))
                self.db.executemany("INSERT INTO eligible VALUES(?,?)", [(low, p) for p in segment["profiles"]])
        if self.job.get("checkpoint_format") == PAGE_FORMAT:
            for folder in (directory / "pages").iterdir():
                if not folder.name.isdigit() or linked(folder) or not folder.is_dir():
                    raise ValueError("Invalid checkpoint directory.")
                task = self.db.execute("SELECT * FROM tasks WHERE low=?", (int(folder.name),)).fetchone()
                if not task or folder.name != str(task["low"]):
                    raise ValueError("Checkpoint range is outside the signed plan.")
                pages = RangePages(directory, self.job, task)
                self.page_states[task["low"]] = pages
                if pages.state["profile_id"] is not None:
                    self.record_page(task["low"], pages.state)
        by_profile = {w["profile_id"]: w for w in self.job["workers"]}
        for receipt in (directory / "receipts").glob("*.json"):
            if not receipt.stem.isdigit() or linked(receipt):
                raise ValueError("Invalid chunk receipt path.")
            envelope = read_json(receipt)
            profile = envelope["statement"]["profile_id"]
            value = verified(receipt, by_profile[profile]["public_key"])
            if receipt.stem != str(value["low"]):
                raise ValueError("Chunk receipt filename differs from its signed range.")
            task = self.db.execute("SELECT * FROM tasks WHERE low=? AND high=?", (value["low"], value["high"])).fetchone()
            if not task or value["job_id"] != self.job["id"] or not self.db.execute(
                    "SELECT 1 FROM eligible WHERE low=? AND profile=?", (value["low"], profile)).fetchone():
                raise ValueError("Chunk receipt does not belong to the signed acquisition plan.")
            if self.job.get("transport", "regular") == "takeout" and (value.get("transport") != "takeout"
                    or type(value.get("transport_generation")) is not int or value["transport_generation"] < 1):
                raise ValueError("Chunk receipt does not identify its Takeout generation.")
            if self.job.get("checkpoint_format") == PAGE_FORMAT:
                pages = self.page_states.get(value["low"])
                if (not pages or not pages.state["terminal"] or pages.state["profile_id"] != profile
                        or value.get("checkpoint") != self.page_summary(pages.state)
                        or value.get("transport", "regular") != self.job.get("transport", "regular")
                        or value.get("transport_generation") != pages.state["transport_generation"]):
                    raise ValueError("Chunk receipt differs from its signed checkpoints.")
            count, digest = self.check_chunk(directory / "chunks" / (str(value["low"]) + ".jsonl"), task)
            if (count, digest) != (value["count"], value["sha256"]):
                raise ValueError("Saved chunk differs from its signed receipt.")
            self.db.execute("UPDATE tasks SET phase='done',profile=?,count=?,sha256=? WHERE low=?",
                            (profile, count, digest, value["low"]))
        self.db.commit()
        verified_count = self.db.execute("SELECT coalesce(sum(count),0) FROM tasks").fetchone()[0]
        if self.job.get("checkpoint_format") == PAGE_FORMAT and verified_count < retained_count:
            raise ValueError("Saved checkpoint progress is missing; preserve this job for inspection.")
        self.update_counts()

    @staticmethod
    def check_chunk(path, task):
        if linked(path):
            raise ValueError("Chunk must not be a link.")
        digest, count, previous = hashlib.sha256(), 0, task["high"] + 1
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                mid = record["id"]
                if type(mid) is not int or not task["low"] <= mid < previous:
                    raise ValueError("Chunk messages are outside their range or repeated.")
                digest.update(canonical(record) + b"\n")
                count, previous = count + 1, mid
        return count, digest.hexdigest()

    def update_counts(self):
        count, captured = self.db.execute("SELECT coalesce(sum(phase='done'),0),coalesce(sum(count),0) FROM tasks").fetchone()
        self.state.update(ranges_done=count, captured=captured)
        for worker in self.state["workers"]:
            ranges, messages = self.db.execute("SELECT coalesce(sum(phase='done'),0),coalesce(sum(count),0) FROM tasks "
                "WHERE profile=?", (worker["profile_id"],)).fetchone()
            worker.update(ranges=ranges, captured=messages)

    @staticmethod
    def page_summary(state):
        return {"format": PAGE_FORMAT, "pages": state["pages"], "head_sha256": state["head_sha256"],
                "count": state["count"], "byte_end": state["byte_end"]}

    def record_page(self, low, state):
        self.db.execute("UPDATE tasks SET profile=?,count=? WHERE low=?", (state["profile_id"], state["count"], low))
        self.db.execute("DELETE FROM eligible WHERE low=? AND profile!=?", (low, state["profile_id"]))
        self.db.commit()

    async def work(self, worker):
        await self.read_ranges(worker)

    async def read_ranges(self, worker):
        profile = worker["profile_id"]
        collector = self.app_for(profile).state.collector
        directory = self.directory(self.state["id"])
        worker["state"] = "running"
        outages = errors = 0
        while True:
            task = self.db.execute("SELECT t.* FROM tasks t JOIN eligible e USING(low) WHERE e.profile=? "
                                   "AND t.phase='pending' ORDER BY low DESC LIMIT 1", (profile,)).fetchone()
            if not task:
                if self.db.execute("SELECT 1 FROM tasks WHERE phase='running' LIMIT 1").fetchone():
                    await asyncio.sleep(.1)
                    continue
                worker["state"] = "done"
                return
            self.db.execute("UPDATE tasks SET phase='running' WHERE low=?", (task["low"],))
            self.db.commit()
            path = directory / "chunks" / (str(task["low"]) + ".jsonl")
            temporary = path.with_suffix(".part")
            worker["current_range"] = [task["low"], task["high"]]
            def waiting(seconds):
                worker.update(state="waiting", wait_until=time.time() + seconds)
            transport = self.history_transports.get(profile)
            try:
                if shutil.disk_usage(directory).free < collector.param("media_min_free_mb") * 1024**2:
                    raise ValueError("Insufficient free disk space for another chunk.")
                if linked(temporary) or linked(path):
                    raise ValueError("Chunk paths must not be links.")
                pages = None
                if self.job.get("checkpoint_format") == PAGE_FORMAT:
                    pages = self.page_states.get(task["low"])
                    if pages is None:
                        pages = self.page_states[task["low"]] = RangePages(directory, self.job, task)
                    def committed(state):
                        self.record_page(task["low"], state)
                        worker.update(state="running", wait_until=None)
                        self.update_counts()
                        self.persist()
                    await pages.fetch(collector, self.entities[profile], profile, committed, waiting, transport,
                                      page_timeout=PAGE_TIMEOUT, attempts=1)
                    if await complete_in_thread(pages.verify) != pages.state:
                        raise ValueError("Checkpoint data changed during acquisition.")
                    count, digest = await complete_in_thread(self.check_chunk, path, task)
                else:
                    await collector.fetch_range(self.entities[profile], task["low"], task["high"], temporary,
                                                lambda: None, waiting, page_timeout=PAGE_TIMEOUT, attempts=1,
                                                **({"history_client": transport.client} if transport else {}))
                    count, digest = self.check_chunk(temporary, task)
                    with temporary.open("r+b") as stream:
                        os.fsync(stream.fileno())
                    temporary.replace(path)
                receipt = {"job_id": self.job["id"], "low": task["low"], "high": task["high"],
                           "profile_id": profile, "count": count, "sha256": digest, "observed_at": utcnow()}
                if transport:
                    receipt.update(transport="takeout", transport_generation=pages.state["transport_generation"] if pages
                                   else transport.secret["generations"][-1]["generation"])
                if pages:
                    receipt["checkpoint"] = self.page_summary(pages.state)
                durable_write(directory / "receipts" / (str(task["low"]) + ".json"),
                              canonical(self.signed(receipt, collector.vault)))
                self.db.execute("UPDATE tasks SET phase='done',profile=?,count=?,sha256=? WHERE low=?",
                                (profile, count, digest, task["low"]))
                self.db.commit()
                worker.update(state="running", wait_until=None)
                self.update_counts()
                self.persist()
            except asyncio.CancelledError:
                raise
            except telegram_errors.TakeoutInvalidError:
                if transport:
                    transport.invalidate()
                raise
            except Exception as exc:
                self.db.execute("UPDATE tasks SET phase='pending' WHERE low=?", (task["low"],))
                self.db.commit()
                if isinstance(exc, OSError) and (exc.filename is not None or exc.errno in {
                        errno.ENOSPC, errno.EDQUOT, errno.EROFS, errno.EACCES, errno.EPERM, errno.EIO}):
                    raise
                if isinstance(exc, (OSError, ConnectionError, TimeoutError)) and outages < OUTAGE_RETRIES:
                    outages += 1
                    pause = min(300, OUTAGE_PAUSE * 2 ** (outages - 1))
                    worker.update(state="waiting", wait_until=time.time() + pause, error="no_connection")
                    self.persist()
                    await asyncio.sleep(pause)
                    worker.update(state="running", wait_until=None, error=None)
                    continue
                reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
                failed = self.chunk_failures.setdefault(task["low"], {})
                failed[profile] = reason
                self.db.execute("DELETE FROM eligible WHERE low=? AND profile=?", (task["low"], profile))
                if len(failed) >= POISON_ACCOUNTS:
                    self.db.execute("UPDATE tasks SET phase='failed' WHERE low=?", (task["low"],))
                errors += 1
                if isinstance(exc, AUTHORIZATION_ERRORS + (OSError, ConnectionError, TimeoutError)) or errors > ACCOUNT_ERRORS:
                    self.db.execute("DELETE FROM eligible WHERE profile=?", (profile,))
                    self.db.commit()
                    worker.update(state="failed", error=type(exc).__name__, reason=reason)
                    return
                self.db.commit()
                continue
            finally:
                temporary.unlink(missing_ok=True)
            outages = errors = 0
            await asyncio.sleep(0)

    async def context(self, index, options):
        for depth in range(1, options.context_depth + 1):
            missing = index.expand(options, depth)
            fetched = set()
            for row in missing:
                if (row["parent_chat"], row["parent"]) in fetched:
                    continue
                fetched.add((row["parent_chat"], row["parent"]))
                reason = "outside_selected_source"
                if row["parent_chat"] == self.job["chat_id"]:
                    profile = row["profile"]
                    collector = self.app_for(profile).state.collector
                    message = await collector.client.get_messages(self.entities[profile], ids=row["parent"])
                    if message and not isinstance(message, types.MessageEmpty):
                        if message.id != row["parent"] or utils.get_peer_id(message.peer_id) != self.job["chat_id"]:
                            raise ValueError("Context reply belongs to a different message or source.")
                        index.add(message_record(message), profile)
                        index.db.execute("UPDATE messages SET selected=1,depth=? WHERE id=?", (depth, message.id))
                        continue
                    reason = "unavailable_to_fetching_account"
                index.db.execute("UPDATE messages SET missing_parent=? WHERE parent=? AND parent_chat=?",
                                 (reason, row["parent"], row["parent_chat"]))
            index.db.commit()

    async def finish_selection(self, directory, options):
        index_path = directory / "selection.sqlite3"
        if linked(index_path):
            raise ValueError("Selection index must not be a link.")
        index = SelectionIndex(index_path, self.job["chat_id"])
        try:
            index.db.execute("DELETE FROM messages")
            for task in self.db.execute("SELECT * FROM tasks ORDER BY low DESC"):
                path = directory / "chunks" / (str(task["low"]) + ".jsonl")
                if self.check_chunk(path, task) != (task["count"], task["sha256"]):
                    raise ValueError("Acquired chunk changed before selection.")
                with path.open(encoding="utf-8") as stream:
                    for line in stream:
                        index.add(json.loads(line), task["profile"])
                index.db.commit()
                await asyncio.sleep(0)
            self.recheck = await self.recheck_absent(index, options)
            batches = index.classify_batches(options)
            uncertain = 0
            while (result := await complete_in_thread(next, batches, None)) is not None:
                uncertain = result
            await self.context(index, options)
            self.state["counts"] = {**index.counts(), "uncertain_language": uncertain}
            self.state["counts"]["context_limit_reached"] = bool(options.context_depth and
                self.state["counts"]["context"] >= options.max_context_messages)
            scratch = directory / "selected.jsonl"
            ranges, current = [], None
            with scratch.open("w", encoding="utf-8") as output:
                for record, profile in index.output():
                    if options.download_media and record.get("media_type"):
                        collector = self.app_for(profile).state.collector
                        message = await collector.client.get_messages(self.entities[profile], ids=record["id"])
                        stored = json.loads(index.db.execute(
                            "SELECT record FROM messages WHERE id=?", (record["id"],)).fetchone()[0])
                        stored.pop("found_on_recheck", None)
                        if message and message_record(message) == stored:
                            record.update(await collector.export_attachment(message, directory / "media"))
                        else:
                            record["file_status"] = "message_changed_or_unavailable_at_media_read"
                    encoded = canonical(record) + b"\n"
                    output.write(encoded.decode())
                    if current is None or current["profile_id"] != profile:
                        current = {"profile_id": profile, "low": record["id"], "high": record["id"],
                                   "count": 0, "digest": hashlib.sha256()}
                        ranges.append(current)
                    current["low"] = record["id"]
                    current["count"] += 1
                    current["digest"].update(encoded)
                    await asyncio.sleep(0)
            for part in ranges:
                part["sha256"] = part.pop("digest").hexdigest()
            return scratch, ranges
        finally:
            index.close()

    async def recheck_absent(self, index, options):
        if options.excludes_messages() or self.job["chat_id"] >= -1000000000000:
            return None
        present = [row[0] for row in index.db.execute("SELECT id FROM messages ORDER BY id")]
        if not present:
            return None
        edge = list(range(max(1, present[0] - RECHECK_EDGE), present[0]))
        gaps = MissingNumbers(present)
        if not edge and not gaps:
            return None
        readers = [w["profile_id"] for w in self.state["workers"]
                   if w["state"] not in ("skipped", "failed") and w["profile_id"] in self.entities]
        wanted = len(edge) + len(gaps)
        budget = len(gaps) if options.recheck_all else max(0, RECHECK_PER_ACCOUNT * len(readers) - len(edge))
        step = max(1, -(-len(gaps) // budget)) if budget else len(gaps) + 1
        planned = len(edge) + min(budget, -(-len(gaps) // step))
        numbers = chain(edge, islice(gaps.sample(step), budget))
        queue = deque()
        found, errors, started = {}, {}, utcnow()
        progress = self.state["recheck"] = {"asked": 0, "total": planned}

        async def read(profile):
            collector = self.app_for(profile).state.collector
            while True:
                batch = queue.popleft() if queue else list(islice(numbers, 100))
                if not batch:
                    return
                try:
                    answer = await collector.read_numbers(self.entities[profile], batch)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    errors[profile] = type(exc).__name__
                    queue.append(batch)
                    return
                for number, value in answer.items():
                    found[number] = (value, profile)
                progress["asked"] += len(batch)
        await asyncio.gather(*(read(profile) for profile in readers))
        for number, (value, profile) in sorted(found.items()):
            record = unparsed_record(number, value) if isinstance(value, TypeNotFoundError) else message_record(value)
            index.add({**record, "found_on_recheck": True}, profile)
        index.db.commit()
        checked = progress["asked"]
        returned = sorted(found)
        return {"asked_at": started, "asked": checked, "absent_total": len(gaps), "empty": checked - len(returned),
                "returned": returned, "unchecked": wanted - checked, "limit_reached": wanted > planned,
                "sampling": "every number" if planned == wanted else "every " + str(step) + "th absent number",
                "edge": [edge[0], edge[-1]] if edge else None,
                "edge_found": sum(1 for number in returned if number < present[0]),
                "accounts": len(readers), **({"errors": errors} if errors else {}),
                "method": "channels.getMessages by number, shared by the accounts of this export",
                "meaning": "An empty answer means Telegram has no message under that number for these accounts: "
                           "deleted, or never visible to them. Telegram does not say which. Unchecked numbers "
                           "cannot be told apart from deleted ones."}

    def sign_parts(self, ranges):
        parts = []
        for profile in dict.fromkeys(p["profile_id"] for p in ranges):
            vault = self.app_for(profile).state.vault
            worker = next(w for w in self.job["workers"] if w["profile_id"] == profile)
            statement = {"format": "tgwitness-chat-part-v1", "export_id": self.job["id"],
                         "chat_id": self.job["chat_id"], "account_id": worker["account_id"],
                         "fetched_by_public_key": vault.public_key, "signed_at": utcnow(),
                         "selection": self.job["selection"],
                         "ranges": [{k: p[k] for k in ("low", "high", "count", "sha256")}
                                    for p in ranges if p["profile_id"] == profile]}
            parts.append({"statement": statement, "signature": vault.sign(canonical(statement)),
                          "fingerprint": fingerprint(vault.public_key)})
        return parts

    def clean(self):
        directory = self.directory(self.state["id"])
        for name in ("chunks", "receipts", "media", "pages"):
            shutil.rmtree(directory / name, ignore_errors=True)
        for path in [*directory.glob("*.sqlite3*"), directory / "selected.jsonl"]:
            with suppress(OSError):
                path.unlink(missing_ok=True)

    async def run(self):
        directory = self.directory(self.state["id"])
        lead = self.app_for(self.job["lead"]).state.collector
        self.history_transports = {}
        try:
            await complete_in_thread(self.prepare_chunks)
            self.chunk_failures = {}
            self.timing.baseline = self.state["captured"]
            for worker in self.job["workers"]:
                profile_id = worker["profile_id"]
                if worker["state"] != "skipped" and profile_id not in self.entities:
                    self.entities[profile_id] = await self.app_for(profile_id).state.collector.resolve_for_export(
                        self.job["chat_id"], self.job["username"])
                if worker["state"] != "skipped" and self.job.get("transport") == "takeout":
                    network = HistoryTakeout(self.app_for(profile_id).state.collector, self.job["id"],
                                             worker["account_id"], self.job["megagroup"])
                    self.history_transports[profile_id] = network
                    if self.db.execute("SELECT 1 FROM tasks t JOIN eligible e USING(low) "
                                       "WHERE e.profile=? AND t.phase!='done' LIMIT 1", (profile_id,)).fetchone():
                        await network.open()
            clock = await lead.telegram_clock()
            capture = capture_settings(lead.store)
            profile, observer, problems = await lead.chat_profile(self.entities[self.job["lead"]],
                include_photo=bool(self.job["selection"].get("download_media")
                                   and capture["download_media"] and capture["include_avatars"]))
            log = await lead.admin_log(self.entities[self.job["lead"]]) if observer.get("role") in ("admin", "creator") else None
            self.set_phase("running")
            self.persist()
            workers = [asyncio.create_task(self.work(w)) for w in self.state["workers"] if w["state"] != "skipped"]
            try:
                await asyncio.gather(*workers)
            finally:
                for task in workers:
                    if not task.done() and not task.cancelling():
                        task.cancel()
                drained = asyncio.gather(*workers, return_exceptions=True)
                interrupted = False
                while not drained.done():
                    try:
                        await asyncio.shield(drained)
                    except asyncio.CancelledError:
                        interrupted = True
                if interrupted:
                    raise asyncio.CancelledError
            stuck = self.db.execute("SELECT low, high FROM tasks WHERE phase='failed' ORDER BY low DESC").fetchall()
            if stuck:
                low, high = stuck[0]["low"], stuck[0]["high"]
                reasons = sorted(set(self.chunk_failures.get(low, {}).values()))
                raise ValueError("Message numbers " + str(low) + "–" + str(high) + (" and " + str(len(stuck) - 1)
                                 + " more ranges" if len(stuck) > 1 else "") + " failed on " + str(POISON_ACCOUNTS)
                                 + " different accounts (" + "; ".join(reasons) + "). The accounts were kept; "
                                 "saved chunks are retained.")
            if self.db.execute("SELECT 1 FROM tasks WHERE phase!='done' LIMIT 1").fetchone():
                raise ValueError("Some ranges could not be read. Saved chunks are retained; resume when accounts are available.")
            self.set_phase("selecting")
            self.persist()
            scratch, ranges = await self.finish_selection(directory, Selection.model_validate(self.job["selection"]))
            meta = {"chat": {**self.job["chat"], "profile": profile, "profile_errors": problems},
                    "observer": observer, "admin_log": log, "recheck": self.recheck,
                    "journal": chat_export.journal_changes(lead.store, self.job["chat_id"]),
                    "account": lead.store.get_setting("account", {}),
                    "client": lead.client_identity(), "route": lead.route_receipt(),
                    "message_count": self.state["counts"]["selected"], "parts": self.sign_parts(ranges),
                    "collection": {"mode": "distributed_selection", "selection": self.job["selection"],
                        "history_transport": self.job.get("transport", "regular"),
                        "counts": self.state["counts"], "scan_end": self.job["scan_end"],
                        "scope": "Selected messages and explicitly labelled context in the observed accessible ranges; "
                                 "reply absence is limited to the scanned scope; not an atomic snapshot."},
                    "acquisition": {"started_at": self.job["started_at"], "finished_at": utcnow(),
                                    "segments": self.job["segments"], "chunk_size": self.job["chunk_size"], "clock_at_start": clock,
                                    "clock_at_end": await lead.telegram_clock(),
                                    "clock_scope": "Current run; saved chunks retain their original local commit times."}}
            if self.job.get("checkpoint_format") == PAGE_FORMAT:
                meta["acquisition"]["checkpoints"] = {"format": PAGE_FORMAT, "max_messages": 100,
                    "pages": sum(p.state["pages"] for p in self.page_states.values()),
                    "scope": "Local decoded-message checkpoints, not RPC responses. Excluded records and page receipts "
                             "are not included in this archive. Working files are removed after successful archive "
                             "verification; selected messages have the archive's account signatures."}
            for profile_id, network in self.history_transports.items():
                try:
                    await network.finish()
                    self.state.get("transport_close_errors", {}).pop(profile_id, None)
                except (telegram_errors.RPCError, OSError, ConnectionError, TimeoutError) as exc:
                    self.state.setdefault("transport_close_errors", {})[profile_id] = type(exc).__name__
            if self.history_transports:
                meta["acquisition"]["history_transports"] = {p: n.public() for p, n in self.history_transports.items()}
                meta["acquisition"]["transport_close_errors"] = self.state.get("transport_close_errors", {})
            self.set_phase("packaging")
            self.persist()
            out = directory / "export.zip"
            max_gib = tuning.value(lead.store, "export_max_gib")
            names = await complete_in_thread(chat_export.journal_names, lead.store, self.job["chat_id"], scratch)
            await complete_in_thread(chat_export.build_bundle, scratch, meta, lead.vault, out,
                                     max_gib * 1024**3, self.job["report"], directory / "media", names)
            await complete_in_thread(verify_chat_export, out, fingerprint(lead.vault.public_key), max_gib)
            replica.outbox(lead.store, out)
            self.state.update(phase="done", ready=True, error=None, filename=chat_export.archive_name(
                lead.store, self.job["chat_id"], self.job["chat"]["title"]))
            self.set_phase("done")
            lead.store.append("chat_export.completed", {"export_id": self.job["id"], "mode": "distributed_selection",
                              "counts": self.state["counts"], "performance": self.state["performance"]}, self.job["chat_id"])
        except asyncio.CancelledError:
            self.state.update(phase="paused", ready=False, error="Paused; committed chunks are retained.")
            for worker in self.state["workers"]:
                if worker["state"] in ("pending", "running", "waiting"):
                    worker["state"] = "paused"
            raise
        except telegram_errors.TakeoutInitDelayError as exc:
            self.state.update(phase="paused", ready=False, wait_until=time.time() + exc.seconds,
                approval_profile=profile_id,
                error="Telegram Takeout approval is pending. Approve the export in Telegram or wait, then resume. "
                      "No regular-speed fallback was started.")
            waiting = next(w for w in self.state["workers"] if w["profile_id"] == profile_id)
            waiting.update(state="waiting", wait_until=self.state["wait_until"], error="Takeout approval required")
        except telegram_errors.TakeoutInvalidError:
            self.state.update(phase="paused", ready=False,
                error="Telegram ended the Takeout session. Resume validates a new session against the saved range.")
        except Exception as exc:
            self.state.update(phase="failed", ready=False,
                              error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        finally:
            if self.state["phase"] == "paused":
                for worker in self.state["workers"]:
                    if worker["state"] in ("pending", "running", "waiting"):
                        worker["state"] = "paused"
            self.set_phase(self.state["phase"])
            if self.db:
                self.db.close()
                self.db = None
            self.persist()
            if self.state["phase"] == "done":
                self.clean()
