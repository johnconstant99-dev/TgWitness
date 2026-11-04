"""Durable, exclusive multi-account acquisition and local message selection."""
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
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from telethon import utils
from telethon.tl import types

from . import chat_export, replica, report, tuning
from .account_export import durable_write, linked, read_json
from .collector import message_record
from .message_selection import Selection, SelectionIndex, utc
from .store import canonical, utcnow
from .verify import fingerprint, verify_chat_export
from .workers import complete_in_thread

CHUNK = 2000
JOB_ID = re.compile(r"[a-f0-9]{32}")


class DistributedExport:
    def __init__(self, profiles):
        self.profiles = profiles
        self.root = profiles.app.state.store.root / "distributed-exports"
        if linked(self.root):
            raise ValueError("Distributed-export storage must not be a link.")
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.state = self.job = self.task = self.db = None
        self.preparing = set()
        self.reserved = {}
        self.entities = {}
        latest = self.list_jobs()
        if latest:
            self.state = latest[0]

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
        if any(linked(path / name) for name in ("chunks", "receipts", "media")):
            raise ValueError("Export working directories must not be links.")
        return path

    def busy(self):
        return bool(self.preparing or self.task and not self.task.done())

    def uses(self, profile):
        return profile in self.reserved or profile in self.preparing

    def signed(self, value, vault=None):
        vault = vault or self.app_for(self.state["lead"]).state.vault
        return {"statement": value, "public_key": vault.public_key, "signature": vault.sign(canonical(value))}

    def verified(self, path, public):
        envelope = read_json(path)
        if envelope["public_key"] != public:
            raise ValueError("Export signing identity changed.")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
            base64.b64decode(envelope["signature"], validate=True), canonical(envelope["statement"]))
        return envelope["statement"]

    def persist(self):
        self.state["updated_at"] = utcnow()
        durable_write(self.directory(self.state["id"]) / "status.json", canonical(self.signed(self.state)))

    def public(self, job_id=None):
        if job_id is None or self.state and job_id == self.state["id"]:
            return json.loads(json.dumps(self.state)) if self.state else {"phase": "none"}
        path = self.directory(job_id) / "status.json"
        if not path.is_file():
            return {"phase": "unknown"}
        envelope = read_json(path)
        state = envelope["statement"]
        public = self.app_for(state["lead"]).state.vault.public_key
        state = self.verified(path, public)
        if state["phase"] in ("preparing", "running", "selecting", "packaging"):
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
        reserved = {}
        try:
            for profile in profiles:
                app = self.app_for(profile)
                collector = app.state.collector
                if not app.state.vault.read("credentials").get("session"):
                    raise ValueError("Connect every selected Telegram account before exporting.")
                if not collector.reserve_export(owner):
                    label = self.profiles.entries[profile].get("label", profile)
                    raise ValueError(label + ": account is busy. Pause its current task explicitly or deselect it.")
                reserved[profile] = collector
            self.reserved = reserved
        except BaseException:
            for collector in reserved.values():
                collector.release_export(owner)
            raise

    def release(self, owner):
        for profile, collector in list(self.reserved.items()):
            if collector.export_claim == owner:
                collector.release_export(owner)
                self.reserved.pop(profile, None)

    async def start(self, chat_id, profile_ids, lead_id, language="en", selection=None):
        options = Selection.model_validate(selection or {})
        if self.busy():
            raise ValueError("Pause the current distributed export before starting another.")
        chosen = list(dict.fromkeys([lead_id, *profile_ids]))
        export_id = secrets.token_hex(16)
        self.reserve(chosen, export_id)  # Atomic before the first await, including monitoring accounts.
        self.preparing = set(chosen)
        try:
            lead_app = self.app_for(lead_id)
            lead = lead_app.state.collector
            entity = await lead.resolve_for_export(chat_id)
            if len(chosen) > 1 and not isinstance(entity, types.Channel):
                raise ValueError("Only one account can export an ordinary group or private chat.")
            now = utc(utcnow())
            scan_end = options.to_utc if options.reply_scope == "period" else None
            scan_end = min(scan_end, now) if scan_end else now
            username = getattr(entity, "username", None)
            workers, bounds = [], []
            self.entities = {}
            for profile in chosen:
                app = self.app_for(profile)
                collector = app.state.collector
                worker = {"profile_id": profile, "label": self.profiles.entries[profile].get("label", profile),
                          "account_id": (app.state.store.get_setting("account", {}) or {}).get("id"),
                          "public_key": app.state.vault.public_key, "state": "pending", "captured": 0,
                          "ranges": 0, "wait_until": None, "error": None}
                try:
                    peer = entity if profile == lead_id else await collector.resolve_for_export(chat_id, username)
                    latest = await collector.client.get_messages(peer, limit=1,
                        offset_date=datetime.fromisoformat(scan_end))
                    upper = latest[0].id if latest else 0
                    lower = 1
                    if upper and options.from_utc:
                        before = await collector.client.get_messages(peer, limit=1,
                            offset_date=datetime.fromisoformat(options.from_utc))
                        lower = before[0].id + 1 if before else 1
                    if upper >= lower:
                        bounds.append((lower, upper, profile))
                    worker.update(low=lower, high=upper)
                    self.entities[profile] = peer
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    worker.update(state="skipped", error=type(exc).__name__)
                workers.append(worker)
            if lead_id not in self.entities:
                raise ValueError("The starting account cannot read this chat.")
            cuts = sorted({edge for low, high, _ in bounds for edge in (low, high + 1)})
            segments = []
            for low, end in zip(cuts, cuts[1:]):
                eligible = [p for left, right, p in bounds if left <= low and end - 1 <= right]
                if eligible:
                    segments.append({"low": low, "high": end - 1, "profiles": eligible})
            info = lead.dialog_cache.get(chat_id, {})
            self.state = {"id": export_id, "chat_id": chat_id, "title": info.get("title"), "lead": lead_id,
                          "phase": "preparing", "started_at": now, "workers": workers,
                          "captured": 0, "ranges_done": 0, "ranges_total": sum(
                              (s["high"] - s["low"]) // CHUNK + 1 for s in segments),
                          "total": None, "eta_seconds": None, "ready": False, "error": None,
                          "selection": options.model_dump(), "counts": {}}
            self.job = {"format": "tgwitness-distributed-job-v1", "id": export_id, "chat_id": chat_id,
                        "lead": lead_id, "started_at": now, "scan_end": scan_end, "username": username,
                        "chunk_size": CHUNK, "segments": segments, "workers": [dict(w) for w in workers],
                        "selection": options.model_dump(), "report": report.resolved(lead.store, language),
                        "chat": {"id": chat_id, "title": info.get("title"), "kind": info.get("kind")}}
            directory = self.directory(export_id)
            directory.mkdir(mode=0o700)
            for folder in ("chunks", "receipts", "media"):
                (directory / folder).mkdir(mode=0o700)
            durable_write(directory / "job.json", canonical(self.signed(self.job)))
            self.persist()
            self.launch()
            return self.public()
        except BaseException:
            self.release(export_id)
            raise
        finally:
            self.preparing.clear()

    def launch(self):
        self.task = asyncio.create_task(self.run())
        owner = self.state["id"]
        self.task.add_done_callback(lambda _: self.release(owner))

    async def resume(self, job_id):
        if self.busy():
            raise ValueError("Pause the current distributed export first.")
        state = self.public(job_id)
        if state.get("phase") not in ("paused", "failed", "cancelled"):
            raise ValueError("This export is not available to resume.")
        public = self.app_for(state["lead"]).state.vault.public_key
        job = self.verified(self.directory(job_id) / "job.json", public)
        active = [w for w in job["workers"] if w["state"] != "skipped"]
        for worker in active:
            app = self.app_for(worker["profile_id"])
            if (app.state.vault.public_key != worker["public_key"] or
                    (app.state.store.get_setting("account", {}) or {}).get("id") != worker["account_id"]):
                raise ValueError("A participating account or signing identity has changed.")
        self.reserve([w["profile_id"] for w in active], job_id)
        self.preparing = {w["profile_id"] for w in active}
        try:
            self.state, self.job = state, job
            self.entities = {}
            self.state.update(phase="preparing", ready=False, error=None)
            self.state["workers"] = [{**w, "state": "pending" if w["state"] != "skipped" else "skipped",
                                      "wait_until": None} for w in job["workers"]]
            self.persist()
            self.launch()
            return self.public()
        except BaseException:
            self.release(job_id)
            raise
        finally:
            self.preparing.clear()

    def prepare_chunks(self):
        directory = self.directory(self.state["id"])
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
        by_profile = {w["profile_id"]: w for w in self.job["workers"]}
        for receipt in (directory / "receipts").glob("*.json"):
            if not receipt.stem.isdigit() or linked(receipt):
                raise ValueError("Invalid chunk receipt path.")
            envelope = read_json(receipt)
            profile = envelope["statement"]["profile_id"]
            value = self.verified(receipt, by_profile[profile]["public_key"])
            if receipt.stem != str(value["low"]):
                raise ValueError("Chunk receipt filename differs from its signed range.")
            task = self.db.execute("SELECT * FROM tasks WHERE low=? AND high=?", (value["low"], value["high"])).fetchone()
            if not task or value["job_id"] != self.job["id"] or not self.db.execute(
                    "SELECT 1 FROM eligible WHERE low=? AND profile=?", (value["low"], profile)).fetchone():
                raise ValueError("Chunk receipt does not belong to the signed acquisition plan.")
            count, digest = self.check_chunk(directory / "chunks" / (str(value["low"]) + ".jsonl"), task)
            if (count, digest) != (value["count"], value["sha256"]):
                raise ValueError("Saved chunk differs from its signed receipt.")
            self.db.execute("UPDATE tasks SET phase='done',profile=?,count=?,sha256=? WHERE low=?",
                            (profile, count, digest, value["low"]))
        self.db.commit()
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
        count, captured = self.db.execute("SELECT count(*),coalesce(sum(count),0) FROM tasks WHERE phase='done'").fetchone()
        self.state.update(ranges_done=count, captured=captured)
        for worker in self.state["workers"]:
            ranges, messages = self.db.execute("SELECT count(*),coalesce(sum(count),0) FROM tasks "
                "WHERE phase='done' AND profile=?", (worker["profile_id"],)).fetchone()
            worker.update(ranges=ranges, captured=messages)

    async def work(self, worker):
        profile = worker["profile_id"]
        collector = self.app_for(profile).state.collector
        directory = self.directory(self.state["id"])
        worker["state"] = "running"
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
            try:
                if shutil.disk_usage(directory).free < collector.param("media_min_free_mb") * 1024**2:
                    raise ValueError("Insufficient free disk space for another chunk.")
                if linked(temporary) or linked(path):
                    raise ValueError("Chunk paths must not be links.")
                await collector.fetch_range(self.entities[profile], task["low"], task["high"], temporary,
                                            lambda: None, waiting)
                count, digest = self.check_chunk(temporary, task)
                with temporary.open("r+b") as stream:
                    os.fsync(stream.fileno())
                temporary.replace(path)
                receipt = {"job_id": self.job["id"], "low": task["low"], "high": task["high"],
                           "profile_id": profile, "count": count, "sha256": digest, "observed_at": utcnow()}
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
            except Exception as exc:
                self.db.execute("UPDATE tasks SET phase='pending' WHERE low=?", (task["low"],))
                self.db.execute("DELETE FROM eligible WHERE profile=?", (profile,))
                self.db.commit()
                worker.update(state="failed", error=type(exc).__name__)
                return
            finally:
                temporary.unlink(missing_ok=True)
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
                        if message and message_record(message) == json.loads(index.db.execute(
                                "SELECT record FROM messages WHERE id=?", (record["id"],)).fetchone()[0]):
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

    async def run(self):
        directory = self.directory(self.state["id"])
        lead = self.app_for(self.job["lead"]).state.collector
        try:
            await complete_in_thread(self.prepare_chunks)
            for worker in self.job["workers"]:
                profile_id = worker["profile_id"]
                if worker["state"] != "skipped" and profile_id not in self.entities:
                    self.entities[profile_id] = await self.app_for(profile_id).state.collector.resolve_for_export(
                        self.job["chat_id"], self.job["username"])
            self.state["phase"] = "running"
            self.persist()
            clock = await lead.telegram_clock()
            profile, observer, problems = await lead.chat_profile(self.entities[self.job["lead"]])
            log = await lead.admin_log(self.entities[self.job["lead"]]) if observer.get("role") in ("admin", "creator") else None
            workers = [asyncio.create_task(self.work(w)) for w in self.state["workers"] if w["state"] != "skipped"]
            try:
                await asyncio.gather(*workers)
            finally:
                # gather propagates a worker error without stopping its siblings.
                # Keep the index and every account reservation until they finish.
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
            if self.db.execute("SELECT 1 FROM tasks WHERE phase!='done' LIMIT 1").fetchone():
                raise ValueError("Some ranges could not be read. Saved chunks are retained; resume when accounts are available.")
            self.state["phase"] = "selecting"
            self.persist()
            scratch, ranges = await self.finish_selection(directory, Selection.model_validate(self.job["selection"]))
            meta = {"chat": {**self.job["chat"], "profile": profile, "profile_errors": problems},
                    "observer": observer, "admin_log": log, "account": lead.store.get_setting("account", {}),
                    "client": lead.client_identity(), "route": lead.route_receipt(),
                    "message_count": self.state["counts"]["selected"], "parts": self.sign_parts(ranges),
                    "collection": {"mode": "distributed_selection", "selection": self.job["selection"],
                        "counts": self.state["counts"], "scan_end": self.job["scan_end"],
                        "scope": "Selected messages and explicitly labelled context in the observed accessible ranges; "
                                 "reply absence is limited to the scanned scope; not an atomic snapshot."},
                    "acquisition": {"started_at": self.job["started_at"], "finished_at": utcnow(),
                                    "segments": self.job["segments"], "clock_at_start": clock,
                                    "clock_at_end": await lead.telegram_clock(),
                                    "clock_scope": "Current run; saved chunks retain their original local commit times."}}
            self.state["phase"] = "packaging"
            self.persist()
            out = directory / "export.zip"
            max_gib = tuning.value(lead.store, "export_max_gib")
            await complete_in_thread(chat_export.build_bundle, scratch, meta, lead.vault, out,
                                     max_gib * 1024**3, self.job["report"], directory / "media")
            await complete_in_thread(verify_chat_export, out, fingerprint(lead.vault.public_key), max_gib)
            replica.outbox(lead.store, out)
            self.state.update(phase="done", ready=True, error=None)
            lead.store.append("chat_export.completed", {"export_id": self.job["id"], "mode": "distributed_selection",
                              "counts": self.state["counts"]}, self.job["chat_id"])
        except asyncio.CancelledError:
            self.state.update(phase="paused", ready=False, error="Paused; committed chunks are retained.")
            for worker in self.state["workers"]:
                if worker["state"] in ("pending", "running", "waiting"):
                    worker["state"] = "paused"
            raise
        except Exception as exc:
            self.state.update(phase="failed", ready=False,
                              error=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        finally:
            if self.db:
                self.db.close()
                self.db = None
            self.persist()

    def poll(self, job_id):
        return self.public(job_id)

    async def pause(self, job_id):
        if self.state and self.state["id"] == job_id and self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            if self.state["phase"] not in ("done", "failed", "paused"):
                self.state.update(phase="paused", ready=False, error="Paused; committed chunks are retained.")
                self.persist()
        return self.public(job_id)

    async def cancel(self, job_id):
        if self.busy() and (not self.state or self.state["id"] != job_id):
            raise ValueError("Pause the current distributed export before changing another job.")
        state = await self.pause(job_id)
        if state.get("phase") not in ("done", "unknown"):
            self.state = state
            self.state["phase"] = "cancelled"
            self.persist()
        return self.public(job_id)

    def result_path(self, job_id):
        state = self.public(job_id)
        path = self.directory(job_id) / "export.zip"
        return path if state.get("ready") and path.is_file() and not path.is_symlink() else None

    async def close(self):
        if self.state:
            await self.pause(self.state["id"])
