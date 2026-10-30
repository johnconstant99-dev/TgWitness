"""Export one chat with several accounts at once, merged into a single signed bundle.

The chat's message numbers 1..N (N = newest message when the export starts) are cut into
ranges of CHUNK numbers placed in a shared queue. Every selected account takes the next
range, fetches it with its own single client and takes another, so an account waiting
out a FloodWait simply does less and a range left by a failed account is fetched by
another. Telegram flood limits apply per account, so throughput grows with accounts.

Rules followed: each account uses only its existing client (a second connection on the
same authorization key makes Telegram revoke the session: AUTH_KEY_DUPLICATED), and the
same Telegram account can never be in two workspaces. Ranges only make sense where
message numbers are per chat — channels and supergroups. Ordinary groups number messages
per account, so they are exported by the starting account alone.

Integrity: a range's SHA-256 is computed while its messages arrive. Before signing, every
range file is re-read and must reproduce that hash. Each account signs, with its own key,
the ranges it fetched; the starting account signs the whole bundle.
"""
import asyncio
import hashlib
import json
import secrets
import time
from contextlib import suppress

from . import chat_export
from . import replica
from . import tuning
from .store import canonical, utcnow
from .verify import fingerprint
from .workers import complete_in_thread

CHUNK = 2000


class MultiExport:
    def __init__(self, profiles):
        self.profiles = profiles
        self.state = None
        self.task = None
        self.path = None

    def busy(self):
        return bool(self.task and not self.task.done())

    def app_for(self, profile_id):
        entry = self.profiles.entries.get(profile_id)
        if not entry or entry.get("app") is None:
            raise ValueError("Unknown or unavailable account workspace.")
        return entry["app"]

    def public(self):
        return json.loads(json.dumps(self.state, default=str)) if self.state else {"phase": "none"}

    async def start(self, chat_id, profile_ids, lead_id):
        if self.busy():
            raise ValueError("A multi-account export is already running. Wait for it or cancel it.")
        lead_app = self.app_for(lead_id)
        lead = lead_app.state.collector
        export_id = secrets.token_urlsafe(18)
        # Every participating account is reserved with a check-and-take that has no await in
        # between, so an individual export can never start on it at the same time.
        if not lead.reserve_export(export_id):
            raise ValueError("The starting account is already exporting. Wait for it or cancel it.")
        reserved = {lead_id: lead}
        try:
            entity = await lead.resolve_for_export(chat_id)
            info = lead.dialog_cache.get(chat_id, {})
            latest = await lead.client.get_messages(entity, limit=1)
            total, newest = getattr(latest, "total", None) or 0, (latest[0].id if latest else 0)
            basic_group = info.get("kind") == "group"
            chosen = [lead_id] + [p for p in dict.fromkeys(profile_ids) if p != lead_id]
            if basic_group:
                chosen = [lead_id]
            workers = []
            for profile_id in chosen:
                entry = self.profiles.entries.get(profile_id) or {}
                app = entry.get("app")
                worker = {"profile_id": profile_id, "label": entry.get("label", profile_id), "account_id": None,
                          "state": "pending", "captured": 0, "ranges": 0, "error": None, "wait_until": None}
                if app is None:
                    worker.update(state="skipped", error="Workspace unavailable.")
                else:
                    worker["account_id"] = (app.state.store.get_setting("account", {}) or {}).get("id")
                    collector = app.state.collector
                    if not app.state.vault.read("credentials").get("session"):
                        worker.update(state="skipped", error="No Telegram account connected.")
                    elif profile_id != lead_id:
                        if collector.reserve_export(export_id):
                            reserved[profile_id] = collector
                        else:
                            worker.update(state="skipped", error="Another export is running on this account.")
                workers.append(worker)
            active = sum(1 for w in workers if w["state"] == "pending")
            pages = -(-total // 100)
            self.state = {
                "id": export_id, "chat_id": chat_id, "title": info.get("title"),
                "kind": info.get("kind"), "basic_group": basic_group, "lead": lead_id, "phase": "running",
                "total": total, "newest_message_id": newest, "captured": 0,
                "ranges_total": -(-newest // CHUNK), "ranges_done": 0,
                "eta_seconds": round(pages * (1 if total > 3000 else 0.3) / max(1, active)),
                "workers": workers, "ready": False, "error": None, "started_at": utcnow()}
            self.path = None
            self.task = asyncio.create_task(self.run(lead_app, entity, getattr(entity, "username", None), info))
        except BaseException:
            self.release(reserved, export_id)
            raise
        # Released however the task ends, even if it is cancelled before its first step.
        self.task.add_done_callback(lambda _: self.release(reserved, export_id))
        await asyncio.sleep(0)
        return self.public()

    @staticmethod
    def release(reserved, export_id):
        for collector in reserved.values():
            collector.release_export(export_id)

    def uses(self, profile_id):
        """Whether a running export still depends on this workspace (its store, client or keys)."""
        # A failed account's earlier ranges are still signed with its key when the export ends.
        return self.busy() and any(w["profile_id"] == profile_id and w["state"] != "skipped"
                                   and (w["state"] != "failed" or w["ranges"]) for w in self.state["workers"])

    async def run(self, lead_app, lead_entity, username, info):
        state, lead = self.state, lead_app.state.collector
        directory = lead.store.root / "temporary-exports"
        stem = "tgwitness-export-multi-" + state["id"]
        newest = state["newest_message_id"]
        ranges = [(low, min(low + CHUNK - 1, newest)) for low in range(1, newest + 1, CHUNK)]
        queue = asyncio.Queue()
        for item in reversed(ranges):  # newest messages first
            queue.put_nowait(item)
        results, started = {}, time.monotonic()
        in_flight = {"ranges": 0}  # ranges being fetched; a failure can return one to the queue
        out = directory / (stem + ".zip")
        scratch = directory / (stem + ".jsonl")

        async def work(worker):
            app = self.app_for(worker["profile_id"])
            collector = app.state.collector
            try:
                entity = lead_entity if worker["profile_id"] == state["lead"] else \
                    await collector.resolve_for_export(state["chat_id"], username)
            except Exception as exc:
                worker.update(state="skipped", error="This account cannot open the chat (" + type(exc).__name__ + ").")
                if worker["profile_id"] != state["lead"]:
                    collector.release_export(state["id"])  # free for its own exports again
                return
            worker["state"] = "running"
            while True:
                try:
                    low, high = queue.get_nowait()
                except asyncio.QueueEmpty:
                    if not in_flight["ranges"]:
                        break
                    await asyncio.sleep(0.5)  # another account may still hand a range back
                    continue
                path = directory / (stem + "-" + str(low) + ".jsonl")
                got = 0
                in_flight["ranges"] += 1

                def progress():
                    nonlocal got
                    got += 1
                    worker["captured"] += 1
                    state["captured"] += 1
                    if worker["state"] == "waiting":
                        worker.update(state="running", wait_until=None)

                def waiting(seconds):
                    worker.update(state="waiting", wait_until=time.time() + seconds)

                try:
                    count, digest = await collector.fetch_range(entity, low, high, path, progress, waiting)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    queue.put_nowait((low, high))  # another account picks it up
                    worker["captured"] -= got
                    state["captured"] -= got
                    path.unlink(missing_ok=True)
                    worker.update(state="failed", error=type(exc).__name__)
                    return
                finally:
                    in_flight["ranges"] -= 1
                results[low] = {"low": low, "high": high, "count": count, "sha256": digest,
                                "profile_id": worker["profile_id"], "path": path}
                worker["ranges"] += 1
                worker.update(state="running", wait_until=None)
                state["ranges_done"] += 1
                elapsed = time.monotonic() - started
                if state["captured"] and state["total"] and elapsed > 0:
                    state["eta_seconds"] = round(max(0, state["total"] - state["captured"]) / (state["captured"] / elapsed))
            worker["state"] = "done"

        try:
            # Setup is inside the lifecycle: a failure here still ends the export as failed.
            directory.mkdir(mode=0o700, exist_ok=True)
            lead.store.append("chat_export.started", {
                "chat_id": state["chat_id"], "title": info.get("title"), "mode": "multi_account",
                "accounts": [w["account_id"] for w in state["workers"] if w["state"] == "pending"],
                "newest_message_id": newest, "meaning": "full visible history snapshot"}, state["chat_id"])
            await asyncio.gather(*(work(w) for w in state["workers"] if w["state"] == "pending"))
            if len(results) != len(ranges):
                raise RuntimeError("Some message ranges could not be fetched by any selected account.")
            parts = [results[low] for low, _ in reversed(ranges)]
            await complete_in_thread(self.merge, parts, scratch)
            signed = self.sign_parts(parts)
            message_count = sum(p["count"] for p in parts)
            meta = {"chat": {"id": state["chat_id"], "title": info.get("title"), "kind": info.get("kind"),
                             "visibility": info.get("visibility")},
                    "account": lead.store.get_setting("account", None), "message_count": message_count,
                    "collection": {"mode": "multi_account", "range_size": CHUNK, "newest_message_id": newest,
                                   "scope": "message numbers 1..newest_message_id at export start"},
                    "parts": signed}
            await complete_in_thread(chat_export.build_bundle, scratch, meta, lead.vault, out,
                                    tuning.value(lead.store, "export_max_gib") * 1024**3)
            replica.outbox(lead.store, out)
            self.path = out
            state.update(phase="done", ready=True, captured=message_count, eta_seconds=0)
            lead.store.append("chat_export.completed", {
                "chat_id": state["chat_id"], "message_count": message_count, "mode": "multi_account",
                "accounts": [p["statement"]["account_id"] for p in signed],
                "fingerprint": fingerprint(lead.vault.public_key), "reconstructed_missed_events": False},
                state["chat_id"])
        except asyncio.CancelledError:
            state["phase"] = "cancelled"
            lead.note("chat_export.interrupted", {"chat_id": state["chat_id"], "mode": "multi_account",
                                                  "captured": state["captured"], "reason": "cancelled"},
                      state["chat_id"])
            with suppress(OSError):
                out.unlink(missing_ok=True)
            raise
        except BaseException as exc:
            state.update(phase="failed", error=str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__)
            lead.note("chat_export.interrupted", {"chat_id": state["chat_id"], "mode": "multi_account",
                                                  "captured": state["captured"],
                                                  "error_type": type(exc).__name__}, state["chat_id"])
            with suppress(OSError):
                out.unlink(missing_ok=True)
        finally:
            with suppress(OSError):
                for item in directory.glob(stem + "-*.jsonl"):
                    item.unlink(missing_ok=True)
                scratch.unlink(missing_ok=True)

    @staticmethod
    def merge(parts, scratch):
        """Concatenate ranges newest first; each must still match the hash taken on arrival."""
        with scratch.open("w", encoding="utf-8") as merged:
            for part in parts:
                digest, count = hashlib.sha256(), 0
                with part["path"].open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        digest.update(canonical(json.loads(line)) + b"\n")
                        merged.write(line if line.endswith("\n") else line + "\n")
                        count += 1
                if count != part["count"] or digest.hexdigest() != part["sha256"]:
                    raise ValueError("Range " + str(part["low"]) + "-" + str(part["high"]) +
                                     " changed on disk after it was fetched; export stopped.")

    def sign_parts(self, parts):
        """One statement per account, signed with that account's own key."""
        by_profile = {}
        for part in parts:
            by_profile.setdefault(part["profile_id"], []).append(part)
        signed = []
        for profile_id, items in by_profile.items():
            app = self.app_for(profile_id)
            vault = app.state.vault
            statement = {
                "format": "tgwitness-chat-part-v1", "export_id": self.state["id"], "chat_id": self.state["chat_id"],
                "account_id": (app.state.store.get_setting("account", {}) or {}).get("id"),
                "fetched_by_public_key": vault.public_key, "signed_at": utcnow(),
                "ranges": [{"low": p["low"], "high": p["high"], "count": p["count"], "sha256": p["sha256"]}
                           for p in items]}
            signed.append({"statement": statement, "signature": vault.sign(canonical(statement)),
                           "fingerprint": fingerprint(vault.public_key)})
        return signed

    def poll(self, export_id):
        if not self.state or self.state["id"] != export_id:
            return {"phase": "unknown"}
        return self.public()

    async def cancel(self, export_id):
        if self.state and self.state["id"] == export_id and self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        return {"phase": "cancelled"}

    def result_path(self, export_id):
        if self.state and self.state["id"] == export_id and self.state.get("ready") and self.path and self.path.is_file():
            return self.path
        return None

    async def close(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
