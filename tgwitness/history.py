"""Resumable history acquisition into the signed journal, using the existing media queue.

A run freezes the enabled source list. Each source fixes its upper message ID when first
read; Telegram history is not an atomic snapshot and gaps in IDs are not deletion evidence.
The cursor, journal observation and media job commit together. Restart requires an explicit
resume, and completed/failed sources remain visible instead of being silently discarded.
"""
import asyncio
import secrets
import shutil
import time

from telethon import utils
from telethon.errors import FloodWaitError, RPCError

from .evidence import checkpoint, retain_checkpoint
from .monitoring import capture_settings
from .scope import scope_settings
from .store import canonical, utcnow

PAGE_SIZE = 100


class History:
    def __init__(self, collector):
        self.collector, self.store = collector, collector.store
        self.task = None
        with self.store.transaction():
            for statement in (
                "CREATE TABLE IF NOT EXISTS history_runs (id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, "
                "phase TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, reason TEXT)",
                "CREATE TABLE IF NOT EXISTS history_sources (run_id TEXT NOT NULL, chat_id INTEGER NOT NULL, "
                "title TEXT NOT NULL, position INTEGER NOT NULL, phase TEXT NOT NULL DEFAULT 'queued', "
                "upper_id INTEGER, offset_id INTEGER NOT NULL DEFAULT 0, captured INTEGER NOT NULL DEFAULT 0, "
                "unavailable INTEGER NOT NULL DEFAULT 0, error TEXT, PRIMARY KEY(run_id,chat_id))",
                "CREATE TABLE IF NOT EXISTS history_items (run_id TEXT NOT NULL, message_event INTEGER NOT NULL, "
                "PRIMARY KEY(run_id,message_event))",
            ):
                self.store.db.execute(statement)

            self.store.db.execute("UPDATE history_runs SET phase='paused',reason='process_restart',updated_at=? "
                                  "WHERE phase='running'", (utcnow(),))

    @property
    def busy(self):
        return self.task is not None and not self.task.done()

    def current(self):
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM history_runs ORDER BY rowid DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def status(self):
        with self.store.lock:
            run = self.current()
            if not run:
                return {"phase": "none"}
            run_id = run["id"]
            counts = dict(self.store.db.execute("SELECT phase,count(*) FROM history_sources "
                                               "WHERE run_id=? GROUP BY phase", (run_id,)))
            totals = self.store.db.execute("SELECT coalesce(sum(captured),0),coalesce(sum(unavailable),0) "
                                           "FROM history_sources WHERE run_id=?", (run_id,)).fetchone()
            sources = [dict(row) for row in self.store.db.execute(
                "SELECT chat_id,title,phase,captured,unavailable,upper_id,offset_id,error FROM history_sources "
                "WHERE run_id=? ORDER BY CASE phase WHEN 'reading' THEN 0 WHEN 'failed' THEN 1 "
                "WHEN 'skipped' THEN 2 ELSE 3 END,position LIMIT 50", (run_id,))]
            media = dict(self.store.db.execute(
                "SELECT j.state,count(*) FROM history_items h JOIN media_jobs j ON j.message_event=h.message_event "
                "WHERE h.run_id=? GROUP BY j.state", (run_id,)))
            return {**run, "sources_total": sum(counts.values()), "sources_by_phase": counts,
                    "captured": totals[0], "unavailable": totals[1], "sources": sources, "media": media,
                    "media_pending": sum(media.get(k, 0) for k in ("queued", "retry", "running")),
                    "scope": "enabled sources fixed at run creation; media follows capture settings"}

    def require_running(self):
        if not self.collector.running:
            raise ValueError("Start observation before loading full history.")
        account = (self.store.get_setting("account", {}) or {}).get("id")
        if not account:
            raise ValueError("Connect a Telegram account first.")
        return account

    async def start(self):
        account = self.require_running()
        current = self.current()
        if self.busy or current and current["phase"] in ("running", "paused"):
            raise ValueError("Resume or cancel the existing history run before starting another.")
        targets = self.store.targets(True)
        if not targets:
            raise ValueError("Select at least one source first.")
        run_id, now = secrets.token_hex(16), utcnow()
        with self.store.transaction():
            self.store.db.execute("INSERT INTO history_runs VALUES (?,?,?,?,?,NULL)",
                                  (run_id, account, "running", now, now))
            self.store.db.executemany(
                "INSERT INTO history_sources(run_id,chat_id,title,position) VALUES (?,?,?,?)",
                [(run_id, t["chat_id"], t["title"], i) for i, t in enumerate(targets)])
            self.store.append("history.started", {
                "history_run_id": run_id, "account_id": account,
                "sources": [t["chat_id"] for t in targets], "scope": scope_settings(self.store),
                "dialog_list_limit": self.collector.param("dialog_limit"),
                "capture": capture_settings(self.store),
                "meaning": "History of the listed enabled sources; not proof all account dialogs were enumerated. "
                           "Each source fixes its upper message ID on first read. Messages may change during reading; "
                           "unseen deletions and intermediate edits cannot be recovered."})
        self.task = asyncio.create_task(self.run(run_id))
        return self.status()

    def transition(self, run_id, phase, reason=None):
        with self.store.transaction():
            self.store.db.execute("UPDATE history_runs SET phase=?,reason=?,updated_at=? WHERE id=?",
                                  (phase, reason, utcnow(), run_id))
            self.store.append("history." + phase, {"history_run_id": run_id, "reason": reason})

    async def resume(self):
        account = self.require_running()
        run = self.current()
        if self.busy or not run or run["phase"] != "paused":
            raise ValueError("There is no paused history run to resume.")
        if account != run["account_id"]:
            raise ValueError("This history run belongs to a different Telegram account.")
        self.transition(run["id"], "running", "operator_resume")
        self.task = asyncio.create_task(self.run(run["id"]))
        return self.status()

    async def pause(self, reason="operator_pause"):
        if self.busy:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        run = self.current()
        if run and run["phase"] == "running":
            self.transition(run["id"], "paused", reason)
        return self.status()

    async def cancel(self):
        await self.pause()
        run = self.current()
        if run and run["phase"] == "paused":
            self.transition(run["id"], "cancelled", "operator_cancel; observations already saved are retained")
        return self.status()

    def source(self, run_id):
        with self.store.lock:
            row = self.store.db.execute("SELECT * FROM history_sources WHERE run_id=? "
                                        "AND phase IN ('queued','reading') ORDER BY position LIMIT 1",
                                        (run_id,)).fetchone()
            return dict(row) if row else None

    def finish_source(self, job, phase, error=None):
        with self.store.transaction():
            self.store.db.execute("UPDATE history_sources SET phase=?,error=? WHERE run_id=? AND chat_id=?",
                                  (phase, error, job["run_id"], job["chat_id"]))
            latest = dict(self.store.db.execute("SELECT * FROM history_sources WHERE run_id=? AND chat_id=?",
                                               (job["run_id"], job["chat_id"])).fetchone())
            self.store.append("history.source." + phase, {
                "history_run_id": job["run_id"], "upper_message_id": latest["upper_id"],
                "last_message_id": latest["offset_id"], "captured": latest["captured"],
                "unavailable": latest["unavailable"], "error_type": error,
                "meaning": "End of the available history read, not proof of complete past delivery."}, job["chat_id"])

    async def run(self, run_id):
        try:
            while True:
                run = self.current()
                if not self.collector.running:
                    self.transition(run_id, "paused", "observation_stopped")
                    return
                if self.require_running() != run["account_id"]:
                    self.transition(run_id, "paused", "account_changed")
                    return
                job = self.source(run_id)
                if not job:
                    state = self.status()
                    phase = "incomplete" if state["unavailable"] or any(
                        state["sources_by_phase"].get(k) for k in ("failed", "skipped")) else "complete"
                    with self.store.transaction():
                        self.transition(run_id, phase, "History reading ended; attachment outcomes are separate.")
                        self.store.append("history.summary", {
                            "history_run_id": run_id, "captured": state["captured"],
                            "unavailable": state["unavailable"], "sources": state["sources_by_phase"],
                            "media": state["media"], "media_pending": state["media_pending"]})
                    retain_checkpoint(self.store, self.collector.vault)
                    return
                if not self.collector.selected(job["chat_id"]):
                    self.finish_source(job, "skipped", "source_disabled")
                    continue
                if shutil.disk_usage(self.store.root).free < self.collector.param("media_min_free_mb") * 1024**2:
                    self.transition(run_id, "paused", "insufficient_free_space")
                    return
                backoff = self.store.get_setting("rpc_backoff_until", 0) - time.time()
                if backoff > 0:
                    await asyncio.sleep(min(backoff, 1))
                    continue
                client = self.collector.client
                try:
                    await asyncio.wait_for(self.read_page(job), self.collector.param("operation_timeout_seconds"))
                except FloodWaitError as exc:
                    with self.store.transaction():
                        self.store.set_setting("rpc_backoff_until", max(time.time() + exc.seconds,
                            self.store.get_setting("rpc_backoff_until", 0)))
                        self.store.append("history.waiting", {"history_run_id": run_id,
                            "retry_after_seconds": exc.seconds}, job["chat_id"])
                except RPCError as exc:
                    if self.collector.handle_authorization_error(exc, "history", client=client):
                        self.transition(run_id, "paused", "authorization_required")
                        return
                    self.finish_source(job, "failed", type(exc).__name__)
                except (OSError, TimeoutError) as exc:

                    self.transition(run_id, "paused", type(exc).__name__)
                    return
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except Exception as exc:

            self.transition(run_id, "paused", type(exc).__name__)

    async def read_page(self, job):
        chat_id, run_id = job["chat_id"], job["run_id"]
        entity = await self.collector.resolve_target(chat_id)
        offset = job["offset_id"] or ((job["upper_id"] + 1) if job["upper_id"] is not None else 0)
        messages = await self.collector.client.get_messages(entity, limit=PAGE_SIZE, offset_id=offset)
        if not self.collector.selected(chat_id):
            self.finish_source(job, "skipped", "source_disabled")
            return
        previous = offset or 2**63
        for message in messages:
            mid = getattr(message, "id", None)
            if type(mid) is not int or not 0 < mid < previous:
                raise ValueError("History reply does not advance the requested cursor.")
            previous = mid
            if getattr(message, "peer_id", None) is not None and utils.get_peer_id(message.peer_id) != chat_id:
                raise ValueError("History reply belongs to a different chat.")
        if job["upper_id"] is None:
            upper = messages[0].id if messages else 0
            with self.store.transaction():
                self.store.db.execute("UPDATE history_sources SET upper_id=?,phase='reading' "
                                      "WHERE run_id=? AND chat_id=?", (upper, run_id, chat_id))
                self.store.append("history.source.started", {"history_run_id": run_id,
                    "upper_message_id": upper}, chat_id)
        if not messages:
            self.finish_source(job, "complete")
            return
        for message in messages:
            if not self.collector.selected(chat_id):
                self.finish_source(job, "skipped", "source_disabled")
                return
            with self.store.transaction():

                unavailable = not hasattr(message, "message") or getattr(message, "peer_id", None) is None
                if unavailable:
                    event = self.store.append("history.message.unavailable", {"history_run_id": run_id},
                                              chat_id, message.id)
                else:
                    event = await self.collector.capture_message(message, "message.snapshot", chat_id,
                        source="history_acquisition", history_run_id=run_id)
                self.store.db.execute("INSERT INTO history_items VALUES (?,?)", (run_id, event["seq"]))
                self.store.db.execute("UPDATE history_sources SET offset_id=?,captured=captured+?,"
                                      "unavailable=unavailable+? WHERE run_id=? AND chat_id=?",
                                      (message.id, int(not unavailable), int(unavailable), run_id, chat_id))

            await asyncio.sleep(0)

    def report(self):
        """A current signed progress report; immutable source events remain in the evidence journal."""
        with self.store.lock:
            statement = self.status()
            if statement["phase"] == "none":
                raise ValueError("No history run exists.")
            statement["sources"] = [dict(r) for r in self.store.db.execute(
                "SELECT * FROM history_sources WHERE run_id=? ORDER BY position", (statement["id"],))]
            statement.update(format="tgwitness-history-report-v1", generated_at=utcnow(),
                             public_key=self.collector.vault.public_key,
                             checkpoint=checkpoint(self.store, self.collector.vault))
            return {"statement": statement, "signature": self.collector.vault.sign(canonical(statement))}
