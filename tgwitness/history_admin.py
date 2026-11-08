from telethon import errors
from telethon.tl import functions as f, types as t

from .store import utcnow


async def page(history, job, entity, stage):
    from .collector import admin_event

    meta = history.metadata(job)
    key = "admin_" + stage
    progress = meta.setdefault(key, {"status": "reading", "offset": 0, "newest": 0,
                                    "observed": 0, "started_at": utcnow()})
    if progress["status"] != "reading":
        return False
    lower = meta.get("admin_before", {}).get("newest", 0) if stage == "after" else 0
    if not isinstance(entity, (t.Channel, t.InputPeerChannel, t.InputChannel)):
        progress.update(status="not_applicable", ended_at=utcnow())
        history.save_metadata(job, meta)
        return True
    try:
        result = await history.collector.client(f.channels.GetAdminLogRequest(entity, "",
            progress["offset"], lower, 100,
            events_filter=t.ChannelAdminLogEventsFilter(delete=True, edit=True)))
    except (errors.FloodWaitError, errors.ServerError, errors.TakeoutInvalidError):
        raise
    except errors.RPCError as exc:
        if history.collector.handle_authorization_error(exc, "history admin log", client=history.collector.client):
            raise
        progress.update(status="unavailable", error=type(exc).__name__, ended_at=utcnow())
        with history.store.transaction():
            history.store.append("history.admin_log.unavailable", {"history_run_id": job["run_id"],
                "source": "admin_log", "stage": stage, "error_type": type(exc).__name__}, job["chat_id"])
            history.save_metadata(job, meta)
        return True
    previous = progress["offset"] or 2**63
    for event in result.events:
        if not lower < event.id < previous:
            raise ValueError("Admin log did not advance the requested cursor.")
        previous = event.id
    with history.store.transaction():
        for event in result.events:
            duplicate = history.store.db.execute("SELECT 1 FROM history_admin_items "
                "WHERE run_id=? AND chat_id=? AND provider_id=?", (job["run_id"], job["chat_id"], event.id)).fetchone()
            if duplicate:
                continue
            observation = history.store.append("history.admin_log.observed", {
                "history_run_id": job["run_id"], "source": "admin_log", "source_mode": "standard",
                "stage": stage, "provider_event_id": event.id, "event": admin_event(event),
                "meaning": "Server-reported historical action from Telegram's recent-actions window."},
                job["chat_id"])
            history.store.db.execute("INSERT INTO history_admin_items VALUES (?,?,?,?)",
                (job["run_id"], job["chat_id"], event.id, observation["seq"]))
            for field in ("message", "prev_message", "new_message"):
                message = getattr(event.action, field, None)
                if message is not None and getattr(message, "media", None):
                    captured = await history.collector.capture_message(message, "message.admin_log", job["chat_id"],
                        source="admin_log", history_run_id=job["run_id"], acquisition={"source_mode": "standard",
                            "admin_event": observation["seq"], "version": field})
                    history.store.db.execute("INSERT INTO history_items VALUES (?,?)", (job["run_id"], captured["seq"]))
            progress["observed"] += 1
        if result.events:
            progress["newest"] = max(progress["newest"], result.events[0].id)
            progress["offset"] = result.events[-1].id
            progress["oldest_event_at"] = result.events[-1].date.isoformat()
            progress.setdefault("newest_event_at", result.events[0].date.isoformat())
        else:
            progress.update(status="complete", ended_at=utcnow())
            history.store.append("history.admin_log.finished", {"history_run_id": job["run_id"],
                "source": "admin_log", "stage": stage, **progress}, job["chat_id"])
        history.save_metadata(job, meta)
    return True
