"""Bind mutable history progress to the latest matching signed journal record."""
import json

from .store import canonical

FIELDS = ("run_id", "chat_id", "title", "position", "phase", "upper_id", "offset_id",
          "captured", "unavailable", "error", "metadata")


def state(row):
    value = {key: row[key] for key in FIELDS}
    value["metadata"] = json.loads(value["metadata"])
    return value


def seal(store, run_id, chat_id):
    """The caller's transaction includes message, media job, cursor and signature."""
    row = store.db.execute("SELECT * FROM history_sources WHERE run_id=? AND chat_id=?",
                           (run_id, chat_id)).fetchone()
    event = store.append("history.cursor", {"history_run_id": run_id, "state": state(row)}, chat_id)
    store.db.execute("UPDATE history_sources SET cursor_seq=?,cursor_hash=? WHERE run_id=? AND chat_id=?",
                     (event["seq"], event["hash"], run_id, chat_id))


def verify(store, vault, run):
    store.verify(vault.public_key)
    with store.transaction():
        start = store.db.execute("SELECT * FROM events WHERE kind='history.started' "
            "AND json_extract(payload,'$.history_run_id')=? ORDER BY seq DESC LIMIT 1", (run["id"],)).fetchone()
        if start is None:
            raise ValueError("History run has no signed source plan.")
        plan = store.decode(start)["payload"]
        sources = list(store.db.execute("SELECT * FROM history_sources WHERE run_id=? ORDER BY position", (run["id"],)))
        if (plan["account_id"] != run["account_id"]
                or plan["sources"] != [row["chat_id"] for row in sources]
                or canonical(plan.get("options", {})) != canonical(json.loads(run["options"]))):
            raise ValueError("History account, source plan or options differ from the signed journal.")
        for row in sources:
            cursor = store.db.execute("SELECT * FROM events WHERE kind='history.cursor' AND chat_id=? "
                "AND json_extract(payload,'$.history_run_id')=? ORDER BY seq DESC LIMIT 1",
                (row["chat_id"], run["id"])).fetchone()
            if cursor is None:
                if plan.get("cursor_format"):
                    raise ValueError("Missing signed history cursor.")
                migrate_legacy(store, run, row)
                continue
            event = store.decode(cursor)
            if (row["cursor_seq"] != event["seq"] or row["cursor_hash"] != event["hash"]
                    or canonical(state(row)) != canonical(event["payload"]["state"])):
                raise ValueError("History cursor differs from its latest signed commitment.")
        store.db.execute("DELETE FROM history_items WHERE run_id=?", (run["id"],))
        store.db.execute("INSERT INTO history_items SELECT ?,seq FROM events WHERE "
            "json_extract(payload,'$.history_run_id')=? AND kind IN "
            "('message.snapshot','history.message.unavailable','message.admin_log')", (run["id"], run["id"]))
        store.db.execute("DELETE FROM history_admin_items WHERE run_id=?", (run["id"],))
        store.db.execute("INSERT INTO history_admin_items SELECT ?,chat_id,json_extract(payload,'$.provider_event_id'),seq "
            "FROM events WHERE json_extract(payload,'$.history_run_id')=? AND kind='history.admin_log.observed'",
            (run["id"], run["id"]))


def migrate_legacy(store, run, row):
    """Recover old progress from signed observations, never bless an unsigned offset."""
    upper, offset, captured, unavailable, phase, error = None, 0, 0, 0, "queued", None
    for raw in store.db.execute("SELECT * FROM events WHERE chat_id=? "
            "AND json_extract(payload,'$.history_run_id')=? ORDER BY seq", (row["chat_id"], run["id"])):
        event = store.decode(raw)
        if event["kind"] == "history.source.started":
            upper, phase = event["payload"]["upper_message_id"], "reading"
        elif event["kind"] in ("message.snapshot", "history.message.unavailable"):
            mid = event["message_id"]
            offset = min(offset, mid) if offset else mid
            captured += event["kind"] == "message.snapshot"
            unavailable += event["kind"] == "history.message.unavailable"
            store.db.execute("INSERT OR IGNORE INTO history_items(run_id,message_event) VALUES (?,?)",
                             (run["id"], event["seq"]))
        elif event["kind"] in ("history.source.complete", "history.source.failed", "history.source.skipped"):
            phase, error = event["kind"].rsplit(".", 1)[-1], event["payload"].get("error_type")
    store.db.execute("UPDATE history_sources SET upper_id=?,offset_id=?,captured=?,unavailable=?,phase=?,error=?,metadata='{}' "
                     "WHERE run_id=? AND chat_id=?", (upper, offset, captured, unavailable, phase, error,
                                                     run["id"], row["chat_id"]))
    seal(store, run["id"], row["chat_id"])
