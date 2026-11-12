import json
import sqlite3
import time

from .verify import CHANNEL_IDS_BELOW, GAP_DEFAULTS, MESSAGE_KINDS, Sequences, missing_ranges, numbered_per_chat

SCOPE_KINDS = ("scope.changed", "scope.applied", "deletion.unscoped", "observation.started",
               "observation.stopped", "process.started", "process.stopped")
SERVICE_KINDS = ("chat.service", "membership.service")


def settings(store):
    from .tuning import value
    return {key: value(store, key) for key in GAP_DEFAULTS}


def page_gaps(store, chat_id, numbers, *, before_id=None, after_id=None, limit=5000, budget=2):
    if not numbers or not numbered_per_chat(chat_id) or not settings(store)["gap_analysis"]:
        return []
    low, high = min(numbers), max(numbers)
    if before_id is not None:
        high = max(high, before_id)
    if after_id is not None:
        low = min(low, after_id)
    kinds = MESSAGE_KINDS + SERVICE_KINDS
    try:
        rows = store.bounded_read(
            "SELECT DISTINCT message_id FROM events WHERE chat_id=? AND message_id BETWEEN ? AND ? AND kind IN ("
            + ",".join("?" * len(kinds)) + ") ORDER BY message_id LIMIT ?", [chat_id, low, high, *kinds, limit], budget)
    except TimeoutError:
        return []
    return [{"low": first, "high": last, "missing": last - first + 1}
            for first, last in missing_ranges([row[0] for row in rows])]


def capture_summary(store, chat_ids=None, *, chat_id=None, budget=4, titles=None):
    wanted = settings(store)
    chats = {chat_id} if chat_id is not None else chat_ids
    sequences = Sequences(wanted, chats_selected=chats is not None)
    if not wanted["gap_analysis"]:
        return sequences.result()
    kinds = MESSAGE_KINDS + SERVICE_KINDS
    where, params = ["kind IN (" + ",".join("?" * len(kinds)) + ")", "message_id IS NOT NULL"], list(kinds)
    if chats is not None:
        where.append("chat_id IN (" + ",".join("?" * len(chats)) + ")")
        params += sorted(chats)
    sql = "SELECT seq,kind,chat_id,message_id,observed_at,NULL AS payload FROM events WHERE " + " AND ".join(where)
    if chats is None:
        sql += (" UNION ALL SELECT seq,kind,chat_id,message_id,observed_at,payload FROM events WHERE kind IN ("
                + ",".join("?" * len(SCOPE_KINDS)) + ")")
        params += SCOPE_KINDS
    deadline, complete = time.monotonic() + budget, True
    with store.snapshot() as snapshot:
        snapshot.connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            rows = snapshot.connection.execute("SELECT * FROM (" + sql + ") ORDER BY seq", params)
            for number, row in enumerate(rows):
                if number % 4096 == 0 and time.monotonic() >= deadline:
                    complete = False
                    break
                if chats is not None and not (isinstance(row["chat_id"], int) and row["chat_id"] < CHANNEL_IDS_BELOW):
                    continue
                sequences.add({"kind": row["kind"], "chat_id": row["chat_id"], "message_id": row["message_id"],
                               "observed_at": row["observed_at"],
                               "payload": json.loads(row["payload"]) if row["payload"] else {}}, MESSAGE_KINDS)
        except sqlite3.OperationalError:
            if time.monotonic() < deadline:
                raise
            complete = False
        finally:
            snapshot.connection.set_progress_handler(None, 0)
    summary = sequences.result(titles, chat_limit=None if chat_id is not None else 50)
    if chat_id is None:
        for entry in summary["chats"]:
            entry.pop("clusters", None)
    if chat_ids is not None:
        summary["account"] = {"status": "not_applicable",
                              "reason": "Shown only to access covering the whole workspace: the account-wide "
                                        "sequence is shared by every private chat, bot and ordinary group."}
    elif chat_id is not None:
        summary["account"] = {"status": "not_applicable",
                              "reason": "Measured across all chats; leave the chat unselected to see it."}
    if not complete:
        summary["partial"] = "Time limit reached; only part of the journal was measured. Choose one chat."
    return summary
