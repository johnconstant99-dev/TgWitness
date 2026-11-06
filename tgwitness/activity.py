"""Activity statistics computed on request from saved observations.

Nothing here is stored. Every figure is derived from signed journal records when it is requested, and the
result names the journal position it covers."""
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone

from .fulltext import message_urls, reference_items
from .people import stamp

FIRST_KINDS = ("message.new", "message.snapshot", "message.recovered")
SCANNED_KINDS = (*FIRST_KINDS, "message.edited", "message.deleted", "message.missing_on_recheck")
BUDGET = 5
CANDIDATE = re.compile(r"\w\.\w|@\w")
MEANING = ("Counts of saved observations only. Message times are the times Telegram reported, in UTC; hour "
           "and weekday counts help estimate a time zone but do not establish one. Missing messages do not prove "
           "inactivity: check the coverage section for periods without confirmed collection.")


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds") if value is not None else None


def bound(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds")


def plain(value, limit):
    return value[:limit] if isinstance(value, str) and value else None


def references(payload):
    text = payload.get("text") if isinstance(payload.get("text"), str) else ""
    urls, _ = message_urls(payload)
    if not urls and not CANDIDATE.search(text):
        return (), ()
    items = reference_items(text, urls)
    return (tuple({item["value"] for item in items if item["kind"] == "domain"}),
            tuple({item["value"].casefold() for item in items if item["kind"] == "telegram"}))


def ranked(counter, top, name):
    return [{name: value, "messages": count} for value, count in
            sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:top]]


def unconfirmed(db, start, end, deadline, limit=20):
    """Intervals without a connected collector heartbeat; the collector's liveness, not complete capture."""
    rows = db.execute("SELECT observed_at, json_extract(payload,'$.connected'), json_extract(payload,'$.interval_seconds') "
                      "FROM events WHERE kind='collector.heartbeat' AND observed_at>=? AND observed_at<=? ORDER BY seq",
                      (bound(start), bound(end)))
    intervals, last, allowed, complete = [], start, 135, True
    for number, (observed, connected, interval) in enumerate(rows):
        if number % 2048 == 0 and time.monotonic() >= deadline:
            complete = False
            break
        when = stamp(observed)
        if when is None:
            continue
        try:
            allowed = max(120, min(float(interval or 60), 3600) * 2 + 15)
        except (TypeError, ValueError):
            allowed = 135
        if not connected:
            continue
        if when - last > allowed:
            intervals.append((last, when))
        last = when
    if complete and end - last > allowed:
        intervals.append((last, end))
    longest = sorted(intervals, key=lambda pair: pair[0] - pair[1])[:limit]
    return {"complete": complete, "intervals": len(intervals),
            "unconfirmed_seconds": round(sum(b - a for a, b in intervals)),
            "longest": [{"from": iso(a), "until": iso(b), "seconds": round(b - a)} for a, b in sorted(longest)]}


def gap_records(db, chats, start, end, workspace):
    if chats is not None and not chats:
        return {"count": 0, "recent": []}
    where = ["kind='coverage.gap'", "observed_at>=?", "observed_at<=?"]
    params = [bound(start), bound(end)]
    if chats is not None:
        scope = "chat_id IN (" + ",".join("?" * len(chats)) + ")"
        where.append("(" + scope + " OR chat_id IS NULL)" if workspace else scope)
        params.extend(sorted(chats))
    elif not workspace:
        where.append("chat_id IS NOT NULL")
    rows = db.execute("SELECT seq,observed_at,chat_id,json_extract(payload,'$.reason') FROM events WHERE "
                      + " AND ".join(where) + " ORDER BY seq DESC LIMIT 1001", params).fetchall()
    return {"count": len(rows) if len(rows) <= 1000 else "more than 1000",
            "recent": [{"event_seq": seq, "observed_at": observed, "chat_id": chat,
                        "reason": reason if isinstance(reason, str) else None} for seq, observed, chat, reason in rows[:10]]}


def activity(store, *, chat_id=None, sender_id=None, chat_ids=None, since=None, until=None, top=10,
             budget=BUDGET, workspace_gaps=True, now=None):
    """Counts for one chat or every chat in scope; chat_ids=None means the whole workspace."""
    now = datetime.now(timezone.utc).timestamp() if now is None else now
    start, end = (since.timestamp() if since else None), (until.timestamp() if until else None)
    chats = {chat_id} if chat_id is not None else chat_ids
    deadline = time.monotonic() + budget
    first, edits, deleted, missing = {}, Counter(), set(), set()
    found, names, observed = {}, {}, [None, None]
    complete, stopped_at = True, None
    with store.snapshot() as snapshot:
        db, head = snapshot.connection, snapshot.head
        rows = []
        if chats is None or chats:
            where = ["kind IN (" + ",".join("?" * len(SCANNED_KINDS)) + ")", "message_id IS NOT NULL"]
            params = list(SCANNED_KINDS)
            if chats is not None:
                where.append("chat_id IN (" + ",".join("?" * len(chats)) + ")")
                params.extend(sorted(chats))
            rows = db.execute("SELECT seq,kind,chat_id,message_id,observed_at,source_at,payload FROM events WHERE "
                              + " AND ".join(where) + " ORDER BY seq DESC", params)
        for number, row in enumerate(rows):
            if number % 512 == 0 and time.monotonic() >= deadline:
                complete, stopped_at = False, row["seq"]
                break
            key, kind = (row["chat_id"], row["message_id"]), row["kind"]
            observed[0] = row["observed_at"] if observed[0] is None else min(observed[0], row["observed_at"])
            observed[1] = row["observed_at"] if observed[1] is None else max(observed[1], row["observed_at"])
            if kind == "message.deleted":
                deleted.add(key)
                continue
            if kind == "message.missing_on_recheck":
                missing.add(key)
                continue
            payload = json.loads(row["payload"])
            sender = payload.get("sender_id")
            sender = sender if type(sender) is int else None
            domains_seen, handles_seen = references(payload)
            if domains_seen or handles_seen:
                known = found.setdefault(key, (set(), set()))
                known[0].update(domains_seen)
                known[1].update(handles_seen)
            if sender is not None:
                seen = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
                name, username = names.get(sender, (None, None))
                names[sender] = (name or plain(seen.get("display_name"), 256), username or plain(seen.get("username"), 64))
            if kind == "message.edited":
                edits[key] += 1
                continue
            first[key] = (stamp(payload.get("sent_at") or row["source_at"]), sender)
        window = start if start is not None else stamp(observed[0]) if observed[0] else None
        closing = min(end, now) if end is not None else now
        coverage = {"first_observed_at": observed[0], "last_observed_at": observed[1],
                    "gap_records": gap_records(db, chats, window, closing, workspace_gaps) if window is not None else
                    {"count": 0, "recent": []}, "workspace_gaps_visible": workspace_gaps}
        if workspace_gaps and window is not None and window < closing:
            coverage["collector_liveness"] = unconfirmed(db, window, closing, max(deadline, time.monotonic() + 1))
        elif not workspace_gaps:
            coverage["note"] = "Collector liveness is shown only to access covering the whole workspace."
    counted, untimed = {}, 0
    for key, (sent, sender) in first.items():
        if sender_id is not None and sender != sender_id:
            continue
        if sent is None:
            if start is not None or end is not None:
                continue
            untimed += 1
        elif start is not None and sent < start or end is not None and sent > end:
            continue
        counted[key] = (sent, sender)
    hours, weekdays, days = [0] * 24, [0] * 7, Counter()
    people, domains, handles = {}, Counter(), Counter()
    for key, (sent, sender) in counted.items():
        person = people.setdefault(sender, {"sender_id": sender, "messages": 0, "edited": 0, "deleted": 0,
                                            "first_message_at": None, "last_message_at": None})
        person["messages"] += 1
        person["edited"] += key in edits
        person["deleted"] += key in deleted
        if sent is not None:
            moment = datetime.fromtimestamp(sent, timezone.utc)
            hours[moment.hour] += 1
            weekdays[moment.weekday()] += 1
            days[moment.date().isoformat()] += 1
            person["first_message_at"] = sent if person["first_message_at"] is None else min(person["first_message_at"], sent)
            person["last_message_at"] = sent if person["last_message_at"] is None else max(person["last_message_at"], sent)
        found_domains, found_handles = found.get(key, ((), ()))
        domains.update(found_domains)
        handles.update(found_handles)
    total = len(counted)
    share = (lambda part: round(part / total, 4) if total else None)
    edited_count = sum(key in edits for key in counted)
    deleted_count = sum(key in deleted for key in counted)
    missing_count = sum(key in missing and key not in deleted for key in counted)
    participants = sorted(people.values(), key=lambda p: (-p["messages"], p["sender_id"] is None, p["sender_id"] or 0))
    for person in participants:
        name, username = names.get(person["sender_id"], (None, None))
        person.update(name=name, username=username, first_message_at=iso(person["first_message_at"]),
                      last_message_at=iso(person["last_message_at"]))
    times = [sent for sent, _ in counted.values() if sent is not None]
    result = {
        "chat_id": chat_id, "sender_id": sender_id,
        "period": {"since": iso(start), "until": iso(end), "basis": "message time reported by Telegram (UTC)"},
        "complete": complete, "messages": total, "messages_without_time": untimed,
        "senders": len([p for p in people if p is not None]),
        "first_message_at": iso(min(times)) if times else None, "last_message_at": iso(max(times)) if times else None,
        "edited": {"messages": edited_count, "share": share(edited_count),
                   "versions": sum(edits[key] for key in counted if key in edits)},
        "deleted": {"messages": deleted_count, "share": share(deleted_count)},
        "missing_on_recheck": {"messages": missing_count, "share": share(missing_count)},
        "by_hour_utc": hours, "by_weekday_utc": weekdays, "weekday_order": "Monday first",
        "peaks": {"hours_utc": [{"hour": hour, "messages": hours[hour]} for hour in
                                sorted(range(24), key=lambda h: (-hours[h], h))[:3] if hours[hour]],
                  "days": [{"date": day, "messages": count} for day, count in
                           sorted(days.items(), key=lambda item: (-item[1], item[0]))[:5]]},
        "participants": participants[:top], "participants_truncated": len(participants) > top,
        "domains": ranked(domains, top, "domain"), "handles": ranked(handles, top, "handle"),
        "coverage": coverage, "meaning": MEANING, "untrusted_content": True}
    if not complete:
        result["partial"] = {"records_before_seq_not_read": stopped_at,
                             "reason": "Time limit reached; only the most recent records were counted. Narrow the "
                                       "period or chat, or allow more time when reading locally."}
    if workspace_gaps and head:
        result["journal_head"] = {"seq": head["seq"], "hash": head["hash"]}
    return result
