from bisect import bisect_left
from collections import Counter
from datetime import timedelta
from statistics import median

from tgwitness.action_protocol import moment, reference, seconds

FORMAT = "tgwitness-insights-v1"
LIMIT = 50000
BURST_SECONDS = 60
CONTEXT_SECONDS = 600
KINDS = "message.new,message.snapshot,message.recovered,message.deleted,deletion.batch,actor.status"
MESSAGE_KINDS = ("message.new", "message.snapshot", "message.recovered")
LIFETIMES = ((60, "under 1 minute"), (600, "1–10 minutes"), (3600, "10–60 minutes"), (86400, "1–24 hours"),
             (None, "over 1 day"))
REPLIES = ((10, "under 10 seconds"), (60, "10–60 seconds"), (600, "1–10 minutes"), (3600, "10–60 minutes"),
           (None, "over 1 hour"))
LIMITS = (
    "Message and reply times are Telegram server dates with one-second resolution; deletion times are the collector's "
    "clock when the notice arrived.",
    "A reply is the first message from the other side after one of this account's messages. In groups it may answer "
    "something else.",
    "A deletion wave groups notices that arrived within a minute.",
    "Online observations exist only while presence recording is on and the person's privacy settings allow it.",
    "Counts cover the newest records read for this analysis, not necessarily the whole chat.",
)


def bucket(value, buckets):
    return next(label for limit, label in buckets if limit is None or value < limit)


def hour(value, offset_minutes):
    parsed = moment(value)
    return None if parsed is None else (parsed + timedelta(minutes=offset_minutes)).hour


def summary(values):
    return {"count": len(values), "median": median(values) if values else None,
            "min": min(values) if values else None, "max": max(values) if values else None}


def counted(values, buckets):
    found = Counter(bucket(value, buckets) for value in values)
    return [{"label": label, "count": found.get(label, 0)} for _, label in buckets]


def analyze(events, chat_id=None, offset_minutes=0, lookup=None):
    events = sorted((e for e in events if type(e.get("seq")) is int), key=lambda e: e["seq"])
    messages, deletions, batches, presence = {}, [], [], {}
    for event in events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        kind, message_id = event.get("kind"), event.get("message_id")
        if kind in MESSAGE_KINDS and message_id is not None and message_id not in messages:
            sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
            messages[message_id] = {"id": message_id, "sent_at": payload.get("sent_at"), "seq": event["seq"],
                                    "outgoing": bool(payload.get("outgoing")), "sender_id": payload.get("sender_id"),
                                    "name": sender.get("display_name"), "ref": reference(event)}
        elif kind == "message.deleted" and message_id is not None:
            deletions.append(event)
        elif kind == "deletion.batch":
            batches.append({"at": event.get("observed_at"), "count": payload.get("count"), "ref": reference(event)})
        elif kind == "actor.status":
            status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
            person = presence.setdefault(payload.get("user_id"), {"user_id": payload.get("user_id"), "online": [0] * 24,
                                                                     "observations": 0})
            person["observations"] += 1
            when = hour(event.get("observed_at"), offset_minutes)
            if status.get("state") == "online" and when is not None:
                person["online"][when] += 1
    ordered = sorted((m for m in messages.values() if moment(m["sent_at"])), key=lambda m: (moment(m["sent_at"]), m["id"]))
    hours = {"incoming": [0] * 24, "outgoing": [0] * 24}
    senders = {}
    for item in ordered:
        hours["outgoing" if item["outgoing"] else "incoming"][hour(item["sent_at"], offset_minutes)] += 1
        if not item["outgoing"] and item["sender_id"] is not None:
            person = senders.setdefault(item["sender_id"], {"sender_id": item["sender_id"], "name": item["name"],
                                                            "count": 0, "hours": [0] * 24})
            person["count"] += 1
            person["name"] = person["name"] or item["name"]
            person["hours"][hour(item["sent_at"], offset_minutes)] += 1
    pairs, unanswered, waiting = [], 0, None
    for item in ordered:
        if item["outgoing"]:
            unanswered += waiting is not None
            waiting = item
        elif waiting is not None:
            delay = seconds(item["sent_at"], waiting["sent_at"])
            if delay is not None and delay >= 0:
                pairs.append({"message_id": waiting["id"], "sent_at": waiting["sent_at"], "reply_id": item["id"],
                              "reply_at": item["sent_at"], "seconds": delay, "hour": hour(waiting["sent_at"], offset_minutes),
                              "ref": item["ref"]})
            waiting = None
    unanswered += waiting is not None
    by_hour = []
    for value in range(24):
        found = [pair["seconds"] for pair in pairs if pair["hour"] == value]
        if found:
            by_hour.append({"hour": value, "count": len(found), "median": median(found)})
    lifetimes, removed = [], []
    for event in deletions:
        known = messages.get(event["message_id"]) or (lookup(event["message_id"]) if lookup else None)
        sent = (known or {}).get("sent_at")
        life = seconds(event.get("observed_at"), sent) if sent else None
        removed.append({"message_id": event["message_id"], "at": event.get("observed_at"), "sent_at": sent,
                        "lifetime": life if life is not None and life >= 0 else None,
                        "outgoing": (known or {}).get("outgoing"), "seq": event["seq"], "ref": reference(event)})
    lifetimes = [item["lifetime"] for item in removed if item["lifetime"] is not None]
    waves = []
    for item in removed:
        if waves and (seconds(item["at"], waves[-1]["end"]) or 0) <= BURST_SECONDS:
            wave = waves[-1]
            wave.update(end=item["at"], count=wave["count"] + 1, last_id=max(wave["last_id"], item["message_id"]),
                        first_id=min(wave["first_id"], item["message_id"]))
        else:
            wave = {"start": item["at"], "end": item["at"], "count": 1, "first_id": item["message_id"],
                    "last_id": item["message_id"], "own": 0, "other": 0, "unknown": 0, "start_seq": item["seq"]}
            waves.append(wave)
        wave["own" if item["outgoing"] is True else "other" if item["outgoing"] is False else "unknown"] += 1
    by_seq = {m["seq"]: m for m in messages.values()}
    order = sorted(by_seq)
    for index, wave in enumerate(waves):
        position = bisect_left(order, wave["start_seq"]) - 1
        last = by_seq[order[position]] if position >= 0 else None
        gap = seconds(wave["start"], last["sent_at"]) if last else None
        if last and gap is not None and 0 <= gap <= CONTEXT_SECONDS:
            wave["after"] = {"message_id": last["id"], "outgoing": last["outgoing"], "seconds": gap, "ref": last["ref"]}
        if index:
            wave["since_previous_wave"] = seconds(wave["start"], waves[index - 1]["end"])
        del wave["start_seq"]
    per_day = Counter((item["at"] or "")[:10] for item in removed if item["at"])
    return {"format": FORMAT, "chat_id": chat_id, "offset_minutes": offset_minutes,
            "counts": {"messages": len(ordered), "incoming": sum(not m["outgoing"] for m in ordered),
                       "outgoing": sum(m["outgoing"] for m in ordered), "deletions": len(removed),
                       "own_deletions": sum(item["outgoing"] is True for item in removed),
                       "cleared_histories": len(batches)},
            "hours": hours,
            "senders": sorted(senders.values(), key=lambda p: -p["count"])[:5],
            "replies": {**summary([p["seconds"] for p in pairs]), "unanswered": unanswered,
                        "buckets": counted([p["seconds"] for p in pairs], REPLIES), "by_hour": by_hour,
                        "pairs": pairs[-200:]},
            "deletions": {**summary(lifetimes), "lifetimes": counted(lifetimes, LIFETIMES), "waves": waves[-100:],
                          "per_day": [{"day": day, "count": count} for day, count in sorted(per_day.items())],
                          "cleared_histories": batches[-20:]},
            "presence": sorted(presence.values(), key=lambda p: -p["observations"])[:10],
            "limits": list(LIMITS)}


def collect(store, chat_id, offset_minutes=0, limit=LIMIT):
    events = store.events(chat_id=chat_id, kind=KINDS, limit=limit)

    def lookup(message_id):
        content = store.message_state(chat_id, message_id)["content"]
        return {"sent_at": content.get("sent_at"), "outgoing": bool(content.get("outgoing"))} if content else None

    result = analyze(events, chat_id, offset_minutes, lookup)
    result["truncated"] = len(events) >= limit
    return result
