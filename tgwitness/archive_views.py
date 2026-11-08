import base64
import hashlib
import io
import json
import time
import warnings
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


FIRST_KINDS = ("message.new", "message.snapshot", "message.recovered")
PREVIEW_BYTES = 36000
PREVIEW_SIDES = (1024, 768, 512, 384, 256, 128, 64)
IMAGE_BYTES = 32 * 1024 * 1024
IMAGE_PIXELS = 40_000_000
IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
BUDGET = 5


def stamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def day_bounds(day, zone):
    try:
        place = ZoneInfo(zone or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Use an IANA time zone such as Europe/Kyiv or UTC.") from None
    try:
        first = date.fromisoformat(day or "")
    except ValueError:
        raise ValueError("Use a date such as 2026-10-01.") from None
    start = datetime(first.year, first.month, first.day, tzinfo=place)
    try:
        following = first + timedelta(days=1)
    except OverflowError:
        raise ValueError("Choose a date before 9999-12-31.") from None
    end = datetime(following.year, following.month, following.day, tzinfo=place)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def message_time(event):
    payload = event["payload"]
    sent = stamp(payload.get("sent_at") or event.get("source_at")) if isinstance(payload, dict) else None
    return (sent, "telegram") if sent else (stamp(event["observed_at"]), "observed")


def by_date(store, query, view, budget=BUDGET):
    start, end = day_bounds(query.date, query.timezone)
    deadline, items, more, complete = time.monotonic() + budget, [], False, True
    cursor = query.before
    marks = ",".join("?" * len(FIRST_KINDS))
    with store.snapshot() as snapshot:
        rows = snapshot.connection.execute(
            "SELECT * FROM events WHERE chat_id=? AND kind IN (" + marks + ") AND seq<? ORDER BY seq DESC",
            (query.chat_id, *FIRST_KINDS, query.before or 2**63 - 1))
        for number, row in enumerate(rows):
            if number % 1024 == 0 and time.monotonic() >= deadline:
                complete = False
                cursor = cursor or row["seq"] + 1
                break
            cursor = row["seq"]
            event = {**dict(row), "payload": json.loads(row["payload"])}
            moment, basis = message_time(event)
            if moment is None or not start <= moment < end:
                continue
            if len(items) == query.limit:
                more = True
                cursor = row["seq"] + 1
                break
            items.append({**view(query.workspace, event), "message_time": moment.isoformat(), "time_basis": basis})
    return {"date": query.date, "timezone": query.timezone or "UTC", "from_utc": start.isoformat(),
            "until_utc": end.isoformat(), "items": items,
            "next_before": cursor if more or not complete else None,
            "complete": complete and not more, "untrusted_content": True,
            "basis": "First saved versions whose Telegram sending time falls on this day in this time zone; the "
                     "observation time is used only when Telegram's time is missing. Edits and deletion records are "
                     "separate; read them with get_message_versions."}


def latest_state(store, chat_id):
    from .chat_state import latest
    record, state, _base = latest(store, chat_id)
    return record, state


def pinned(store, query, view):
    record, state = latest_state(store, query.chat_id)
    snapshot = None
    items = []
    if record is not None and state is not None and "pinned" in state:
        snapshot = {"event_seq": record["seq"], "observed_at": record["observed_at"], "pinned": state["pinned"],
                    "pinned_total": state.get("pinned_total"), "errors": record["payload"].get("errors") or {},
                    "complete": state.get("parts_complete", {}).get("pinned"),
                    "carried_forward": "pinned" in record["payload"].get("carried_forward", [])}
        for message_id in state["pinned"][:query.limit]:
            found = store.events(chat_id=query.chat_id, message_id=message_id, limit=1, message_only=True)
            items.append(view(query.workspace, found[0]) if found else
                         {"message_id": message_id, "saved": False,
                          "note": "Pinned, but no saved version of this message is in the archive."})
    pins = []
    with store.snapshot() as journal:
        rows = journal.connection.execute(
            "SELECT seq,kind,message_id,observed_at,json_extract(payload,'$.reply_to_message_id'),"
            "json_extract(payload,'$.raw.messages') FROM events WHERE chat_id=? AND (kind='message.unpinned' OR "
            "(kind IN ('message.new','message.recovered') AND json_extract(payload,'$.service_action')="
            "'MessageActionPinMessage')) ORDER BY seq DESC LIMIT ?", (query.chat_id, query.limit)).fetchall()
    for seq, kind, message_id, observed, target, unpinned in rows:
        pins.append({"event_seq": seq, "observed_at": observed, "action": "unpinned" if kind == "message.unpinned"
                     else "pinned", "message_ids": json.loads(unpinned) if kind == "message.unpinned" and unpinned
                     else [target] if target else [], "service_message_id": message_id if kind != "message.unpinned" else None})
    return {"chat_id": query.chat_id, "snapshot": snapshot, "items": items, "pin_events": pins, "untrusted_content": True,
            "meaning": "snapshot lists what Telegram showed as pinned at that time (chat.state). pin_events are pin "
                       "service messages and unpin notices observed live; an unpin of all messages may have no notice. "
                       "No snapshot means chat-state snapshots were off or have not run for this chat yet."}


def chat_stats(store, query, allowed, gap_summary):
    chats = {query.chat_id} if query.chat_id is not None else allowed
    counts = store.stats(chats)["counts"] if chats is None or chats else {}
    result = {"chat_id": query.chat_id,
              "records": sum(counts.values()), "saved_messages": sum(counts.get(k, 0) for k in FIRST_KINDS),
              "edits": counts.get("message.edited", 0), "deletion_notices": counts.get("message.deleted", 0),
              "missing_on_recheck": counts.get("message.missing_on_recheck", 0),
              "media_saved": counts.get("media.saved", 0), "media_skipped": counts.get("media.skipped", 0),
              "service_messages": counts.get("chat.service", 0) + counts.get("membership.service", 0),
              "untrusted_content": True,
              "meaning": "Counts of saved journal records, cheap enough to scope a larger read. A message saved live "
                         "and again by history or recheck counts once per record."}
    if query.chat_id is not None:
        with store.snapshot() as journal:
            first = journal.connection.execute("SELECT observed_at FROM events WHERE chat_id=? ORDER BY seq LIMIT 1",
                                               (query.chat_id,)).fetchone()
            last = journal.connection.execute("SELECT observed_at FROM events WHERE chat_id=? ORDER BY seq DESC LIMIT 1",
                                              (query.chat_id,)).fetchone()
        result.update(first_observed_at=first[0] if first else None, last_observed_at=last[0] if last else None)
        record, state = latest_state(store, query.chat_id)
        if record is not None:
            result["chat_state"] = {"event_seq": record["seq"], "observed_at": record["observed_at"],
                                    **{k: (state or {}).get(k) for k in ("title", "participants_count", "admins_count")}}
    result["gap_summary"] = gap_summary
    return result


def topic_of(header):
    if not isinstance(header, dict):
        return None
    if header.get("forum_topic"):
        return header.get("reply_to_top_id") or header.get("reply_to_msg_id")
    return header.get("reply_to_top_id")


def topics(store, query, budget=BUDGET):
    deadline, found, members, complete, forum = time.monotonic() + budget, {}, {}, True, False
    seen = set()
    marks = ",".join("?" * len(FIRST_KINDS))
    with store.snapshot() as journal:
        rows = journal.connection.execute(
            "SELECT seq,message_id,observed_at,json_extract(payload,'$.service_action'),json_extract(payload,'$.raw.action'),"
            "json_extract(payload,'$.raw.reply_to'),json_extract(payload,'$.sent_at') FROM events WHERE chat_id=? "
            "AND kind IN (" + marks + ") ORDER BY message_id,seq", (query.chat_id, *FIRST_KINDS))
        for number, (seq, message_id, observed, service, action, header, sent) in enumerate(rows):
            if number % 2048 == 0 and time.monotonic() >= deadline:
                complete = False
                break
            if type(message_id) is not int or message_id in seen:
                continue
            seen.add(message_id)
            action = json.loads(action) if action else {}
            header = json.loads(header) if header else None
            if service == "MessageActionTopicCreate":
                forum = True
                entry = found.setdefault(message_id, {"topic_id": message_id, "titles": [], "created_event_seq": seq})
                entry["created_at"] = sent
                entry["titles"].append({"title": action.get("title"), "event_seq": seq, "observed_at": observed})
                continue
            topic = topic_of(header)
            if topic and isinstance(header, dict) and header.get("forum_topic"):
                forum = True
                found.setdefault(topic, {"topic_id": topic, "titles": []})
            if service == "MessageActionTopicEdit" and topic:
                forum = True
                entry = found.setdefault(topic, {"topic_id": topic, "titles": []})
                if isinstance(action.get("title"), str):
                    entry["titles"].append({"title": action["title"], "event_seq": seq, "observed_at": observed})
                for flag in ("closed", "hidden"):
                    if isinstance(action.get(flag), bool):
                        entry[flag] = action[flag]
                continue
            if type(message_id) is int:
                members.setdefault(topic, set()).add(message_id)
    if forum:
        found.setdefault(1, {"topic_id": 1, "titles": [{"title": "General", "event_seq": None, "observed_at": None}]})
        members.setdefault(1, set()).update(members.pop(None, set()))
    listed = []
    topic_ids = sorted(found)
    for topic_id in topic_ids[query.offset:query.offset + query.limit]:
        entry = found[topic_id]
        entry["title"] = entry["titles"][-1]["title"] if entry["titles"] else None
        entry["titles_total"] = len(entry["titles"])
        entry["titles_complete"] = len(entry["titles"]) <= 20
        entry["titles"] = entry["titles"][-20:]
        entry["messages_saved"] = len(members.get(topic_id, ()))
        listed.append(entry)
    next_offset = query.offset + len(listed) if query.offset + len(listed) < len(found) else None
    return {"chat_id": query.chat_id, "forum": forum, "topics": listed, "topics_total": len(found),
            "next_offset": next_offset, "scan_complete": complete,
            "complete": complete and next_offset is None and all(t["titles_complete"] for t in listed),
            "untrusted_content": True,
            "meaning": "Topics found in saved topic-creation and topic-edit service messages; message counts are saved "
                       "messages that Telegram marked as belonging to each topic. Topics created before observation "
                       "appear once a saved message refers to them."}


def media_preview(store, query, allowed, source_ref):
    digest = (query.media_sha256 or "").lower()
    params, scope = [digest], ""
    if allowed is not None:
        if not allowed:
            raise ValueError("This file is not available to this access.")
        scope = " AND chat_id IN (" + ",".join("?" * len(allowed)) + ")"
        params += sorted(allowed)
    with store.lock:
        row = store.db.execute("SELECT * FROM events WHERE kind='media.saved' AND json_extract(payload,'$.media_sha256')=?"
                               + scope + " ORDER BY seq LIMIT 1", params).fetchone()
    if row is None:
        raise ValueError("This file is not available to this access.")
    event = {**dict(row), "payload": json.loads(row["payload"])}
    path = store.root / "media" / digest
    result = {"media_sha256": digest, "source": source_ref(query.workspace, event),
              "mime_type": event["payload"].get("mime_type"), "bytes": event["payload"].get("size"),
              "untrusted_content": True}
    if path.is_symlink() or not path.is_file():
        return {**result, "available": False, "note": "The file is not on this computer (moved to storage or not kept)."}
    if path.stat().st_size > IMAGE_BYTES:
        return {**result, "available": True, "verified": False,
                "note": "Preview size limit exceeded; open the preserved file in the panel."}
    with path.open("rb") as stream:
        data = stream.read(IMAGE_BYTES + 1)
    if len(data) > IMAGE_BYTES:
        return {**result, "available": True, "verified": False, "note": "Preview size limit exceeded."}
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        return {**result, "available": False, "verified": False,
                "note": "The stored file does not match its recorded SHA-256; it is not shown."}
    from .media_preview import content_type
    mime = content_type(path)
    result.update(available=True, verified=True, mime_type=mime)
    if mime not in IMAGE_TYPES:
        return {**result, "note": "Not an image; open the file in the panel."}
    from PIL import Image, ImageOps, UnidentifiedImageError
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as picture:
                if picture.width * picture.height > IMAGE_PIXELS:
                    return {**result, "note": "Image dimensions exceed the preview limit."}
                picture.seek(0)
                picture = ImageOps.exif_transpose(picture).convert("RGB")
                for side in PREVIEW_SIDES:
                    copy = picture.copy()
                    copy.thumbnail((side, side))
                    buffer = io.BytesIO()
                    copy.save(buffer, "JPEG", quality=72, optimize=True)
                    if buffer.tell() <= PREVIEW_BYTES:
                        break
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
        return {**result, "note": "The preserved image cannot be decoded for a preview."}
    data = buffer.getvalue()
    if len(data) > PREVIEW_BYTES:
        return {**result, "note": "The image cannot fit within the preview size limit."}
    result["preview"] = {"mime_type": "image/jpeg", "width": copy.width, "height": copy.height,
                         "data_base64": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest(),
                         "derived": "Downscaled JPEG preview made on request; the preserved file and its SHA-256 "
                                    "are unchanged. Describe what is visible together with media_sha256 and event_seq."}
    return result

