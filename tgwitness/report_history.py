VERSION_KINDS = frozenset(("message.new", "message.snapshot", "message.recovered", "message.edited"))
GONE_KINDS = frozenset(("message.deleted", "message.missing_on_recheck"))


def collect(events, changed, limit=1000, *, predicate=None):
    from .report import message_times, pointing, shown_details

    if type(limit) is not int or limit < 0:
        raise ValueError("History limit must be a non-negative integer")
    changed = set(changed)
    found = {}
    for event in events:
        key = (event.get("chat_id"), event.get("message_id"))
        kind = event.get("kind")
        if key not in changed or kind not in VERSION_KINDS | GONE_KINDS:
            continue
        if key not in found:
            if len(found) >= limit:
                continue
            found[key] = {"versions": [], "gone": []}
        item = found[key]
        selected = bool(predicate(event)) if predicate is not None else True
        flags = {"in_selection": selected, "context_only": not selected}
        payload = event.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        if kind in VERSION_KINDS:
            times = message_times(payload)
            version = {"seq": event["seq"], "kind": kind, "observed_at": event["observed_at"],
                       "text": payload.get("text") if isinstance(payload.get("text"), str) else "",
                       **times, "telegram_at": times["edited_at"] or times["sent_at"],
                       "sender": payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {},
                       "sender_id": payload.get("sender_id"), "details": shown_details(payload),
                       "withheld": bool(payload.get("text_withheld")), **flags}
            last = item["versions"][-1] if item["versions"] else None
            if kind != "message.edited" and last and last["text"] == version["text"] \
                    and pointing(last) == pointing(version) and last["withheld"] == version["withheld"] \
                    and message_times(last) == times \
                    and last["in_selection"] == version["in_selection"]:
                continue
            item["versions"].append(version)
        else:
            previous = item["versions"][-1] if item["versions"] else None
            item["gone"].append({"seq": event["seq"], "kind": kind, "observed_at": event["observed_at"],
                                 "previous_version_seq": previous["seq"] if previous else None, **flags})
    return found


def preview(events, changed, *, predicate):
    from .report import message_times
    keys = set(tuple(key) for key in changed)
    found, previous = {}, {}
    for event in events:
        key = (event.get("chat_id"), event.get("message_id"))
        kind = event.get("kind")
        if key not in keys or kind not in VERSION_KINDS | GONE_KINDS:
            continue
        item = found.setdefault(key, {"chat_id": key[0], "message_id": key[1], "versions": [], "gone": [],
                                      "versions_truncated": False, "gone_truncated": False})
        row = {"seq": event["seq"], "kind": kind, "observed_at": event["observed_at"],
               "context_only": not predicate(event)}
        if kind in VERSION_KINDS:
            payload = event.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            text = payload.get("text") if isinstance(payload.get("text"), str) else ""
            row.update(text=text[:240], text_truncated=len(text) > 240, **message_times(payload))
            previous[key] = row["seq"]
            item["versions"].append(row)
            if len(item["versions"]) > 40:
                del item["versions"][0]
                item["versions_truncated"] = True
        else:
            row["previous_version_seq"] = previous.get(key)
            item["gone"].append(row)
            if len(item["gone"]) > 40:
                del item["gone"][0]
                item["gone_truncated"] = True
    return list(found.values())
