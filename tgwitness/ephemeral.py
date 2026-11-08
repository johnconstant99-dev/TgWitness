
VIEW_ONCE = 0x7FFFFFFF
VIEWING_NOTE = "This attachment was saved when Telegram delivered it to this account."
RETRY_NOTE = "Self-destructing media may disappear before another attempt."
OPENED = {False: "Not opened by the observing account", True: "Opened by the observing account"}


def describe(media, unread=None):
    if hasattr(media, "to_dict"):
        media = media.to_dict()
    if not isinstance(media, dict):
        return None
    field = {"MessageMediaPhoto": "photo", "MessageMediaDocument": "document"}.get(media.get("_"))
    ttl = media.get("ttl_seconds")
    if not field or type(ttl) is not int or ttl <= 0:
        return None
    attachment = media.get(field)
    if hasattr(attachment, "to_dict"):
        attachment = attachment.to_dict()
    present = isinstance(attachment, dict) and attachment.get("_") == field.title()
    facts = {"ttl_seconds": ttl, "mode": "view_once" if ttl == VIEW_ONCE else "timer",
             "availability": "available_at_observation" if present else "unavailable_at_observation",
             "human_viewing": "not_established"}
    if type(unread) is bool:
        facts["observer_opened"] = not unread
    return facts


def outcome(facts, status):
    return {"ephemeral_media": {**facts, "outcome": status}, "viewing_note": VIEWING_NOTE,
            **({"retry_warning": RETRY_NOTE} if status != "saved" else {})}


def label(say, facts):
    if not facts:
        return ""
    title = say("View-once media") if facts.get("mode") == "view_once" else say(
        "Self-destructing media：{n} s", n=facts["ttl_seconds"])
    status = facts.get("outcome")
    detail = {"saved": "File preserved", "unavailable": "Attachment unavailable when observed",
              "not_saved": "File not preserved", "retry": "Preservation pending",
              "hashed": "File hashes; content not downloaded"}.get(status)
    if detail is None and facts.get("availability") == "unavailable_at_observation":
        detail = "Attachment unavailable when observed"
    opened = OPENED.get(facts.get("observer_opened"))
    return " · ".join([title, *([say(opened)] if opened else []), *([say(detail)] if detail else []), say(VIEWING_NOTE),
                       *([say(RETRY_NOTE)] if status and status != "saved" else [])])
