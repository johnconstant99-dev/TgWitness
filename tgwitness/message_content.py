"""Comparable message content, excluding delivery and file-access metadata."""
from . import keyboard


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items()
                if k not in ("access_hash", "file_reference", "dc_id")}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


# Parts of an attachment that Telegram fills in or updates on its own, not the sender:
# a link preview loading, story views, paid media unlocked by this account.
GENERATED = {"MessageMediaWebPage": ("webpage",), "MessageMediaStory": ("story",),
             "MessageMediaPaidMedia": ("extended_media",), "MessageMediaInvoice": ("receipt_msg_id",)}


def of_payload(payload):
    raw = payload.get("raw") or {}
    media = stable(raw.get("media"))
    if isinstance(media, dict) and media.get("_") == "MessageMediaPoll":
        media.pop("results", None)  # Vote counts are observations, not message edits.
    if isinstance(media, dict):
        for key in GENERATED.get(media.get("_"), ()):
            media.pop(key, None)
    return {"text": payload.get("text") or "", "buttons": keyboard.of_payload(payload),
            "media": media, "entities": raw.get("entities") or [],
            "action": raw.get("action"), "invert_media": bool(raw.get("invert_media"))}
