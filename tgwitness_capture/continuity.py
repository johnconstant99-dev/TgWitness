"""Analysis of an unchanged Desktop chat export, never a Telegram API client."""
import html
import base64
import hashlib
from datetime import datetime, timezone

from .format import decode

CHANNEL_TYPES = {"private_supergroup", "public_supergroup", "private_channel", "public_channel"}
CHAT_TYPES = CHANNEL_TYPES | {"personal_chat", "private_group", "saved_messages", "bot_chat"}
MAX_MESSAGES = 200000
CHAT_STYLE = ('body{font:16px system-ui;background:#101923;color:#ecf1f6;max-width:880px;margin:32px auto;padding:0 16px}'
              'article{background:#1c2b39;border:1px solid #354b5e;padding:16px;border-radius:12px;margin:12px 0}'
              'header{color:#a5c3d9}p{white-space:pre-wrap;overflow-wrap:anywhere}'
              'aside{padding:14px;background:#48391c;border-left:4px solid #f0ba58;overflow-wrap:anywhere}li{margin:8px 0}')
STYLE_HASH = base64.b64encode(hashlib.sha256(CHAT_STYLE.encode()).digest()).decode()
LIMITS = [
    "Only the selected export and recorded viewports are covered; full history is not established.",
    "An absent ID or reply is not proof of deletion. Time intervals may be ordinary inactivity.",
    "Private chats and basic groups share an account-wide ID sequence; numeric gaps are not counted.",
    "Visual observations are operator annotations linked to frames, not Telegram-authenticated messages.",
    "Signatures protect recorded bytes relative to trusted keys and retained checkpoints, not authorship or truth.",
    "Official clients, pacing and WARP cannot guarantee account safety or legal admissibility.",
]


def positive_id(value):
    return type(value) is int and 0 < value < 2**63


def text_of(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(item if isinstance(item, str) else str(item.get("text", ""))
                       for item in value if isinstance(item, (str, dict)))
    return ""


def parse_export(raw):
    if len(raw) > 64 * 1024**2:
        raise ValueError("Chat JSON exceeds 64 MiB; split the collection scope")
    chat = decode(raw)
    if (not isinstance(chat, dict) or chat.get("type") not in CHAT_TYPES
            or not positive_id(chat.get("id")) or not isinstance(chat.get("messages"), list)):
        raise ValueError("Choose a single Telegram Desktop chat export (result.json), not an account export")
    if len(chat["messages"]) > MAX_MESSAGES:
        raise ValueError("Chat exceeds the analysis limit")
    seen = set()
    for message in chat["messages"]:
        if not isinstance(message, dict) or not positive_id(message.get("id")) or message["id"] in seen:
            raise ValueError("Invalid or duplicate message ID")
        seen.add(message["id"])
        reply = message.get("reply_to_message_id")
        if reply is not None and not positive_id(reply):
            raise ValueError("Invalid reply ID")
    return chat


def timestamp(message):
    value = message.get("date_unixtime")
    try:
        if isinstance(value, bool):
            return None
        return datetime.fromtimestamp(int(value), timezone.utc)
    except (ValueError, TypeError, OSError, OverflowError):
        return None


def analyze(chat, visual=(), time_gap_seconds=86400):
    """No per-ID expansion: huge gaps cost one record, not billions of entries."""
    messages = sorted(chat["messages"], key=lambda item: item["id"])
    by_id = {message["id"]: message for message in messages}
    findings = []
    previous = None
    for message in messages:
        mid = message["id"]
        if previous is not None:
            if chat["type"] in CHANNEL_TYPES and mid > previous["id"] + 1:
                findings.append({"kind": "id_interval_candidate", "before_id": mid,
                                 "first": previous["id"] + 1, "last": mid - 1,
                                 "count": mid - previous["id"] - 1, "cause": "unknown"})
            start, end = timestamp(previous), timestamp(message)
            if start and end and (end - start).total_seconds() >= time_gap_seconds:
                findings.append({"kind": "time_interval", "before_id": mid,
                                 "seconds": int((end - start).total_seconds()), "cause": "unknown"})
        reply = message.get("reply_to_message_id")
        if reply and reply not in by_id:
            findings.append({"kind": "unresolved_reply", "before_id": mid, "reply_to": reply,
                             "cause": "outside_export_or_unavailable"})
        previous = message
    matched = 0
    for observation in visual:
        if observation["chat_id"] != chat["id"]:
            continue
        mid = observation["message_id"]
        message = by_id.get(mid)
        kind = "visual_id_outside_export" if message is None else (
            "source_mismatch" if observation["text"] != text_of(message.get("text")) else "operator_match")
        matched += kind == "operator_match"
        findings.append({"kind": kind, "before_id": mid, "frame_sha256": observation["frame_sha256"],
                         "cause": "unknown", "basis": "operator_transcription", "observed_at": observation["observed_at"]})
    return {"format": "tgwitness-trusted-continuity-v1", "chat_id": chat["id"], "chat_type": chat["type"],
            "messages": len(messages), "id_intervals_applicable": chat["type"] in CHANNEL_TYPES,
            "scope": "IDs between the first and last exported message; export filters unknown",
            "visual_comparison": "operator_annotated" if visual else "unavailable_no_annotated_frames",
            "operator_matches": matched, "findings": findings, "limits": LIMITS}


def render(chat, report):
    escape = lambda value: html.escape(str(value), quote=True)
    annotations = {}
    for finding in report["findings"]:
        annotations.setdefault(finding["before_id"], []).append(finding)
    rows = []
    for message in sorted(chat["messages"], key=lambda item: item["id"]):
        mid = message["id"]
        for finding in annotations.pop(mid, []):
            rows.append('<aside role="note">' + escape(describe(finding)) + '</aside>')
        context = ''
        if message.get("reply_to_message_id"):
            reply = message["reply_to_message_id"]
            context += f'<p>Reply to <a href="#m{reply}">#{reply}</a></p>'
        if message.get("forwarded_from"):
            context += '<p>Forwarded from: ' + escape(message["forwarded_from"]) + '</p>'
        if message.get("action"):
            context += '<p>Service record: ' + escape(message["action"]) + '</p>'
        for field in ("photo", "file"):
            if message.get(field):
                context += '<p>Attachment reference (bytes not included): ' + escape(message[field]) + '</p>'
        rows.append(f'<article id="m{mid}"><header>#{mid} · {escape(message.get("date", ""))} · '
                    f'{escape(message.get("from", message.get("actor", "")))}</header>'
                    + context + f'<p>{escape(text_of(message.get("text")))}</p></article>')
    for findings in annotations.values():
        rows.extend('<aside role="note">' + escape(describe(finding)) + '</aside>' for finding in findings)
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Trusted Live · annotated chat</title><style>' + CHAT_STYLE + '</style>'
            '<h1>Trusted Live · ' + escape(chat.get("name", "Chat")) + '</h1>'
            '<p>Analysis of the preserved Desktop export. Highlighted intervals have an unknown cause.</p><ul>'
            + ''.join('<li>' + escape(limit) + '</li>' for limit in report["limits"]) + '</ul>'
            + ''.join(rows) + '</html>').encode()


def describe(finding):
    kind = finding["kind"]
    if kind == "id_interval_candidate":
        return f'IDs {finding["first"]}–{finding["last"]} are absent from this export ({finding["count"]} IDs). Cause unknown.'
    if kind == "unresolved_reply":
        return f'Reply to #{finding["reply_to"]}: the referenced message is outside this export or unavailable.'
    if kind == "time_interval":
        return f'Time interval: {finding["seconds"] / 3600:.1f} hours between exported messages. This may be ordinary inactivity.'
    if kind == "source_mismatch":
        return 'Exported text differs from the operator’s frame transcription. Review both sources; this alone does not prove an edit.'
    if kind == "operator_match":
        return 'Exported text matches the operator’s frame transcription. This is an operator comparison, not Telegram authentication.'
    return f'Operator annotated message #{finding["before_id"]} is absent from the export. Cause unknown.'
