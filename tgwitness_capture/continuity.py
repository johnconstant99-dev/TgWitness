import html
import base64
import hashlib
from datetime import datetime, timezone

from .format import decode

CHANNEL_TYPES = {"private_supergroup", "public_supergroup", "private_channel", "public_channel"}
CHAT_TYPES = CHANNEL_TYPES | {"personal_chat", "private_group", "saved_messages", "bot_chat"}
FORMATS = {1: "tgwitness-trusted-continuity-v1", 2: "tgwitness-trusted-continuity-v2",
           3: "tgwitness-trusted-continuity-v3"}
MAX_MESSAGES = 200000
RICH_DEPTH = 64
CHAT_STYLE = ('body{font:16px system-ui;background:#101923;color:#ecf1f6;max-width:880px;margin:32px auto;padding:0 16px}'
              'article{background:#1c2b39;border:1px solid #354b5e;padding:16px;border-radius:12px;margin:12px 0}'
              'header{color:#a5c3d9}p{white-space:pre-wrap;overflow-wrap:anywhere}'
              'aside{padding:14px;background:#48391c;border-left:4px solid #f0ba58;overflow-wrap:anywhere}li{margin:8px 0}')
STYLE_HASH = base64.b64encode(hashlib.sha256(CHAT_STYLE.encode()).digest()).decode()
LIMITS = [
    "Covers the selected export and the recorded viewports.",
    "An absent ID or reply is a gap in what was shown, not a deletion notice; long intervals can be ordinary inactivity.",
    "Private chats and basic groups share an account-wide ID sequence; numeric gaps are not counted.",
    "Visual observations are operator annotations linked to recorded frames.",
    "Signatures bind the recorded bytes to the capture key; retained checkpoints fix them against later replacement.",
    "Official clients, pacing and WARP reduce the risk of account restrictions.",
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


def listed(value):
    return value if isinstance(value, list) else []


def rich_inline(node, depth=0):
    if depth > RICH_DEPTH:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(rich_inline(item, depth + 1) for item in node)
    if isinstance(node, dict):
        return rich_inline(node.get("text"), depth + 1)
    return ""


def rich_block(block, depth=0):
    if depth > RICH_DEPTH or not isinstance(block, dict):
        return ""
    if block.get("type") == "table":
        rows = [" | ".join(rich_inline(cell.get("text"), depth + 1)
                           for cell in listed(row.get("cells")) if isinstance(cell, dict))
                for row in listed(block.get("rows")) if isinstance(row, dict)]
        return "\n".join(part for part in [rich_inline(block.get("title"), depth + 1), *rows] if part)
    if block.get("type") == "list":
        return "\n".join("• " + rich_block(item, depth + 1) for item in listed(block.get("items")))
    parts = [rich_inline(block.get("text"), depth + 1), rich_inline(block.get("caption"), depth + 1)]
    parts += [rich_block(item, depth + 1) for item in listed(block.get("blocks"))]
    return "\n".join(part for part in parts if part)


def message_text(message):
    text = text_of(message.get("text"))
    rich = message.get("rich_message")
    if text or not isinstance(rich, dict):
        return text
    return "\n\n".join(part for part in map(rich_block, listed(rich.get("blocks"))) if part)


def external_reply_peer(chat, message):
    peer = message.get("reply_to_peer_id")
    if not peer:
        return None
    peer = str(peer)
    return None if peer in {prefix + str(chat["id"]) for prefix in ("user", "chat", "channel")} else peer


def report_version(report):
    for version, name in FORMATS.items():
        if isinstance(report, dict) and report.get("format") == name:
            return version
    raise ValueError("Continuity report format is not supported by this verifier")


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


def analyze(chat, visual=(), time_gap_seconds=86400, version=3):
    text = (lambda message: text_of(message.get("text"))) if version == 1 else message_text
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
        if reply and reply not in by_id and (version == 1 or not external_reply_peer(chat, message)):
            findings.append({"kind": "unresolved_reply", "before_id": mid, "reply_to": reply,
                             "cause": "outside_export_or_unavailable"})
        previous = message
    matched = 0
    relevant = 0
    for observation in visual:
        if observation["chat_id"] != chat["id"]:
            continue
        relevant += 1
        mid = observation["message_id"]
        message = by_id.get(mid)
        kind = "visual_id_outside_export" if message is None else (
            "source_mismatch" if observation["text"] != text(message) else "operator_match")
        matched += kind == "operator_match"
        findings.append({"kind": kind, "before_id": mid, "frame_sha256": observation["frame_sha256"],
                         "cause": "unknown", "basis": "operator_transcription", "observed_at": observation["observed_at"]})
    return {"format": FORMATS[version], "chat_id": chat["id"], "chat_type": chat["type"],
            "messages": len(messages), "id_intervals_applicable": chat["type"] in CHANNEL_TYPES,
            "scope": "IDs between the first and last exported message; export filters unknown",
            "visual_comparison": "operator_annotated" if (relevant if version > 2 else visual) else "unavailable_no_annotated_frames",
            "operator_matches": matched, "findings": findings, "limits": LIMITS}


def render(chat, report):
    escape = lambda value: html.escape(str(value), quote=True)
    version = report_version(report)
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
            peer = external_reply_peer(chat, message) if version > 1 else None
            if peer:
                context += (f'<p>Reply to message #{reply} in another chat ({escape(peer)}); '
                            'it is not part of this export.</p>')
            else:
                context += f'<p>Reply to <a href="#m{reply}">#{reply}</a></p>'
        if message.get("forwarded_from"):
            context += '<p>Forwarded from: ' + escape(message["forwarded_from"]) + '</p>'
        if message.get("action"):
            context += '<p>Service record: ' + escape(message["action"]) + '</p>'
        for field in ("photo", "file"):
            if message.get(field):
                context += '<p>Attachment reference (bytes not included): ' + escape(message[field]) + '</p>'
        body = text_of(message.get("text"))
        if version > 1 and not body:
            body = message_text(message)
            if body:
                context += '<p>Rich message: text only, formatting is not reproduced.</p>'
        rows.append(f'<article id="m{mid}"><header>#{mid} · {escape(message.get("date", ""))} · '
                    f'{escape(message.get("from", message.get("actor", "")))}</header>'
                    + context + f'<p>{escape(body)}</p></article>')
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
        return 'Exported text differs from the operator’s frame transcription. Review both sources.'
    if kind == "operator_match":
        return 'Exported text matches the operator’s frame transcription.'
    return f'Operator annotated message #{finding["before_id"]} is absent from the export. Review its scope and filters.'
