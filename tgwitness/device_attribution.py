import re
import struct
from datetime import datetime, timezone

ROUND_SIZES = {(384, 384): "Telegram for Android", (300, 300): "Telegram for macOS", (240, 240): "Telegram X"}
VENDORS = (("libopus 1.5.1", "Telegram for iOS"), ("libopus unknown-fixed", "Telegram for Android"),
           ("libopus 1.3.1-fixed", "Telegram for macOS"), ("telegram-web-a", "Telegram Web A"),
           ("tweb", "Telegram Web K"), ("Lavf", "Telegram Desktop"))
PRE_EXISTING_SECONDS = 120
MAX_HEADER = 65536
BASIS = {
    "round_video_filename": "The filename matches a configured pattern.",
    "round_video_size": "The dimensions match a configured pattern shared by possible encoders.",
    "round_video_default_name": "A generic filename matches a configured pattern.",
    "voice_encoder": "Opus metadata matches a configured vendor-string pattern.",
}
MEANING = ("Client that encoded the file, read from the file's own metadata. "
           "A forwarded or re-uploaded file carries the encoder of whoever made it first.")
PROVENANCE_MEANING = ("Difference between document and message dates in retained metadata. It shows how long "
                      "before sending the file already existed.")


def attributes(info):
    return [a for a in (info or {}).get("attributes") or [] if isinstance(a, dict)]


def document_of(raw):
    media = raw.get("media") if isinstance(raw, dict) else None
    document = (media or {}).get("document") if isinstance(media, dict) else None
    return document if isinstance(document, dict) else None


def round_video(raw):
    document = document_of(raw)
    if not document:
        return None
    name, size, is_round = None, None, False
    for attribute in document.get("attributes") or []:
        kind = (attribute or {}).get("_")
        if kind == "DocumentAttributeFilename":
            name = attribute.get("file_name")
        elif kind == "DocumentAttributeVideo":
            if attribute.get("round_message"):
                is_round = True
                size = (attribute.get("w"), attribute.get("h"))
    if not is_round:
        return None
    if isinstance(name, str) and name.startswith("round_"):
        return {"client": "Telegram Desktop", "basis": "round_video_filename", "confidence": "weak", "file_name": name}
    if size in ROUND_SIZES:
        return {"client": ROUND_SIZES[size], "basis": "round_video_size", "confidence": "weak",
                "size": "%sx%s" % size}
    if name == "video.mp4":
        return {"client": "Telegram for iOS or Telegram Web", "basis": "round_video_default_name",
                "confidence": "weak", "file_name": name}
    return None


def opus_vendor(data):
    head = data[:MAX_HEADER] if isinstance(data, (bytes, bytearray)) else b""
    start = head.find(b"OpusTags")
    if start == -1 or start + 12 > len(head):
        return None
    length = struct.unpack("<I", head[start + 8:start + 12])[0]
    if not 0 < length <= 1024 or start + 12 + length > len(head):
        return None
    text = head[start + 12:start + 12 + length].decode("utf-8", "replace")
    return re.sub(r"[\x00-\x1f\x7f]", " ", text).strip() or None


def voice_client(data):
    vendor = opus_vendor(data)
    if vendor is None:
        return None
    for signature, client in VENDORS:
        if signature in vendor:
            return {"client": client, "basis": "voice_encoder", "confidence": "weak", "encoder": vendor}
    return {"client": None, "basis": "voice_encoder", "confidence": "unknown", "encoder": vendor}


def moment(value):
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def provenance(raw):
    document = document_of(raw)
    sent, uploaded = moment((raw or {}).get("date")), moment((document or {}).get("date"))
    if sent is None or uploaded is None:
        return None
    gap = int((sent - uploaded).total_seconds())
    found = {"uploaded_at": uploaded.isoformat(), "sent_at": sent.isoformat(), "uploaded_before_seconds": gap}
    if gap > PRE_EXISTING_SECONDS:
        found["status"] = "uploaded_earlier"
    elif gap < -PRE_EXISTING_SECONDS:
        found["status"] = "uploaded_later"
    else:
        found["status"] = "uploaded_with_message"
    return found


def sticker_sets(raw):
    found = []
    document = document_of(raw)
    for attribute in (document or {}).get("attributes") or []:
        source = (attribute or {}).get("stickerset") if isinstance(attribute, dict) else None
        if isinstance(source, dict) and source.get("id") is not None:
            found.append({"set_id": str(source["id"]), "access_hash": str(source.get("access_hash") or ""),
                          "from": "sticker", "alt": attribute.get("alt")})
    for entity in (raw or {}).get("entities") or []:
        if isinstance(entity, dict) and entity.get("_") == "MessageEntityCustomEmoji" and entity.get("document_id"):
            found.append({"custom_emoji_id": str(entity["document_id"]), "from": "custom_emoji"})
    seen, unique = set(), []
    for item in found:
        key = item.get("set_id") or item.get("custom_emoji_id")
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def describe(raw, voice_bytes=None):
    found = {}
    client = round_video(raw)
    if client is None and voice_bytes is not None:
        info = (raw.get("media") or {}).get("document") or {}
        if any((a or {}).get("voice") for a in info.get("attributes") or []):
            client = voice_client(voice_bytes)
    if client:
        found["client"] = {**client, "meaning": MEANING}
    timing = provenance(raw)
    if timing and timing["status"] != "uploaded_with_message":
        found["media_timing"] = {**timing, "meaning": PROVENANCE_MEANING}
    sets = sticker_sets(raw)
    if sets:
        found["sticker_sets"] = sets
    return found
