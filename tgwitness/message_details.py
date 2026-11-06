import re

from . import keyboard
from . import ephemeral

ENTITY_TYPES = {"MessageEntityTextUrl": "text_link", "MessageEntityUrl": "link", "MessageEntityMention": "mention",
                "MessageEntityMentionName": "mention_name", "MessageEntityEmail": "email",
                "MessageEntityPhone": "phone", "MessageEntityHashtag": "hashtag", "MessageEntityCashtag": "cashtag",
                "MessageEntityBotCommand": "bot_command", "MessageEntityBankCard": "bank_card",
                "MessageEntityCustomEmoji": "custom_emoji", "MessageEntityBlockquote": "blockquote",
                "MessageEntityCode": "code", "MessageEntityPre": "pre", "MessageEntityBold": "bold",
                "MessageEntityItalic": "italic", "MessageEntityUnderline": "underline",
                "MessageEntityStrike": "strikethrough", "MessageEntitySpoiler": "spoiler"}
POINTING = ("text_link", "link", "mention", "mention_name", "email", "phone", "bank_card", "cashtag", "bot_command")


def snake(name):
    return "".join("_" + c.lower() if c.isupper() else c for c in name).lstrip("_")


def entity_text(text, offset, length):
    data = text.encode("utf-16-le")
    return data[2 * offset:2 * (offset + length)].decode("utf-16-le", errors="replace")


def peer_id(peer):
    if not isinstance(peer, dict):
        return None
    if peer.get("_") == "PeerUser":
        return peer.get("user_id")
    if peer.get("_") == "PeerChat":
        return -peer["chat_id"] if isinstance(peer.get("chat_id"), int) else None
    if peer.get("_") == "PeerChannel" and isinstance(peer.get("channel_id"), int):
        return -1000000000000 - peer["channel_id"]
    return None


def entities(text, raw_entities):
    result = []
    for entity in raw_entities or []:
        if not isinstance(entity, dict) or not isinstance(entity.get("offset"), int) \
                or not isinstance(entity.get("length"), int):
            continue
        name = entity.get("_", "")
        item = {"type": ENTITY_TYPES.get(name, snake(name.replace("MessageEntity", ""))),
                "text": entity_text(text or "", entity["offset"], entity["length"])}
        for field, key in (("url", "href"), ("user_id", "user_id"), ("language", "language"),
                           ("document_id", "document_id")):
            if entity.get(field) not in (None, ""):
                item[key] = entity[field]
        if item["type"] == "text_link" and deceptive(item["text"], item.get("href")):
            item["deceptive"] = True
        result.append(item)
    return result


def host(value):
    found = re.search(r"(?i)(?:[a-z][a-z0-9+.-]*://)?((?:[\w-]+\.)+[\w-]{2,})", value or "")
    name = found.group(1).lower().rstrip(".") if found else ""
    return name[4:] if name.startswith("www.") else name


def deceptive(text, href):
    shown, target = host(text), host(href)
    return bool(shown and target and shown != target and not target.endswith("." + shown))


def reactions(raw):
    found = []
    for result in (raw or {}).get("results") or [] if isinstance(raw, dict) else []:
        reaction = (result or {}).get("reaction") or {}
        name = reaction.get("_")
        label = reaction.get("emoticon") if name == "ReactionEmoji" else \
            "custom:" + str(reaction.get("document_id")) if name == "ReactionCustomEmoji" else \
            "paid" if name == "ReactionPaid" else name
        if label and isinstance(result.get("count"), int):
            found.append({"reaction": label, "count": result["count"]})
    return found


def forward(header):
    if not isinstance(header, dict):
        return None
    found = {"from_id": peer_id(header.get("from_id")), "from_name": header.get("from_name"),
             "date": header.get("date"), "channel_post": header.get("channel_post"),
             "post_author": header.get("post_author"), "saved_from_id": peer_id(header.get("saved_from_peer")),
             "saved_from_message_id": header.get("saved_from_msg_id"), "imported": header.get("imported") or None}
    return {k: v for k, v in found.items() if v not in (None, "")} or None


def media_info(media):
    if not isinstance(media, dict) or media.get("_") in (None, "", "MessageMediaEmpty"):
        return None
    info = {"kind": media["_"]}
    document = media.get("document") if isinstance(media.get("document"), dict) else None
    if document:
        info.update(mime_type=document.get("mime_type"), size=document.get("size"), document_id=document.get("id"),
                    dc_id=document.get("dc_id"))
        for attribute in document.get("attributes") or []:
            name = (attribute or {}).get("_")
            if name == "DocumentAttributeFilename":
                info["file_name"] = attribute.get("file_name")
            elif name in ("DocumentAttributeVideo", "DocumentAttributeAudio"):
                info["duration_seconds"] = attribute.get("duration")
                if attribute.get("w"):
                    info.update(width=attribute.get("w"), height=attribute.get("h"))
            elif name == "DocumentAttributeImageSize":
                info.update(width=attribute.get("w"), height=attribute.get("h"))
    photo = media.get("photo") if isinstance(media.get("photo"), dict) else None
    if photo:
        sizes = [s for s in photo.get("sizes") or [] if isinstance(s, dict) and s.get("w")]
        largest = max(sizes, key=lambda s: s["w"] * s["h"], default=None)
        info.update(photo_id=photo.get("id"), dc_id=photo.get("dc_id"), width=largest and largest["w"],
                    height=largest and largest["h"], size=largest and largest.get("size"))
    webpage = media.get("webpage") if isinstance(media.get("webpage"), dict) else None
    if webpage and webpage.get("url"):
        info.update(url=webpage.get("url"), site_name=webpage.get("site_name"), title=webpage.get("title"))
    if media.get("ttl_seconds"):
        info["self_destruct_seconds"] = media["ttl_seconds"]
    if facts := ephemeral.describe(media):
        info["ephemeral_media"] = facts
    return {k: v for k, v in info.items() if v not in (None, "")}


def details(raw):
    if not isinstance(raw, dict):
        return {}
    text = raw.get("message") or ""
    found = {"text_entities": entities(text, raw.get("entities")), "forwarded_from": forward(raw.get("fwd_from")),
             "via_bot_id": raw.get("via_bot_id"), "author": raw.get("post_author"), "views": raw.get("views"),
             "forwards": raw.get("forwards"), "buttons": keyboard.keyboard(raw.get("reply_markup")),
             "replies": (raw.get("replies") or {}).get("replies") if isinstance(raw.get("replies"), dict) else None,
             "reactions": reactions(raw.get("reactions")),
             "auto_delete_seconds": raw.get("ttl_period"), "protected": raw.get("noforwards") or None,
             "album_id": raw.get("grouped_id"), "media_info": media_info(raw.get("media"))}
    return {k: v for k, v in found.items() if v not in (None, "", [], {})}
