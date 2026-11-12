import hashlib
import time


def update_digest_record(raw_bytes, now=None):
    if not raw_bytes:
        return None
    return {"kind": "forensics.update_seen",
            "payload": {"mtproto_raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                        "mtproto_raw_length": len(raw_bytes), "observed_at": time.time() if now is None else now,
                        "meaning": "Digest of serialized update bytes; capture matching requires exact byte correspondence."}}


def peer_fields(peer):
    for kind, field in (("user", "user_id"), ("chat", "chat_id"), ("channel", "channel_id")):
        raw = getattr(peer, field, None)
        if isinstance(raw, int) and not isinstance(raw, bool):
            chat_id = raw if kind == "user" else -raw if kind == "chat" else -1000000000000 - raw
            return {"peer_user_id": raw if kind == "user" else None, "peer_type": kind, "peer_id": raw,
                    "chat_id": chat_id}
    return {"peer_user_id": None}


def peer_settings_record(update, now=None):
    settings = getattr(update, "settings", None)
    if settings is None or not getattr(settings, "need_contacts_exception", False):
        return None
    return {"kind": "forensics.peer_settings_observed",
            "payload": {**peer_fields(getattr(update, "peer", None)),
                        "observed_at": time.time() if now is None else now,
                        "need_contacts_exception": True,
                        "meaning": "Observed peer-settings flag, recorded as Telegram delivered it."}}


def outbox_read_record(update, now=None):
    return {"kind": "forensics.outbox_read_watermark",
            "payload": {**peer_fields(getattr(update, "peer", None)), "max_id": getattr(update, "max_id", None),
                        "observed_at": time.time() if now is None else now,
                        "meaning": "Observed outgoing read watermark."}}


BUILDERS = {"UpdatePeerSettings": peer_settings_record, "UpdateReadHistoryOutbox": outbox_read_record}


def record_for(update, now=None):
    return BUILDERS.get(type(update).__name__, lambda *_: None)(update, now)


def register(client, journal, now=time.time, enabled=lambda: True):
    from telethon import events
    from telethon.tl import types

    @client.on(events.Raw(types.UpdatePeerSettings))
    async def _contacts(update):
        if not enabled():
            return
        record = peer_settings_record(update, now())
        if record:
            journal.append(record["kind"], record["payload"])

    @client.on(events.Raw(types.UpdateReadHistoryOutbox))
    async def _read(update):
        if not enabled():
            return
        record = outbox_read_record(update, now())
        journal.append(record["kind"], record["payload"])

    @client.on(events.Raw)
    async def _digest(update):
        if not enabled():
            return
        try:
            raw = bytes(update)
        except Exception:
            return
        record = update_digest_record(raw, now())
        if record:
            journal.append(record["kind"], record["payload"])
