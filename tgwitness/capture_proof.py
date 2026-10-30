"""Signed, content-free collection counters bound to one immutable journal prefix."""
from .store import ZERO, canonical, utcnow
from .verify import CAPTURE_KINDS, fingerprint


def capture_head(store, vault, status, challenge=None):
    with store.snapshot() as snapshot:
        head = snapshot.head
        boundary = {"created_at": utcnow(), "public_key": vault.public_key,
                    "event_count": head["seq"] if head else 0,
                    "head_hash": head["hash"] if head else ZERO}
        counts, last = {}, None
        for kind in CAPTURE_KINDS:
            count, at = snapshot.connection.execute(
                "SELECT count(*),max(observed_at) FROM events WHERE kind=?", (kind,)).fetchone()
            counts[kind] = count
            if kind.startswith("message.") and at:
                last = max(last or at, at)
    checkpoint = {"format": "tgwitness-checkpoint-v1", **boundary}
    statement = {"format": "tgwitness-capture-v1", **boundary, "challenge": challenge, "counts": counts,
                 "last_message_at": last, "health": {
                     "running": bool(status.get("running")), "connected": bool(status.get("connected")),
                     "last_heartbeat": status.get("last_heartbeat"),
                     "media_pending": status.get("media_pending", 0),
                     "media_failed": (status.get("media_jobs") or {}).get("failed", 0),
                     "backoff_until": status.get("rpc_backoff_until", 0)}}
    return {"checkpoint": {"statement": checkpoint, "signature": vault.sign(canonical(checkpoint)),
                           "fingerprint": fingerprint(vault.public_key)},
            "capture": {"statement": statement, "signature": vault.sign(canonical(statement))}}
