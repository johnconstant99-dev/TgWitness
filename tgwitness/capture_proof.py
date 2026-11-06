import json

from .store import ZERO, canonical, utcnow
from .verify import CAPTURE_KINDS, fingerprint
from . import continuity


def capture_head(store, vault, status, challenge=None, consistency_from=None):
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
        proof = continuity.answer(snapshot, vault, challenge, consistency_from) if consistency_from is not None else None
        authorized = snapshot.connection.execute(
            "SELECT count(*) OVER() AS total,seq,payload FROM events WHERE kind='account.authorized' "
            "ORDER BY seq DESC LIMIT 1").fetchone()
        origin = json.loads(authorized["payload"]).get("key_origin") if authorized else None
        # Count recorded Telegram authorizations, not secret key copies or signing-key rotations.
        keys = {"count": authorized["total"] if authorized else 0,
                "origin": origin if origin in ("created", "imported") else "unknown",
                "authorized_seq": authorized["seq"] if authorized else None}
    checkpoint = {"format": "tgwitness-checkpoint-v1", **boundary}
    statement = {"format": "tgwitness-capture-v1", **boundary, "challenge": challenge, "counts": counts,
                 "last_message_at": last, "keys": keys, "health": {
                     "running": bool(status.get("running")), "connected": bool(status.get("connected")),
                     "last_heartbeat": status.get("last_heartbeat"),
                     "media_pending": status.get("media_pending", 0),
                     "media_failed": (status.get("media_jobs") or {}).get("failed", 0),
                     "backoff_until": status.get("rpc_backoff_until", 0)}}
    return {"checkpoint": {"statement": checkpoint, "signature": vault.sign(canonical(checkpoint)),
                           "fingerprint": fingerprint(vault.public_key)},
            "capture": {"statement": statement, "signature": vault.sign(canonical(statement))},
            **({"continuity": proof} if proof is not None else {})}
