"""Read-only witness access to signed journal heads and content-free capture summaries.

A token is shown once; the vault keeps its SHA-256. It cannot open the panel, read messages,
change settings or reach the Telegram session — only GET /api/witness/head answers it.
"""
import hashlib
import re
import secrets
import time

from .evidence import producer
from .capture_proof import capture_head
from .store import utcnow


def tokens(vault):
    return vault.read("witness").get("tokens", [])


def create(vault, store, label):
    token = "tgww_" + secrets.token_urlsafe(32)
    entry = {"id": secrets.token_hex(8), "label": label, "sha256": hashlib.sha256(token.encode()).hexdigest(),
             "created_at": utcnow()}
    vault.save("witness", {"tokens": [*tokens(vault), entry]})
    store.append("witness.token_created", {"token_id": entry["id"], "label": label,
                                           "access": "signed checkpoint, capture counters and collector health; no message content"})
    return token, entry


def revoke(vault, store, token_id):
    kept = [t for t in tokens(vault) if t["id"] != token_id]
    if len(kept) == len(tokens(vault)):
        raise ValueError("Unknown witness token.")
    vault.save("witness", {"tokens": kept})
    polls = store.get_setting("witness_polls", {})
    polls.pop(token_id, None)
    with store.transaction():
        store.set_setting("witness_polls", polls)
        store.append("witness.token_revoked", {"token_id": token_id})


def match(vault, presented):
    digest = hashlib.sha256(presented.encode()).hexdigest()
    found = None
    for entry in tokens(vault):
        if secrets.compare_digest(entry["sha256"], digest):
            found = entry
    return found


def head(store, vault, entry, headers, address, status=None):
    """The signed checkpoint for a witness; remembers when and by which witness key it was asked."""
    witness = (headers.get("x-tgwitness-witness") or "").lower()
    witness = witness if re.fullmatch(r"[0-9a-f]{64}", witness) else None
    interval = headers.get("x-tgwitness-interval") or ""
    polls = store.get_setting("witness_polls", {})
    previous = polls.get(entry["id"]) or {}
    polls[entry["id"]] = {"at": utcnow(), "unix": time.time(), "witness": witness, "address": address,
                          "interval_minutes": int(interval) if interval.isdigit() and 0 < int(interval) <= 1440 else None}
    with store.transaction():
        store.set_setting("witness_polls", polls)
        if witness and previous.get("witness") != witness:
            # A new or replaced witness key: worth a signed record; ordinary polls are not.
            store.append("witness.seen", {"token_id": entry["id"], "label": entry["label"],
                                          "witness_fingerprint": witness,
                                          "meaning": "an independent witness began fetching the signed journal head"})
    challenge = headers.get("x-tgwitness-challenge") or ""
    challenge = challenge if re.fullmatch(r"[0-9a-f]{32}", challenge) else None
    start = headers.get("x-tgwitness-consistency-from")
    if start is not None:
        if not re.fullmatch(r"0|[1-9][0-9]{0,18}", start) or int(start) >= 2**63 or challenge is None:
            from fastapi import HTTPException
            raise HTTPException(400, "A bounded record count and challenge are required for continuity proofs")
        start = int(start)
    return {"format": "tgwitness-witness-head-v1",
            **capture_head(store, vault, status or {}, challenge, consistency_from=start), "producer": producer()}


def state(vault, store):
    polls, now = store.get_setting("witness_polls", {}), time.time()
    listed = []
    for entry in tokens(vault):
        poll = polls.get(entry["id"])
        overdue = None
        if poll and poll.get("interval_minutes"):
            overdue = now - poll["unix"] > poll["interval_minutes"] * 60 * 2.5
        listed.append({"id": entry["id"], "label": entry["label"], "created_at": entry["created_at"],
                       "last_poll": {k: v for k, v in poll.items() if k != "unix"} if poll else None,
                       "overdue": overdue})
    return {"tokens": listed, "path": "/api/witness/head"}
