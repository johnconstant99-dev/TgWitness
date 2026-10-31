"""Bounded export metadata, separate from the signed journal and archive formats."""
import hashlib
import os
from datetime import datetime, timezone

LIMIT = 20
KEY = "prepared_exports"


def prepared(store, path, fmt, encrypted):
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        size = os.fstat(source.fileno()).st_size
    entry = {"format": fmt, "encrypted": bool(encrypted), "bytes": size, "sha256": digest,
             "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with store.transaction():
        previous = store.get_setting(KEY, [])
        store.set_setting(KEY, [entry, *previous][:LIMIT])
    return entry


def listing(store):
    return {"exports": store.get_setting(KEY, [])[:LIMIT], "limit": LIMIT}


def headers(entry):
    return {"X-TgWitness-Export-SHA256": entry["sha256"], "X-TgWitness-Export-Created": entry["created_at"]}
