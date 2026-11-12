from datetime import timedelta
import json

from .store import canonical, utcnow
from .verify import fingerprint, parse_time

FORMAT = "tgwitness-account-loss-v1"
WINDOW_HOURS = 24
MAX_RECORDS = 20000
PREFIXES = ("connection.", "network.", "account.", "session.", "coverage.gap", "process.", "telegram.", "clock.",
            "collector.")
SKIPPED = ("collector.heartbeat",)
FIELDS = ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id", "actor_id", "payload", "previous_hash",
          "hash", "signature")
MEANING = ("Journal records of this workspace from the 24 hours before Telegram ended the session until this report: "
           "connections, routes, sessions, account notices and coverage gaps. Each record keeps its journal hash and "
           "Ed25519 signature; the evidence export holds the complete hash chain.")


def relevant(kind):
    return kind.startswith(PREFIXES) and kind not in SKIPPED


def build(store, vault):
    loss = store.get_setting("account_loss", None)
    if not loss or not loss.get("at"):
        raise ValueError("Telegram has not ended this account's session; there is no loss to report.")
    start = (parse_time(loss["at"]) - timedelta(hours=WINDOW_HOURS)).isoformat(timespec="milliseconds")
    records, truncated = [], False
    with store.snapshot() as snapshot:
        for row in snapshot.connection.execute("SELECT * FROM events WHERE observed_at>=? ORDER BY seq", (start,)):
            if not relevant(row["kind"]):
                continue
            if len(records) >= MAX_RECORDS:
                truncated = True
                break
            event = {**dict(row), "payload": json.loads(row["payload"])}
            records.append({key: event[key] for key in FIELDS})
        head = snapshot.head
    account = store.get_setting("account", None) or {}
    from .evidence import producer
    statement = {"format": FORMAT, "generated_at": utcnow(), "producer": producer(), "public_key": vault.public_key,
                 "account": {key: account.get(key) for key in ("id", "username")}, "loss": loss,
                 "window": {"from": start, "loss_at": loss["at"]}, "journal_head": head,
                 "records": records, "truncated": truncated, "meaning": MEANING}
    return {"statement": statement, "fingerprint": fingerprint(vault.public_key),
            "signature": vault.sign(canonical(statement))}
