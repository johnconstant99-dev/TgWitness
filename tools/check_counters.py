from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import alerts, i18n, store as store_module  # noqa: E402
from tgwitness import health  # noqa: E402
from tgwitness.collector import Collector  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402

CHAT = -1001


def journal(store):
    clock, store_module.utcnow = store_module.utcnow, lambda: "2026-11-02T10:15:00.000+00:00"
    try:
        record(store)
    finally:
        store_module.utcnow = clock


def record(store):
    store.set_target(CHAT, "Synthetic chat", "supergroup", True)
    store.append("message.new", {"text": "kept then deleted"}, CHAT, 1, 7)
    store.append("message.new", {"text": "edited"}, CHAT, 2, 7)
    store.append("message.edited", {"text": "edited again"}, CHAT, 2)
    store.append("message.deleted", {}, CHAT, 1)
    store.append("message.deleted", {}, CHAT, 3)
    store.append("message.new", {"text": "gone at recheck"}, CHAT, 4, 7)
    store.append("message.missing_on_recheck", {}, CHAT, 4)


def expected(row):
    assert row["saved"] == 3, row
    assert row["deleted"] == 2 and row["deleted_saved"] == 1 and row["deleted_unsaved"] == 1, row
    assert row["edited"] == 1 and row["missing"] == 1, row


def main():
    with tempfile.TemporaryDirectory(prefix="tgw-counters-") as scratch:
        path = Path(scratch)
        vault, store = Vault(path), Store(path)
        store.bind(vault)
        journal(store)
        expected(store.chat_overview()[CHAT])

        words = i18n.words("en")
        items = alerts.panel_items(store, words)
        change = next(item for item in items if item.get("category") == "change" or "this hour" in item.get("text", ""))
        text = change["text"]
        for part in ("1 deleted, text kept", "1 deleted before saving", "1 edited", "1 not found on recheck", "this hour"):
            assert part in text, (part, text)
        assert alerts.change_item({"kind": "message.deleted", "message_id": 3}, "Chat", words, kept=False).endswith(
            "before its text was saved")

        store.db.execute("ALTER TABLE chat_state_index DROP COLUMN deleted_saved")
        store.db.commit()
        store.close()
        reopened = Store(path)
        reopened.bind(vault)
        expected(reopened.chat_overview()[CHAT])
        reopened.close()
    source_status()
    print("Chat counters and source status: one definition for list, header, health and notifications; "
          "older index rebuilt.")


def source_status():
    collector = SimpleNamespace(dialog_cache={}, dialogs_truncated=True, RECEIVING_DAYS=Collector.RECEIVING_DAYS)
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="milliseconds")
    stale = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="milliseconds")
    receiving = Collector.source_visibility(collector, CHAT, {CHAT: {"last_observed_at": recent}})
    assert receiving["state"] == "receiving_updates", receiving
    silent = Collector.source_visibility(collector, CHAT, {CHAT: {"last_observed_at": stale}})
    assert silent["state"] == "access_unconfirmed" and silent["reason"] == "beyond_dialog_limit", silent
    collector.dialogs_truncated = False
    assert Collector.source_visibility(collector, CHAT, {})["reason"] == "not_in_dialogs"
    collector.dialog_cache = {CHAT: {"visibility": "public_username", "role": "member_or_unknown"}}
    assert Collector.source_visibility(collector, CHAT, {})["state"] == "visible_in_dialogs"
    part = health.sources({"source_status": {str(CHAT): receiving}}, 1)
    assert part["state"] == "working" and part["counts"]["receiving"] == 1, part


if __name__ == "__main__":
    main()
