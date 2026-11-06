from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import types

from tgwitness import chat_export, report
from tgwitness.collector import message_record
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, verify_chat_export

GROUP = -1000000000999
NOW = datetime.now(timezone.utc)


def observed(store, mid, name):
    store.append("message.new", {"sender_id": 91, "text": "Live " + str(mid), "source": "live_update",
                                 "sent_at": NOW.isoformat(), "sender_observation": {"id": 91, "display_name": name,
                                 "username": None, "flags": {"contact": False}}}, GROUP, mid, 91)


def record(mid, when, name="Name At Export", source="profile", sender=91):
    return {"id": mid, "type": "message", "date": when.isoformat(), "from": name, "from_id": sender,
            "from_username": None, "from_source": source, "text": "Exported " + str(mid)}


def check(root):
    sent = types.Message(1, types.PeerUser(91), date=NOW, message="Hello", from_id=types.PeerUser(91))
    sent._sender = types.User(91, first_name="Saved", last_name="Contact", contact=True)
    assert message_record(sent)["from_source"] == "contact"
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        store.set_target(GROUP, "Watched group", "supergroup", True)
        observed(store, 1, "Original Name")
        observed(store, 2, "Renamed Name")
        rows = [record(0, NOW - timedelta(days=400)), record(1, NOW), record(2, NOW),
                record(3, NOW + timedelta(hours=1)), record(4, NOW - timedelta(days=400), "Y test", "contact", 92)]
        scratch = root / "messages.jsonl"
        scratch.write_bytes(b"\n".join(canonical(row) for row in rows) + b"\n")
        names = chat_export.journal_names(store, GROUP, scratch)
    finally:
        store.close()
    archive = root / "chat.zip"
    chat_export.build_bundle(scratch, {"chat": {"id": GROUP, "title": "Watched group"}, "message_count": len(rows)},
                             vault, archive, names=names)
    assert verify_chat_export(archive, fingerprint(vault.public_key))["message_count"] == len(rows)
    with zipfile.ZipFile(archive) as bundle:
        chat = json.loads(bundle.read("chat.json"))
        listed = json.loads(bundle.read("sender-names.json"))["messages"]
        viewer = "".join(bundle.read(n).decode("utf-8") for n in bundle.namelist() if n.startswith("viewer/messages-"))
    assert [m["from"] for m in chat["messages"]] == [r["from"] for r in rows]
    assert chat["sender_names"]["from_journal"] == 3 and chat["sender_names"]["at_export"] == 2, chat["sender_names"]
    assert [(m["id"], m["name"], m["basis"]) for m in listed] == [
        (1, "Original Name", "received_with_message"), (2, "Renamed Name", "received_with_message"),
        (3, "Renamed Name", "recorded_before_message")], listed
    assert all(m["source"] == "profile" and m["record"]["seq"] for m in listed)
    assert "Original Name" in viewer and "Renamed Name" in viewer and "export_time" in viewer
    shown = [chat_export.named(r, names, GROUP) for r in rows]
    html = "".join(report.chat_rows(shown, report.Words("en")))
    assert "Original Name" in html and "Renamed Name" in html
    assert "name at export · from the Telegram profile" in html
    assert "name at export · from the account&#x27;s contacts" in html


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="sender-names-") as temporary:
        check(Path(temporary))
    print("Exports name each sender as the journal recorded them at the message; other names are marked as names at export.")
