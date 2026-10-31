import io
import json
import zipfile

import pytest

from tgwitness import chat_export
from tgwitness.verify import fingerprint, verify_chat_export, bundle_format


def write_scratch(path, records):
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


RECORDS = [
    {"id": 3, "type": "message", "date": "2026-01-02T00:00:00+00:00", "from": "Алиса",
     "from_id": 11, "reply_to_message_id": 2, "text": "Привет <b>мир</b>\nвторая строка"},
    {"id": 2, "type": "service", "date": "2026-01-01T00:00:10+00:00", "from": None,
     "from_id": None, "action": "MessageActionChatAddUser", "text": ""},
    {"id": 1, "type": "message", "date": "2026-01-01T00:00:00+00:00", "from": "Bob",
     "from_id": 22, "text": "with photo", "media_type": "MessageMediaPhoto"},
]


def build(journal, records=RECORDS):
    store, vault = journal
    scratch = store.root / "scratch.jsonl"
    write_scratch(scratch, records)
    out = store.root / "chat.zip"
    meta = {"chat": {"id": -100123, "title": "Secret group", "kind": "supergroup",
                     "visibility": "private_or_unlisted"},
            "account": {"id": 55, "username": "watcher"}, "message_count": len(records)}
    chat_export.build_bundle(scratch, meta, vault, out)
    return out, vault


def test_bundle_members_and_signature_verify(journal):
    out, vault = build(journal)
    assert bundle_format(out) == "tgwitness-chat-export-v1"
    with zipfile.ZipFile(out) as archive:
        names = set(archive.namelist())
        assert {"chat.json", "chat.html", "manifest.json", "manifest.sig",
                "verify.py", "README.txt"} <= names
        chat = json.loads(archive.read("chat.json"))
        assert chat["format"] == "tgwitness-chat-export-v1"
        assert chat["message_count"] == 3
        assert chat["chat"]["title"] == "Secret group"
        assert [m["id"] for m in chat["messages"]] == [3, 2, 1]
        assert chat["messages"][0]["text"].startswith("Привет")
        html = archive.read("chat.html").decode("utf-8")

        assert "Алиса" in html and "&lt;b&gt;" in html and "<br>" in html
    result = verify_chat_export(out, fingerprint(vault.public_key))
    assert result["message_count"] == 3
    assert result["key_pinned"] is True
    assert result["chat"]["id"] == -100123


def test_wrong_fingerprint_rejected(journal):
    out, vault = build(journal)
    with pytest.raises(ValueError):
        verify_chat_export(out, "0" * 64)


def test_tampered_chat_json_detected(journal):
    out, vault = build(journal)
    buffer = io.BytesIO()
    with zipfile.ZipFile(out) as src:
        items = {name: src.read(name) for name in src.namelist()}
    items["chat.json"] = items["chat.json"].replace(b"Secret group", b"Public group")
    with zipfile.ZipFile(buffer, "w") as dst:
        for name, data in items.items():
            dst.writestr(name, data)
    out.write_bytes(buffer.getvalue())
    with pytest.raises(ValueError):
        verify_chat_export(out, fingerprint(vault.public_key))


def test_empty_chat_is_valid(journal):
    out, vault = build(journal, records=[])
    with zipfile.ZipFile(out) as archive:
        chat = json.loads(archive.read("chat.json"))
        assert chat["messages"] == []
    assert verify_chat_export(out, fingerprint(vault.public_key))["message_count"] == 0


def test_authors_sheet_is_signed_and_counts_posters(journal):
    records = [
        {"id": 4, "type": "message", "date": "2026-01-03T00:00:00+00:00", "from": "Алиса", "from_id": 11,
         "from_username": "alisa", "text": "=HYPERLINK(\"x\")"},
        {"id": 3, "type": "service", "date": "2026-01-02T12:00:00+00:00", "from": "Алиса", "from_id": 11,
         "action": "MessageActionPinMessage", "text": ""},
        {"id": 2, "type": "message", "date": "2026-01-02T00:00:00+00:00", "from": "Алиса", "from_id": 11, "text": "b"},
        {"id": 1, "type": "message", "date": "2026-01-01T00:00:00+00:00", "from": "=cmd", "from_id": 22, "text": "a"},
    ]
    out, vault = build(journal, records)
    with zipfile.ZipFile(out) as archive:
        people = json.loads(archive.read("authors.json"))
        sheet = archive.read("authors.csv").decode("utf-8-sig")
        assert json.loads(archive.read("chat.json"))["author_count"] == 2
    assert [(p["user_id"], p["messages"]) for p in people] == [(11, 2), (22, 1)]
    assert people[0]["username"] == "alisa" and people[0]["name"] == "Алиса"
    assert people[0]["first_message_id"] == 2 and people[0]["last_message_id"] == 4
    assert "'=cmd" in sheet and "Алиса" in sheet
    assert verify_chat_export(out, fingerprint(vault.public_key))["message_count"] == 4


def test_archives_and_checkpoints_named_before_the_rename_still_verify(journal):
    from tgwitness.store import canonical
    from tgwitness.verify import verify_checkpoint
    out, vault = build(journal)
    with zipfile.ZipFile(out) as archive:
        members = {n: archive.read(n) for n in archive.namelist()}
    manifest = json.loads(members["manifest.json"])
    manifest["format"] = "tgwatch-chat-export-v1"
    members["manifest.json"] = canonical(manifest)
    members["manifest.sig"] = vault.sign(members["manifest.json"]).encode()
    legacy = out.with_name("legacy.zip")
    with zipfile.ZipFile(legacy, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    assert verify_chat_export(legacy, fingerprint(vault.public_key))["format"] == "tgwatch-chat-export-v1"
    statement = {"format": "tgwatch-checkpoint-v1", "created_at": "2026-10-27T00:00:00+00:00",
                 "public_key": vault.public_key, "event_count": 0, "head_hash": "0" * 64}
    verify_checkpoint({"statement": statement, "signature": vault.sign(canonical(statement))},
                      vault.public_key, 0, lambda seq: "0" * 64)
    statement["format"] = "other-checkpoint-v1"
    with pytest.raises(ValueError):
        verify_checkpoint({"statement": statement, "signature": vault.sign(canonical(statement))},
                          vault.public_key, 0, lambda seq: "0" * 64)
