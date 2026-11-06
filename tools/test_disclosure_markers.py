"""Minimized disclosure keeps its shape: messages left out by the selection become content-free markers,
replies say what they answer, and the verifier rejects a reply that points at nothing."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.account_export import AccountExport  # noqa: E402
from tgwitness.disclosure import DisclosurePolicy, Disclosures, Projection, Withholding, entries  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store, canonical  # noqa: E402
from tgwitness.verify import fingerprint, verify_account_disclosure  # noqa: E402
from tools.check_disclosure_privacy import SyntheticTransport  # noqa: E402
from tools.demo_account_export import SyntheticCollector  # noqa: E402

AT = "2026-11-01T12:00:00+00:00"
CHAT, QUIET = {"id": 1, "kind": "group", "title": "Synthetic group"}, {"id": 2, "kind": "group", "title": "Quiet"}


def message(ident, sender, reply=None):
    row = {"id": ident, "date": AT, "from_id": sender, "text": "text " + str(ident)}
    if reply is not None:
        row["reply_to"] = {"_": "MessageReplyHeader", "reply_to_msg_id": reply}
    return row


SOURCE = ([(CHAT, message(1, 42)), (CHAT, message(2, 7)), (CHAT, message(3, 7)), (CHAT, message(4, 42, reply=3)),
           (CHAT, message(5, 7)), (CHAT, message(6, 7)), (CHAT, message(7, 7)), (CHAT, message(8, 42, reply=99)),
           (CHAT, message(9, 42, reply=1))] + [(QUIET, message(n, 7)) for n in (1, 2)])


def stream(**options):
    policy = DisclosurePolicy(purpose="Synthetic selection", sender_ids=[42], **options)
    with patch("tgwitness.disclosure.source_rows", lambda _source: iter(SOURCE)):
        projection = Projection(policy, b"synthetic-seed", None)
        return list(entries(None, policy, projection, Withholding(None, policy)))


def test_markers_keep_the_shape_of_the_chat():
    rows = stream(identity_mode="keep")
    shape = [(r["message"]["id"], r["message"]["state"], r["message"].get("count")) for r in rows]
    assert shape == [(1, "disclosed", None), ("withheld-2-2", "withheld", 1), (3, "withheld", 1), (4, "disclosed", None),
                     ("withheld-5-7", "withheld", 3), (8, "disclosed", None), (9, "disclosed", None)]
    assert {r["chat"]["id"] for r in rows} == {1}, "A chat with nothing disclosed is left out entirely"
    replies = {r["message"]["id"]: r["message"]["reply_to"] for r in rows if "reply_to" in r["message"]}
    assert replies == {4: {"id": 3, "state": "withheld"}, 8: {"id": 99, "state": "not_in_source"},
                       9: {"id": 1, "state": "disclosed"}}
    marker = rows[1]["message"]
    assert marker["rules"] == ["sender"] and marker["attachments"] == [] and "text 2" not in json.dumps(rows[1])
    assert marker["text"] == "[withheld by selection — rule: sender]"
    each = stream(identity_mode="keep", withheld_markers="each")
    assert [r["message"]["id"] for r in each if r["message"]["state"] == "withheld"] == [2, 3, 5, 6, 7]


def test_pseudonymized_replies_point_at_their_markers():
    rows = stream(identity_mode="pseudonymize_all")
    ids = {r["message"]["id"]: r["message"]["state"] for r in rows}
    for row in rows:
        reply = row["message"].get("reply_to")
        if reply and reply["state"] != "not_in_source":
            assert ids[reply["id"]] == reply["state"]
    assert all(isinstance(r["message"]["id"], str) and "text 3" not in json.dumps(r) for r in rows
               if r["message"]["state"] == "withheld")


class ReplyTransport(SyntheticTransport):
    async def discover(self):
        chats = [{"id": 101, "title": "Synthetic group", "kind": "group", "selected": True}]
        tasks = [{"id": "messages:101:0", "category": "messages", "chat_id": 101, "newest_message_id": 6,
                  "cursor_start": 7, "own_only": False, "telegram_range": None}]
        return chats, tasks, []

    async def page(self, task, cursor):
        rows = []
        for ident, sender, reply in ((6, 42, 3), (5, 7, None), (4, 7, None), (3, 7, None), (2, 42, None), (1, 7, None)):
            row = dict(category="messages", chat_id=101, id=ident, date=AT, outgoing=False, text="synthetic " + str(ident),
                       sender={"id": sender, "first_name": "Person" + str(sender)}, from_id=sender)
            if reply:
                row["reply_to"] = {"_": "MessageReplyHeader", "reply_to_msg_id": reply}
            rows.append((row, None))
        return rows, 1, True


def resign(path, target, vault, change):
    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(members.pop("manifest.json"))
    members.pop("manifest.sig")
    change(members, manifest)
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in members.items()}
    members["SHA256SUMS"] = "".join(f"{v}  {k}\n" for k, v in sorted(manifest["files"].items())
                                    if k != "SHA256SUMS").encode()
    manifest["files"]["SHA256SUMS"] = hashlib.sha256(members["SHA256SUMS"]).hexdigest()
    with zipfile.ZipFile(target, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        archive.writestr("manifest.json", canonical(manifest))
        archive.writestr("manifest.sig", vault.sign(canonical(manifest)))
    return target


@pytest.fixture
def package(tmp_path):
    async def build():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = SyntheticCollector()
        collector.store = store
        store.set_setting("account", {"id": ReplyTransport.account_id})
        exports = AccountExport(collector, store, vault)
        exports.transport_factory = ReplyTransport
        manager = Disclosures(exports, vault)
        try:
            job = await exports.start({"transport": "regular", "include_profile": False, "include_contacts": False,
                                       "media_types": []})
            await asyncio.wait_for(asyncio.shield(exports.task), 15)
            policy = {"purpose": "Synthetic reply shape", "sender_ids": [42], "identity_mode": "keep"}
            preview = manager.preview(job["id"], policy, "owner")
            info = await manager.create(job["id"], preview["preview_id"], "owner")
            return vault, preview, manager.result_path(job["id"], info["id"])
        finally:
            await manager.close()
            await exports.close()
            store.close()
    return asyncio.run(build())


def test_disclosure_package_is_marked_and_verified(package, tmp_path):
    vault, preview, path = package
    assert preview["summary"]["messages_after"] == 2 and preview["summary"]["messages_withheld"] == 4
    answer = verify_account_disclosure(path, fingerprint(vault.public_key))
    assert answer["counts"] == {"messages": 2, "chats": 1, "media": 0, "withheld": 4}
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        rows = [json.loads(line) for line in archive.read("messages.jsonl").splitlines()]
        page = archive.read("index.html").decode("utf-8")
    assert manifest["format"] == "tgwitness-account-disclosure-v2"
    assert manifest["policy"]["withheld_markers"] == "collapsed"
    reply = next(r["message"]["reply_to"] for r in rows if r["message"].get("reply_to"))
    assert reply == {"id": 3, "state": "withheld"} and any(r["message"]["id"] == 3 for r in rows)
    assert "Withheld by selection" in page and "This reply answers a message withheld by the selection." in page
    assert "synthetic 3" not in page and "synthetic 5" not in page, "Withheld content never enters the package"

    def dangling(members, _manifest):
        lines = [json.loads(line) for line in members["messages.jsonl"].splitlines()]
        lines = [row for row in lines if row["message"]["id"] != 3]
        members["messages.jsonl"] = b"".join(canonical(row) + b"\n" for row in lines)
        _manifest["counts"]["withheld"] -= 1
    with pytest.raises(ValueError, match="points at a record"):
        verify_account_disclosure(resign(path, tmp_path / "dangling.zip", vault, dangling))

    def content(members, _manifest):
        lines = [json.loads(line) for line in members["messages.jsonl"].splitlines()]
        for row in lines:
            if row["message"]["state"] == "withheld":
                row["message"]["sender"] = "Leaked"
        members["messages.jsonl"] = b"".join(canonical(row) + b"\n" for row in lines)
    with pytest.raises(ValueError, match="withheld-by-selection marker"):
        verify_account_disclosure(resign(path, tmp_path / "content.zip", vault, content))

    def first_version(members, manifest):
        lines = [json.loads(line) for line in members["messages.jsonl"].splitlines()]
        lines = [row for row in lines if row["message"]["state"] == "disclosed"]
        for row in lines:
            row["message"].pop("state")
            row["message"].pop("reply_to", None)
        members["messages.jsonl"] = b"".join(canonical(row) + b"\n" for row in lines)
        manifest["format"] = "tgwitness-account-disclosure-v1"
        manifest["counts"].pop("withheld")
    earlier = verify_account_disclosure(resign(path, tmp_path / "v1.zip", vault, first_version))
    assert earlier["counts"] == {"messages": 2, "chats": 1, "media": 0}, "Version 1 packages verify as before"


@pytest.mark.parametrize("field,value", [
    ("text", "private message content"),
    ("redacted_fields", ["private message content"]),
    ("rules", [{"private": "message content"}]),
])
def test_marker_payload_cannot_carry_withheld_content(package, tmp_path, field, value):
    vault, _preview, path = package

    def change(members, _manifest):
        rows = [json.loads(line) for line in members["messages.jsonl"].splitlines()]
        next(row["message"] for row in rows if row["message"]["state"] == "withheld")[field] = value
        members["messages.jsonl"] = b"".join(canonical(row) + b"\n" for row in rows)

    with pytest.raises(ValueError, match="withheld-by-selection marker"):
        verify_account_disclosure(resign(path, tmp_path / "payload.zip", vault, change))


def test_reply_cannot_label_an_existing_record_as_absent(package, tmp_path):
    vault, _preview, path = package

    def change(members, _manifest):
        rows = [json.loads(line) for line in members["messages.jsonl"].splitlines()]
        next(row["message"]["reply_to"] for row in rows if row["message"].get("reply_to"))["state"] = "not_in_source"
        members["messages.jsonl"] = b"".join(canonical(row) + b"\n" for row in rows)

    with pytest.raises(ValueError, match="reply"):
        verify_account_disclosure(resign(path, tmp_path / "absent.zip", vault, change))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
