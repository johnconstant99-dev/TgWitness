import json
import zipfile

import pytest
from PIL import Image

from tgwitness import dossier
from tgwitness.evidence import export_file, producer
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_dossier

CHAT, OTHER = -1000000000123, -1000000000999
ALICE, BOB = 70001, 70002
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"   # a real Bitcoin address (valid checksum)
EVM = "0x52908400098527886E0F7030069857D2E4169EE7"


def say(store, chat, message_id, sender, text, name, username=None, flags=None, photo=None, reply=None, raw=None):
    observed = {"id": sender, "display_name": name, "username": username}
    if flags:
        observed["flags"] = flags
    if photo:
        observed["photo_id"] = photo
    return store.append("message.new", {"text": text, "sender_id": sender, "sender_observation": observed,
                                        "sent_at": "2026-01-01T0" + str(message_id % 10) + ":00:00+00:00",
                                        "reply_to_message_id": reply, "raw": raw or {}},
                        chat, message_id, sender)


def picture(path, pattern):
    image = Image.new("L", (64, 64))
    image.putdata([pattern(x, y) for y in range(64) for x in range(64)])
    image.convert("RGB").save(path, "JPEG", quality=95)


def test_profiles_cite_records_and_verify_against_an_export(journal, tmp_path):
    store, vault = journal
    store.set_target(CHAT, "Harbor", "supergroup", True)
    say(store, CHAT, 1, ALICE, "Send to " + GENESIS + " or " + EVM + ", call +7 999 123-45-67",
        "Alice A", "alice", {"scam": False, "premium": True}, photo=11)
    say(store, CHAT, 2, ALICE, "Support: @Fake_Support and https://evil.example/login, not 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "Alice Ann", "alice", {"scam": True, "premium": True}, photo=12,
        raw={"entities": [{"_": "MessageEntityTextUrl", "offset": 0, "length": 7, "url": "https://hidden.example/x"}]})
    say(store, CHAT, 3, BOB, "Is this legit?", "Bob", reply=1)
    store.append("message.edited", {"text": "edited", "sender_id": ALICE, "edited_at": "x"}, CHAT, 2)
    store.append("message.deleted", {"deleted_by": None}, CHAT, 1)
    say(store, OTHER, 7, ALICE, "elsewhere", "Alice Ann")
    avatars = store.root / "avatars"
    avatars.mkdir()
    picture(avatars / (str(ALICE) + ".jpg"), lambda x, y: x * 4)
    picture(avatars / (str(BOB) + ".jpg"), lambda x, y: min(255, x * 4 + 2))     # nearly the same picture
    picture(avatars / "70003.jpg", lambda x, y: 255 * ((x // 8 + y // 8) % 2))   # a different one

    value = dossier.signed(store, vault, CHAT, "Harbor", producer())
    people = {p["id"]: p for p in value["statement"]["people"]}
    alice, bob = people[ALICE], people[BOB]
    assert [n["value"] for n in alice["names"]] == ["Alice A", "Alice Ann"] and alice["usernames"][0]["value"] == "@alice"
    assert alice["flags"]["scam"]["value"] is True and alice["flags"]["premium"]["value"] is True
    assert [p["value"] for p in alice["avatar"]["photo_ids"]] == [11, 12]
    assert {(w["value"], w["detail"]) for w in alice["mentions"]["wallets"]} == {(GENESIS, "BTC"), (EVM, "EVM")}
    assert alice["mentions"]["phones"][0]["value"] == "+79991234567"
    assert {u["value"] for u in alice["mentions"]["usernames"]} == {"@fake_support"}
    assert {link["value"] for link in alice["mentions"]["links"]} == {"https://evil.example/login", "https://hidden.example/x"}
    activity = alice["activity"]
    assert (activity["messages"], activity["edited"], activity["deleted"]) == (2, 1, 1)
    assert activity["deleted_share"] == 0.5 and activity["hours_utc"][1] == 1 and activity["hours_utc"][2] == 1
    assert bob["relations"]["replies_to"][0]["id"] == ALICE and alice["relations"]["replied_by"] == [{"id": BOB, "count": 1}]
    assert alice["relations"]["other_chats"] == [{"chat_id": OTHER, "title": None, "messages": 1}]
    cached = alice["avatar"]["cached"]
    assert len(cached["sha256"]) == 64 and len(cached["phash"]) == 16 and "not a journal record" in cached["source"]
    assert [s["id"] for s in alice["avatar"]["similar"]] == [BOB]  # the checkerboard is not similar
    # Every cited record is hashed, nothing about profiles entered the journal, and an export confirms the facts.
    assert all(fact["records"] for fact in alice["names"]) and value["statement"]["record_hashes"]
    assert not store.events(search="Alice Ann", kind="dossier.changed")
    bundle = export_file(store, vault, "zip")
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    result = verify_dossier(path, value["fingerprint"], bundle)
    assert result["people"] == 2 and result["records_checked"] == len(value["statement"]["record_hashes"])
    # The export is verified too: a record changed behind an unchanged hash field is caught.
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(tampered, "w") as target:
        for item in source.infolist():
            data = source.read(item)
            if item.filename == "events.jsonl":
                data = data.replace(b"Alice", b"Alicf", 1)
            target.writestr(item, data)
    with pytest.raises(ValueError):
        verify_dossier(path, value["fingerprint"], tampered)
    value["statement"]["people"][0]["names"][0]["value"] = "Someone else"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(Exception):
        verify_dossier(path)
    bundle.unlink()


def test_profiles_check_the_export_belongs_to_the_same_workspace(journal, tmp_path, monkeypatch):
    store, vault = journal
    say(store, CHAT, 1, ALICE, "hello", "Alice")
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(dossier.signed(store, vault, CHAT)), encoding="utf-8")
    other_root = tmp_path / "other"
    other_vault = Vault(other_root)
    other = Store(other_root)
    other.bind(other_vault)
    other.append("message.new", {"text": "x"}, CHAT, 1)
    bundle = export_file(other, other_vault, "zip")
    with pytest.raises(ValueError, match="another workspace key"):
        verify_dossier(path, bundle=bundle)
    other.close()


def test_private_chat_profiles_include_the_other_person(journal):
    store, _ = journal
    say(store, ALICE, 1, ALICE, "send to " + GENESIS, "Alice")  # a private chat's ID is the person's ID
    say(store, ALICE, 2, BOB, "who is this", "Bob")
    people = {p["id"] for p in dossier.build(store, ALICE)["people"]}
    assert people == {ALICE, BOB}


def test_repeat_observations_do_not_inflate_reply_and_cross_chat_counts(journal):
    """Audit A9: snapshots, edits and recoveries are more records of one message, not more messages."""
    store, _ = journal
    say(store, CHAT, 1, ALICE, "Synthetic parent", "Alice")
    reply = say(store, CHAT, 2, BOB, "Synthetic reply", "Bob", reply=1)
    other = say(store, OTHER, 3, BOB, "Synthetic other chat", "Bob")

    def bob():
        people = {p["id"]: p for p in dossier.build(store, CHAT)["people"]}
        return people[BOB]["relations"], people[ALICE]["relations"]

    first, parent = bob()
    assert first["replies_to"][0]["count"] == 1 and parent["replied_by"] == [{"id": BOB, "count": 1}]
    for kind in ("message.snapshot", "message.snapshot", "message.edited", "message.recovered"):
        store.append(kind, dict(reply["payload"]), CHAT, 2, BOB)
    store.append("message.snapshot", dict(other["payload"]), OTHER, 3, BOB)
    repeated, parent = bob()
    assert repeated["replies_to"][0]["count"] == 1 and parent["replied_by"] == [{"id": BOB, "count": 1}]
    assert len(repeated["replies_to"][0]["records"]) > 1  # every observation is still cited
    assert repeated["other_chats"] == [{"chat_id": OTHER, "title": None, "messages": 1}]
    say(store, CHAT, 4, BOB, "A second, different reply", "Bob", reply=1)
    second, parent = bob()
    assert second["replies_to"][0]["count"] == 2 and parent["replied_by"] == [{"id": BOB, "count": 2}]


def test_switching_profiles_on_and_off_keeps_contents_out_of_the_journal(journal):
    store, vault = journal
    say(store, CHAT, 1, ALICE, "wallet " + GENESIS, "Alice")
    dossier.set_enabled(store, CHAT, True)
    assert dossier.enabled_chats(store) == [CHAT]
    dossier.signed(store, vault, CHAT)
    assert dossier.cache_path(store, CHAT).exists()
    dossier.set_enabled(store, CHAT, False)
    assert not dossier.cache_path(store, CHAT).exists() and dossier.enabled_chats(store) == []
    changes = store.events(kind="dossier.changed")
    assert [c["payload"]["enabled"] for c in changes] == [False, True]
    assert all(GENESIS not in json.dumps(c["payload"]) for c in changes)


def test_perceptual_hash_tolerates_recompression(tmp_path):
    picture(tmp_path / "a.jpg", lambda x, y: (x * 3 + y * 2) % 256)
    Image.open(tmp_path / "a.jpg").save(tmp_path / "b.jpg", "JPEG", quality=40)
    picture(tmp_path / "c.jpg", lambda x, y: 255 * ((x // 8 + y // 8) % 2))
    a, b, c = (dossier.phash(tmp_path / n) for n in ("a.jpg", "b.jpg", "c.jpg"))
    assert dossier.distance(a, b) <= 4 < dossier.distance(a, c)
