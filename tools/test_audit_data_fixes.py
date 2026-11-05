import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import zipfile

import pytest
from telethon.tl import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import account_export_transport, dossier, evidence, export_history, handover, pdf_report, report
from tgwitness.account_export import BoundedWriter
from tgwitness.collector import Collector, describe_message
from tgwitness.multi_export import MultiExport
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import (SEAL_CLOSE, SEAL_OPEN, fingerprint, verify_bundle, verify_dossier, verify_handover,
                              verify_report)

CHAT, PERSON = -1000000000123, 77001
WHEN = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


@pytest.fixture
def workspace(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.set_target(CHAT, "Synthetic source", "supergroup", True)
    yield store, vault
    store.close()


def payload(text="Synthetic message"):
    return {"text": text, "sender_id": PERSON,
            "sender_observation": {"id": PERSON, "display_name": "Synthetic sender"},
            "sent_at": WHEN.isoformat(), "edited_at": None}


def private_payload():
    return {**payload("PRIVATE_MESSAGE"), "raw": {
        "message": "PRIVATE_MESSAGE", "entities": [
            {"_": "MessageEntityTextUrl", "offset": 0, "length": 4, "url": "mailto:private@example.invalid"}],
        "reply_markup": {"_": "ReplyInlineMarkup", "rows": [{"buttons": [
            {"_": "KeyboardButtonCopy", "text": "PRIVATE_LABEL", "copy_text": "PRIVATE_COPY"},
            {"_": "KeyboardButtonUserProfile", "text": "PRIVATE_PROFILE", "user_id": PERSON},
            {"_": "KeyboardButtonUrl", "text": "Contact", "url": "mailto:private@example.invalid"},
            {"_": "KeyboardButtonCallback", "text": "Callback", "data": {"bytes_base64": "cHJpdmF0ZQ=="}}]}]},
        "media": {"_": "MessageMediaWebPage", "webpage": {
            "url": "https://example.invalid/private", "title": "PRIVATE_PREVIEW"}}}}


def test_handover_omits_withheld_details_from_signed_outputs(workspace):
    store, vault = workspace
    store.append("message.new", private_payload(), CHAT, 1, PERSON)
    before = store.all_events()
    options = handover.Options(purpose="Synthetic disclosure", chats=[CHAT], others="pseudonymize",
                               text="none", attachments="none", mask_contacts=True)
    path, _ = handover.export(store, vault, options, report.resolved())
    verify_handover(path, fingerprint(vault.public_key))
    markers = ("PRIVATE_MESSAGE", "PRIVATE_LABEL", "PRIVATE_COPY", "PRIVATE_PREVIEW", "PRIVATE_PROFILE",
               "private@example.invalid", "cHJpdmF0ZQ==", str(PERSON))
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith((".json", ".jsonl", ".html")) and name != "manifest.json":
                data = archive.read(name).decode("utf-8")
                assert not any(marker in data for marker in markers), name
        pdf = store.root / "projected.pdf"
        pdf.write_bytes(archive.read("report.pdf"))
        assert verify_report(pdf, fingerprint(vault.public_key))["pdf_signature"]
        row = json.loads(archive.read("records.jsonl").splitlines()[0])
    assert row["payload"]["sender_id"] is None and row["actor_id"] is None
    assert row["payload"]["text"] is None and "raw" not in row["payload"]
    assert store.all_events() == before


def test_handover_masks_metadata_even_when_message_text_has_no_contacts(workspace):
    store, vault = workspace
    value = private_payload()
    value["text"] = value["raw"]["message"] = "Open"
    value["raw"]["media"] = {"_": "MessageMediaContact", "phone_number": "+12025550173"}
    store.append("message.new", value, CHAT, 1, PERSON)
    options = handover.Options(purpose="Synthetic contact masking", chats=[CHAT], others="show",
                               text="all", attachments="none", mask_contacts=True)
    path, _ = handover.export(store, vault, options, report.resolved())
    verify_handover(path, fingerprint(vault.public_key))
    with zipfile.ZipFile(path) as archive:
        for name in ("records.jsonl", "report.json"):
            data = archive.read(name).decode()
            assert "private@example.invalid" not in data and "+12025550173" not in data
            assert "cHJpdmF0ZQ==" not in data
        row = json.loads(archive.read("records.jsonl").splitlines()[0])
    assert "raw" not in row["payload"] and row["payload"]["text"] == "Open"


def test_handover_profile_buttons_and_empty_forward_are_projected(workspace):
    store, _ = workspace
    event = store.append("message.new", private_payload(), CHAT, 1, PERSON)
    options = handover.Options(purpose="Synthetic pseudonyms", chats=[CHAT], others="pseudonymize", text="all")
    minimiser = handover.Minimiser(options, None, {})
    projected = minimiser.present(event)
    profile = projected["payload"]["details"]["buttons"]["rows"][0][1]
    assert profile["user_id"] == profile["text"] == "P01"
    assert minimiser.details({"forwarded_from": {"from_name": "PRIVATE_NAME"}}, "other", True) == {}


def test_handover_missing_selected_file_fails_until_restored(workspace):
    store, vault = workspace
    content = b"Synthetic preserved attachment."
    digest = hashlib.sha256(content).hexdigest()
    event = store.append("message.new", payload(), CHAT, 1, PERSON)
    store.append("media.saved", {"message_event": event["seq"], "media_sha256": digest,
                                 "size": len(content)}, CHAT, 1)
    options = handover.Options(purpose="Synthetic attachment", chats=[CHAT], others="show", attachments="all")
    with pytest.raises(FileNotFoundError, match="selected attachment is missing"):
        handover.export(store, vault, options, report.resolved())
    omitted, _ = handover.export(store, vault, options.model_copy(update={"attachments": "none"}), report.resolved())
    assert verify_handover(omitted, fingerprint(vault.public_key))["attachments"] == 0
    (store.root / "media").mkdir(exist_ok=True)
    (store.root / "media" / digest).write_bytes(content)
    complete, _ = handover.export(store, vault, options, report.resolved())
    assert verify_handover(complete, fingerprint(vault.public_key))["attachments"] == 1


def test_pdf_metadata_placeholder_does_not_replace_signature_range(workspace):
    store, vault = workspace
    store.append("message.new", payload(), CHAT, 1, PERSON)
    title = pdf_report.BYTE_RANGE_PLACEHOLDER.decode()
    path = evidence.export_file(store, vault, "pdf", report.ReportOptions(case_title=title).model_dump())
    assert verify_report(path, fingerprint(vault.public_key))["pdf_signature"]
    assert b"/Title (" + title.encode() + b")" in path.read_bytes()


def message(edit_date=None):
    return types.Message(id=1, peer_id=types.PeerChannel(123), date=WHEN, edit_date=edit_date,
                         from_id=types.PeerUser(PERSON), message="Synthetic unchanged text")


def test_same_text_edit_timestamp_and_duplicate_delivery(workspace):
    store, vault = workspace
    store.append("message.new", describe_message(message()), CHAT, 1, PERSON)
    collector = Collector(store, vault)
    collector.running = True
    collector.covers = AsyncMock(return_value=True)
    collector.failure = AsyncMock()
    async def capture(value, kind, chat, *args, **kwargs):
        store.append(kind, describe_message(value), chat, value.id, PERSON)
    collector.capture_message = AsyncMock(side_effect=capture)
    event = SimpleNamespace(message=message(WHEN + timedelta(minutes=5)), chat_id=CHAT)
    async def scenario():
        await collector.on_edit(event)
        await collector.on_edit(event)
    asyncio.run(scenario())
    assert collector.capture_message.await_count == 1 and collector.failure.await_count == 0
    shown = store.chat_messages(CHAT)["messages"][0]
    assert len(shown["versions"]) == 2 and shown["versions"][-1]["edited_at"] == event.message.edit_date.isoformat()


def test_recheck_uncertain_access_retries_missing_and_recovers(workspace):
    store, vault = workspace
    for i in range(1, 13):
        store.append("message.new", describe_message(message()), CHAT, i, PERSON)
    collector = Collector(store, vault)
    collector.running = True
    collector.resolve_target = AsyncMock(return_value=types.InputPeerChannel(123, 1))
    returned = {}
    async def fetch(entity, **kwargs):
        return [returned.get(i) for i in kwargs["ids"]] if "ids" in kwargs else []
    collector.client = SimpleNamespace(get_messages=fetch)
    async def capture(value, kind, chat, *args, **kwargs):
        store.append(kind, describe_message(value), chat, value.id, PERSON)
    collector.capture_message = AsyncMock(side_effect=capture)
    settings = {"messages": False, "edits": True, "deletions": True}
    uncertain = asyncio.run(collector.recheck_chat(CHAT, settings))
    assert uncertain["missing"] == 0 and uncertain["visibility_uncertain"]
    assert len(store.alive_message_ids(CHAT)) == 12
    returned[1] = message()
    missing = asyncio.run(collector.recheck_chat(CHAT, settings))
    assert missing["missing"] == 11 and store.message_state(CHAT, 2)["missing"]
    restored = message()
    restored.id = 2
    returned[2] = restored
    recovered = asyncio.run(collector.recheck_chat(CHAT, settings))
    assert recovered["recovered"] == 1 and not store.message_state(CHAT, 2)["missing"]
    assert not next(m for m in store.chat_messages(CHAT)["messages"] if m["message_id"] == 2)["missing"]
    assert store.chat_authors(CHAT)["authors"][0]["missing"] == 10
    assert any(e["kind"] == "message.missing_on_recheck" and e["message_id"] == 2 for e in store.all_events())
    returned[1] = message(WHEN + timedelta(minutes=6))
    edited = asyncio.run(collector.recheck_chat(CHAT, settings))
    assert edited["edited"] == 1


def test_legacy_missing_index_repair_preserves_journal(workspace):
    store, _ = workspace
    store.append("message.new", payload(), CHAT, 1, PERSON)
    store.append("message.missing_on_recheck", {}, CHAT, 1)
    store.append("message.snapshot", payload(), CHAT, 1, PERSON)
    before = copy.deepcopy(store.all_events())
    with store.transaction():
        store.db.execute("UPDATE message_state_index SET missing=1")
        store.db.execute("UPDATE chat_state_index SET missing=1")
        store.db.execute("DELETE FROM journal_read_index WHERE name='missing_recovery'")
    reopened = Store(store.root)
    try:
        assert not reopened.message_state(CHAT, 1)["missing"]
        assert reopened.alive_message_ids(CHAT) == [1]
        assert reopened.all_events() == before
    finally:
        reopened.close()


def test_oversized_export_keeps_metadata_and_other_cached_exports(workspace):
    store, _ = workspace
    source = store.root / "synthetic.zip"
    with patch.object(export_history, "MAX_CACHE_BYTES", 16):
        source.write_bytes(b"a" * 8)
        small = export_history.prepared(store, source, "zip", False)
        source = store.root / "large.zip"
        source.write_bytes(b"b" * 32)
        large = export_history.prepared(store, source, "zip", False)
        assert large["bytes"] == 32 and large.get("cache_warning")
        assert not (store.root / "prepared-exports" / large["id"]).exists()
        assert (store.root / "prepared-exports" / small["id"]).read_bytes() == b"a" * 8
        assert source.read_bytes() == b"b" * 32
        source = store.root / "another.zip"
        source.write_bytes(b"c" * 8)
        export_history.prepared(store, source, "zip", False)
    rows = export_history.listing(store)["exports"]
    assert len(rows) == 3 and sum(row["available"] for row in rows) == 2


@pytest.mark.parametrize("container", ["document", "webpage", "paid"])
@pytest.mark.parametrize("changed", [False, True])
def test_file_reference_refresh_matches_actual_attachment(container, changed):
    def document(reference, ident=900):
        return types.Document(id=ident, access_hash=1, file_reference=reference, date=WHEN,
                              mime_type="application/octet-stream", size=4, dc_id=2, attributes=[])
    def wrap(doc):
        if container == "webpage":
            return types.MessageMediaWebPage(webpage=types.WebPage(id=88, url="https://example.invalid/",
                display_url="example.invalid", hash=1, document=doc))
        if container == "paid":
            return types.MessageMediaPaidMedia(stars_amount=1, extended_media=[
                types.MessageExtendedMedia(media=types.MessageMediaDocument(document=document(b"other", 800))),
                types.MessageExtendedMedia(media=types.MessageMediaDocument(document=doc))])
        return types.MessageMediaDocument(document=doc)
    first = document(b"old")
    refreshed = SimpleNamespace(id=1, media=wrap(document(b"new", 901 if changed else 900)))
    class Client:
        calls = 0
        async def download_media(self, media, *, file, progress_callback):
            self.calls += 1
            if self.calls == 1:
                file.write(b"partial")
                raise account_export_transport.errors.FileReferenceExpiredError(request=None)
            file.write(b"data")
            return file
        async def __call__(self, request):
            return SimpleNamespace(messages=[refreshed])
    client = Client()
    transport = account_export_transport.Transport.__new__(account_export_transport.Transport)
    transport.ranged = lambda task: client
    transport.peers = {CHAT: types.InputPeerChannel(123, 1)}
    stream = io.BytesIO()
    writer = BoundedWriter(stream, 32)
    task = {"category": "messages", "chat_id": CHAT, "message_id": 1}
    if changed:
        with pytest.raises(ValueError, match="Attachment changed"):
            asyncio.run(transport.download(first, writer, AsyncMock(), task))
        assert client.calls == 1
    else:
        asyncio.run(transport.download(first, writer, AsyncMock(), task))
        assert client.calls == 2 and stream.getvalue() == b"data"


@pytest.mark.parametrize("channel", [False, True])
def test_multi_export_requires_shared_message_namespace(tmp_path, channel):
    stores, entries = [], {}
    peer = types.Channel(id=123, title="Synthetic group", photo=types.ChatPhotoEmpty(), date=WHEN,
                         access_hash=1, megagroup=True) if channel else types.User(id=PERSON, first_name="Synthetic peer")
    chat = CHAT if channel else PERSON
    try:
        for i, name in enumerate(("default", "extra"), 1):
            root = tmp_path / name
            vault, store = Vault(root), Store(root)
            stores.append(store)
            store.bind(vault)
            store.set_setting("account", {"id": 100 + i})
            vault.save("credentials", {"session": "synthetic-presence-marker"})
            collector = Collector(store, vault)
            collector.restore = AsyncMock()
            collector.dialog_cache = {chat: {"kind": "supergroup", "entity": peer}}
            collector.client = SimpleNamespace(get_messages=AsyncMock(return_value=[SimpleNamespace(id=4001)]))
            entries[name] = {"app": SimpleNamespace(state=SimpleNamespace(collector=collector, store=store, vault=vault))}
        multi = MultiExport(SimpleNamespace(entries=entries))
        multi.run = AsyncMock()
        async def scenario():
            result = await multi.start(chat, ["default", "extra"], "default")
            await multi.task
            await asyncio.sleep(0)
            return result
        result = asyncio.run(scenario())
        assert [w["profile_id"] for w in result["workers"]] == (["default", "extra"] if channel else ["default"])
    finally:
        for store in stores:
            store.close()


def test_dossier_scope_filters_relations_and_unscoped_avatar_cache(workspace):
    store, vault = workspace
    hidden = CHAT - 1
    store.set_target(hidden, "PRIVATE_SOURCE", "supergroup", True)
    for chat in (CHAT, hidden):
        store.append("message.new", payload(), chat, 1, PERSON)
    store.set_setting("dossiers", {str(CHAT): {"enabled_at": WHEN.isoformat(), "generation": "synthetic"}})
    cached = {PERSON: {"phash": "0" * 16}, 88002: {"phash": "0" * 16}}
    with patch.object(dossier, "avatar_index", return_value=cached):
        full = dossier.signed(store, vault, CHAT)
        saved = dossier.cache_path(store, CHAT).read_bytes()
        restricted = dossier.signed(store, vault, CHAT, allowed_chats={CHAT})
    assert full["statement"]["people"][0]["relations"]["other_chats"][0]["chat_id"] == hidden
    person = restricted["statement"]["people"][0]
    assert person["relations"]["other_chats"] == [] and person["avatar"]["cached"] is None
    assert not person["avatar"]["similar"] and "PRIVATE_SOURCE" not in json.dumps(restricted)
    assert dossier.cache_path(store, CHAT).read_bytes() == saved
    path = store.root / "restricted-dossier.json"
    path.write_bytes(canonical(restricted))
    verify_dossier(path, fingerprint(vault.public_key))
    with pytest.raises(ValueError, match="permitted scope"):
        dossier.signed(store, vault, hidden, allowed_chats={CHAT})


def test_report_seal_rejects_appended_markup(workspace):
    store, vault = workspace
    store.append("message.new", payload(), CHAT, 1, PERSON)
    path = evidence.export_file(store, vault, "html", {**report.resolved(), "language": "en"})
    assert verify_report(path, fingerprint(vault.public_key))
    data = path.read_bytes()
    at = data.rfind(SEAL_OPEN)
    seal = json.loads(data[at + len(SEAL_OPEN):-len(SEAL_CLOSE)])
    seal["note"] = "</script><div>send 1 BTC to bc1qsynthetic</div><script type='text/plain'>"
    path.write_bytes(data[:at] + SEAL_OPEN + json.dumps(seal).encode() + SEAL_CLOSE)
    with pytest.raises(ValueError, match="markup"):
        verify_report(path, fingerprint(vault.public_key))


def test_bundle_rejects_bytes_before_first_member(workspace, tmp_path):
    store, vault = workspace
    store.append("message.new", payload(), CHAT, 1, PERSON)
    path = evidence.export_file(store, vault, "zip")
    assert verify_bundle(path, fingerprint(vault.public_key))
    decoy = io.BytesIO()
    with zipfile.ZipFile(decoy, "w") as archive:
        archive.writestr("events.jsonl", "{}\n")
    forged = tmp_path / "prepended.zip"
    forged.write_bytes(decoy.getvalue() + path.read_bytes())
    with pytest.raises(ValueError, match="before its first member"):
        verify_bundle(forged, fingerprint(vault.public_key))


def test_signed_json_rejects_duplicate_keys(workspace, tmp_path):
    store, vault = workspace
    store.append("message.new", payload(), CHAT, 1, PERSON)
    path = evidence.export_file(store, vault, "json", {**report.resolved(), "language": "en"})
    assert verify_report(path, fingerprint(vault.public_key))
    forged = tmp_path / "duplicate.json"
    forged.write_bytes(b'{"report": {"forged": true}, ' + path.read_bytes().lstrip()[1:])
    with pytest.raises(ValueError, match="duplicate key"):
        verify_report(forged, fingerprint(vault.public_key))


def test_public_proof_pins_its_witness_key(workspace, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _, vault = workspace
    witness = Ed25519PrivateKey.generate()
    public = base64.b64encode(witness.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    statement = {"format": "tgwitness-public-proof-v1", "alias": "synthetic", "witness_public_key": public,
                 "observed_at": "2026-10-01T12:00:00.000+00:00", "witness_seq": 1, "witness_record_hash": "ab" * 32,
                 "status": "legacy_head", "collector_fingerprint": fingerprint(vault.public_key),
                 "interval_minutes": 10, "checkpoint": None, "capture": None, "capture_delta": None}
    proof = tmp_path / "proof.json"
    proof.write_text(json.dumps({"statement": statement,
                                 "signature": base64.b64encode(witness.sign(canonical(statement))).decode()}))

    def run(*extra):
        output = subprocess.run([sys.executable, "-m", "tgwitness.verify", str(proof), "--json", *extra],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=120)
        return json.loads(output.stdout)

    assert run("--fingerprint", fingerprint(vault.public_key))["signer_pinned"] is False
    assert run("--witness-fingerprint", fingerprint(public))["signer_pinned"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
