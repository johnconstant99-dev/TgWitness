import base64
import hashlib
import sqlite3
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.exceptions import InvalidSignature

from tgwitness.evidence import checkpoint, csv_bytes, export_file, html_bytes
from tgwitness.security import InstanceLock, Vault
from tgwitness.verify import fingerprint, verify_bundle, verify_events


def test_temporary_exports_stay_in_profile_and_orphans_are_cleaned(journal):
    from tgwitness.evidence import cleanup_exports
    store, vault = journal
    path = export_file(store, vault, "zip")
    directory = store.root / "temporary-exports"
    assert path.parent.resolve() == directory.resolve()
    unrelated = directory / "keep.zip"
    unrelated.write_bytes(b"user file")
    lookalike = directory / "tgwitness-export-keep.txt"
    lookalike.write_bytes(b"user file")
    cleanup_exports(store.root)
    assert not path.exists()
    assert unrelated.read_bytes() == lookalike.read_bytes() == b"user file"


def message(store, text="Before"):
    return store.append("message.new", {"text": text}, -100123, 7, 42)


def test_versions_immutable_and_chat_scoped(journal):
    store, vault = journal
    message(store)
    store.append("message.edited", {"text": "After"}, -100123, 7)
    store.append("message.deleted", {"deleted_by": None}, -100123, 7)
    message(store, "Another delivery is an observation")
    store.append("message.new", {"text": "Other chat"}, -100999, 7)
    assert len(store.events(chat_id=-100123, message_id=7)) == 4
    assert store.events(chat_id=-100123, message_id=7)[-1]["payload"]["text"] == "Before"
    for sql in ("UPDATE events SET kind='forged' WHERE seq=1", "DELETE FROM events WHERE seq=1"):
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(sql)
    assert verify_events(store.all_events(), vault.public_key)["events"] == 5


@pytest.mark.parametrize("field,value", [
    ("payload", {"text": "forged"}), ("observed_at", "1999-01-01"), ("chat_id", -999),
    ("actor_id", 1), ("source_at", "2020-01-01"), ("message_id", 999),
    ("seq", 100), ("previous_hash", "a"*64), ("kind", "invented"), ("hash", "f"*64),
    ("signature", base64.b64encode(b"x"*64).decode()),
])
def test_tamper_detection(journal, field, value):
    store, vault = journal
    message(store)
    records = store.all_events()
    records[0][field] = value
    with pytest.raises((ValueError, InvalidSignature)):
        verify_events(records, vault.public_key)


def test_unsigned_extra_fields_are_rejected(journal):
    store, vault = journal
    message(store)
    records = store.all_events()
    records[0]["claimed_editor"] = 999
    with pytest.raises(ValueError, match="fields"):
        verify_events(records, vault.public_key)


def test_concurrent_append_order(journal):
    store, vault = journal
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: message(store, str(i)), range(120)))
    assert verify_events(store.all_events(), vault.public_key)["events"] == 120


def test_bundle_checkpoint_secret_exclusion_and_media(journal, tmp_path):
    store, vault = journal
    vault.save("credentials", {"api_hash": "SECRET-API", "session": "SECRET-SESSION"})
    message(store, "Текст • emoji 👍")
    blob = b"preserved bytes"
    digest = hashlib.sha256(blob).hexdigest()
    (tmp_path / "media").mkdir()
    (tmp_path / "media" / digest).write_bytes(blob)
    store.append("media.saved", {"media_sha256": digest, "message_event": 1})
    cp = checkpoint(store, vault)
    path = export_file(store, vault, "zip")
    try:
        result = verify_bundle(path, fingerprint(vault.public_key), cp)
        assert result["events"] == 2 and result["key_pinned"]
        with zipfile.ZipFile(path) as z:
            assert z.read("media/" + digest) == blob
            assert "verify.py" in z.namelist()
            for name in z.namelist():
                assert b"SECRET-" not in z.read(name)
        with pytest.raises(ValueError, match="fingerprint"):
            verify_bundle(path, "0"*64)
    finally:
        path.unlink()


def test_truncation_requires_independent_checkpoint(journal):
    store, vault = journal
    message(store)
    old = export_file(store, vault, "zip")
    message(store, "Later")
    cp = checkpoint(store, vault)
    try:
        assert verify_bundle(old)["events"] == 1
        with pytest.raises(ValueError, match="shorter"):
            verify_bundle(old, checkpoint=cp)
    finally:
        old.unlink()


def test_corrupt_bundle_file_detected(journal, tmp_path):
    store, vault = journal
    message(store)
    source = export_file(store, vault, "zip")
    changed = tmp_path / "changed.zip"
    try:
        with zipfile.ZipFile(source) as zin, zipfile.ZipFile(changed, "w") as zout:
            for name in zin.namelist():
                zout.writestr(name, b"forged" if name == "events.csv" else zin.read(name))
        with pytest.raises(ValueError, match="hash mismatch"):
            verify_bundle(changed)
    finally:
        source.unlink()


def test_missing_or_modified_attachment_refuses_export(journal, tmp_path):
    store, vault = journal
    digest = hashlib.sha256(b"original").hexdigest()
    store.append("media.saved", {"media_sha256": digest})
    with pytest.raises(FileNotFoundError):
        export_file(store, vault, "zip")
    (tmp_path / "media").mkdir()
    (tmp_path / "media" / digest).write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        export_file(store, vault, "zip")


def test_derivatives_escape_untrusted_content(journal):
    store, _ = journal
    event = message(store, '=WEBSERVICE("https://invalid")<script>alert(1)</script>')
    html = html_bytes([event]).decode()
    csv = csv_bytes([event]).decode()
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "'=WEBSERVICE" in csv
    assert event["payload"]["text"].startswith("=")


def test_encrypted_vault_and_missing_key_fail_closed(journal, tmp_path):
    _, vault = journal
    vault.save("credentials", {"session": "TOPSECRET"})
    assert b"TOPSECRET" not in (tmp_path / "credentials.enc").read_bytes()
    (tmp_path / "vault.key").unlink()
    with pytest.raises(RuntimeError, match="missing"):
        Vault(tmp_path)


def test_instance_lock(journal, tmp_path):
    first = InstanceLock(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="already open"):
            InstanceLock(tmp_path)
    finally:
        first.close()
    InstanceLock(tmp_path).close()


def test_filters_and_pagination(journal):
    store, _ = journal
    for i in range(8):
        message(store, "needle " + str(i))
    store.append("membership.service", {})
    store.append("membership.update", {})
    store.append("coverage.gap", {})
    assert len(store.events(kind="membership")) == 2
    assert len(store.events(kind="coverage")) == 1
    assert [e["seq"] for e in store.events(before=6, limit=2)] == [5, 4]
    assert len(store.events(search="needle")) == 8
