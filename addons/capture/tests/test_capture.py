import io
import sqlite3
import zipfile

import pytest
from fastapi.testclient import TestClient

from tgwitness_capture.adapters import sqlite_snapshot
from tgwitness_capture.export import export_zip
from tgwitness_capture.format import canonical, decode, digest, seal
from tgwitness_capture.journal import Journal
from tgwitness_capture.service import Config, create_app
from tgwitness_capture.verify import verify_zip


@pytest.fixture
def journal(tmp_path):
    value = Journal(tmp_path / "observer")
    yield value
    value.close()


def saved(journal, text=b"original page"):
    artifact = journal.artifact(text, "rendered_page", "text/html")
    return journal.append("capture.saved", {"title": "<script>alert('x')</script>"}, [artifact])


def rewrite_archive(source, destination, change):
    with zipfile.ZipFile(source) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    change(entries)
    with zipfile.ZipFile(destination, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_export_independent_verification_and_no_secrets(journal, tmp_path):
    saved(journal)
    checkpoint = journal.checkpoint()
    destination = tmp_path / "capture.zip"
    export_zip(journal, destination)
    result = verify_zip(destination, journal.fingerprint, checkpoint, require_final_anchor=True)
    assert result["valid"] and result["key_pinned"] and result["checkpoint_checked"]
    assert result["unanchored_events"] == 0
    with zipfile.ZipFile(destination) as archive:
        assert not any("private" in name or "token" in name or "sqlite3" in name for name in archive.namelist())
        page = archive.read("report.html")
        assert b"<script>alert" not in page
        assert b"&lt;script&gt;" in page
    assert not verify_zip(destination)["key_pinned"]
    with pytest.raises(ValueError, match="Untrusted observer"):
        verify_zip(destination, "0" * 64)


@pytest.mark.parametrize("mutation", ["artifact", "event", "extra", "manifest"])
def test_tampering_rejected(journal, tmp_path, mutation):
    saved(journal)
    destination = tmp_path / "good.zip"
    export_zip(journal, destination)

    def change(entries):
        if mutation == "artifact":
            name = next(name for name in entries if name.startswith("objects/"))
            entries[name] = b"forged page"
        elif mutation == "event":
            entries["events.jsonl"] = entries["events.jsonl"].replace(b"capture.saved", b"capture.faked")
        elif mutation == "extra":
            entries["../private-key.bin"] = b"surprise"
        else:
            body = decode(entries["manifest.json"])
            body["seq"] += 1
            entries["manifest.json"] = canonical(body)

    bad = tmp_path / "bad.zip"
    rewrite_archive(destination, bad, change)
    with pytest.raises(Exception):
        verify_zip(bad, journal.fingerprint)


def test_retained_checkpoint_detects_valid_short_prefix(journal, tmp_path):
    saved(journal)
    early_checkpoint = journal.checkpoint()
    early = tmp_path / "early.zip"
    export_zip(journal, early)
    saved(journal, b"later page")
    later_checkpoint = journal.checkpoint()
    assert verify_zip(early, journal.fingerprint)["valid"]
    with pytest.raises(ValueError, match="shorter"):
        verify_zip(early, journal.fingerprint, later_checkpoint)
    later = tmp_path / "later.zip"
    export_zip(journal, later)
    assert verify_zip(later, journal.fingerprint, early_checkpoint)["unanchored_events"] > 0
    with pytest.raises(ValueError, match="unanchored"):
        verify_zip(later, journal.fingerprint, early_checkpoint, require_final_anchor=True)


def test_deduplicates_bytes_but_retains_each_observation(journal):
    first = saved(journal)
    second = saved(journal)
    assert len(list(journal.objects.iterdir())) == 1
    assert first["hash"] != second["hash"]
    assert first["artifacts"] == second["artifacts"]


def test_coarse_monotonic_clock_can_repeat_without_breaking_export(journal, tmp_path, monkeypatch):
    monkeypatch.setattr("tgwitness_capture.journal.time.monotonic_ns", lambda: 100000)
    saved(journal)
    saved(journal, b"another state within the same clock tick")
    destination = tmp_path / "coarse-clock.zip"
    export_zip(journal, destination)
    assert verify_zip(destination, journal.fingerprint)["events"] == 2


def test_export_checks_object_bytes_before_release(journal, tmp_path):
    event = saved(journal)
    (journal.objects / event["artifacts"][0]["sha256"]).write_bytes(b"changed")
    destination = tmp_path / "never-released.zip"
    with pytest.raises(ValueError):
        export_zip(journal, destination)
    assert not destination.exists()


def test_zip_symlink_metadata_rejected_even_when_signed_bytes_match(journal, tmp_path):
    saved(journal, b"/etc/passwd")
    destination = tmp_path / "original.zip"
    export_zip(journal, destination)
    modified = tmp_path / "symlink.zip"
    with zipfile.ZipFile(destination) as original, zipfile.ZipFile(modified, "w") as target:
        for info in original.infolist():
            if info.filename.startswith("objects/"):
                info.create_system = 3
                info.external_attr = 0o120777 << 16
            target.writestr(info, original.read(info.filename))
    with pytest.raises(ValueError, match="Unsupported archive member"):
        verify_zip(modified, journal.fingerprint)


def test_exclusive_writer_and_missing_key_refusal(tmp_path):
    root = tmp_path / "exclusive"
    journal = Journal(root)
    with pytest.raises(ValueError, match="already in use"):
        Journal(root)
    journal.append("capture.paused")
    journal.close()
    (root / "private-key.bin").unlink()
    with pytest.raises(ValueError, match="Missing signing key"):
        Journal(root)
    assert not (root / "private-key.bin").exists()


def test_reopen_rejects_modified_journal(tmp_path):
    root = tmp_path / "corrupt"
    journal = Journal(root)
    saved(journal)
    journal.close()
    with sqlite3.connect(root / "journal.sqlite3") as db:
        event = decode(db.execute("SELECT body FROM events WHERE seq=1").fetchone()[0])
        event["payload"]["title"] = "tampered"
        db.execute("UPDATE events SET body=? WHERE seq=1", (canonical(event),))
    with pytest.raises(ValueError, match="hash mismatch"):
        Journal(root)


def test_sqlite_backup_includes_wal_without_changing_source(journal, tmp_path):
    source = tmp_path / "ayudata.db"
    live = sqlite3.connect(source)
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("CREATE TABLE saved_messages (id INTEGER, text TEXT, deleted INTEGER)")
        live.execute("INSERT INTO saved_messages VALUES (1, 'before', 0)")
        live.commit()
        before = digest(source.read_bytes())
        meta, artifacts, observed = sqlite_snapshot(journal, source, "synthetic-fixture")
        assert meta["quick_check"] == "ok" and not meta["message_schema_interpreted"]
        with sqlite3.connect(journal.objects / artifacts[0]["sha256"]) as db:
            assert db.execute("SELECT text FROM saved_messages").fetchone() == ("before",)
        live.execute("UPDATE saved_messages SET text='edited', deleted=1")
        live.commit()
        _, newer, _ = sqlite_snapshot(journal, source, "synthetic-fixture")
        assert newer[0]["sha256"] != artifacts[0]["sha256"]
        with sqlite3.connect(journal.objects / newer[0]["sha256"]) as db:
            assert db.execute("SELECT text, deleted FROM saved_messages").fetchone() == ("edited", 1)
        assert digest(source.read_bytes()) == before
    finally:
        live.close()


def test_panel_controls_are_optional_authenticated_and_independent(tmp_path):
    source = tmp_path / "ayudata.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE example(value TEXT)")
        db.execute("INSERT INTO example VALUES ('local observation')")
    root = tmp_path / "ayugram"
    config = Config(kind="ayugram", ayugram_db=str(source), poll_seconds=60, snapshot_seconds=60)
    with TestClient(create_app(root, config)) as client:
        assert client.get("/api/status").status_code == 401
        witness = {"Authorization": "Bearer " + (root / "witness-token.txt").read_text()}
        assert client.get("/api/checkpoint", headers=witness).status_code == 200
        assert client.post("/api/settings", headers=witness, json={"enabled": True}).status_code == 401
        client.headers["Authorization"] = "Bearer " + (root / "control-token.txt").read_text()
        initial = client.get("/api/status").json()
        assert initial["settings"]["enabled"] is False and initial["settings"]["video"] is False
        assert client.post("/api/snapshot", json={}).status_code == 409
        assert client.post("/api/settings", headers={"Origin": "https://hostile.example"}, json={"enabled": True}).status_code == 403
        assert client.post("/api/settings", json={"enabled": "false"}).status_code == 422
        assert client.post("/api/settings", json={"private_key": "injected"}).status_code == 422
        assert client.post("/api/settings", json={"enabled": True, "video": True}).status_code == 400
        assert client.post("/api/settings", json={"enabled": True}).status_code == 200
        assert client.post("/api/export", json={}).status_code == 409
        snapshot = client.post("/api/snapshot", json={})
        assert snapshot.status_code == 200 and snapshot.json()["event"]["kind"] == "capture.saved"
        assert client.post("/api/settings", json={"enabled": False}).status_code == 200
        checkpoint = client.get("/api/checkpoint").json()
        exported = client.post("/api/export", json={})
        assert exported.status_code == 200
        assert verify_zip(io.BytesIO(exported.content), initial["fingerprint"], checkpoint, require_final_anchor=True)["valid"]
    with TestClient(create_app(root, config)) as client:
        client.headers["Authorization"] = "Bearer " + (root / "control-token.txt").read_text()
        assert client.get("/api/status").json()["settings"]["enabled"] is False
        assert client.get("/api/status").json()["fingerprint"] == initial["fingerprint"]
    with TestClient(create_app(tmp_path / "browser", Config())) as client:
        assert client.app.state.recorder.journal.fingerprint != initial["fingerprint"]


def test_witness_receipt_requires_separate_pinned_key(journal, tmp_path):
    saved(journal)
    checkpoint = journal.checkpoint("a" * 64)
    destination = tmp_path / "capture.zip"
    export_zip(journal, destination)
    witness = Journal(tmp_path / "witness")
    try:
        body = {"format": "tgwitness-capture-v1", "kind": "witness.receipt", "public_key": witness.public_key,
                "checkpoint": checkpoint, "received_at": "2026-11-02T00:00:00Z"}
        receipt = {"body": body, "signature": seal(witness.key, "receipt", body)}
        assert verify_zip(destination, journal.fingerprint, receipt=receipt,
                          witness_fingerprint=witness.fingerprint)["independently_witnessed"]
        with pytest.raises(ValueError, match="trusted witness"):
            verify_zip(destination, journal.fingerprint, receipt=receipt)
    finally:
        witness.close()


@pytest.mark.parametrize("raw", [b'{"kind":"browser","kind":"ayugram"}', b'{"poll_seconds":NaN}',
                                  b'{"poll_seconds":false}', b'{"unexpected":true}'])
def test_invalid_config_rejected(tmp_path, raw):
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        Config.load(path)
