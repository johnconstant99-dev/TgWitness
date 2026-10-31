import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tgwitness import chat_export, i18n, report
from tgwitness.app import create_app
from tgwitness.evidence import export_file
from tgwitness.verify import (SEAL_OPEN, fingerprint, read_sealed, verify_bundle, verify_chat_export,
                              verify_report)

CHAT = -1001234567890
VERIFIER = str(Path("tgwitness") / "verify.py")
CASE = {"case_title": "Fake exchange support", "case_id": "PD-2026-0142", "examiner": "Analyst",
        "organization": "PhishDestroy", "notes": "Wallets sent to the blocklist.\nHosting abuse filed."}


def journal_with_messages(store):
    store.append("observation.started", {})
    store.append("target.changed", {"title": "Harbor", "enabled": True}, CHAT)
    for i in (1, 2, 4):
        store.append("message.new", {"text": "Pay to <b>wallet</b> " + str(i), "sender_id": 7,
                                     "sender_observation": {"id": 7, "username": "support", "display_name": "Support"}},
                     CHAT, i, 7)
    store.append("message.deleted", {}, CHAT, 2)


def evidence(journal, language="ru"):
    store, vault = journal
    journal_with_messages(store)
    return export_file(store, vault, "zip", {**report.resolved(None, language), **CASE})


def test_evidence_archive_carries_a_sealed_localized_report_custody_and_sums(journal):
    _, vault = journal
    path = evidence(journal)
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read("manifest.json"))
            page = archive.read("report.html").decode("utf-8")
            custody = json.loads(archive.read("custody.json"))
            sums = archive.read("SHA256SUMS").decode()
            readme = archive.read("README.txt").decode("utf-8")
        assert {"report.html", "custody.json", "SHA256SUMS", "README.txt", "verify.py"} <= names
        assert manifest["case"]["id"] == "PD-2026-0142" and manifest["report"]["language"] == "ru"
        assert all(line.split("  ")[0] == manifest["files"][line.split("  ")[1]] for line in sums.splitlines())
        assert custody["format"] == "tgwitness-custody-v1" and custody["case"]["examiner"] == "Analyst"
        assert custody["acquisition"]["record_count"] == manifest["event_count"]
        assert any(s["reference"] == "ISO/IEC 27037:2012" for s in custody["standards"])
        # Localized, with metadata for people and machines, and nothing that loads from the network.
        assert '<html lang="ru"' in page and "Цепочка хранения" in page and "Печать" in page
        assert 'name="DC.identifier" content="urn:uuid:' in page and "application/ld+json" in page
        assert "Content-Security-Policy" in page and "default-src &#x27;none&#x27;" in page
        assert "&lt;b&gt;wallet&lt;/b&gt;" in page and "<b>wallet</b>" not in page
        assert "Как проверить" in readme and "Use a verifier from a trusted checkout" in readme
        result = verify_bundle(path, fingerprint(vault.public_key))
        assert result["report_seal"]["language"] == "ru" and result["report_seal"]["case"]["id"] == "PD-2026-0142"
        assert result["sha256sums"] == len(manifest["files"]) - 1
    finally:
        path.unlink()


def test_a_report_handed_over_alone_is_verifiable_and_tamper_evident(journal, tmp_path):
    _, vault = journal
    archive_path = evidence(journal, "en")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            data = archive.read("report.html")
        page = tmp_path / "report.html"
        page.write_bytes(data)
        pin = fingerprint(vault.public_key)
        result = verify_report(page, pin, archive_path)
        assert result["evidence_checked"] and result["report_seal"]["subject"]["event_count"] == 6
        with pytest.raises(ValueError, match="trusted fingerprint"):
            verify_report(page, "0" * 64)
        page.write_bytes(data.replace(b"Fake exchange support", b"Real exchange support", 1))
        with pytest.raises(ValueError, match="changed after it was sealed"):
            verify_report(page, pin)
        page.write_bytes(data + b"<script>alert(1)</script>")
        with pytest.raises(ValueError, match="not at the end"):
            verify_report(page, pin)
        page.write_bytes(data[:data.rindex(SEAL_OPEN)] + b"</body></html>\n")
        with pytest.raises(ValueError, match="no seal"):
            verify_report(page, pin)
    finally:
        archive_path.unlink()


def test_a_standalone_html_export_matches_a_later_archive_as_a_prefix(journal, tmp_path):
    store, vault = journal
    journal_with_messages(store)
    html_path = export_file(store, vault, "html")
    store.append("message.new", {"text": "later"}, CHAT, 5)
    archive_path = export_file(store, vault, "zip")
    try:
        sealed = read_sealed(html_path.open("rb"))
        assert sealed and sealed[1]["statement"]["subject"]["event_count"] == 6
        assert verify_report(html_path, fingerprint(vault.public_key), archive_path)["evidence_checked"]
    finally:
        html_path.unlink()
        archive_path.unlink()


@pytest.mark.parametrize("later_event", (False, True))
def test_empty_report_is_a_valid_signed_journal_prefix(journal, later_event):
    store, vault = journal
    page = export_file(store, vault, "html")
    if later_event:
        store.append("message.new", {"text": "later"}, CHAT, 1)
    bundle = export_file(store, vault, "zip")
    try:
        result = verify_report(page, fingerprint(vault.public_key), bundle)
        assert result["evidence_checked"]
        assert result["report_seal"]["subject"]["event_count"] == 0
    finally:
        page.unlink()
        bundle.unlink()


def test_chat_report_is_chronological_sealed_and_bound_to_chat_json(journal):
    store, vault = journal
    scratch = store.root / "scratch.jsonl"
    rows = [{"id": i, "type": "message", "date": "2026-01-0%dT10:00:00+00:00" % i, "from": "Alice", "from_id": 11,
             "text": "message " + str(i), "reply_to_message_id": i - 1 if i > 1 else None} for i in (3, 2, 1)]
    scratch.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    out = chat_export.build_bundle(scratch, {"chat": {"id": CHAT, "title": "Harbor"}, "message_count": 3}, vault,
                                   store.root / "chat.zip", options={**report.resolved(None, "uk"), **CASE})
    with zipfile.ZipFile(out) as archive:
        page = archive.read("chat.html").decode("utf-8")
        assert {"custody.json", "SHA256SUMS"} <= set(archive.namelist())
    assert page.index('id="m1"') < page.index('id="m2"') < page.index('id="m3"')  # oldest first
    assert 'href="#m1"><b>Alice</b>message 1' in page and '<html lang="uk"' in page
    result = verify_chat_export(out, fingerprint(vault.public_key))
    assert result["report_seal"]["subject"]["chat_json_sha256"] == result["chat_json_sha256"]


@pytest.mark.parametrize("field,value", [("case_title", "Case\u202egnp.exe"), ("case_id", "PD\n1"),
                                         ("examiner", "a\x00b"), ("language", "xx")])
def test_report_options_refuse_hidden_characters_and_unknown_languages(field, value):
    with pytest.raises(ValueError):
        report.ReportOptions(**{field: value})
    assert report.ReportOptions(notes="line one\r\nline two").notes == "line one\nline two"


def test_every_report_text_is_translated_into_every_panel_language():
    keys = report.text_keys()
    assert len(keys) > 200
    for lang in i18n.LANGUAGES:
        if lang != "en":
            missing = set(keys) - set(i18n.words(lang))
            assert not missing, (lang, sorted(missing)[:3])


def test_report_settings_are_saved_per_workspace_and_used_by_exports(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert c.get("/api/report-options").json()["language"] == "auto"
        assert c.post("/api/report-options", json={"case_title": "x\u202ey"}).status_code == 422
        saved = c.post("/api/report-options", json={**CASE, "language": "de", "theme": "dark"}).json()
        assert saved["language"] == "de" and saved["case_id"] == "PD-2026-0142"
        page = c.get("/api/export/html").text
    assert '<html lang="de" dir="ltr" data-theme="dark"' in page and "PD-2026-0142" in page


def test_report_language_follows_the_panel_when_set_to_auto(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        c.cookies.set(i18n.COOKIE, "ar")
        page = c.get("/api/export/html").text
    assert '<html lang="ar" dir="rtl"' in page


def test_verifier_answers_scripts_in_json_and_people_in_colour(journal):
    path = evidence(journal)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    try:
        answer = subprocess.run([sys.executable, VERIFIER, str(path), "--json"], capture_output=True, text=True,
                                encoding="utf-8", env=env)
        assert answer.returncode == 0 and json.loads(answer.stdout)["verified"] is True
        shown = subprocess.run([sys.executable, VERIFIER, str(path), "--pretty", "--no-color", "--lang", "ru"],
                               capture_output=True, text=True, encoding="utf-8", env=env)
        assert shown.returncode == 0, shown.stderr
        assert "ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА" in shown.stdout and "Печать отчёта" in shown.stdout
        assert "PD-2026-0142" in shown.stdout and "\033[" not in shown.stdout
        with zipfile.ZipFile(path) as archive:
            report_path = path.with_name("report-" + path.stem + ".html")
            report_path.write_bytes(archive.read("report.html").replace(b"Analyst", b"Someone", 1))
        failed = subprocess.run([sys.executable, VERIFIER, str(report_path), "--pretty", "--no-color", "--lang", "en"],
                                capture_output=True, text=True, encoding="utf-8", env=env)
        assert failed.returncode == 1 and "VERIFICATION FAILED" in failed.stdout
        report_path.unlink()
    finally:
        path.unlink()
