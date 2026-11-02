"""The two approved compositions share real, signed report data, not demo fixtures."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import chat_export, evidence, handover, pdf_report, report, report_composition_pdf, report_layouts
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, verify_bundle, verify_report


DESIGNS = ("reading_series", "ledger_margin")


def capture_documents(monkeypatch):
    documents = []
    factory = pdf_report.document

    def capture(*args, **kwargs):
        pdf = factory(*args, **kwargs)
        pdf.reading_lines = []
        original = pdf.multi_cell

        def text(w=None, h=None, text="", *args, **kwargs):
            if not kwargs.get("dry_run"):
                pdf.reading_lines.append(str(text))
            return original(w, h, text, *args, **kwargs)

        pdf.multi_cell = text
        documents.append(pdf)
        return pdf

    monkeypatch.setattr(pdf_report, "document", capture)
    return documents


def seed(store):
    at = "2026-10-12T10:00:00Z"
    hidden = {"_": "Message", "message": "PRIVATE_RAW_BODY", "reply_to": {"quote_text": "PRIVATE_RAW_QUOTE"}}
    with patch("tgwitness.store.utcnow", return_value=at):
        store.append("message.new", {"text": "Before: the complete original instruction.", "sender_id": 11,
                     "sent_at": at, "sender_observation": {"id": 11, "display_name": "Permitted alias"},
                     "details": {}, "raw": hidden}, -1001, 1, 11)
        store.append("message.edited", {"text": "After: the complete revised instruction.", "sender_id": 11,
                     "sent_at": at, "edited_at": at, "details": {"reply_to_message_id": 7, "reply_to_top_id": 3},
                     "raw": hidden}, -1001, 1, 11)
        store.append("message.deleted", {}, -1001, 1)
        store.append("message.new", {"text": "EXCLUDED_OTHER_CHAT", "sender_id": 22}, -1002, 1, 22)


@pytest.mark.parametrize("design", DESIGNS)
def test_signed_selected_pdf_preserves_subject_full_changes_and_private_boundaries(tmp_path, monkeypatch, design):
    documents = capture_documents(monkeypatch)
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        seed(store)
        options = report.ReportOptions(design=design, case_title="Fictional instruction review",
                     review_question="Which saved instruction changed?",
                     selection={"enabled": True, "chats": [-1001]}).model_dump() | {"language": "en"}
        archive = evidence.export_file(store, vault, "zip", options)
        pin = fingerprint(vault.public_key)
        assert verify_bundle(archive, pin)["report_pdf"]
        with zipfile.ZipFile(archive) as source:
            data = json.loads(source.read("report.json"))["report"]
            pdf_bytes = source.read("report.pdf")
            assert data["presentation"]["design"] == design
            assert ("report design: " + design).encode() in pdf_bytes
            source_hash = hashlib.sha256(source.read("events.jsonl")).hexdigest()
        path = tmp_path / (design + ".pdf")
        path.write_bytes(pdf_bytes)
        checked = verify_report(path, pin, archive)
        assert checked["evidence_checked"] and checked["pdf_signature"]
        assert checked["report_seal"]["subject"]["events_sha256"] == source_hash
        assert checked["report_seal"]["subject"]["event_count"] == 4
        pdf = documents[-1]
        text = "\n".join(pdf.reading_lines)
        assert "Before: the complete original instruction." in text
        assert "After: the complete revised instruction." in text
        assert "Saved text before deletion" in text
        assert "PRIVATE_RAW" not in text and "EXCLUDED_OTHER_CHAT" not in text
        assert "Permitted alias" in text and "Reply thread: #3" in text
        chapters = [entry.name.split(". ", 1)[-1] for entry in pdf._outline if entry.level == 1]
        plan = [chapter.title for chapter in report_layouts.chapter_plan(design)]
        actual = [title for title in chapters if title in plan]
        assert actual == [title for title in plan if title in actual]
        assert len(actual) >= 8 and "Operator actions" not in chapters
        if design == "reading_series":
            assert chapters.index("Observation journal") < chapters.index("Custody, integrity & verification")
            assert pdf.l_margin == 20
        else:
            assert chapters.index("Observation journal") > chapters.index("Provenance, custody & integrity")
            assert pdf.l_margin == 46
    finally:
        store.close()


@pytest.mark.parametrize("design", DESIGNS)
def test_chat_export_uses_native_design_and_keeps_snapshot_semantics(tmp_path, monkeypatch, design):
    documents = capture_documents(monkeypatch)
    vault = Vault(tmp_path)
    messages = [{"id": 1, "type": "message", "date": "2026-10-12T10:00:00Z", "from_id": 11,
                 "from": "Fictional sender", "text": "Current snapshot text.", "edited": "2026-10-12T11:00:00Z",
                 "reply_to_message_id": 7, "reply_to_top_id": 3}]
    scratch = tmp_path / "messages.jsonl"
    scratch.write_bytes(b"\n".join(canonical(row) for row in messages))
    archive = tmp_path / (design + ".zip")
    options = report.ReportOptions(design=design, case_title="Fictional snapshot").model_dump() | {"language": "en"}
    chat_export.build_bundle(scratch, {"chat": {"id": -1001, "title": "Fictional group", "kind": "supergroup"},
                                      "message_count": 1}, vault, archive, options=options)
    with zipfile.ZipFile(archive) as source:
        path = tmp_path / "chat.pdf"
        path.write_bytes(source.read("chat.pdf"))
        assert ("report design: " + design).encode() in path.read_bytes()
        expected = hashlib.sha256(source.read("chat.json")).hexdigest()
    checked = verify_report(path, fingerprint(vault.public_key), archive)
    assert checked["evidence_checked"] and checked["pdf_signature"]
    assert checked["report_seal"]["subject"]["chat_json_sha256"] == expected
    text = "\n".join(documents[-1].reading_lines)
    assert "Current snapshot text." in text
    assert "A history snapshot holds only the current text" in text
    assert "Reply thread: #3" in text
    assert any("Message transcript" in entry.name for entry in documents[-1]._outline)


def test_bounded_directory_replays_every_event_without_hidden_metadata():
    events = [{"seq": number, "kind": "message.new", "chat_id": -1001, "message_id": number,
               "payload": {"text": "Permitted", "sender_id": 11, "details": {},
                           "raw": {"reply_to": {"quote_text": "PRIVATE_RAW"}}}} for number in range(1, 704)]
    before = deepcopy(events)
    restored, index = report_composition_pdf.indexed_events(iter(events), len(events))
    assert index["limited"] and index["records_examined"] == 500
    assert index["relations"] == [] and "PRIVATE_RAW" not in json.dumps(index)
    assert list(restored) == before and events == before


@pytest.mark.parametrize("design", DESIGNS)
def test_minimised_handover_never_restores_original_content_or_operator_analysis(tmp_path, monkeypatch, design):
    documents = capture_documents(monkeypatch)
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        seed(store)
        options = report.ReportOptions(design=design, review_findings="PRIVATE_OPERATOR_FINDING").model_dump() | {"language": "en"}
        minimisation = handover.Options(chats=[-1001], purpose="Fictional sharing test", others="pseudonymize",
                                        text="none", attachments="none")
        archive, _ = handover.export(store, vault, minimisation, options)
        with zipfile.ZipFile(archive) as source:
            path = tmp_path / "handover.pdf"
            path.write_bytes(source.read("report.pdf"))
        assert verify_report(path, fingerprint(vault.public_key), archive)["evidence_checked"]
        text = "\n".join(documents[-1].reading_lines)
        assert "Text withheld in this extract" in text
        for hidden in ("Before: the complete original instruction.", "After: the complete revised instruction.",
                       "Permitted alias", "PRIVATE_RAW", "PRIVATE_OPERATOR_FINDING", "EXCLUDED_OTHER_CHAT"):
            assert hidden not in text
    finally:
        store.close()


@pytest.mark.parametrize("design", DESIGNS)
def test_complete_long_comparisons_flow_in_native_pdf(tmp_path, monkeypatch, design):
    documents = capture_documents(monkeypatch)
    say = report.Words("en")
    pdf = pdf_report.document(say, "Fictional comparison", design)
    lay = pdf_report.Layout(pdf, say)
    lay.title_block("Evidence report", "Complete long comparison", [], "Synthetic test.")
    lay.section("Preserved versions")
    before, after = "before " * 1700, "after " * 1700
    report_composition_pdf.comparison(lay, before, after)
    if design == "ledger_margin":
        lay.diff(before, after)
    raw = bytes(pdf.output())
    assert raw.startswith(b"%PDF-") and len(pdf.pages) > 2
    assert before in documents[-1].reading_lines and after in documents[-1].reading_lines
    assert pdf.get_y() < pdf.h


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
