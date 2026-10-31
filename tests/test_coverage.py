import json
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tgwitness.evidence import export_file
from tgwitness.verify import Coverage, coverage_lines, verify_bundle, verify_chat_export

START = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
CHANNEL, GROUP = -1000000000123, -4001


def at(minutes, seconds=0):
    return (START + timedelta(minutes=minutes, seconds=seconds)).isoformat(timespec="milliseconds")


def record(minutes, kind, payload=None, chat_id=None, message_id=None, seconds=0):
    return {"observed_at": at(minutes, seconds), "kind": kind, "payload": payload or {}, "chat_id": chat_id,
            "message_id": message_id}


def test_continuity_gaps_and_unobserved_ids():
    events = [record(0, "process.started"), record(0, "observation.started", seconds=1)]
    events += [record(m, "collector.heartbeat") for m in range(1, 5)]
    events += [record(2, "message.new", chat_id=CHANNEL, message_id=i) for i in (1, 2, 5, 9)]
    events += [record(3, "message.new", chat_id=GROUP, message_id=i) for i in (100, 250)]
    events += [record(5, "coverage.gap", {"reason": "transport_disconnected"}),
               record(6, "connection.restored", {"reason": "transport_connected"}),
               record(7, "collector.heartbeat"),
               record(20, "collector.heartbeat"),
               record(21, "observation.stopped", {"reason": "operator"}),
               record(30, "observation.started"),
               record(30, "coverage.gap", {"reason": "Telegram reported channel updates requiring difference recovery"},
                      chat_id=CHANNEL),
               record(40, "process.started")]
    events.sort(key=lambda e: e["observed_at"])
    coverage = Coverage()
    for event in events:
        coverage.add(event)
    result = coverage.result()
    assert [(p["from"], p["to"]) for p in result["continuous"]] == [
        (at(0, 1), at(5)), (at(6), at(7)), (at(20), at(21)), (at(30), at(30))]
    reasons = [(g["from"], g["to"], g["reason"]) for g in result["gaps"]]
    assert reasons[0] == (at(5), at(6), "connection to Telegram lost")
    assert reasons[1][:2] == (at(7), at(20)) and reasons[1][2].startswith("no records for 13 min")
    assert reasons[2] == (at(21), at(30), "observation paused by the operator")
    assert reasons[3] == (at(30), at(40), "collector process ended without an orderly stop")
    assert result["gaps"][3]["not_resumed_by_last_record"] is True
    assert result["notes"][0]["chat_id"] == CHANNEL
    ids = result["unobserved_ids"]
    assert [c["chat_id"] for c in ids] == [CHANNEL]
    assert ids[0]["not_observed"] == 5 and ids[0]["ranges"] == [{"low": 3, "high": 4}, {"low": 6, "high": 8}]
    lines = coverage_lines(result)
    assert lines[0].startswith("Continuously observed from " + at(0, 1))
    assert any("5 ID(s) not observed in 2 range(s) (not evidence of deletion)" in line for line in lines)


def test_exports_carry_coverage_and_a_signed_producer(journal, tmp_path):
    store, vault = journal
    store.append("observation.started", {})
    for i in (1, 2, 4):
        store.append("message.new", {"text": str(i)}, CHANNEL, i)
    store.append("target.changed", {"title": "Harbor", "enabled": True}, CHANNEL)
    path = export_file(store, vault, "zip")
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            report = archive.read("report.html").decode()
            stored = json.loads(archive.read("coverage.json"))
        assert manifest["producer"]["software"] == "TgWitness" and manifest["producer"]["project"] == "PhishDestroy"
        assert "coverage.json" in manifest["files"]
        assert "PhishDestroy" in report and "Continuously observed from" in report
        assert "Chat Harbor: IDs 1-4, 1 ID(s) not observed" in report
        result = verify_bundle(path)
        assert result["producer"] == manifest["producer"] and result["coverage"]["unobserved_ids"] == stored["unobserved_ids"]
        shown = subprocess.run([sys.executable, str(Path("tgwitness") / "verify.py"), str(path)], capture_output=True,
                               text=True, errors="replace", check=True).stdout
        assert shown.startswith("TgWitness verifier - PhishDestroy")
        assert "Producer (signed): TgWitness" in shown and "still observing at the last record" in shown
    finally:
        path.unlink()


def test_chat_exports_name_their_producer(tmp_path, journal):
    from tgwitness.chat_export import build_bundle
    store, vault = journal
    scratch = tmp_path / "chat.jsonl"
    scratch.write_text(json.dumps({"id": 1, "type": "message", "text": "hi", "from_id": 7}) + "\n", encoding="utf-8")
    out = build_bundle(scratch, {"chat": {"id": CHANNEL, "title": "Harbor"}, "message_count": 1}, vault, tmp_path / "c.zip")
    assert verify_chat_export(out)["producer"]["homepage"] == "https://phishdestroy.io"
