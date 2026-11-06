"""Regression cases for claims made after cryptographic verification succeeds."""
import asyncio
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.collector import Collector
from tgwitness.evidence import export_file
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import Coverage, compare_chat_exports, fingerprint, verify_bundle, verify_chat_export


def stamp(seconds):
    return (datetime(2026, 11, 6, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat()


def event(seconds, kind, **payload):
    return dict(observed_at=stamp(seconds), kind=kind, payload=payload, chat_id=None, message_id=None)


def coverage(*events):
    found = Coverage()
    for item in events:
        found.add(item)
    return found.result()


START = event(0, "observation.started", run_id="run-a")
BEAT = event(60, "collector.heartbeat", connected=True, run_id="run-a", interval_seconds=60)


@pytest.mark.parametrize("kind,payload", [
    ("collector.error", {"error_type": "RuntimeError"}),
    ("connection.closed", {"role": "current"}),
    ("collector.heartbeat", {"connected": False, "run_id": "run-a"}),
])
def test_capture_failures_do_not_remain_continuous(kind, payload):
    found = coverage(START, BEAT, event(70, kind, **payload), *[
        event(70 + minute * 60, "parameters.changed", after={"heartbeat_seconds": 60})
        for minute in range(1, 11)])
    assert not any(p.get("still_observing") for p in found["continuous"])
    assert found["continuous"][-1]["to"] <= stamp(70)
    assert found["gaps"][-1]["to"] == stamp(670)


@pytest.mark.parametrize("kind,payload", [
    ("parameters.changed", {}), ("message.snapshot", {"source": "history_snapshot"}),
    ("host.state", {}), ("media.saved", {}),
    ("collector.heartbeat", {"connected": True, "run_id": "another-run"}),
])
def test_only_capture_liveness_can_extend_or_resume_observation(kind, payload):
    found = coverage(START, BEAT, *[event(t, kind, **payload) for t in range(120, 601, 60)])
    assert found["continuous"] == [{"from": stamp(0), "to": stamp(60), "seconds": 60}]
    assert found["gaps"][-1]["to"] == stamp(600)


@pytest.mark.parametrize("stop", ["observation.stopped", "process.stopped", "process.started"])
def test_late_connection_and_heartbeat_cannot_undo_a_stop(stop):
    found = coverage(START, BEAT, event(70, "coverage.gap", reason="transport_disconnected"),
                     event(80, stop, reason="operator"), event(90, "connection.restored"),
                     event(100, "collector.heartbeat", connected=True, run_id="run-a"))
    assert len(found["continuous"]) == 1
    assert found["gaps"][-1]["not_resumed_by_last_record"]


def test_confirmed_recovery_and_explicit_restart_can_resume():
    found = coverage(START, BEAT, event(70, "coverage.gap", reason="transport_disconnected"),
                     event(80, "connection.restored"),
                     event(90, "collector.heartbeat", connected=True, run_id="run-a"),
                     event(100, "observation.stopped"),
                     event(110, "observation.started", run_id="run-b"),
                     event(120, "collector.heartbeat", connected=True, run_id="run-b"))
    assert [(p["from"], p["to"]) for p in found["continuous"]] == [
        (stamp(0), stamp(70)), (stamp(90), stamp(100)), (stamp(110), stamp(120))]
    assert found["continuous"][-1]["still_observing"]


def test_nonfatal_error_records_uncertainty_until_the_next_capture_heartbeat():
    found = coverage(START, BEAT, event(70, "collector.error", error_type="ValueError"),
                     event(80, "parameters.changed"),
                     event(120, "collector.heartbeat", connected=True, run_id="run-a"))
    assert found["gaps"][0]["from"] == stamp(60)
    assert found["gaps"][0]["to"] == stamp(120)
    assert found["continuous"][-1]["still_observing"]


def test_candidate_connection_close_does_not_stop_current_capture():
    found = coverage(START, BEAT, event(70, "connection.closed", role="candidate"),
                     event(120, "collector.heartbeat", connected=True, run_id="run-a"))
    assert not found["gaps"] and found["continuous"][0]["seconds"] == 120


@pytest.mark.parametrize("storage_failure", [False, True, "stop_only"])
@pytest.mark.parametrize("export_active", [False, True])
def test_real_supervisor_failure_and_signed_bundle(tmp_path, storage_failure, export_active):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = Collector(store, vault)
        collector.running, collector.phase, collector.run_id = True, "observing", "run-a"
        collector.client = SimpleNamespace(disconnect=AsyncMock())
        collector.cancel_workers = AsyncMock()
        collector.avatar_history.close = AsyncMock()
        collector.export_claim = "export" if export_active else None
        try:
            for item in (START, BEAT):
                with patch("tgwitness.store.utcnow", return_value=item["observed_at"]):
                    store.append(item["kind"], item["payload"])

            async def crash():
                raise RuntimeError("synthetic worker failure")

            with patch("tgwitness.store.utcnow", return_value=stamp(70)):
                if storage_failure:
                    append = store.append

                    def failing_write(kind, payload):
                        if storage_failure == "stop_only" and kind != "observation.stopped":
                            return append(kind, payload)
                        raise OSError("synthetic full disk")

                    with patch.object(store, "append", side_effect=failing_write):
                        await collector.supervise(crash, "synthetic worker")
                else:
                    await collector.supervise(crash, "synthetic worker")
            assert not collector.running
            assert collector.phase == ("storage_error" if storage_failure else "collector_error")
            collector.cancel_workers.assert_awaited()
            assert collector.client.disconnect.await_count == (not export_active)
            if not storage_failure:
                stops = store.events(kind="observation.stopped")
                assert len(stops) == 1 and stops[0]["payload"]["reason"] == "collector_error"
            for minute in range(1, 11):
                with patch("tgwitness.store.utcnow", return_value=stamp(70 + minute * 60)):
                    store.append("parameters.changed", {"after": {"heartbeat_seconds": 60}})
            bundle = export_file(store, vault, "zip", compact=True, include_board=False)
            checked = verify_bundle(bundle, expected_fingerprint=fingerprint(vault.public_key))
            assert checked["key_pinned"]
            found = checked["coverage"]
            assert found["continuous"][-1]["to"] <= stamp(70)
            assert not found["continuous"][-1].get("still_observing")
            assert found["gaps"][-1]["to"] == stamp(670)
        finally:
            store.close()
    asyncio.run(scenario())


def signed_chat(path, vault, rows, account=1, chat=42):
    """Small real signed archive; comparison still runs the complete verifier."""
    contents = ('{\n "messages": [\n' + ',\n'.join(json.dumps(row) for row in rows) + '\n]}').encode()
    manifest = {"format": "tgwitness-chat-export-v1", "public_key": vault.public_key,
                "chat": {"id": chat}, "account": {"id": account}, "message_count": len(rows),
                "files": {"chat.json": hashlib.sha256(contents).hexdigest()}}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("chat.json", contents)
        archive.writestr("manifest.json", canonical(manifest))
        archive.writestr("manifest.sig", vault.sign(canonical(manifest)))
    return path


@pytest.mark.parametrize("account", [1, 2])
@pytest.mark.parametrize("change", ["text_tail", "entities", "caption", "reply", "sender"])
def test_comparison_does_not_confuse_matching_with_equal_content(tmp_path, account, change):
    vault = Vault(tmp_path)
    row = {"id": 1, "type": "message", "from_id": "user1", "date": stamp(0), "text": "x" * 300 + "A"}
    other = dict(row)
    if change == "text_tail":
        other["text"] = "x" * 300 + "B"
    elif change == "entities":
        row["text_entities"] = [{"type": "text_link", "text": row["text"], "href": "https://one.invalid"}]
        other["text_entities"] = [{"type": "text_link", "text": row["text"], "href": "https://two.invalid"}]
    elif change == "caption":
        row["file_sha256"] = other["file_sha256"] = hashlib.sha256(b"same file").hexdigest()
        other["text"] = "Different caption"
        # No media bytes are claimed as preserved by these snapshots.
        row["file_status"] = other["file_status"] = "not_downloaded"
    elif change == "reply":
        row["reply_to_message_id"], other["reply_to_message_id"] = 4, 5
    else:
        other["from_id"] = "user2"
    first = signed_chat(tmp_path / "first.zip", vault, [row])
    second = signed_chat(tmp_path / "second.zip", vault, [other], account=account)
    checked = compare_chat_exports(first, second, fingerprint(vault.public_key), fingerprint(vault.public_key))
    assert checked["first"]["key_pinned"] and checked["second"]["key_pinned"]
    assert checked["unchanged"] == 0


def test_candidate_matches_compare_record_ids_and_timestamps(tmp_path):
    vault = Vault(tmp_path)
    row = {"id": 1, "type": "message", "from_id": "user1", "date": stamp(0), "text": "x" * 400}
    other = dict(row, id=99, date=stamp(1))
    first = signed_chat(tmp_path / "first.zip", vault, [row])
    second = signed_chat(tmp_path / "second.zip", vault, [other], account=2)
    result = compare_chat_exports(first, second)
    assert result["unchanged"] == 0 and len(result["changed"]) == 1
    assert result["changed"][0]["changed_fields"] == ["date", "id"]


@pytest.mark.parametrize("change", ["compact", "count", "duplicate", "invalid_row", "trailing_comma", "tail"])
def test_signed_chat_cannot_silently_skip_records(tmp_path, change):
    vault = Vault(tmp_path)
    row = {"id": 1, "type": "message", "date": stamp(0), "text": "Observed"}
    path = signed_chat(tmp_path / "original.zip", vault, [row, row] if change == "duplicate" else [row])
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        contents = archive.read("chat.json")
    if change == "compact":
        contents = canonical(json.loads(contents))
    elif change == "count":
        manifest["message_count"] += 1
    elif change == "invalid_row":
        contents = contents.replace(b'\n]}', b',\n42\n]}')
    elif change == "trailing_comma":
        contents = contents.replace(b'\n]}', b',\n]}')
    elif change == "tail":
        contents += b'\n{"ignored": true}'
    manifest["files"]["chat.json"] = hashlib.sha256(contents).hexdigest()
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("chat.json", contents)
        archive.writestr("manifest.json", canonical(manifest))
        archive.writestr("manifest.sig", vault.sign(canonical(manifest)))
    with pytest.raises(ValueError):
        verify_chat_export(path, fingerprint(vault.public_key))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
