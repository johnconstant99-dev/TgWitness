"""Capture stops and liveness are derived from collection, not administrative writes."""
import asyncio
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.verify import Coverage, fingerprint, verify_bundle
from tgwitness.evidence import export_file
from tools.browser_fixtures import saved_session
from tools.check_session_reservations import workspace


def event(kind, seconds, **payload):
    return {"kind": kind, "chat_id": None, "message_id": None, "payload": payload,
            "observed_at": f"2026-11-06T00:{seconds // 60:02}:{seconds % 60:02}+00:00"}


def test_worker_failure_closes_signed_capture_before_cleanup(tmp_path):
    async def run():
        async with workspace() as (app, _):
            collector, store, vault = app.state.collector, app.state.store, app.state.vault
            await collector.configure(123, "a" * 32, saved_session())
            collector.running, collector.phase = True, "observing"
            with patch("tgwitness.store.utcnow", return_value=event("", 0)["observed_at"]):
                store.append("observation.started", {})
            with patch("tgwitness.store.utcnow", return_value=event("", 60)["observed_at"]):
                store.append("collector.heartbeat", {"connected": True})
            async def failed():
                raise RuntimeError("Synthetic worker failure")
            with patch("tgwitness.store.utcnow", return_value=event("", 70)["observed_at"]):
                await collector.supervise(failed, "media worker")
            assert not collector.running and collector.phase == "collector_error"
            assert store.events(kind="observation.stopped")[0]["payload"]["reason"] == "collector_error"
            for minute in range(2, 12):
                with patch("tgwitness.store.utcnow", return_value=event("", minute * 60)["observed_at"]):
                    store.append("parameters.changed", {"after": {"heartbeat_seconds": 60}})
            archive = export_file(store, vault, "zip")
            result = verify_bundle(archive, expected_fingerprint=fingerprint(vault.public_key))
            coverage = result["coverage"]
            assert result["key_pinned"]
            assert coverage["continuous"][-1]["to"] == event("", 60)["observed_at"]
            assert not any(p.get("still_observing") for p in coverage["continuous"])
            assert coverage["gaps"][-1]["not_resumed_by_last_record"]
    asyncio.run(run())


@pytest.mark.parametrize("kind", ["parameters.changed", "message.snapshot", "media.downloaded", "checkpoint.created"])
def test_administrative_and_backfill_records_do_not_keep_capture_alive(kind):
    coverage = Coverage()
    for record in [event("observation.started", 0), event("collector.heartbeat", 60, connected=True),
                   *[event(kind, n * 60) for n in range(2, 12)]]:
        coverage.add(record)
    result = coverage.result()
    assert result["continuous"][-1]["to"] == event("", 60)["observed_at"]
    assert result["gaps"][-1]["not_resumed_by_last_record"]
    coverage.add(event("collector.heartbeat", 720, connected=True))
    assert coverage.result()["continuous"][-1]["from"] == event("", 720)["observed_at"]


def test_current_disconnect_closes_legacy_capture_but_candidate_disconnect_does_not():
    coverage = Coverage()
    coverage.add(event("observation.started", 0))
    coverage.add(event("connection.closed", 10, role="candidate"))
    assert coverage.observing
    coverage.add(event("connection.closed", 20, role="current"))
    assert not coverage.observing
    coverage.add(event("parameters.changed", 30))
    assert not coverage.observing
    coverage.add(event("collector.heartbeat", 40, connected=True))
    assert coverage.observing and coverage.result()["gaps"][0]["to"] == event("", 40)["observed_at"]


def test_explicit_stop_is_not_resumed_by_stray_heartbeat_or_disconnect():
    coverage = Coverage()
    for record in [event("observation.started", 0), event("observation.stopped", 10, reason="operator"),
                   event("connection.closed", 20, role="current"), event("collector.heartbeat", 30, connected=True)]:
        coverage.add(record)
    assert not coverage.observing


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
