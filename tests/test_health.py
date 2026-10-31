"""States of each part kept apart from its switch: off, configured, running, working, degraded,
failed and unknown; missing or stale data is never reported as success."""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tgwitness import access, alerts, anchoring, health, replica
from tgwitness.app import create_app
from tgwitness.evidence import retain_checkpoint
from tgwitness.network import NetworkConfig
from tgwitness.verify import OTS_PENDING
from test_access import issue, login
from test_collector import FakeClient
from test_replica import configure, fake_s3

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
OTS_ANSWER = b"\xf0\x10" + bytes(range(16)) + b"\x08\x00" + OTS_PENDING + b"\x1b\x1ahttps://cal.example/digest"
EVIDENCE = {"enabled": True, "interval_minutes": 10, "tsa_urls": ["https://tsa.example/tsr"],
            "ots_calendars": ["https://cal.example"]}


def ago(**delta):
    return (NOW - timedelta(**delta)).isoformat(timespec="milliseconds")


def attempt(*results, at=None, covered=()):
    return {"at": at or ago(minutes=1), "checkpoint": {"event_count": 5}, "results": list(results),
            "covered": list(covered)}


TSA_OK = {"service": "https://tsa.example/tsr", "kind": "rfc3161", "ok": True, "time": "2026-10-31T11:59:00Z"}
TSA_DOWN = {"service": "https://tsa.example/tsr", "kind": "rfc3161", "ok": False, "received": False, "error": "OSError"}
TSA_BAD = {"service": "https://tsa.example/tsr", "kind": "rfc3161", "ok": False, "received": True,
           "error": "The timestamp certificate does not chain to a trusted root"}
OTS_OK = {"service": "https://cal.example", "kind": "opentimestamps", "ok": True, "status": "pending"}
OTS_DOWN = {"service": "https://cal.example", "kind": "opentimestamps", "ok": False, "received": False,
            "error": "HTTP 500"}


def stamps(last=None, runtime=None, settings=None, route=None, success=None, failure=None):
    return health.timestamps({**EVIDENCE, **(settings or {})}, last, success, failure, runtime or {}, route, NOW)


def test_timestamps_switched_on_is_not_success():
    assert stamps(settings={"enabled": False})["state"] == "off"
    first = stamps()
    assert (first["state"], first["reason"]) == ("configured", "first_pending")
    assert stamps(runtime={"busy": True})["state"] == "running"
    blocked = stamps(route="Requests outside Telegram are switched off")
    assert (blocked["state"], blocked["reason"]) == ("failed", "route")
    crashed = stamps(runtime={"error": "KeyError", "last_pass_at": ago(minutes=1)})
    assert (crashed["state"], crashed["reason"], crashed["error"]) == ("failed", "loop_error", "KeyError")


def test_timestamps_tell_verified_answers_from_rejected_pending_and_missing_ones():
    working = stamps(attempt(TSA_OK, OTS_OK))
    assert (working["state"], working["reason"]) == ("working", "stamped")
    assert working["counts"]["verified"] == 1 and working["counts"]["ots_pending"] == 1
    partial = stamps(attempt(TSA_OK, OTS_DOWN))
    assert (partial["state"], partial["reason"]) == ("degraded", "partial")
    nothing = stamps(attempt(TSA_BAD, OTS_DOWN))
    assert (nothing["state"], nothing["reason"]) == ("failed", "no_answer")
    assert nothing["counts"]["rejected"] == 1 and nothing["counts"]["unreachable"] == 1  # answered but refused
    pending_only = stamps(attempt(TSA_DOWN, OTS_OK))
    assert pending_only["state"] == "degraded"
    only_ots = stamps(attempt(OTS_OK), settings={"tsa_urls": []})
    assert (only_ots["state"], only_ots["reason"]) == ("working", "stamped")
    unverified = stamps(attempt(OTS_OK), settings={"tsa_urls": ["https://tsa.example/tsr"]})
    assert (unverified["state"], unverified["reason"]) == ("degraded", "unverified")


def test_a_retry_for_an_already_stamped_checkpoint_is_partial_not_a_total_failure():
    retry = stamps(attempt(OTS_DOWN, covered=[{"service": TSA_OK["service"], "kind": "rfc3161"}]))
    assert (retry["state"], retry["reason"]) == ("degraded", "partial")
    assert retry["counts"]["covered_verified"] == 1


def test_timestamp_data_older_than_its_schedule_is_unknown():
    old = attempt(TSA_OK, OTS_OK, at=ago(minutes=24))  # interval 10 min: stale after 2 × 10 min + 3 min
    assert stamps(old)["state"] == "unknown"
    assert stamps(attempt(TSA_OK, OTS_OK, at=ago(minutes=22)))["state"] == "working"
    # A later pass that found the latest checkpoint already stamped keeps it current.
    current = stamps(old, runtime={"last_pass_at": ago(minutes=1), "outcome": "up_to_date"})
    assert (current["state"], current["reason"]) == ("working", "up_to_date")
    assert stamps(runtime={"last_pass_at": ago(minutes=1), "outcome": "no_checkpoint"})["reason"] == "no_checkpoint"


def test_anchoring_keeps_the_last_success_apart_from_later_failures(journal, monkeypatch):
    store, vault = journal
    calendars = ["https://cal-a.example", "https://cal-b.example", "https://cal-c.example"]
    answers = {calendars[0]: OTS_ANSWER, calendars[1]: b"not a proof"}

    async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
        base = url.rsplit("/", 1)[0]
        if base not in answers:
            raise OSError("unreachable")
        return answers[base]
    monkeypatch.setattr(anchoring, "post", post)
    settings = {"tsa_urls": [], "ots_calendars": calendars}
    store.append("test", {"n": 1})
    retain_checkpoint(store, vault)
    first = asyncio.run(anchoring.anchor_latest(store, NetworkConfig(kind="direct"), settings))
    by_service = {r["service"]: r for r in first["results"]}
    assert by_service[calendars[0]]["ok"]
    assert by_service[calendars[1]]["received"] and not by_service[calendars[2]]["received"]
    success = store.get_setting("evidence_success", None)
    assert success["checkpoint"] == first["checkpoint"] and success["verified_at"] is None  # no RFC 3161 token
    # The same checkpoint again: only the two failed calendars are asked, and fail again.
    second = asyncio.run(anchoring.anchor_latest(store, NetworkConfig(kind="direct"), settings))
    assert [r["service"] for r in second["results"]] == calendars[1:]
    assert second["covered"] == [{"service": calendars[0], "kind": "opentimestamps"}]
    assert store.get_setting("evidence_success", None) == success
    failure = store.get_setting("evidence_failure", None)
    assert [e["service"] for e in failure["errors"]] == calendars[1:]
    # Not "no service answered": cal-a's proof for this checkpoint is on disk.
    [_, latest] = store.events(kind="anchor.completed")[::-1]
    assert alerts.problem_line(latest, {}, {}) is None
    view = health.timestamps({**EVIDENCE, **settings}, store.get_setting("evidence_last", None), success, failure,
                             {}, None, datetime.now(timezone.utc))
    assert (view["state"], view["reason"]) == ("degraded", "partial")


def test_anchor_loop_reports_its_pass_and_next_attempt(journal, monkeypatch):
    store, vault = journal
    store.set_setting("evidence", {**EVIDENCE, "tsa_urls": [], "ots_calendars": ["https://cal.example"]})

    async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
        return OTS_ANSWER
    monkeypatch.setattr(anchoring, "post", post)
    retain_checkpoint(store, vault)

    async def run():
        status, wakeup = {"busy": False}, asyncio.Event()
        wakeup.set()
        task = asyncio.create_task(anchoring.anchor_loop(store, lambda: NetworkConfig(kind="direct"), wakeup, status))
        for _ in range(200):
            if status.get("last_pass_at"):
                break
            await asyncio.sleep(0.01)
        first = dict(status)
        wakeup.set()  # nothing new: the latest checkpoint is already stamped by every service
        for _ in range(200):
            if status.get("last_pass_at") != first["last_pass_at"] or status.get("outcome") == "up_to_date":
                break
            await asyncio.sleep(0.01)
        task.cancel()
        return first, dict(status)
    first, second = asyncio.run(run())
    assert first["outcome"] == "anchored" and not first["busy"] and first["next_at"] > first["last_pass_at"]
    assert second["outcome"] == "up_to_date"


def copy(last=None, runtime=None, success=None, route=None, head=50, enabled=True):
    settings = {**replica.ReplicaSettings().model_dump(), "enabled": enabled, "interval_minutes": 60}
    return health.replica(settings, last, success, runtime or {}, route, head, NOW)


def test_offsite_copy_states_lag_and_staleness():
    assert copy(enabled=False)["state"] == "off"
    assert copy()["reason"] == "first_pending"
    assert copy(runtime={"busy": True})["state"] == "running"
    done = {"at": ago(minutes=5), "journal_seq": 42, "error": None}
    working = copy(done, success={"at": ago(minutes=5), "journal_seq": 42})
    assert working["state"] == "working" and working["lag_records"] == 8 and working["journal_seq"] == 42
    assert working["lag_seconds"] == 300
    broken = copy({"at": ago(minutes=1), "journal_seq": 44, "error": "ConnectError"},
                  success={"at": ago(hours=2), "journal_seq": 30})
    assert (broken["state"], broken["reason"]) == ("failed", "error")
    assert broken["journal_seq"] == 44 and broken["last_success_at"] == ago(hours=2)  # boundary of the latest pass
    stale = copy({"at": ago(hours=3), "journal_seq": 42, "error": None})  # interval 60 min
    assert stale["state"] == "unknown"


def test_a_failed_copy_pass_does_not_hide_the_last_complete_one(journal):
    store, vault = journal

    async def run():
        server, endpoint, _, _ = await fake_s3()
        configure(store, vault, endpoint)
        store.append("message.new", {"text": "x"}, -100123, 1, 44)
        retain_checkpoint(store, vault)
        first = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        server.close()
        await server.wait_closed()
        store.append("message.new", {"text": "y"}, -100123, 2, 44)
        second = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        return first, second
    first, second = asyncio.run(run())
    assert first["error"] is None and second["error"]
    assert store.get_setting("replica_success", None) == {"at": first["at"], "journal_seq": first["journal_seq"]}
    assert store.get_setting("replica_last", None)["error"] == second["error"]


BASELINE = {"deployment": {"sha256": "ab"}, "ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 3}


def server(state, measured_at=None, provider=None, baseline=BASELINE):
    deployed = {"mode": "hetzner", "provider": provider or {"instance_id": 42}}
    return health.server(deployed, baseline, {"state": state, "measured_at": measured_at or ago(seconds=30)}, NOW)


def test_sealed_server_deployment_and_protection_checks_are_separate():
    plain = health.server(None, None, {}, NOW)
    assert plain["deployment"]["state"] == "off" and plain["checks"]["state"] == "off"
    quiet = server({"ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 3})
    assert quiet["deployment"]["state"] == "working" and quiet["checks"]["state"] == "working"
    sshd = server({"ssh_listening": False, "ssh_processes": 2, "sessions": 0, "logins": 3})
    assert sshd["deployment"]["state"] == "working"  # running here, but a condition needs attention
    assert (sshd["checks"]["state"], sshd["checks"]["reason"]) == ("degraded", "attention")
    items = {c["name"]: c for c in sshd["checks"]["items"]}
    assert items["ssh_processes"] == {"name": "ssh_processes", "value": 2, "result": "attention"}
    assert items["new_logins"]["result"] == "pass" and items["sessions"]["result"] == "pass"
    login_seen = server({"ssh_listening": True, "ssh_processes": 1, "sessions": 1, "logins": 5})
    assert {c["name"]: c["value"] for c in login_seen["checks"]["items"]}["new_logins"] == 2
    unreadable = server({"ssh_listening": False, "ssh_processes": 0, "sessions": None, "logins": None})
    assert unreadable["checks"]["state"] == "unknown"  # an unreadable utmp is not a clean one
    stale = server({"ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 3}, ago(minutes=10))
    assert stale["checks"]["state"] == "unknown" and {c["result"] for c in stale["checks"]["items"]} == {"unknown"}
    assert server({}, provider={"error": "URLError"})["deployment"]["reason"] == "provider_unavailable"
    assert server({}, baseline={**BASELINE, "deployment": None})["deployment"]["reason"] == "no_deployment_record"


def test_an_ssh_process_alone_is_not_reported_as_access():
    quiet = {"ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 0}
    process = alerts.host_line({"before": quiet, **{**quiet, "ssh_processes": 1}}, {})
    assert process == "SSH change on the server, no new login recorded: SSH server processes started"
    login = alerts.host_line({"before": quiet, **{**quiet, "ssh_processes": 1, "logins": 1}}, {})
    assert login.startswith("Server access detected: ")


COLLECTING = {"has_session": True, "running": True, "connected": True, "phase": "observing",
              "last_heartbeat": ago(seconds=20), "last_update_at": ago(days=3),
              "source_status": {"1": {"state": "visible_in_dialogs"}, "2": {"state": "visible_in_dialogs"}},
              "media_jobs": {"done": 4}, "scope": {"mode": "selected"}, "disk_free_bytes": 10 ** 10}


def parts(capture=None, sources=2, **changes):
    return health.collector({**COLLECTING, **changes}, capture or {"download_media": True}, 60, sources, NOW)


def test_collector_parts_are_reported_separately():
    quiet = parts()
    assert quiet["state"] == "working"
    # Nothing new for three days in quiet chats is not a fault while the heartbeat is current.
    assert (quiet["intake"]["state"], quiet["intake"]["reason"]) == ("working", "live")
    busy = parts(media_jobs={"done": 4, "failed": 2},
                 source_status={"1": {"state": "visible_in_dialogs"}, "2": {"state": "access_unconfirmed"}})
    assert busy["connection"]["state"] == "working"
    assert (busy["media"]["state"], busy["media"]["reason"]) == ("degraded", "failed_items")
    assert (busy["sources"]["state"], busy["sources"]["reason"]) == ("degraded", "some_unconfirmed")
    assert busy["state"] == "degraded"
    none = parts(source_status={"1": {"state": "access_unconfirmed"}})
    assert none["sources"]["state"] == "failed"
    assert parts(source_status={})["sources"]["state"] == "unknown"
    assert parts(sources=0)["sources"]["reason"] == "no_sources"


def test_collector_connection_and_liveness_transitions():
    reconnecting = parts(connected=False, phase="reconnecting", reconnect_attempts=3)
    assert (reconnecting["connection"]["state"], reconnecting["connection"]["attempts"]) == ("degraded", 3)
    assert reconnecting["intake"]["reason"] == "disconnected"
    signed_out = parts(running=False, connected=False, phase="authorization_required")
    assert (signed_out["connection"]["state"], signed_out["connection"]["reason"]) == ("failed", "signed_out")
    paused = parts(running=False, connected=False, phase="paused")
    assert paused["connection"]["state"] == "off" and paused["intake"]["state"] == "off"
    assert parts(rpc_backoff_until=(NOW + timedelta(minutes=5)).timestamp())["connection"]["reason"] == "telegram_pause"
    assert parts(has_session=False, running=False, phase="code_required")["connection"]["state"] == "configured"
    assert parts(last_heartbeat=None)["intake"]["state"] == "unknown"
    stale = parts(last_heartbeat=ago(minutes=4))  # heartbeat every 60 s: stale after 3 × 60 + 30 s
    assert (stale["intake"]["state"], stale["intake"]["reason"]) == ("unknown", "stale")
    assert parts(last_heartbeat=ago(minutes=3))["intake"]["state"] == "working"


def test_attachment_queue_states():
    assert parts(capture={"download_media": False})["media"]["state"] == "off"
    assert parts(storage_low=True)["media"]["reason"] == "disk_low"
    waiting = parts(media_jobs={"queued": 3}, oldest_pending_media_at=ago(hours=2))
    assert (waiting["media"]["state"], waiting["media"]["counts"]["pending"]) == ("degraded", 3)
    assert parts(media_jobs={"queued": 3}, oldest_pending_media_at=ago(minutes=5))["media"]["state"] == "working"
    assert parts(running=False, phase="paused", media_jobs={"queued": 3})["media"]["reason"] == "paused"


def test_worst_state_wins_and_unknown_is_never_success():
    assert health.worst(["working", "off", "degraded"]) == "degraded"
    assert health.worst(["working", "unknown"]) == "unknown"
    assert health.worst([]) == "unknown"
    assert health.worst(["off", "working"]) == "working"


def test_health_api_answers_the_whole_workspace_only(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    assert access.POLICY["GET /api/health"] == ("view", None)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        app.state.store.set_target(-100123, "Harbor", "supergroup", True)
        answer = client.get("/api/health").json()
        assert answer["timestamps"]["state"] == "off" and answer["replica"]["state"] == "off"
        assert answer["server"]["deployment"]["state"] == "off"
        assert answer["collector"]["connection"]["reason"] in ("no_account", "paused")
        status = client.get("/api/status").json()
        assert set(status["health"]) == {"connection", "intake", "sources", "media", "state"}
        assert client.get("/api/evidence").json()["health"]["state"] == "off"
        assert client.get("/api/replica").json()["health"]["state"] == "off"
        assert client.get("/api/profiles").json()["profiles"][0]["health"]["state"]
        token, _ = issue(client, workspaces={"default": [-100123]})
        browser, _ = login(app, token)
        assert browser.get("/api/health").status_code == 403  # one chat opens no workspace-wide state
        assert "health" in browser.get("/api/status").json()


def test_failed_timestamp_attempt_is_shown_as_failure_with_its_reason(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)

    async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
        raise OSError("unreachable")
    monkeypatch.setattr(anchoring, "post", post)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        app.state.collector.outside_route = lambda: NetworkConfig(kind="direct")
        body = {"enabled": True, "interval_minutes": 10, "tsa_urls": ["https://tsa.example/tsr"], "ots_calendars": []}
        assert client.post("/api/evidence", json=body).json()["health"]["state"] in ("configured", "running")
        for _ in range(300):
            state = client.get("/api/evidence").json()["health"]
            if state["state"] not in ("configured", "running"):
                break
            asyncio.run(asyncio.sleep(0.05))
        assert (state["state"], state["reason"]) == ("failed", "no_answer")
        assert state["last_success_at"] is None and state["last_verified_at"] is None
        assert state["last_failure"]["errors"][0]["service"] == "https://tsa.example/tsr"
        assert state["next_attempt_at"] and state["counts"]["unreachable"] == 1


def test_digest_only_leaves_for_the_calendar(journal, monkeypatch):
    """The anchoring change keeps sending only the checkpoint hash."""
    store, vault = journal
    sent = []

    async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
        sent.append(body)
        return OTS_ANSWER
    monkeypatch.setattr(anchoring, "post", post)
    retain_checkpoint(store, vault)
    record = asyncio.run(anchoring.anchor_latest(store, NetworkConfig(kind="direct"),
                                                 {"tsa_urls": [], "ots_calendars": ["https://cal.example"]}))
    data = (store.root / "checkpoints" / record["checkpoint"]["file"]).read_bytes()
    assert sent == [hashlib.sha256(data).digest()]
