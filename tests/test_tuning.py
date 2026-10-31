import asyncio
import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from tgwitness import alerts, dossier, tuning
from tgwitness.app import create_app
from tgwitness.verify import Coverage
from tgwitness.witness import Witness, load_config, resolve
from tests.test_collector import CHAT, FakeClient
from tests.test_coverage import record
from tests.test_scope import ALICE, collector_with


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        yield c, app


def test_every_parameter_has_a_group_label_and_a_valid_default():
    groups = {group for group, _, _ in tuning.GROUPS}
    for parameter in tuning.PARAMETERS:
        assert parameter.group in groups and parameter.label, parameter.key
        if parameter.kind == "int":
            assert parameter.low <= parameter.default <= parameter.high and parameter.unit, parameter.key
        assert tuning.validate(parameter, parameter.initial()) == parameter.initial()
    assert len({p.key for p in tuning.PARAMETERS}) == len(tuning.PARAMETERS)
    assert "Recheck" in tuning.texts() and "Chats per recheck pass" in tuning.texts()


def test_values_are_validated_saved_as_overrides_and_fall_back_to_defaults(journal):
    store, _ = journal
    assert tuning.values(store)["recheck_max_chats"] == 30
    saved, before, after = tuning.changes(store, {"recheck_max_chats": 5, "dialog_limit": 1000})
    assert saved == {"recheck_max_chats": 5} and before == {"recheck_max_chats": 30} and after == {"recheck_max_chats": 5}
    for wrong in ({"recheck_max_chats": 0}, {"recheck_max_chats": 2.5}, {"recheck_max_chats": True},
                  {"dossier_wallets": 1}, {"nonsense": 1}, {"dossier_patterns": ["no colon here"]},
                  {"dossier_patterns": ["Bad: ("]}, {"dossier_patterns": ["x: y"] * 31}):
        with pytest.raises(tuning.Invalid):
            tuning.changes(store, wrong)
    store.set_setting("parameters", {"recheck_max_chats": 99999, "dialog_limit": 250})
    assert tuning.value(store, "recheck_max_chats") == 30
    assert tuning.value(store, "dialog_limit") == 250
    saved, _, after = tuning.changes(store, {"dialog_limit": None})
    assert "dialog_limit" not in saved and after == {"dialog_limit": 1000}


def test_parameters_api_records_changes_and_status_carries_them(client):
    c, app = client
    groups = c.get("/api/parameters").json()["groups"]
    assert [g["id"] for g in groups] == [g for g, _, _ in tuning.GROUPS]
    item = next(i for g in groups for i in g["items"] if i["key"] == "snapshot_max")
    assert (item["value"], item["default"], item["low"], item["high"], item["unit"]) == (500, 500, 1, 10000, "messages")
    response = c.post("/api/parameters", json={"values": {"snapshot_max": 0}})
    assert response.status_code == 422 and response.json()["detail"]["parameter"] == "snapshot_max"
    changed = c.post("/api/parameters", json={"values": {"snapshot_max": 50, "dossier_patterns": ["Domain: \\bevil\\.top\\b"]}})
    assert changed.status_code == 200
    record = app.state.store.events(kind="parameters.changed")[0]["payload"]
    assert record["before"] == {"snapshot_max": 500, "dossier_patterns": []}
    assert record["after"] == {"snapshot_max": 50, "dossier_patterns": ["Domain: \\bevil\\.top\\b"]}
    assert c.get("/api/status").json()["parameters"]["snapshot_max"] == 50
    c.post("/api/parameters", json={"values": {"snapshot_max": 50}})
    assert len(app.state.store.events(kind="parameters.changed")) == 1
    c.post("/api/auth/configure", json={"api_id": 123, "api_hash": "a" * 32})
    c.post("/api/auth/phone", json={"phone": "+15551112222"})
    c.post("/api/auth/code", json={"code": "12345"})
    c.get("/api/dialogs")
    c.post("/api/targets", json={"chat_id": CHAT, "enabled": True})
    c.post("/api/collector/start", json={})
    too_many = c.post("/api/snapshot", json={"chat_id": CHAT, "limit": 51})
    assert too_many.status_code == 422 and "Parameters" in too_many.json()["detail"]
    assert c.post("/api/snapshot", json={"chat_id": CHAT, "limit": 3}).json()["captured"] == 3
    started = app.state.store.events(kind="observation.started")[0]["payload"]
    assert started["parameters"]["snapshot_max"] == 50


def test_collector_follows_parameters(journal):
    store, vault = journal

    async def run():
        collector = await collector_with(store, vault)
        store.set_target(CHAT, "Priority", "supergroup", True)
        store.set_target(ALICE, "Alice", "private", True, origin="scope", priority=0)
        assert len(collector.due_targets()) == 2
        store.set_setting("parameters", {"recheck_max_chats": 1, "media_min_free_mb": 2048,
                                         "telegram_timeout_seconds": 40})
        assert [t["chat_id"] for t in collector.due_targets()] == [CHAT]
        assert collector.status()["media_min_free_bytes"] == 2048 * 1024**2
        client = collector.make_client(123, "a" * 32)
        assert client.options["timeout"] == 40 and client.options["request_retries"] == 2
    asyncio.run(run())


def test_profiles_follow_parameters_and_your_own_patterns(journal):
    store, vault = journal
    store.set_target(CHAT, "Harbor", "supergroup", True)
    for i in range(1, 5):
        store.append("message.new", {"text": "pay at https://evil.top/x or +7 999 123-45-67 #" + str(i),
                                     "sender_id": 70001, "sender_observation": {"id": 70001, "display_name": "A"},
                                     "sent_at": "2026-01-01T00:00:00+00:00"}, CHAT, i, 70001)
    built = dossier.build(store, CHAT)
    person = built["people"][0]
    assert person["mentions"]["phones"] and person["mentions"]["links"] and person["mentions"]["patterns"] == []
    store.set_setting("parameters", {"dossier_phones": False, "dossier_max_refs": 2,
                                     "dossier_patterns": ["Phishing domain: [a-z0-9-]+\\.top\\b"]})
    built = dossier.build(store, CHAT)
    person = built["people"][0]
    assert person["mentions"]["phones"] == []
    assert person["mentions"]["patterns"][0]["value"] == "evil.top"
    assert person["mentions"]["patterns"][0]["detail"] == "Phishing domain"
    assert person["mentions"]["patterns"][0]["count"] == 4 and len(person["mentions"]["patterns"][0]["records"]) == 2
    assert built["settings"]["find"]["phones"] is False and built["settings"]["max_refs"] == 2


def test_notifications_follow_parameters(journal):
    store, _ = journal
    lines = [str(i) for i in range(10)]
    assert alerts.capped(lines, {}, 3).splitlines() == ["0", "1", "2", "…and 7 more."]
    store.append("message.new", {"text": "x" * 500}, CHAT, 1)
    event = store.append("message.edited", {"text": "y" * 500}, CHAT, 1)
    assert len(alerts.excerpt_line(store, event, "Chat", {}, 30).split(": ", 1)[1]) == 30


def test_coverage_gap_threshold_follows_the_recorded_heartbeat_interval():
    def gaps(interval):
        payload = {"interval_seconds": interval} if interval else {}
        events = [record(0, "observation.started", {"parameters": {"heartbeat_seconds": interval or 60}})]
        events += [record(m, "collector.heartbeat", payload) for m in (5, 10, 15)]
        coverage = Coverage()
        for event in events:
            coverage.add(event)
        return coverage.result()["gaps"]
    assert gaps(None)
    assert gaps(300) == []

    coverage = Coverage()
    for event in [record(0, "observation.started", {"parameters": {"heartbeat_seconds": 60}}),
                  record(1, "collector.heartbeat", {"interval_seconds": 60}),
                  record(2, "parameters.changed", {"before": {"heartbeat_seconds": 60},
                                                   "after": {"heartbeat_seconds": 600}}),
                  record(11, "collector.heartbeat", {"interval_seconds": 600})]:
        coverage.add(event)
    assert coverage.result()["gaps"] == []


def test_witness_options_come_from_file_environment_and_command_line(tmp_path, monkeypatch):
    config = tmp_path / "witness.json"
    config.write_text(json.dumps({"collector": "https://c.example", "token": "tgww_x", "interval": 5, "post": "changes",
                                  "title": "Partner witness", "texts": {"ok": "head seen"}}), encoding="utf-8")
    args = type("Args", (), {"interval": None, "timeout": 45, "data_dir": None})()
    monkeypatch.setenv("TGWITNESS_WITNESS_INTERVAL", "7")
    options = resolve(args, load_config(config))
    assert (options["interval"], options["timeout"], options["post"], options["title"]) == (7, 45, "changes", "Partner witness")
    assert options["token"] == "tgww_x" and options["texts"] == {"ok": "head seen"}
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"intervall": 5}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown config options: intervall"):
        load_config(bad)
    with pytest.raises(ValueError):
        Witness(tmp_path / "w", "https://c.example", "t", post="sometimes")
    with pytest.raises(ValueError):
        Witness(tmp_path / "w", "https://c.example", "t", texts={"unknown": "x"})


def test_witness_post_policy_and_texts(tmp_path):
    heads = iter(["a" * 64, "a" * 64, "b" * 64])
    posts = []

    async def send(text):
        posts.append(text)
        return len(posts)

    witness = Witness(tmp_path / "w", "https://c.example", "t", channel="@c", bot_token="1:x", send=send,
                      post="changes", title="Partner", texts={"ok": "head seen", "records": "entries"})
    count = iter(range(10, 20))

    def check(_):
        head = next(heads)
        return {"status": "ok", "collector": "c.example", "collector_fingerprint": "f" * 64,
                "pinned_fingerprint": "f" * 64, "event_count": next(count), "head_hash": head}

    async def fetch():
        return {}
    witness.fetch, witness.check = fetch, check
    try:
        for _ in range(3):
            asyncio.run(witness.tick())
        assert len(posts) == 2
        assert posts[0].startswith("Partner #") and "head seen" in posts[0] and "entries" in posts[0]
        assert "TGW1." in posts[0]
        witness.post = "problems"

        async def silent():
            raise ConnectionRefusedError()
        witness.fetch = silent
        asyncio.run(witness.tick())
        assert len(posts) == 3 and "no answer from the collector" in posts[2]
    finally:
        witness.close()


def test_verifier_size_limit_is_an_option():
    output = subprocess.run([sys.executable, "-m", "tgwitness.verify", "--help"], capture_output=True, text=True)
    assert "--max-gib" in output.stdout
