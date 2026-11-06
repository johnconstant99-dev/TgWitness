"""Registered metric processors: registry, the four anomaly metrics, and their place in evidence reports."""
from datetime import date, timedelta
from pathlib import Path
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import metrics, tuning  # noqa: E402
from tgwitness.evidence import export_file  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402

CHAT = -1001000000001
START = date(2026, 9, 1)


def message(day, sender, number, chat=CHAT, **payload):
    return {"kind": "message.new", "chat_id": chat, "message_id": number, "observed_at": day + "T12:00:00+00:00",
            "payload": {"sender_id": sender, "sent_at": day + "T10:00:00+00:00", **payload}}


def test_registry_lists_versioned_processors_with_parameters():
    found = metrics.load()
    assert sorted(found) == ["first_time_posters_over_time", "join_leave_per_month", "pinned_per_month",
                             "service_vs_message_ratio"]
    assert all(cls.version == 1 and cls.methodology and cls.parameter in tuning.BY_KEY for cls in found.values())
    with pytest.raises(ValueError, match="Duplicate"):
        metrics.register("pinned_per_month", version=2, title="", methodology="", parameter="metric_pinned")(type("X", (), {}))
    result = metrics.run([], names=["pinned_per_month"])
    assert result["format"] == "tgwitness-metric-processors-v1"
    assert [(p["name"], p["version"]) for p in result["processors"]] == [("pinned_per_month", 1)]


def steady_chat(spike_day=None, early_spike=False):
    events, number = [], 0
    for offset in range(21):
        day = (START + timedelta(days=offset)).isoformat()
        for sender in (1, 2):
            for _ in range(5):
                number += 1
                events.append(message(day, sender, number))
        newcomers = 8 if offset == spike_day or early_spike and offset == 2 else 0
        for index in range(newcomers):
            number += 1
            events[-1 - index]["payload"]["sender_id"] = 100 + offset * 10 + index
    return events


def test_first_time_posters_flag_injection_after_warm_up():
    result = metrics.REGISTRY["first_time_posters_over_time"].run(steady_chat(spike_day=15))
    assert result["flags_total"] == 1 and result["flags"][0]["day"] == (START + timedelta(days=15)).isoformat()
    assert result["flags"][0]["first_time_posters"] == 8 and result["flags"][0]["messages"] == 10
    quiet = metrics.REGISTRY["first_time_posters_over_time"].run(steady_chat(early_spike=True))
    assert quiet["flags_total"] == 0, "The warm-up days are never flagged"
    assert quiet["rows"][0][1] == 2 and quiet["rows"][2][1] == 8 and quiet["summary"]["chats"] == 1


def test_service_share_counts_distinct_numbers():
    events = [message("2026-09-01", 1, n) for n in range(1, 11)]
    events += [{"kind": "chat.service", "chat_id": CHAT, "message_id": n, "payload": {}} for n in (2, 5, 5)]
    result = metrics.REGISTRY["service_vs_message_ratio"].run(events)
    assert result["rows"][0][1:] == ["per chat", 8, 2, 0.2] and result["summary"]["service_share"] == 0.2


def test_history_service_messages_are_classified_without_duplicate_service_record():
    events = [message("2026-09-01", 1, 1),
              {**message("2026-09-01", 2, 2, service_action="MessageActionPinMessage"), "kind": "message.snapshot"}]
    ratio = metrics.load()["service_vs_message_ratio"].run(events)
    assert ratio["summary"] == {"ordinary": 1, "service": 1, "service_share": 0.5}
    posters = metrics.load()["first_time_posters_over_time"].run(events)
    assert posters["summary"]["senders"] == 1


def test_posters_warmup_uses_calendar_days():
    events = [message("2026-09-01", 1, number) for number in range(10)]
    events += [message("2026-10-01", 100 + number, 100 + number) for number in range(8)]
    result = metrics.load()["first_time_posters_over_time"].run(events)
    assert result["flags_total"] == 0, "A month without baseline observations cannot supply a 14-day baseline"


def membership(day, action, actor, users=None, user=None):
    body = {"_": action, **({"users": users} if users else {}), **({"user_id": user} if user else {})}
    return {"kind": "membership.service", "chat_id": CHAT, "message_id": 1, "actor_id": actor,
            "source_at": day + "T10:00:00+00:00", "observed_at": day + "T10:00:00+00:00", "payload": {"action": body}}


def test_joins_and_departures_per_month_count_each_change_once():
    events = [membership("2026-09-02", "MessageActionChatAddUser", 5, users=[7, 8]),
              membership("2026-09-02", "MessageActionChatAddUser", 5, users=[7]),
              membership("2026-09-20", "MessageActionChatDeleteUser", 7, user=7),
              membership("2026-10-01", "MessageActionChatDeleteUser", 5, user=8)]
    rows = metrics.REGISTRY["join_leave_per_month"].run(events)["rows"]
    assert rows == [["2026-09", 2, 1, 0, 1], ["2026-10", 0, 0, 1, -1]]


def test_pins_unpins_and_snapshot_changes_per_month():
    events = [message("2026-09-03", 1, 40, service_action="MessageActionPinMessage"),
              message("2026-09-03", 1, 40, service_action="MessageActionPinMessage"),
              {"kind": "message.unpinned", "chat_id": CHAT, "observed_at": "2026-10-04T00:00:00+00:00",
               "payload": {"raw": {"messages": [40, 41]}}},
              {"kind": "chat.state", "chat_id": CHAT, "observed_at": "2026-10-05T00:00:00+00:00",
               "payload": {"changes": {"pinned": {"added": [], "removed": [40, 41, 42]}}}}]
    rows = metrics.REGISTRY["pinned_per_month"].run(events)["rows"]
    assert rows == [["2026-09", 1, 0, 0, 0], ["2026-10", 0, 2, 0, 3]]


def test_reports_list_processors_and_follow_parameters(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        for event in steady_chat(spike_day=15)[:60]:
            store.append(event["kind"], event["payload"], event["chat_id"], event["message_id"])
        archive = export_file(store, vault, "zip")
        with zipfile.ZipFile(archive) as bundle:
            page = bundle.read("report.html").decode("utf-8")
        archive.unlink(missing_ok=True)
        assert "Anomaly indicators" in page and "first_time_posters_over_time v1" in page
        assert "service_vs_message_ratio v1" in page and "Method" in page
        store.set_setting("parameters", {"metric_first_time_posters": False, "metric_service_ratio": False,
                                         "metric_join_leave": False, "metric_pinned": False})
        archive = export_file(store, vault, "zip")
        with zipfile.ZipFile(archive) as bundle:
            assert "Anomaly indicators" not in bundle.read("report.html").decode("utf-8")
        archive.unlink(missing_ok=True)
        from tgwitness import report
        options = report.resolved()
        options["selection"] = {"enabled": True, "chats": [CHAT]}
        archive = export_file(store, vault, "zip", options)
        with zipfile.ZipFile(archive) as bundle:
            assert "Anomaly indicators" not in bundle.read("report.html").decode("utf-8")
        archive.unlink(missing_ok=True)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
