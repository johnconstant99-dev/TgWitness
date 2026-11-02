"""Synthetic counts, chart projections and privacy boundaries for report analytics."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import report_analytics as analytics


def event(seq, kind="message.new", sender=11, chat=-1001, at="2026-11-02T10:00:00Z", **extra):
    return {"seq": seq, "kind": kind, "observed_at": at, "chat_id": chat, "message_id": 7,
            "actor_id": 999, "payload": {"sender_id": sender}, **extra}


def collect(*events):
    result = analytics.Analytics()
    for item in events:
        result.add(item)
    return result.result()


def test_observation_counts_are_not_unique_messages_or_extra_panel_actions():
    data = collect(
        event(1), event(2, "message.snapshot"), event(3, "message.recovered"),
        event(4, "message.edited"), event(5, "message.deleted"), event(6, "message.missing_on_recheck"),
        event(7, "collector.heartbeat"), event(8, "interaction.requested"), event(9, "interaction.result"),
        event(10, "media.saved"), event(11, "actor.avatar_saved"),
    )
    assert data["activity_events"] == 6
    assert data["totals"] == dict.fromkeys(analytics.KINDS.values(), 1)
    assert data["message_observations"] == 3  # same message ID, three observations
    assert data["sequence"] == {"from": 1, "to": 6}
    assert data["participants"]["total"] == 3
    assert data["participants"]["rows"][0]["total"] == 3
    assert data["chats"]["total"] == 6
    assert data["activity"]["rows"][0]["counts"] == data["totals"]
    assert data["hourly"]["rows"][0][10] == 6  # 2 November 2026 was Monday
    assert sum(map(sum, data["hourly"]["rows"])) == 6


def test_sender_rankings_never_infer_an_editor_or_deletion_actor():
    data = collect(event(1, sender=11), event(2, "message.edited", sender=12),
                   event(3, "message.deleted", sender=13), event(4, "message.missing_on_recheck", sender=14),
                   event(5, sender=None), event(6, payload={"sender_observation": {"id": 15, "display_name": "SECRET"}}))
    assert [(row["id"], row["total"]) for row in data["participants"]["rows"]] == [(11, 1), (15, 1)]
    assert data["participants"]["unknown_count"] == 1
    assert "999" not in json.dumps(data["participants"])  # actor_id must not fill in an unknown sender
    assert "SECRET" not in json.dumps(data)


def test_times_are_normalized_to_utc_and_sorted_independently_of_input_order():
    data = collect(event(20, at="2026-11-03T00:30:00+02:00"), event(3, at="2026-11-01T23:30:00-02:00"),
                   event(9, at="2026-11-01T23:00:00Z"))
    assert data["first_observed_at"] == "2026-11-01T23:00:00+00:00"
    assert data["last_observed_at"] == "2026-11-02T22:30:00+00:00"
    assert data["sequence"] == {"from": 3, "to": 20}
    assert [(row["period"], row["total"]) for row in data["activity"]["rows"]] == [("2026-11-01", 1), ("2026-11-02", 2)]
    assert data["hourly"]["rows"][6][23] == data["hourly"]["rows"][0][1] == data["hourly"]["rows"][0][22] == 1
    assert data["activity"]["rows"][1]["first_seq"] == 3
    assert data["activity"]["rows"][1]["last_seq"] == 20


@pytest.mark.parametrize("timestamp", [None, 7, True, "", "bad", "2026-11-01", "2026-11-01T00:00:00",
                                        "2026-11-01T00:00:00+27:00", "0001-01-01T00:00:00+01:00",
                                        "9999-12-31T23:59:59-01:00", "X" * 1000])
def test_bad_or_naive_times_remain_in_totals_without_entering_time_charts(timestamp):
    data = collect(event(1, at=timestamp))
    assert data["activity_events"] == data["message_observations"] == data["invalid_time_events"] == 1
    assert data["first_observed_at"] is data["last_observed_at"] is None
    assert data["activity"]["rows"] == []
    assert data["activity"]["counted_events"] == data["hourly"]["counted_events"] == 0
    assert data["participants"]["total"] == data["chats"]["total"] == 1


def test_malformed_identifiers_and_payloads_cannot_leak_content():
    values = [None, True, False, 0, "SECRET", {"secret": "SECRET"}, ["SECRET"], 2**63, -2**63, 1.5]
    data = collect(*(event(seq, sender=value, chat=value) for seq, value in enumerate(values, 1)),
                   event(20, payload="SECRET"), event(21, payload=None), event(True), event("SECRET"))
    assert data["participants"]["unknown_count"] == len(values) + 2
    assert data["chats"]["unknown_count"] == len(values)
    assert data["sequence"] == {"from": 1, "to": 21}
    assert "SECRET" not in json.dumps(data)
    empty = collect(None, [], {"kind": {}}, {"kind": "unknown"})
    assert empty["activity_events"] == 0
    assert empty["sequence"] == {"from": None, "to": None}


def test_exact_monthly_rollup_preserves_all_counts_and_sequences(monkeypatch):
    monkeypatch.setattr(analytics, "MAX_DAY_BUCKETS", 2)
    data = collect(event(4, at="2026-01-01T00:00:00Z"), event(1, at="2026-01-31T01:00:00Z"),
                   event(8, "message.edited", at="2026-02-02T02:00:00Z"), event(2, at="2026-01-15T00:00:00Z"))
    assert data["activity"]["granularity"] == "month"
    assert [(row["period"], row["total"]) for row in data["activity"]["rows"]] == [("2026-01", 3), ("2026-02", 1)]
    assert data["activity"]["rows"][0]["first_seq"] == 1
    assert data["activity"]["rows"][0]["last_seq"] == 4
    assert data["activity"]["rows"][1]["counts"]["edited"] == 1
    assert sum(row["total"] for row in data["activity"]["rows"]) == data["activity_events"]


def test_cardinality_overflow_is_explicit_never_a_partial_top_chart(monkeypatch):
    monkeypatch.setattr(analytics, "MAX_GROUPS", 2)
    monkeypatch.setattr(analytics, "MAX_DAY_BUCKETS", 1)
    monkeypatch.setattr(analytics, "MAX_MONTH_BUCKETS", 2)
    instance = analytics.Analytics()
    for seq in range(1, 6):
        instance.add(event(seq, sender=seq, chat=-seq, at=f"2026-0{seq}-01T00:00:00Z"))
    instance.add(event(6, sender=None, chat=None))
    result = instance.result()
    assert result["activity_events"] == result["message_observations"] == 6
    for name in ("participants", "chats"):
        assert result[name]["status"] == "too_many_groups"
        assert result[name]["rows"] == []
        assert result[name]["total"] == 6
        assert result[name]["unknown_count"] == 1
        assert analytics.selected(result, {})[name]["rows"] == []
    assert result["activity"]["status"] == "too_many_periods"
    assert result["activity"]["rows"] == []
    assert result["hourly"]["counted_events"] == sum(map(sum, result["hourly"]["rows"])) == 6
    assert instance.periods == instance.participants.rows == instance.chats.rows == {}


def test_aliases_are_stable_across_ranking_limits_and_have_no_identity_mapping():
    events = []
    seq = 0
    for identity in range(800001, 800009):
        for _ in range(identity - 800000):
            seq += 1
            events.append(event(seq, sender=identity, payload={"sender_id": identity,
                "text": "PRIVATE MESSAGE", "sender_observation": {"username": "SECRET", "phone": "SECRET"}}))
    data = collect(*events, event(100, sender=None))
    narrow = analytics.selected(data, {"chart_limit": 5})["participants"]
    wide = analytics.selected(data, {"chart_limit": 30})["participants"]
    assert narrow["rows"][0]["label_values"] == wide["rows"][0]["label_values"] == {"n": "08"}
    assert narrow["rows"][0]["count"] == 8
    assert sum(row["count"] for row in narrow["rows"]) == narrow["total"] == 37
    assert narrow["other_groups"] == 3
    assert narrow["rows"][-2]["label"] == "Other"
    assert narrow["rows"][-2]["count"] == 6
    assert narrow["rows"][-1]["label"] == "Unknown" and narrow["rows"][-1]["count"] == 1
    for private in ["PRIVATE", "SECRET", *(str(identity) for identity in range(800001, 800009))]:
        assert private not in json.dumps(narrow)
    ids = analytics.selected(data, {"participant_labels": "ids"})["participants"]
    assert ids["rows"][0]["id"] == 800008
    assert ids["rows"][0]["label"] == "Sender {id}"
    assert ids["rows"][0]["label_values"] == {"id": "800008"}


def test_hidden_charts_are_absent_and_selected_does_not_mutate_source():
    data = collect(event(1))
    before = json.dumps(data, sort_keys=True)
    hidden = analytics.selected(data, {name: False for name in ("activity_chart", "hourly_chart", "participant_chart", "chat_chart")})
    assert not any(name in hidden for name in ("activity", "hourly", "participants", "chats"))
    assert hidden["activity_events"] == 1
    projected = analytics.selected(data, {})
    projected["activity"]["rows"][0]["counts"]["new"] = 999
    projected["hourly"]["rows"][0][10] = 999
    projected["totals"]["new"] = 999
    projected["sequence"]["from"] = 999
    projected["chats"]["rows"][0]["counts"]["new"] = 999
    assert json.dumps(data, sort_keys=True) == before
    invalid = analytics.selected(data, {"participant_labels": "anything", "chart_limit": "bad"})
    assert invalid["participants"]["rows"][0]["label"] == "Participant {n}"


def test_group_ranking_and_other_totals_are_exact_with_ties():
    data = collect(*(event(seq, chat=-seq, sender=seq) for seq in range(1, 9)), event(9, chat=None))
    chart = analytics.selected(data, {"chart_limit": 5})["chats"]
    assert [row["id"] for row in chart["rows"][:5]] == [-8, -7, -6, -5, -4]
    assert chart["rows"][-2]["label"] == "Other" and chart["rows"][-2]["total"] == 3
    assert chart["rows"][-1]["label"] == "Unknown" and chart["rows"][-1]["total"] == 1
    assert sum(row["total"] for row in chart["rows"]) == chart["total"] == 9
    assert sum(row["counts"]["new"] for row in chart["rows"]) == 9


def test_large_event_volume_does_not_grow_per_event_storage():
    instance = analytics.Analytics()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for seq in range(1, 20001):
        instance.add(event(seq, sender=seq % 10 + 1, chat=-(seq % 3 + 1),
                           at=(start + timedelta(seconds=seq)).isoformat()))
    data = instance.result()
    assert data["activity_events"] == data["participants"]["total"] == data["chats"]["total"] == 20000
    assert len(instance.periods) == 1 and len(instance.participants.rows) == 10 and len(instance.chats.rows) == 3
    assert data["sequence"] == {"from": 1, "to": 20000}
    assert sum(row["count"] for row in analytics.selected(data, {})["participants"]["rows"]) == 20000
    snapshot = instance.result()
    snapshot["hourly"]["rows"][0][0] = -1
    snapshot["participants"]["rows"][0]["counts"]["new"] = -1
    assert instance.result() == data
    assert json.loads(json.dumps(data, allow_nan=False)) == data


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
