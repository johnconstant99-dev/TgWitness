"""Exact selection and missing-number context; every record is synthetic."""
import copy
import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import report_analytics
from tgwitness import report_selection as selection
from tgwitness.security import Vault
from tgwitness.store import Store


def event(seq, message=None, *, chat=-1001, sender=10, at="2026-11-02T12:00:00Z", kind="message.new", text=None):
    return {"seq": seq, "hash": f"{seq:064x}", "kind": kind, "chat_id": chat,
            "message_id": message, "observed_at": at, "actor_id": 999,
            "payload": {"sender_id": sender, "text": text if text is not None else f"Synthetic message {message}"}}


class Snapshot:
    def __init__(self, events):
        self.items = events
        self.head = {"seq": events[-1]["seq"], "hash": events[-1]["hash"]} if events else None

    def events(self):
        return iter(self.items)


def analyze(events, **options):
    return selection.analyze(Snapshot(events), selection.Selection(enabled=True, **options))


@pytest.mark.parametrize("patch", [
    {"chats": [True]}, {"senders": [False]}, {"chats": ["10"]}, {"senders": [1.0]},
    {"chats": [0]}, {"senders": [2**63]}, {"chats": [-2**63]}, {"chats": [1, 1]},
    {"senders": [1, 1]}, {"kinds": ["message.new", "message.new"]}, {"kinds": ["collector.heartbeat"]},
    {"date_from": "2026-02-30"}, {"date_to": "2026-2-03"}, {"date_to": "2026-11-02T12:00:00Z"},
    {"date_from": "2026-11-03", "date_to": "2026-11-02"}, {"date_from": 20261102},
    {"enabled": "true"}, {"id_gaps": 1}, {"unknown": True},
    {"chats": list(range(1, selection.MAX_SELECTION_IDS+2))},
])
def test_selection_rejects_ambiguous_unbounded_or_invalid_inputs(patch):
    with pytest.raises(ValidationError):
        selection.Selection(**patch)


def test_disabled_selection_preserves_all_records_and_empty_kinds_is_explicit():
    disabled = selection.Selection(chats=[-1002], senders=[12], kinds=[], date_from="2030-01-01")
    assert selection.matches(event(1, kind="collector.heartbeat"), disabled)
    assert selection.matches(event(2, at="invalid"), disabled)
    enabled = disabled.model_copy(update={"enabled": True})
    assert not selection.matches(event(3), enabled)
    empty = analyze([event(1, 1), event(2, 2)], kinds=[])
    assert empty["counts"]["selected_records"] == 0
    assert empty["messages"]["total"] == 0
    assert empty["catalog"]["chats_total"] == empty["catalog"]["senders_total"] == 1


def test_dates_are_inclusive_utc_not_input_offset_dates():
    predicate = selection.compile_selection(selection.Selection(enabled=True, date_from="2026-11-02", date_to="2026-11-02"))
    for at in ("2026-11-02T00:00:00Z", "2026-11-02T23:59:59.999999Z", "2026-11-03T00:30:00+02:00",
               "2026-11-01T23:30:00-02:00"):
        assert predicate(event(1, at=at)), at
    for at in ("2026-11-01T23:59:59Z", "2026-11-03T00:00:00Z", "2026-11-02T00:30:00+02:00",
               "2026-11-02T23:30:00-02:00", "2026-11-02T12:00:00", "invalid"):
        assert not predicate(event(1, at=at)), at
    # The inclusive upper bound never adds a day beyond datetime's range.
    assert selection.matches(event(1, at="9999-12-31T23:59:59Z"),
                             selection.Selection(enabled=True, date_to="9999-12-31"))


def test_sender_filter_never_uses_actor_and_unknown_deletion_is_excluded():
    chosen = selection.Selection(enabled=True, senders=[999])
    assert not selection.matches(event(1, sender=None), chosen)
    assert not selection.matches(event(2, kind="message.deleted", sender=None), chosen)
    assert selection.matches(event(3, kind="message.deleted", sender=999), chosen)
    alternate = event(4)
    alternate["payload"] = {"sender_observation": {"id": 999, "display_name": "Synthetic"}}
    assert selection.matches(alternate, chosen)
    alternate["payload"]["sender_id"] = None
    assert not selection.matches(alternate, chosen), "Explicit unknown cannot be filled from another field"


def test_counts_and_catalog_scope_before_sender_and_event_filters():
    events = [event(1, 1), event(2, 1, kind="message.snapshot"), event(3, 2, sender=20),
              event(4, 2, sender=20, kind="message.edited"), event(5, 3, sender=30, chat=-1002),
              event(6, 4, sender=40, at="2026-11-03T12:00:00Z"), event(7, 5, sender=None, kind="message.deleted"),
              event(8, None, kind="collector.heartbeat"), event(9, 6, at="invalid")]
    title = event(10, kind="target.changed")
    title["payload"] = {"title": "Synthetic channel"}
    events.append(title)
    data = analyze(events, chats=[-1001], senders=[10], date_from="2026-11-02", date_to="2026-11-02", kinds=["message.new"])
    assert data["source"] == {"records": 10, "last_seq": 10, "journal_head": f"{10:064x}"}
    assert data["counts"] == {"selected_records": 1, "selected_message_records": 1, "message_observations": 1,
                               "participants": 1, "chats": 1, "invalid_time_excluded": 1}
    assert [(row["id"], row["count"]) for row in data["catalog"]["chats"]] == [(-1001, 7), (-1002, 1)]
    assert data["catalog"]["chats"][0]["title"] == "Synthetic channel"
    assert data["catalog"]["senders"] == [{"id": 10, "count": 2}, {"id": 20, "count": 2}]
    assert data["catalog"]["unknown_sender_records"] == 1
    assert data["messages"]["rows"][0]["seq"] == 1
    assert data["analytics"]["totals"]["new"] == 1 and data["analytics"]["activity_events"] == 1
    full = selection.analyze(Snapshot(events), selection.Selection())
    assert full["counts"]["selected_records"] == 10 and full["messages"]["total"] == 8


def test_gap_basis_uses_all_known_ids_not_filtered_messages():
    events = [event(1, 10, sender=10), event(2, 11, sender=20, at="2026-11-01T12:00:00Z"),
              event(3, 12, sender=None, kind="message.deleted", at="2026-11-01T12:00:00Z"),
              event(4, 13, sender=None, kind="message.missing_on_recheck"),
              event(5, 14, sender=None, kind="media.saved", at="2026-11-03T12:00:00Z"),
              event(6, 20, sender=10), event(7, 20, sender=10, kind="message.snapshot")]
    data = analyze(events, chats=[-1001], senders=[10], kinds=["message.new"],
                   date_from="2026-11-02", date_to="2026-11-02")
    gaps = data["id_gaps"]
    assert gaps["ranges_total"] == 1 and gaps["ids_total"] == 5
    row = gaps["rows"][0]
    assert (row["start"], row["end"], row["count"]) == (15, 19, 5)
    assert row["before"]["message_id"] == 14 and row["before"]["seq"] == 5
    assert row["before"]["context_only"] and not row["before"]["matches_selection"]
    assert row["after"]["seq"] == 6 and row["after"]["matches_selection"]
    assert data["counts"]["selected_records"] == 2
    assert "not proof" in gaps["basis"] and "Sender and event-kind" in gaps["basis"]


def test_no_false_gaps_from_author_or_kind_filters_and_no_before_or_after_inference():
    events = [event(1, 100, sender=10), event(2, 101, sender=20), event(3, 102, kind="message.edited"),
              event(4, 103, sender=10), event(5, 900, sender=10, at="2030-01-01T00:00:00Z")]
    data = analyze(events, senders=[10], kinds=["message.new"], date_to="2026-11-02")
    assert [row["message_id"] for row in data["messages"]["rows"]] == [100, 103]
    assert data["id_gaps"]["rows"] == []
    assert data["id_gaps"]["ids_total"] == 0
    # The future-known number is excluded only from date boundaries; it cannot
    # create a gap after the last message observed in the requested interval.
    all_dates = analyze(events, senders=[10], kinds=["message.new"])
    assert [(row["start"], row["end"]) for row in all_dates["id_gaps"]["rows"]] == [(104, 899)]


def test_gap_neighbors_prefer_saved_message_content_and_earliest_record():
    events = [event(1, 7, kind="message.deleted", sender=None), event(2, 7, text="Earliest saved version"),
              event(3, 7, kind="message.edited", text="Later saved version"), event(4, 10)]
    gap = analyze(events)["id_gaps"]["rows"][0]
    assert gap["before"]["seq"] == 2 and gap["before"]["text"] == "Earliest saved version"
    assert gap["count"] == 2


def test_gap_totals_remain_exact_after_preview_limit_and_large_range_is_not_expanded():
    events = [event(seq, seq*2) for seq in range(1, 105)]
    events += [event(105, 2**31-1), event(106, 1, chat=-1002), event(107, 3, chat=-1002)]
    data = analyze(events, chats=[-1001])
    gaps = data["id_gaps"]
    assert len(gaps["rows"]) == selection.MAX_GAP_ROWS == 100
    assert gaps["ranges_total"] == 104 and gaps["truncated"]
    assert gaps["ids_total"] == (2**31-1-2+1) - 105
    assert all(row["chat_id"] == -1001 for row in gaps["rows"])
    assert gaps["rows"][0]["start"] == 3


def test_invalid_message_numbers_cannot_poison_gap_boundaries():
    events = [event(1, 10), event(2, 12)]
    for seq, invalid in enumerate((True, False, 0, -1, 1.5, "11", None, 2**31, 2**63), 3):
        events.append(event(seq, invalid))
    data = analyze(events)
    assert data["id_gaps"]["ids_total"] == 1
    assert data["id_gaps"]["rows"][0]["start"] == 11


def test_previews_are_bounded_and_never_coerce_arbitrary_objects_to_text():
    events = [event(1, 1, text="x"*500), event(2, 2, text={"password":"SECRET"}), event(3, 3)]
    data = selection.analyze(Snapshot(events), selection.Selection(enabled=True), preview_limit=2)
    assert len(data["messages"]["rows"]) == 2 and data["messages"]["truncated"]
    assert len(data["messages"]["rows"][0]["text"]) == selection.PREVIEW_CHARS
    assert data["messages"]["rows"][1]["text"] == ""
    assert "SECRET" not in json.dumps(data)
    empty = selection.analyze(Snapshot(events), selection.Selection(enabled=True), preview_limit=0)
    assert empty["messages"]["rows"] == [] and empty["messages"]["total"] == 3


def test_counts_survive_catalog_and_chart_cardinality_caps(monkeypatch):
    monkeypatch.setattr(selection, "MAX_CATALOG_ROWS", 2)
    monkeypatch.setattr(report_analytics, "MAX_GROUPS", 2)
    data = analyze([event(seq, seq, sender=seq, chat=-seq) for seq in range(1, 6)])
    assert data["counts"]["participants"] == data["counts"]["chats"] == 5
    assert data["catalog"]["chats_status"] == data["catalog"]["senders_status"] == "too_many_groups"
    assert data["catalog"]["chats"] == data["catalog"]["senders"] == []
    assert data["catalog"]["chats_total"] == data["catalog"]["senders_total"] == 5
    assert data["analytics"]["participants"]["status"] == "too_many_groups"


def test_disabled_gap_analysis_skips_message_index_work(monkeypatch):
    def unexpected(*args):
        raise AssertionError("Gap index must not be built when disabled")
    monkeypatch.setattr(selection, "_known", unexpected)
    data = analyze([event(1, 10), event(2, 20)], id_gaps=False)
    assert data["id_gaps"]["status"] == "disabled" and data["id_gaps"]["rows"] == []
    assert data["counts"]["selected_records"] == 2


def test_empty_snapshot_and_no_matching_dates():
    data = analyze([])
    assert data["source"]["records"] == data["counts"]["selected_records"] == 0
    assert data["catalog"]["chats_status"] == "available"
    assert data["id_gaps"]["ids_total"] == 0 and not data["messages"]["truncated"]
    data = analyze([event(1, 10), event(2, 20)], date_from="2030-01-01")
    assert data["counts"]["selected_records"] == data["id_gaps"]["ids_total"] == 0
    assert data["catalog"]["chats_total"] == 1 and data["catalog"]["senders_total"] == 0


def test_scans_after_fifty_thousand_records_without_buffering_or_cutoff():
    class StreamingSnapshot:
        head = {"seq": 50003, "hash": f"{50003:064x}"}
        def events(self):
            for seq in range(1, 50004):
                yield event(seq, seq, sender=20 if seq <= 50000 else 10)
    result = selection.analyze(StreamingSnapshot(), selection.Selection(enabled=True, senders=[10], id_gaps=False), preview_limit=1)
    assert result["source"]["records"] == 50003
    assert result["counts"]["selected_records"] == 3 and result["messages"]["total"] == 3
    assert result["messages"]["rows"][0]["seq"] == 50001 and result["messages"]["truncated"]
    assert result["catalog"]["senders"] == [{"id":20,"count":50000},{"id":10,"count":3}]


def test_real_snapshot_is_stable_read_only_and_never_modified(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        store.append("message.new", {"sender_id": 10, "text": "First synthetic"}, -1001, 10)
        with store.snapshot() as snapshot:
            head = copy.deepcopy(snapshot.head)
            store.append("message.new", {"sender_id": 20, "text": "After snapshot"}, -1001, 20)
            assert snapshot.connection.execute("PRAGMA query_only").fetchone()[0] == 1
            result = selection.analyze(snapshot, selection.Selection(enabled=True))
            assert result["source"] == {"records":1,"last_seq":head["seq"],"journal_head":head["hash"]}
            assert result["messages"]["total"] == 1 and result["id_gaps"]["rows"] == []
            assert snapshot.connection.execute("PRAGMA query_only").fetchone()[0] == 1
            assert snapshot.connection.execute("SELECT count(*) FROM events").fetchone()[0] == 1
        assert store.db.execute("SELECT count(*) FROM events").fetchone()[0] == 2
        assert not any("selection" in row[0] for row in store.db.execute("SELECT name FROM sqlite_master"))
        assert json.loads(json.dumps(result, allow_nan=False)) == result
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
