import copy
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import report_history, report_selection


def record(seq, kind, text=None, *, chat=-1001, message=1, sender=10, at="2026-11-02T12:00:00Z"):
    return {"seq":seq,"kind":kind,"chat_id":chat,"message_id":message,"actor_id":999,
            "observed_at":at,"payload":{"text":text,"sender_id":sender}}


def test_edit_only_selection_restores_original_outside_date_range():
    events = [record(1,"message.new","Delivery 20 November",at="2026-11-01T12:00:00Z"),
              record(2,"message.edited","Delivery 27 November"),
              record(3,"message.new","UNRELATED",message=2),
              record(4,"message.edited","UNRELATED EDIT",message=2)]
    original = copy.deepcopy(events)
    predicate = report_selection.compile_selection(report_selection.Selection(enabled=True,
        kinds=["message.edited"],date_from="2026-11-02",date_to="2026-11-02"))
    result = report_history.collect(iter(events),{(-1001,1)},predicate=predicate)
    assert list(result) == [(-1001,1)]
    versions = result[(-1001,1)]["versions"]
    assert [row["text"] for row in versions] == ["Delivery 20 November","Delivery 27 November"]
    assert versions[0]["context_only"] and not versions[0]["in_selection"]
    assert not versions[1]["context_only"] and versions[1]["in_selection"]
    assert events == original


def test_delete_only_selection_exposes_saved_text_and_its_source_record():
    events = [record(1,"message.snapshot","Preserved before deletion",at="2026-10-01T00:00:00Z"),
              record(2,"message.deleted",sender=None)]
    predicate = report_selection.compile_selection(report_selection.Selection(enabled=True,kinds=["message.deleted"]))
    item = report_history.collect(iter(events),{(-1001,1)},predicate=predicate)[(-1001,1)]
    assert item["versions"][0]["text"] == "Preserved before deletion"
    assert item["versions"][0]["context_only"]
    assert item["gone"] == [{"seq":2,"kind":"message.deleted","observed_at":"2026-11-02T12:00:00Z",
                             "previous_version_seq":1,"in_selection":True,"context_only":False}]


def test_unseen_deletion_never_invents_a_prior_version():
    events = [record(1,"message.deleted",sender=None), record(2,"message.new","Saved afterwards")]
    item = report_history.collect(iter(events),{(-1001,1)})[(-1001,1)]
    assert item["gone"][0]["previous_version_seq"] is None
    assert item["versions"][0]["seq"] == 2
    missing = report_history.collect(iter(events[:1]),{(-1001,1)})[(-1001,1)]
    assert missing["versions"] == [] and missing["gone"][0]["previous_version_seq"] is None


def test_recheck_preserves_context_and_does_not_claim_a_deletion():
    events = [record(1,"message.new","Previously seen"), record(2,"message.missing_on_recheck",sender=None)]
    item = report_history.collect(iter(events),{(-1001,1)},predicate=lambda row:row["seq"]==2)[(-1001,1)]
    assert item["gone"][0]["kind"] == "message.missing_on_recheck"
    assert item["gone"][0]["previous_version_seq"] == 1


def test_deduplication_does_not_hide_selected_edits_or_selection_changes():
    events = [record(1,"message.new","Same text"), record(2,"message.snapshot","Same text"),
              record(3,"message.edited","Same text"), record(4,"message.snapshot","Same text")]
    item = report_history.collect(iter(events),{(-1001,1)},predicate=lambda row:row["seq"]>=3)[(-1001,1)]
    assert [row["seq"] for row in item["versions"]] == [1,3]
    assert item["versions"][0]["context_only"] and item["versions"][1]["in_selection"]
    selected_snapshot = report_history.collect(iter(events[:2]),{(-1001,1)},predicate=lambda row:row["seq"]==2)[(-1001,1)]
    assert [row["seq"] for row in selected_snapshot["versions"]] == [1,2]


def test_limits_apply_to_groups_without_stopping_later_versions():
    events = [record(1,"message.new","First"), record(2,"message.new","Another",message=2),
              record(3,"message.edited","First revised"),record(4,"message.deleted",message=2)]
    result = report_history.collect(iter(events),{(-1001,1),(-1001,2)},limit=1)
    assert list(result) == [(-1001,1)]
    assert [row["seq"] for row in result[(-1001,1)]["versions"]] == [1,3]
    assert report_history.collect(iter(events),{(-1001,1)},limit=0) == {}
    with pytest.raises(ValueError):
        report_history.collect(iter(events),{(-1001,1)},limit=-1)


def test_other_chats_and_same_message_number_are_not_mixed():
    events = [record(1,"message.new","Correct chat"),record(2,"message.new","Wrong chat",chat=-1002),
              record(3,"message.edited","Correct update"),record(4,"message.deleted",chat=-1002)]
    result = report_history.collect(iter(events),{(-1001,1)})
    assert list(result) == [(-1001,1)]
    assert all(row["text"].startswith("Correct") for row in result[(-1001,1)]["versions"])


def test_participant_count_includes_known_authors_of_selected_edits():
    class Snapshot:
        head = None
        def events(self):
            yield record(1,"message.edited","Only retained edit",sender=10)
            yield record(2,"message.deleted",sender=None)
    data = report_selection.analyze(Snapshot(),report_selection.Selection(enabled=True,kinds=["message.edited"],id_gaps=False))
    assert data["counts"]["participants"] == 1
    assert data["analytics"]["participants"]["total"] == 0


def test_preview_keeps_last_forty_versions_and_notices_with_bounded_text():
    consumed = []

    def events():
        for index in range(80):
            seq = index * 3 + 1
            consumed.append(seq)
            yield record(seq, "message.edited", "\U0001f4ac" * 241)
            yield record(seq + 1, "message.deleted", sender=None)
            yield record(seq + 2, "message.edited", "Unrelated", chat=-1002)

    result = report_history.preview(events(), [(-1001, 1)], predicate=lambda row: row["seq"] % 2 == 0)
    assert len(consumed) == 80
    assert len(result) == 1
    item = result[0]
    assert item["chat_id"] == -1001 and item["message_id"] == 1
    assert item["versions_truncated"] and item["gone_truncated"]
    assert [row["seq"] for row in item["versions"]] == [index * 3 + 1 for index in range(40, 80)]
    assert [row["seq"] for row in item["gone"]] == [index * 3 + 2 for index in range(40, 80)]
    for version, gone in zip(item["versions"], item["gone"], strict=True):
        assert len(version["text"]) == 240 and version["text_truncated"]
        assert gone["previous_version_seq"] == version["seq"]
        assert version["context_only"] == (version["seq"] % 2 != 0)
        assert gone["context_only"] == (gone["seq"] % 2 != 0)


def test_preview_exact_limits_do_not_claim_truncation_or_invent_text():
    events = []
    for index in range(40):
        text = "a" * 240 if index else {"private": "not text"}
        events.extend((record(index * 2 + 1, "message.snapshot", text),
                       record(index * 2 + 2, "message.missing_on_recheck", sender=None)))
    original = copy.deepcopy(events)
    item = report_history.preview(iter(events), [(-1001, 1)], predicate=lambda row: True)[0]
    assert len(item["versions"]) == len(item["gone"]) == 40
    assert not item["versions_truncated"] and not item["gone_truncated"]
    assert item["versions"][0]["text"] == ""
    assert all(not row["text_truncated"] for row in item["versions"])
    assert all(not row["context_only"] for row in item["versions"] + item["gone"])
    assert all(row["kind"] == "message.missing_on_recheck" for row in item["gone"])
    assert events == original


def test_preview_unseen_deletion_does_not_borrow_later_text_or_other_chats():
    events = [record(1, "message.new", "Another chat", chat=-1002),
              record(2, "message.deleted", sender=None),
              record(3, "message.new", "Saved afterwards")]
    item = report_history.preview(iter(events), [(-1001, 1)], predicate=lambda row: row["seq"] == 2)[0]
    assert item["gone"][0]["previous_version_seq"] is None
    assert not item["gone"][0]["context_only"]
    assert item["versions"][0]["seq"] == 3 and item["versions"][0]["context_only"]
    assert report_history.preview(iter(events), [], predicate=lambda row: True) == []


def test_preview_keeps_reference_when_saved_pre_deletion_version_is_outside_preview():
    events = [record(1, "message.new", "Saved before deletion"),
              record(2, "message.deleted", sender=None)]
    events.extend(record(seq, "message.edited", "Later saved content") for seq in range(3, 44))
    item = report_history.preview(iter(events), [(-1001, 1)], predicate=lambda row: row["seq"] == 2)[0]
    assert item["versions_truncated"] and not item["gone_truncated"]
    assert len(item["versions"]) == 40
    assert item["gone"][0]["previous_version_seq"] == 1
    assert all(version["seq"] > 2 for version in item["versions"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__,"-q"]))
