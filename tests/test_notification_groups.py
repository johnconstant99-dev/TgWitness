import json

import pytest

from test_access import HARBOR, OTHER, issue, login, panel as panel
from tgwitness import alerts


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr("tgwitness.store.utcnow", lambda: "2026-10-31T12:30:00.000+00:00")


def failure(store, *, chat_id=HARBOR, operation="recheck", error="TimeoutError"):
    return store.append("collector.error", {"operation": operation, "error_type": error}, chat_id=chat_id)


def test_repeated_problems_group_without_changing_signed_records(journal):
    store, vault = journal
    records = [failure(store) for _ in range(10)]
    before = store.stats()["head"]
    items = alerts.panel_items(store, {})
    assert len(items) == 1
    [item] = items
    assert item["seq"] == records[-1]["seq"] and item["first_seq"] == records[0]["seq"]
    assert item["count"] == item["occurrences"] == 10 and item["count_exact"]
    assert item["at"] == item["last_at"] == records[-1]["observed_at"]
    assert item["first_at"] == records[0]["observed_at"]
    assert item["severity"] == "error" and item["category"] == "collection"
    assert item["action"] == {"type": "diagnostics", "part": "intake"}
    assert store.stats()["head"] == before
    assert len(store.events(kind="collector.error")) == 10
    store.verify(vault.public_key)


def test_identity_uses_ids_and_error_fields_not_display_titles(journal):
    store, _ = journal
    for chat in (HARBOR, OTHER):
        store.set_target(chat, "Same title", "supergroup", True)
    for chat, operation, error in ((HARBOR, "recheck", "TimeoutError"),
                                    (OTHER, "recheck", "TimeoutError"),
                                    (HARBOR, "capture", "TimeoutError"),
                                    (HARBOR, "recheck", "ValueError")):
        for _ in range(2):
            failure(store, chat_id=chat, operation=operation, error=error)
    items = alerts.panel_items(store, {})
    assert len(items) == len({item["group_id"] for item in items}) == 4
    assert all(item["count"] == 2 for item in items)
    translated = alerts.panel_items(store, alerts.i18n.words("ru"))
    assert [item["read_key"] for item in translated] == [item["read_key"] for item in items]
    assert translated[0]["text"] != items[0]["text"]
    other_workspace = alerts.panel_items(store, {}, workspace_id="second")
    assert {item["group_id"] for item in other_workspace}.isdisjoint(item["group_id"] for item in items)


@pytest.mark.parametrize("kind,payload,recovery,recovered", [
    ("storage.low", {"free_bytes": 12}, "storage.ok", {"free_bytes": 10000000000}),
    ("connection.retry_failed", {"attempt": 3, "error_type": "TimeoutError"}, "connection.restored", {}),
    ("replica.completed", {"error": "TimeoutError", "destination": "https://copy.example/bucket"},
     "replica.completed", {"error": None, "destination": "https://copy.example/bucket"}),
    ("anchor.completed", {"results": [{"kind": "rfc3161", "ok": False}]},
     "anchor.completed", {"results": [{"kind": "rfc3161", "ok": True}]}),
])
def test_recovery_separates_problem_episodes_in_the_same_hour(journal, kind, payload, recovery, recovered):
    store, _ = journal
    for _ in range(2):
        store.append(kind, payload)
    store.append(recovery, recovered)
    for _ in range(2):
        store.append(kind, payload)
    items = [i for i in alerts.panel_items(store, {}) if i["level"] == "problem"]
    assert len(items) == 2
    assert [i["count"] for i in items] == [2, 2]
    assert items[0]["group_id"] != items[1]["group_id"]
    assert items[0]["read_key"] == items[1]["read_key"]
    assert items[0]["seq"] > items[1]["seq"]


def test_destinations_and_timestamp_failures_do_not_merge(journal):
    store, _ = journal
    for destination in ("https://a.example/bucket", "https://b.example/bucket"):
        for _ in range(2):
            store.append("replica.completed", {"error": "TimeoutError", "destination": destination})
    for received in (False, True):
        for _ in range(2):
            store.append("anchor.completed", {"results": [{"kind": "rfc3161", "received": received, "ok": False}]})
    items = alerts.panel_items(store, {})
    assert len(items) == 4 and all(i["count"] == 2 for i in items)
    assert len({i["group_id"] for i in items}) == 4


def test_same_utc_hour_groups_across_offset_spellings_and_splits_next_hour(journal, monkeypatch):
    store, _ = journal
    for at in ("2026-10-31T12:10:00+00:00", "2026-10-31T13:40:00+01:00", "2026-10-31T13:01:00+00:00"):
        monkeypatch.setattr("tgwitness.store.utcnow", lambda at=at: at)
        failure(store)
    items = alerts.panel_items(store, {})
    assert len(items) == 2 and [i["count"] for i in items] == [1, 2]
    assert items[1]["first_at"] == "2026-10-31T12:10:00+00:00"
    assert items[1]["last_at"] == "2026-10-31T13:40:00+01:00"


def test_scope_is_applied_before_query_limits_for_every_notice_family(journal):
    store, _ = journal
    store.set_target(HARBOR, "Visible", "supergroup", True)
    store.set_target(OTHER, "SECRET HIDDEN", "supergroup", True)
    failure(store)
    store.append("message.edited", {}, chat_id=HARBOR, message_id=1)
    store.append("source.discovered", {"title": "Visible"}, chat_id=HARBOR)
    for i in range(8):
        failure(store, chat_id=OTHER, operation="SECRET OP " + str(i))
        store.append("storage.low", {"free_bytes": 1})
        store.append("source.discovered", {"title": "SECRET DISCOVERY"}, chat_id=OTHER)
        store.append("message.edited", {}, chat_id=OTHER, message_id=i)
    rows = store.events_of(("collector.error",), limit=1, chat_ids={HARBOR})
    assert len(rows) == 1 and rows[0]["chat_id"] == HARBOR
    assert store.events_of(("collector.error",), chat_ids=set()) == []
    items = alerts.panel_items(store, {}, limit=3, allowed_chats={HARBOR})
    assert {i["kind"] for i in items} == {"collector.error", "message.edited", "source.discovered"}
    assert {i["chat_id"] for i in items} == {HARBOR}
    assert "SECRET" not in json.dumps(items)
    assert alerts.panel_items(store, {}, allowed_chats=set()) == []


def test_api_scope_precedes_global_problem_priority_and_limit(panel):
    app, admin = panel
    store = app.state.store
    visible = failure(store)
    for _ in range(65):
        store.append("export.failed", {"format": "SECRET"})
        store.append("chat_export.interrupted", {"error_type": "SECRET"}, chat_id=OTHER)
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    browser, result = login(app, token)
    assert result.status_code == 200
    response = browser.get("/api/notifications")
    assert response.status_code == 200
    [item] = response.json()["items"]
    assert item["seq"] == visible["seq"] and item["count"] == 1
    assert "SECRET" not in response.text


def test_hidden_recovery_does_not_change_visible_group_identity(journal):
    store, _ = journal
    args = ("connection.retry_failed", {"attempt": 3, "error_type": "TimeoutError"})
    store.append(*args, chat_id=HARBOR)
    store.append("connection.restored", {}, chat_id=OTHER)
    store.append(*args, chat_id=HARBOR)
    [item] = alerts.panel_items(store, {}, allowed_chats={HARBOR})
    assert item["count"] == 2


def test_bounded_group_counts_are_lower_bounds_and_read_key_survives(journal, monkeypatch):
    store, _ = journal
    monkeypatch.setattr(alerts, "PROBLEM_PAGES", 1)
    for _ in range(8):
        failure(store)
    [first] = alerts.panel_items(store, {}, limit=1)
    assert first["count"] == first["scan_limit"] == 5 and not first["count_exact"]
    last = failure(store)
    [later] = alerts.panel_items(store, {}, limit=1)
    assert later["read_key"] == first["read_key"] and later["seq"] == last["seq"]
    assert later["seq"] > first["seq"]


def test_limited_change_scan_never_claims_a_complete_chat_total(journal, monkeypatch):
    store, _ = journal
    monkeypatch.setattr(alerts, "CHANGE_SCAN", 3)
    store.set_target(HARBOR, "Harbor", "supergroup", True)
    for message in range(5):
        store.append("message.deleted", {}, chat_id=HARBOR, message_id=message)
    [item] = alerts.panel_items(store, {})
    assert item["count"] == item["records"] == item["scan_limit"] == 3
    assert not item["count_exact"]
    assert item["text"] == "Recent changes in Harbor"


def test_reconnect_milestones_and_distinct_user_export_attempts_are_preserved(journal):
    store, _ = journal
    for attempt in (1, 2, 3, 4, 19, 20, 21, 40):
        store.append("connection.retry_failed", {"attempt": attempt, "error_type": "TimeoutError"})
    for _ in range(2):
        store.append("export.failed", {"format": "zip", "error_type": "OSError"})
    items = alerts.panel_items(store, {})
    assert len(items) == 3
    exports = [i for i in items if i["kind"] == "export.failed"]
    assert len(exports) == 2 and all(i["count"] == 1 for i in exports)
    [reconnect] = [i for i in items if i["kind"] == "connection.retry_failed"]
    assert reconnect["count"] == 3 and "40 reconnect attempts" in reconnect["text"]
    assert reconnect["action"] == {"type": "diagnostics", "part": "connection"}


def test_event_scope_composes_with_sequence_bounds_and_unrestricted_calls(journal):
    store, _ = journal
    records = [failure(store, chat_id=chat) for chat in (HARBOR, OTHER, HARBOR, OTHER, HARBOR)]
    rows = store.events_of(("collector.error",), after=records[0]["seq"], before=records[-1]["seq"],
                           chat_ids={HARBOR})
    assert [r["seq"] for r in rows] == [records[2]["seq"]]
    assert len(store.events_of(("collector.error",))) == 5
    assert store.events_of((), chat_ids={HARBOR}) == []


def test_host_and_start_records_remain_individual_and_benign_changes_stay_quiet(journal):
    store, vault = journal
    quiet = {"ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 0}
    store.append("process.started", {"run": {"run_id": "one"}})
    store.append("process.started", {"run": {"run_id": "two"}})
    store.append("host.state", {"before": quiet, **quiet, "wtmp_sha256": "a" * 64})
    for _ in range(2):
        store.append("host.state", {"before": quiet, **quiet, "sessions": 1, "logins": 1})
    before = store.stats()["head"]
    items = alerts.panel_items(store, {})
    assert len(items) == 2 and all(i["kind"] == "host.state" and i["count"] == 1 for i in items)
    assert all(i["category"] == "server" and i["action"]["part"] == "server" for i in items)
    assert store.stats()["head"] == before and len(store.events(kind="process.started")) == 2
    store.verify(vault.public_key)


def test_missing_or_old_optional_payload_fields_cannot_break_the_list(journal):
    store, _ = journal
    store.append("export.failed", {"format": {"old": "value"}})
    store.append("anchor.completed", {"results": ["old-value"]})
    store.append("host.state", {"before": "old-value", "ssh_processes": "unknown"})
    items = alerts.panel_items(store, {})
    assert len(items) == 3 and all(isinstance(i["text"], str) and i["text"] for i in items)
    assert all(i["action"]["type"] in ("record", "diagnostics") for i in items)


def test_changes_keep_backward_compatible_counts_and_exact_chat_actions(journal):
    store, _ = journal
    store.set_target(HARBOR, "Same name", "supergroup", True)
    store.set_target(OTHER, "Same name", "supergroup", True)
    store.append("message.deleted", {}, chat_id=HARBOR, message_id=1)
    store.append("message.edited", {}, chat_id=HARBOR, message_id=2)
    store.append("source.discovered", {"title": "Same name"}, chat_id=OTHER)
    items = alerts.panel_items(store, {})
    assert len(items) == 2
    change = next(i for i in items if i["chat_id"] == HARBOR)
    assert change["records"] == change["count"] == 2
    assert change["action"] == {"type": "chat", "chat_id": HARBOR}
    assert items[0]["action"] == {"type": "chat", "chat_id": OTHER}
    assert items[0]["group_id"] != change["group_id"]
