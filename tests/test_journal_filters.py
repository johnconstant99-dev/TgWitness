from datetime import datetime, timezone

from test_access import HARBOR, OTHER, issue, login, panel as panel


def test_type_groups_combine_before_source_date_search_and_cursor_limits(panel, monkeypatch):
    app, admin = panel
    store = app.state.store
    for index, kind in enumerate(("message.new", "message.edited", "media.saved", "membership.update", "collector.error")):
        monkeypatch.setattr("tgwitness.store.utcnow", lambda index=index: f"2026-10-30T12:0{index}:00.000+00:00")
        for chat in (HARBOR, OTHER):
            store.append(kind, {"text": "Invoice review"}, chat, index)
    since = datetime(2026, 10, 30, 12, 1, tzinfo=timezone.utc)
    until = datetime(2026, 10, 30, 12, 4, tzinfo=timezone.utc)
    result = store.events(kind="messages,message.edited,media,coverage", chat_ids={HARBOR},
                          since=since, until=until, search="invoice", limit=2)
    assert [record["kind"] for record in result] == ["collector.error", "media.saved"]
    rest = store.events(kind="messages,message.edited,media,coverage", chat_ids={HARBOR},
                        since=since, until=until, search="invoice", before=result[-1]["seq"], limit=2)
    assert [record["kind"] for record in rest] == ["message.edited"]
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    client, _ = login(app, token)
    response = client.get("/api/events", params={"kind": "membership,media", "search": "invoice"})
    assert response.status_code == 200, response.text
    assert {record["kind"] for record in response.json()["events"]} == {"membership.update", "media.saved"}
    assert all(record["chat_id"] == HARBOR for record in response.json()["events"])
    assert client.get("/api/events", params={"kind": "media", "chat_id": OTHER}).status_code == 403


def test_journal_filter_validation_and_exact_custom_event_kind(panel):
    app, admin = panel
    record = app.state.store.append("custom.saved", {}, HARBOR)
    assert admin.get("/api/events", params={"kind": "custom.saved"}).json()["events"][0]["seq"] == record["seq"]
    for kind in ("x" * 301, ",".join(["media"] * 17)):
        assert admin.get("/api/events", params={"kind": kind}).status_code == 422
    for dates in ({"since": "2026-10-30T12:00:00"}, {"since": "invalid"},
                  {"since": "2026-10-31T00:00:00Z", "until": "2026-10-30T00:00:00Z"}):
        assert admin.get("/api/events", params=dates).status_code == 422
