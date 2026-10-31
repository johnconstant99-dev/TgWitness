from test_access import HARBOR, OTHER, issue, login, panel as panel


def test_journal_windows_move_both_directions_without_gaps_or_unbounded_append(panel):
    app, admin = panel
    for index in range(19):
        app.state.store.append("message.new", {"text": f"Invoice {index}"}, HARBOR, index+10)
    filters = {"kind": "messages", "chat_id": HARBOR, "limit": 5, "include_count": "true"}
    first = admin.get("/api/events", params=filters).json()
    assert first["matched"] == 20 and first["count_exact"] is True
    assert first["next_after"] is None and len(first["events"]) == 5
    second = admin.get("/api/events", params={**filters, "before": first["next_before"]}).json()
    back = admin.get("/api/events", params={**filters, "after": second["next_after"]}).json()
    assert [event["hash"] for event in back["events"]] == [event["hash"] for event in first["events"]]
    seen = [event["seq"] for event in first["events"]]
    page = first
    while page["next_before"] is not None:
        page = admin.get("/api/events", params={**filters, "before": page["next_before"]}).json()
        assert 0 < len(page["events"]) <= 5
        seen.extend(event["seq"] for event in page["events"])
    assert len(seen) == len(set(seen)) == 20
    assert len(page["events"]) == 5  # No extra empty page for an exact multiple of the window size.


def test_filtered_counts_and_newer_queries_respect_chat_scope(panel):
    app, admin = panel
    for chat in (HARBOR, OTHER):
        for index in range(8):
            app.state.store.append("message.edited", {"text": "invoice query"}, chat, index)
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    client, _ = login(app, token)
    query = {"kind": "message.edited", "search": "invoice", "include_count": "true", "limit": 3, "after": 1}
    result = client.get("/api/events", params=query).json()
    assert result["matched"] == 8 and len(result["events"]) == 3
    assert all(record["chat_id"] == HARBOR for record in result["events"])
    assert client.get("/api/events", params={**query, "chat_id": OTHER}).status_code == 403


def test_count_timeout_does_not_discard_readable_window_and_cursors_are_validated(panel, monkeypatch):
    app, admin = panel
    def busy_count(**kwargs):
        raise TimeoutError("Synthetic slow count")
    monkeypatch.setattr(app.state.store, "count_events", busy_count)
    response = admin.get("/api/events", params={"include_count": "true", "limit": 1})
    assert response.status_code == 200 and len(response.json()["events"]) == 1
    assert response.json()["matched"] is None and response.json()["count_exact"] is False
    for query in ({"before": 2, "after": 1}, {"before": -1}, {"after": 2**53}):
        assert admin.get("/api/events", params=query).status_code == 422
