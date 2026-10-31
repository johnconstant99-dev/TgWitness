from fastapi.testclient import TestClient

from tgwitness.app import create_app
from tgwitness.panel_routes import DOCUMENTS


def test_document_refresh_returns_the_same_shell_and_security_headers(tmp_path):
    client = TestClient(create_app(tmp_path))
    root = client.get("/")
    assert root.status_code == 200
    paths = (*DOCUMENTS, "/chats/-1001234567890", "/chats/42", "/journal/event/73")
    for path in paths:
        response = client.get(path + "?ws=private-workspace&event=919&lang=de")
        assert response.status_code == 200, (path, response.text)
        assert response.content == root.content
        assert "private-workspace" not in response.text
        for header in ("content-type", "content-security-policy", "cache-control",
                       "x-content-type-options", "x-frame-options", "referrer-policy"):
            assert response.headers[header] == root.headers[header], (path, header)
        head = client.head(path)
        assert head.status_code == 200 and not head.content
        assert head.headers["content-length"] == root.headers["content-length"]


def test_panel_routes_do_not_swallow_apis_assets_or_unknown_documents(tmp_path):
    client = TestClient(create_app(tmp_path))
    for path in (
        "/api/no-such-api", "/api/chats/42/unknown", "/missing.js", "/missing.svg",
        "/assets/missing.css", "/chats/42/missing.js", "/journal/event/73/anything",
        "/extras/unknown", "/unknown", "/system-log/no", "/panel-token.txt",
        "/journal/event/0", "/journal/event/-1", "/journal/event/not-a-number",
        "/journal/event/9223372036854775808", "/chats/0", "/chats/name",
        "/chats/１２３", "/chats/42.json", "/chats/%2e%2e", "/chats/%2fetc",
        "/extras/%2e%2e/panel-token.txt", "/%2e%2e/panel-token.txt",
    ):
        response = client.get(path)
        assert response.status_code == 404, (path, response.status_code)
        assert "<html" not in response.text.lower()
    assert client.get("/style.css").status_code == 200
    assert client.get("/api/status?ws=default").status_code == 401
    assert client.get("/api/events?ws=default").status_code == 401
    assert client.post("/chats/42", json={}).status_code == 405


def test_journal_url_dates_are_validated_and_keep_inclusive_boundaries_and_scope(tmp_path, monkeypatch):
    from tgwitness import store
    from test_access import issue, login
    from test_collector import FakeClient

    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        for number, at in enumerate(("2026-10-30T23:59:59.999+00:00",
                                     "2026-10-31T00:00:00.000+00:00",
                                     "2026-10-31T00:00:00.001+00:00"), 1):
            with monkeypatch.context() as clock:
                clock.setattr(store, "utcnow", lambda: at)
                app.state.store.append("message.new", {"text": "record"}, chat_id=-1001, message_id=number)
                app.state.store.append("message.new", {"text": "private"}, chat_id=-1002, message_id=number)
        token, _ = issue(client, workspaces={"default": [-1001]})
        scoped, result = login(app, token)
        assert result.status_code == 200
        params = {"kind": "message.new", "since": "2026-10-30T17:00:00-07:00",
                  "until": "2026-10-31T01:00:00+01:00"}
        response = scoped.get("/api/events", params=params)
        assert response.status_code == 200, response.text
        records = response.json()["events"]
        assert [(r["chat_id"], r["message_id"]) for r in records] == [(-1001, 2)]
        assert [r["message_id"] for r in scoped.get("/api/events", params={
            "kind": "message.new", "until": "2026-10-31T00:00:00Z"}).json()["events"]] == [2, 1]
        assert [r["message_id"] for r in scoped.get("/api/events", params={
            "kind": "message.new", "since": "2026-10-31T00:00:00Z"}).json()["events"]] == [3, 2]
        for field in ("since", "until"):
            for value in ("", "yesterday", "1793404800", "2026-10-31", "2026-10-31T00:00:00",
                          "2026-10-99T00:00:00Z", "x" * 65, "0001-01-01T00:00:00+23:00"):
                assert scoped.get("/api/events", params={field: value}).status_code == 422, (field, value)
        assert scoped.get("/api/events", params={
            "since": "2026-11-01T00:00:00Z", "until": "2026-10-31T00:00:00Z"}).status_code == 422
