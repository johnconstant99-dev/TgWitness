import time

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from tgwitness import access
from tgwitness.app import create_app
from test_collector import FakeClient

HARBOR, OTHER = -1001, -1002

NOT_IN_POLICY = {
    "POST /api/network/sources", "POST /api/network/sources/list",
    "GET /locale.js", "GET /api/demo-access", "GET /api/witness/head", "GET /api/assurance",
    "POST /api/access/login", "POST /api/access/logout", "GET /api/access/me",
    "POST /api/profiles", "PATCH /api/profiles/{profile_id}", "DELETE /api/profiles/{profile_id}",
    "POST /api/profiles/import", "PUT /api/profiles/{profile_id}/group", "POST /api/profile-groups",
    "PATCH /api/profile-groups/{group_id}", "DELETE /api/profile-groups/{group_id}",
    "POST /api/profile-groups/{group_id}/apply",
    "GET /api/access", "POST /api/access/grants", "PATCH /api/access/grants/{grant_id}",
    "DELETE /api/access/grants/{grant_id}", "DELETE /api/access/sessions/{session_id}",
    "POST /api/access/admin", "GET /api/access/console",
    "GET /api/integrations/mcp", "POST /api/integrations/mcp", "DELETE /api/integrations/mcp/{connection_id}",
    "POST /api/integrations/mcp/check",
    "GET /api/archive/identity", "POST /api/archive/query",
    "POST /api/analysis/provider", "POST /api/analysis/provider/test",
    "GET /api/integrations/webhooks", "POST /api/integrations/webhooks",
    "DELETE /api/integrations/webhooks/{hook_id}", "POST /api/integrations/webhooks/{hook_id}/test",
}


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        store = app.state.store
        for chat_id, title in ((HARBOR, "Harbor"), (OTHER, "Other")):
            store.set_target(chat_id, title, "supergroup", True)
            store.append("message.new", {"text": title + " text", "sender_id": 7}, chat_id=chat_id, message_id=1)
        yield app, client


def issue(client, **settings):
    body = {"label": "Observer", "workspaces": {"default": None}, **settings}
    result = client.post("/api/access/grants", json=body)
    assert result.status_code == 200, result.text
    return result.json()["token"], result.json()["id"]


def login(app, token, address="testclient"):
    """A separate browser: signs in with the token and keeps only the session."""
    browser = TestClient(app, client=(address, 50000))
    result = browser.post("/api/access/login", json={"token": token})
    if result.status_code == 200:
        browser.headers["Authorization"] = "Bearer " + result.json()["session"]
    return browser, result


def test_every_route_has_a_rule_or_is_deliberately_outside_them(panel):
    app, _ = panel
    routes = {m + " " + r.path for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    assert set(access.POLICY) <= routes
    assert routes - set(access.POLICY) == NOT_IN_POLICY


def test_panel_token_signs_in_to_a_session_that_can_be_listed_and_ended(panel):
    app, client = panel
    browser, result = login(app, app.state.vault.token)
    assert result.status_code == 200 and result.json()["me"]["admin"]
    session = result.json()["session"]
    assert session.startswith("tgws_") and app.state.vault.token not in session
    assert browser.get("/api/status").status_code == 200
    listed = client.get("/api/access").json()["sessions"]
    assert [s["admin"] for s in listed] == [True]
    assert app.state.store.events(kind="access.session_started")[0]["payload"]["label"] == "Main administrator"
    assert browser.post("/api/access/logout").status_code == 200
    assert browser.get("/api/status").status_code == 401
    assert app.state.store.events(kind="access.session_ended")[0]["payload"]["reason"] == "signed out"

    token, _ = issue(client)
    assert TestClient(app).get("/api/status", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert login(app, "tgwa_wrong")[1].status_code == 401


def test_an_issued_token_is_shown_once_and_journaled_without_it(panel):
    app, client = panel
    token, grant_id = issue(client, label="Lawyer", permissions=["export"])
    state = client.get("/api/access").json()
    assert token not in str(state) and "sha256" not in str(state["grants"])
    assert state["grants"][0]["permissions"] == ["view", "export"]
    record = app.state.store.events(kind="access.granted")[0]["payload"]
    assert record["access_id"] == grant_id and record["label"] == "Lawyer"
    assert token not in str(record) and access.digest(token) not in str(record)
    assert token not in (app.state.vault.root / "access.enc").read_text()


def test_a_read_only_access_reads_but_changes_nothing(panel):
    app, client = panel
    token, _ = issue(client)
    browser, _ = login(app, token)
    assert browser.get("/api/status").status_code == 200
    assert len(browser.get("/api/events").json()["events"]) >= 2
    assert browser.get("/api/access/me").json()["permissions"] == ["view"]
    for method, path, body in (("post", "/api/collector/start", {}), ("get", "/api/export/zip", None),
                               ("post", "/api/capture", {}), ("get", "/api/dialogs", None),
                               ("post", "/api/profiles", {"label": "x"}), ("get", "/api/access", None),
                               ("get", "/api/access/console", None), ("post", "/api/auth/logout", None)):
        response = getattr(browser, method)(path, **({"json": body} if body is not None else {}))
        assert response.status_code == 403, (path, response.text)
    assert "allow" in browser.post("/api/collector/start", json={}).json()["detail"]
    refused = [line["text"] for line in app.state.access.console.after(0) if "→ 403" in line["text"]]
    assert any("Observer · POST /api/collector/start" in text for text in refused)


def test_an_access_to_one_chat_sees_only_that_chat(panel):
    app, client = panel
    app.state.store.append("media.saved", {"media_sha256": "a" * 64}, chat_id=OTHER, message_id=1)
    (app.state.vault.root / "media").mkdir(exist_ok=True)
    (app.state.vault.root / "media" / ("a" * 64)).write_bytes(b"file")
    token, _ = issue(client, workspaces={"default": [HARBOR]}, permissions=["export", "sources"])
    browser, _ = login(app, token)
    status = browser.get("/api/status").json()
    assert [t["chat_id"] for t in status["targets"]] == [HARBOR] and status["chats_limited"]
    assert status["stats"]["counts"] == {"message.new": 1}
    assert {e["chat_id"] for e in browser.get("/api/events").json()["events"]} == {HARBOR}
    assert [c["chat_id"] for c in browser.get("/api/chats").json()["chats"]] == [HARBOR]
    assert browser.get("/api/chats/%d/messages" % HARBOR).status_code == 200
    for path in ("/api/chats/%d/messages" % OTHER, "/api/events?chat_id=%d" % OTHER):
        assert browser.get(path).status_code == 403, path
    assert browser.get("/api/media/" + "a" * 64).status_code == 404
    assert client.get("/api/media/" + "a" * 64).status_code == 200
    assert browser.get("/api/avatar/7").status_code != 403
    assert browser.get("/api/avatar/99").status_code == 404
    assert browser.post("/api/chat-export/start", json={"chat_id": OTHER}).status_code == 403
    assert browser.post("/api/targets", json={"chat_id": OTHER, "enabled": False}).status_code == 403

    for path in ("/api/export/zip", "/api/dialogs", "/api/scope", "/api/parameters"):
        assert browser.get(path).status_code == 403, path
    assert browser.post("/api/interactions", json={"request_id": "r" * 16, "action": "open",
                                                   "preview_id": "a" * 32}).status_code == 403


def test_workspaces_open_only_where_the_access_names_them(panel):
    app, client = panel
    profile = client.post("/api/profiles", json={"label": "Second"}).json()["id"]
    token, _ = issue(client, workspaces={profile: None})
    browser, _ = login(app, token)
    assert [p["id"] for p in browser.get("/api/profiles").json()["profiles"]] == [profile]
    assert browser.get("/profiles/" + profile + "/api/status").status_code == 200
    assert browser.get("/api/status").status_code == 403
    assert client.post("/api/access/grants", json={"label": "x", "workspaces": {"f" * 32: None}}).status_code == 422
    everywhere, _ = issue(client, workspaces={}, all_workspaces=True)
    browser, _ = login(app, everywhere)
    assert len(browser.get("/api/profiles").json()["profiles"]) == 2


def test_address_binding_sign_in_limit_and_end_date(panel, monkeypatch):
    app, client = panel
    subnet, _ = issue(client, ips=["203.0.113.0/24"])
    assert login(app, subnet, "198.51.100.1")[1].status_code == 403
    browser, result = login(app, subnet, "203.0.113.9")
    assert result.status_code == 200
    first, _ = issue(client, bind_first_ip=True, max_sessions=5)
    assert login(app, first, "203.0.113.1")[1].status_code == 200
    assert login(app, first, "203.0.113.2")[1].status_code == 403
    assert login(app, first, "203.0.113.1")[1].status_code == 200
    once, _ = issue(client, max_uses=1)
    assert login(app, once)[1].status_code == 200
    assert "times" in login(app, once)[1].json()["detail"]
    assert client.post("/api/access/grants", json={"label": "x", "workspaces": {"default": None},
                                                   "expires_at": time.time() - 1}).status_code == 422
    dated, _ = issue(client, expires_at=time.time() + 3600)
    browser, _ = login(app, dated)
    assert browser.get("/api/status").status_code == 200
    later = time.time() + 7200
    monkeypatch.setattr(access.time, "time", lambda: later)
    assert browser.get("/api/status").json()["detail"] == "This access has expired."
    assert browser.get("/api/status").status_code == 401
    assert login(app, dated)[1].status_code == 403


def test_parallel_session_limit_refuses_or_replaces(panel):
    app, client = panel
    strict, _ = issue(client, max_sessions=1, on_limit="refuse")
    first, _ = login(app, strict)
    assert "sessions" in login(app, strict)[1].json()["detail"]
    assert first.get("/api/status").status_code == 200
    rolling, grant_id = issue(client, max_sessions=1, on_limit="replace")
    old, _ = login(app, rolling)
    new, _ = login(app, rolling)
    assert old.get("/api/status").status_code == 401 and new.get("/api/status").status_code == 200
    session = next(s for s in client.get("/api/access").json()["sessions"] if s["access_id"] == grant_id)
    assert client.delete("/api/access/sessions/" + session["id"]).status_code == 200
    assert new.get("/api/status").status_code == 401
    assert client.post("/api/access/admin", json={"max_sessions": 1, "on_limit": "refuse"}).status_code == 200
    assert login(app, app.state.vault.token)[1].status_code == 200
    assert login(app, app.state.vault.token)[1].status_code == 403
    assert client.get("/api/status").status_code == 200


def test_changes_and_revocation_apply_to_open_sessions(panel):
    app, client = panel
    token, grant_id = issue(client, max_sessions=3)
    browser, _ = login(app, token)
    assert browser.post("/api/collector/stop").status_code == 403
    body = {"label": "Observer", "workspaces": {"default": None}, "permissions": ["collect"], "max_sessions": 3}
    assert client.patch("/api/access/grants/" + grant_id, json=body).status_code == 200
    assert browser.post("/api/collector/stop").status_code == 200
    assert app.state.store.events(kind="access.changed")[0]["payload"]["permissions"] == ["view", "collect"]
    assert client.delete("/api/access/grants/" + grant_id).status_code == 200
    assert browser.get("/api/status").status_code == 401
    assert login(app, token)[1].status_code == 401
    assert app.state.store.events(kind="access.revoked")[0]["payload"]["access_id"] == grant_id


def test_sessions_survive_a_restart(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        session = client.post("/api/access/login", json={"token": app.state.vault.token}).json()["session"]
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        assert client.get("/api/status", headers={"Authorization": "Bearer " + session}).status_code == 200


def test_console_shows_the_process_log_and_journal_records_of_every_workspace(panel):
    app, client = panel
    assert client.post("/api/profiles", json={"label": "Second"}).status_code == 200
    issue(client, label="Auditor")
    result = client.get("/api/access/console").json()
    texts = [line["text"] for line in result["lines"]]
    assert any("Access Auditor issued" in t for t in texts)
    assert any(t.startswith("Main account · #") and "process.started" in t for t in texts)
    assert any(t.startswith("Second · #") and "process.started" in t for t in texts)
    assert not any("message.new" in t or "Harbor text" in t for t in texts)
    newer = client.get("/api/access/console?after=%d" % result["last"]).json()["lines"]
    assert all(line["n"] > result["last"] for line in newer)
    assert client.get("/api/access/console?after=99999999").json()["lines"]
