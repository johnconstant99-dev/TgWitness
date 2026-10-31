"""Source mutations must not return chats outside the caller's access."""
import pytest

from test_access import HARBOR, OTHER, issue, login, panel as panel


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/targets", {"chat_id": HARBOR, "enabled": False}),
    ("post", "/api/targets/priority", {"chat_id": HARBOR, "priority": True}),
    ("delete", f"/api/targets/{HARBOR}", None),
    ("post", f"/api/chats/{HARBOR}/dossier", {"enabled": True}),
])
def test_source_changes_return_only_authorized_chats(panel, method, path, body):
    app, admin = panel
    app.state.store.set_setting("dossiers", {str(OTHER): True})
    token, _ = issue(admin, workspaces={"default": [HARBOR]}, permissions=["sources"])
    browser, _ = login(app, token)
    response = getattr(browser, method)(path, **({"json": body} if body is not None else {}))
    assert response.status_code == 200, response.text
    payload = response.json()
    if "targets" in payload:
        assert all(target["chat_id"] == HARBOR for target in payload["targets"])
    if "dossiers" in payload:
        assert payload["dossiers"] == [HARBOR]
    assert str(OTHER) not in response.text
    assert any(target["chat_id"] == OTHER for target in app.state.store.targets())
    assert app.state.store.verify(app.state.vault.public_key)


def test_admin_source_changes_keep_the_full_target_list(panel):
    _, admin = panel
    response = admin.post("/api/targets/priority", json={"chat_id": HARBOR, "priority": True})
    assert {target["chat_id"] for target in response.json()["targets"]} == {HARBOR, OTHER}
