import base64
import asyncio
import os

import pytest

from fastapi.testclient import TestClient

from tgwitness.account_import import string_session
from tgwitness.app import create_app
from test_collector import FakeClient


def session_file(name="account.txt"):
    text = string_session(2, os.urandom(256))
    return {"name": name, "content": base64.b64encode(text.encode()).decode()}


def panel(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    client = TestClient(app)
    client.__enter__()
    client.headers["Authorization"] = "Bearer " + app.state.vault.token
    return app, client


def test_bulk_import_gives_each_account_a_workspace_in_a_group_and_rolls_back_failures(tmp_path):
    app, client = panel(tmp_path)
    try:
        group = client.post("/api/profile-groups", json={"label": "Scam monitors"}).json()["groups"][0]["id"]
        first = client.post("/api/profiles/import", json={"files": [session_file("alpha.session.txt")], "group": group,
                                                          "api_id": 501, "api_hash": "a" * 32})
        assert first.status_code == 200, first.text
        assert first.json()["account"]["id"] == 501 and first.json()["profile"]["label"] == "alpha.session"
        second = client.post("/api/profiles/import", json={"files": [session_file()], "group": group, "label": "Beta",
                                                           "api_id": 502, "api_hash": "b" * 32})
        assert second.status_code == 200, second.text
        duplicate = client.post("/api/profiles/import", json={"files": [session_file()], "group": group,
                                                              "api_id": 501, "api_hash": "a" * 32})
        assert duplicate.status_code == 400 and "Not imported" in duplicate.text
        listed = client.get("/api/profiles").json()["profiles"]
        assert sorted(p["label"] for p in listed) == ["Beta", "Main account", "alpha.session"]
        groups = client.get("/api/profile-groups").json()["groups"]
        assert len(groups[0]["members"]) == 2
        assert client.post("/api/profiles/import", json={"files": [{"name": "x.txt", "content": "bm90IGEgc2Vzc2lvbg=="}]}
                           ).status_code == 400
        reader = client.post("/api/witness/tokens", json={"label": "Read only"}).json()["token"]
        assert client.post("/api/profiles/import", json={"files": [session_file()]},
                           headers={"Authorization": "Bearer " + reader}).status_code == 401
    finally:
        client.__exit__(None, None, None)


def test_group_settings_come_from_the_template_and_each_member_journals_them(tmp_path):
    app, client = panel(tmp_path)
    try:
        members = [client.post("/api/profiles", json={"label": name}).json()["id"] for name in ("One", "Two")]
        assert client.post("/api/parameters", json={"values": {"snapshot_max": 777}}).status_code == 200
        assert client.post("/api/report-options", json={"case_id": "PD-1", "language": "ru"}).status_code == 200
        group = client.post("/api/profile-groups", json={"label": "Team", "template": "default",
                                                        "sections": ["parameters", "reports"]}).json()["groups"][0]
        for profile_id in ["default", *members]:
            assert client.put("/api/profiles/" + profile_id + "/group", json={"group": group["id"]}).status_code == 200
        applied = client.post("/api/profile-groups/" + group["id"] + "/apply", json={}).json()
        assert {r["status"] for r in applied["results"]} == {"applied"} and len(applied["results"]) == 2
        for profile_id in members:
            prefix = "/profiles/" + profile_id + "/api"
            values = {p["key"]: p["value"] for group_ in client.get(prefix + "/parameters").json()["groups"]
                      for p in group_["items"]}
            assert values["snapshot_max"] == 777
            assert client.get(prefix + "/report-options").json()["case_id"] == "PD-1"
            events = client.get(prefix + "/events?kind=group.settings_applied").json()["events"]
            assert events and events[0]["payload"]["sections"] == ["parameters", "reports"]
        assert client.post("/api/profile-groups", json={"label": "Bad", "sections": ["secrets"]}).status_code == 400
        assert client.delete("/api/profile-groups/" + group["id"]).status_code == 200
        assert all(p["group"] is None for p in client.get("/api/profiles").json()["profiles"])
    finally:
        client.__exit__(None, None, None)


def test_group_list_only_shows_granted_members_and_template_can_be_cleared(tmp_path):
    app, client = panel(tmp_path)
    try:
        child = client.post("/api/profiles", json={"label": "Private account"}).json()["id"]
        group = client.post("/api/profile-groups", json={"label": "Shared", "template": child}).json()["groups"][0]
        for pid in ("default", child):
            client.put("/api/profiles/" + pid + "/group", json={"group": group["id"]})
        client.post("/api/profile-groups", json={"label": "Private group"})
        grant = client.post("/api/access/grants", json={"label": "Reader", "workspaces": {"default": None}}).json()
        session = client.post("/api/access/login", json={"token": grant["token"]}).json()["session"]
        result = client.get("/api/profile-groups", headers={"Authorization": "Bearer " + session})
        assert result.status_code == 200
        visible = result.json()["groups"]
        assert len(visible) == 1 and visible[0]["members"] == ["default"] and visible[0]["template"] is None
        assert child not in result.text and "Private group" not in result.text
        updated = client.patch("/api/profile-groups/" + group["id"], json={"label": "Shared", "template": None})
        assert updated.json()["groups"][0]["template"] is None
        assert client.post("/api/profile-groups", json={"label": "  "}).status_code == 400
    finally:
        client.__exit__(None, None, None)


def test_cancelled_import_removes_the_incomplete_workspace(tmp_path, monkeypatch):
    from tgwitness.app import ProfileImport
    from tgwitness.collector import Collector

    async def scenario():
        app = create_app(tmp_path, client_factory=FakeClient)
        async with app.router.lifespan_context(app):
            started = asyncio.Event()

            async def wait_for_login(self, *args):
                started.set()
                await asyncio.Event().wait()

            monkeypatch.setattr(Collector, "configure", wait_for_login)
            endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", None) == "/api/profiles/import")
            task = asyncio.create_task(endpoint(ProfileImport(files=[session_file()], api_id=501, api_hash="a" * 32)))
            await asyncio.wait_for(started.wait(), 5)
            assert len(app.state.profiles.entries) == 2
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert list(app.state.profiles.entries) == ["default"]
            assert app.state.store.get_setting("profiles") == []
            assert not list((tmp_path / "profiles").iterdir())

    asyncio.run(scenario())


def test_group_copies_default_ip_policy_without_copying_sessions(tmp_path):
    app, client = panel(tmp_path)
    try:
        child = client.post("/api/profiles", json={"label": "Member"}).json()["id"]
        prefix = "/profiles/" + child + "/api"
        assert client.post(prefix + "/network/policy", json={"exposure": "tunnel"}).status_code == 200
        assert app.state.store.get_setting("route_policy", None) is None
        group = client.post("/api/profile-groups", json={"label": "Routes", "template": "default",
                                                        "sections": ["route"]}).json()["groups"][0]
        client.put("/api/profiles/" + child + "/group", json={"group": group["id"]})
        result = client.post("/api/profile-groups/" + group["id"] + "/apply", json={})
        assert result.status_code == 200 and result.json()["results"][0]["applied"] == ["route"]
        child_app = app.state.profiles.entries[child]["app"]
        assert child_app.state.store.get_setting("route_policy")["exposure"] == "hide"
        assert not child_app.state.collector.status()["has_session"]
    finally:
        client.__exit__(None, None, None)
