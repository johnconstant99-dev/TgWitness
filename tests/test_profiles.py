
from fastapi.testclient import TestClient
import pytest

from tgwitness.app import create_app
from tgwitness.verify import verify_bundle
from test_collector import FakeClient, CHAT


def authorize(client, prefix, api_id=123):
    assert client.post(prefix + "/auth/configure", json={"api_id":api_id,"api_hash":"a"*32}).status_code == 200
    assert client.post(prefix + "/auth/phone", json={"phone":"+15550001111"}).status_code == 200
    assert client.post(prefix + "/auth/code", json={"code":"12345"}).status_code == 200
    assert client.get(prefix + "/dialogs").status_code == 200
    assert client.post(prefix + "/targets", json={"chat_id":CHAT,"enabled":True}).status_code == 200
    assert client.post(prefix + "/collector/start", json={}).status_code == 200


def test_isolated_accounts_running_together_and_restart(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        created = client.post("/api/profiles", json={"label":"Closed groups B"})
        assert created.status_code == 200, created.text
        profile_id = created.json()["id"]
        prefix = "/profiles/" + profile_id + "/api"
        assert client.get(prefix + "/status", headers={"Authorization":""}).status_code == 401
        assert client.get("/profiles/../../api/status", headers={"Authorization":""}).status_code in (401,404)
        authorize(client, "/api")
        authorize(client, prefix, api_id=124)
        assert client.get("/api/status").json()["collector"]["running"]
        assert client.get(prefix + "/status").json()["collector"]["running"]
        assert client.post(prefix + "/snapshot", json={"chat_id":CHAT,"limit":2}).json()["captured"] == 2
        assert not client.get("/api/events?kind=message.snapshot").json()["events"]
        assert len(client.get(prefix + "/events?kind=message.snapshot").json()["events"]) == 2
        fingerprints = [client.get(p + "/status").json()["fingerprint"] for p in ("/api", prefix)]
        assert len(set(fingerprints)) == 2
        for index, api in enumerate(("/api", prefix)):
            archive = tmp_path / ("profile-" + str(index) + ".zip")
            archive.write_bytes(client.get(api + "/export/zip").content)
            assert verify_bundle(archive, fingerprints[index])["key_pinned"]
        assert client.post(prefix + "/collector/stop", json={}).status_code == 200
        assert client.get("/api/status").json()["collector"]["running"]
        client.post("/api/collector/stop", json={})
        source = app.state.store.events(kind="process.started")[0]["payload"]["run"]
        assert source["source_tree_sha256"] and source["source_files"]["collector.py"]
    with TestClient(create_app(tmp_path, client_factory=FakeClient)) as client:
        client.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        profiles = client.get("/api/profiles").json()["profiles"]
        assert len(profiles) == 2 and profiles[1]["id"] == profile_id
        assert client.get(prefix + "/status").json()["fingerprint"] == fingerprints[1]


def test_corrupt_child_does_not_block_other_profiles(tmp_path):
    import sqlite3
    with TestClient(create_app(tmp_path)) as client:
        client.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        profile_id = client.post("/api/profiles", json={"label":"Damaged"}).json()["id"]
    db = sqlite3.connect(tmp_path / "profiles" / profile_id / "journal.sqlite3")
    db.execute("DROP TRIGGER immutable_update")
    db.execute("UPDATE events SET payload='{}' WHERE seq=1")
    db.commit()
    db.close()
    with TestClient(create_app(tmp_path)) as client:
        client.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        assert client.get("/api/status").status_code == 200
        assert client.get("/profiles/" + profile_id + "/api/status").status_code == 503
        assert client.get("/api/profiles").json()["profiles"][1]["error_type"] == "ValueError"


def test_duplicate_telegram_account_is_not_assigned_twice(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        authorize(client, "/api")
        profile_id = client.post("/api/profiles", json={"label":"Duplicate"}).json()["id"]
        prefix = "/profiles/" + profile_id + "/api"
        client.post(prefix + "/auth/configure", json={"api_id":123,"api_hash":"a"*32})
        client.post(prefix + "/auth/phone", json={"phone":"+15550001111"})
        response = client.post(prefix + "/auth/code", json={"code":"12345"})
        assert response.status_code == 400 and "already belongs" in response.text
        assert client.get(prefix + "/status").json()["collector"]["has_session"] is False
        assert client.get("/api/status").json()["collector"]["running"] is True


def test_rename_and_delete_profile(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        pid = client.post("/api/profiles", json={"label": "Temp"}).json()["id"]
        prefix = "/profiles/" + pid + "/api"
        assert client.get(prefix + "/status").status_code == 200
        assert client.patch("/api/profiles/default", json={"label": "Primary"}).status_code == 200
        assert client.patch("/api/profiles/" + pid, json={"label": "Renamed"}).status_code == 200
        assert client.patch("/api/profiles/" + pid, json={"label": "  "}).status_code == 422
        profiles = {p["id"]: p for p in client.get("/api/profiles").json()["profiles"]}
        assert profiles["default"]["label"] == "Primary"
        assert profiles[pid]["label"] == "Renamed"
        assert profiles[pid]["sources_enabled"] == 0 and profiles[pid]["sources_total"] == 0
        assert client.delete("/api/profiles/default").status_code == 400
        assert client.delete("/api/profiles/" + pid).status_code == 200
        assert not (tmp_path / "profiles" / pid).exists()
        assert client.get(prefix + "/status").status_code == 404
        assert [p["id"] for p in client.get("/api/profiles").json()["profiles"]] == ["default"]
    with TestClient(create_app(tmp_path, client_factory=FakeClient)) as client:
        client.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        profiles = client.get("/api/profiles").json()["profiles"]
        assert len(profiles) == 1 and profiles[0]["label"] == "Primary"


@pytest.mark.parametrize("partial", [False, True])
def test_failed_profile_erasure_stays_visible_and_can_be_retried_after_restart(tmp_path, monkeypatch, partial):
    import shutil

    app = create_app(tmp_path)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        pid = client.post("/api/profiles", json={"label": "Erase me"}).json()["id"]
        directory = tmp_path / "profiles" / pid

        def fail_erasure(path, ignore_errors=False):
            assert path == directory
            if partial:
                (directory / "journal.sqlite3").unlink(missing_ok=True)
            if not ignore_errors:
                raise PermissionError("synthetic locked private file")

        with monkeypatch.context() as patch:
            patch.setattr(shutil, "rmtree", fail_erasure)
            response = client.delete("/api/profiles/" + pid)
        assert response.status_code == 400
        assert "retry" in response.json()["detail"].lower()
        assert "synthetic locked private file" not in response.text
        assert directory.exists()
        assert client.get("/profiles/" + pid + "/api/status").status_code == 503
        assert app.state.store.events(kind="profile.deletion_failed")
        assert not app.state.store.events(kind="profile.deleted")

    remaining = {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    app = create_app(tmp_path)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        profiles = {p["id"]: p for p in client.get("/api/profiles").json()["profiles"]}
        assert profiles[pid]["error_type"] == "DeletionPending"
        assert profiles[pid]["collector"] is None
        # Restart must not reopen a half-erased vault or silently create a replacement journal.
        assert {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()} == remaining
        assert client.delete("/api/profiles/" + pid).status_code == 200
        assert not directory.exists()
        assert app.state.store.events(kind="profile.deleted")
        assert len(client.get("/api/profiles").json()["profiles"]) == 1
