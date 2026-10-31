import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from tgwitness import recording
from tgwitness.app import create_app
from test_access import issue, login
from test_collector import FakeClient


SELECTED = {
    "monitoring": {"reactions": False, "membership": False},
    "capture": {"download_media": False, "max_media_mb": 50},
    "scope": {"mode": "account", "acknowledged": True, "exclude": [-1002, -1002]},
    "recheck": {"recheck_minutes": 20, "recheck_other_minutes": 120},
}
RECEIPTS = {"monitoring.changed", "capture.changed", "scope.changed", "recheck.changed"}


@pytest.fixture
def panel(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        yield app, client


def test_combined_save_keeps_receipts_and_survives_restart(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        assert client.post("/api/recording", json=SELECTED).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        response = client.post("/api/recording", json=SELECTED)
        assert response.status_code == 200, response.text
        saved = response.json()
        assert saved["saved"] and not saved["collector"]["running"]
        assert saved["application"] == {"state": "pending", "reason": "next_start"}
        assert saved["scope"]["exclude"] == [-1002]
        assert set(saved["changed"]) == {"monitoring", "capture", "scope", "recheck"}
        records = [e for e in app.state.store.all_events() if e["kind"] in RECEIPTS]
        assert {e["kind"] for e in records} == RECEIPTS
        assert client.post("/api/recording", json=SELECTED).json()["changed"] == []
        assert [e for e in app.state.store.all_events() if e["kind"] in RECEIPTS] == records
        app.state.store.verify(app.state.vault.public_key)
    with TestClient(create_app(tmp_path, client_factory=FakeClient)) as client:
        client.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        status = client.get("/api/status").json()
        for name in ("monitoring", "capture", "scope"):
            assert status[name] == saved[name]
        assert client.get("/api/scope").json()["recheck"] == saved["recheck"]


def test_invalid_group_or_scope_consent_changes_nothing(panel):
    app, client = panel
    before = recording.settings(app.state.store)
    head = app.state.store.stats()["head"]
    for body, status in (
        ({}, 422), ({"capture": None}, 422), ({"unknown": {}}, 422),
        ({**SELECTED, "recheck": {"recheck_minutes": -1}}, 422),
        ({**SELECTED, "scope": {"mode": "account"}}, 409),
        ({**SELECTED, "scope": {"mode": "folder", "acknowledged": True}}, 422),
    ):
        result = client.post("/api/recording", json=body)
        assert result.status_code == status, result.text
        assert recording.settings(app.state.store) == before
        assert app.state.store.stats()["head"] == head


def test_permission_union_is_checked_before_any_changes(panel):
    app, client = panel
    cases = [
        (["settings"], {"default": None}, {"scope": SELECTED["scope"]}),
        (["sources"], {"default": None}, {"capture": SELECTED["capture"]}),
        (["settings"], {"default": None}, SELECTED),
        (["sources"], {"default": None}, SELECTED),
        (["settings", "sources"], {"default": [-1001]}, SELECTED),
    ]
    for permissions, workspaces, body in cases:
        token, _ = issue(client, permissions=permissions, workspaces=workspaces)
        scoped, result = login(app, token)
        assert result.status_code == 200
        before, head = recording.settings(app.state.store), app.state.store.stats()["head"]
        assert scoped.post("/api/recording", json=body).status_code == 403
        assert recording.settings(app.state.store) == before
        assert app.state.store.stats()["head"] == head
    token, _ = issue(client, permissions=["settings", "sources"])
    scoped, _ = login(app, token)
    assert scoped.post("/api/recording", json=SELECTED).status_code == 200


def test_append_failure_rolls_back_every_setting_and_receipt(journal, monkeypatch):
    store, vault = journal
    before, events = recording.settings(store), list(store.all_events())
    append = store.append

    def failed(kind, *args, **kwargs):
        if kind == "recheck.changed":
            raise OSError("Synthetic disk error")
        return append(kind, *args, **kwargs)

    monkeypatch.setattr(store, "append", failed)
    with pytest.raises(OSError, match="Synthetic"):
        recording.save(store, recording.RecordingUpdate.model_validate(SELECTED))
    assert recording.settings(store) == before
    assert list(store.all_events()) == events
    store.verify(vault.public_key)


def test_save_only_changes_the_requested_workspace(panel):
    app, client = panel
    before = recording.settings(app.state.store)
    profile = client.post("/api/profiles", json={"label": "Second"}).json()["id"]
    endpoint = "/profiles/" + profile + "/api/recording"
    token, _ = issue(client, permissions=["settings", "sources"])
    scoped, _ = login(app, token)
    assert scoped.post(endpoint, json=SELECTED).status_code == 403
    response = client.post(endpoint, json=SELECTED)
    assert response.status_code == 200, response.text
    assert response.json()["scope"]["mode"] == "account"
    assert recording.settings(app.state.store) == before


def test_failed_apply_reports_saved_state_and_unchanged_retry_can_apply(panel, monkeypatch):
    app, client = panel
    collector = app.state.collector
    collector.running = True

    async def unavailable():
        raise TimeoutError()

    monkeypatch.setattr(collector, "apply_scope", unavailable)
    response = client.post("/api/recording", json=SELECTED)
    assert response.status_code == 200, response.text
    saved = response.json()
    assert saved["saved"] and saved["application"]["state"] == "failed"
    assert saved["application"]["status"] == 503
    assert recording.settings(app.state.store)["scope"]["mode"] == "account"

    async def applied():
        return {"added": 0, "paused": 0, "resumed": 0}

    monkeypatch.setattr(collector, "apply_scope", applied)
    response = client.post("/api/recording", json=SELECTED).json()
    assert response["changed"] == [] and response["application"]["state"] == "applied"
    assert len(app.state.store.events(kind="scope.changed")) == 1
    collector.running = False


def test_save_waits_for_start_and_cancellation_preserves_commit_boundary(tmp_path, monkeypatch):
    async def run():
        app = create_app(tmp_path, client_factory=FakeClient, allow_profiles=False)
        async with app.router.lifespan_context(app):
            collector, store = app.state.collector, app.state.store
            entered, release, applying = asyncio.Event(), asyncio.Event(), asyncio.Event()

            async def start():
                entered.set()
                await release.wait()
                collector.running = True

            async def apply():
                applying.set()
                await asyncio.Event().wait()

            monkeypatch.setattr(collector, "start", start)
            monkeypatch.setattr(collector, "apply_scope", apply)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + app.state.vault.token}) as client:
                start_task = asyncio.create_task(client.post("/api/collector/start"))
                await asyncio.wait_for(entered.wait(), 2)
                before, head = recording.settings(store), store.stats()["head"]
                cancelled = asyncio.create_task(client.post("/api/recording", json=SELECTED))
                await asyncio.sleep(0.03)
                assert not cancelled.done() and recording.settings(store) == before
                cancelled.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await cancelled
                assert recording.settings(store) == before and store.stats()["head"] == head

                saving = asyncio.create_task(client.post("/api/recording", json=SELECTED))
                await asyncio.sleep(0.03)
                assert not saving.done() and recording.settings(store) == before
                release.set()
                assert (await start_task).status_code == 200
                await asyncio.wait_for(applying.wait(), 2)
                assert recording.settings(store)["scope"]["mode"] == "account"
                committed = recording.settings(store)
                for path, body in (
                    ("/api/capture", {"download_media": True}),
                    ("/api/scope", {"mode": "selected"}),
                    ("/api/recheck", {"recheck_minutes": 99}),
                ):
                    blocked = asyncio.create_task(client.post(path, json=body))
                    await asyncio.sleep(0.03)
                    assert not blocked.done() and recording.settings(store) == committed
                    blocked.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await blocked
                saving.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await saving
                assert recording.settings(store)["capture"]["download_media"] is False
                assert len(store.events(kind="scope.changed")) == 1
                assert (await client.post("/api/capture", json={"download_media": True})).status_code == 200
                store.verify(app.state.vault.public_key)
            collector.running = False

    asyncio.run(run())
