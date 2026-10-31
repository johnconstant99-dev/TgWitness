"""Export concurrency, account deletion and failed setup."""
import asyncio
import hashlib
from unittest.mock import patch

from fastapi.testclient import TestClient
from telethon.helpers import TotalList

from tgwitness.app import create_app
from test_collector import CHAT, FakeClient, telegram_message
from test_profiles import authorize


class LifecycleClient(FakeClient):
    async def get_messages(self, entity, limit):
        messages = TotalList([telegram_message(10)] if limit else [])
        messages.total = 10
        return messages


def open_two(app, client):
    client.headers["Authorization"] = "Bearer " + app.state.vault.token
    authorize(client, "/api")
    profile = client.post("/api/profiles", json={"label": "Synthetic second account"}).json()["id"]
    authorize(client, "/profiles/" + profile + "/api", api_id=124)
    return profile, app.state.profiles.entries[profile]["app"].state.collector


async def empty_range(entity, low, high, path, *args):
    path.write_text("", encoding="utf-8")
    return 0, hashlib.sha256(b"").hexdigest()


def wait_finished(client, url, phases=("done", "failed", "cancelled")):
    for _ in range(200):
        state = client.get(url).json()
        if state["phase"] in phases:
            return state
        client.portal.call(asyncio.sleep, 0.02)
    raise AssertionError("export did not finish: " + str(state))


def test_individual_export_is_refused_while_a_multi_export_resolves_the_account(tmp_path):
    app = create_app(tmp_path, client_factory=LifecycleClient)
    with TestClient(app) as client:
        profile, child = open_two(app, client)
        entered, release = asyncio.Event(), asyncio.Event()
        original = child.resolve_for_export

        async def paused(*args):
            entered.set()
            await release.wait()
            return await original(*args)

        with patch.object(child, "resolve_for_export", paused), patch.object(child, "fetch_range", empty_range), \
                patch.object(app.state.collector, "fetch_range", empty_range):
            multi = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": "default", "profiles": [profile]})
            assert multi.status_code == 200, multi.text
            client.portal.call(asyncio.wait_for, entered.wait(), 5)
            single = client.post("/profiles/" + profile + "/api/chat-export/start", json={"chat_id": CHAT})
            assert single.status_code == 400 and "already running" in single.json()["detail"]
            client.portal.call(release.set)
            assert wait_finished(client, "/api/multi-export/" + multi.json()["id"])["phase"] == "done"
        assert child.export_claim is None and app.state.collector.export_claim is None


def test_multi_export_skips_an_account_whose_individual_export_is_starting(tmp_path):
    app = create_app(tmp_path, client_factory=LifecycleClient)
    with TestClient(app) as client:
        profile, child = open_two(app, client)
        entered, release = asyncio.Event(), asyncio.Event()
        original = child.resolve_target

        async def paused(*args):
            entered.set()
            await release.wait()
            return await original(*args)

        async def start_single():
            return await child.start_export(CHAT)

        with patch.object(child, "resolve_target", paused), patch.object(app.state.collector, "fetch_range", empty_range):
            single = client.portal.start_task_soon(start_single)
            client.portal.call(asyncio.wait_for, entered.wait(), 5)
            multi = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": "default", "profiles": [profile]})
            assert multi.status_code == 200, multi.text
            worker = next(w for w in multi.json()["workers"] if w["profile_id"] == profile)
            assert worker["state"] == "skipped" and "Another export" in worker["error"]
            lead_busy = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": profile, "profiles": []})
            assert lead_busy.status_code == 400
            client.portal.call(release.set)
            record = single.result(5)
            wait_finished(client, "/profiles/" + profile + "/api/chat-export/" + record["id"])
            wait_finished(client, "/api/multi-export/" + multi.json()["id"])
        assert child.export_claim is None and app.state.collector.export_claim is None


def test_participating_workspace_cannot_be_deleted_until_the_multi_export_ends(tmp_path):
    app = create_app(tmp_path, client_factory=LifecycleClient)
    with TestClient(app) as client:
        profile, child = open_two(app, client)
        entered, release = asyncio.Event(), asyncio.Event()

        async def open_fetch(entity, low, high, path, *args):
            with path.open("w"):
                entered.set()
                await release.wait()
            raise ConnectionError("Synthetic disconnect")

        with patch.object(child, "fetch_range", open_fetch):
            started = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": profile, "profiles": []})
            assert started.status_code == 200, started.text
            client.portal.call(asyncio.wait_for, entered.wait(), 5)
            refused = client.delete("/api/profiles/" + profile)
            assert refused.status_code == 400 and "multi-account export" in refused.json()["detail"]
            assert app.state.profiles.entries[profile]["app"] is not None
            assert not app.state.profiles.entries[profile].get("deleting")
            client.portal.call(release.set)
            state = wait_finished(client, "/api/multi-export/" + started.json()["id"])
            assert state["phase"] == "failed"
            for _ in range(100):
                if app.state.multi_export.task.done():
                    break
                client.portal.call(asyncio.sleep, 0.02)
            assert app.state.multi_export.task.exception() is None
        assert client.delete("/api/profiles/" + profile).status_code == 200


def test_setup_failures_end_both_exports_as_failed(tmp_path):
    app = create_app(tmp_path, client_factory=LifecycleClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        authorize(client, "/api")
        (tmp_path / "temporary-exports").write_text("Synthetic path collision")
        single = client.post("/api/chat-export/start", json={"chat_id": CHAT})
        assert single.status_code == 200
        state = wait_finished(client, "/api/chat-export/" + single.json()["id"])
        assert state["phase"] == "failed" and state["error"] == "FileExistsError"
        assert app.state.collector.export_task.exception() is None
        multi = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": "default", "profiles": []})
        assert multi.status_code == 200
        state = wait_finished(client, "/api/multi-export/" + multi.json()["id"])
        assert state["phase"] == "failed"
        assert app.state.multi_export.task.exception() is None

        assert app.state.collector.export_claim is None


def test_failed_journal_write_still_ends_the_export(tmp_path):
    app = create_app(tmp_path, client_factory=LifecycleClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        authorize(client, "/api")
        store = app.state.collector.store
        original = store.append

        def failing(kind, *args, **kwargs):
            if kind.startswith("chat_export."):
                raise OSError("Synthetic disk failure")
            return original(kind, *args, **kwargs)

        with patch.object(store, "append", failing):
            single = client.post("/api/chat-export/start", json={"chat_id": CHAT})
            state = wait_finished(client, "/api/chat-export/" + single.json()["id"])
        assert state["phase"] == "failed" and state["error"] == "OSError"
        assert app.state.collector.export_claim is None
