import asyncio
import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from test_access import HARBOR, OTHER, issue, panel as panel


def connect(app, admin):
    result = admin.post("/api/integrations/mcp", json={"name": "Archive reader",
                        "workspaces": {"default": [HARBOR]}, "expires_at": time.time() + 3600})
    assert result.status_code == 200, result.text
    client = TestClient(app, headers={"Authorization": "Bearer " + result.json()["token"]})
    return client, result.json()


def test_connection_is_separate_revocable_and_has_no_panel_access(panel):
    app, admin = panel
    client, issued = connect(app, admin)
    assert client.get("/api/status").status_code == 401
    assert client.post("/api/access/login", json={"token": issued["token"]}).status_code == 401
    assert admin.get("/api/archive/identity").status_code == 401
    public = admin.get("/api/integrations/mcp").text
    assert issued["token"] not in public and "sha256" not in public
    assert client.get("/api/archive/identity").status_code == 200
    assert issued["token"] not in json.dumps(app.state.vault.read("archive-access"))
    admin.delete("/api/integrations/mcp/" + issued["connection"]["id"])
    assert client.get("/api/archive/identity").status_code == 401


@pytest.mark.parametrize("tool", ["search_messages", "get_message_versions", "get_message_context", "get_capture_status", "get_journal_event"])
def test_every_reader_rejects_other_chats_and_workspaces(panel, tool):
    app, admin = panel
    client, _ = connect(app, admin)
    query = {"tool": tool, "workspace": "default", "chat_id": OTHER, "message_id": 1, "event_seq": 1}
    assert client.post("/api/archive/query", json=query).status_code == 403
    query.update(workspace="a" * 32, chat_id=HARBOR)
    assert client.post("/api/archive/query", json=query).status_code == 403


def test_search_has_provenance_and_keeps_deletion_distinctions(panel):
    app, admin = panel
    store = app.state.store
    store.append("message.edited", {"text": "example.org revised", "access_hash": "PRIVATE_ACCESS_HASH",
                                   "raw": {"session": "PRIVATE_SESSION"}, "file_reference": "PRIVATE_REFERENCE"},
                 chat_id=HARBOR, message_id=1)
    deletion = store.append("message.deleted", {}, chat_id=HARBOR, message_id=1)
    store.append("message.missing_on_recheck", {}, chat_id=HARBOR, message_id=2)
    client, _ = connect(app, admin)
    response = client.post("/api/archive/query", json={"tool": "search_messages"})
    assert response.status_code == 200, response.text
    rows = response.json()["items"]
    assert rows and all(row["source"]["chat_id"] == HARBOR for row in rows)
    assert any(row["deletion_notice"] for row in rows) and any(row["missing_on_recheck"] for row in rows)
    assert all(row["source"]["hash"] and row["source"]["href"] for row in rows)
    assert "PRIVATE_" not in response.text
    hidden = client.post("/api/archive/query", json={"tool": "search_messages", "query": "PRIVATE_ACCESS_HASH"}).json()
    assert not hidden["items"]
    found = client.post("/api/archive/query", json={"tool": "search_messages", "query": "example.org"}).json()
    assert len(found["items"]) == 1
    versions = client.post("/api/archive/query", json={"tool": "get_message_versions", "chat_id": HARBOR, "message_id": 1}).json()
    assert {row["kind"] for row in versions["items"]} == {"message.new", "message.edited", "message.deleted"}
    foreign = store.events(chat_id=OTHER, limit=1)[0]["seq"]
    assert client.post("/api/archive/query", json={"tool": "get_journal_event", "event_seq": foreign}).status_code == 403
    own = client.post("/api/archive/query", json={"tool": "get_journal_event", "event_seq": deletion["seq"]})
    assert own.status_code == 200


def test_bounds_expiration_and_non_admin_cannot_issue(panel):
    app, admin = panel
    client, issued = connect(app, admin)
    result = client.post("/api/archive/query", json={"tool": "search_messages", "limit": 1}).json()
    assert len(result["items"]) == 1
    assert client.post("/api/archive/query", json={"tool": "search_messages", "limit": 1000}).status_code == 422
    assert client.post("/api/archive/query", json={"tool": "send_message"}).status_code == 422
    token, _ = issue(admin)
    viewer = TestClient(app, headers={"Authorization": "Bearer " + token})
    assert viewer.get("/api/integrations/mcp").status_code in (401, 403)
    app.state.access.archive_connections.entries[0]["expires_at"] = time.time() - 1
    assert client.get("/api/archive/identity").status_code == 401


def test_request_rate_is_bounded(panel):
    app, admin = panel
    client, _ = connect(app, admin)
    for _ in range(60):
        assert client.get("/api/archive/identity").status_code == 200
    response = client.get("/api/archive/identity")
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"


def test_saved_chat_is_listed_after_capture_target_is_absent(panel):
    app, admin = panel
    app.state.store.append("message.new", {"text": "Old saved chat"}, chat_id=-1003, message_id=1)
    issued = admin.post("/api/integrations/mcp", json={"name": "Historical chat", "workspaces": {"default": [-1003]},
                                                     "expires_at": time.time() + 3600}).json()
    client = TestClient(app, headers={"Authorization": "Bearer " + issued["token"]})
    response = client.post("/api/archive/query", json={"tool": "list_chats", "limit": 1})
    assert response.status_code == 200, response.text
    assert [row["chat_id"] for row in response.json()["items"]] == [-1003]
    assert response.json()["next_offset"] is None
    assert client.post("/api/archive/query", json={"tool": "search_messages", "since": "2026-10-02T00:00:00Z",
                                                  "until": "2026-10-01T00:00:00Z"}).status_code == 422


def test_unavailable_workspace_returns_an_explanation_instead_of_a_server_error(panel):
    app, admin = panel
    workspace = "a" * 32
    app.state.profiles.entries[workspace] = {"app": None, "label": "Unavailable workspace"}
    result = admin.post("/api/integrations/mcp", json={"name": "Unavailable archive",
                        "workspaces": {workspace: None}, "expires_at": time.time() + 3600})
    assert result.status_code == 200, result.text
    client = TestClient(app, raise_server_exceptions=False,
                        headers={"Authorization": "Bearer " + result.json()["token"]})
    response = client.post("/api/archive/query", json={"tool": "list_chats", "workspace": workspace})
    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "Workspace is unavailable."
    response = admin.get("/api/analysis/provider", params={"workspace_id": workspace})
    assert response.status_code == 403 and response.json()["detail"] == "Workspace is unavailable."


@pytest.mark.parametrize("worker_fails", [False, True])
def test_cancelled_queries_keep_the_read_limit_until_the_workers_finish(panel, monkeypatch, worker_fails):
    from tgwitness.archive import ArchiveReader

    app, admin = panel
    _, issued = connect(app, admin)
    original = ArchiveReader.read

    async def run():
        loop = asyncio.get_running_loop()
        entered, finished, release = asyncio.Queue(), asyncio.Queue(), threading.Event()
        started = []

        def paused(reader, query):
            started.append(True)
            index = len(started)
            loop.call_soon_threadsafe(entered.put_nowait, True)
            try:
                assert release.wait(10), "Archive reader was not released"
                if worker_fails and index <= 2:
                    raise ValueError("Synthetic cancelled read failure")
                return original(reader, query)
            finally:
                loop.call_soon_threadsafe(finished.put_nowait, True)

        monkeypatch.setattr(ArchiveReader, "read", paused)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver",
                                     headers={"Authorization": "Bearer " + issued["token"]}) as client:
            def query():
                return asyncio.create_task(client.post("/api/archive/query", json={"tool": "list_chats"}))

            requests = [query(), query()]
            try:
                for _ in requests:
                    await asyncio.wait_for(entered.get(), 5)
                for task in requests:
                    task.cancel()
                await asyncio.gather(*requests, return_exceptions=True)
                third = query()
                requests.append(third)
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(entered.get(), 0.1)
                release.set()
                response = await asyncio.wait_for(third, 5)
                assert response.status_code == 200 and response.json()["items"]
            finally:
                release.set()
                await asyncio.gather(*requests, return_exceptions=True)
                for _ in started:
                    await asyncio.wait_for(finished.get(), 5)

    asyncio.run(run())
