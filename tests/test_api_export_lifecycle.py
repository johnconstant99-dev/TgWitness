"""Temporary evidence stays owned until its worker and HTTP response have ended."""
import asyncio
import threading
from pathlib import Path

import pytest
from starlette.requests import Request

from tgwitness import app as panel, webhooks


def scope():
    return {"type": "http", "asgi": {"spec_version": "2.4"}, "method": "GET", "path": "/api/export/jsonl", "headers": [],
            "query_string": b"", "scheme": "http", "server": ("localhost", 80)}


def endpoint(app, path, method="GET"):
    return next(r.endpoint for r in app.routes if getattr(r, "path", None) == path and method in r.methods)


def setup(journal):
    store, vault = journal
    app = panel.create_app(store.root)
    app.state.store, app.state.vault = store, vault
    app.state.alert_wakeup = asyncio.Event()
    return app


@pytest.mark.parametrize("encrypted", [False, True])
def test_cancelled_export_waits_for_worker_and_removes_its_result(journal, monkeypatch, encrypted):
    app = setup(journal)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    path = app.state.store.root / "temporary-exports" / "tgwitness-export-cancel.jsonl"

    def build(*args):
        entered.set()
        assert release.wait(5)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b"private captured messages")
        finished.set()
        return path

    monkeypatch.setattr(panel, "export_file", build)

    async def run():
        call = endpoint(app, "/api/export/{fmt}", "POST" if encrypted else "GET")
        args = [Request(scope()), "jsonl"]
        if encrypted:
            args.append(panel.ExportPassword(password="synthetic-password"))
        task = asyncio.create_task(call(*args))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0.02)
            premature = task.done()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await asyncio.to_thread(finished.wait, 5)
        assert not premature, "The export lock was released while its file worker was still running"
        assert not list(path.parent.iterdir()), "Cancelled export left captured data on disk"

    asyncio.run(run())


def test_cancelled_export_notification_removes_the_completed_file(journal, monkeypatch):
    app = setup(journal)

    async def run():
        entered = asyncio.Event()

        async def notify(*args):
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(webhooks, "export_completed", notify)
        task = asyncio.create_task(endpoint(app, "/api/export/{fmt}")(Request(scope()), "jsonl"))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not list((app.state.store.root / "temporary-exports").iterdir())

    asyncio.run(run())


@pytest.mark.parametrize("kind", ["evidence", "dossier", "encrypted_dossier"])
@pytest.mark.parametrize("failure", ["headers", "body", "cancel"])
def test_download_disconnect_removes_temporary_file(journal, monkeypatch, kind, failure):
    app = setup(journal)
    app.state.store.set_setting("dossiers", {"123": True})
    monkeypatch.setattr(panel.dossier, "signed", lambda *args: {"synthetic": True})

    async def run():
        if kind == "evidence":
            response = await endpoint(app, "/api/export/{fmt}")(Request(scope()), "jsonl")
        else:
            method = "POST" if kind == "encrypted_dossier" else "GET"
            args = [123]
            if method == "POST":
                args.append(panel.ExportPassword(password="synthetic-password"))
            response = await endpoint(app, "/api/chats/{chat_id}/dossier/export", method)(*args)
        path = Path(response.path)
        assert path.is_file()

        async def receive():
            return {"type": "http.disconnect"}

        async def send(message):
            if failure == "cancel":
                raise asyncio.CancelledError()
            if message["type"] == ("http.response.start" if failure == "headers" else "http.response.body"):
                raise OSError("Synthetic disconnected download")

        with pytest.raises(asyncio.CancelledError if failure == "cancel" else OSError):
            await response(scope(), receive, send)
        assert not path.exists()

    asyncio.run(run())
