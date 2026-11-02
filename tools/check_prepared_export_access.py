"""Prepared downloads: scope, one-use tickets, revocation, expiry and corrupt cache."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import AsyncMock, patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tgwitness import analysis_api, app as app_module, export_history
from tgwitness.access import GrantSettings
from tools.check_session_reservations import workspace


async def native(app, path, ticket, headers=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        return await client.get(path, headers={"Cookie": "tgwitness-download=" + ticket, **(headers or {})})


async def account_tickets():
    """Account jobs keep their existing ACL and files; browser tickets add no authority."""
    async with workspace() as (app, client):
        job, disclosure = "a" * 32, "b" * 32
        payload = b"Synthetic account export transport bytes" * 4096
        archive = app.state.store.root / "synthetic-account.zip"
        archive.write_bytes(payload)
        prefix = "/api/account-export/" + job
        session, _ = app.state.access.login(app.state.vault.token, "127.0.0.1", "Synthetic admin")
        admin = {"Authorization": "Bearer " + session}
        _, reviewer = grant_session(app)
        with patch.object(app.state.account_export, "result_path", return_value=archive), \
                patch.object(app.state.account_export, "public", return_value={"archive_sha256": hashlib.sha256(payload).hexdigest()}), \
                patch.object(app.state.disclosures, "result_path", return_value=archive):
            for endpoint in (prefix, prefix + "/disclosures/" + disclosure):
                direct = await client.get(endpoint + "/download", headers=admin)
                assert direct.content == payload
                assert direct.headers["x-tgwitness-download-ticket"] == endpoint.removeprefix("/api/") + "/ticket"
                assert (await client.get(endpoint + "/download", headers=reviewer)).status_code == 403
                assert (await client.post(endpoint + "/ticket", headers=reviewer)).status_code == 403
                result = await client.post(endpoint + "/ticket", headers=admin)
                assert result.status_code == 200, result.text
                cookie = result.cookies.get("tgwitness-download")
                assert result.json()["url"] == endpoint + "/download"
                assert "HttpOnly" in result.headers["set-cookie"] and "SameSite=strict" in result.headers["set-cookie"]
                response = await native(app, result.json()["url"], cookie)
                assert response.status_code == 200 and response.content == payload
                assert "attachment" in response.headers["content-disposition"]
                assert (await native(app, result.json()["url"], cookie)).status_code == 403

            result = await client.post(prefix + "/ticket", headers=admin)
            cookie = result.cookies.get("tgwitness-download")
            assert (await native(app, prefix + "/disclosures/" + disclosure + "/download", cookie)).status_code == 403
            child = await app.state.profiles.create("Synthetic account download boundary")
            result = await client.post(prefix + "/ticket", headers=admin)
            cookie = result.cookies.get("tgwitness-download")
            assert (await native(app, "/profiles/" + child["id"] + prefix + "/download", cookie)).status_code == 403
            assert (await native(app, prefix + "/download", cookie)).status_code == 200
            await child_download_lifecycle(app, client, child, admin, payload)

            # Authorization may be revoked while a request waits for a panel
            # operation. Both ticket creation and lease acquisition recheck it.
            for action, method in (("ticket", "POST"), ("download", "GET")):
                temporary, _ = app.state.access.login(app.state.vault.token, "127.0.0.1", "Queued download")
                waiting_at_lock = asyncio.Event()
                acquire = app.state.operation_lock.acquire

                async def tracked_acquire():
                    waiting_at_lock.set()
                    return await acquire()

                async with app.state.operation_lock:
                    with patch.object(app.state.operation_lock, "acquire", tracked_acquire):
                        pending = asyncio.create_task(client.request(method, prefix + "/" + action,
                            headers={"Authorization": "Bearer " + temporary}))
                        await asyncio.wait_for(waiting_at_lock.wait(), 5)
                    principal = app.state.access.resolve(temporary, "127.0.0.1")
                    app.state.access.end(principal.session_id, "Revoked while waiting for operation")
                response = await pending
                assert response.status_code == 403, (action, response.text)
                assert not app.state.account_downloads

            # The download lease starts before response bytes. Neither the source
            # nor its sharing copies can disappear while any such response is active.
            started, release = asyncio.Event(), asyncio.Event()

            async def slow(scope, receive, send):
                async def held(message):
                    if message["type"] == "http.response.start":
                        started.set()
                        await release.wait()
                    await send(message)
                await app(scope, receive, held)

            removed = AsyncMock(return_value={"deleted": True})
            with patch.object(app.state.account_export, "remove", removed):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=slow), base_url="http://127.0.0.1") as downloader:
                    pending = asyncio.create_task(downloader.get(prefix + "/disclosures/" + disclosure + "/download", headers=admin))
                    await asyncio.wait_for(started.wait(), 5)
                    assert (await client.delete(prefix)).status_code == 409
                    removed.assert_not_awaited()
                    release.set()
                    assert (await pending).content == payload
                    assert (await client.delete(prefix)).status_code == 200
                    removed.assert_awaited_once()

                    # Aborting a response releases the lease without deleting the archive.
                    started.clear()
                    release.clear()
                    pending = asyncio.create_task(downloader.get(prefix + "/download", headers=admin))
                    await asyncio.wait_for(started.wait(), 5)
                    pending.cancel()
                    try:
                        await pending
                    except asyncio.CancelledError:
                        pass
                    assert archive.read_bytes() == payload
                    assert (await client.delete(prefix)).status_code == 200

            result = await client.post(prefix + "/ticket", headers=admin)
            cookie = result.cookies.get("tgwitness-download")
            principal = app.state.access.resolve(session, "127.0.0.1")
            app.state.access.end(principal.session_id, "Synthetic revocation")
            assert (await native(app, prefix + "/download", cookie)).status_code == 403
            assert archive.read_bytes() == payload


async def child_download_lifecycle(app, client, profile, admin, payload):
    child = app.state.profiles.entries[profile["id"]]["app"]
    archive = child.state.store.root / "synthetic-child-export.zip"
    archive.write_bytes(payload)
    prefix = "/profiles/" + profile["id"] + "/api/account-export/" + "c" * 32
    disclosure = prefix + "/disclosures/" + "d" * 32
    started, release = asyncio.Event(), asyncio.Event()
    original = app_module.RetainedDownload.__call__

    async def held(response, scope, receive, send):
        # Hold after the route acquired its lease, before FileResponse opens the
        # archive. Deleting the workspace here used to remove the download source.
        started.set()
        await release.wait()
        return await original(response, scope, receive, send)

    with patch.object(child.state.account_export, "result_path", return_value=archive), \
            patch.object(child.state.account_export, "public", return_value={"archive_sha256": hashlib.sha256(payload).hexdigest()}), \
            patch.object(child.state.disclosures, "result_path", return_value=archive):
        child.state.closing = True
        try:
            for endpoint in (prefix, disclosure):
                assert (await client.post(endpoint + "/ticket", headers=admin)).status_code == 503
                assert (await client.get(endpoint + "/download", headers=admin)).status_code == 503
            assert not child.state.account_downloads
        finally:
            child.state.closing = False
        with patch.object(app_module.RetainedDownload, "__call__", held):
            pending = asyncio.create_task(client.get(disclosure + "/download", headers=admin))
            await asyncio.wait_for(started.wait(), 5)
            try:
                response = await client.delete("/api/profiles/" + profile["id"])
                assert response.status_code == 400 and "active downloads" in response.text, response.text
                assert archive.read_bytes() == payload and child.state.account_downloads
                assert not child.state.closing
            finally:
                release.set()
            assert (await pending).content == payload
        assert not child.state.account_downloads
        assert (await client.delete("/api/profiles/" + profile["id"])).status_code == 200
        assert not archive.exists()


def grant_session(app, workspaces=None, permissions=None):
    token, grant = app.state.access.issue(GrantSettings(label="Synthetic reviewer",
        workspaces=workspaces or {"default": None}, permissions=permissions or ["view", "export"]))
    session, _ = app.state.access.login(token, "127.0.0.1", "Synthetic test")
    return grant, {"Authorization": "Bearer " + session}


async def tickets():
    async with workspace() as (app, client):
        path = app.state.store.root / "synthetic-export.zip"
        payload = b"Synthetic signed export fixture; exact bytes must survive transport."
        path.write_bytes(payload)
        prepared = export_history.prepared(app.state.store, path, "zip", False)
        ident = prepared["id"]
        endpoint = "/api/exports/" + ident
        _, headers = grant_session(app)
        response = await client.post(endpoint + "/ticket", headers=headers)
        assert response.status_code == 200, response.text
        cookie = response.cookies.get("tgwitness-download")
        assert "HttpOnly" in response.headers["set-cookie"] and "SameSite=strict" in response.headers["set-cookie"]
        downloaded = await native(app, response.json()["url"], cookie)
        assert downloaded.status_code == 200 and downloaded.content == payload
        assert downloaded.headers["x-tgwitness-export-sha256"] == hashlib.sha256(payload).hexdigest()
        assert downloaded.headers["cache-control"] == "no-store" and "attachment" in downloaded.headers["content-disposition"]
        assert (await native(app, endpoint + "/download", cookie)).status_code == 403, "Ticket reused"

        # Subset grants cannot fetch a cached whole-workspace archive, even when
        # they can export one of their assigned chats through the scoped exporter.
        _, restricted = grant_session(app, {"default": [11]})
        assert (await client.post(endpoint + "/ticket", headers=restricted)).status_code == 403
        assert (await client.get(endpoint + "/download", headers=restricted)).status_code == 403
        _, view_only = grant_session(app, permissions=["view"])
        assert (await client.post(endpoint + "/ticket", headers=view_only)).status_code == 403

        # Another workspace cannot consume or reuse this workspace's ticket.
        child = await app.state.profiles.create("Synthetic second workspace")
        response = await client.post(endpoint + "/ticket", headers=headers)
        cookie = response.cookies.get("tgwitness-download")
        assert (await native(app, "/profiles/" + child["id"] + endpoint + "/download", cookie)).status_code == 403
        assert (await native(app, endpoint + "/download", cookie)).status_code == 200

        # Expiration uses monotonic time. Patch only app.py's reference, leaving
        # the event loop and access-session clocks untouched.
        issued = time.monotonic()

        class Clock:
            now = issued

            def monotonic(self):
                return self.now

            def __getattr__(self, name):
                return getattr(time, name)

        clock = Clock()
        with patch.object(app_module, "time", clock):
            response = await client.post(endpoint + "/ticket", headers=headers)
            cookie = response.cookies.get("tgwitness-download")
            clock.now += 121
            assert (await native(app, endpoint + "/download", cookie)).status_code == 403

        # Revocation takes effect even for an already-issued ticket.
        grant, revocable = grant_session(app)
        response = await client.post(endpoint + "/ticket", headers=revocable)
        cookie = response.cookies.get("tgwitness-download")
        app.state.access.revoke(grant["id"])
        assert (await native(app, endpoint + "/download", cookie)).status_code == 403

        # Integrity check cannot become an authorization gap while hashing a
        # large archive in a worker thread.
        grant, revocable = grant_session(app)
        response = await client.post(endpoint + "/ticket", headers=revocable)
        cookie = response.cookies.get("tgwitness-download")
        entered, release = threading.Event(), threading.Event()
        original = export_history.locate

        def held(*args):
            entered.set()
            if not release.wait(5):
                raise AssertionError("Test did not release hash lookup")
            return original(*args)

        with patch.object(export_history, "locate", held):
            pending = asyncio.create_task(native(app, endpoint + "/download", cookie))
            assert await asyncio.to_thread(entered.wait, 3)
            app.state.access.revoke(grant["id"])
            release.set()
            response = await pending
        assert response.status_code == 403, "Revoked access began a download after hashing"
        assert not list((app.state.store.root / "temporary-exports").glob("tgwitness-export-download-*")), "Revocation leaked its private download copy"

        # A retained file cannot be served merely because its ID is valid.
        cached, _ = export_history.locate(app.state.store, ident)
        cached.write_bytes(b"replaced")
        response = await client.get(endpoint + "/download")
        assert response.status_code == 404 and "changed" in response.text
        assert (await client.post(endpoint + "/ticket")).status_code == 404


async def research_scope():
    async with workspace() as (app, client):
        store = app.state.store
        store.set_target(11, "Synthetic source", "channel", True)
        store.append("message.new", {"text": "synthetic observation", "sender_id": 42}, chat_id=11, message_id=1)
        now = datetime.now(timezone.utc)
        question = {"workspace": "default", "chats": [11], "query": "synthetic", "question": "Find synthetic observations",
                    "since": (now - timedelta(days=1)).isoformat(), "until": (now + timedelta(minutes=1)).isoformat()}
        grant, headers = grant_session(app, {"default": [11]})
        preview = await client.post("/api/analysis/preview", json=question, headers=headers)
        assert preview.status_code == 200, preview.text
        plan = preview.json()
        request = {"plan_id": plan["plan_id"], "source_ids": [plan["sources"][0]["id"]]}
        result = await client.post("/api/analysis/context-export", json=request, headers=headers)
        assert result.status_code == 200, result.text
        # Same preview belongs to the issuing access, not any other session.
        _, other = grant_session(app, {"default": [11]})
        assert (await client.post("/api/analysis/context-export", json=request, headers=other)).status_code == 403
        _, readonly = grant_session(app, {"default": [11]}, ["view"])
        preview = await client.post("/api/analysis/preview", json=question, headers=readonly)
        assert preview.status_code == 200, preview.text
        plan = preview.json()
        assert (await client.post("/api/analysis/context-export", json={"plan_id": plan["plan_id"], "source_ids": [plan["sources"][0]["id"]]}, headers=readonly)).status_code == 403
        entered, release = threading.Event(), threading.Event()
        original = analysis_api.verify_sources

        def held(*args):
            result = original(*args)
            entered.set()
            if not release.wait(5):
                raise AssertionError("Test did not release source verification")
            return result

        with patch.object(analysis_api, "verify_sources", held):
            pending = asyncio.create_task(client.post("/api/analysis/context-export", json=request, headers=headers))
            assert await asyncio.to_thread(entered.wait, 3)
            app.state.access.change(grant["id"], GrantSettings(label="Scope narrowed", workspaces={"default": [22]}, permissions=["view", "export"]))
            release.set()
            result = await pending
        assert result.status_code == 403, "Removed chat escaped after source verification"
        assert (await client.post("/api/analysis/context-export", json=request, headers=headers)).status_code == 403


async def local_demo():
    with tempfile.TemporaryDirectory(prefix="prepared-local-demo-") as temp:
        app = app_module.create_app(Path(temp), demo=True)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as client:
                demo = await client.get("/api/demo-access")
                assert demo.json()["available"]
                headers = {"Authorization": "Bearer " + demo.json()["token"]}
                path = Path(temp) / "synthetic.zip"
                path.write_bytes(b"fictional demo archive")
                prepared = export_history.prepared(app.state.store, path, "zip", False)
                endpoint = "/api/exports/" + prepared["id"]
                response = await client.post(endpoint + "/ticket", headers=headers)
                assert response.status_code == 200, response.text
                cookie = response.cookies.get("tgwitness-download")
                downloaded = await native(app, endpoint + "/download", cookie)
                assert downloaded.status_code == 200 and downloaded.content == path.read_bytes(), downloaded.text
                response = await client.get(endpoint + "/download", headers=headers)
                assert response.status_code == 200, response.text
                response = await client.get(endpoint + "/download", headers={**headers, "X-Forwarded-For": "203.0.113.8"})
                assert response.status_code in (401, 403), "Local demo token accepted over a forwarded connection"


async def download_lifetime():
    async with workspace() as (app, client):
        store = app.state.store
        source = store.root / "synthetic.zip"
        payload = b"Exact bytes during concurrent cache eviction.\n" * 10000
        source.write_bytes(payload)
        entry = export_history.prepared(store, source, "zip", False)
        _, headers = grant_session(app)
        started, release = asyncio.Event(), asyncio.Event()

        async def held_app(scope, receive, send):
            async def held_send(message):
                if message["type"] == "http.response.body" and message.get("body") and not started.is_set():
                    started.set()
                    await release.wait()
                await send(message)
            await app(scope, receive, held_send)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=held_app), base_url="http://127.0.0.1") as downloader:
            pending = asyncio.create_task(downloader.get("/api/exports/" + entry["id"] + "/download", headers=headers))
            await asyncio.wait_for(started.wait(), 5)
            copies = list((store.root / "temporary-exports").glob("tgwitness-export-download-*"))
            assert len(copies) == 1, "No owned download copy while streaming"
            with patch.object(export_history, "LIMIT", 1):
                replacement = await asyncio.to_thread(export_history.prepared, store, source, "zip", False)
            assert not (store.root / "prepared-exports" / entry["id"]).exists(), "Active stream locked cache eviction"
            assert copies[0].exists(), "Cache eviction removed the active response"
            release.set()
            result = await pending
            assert result.status_code == 200 and result.content == payload
            assert result.headers["x-tgwitness-export-sha256"] == hashlib.sha256(payload).hexdigest()
            assert not copies[0].exists(), "Completed stream leaked its copy"

            # Cancellation after the file is open must close it and remove the
            # response copy; the retained cache remains available for retry.
            started.clear()
            release.clear()
            pending = asyncio.create_task(downloader.get("/api/exports/" + replacement["id"] + "/download", headers=headers))
            await asyncio.wait_for(started.wait(), 5)
            pending.cancel()
            try:
                await pending
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Cancelled download unexpectedly completed")
            assert not list((store.root / "temporary-exports").glob("tgwitness-export-download-*"))
            assert export_history.locate(store, replacement["id"])[0].exists()

        # OS/antivirus locks must not fail an otherwise complete export, grow
        # the cache, or silently pretend that a retry copy was retained.
        locked = store.root / "prepared-exports" / replacement["id"]
        original_unlink = Path.unlink

        def held_unlink(path, *args, **kwargs):
            if path == locked:
                raise PermissionError("Synthetic file lock")
            return original_unlink(path, *args, **kwargs)

        with patch.object(export_history, "LIMIT", 1), patch.object(Path, "unlink", held_unlink):
            uncached = export_history.prepared(store, source, "zip", False)
            assert "cleanup" in uncached["cache_warning"]
            assert not (store.root / "prepared-exports" / uncached["id"]).exists()
            assert len(list((store.root / "prepared-exports").iterdir())) == 1
            assert not export_history.listing(store)["exports"][0]["available"]
        with patch.object(export_history, "LIMIT", 1):
            retried = export_history.prepared(store, source, "zip", False)
        assert not locked.exists() and export_history.locate(store, retried["id"])[0].exists()
        assert store.get_setting(export_history.CLEANUP_KEY) == []
        assert len(list((store.root / "prepared-exports").iterdir())) == 1

        partial_path = None

        def partial_copy(source, destination):
            nonlocal partial_path
            partial_path = Path(destination)
            partial_path.write_bytes(b"incomplete copy")
            raise PermissionError("Synthetic write failure")

        def partial_unlink(path, *args, **kwargs):
            if path == partial_path:
                raise PermissionError("Synthetic antivirus lock")
            return original_unlink(path, *args, **kwargs)

        with patch.object(export_history, "LIMIT", 1), patch.object(export_history.os, "link", side_effect=OSError), \
                patch.object(export_history.shutil, "copy2", partial_copy), patch.object(Path, "unlink", partial_unlink):
            failed = export_history.prepared(store, source, "zip", False)
            assert failed["cache_warning"] and partial_path.is_file()
            assert not export_history.listing(store)["exports"][0]["available"], "Partial locked copy advertised as downloadable"
            assert (await client.get("/api/exports/" + failed["id"] + "/download")).status_code == 404
        with patch.object(export_history, "LIMIT", 1):
            complete = export_history.prepared(store, source, "zip", False)
        assert not partial_path.exists() and export_history.locate(store, complete["id"])[0].exists()
        assert len(list((store.root / "prepared-exports").iterdir())) == 1


async def main():
    await tickets()
    await account_tickets()
    await research_scope()
    await local_demo()
    await download_lifetime()
    print("Prepared downloads and research exports passed: single use, expiry, scoped access, revocation during hashing, corruption, concurrent eviction, stream cancellation, locked-file retry and ownership.")


if __name__ == "__main__":
    asyncio.run(main())
