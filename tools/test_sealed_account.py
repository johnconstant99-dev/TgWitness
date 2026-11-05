"""Restricted HTTP account export: fresh auth, Takeout approval, native views and time limit."""
import asyncio
import json
from pathlib import Path
import sys
import zipfile

import httpx
import pytest
from telethon import errors

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.sealed import create_app
from tgwitness.sealed_crypto import keypair
from tgwitness.verify import verify_bundle
from tools.browser_fixtures import CapsuleClient, QRClient, config
from tools.test_file_hash_export import CONTENT, ExportTransport


class AccountClient(CapsuleClient, QRClient):
    pass


def test_stop_error_still_revokes_fresh_authorization(tmp_path, key):
    async def run():
        cfg = config(key)
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, CapsuleClient)
        async with app.router.lifespan_context(app):
            session = app.state.session
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                await login(client, session, "2fa")
                original = session.collector.stop

                async def broken_stop(shutdown=False):
                    await original(shutdown=shutdown)
                    raise OSError("Synthetic disconnect failure")

                session.collector.stop = broken_stop
                try:
                    await session.finish("operator_finished")
                finally:
                    session.collector.stop = original
                assert session.phase == "failed" and session.revocation == "revoked"
                assert not session.vault.read("credentials")
                assert not (tmp_path / "out/evidence.zip").exists()
    asyncio.run(run())


@pytest.fixture(scope="module")
def key():
    return keypair()


async def login(client, session, method):
    credentials = {"api_id": 123, "api_hash": "a" * 32}
    if method in ("qr", "qr_2fa"):
        response = await client.post("/api/qr", json=credentials)
        assert response.status_code == 200, response.text
        login_id = response.json()["id"]
        if method == "qr_2fa":
            session.collector.login_client.qr_outcome = "password"
        session.collector.login_client.scan.set()
        async with asyncio.timeout(10):
            while not session.store.get_setting("account", None):
                await client.get("/api/qr/" + login_id)
                if session.collector.phase == "password_required":
                    assert (await client.post("/api/password", json={"password": "fictional-test-password"})).status_code == 200
                await asyncio.sleep(.01)
    else:
        assert (await client.post("/api/phone", json={**credentials, "phone": "+15550001111"})).status_code == 200
        assert (await client.post("/api/code", json={"code": "22222" if method == "2fa" else "12345"})).status_code == 200
        if method == "2fa":
            assert session.collector.phase == "password_required"
            assert (await client.post("/api/password", json={"password": "fictional-test-password"})).status_code == 200


@pytest.mark.parametrize("method", ["phone", "2fa", "qr", "qr_2fa"])
@pytest.mark.parametrize("transport", ["regular", "takeout"])
@pytest.mark.parametrize("media_action", ["download", "hashes_only", "exclude"])
def test_fresh_account_capture_through_http(tmp_path, key, method, transport, media_action):
    async def run():
        cfg = config(key)
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, AccountClient)
        approved = False

        class Network(ExportTransport):
            account_id = 44
            async def open(self):
                if transport == "takeout" and not approved:
                    raise errors.TakeoutInitDelayError(None, capture=3600)

            async def download(self, media, stream, progress, task):
                assert media_action == "download"
                stream.write(CONTENT)
                return stream

        async with app.router.lifespan_context(app):
            session = app.state.session
            session.account_export.transport_factory = Network
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                body = {"mode": "account", "account_options": {"transport": transport, "export_format": "telegram_both",
                    "media_action": media_action, "include_profile": False, "include_contacts": False}}
                assert (await client.post("/api/collect", json=body)).status_code == 400
                await login(client, session, method)
                response = await client.post("/api/collect", json=body)
                assert response.status_code == 200, response.text
                await asyncio.wait_for(session.account_export.task, 10)
                if transport == "takeout":
                    state = (await client.get("/api/status")).json()["account_export"]
                    assert state["wait_reason"] == "takeout_approval" and state["delay_seconds"] == 3600
                    assert not state["ready"] and not state["active"]
                    approved = True
                    response = await client.post("/api/resume", json={})
                    assert response.status_code == 200, response.text
                await asyncio.wait_for(asyncio.shield(session.monitor_task), 20)
                assert session.phase == "sealed", session.reason
                assert session.revocation == "revoked" and not session.vault.read("credentials")
                path = tmp_path / "out/evidence.zip"
                verified = verify_bundle(path)
                assert verified["account_export"]["counts"]["messages"] == 2
                assert verified["account_export"]["complete_within_scope"]
                with zipfile.ZipFile(path) as archive:
                    with archive.open("account-export.zip") as nested, zipfile.ZipFile(nested) as account:
                        native = json.loads(account.read("result.json"))
                        assert len(native["chats"]["list"][0]["messages"]) == 2
                        assert "export_results.html" in account.namelist()
                        assert not any(n.startswith("attachment-queue/") for n in account.namelist())
    asyncio.run(run())


def test_deadline_during_takeout_approval_produces_partial_archive_and_revokes(tmp_path, key):
    async def run():
        cfg = config(key)
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, CapsuleClient)

        class Waiting(ExportTransport):
            account_id = 44
            async def open(self):
                raise errors.TakeoutInitDelayError(None, capture=86400)

        async with app.router.lifespan_context(app):
            session = app.state.session
            session.account_export.transport_factory = Waiting
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                await login(client, session, "2fa")
                assert (await client.post("/api/collect", json={"mode": "account", "account_options": {"transport": "takeout"}})).status_code == 200
                await session.account_export.task
                session.started -= 61
                await asyncio.wait_for(asyncio.shield(session.monitor_task), 10)
                assert session.phase == "sealed" and session.revocation == "revoked"
                result = verify_bundle(tmp_path / "out/evidence.zip")["account_export"]
                assert not result["complete_within_scope"] and result["counts"]["messages"] == 0
                assert "deadline" in result["coverage"]["gaps"][0]
    asyncio.run(run())
