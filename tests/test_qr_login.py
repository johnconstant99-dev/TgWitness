import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient
from telethon.errors import SessionPasswordNeededError

from tgwitness.app import create_app
from tgwitness.collector import Collector
from test_collector import CHAT, FakeClient, saved_session


class QRClient(FakeClient):
    async def qr_login(self):
        self.scan = asyncio.Event()
        self.loop = asyncio.get_running_loop()
        self.qr_outcome = "authorized"
        async def wait():
            await self.scan.wait()
            if self.qr_outcome == "password":
                raise SessionPasswordNeededError(None)
            if self.qr_outcome == "expired":
                raise TimeoutError()
            self.authorized = True
            return await self.get_me()
        return NS(url="tg://login?token=c3ludGhldGljLXFS", expires=datetime.now(timezone.utc)+timedelta(seconds=60), wait=wait)


@pytest.mark.parametrize("outcome", ["authorized", "password", "expired"])
def test_qr_lifecycle_and_no_token_persistence(journal, outcome):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, QRClient)
        result = await collector.start_qr(123, "a"*32)
        candidate = collector.login_client
        candidate.qr_outcome = outcome
        task = collector.qr_task
        candidate.scan.set()
        await task
        if outcome == "password":
            assert collector.poll_qr(result["id"])["step"] == "password"
            assert not vault.read("credentials")
            await collector.confirm_password("synthetic-password")
        if outcome != "expired":
            assert collector.poll_qr(result["id"])["step"] == "authorized"
            assert vault.read("credentials")["session"] == saved_session()
            assert not collector.running
        else:
            assert collector.poll_qr(result["id"])["step"] == "expired"
            assert not candidate.connected and collector.login_client is None
        assert "tg://login" not in str(store.all_events())
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_qr_cancellation_stale_cancel_and_account_rejection(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, QRClient)
        await collector.configure(123, "a"*32, saved_session())
        original = collector.client
        first = await collector.start_qr(999, "b"*32)
        cancelled = collector.login_client
        second = await collector.start_qr(999, "b"*32)
        assert not cancelled.connected
        await collector.cancel_qr(first["id"])
        assert collector.poll_qr(second["id"])["step"] == "qr"
        task = collector.qr_task
        rejected = collector.login_client
        rejected.scan.set()
        await task
        assert collector.poll_qr(second["id"])["step"] == "failed"
        assert collector.client is original and not rejected.connected
        assert store.get_setting("account")["id"] == 44
        third = await collector.start_qr(123, "a"*32)
        task = collector.qr_task
        collector.login_client.scan.set()
        await task
        store.set_target(CHAT, "Synthetic source", "supergroup", True)
        await collector.start()
        await collector.cancel_qr(third["id"])
        assert collector.running and collector.phase == "observing"
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_imported_account_claim_is_checked_online(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, QRClient)
        with pytest.raises(ValueError, match="imported account ID"):
            await collector.configure(123, "a"*32, saved_session(), expected_user_id=45)
        assert not vault.read("credentials") and collector.login_client is None
        assert not QRClient.instances[-1].connected
    asyncio.run(run())


def test_qr_api_authentication_image_and_profile_isolation(tmp_path):
    app = create_app(tmp_path, client_factory=QRClient)
    with TestClient(app) as client:
        body = {"api_id":123, "api_hash":"a"*32}
        assert client.post("/api/auth/qr/start", json=body).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        response = client.post("/api/auth/qr/start", json=body)
        assert response.status_code == 200
        qr = response.json()
        assert qr["image"].startswith("data:image/svg+xml;base64,") and "url" not in qr
        child = client.post("/api/profiles", json={"label":"Another account"}).json()["id"]
        assert client.get("/profiles/"+child+"/api/auth/qr/"+qr["id"]).json()["step"] == "cancelled"
        assert client.get("/api/auth/qr/"+qr["id"]).json()["step"] == "qr"
        candidate = app.state.collector.login_client
        assert client.post("/api/auth/qr/"+qr["id"]+"/cancel", json={}).status_code == 200
        assert not candidate.connected
