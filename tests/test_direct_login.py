import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from telethon.errors import ApiIdInvalidError

from tgwitness import api_pool
from tgwitness.app import create_app
from tgwitness.collector import Collector
from test_collector import saved_session
from test_qr_login import QRClient


def test_phone_start_reaches_code_and_only_saves_after_authorization(tmp_path):
    app = create_app(tmp_path, client_factory=QRClient)
    with TestClient(app) as client:
        body = {"phone": "+15550001111", "api_id": 123, "api_hash": "a" * 32}
        assert client.post("/api/auth/phone/start", json=body).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        response = client.post("/api/auth/phone/start", json=body)
        assert response.json() == {"step": "code"}
        assert not app.state.vault.read("credentials")
        assert client.post("/api/auth/code", json={"code": "22222"}).json()["step"] == "password"
        assert client.post("/api/auth/password", json={"password": "synthetic"}).json()["step"] == "authorized"
        status = client.get("/api/status").json()
        assert status["collector"]["has_api_credentials"]
        assert not status["collector"]["running"] and not status["targets"]
        assert "a" * 32 not in json.dumps(status)
        assert "password" not in app.state.vault.read("credentials")


def test_saved_api_credentials_work_for_phone_qr_and_import_only_in_their_profile(tmp_path):
    app = create_app(tmp_path, client_factory=QRClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        explicit = {"api_id": 123, "api_hash": "a" * 32, "session": saved_session()}
        assert client.post("/api/auth/configure", json=explicit).json()["step"] == "authorized"
        original = dict(app.state.vault.read("credentials"))
        assert client.post("/api/auth/phone/start", json={"phone": "+15550001111"}).json()["step"] == "code"
        qr = client.post("/api/auth/qr/start", json={})
        assert qr.status_code == 200 and qr.json()["step"] == "qr"
        assert client.post("/api/auth/configure", json={"session": saved_session()}).json()["step"] == "authorized"
        child = client.post("/api/profiles", json={"label": "Empty workspace"}).json()["id"]
        prefix = "/profiles/" + child + "/api"
        status = client.get(prefix + "/status").json()["collector"]
        assert not status["has_api_credentials"] and status["builtin_api"]
        # Another workspace never borrows the saved pair; it falls back to the built-in one.
        assert client.post(prefix + "/auth/phone/start", json={"phone": "+15550001111"}).json()["step"] == "code"
        assert QRClient.instances[-1].account_id in api_pool.POOL_IDS
        assert client.post(prefix + "/auth/qr/start", json={}).json()["step"] == "qr"
        assert app.state.vault.read("credentials") == original


def test_partial_credentials_are_rejected_and_missing_ones_use_the_builtin_pool(tmp_path):
    app = create_app(tmp_path, client_factory=QRClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        for body in ({"api_id": 123}, {"api_hash": "a" * 32}, {"api_id": 123, "api_hash": "short"}):
            response = client.post("/api/auth/phone/start", json={**body, "phone": "+15550001111"})
            assert response.status_code == 422
            assert "a" * 32 not in response.text
        assert app.state.collector.login_client is None
        assert client.post("/api/auth/phone/start", json={"phone": "+15550001111"}).json() == {"step": "code"}
        candidate = app.state.collector.login_client
        assert candidate.account_id in api_pool.POOL_IDS
        device = {key: candidate.options[key] for key in api_pool.DESKTOP_DEVICE if key in candidate.options}
        assert device == (api_pool.DESKTOP_DEVICE if candidate.account_id == api_pool.DESKTOP_ID else {})
        assert not app.state.vault.read("credentials")  # Saved only after authorization.
        assert client.post("/api/auth/code", json={"code": "22222"}).json()["step"] == "password"
        assert client.post("/api/auth/password", json={"password": "synthetic"}).json()["step"] == "authorized"
        assert app.state.vault.read("credentials")["api_id"] == candidate.account_id
        assert client.get("/api/status").json()["collector"]["builtin_api"]


def test_explicit_credentials_do_not_send_the_builtin_client_description(tmp_path):
    app = create_app(tmp_path, client_factory=QRClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        body = {"phone": "+15550001111", "api_id": 123, "api_hash": "a" * 32}
        assert client.post("/api/auth/phone/start", json=body).json() == {"step": "code"}
        assert not set(api_pool.DESKTOP_DEVICE) & set(app.state.collector.login_client.options)


class RejectingClient(QRClient):
    refused = set()

    async def send_code_request(self, phone):
        if self.account_id in self.refused:
            raise ApiIdInvalidError(None)
        return await super().send_code_request(phone)

    async def qr_login(self):
        if self.account_id in self.refused:
            raise ApiIdInvalidError(None)
        return await super().qr_login()


@pytest.fixture
def fresh_pool(monkeypatch):
    monkeypatch.setattr(api_pool, "rejected", set())
    yield
    RejectingClient.refused = set()


@pytest.mark.parametrize("method", ["phone", "qr"])
def test_refused_pool_pairs_are_skipped_until_one_works(journal, fresh_pool, monkeypatch, method):
    async def run():
        store, vault = journal
        login_order = api_pool.login_order
        order = login_order()
        RejectingClient.refused = {pair[0] for pair in order[:3]}
        collector = Collector(store, vault, RejectingClient)
        first = len(RejectingClient.instances)
        monkeypatch.setattr(api_pool, "login_order", lambda first=None: order)
        result = await (collector.start_phone("+15550001111") if method == "phone" else collector.start_qr())
        monkeypatch.setattr(api_pool, "login_order", login_order)
        assert result["step"] == ("code" if method == "phone" else "qr")
        tried = [client.account_id for client in RejectingClient.instances[first:]]
        assert tried == [pair[0] for pair in order[:4]]
        assert not any(client.connected for client in RejectingClient.instances[first:-1])
        assert collector.login_client.account_id == order[3][0]
        assert RejectingClient.refused <= api_pool.rejected
        assert all(pair[0] not in RejectingClient.refused for pair in api_pool.login_order())
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_own_pair_is_never_replaced_by_the_pool(journal, fresh_pool):
    async def run():
        store, vault = journal
        RejectingClient.refused = {44}  # FakeClient maps the own API ID 123 to account 44.
        collector = Collector(store, vault, RejectingClient)
        with pytest.raises(ApiIdInvalidError):
            await collector.start_phone("+15550001111", 123, "a" * 32)
        assert collector.login_client is None and collector.phase == "offline"
        assert not api_pool.rejected
    asyncio.run(run())


def test_every_pool_pair_is_well_formed():
    assert len(api_pool.POOL) == len(api_pool.POOL_IDS) == 50
    assert all(0 < api_id <= 2147483647 and len(api_hash) == 32 and int(api_hash, 16) >= 0
               for api_id, api_hash in api_pool.POOL)
