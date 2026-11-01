"""Offline sealed-login acceptance: shared pool, explicit overrides and strict pair validation."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

import httpx
from telethon.errors import ApiIdInvalidError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import api_pool
from tgwitness.sealed import create_app
from tgwitness.sealed_crypto import keypair
from tools.browser_fixtures import CapsuleClient, QRClient, config


class RecordingClient(CapsuleClient, QRClient):
    attempts = []
    fail_ids = set()

    def __init__(self, session, api_id, api_hash, **kwargs):
        self.pair = (api_id, api_hash)
        self.attempts.append(self.pair)
        super().__init__(session, api_id, api_hash, **kwargs)

    async def connect(self):
        if self.pair[0] in self.fail_ids:
            raise ApiIdInvalidError(None)
        await super().connect()


@asynccontextmanager
async def capsule(recipient):
    with tempfile.TemporaryDirectory(prefix="sealed-login-") as temporary:
        root = Path(temporary)
        cfg = config(recipient)
        app = create_app(root / "data", root / "out", cfg, RecordingClient)
        async with app.router.lifespan_context(app):
            RecordingClient.attempts = []
            RecordingClient.fail_ids = set()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                yield app.state.session, client


async def login_cases(recipient):
    cases = ({}, {"api_id": None, "api_hash": None}, {"api_id": "", "api_hash": " "},
             {"api_id": 123, "api_hash": "0123456789abcdef" * 2},
             {"api_id": next(iter(api_pool.POOL_IDS)), "api_hash": "b" * 32})
    for method in ("phone", "qr"):
        for fields in cases:
            async with capsule(recipient) as (session, client):
                payload = {**fields, **({"phone": "+15550001111"} if method == "phone" else {})}
                response = await client.post("/api/" + method, json=payload)
                assert response.status_code == 200, (method, response.status_code)
                pair, = RecordingClient.attempts
                if isinstance(fields.get("api_id"), int):
                    assert pair == (fields["api_id"], fields["api_hash"])
                else:
                    assert pair in api_pool.POOL
                if method == "phone":
                    result = await client.post("/api/code", json={"code": "12345"})
                    assert result.status_code == 200
                else:
                    assert response.json()["svg"].startswith("<?xml")
                    session.collector.login_client.scan.set()
                    await asyncio.wait_for(session.collector.qr_task, 5)
                status = await client.get("/api/status")
                assert status.json()["authorized"] is True
                assert pair[1] not in status.text
                rejected = await client.post("/api/" + method, json=payload)
                assert rejected.status_code == 400 and len(RecordingClient.attempts) == 1
                assert (await client.post("/api/cancel", json={})).json()["phase"] == "cancelled"
                assert session.vault.read("credentials") == {}


async def invalid_cases(recipient):
    invalid = [
        {"api_id": 123}, {"api_hash": "a" * 32}, {"api_id": 123, "api_hash": None},
        {"api_id": "", "api_hash": "a" * 32}, {"api_id": 123, "api_hash": ""},
        *({"api_id": value, "api_hash": "a" * 32} for value in (False, True, 0, -1, 2147483648, 1.5, "123")),
        *({"api_id": 123, "api_hash": value} for value in ("a" * 31, "g" * 32, "a" * 32 + "\n", 123)),
        {"api_id": 123, "api_hash": "a" * 32, "session": "untrusted"},
    ]
    async with capsule(recipient) as (session, client):
        for method in ("phone", "qr"):
            for fields in invalid:
                payload = {**fields, **({"phone": "+15550001111"} if method == "phone" else {})}
                response = await client.post("/api/" + method, json=payload)
                assert response.status_code == 422, (method, response.status_code)
                assert response.json() == {"detail": "Invalid request fields"}
                assert not RecordingClient.attempts and session.collector.login_client is None
        assert (await client.post("/api/qr", json={}, headers={"Authorization": "Bearer invalid"})).status_code == 401
        assert (await client.post("/api/qr", json={}, headers={"Origin": "https://untrusted.invalid"})).status_code == 403
        assert not RecordingClient.attempts


async def pool_and_override_failures(recipient):
    pairs = [(700001, "c" * 32), (700002, "d" * 32)]
    async with capsule(recipient) as (session, client), _context_patch_pool(pairs):
        RecordingClient.fail_ids = {pairs[0][0]}
        response = await client.post("/api/phone", json={"phone": "+15550001111"})
        assert response.status_code == 200
        assert RecordingClient.attempts == pairs
        assert session.collector.login_client.pair == pairs[1]
    async with capsule(recipient) as (_, client):
        pair = (next(iter(api_pool.POOL_IDS)), "e" * 32)
        RecordingClient.fail_ids = {pair[0]}
        rejected_before = api_pool.rejected.copy()
        with patch.object(api_pool, "login_order", side_effect=AssertionError("Custom credentials fell back to pool")):
            response = await client.post("/api/phone", json={"phone": "+15550001111", "api_id": pair[0], "api_hash": pair[1]})
        assert response.status_code == 400
        assert RecordingClient.attempts == [pair] and api_pool.rejected == rejected_before

    async with capsule(recipient) as (session, _):
        collector = session.collector
        saved = next(pair for pair in api_pool.POOL if pair[0] not in api_pool.rejected)
        session.vault.save("credentials", {"api_id": saved[0], "api_hash": saved[1]})
        assert collector.login_pairs(None, None)[0] == saved
        own = (123, "f" * 32)
        session.vault.save("credentials", {"api_id": own[0], "api_hash": own[1]})
        assert collector.login_pairs(None, None) == [own]

    async with capsule(recipient) as (session, client):
        # A saved custom hash must remain authoritative even when its ID matches a pool ID.
        own = (next(iter(api_pool.POOL_IDS)), "f" * 32)
        assert own not in api_pool.POOL
        session.vault.save("credentials", {"api_id": own[0], "api_hash": own[1]})
        with patch.object(api_pool, "login_order", side_effect=AssertionError("Saved custom pair replaced by pool")):
            response = await client.post("/api/phone", json={"phone": "+15550001111"})
            assert response.status_code == 200
            assert RecordingClient.attempts == [own]
            await session.collector.cancel_login()
            RecordingClient.attempts = []
            RecordingClient.fail_ids = {own[0]}
            response = await client.post("/api/qr", json={})
            assert response.status_code == 400
            assert RecordingClient.attempts == [own]


@asynccontextmanager
async def _context_patch_pool(pairs):
    with patch.object(api_pool, "login_order", return_value=pairs):
        yield


async def main():
    recipient = keypair()
    with patch.object(socket, "create_connection", side_effect=AssertionError("Network prohibited")), \
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited")):
        await login_cases(recipient)
        await invalid_cases(recipient)
        await pool_and_override_failures(recipient)
    print("Sealed login passed: default/custom phone and QR, pair validation before connection, pool retry, no custom fallback, authentication and revocation.")


if __name__ == "__main__":
    asyncio.run(main())
