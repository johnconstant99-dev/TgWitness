"""Adversarial capsule boundaries and encrypted handoff; no real accounts or network."""
import asyncio
import json
import secrets
import time
import zipfile
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace as NS

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from tgwitness import sealed, sealed_crypto, sealed_package, sealed_verify
from tgwitness.verify import verify_bundle
from test_collector import CHAT, FakeClient, telegram_message, media_message


@pytest.fixture(scope="module")
def recipient():
    return sealed_crypto.keypair()


class CapsuleClient(FakeClient):
    logout_calls = 0

    async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
        rows = [media_message(3), telegram_message(2, "Private synthetic text"), telegram_message(1)]
        return [m for m in rows if not offset_id or m.id < offset_id][:limit]

    async def log_out(self):
        type(self).logout_calls += 1
        return await super().log_out()


def config(recipient):
    return {"token": secrets.token_urlsafe(32), "recipient": recipient["recipient"], "seconds": 60,
            "context": {"collector_sha": "a" * 40, "repository": "user/fork", "run_id": "123", "run_attempt": "1"}}


def login(client, headers):
    assert client.post("/api/phone", headers=headers,
        json={"api_id": 123, "api_hash": "a" * 32, "phone": "+15550001111"}).status_code == 200
    assert client.post("/api/code", headers=headers, json={"code": "12345"}).status_code == 200
    assert client.get("/api/dialogs", headers=headers).status_code == 200


def completed(client, headers):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = client.get("/api/status", headers=headers).json()
        if value["phase"] in sealed.TERMINAL:
            return value
        time.sleep(.03)
    raise AssertionError("Synthetic capsule did not finish")


def test_full_capture_handoff_and_strict_verifier(tmp_path, recipient):
    cfg = config(recipient)
    headers = {"Authorization": "Bearer " + cfg["token"]}
    app = sealed.create_app(tmp_path / "data", tmp_path / "out", cfg, CapsuleClient)
    with TestClient(app) as client:
        login(client, headers)
        assert client.post("/api/collect", headers=headers, json={"chat_id": CHAT}).status_code == 200
        assert completed(client, headers)["phase"] == "sealed"
        assert client.post("/api/collect", headers=headers, json={"chat_id": CHAT}).status_code == 409
        assert app.state.session.vault.read("credentials") == {}
        events = app.state.session.store.all_events()
        assert {e["chat_id"] for e in events if e["kind"] == "message.snapshot"} == {CHAT}
        assert len([e for e in events if e["kind"] == "message.snapshot"]) == 3
        assert len([e for e in events if e["kind"] == "media.saved"]) == 1
        assert [e for e in events if e["kind"] == "sealed.finished"][0]["payload"]["revocation"] == "revoked"
    evidence = tmp_path / "out" / "evidence.zip"
    assert verify_bundle(evidence)["events"] >= 3

    attestation = tmp_path / "synthetic-attestation.jsonl"
    attestation.write_text('{"synthetic":true}\n')
    sealed_package.package(cfg, tmp_path / "out", attestation)
    delivery = tmp_path / "delivery.zip"
    sealed_crypto.decrypt_file(tmp_path / "out" / "delivery.tgwsealed", delivery, recipient)
    with zipfile.ZipFile(delivery) as archive:
        assert set(archive.namelist()) == {"evidence.zip", "attestation.jsonl", "README.txt"}
        assert archive.read("evidence.zip") == evidence.read_bytes()
        assert b"credentials" not in b" ".join(n.encode() for n in archive.namelist())
    policy = tmp_path / "trusted-policy.json"
    policy.write_text(json.dumps({"format": "tgwitness-sealed-policy-v1", "workflow": sealed_verify.WORKFLOW,
        "releases": [{"workflow_sha": "b" * 40, "collector_sha": "a" * 40}]}))
    called = []
    def approved(args, **kwargs):
        called.append(args)
        return NS(returncode=0, stdout='[{"verificationResult":{}}]')
    result = sealed_verify.verify(evidence, attestation, "user/fork", policy=policy, run=approved)
    assert result["verified"] and result["collection"]["history"]["captured"] == 3
    assert "--deny-self-hosted-runners" in called[0]
    assert called[0][called[0].index("--signer-digest") + 1] == "b" * 40
    assert called[0][called[0].index("--signer-workflow") + 1] == sealed_verify.WORKFLOW
    with pytest.raises(ValueError, match="did not match"):
        sealed_verify.verify(evidence, attestation, "user/fork", policy=policy,
                             run=lambda *a, **k: NS(returncode=1, stdout=""))
    with pytest.raises(ValueError, match="fresh-session"):
        sealed_verify.verify(evidence, attestation, "other/fork", policy=policy, run=approved)

    policy.write_text(json.dumps({"format": "tgwitness-sealed-policy-v1", "workflow": sealed_verify.WORKFLOW,
                                 "releases": []}))
    with pytest.raises(ValueError, match="No approved"):
        sealed_verify.verify(evidence, attestation, "user/fork", policy=policy, run=approved)


def test_http_surface_refuses_imports_overrides_and_unsigned_outputs(tmp_path, recipient):
    cfg = config(recipient)
    headers = {"Authorization": "Bearer " + cfg["token"]}
    with TestClient(sealed.create_app(tmp_path / "data", tmp_path / "out", cfg, CapsuleClient)) as client:
        assert client.get("/api/status").status_code == 401
        assert cfg["token"] not in client.get("/").text
        for path in ("/style.css", "/theme.js", "/mark.svg"):
            assert client.get(path).status_code == 200
        for path in ("auth/import", "auth/configure", "network", "parameters", "snapshot", "sign", "export/zip",
                     "profiles", "access/admin", "replica", "source-check"):
            assert client.post("/api/" + path, headers=headers, json={}).status_code == 404
        for path in ("/api/export/zip", "/data/credentials.enc", "/api/media/abc", "/docs", "/openapi.json", "/app.js", "/capture.html"):
            assert client.get(path, headers=headers).status_code == 404
        response = client.post("/api/phone", headers=headers, json={"api_id":123,"api_hash":"a"*32,
            "phone":"+15550001111", "session":"IMPORTED_SECRET"})
        assert response.status_code == 422 and "IMPORTED_SECRET" not in response.text
        assert client.post("/api/collect", headers=headers, json={"chat_id":CHAT,"text":"invented"}).status_code == 422
        assert client.post("/api/collect", headers={**headers,"Origin":"https://attacker.invalid"},
                           json={"chat_id":CHAT}).status_code == 403
        assert client.post("/api/collect", headers=headers, content=b"x"*17000).status_code == 413
        assert client.post("/api/collect", headers=headers, json={"chat_id":CHAT}).status_code == 400
        login(client, headers)
        assert client.post("/api/collect", headers=headers, json={"chat_id":123456}).status_code == 400
        assert client.post("/api/cancel", headers=headers, json={}).status_code == 200
        assert client.get("/api/status", headers=headers).json()["phase"] == "cancelled"
        assert not (tmp_path / "out" / "evidence.zip").exists()


def test_deadline_seals_partial_capture_and_records_revocation_failure(tmp_path, recipient):
    class Blocked(CapsuleClient):
        async def get_messages(self, *args, **kwargs):
            await asyncio.Event().wait()
        async def log_out(self):
            raise OSError("synthetic failure")
    cfg = config(recipient)
    headers = {"Authorization":"Bearer " + cfg["token"]}
    app = sealed.create_app(tmp_path / "data", tmp_path / "out", cfg, Blocked)
    with TestClient(app) as client:
        login(client, headers)
        assert client.post("/api/collect", headers=headers, json={"chat_id":CHAT}).status_code == 200
        app.state.session.started -= 65
        assert completed(client, headers)["phase"] == "sealed"
        last = app.state.session.store.all_events()[-1]
        assert last["kind"] == "sealed.finished"
        assert last["payload"]["reason"] == "deadline"
        assert last["payload"]["history"]["phase"] == "paused"
        assert last["payload"]["revocation"] == "not_confirmed"


@pytest.mark.parametrize("confirmed", [True, False])
def test_cancel_pending_login_preserves_revocation_result(tmp_path, recipient, confirmed):
    class Pending(CapsuleClient):
        async def log_out(self):
            if not confirmed:
                raise OSError("synthetic logout failure")
            return await super().log_out()
    cfg = config(recipient)
    headers = {"Authorization": "Bearer " + cfg["token"]}
    app = sealed.create_app(tmp_path / "data", tmp_path / "out", cfg, Pending)
    with TestClient(app) as client:
        assert client.post("/api/phone", headers=headers,
            json={"api_id":123,"api_hash":"a"*32,"phone":"+15550001111"}).status_code == 200
        assert client.post("/api/cancel", headers=headers, json={}).status_code == 200
        status = client.get("/api/status", headers=headers).json()
        assert status["phase"] == "cancelled"
        assert status["revocation"] == ("revoked" if confirmed else "not_confirmed")
        assert app.state.session.collector.login_client is None
        assert not (tmp_path / "out" / "evidence.zip").exists()


@pytest.mark.parametrize("directory", ["data", "out"])
def test_preloaded_state_is_rejected(tmp_path, recipient, directory):
    target = tmp_path / directory
    target.mkdir()
    (target / "injected.txt").write_text("fake")
    with pytest.raises(ValueError, match="empty"):
        with TestClient(sealed.create_app(tmp_path / "data", tmp_path / "out", config(recipient), CapsuleClient)):
            pass


def test_crypto_roundtrip_tampering_wrong_key_and_no_overwrite(tmp_path, recipient):
    source = tmp_path / "plain"
    source.write_bytes(b"synthetic private bytes" * 80000)
    encrypted, opened = tmp_path / "sealed", tmp_path / "opened"
    sealed_crypto.encrypt_file(source, encrypted, recipient["recipient"])
    assert source.read_bytes()[:100] not in encrypted.read_bytes()
    sealed_crypto.decrypt_file(encrypted, opened, recipient)
    assert opened.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        sealed_crypto.decrypt_file(encrypted, opened, recipient)
    with pytest.raises(FileExistsError):
        sealed_crypto.encrypt_file(source, encrypted, recipient["recipient"])
    assert encrypted.exists()
    opened.unlink()
    with pytest.raises(ValueError):
        sealed_crypto.decrypt_file(encrypted, opened, sealed_crypto.keypair())
    assert not opened.exists()
    original = encrypted.read_bytes()
    for position in (-1, -18, len(original)//2):
        changed = bytearray(original)
        changed[position] ^= 1
        encrypted.write_bytes(changed)
        with pytest.raises(InvalidTag):
            sealed_crypto.decrypt_file(encrypted, opened, recipient)
        assert not opened.exists() and not list(tmp_path.glob(".tgw-unseal-*"))
    encrypted.write_bytes(original[:20])
    with pytest.raises((ValueError, json.JSONDecodeError)):
        sealed_crypto.decrypt_file(encrypted, opened, recipient)


def test_encrypted_connection_contains_no_public_access_token(tmp_path, recipient):
    cfg = config(recipient)
    out = tmp_path / "connection.tgwsealed"
    sealed_package.connection(cfg, "https://synthetic.trycloudflare.com", out)
    assert cfg["token"].encode() not in out.read_bytes()
    opened = tmp_path / "connection.json"
    sealed_crypto.decrypt_file(out, opened, recipient)
    assert json.loads(opened.read_bytes())["url"].endswith("#access=" + cfg["token"])
    for url in ("http://example.com", "https://trycloudflare.com.attacker.invalid", "https://a.trycloudflare.com:443",
                "https://user:pass@a.trycloudflare.com", "https://a.trycloudflare.com/path"):
        with pytest.raises(ValueError):
            sealed_package.connection(cfg, url, tmp_path / "bad")


def test_qr_login_and_two_factor_and_no_replacement_of_pending_key(tmp_path, recipient):
    class QRClient(CapsuleClient):
        async def qr_login(self):
            async def scan():
                await asyncio.sleep(.1)
                self.authorized = True
            return NS(url="tg://login?token=synthetic", expires=datetime.now(timezone.utc)+timedelta(minutes=1), wait=scan)
    cfg = config(recipient)
    headers = {"Authorization":"Bearer " + cfg["token"]}
    with TestClient(sealed.create_app(tmp_path / "qr-data", tmp_path / "qr-out", cfg, QRClient)) as client:
        response = client.post("/api/qr", headers=headers, json={"api_id":123,"api_hash":"a"*32})
        assert response.status_code == 200 and "<svg" in response.json()["svg"]
        deadline = time.monotonic() + 3
        while not client.get("/api/status", headers=headers).json()["authorized"]:
            assert time.monotonic() < deadline
            time.sleep(.02)
        assert client.get("/api/qr/" + response.json()["id"], headers=headers).json()["step"] == "authorized"
        assert client.post("/api/qr", headers=headers, json={"api_id":123,"api_hash":"a"*32}).status_code == 400
    with TestClient(sealed.create_app(tmp_path / "phone-data", tmp_path / "phone-out", cfg, CapsuleClient)) as client:
        body = {"api_id":123,"api_hash":"a"*32,"phone":"+15550001111"}
        assert client.post("/api/phone", headers=headers, json=body).status_code == 200
        assert client.post("/api/phone", headers=headers, json=body).status_code == 400
        assert client.post("/api/code", headers=headers, json={"code":"22222"}).json()["step"] == "password"
        assert client.post("/api/password", headers=headers, json={"password":"synthetic-2fa"}).status_code == 200
        assert client.get("/api/status", headers=headers).json()["authorized"]


def test_explicit_finish_of_paused_history_and_shutdown_does_not_race_export(tmp_path, recipient):
    class Paused(CapsuleClient):
        async def get_messages(self, *args, **kwargs):
            raise TimeoutError("synthetic")
    cfg = config(recipient)
    headers = {"Authorization":"Bearer " + cfg["token"]}
    app = sealed.create_app(tmp_path / "data", tmp_path / "out", cfg, Paused)
    with TestClient(app) as client:
        login(client, headers)
        assert client.post("/api/collect", headers=headers, json={"chat_id":CHAT}).status_code == 200
        assert client.post("/api/finish", headers=headers, json={}).status_code == 202

    assert (tmp_path / "out" / "evidence.zip").is_file()
    assert verify_bundle(tmp_path / "out" / "evidence.zip")["events"] > 0
