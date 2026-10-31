import json
from fastapi.testclient import TestClient
import pytest

from tgwitness.app import create_app
from tgwitness.verify import verify_bundle
from test_collector import FakeClient, CHAT


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        yield c, app


def test_access_control_and_headers(client):
    c, app = client
    response = c.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert c.get("/api/status", headers={"Authorization":"Bearer wrong"}).status_code == 401
    assert c.get("/api/export/zip", headers={"Authorization":""}).status_code == 401
    assert c.post("/api/collector/start", headers={"Authorization":""}, json={}).status_code == 401
    assert c.get("/panel-token.txt").status_code == 404
    assert c.get("/api/status").status_code == 200


def test_validation_never_echoes_credentials(client):
    c, _ = client
    response = c.post("/api/auth/configure", json={"api_id":123,"api_hash":"VERY_PRIVATE_SECRET"})
    assert response.status_code == 422
    assert "VERY_PRIVATE_SECRET" not in response.text


def test_timestamp_request_requires_auth_and_binds_signed_checkpoint(client):
    import hashlib
    import zipfile
    from io import BytesIO
    from tgwitness.verify import verify_checkpoint
    c, app = client
    assert c.get("/api/anchor-request", headers={"Authorization":""}).status_code == 401
    response = c.get("/api/anchor-request")
    assert response.status_code == 200
    with zipfile.ZipFile(BytesIO(response.content)) as archive:
        data = archive.read("checkpoint.json")
        assert hashlib.sha256(data).digest() in archive.read("timestamp.tsq")
        with app.state.store.snapshot() as snapshot:
            verify_checkpoint(json.loads(data), app.state.vault.public_key,
                              snapshot.head["seq"], snapshot.hash_at)


def test_chunked_body_limit_is_enforced_without_content_length(client):
    c, _ = client
    def chunks():
        for i in range(20):
            yield b"x" * 1024
    response = c.post("/api/auth/configure", content=chunks(), headers={"Content-Type":"application/json"})
    assert response.status_code == 413
    assert c.get("/api/status").status_code == 200


def test_api_login_targets_capture_and_export(client, tmp_path):
    c, app = client
    assert c.post("/api/auth/configure", json={"api_id":123,"api_hash":"a"*32}).json()["step"] == "phone"
    assert c.post("/api/auth/phone", json={"phone":"+15551112222"}).status_code == 200
    assert c.post("/api/auth/code", json={"code":"12345"}).json()["step"] == "authorized"
    assert c.post("/api/targets", json={"chat_id":CHAT,"enabled":True}).status_code == 400
    assert [d["kind"] for d in c.get("/api/dialogs").json()["dialogs"]] == ["supergroup", "private"]
    assert c.post("/api/targets", json={"chat_id":CHAT,"enabled":True}).status_code == 200
    assert c.post("/api/collector/start", json={}).status_code == 200
    assert c.post("/api/snapshot", json={"chat_id":CHAT,"limit":3}).json()["captured"] == 3
    assert c.post("/api/capture", json={"download_media":True,"max_media_mb":3000}).status_code == 422
    assert c.post("/api/collector/stop", json={}).status_code == 200
    assert c.post("/api/verify", json={}).status_code == 200
    for fmt in ("csv", "html", "jsonl", "zip"):
        r = c.get("/api/export/" + fmt)
        assert r.status_code == 200
        assert "attachment;" in r.headers["content-disposition"]
        if fmt == "zip":
            path = tmp_path / "export.zip"
            path.write_bytes(r.content)
            assert verify_bundle(path)["events"] >= 3
    status = c.get("/api/status").json()
    assert "api_hash" not in json.dumps(status) and "session" not in status


def test_password_protected_export_wraps_the_signed_archive(client, tmp_path):
    import zipfile
    import pyzipper
    c, _ = client
    assert c.post("/api/export/zip", json={"password": "too short"}).status_code == 422
    secret = "correct horse battery staple"
    response = c.post("/api/export/zip", json={"password": secret})
    assert response.status_code == 200
    assert "tgwitness-evidence-zip-encrypted.zip" in response.headers["content-disposition"]
    outer = tmp_path / "protected.zip"
    outer.write_bytes(response.content)
    with pyzipper.AESZipFile(outer) as archive:
        info = archive.getinfo("tgwitness-evidence.zip")
        assert info.flag_bits & 1 and response.content[8:10] == (99).to_bytes(2, "little")
        field = info.extra[info.extra.index(b"\x01\x99"):]
        assert field[6:8] == b"AE" and field[8] == 3
        with pytest.raises(RuntimeError):
            archive.read(info.filename, pwd=b"wrong password, twelve+")
        inner = archive.read(info.filename, pwd=secret.encode())
    (tmp_path / "inner.zip").write_bytes(inner)
    assert verify_bundle(tmp_path / "inner.zip")["events"] >= 1
    with zipfile.ZipFile(tmp_path / "inner.zip") as signed:
        assert not any(name.encode() in response.content for name in signed.namelist())
    for fmt in ("jsonl", "csv", "html"):
        path = tmp_path / ("protected." + fmt + ".zip")
        path.write_bytes(c.post("/api/export/" + fmt, json={"password": secret}).content)
        with pyzipper.AESZipFile(path) as archive:
            assert archive.namelist() == ["tgwitness-evidence." + fmt]
            assert archive.read("tgwitness-evidence." + fmt, pwd=secret.encode())


def test_demo_isolation(tmp_path):
    with TestClient(create_app(tmp_path, demo=True)) as c:
        c.headers["Authorization"] = "Bearer " + (tmp_path / "panel-token.txt").read_text()
        assert c.get("/api/status").json()["demo"] is True
        assert c.post("/api/auth/configure", json={"api_id":123,"api_hash":"a"*32}).status_code == 409
        assert c.post("/api/targets", json={"chat_id":CHAT,"enabled":True}).status_code == 409
        assert c.post("/api/collector/start", json={}).status_code == 409
        assert c.get("/api/export/zip").status_code == 200


def test_rate_limits_and_query_bounds(client):
    c, _ = client
    assert c.get("/api/events?limit=99999").status_code == 422
    for i in range(15):
        assert c.get("/api/status", headers={"Authorization":"Bearer wrong"}).status_code == 401
    assert c.get("/api/status", headers={"Authorization":"Bearer wrong"}).status_code == 429


def test_corrupt_startup_does_not_append_and_releases_lock(tmp_path):
    import sqlite3
    from tgwitness.security import InstanceLock
    with TestClient(create_app(tmp_path)):
        pass
    db = sqlite3.connect(tmp_path / "journal.sqlite3")
    db.execute("DROP TRIGGER immutable_update")
    db.execute("UPDATE events SET payload='{}' WHERE seq=1")
    db.commit()
    before = db.execute("SELECT count(*) FROM events").fetchone()[0]
    db.close()
    with pytest.raises(ValueError, match="Changed content"):
        with TestClient(create_app(tmp_path)):
            pass
    InstanceLock(tmp_path).close()
    with sqlite3.connect(tmp_path / "journal.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM events").fetchone()[0] == before


def sign_in(c, api_id=123):
    assert c.post("/api/auth/configure", json={"api_id": api_id, "api_hash": "a" * 32}).json()["step"] == "phone"
    assert c.post("/api/auth/phone", json={"phone": "+15551112222"}).status_code == 200
    return c.post("/api/auth/code", json={"code": "12345"})


def test_sign_out_ends_the_session_and_keeps_the_journal(client):
    c, app = client
    assert sign_in(c).json()["step"] == "authorized"
    c.get("/api/dialogs")
    assert c.post("/api/targets", json={"chat_id": CHAT, "enabled": True}).status_code == 200
    assert c.post("/api/collector/start", json={}).status_code == 200
    refused = c.post("/api/auth/logout", json={})
    assert refused.status_code == 400 and "Pause observation" in refused.json()["detail"]
    assert c.post("/api/collector/stop", json={}).status_code == 200
    assert c.post("/api/auth/logout", json={}).json() == {"telegram_session_ended": True}
    status = c.get("/api/status").json()
    assert not status["collector"]["has_session"] and status["collector"]["phase"] == "offline"
    assert status["targets"], "sources stay"
    record = app.state.store.events(kind="account.signed_out")[0]["payload"]
    assert record["account_id"] == 44 and record["telegram_session_ended"] is True
    assert c.post("/api/verify", json={}).status_code == 200
    assert c.post("/api/auth/logout", json={}).status_code == 400

    assert sign_in(c, 777).status_code == 400
    assert sign_in(c).json()["step"] == "authorized"


def test_sign_out_forgets_the_session_even_if_telegram_does_not_answer(client, monkeypatch):
    c, app = client
    assert sign_in(c).json()["step"] == "authorized"

    async def unreachable(self):
        raise OSError("network down")
    monkeypatch.setattr(FakeClient, "log_out", unreachable)
    assert c.post("/api/auth/logout", json={}).json() == {"telegram_session_ended": False, "error_type": "OSError"}
    assert not c.get("/api/status").json()["collector"]["has_session"]
    assert app.state.store.events(kind="account.signed_out")[0]["payload"]["error_type"] == "OSError"
