import asyncio
import hashlib
import json
import logging
import sqlite3
from collections import defaultdict

import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi.testclient import TestClient
from pydantic import ValidationError
from telethon.network.connection import ConnectionTcpFull, ConnectionTcpMTProxyRandomizedIntermediate
from telethon.sessions import StringSession

from tgwitness.app import create_app
from tgwitness.network import NetworkConfig
from tgwitness.security import Vault
from tgwitness.sessions import convert_telethon
from test_collector import FakeClient, saved_session, CHAT


def test_route_validation_and_mtproxy_boundaries():
    c = NetworkConfig(kind="mtproxy", host="127.0.0.1", port=443, secret="dd"+"a"*32)
    assert c.client_options()["connection"] is ConnectionTcpMTProxyRandomizedIntermediate
    assert c.public()["fallback_to_direct"] is False
    for raw in ("dd"+"1"*30, "ee"+"2"*30, "a"*32):
        config = NetworkConfig(kind="mtproxy", host="localhost", secret=raw)
        encoded = config.client_options()["proxy"][2]
        assert ConnectionTcpMTProxyRandomizedIntermediate.normalize_secret(encoded) == bytes.fromhex(raw)
    for kwargs in ({"kind":"socks5", "host":"https://user:secret@host"},
                   {"kind":"mtproxy", "host":"host", "secret":"ee"+"a"*64},
                   {"kind":"direct", "password":"should-not-survive"},
                   {"kind":"http", "host":"host", "secret":"a"*32}):
        with pytest.raises(ValidationError):
            NetworkConfig(**kwargs)


def test_route_survives_restart_isolated_and_redacted(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert client.post("/api/network", json={"kind":"socks5","host":"localhost","port":9988,
                           "username":"private-proxy-user","password":"private-proxy-password"}).status_code == 200
        assert client.post("/api/auth/configure", json={"api_id":123,"api_hash":"a"*32,
                           "session":saved_session()}).status_code == 200
        assert app.state.collector.client.options["proxy"]["password"] == "private-proxy-password"
        assert client.post("/api/network/test", json={}).json()["connected"]
        secret_dump = json.dumps(client.get("/api/status").json()) + json.dumps(app.state.store.all_events())
        assert "private-proxy-password" not in secret_dump and "private-proxy-user" not in secret_dump
        child = client.post("/api/profiles", json={"label":"Other account"}).json()["id"]
        assert client.get("/profiles/"+child+"/api/status").json()["collector"]["network"]["kind"] == "mtproxy_auto"
        client.get("/api/dialogs")
        client.post("/api/targets", json={"chat_id":CHAT,"enabled":True})
        client.post("/api/collector/start", json={})
        assert client.post("/api/network", json={"kind":"direct"}).status_code == 400
        client.post("/api/collector/stop", json={})
    restarted = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(restarted) as client:
        c = restarted.state.collector
        assert c.network_config().kind == "socks5"
        restored = c.make_client(123, "a"*32, saved_session())
        assert restored.options["proxy"]["password"] == "private-proxy-password"
    assert b"private-proxy-password" not in (tmp_path / "network.enc").read_bytes()


@pytest.mark.parametrize("kind", ["socks5", "http"])
def test_real_local_proxy_handshake(kind):
    async def run():
        seen = []
        errors = []
        async def exchange(reader, writer):
            try:
                if kind == "socks5":
                    greeting = await reader.readexactly(2)
                    await reader.readexactly(greeting[1])
                    writer.write(b"\x05\x02"); await writer.drain()
                    auth = await reader.readexactly(2)
                    username = await reader.readexactly(auth[1])
                    length = (await reader.readexactly(1))[0]
                    password = await reader.readexactly(length)
                    assert username == b"fixture-user" and password == b"fixture-password"
                    writer.write(b"\x01\x00"); await writer.drain()
                    command = await reader.readexactly(4)
                    assert command == b"\x05\x01\x00\x03"  # Hostname resolution at proxy.
                    length = (await reader.readexactly(1))[0]
                    seen.append((await reader.readexactly(length)).decode())
                    assert int.from_bytes(await reader.readexactly(2), "big") == 443
                    writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                else:
                    request = await reader.readuntil(b"\r\n\r\n")
                    assert b"CONNECT telegram-fixture.invalid:443 HTTP/1.1" in request
                    assert b"Proxy-Authorization: Basic " in request
                    seen.append("telegram-fixture.invalid")
                    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(), 1)
                except (TimeoutError, ConnectionResetError):
                    pass  # EOF/reset after the successful handshake is an expected client close.
            except Exception as exc:
                errors.append(exc)
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 1)
                except (OSError, TimeoutError):
                    writer.transport.abort()
        async def proxy(reader, writer):
            try:
                await asyncio.wait_for(exchange(reader, writer), 4)
            except TimeoutError:
                errors.append(TimeoutError("Test proxy handshake did not finish"))
            finally:
                writer.transport.abort()
        server = await asyncio.start_server(proxy, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        config = NetworkConfig(kind=kind, host="127.0.0.1", port=port,
                               username="fixture-user", password="fixture-password")
        connection = ConnectionTcpFull("telegram-fixture.invalid", 443, 2,
                        loggers=defaultdict(lambda: logging.getLogger("test")), **config.client_options())
        async with server:
            sock = await connection._proxy_connect(timeout=3)
            sock.close()
            await asyncio.sleep(.05)
        assert seen == ["telegram-fixture.invalid"]
        assert not errors, errors
        # Dead proxy: connection fails; never attempts the destination directly.
        with pytest.raises((OSError, ConnectionError)):
            await connection._proxy_connect(timeout=1)
    asyncio.run(run())


@pytest.mark.parametrize("version", [7, 8])
def test_offline_sqlite_conversion_is_read_only(tmp_path, version):
    path = tmp_path / "account.session"
    original = StringSession(saved_session())
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE version(version INTEGER); CREATE TABLE sessions "
                         "(dc_id INTEGER,server_address TEXT,port INTEGER,auth_key BLOB);")
        db.execute("INSERT INTO version VALUES (?)", (version,))
        db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (original.dc_id, original.server_address,
                                                               original.port, original.auth_key.key))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    assert convert_telethon(path) == saved_session()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    (tmp_path / "account.session-wal").write_bytes(b"incomplete snapshot")
    with pytest.raises(ValueError, match="offline"):
        convert_telethon(path)


def test_session_converter_rejects_other_formats_and_views(tmp_path):
    path = tmp_path / "fake.session"
    path.write_bytes(b"TDF$not-a-telethon-session")
    with pytest.raises(ValueError, match="tdata"):
        convert_telethon(path)
    path.unlink()
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE version(version INTEGER); INSERT INTO version VALUES (7); "
                         "CREATE VIEW sessions AS SELECT 1 AS dc_id;")
    with pytest.raises(ValueError, match="tables"):
        convert_telethon(path)


def test_external_master_key_distinct_profiles_and_fail_closed(tmp_path, monkeypatch):
    key = tmp_path / "master.key"
    key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv("TGWITNESS_VAULT_KEY_FILE", str(key))
    a, b = Vault(tmp_path / "a"), Vault(tmp_path / "b")
    a.save("credentials", {"secret":"test credential"})
    assert not (a.root / "vault.key").exists()
    with pytest.raises(InvalidToken):
        b.fernet.decrypt((a.root / "credentials.enc").read_bytes())
    assert Vault(a.root).read("credentials")["secret"] == "test credential"
    key.write_bytes(Fernet.generate_key())
    with pytest.raises(InvalidToken):
        Vault(a.root)
    monkeypatch.delenv("TGWITNESS_VAULT_KEY_FILE")
    with pytest.raises(RuntimeError, match="requires TGWITNESS"):
        Vault(a.root)
    assert not (a.root / "vault.key").exists()


def test_external_key_does_not_silently_migrate_local_vault(tmp_path, monkeypatch):
    root = tmp_path / "existing"
    original = Vault(root).public_key
    key = tmp_path / "master.key"
    key.write_bytes(Fernet.generate_key())
    monkeypatch.setenv("TGWITNESS_VAULT_KEY_FILE", str(key))
    with pytest.raises(RuntimeError, match="not migrated"):
        Vault(root)
    monkeypatch.delenv("TGWITNESS_VAULT_KEY_FILE")
    assert Vault(root).public_key == original
