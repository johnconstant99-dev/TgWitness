import base64
import hashlib
import io
import json
import sqlite3
import struct
import zipfile

import pytest
from fastapi.testclient import TestClient
from telethon.crypto import AES
from telethon.sessions import StringSession

from tgwitness.account_import import import_accounts, identity
from tgwitness.app import create_app
from test_collector import FakeClient, saved_session


def upload(name, content):
    return {"name": name, "content": base64.b64encode(content).decode()}


def sqlite_fixture(kind="telethon", version=None, bot=0, test=0, address=None, port=None):
    source = StringSession(saved_session())
    with sqlite3.connect(":memory:") as db:
        if kind == "telethon":
            db.executescript("CREATE TABLE version(version INTEGER); CREATE TABLE sessions "
                             "(dc_id INTEGER,server_address TEXT,port INTEGER,auth_key BLOB);")
            db.execute("INSERT INTO version VALUES (?)", (version or 8,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (source.dc_id, address or source.server_address,
                                                                 port or source.port, source.auth_key.key))
        else:
            db.executescript("CREATE TABLE version(number INTEGER); CREATE TABLE sessions "
                             "(dc_id INTEGER,auth_key BLOB,test_mode INTEGER,user_id INTEGER,is_bot INTEGER);")
            db.execute("INSERT INTO version VALUES (?)", (version or 3,))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)", (source.dc_id, source.auth_key.key, test, 44, bot))
        db.commit()
        return db.serialize()


def tdata_fixture(passcode="", account_count=1, user_id=44):
    """Synthetic Desktop encoding, using Telethon's separate AES-IGE implementation."""
    def array(data):
        return struct.pack(">I", len(data)) + data

    def encrypt(content, key):
        plain = struct.pack("<I", len(content) + 4) + content
        plain += b"\0" * (-len(plain) % 16)
        msg = hashlib.sha1(plain).digest()[:16]
        a = hashlib.sha1(msg + key[8:40]).digest()
        b = hashlib.sha1(key[40:56] + msg + key[56:72]).digest()
        c = hashlib.sha1(key[72:104] + msg).digest()
        d = hashlib.sha1(msg + key[104:136]).digest()
        return msg + AES.encrypt_ige(plain, a[:8] + b[8:20] + c[4:16], a[8:20] + b[:8] + c[16:20] + d[:8])

    def container(data):
        version = struct.pack("<I", 3004000)
        return b"TDF$" + version + data + hashlib.md5(data + struct.pack("<I", len(data)) + version + b"TDF$").digest()

    salt, local = b"s" * 32, b"l" * 256
    seed = hashlib.sha512(salt + passcode.encode() + salt).digest()
    key = hashlib.pbkdf2_hmac("sha512", seed, salt, 100000 if passcode else 1, 256)
    source = StringSession(saved_session())
    authorization = struct.pack(">qqii", -1, user_id, source.dc_id, 1) + struct.pack(">i", source.dc_id) + source.auth_key.key + struct.pack(">i", 0)
    keys = array(salt) + array(encrypt(local, key)) + array(encrypt(struct.pack(">iii", account_count, 0, 0), local))
    mtp = array(encrypt(struct.pack(">i", 75) + array(authorization), local))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("tdata/key_datas", container(keys))
        archive.writestr("tdata/D877F783D5D3EF8Cs", container(mtp))
    return output.getvalue()


@pytest.mark.parametrize("kind,version", [("telethon", 7), ("telethon", 8), ("pyrogram", 2), ("pyrogram", 3)])
def test_both_sqlite_libraries(kind, version):
    payload = sqlite_fixture(kind, version)
    before = hashlib.sha256(payload).digest()
    result = import_accounts([upload("account.session", payload)])
    assert identity(result["session"]) == identity(saved_session())
    assert hashlib.sha256(payload).digest() == before


@pytest.mark.parametrize("passcode", ["", "synthetic desktop passcode"])
def test_tdata_and_companion_json(passcode):
    result = import_accounts([upload("tdata.zip", tdata_fixture(passcode)),
                              upload("account.json", b'{"app_id":123,"app_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":null}')], passcode)
    assert identity(result["session"]) == identity(saved_session())
    assert result["expected_user_id"] == 44 and result["api_id"] == 123


def test_all_four_formats_match_and_conflicting_files_fail():
    files = [upload("telethon.session", sqlite_fixture()), upload("pyrogram.session", sqlite_fixture("pyrogram")),
             upload("tdata.zip", tdata_fixture()), upload("account.json", b'{"app_id":123,"app_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')]
    assert len(import_accounts(files)["formats"]) == 4
    files[-1] = upload("account.json", b'{"user_id":45,"app_id":123}')
    with pytest.raises(ValueError, match="different accounts"):
        import_accounts(files)


def test_json_metadata_key_and_session_variants():
    result = import_accounts([upload("account.json", b'{"app_id":123,"app_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')])
    assert not result["has_authorization"] and "session" not in result
    source = StringSession(saved_session())
    for record in ({"auth_key": source.auth_key.key.hex(), "dc_id": source.dc_id, "user_id":44},
                   {"string_session": saved_session()}):
        result = import_accounts([upload("account.json", json.dumps(record).encode())])
        assert identity(result["session"]) == identity(saved_session())


def test_session_address_from_a_file_is_never_used(tmp_path):
    """A file pointing at another server would let that server answer as Telegram with the key it supplied."""
    def address(value):
        session = StringSession(value)
        return session.server_address, session.port
    reference = ("149.154.167.51", 443)
    forged = StringSession(saved_session())
    forged.set_dc(forged.dc_id, "203.0.113.7", 8443)
    forged = forged.save()
    for files in ([upload("account.session", sqlite_fixture(address="attacker.example", port=8443))],
                  [upload("session.txt", forged.encode())],
                  [upload("account.json", json.dumps({"string_session": forged}).encode())]):
        assert address(import_accounts(files)["session"]) == reference
    seen = []

    class Recording(FakeClient):
        def __init__(self, session, *args, **kwargs):
            seen.append((session.server_address, session.port))
            super().__init__(session, *args, **kwargs)
    app = create_app(tmp_path, client_factory=Recording)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        response = client.post("/api/auth/configure", json={"api_id": 123, "api_hash": "a" * 32, "session": forged})
        assert response.status_code == 200, response.text
        authorized = [e for e in app.state.store.all_events() if e["kind"] == "account.authorized"]
        assert authorized[-1]["payload"]["key_origin"] == "imported"
    assert seen == [reference]


@pytest.mark.parametrize("payload", [b'{"auth_key":"ab...cd","dc_id":2}', b'[]', b'{"api_id":123,"api_id":456}',
                                     b'{"api_id":true}', b'{"string_session":"1AAAA"}'])
def test_invalid_json_does_not_echo_credentials(payload):
    with pytest.raises(ValueError) as error:
        import_accounts([upload("account.json", payload)])
    assert payload.decode() not in str(error.value)


@pytest.mark.parametrize("payload,passcode", [(tdata_fixture("correct"), "wrong"),
                                             (tdata_fixture(account_count=2), ""),
                                             (sqlite_fixture("pyrogram", bot=1), ""),
                                             (sqlite_fixture("pyrogram", test=1), "")],
                         ids=["wrong-passcode", "multiple-accounts", "bot", "test-dc"])
def test_rejects_unsupported_or_unusable_authorization(payload, passcode):
    with pytest.raises(ValueError):
        import_accounts([upload("account.zip", payload)], passcode)


@pytest.mark.parametrize("name", ["../key_datas", "/key_datas", "C:/key_datas", "tdata\\key_datas"])
def test_zip_paths_are_never_extracted(name):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        entry = zipfile.ZipInfo("placeholder")
        entry.filename = name
        archive.writestr(entry, b"data")
    with pytest.raises(ValueError, match="Unsafe"):
        import_accounts([upload("account.zip", output.getvalue())])


def test_tdata_checksum_tampering_is_rejected():
    original = zipfile.ZipFile(io.BytesIO(tdata_fixture()))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in original.namelist():
            data = bytearray(original.read(name))
            if name.endswith("key_datas"):
                data[20] ^= 1
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="checksum"):
        import_accounts([upload("account.zip", output.getvalue())])


def test_import_api_is_offline_authenticated_and_memory_only(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    files = [upload("account.session", sqlite_fixture()), upload("metadata.json", b'{"api_id":123}')]
    with TestClient(app) as client:
        assert client.post("/api/auth/import", json={"files": files}).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        before = {p.name:p.read_bytes() for p in tmp_path.iterdir() if p.is_file() and p.name != ".instance.lock"}
        response = client.post("/api/auth/import", json={"files": files})
        assert response.status_code == 200
        assert identity(response.json()["session"]) == identity(saved_session())
        assert app.state.collector.login_client is app.state.collector.client is None
        assert {p.name:p.read_bytes() for p in tmp_path.iterdir() if p.is_file() and p.name != ".instance.lock"} == before
        assert response.headers["cache-control"] == "no-store"
        assert client.post("/api/auth/configure", content=b"x"*20000).status_code == 413
        assert client.post("/api/auth/import", json={"files": files * 3}).status_code == 422
