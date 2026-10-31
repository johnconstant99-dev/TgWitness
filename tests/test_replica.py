import asyncio
import base64
import hashlib
import io
import os
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from tgwitness import replica
from tgwitness.app import create_app
from tgwitness.evidence import retain_checkpoint
from tgwitness.network import NetworkConfig
from tgwitness.s3 import sign
from test_collector import FakeClient

AK, SK, BUCKET = "AKIDEXAMPLETEST", "secret/EXAMPLE+key", "evidence-bucket"


async def fake_s3(honour_lock=True):
    """Path-style S3 that checks SigV4, Content-MD5 and the payload hash on every request.

    honour_lock=False imitates storage that accepts Object Lock headers and silently ignores them.
    """
    objects, puts, locks = {}, [], {}

    async def handle(reader, writer):
        head = (await reader.readuntil(b"\r\n\r\n")).decode().split("\r\n")
        method, target, _ = head[0].split(" ")
        headers = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:] if h)}
        body = await reader.readexactly(int(headers.get("content-length", 0)))
        auth = dict(p.split("=", 1) for p in headers["authorization"].split(" ", 1)[1].split(","))
        names = auth["SignedHeaders"].split(";")
        when = datetime.strptime(headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        expected = sign(method, "http://" + headers["host"] + target,
                        {n: headers[n] for n in names if n not in ("host", "x-amz-date", "x-amz-content-sha256")},
                        headers["x-amz-content-sha256"], AK, SK, "us-east-1", when)["authorization"]
        path, query = urlsplit(target).path, parse_qs(urlsplit(target).query)
        raw_query = urlsplit(target).query
        if expected != headers["authorization"]:
            status, data = 403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>"
        elif method == "PUT":
            assert base64.b64decode(headers["content-md5"]) == hashlib.md5(body).digest()
            assert headers["x-amz-content-sha256"] == hashlib.sha256(body).hexdigest()
            objects[path.split("/", 2)[2]] = body
            puts.append(headers)
            if "x-amz-object-lock-mode" in headers:
                locks[path.split("/", 2)[2]] = (headers["x-amz-object-lock-mode"],
                                                headers["x-amz-object-lock-retain-until-date"])
            status, data = 200, b""
        elif raw_query == "object-lock":
            status, data = ((200, b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>"
                                  b"</ObjectLockConfiguration>") if honour_lock
                            else (404, b"<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>"))
        elif raw_query == "retention":
            lock = locks.get(path.split("/", 2)[2]) if honour_lock else None
            status, data = ((200, ("<Retention><Mode>" + lock[0] + "</Mode><RetainUntilDate>" + lock[1]
                                   + "</RetainUntilDate></Retention>").encode()) if lock
                            else (404, b"<Error><Code>NoSuchObjectLockConfiguration</Code></Error>"))
        elif query.get("list-type") == ["2"]:
            prefix, start = query["prefix"][0], int(query.get("continuation-token", ["0"])[0])
            keys = sorted(k for k in objects if k.startswith(prefix))
            page = keys[start:start + 2]
            more = start + 2 < len(keys)
            data = ("<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                    + "".join("<Contents><Key>" + k + "</Key><Size>" + str(len(objects[k])) + "</Size></Contents>"
                              for k in page)
                    + "<IsTruncated>" + ("true" if more else "false") + "</IsTruncated>"
                    + ("<NextContinuationToken>" + str(start + 2) + "</NextContinuationToken>" if more else "")
                    + "</ListBucketResult>").encode()
            status = 200
        else:
            key = path.split("/", 2)[2]
            status, data = (200, objects[key]) if key in objects else (404, b"")
        writer.write(b"HTTP/1.1 " + str(status).encode() + b" X\r\nContent-Length: " + str(len(data)).encode()
                     + b"\r\n\r\n" + data)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1]), objects, puts


def configure(store, vault, endpoint, **extra):
    store.set_setting("replica", replica.ReplicaSettings(enabled=True, endpoint=endpoint, bucket=BUCKET,
                                                         **extra).model_dump())
    vault.save("replica", {"access_key": AK, "secret_key": SK, "key": base64.b64encode(os.urandom(32)).decode()})


def test_encryption_round_trip_detects_changes_truncation_and_swaps():
    key = os.urandom(32)
    for size in (0, 5, replica.CHUNK, 2 * replica.CHUNK + 7):
        data = os.urandom(size)
        sealed = b"".join(replica.encrypt(key, "a/b.tgwr", io.BytesIO(data).read, os.urandom(8)))
        assert len(sealed) == replica.encrypted_size(size)
        assert b"".join(replica.decrypt(key, "a/b.tgwr", io.BytesIO(sealed).read)) == data
    with pytest.raises(InvalidTag):
        b"".join(replica.decrypt(key, "a/b.tgwr", io.BytesIO(sealed[:40] + bytes([sealed[40] ^ 1]) + sealed[41:]).read))
    with pytest.raises(InvalidTag):
        b"".join(replica.decrypt(key, "a/b.tgwr", io.BytesIO(sealed[:13 + replica.CHUNK + 16]).read))
    with pytest.raises(InvalidTag):
        b"".join(replica.decrypt(key, "a/c.tgwr", io.BytesIO(sealed).read))


def test_everything_is_copied_encrypted_and_restores_verified(journal, tmp_path):
    store, vault = journal

    async def run():
        server, endpoint, objects, puts = await fake_s3()
        configure(store, vault, endpoint, retention_days=30, retention_mode="COMPLIANCE")
        store.append("message.new", {"text": "secret wallet bc1qprivatewallet"}, -100123, 1, 44)
        media = b"photo bytes " * 1000
        digest = hashlib.sha256(media).hexdigest()
        (store.root / "media").mkdir()
        (store.root / "media" / digest).write_bytes(media)
        store.append("media.saved", {"media_sha256": digest, "size": len(media)}, -100123, 1)
        retain_checkpoint(store, vault)
        (store.root / "checkpoints" / "anchors").mkdir()
        (store.root / "checkpoints" / "anchors" / "checkpoint-000000000002.tsa.example.tsr").write_bytes(b"reply")
        export = tmp_path / "chat.zip"
        export.write_bytes(b"PK signed chat export")
        replica.outbox(store, export)

        first = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        again = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        store.append("message.new", {"text": "later"}, -100123, 2, 44)
        third = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        restored = await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "restored")
        server.close()
        return first, again, third, restored, objects, puts, media, digest
    first, again, third, restored, objects, puts, media, digest = asyncio.run(run())

    assert first["error"] is None and first["objects"] == 5 and again["objects"] == 0
    assert first["object_lock"]["verified"] is True and first["object_lock"]["object"]["mode"] == "COMPLIANCE"
    kinds = sorted(name.split("/")[2] for name in objects)
    assert kinds == ["checkpoints", "checkpoints", "exports", "journal", "journal", "media"]
    assert not any(digest in name for name in objects)
    assert all(b"bc1qprivatewallet" not in body and b"photo bytes" not in body for body in objects.values())
    assert all(h["x-amz-object-lock-mode"] == "COMPLIANCE" for h in puts)
    assert third["objects"] == 1 and not list((store.root / "replica-outbox").iterdir())
    out = tmp_path / "restored"
    assert restored["events"] == third["journal_seq"] and restored["checkpoints_verified"] == 1
    assert (out / "media" / digest).read_bytes() == media
    assert next((out / "exports").iterdir()).read_bytes() == b"PK signed chat export"
    assert len(store.events(kind="replica.completed")) == 2


def test_tampered_or_swapped_objects_fail_restore(journal, tmp_path):
    store, vault = journal

    async def run():
        server, endpoint, objects, _ = await fake_s3()
        configure(store, vault, endpoint)
        for i in range(3):
            store.append("message.new", {"text": str(i)}, -100123, i, 44)
        retain_checkpoint(store, vault)
        await replica.sync(store, vault, NetworkConfig(kind="direct"))
        journal_key = next(k for k in objects if "/journal/" in k)
        objects[journal_key] = objects[journal_key][:-1] + bytes([objects[journal_key][-1] ^ 1])
        with pytest.raises(InvalidTag):
            await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "a")
        checkpoint_key = next(k for k in objects if "/checkpoints/" in k)
        objects[journal_key] = objects[checkpoint_key]
        with pytest.raises(InvalidTag):
            await replica.restore(replica.key_file(store, vault), AK, SK, tmp_path / "b")
        server.close()
    asyncio.run(run())


def test_missing_file_is_reported_without_stopping_the_rest_of_the_copy(journal):
    store, vault = journal

    async def run():
        server, endpoint, objects, _ = await fake_s3()
        configure(store, vault, endpoint)
        (store.root / "media").mkdir()
        files = [b"first file", b"second file"]
        digests = [hashlib.sha256(data).hexdigest() for data in files]
        (store.root / "media" / digests[1]).write_bytes(files[1])
        for i, (data, digest) in enumerate(zip(files, digests)):
            store.append("media.saved", {"media_sha256": digest, "size": len(data)}, -100123, i)
        retain_checkpoint(store, vault)
        first = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        uploaded = sorted(name.split("/")[2] for name in objects)
        (store.root / "media" / digests[0]).write_bytes(files[0])
        second = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        server.close()
        return first, uploaded, second
    first, uploaded, second = asyncio.run(run())
    assert first["error"] == "Preserved media is missing: " + hashlib.sha256(b"first file").hexdigest()
    assert uploaded == ["checkpoints", "journal", "media"]
    assert second["error"] is None and second["objects"] == 1


def test_mtproxy_route_never_uploads(journal):
    store, vault = journal
    configure(store, vault, "http://127.0.0.1:9")
    store.append("message.new", {"text": "x"}, -100123, 1, 44)
    route = NetworkConfig(kind="mtproxy", host="proxy.example", port=443, secret="dd" + "a" * 32)
    status = asyncio.run(replica.sync(store, vault, route))
    assert "MTProxy" in status["error"] and status["objects"] == 0


def test_replica_api_keeps_keys_write_only(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        base = {"enabled": True, "endpoint": "https://s3.example.com", "bucket": BUCKET}
        assert c.post("/api/replica", json=base).status_code == 422
        assert c.post("/api/replica", json={**base, "endpoint": "https://s3.example.com/path"}).status_code == 422
        state = c.post("/api/replica", json={**base, "enabled": False, "access_key": AK, "secret_key": SK}).json()
        assert state["has_credentials"] and state["has_key"] and SK not in str(state) and AK not in str(state)
        state = c.post("/api/replica", json={**base, "interval_minutes": 15}).json()
        assert state["settings"]["enabled"] and app.state.vault.read("replica")["secret_key"] == SK
        key = c.get("/api/replica/key").json()
        assert key["format"] == "tgwitness-replica-key-v1" and len(base64.b64decode(key["key"])) == 32
        assert SK not in str(key)


def test_storage_that_ignores_object_lock_is_reported(journal):
    store, vault = journal

    async def run():
        server, endpoint, _, puts = await fake_s3(honour_lock=False)
        configure(store, vault, endpoint, retention_days=7, retention_mode="GOVERNANCE")
        store.append("message.new", {"text": "x"}, -100123, 1, 44)
        status = await replica.sync(store, vault, NetworkConfig(kind="direct"))
        server.close()
        return status, puts
    status, puts = asyncio.run(run())
    assert puts and all(h["x-amz-object-lock-mode"] == "GOVERNANCE" for h in puts)
    assert status["object_lock"]["verified"] is False and status["object_lock"]["bucket_enabled"] is False
    assert "did not lock" in status["error"]
    assert store.events(kind="replica.completed")[-1]["payload"]["error"] == status["error"]
