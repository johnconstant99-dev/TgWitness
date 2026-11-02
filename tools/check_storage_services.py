import asyncio
import base64
import copy
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI

from tgwitness import alerts, handover, operator_bot, research_export, services, storage, storage_api, witness
from tgwitness.network import NetworkConfig, NoRoute
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint


class Remote:
    def __init__(self):
        self.objects, self.corrupt, self.fail, self.pause = {}, False, False, None

    async def put(self, name, path):
        if self.fail:
            raise OSError("synthetic upload refused")
        self.objects[name] = path.read_bytes()

    async def get(self, name, sink):
        if self.pause:
            await self.pause.wait()
        data = self.objects[name]
        if self.corrupt:
            data = data[:-1] + bytes([data[-1] ^ 1])
        for start in range(0, len(data), 13):
            await sink(data[start:start + 13])


class Workspace:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        self.vault, self.store = Vault(root), Store(root)
        self.store.bind(self.vault)
        self.vault.save("storage", {"config": "[test]\ntype = mega\nuser = synthetic@example.invalid\npass = synthetic"})
        self.store.set_setting("storage", storage.Settings(purpose="offload", older_than_days=0).model_dump())
        self.remote = Remote()
        self.manager = storage.Storage(self.store, self.vault, lambda: NetworkConfig(kind="direct"))
        self.manager.backend = lambda config=None: self.remote

    def media(self, data=b"Original attachment bytes " * 1000):
        digest = hashlib.sha256(data).hexdigest()
        path = storage.safe_file(self.root, digest)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        self.store.append("media.saved", {"media_sha256": digest}, chat_id=11, message_id=2)
        return path, digest, data

    def close(self):
        self.store.close()


async def raises(awaitable, text):
    try:
        await awaitable
    except ValueError as exc:
        assert text.lower() in str(exc).lower(), str(exc)
    else:
        raise AssertionError("Expected refusal: " + text)


async def offload_checks(base):
    for compressed in (False, True):
        ws = Workspace(base / ("packed" if compressed else "plain"))
        try:
            cfg = storage.settings(ws.store)
            ws.store.set_setting("storage", {**cfg, "compress": compressed})
            path, digest, original = ws.media()
            result = await ws.manager.sync()
            assert result["files"] == 1 and result["freed_bytes"] == len(original) and not result["error"], result
            assert not path.exists() and ws.manager.public()["remote_files"] == 1
            assert all(original not in value for value in ws.remote.objects.values()), "Remote object contains plaintext"
            try:
                ws.manager.require_local_media()
            except ValueError as exc:
                assert "Restore all files" in str(exc)
            else:
                raise AssertionError("Full export allowed before remote attachments restored")

            manifest = ws.manager.recovery()
            storage.validate_recovery(manifest, fingerprint(ws.vault.public_key))
            changed = copy.deepcopy(manifest)
            changed["objects"][0]["bytes"] += 1
            await raises(storage.recover_directory(changed, fingerprint(ws.vault.public_key), "", base / "must-not-exist", False), "signature")
            assert not (base / "must-not-exist").exists()

            ws.remote.corrupt = True
            await raises(ws.manager.restore(digest), "checksum")
            assert not path.exists()
            ws.remote.corrupt = False
            wrong = dict(ws.vault.read("storage"))
            wrong["key"] = base64.b64encode(b"wrong storage key".ljust(32, b"!")).decode()
            ws.vault.save("storage", wrong)
            await raises(ws.manager.restore(digest), "key")
            ws.vault.save("storage", {**wrong, "key": manifest["key"]})
            await ws.manager.restore(digest)
            assert path.read_bytes() == original and ws.manager.public()["remote_files"] == 0
            ws.manager.require_local_media()
            assert not list(ws.root.glob("storage-*/")), "Plaintext staging directory retained"

            path.unlink()
            (ws.root / "storage.sqlite3").unlink()
            ws.manager.import_recovery(manifest)
            assert ws.manager.public()["remote_files"] == 1
            await ws.manager.restore_all()
            assert path.read_bytes() == original

            recovery_dir = base / ("recovered-packed" if compressed else "recovered-plain")
            with patch.object(storage.Storage, "backend", return_value=ws.remote):
                result = await storage.recover_directory(manifest, fingerprint(ws.vault.public_key),
                    ws.vault.read("storage")["config"], recovery_dir, install_helper=False)
            assert result == {"restored": 1}
            assert (recovery_dir / "media" / digest).read_bytes() == original
            assert not (recovery_dir / "journal.sqlite3").exists(), "Recovery invented an original journal"
            assert not (recovery_dir / "credentials.enc").exists(), "Recovery persisted destination credentials"
        finally:
            ws.close()

    ws = Workspace(base / "adverse")
    try:
        path, digest, original = ws.media()
        ws.remote.corrupt = True
        result = await ws.manager.sync()
        assert result["error"] and path.read_bytes() == original and not ws.manager.public()["copied_files"]
        ws.remote.corrupt = False
        ws.remote.fail = True
        result = await ws.manager.sync()
        assert result["error"] == "OSError" and path.read_bytes() == original
        ws.remote.fail = False

        ws.store.set_setting("storage", {**storage.settings(ws.store), "purpose": "copy"})
        assert not (await ws.manager.sync())["error"] and path.exists()
        ws.store.set_setting("storage", {**storage.settings(ws.store), "purpose": "offload"})
        secret = ws.vault.read("storage")
        ws.vault.save("storage", {"config": secret["config"]})
        assert "key is missing" in (await ws.manager.sync())["error"] and path.exists()
        ws.vault.save("storage", {**secret, "key": base64.b64encode(b"x" * 32).decode()})
        assert "does not match" in (await ws.manager.sync())["error"] and path.exists()
        ws.vault.save("storage", secret)
        ws.remote.corrupt = True
        assert (await ws.manager.sync())["error"] and path.exists()
        ws.remote.corrupt = False

        ws.remote.pause = asyncio.Event()
        task = asyncio.create_task(ws.manager.sync())
        await asyncio.sleep(.03)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert path.read_bytes() == original and not ws.manager.busy and not ws.manager.lock.locked()
        ws.remote.pause = None

        ws.store.set_setting("replica", {"enabled": True})
        result = await ws.manager.sync()
        assert "evidence backup" in result["error"] and path.exists()
        ws.store.set_setting("replica", {"enabled": False})

        path.write_bytes(b"changed")
        assert "journal hash" in (await ws.manager.sync())["error"] and path.read_bytes() == b"changed"
    finally:
        ws.close()


async def api_checks(base):
    ws = Workspace(base / "api")
    app = FastAPI()
    principal = SimpleNamespace(admin=True)

    async def authenticate():
        return principal

    app.state.storage, app.state.store, app.state.vault = ws.manager, ws.store, ws.vault
    app.state.collector = SimpleNamespace(outside_route=lambda: NetworkConfig(kind="direct"))
    storage_api.register(app, authenticate, lambda: None)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/storage", json={"rclone_config": "[test]\ntype=local"})
            assert response.status_code == 422, response.text
            response = await client.post("/api/storage", json={"purpose": "offload"})
            assert response.status_code == 422 and "Confirm" in response.text
            response = await client.post("/api/storage", json={"enabled": True, "rclone_config": "[test]\ntype=mega"})
            assert response.status_code == 200, response.text
            app.state.collector.outside_route = lambda: NoRoute("External requests disabled")
            response = await client.post("/api/storage", json={"enabled": True})
            assert response.status_code == 422 and "Direct route" in response.text
            response = await client.get("/api/storage/recovery")
            assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
            response = await client.post("/api/storage/recovery", json={"recovery": response.json()})
            assert response.status_code == 200, response.text
            principal.admin = False
            for url in ("/api/storage", "/api/storage/recovery"):
                assert (await client.get(url)).status_code == 403
    finally:
        ws.close()


async def lifecycle_checks():
    from tools.check_session_reservations import workspace
    async with workspace() as (app, client):
        for path in ("/api/storage", "/api/operator-bot", "/api/services/notifications"):
            response = await client.get(path)
            assert response.status_code == 200, (path, response.text)
        bot_token = "123456789:" + "a" * 35
        assert (await client.post("/api/operator-bot", json={"token": bot_token})).status_code == 200
        for invalid in ("0" * 249, "0" * 100 + ":" + "a" * 35, "٠١٢:" + "a" * 35,
                        "123:" + "a" * 19, bot_token + ":extra", bot_token + "\n", "0" * 10000):
            assert (await client.post("/api/operator-bot", json={"token": invalid})).status_code == 422
            assert app.state.vault.read("operator_bot")["token"] == bot_token
        response = await client.post("/api/storage", json={"rclone_config": "[remote]\ntype=local"})
        assert response.status_code == 422, response.text
        grant = await client.post("/api/access/grants", json={"label": "Synthetic reviewer", "workspaces": {"default": None}, "permissions": ["view"]})
        assert grant.status_code == 200, grant.text
        token, _ = app.state.access.login(grant.json()["token"], "127.0.0.1", "Synthetic acceptance")
        headers = {"Authorization": "Bearer " + token}
        for path in ("/api/storage", "/api/operator-bot", "/api/storage/recovery"):
            response = await client.get(path, headers=headers)
            assert response.status_code == 403, (path, response.text)
        response = await client.post("/api/storage/recovery", json={"recovery": {}}, headers=headers)
        assert response.status_code == 403, response.text
        selection = {"purpose": "Synthetic handover", "chats": [11], "attachments": "all"}
        assert (await client.post("/api/handover", json=selection, headers=headers)).status_code == 403

        def remote_attachment(*args):
            assert app.state.storage.lock.locked(), "Handover raced with offloading"
            raise handover.RemoteAttachment("Open Storage → Restore all files before creating this handover.")

        with patch.object(handover, "export", remote_attachment):
            response = await client.post("/api/handover", json=selection)
        assert response.status_code == 409 and "Restore all files" in response.text, response.text
        assert not app.state.storage.lock.locked()


async def storage_destination_checks(base):
    ws = Workspace(base / "destination-change")
    app = FastAPI()

    async def authenticate():
        return SimpleNamespace(admin=True)

    app.state.storage, app.state.store, app.state.vault = ws.manager, ws.store, ws.vault
    app.state.collector = SimpleNamespace(outside_route=lambda: NetworkConfig(kind="direct"))
    storage_api.register(app, authenticate, lambda: None)
    try:
        old_recovery = ws.manager.recovery()
        first, digest, original = ws.media(b"first attachment")
        ws.media(b"second attachment")
        ws.store.set_setting("storage", {**storage.settings(ws.store), "purpose": "copy"})
        assert (await ws.manager.sync())["files"] == 2
        old_settings = storage.settings(ws.store)
        change = {**old_settings, "remote_path": "second-destination", "purpose": "offload",
                  "batch_files": 1, "confirm_offload": True}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            first.unlink()
            response = await client.post("/api/storage", json=change)
            assert response.status_code == 409 and "Restore" in response.text
            first.write_bytes(b"corrupt original")
            response = await client.post("/api/storage", json=change)
            assert response.status_code == 409 and "recorded hash" in response.text
            assert storage.settings(ws.store) == old_settings and ws.manager.public()["copied_files"] == 2
            first.write_bytes(original)
            response = await client.post("/api/storage", json=change)
            assert response.status_code == 200, response.text
            assert response.json()["copied_files"] == 0 and first.read_bytes() == original
        assert (await ws.manager.sync())["files"] == 1
        manifest = ws.manager.recovery()
        assert len(manifest["objects"]) == 1
        assert manifest["objects"][0]["destination"] == ws.manager.destination()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/storage/recovery", json={"recovery": old_recovery})
            assert response.status_code == 422 and "Restore" in response.text, response.text
            assert storage.settings(ws.store)["remote_path"] == "second-destination"
            assert ws.manager.public()["remote_files"] == 1
            assert ws.manager.recovery()["objects"] == manifest["objects"]
        with patch.object(storage.Storage, "backend", return_value=ws.remote):
            restored = await storage.recover_directory(manifest, fingerprint(ws.vault.public_key),
                ws.vault.read("storage")["config"], base / "new-destination-recovered", install_helper=False)
        assert restored == {"restored": 1}
    finally:
        ws.close()

    from tools.check_session_reservations import workspace
    async with workspace() as (app, client):
        initial = {"endpoint": "https://old.example.invalid", "bucket": "old-bucket", "enabled": False,
                   "access_key": "synthetic", "secret_key": "synthetic"}
        assert (await client.post("/api/replica", json=initial)).status_code == 200
        app.state.store.set_setting("storage", storage.Settings(backend="s3", purpose="offload", older_than_days=0).model_dump())
        manager, remote = app.state.storage, Remote()
        manager.backend = lambda config=None: remote
        content = b"S3 attachment original"
        digest = hashlib.sha256(content).hexdigest()
        path = storage.safe_file(app.state.store.root, digest)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
        app.state.store.append("media.saved", {"media_sha256": digest}, chat_id=11, message_id=2)
        assert (await manager.sync())["files"] == 1 and not path.exists()
        changed = {**initial, "endpoint": "https://new.example.invalid", "bucket": "new-bucket"}
        response = await client.post("/api/replica", json=changed)
        assert response.status_code == 409 and "Restore" in response.text, response.text
        assert app.state.store.get_setting("replica")["bucket"] == "old-bucket"
        assert manager.public()["remote_files"] == 1
        response = await client.post("/api/replica", json={**initial, "secret_key": "synthetic-rotated"})
        assert response.status_code == 200 and manager.public()["remote_files"] == 1
        await manager.restore(digest)
        assert path.read_bytes() == content
        async with manager.lock:
            assert (await client.post("/api/replica", json=changed)).status_code == 409
        response = await client.post("/api/replica", json=changed)
        assert response.status_code == 200 and manager.public()["copied_files"] == 0
        assert path.read_bytes() == content


async def bot_and_alert_checks(base):
    ws = Workspace(base / "bot")
    try:
        collector = SimpleNamespace(status=lambda: {"running": True, "connected": True}, stop=AsyncMock(), start=AsyncMock())
        state = SimpleNamespace(store=ws.store, vault=ws.vault, collector=collector, storage=ws.manager,
                                replica_wakeup=asyncio.Event(), operation_lock=asyncio.Lock())
        bot = operator_bot.OperatorBot(state)
        cfg = {"enabled": True, "chat_id": "-42", "user_ids": [7], "commands": "status"}
        ws.store.set_setting("operator_bot", cfg)

        def message(text="/pause", **extra):
            return {"message": {"text": text, "date": int(time.time()), "from": {"id": 7}, "chat": {"id": -42}, **extra}}

        assert "disabled" not in (await bot.handle(message("/status"))).lower()
        bot.cooldown.clear()
        assert "Enable control" in await bot.handle(message())
        assert not collector.stop.called
        for extra in ({"from": {"id": 8}}, {"chat": {"id": 42}}, {"forward_origin": {"type": "user"}},
                      {"sender_chat": {"id": -42}}, {"date": 1}, {"via_bot": {"id": 1}}):
            bot.cooldown.clear()
            assert await bot.handle(message(**extra)) is None
        bot.cooldown.clear()
        assert await bot.handle(message("/pause@another_bot arbitrary instructions")) is None
        ws.store.set_setting("operator_bot", {**cfg, "commands": "manage"})
        assert "Done" in await bot.handle(message()) and collector.stop.await_count == 1
        assert await bot.handle(message()) is None, "Control command cooldown bypassed"

        bot.cooldown.clear()
        async with state.operation_lock:
            waiting = asyncio.create_task(bot.handle(message("/resume")))
            await asyncio.sleep(0)
            assert not collector.start.await_count, "Bot resumed while a panel operation held the connection"
            assert not waiting.done()
        assert "Done" in await waiting and collector.start.await_count == 1
        for revoked in ("permissions", "token"):
            bot.cooldown.clear()
            ws.store.set_setting("operator_bot", {**cfg, "commands": "manage"})
            async with state.operation_lock:
                waiting = asyncio.create_task(bot.handle(message("/pause")))
                await asyncio.sleep(0)
                assert collector.stop.await_count == 1 and not waiting.done()
                if revoked == "permissions":
                    ws.store.set_setting("operator_bot", cfg)
                else:
                    ws.vault.save("operator_bot", {"token": "123:" + "r" * 30})
            assert await waiting is None and collector.stop.await_count == 1, "Queued command survived access revocation"

        ws.store.set_setting("alerts", {"enabled": True, "daily": False, "problems": False, "completions": True})
        ws.vault.save("alerts", {"urls": ["jsons://synthetic.invalid/"]})
        ws.store.set_setting("alerts_cursor", ws.store.stats()["head"]["seq"])
        ws.store.append("account_export.completed", {"complete_within_scope": False})
        ws.store.append("snapshot.completed", {"captured": 11})
        ws.store.append("storage.completed", {"files": 2, "freed_bytes": 1024, "error": None})
        with patch.object(alerts, "deliver", return_value={"sent": 1, "failed": 0, "error": None}) as deliver:
            await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"))
        assert deliver.call_count == 1
        body = deliver.call_args.args[2]
        assert "with gaps" in body and "11 messages" in body and "2 files" in body, body
    finally:
        ws.close()


async def transport_checks(base):
    ws = Workspace(base / "transports")
    try:
        ws.store.set_setting("replica", {"endpoint": "https://objects.example.invalid", "bucket": "synthetic",
                                        "retention_days": 30, "retention_mode": "COMPLIANCE"})
        ws.vault.save("replica", {"access_key": "synthetic", "secret_key": "synthetic"})
        payload = ws.root / "upload"
        payload.write_bytes(b"synthetic ciphertext")
        client = SimpleNamespace(put=AsyncMock(), get=AsyncMock())
        with patch.object(storage.replica, "client", return_value=client), patch.object(storage.replica, "lock_report", AsyncMock(return_value={"verified": False})):
            backend = storage.S3Backend(ws.store, ws.vault, NetworkConfig(kind="direct"))
            await raises(backend.put("synthetic", payload), "Object Lock")
        assert client.put.await_count == 1
        headers = client.put.call_args.args[-1]
        assert headers["x-amz-object-lock-mode"] == "COMPLIANCE"
        assert headers["x-amz-object-lock-retain-until-date"]

        helper = storage.safe_helper(ws.root)
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"synthetic executable, never run")
        helper.with_suffix(".sha256").write_text(storage.file_hash(helper))
        route = storage.Rclone(ws.root, ws.vault.read("storage")["config"], "tgwitness", NetworkConfig(kind="direct"))
        launched = {}

        class Process:
            returncode = None
            stdout = SimpleNamespace(read=AsyncMock(return_value=b""))
            terminated = False

            async def wait(self):
                self.returncode = 0
                return 0

            def terminate(self):
                self.terminated = True
                self.returncode = -15

        process = Process()

        async def spawn(*args, **kwargs):
            launched.update(args=args, kwargs=kwargs)
            assert args[1] == "--config" and Path(args[2]).is_relative_to(ws.root)
            assert Path(args[2]).read_text() == route.config
            assert "shell" not in kwargs
            assert not any(key.startswith(("RCLONE_", "AWS_", "AZURE_", "GOOGLE_")) for key in kwargs["env"])
            return process

        with patch.object(asyncio, "create_subprocess_exec", spawn), patch.dict(storage.os.environ, {"RCLONE_CONFIG_EVIL_TYPE": "local", "AWS_SECRET_ACCESS_KEY": "synthetic"}):
            await route.run(["cat", "test:tgwitness/object"], AsyncMock())
        assert not Path(launched["args"][2]).exists()
        started = asyncio.Event()

        async def block(size):
            started.set()
            await asyncio.Event().wait()

        process.returncode = None
        process.stdout.read = block
        with patch.object(asyncio, "create_subprocess_exec", spawn):
            task = asyncio.create_task(route.run(["cat", "test:tgwitness/object"], AsyncMock()))
            await asyncio.wait_for(started.wait(), 2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        assert process.terminated and not Path(launched["args"][2]).exists()
    finally:
        ws.close()


async def bot_reconfiguration_checks(base):
    for change in ("token", "permissions"):
        ws = Workspace(base / ("bot-change-" + change))
        try:
            cfg = {"enabled": True, "chat_id": "-42", "user_ids": [7, 8],
                   "commands": "manage" if change == "token" else "status"}
            ws.store.set_setting("operator_bot", cfg)
            ws.vault.save("operator_bot", {"token": "123:" + "a" * 30})
            collector = SimpleNamespace(status=lambda: {"running": True, "connected": True},
                                        stop=AsyncMock(), start=AsyncMock())
            bot = operator_bot.OperatorBot(SimpleNamespace(store=ws.store, vault=ws.vault,
                                                           collector=collector, storage=ws.manager,
                                                           operation_lock=asyncio.Lock()))
            polls, next_offset = 0, None

            def update(ident, text, user):
                return {"update_id": ident, "message": {"text": text, "date": int(time.time()),
                        "from": {"id": user}, "chat": {"id": -42}}}

            async def call(method, payload, token=None):
                nonlocal polls, next_offset
                if method == "getUpdates":
                    polls += 1
                    if polls > 1:
                        next_offset = payload["offset"]
                        raise asyncio.CancelledError()
                    return [update(10, "/status", 7), update(11, "/pause", 8)]
                if change == "token":
                    ws.vault.save("operator_bot", {"token": "456:" + "b" * 30})
                    ws.store.set_setting("operator_bot_offset", 0)
                else:
                    ws.store.set_setting("operator_bot", {**cfg, "commands": "manage"})
                await asyncio.sleep(0)
                return {}

            bot.call = call
            try:
                await bot.loop()
            except asyncio.CancelledError:
                pass
            assert collector.stop.await_count == 0, "An old update acquired the replacement bot's policy"
            assert next_offset == (0 if change == "token" else 11), "An old batch overwrote the replacement cursor"
        finally:
            ws.close()


async def discord_and_handover_checks(base):
    webhook = "https://discord.com/api/webhooks/123456789012345678/synthetic-secret"
    for url in ("http://discord.com/api/webhooks/123/synthetic-secret", webhook + "?wait=false", webhook + "#secret",
                "https://discord.com.evil.invalid/api/webhooks/123/synthetic-secret",
                "https://user:pass@discord.com/api/webhooks/123/synthetic-secret",
                "https://discord.com/api/webhooks/١٢٣/synthetic-secret", "https://example.invalid/synthetic-secret"):
        try:
            instance = witness.Witness(base / "invalid-witness", "https://collector.invalid", "synthetic", discord_webhook=url)
        except ValueError as exc:
            assert "synthetic-secret" not in str(exc)
        else:
            instance.close()
            raise AssertionError("Invalid webhook accepted")
    try:
        instance = witness.Witness(base / "invalid-witness", "https://collector.invalid", "synthetic", channel="@synthetic", discord_webhook=webhook)
    except ValueError:
        pass
    else:
        instance.close()
        raise AssertionError("Ambiguous publisher accepted")
    instance = witness.Witness(base / "discord-witness", "https://collector.invalid", "synthetic", discord_webhook=webhook)
    try:
        event = instance.store.append("witness.anchor", {"status": "ok", "collector_fingerprint": "a" * 64,
                                                        "event_count": 1, "head_hash": "b" * 64})
        text = "@everyone <@123456789012345678>\n" + instance.post_text(event)
        calls = []

        async def request(*args, **kwargs):
            calls.append((args, kwargs))
            return 200, {}, b'{"id":"987654321098765432"}'

        with patch.object(witness, "request", request):
            assert await instance.discord_send(text) == "987654321098765432"
            long_text = "Длинный подписанный отчёт " * 150 + "\n" + text
            assert await instance.discord_send(long_text) == "987654321098765432"
        short, kwargs = calls[0]
        assert short[:2] == ("POST", webhook + "?wait=true")
        body = json.loads(short[4])
        assert body["content"] == text and body["allowed_mentions"] == {"parse": []}
        assert kwargs["limit"] == 256 * 1024
        long, _ = calls[1]
        message = BytesParser(policy=email_policy.default).parsebytes(
            ("Content-Type: " + long[3]["Content-Type"] + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + long[4])
        parts = {part.get_param("name", header="Content-Disposition"): part for part in message.iter_parts()}
        envelope = json.loads(parts["payload_json"].get_payload(decode=True))
        assert envelope["allowed_mentions"] == {"parse": []} and len(envelope["content"]) <= 2000
        assert parts["files[0]"].get_filename() == "witness-check.txt"
        restored = parts["files[0]"].get_payload(decode=True).decode()
        assert restored == long_text, "Signed Discord attachment was truncated or changed"
        token = restored.splitlines()[-1].split(".")
        assert token[0] == "TGW1"
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        Ed25519PublicKey.from_public_bytes(base64.b64decode(instance.key.public_key)).verify(decode(token[2]), decode(token[1]))
    finally:
        instance.close()

    ws = Workspace(base / "handover-offload")
    try:
        original = ws.store.append("message.new", {"text": "Synthetic attachment", "sender_id": 42, "has_media": True}, chat_id=11, message_id=2)
        path, digest, _ = ws.media()
        ws.store.append("media.saved", {"media_sha256": digest, "message_event": original["seq"]}, chat_id=11, message_id=2)
        assert not (await ws.manager.sync())["error"] and not path.exists()
        options = handover.Options(purpose="Synthetic recipient review", chats=[11], others="show", attachments="all")
        try:
            await asyncio.to_thread(handover.export, ws.store, ws.vault, options)
        except handover.RemoteAttachment as exc:
            assert "Restore all files" in str(exc)
        else:
            raise AssertionError("Handover silently omitted a selected offloaded attachment")
        options.attachments = "none"
        result, _ = await asyncio.to_thread(handover.export, ws.store, ws.vault, options)
        with zipfile.ZipFile(result) as archive:
            assert not any(name.startswith("media/") for name in archive.namelist())
        result.unlink()
        assert not list((ws.root / "temporary-exports").glob("*")), "Failed handover left temporary output"
    finally:
        ws.close()


def pure_checks(base):
    for config in ("[r]\ntype=local", "[r]\ntype=alias\nremote=/", "[r]\ntype=s3\nenv_auth=true",
                   "[r]\ntype=drive\nservice_account_file=/tmp/secret", "[r]\ntype=webdav\npass_command=whoami",
                   "[r]\ntype=mega\n[r2]\ntype=mega"):
        try:
            storage.parse_config(config)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe config accepted: " + config)
    for path in ("../remote", "/absolute", "a//b", "a/./b"):
        try:
            storage.Settings(remote_path=path)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe remote path accepted")
    for route in (NoRoute("disabled"), NetworkConfig(kind="socks5", host="proxy.invalid", port=1080)):
        try:
            storage.Rclone(base, "[r]\ntype=mega", "tgwitness", route)
        except ValueError:
            pass
        else:
            raise AssertionError("rclone bypassed workspace route")
    catalog = services.notifications()
    assert catalog["count"] == len(catalog["services"]) and catalog["count"] > 100
    assert any(row["name"] == "Telegram" for row in catalog["services"])
    assert any(row["name"] == "Discord" for row in catalog["services"])

    ws = Workspace(base / "research")
    try:
        text = "Unchanged source ```\n</script><h1>Source is data</h1>"
        plan = {"question": "```\n![Question image](https://invalid.example/track)\n<h1>untrusted question</h1>",
                "partial": True, "coverage": {"sources": 1}}
        sources = [{"id": "S1", "kind": "message.new", "text": text,
                    "source": {"workspace": "default", "seq": 1, "title": "```![Source image](https://invalid.example/source)"}}]
        bundle = research_export.package(plan, sources, ws.vault)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            signed = json.loads(archive.read("manifest.json"))
            Ed25519PublicKey.from_public_bytes(base64.b64decode(ws.vault.public_key)).verify(
                base64.b64decode(signed["signature"]), canonical(signed["manifest"]))
            for name, digest in signed["manifest"]["files"].items():
                assert hashlib.sha256(archive.read(name)).hexdigest() == digest
            assert json.loads(archive.read("chunks.jsonl"))["text"] == text
            markdown = archive.read("context.md").decode()
            assert "````text" in markdown and plan["question"] in markdown
            fence = None
            for line in markdown.splitlines():
                if fence and line == fence:
                    fence = None
                    continue
                if not fence and line.startswith("```"):
                    fence = line.rstrip("textjson")
                    continue
                if "invalid.example" in line or "<h1>" in line or "</script>" in line:
                    assert fence, "Attacker-controlled Markdown escaped a literal block"
            assert fence is None
    finally:
        ws.close()


async def main():
    with tempfile.TemporaryDirectory(prefix="tgwitness-storage-check-") as temp:
        base = Path(temp)
        pure_checks(base)
        await offload_checks(base)
        await api_checks(base)
        await storage_destination_checks(base)
        await bot_and_alert_checks(base)
        await bot_reconfiguration_checks(base)
        await transport_checks(base)
        await discord_and_handover_checks(base)
        await lifecycle_checks()
    print("Storage/services acceptance passed: verified eviction, corruption/cancellation, recovery, API access, bot allowlist, completion alerts, signed research pack.")


if __name__ == "__main__":
    asyncio.run(main())
