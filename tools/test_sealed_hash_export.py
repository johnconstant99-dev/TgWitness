"""Exercise the actual restricted GitHub server, queue, signed ZIP and preflight."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

import httpx
import pytest
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import history
from tgwitness.sealed import create_app
from tgwitness.sealed_crypto import keypair
from tgwitness.verify import fingerprint, verify_bundle
from tools.browser_fixtures import CapsuleClient, CHAT, config, media_message


class HashCapsuleClient(CapsuleClient):
    _sender = object()
    calls = 0
    session_probe = None
    incomplete = False

    async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
        return [m for m in (media_message(2), media_message(1)) if not offset_id or m.id < offset_id][:limit]

    async def _call(self, sender, request):
        assert isinstance(request, f.upload.GetFileHashesRequest), "File payload RPC in hash-only capture"
        sources = type(self).session_probe.collector.history.status()["sources_by_phase"]
        assert sources.get("complete") and not any(sources.get(k) for k in ("queued", "reading")), "Attachment preceded message history"
        type(self).calls += 1
        return [] if self.incomplete else [t.FileHash(0, 131072, hashlib.sha256(b"data").digest())]

    async def download_media(self, *args, **kwargs):
        raise AssertionError("File download in hash-only capture")

    async def download_profile_photo(self, *args, **kwargs):
        raise AssertionError("Avatar download with avatars disabled")


@pytest.mark.parametrize("incomplete", [False, True])
def test_sealed_hash_queue_and_preflight(tmp_path, incomplete):
    async def run():
        cfg = config(keypair())
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, HashCapsuleClient)
        HashCapsuleClient.calls, HashCapsuleClient.incomplete = 0, incomplete
        async with app.router.lifespan_context(app):
            session = app.state.session
            HashCapsuleClient.session_probe = session
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                assert (await client.post("/api/phone", json={"phone": "+15550001111", "api_id": 123, "api_hash": "a" * 32})).status_code == 200
                assert (await client.post("/api/code", json={"code": "12345"})).status_code == 200
                assert (await client.get("/api/dialogs")).status_code == 200
                body = {"chat_id": CHAT, "capture": {"media_action": "hashes_only", "include_avatars": False,
                    "messages_first": True, "types": {"document": {"enabled": True, "max_mb": 1}}}}
                settings_before = session.store.get_setting("capture", None)
                pre = await client.post("/api/preflight", json=body)
                assert pre.status_code == 200, pre.text
                pre = pre.json()
                assert pre["fit"] == "unknown" and pre["sample"]["known_download_bytes"] == 0
                assert pre["sample"]["known_hash_source_bytes"] == 4 and pre["sample"]["duplicate_references"] == 1
                assert HashCapsuleClient.calls == 0 and session.store.get_setting("capture", None) == settings_before
                response = await client.post("/api/collect", json=body)
                assert response.status_code == 200, response.text
                async with asyncio.timeout(20):
                    while session.phase not in ("sealed", "failed"):
                        await asyncio.sleep(.1)
                assert session.phase == "sealed", session.reason
                assert session.revocation == "revoked"
                assert session.vault.read("credentials") == {}
                state = session.store.media_stats()
                assert state == ({"failed": 2} if incomplete else {"hashed": 2}), state
                assert HashCapsuleClient.calls == (2 if incomplete else 1)
                archive = tmp_path / "out/evidence.zip"
                assert verify_bundle(archive, fingerprint(session.vault.public_key))["events"] > 5
                with zipfile.ZipFile(archive) as z:
                    assert not any(n.startswith("media/") for n in z.namelist())
                    hashes = [n for n in z.namelist() if n.startswith("hashes/")]
                    assert len(hashes) == (0 if incomplete else 1)
                    events = [json.loads(line) for line in z.read("events.jsonl").splitlines()]
                    outcomes = [e for e in events if e["kind"] in ("media.hashed", "media.failed")]
                    assert len(outcomes) == 2
                    if not incomplete:
                        assert all(e["payload"]["server_hashes"]["status"] == "complete" for e in outcomes)
                        assert any(b"File content not downloaded" in z.read(n) for n in z.namelist() if n.endswith(".html"))
                assert (await client.post("/api/preflight", json=body)).status_code == 409
    asyncio.run(run())


def test_messages_first_reads_every_source_before_any_attachment(tmp_path, monkeypatch):
    sequence = []

    class MultiSourceClient(HashCapsuleClient):
        async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
            sequence.append(("messages", entity.id))
            if offset_id:
                return []
            message = media_message(1, document_id=entity.id)
            message.peer_id = t.PeerChannel(entity.id)
            return [message]

        async def _call(self, sender, request):
            sequence.append(("hashes", request.location.id))
            return await super()._call(sender, request)

    async def run():
        cfg = config(keypair())
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, MultiSourceClient)
        async with app.router.lifespan_context(app):
            session = app.state.session
            MultiSourceClient.session_probe, MultiSourceClient.incomplete = session, False
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                assert (await client.post("/api/phone", json={"phone": "+15550001111", "api_id": 123, "api_hash": "a" * 32})).status_code == 200
                assert (await client.post("/api/code", json={"code": "12345"})).status_code == 200
                session.store.set_setting("capture", {"media_action": "hashes_only", "messages_first": True,
                                                       "include_avatars": False})
                for number in (123, 456):
                    chat_id = -1000000000000 - number
                    session.collector.dialog_cache[chat_id] = {"entity": SimpleNamespace(id=number)}
                    session.store.set_target(chat_id, "Synthetic " + str(number), "supergroup", True)
                await session.collector.history.start()
                await asyncio.wait_for(session.collector.history.task, 20)
                state = session.collector.history.status()
                assert state["phase"] == "complete" and state["captured"] == 2, state
                assert state["media"] == {"hashed": 2}, state
                assert [kind for kind, _ in sequence] == ["messages"] * 4 + ["hashes"] * 2, sequence
                assert {number for kind, number in sequence if kind == "messages"} == {123, 456}
                assert not session.collector.running
                assert (await client.post("/api/cancel", json={})).status_code == 200
                assert session.revocation == "revoked"

    monkeypatch.setattr(history, "PAGE_SIZE", 1)
    asyncio.run(run())


@pytest.mark.parametrize("state", ["false", "true", "stop_failed"])
def test_runner_requires_confirmed_shutdown(tmp_path, monkeypatch, state):
    from scripts import sealed_runner
    (tmp_path / "config").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "config/session.json").write_text('{"seconds":60}')
    (tmp_path / "out/result.json").write_text('{"phase":"sealed"}')
    (tmp_path / "out/evidence.zip").write_bytes(b"synthetic")
    monkeypatch.setattr(sealed_runner, "location", lambda: (tmp_path, "synthetic-capsule"))
    calls = []

    def command(args, timeout=120, check=True):
        calls.append(args)
        assert check, "Shutdown failure must not be ignored"
        if args[1] == "stop" and state == "stop_failed":
            raise RuntimeError("Synthetic Docker stop failed")
        return state if args[1] == "inspect" else ""

    monkeypatch.setattr(sealed_runner, "command", command)
    if state == "false":
        sealed_runner.wait()
        assert [args[1] for args in calls] == ["rm", "stop", "inspect"]
    else:
        with pytest.raises(RuntimeError):
            sealed_runner.wait()


def test_runner_wait_does_not_restart_the_capture_clock(tmp_path, monkeypatch):
    from scripts import sealed_runner
    (tmp_path / "config").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "config/session.json").write_text(json.dumps({"seconds": 7200, "supervisor_deadline": 102}))
    monkeypatch.setattr(sealed_runner, "location", lambda: (tmp_path, "synthetic-capsule"))
    clock = [101]
    inspections = []
    monkeypatch.setattr(sealed_runner.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(sealed_runner.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def command(args, **kwargs):
        inspections.append(args)
        return "true"

    monkeypatch.setattr(sealed_runner, "command", command)
    with pytest.raises(RuntimeError, match="deadline"):
        sealed_runner.wait()
    assert clock[0] == 103 and len(inspections) == 1


def test_runner_deadline_is_set_after_the_image_build(tmp_path, monkeypatch):
    from scripts import sealed_runner
    directory = tmp_path / "capsule"
    monkeypatch.setattr(sealed_runner, "location", lambda: (directory, "synthetic-capsule"))
    monkeypatch.setattr(sealed_runner, "restrictions", lambda: [])
    for key, value in {"SESSION_MINUTES": "120", "RECIPIENT": "A" * 512,
                       "GITHUB_REPOSITORY": "synthetic/fork", "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}.items():
        monkeypatch.setenv(key, value)
    clock = [100]
    monkeypatch.setattr(sealed_runner.time, "monotonic", lambda: clock[0])

    def command(args, **kwargs):
        if args[0] == "git":
            return "a" * 40
        if args[1] == "build":
            assert not (directory / "config/session.json").exists()
            clock[0] += 900
        if args[1] == "run" and "--detach" in args:
            assert json.loads((directory / "config/session.json").read_bytes())["supervisor_deadline"] == 8800
        return ""

    monkeypatch.setattr(sealed_runner, "command", command)
    monkeypatch.setattr(sealed_runner.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        stdout="https://synthetic-test.trycloudflare.com", stderr=""))
    monkeypatch.setattr(sealed_runner, "helper", lambda *a, **kw: (directory / "out/connection.tgwsealed").write_bytes(b"synthetic"))
    sealed_runner.start()
    assert (directory / "public/connection.tgwsealed").read_bytes() == b"synthetic"
