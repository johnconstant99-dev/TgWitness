import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tomllib
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import requests
from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tgwitness import alerts, assurance, cloud, evidence, group_settings, provenance, replica, security
from tgwitness import settings_hub, source_check, storage, storage_api
from tgwitness.network import NetworkConfig
from tools.check_session_reservations import workspace
from tools.check_storage_services import Workspace


def test_main_account_scope_is_checked_before_changes():
    async def run():
        async with workspace() as (app, client):
            store = app.state.store
            store.set_setting("first_run", {"completed": True, "goal": "copy", "account_kind": "main"})
            store.set_setting("scope", {"mode": "account"})
            store.set_setting("resume", False)
            settings_hub.save_goal(store, "copy")
            before = settings_hub.revision(app)
            head = store.stats()["head"]
            with patch.object(app.state.collector, "start", new_callable=AsyncMock) as start:
                for goal in ("watch", "evidence"):
                    response = await client.post("/api/settings/goal", json={"goal": goal, "revision": before})
                    assert response.status_code == 409 and "chosen chats" in response.text
                    assert settings_hub.revision(app) == before
                response = await client.post("/api/settings/edit", json={
                    "key": "continuous", "value": True, "revision": before})
                assert response.status_code == 409 and not start.called
            assert store.stats()["head"] == head, "A rejected policy change mutated the journal"
            assert store.get_setting("first_run")["goal"] == "copy"
            with pytest.raises(ValueError, match="chosen chats"):
                settings_hub.validate_collection_scope(store)
            store.set_setting("resume", True)
            before = settings_hub.revision(app)
            error = await group_settings.apply_member(app, {"goal": "watch", "files": "all"},
                                                       {"id": "g", "label": "Synthetic"}, "test")
            assert "chosen chats" in error and settings_hub.revision(app) == before
            store.set_setting("scope", {"mode": "selected"})
            store.set_setting("resume", False)
            with patch.object(app.state.collector, "start", new_callable=AsyncMock) as start:
                response = await client.post("/api/settings/goal", json={
                    "goal": "watch", "revision": settings_hub.revision(app)})
                assert response.status_code == 200, response.text
                assert start.await_count == 1
            assert store.get_setting("first_run")["goal"] == store.get_setting("goal_preset")["goal"] == "watch"
            store.set_setting("resume", True)
            response = await client.post("/api/settings/scope", json={"goal": "copy", "scope": "account"})
            assert response.status_code == 409
    asyncio.run(run())


def test_route_only_group_adoption_does_not_claim_applied():
    async def run():
        async with workspace() as (app, client):
            response = await client.post("/api/profile-groups", json={"label": "Synthetic group"})
            assert response.status_code == 200, response.text
            group_id = response.json()["groups"][0]["id"]
            response = await client.put("/api/profiles/default/group", json={"group": group_id})
            assert response.status_code == 200, response.text
            registry = app.state.profiles
            group_settings.save_values(registry, group_id, {"route": {"mode": "direct", "allow_direct": True}})
            before = app.state.store.get_setting("connection_strategy", {})
            response = await client.post(f"/api/profile-groups/{group_id}/settings/adopt", json={
                "profiles": ["default"], "keys": ["route"]})
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["applied"] == [] and result["failed"] == []
            assert result["kept_own"][0]["keys"] == ["route"]
            assert app.state.store.get_setting("connection_strategy", {}) == before
    asyncio.run(run())


def test_rclone_token_replacement_keeps_recovery(tmp_path):
    async def run():
        ws = Workspace(tmp_path / "storage")
        try:
            old_config = '[remote]\ntype=drive\ntoken={"access_token":"synthetic-old"}\n'
            new_config = old_config.replace("synthetic-old", "synthetic-new")
            ws.vault.save("storage", {"config": old_config})
            path, digest, original = ws.media()
            assert (await ws.manager.sync())["files"] == 1 and not path.exists()
            assert ws.manager.destination(remote_config=old_config) == ws.manager.destination(remote_config=new_config)
            original_secret = dict(ws.vault.read("storage"))
            app = FastAPI()
            app.state.store, app.state.vault, app.state.storage = ws.store, ws.vault, ws.manager
            app.state.collector = SimpleNamespace(outside_route=lambda: NetworkConfig(kind="direct"))
            async def authenticate():
                return SimpleNamespace(admin=True)
            storage_api.register(app, authenticate, lambda: None)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                body = {**storage.settings(ws.store), "confirm_offload": True, "rclone_config": new_config}
                response = await client.post("/api/storage", json=body)
                assert response.status_code == 409 and "Restore" in response.text
                assert ws.vault.read("storage") == original_secret
                assert ws.manager.public()["remote_files"] == 1
                response = await client.post("/api/storage", json={**body, "rclone_config": "# harmless comment\n" + old_config})
                assert response.status_code == 200, response.text
                assert ws.manager.public()["remote_files"] == 1
                await ws.manager.restore(digest)
                assert path.read_bytes() == original
                response = await client.post("/api/storage", json=body)
                assert response.status_code == 200, response.text
                assert ws.vault.read("storage")["config"] == new_config
                assert ws.manager.public()["copied_files"] == 0
        finally:
            ws.close()
    asyncio.run(run())


class Bucket:
    def __init__(self):
        self.objects = {}

    async def put(self, name, body, length, *args):
        self.objects[name] = b"".join([piece async for piece in body])
        assert len(self.objects[name]) == length

    async def get(self, name, sink):
        await sink(self.objects[name])

    async def list(self, prefix):
        for name in sorted(self.objects):
            if name.startswith(prefix):
                yield name, len(self.objects[name])


def test_replica_restore_coexists_with_ordinary_s3_storage(tmp_path):
    async def run():
        ws, bucket = Workspace(tmp_path / "replica"), Bucket()
        try:
            ws.store.set_setting("replica", replica.ReplicaSettings(enabled=True,
                endpoint="https://synthetic.invalid", bucket="synthetic-bucket").model_dump())
            ws.vault.save("replica", {"access_key": "synthetic", "secret_key": "synthetic",
                                     "key": base64.b64encode(b"R" * 32).decode()})
            _, digest, original = ws.media()
            evidence.retain_checkpoint(ws.store, ws.vault)
            with patch.object(replica, "S3", return_value=bucket):
                assert (await replica.sync(ws.store, ws.vault, NetworkConfig(kind="direct")))["error"] is None
                keyinfo = replica.key_file(ws.store, ws.vault)
                ws.store.set_setting("storage", storage.Settings(backend="s3", purpose="copy", older_than_days=0).model_dump())
                manager = storage.Storage(ws.store, ws.vault, lambda: NetworkConfig(kind="direct"))
                assert (await manager.sync())["files"] == 1
                assert any("/storage/media/" in name for name in bucket.objects)
                result = await replica.restore(keyinfo, "synthetic", "synthetic", tmp_path / "restored")
                assert result["media_verified"] == 1
                assert (tmp_path / "restored" / "media" / digest).read_bytes() == original
                base = next(name.split("/storage/")[0] for name in bucket.objects if "/storage/" in name)
                bucket.objects[base + "/../unsafe.tgwr"] = b"synthetic"
                with pytest.raises(ValueError, match="Unsafe backup"):
                    await replica.restore(keyinfo, "synthetic", "synthetic", tmp_path / "unsafe")
        finally:
            ws.close()
    asyncio.run(run())


def test_partial_notification_retry_is_per_destination(tmp_path):
    async def run():
        ws = Workspace(tmp_path / "notifications")
        try:
            good, bad = "jsons://good.example/?token=synthetic-good", "jsons://bad.example/?token=synthetic-bad"
            ws.store.set_setting("alerts", {"enabled": True, "daily": True, "daily_hour": 0})
            ws.vault.save("alerts", {"urls": [good, bad]})
            ws.store.set_setting("alerts_cursor", 0)
            ws.store.append("storage.low", {"free_bytes": 12})
            now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
            calls, failing = [], {bad}
            def send(urls, title, body, network):
                assert len(urls) == 1
                calls.append((urls[0], title, body))
                failed = urls[0] in failing
                return {"sent": 0 if failed else 1, "failed": int(failed), "error": "Synthetic refusal" if failed else None}
            with patch.object(alerts, "deliver", send):
                await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"), now)
                assert len([row for row in calls if row[0] == good]) == 2
                assert ws.store.get_setting("alerts_cursor") == 0, "Failed receiver lost pending events"
                await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"), now + timedelta(seconds=1))
                assert len(calls) == 3, "Acknowledged delivery or backed-off failure was retried"
                failing.clear()
                await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"), now + timedelta(seconds=31))
                assert len([row for row in calls if row[0] == good]) == 2
                assert len([row for row in calls if row[0] == bad]) == 3
                assert ws.store.get_setting("alerts_cursor") == ws.store.stats()["head"]["seq"]
                await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"), now + timedelta(seconds=60))
                assert len(calls) == 5
                ws.vault.save("alerts", {"urls": [bad, good]})
                ws.store.append("storage.low", {"free_bytes": 1})
                failing.add(bad)
                original_send = send
                def raises(urls, title, body, network):
                    if urls == [bad]:
                        raise OSError("synthetic provider failure")
                    return original_send(urls, title, body, network)
                with patch.object(alerts, "deliver", raises):
                    result = await alerts.alert_pass(ws.store, ws.vault, NetworkConfig(kind="direct"), now + timedelta(seconds=90))
                assert result["error"] == "OSError" and result["notifications"] == 1
                assert ws.store.get_setting("alerts_cursor") < ws.store.stats()["head"]["seq"]
            persisted = json.dumps(ws.store.get_setting("alerts_delivery"))
            assert good not in persisted and bad not in persisted and "synthetic-good" not in persisted
        finally:
            ws.close()
    asyncio.run(run())


def test_notification_route_isolated_from_unrelated_threads():
    def current_route():
        return requests.Session().merge_environment_settings("https://example.invalid", {}, None, None, None)["proxies"]
    with patch.dict("os.environ", {"HTTPS_PROXY": "http://environment.invalid:8080", "NO_PROXY": ""}):
        baseline = current_route()
        with ThreadPoolExecutor(max_workers=1) as pool, alerts._routed("socks5h://notification.invalid:1080"):
            assert current_route()["https"] == "socks5h://notification.invalid:1080"
            assert pool.submit(current_route).result() == baseline
            guard = alerts._guard.get()
            guard.update(on=True, pinned={"reserved.invalid": ["192.0.2.1"]})
            assert alerts._checked("reserved.invalid", 443) == ["192.0.2.1"]
            assert pool.submit(alerts._checked, "reserved.invalid", 443).result() is None
        assert current_route() == baseline and alerts._guard.get() is None


def test_deployment_record_replacement_failure_preserves_inventory(tmp_path):
    path = tmp_path / "deployment.json"
    old = {"deployment_id": "synthetic", "resources": {"server": "synthetic-id"}}
    cloud.write_record(path, old)
    with patch.object(security.os, "replace", side_effect=OSError("Synthetic interruption")):
        with pytest.raises(OSError, match="Synthetic"):
            cloud.write_record(path, {**old, "resources": {"server": "new-id"}})
    assert json.loads(path.read_bytes()) == old
    cloud.write_record(path, {**old, "completed": True})
    assert json.loads(path.read_bytes())["completed"] is True


def test_versioned_measurement_includes_resources_and_preserves_legacy(tmp_path):
    package = tmp_path / "tgwitness"
    (package / "fonts").mkdir(parents=True)
    (package / "static").mkdir()
    (package / "__pycache__").mkdir()
    (package / "code.py").write_bytes(b"x = 1\n")
    (package / "sealed_policy.json").write_bytes(b'{"mode":"first"}')
    (package / "fonts" / "synthetic.ttf").write_bytes(b"synthetic font")
    (package / "fonts" / "OFL.txt").write_bytes(b"synthetic license")
    (package / "unknown.asset").write_bytes(b"synthetic resource")
    (package / "README.md").write_text("Package reference documentation", encoding="utf-8")
    (package / "static" / "README.md").write_text("Panel reference documentation", encoding="utf-8")
    (package / "__pycache__" / "code.pyc").write_bytes(b"cache")
    v1 = provenance.source_files(package, provenance.LEGACY_SOURCE_POLICY)
    assert v1 == {"code.py": hashlib.sha256(b"x = 1\n").hexdigest()}
    v2 = provenance.source_files(package)
    assert set(v2) == {"code.py", "sealed_policy.json", "fonts/synthetic.ttf", "fonts/OFL.txt", "unknown.asset"}
    for name in ("README.md", "static/README.md"):
        (package / name).write_text("Changed reference documentation", encoding="utf-8")
    assert provenance.source_files(package) == v2, "Unshipped reference docs changed the package measurement"
    for name in ("sealed_policy.json", "fonts/synthetic.ttf", "fonts/OFL.txt", "unknown.asset"):
        original = (package / name).read_bytes()
        (package / name).write_bytes(original + b" changed")
        assert provenance.source_tree_sha256(provenance.source_files(package)) != provenance.source_tree_sha256(v2), name
        (package / name).write_bytes(original)
    assert provenance.source_files(package, provenance.LEGACY_SOURCE_POLICY) == v1
    run = {"public_key": "synthetic", "run_id": "synthetic", "source_tree_sha256": "old", "host": {}}
    assert assurance.start_binding(run) == {"format": "tgwitness-tdx-start-v1", **run}
    assert assurance.start_binding({**run, "source_policy": provenance.SOURCE_POLICY})["source_policy"] == provenance.SOURCE_POLICY
    async def github(path, _):
        if "/commits/" in path:
            return {"sha": "synthetic-commit"}
        return {"tree": [{"type": "blob", "path": "tgwitness/" + name,
                          "sha": next(iter(source_check.blob_ids((package / name).read_bytes())))}
                         for name in (path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file())]}
    with patch.object(source_check, "github", github):
        checked = asyncio.run(source_check.check("synthetic/project", "main", None, package))
    assert checked["matches"] and checked["source_policy"] == provenance.SOURCE_POLICY
    with pytest.raises(ValueError, match="Unknown"):
        provenance.source_files(package, "unknown")


def test_package_measurement_matches_declared_wheel_inventory():
    package = ROOT / "tgwitness"
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {path.relative_to(package).as_posix() for path in package.rglob("*.py")
                if "__pycache__" not in path.parts}
    for pattern in config["tool"]["setuptools"]["package-data"]["tgwitness"]:
        declared.update(path.relative_to(package).as_posix() for path in package.glob(pattern) if path.is_file())
    assert set(provenance.source_files(package)) == declared


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
