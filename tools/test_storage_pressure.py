import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from pydantic import ValidationError

from tgwitness import storage
from tools.check_storage_services import Workspace


@pytest.fixture
def ws(tmp_path):
    workspace = Workspace(tmp_path / "storage")
    try:
        yield workspace
    finally:
        workspace.close()


def configure(ws, **changes):
    ws.store.set_setting("storage", {**storage.settings(ws.store), **changes})


def disk(monkeypatch, free):
    monkeypatch.setattr(storage.shutil, "disk_usage", lambda _: SimpleNamespace(free=free(), total=100 * storage.MIB))


@pytest.mark.parametrize("compressed", [False, True])
def test_low_space_keeps_original_without_upload_or_staging(ws, monkeypatch, compressed):
    configure(ws, compress=compressed)
    path, _, original = ws.media()
    disk(monkeypatch, lambda: ws.manager.reserve_bytes())
    result = asyncio.run(ws.manager.sync())
    assert result["files"] == 0 and result["skipped_space"] == 1
    assert result["required_free_bytes"] > ws.manager.reserve_bytes()
    assert result["error"] == storage.SPACE_MESSAGE
    assert path.read_bytes() == original and not ws.remote.objects
    assert not list(ws.root.glob("storage-*"))


def test_large_file_does_not_block_smaller_eligible_file(ws, monkeypatch):
    large, _, data = ws.media(b"L" * (512 * 1024))
    small, _, _ = ws.media(b"small file")
    disk(monkeypatch, lambda: ws.manager.reserve_bytes() + 128 * 1024)
    result = asyncio.run(ws.manager.sync())
    assert result["files"] == 1 and result["skipped_space"] == 1 and not result["error"]
    assert large.read_bytes() == data and not small.exists()
    assert len(ws.remote.objects) == 1


@pytest.mark.parametrize("compressed", [False, True])
def test_space_consumed_after_preflight_aborts_without_deleting(ws, monkeypatch, compressed):
    configure(ws, compress=compressed)
    path, _, original = ws.media()
    readings = iter([10 * 1024**3, 0])
    disk(monkeypatch, lambda: next(readings, 0))
    result = asyncio.run(ws.manager.sync())
    assert result["skipped_space"] == 1 and result["files"] == 0
    assert path.read_bytes() == original and not ws.remote.objects
    assert not list(ws.root.glob("storage-*"))


def test_existing_verified_copy_frees_space_without_repacking(ws, monkeypatch):
    configure(ws, purpose="copy", compress=True)
    path, _, original = ws.media()
    assert asyncio.run(ws.manager.sync())["files"] == 1
    assert path.exists()
    configure(ws, purpose="offload", compress=False)
    disk(monkeypatch, lambda: 0)
    result = asyncio.run(ws.manager.sync())
    assert result["freed_bytes"] == len(original) and not result["error"]
    assert not path.exists() and len(ws.remote.objects) == 1


@pytest.mark.parametrize("compressed", [False, True])
def test_restore_checks_space_before_downloading(ws, monkeypatch, compressed):
    configure(ws, compress=compressed)
    path, digest, _ = ws.media()
    assert asyncio.run(ws.manager.sync())["files"] == 1
    ws.remote.get = AsyncMock()
    disk(monkeypatch, lambda: ws.manager.reserve_bytes())
    with pytest.raises(storage.StorageSpaceError):
        asyncio.run(ws.manager.restore(digest))
    ws.remote.get.assert_not_called()
    assert not path.exists() and not list(ws.root.glob("storage-*"))
    assert ws.manager.public()["remote_files"] == 1


@pytest.mark.parametrize("changes", [{"enabled": False}, {"purpose": "copy"}, {"pressure_enabled": False}])
def test_pressure_never_enables_automation_or_removal(ws, monkeypatch, changes):
    configure(ws, enabled=True, purpose="offload", pressure_enabled=True)
    configure(ws, **changes)
    ws.store.set_setting("storage_last", {"at": "previous"})
    ws.store.set_setting("storage_attempt", 1000)
    monkeypatch.setattr(storage.time, "time", lambda: 1001)
    disk(monkeypatch, lambda: 0)
    ws.manager.sync = AsyncMock()
    asyncio.run(ws.manager.tick())
    ws.manager.sync.assert_not_called()
    assert not ws.manager.disk_status()["pressure_active"]


def test_pressure_hysteresis_and_restart_with_notifications_disabled(ws, monkeypatch):
    configure(ws, enabled=True, pressure_enabled=True, pressure_low_mb=5, pressure_high_mb=10)
    ws.store.set_setting("alerts", {"enabled": False})
    ws.store.set_setting("storage_attempt", 1000)
    ws.store.set_setting("storage_last", {"at": "previous"})
    clock, free = [1001], [4 * storage.MIB]
    monkeypatch.setattr(storage.time, "time", lambda: clock[0])
    disk(monkeypatch, lambda: free[0])
    ws.manager.sync = AsyncMock(return_value={"freed_bytes": 1, "error": None})
    asyncio.run(ws.manager.tick())
    ws.manager.sync.assert_awaited_once_with(reason="pressure")
    assert ws.store.get_setting("storage_pressure_active")

    restarted = storage.Storage(ws.store, ws.vault, ws.manager.network)
    restarted.sync = AsyncMock(return_value={"freed_bytes": 1, "error": None})
    free[0], clock[0] = 7 * storage.MIB, 1032
    asyncio.run(restarted.tick())
    restarted.sync.assert_awaited_once_with(reason="pressure")
    free[0], clock[0] = 10 * storage.MIB, 1063
    asyncio.run(restarted.tick())
    assert restarted.sync.await_count == 1
    assert not ws.store.get_setting("storage_pressure_active")


@pytest.mark.parametrize("error", [None, "Cloud unavailable"])
def test_no_progress_backs_off_across_restart(ws, monkeypatch, error):
    configure(ws, enabled=True, pressure_enabled=True)
    clock = [1000]
    monkeypatch.setattr(storage.time, "time", lambda: clock[0])
    disk(monkeypatch, lambda: 0)
    ws.manager.sync = AsyncMock(return_value={"freed_bytes": 0, "error": error})
    asyncio.run(ws.manager.tick())
    assert ws.store.get_setting("storage_pressure_retry_at") == 1300
    restarted = storage.Storage(ws.store, ws.vault, ws.manager.network)
    restarted.sync = AsyncMock(return_value={"freed_bytes": 0, "error": error})
    clock[0] = 1299
    asyncio.run(restarted.tick())
    restarted.sync.assert_not_called()
    clock[0] = 1300
    asyncio.run(restarted.tick())
    restarted.sync.assert_awaited_once_with(reason="pressure")


def test_pressure_stops_batch_at_target(ws, monkeypatch):
    configure(ws, enabled=True, pressure_enabled=True, pressure_low_mb=2048, pressure_high_mb=4096)
    first, _, _ = ws.media(b"first")
    second, _, _ = ws.media(b"second")
    free = [1536 * storage.MIB]
    disk(monkeypatch, lambda: free[0])
    copy_one = ws.manager.copy_one

    async def copy_and_free(*args):
        result = await copy_one(*args)
        free[0] = 4096 * storage.MIB
        return result

    ws.manager.copy_one = copy_and_free
    result = asyncio.run(ws.manager.tick())
    assert result["reason"] == "pressure" and result["files"] == 1
    assert not first.exists() and second.exists()


def test_pressure_honors_age_and_busy_operation(ws, monkeypatch):
    configure(ws, enabled=True, pressure_enabled=True, older_than_days=7)
    path, _, original = ws.media()
    disk(monkeypatch, lambda: 2 * 1024**3)
    result = asyncio.run(ws.manager.tick())
    assert result["files"] == 0 and not result["error"]
    assert path.read_bytes() == original and not ws.remote.objects

    async def busy():
        async with ws.manager.lock:
            ws.manager.sync = AsyncMock()
            await ws.manager.tick()
            ws.manager.sync.assert_not_called()

    asyncio.run(busy())


def test_thresholds_must_have_gap():
    with pytest.raises(ValidationError, match="greater"):
        storage.Settings(pressure_low_mb=50, pressure_high_mb=50)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
