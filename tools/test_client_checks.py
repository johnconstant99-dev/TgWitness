import asyncio
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FloodWaitError, FloodPremiumWaitError

from tgwitness import client_checks, client_identity
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_events


def client(official=True):
    current = NS(current=True, official_app=official, api_id=6, device_model="Synthetic phone", platform="Android",
                 system_version="SDK 34", app_name="Telegram Android", app_version="12.8.3", ip="private-ip", hash=123)
    fake = AsyncMock(side_effect=[NS(this_dc=2), NS(this_dc=2, nearest_dc=2), NS(authorizations=[current]), [], NS(), NS()])
    fake.api_id = 6
    fake._init_request = NS(api_id=6)
    fake.rpc_backoff_getter = lambda: 0
    fake.tgwitness_client_profile = client_identity.resolve(6, seed="synthetic")
    return fake


@pytest.mark.parametrize("official", [True, False])
def test_connection_checks_report_flags_without_safety_claims(monkeypatch, official):
    fake = client(official)
    monkeypatch.setattr(client_checks.asyncio, "sleep", AsyncMock())
    report = asyncio.run(client_checks.inspect_connection(fake))
    assert report["official_app"] is official and len(report["checks"]) == 7
    assert fake.await_count == 6
    assert report["authorization"]["device_model"] == "Synthetic phone"
    assert not {"ip", "hash", "api_hash"} & report["authorization"].keys()
    assert report["checks"][2]["status"] == ("ok" if official else "warning")
    assert report["checks"][3]["actual"] == client_checks.LAYER


@pytest.mark.parametrize("failure", [FloodWaitError(None, 100), FloodPremiumWaitError(None, 200), OSError("private proxy")])
def test_failed_checks_stop_and_do_not_report_false_flag(monkeypatch, failure):
    fake = client()
    fake.side_effect = failure
    monkeypatch.setattr(client_checks.asyncio, "sleep", AsyncMock())
    report = asyncio.run(client_checks.inspect_connection(fake))
    assert fake.await_count == 1 and report["official_app"] is None
    assert len(report["checks"]) == 7 and report["checks"][1]["status"] == "skipped"
    assert report["checks"][3]["status"] in ("ok", "warning")
    assert report["checks"][0]["error"] == type(failure).__name__
    assert "private proxy" not in str(report)


def test_checks_respect_saved_wait_and_share_concurrent_result(tmp_path, monkeypatch):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = Collector(store, vault)
        fake = client()
        fake.tgwitness_connection_check = None
        fake.rpc_backoff_getter = lambda: client_checks.time.time() + 300
        collector.client = fake
        monkeypatch.setattr(client_checks.asyncio, "sleep", AsyncMock())
        try:
            reports = await asyncio.gather(collector.check_client_connection(fake), collector.check_client_connection(fake))
            assert reports[0] == reports[1] and fake.await_count == 0
            assert store.get_setting("client_checks") == reports[0]
            events = list(reversed(store.events()))
            assert len(events) == 1 and events[0]["kind"] == "account.connection_checked"
            assert verify_events(events, vault.public_key)["events"] == 1
            assert store.count_events(kind="account.connection_checked") == 1
        finally:
            store.close()
    asyncio.run(scenario())


def test_cancelled_or_replaced_client_cannot_leave_a_stale_check(tmp_path, monkeypatch):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = Collector(store, vault)
        fake = client()
        fake.tgwitness_connection_check = None
        collector.client = fake
        started, release = asyncio.Event(), asyncio.Event()
        async def inspect(_):
            started.set()
            await release.wait()
            return {"official_app": True, "checks": []}
        monkeypatch.setattr(client_checks, "inspect_connection", inspect)
        try:
            pending = asyncio.create_task(collector.check_client_connection(fake))
            await started.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert fake.tgwitness_connection_check is None
            collector.client = None
            release.set()
            await collector.check_client_connection(fake)
            assert store.get_setting("client_checks", None) is None and not store.events()
        finally:
            store.close()
    asyncio.run(scenario())


def test_reported_connection_keeps_actual_language_pack(tmp_path):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        vault.save("network", {"kind": "direct"})
        collector = Collector(store, vault)
        fake = collector.make_client(6, "a" * 32)
        try:
            actual = collector.client_identity(fake)
            assert actual["lang_pack"] == "android"
            assert not any("lang_pack" in warning for warning in actual.get("warnings", []))
        finally:
            await fake.disconnect()
            store.close()
    asyncio.run(scenario())
