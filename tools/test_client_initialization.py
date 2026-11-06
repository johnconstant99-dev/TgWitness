import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FloodWaitError, FloodPremiumWaitError

from tgwitness import client_initialization
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_events
from tools.browser_fixtures import FakeClient, saved_session


@pytest.mark.parametrize("lang_pack, count", [("android", 6), ("tdesktop", 6), ("", 5)])
def test_initialization_sequence(monkeypatch, lang_pack, count):
    client = AsyncMock()
    client.tgwitness_client_profile = {"lang_pack": lang_pack}
    sleep = AsyncMock()
    monkeypatch.setattr(client_initialization.asyncio, "sleep", sleep)
    result = asyncio.run(client_initialization.post_login(client))
    assert len(result) == count and all(row["status"] == "completed" for row in result)
    requests = [call.args[0] for call in client.await_args_list]
    assert [type(r).__name__ for r in requests[:3]] == ["GetConfigRequest", "GetNearestDcRequest", "UpdateStatusRequest"]
    assert requests[2].offline is False
    assert [type(r).__name__ for r in requests[-2:]] == ["GetAppUpdateRequest", "GetTermsOfServiceUpdateRequest"]
    assert all(.3 <= call.args[0] <= 1.5 for call in sleep.await_args_list)
    assert sleep.await_count == count - 1


@pytest.mark.parametrize("failure", [FloodWaitError(None, 100), FloodPremiumWaitError(None, 200), OSError("private proxy")])
def test_initialization_stops_without_retries_or_secret_errors(monkeypatch, failure):
    client = AsyncMock(side_effect=[SimpleNamespace(), failure])
    client.tgwitness_client_profile = {"lang_pack": "android"}
    monkeypatch.setattr(client_initialization.asyncio, "sleep", AsyncMock())
    result = asyncio.run(client_initialization.post_login(client))
    assert client.await_count == 2 and result[-1]["error"] == type(failure).__name__
    assert "private proxy" not in str(result)
    if hasattr(failure, "seconds"):
        assert result[-1]["wait_seconds"] == failure.seconds


def test_initialization_only_on_new_authorization_and_signed(tmp_path, monkeypatch):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        vault.save("network", {"kind": "direct"})
        collector = Collector(store, vault, FakeClient)
        post = AsyncMock(return_value=[{"request": "help.GetConfigRequest", "status": "completed"}])
        monkeypatch.setattr(client_initialization, "post_login", post)
        try:
            await collector.start_phone("+15550001111", 123, "a" * 32)
            await collector.confirm_code("11111")
            post.assert_awaited_once()
            assert vault.read("credentials")["session"]
            await collector.stop(shutdown=True)
            collector = Collector(store, vault, FakeClient)
            await collector.restore()
            await collector.configure(123, "a" * 32, saved_session(), 44)
            post.assert_awaited_once()
            events = list(reversed(store.events()))
            assert len([e for e in events if e["kind"] == "account.initialized"]) == 1
            verify_events(events, vault.public_key)
            assert store.db.execute("SELECT total FROM event_kind_counts WHERE kind='account.initialized'").fetchone()[0] == 1
        finally:
            await collector.stop(shutdown=True)
            store.close()
    asyncio.run(scenario())
