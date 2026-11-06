import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telethon.errors import FloodWaitError, FloodPremiumWaitError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import collector as collector_module
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store


@pytest.mark.parametrize("error_type", [FloodWaitError, FloodPremiumWaitError])
def test_lookup_preserves_telegram_wait(error_type):
    error = error_type(None, 30)
    client = SimpleNamespace(get_entity=AsyncMock(side_effect=error))
    collector = SimpleNamespace(client=client)
    with pytest.raises(error_type) as caught:
        asyncio.run(Collector.lookup_entity(collector, -100123))
    assert caught.value is error
    client.get_entity.assert_awaited_once_with(-100123)


def test_unknown_peer_still_returns_no_entity():
    client = SimpleNamespace(get_entity=AsyncMock(side_effect=ValueError("Unknown peer")))
    assert asyncio.run(Collector.lookup_entity(SimpleNamespace(client=client), -100123)) is None


@pytest.mark.parametrize("error_type", [FloodWaitError, FloodPremiumWaitError])
def test_new_chat_intake_requeues_lookup_after_wait(tmp_path, monkeypatch, error_type):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("scope", {"new_chats": {"profile": True}})
        collector = Collector(store, vault)
        entity = SimpleNamespace(id=123)

        async def limited(chat_id):
            # The shared RPC handler may already have retained a longer wait.
            store.set_setting("rpc_backoff_until", 240)
            collector.running = False
            raise error_type(None, 30)

        async def captured(chat_id, observed):
            assert chat_id == -100123 and observed is entity
            collector.running = False

        collector.client = SimpleNamespace(get_entity=AsyncMock(side_effect=limited))
        collector.capture_profile = AsyncMock(side_effect=captured)
        monkeypatch.setattr(collector_module, "time", SimpleNamespace(time=lambda: 100))
        try:
            collector.running = True
            collector.intake.put_nowait((-100123, None, False))
            await collector.intake_loop()
            assert collector.intake.qsize() == 1, "FloodWait must not discard the pending chat"
            assert store.get_setting("rpc_backoff_until") == 240
            assert not collector.capture_profile.called
            records = store.events()
            assert any(row["kind"] == "telegram.backoff" for row in records)
            assert not any(row["kind"] == "collector.error" for row in records)

            store.set_setting("rpc_backoff_until", 0)
            collector.client.get_entity.side_effect = None
            collector.client.get_entity.return_value = entity
            collector.running = True
            await collector.intake_loop()
            collector.capture_profile.assert_awaited_once_with(-100123, entity)
            assert collector.client.get_entity.await_count == 2
            assert collector.intake.empty()
            store.verify(vault.public_key)
        finally:
            store.close()
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
