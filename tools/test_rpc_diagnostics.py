import asyncio
import json
from pathlib import Path
import sys

import pytest
from telethon.errors import FloodWaitError, FloodPremiumWaitError
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import telegram_client as mod
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store


def history():
    return f.messages.GetHistoryRequest(t.InputPeerChannel(42, 123456789),
        offset_id=0, offset_date=None, add_offset=0, limit=100, max_id=0, min_id=0, hash=0)


@pytest.mark.parametrize("error_type", [FloodWaitError, FloodPremiumWaitError])
def test_backoff_keeps_method_wrapper_counts_and_deadline(tmp_path, monkeypatch, error_type):
    async def scenario():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        collector = Collector(store, vault)
        monkeypatch.setattr(collector, "route_options", lambda: {})
        client = collector.make_client(123456, "a" * 32)
        collector.client = client
        clock, sent = [100.0], []
        first = f.contacts.ResolveUsernameRequest("private_fixture_argument")
        inner = history()
        wrapped = f.InvokeWithTakeoutRequest(987654321,
            f.InvokeWithMessagesRangeRequest(t.MessageRange(1, 999), inner))

        async def call(self, sender, req, ordered=False, flood_sleep_threshold=None):
            sent.append((req, clock[0]))
            if req is wrapped:
                # Another callback may have already retained a longer deadline.
                store.set_setting("rpc_backoff_until", 10000)
                raise error_type(inner, capture=7200)
            return req

        async def sleep(seconds):
            clock[0] += seconds

        monkeypatch.setattr(mod.TelegramClient, "_call", call)
        monkeypatch.setattr(mod.time, "time", lambda: clock[0])
        monkeypatch.setattr(mod.asyncio, "sleep", sleep)
        try:
            await client._call(None, first)
            with pytest.raises(error_type):
                await client._call(None, wrapped)
            details = store.get_setting("rpc_backoff")
            assert details["method"] == details["failed_method"] == "messages.getHistory"
            assert details["wrappers"] == ["invokeWithTakeout", "invokeWithMessagesRange"]
            assert details["wait_until"] == store.get_setting("rpc_backoff_until") == 10000
            assert client.bulk_pacer.state()["floodwait_count"] == 1
            assert client.bulk_pacer.state()["delay_seconds"] > 1
            stats = details["activity"]["methods"]
            assert stats["contacts.resolveUsername"]["ok"] == 1
            assert stats["invokeWithTakeout/invokeWithMessagesRange/messages.getHistory"]["flood_waits"] == 1
            assert collector.status()["rpc_backoff"] == details
            assert collector.status()["rpc_activity"] == details["activity"]
            event = next(row for row in store.events() if row["kind"] == "telegram.backoff")
            encoded = json.dumps(event)
            for secret in ("private_fixture_argument", "123456789", "987654321", "access_hash", "api_hash"):
                assert secret not in encoded
            store.verify(vault.public_key)
            # A fresh client must respect the persisted deadline, before ANY method.
            fresh = collector.make_client(123456, "a" * 32)
            assert fresh.bulk_pacer.state() == client.bulk_pacer.state()
            await fresh._call(None, f.help.GetConfigRequest())
            assert sent[-1][1] >= 10000
            assert store.get_setting("rpc_backoff") == details
        finally:
            store.close()
    asyncio.run(scenario())


def test_nested_resolution_batch_cancellation_and_snapshot(monkeypatch):
    async def scenario():
        client = object.__new__(mod.WitnessClient)
        lookup = f.contacts.ResolveUsernameRequest("fixture")
        blocked = f.help.GetNearestDcRequest()
        entered = asyncio.Event()

        async def call(self, sender, req, ordered=False, flood_sleep_threshold=None):
            if isinstance(req, f.messages.GetHistoryRequest):
                await self._call(sender, lookup)
            if req is blocked:
                entered.set()
                await asyncio.Event().wait()
            return req

        monkeypatch.setattr(mod.TelegramClient, "_call", call)
        assert client.rpc_activity() is None
        await client._call(None, [history(), f.help.GetConfigRequest()])
        task = asyncio.create_task(client._call(None, blocked))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        counts = client.rpc_activity()["methods"]
        assert counts["contacts.resolveUsername"]["ok"] == 1
        assert counts["messages.getHistory"]["ok"] == 1
        assert counts["help.getNearestDc"]["cancelled"] == 1
        counts.clear()
        assert len(client.rpc_activity()["methods"]) == 4
        await client._call(None, f.help.GetConfigRequest())
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
