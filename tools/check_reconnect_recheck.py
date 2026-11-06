"""Check that a reconnect rechecks every observed chat at once (T25)."""
import asyncio
from pathlib import Path
import sys
import time
from unittest.mock import AsyncMock, patch

from telethon import TelegramClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.telegram_client import WitnessClient
from tools.browser_fixtures import saved_session
from tools.check_session_reservations import workspace

PRIORITY, REGULAR, QUIET = -1000000000111, -1000000000222, -1000000000333


def targets(store):
    store.set_target(PRIORITY, "Priority chat", "supergroup", True, priority=1)
    store.set_target(REGULAR, "Regular chat", "supergroup", True, priority=0)
    store.set_target(QUIET, "Quiet chat", "channel", True, priority=0)
    store.set_setting("recheck_last", {str(chat_id): time.time() for chat_id in (PRIORITY, REGULAR, QUIET)})


async def pass_after(collector, wake):
    passes, done = [], asyncio.Event()
    async def recorded(due):
        passes.append([target["chat_id"] for target in due])
        done.set()
    with patch.object(collector, "recheck_pass", recorded):
        task = asyncio.create_task(collector.recheck_loop())
        try:
            await asyncio.sleep(0.05)
            assert not passes, "no recheck before its schedule or a reconnect"
            wake()
            await asyncio.wait_for(done.wait(), 5)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    return passes[0]


async def check_loop():
    async with workspace() as (app, _):
        collector, store = app.state.collector, app.state.store
        await collector.configure(123, "a" * 32, saved_session())
        targets(store)
        collector.running = True
        assert collector.due_targets(forced=True) == [t for t in store.targets(True) if t["chat_id"] == PRIORITY], \
            "the first pass after a start still covers priority chats only"
        due = await pass_after(collector, collector.recheck_wakeup.set)
        assert due[0] == PRIORITY and sorted(due[1:]) == sorted([REGULAR, QUIET]), due

        reconnected = time.time()
        store.set_setting("parameters", {"recheck_max_chats": 1})
        order = []
        for _ in range(3):
            due = collector.due_targets(reconnected=reconnected)
            assert len(due) == 1
            order.append(due[0]["chat_id"])
            store.set_setting("recheck_last", {**store.get_setting("recheck_last"), str(due[0]["chat_id"]): time.time()})
        assert order[0] == PRIORITY and sorted(order) == sorted([PRIORITY, REGULAR, QUIET]), order
        assert collector.due_targets(reconnected=reconnected) == [], "each chat is rechecked once per reconnect"

        store.set_setting("parameters", {})
        store.set_setting("recheck_other_minutes", 0)
        assert [t["chat_id"] for t in collector.due_targets(reconnected=time.time())] == [PRIORITY], \
            "a tier switched off stays off after a reconnect"
        collector.running = False
    return "ok  loop: a reconnect makes every observed chat due, priority first, spread over passes"


async def check_transport_reconnect():
    async with workspace() as (app, _):
        collector, store = app.state.collector, app.state.store
        await collector.configure(123, "a" * 32, saved_session())
        targets(store)
        collector.client_factory = WitnessClient
        client = collector.make_client(123, "a" * 32, saved_session(b"r"))
        other = collector.make_client(123, "a" * 32, saved_session(b"o"))
        try:
            assert client._sender._auto_reconnect_callback.__func__ is WitnessClient._handle_auto_reconnect
            collector.client, collector.running = client, True
            with patch.object(TelegramClient, "_handle_auto_reconnect", AsyncMock()) as telethon:
                await other._handle_auto_reconnect()
                assert not collector.recheck_wakeup.is_set(), "a client that is not observing wakes nothing"
                collector.running = False
                await client._handle_auto_reconnect()
                assert not collector.recheck_wakeup.is_set(), "nothing is rechecked while observation is paused"
                collector.running = True
                await client._handle_auto_reconnect()
                assert telethon.await_count == 3 and collector.recheck_wakeup.is_set()
                collector.recheck_wakeup.clear()
                with patch.object(client, "is_connected", lambda: True):
                    due = await pass_after(collector, lambda: asyncio.ensure_future(client._handle_auto_reconnect()))
            assert due[0] == PRIORITY and sorted(due) == sorted([PRIORITY, REGULAR, QUIET]), due
        finally:
            collector.running = False
            await other.disconnect()
            await client.disconnect()
    return "ok  transport: Telethon's own reconnect wakes the recheck of every observed chat"


async def main():
    print(await asyncio.wait_for(check_loop(), 60))
    print(await asyncio.wait_for(check_transport_reconnect(), 60))
    print("reconnect recheck checks passed")


if __name__ == "__main__":
    asyncio.run(main())
