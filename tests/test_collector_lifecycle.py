import asyncio
from types import SimpleNamespace as NS

import pytest
from telethon.tl import types

from test_collector import CHAT, FakeClient, saved_session, telegram_message
from tgwitness.collector import Collector
from tgwitness.network import NetworkConfig
from test_reliability import prepared


class ProfileClient(FakeClient):
    async def __call__(self, request):
        return types.users.UserFull(full_user=types.UserFull(
            id=55, settings=types.PeerSettings(), notify_settings=types.PeerNotifySettings(),
            common_chats_count=0, about="Synthetic profile"), chats=[], users=[])


def test_avatar_history_only_receives_recorded_sources_and_closes_before_disconnect(journal, monkeypatch):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, ProfileClient)
        await collector.configure(123, "a" * 32, saved_session())
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        observed, closes = [], []

        def observe(entity, *, chat_id):
            observed.append((entity.id, chat_id, store.events(limit=1)[0]["kind"]))

        async def close():
            closes.append(collector.client.connected)

        monkeypatch.setattr(collector.avatar_history, "observe", observe)
        monkeypatch.setattr(collector.avatar_history, "close", close)
        actor = types.User(id=55, first_name="Alice", photo=types.UserProfilePhoto(photo_id=70, dc_id=2))
        collector.remember(actor)
        assert not observed
        collector.running = True
        message = telegram_message()
        message._sender = actor
        await collector.on_new(NS(chat_id=-100999, message=message))
        assert not observed
        await collector.on_new(NS(chat_id=CHAT, message=message))
        assert observed == [(55, CHAT, "message.new")]
        await collector.capture_profile(55, actor)
        assert observed[-1] == (55, 55, "source.profile")
        await collector.stop(shutdown=True)
        assert closes == [True]
        assert not collector.client.connected
    asyncio.run(run())


@pytest.mark.parametrize("action", ["sign_out", "set_network", "configure"])
@pytest.mark.parametrize("reservation", ["multi", "single"])
def test_export_keeps_its_connection_until_finished(journal, action, reservation):
    async def run():
        store, vault = journal
        collector = await prepared(journal)
        client, credentials = collector.client, vault.read("credentials")
        if reservation == "multi":
            assert collector.reserve_export("synthetic-export")
        else:
            collector.export_task = asyncio.create_task(asyncio.Event().wait())
        before = store.stats()["total"]
        try:
            args = {"sign_out": (), "set_network": (NetworkConfig(kind="mtproxy_auto"),),
                    "configure": (123, "a" * 32, saved_session())}[action]
            with pytest.raises(ValueError, match="export"):
                await getattr(collector, action)(*args)
            assert collector.client is client and client.connected
            assert vault.read("credentials") == credentials
            assert store.stats()["total"] == before
        finally:
            collector.release_export("synthetic-export")
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_export_cannot_reserve_an_account_while_its_route_is_changing(journal):
    async def run():
        collector = await prepared(journal)
        entered, release = asyncio.Event(), asyncio.Event()
        client = collector.client

        async def disconnect():
            entered.set()
            await release.wait()
            client.connected = False

        client.disconnect = disconnect
        change = asyncio.create_task(collector.set_network(NetworkConfig(kind="mtproxy_auto")))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not collector.reserve_export("too-early")
            release.set()
            await change
            assert collector.reserve_export("after-change")
        finally:
            release.set()
            await asyncio.gather(change, return_exceptions=True)
            collector.release_export("too-early")
            collector.release_export("after-change")
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_cancelled_start_does_not_leave_a_collector_without_workers(journal, monkeypatch):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        entered = asyncio.Event()

        async def buffered_update(_):
            entered.set()
            await asyncio.Event().wait()

        original = collector.prepare_start

        async def prepare():
            await original()
            collector.buffered.append((buffered_update, None))

        monkeypatch.setattr(collector, "prepare_start", prepare)
        start = asyncio.create_task(collector.start())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            start.cancel()
            with pytest.raises(asyncio.CancelledError):
                await start
            assert not collector.running
            assert not store.get_setting("resume", False)
            assert all(task is None or task.done() for task in (
                collector.watchdog, collector.media_worker, collector.urgent_media_worker,
                collector.reconciler, collector.intake_worker))
            assert store.events(kind="observation.stopped")
            assert not collector.client.connected
        finally:
            start.cancel()
            await asyncio.gather(start, return_exceptions=True)
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_history_write_failure_is_not_a_network_retry_that_skips_the_message(journal, monkeypatch):
    async def run():
        collector = await prepared(journal)
        requests, saved = [], []

        async def messages(entity, *, offset_id, min_id):
            requests.append(offset_id)
            for number in (3, 2, 1):
                if number > min_id and (not offset_id or number < offset_id):
                    yield telegram_message(number)

        async def write(message):
            if message.id == 2:
                raise OSError("Synthetic disk write failed")
            saved.append(message.id)

        async def no_delay(_):
            pass

        monkeypatch.setattr(collector.client, "iter_messages", messages)
        monkeypatch.setattr(asyncio, "sleep", no_delay)
        try:
            with pytest.raises(OSError, match="disk write"):
                await collector.iterate_history(CHAT, write)
            assert requests == [0] and saved == [3]
        finally:
            await collector.stop(shutdown=True)
    asyncio.run(run())
