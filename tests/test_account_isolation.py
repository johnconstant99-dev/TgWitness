import asyncio
from types import SimpleNamespace as NS

import pytest
from telethon.tl import types

from tgwitness.collector import Collector
from test_collector import CHAT, FakeClient, saved_session, telegram_message


async def emit_registered(client):
    updates = [
        NS(chat_id=CHAT, message=telegram_message(901, "Delivered by this client")),
        NS(chat_id=CHAT, message=telegram_message(901, "Edited by this client")),
        NS(chat_id=CHAT, deleted_ids=[901], original_update={}),
        types.UpdateMessageReactions(peer=types.PeerChannel(123), msg_id=901,
            reactions=types.MessageReactions(results=[])),
    ]
    for handler, update in zip(client.handlers, updates, strict=True):
        await handler(update)


@pytest.mark.parametrize("method", ["session", "code", "password"])
def test_rejected_account_is_disconnected_and_cannot_contribute(journal, method):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a" * 32, saved_session())
        original = collector.client
        credentials = vault.read("credentials")
        store.set_target(CHAT, "Common source", "supergroup", True)
        try:
            with pytest.raises(ValueError, match="different Telegram account"):
                await collector.configure(999, "b" * 32, saved_session() if method == "session" else "")
                await collector.send_code("+15550001111")
                await collector.confirm_code("22222" if method == "password" else "12345")
                if method == "password":
                    await collector.confirm_password("synthetic-password")
            rejected = FakeClient.instances[-1]
            assert not rejected.is_connected()
            assert collector.login_client is None
            assert collector.pending_credentials is collector.pending_phone is collector.phone_hash is None
            assert collector.client is original
            assert vault.read("credentials") == credentials
            await collector.start()
            before = store.stats()["total"]
            await emit_registered(rejected)
            assert store.stats()["total"] == before
            await emit_registered(original)
            assert {e["kind"] for e in store.events(message_id=901)} == {
                "message.new", "message.edited", "message.deleted", "reaction.snapshot"}
            assert store.events(kind="message.new")[0]["payload"]["collector_account_id"] == 44
            store.verify(vault.public_key)
        finally:
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_pending_superseded_and_probe_clients_are_not_active_collectors(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        await collector.configure(123, "a" * 32, saved_session())
        superseded = collector.client
        await collector.configure(123, "a" * 32, saved_session())
        await collector.configure(999, "b" * 32)
        pending = collector.login_client
        store.set_target(CHAT, "Common source", "supergroup", True)
        probe = collector.make_client(123, "a" * 32, saved_session())
        await probe.connect()
        try:
            await collector.start()
            assert not superseded.is_connected() and not pending.is_connected()
            assert collector.login_client is None
            before = store.stats()["total"]
            for other in (superseded, pending, probe):
                await emit_registered(other)
            assert store.stats()["total"] == before
            await emit_registered(collector.client)
            assert len(store.events(message_id=901)) == 4
        finally:
            await probe.disconnect()
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_cancelled_identity_lookup_discards_login_candidate(journal):
    class CancelledIdentity(FakeClient):
        async def get_me(self):
            raise asyncio.CancelledError()

    async def run():
        store, vault = journal
        collector = Collector(store, vault, CancelledIdentity)
        with pytest.raises(asyncio.CancelledError):
            await collector.configure(123, "a" * 32, saved_session())
        assert not FakeClient.instances[-1].is_connected()
        assert collector.login_client is None
        assert collector.pending_credentials is None
        assert vault.read("credentials") == {}
        assert not store.events(kind="account.authorized")
    asyncio.run(run())
