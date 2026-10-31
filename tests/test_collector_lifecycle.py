import asyncio
from types import SimpleNamespace as NS

from telethon.tl import types

from test_collector import CHAT, FakeClient, saved_session, telegram_message
from tgwitness.collector import Collector


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
