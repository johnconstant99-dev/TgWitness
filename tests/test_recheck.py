import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from telethon.errors import ChannelPrivateError
from telethon.tl import types

from tgwitness.collector import Collector
from tests.test_collector import CHAT, FakeClient, saved_session


def message(id, text="Message", edited=None):
    return types.Message(id=id, peer_id=types.PeerChannel(123), date=datetime(2026, 1, 1, tzinfo=timezone.utc),
                         message=text, from_id=types.PeerUser(44), edit_date=edited)


class RecheckClient(FakeClient):
    """Keeps the real StringSession and answers like Telegram from a server-side message table."""
    server = {}
    lost_access = False

    def __init__(self, session, api_id, api_hash, **kwargs):
        super().__init__(session, api_id, api_hash, **kwargs)
        self.session = session
        self.caught_up = 0
        self.during_start = []

    async def catch_up(self):
        self.caught_up += 1

    async def iter_dialogs(self, limit):
        for event in self.during_start:  # updates that arrive while observation is starting
            await self.handlers[0](event)
        self.during_start = []
        async for dialog in super().iter_dialogs(limit):
            yield dialog

    async def get_messages(self, entity, limit=None, ids=None):
        if ids is None:
            if RecheckClient.lost_access:
                raise ChannelPrivateError(request=None)
            return [RecheckClient.server[i] for i in sorted(RecheckClient.server, reverse=True)][:limit]
        return [RecheckClient.server.get(i) for i in ids]

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0, reverse=False):
        for i in [i for i in sorted(RecheckClient.server) if i > min_id][:limit]:
            yield RecheckClient.server[i]


async def observing(store, vault):
    store.set_target(CHAT, "Synthetic", "supergroup", True)
    collector = Collector(store, vault, RecheckClient)
    await collector.configure(123, "a" * 32, saved_session())
    await collector.dialogs()
    collector.running = True
    return collector


def kinds(store, kind):
    return [e for e in store.all_events() if e["kind"] == kind]


def test_update_position_survives_restart_and_turns_on_catch_up(journal):
    store, vault = journal
    store.set_setting("account", {"id": 44, "username": "synthetic"})
    collector = Collector(store, vault, RecheckClient)
    client = collector.make_client(123, "a" * 32, saved_session())
    assert client.options["catch_up"] is True
    # What Telethon writes into the in-memory session about once a minute.
    client.session.set_update_state(0, types.updates.State(
        pts=500, qts=7, date=datetime(2026, 1, 1, tzinfo=timezone.utc), seq=3, unread_count=0))
    client.session.set_update_state(123, types.updates.State(
        pts=18244, qts=0, date=datetime.now(timezone.utc), seq=0, unread_count=0))
    client.session.process_entities([types.InputPeerChannel(123, 777)])
    collector.client = client
    collector.save_update_state()
    saved = vault.read("update_state")
    assert saved["account"] == {"pts": 500, "qts": 7, "seq": 3, "date": 1767225600}
    assert saved["channels"] == [{"id": 123, "pts": 18244, "access_hash": 777}]

    restarted = Collector(store, vault, RecheckClient)
    session = restarted.make_client(123, "a" * 32, saved_session()).session
    states = dict(session.get_update_states())
    assert (states[0].pts, states[0].qts, states[0].seq) == (500, 7, 3) and states[123].pts == 18244
    assert session.get_input_entity(CHAT).access_hash == 777  # Telethon needs it to catch up the channel
    assert restarted.resumed_state_at == saved["saved_at"]

    # A different account's journal never resumes this position.
    store.set_setting("account", {"id": 45, "username": "other"})
    other = Collector(store, vault, RecheckClient).make_client(123, "a" * 32, saved_session())
    assert not dict(other.session.get_update_states())


def test_updates_during_start_are_kept_and_resent_ones_are_not_duplicated(journal):
    async def run():
        store, vault = journal
        store.set_setting("account", {"id": 44, "username": "synthetic"})
        store.set_target(CHAT, "Synthetic", "supergroup", True)
        collector = Collector(store, vault, RecheckClient)
        await collector.configure(123, "a" * 32, saved_session())
        collector.client.during_start.append(NS(chat_id=CHAT, message=message(70, "sent while starting"),
                                                original_update=None))
        await collector.start()
        assert collector.client.caught_up == 1
        started = kinds(store, "observation.started")[0]
        early = kinds(store, "message.new")[0]
        assert early["message_id"] == 70 and early["seq"] > started["seq"]

        resent = types.UpdateNewChannelMessage(message=message(70), pts=0, pts_count=0)
        await collector.on_new(NS(chat_id=CHAT, message=message(70), original_update=resent))
        recovered = types.UpdateNewChannelMessage(message=message(71, "missed"), pts=0, pts_count=0)
        await collector.on_new(NS(chat_id=CHAT, message=message(71, "missed"), original_update=recovered))
        new = kinds(store, "message.new")
        assert [e["message_id"] for e in new] == [70, 71]
        assert new[1]["payload"]["source"] == "update_recovery"

        edited = message(70, "changed", datetime(2026, 1, 2, tzinfo=timezone.utc))
        for _ in range(2):
            await collector.on_edit(NS(chat_id=CHAT, message=edited, original_update=None))
            await collector.on_delete(NS(chat_id=CHAT, deleted_ids=[70], original_update=None))
        assert len(kinds(store, "message.edited")) == 1 and len(kinds(store, "message.deleted")) == 1
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_recheck_recovers_missed_messages_edits_and_silent_removals(journal):
    async def run():
        store, vault = journal
        RecheckClient.lost_access = False
        RecheckClient.server = {i: message(i, "text " + str(i)) for i in range(1, 6)}
        collector = await observing(store, vault)
        for i in range(1, 6):
            await collector.capture_message(message(i, "text " + str(i)), "message.new", CHAT)
        saved_2 = kinds(store, "message.new")[1]
        # While nothing was delivered: #2 removed, #3 edited, #6 and #7 sent.
        del RecheckClient.server[2]
        RecheckClient.server[3] = message(3, "text 3 changed", datetime(2026, 1, 2, tzinfo=timezone.utc))
        RecheckClient.server[6] = message(6, "missed one")
        RecheckClient.server[7] = message(7, "missed two")

        state = await collector.recheck_pass()
        assert (state["recovered"], state["edited"], state["missing"], state["checked"]) == (2, 1, 1, 7)
        recovered = kinds(store, "message.recovered")
        assert [e["message_id"] for e in recovered] == [6, 7] and recovered[0]["actor_id"] == 44
        assert recovered[0]["payload"]["source"] == "recheck"
        edit = kinds(store, "message.edited")[0]
        assert edit["message_id"] == 3 and edit["payload"]["text"] == "text 3 changed"
        missing = kinds(store, "message.missing_on_recheck")[0]
        assert missing["message_id"] == 2
        assert missing["payload"]["last_saved_event"] == {"seq": saved_2["seq"], "hash": saved_2["hash"]}
        assert not kinds(store, "message.deleted")  # a missing message is not a deletion notice

        # A second pass finds nothing new and repeats nothing.
        before = len(store.all_events())
        again = await collector.recheck_pass()
        assert (again["recovered"], again["edited"], again["missing"]) == (0, 0, 0)
        assert [e["kind"] for e in store.all_events()[before:]] == ["recheck.completed"]

        view = {m["message_id"]: m for m in store.chat_messages(CHAT)["messages"]}
        assert view[2]["missing"] and not view[2]["deleted"] and view[2]["text"] == "text 2"
        assert "recheck" in view[6]["origins"] and view[3]["text"] == "text 3 changed"
        assert store.chat_overview()[CHAT]["missing"] == 1
        assert store.chat_authors(CHAT)["authors"][0]["missing"] == 1
    asyncio.run(run())


def test_recheck_does_not_mark_messages_missing_when_access_was_lost(journal):
    async def run():
        store, vault = journal
        RecheckClient.server = {i: message(i) for i in range(1, 13)}
        collector = await observing(store, vault)
        for i in range(1, 13):
            await collector.capture_message(message(i), "message.new", CHAT)
        RecheckClient.server = {}
        RecheckClient.lost_access = True
        state = await collector.recheck_pass()
        assert state["errors"] == 1 and not kinds(store, "message.missing_on_recheck")
        RecheckClient.lost_access = False  # still readable, just emptied: a purge is recorded
        state = await collector.recheck_pass()
        assert state["missing"] == 12 and len(kinds(store, "message.missing_on_recheck")) == 12
    asyncio.run(run())


def test_recheck_after_a_long_stop_fills_the_gap_below_newer_live_messages(journal):
    async def run():
        store, vault = journal
        RecheckClient.lost_access = False
        RecheckClient.server = {i: message(i) for i in range(1, 31)}
        collector = await observing(store, vault)
        for i in range(1, 6):
            await collector.capture_message(message(i), "message.new", CHAT)
        # Observation starts again after a stop; live messages arrive before the first recheck.
        collector.mark_recheck_start()
        for i in (29, 30):
            await collector.capture_message(message(i), "message.new", CHAT)
        param = collector.param
        collector.param = lambda key: 10 if key == "recheck_new_limit" else param(key)
        first = await collector.recheck_pass()
        assert first["recovered"] == 10
        assert kinds(store, "recheck.completed")[-1]["payload"]["chats"][0]["continues_after"] == 15
        assert [t["chat_id"] for t in collector.due_targets()] == [CHAT]  # continues on the next tick
        await collector.recheck_pass()
        last = await collector.recheck_pass()
        assert last["recovered"] == 3 and store.get_setting("recheck_walked") == {str(CHAT): 30}
        assert not collector.due_targets()  # caught up: back to the normal interval
        assert (await collector.recheck_pass())["recovered"] == 0
        assert [e["message_id"] for e in kinds(store, "message.recovered")] == list(range(6, 29))

        # 0 turns recovery off: nothing is fetched and the chat waits for its normal interval.
        RecheckClient.server[31] = message(31)
        collector.param = lambda key: 0 if key == "recheck_new_limit" else param(key)
        store.set_setting("recheck_last", {})
        assert (await collector.recheck_pass())["recovered"] == 0 and not collector.due_targets()
    asyncio.run(run())


def test_recheck_starts_from_the_newest_message_instead_of_all_history(journal):
    async def run():
        store, vault = journal
        RecheckClient.lost_access = False
        RecheckClient.server = {i: message(i) for i in range(1, 51)}
        collector = await observing(store, vault)
        await collector.recheck_pass()
        assert store.get_setting("recheck_floor") == {str(CHAT): 50} and not kinds(store, "message.recovered")
        RecheckClient.server[51] = message(51, "after observation began")
        await collector.recheck_pass()
        assert [e["message_id"] for e in kinds(store, "message.recovered")] == [51]
    asyncio.run(run())
