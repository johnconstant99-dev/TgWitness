import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from telethon.tl import types

from tgwitness import people
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store
from tools.check_prepared_export_access import grant_session
from tools.check_session_reservations import workspace

NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
CHAT = -1000000000042


@pytest.fixture
def ws(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.set_target(CHAT, "Observed chat", "supergroup", True)
    store.set_setting("monitoring", {"profiles": True, "presence": True})
    collector = Collector(store, vault)
    collector.running = True
    try:
        yield store, vault, collector
    finally:
        store.close()


def message(store, mid=1, uid=91, sent=None, chat=CHAT, name="Original", username="original", partial=False, kind="message.new"):
    return store.append(kind, {"sender_id": uid, "text": "Synthetic message", "sent_at": (sent or NOW).isoformat(),
        "source": "live_update" if kind == "message.new" else "history_snapshot",
        "sender_observation": {"id": uid, "display_name": name, "username": username, "partial": partial}}, chat, mid, uid)


def raw(collector, update):
    asyncio.run(collector.on_raw(update))


def detail(store, uid=91, **kwargs):
    return people.timeline(store, CHAT, uid, now=NOW.timestamp(), **kwargs)


def test_received_names_statuses_are_scoped_and_deduplicated(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUserName(91, "Renamed", "User", [types.Username("renamed", active=True)]))
    online = types.UpdateUserStatus(91, types.UserStatusOnline(NOW + timedelta(minutes=1)))
    raw(collector, online)
    count = len(store.all_events())
    raw(collector, online)
    raw(collector, types.UpdateUserStatus(999, types.UserStatusOnline(NOW + timedelta(minutes=1))))
    assert len(store.all_events()) == count
    result = detail(store)
    assert result["person"]["profile"]["display_name"] == "Renamed User"
    assert result["person"]["profile"]["username"] == "renamed"
    assert result["person"]["status"]["state"] == "online"
    assert [e["category"] for e in result["events"]] == ["status", "profile", "message"]
    assert store.verify(collector.vault.public_key)["events"] == count


def test_disabled_categories_and_stopped_collector_do_not_capture(ws):
    store, _, collector = ws
    message(store)
    store.set_setting("monitoring", {"profiles": False, "presence": False})
    count = len(store.all_events())
    raw(collector, types.UpdateUserName(91, "Not captured", "", []))
    raw(collector, types.UpdateUserStatus(91, types.UserStatusRecently()))
    assert len(store.all_events()) == count
    collector.running = False
    store.set_setting("monitoring", {"presence": True})
    raw(collector, types.UpdateUserStatus(91, types.UserStatusRecently()))
    assert len(store.all_events()) == count


def test_expiry_is_unknown_not_a_fabricated_offline_event(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUserStatus(91, types.UserStatusOnline(NOW - timedelta(seconds=1))))
    value = detail(store)
    assert value["person"]["status"]["state"] == "unknown"
    assert value["person"]["status"]["last_observed_state"] == "online"
    assert value["events"][0]["data"]["state"] == "online"
    raw(collector, types.UpdateUserStatus(91, types.UserStatusOffline(NOW - timedelta(minutes=2))))
    assert detail(store)["person"]["status"]["was_online"] == (NOW - timedelta(minutes=2)).isoformat()


@pytest.mark.parametrize("status,expected", [(types.UserStatusRecently(), "recently"),
    (types.UserStatusLastWeek(), "last_week"), (types.UserStatusLastMonth(), "last_month"), (types.UserStatusEmpty(), "unknown")])
def test_approximate_status_never_invents_a_time(ws, status, expected):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUserStatus(91, status))
    value = detail(store)["person"]["status"]
    assert value["state"] == expected and "was_online" not in value


def test_minimal_or_cached_profiles_do_not_undo_delivered_names(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUserName(91, "Fresh", "", [types.Username("fresh", active=True)]))
    message(store, 2, name="Original", username="original", kind="message.snapshot")
    assert detail(store)["person"]["profile"]["display_name"] == "Fresh"
    message(store, 3, name="", username=None, partial=True)
    assert detail(store)["person"]["profile"]["username"] == "fresh"
    raw(collector, types.UpdateUserName(91, "Fresh", "", []))
    assert detail(store)["person"]["profile"]["username"] is None


def test_history_and_duplicate_edits_do_not_create_new_activity(ws):
    store, _, _ = ws
    message(store, 1, sent=NOW - timedelta(days=30))
    message(store, 2, sent=NOW - timedelta(days=10), kind="message.snapshot")
    message(store, 2, sent=NOW - timedelta(days=10), kind="message.edited")
    message(store, 1, sent=NOW - timedelta(days=30), kind="message.snapshot")
    result = detail(store)
    assert result["person"]["messages"] == 2
    assert result["person"]["silence_days"] == 10
    assert result["person"]["activity"] == "quiet"
    assert result["last_message_gap_days"] == 20
    assert result["coverage"] == "unknown"
    assert people.listing(store, CHAT, mode="quiet", now=NOW.timestamp())["total"] == 1


def test_membership_is_separate_from_silence_and_lists(ws):
    store, _, collector = ws
    joined = types.UpdateChannelParticipant(42, NOW, 8, 91, 1, new_participant=types.ChannelParticipant(91, NOW))
    raw(collector, joined)
    result = detail(store)
    assert result["person"]["membership"]["state"] == "joined"
    assert result["person"]["activity"] == "never_posted"
    raw(collector, types.UpdateChannelParticipant(42, NOW, 91, 91, 2, prev_participant=joined.new_participant))
    assert detail(store)["person"]["membership"]["state"] == "left"
    raw(collector, joined)
    raw(collector, types.UpdateChannelParticipant(42, NOW, 8, 91, 3, prev_participant=joined.new_participant))
    assert detail(store)["person"]["membership"]["state"] == "removed"
    assert detail(store)["events"][0]["data"]["actor_id"] == 8
    assert people.listing(store, CHAT, mode="departed", now=NOW.timestamp())["total"] == 1


def test_service_join_and_leave_tracks_subject_not_only_sender(ws):
    store, _, _ = ws
    store.append("membership.service", {"action": {"_": "MessageActionChatAddUser", "users": [91, 92]}}, CHAT, 1, 8)
    assert people.listing(store, CHAT, now=NOW.timestamp())["total"] == 2
    store.append("membership.service", {"action": {"_": "MessageActionChatDeleteUser", "user_id": 92}}, CHAT, 2, 92)
    assert detail(store, 92)["person"]["membership"]["state"] == "left"


def test_explicit_deleted_flag_and_event_driven_refresh(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUser(91))
    raw(collector, types.UpdateUser(91))
    assert store.db.execute("SELECT count(*) FROM people_refresh_jobs").fetchone()[0] == 1
    collector.client = type("Client", (), {"is_connected": lambda _: True})()
    collector.client.get_entity = AsyncMock(return_value=types.User(91, deleted=True))
    asyncio.run(people.refresh_one(collector))
    collector.client.get_entity.assert_awaited_once_with(91)
    assert detail(store)["person"]["profile"]["flags"]["deleted"] is True
    assert people.listing(store, CHAT, mode="deleted")["total"] == 1
    assert not store.db.execute("SELECT 1 FROM people_refresh_jobs").fetchone()


def test_unavailable_profile_does_not_mean_deleted_and_wait_is_respected(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUser(91))
    collector.client = type("Client", (), {"is_connected": lambda _: True})()
    collector.client.get_entity = AsyncMock(side_effect=ValueError("Unavailable"))
    store.set_setting("rpc_backoff_until", 10**12)
    asyncio.run(people.refresh_one(collector))
    collector.client.get_entity.assert_not_called()
    store.set_setting("rpc_backoff_until", 0)
    asyncio.run(people.refresh_one(collector))
    assert not detail(store)["person"]["profile"].get("flags", {}).get("deleted")
    assert detail(store)["events"][0]["category"] == "profile_unavailable"
    asyncio.run(people.refresh_one(collector))
    assert collector.client.get_entity.await_count == 1


def test_restart_and_index_rebuild_preserve_history_and_completed_refresh(ws):
    store, vault, collector = ws
    message(store)
    raw(collector, types.UpdateUser(91))
    job = store.db.execute("SELECT * FROM people_refresh_jobs").fetchone()
    people.complete_refresh(store, 91, job["requested_seq"], "test_completed")
    raw(collector, types.UpdateUserName(91, "Persisted", "", []))
    expected = detail(store)
    store.close()
    reopened = Store(store.root)
    reopened.bind(vault)
    try:
        assert detail(reopened) == expected
        reopened.db.execute("DROP TABLE people_observations")
        reopened.db.commit()
    finally:
        reopened.close()
    repaired = Store(store.root)
    repaired.bind(vault)
    try:
        assert detail(repaired) == expected
        assert not repaired.db.execute("SELECT 1 FROM people_refresh_jobs").fetchone()
        repaired.verify(vault.public_key)
    finally:
        repaired.close()


def test_coverage_marks_collection_gaps(ws):
    store, _, _ = ws
    message(store, sent=NOW - timedelta(days=10))
    with patch("tgwitness.store.utcnow", return_value=(NOW - timedelta(days=1)).isoformat()):
        store.append("coverage.gap", {"reason": "disconnected"})
    assert detail(store)["coverage"] == "interrupted"


def test_timeline_pagination_has_no_duplicates(ws):
    store, _, _ = ws
    for mid in range(1, 7):
        message(store, mid)
    first = detail(store, limit=3)
    second = detail(store, limit=3, before=first["next_before"])
    assert len(first["events"]) == len(second["events"]) == 3
    assert not ({e["event_seq"] for e in first["events"]} & {e["event_seq"] for e in second["events"]})
    assert second["next_before"] is None


def test_api_chat_access_and_validation():
    async def run():
        async with workspace() as (app, client):
            store = app.state.store
            message(store)
            message(store, chat=CHAT-1, name="Hidden identity", uid=92)
            _, scoped = grant_session(app, {'default': [CHAT]}, ['view'])
            assert (await client.get(f'/api/chats/{CHAT}/people', headers=scoped)).status_code == 200
            response = await client.get(f'/api/chats/{CHAT}/people/91', headers=scoped)
            assert response.status_code == 200 and 'Hidden identity' not in response.text
            assert (await client.get(f'/api/chats/{CHAT-1}/people', headers=scoped)).status_code == 403
            assert (await client.get(f'/api/chats/{CHAT-1}/people/92', headers=scoped)).status_code == 403
            assert (await client.get(f'/api/chats/{CHAT}/people/92', headers=scoped)).status_code == 404
            assert (await client.get(f'/api/chats/{CHAT}/people?limit=9999', headers=scoped)).status_code == 422
            assert (await client.get(f'/api/chats/{CHAT}/people?quiet_days=0', headers=scoped)).status_code == 422
            assert (await client.get(f'/api/chats/{CHAT}/people/{2**64}', headers=scoped)).status_code == 422
            assert (await client.get(f'/api/chats/{CHAT}/people/91?before={2**64}', headers=scoped)).status_code == 422
    asyncio.run(run())


def test_edit_without_original_date_is_not_new_activity(ws):
    store, _, _ = ws
    store.append('message.edited', {'sender_id': 91, 'text': 'Edited'}, CHAT, 1, 91, source_at=NOW.isoformat())
    person = detail(store)['person']
    assert person['messages'] == 1 and person['last_message_at'] is None
    assert person['activity'] == 'unknown'


def test_cached_profile_is_not_a_reported_name_change(ws):
    store, _, collector = ws
    message(store)
    raw(collector, types.UpdateUserName(91, 'New name', '', []))
    message(store, 2, name='Original')
    assert detail(store)['events'][0]['data']['profile_changes'] == {}


def test_api_rechecks_revoked_access_after_read():
    async def run():
        async with workspace() as (app, client):
            message(app.state.store)
            grant, scoped = grant_session(app, {'default': [CHAT]}, ['view'])
            original = people.listing

            def revoked_read(*args, **kwargs):
                result = original(*args, **kwargs)
                app.state.access.revoke(grant['id'])
                return result

            with patch('tgwitness.people.listing', revoked_read):
                response = await client.get(f'/api/chats/{CHAT}/people', headers=scoped)
            assert response.status_code == 403
            assert 'Original' not in response.text
    asyncio.run(run())


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
