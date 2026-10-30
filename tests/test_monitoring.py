import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from fastapi.testclient import TestClient
from telethon.tl import types

from tgwitness.app import create_app
from tgwitness.collector import Collector
from tgwitness.monitoring import Monitoring
from tgwitness.verify import verify_events
from test_collector import CHAT, FakeClient, telegram_message, saved_session


async def emit(collector):
    await collector.on_new(NS(chat_id=CHAT, message=telegram_message()))
    await collector.on_edit(NS(chat_id=CHAT, message=telegram_message(text="Edited")))
    await collector.on_delete(NS(chat_id=CHAT, deleted_ids=[9], original_update={}))
    await collector.on_delete(NS(chat_id=None, deleted_ids=[9], original_update={}))
    await collector.on_raw(types.UpdateMessageReactions(peer=types.PeerChannel(123), msg_id=9,
        reactions=types.MessageReactions(results=[types.ReactionCount(reaction=types.ReactionEmoji("+"), count=1)])))
    await collector.on_raw(types.UpdateChannelParticipant(channel_id=123,
        date=datetime.now(timezone.utc), actor_id=44, user_id=55, qts=1))
    message = types.MessageService(id=70, peer_id=types.PeerChannel(123),
        date=datetime.now(timezone.utc), from_id=types.PeerUser(44), action=types.MessageActionChatAddUser([55]))
    await collector.on_raw(types.UpdateNewChannelMessage(message=message, pts=1, pts_count=1))


def test_policy_changes_real_handlers_but_keeps_coverage_and_explicit_history(journal):
    async def run():
        store, vault = journal
        collector = Collector(store, vault, FakeClient)
        store.set_target(CHAT, "Synthetic source", "supergroup", True)
        collector.running = True
        store.set_setting("monitoring", {name:False for name in Monitoring.model_fields})
        await emit(collector)
        assert store.stats()["total"] == 0
        await collector.on_raw(types.UpdateChannelTooLong(channel_id=123, pts=4))
        assert len(store.events(kind="coverage.gap")) == 1

        store.set_setting("monitoring", Monitoring(reactions=False, membership=False).model_dump())
        await emit(collector)
        assert len(store.events(kind="message.new")) == 1
        assert len(store.events(kind="message.edited")) == 1
        assert len(store.events(kind="message.deleted")) == 1
        assert len(store.events(kind="deletion.unscoped")) == 1
        assert not store.events(kind="membership") and not store.events(kind="reaction.snapshot")

        store.set_setting("monitoring", Monitoring(messages=False, edits=False, deletions=False).model_dump())
        await emit(collector)
        assert len(store.events(kind="reaction.snapshot")) == 1
        assert len(store.events(kind="membership.service")) == 1
        assert len(store.events(kind="membership.update")) == 1
        assert len(store.events(kind="message.edited")) == 1
        assert len(store.events(kind="message.deleted")) == 1

        collector.running = False
        await collector.configure(123, "a"*32, saved_session())
        store.set_setting("monitoring", {name:False for name in Monitoring.model_fields})
        await collector.snapshot(CHAT, 2)
        assert len(store.events(kind="message.snapshot")) == 2
        verify_events(store.all_events(), vault.public_key)
        await collector.stop()
    asyncio.run(run())


def test_policy_is_authenticated_audited_profile_specific_and_persistent(tmp_path):
    root = tmp_path / "live"
    app = create_app(root, client_factory=FakeClient)
    selected = Monitoring(reactions=False, membership=False).model_dump()
    with TestClient(app) as c:
        assert c.post("/api/monitoring", json=selected).status_code == 401
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        assert c.get("/api/status").json()["monitoring"] == Monitoring().model_dump()
        assert c.post("/api/monitoring", json={"reactions":"false"}).status_code == 422
        assert c.post("/api/monitoring", json={"unknown":True}).status_code == 422
        assert c.post("/api/monitoring", json=selected).json() == selected
        records = app.state.store.events(kind="monitoring.changed")
        assert len(records) == 1
        assert records[0]["payload"]["before"] == Monitoring().model_dump()
        assert records[0]["payload"]["after"] == selected
        c.post("/api/monitoring", json=selected)
        assert len(app.state.store.events(kind="monitoring.changed")) == 1
        profile = c.post("/api/profiles", json={"label":"Independent"}).json()["id"]
        assert c.get(f"/profiles/{profile}/api/status").json()["monitoring"] == Monitoring().model_dump()
        app.state.store.verify(app.state.vault.public_key)
    with TestClient(create_app(root, client_factory=FakeClient)) as c:
        c.headers["Authorization"] = "Bearer " + (root / "panel-token.txt").read_text()
        assert c.get("/api/status").json()["monitoring"] == selected
        assert c.get("/api/run-receipt").json()["statement"]["run"]["monitoring"] == selected


def test_local_demo_entry_is_scoped_and_never_discloses_master_token(tmp_path, monkeypatch):
    master = "synthetic-master-panel-token-123456789"
    monkeypatch.setenv("TGWITNESS_TOKEN", master)
    app = create_app(tmp_path / "demo", demo=True)
    with TestClient(app, base_url="http://127.0.0.1:8787", client=("127.0.0.1",50123)) as c:
        token = c.get("/api/demo-access").json()["token"]
        assert token != master and master not in c.get("/api/demo-access").text
        assert c.get("/api/status").status_code == 401
        c.headers["Authorization"] = "Bearer " + token
        assert c.get("/api/status").json()["demo"]
        assert c.post("/api/monitoring", json=Monitoring().model_dump()).status_code == 409
        assert c.post("/api/auth/configure", json={"api_id":123,"api_hash":"a"*32}).status_code == 409
        for headers in ({"Host":"attacker.example"},{"Origin":"https://attacker.example"},
                        {"Sec-Fetch-Site":"cross-site"},{"X-Forwarded-For":"127.0.0.1"}):
            assert c.get("/api/demo-access",headers=headers).json() == {"available":False}
            assert c.get("/api/status",headers=headers).status_code == 401
    with TestClient(create_app(tmp_path / "live"),base_url="http://127.0.0.1",client=("127.0.0.1",50123)) as c:
        assert c.get("/api/demo-access").json() == {"available":False}
        assert c.get("/api/status",headers={"Authorization":"Bearer "+token}).status_code == 401
    with TestClient(create_app(tmp_path / "demo",demo=True),base_url="http://127.0.0.1",client=("192.0.2.1",50123)) as c:
        assert c.get("/api/demo-access").json() == {"available":False}
    with TestClient(create_app(tmp_path / "demo"),base_url="http://127.0.0.1",client=("127.0.0.1",50123)) as c:
        assert c.get("/api/demo-access").json() == {"available":False}
