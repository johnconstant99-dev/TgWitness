import asyncio
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from telethon.errors import FloodWaitError
from telethon.tl import functions, types

from tgwitness import interactions
from tgwitness.security import Vault
from tgwitness.store import Store
from tools.browser_fixtures import SHOP_BOT, InteractionClient, saved_session
from tools.check_browser import RunningApp

ACCOUNTS, CHANNELS, WHEN = 10, 5, datetime(2026, 1, 1, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def time(self):
        return self.now


class Telegram:
    def __init__(self, clock):
        self.clock, self.joins, self.floods, self.entities = clock, [], 0, {}

    async def get_entity(self, username):
        return self.entities.setdefault(username, types.Channel(
            id=7000 + len(self.entities), title="Synthetic " + username, photo=types.ChatPhotoEmpty(), date=WHEN,
            access_hash=1, username=username))

    async def __call__(self, request):
        if isinstance(request, functions.channels.GetFullChannelRequest):
            raise NotImplementedError
        assert isinstance(request, functions.channels.JoinChannelRequest)
        if sum(1 for at in self.joins if at > self.clock.now - 60) >= 3:
            self.floods += 1
            raise FloodWaitError(request, capture=300)
        self.joins.append(self.clock.now)
        return SimpleNamespace(chats=[request.channel])


def workspace(root, number, clock, origin="created"):
    root.mkdir(parents=True)
    store, vault = Store(root), Vault(root)
    store.bind(vault)
    store.set_setting("account", {"id": 5000 + number, "key_origin": origin})
    return SimpleNamespace(store=store, vault=vault, running=False, restore=AsyncMock(), client=Telegram(clock),
                           dialog_cache={}, selected=lambda chat: chat in {t["chat_id"] for t in store.targets()},
                           request_baseline=lambda chat_ids: None)


async def join(collector, number, queued, observe=True):
    preview = await interactions.preview(collector, interactions.Preview(link="@pace%dchan%d" % (
        collector.store.get_setting("account")["id"], number)))
    body = interactions.Action(request_id="pace-join-%d-%02d-synthetic" % (collector.store.get_setting("account")["id"],
                                                                         number),
                               action="open", preview_id=preview["preview_id"], observe=observe)
    return await interactions.execute(collector, body, lambda run_at, item: queued.append((run_at, collector, item)))


def kinds(store, kind):
    return [event["payload"] for event in store.all_events() if event["kind"] == kind]


async def mass_join(root, clock):
    collectors = [workspace(root / str(number), number, clock) for number in range(ACCOUNTS)]
    try:
        queued, statuses = [], []
        for collector in collectors:
            for number in range(CHANNELS):
                statuses.append((await join(collector, number, queued))["status"])
        assert statuses == (["succeeded"] + ["queued"] * (CHANNELS - 1)) * ACCOUNTS, statuses
        assert len(queued) == ACCOUNTS * (CHANNELS - 1)
        assert interactions.pace_status(collectors[0].store) == {"read_only": False, "queued": CHANNELS - 1,
                                                                 "next_at": clock.now + 180}
        for run_at, collector, body in sorted(queued, key=lambda item: item[0]):
            clock.now = run_at
            result = await interactions.run_queued(collector, body)
            assert result["status"] == "succeeded", result
        for collector in collectors:
            joins = collector.client.joins
            assert collector.client.floods == 0 and len(joins) == CHANNELS
            assert all(later - earlier >= 180 for earlier, later in zip(joins, joins[1:])), joins
            results = kinds(collector.store, "interaction.result")
            assert [r["status"] for r in results] == ["succeeded"] * CHANNELS
            assert sum("queued_until" in r for r in kinds(collector.store, "interaction.requested")) == CHANNELS - 1
            assert len(collector.store.targets()) == CHANNELS
            assert interactions.pace_status(collector.store)["queued"] == 0
            collector.store.verify(collector.vault.public_key)
        return max(collector.client.joins[-1] - collector.client.joins[0] for collector in collectors)
    finally:
        for collector in collectors:
            collector.store.close()


async def burst_without_pace(clock):
    client = Telegram(clock)
    for number in range(CHANNELS):
        try:
            await client(functions.channels.JoinChannelRequest(await client.get_entity("burst%d" % number)))
        except FloodWaitError:
            pass
    assert client.floods == CHANNELS - 3, client.floods


def hourly_limit(root, clock):
    root.mkdir(parents=True)
    store = Store(root)
    try:
        store.set_setting("parameters", {"action_join_seconds": 0, "action_joins_per_hour": 3})
        start = clock.now
        slots = [interactions.reserve(store, "join") - start for _ in range(5)]
        assert slots == [0, 0, 0, 3600, 3600], slots
        messages = [interactions.reserve(store, "message") - start for _ in range(3)]
        assert messages == [0, 10, 20], messages
        clock.now += 7200
        assert interactions.reserve(store, "bot") == clock.now
    finally:
        store.close()


async def read_only(root, clock):
    imported = workspace(root / "imported", 1, clock, origin="imported")
    created = workspace(root / "created", 2, clock)
    try:
        assert interactions.read_only(imported.store) and not interactions.read_only(created.store)
        try:
            await join(imported, 0, [])
            raise AssertionError("A read-only account joined a chat.")
        except interactions.AccountRestricted as exc:
            assert str(exc) == interactions.READ_ONLY
        assert not imported.client.joins and not kinds(imported.store, "interaction.requested")
        assert interactions.set_read_only(imported.store, False)["read_only"] is False
        queued = []
        assert (await join(imported, 1, queued))["status"] == "succeeded"
        assert (await join(imported, 2, queued))["status"] == "queued"
        assert (await join(imported, 3, queued, observe=False))["status"] == "queued"
        assert interactions.pace_status(imported.store)["queued"] == 2
        assert interactions.set_read_only(imported.store, True) == {"read_only": True, "queued": 0, "next_at": None}
        for run_at, collector, body in queued:
            clock.now = run_at
            assert await interactions.run_queued(collector, body) is None
        results = kinds(imported.store, "interaction.result")
        assert [r["status"] for r in results] == ["succeeded", "rejected", "rejected"]
        assert results[1]["error"] == results[2]["error"] == interactions.READ_ONLY_STOP
        assert len(imported.client.joins) == 1
        assert [e["enabled"] for e in kinds(imported.store, "account.read_only")] == [False, True]
        imported.store.verify(imported.vault.public_key)
    finally:
        imported.store.close()
        created.store.close()


def wait_for(server, headers, request_id, deadline=30):
    stop = time.monotonic() + deadline
    while time.monotonic() < stop:
        state = requests.get(server.url + "/api/interactions/" + request_id, headers=headers, timeout=10).json()
        if state["status"] != "queued":
            return state
        time.sleep(.2)
    raise AssertionError("The queued action did not run: " + request_id)


def panel(root):
    def send(server, headers, request_id):
        return requests.post(server.url + "/api/interactions", headers=headers, timeout=30, json={
            "request_id": request_id, "action": "send", "chat_id": SHOP_BOT, "text": "Synthetic paced message"})

    with RunningApp(root, client_factory=InteractionClient) as server:
        headers = {"Authorization": "Bearer " + server.app.state.vault.token}
        requests.post(server.url + "/api/auth/configure", headers=headers, timeout=10,
                      json={"api_id": 123, "api_hash": "a" * 32, "session": saved_session()}).raise_for_status()
        store = server.app.state.store
        store.set_target(SHOP_BOT, "Synthetic shop bot", "bot", True)
        store.set_setting("parameters", {"action_message_seconds": 2})
        refused = send(server, headers, "panel-read-only-refusal")
        assert refused.status_code == 409 and refused.json()["detail"] == interactions.READ_ONLY, refused.text
        status = requests.get(server.url + "/api/status", headers=headers, timeout=10).json()
        assert status["actions"] == {"read_only": True, "queued": 0, "next_at": None}
        changed = requests.post(server.url + "/api/interactions/read-only", headers=headers, timeout=10,
                                json={"enabled": False})
        assert changed.ok and changed.json()["read_only"] is False
        assert send(server, headers, "panel-paced-message-one").json()["status"] == "succeeded"
        second = send(server, headers, "panel-paced-message-two").json()
        assert second["status"] == "queued" and second["run_at"] > time.time(), second
        assert send(server, headers, "panel-paced-message-two").json()["status"] == "queued"
        done = wait_for(server, headers, "panel-paced-message-two")
        assert done["status"] == "succeeded" and time.time() >= second["run_at"], done
        assert [item[1] for item in server.app.state.collector.client.sent] == ["Synthetic paced message"] * 2
        store.set_setting("parameters", {"action_message_seconds": 3600})
        assert send(server, headers, "panel-paced-message-three").json()["status"] == "queued"
        requests.post(server.url + "/api/interactions/read-only", headers=headers, timeout=10,
                      json={"enabled": True}).raise_for_status()
        stopped = wait_for(server, headers, "panel-paced-message-three")
        assert stopped["status"] == "rejected" and stopped["error"] == interactions.READ_ONLY_STOP, stopped
        requests.post(server.url + "/api/interactions/read-only", headers=headers, timeout=10,
                      json={"enabled": False}).raise_for_status()
        assert send(server, headers, "panel-paced-message-four").json()["status"] == "queued"
        assert len(server.app.state.collector.client.sent) == 2
    with RunningApp(root, client_factory=InteractionClient) as server:
        headers = {"Authorization": "Bearer " + server.app.state.vault.token}
        restarted = wait_for(server, headers, "panel-paced-message-four", deadline=5)
        assert restarted["status"] == "rejected" and restarted["error"] == interactions.RESTART_STOP, restarted
        status = requests.get(server.url + "/api/status", headers=headers, timeout=10).json()
        assert status["actions"]["queued"] == 0 and status["actions"]["read_only"] is False
        assert requests.get(server.url + "/api/interactions/unknown-request-id-0000", headers=headers,
                            timeout=10).status_code == 404
        server.app.state.store.verify(server.app.state.vault.public_key)


def main():
    clock = Clock()
    with tempfile.TemporaryDirectory(prefix="action-pace-") as temporary, \
            patch.object(interactions, "time", SimpleNamespace(time=clock.time, strftime=time.strftime,
                                                               gmtime=time.gmtime)):
        root = Path(temporary)
        span = asyncio.run(mass_join(root / "mass", clock))
        asyncio.run(burst_without_pace(clock))
        hourly_limit(root / "hourly", clock)
        asyncio.run(read_only(root / "read-only", clock))
    with tempfile.TemporaryDirectory(prefix="action-pace-panel-") as temporary:
        panel(Path(temporary))
    print("%d accounts x %d joins spread over %d s each without FloodWait (the same burst trips it on the 4th join); "
          "hourly caps, server read-only by default for imported sessions, queue polling, cancellation by Read-only "
          "and restart passed." % (ACCOUNTS, CHANNELS, span))


if __name__ == "__main__":
    main()
