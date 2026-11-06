import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import functions, types

from tgwitness import alerts, health, i18n, telegram_client
from tgwitness.collector import UPDATES_CHECK_SECONDS, UPDATES_GRACE_SECONDS, Collector
from tgwitness.security import Vault
from tgwitness.store import Store

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


class Client:
    def __init__(self):
        self.pts, self.calls = 10, 0

    def is_connected(self):
        return True

    async def __call__(self, request):
        assert isinstance(request, functions.updates.GetStateRequest)
        self.calls += 1
        return types.updates.State(pts=self.pts, qts=0, date=NOW, seq=1, unread_count=0)


def later(collector, seconds):
    probe = collector.updates_probe
    probe["checked_at"] -= seconds
    if probe["suspect_at"] is not None:
        probe["suspect_at"] -= seconds


def kinds(store, reason):
    return [e for e in store.events(limit=50) if e["payload"].get("reason") == reason]


async def own_updates(results):
    client = object.__new__(telegram_client.WitnessClient)
    noted = []
    client.updates_listener = lambda: noted.append(True)
    original = telegram_client.TelegramClient._call
    try:
        for result, counted in results:
            async def answer(self, sender, request, ordered=False, flood_sleep_threshold=None, result=result):
                return result
            telegram_client.TelegramClient._call = answer
            before = len(noted)
            await client._call(None, functions.updates.GetStateRequest())
            assert (len(noted) > before) == counted, (type(result).__name__, counted)
    finally:
        telegram_client.TelegramClient._call = original


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        collector = Collector(store, vault)
        client = collector.client = Client()
        collector.running = True

        await collector.watch_updates()
        assert client.calls == 1 and collector.updates_probe["pts"] == 10
        await collector.watch_updates()
        assert client.calls == 1, "updates.getState is not repeated before the check interval"

        later(collector, UPDATES_CHECK_SECONDS)
        store.set_setting("rpc_backoff_until", 10**10)
        await collector.watch_updates()
        assert client.calls == 1, "No probe during a Telegram pause"
        store.set_setting("rpc_backoff_until", 0)

        client.pts = 12
        collector.updates_arrived()
        await collector.watch_updates()
        assert client.calls == 2 and collector.updates_probe["pts"] == 12, "Received updates move the baseline"

        later(collector, UPDATES_CHECK_SECONDS)
        await collector.watch_updates()
        assert collector.updates_probe["suspect_at"] is None, "A quiet account is not a fault"

        client.pts = 13
        later(collector, UPDATES_CHECK_SECONDS)
        await collector.watch_updates()
        assert collector.updates_probe["suspect_at"] is not None
        collector.updates_arrived()
        later(collector, UPDATES_GRACE_SECONDS)
        await collector.watch_updates()
        assert collector.updates_diverted is None, "An update still in flight within the grace period clears it"

        later(collector, UPDATES_CHECK_SECONDS)
        await collector.watch_updates()
        client.pts = 15
        later(collector, UPDATES_CHECK_SECONDS)
        await collector.watch_updates()
        await collector.watch_updates()
        assert collector.updates_diverted is None, "No alarm before the grace period ends"
        later(collector, UPDATES_GRACE_SECONDS)
        await collector.watch_updates()
        diverted = collector.updates_diverted
        assert diverted, "Counter grew and no update arrived: updates go to another session"
        gap = kinds(store, "updates_diverted")
        assert len(gap) == 1 and gap[0]["kind"] == "coverage.gap"
        assert (gap[0]["payload"]["telegram_pts_before"], gap[0]["payload"]["telegram_pts"]) == (13, 15)
        later(collector, UPDATES_GRACE_SECONDS)
        await collector.watch_updates()
        assert len(kinds(store, "updates_diverted")) == 1, "The alarm is recorded once"

        status = {"running": True, "connected": True, "has_session": True,
                  "last_heartbeat": NOW.isoformat(), "updates_diverted": diverted}
        part = health.intake(status, 60, NOW)
        assert (part["state"], part["reason"]) == ("failed", "updates_diverted"), part
        assert part["diverted_since"] == diverted["since"]
        assert health.collector(status, {"download_media": False}, 60, 1, NOW)["state"] == "failed"
        assert collector.status()["updates_diverted"] == diverted
        line = alerts.problem_line({**gap[0], "payload": gap[0]["payload"]}, {}, {})
        assert line.startswith("Updates are going to another session"), line
        assert line != alerts.problem_line({**gap[0], "payload": gap[0]["payload"]}, {}, i18n.words("ru"))

        collector.updates_arrived()
        await collector.watch_updates()
        assert collector.updates_diverted is None
        restored = kinds(store, "updates_resumed")
        assert len(restored) == 1 and restored[0]["kind"] == "connection.restored"
        assert collector.status()["updates_diverted"] is None

        collector.updates_diverted = diverted
        collector.running = False
        assert collector.status()["updates_diverted"] is None, "A paused workspace shows no live alarm"

        await own_updates([
            (types.UpdateShortSentMessage(id=1, pts=16, pts_count=1, date=NOW), True),
            (types.messages.AffectedMessages(pts=17, pts_count=1), True),
            (types.Updates(updates=[], users=[], chats=[], date=NOW, seq=0), True),
            (types.updates.State(pts=17, qts=0, date=NOW, seq=1, unread_count=0), False),
            (types.messages.ChannelMessages(pts=5, count=0, messages=[], topics=[], chats=[], users=[]), False)])
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="updates-diverted-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Telegram's update counter is compared every 2 minutes: growth without arriving updates raises "
          "'updates go to another session' once, in-flight updates and own actions do not.")
