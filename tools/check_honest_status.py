import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.errors import FloodWaitError
from telethon.tl import functions, types

from tgwitness import health, telegram_client
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
CAPTURE = {"download_media": True}


def live(**extra):
    return {"has_session": True, "running": True, "connected": True, "phase": "observing",
            "last_heartbeat": NOW.isoformat(), **extra}


class Pages:
    def __init__(self, record, count):
        self.record, self.count, self.seen = record, count, []

    def iter_messages(self, entity, offset_id=0, min_id=0, **options):
        async def pages():
            for number in range(self.count, 0, -1):
                if (self.count - number) % 100 == 0:
                    await asyncio.sleep(0.2)
                self.seen.append(self.record.get("eta_seconds"))
                yield types.Message(id=number, peer_id=types.PeerUser(7), date=NOW, message="text")
        return pages()


async def floodwait_method():
    client = object.__new__(telegram_client.WitnessClient)
    saved = []
    client.rpc_backoff_setter = lambda until, method: saved.append(method)
    original = telegram_client.TelegramClient._call

    async def refuse(self, sender, request, ordered=False, flood_sleep_threshold=None):
        raise FloodWaitError(request=request, capture=30)
    telegram_client.TelegramClient._call = refuse
    try:
        request = functions.InvokeWithTakeoutRequest(1, functions.messages.GetHistoryRequest(
            types.InputPeerSelf(), 0, None, 0, 100, 0, 0, 0))
        try:
            await client._call(None, request)
        except FloodWaitError:
            pass
        else:
            raise AssertionError("FloodWait must reach the caller")
    finally:
        telegram_client.TelegramClient._call = original
    assert saved == ["messages.getHistory"], saved
    assert telegram_client.method_name(functions.upload.GetFileRequest(
        types.InputDocumentFileLocation(1, 2, b"r", ""), 0, 4096)) == "upload.getFile"


async def check(root):
    sources_down = live(source_status={"-1001": {"state": "access_unconfirmed"}}, storage_low=True)
    summary = health.collector(sources_down, CAPTURE, 60, 1, NOW)
    assert summary["sources"]["state"] == "failed" and summary["media"]["state"] == "failed", summary
    assert summary["state"] == "working", "The account badge follows connection and observation, not sources"

    paused = health.collector({"has_session": True, "running": False, "phase": "paused"}, CAPTURE, 60, 1, NOW)
    assert paused["state"] == "off", paused

    lost = health.collector({"has_session": True, "running": False, "phase": "offline",
                             "account_loss": {"cause": "session_duplicated"}}, CAPTURE, 60, 1, NOW)
    assert (lost["state"], lost["connection"]["reason"], lost["connection"]["cause"]) == \
        ("failed", "signed_out", "session_duplicated"), lost

    await floodwait_method()
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        collector = Collector(store, vault)
        until = time.time() + 600
        collector.telegram_paused(until, "messages.getHistory")
        collector.telegram_paused(until - 300, "upload.getFile")
        status = collector.status()
        assert (status["rpc_backoff_until"], status["rpc_backoff_method"]) == (until, "messages.getHistory"), status
        now = datetime.now(timezone.utc)
        part = health.connection({**live(), "rpc_backoff_until": until,
                                  "rpc_backoff_method": status["rpc_backoff_method"]}, now)
        assert (part["state"], part["reason"], part["telegram_pause_method"]) == \
            ("degraded", "telegram_pause", "messages.getHistory"), part
        assert abs(health.parse(part["telegram_pause_until"]) - (now + timedelta(seconds=600))) < timedelta(seconds=5)
        store.set_setting("rpc_backoff_until", until + 600)
        assert collector.status()["rpc_backoff_method"] is None, "A later pause of unknown origin is not attributed"

        record = {"total": 1000}
        collector.client = Pages(record, 250)
        assert await collector.stream_history(types.User(id=7), root / "export.jsonl", record) == 250
        etas = collector.client.seen
        assert all(value is None for value in etas[:100]), etas[:100]
        assert etas[100] is not None and etas[100] > 0, "ETA is known once the first page is written"
        store.verify(vault.public_key)
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="honest-status-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Badges follow connection and observation, lost accounts ask for sign-in, Telegram pauses name the "
          "method and end time, and export ETA appears after the first page.")
