"""Account-wide pacing for bulk reads, sharing the client's serialized RPC lane."""
import asyncio
import math
import time

from telethon.tl import functions


BULK_READS = (functions.messages.GetHistoryRequest, functions.messages.GetDialogsRequest,
              functions.channels.GetAdminLogRequest,
              functions.upload.GetFileRequest, functions.upload.GetCdnFileRequest)


def bulk_request(request):
    for _ in range(8):
        if isinstance(request, BULK_READS):
            return True
        request = getattr(request, "query", None)
        if request is None:
            return False
    return False


class AccountPacer:
    """Server cooldowns remain authoritative; local delay never shortens them.

    Called while WitnessClient holds its reentrant RPC lock, including media
    requests and requests wrapped in Takeout. State is isolated by account ID.
    """
    def __init__(self, store, *, clock=time.monotonic, sleep=asyncio.sleep):
        self.store, self.clock, self.sleep = store, clock, sleep
        self.next_request = 0.0

    def state(self):
        account = (self.store.get_setting("account", {}) or {}).get("id")
        value = self.store.get_setting("rpc_bulk_pacing", {})
        if not isinstance(value, dict) or value.get("account_id") != account:
            value = {}
        delay = value.get("delay_seconds", 1.0)
        if not isinstance(delay, (int, float)) or not math.isfinite(delay):
            delay = 1.0
        def count(key):
            number = value.get(key, 0)
            return max(0, number) if type(number) is int else 0
        return {"account_id": account, "delay_seconds": max(.5, min(10., delay)),
                "success_streak": min(19, count("success_streak")),
                "floodwait_count": count("floodwait_count"),
                "last_floodwait_at": value.get("last_floodwait_at")}

    async def before(self):
        delay = max(0., self.next_request - self.clock())
        if delay:
            await self.sleep(delay)
        self.next_request = self.clock() + self.state()["delay_seconds"]

    def success(self):
        value = self.state()
        value["success_streak"] += 1
        if value["success_streak"] >= 20:
            value["delay_seconds"] = max(.5, value["delay_seconds"] * .8)
            value["success_streak"] = 0
        self.store.set_setting("rpc_bulk_pacing", value)

    def flooded(self, seconds):
        value = self.state()
        value.update(success_streak=0, floodwait_count=value["floodwait_count"] + 1,
                     last_floodwait_at=time.time())
        value["delay_seconds"] = min(10., value["delay_seconds"] + (.5 if seconds < 10 else 2 if seconds < 60 else 5))
        self.store.set_setting("rpc_bulk_pacing", value)
        self.next_request = self.clock() + value["delay_seconds"]
