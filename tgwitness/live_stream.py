"""Bounded, committed journal notifications. No payloads or signing material leave this path."""
import asyncio
import json
import time

from starlette.responses import JSONResponse, StreamingResponse


class StreamSlots:
    def __init__(self, limit=32):
        self.limit = limit
        self.active = 0

    def acquire(self):
        if self.active >= self.limit:
            return False
        self.active += 1
        return True

    def release(self):
        if self.active <= 0:
            raise RuntimeError("Live stream slot released without acquisition")
        self.active -= 1


class LimitedStreamingResponse(StreamingResponse):
    """Keep the slot for the complete ASGI response, including its first headers."""
    def __init__(self, content, *, slots, **kwargs):
        super().__init__(content, **kwargs)
        self.slots = slots

    async def __call__(self, scope, receive, send):
        acquired = self.slots.acquire()
        try:
            if not acquired:
                await JSONResponse({"detail": "Too many live streams."}, status_code=429,
                                   headers={"Retry-After": "10"})(scope, receive, send)
                return
            await super().__call__(scope, receive, send)
        finally:
            try:
                close = getattr(self.body_iterator, "aclose", None)
                if close is not None:
                    await close()
            finally:
                if acquired:
                    self.slots.release()


def notifications(store, after, allowed, limit=100):
    where, args = ["seq > ?"], [after]
    if allowed is not None:
        if not allowed:
            return []
        where.append("chat_id IN (" + ",".join("?" * len(allowed)) + ")")
        args.extend(sorted(allowed))
    with store.lock:
        rows = store.db.execute(
            "SELECT seq,kind,chat_id,message_id,observed_at FROM events WHERE "
            + " AND ".join(where) + " ORDER BY seq LIMIT ?", (*args, limit)).fetchall()
        return [dict(row) for row in rows]


async def stream(store, after, authorize, disconnected, *, interval=1, lifetime=45):
    cursor = after
    deadline = time.monotonic() + lifetime
    while time.monotonic() < deadline and not await disconnected():
        allowed = authorize()  # Recheck revocation and current chat scope for every batch.
        records = await asyncio.to_thread(notifications, store, cursor, allowed)
        if allowed != authorize():
            await asyncio.sleep(0.05)
            continue
        if records:
            cursor = records[-1]["seq"]
            yield "id: " + str(cursor) + "\nevent: journal\ndata: " + json.dumps(records, separators=(",", ":")) + "\n\n"
        else:
            yield ": keep-alive\n\n"
        # A bounded batch, no unbounded per-browser queue even if the client is slow.
        await asyncio.sleep(interval if len(records) < 100 else 0.05)
