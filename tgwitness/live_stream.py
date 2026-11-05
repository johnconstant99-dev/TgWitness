import asyncio
import copy
import json
import time

from starlette.responses import JSONResponse, StreamingResponse

from .store import ADMIN_RECORDS


class StreamSlots:
    def __init__(self, limit=32, per_token=4):
        self.limit, self.per_token = limit, per_token
        self.active = 0
        self.owners = {}

    def acquire(self, owner=None):
        if self.active >= self.limit or owner is not None and self.owners.get(owner, 0) >= self.per_token:
            return False
        self.active += 1
        if owner is not None:
            self.owners[owner] = self.owners.get(owner, 0) + 1
        return True

    def release(self, owner=None):
        if self.active <= 0:
            raise RuntimeError("Live stream slot released without acquisition")
        self.active -= 1
        if owner is not None:
            count = self.owners[owner] - 1
            if count:
                self.owners[owner] = count
            else:
                del self.owners[owner]


class LimitedStreamingResponse(StreamingResponse):
    def __init__(self, content, *, slots, owner=None, **kwargs):
        super().__init__(content, **kwargs)
        self.slots = slots
        self.owner = owner

    async def __call__(self, scope, receive, send):
        acquired = self.slots.acquire(self.owner)
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
                    self.slots.release(self.owner)


def notifications(store, after, allowed, limit=100, hide_admin=False):
    where, args = ["seq > ?"], [after]
    if hide_admin:
        where.append(ADMIN_RECORDS)
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


async def stream(store, after, authorize, disconnected, *, interval=1, lifetime=45,
                 board_after=0, board_authorize=None, workspace="default", hide_admin=False):
    cursor = after
    deadline = time.monotonic() + lifetime
    while time.monotonic() < deadline and not await disconnected():
        allowed = authorize()
        records = await asyncio.to_thread(notifications, store, cursor, allowed, hide_admin=hide_admin)
        if allowed != authorize():
            await asyncio.sleep(0.05)
            continue
        if board_authorize:
            from .board import notifications as board_notifications
            principal = board_authorize()
            authorization = copy.deepcopy((principal.public(), principal.chats(workspace))) if principal else None
            notes, next_board = await asyncio.to_thread(board_notifications, store, board_after, principal, workspace)
            current = board_authorize()
            if principal and current and authorization == (current.public(), current.chats(workspace)):
                board_after = next_board
                if notes:
                    yield "event: board\ndata: " + json.dumps(notes, separators=(",", ":")) + "\n\n"
        if records:
            cursor = records[-1]["seq"]
            yield "id: " + str(cursor) + "\nevent: journal\ndata: " + json.dumps(records, separators=(",", ":")) + "\n\n"
        else:
            yield ": keep-alive\n\n"
        await asyncio.sleep(interval if len(records) < 100 else 0.05)
