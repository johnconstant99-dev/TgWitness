import asyncio
import json
from typing import Literal

from fastapi import Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field, model_validator

from .dependencies import current_context
from ..profiling import CollectionPaused


class ProfileOptions(BaseModel):
    all_chats: bool = False
    chat_ids: list[int] = Field(default_factory=list, max_length=10000)
    user_id: int | None = Field(None, ge=1, le=2**63 - 1)
    participants: bool = True
    avatars: bool = True
    gifts: bool = True
    links: bool = True

    @model_validator(mode="after")
    def selected(self):
        if self.all_chats and self.chat_ids:
            raise ValueError("Choose this chat or all enabled chats.")
        if any(type(chat) is not int or not -(2**63) <= chat < 2**63 or chat == 0 for chat in self.chat_ids):
            raise ValueError("Choose valid Telegram chats.")
        self.chat_ids = list(dict.fromkeys(self.chat_ids))
        return self


async def status(*, ctx=Depends(current_context)):
    return ctx.app.state.collector.profiling.status()


async def action(action: Literal["start", "pause", "resume", "cancel", "retry"], body: ProfileOptions | None = None, *, ctx=Depends(current_context)):
    ctx.require_live()
    service = ctx.app.state.collector.profiling
    if action == "start" and (body is None or not body.all_chats and not body.chat_ids):
        raise HTTPException(422, "Choose the chats and profile data to collect.")
    try:
        return await ctx.operation(getattr(service, action), *([body.model_dump()] if action == "start" else []))
    except CollectionPaused as exc:
        messages = {"account_changed": "This collection belongs to another Telegram account.",
            "authorization_required": "Sign in to Telegram before continuing.", "source_paused": "Resume the selected chats before continuing their profile collection."}
        raise HTTPException(409, messages.get(str(exc), "Profile collection is paused.")) from None


def saved_assets(store, chat_id, user_id, category, offset, limit, before):
    with store.snapshot() as snapshot:
        db = snapshot.connection
        if not db.execute("SELECT 1 FROM people_state WHERE chat_id=? AND user_id=?", (chat_id, user_id)).fetchone():
            raise ValueError("This user has no recorded observations in this chat.")
        before = before or db.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
        identity = "coalesce(json_extract(data,'$.photo_id'),event_seq)" if category == "avatar" else "coalesce(json_extract(data,'$.key'),event_seq)"
        grouped = "SELECT max(event_seq) AS seq FROM people_observations WHERE chat_id=? AND user_id=? AND category=? AND event_seq<=? GROUP BY " + identity
        args = (chat_id, user_id, category, before)
        if category == "avatar":
            grouped = "SELECT max(seq) AS seq FROM events WHERE chat_id=? AND actor_id=? AND kind IN ('actor.avatar_saved','actor.avatar_observed') AND seq<=? GROUP BY coalesce(json_extract(payload,'$.photo_id'),seq)"
            args = (chat_id, user_id, before)
        total = db.execute("SELECT count(*) FROM (" + grouped + ")", args).fetchone()[0]
        rows = db.execute("SELECT e.seq,e.observed_at,e.hash,e.payload FROM events e JOIN (" + grouped + ") g ON e.seq=g.seq ORDER BY e.seq DESC LIMIT ? OFFSET ?",
            (*args, limit, offset)).fetchall()
        items = [{"event_seq": row[0], "observed_at": row[1], "hash": row[2], **json.loads(row[3])} for row in rows]
        for item in items:
            if "photo_id" in item:
                item["photo_id"] = str(item["photo_id"])
        return {"items": items, "total": total, "before": before,
            "next_offset": offset + len(items) if offset + len(items) < total else None}


async def assets(request: Request, chat_id: int = Path(ge=-(2**63), le=2**63 - 1), user_id: int = Path(ge=1, le=2**63 - 1),
                 category: Literal["avatar", "gift", "link"] = "avatar", offset: int = Query(0, ge=0, le=10**7),
                 limit: int = Query(48, ge=1, le=100), before: int | None = Query(None, ge=1, le=2**63 - 1), *, ctx=Depends(current_context)):
    try:
        value = await asyncio.to_thread(saved_assets, ctx.app.state.store, chat_id, user_id, category, offset, limit, before)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    await ctx.recheck_export_scope(request, {chat_id})
    return value
