import asyncio
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from .fulltext import SOURCES, Query
from .workers import limited_in_thread

MATCH_FIELDS = ("source", "score", "focus", "job_id", "machine_recognition", "excerpt", "excerpt_truncated",
                "engine", "model_version", "language", "completed_at")


class IndexSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["disk", "memory", "off"]


def moment(value):
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value) if len(value) <= 64 else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise HTTPException(422, "Dates must be ISO timestamps with a timezone.")
    return parsed.astimezone(timezone.utc)


def register(app, authenticate, workspace_id):
    reads = asyncio.Semaphore(2)

    def administrator(request):
        if not request.state.principal.admin:
            raise HTTPException(403, "Only the main administrator can change the search index.")

    async def run(function, *args):
        try:
            return await limited_in_thread(reads, function, *args)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError as exc:
            raise HTTPException(503, str(exc)) from None

    @app.get("/api/search", dependencies=[Depends(authenticate)])
    async def search(request: Request, q: str = "", chat_id: int | None = None, source: str = "messages",
                     since: str | None = None, until: str | None = None, order: str = "relevance",
                     match: str = "all", limit: int = 100, offset: int = 0):
        allowed = request.state.principal.chats(workspace_id)
        if chat_id is not None and allowed is not None and chat_id not in allowed:
            raise HTTPException(403, "This chat is not open to this access.")
        if source not in ("all", *SOURCES):
            raise HTTPException(422, "Choose messages, ocr, transcription or all sources.")
        start, end = moment(since), moment(until)
        if start and end and start > end:
            raise HTTPException(422, "The start must precede the end of the selected period.")
        chats = {chat_id} if chat_id is not None else allowed

        def find():
            result = app.state.store.fulltext.search(
                Query(q, match), chat_ids=chats, since=start, until=end,
                sources=SOURCES if source == "all" else (source,), order=order, limit=limit, offset=offset,
                public=allowed is not None)
            events = []
            for hit in result["hits"]:
                events.append({**hit["event"], "match": {key: hit[key] for key in MATCH_FIELDS if key in hit}})
            return {"events": events, "next_offset": result["next_offset"], "matched": result["matched"],
                    "query": result["query"], "index": result["index"], "order": result["order"],
                    "derived_note": "Recognized text is machine output linked to its media.saved record, "
                                    "not text sent in Telegram." if source != "messages" else None}
        return await run(find)

    @app.get("/api/search/status", dependencies=[Depends(authenticate)])
    async def status(request: Request):
        allowed = request.state.principal.chats(workspace_id)
        return await run(app.state.store.fulltext.status, allowed is not None)

    @app.post("/api/search/settings", dependencies=[Depends(authenticate)])
    async def settings(request: Request, body: IndexSettings):
        administrator(request)
        return await run(app.state.store.fulltext.configure, body.mode)

    @app.post("/api/search/rebuild", dependencies=[Depends(authenticate)])
    async def rebuild(request: Request):
        administrator(request)
        return await run(app.state.store.fulltext.rebuild)
