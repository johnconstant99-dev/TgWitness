from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .fulltext import SOURCES, Query
from .workers import complete_in_thread

TOP = 50
MEANING = ("The investigator searched the saved archive and recorded the query, its scope and the number of results, "
           "including searches that found nothing.")


class Recorded(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)
    match: Literal["all", "any"] = "all"
    source: Literal["messages", "ocr", "transcription", "all"] = "messages"
    chat_ids: list[int] = Field(default_factory=list, max_length=200)
    since: datetime | None = None
    until: datetime | None = None
    note: str = Field(default="", max_length=1000)

    @field_validator("since", "until")
    @classmethod
    def aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Include a timezone in dates.")
        return value.astimezone(timezone.utc) if value else None


def record(store, body, allowed, operator):
    if body.since and body.until and body.since > body.until:
        raise ValueError("The start must precede the end of the selected period.")
    wanted = set(body.chat_ids) or None
    if allowed is not None:
        if wanted and not wanted <= allowed:
            raise PermissionError("This chat is not open to this access.")
        wanted = wanted or set(allowed)
    result = store.fulltext.search(Query(body.query, body.match), chat_ids=wanted, since=body.since, until=body.until,
                                   sources=SOURCES if body.source == "all" else (body.source,), order="relevance",
                                   limit=TOP, offset=0, public=allowed is not None)
    top = [{"seq": hit["event"]["seq"], "chat_id": hit["event"].get("chat_id"), "message_id": hit["event"].get("message_id")}
           for hit in result["hits"]]
    event = store.append("search.recorded", {
        "query": body.query, "match": body.match, "source": body.source,
        "chats": sorted(wanted) if wanted is not None else None, "since": body.since.isoformat() if body.since else None,
        "until": body.until.isoformat() if body.until else None, "matched": result["matched"], "top": top,
        "index": result.get("index"), "note": body.note.strip(), "operator": operator, "meaning": MEANING})
    return {"event": event["seq"], "matched": result["matched"], "top": top, "index": result.get("index")}


def register(app, authenticate, visible_chats):
    @app.post("/api/search/record", dependencies=[Depends(authenticate)])
    async def search_record(request: Request, body: Recorded):
        principal = request.state.principal
        operator = {"label": getattr(principal, "label", None) or ("Main administrator" if principal.admin else None),
                    "owner": principal.owner}
        try:
            return await complete_in_thread(record, app.state.store, body, visible_chats(request), operator)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from None
        except (ValueError, TimeoutError) as exc:
            raise HTTPException(422, str(exc)) from None
