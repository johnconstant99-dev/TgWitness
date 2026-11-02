"""Case Board routes. No collector, notification or external-service calls."""
import csv
import copy
import io
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import ValidationError

from . import board, tuning
from .access import Principal, Refused
from .board_models import MODELS, SliceQuery
from .store import canonical, utcnow
from .verify import board_scope, board_slice_summary, board_where
from .workers import complete_in_thread


def register(app, authenticate, workspace):
    def service():
        return board.Board(app.state.store, workspace)

    def current(request):
        token = request.headers.get("authorization", "").partition(" ")[2]
        if request.state.principal.admin and secrets.compare_digest(token, getattr(app.state, "local_demo_token", "") or "\0"):
            return request.state.principal
        who = app.state.access.resolve(token, request.client.host if request.client else "unknown")
        if who is None:
            raise Refused("This access is no longer available.")
        board.require_scope(who, workspace, set())
        return who

    async def run(request, function, *, write=False):
        def execute():
            try:
                if not app.state.store.signer:
                    raise ValueError("Unlock the workspace first.")
                if write:
                    return function(app.state.store.db, current(request))
                with app.state.store.snapshot() as snapshot:
                    who = current(request)
                    authorization = copy.deepcopy((who.public(), who.chats(workspace)))
                    result = function(snapshot.connection, who)
                    latest = current(request)
                    if authorization != (latest.public(), latest.chats(workspace)):
                        raise Refused("Access changed during this read. Reload the board.")
                    return result
            except Refused as exc:
                raise HTTPException(403, str(exc)) from None
            except KeyError:
                raise HTTPException(404, "Card not found.") from None
            except (ValueError, ValidationError) as exc:
                raise HTTPException(422, str(exc)) from None
        return await complete_in_thread(execute)

    @app.get("/api/board", dependencies=[Depends(authenticate)])
    async def feed(request: Request, collection: str | None = None, chat: int | None = None,
                   author: str | None = None, label: str | None = None, state: str | None = None,
                   q: str = "", kind: str | None = None, comments: bool = False,
                   offset: int = 0, limit: int = 50, order: str = "newest"):
        if not 0 <= offset <= 1000000 or not 1 <= limit <= 200 or len(q) > 200 or order not in {"newest", "oldest"}:
            raise HTTPException(422, "Invalid feed window.")
        bounds = {}
        for key in ("from", "to"):
            if raw := request.query_params.get(key):
                try:
                    value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if value.tzinfo is None:
                        raise ValueError()
                    bounds[key] = value.astimezone(timezone.utc)
                except ValueError:
                    raise HTTPException(422, "Feed times must include a UTC offset.") from None
        if "from" in bounds and "to" in bounds and bounds["from"] > bounds["to"]:
            raise HTTPException(422, "Feed start must precede its end.")
        def read(db, who):
            result = service().read(db, who)
            lookup = {item["id"]: item for item in result["items"]}
            counts = {}
            for item in result["items"]:
                if item["kind"] != "board.comment" or item["removed"]:
                    continue
                parent = lookup.get(item["parent_id"])
                while parent and parent["kind"] == "board.comment":
                    parent = lookup.get(parent["parent_id"])
                if parent:
                    counts[parent["id"]] = counts.get(parent["id"], 0) + 1
            cards = []
            for item in result["items"]:
                if item["kind"] not in {"board.bookmark", "board.highlight", "board.slice"} or item["removed"]:
                    continue
                if collection and item.get("collection_id") != (None if collection == "inbox" else collection):
                    continue
                if chat is not None and chat not in (board_scope(item, lookup) or set()):
                    continue
                if author and item["access_id"] != author or label and label not in item.get("labels", []):
                    continue
                if state and item["state"] != state or kind and item["kind"] != "board." + kind:
                    continue
                if q and q.casefold() not in " ".join([item.get("title", ""), item.get("note", ""), item.get("range", {}).get("quote", "")]).casefold():
                    continue
                at = datetime.fromisoformat(item["at"].replace("Z", "+00:00"))
                if "from" in bounds and at < bounds["from"]:
                    continue
                if "to" in bounds and at > bounds["to"]:
                    continue
                item["comment_count"] = counts.get(item["id"], 0)
                if comments and not item["comment_count"]:
                    continue
                cards.append(item)
            cards.sort(key=lambda item: item["annotation_seq"], reverse=order == "newest")
            page = cards[offset:offset+limit]
            for item in page:
                if item.get("target"):
                    target = board.event_by_hash(db, item["target"]["event_hash"])
                    item["preview"] = target
                    item["dangling"] = target is None
                    if target and target["chat_id"] is not None and target["message_id"] is not None and tuning.value(app.state.store, "board_thumbnails"):
                        media = []
                        for row in db.execute("SELECT payload FROM events WHERE chat_id=? AND message_id=? AND kind='media.saved' ORDER BY seq DESC LIMIT 4", (target["chat_id"], target["message_id"])):
                            payload = json.loads(row[0])
                            if payload.get("media_sha256"):
                                media.append({"sha256": payload["media_sha256"], "mime_type": payload.get("mime_type"), "size": payload.get("size"), "name": payload.get("name")})
                        item["preview_media"] = media
            # Only visible content contributes authors, counters and the live cursor.
            return {"cards": page, "total": len(cards), "next_offset": offset+len(page) if offset+len(page) < len(cards) else None,
                    "collections": sorted([item for item in result["items"] if item["kind"] == "board.collection" and not item["removed"]], key=lambda item: (item.get("order", 0), item["title"])),
                    "authors": list({item["access_id"]: {"id": item["access_id"], "label": item["access_label"]} for item in result["items"]}.values()),
                    "cursor": max([item["annotation_seq"] for item in result["items"]] + [0]),
                    "thumbnails": tuning.value(app.state.store, "board_thumbnails"),
                    "limits": board.soft_limits(app.state.store, result)}
        return await run(request, read)

    @app.get("/api/board/card/{identifier}", dependencies=[Depends(authenticate)])
    async def detail(request: Request, identifier: str):
        return await run(request, lambda db, who: service().detail(db, who, identifier))

    def participants(db, who, identifier):
        state = service().read(db, who)
        lookup = {item["id"]: item for item in state["items"]}
        if identifier not in lookup:
            raise KeyError(identifier)
        scope = board_scope(lookup[identifier], lookup)
        result = [{"id": "admin", "label": "Main administrator"}]
        with app.state.access.lock:
            grants = copy.deepcopy(app.state.access.grants)
        for grant in grants:
            if grant.get("revoked_at") or grant.get("expires_at") and grant["expires_at"] <= time.time():
                continue
            try:
                board.require_scope(Principal(False, grant["label"], grant, group_of=app.state.access.group_of), workspace, scope)
            except Refused:
                continue
            result.append({"id": grant["id"], "label": grant["label"]})
        return result

    @app.get("/api/board/card/{identifier}/participants", dependencies=[Depends(authenticate)])
    async def card_participants(request: Request, identifier: str):
        return await run(request, lambda db, who: participants(db, who, identifier))

    @app.post("/api/board/slice-preview", dependencies=[Depends(authenticate)])
    async def preview(request: Request, body: SliceQuery):
        def read(db, who):
            board.require_scope(who, workspace, None if body.include_unscoped else set(body.chats()))
            return board_slice_summary(db, body.model_dump(by_alias=True))
        return await run(request, read)

    @app.get("/api/board/slice/{identifier}/records", dependencies=[Depends(authenticate)])
    async def slice_records(request: Request, identifier: str, offset: int = 0, limit: int | None = None, recompute: int = 1):
        limit = limit or tuning.value(app.state.store, "board_preview_records")
        if offset < 0 or not 1 <= limit <= 5000:
            raise HTTPException(422, "Invalid slice page.")
        return await run(request, lambda db, who: service().slice(db, who, identifier, offset, limit))

    @app.get("/api/board/slice/{identifier}/export", dependencies=[Depends(authenticate)])
    async def slice_export(request: Request, identifier: str, format: str = "json"):
        if format not in {"json", "csv"}:
            raise HTTPException(422, "Choose JSON or CSV.")
        def read(db, who):
            if not who.may("export"):
                raise Refused("Export permission is required.")
            card = service().detail(db, who, identifier)["card"]
            if card["kind"] != "board.slice" or card["removed"]:
                raise KeyError(identifier)
            where, args = board_where(card["query"])
            items = []
            size = 0
            for row in db.execute("SELECT * FROM events WHERE " + where + " ORDER BY seq", args):
                event = dict(row)
                event["payload"] = json.loads(event["payload"])
                size += len(canonical(event))
                if size > 64 * 1024**2:
                    raise ValueError("Selection exceeds 64 MiB. Narrow the slice or use the signed ZIP.")
                items.append(event)
            if format == "csv":
                from .evidence import safe_cell
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["seq", "observed_at", "source_at", "kind", "chat_id", "message_id", "actor_id", "event_hash"])
                for event in items:
                    writer.writerow([safe_cell(event.get(key)) for key in ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id", "actor_id", "hash")])
                return output.getvalue().encode()
            statement = {"format": "tgwitness-board-selection-v1", "public_key": app.state.vault.public_key,
                         "created_at": utcnow(), "journal_head": board.journal_head(db), "card_id": identifier,
                         "query": card["query"], "items": items}
            return canonical({"statement": statement, "signature": app.state.vault.sign(canonical(statement))})
        data = await run(request, read)
        return Response(data, media_type="application/json" if format == "json" else "text/csv",
                        headers={"Content-Disposition": 'attachment; filename="board-slice.' + format + '"'})

    @app.get("/api/board/export", dependencies=[Depends(authenticate)])
    async def export(request: Request):
        def read(db, who):
            if not who.may("export"):
                raise Refused("Export permission is required.")
            state = service().read(db, who)
            if who.chats(workspace) is None:
                return board.export_state(db, app.state.vault)
            statement = {"format": "tgwitness-case-board-disclosure-v1", "created_at": utcnow(),
                         "public_key": app.state.vault.public_key, "state": state,
                         "meaning": "Only annotations visible to the exporting access; not the complete annotations chain"}
            return {"statement": statement, "signature": app.state.vault.sign(canonical(statement))}
        value = await run(request, read)
        return Response(canonical(value), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="case-board.json"'})

    @app.post("/api/board/{action}", dependencies=[Depends(authenticate)])
    async def create(request: Request, action: str, body: dict):
        if action not in MODELS:
            raise HTTPException(404, "Board action not found.")
        def append(db, who):
            validated = MODELS[action].model_validate(body).model_dump(by_alias=True, exclude_none=True)
            with app.state.store.transaction():
                who = current(request)
                if action == "comment" and validated.get("mentions"):
                    allowed = {item["id"] for item in participants(db, who, validated["parent_id"])}
                    if not set(validated["mentions"]) <= allowed:
                        raise ValueError("A mentioned participant does not have access to this card.")
                return service().append(action, validated, who, authorize=lambda: current(request))
        return await run(request, append, write=True)
