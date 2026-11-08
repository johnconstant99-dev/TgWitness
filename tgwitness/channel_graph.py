import asyncio
import secrets
import time

from pydantic import BaseModel, Field, StrictBool, model_validator
from telethon import utils
from telethon.tl import functions, types

from .store import utcnow
from .telegram_client import FLOOD_ERRORS

MEANING = ("Telegram's own similar-channel suggestions for each source, recorded as observations. A suggestion is "
           "produced by Telegram from its usage signals; it does not establish a shared operator, owner, author or "
           "purpose, and the absence of a suggestion does not establish that channels are unrelated.")
FILTER_MEANING = ("Filters drop suggestions from this record. A dropped channel was still suggested by Telegram; "
                  "counts below report what was suggested and what this run kept.")
FLAGS = ("broadcast", "megagroup", "gigagroup", "verified", "scam", "fake", "restricted", "noforwards")


class GraphOptions(BaseModel):
    depth: int = Field(1, ge=0, le=4)
    per_source: int = Field(20, ge=1, le=200)
    total: int = Field(100, ge=1, le=2000)
    min_participants: int | None = Field(None, ge=0)
    max_participants: int | None = Field(None, ge=0)
    require_username: StrictBool = False
    skip_restricted: StrictBool = False
    pause_seconds: float = Field(1.0, ge=0, le=60)

    @model_validator(mode="after")
    def ordered(self):
        low, high = self.min_participants, self.max_participants
        if low is not None and high is not None and low > high:
            raise ValueError("min_participants cannot exceed max_participants")
        return self


def describe(chat, depth, discovered_from):
    found = {"chat_id": utils.get_peer_id(chat), "title": getattr(chat, "title", None),
             "username": getattr(chat, "username", None), "depth": depth, "discovered_from": discovered_from,
             "participants": getattr(chat, "participants_count", None),
             "flags": sorted(name for name in FLAGS if getattr(chat, name, False))}
    usernames = getattr(chat, "usernames", None) or []
    if usernames:
        found["usernames"] = [u.username for u in usernames if getattr(u, "username", None)]
    return found


def excluded(node, options):
    size = node["participants"]
    if options.require_username and not node["username"] and not node.get("usernames"):
        return "no_username"
    if options.skip_restricted and "restricted" in node["flags"]:
        return "restricted"
    if size is None:
        return "size_unknown" if options.min_participants or options.max_participants else None
    if options.min_participants is not None and size < options.min_participants:
        return "below_minimum"
    if options.max_participants is not None and size > options.max_participants:
        return "above_maximum"
    return None


async def suggestions(collector, entity):
    answer = await collector.client(functions.channels.GetChannelRecommendationsRequest(channel=entity))
    return [chat for chat in getattr(answer, "chats", []) if isinstance(chat, types.Channel)]


async def discover(collector, seeds, options=None, progress=None):
    options = options or GraphOptions()
    store = collector.store
    run_id = secrets.token_hex(8)
    store.append("graph.started", {"graph_run_id": run_id, "seeds": list(seeds), "options": options.model_dump(),
                                   "meaning": MEANING})
    nodes, edges, dropped, stopped = {}, [], {}, None
    queue = [(chat_id, 0) for chat_id in dict.fromkeys(seeds)]
    for chat_id, _ in queue:
        nodes[chat_id] = {"chat_id": chat_id, "depth": 0, "discovered_from": None, "seed": True}
    while queue:
        chat_id, depth = queue.pop(0)
        if depth >= options.depth:
            continue
        if len(nodes) >= options.total:
            stopped = "total_reached"
            break
        wait = store.get_setting("rpc_backoff_until", 0) - time.time()
        if wait > 0:
            stopped = "rpc_backoff"
            break
        try:
            entity = await collector.resolve_target(chat_id)
            found = await suggestions(collector, entity)
        except FLOOD_ERRORS as exc:
            until = max(time.time() + exc.seconds, store.get_setting("rpc_backoff_until", 0))
            store.set_setting("rpc_backoff_until", until)
            store.append("telegram.backoff", {"operation": "similar channels", "retry_after_seconds": exc.seconds},
                         chat_id)
            stopped = "rpc_backoff"
            break
        except ValueError as exc:
            store.append("graph.source_unavailable", {"graph_run_id": run_id, "error_type": type(exc).__name__},
                         chat_id)
            continue
        kept, suggested = [], []
        for chat in found[:options.per_source]:
            node = describe(chat, depth + 1, chat_id)
            suggested.append({"chat_id": node["chat_id"], "username": node["username"]})
            edges.append({"from": chat_id, "to": node["chat_id"], "depth": depth + 1})
            reason = excluded(node, options)
            if reason:
                dropped[reason] = dropped.get(reason, 0) + 1
                continue
            kept.append(node)
            if node["chat_id"] in nodes:
                continue
            if len(nodes) >= options.total:
                stopped = "total_reached"
                break
            nodes[node["chat_id"]] = node
            queue.append((node["chat_id"], depth + 1))
        store.append("graph.suggestions", {
            "graph_run_id": run_id, "depth": depth, "suggested": len(found), "returned": len(suggested),
            "kept": len(kept), "channels": suggested, "meaning": MEANING + " " + FILTER_MEANING}, chat_id)
        if progress:
            progress({"run_id": run_id, "visited": len(edges), "channels": len(nodes), "depth": depth})
        if stopped:
            break
        if options.pause_seconds:
            await asyncio.sleep(options.pause_seconds)
    result = {"format": "tgwitness-channel-graph-v1", "graph_run_id": run_id, "generated_at": utcnow(),
              "options": options.model_dump(), "seeds": list(seeds), "nodes": list(nodes.values()), "edges": edges,
              "dropped": dropped, "stopped": stopped, "meaning": MEANING}
    store.append("graph.finished", {"graph_run_id": run_id, "channels": len(nodes), "edges": len(edges),
                                    "dropped": dropped, "stopped": stopped, "meaning": MEANING})
    return result


class GraphRequest(GraphOptions):
    seeds: list[int] = Field(..., min_length=1, max_length=50)


def register(app, authenticate, require_live):
    from fastapi import Depends, HTTPException, Request

    @app.post("/api/channel-graph", dependencies=[Depends(authenticate)])
    async def channel_graph(body: GraphRequest, request: Request):
        if not request.state.principal.admin:
            raise HTTPException(403, "Only the main administrator can map similar channels.")
        require_live()
        options = GraphOptions(**body.model_dump(exclude={"seeds"}))
        try:
            return await discover(app.state.collector, body.seeds, options)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
