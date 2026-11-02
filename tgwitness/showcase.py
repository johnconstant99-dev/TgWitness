import asyncio
import json
import re
import secrets
from typing import Literal

from fastapi import Depends, HTTPException, Query, Request

from . import continuity, tuning
from .access import GrantSettings, Principal
from .journal_index import GONE_KINDS, TEXT_KINDS
from .monitoring import capture_settings, monitoring_settings
from .store import ZERO, canonical, utcnow
from .verify import fingerprint

KINDS = TEXT_KINDS + GONE_KINDS
USERNAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,31}")


def public_channel(connection, chat_id):
    row = connection.execute(
        "SELECT payload,observed_at FROM events INDEXED BY event_kind WHERE chat_id=? AND kind='source.profile' "
        "ORDER BY seq DESC LIMIT 1", (chat_id,)).fetchone()
    if row is None:
        return None
    profile = json.loads(row["payload"])
    username = profile.get("username")
    if profile.get("kind") != "channel" or not isinstance(username, str) or not USERNAME.fullmatch(username):
        return None
    return {"chat_id": chat_id, "title": str(profile.get("title") or username)[:256],
            "username": username, "public_observed_at": row["observed_at"]}


def validate_scope(registry, settings):
    if not settings.showcase:
        return
    for workspace_id, chats in settings.workspaces.items():
        entry = registry.entries.get(workspace_id)
        if entry is None or entry.get("app") is None:
            raise HTTPException(422, "A selected workspace is unavailable.")
        with entry["app"].state.store.snapshot() as snapshot:
            if any(public_channel(snapshot.connection, cid) is None for cid in chats):
                raise HTTPException(422, "Select public channels with a saved source profile. Refresh their profiles first.")


def workspace(registry, principal, workspace_id):
    if principal.admin or not principal.grant.get("showcase") or not principal.opens(workspace_id):
        raise HTTPException(403, "Open a showcase access link to use this page.")
    entry = registry.entries.get(workspace_id)
    if entry is None or entry.get("app") is None:
        raise HTTPException(404, "Showcase workspace unavailable.")
    return entry["app"].state


def selected_channels(connection, principal, workspace_id):
    return [channel for cid in sorted(principal.chats(workspace_id))
            if (channel := public_channel(connection, cid)) is not None]


def signed(vault, statement):
    return {"statement": statement, "signature": vault.sign(canonical(statement)),
            "fingerprint": fingerprint(vault.public_key)}


def summary(registry, principal, workspace_id, challenge, from_count=0):
    state = workspace(registry, principal, workspace_id)
    store, vault, collector = state.store, state.vault, state.collector
    with store.snapshot() as snapshot:
        db, head = snapshot.connection, snapshot.head
        count = head["seq"] if head else 0
        if from_count > count:
            raise HTTPException(409, "The journal is shorter than the retained checkpoint.")
        channels = selected_channels(db, principal, workspace_id)
        counts = dict.fromkeys(KINDS, 0)
        for channel in channels:
            cid = channel["chat_id"]
            channel["counts"] = {row["kind"]: row["total"] for row in db.execute(
                "SELECT kind,total FROM chat_event_kind_counts WHERE chat_id=?", (cid,)) if row["kind"] in KINDS}
            for kind, total in channel["counts"].items():
                counts[kind] += total
            for name, order in (("first_observed_at", "ASC"), ("last_observed_at", "DESC")):
                row = db.execute("SELECT observed_at FROM events WHERE chat_id=? ORDER BY seq " + order + " LIMIT 1",
                                 (cid,)).fetchone()
                channel[name] = row[0] if row else None
            target = db.execute("SELECT enabled FROM targets WHERE chat_id=?", (cid,)).fetchone()
            channel["observation_enabled"] = bool(target and target[0])
        checkpoint = {"format": "tgwitness-checkpoint-v1", "created_at": utcnow(), "public_key": vault.public_key,
                      "event_count": count, "head_hash": head["hash"] if head else ZERO}
        proof = continuity.answer(snapshot, vault, challenge, from_count)
    statement = {"format": "tgwitness-showcase-v1", "public_key": vault.public_key,
                 "created_at": utcnow(), "workspace_id": workspace_id, "challenge": challenge,
                 "synthetic": bool(store.get_setting("demo", False)), "channels": channels, "counts": counts,
                 "health": {"running": bool(collector.running),
                            "connected": bool(collector.client and collector.client.is_connected()),
                            "last_heartbeat": getattr(collector, "last_heartbeat", None)},
                 "settings_now": {"monitoring": monitoring_settings(store),
                                  "download_media": capture_settings(store)["download_media"],
                                  "heartbeat_seconds": tuning.value(store, "heartbeat_seconds"),
                                  "checkpoint_minutes": tuning.value(store, "checkpoint_minutes")},
                 "disclosure": {"files": False, "author_fields": "redacted", "text": "public channel text",
                                "counts": "events in visible channels; not unique messages",
                                "checkpoint": "entire collector journal; content outside this selection is not shared"},
                 "checkpoint": signed(vault, checkpoint), "continuity": proof}
    return signed(vault, statement)


def content(row):
    payload = json.loads(row["payload"])
    text = payload.get("text")
    observed = payload.get("sender_observation")
    return {"text": text if isinstance(text, str) else None,
            "author": "Redacted" if payload.get("sender_id") is not None or observed or row["actor_id"] else None,
            "profile": "Redacted" if observed else None,
            "attachment_present": bool(payload.get("has_media")),
            "observed_at": row["observed_at"], "source_at": row["source_at"], "source_hash": row["hash"]}


def messages(registry, principal, workspace_id, chat_id, before, limit, kind, message_id):
    state = workspace(registry, principal, workspace_id)
    if chat_id not in principal.chats(workspace_id):
        raise HTTPException(404, "Channel unavailable.")
    with state.store.snapshot() as snapshot:
        db = snapshot.connection
        channel = public_channel(db, chat_id)
        if channel is None:
            raise HTTPException(404, "Channel no longer has a saved public profile.")
        kinds = KINDS if kind == "all" else ("message." + kind,)
        where, args = "chat_id=? AND kind IN (" + ",".join("?" for _ in kinds) + ")", [chat_id, *kinds]
        if before is not None:
            where += " AND seq<?"
            args.append(before)
        if message_id is not None:
            where += " AND message_id=?"
            args.append(message_id)
        rows = db.execute("SELECT seq,kind,message_id,payload,actor_id,observed_at,source_at,hash FROM events WHERE " +
                          where + " ORDER BY seq DESC LIMIT ?", (*args, limit + 1)).fetchall()
        items = []
        for row in rows[:limit]:
            item = {"seq": row["seq"], "kind": row["kind"], "message_id": row["message_id"], **content(row)}
            if row["kind"] in GONE_KINDS:
                saved = db.execute(
                    "SELECT payload,actor_id,observed_at,source_at,hash FROM events WHERE chat_id=? AND message_id=? "
                    "AND seq<? AND kind IN (" + ",".join("?" for _ in TEXT_KINDS) + ") ORDER BY seq DESC LIMIT 1",
                    (chat_id, row["message_id"], row["seq"], *TEXT_KINDS)).fetchone()
                item["retained"] = content(saved) if saved else None
            items.append(item)
    return signed(state.vault, {"format": "tgwitness-showcase-messages-v1", "public_key": state.vault.public_key,
                               "created_at": utcnow(), "workspace_id": workspace_id, "channel": channel,
                               "items": items, "next_before": rows[limit - 1]["seq"] if len(rows) > limit else None,
                               "meaning": "Redacted presentation signed separately; source hashes reference original journal records"})


def overview(registry, principal, challenge):
    if principal.admin or not principal.grant.get("showcase"):
        raise HTTPException(403, "Open a showcase access link to use this page.")
    result = {"label": principal.label, "workspaces": [], "unavailable": []}
    for pid in principal.grant["workspaces"]:
        try:
            result["workspaces"].append(summary(registry, principal, pid, challenge))
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            result["unavailable"].append(pid)
    return result


def register(app, authenticate):
    @app.get("/api/showcase/manage", dependencies=[Depends(authenticate)])
    async def manage():
        def read():
            channels = []
            for pid, entry in app.state.profiles.entries.items():
                if entry.get("app") is None:
                    continue
                with entry["app"].state.store.snapshot() as snap:
                    for row in snap.connection.execute("SELECT chat_id FROM targets WHERE kind='channel'"):
                        channel = public_channel(snap.connection, row[0])
                        if channel:
                            channels.append({"workspace_id": pid, "workspace_label": entry["label"], **channel})
            return {"channels": channels, "grants": [g for g in app.state.access.state(None)["grants"] if g.get("showcase")]}
        return await asyncio.to_thread(read)

    @app.post("/api/showcase/preview", dependencies=[Depends(authenticate)])
    async def preview(body: GrantSettings):
        if not body.showcase:
            raise HTTPException(422, "Choose showcase access.")
        def read():
            validate_scope(app.state.profiles, body)
            principal = Principal(False, body.label, body.model_dump())
            result = overview(app.state.profiles, principal, secrets.token_hex(16))
            result["samples"] = [messages(app.state.profiles, principal, pid, cid, None, 3, "all", None)
                                 for pid, chats in body.workspaces.items() for cid in chats]
            return result
        return await asyncio.to_thread(read)

    @app.get("/api/showcase", dependencies=[Depends(authenticate)])
    async def show(request: Request, challenge: str = Query(pattern=r"^[0-9a-f]{32}$")):
        return await asyncio.to_thread(overview, app.state.profiles, request.state.principal, challenge)

    @app.get("/api/showcase/{workspace_id}", dependencies=[Depends(authenticate)])
    async def show_workspace(request: Request, workspace_id: str, challenge: str = Query(pattern=r"^[0-9a-f]{32}$"),
                             from_count: int = Query(default=0, ge=0, lt=2**63)):
        return await asyncio.to_thread(summary, app.state.profiles, request.state.principal, workspace_id, challenge, from_count)

    @app.get("/api/showcase/{workspace_id}/chats/{chat_id}", dependencies=[Depends(authenticate)])
    async def show_messages(request: Request, workspace_id: str, chat_id: int,
                            before: int | None = Query(default=None, ge=1, lt=2**63),
                            limit: int = Query(default=30, ge=1, le=50),
                            kind: Literal["all", "edited", "deleted"] = "all",
                            message_id: int | None = Query(default=None, ge=1, lt=2**63)):
        return await asyncio.to_thread(messages, app.state.profiles, request.state.principal, workspace_id,
                                      chat_id, before, limit, kind, message_id)
