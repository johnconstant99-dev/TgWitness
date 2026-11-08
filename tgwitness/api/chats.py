from .. import alerts
from .. import dossier
from .. import extensions
from .. import i18n
from .. import interactions
from .. import people
from .. import recording
from .. import tuning
from ..access import Refused
from ..access import check as access_check
from ..app import ClearMediaQueue
from ..app import DossierSwitch
from ..app import ExportPassword
from ..app import IgnoreSources
from ..app import ParametersUpdate
from ..app import Snapshot
from ..app import Target
from ..app import TargetBatch
from ..app import TargetPriority
from ..downloads import TemporaryDownload
from ..downloads import build_file
from ..evidence import encrypt_export
from ..evidence import producer
from ..history_options import HistoryOptions
from ..monitoring import Capture
from ..monitoring import Monitoring
from ..monitoring import capture_settings
from ..monitoring import monitoring_settings
from ..monitoring import normalize_capture
from ..scope import EXCLUDE_LIMIT
from ..scope import Recheck
from ..scope import ScopeUpdate
from ..scope import WIDE_WARNING
from ..scope import recheck_settings
from ..scope import scope_settings
from ..scope import unexclude
from ..store import canonical
from ..workers import complete_in_thread
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Path as ApiPath
from fastapi import Query
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Literal
import asyncio
import json
import re
import secrets


class Reveal(BaseModel):
    chat_id: int
    message_id: int | None = None
    reason: Literal["message", "display_preference"] = "message"


async def dialogs(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.dialogs)


async def target(request: Request, body: Target, *, ctx=Depends(current_context)):
    ctx.require_live()
    ctx.require_chat(request, body.chat_id)
    collector, store = (ctx.app.state.collector, ctx.app.state.store)
    async with ctx.op_lock:
        existing = next(
            (t for t in store.targets() if t["chat_id"] == body.chat_id), None
        )
        entry = collector.dialog_cache.get(body.chat_id) or existing
        if not entry:
            raise HTTPException(
                400, "Refresh the group list and select an available target."
            )
        with store.transaction():
            store.set_target(
                body.chat_id,
                entry["title"],
                entry["kind"],
                body.enabled,
                origin="manual",
                priority=body.priority,
            )
            included = body.enabled and unexclude(store, body.chat_id)
            store.append(
                "target.changed",
                {
                    "title": entry["title"],
                    "enabled": body.enabled,
                    **({"removed_from_scope_exclusions": True} if included else {}),
                    "coverage": "No observations promised while target is disabled.",
                },
                body.chat_id,
            )
            if body.enabled and (not (existing and existing["enabled"])):
                collector.request_baseline([body.chat_id])
    return {"targets": ctx.visible_targets(request)}


async def targets_batch(
    request: Request, body: TargetBatch, *, ctx=Depends(current_context)
):
    ctx.require_live()
    collector, store = (ctx.app.state.collector, ctx.app.state.store)
    ids = list(dict.fromkeys(body.chat_ids))
    for chat_id in ids:
        ctx.require_chat(request, chat_id)
    async with ctx.op_lock:
        if body.remove:
            result = ctx.remove_targets(ids)
            return {"targets": ctx.visible_targets(request), **result}
        existing = {t["chat_id"]: t for t in store.targets()}
        entries = {
            chat_id: existing.get(chat_id) or collector.dialog_cache.get(chat_id)
            for chat_id in ids
        }
        if any((entry is None for entry in entries.values())):
            raise HTTPException(
                400, "Refresh the group list and select an available target."
            )
        added = []
        with store.transaction():
            for chat_id, entry in entries.items():
                enabled = (
                    body.enabled
                    if body.enabled is not None
                    else bool(entry.get("enabled", True))
                )
                store.set_target(
                    chat_id,
                    entry["title"],
                    entry["kind"],
                    enabled,
                    origin=entry.get("origin", "manual"),
                    priority=body.priority,
                )
                included = enabled and unexclude(store, chat_id)
                store.append(
                    "target.changed",
                    {
                        "title": entry["title"],
                        "enabled": enabled,
                        "priority": body.priority,
                        "batch": True,
                        **({"removed_from_scope_exclusions": True} if included else {}),
                    },
                    chat_id,
                )
                if enabled and (not existing.get(chat_id, {}).get("enabled")):
                    added.append(chat_id)
            collector.request_baseline(added)
    return {"targets": ctx.visible_targets(request), "updated": len(ids)}


async def target_priority(
    request: Request, body: TargetPriority, *, ctx=Depends(current_context)
):
    ctx.require_live()
    ctx.require_chat(request, body.chat_id)
    store = ctx.app.state.store
    existing = next((t for t in store.targets() if t["chat_id"] == body.chat_id), None)
    if not existing:
        raise HTTPException(404, "This chat is not among the sources.")
    with store.transaction():
        store.set_target(
            body.chat_id,
            existing["title"],
            existing["kind"],
            bool(existing["enabled"]),
            priority=body.priority,
        )
        store.append(
            "target.priority",
            {
                "title": existing["title"],
                "priority": body.priority,
                "recheck": recheck_settings(store),
            },
            body.chat_id,
        )
    return {"targets": ctx.visible_targets(request)}


async def ignore_sources(
    request: Request, body: IgnoreSources, *, ctx=Depends(current_context)
):
    ctx.require_live()
    collector, store = (ctx.app.state.collector, ctx.app.state.store)
    ids = list(dict.fromkeys(body.chat_ids))
    for chat_id in ids:
        ctx.require_chat(request, chat_id)
    async with ctx.op_lock:
        targets = {t["chat_id"]: t for t in store.targets()}
        if any((chat_id not in targets for chat_id in ids)):
            raise HTTPException(404, "A selected chat is no longer among the sources.")
        if body.ignored and any(
            (
                collector.source_status.get(str(chat_id), {}).get("state")
                != "access_unconfirmed"
                for chat_id in ids
            )
        ):
            raise HTTPException(
                409, "Only sources not found in the last dialog check can be ignored."
            )
        with store.transaction():
            ignored = set(store.get_setting("ignored_source_warnings", []))
            for chat_id in ids:
                if (chat_id in ignored) == body.ignored:
                    continue
                if body.ignored:
                    ignored.add(chat_id)
                else:
                    ignored.discard(chat_id)
                target = targets[chat_id]
                store.append(
                    "target.changed",
                    {
                        "title": target["title"],
                        "enabled": bool(target["enabled"]),
                        "ignore_unconfirmed": body.ignored,
                        "reason": "source warning preference changed",
                    },
                    chat_id,
                )
            store.set_setting("ignored_source_warnings", sorted(ignored))
        current, parts, _ = ctx.scoped_status(ctx.app, ctx.visible_chats(request))
    return {"source_status": current["source_status"], "health": parts["sources"]}


async def target_remove(
    request: Request, chat_id: int, *, ctx=Depends(current_context)
):
    ctx.require_live()
    ctx.require_chat(request, chat_id)
    async with ctx.op_lock:
        result = ctx.remove_targets([chat_id])
    return {"targets": ctx.visible_targets(request), **result}


async def capture(body: Capture, *, ctx=Depends(current_context)):
    ctx.require_live()
    async with ctx.op_lock:
        with ctx.app.state.store.transaction():
            saved = body.model_dump()
            if "record_disabled_media" not in body.model_fields_set:
                saved["record_disabled_media"] = capture_settings(ctx.app.state.store)[
                    "record_disabled_media"
                ]
            ctx.save_capture(ctx.app.state.store, saved)
        ctx.app.state.collector.media_wakeup.set()
    return capture_settings(ctx.app.state.store)


async def clear_media_queue(body: ClearMediaQueue, *, ctx=Depends(current_context)):
    ctx.require_live()
    store = ctx.app.state.store
    async with ctx.op_lock:
        head = store.stats()["head"]
        if body.through_seq > (head["seq"] if head else 0):
            raise HTTPException(
                409,
                "The queue snapshot is newer than this workspace. Refresh and try again.",
            )
        cancelled = await complete_in_thread(store.clear_media_queue, body.through_seq)
        return {
            "cancelled": cancelled,
            "through_seq": body.through_seq,
            "media_jobs": store.media_stats(),
        }


async def set_recording(
    request: Request, body: recording.RecordingUpdate, *, ctx=Depends(current_context)
):
    ctx.require_live()
    try:
        for permission in body.permissions():
            access_check(
                request.state.principal, ctx.profile_id, (permission, None), {}
            )
    except Refused as exc:
        raise HTTPException(403, str(exc)) from None
    async with ctx.op_lock:
        try:
            changed, saved = recording.save(ctx.app.state.store, body)
        except recording.Invalid as exc:
            raise HTTPException(exc.status, str(exc)) from None
        collector = ctx.app.state.collector
        application = {"state": "applied"}
        if body.scope is not None:
            if not collector.running:
                application = {"state": "pending", "reason": "next_start"}
            else:
                try:
                    application["scope"] = await ctx.perform_operation(
                        collector.apply_scope
                    )
                except HTTPException as exc:
                    application = {
                        "state": "failed",
                        "status": exc.status_code,
                        "detail": exc.detail,
                    }
        return {
            "saved": True,
            **saved,
            "changed": changed,
            "application": application,
            "collector": {"running": collector.running, "phase": collector.phase},
        }


async def get_scope(*, ctx=Depends(current_context)):
    return ctx.scope_state()


async def set_scope(body: ScopeUpdate, *, ctx=Depends(current_context)):
    ctx.require_live()
    store, collector = (ctx.app.state.store, ctx.app.state.collector)
    async with ctx.op_lock:
        try:
            changed, _ = recording.save(store, recording.RecordingUpdate(scope=body))
        except recording.Invalid as exc:
            raise HTTPException(exc.status, str(exc)) from None
        if "scope" in changed and collector.running:
            await ctx.perform_operation(collector.apply_scope)
    return ctx.scope_state()


async def set_recheck(body: Recheck, *, ctx=Depends(current_context)):
    ctx.require_live()
    store = ctx.app.state.store
    async with ctx.op_lock:
        with store.transaction():
            for key, value in body.model_dump().items():
                store.set_setting(key, value)
            store.append(
                "recheck.changed",
                {
                    **body.model_dump(),
                    "meaning": "minutes between rechecks of priority sources and of every other source; 0 turns a tier off",
                },
            )
    return ctx.scope_state()


async def monitoring(body: Monitoring, *, ctx=Depends(current_context)):
    ctx.require_live()
    async with ctx.op_lock:
        store = ctx.app.state.store
        with store.transaction():
            previous = monitoring_settings(store)
            current = body.model_dump()
            if previous != current:
                store.set_setting("monitoring", current)
                store.append(
                    "monitoring.changed",
                    {
                        "before": previous,
                        "after": current,
                        "applies_to": "subsequent live updates for selected sources in this account profile",
                        "coverage": "disabled categories are intentionally not recorded; no backfill",
                        "history_snapshots": "explicit snapshots remain separate; embedded metadata is not redacted",
                    },
                )
    return current


async def control(action: Literal["start", "stop"], *, ctx=Depends(current_context)):
    collector = ctx.app.state.collector
    await ctx.operation(collector.start if action == "start" else collector.stop)
    return collector.status()


async def snapshot(request: Request, body: Snapshot, *, ctx=Depends(current_context)):
    ctx.require_chat(request, body.chat_id)
    if body.limit > tuning.value(ctx.app.state.store, "snapshot_max"):
        raise HTTPException(
            422,
            "The snapshot is larger than this workspace allows. Raise the limit in Parameters.",
        )
    return await ctx.operation(
        ctx.app.state.collector.snapshot, body.chat_id, body.limit
    )


async def history_status(*, ctx=Depends(current_context)):
    return ctx.app.state.collector.history.status()


async def history_action(
    action: str, options: HistoryOptions | None = None, *, ctx=Depends(current_context)
):
    if action not in ("start", "pause", "resume", "cancel"):
        raise HTTPException(404, "Unknown history action.")
    if action == "start":
        return await ctx.operation(ctx.app.state.collector.history.start, options)
    if options and options.model_fields_set:
        raise HTTPException(
            400, "History options are frozen at start; resume uses the saved choices."
        )
    return await ctx.operation(getattr(ctx.app.state.collector.history, action))


async def history_report(*, ctx=Depends(current_context)):
    try:
        report = ctx.app.state.collector.history.report()
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    return Response(
        canonical(report),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="tgwitness-history-report.json"'
        },
    )


async def get_parameters(*, ctx=Depends(current_context)):
    return tuning.described(ctx.app.state.store)


async def set_parameters(body: ParametersUpdate, *, ctx=Depends(current_context)):
    ctx.require_live()
    store = ctx.app.state.store
    try:
        saved, before, after = tuning.changes(store, body.values)
    except tuning.Invalid as exc:
        raise HTTPException(422, {"message": str(exc), "parameter": exc.key}) from None
    if after:
        with store.transaction():
            ctx.save_parameters(store, saved, before, after)
        ctx.app.state.alert_wakeup.set()
    return tuning.described(store)


async def chats(request: Request, *, ctx=Depends(current_context)):
    store = ctx.app.state.store
    overview = store.chat_overview()
    listed = [
        {**t, "enabled": bool(t["enabled"]), **overview.pop(t["chat_id"], {})}
        for t in store.targets()
    ]
    listed += [
        {"chat_id": chat_id, "title": None, "kind": None, "enabled": False, **extra}
        for chat_id, extra in overview.items()
    ]
    allowed = ctx.visible_chats(request)
    return {"chats": [c for c in listed if allowed is None or c["chat_id"] in allowed]}


async def interaction_preview(
    body: interactions.Preview, *, ctx=Depends(current_context)
):
    return await ctx.operation(interactions.preview, ctx.app.state.collector, body)


async def interaction_action(
    request: Request, body: interactions.Action, *, ctx=Depends(current_context)
):
    if ctx.visible_chats(request) is not None:
        if body.action == "open":
            raise HTTPException(
                403,
                "This access opens only chosen chats; this part of the workspace is closed to it.",
            )
        ctx.require_chat(request, body.chat_id)
    principal = request.state.principal
    operator = {
        "label": getattr(principal, "label", None) or ("Main administrator" if principal.admin else None),
        "owner": principal.owner,
        "admin": bool(principal.admin),
    }
    return await ctx.operation(
        interactions.execute, ctx.app.state.collector, body, ctx.queue_action, operator
    )


async def interaction_read_only(
    body: interactions.ReadOnly, *, ctx=Depends(current_context)
):
    ctx.require_live()
    return interactions.set_read_only(ctx.app.state.store, body.enabled)


async def interaction_state(
    request: Request, request_id: str, *, ctx=Depends(current_context)
):
    pending = interactions.requested(ctx.app.state.store, request_id)
    if not pending:
        raise HTTPException(404, "Unknown action request.")
    if ctx.visible_chats(request) is not None:
        ctx.require_chat(request, pending["request"].get("chat_id"))
    return interactions.progress(pending)


async def chat_messages(
    chat_id: int,
    before_id: int | None = None,
    limit: int = 60,
    after_id: int | None = None,
    *,
    ctx=Depends(current_context),
):
    if not 1 <= limit <= 200:
        raise HTTPException(422, "Limit must be 1–200.")
    if before_id is not None and after_id is not None:
        raise HTTPException(422, "Choose one message cursor.")
    return ctx.app.state.store.chat_messages(
        chat_id, before_id, limit, after_id=after_id
    )


async def chat_authors(chat_id: int, *, ctx=Depends(current_context)):
    return ctx.app.state.store.chat_authors(chat_id)


async def chat_profile(chat_id: int, *, ctx=Depends(current_context)):
    saved = ctx.app.state.store.events(chat_id, None, "source.profile", None, 1, None)
    return ctx.profile_view(saved[0] if saved else None)


async def chat_profile_save(chat_id: int, *, ctx=Depends(current_context)):
    return ctx.profile_view(
        await ctx.operation(ctx.app.state.collector.save_profile, chat_id)
    )


async def people_list(
    request: Request,
    chat_id: int = ApiPath(ge=-(2**63), le=2**63 - 1),
    quiet_days: int = Query(7, ge=1, le=365),
    offset: int = Query(0, ge=0, le=1000000),
    limit: int = Query(100, ge=1, le=200),
    mode: Literal["all", "quiet", "deleted", "departed", "never_posted"] = "all",
    *,
    ctx=Depends(current_context),
):
    value = await asyncio.to_thread(
        people.listing,
        ctx.app.state.store,
        chat_id,
        quiet_days=quiet_days,
        offset=offset,
        limit=limit,
        mode=mode,
    )
    await ctx.recheck_export_scope(request, {chat_id})
    return value


async def person_timeline(
    request: Request,
    chat_id: int = ApiPath(ge=-(2**63), le=2**63 - 1),
    user_id: int = ApiPath(ge=1, le=2**63 - 1),
    before: int | None = Query(None, ge=1, le=2**63 - 1),
    limit: int = Query(100, ge=1, le=200),
    quiet_days: int = Query(7, ge=1, le=365),
    *,
    ctx=Depends(current_context),
):
    try:
        value = await asyncio.to_thread(
            people.timeline,
            ctx.app.state.store,
            chat_id,
            user_id,
            before=before,
            limit=limit,
            quiet_days=quiet_days,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    await ctx.recheck_export_scope(request, {chat_id})
    return value


async def dossier_switch(
    request: Request, chat_id: int, body: DossierSwitch, *, ctx=Depends(current_context)
):
    ctx.require_live()
    dossier.set_enabled(ctx.app.state.store, chat_id, body.enabled)
    allowed = ctx.visible_chats(request)
    return {
        "enabled": body.enabled,
        "dossiers": [
            chat
            for chat in dossier.enabled_chats(ctx.app.state.store)
            if allowed is None or chat in allowed
        ],
    }


async def dossier_view(request: Request, chat_id: int, *, ctx=Depends(current_context)):
    title = ctx.dossier_title(chat_id)
    allowed = ctx.visible_chats(request)
    value = await asyncio.to_thread(
        dossier.signed,
        ctx.app.state.store,
        ctx.app.state.vault,
        chat_id,
        title,
        producer(),
        allowed_chats=allowed,
    )
    await ctx.recheck_export_scope(request, allowed)
    return value


async def dossier_export(
    request: Request, chat_id: int, *, ctx=Depends(current_context)
):
    path = await ctx.dossier_file(request, chat_id)
    return TemporaryDownload(
        path,
        filename="tgwitness-dossier-" + str(chat_id) + ".json",
        media_type="application/json",
    )


async def dossier_export_encrypted(
    request: Request,
    chat_id: int,
    body: ExportPassword,
    *,
    ctx=Depends(current_context),
):
    path = await ctx.dossier_file(request, chat_id, body.password, body.encryption)
    return TemporaryDownload(
        path,
        filename="tgwitness-dossier-" + str(chat_id) + "-encrypted." + body.encryption,
        media_type="application/zip" if body.encryption == "zip" else "application/octet-stream",
    )


async def notifications(request: Request, *, ctx=Depends(current_context)):
    lang = i18n.pick(
        request.cookies.get(i18n.COOKIE), request.headers.get("accept-language")
    )
    items = alerts.panel_items(
        ctx.app.state.store,
        i18n.words(lang),
        tuning.value(ctx.app.state.store, "panel_notifications"),
        allowed_chats=ctx.visible_chats(request),
        workspace_id=ctx.profile_id,
    )
    return {"items": items}


async def chat_scale(chat_id: int, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.chat_scale, chat_id)


async def avatar(request: Request, peer_id: int, *, ctx=Depends(current_context)):
    if ctx.app.state.store.get_setting("demo", False):
        raise HTTPException(404)
    allowed = ctx.visible_chats(request)
    if (
        allowed is not None
        and peer_id not in allowed
        and (not ctx.app.state.store.sender_in_chats(peer_id, allowed))
    ):
        raise HTTPException(404)
    path = await ctx.app.state.collector.avatar(peer_id)
    if not path:
        return Response(status_code=204)
    return FileResponse(
        path,
        media_type="image/jpeg",
        headers={"Cache-Control": "private, max-age=3600"},
    )


async def reveal_secret(
    body: Reveal, request: Request, *, ctx=Depends(current_context)
):
    ctx.require_chat(request, body.chat_id)
    if body.reason == "message" and body.message_id is None:
        raise HTTPException(422, "Select the message to reveal.")
    ctx.app.state.store.append(
        "panel.secret_revealed",
        {
            "chat_id": body.chat_id,
            "message_id": body.message_id,
            "reason": body.reason,
            "operator": request.state.principal.owner,
        },
    )
    return {"recorded": True}


async def media(
    request: Request, digest: str, inline: bool = False, *, ctx=Depends(current_context)
):
    if re.fullmatch("[0-9a-f]{64}", digest) is None:
        raise HTTPException(404)
    allowed = ctx.visible_chats(request)
    if allowed is not None and (
        not ctx.app.state.store.media_in_chats(digest, allowed)
    ):
        raise HTTPException(404)
    path = ctx.root / "media" / digest
    if path.is_symlink() or not path.is_file():
        raise HTTPException(404)
    if inline:
        from ..media_preview import content_type

        mime = await asyncio.to_thread(content_type, path)
        return FileResponse(
            path,
            media_type=mime,
            filename=digest,
            content_disposition_type="inline"
            if mime != "application/octet-stream"
            else "attachment",
            headers={
                "Content-Security-Policy": "default-src 'none'; media-src 'self'; img-src 'self'; style-src 'unsafe-inline'; sandbox"
            },
        )
    return FileResponse(path, media_type="application/octet-stream", filename=digest)


async def extension_list(*, ctx=Depends(current_context)):
    return {
        **ctx.app.state.extensions,
        "goal": extensions.workspace_goal(ctx.app.state.store),
    }


class ChatsOperations:
    def remove_targets(self, ids):
        store = self.app.state.store
        existing = {t["chat_id"]: t for t in store.targets()}
        if any((chat_id not in existing for chat_id in ids)):
            raise HTTPException(404, "This chat is not among the sources.")
        scope = scope_settings(store)
        additions = (
            set(ids) - set(scope["exclude"]) if scope["mode"] != "selected" else set()
        )
        if len(scope["exclude"]) + len(additions) > EXCLUDE_LIMIT:
            raise HTTPException(
                409,
                "The scope already excludes 5,000 chats, the most it keeps. Pause these chats instead, or switch the scope to chosen chats to remove them.",
            )
        with store.transaction():
            if additions:
                store.set_setting(
                    "scope",
                    {**scope, "exclude": sorted(set(scope["exclude"]) | additions)},
                )
            for chat_id in ids:
                store.remove_target(chat_id)
                removed_dossier = dossier.remove(store, chat_id, clear_cache=False)
                store.append(
                    "target.removed",
                    {
                        "title": existing[chat_id]["title"],
                        "dossier_removed": removed_dossier,
                        "excluded_from_scope": scope["mode"] != "selected",
                        "journal": "records already saved for this chat stay in the append-only journal",
                    },
                    chat_id,
                )
        pending = []
        for chat_id in ids:
            try:
                dossier.cache_path(store, chat_id).unlink(missing_ok=True)
            except OSError:
                pending.append(chat_id)
        return {
            "removed": len(ids),
            "excluded": len(additions),
            "cache_cleanup_pending": pending,
            "media": {"pending": "cancelled", "running": "may_finish", "saved": "kept"},
        }

    def save_capture(self, store, saved):
        store.set_setting("capture", normalize_capture(saved))
        store.append("capture.changed", capture_settings(store))

    def scope_state(self):
        collector = self.app.state.collector
        return {
            "settings": scope_settings(self.app.state.store),
            "recheck": recheck_settings(self.app.state.store),
            "folders": [
                {"id": f["id"], "title": f["title"]} for f in collector.folders.values()
            ],
            "warning": WIDE_WARNING,
        }

    def save_parameters(self, store, saved, before, after):
        store.set_setting("parameters", saved)
        store.append(
            "parameters.changed",
            {
                "before": before,
                "after": after,
                "applies": "from the next use of each value; Telegram client timeouts and retries from the next connection",
            },
        )

    def profile_view(self, event):
        if not event:
            return {"profile": None}
        return {
            "profile": {k: v for k, v in event["payload"].items() if k != "raw"},
            "seq": event["seq"],
            "observed_at": event["observed_at"],
        }

    def dossier_title(self, chat_id):
        if not self.app.state.store.get_setting("dossiers", {}).get(str(chat_id)):
            raise HTTPException(409, "Turn on people profiles for this chat first.")
        return next(
            (
                t["title"]
                for t in self.app.state.store.targets()
                if t["chat_id"] == chat_id
            ),
            None,
        )

    async def dossier_file(self, request, chat_id, password=None, encryption="zip"):
        title = self.dossier_title(chat_id)
        allowed = self.visible_chats(request)

        def build():
            value = dossier.signed(
                self.app.state.store,
                self.app.state.vault,
                chat_id,
                title,
                producer(),
                allowed_chats=allowed,
            )
            directory = self.root / "temporary-exports"
            directory.mkdir(mode=448, exist_ok=True)
            if directory.resolve().parent != self.root:
                raise ValueError(
                    "Temporary export directory must belong to this profile"
                )
            path = directory / (
                "tgwitness-export-dossier-" + secrets.token_hex(8) + ".json"
            )
            try:
                with path.open("xb") as out:
                    out.write(
                        json.dumps(value, ensure_ascii=False, indent=1).encode("utf-8")
                    )
                if password is not None:
                    path = encrypt_export(
                        path,
                        "json",
                        password,
                        "tgwitness-dossier-" + str(chat_id) + ".json",
                        mode=encryption,
                    )
                return path
            except BaseException:
                path.unlink(missing_ok=True)
                raise

        async with self.export_lock:
            path = await build_file(build)
        try:
            await self.recheck_export_scope(request, allowed)
            return path
        except BaseException:
            path.unlink(missing_ok=True)
            raise
