from .. import __version__
from .. import dossier
from .. import i18n
from .. import interactions
from .. import tuning
from ..access import POLICY
from ..access import Refused
from ..access import check as access_check
from ..collector import AUTHORIZATION_ERRORS
from ..collector import ProtectedSession
from ..evidence import LIMITS
from ..failures import describe, unexpected
from ..middleware import request_limit
from ..monitoring import capture_settings
from ..monitoring import monitoring_settings
from ..scope import recheck_settings
from ..security import KeyInUse
from ..telegram_client import FLOOD_ERRORS
from ..verify import fingerprint
from ..workers import complete_in_thread
from .dependencies import current_context
from .access import bearer
from datetime import datetime
from datetime import timezone
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials
from telethon.errors import RPCError
import asyncio
import logging
import re
import secrets
import time


async def installation_ready(*, ctx=Depends(current_context)):
    if not re.fullmatch("[0-9a-f]{64}", ctx.installation_id):
        raise HTTPException(404, "Not found")
    return Response(
        ctx.installation_id,
        media_type="text/plain",
        headers={"Cache-Control": "no-store"},
    )


async def locale(request: Request, *, ctx=Depends(current_context)):
    guide = request.query_params.get("scope") == "guide"
    languages = i18n.GUIDE_LANGUAGES if guide else i18n.LANGUAGES
    requested = request.query_params.get("lang")
    choice = requested if requested in languages else request.cookies.get(i18n.COOKIE)
    lang = i18n.pick(choice, request.headers.get("accept-language"), languages)
    return Response(
        i18n.script(lang, guide=guide), media_type="text/javascript; charset=utf-8"
    )


async def demo_access(request: Request, *, ctx=Depends(current_context)):
    if not ctx.local_demo_access(request):
        return {"available": False}
    return {"available": True, "token": ctx.app.state.local_demo_token}


async def status(request: Request, *, ctx=Depends(current_context)):
    from .. import ai, media_analysis
    from ..operator_privacy import connection_details, status_parts, without_diagnostics

    store, vault = (ctx.app.state.store, ctx.app.state.vault)
    allowed = ctx.visible_chats(request)
    collector_status, parts, targets = ctx.scoped_status(ctx.app, allowed)
    principal = request.state.principal
    collector_status, parts = status_parts(principal, collector_status, parts, allowed)
    result = {
        "workspace_id": ctx.profile_id,
        "demo": store.get_setting("demo", False),
        "analysis": {
            "enabled": ai.enabled(ctx.app.state)
            and (not store.get_setting("demo", False)),
            "media_available": media_analysis.available()
            and (not store.get_setting("demo", False)),
        },
        "collector": collector_status,
        "stats": store.stats(allowed),
        "health": parts,
        "history": ctx.app.state.collector.history.status()
        if allowed is None
        else None,
        "targets": targets,
        "capture": capture_settings(store),
        "monitoring": monitoring_settings(store),
        "scope": collector_status["scope"],
        "recheck": recheck_settings(store),
        "dossiers": [
            c for c in dossier.enabled_chats(store) if allowed is None or c in allowed
        ],
        "setup_answered": store.get_setting("setup", None) is not None,
        "setup_goal": (store.get_setting("setup", None) or {}).get("goal"),
        "actions": interactions.pace_status(store),
        "fingerprint": fingerprint(vault.public_key),
        "limitations": LIMITS,
        "chats_limited": allowed is not None,
        "assurance": bool(ctx.app.state.assurance),
    }
    if connection_details(principal, allowed):
        result.update(
            version=__version__,
            run_id=ctx.app.state.run_receipt["run_id"],
            protection={
                "vault_key_mode": vault.key_mode,
                "secrets_encrypted": True,
                "journal_encrypted_by_app": False,
                "media_encrypted_by_app": False,
            },
        )
    else:
        result["history"] = without_diagnostics(result["history"])
    if principal.admin or (principal.may("settings") and allowed is None):
        result["parameters"] = tuning.values(store)
    return result


async def get_events(
    request: Request,
    chat_id: int | None = None,
    message_id: int | None = None,
    kind: str | None = None,
    before: int | None = None,
    search: str | None = None,
    limit: int = 100,
    since: str | None = None,
    until: str | None = None,
    hide_system: bool = False,
    after: int | None = None,
    include_count: bool = False,
    slice_id: str | None = None,
    added_since: bool = False,
    *,
    ctx=Depends(current_context),
):
    if not 1 <= limit <= 500 or (search and len(search) > 200):
        raise HTTPException(
            422, "Limit must be 1–500; search must be at most 200 characters."
        )
    if kind and (len(kind) > 300 or len(kind.split(",")) > 16):
        raise HTTPException(422, "Choose at most 16 event types.")
    if (
        before is not None
        and after is not None
        or any(
            (
                value is not None and (not 0 <= value < 2**53)
                for value in (before, after)
            )
        )
    ):
        raise HTTPException(422, "Choose one valid journal cursor.")
    if slice_id:
        from ..board import Board

        def slice_window():
            try:
                with ctx.app.state.store.snapshot() as snapshot:
                    return Board(ctx.app.state.store, ctx.profile_id).journal_window(
                        snapshot.connection,
                        request.state.principal,
                        slice_id,
                        before,
                        after,
                        limit,
                        added_since,
                    )
            except Refused as exc:
                raise HTTPException(403, str(exc)) from None
            except KeyError:
                raise HTTPException(404, "Slice not found.") from None

        return await complete_in_thread(slice_window)
    if chat_id is not None:
        ctx.require_chat(request, chat_id)
    dates = []
    for value in (since, until):
        try:
            date = (
                datetime.fromisoformat(value)
                if value is not None and len(value) <= 64
                else None
            )
            if value is not None and (date is None or date.tzinfo is None):
                raise ValueError()
            dates.append(date.astimezone(timezone.utc) if date else None)
        except (ValueError, OverflowError):
            raise HTTPException(
                422, "Dates must be ISO timestamps with a timezone."
            ) from None
    if dates[0] is not None and dates[1] is not None and (dates[0] > dates[1]):
        raise HTTPException(
            422, "The start must precede the end of the selected period."
        )
    filters = dict(
        chat_id=chat_id,
        message_id=message_id,
        kind=kind,
        search=search,
        chat_ids=ctx.visible_chats(request),
        since=dates[0],
        until=dates[1],
        hide_system=hide_system,
        hide_admin=not request.state.principal.admin,
    )
    store = ctx.app.state.store

    def read_window():
        records = store.events(
            **filters, before=before, after=after, limit=limit + 1, timeout_s=2
        )
        more = len(records) > limit
        records = records[-limit:] if after is not None else records[:limit]
        older = newer = None
        if records:
            if after is not None:
                newer = records[0]["seq"] if more else None
                older = (
                    records[-1]["seq"]
                    if store.events(
                        **filters, before=records[-1]["seq"], limit=1, timeout_s=1
                    )
                    else None
                )
            else:
                older = records[-1]["seq"] if more else None
                if before is not None and store.events(
                    **filters, after=records[0]["seq"], limit=1, timeout_s=1
                ):
                    newer = records[0]["seq"]
        matched = None
        if include_count:
            try:
                matched = store.count_events(**filters, timeout_s=2)
            except TimeoutError:
                pass
        return {
            "events": records,
            "next_before": older,
            "next_after": newer,
            "matched": matched,
            "count_exact": matched is not None,
        }

    try:
        return await complete_in_thread(read_window)
    except TimeoutError:
        raise HTTPException(
            503, "The journal is busy. Narrow the filters and retry."
        ) from None


async def journal_stream(
    request: Request,
    after: int = 0,
    board_after: int = 0,
    credential: HTTPAuthorizationCredentials = Depends(bearer),
    *,
    ctx=Depends(current_context),
):
    from ..live_stream import LimitedStreamingResponse, stream

    if (
        not 0 <= after <= 9223372036854775807
        or not 0 <= board_after <= 9223372036854775807
    ):
        raise HTTPException(422, "Invalid journal cursor.")
    token = credential.credentials

    def authorize():
        if ctx.local_demo_access(request) and secrets.compare_digest(
            token, ctx.app.state.local_demo_token
        ):
            principal = request.state.principal
        else:
            principal = ctx.app.state.access.resolve(token, ctx.client_address(request))
        if principal is None:
            raise Refused("Access ended")
        access_check(principal, ctx.profile_id, POLICY["GET /api/stream"], {})
        request.state.stream_principal = principal
        return principal.chats(ctx.profile_id)

    def board_authorize():
        authorize()
        principal = request.state.stream_principal
        return principal if principal.may("board.read") else None

    async def updates():
        try:
            yield ": connected\n\n"
            async for item in stream(
                ctx.app.state.store,
                after,
                authorize,
                request.is_disconnected,
                board_after=board_after,
                board_authorize=board_authorize,
                workspace=ctx.profile_id,
                hide_admin=not request.state.principal.admin,
            ):
                yield item
        except Refused:
            yield "event: access-ended\ndata: {}\n\n"

    from ..access import digest

    return LimitedStreamingResponse(
        updates(),
        slots=ctx.app.state.access.stream_slots,
        owner=digest(token),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"},
    )


class SystemOperations:
    async def headers(self, request, call_next):
        if "/api/" in request.url.path and "ws" in request.query_params:
            workspace_path = re.match(
                "^/profiles/([a-f0-9]{32})/api/", request.url.path
            )
            selected = workspace_path[1] if workspace_path else self.profile_id
            if request.query_params.getlist("ws") != [selected]:
                return JSONResponse(
                    {"detail": "Unknown workspace selector."}, status_code=404
                )
        if request.headers.get("content-length", "").isdigit() and int(
            request.headers["content-length"]
        ) > request_limit(request.url.path):
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        audit = getattr(request.state, "audit", None)
        if audit and audit[0] is self.app:
            path = request.url.path
            if (
                request.method != "GET"
                or response.status_code == 403
                or any(
                    (
                        part in path
                        for part in (
                            "/export",
                            "/download",
                            "/media/",
                            "/replica/key",
                            "/anchor-request",
                        )
                    )
                )
            ):
                logging.getLogger("tgwitness.access").info(
                    "%s · %s %s → %d · %s",
                    audit[1].label,
                    request.method,
                    path,
                    response.status_code,
                    request.client.host if request.client else "unknown",
                )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    async def unexpected_error(self, request, exc):
        return JSONResponse(status_code=500, content={"detail": unexpected(exc, request.url.path)},
                            headers={"Cache-Control": "no-store"})

    async def validation_error(self, request, exc):
        return JSONResponse(
            status_code=422,
            content={
                "detail": [
                    {
                        "field": ".".join((str(p) for p in err["loc"])),
                        "message": err["msg"],
                    }
                    for err in exc.errors()
                ]
            },
        )

    async def perform_operation(self, call, *args):
        collector = self.app.state.collector
        client = collector.client
        try:
            return await asyncio.wait_for(
                call(*args),
                tuning.value(self.app.state.store, "operation_timeout_seconds"),
            )
        except FLOOD_ERRORS as exc:
            self.app.state.store.set_setting(
                "rpc_backoff_until",
                max(
                    time.time() + exc.seconds,
                    self.app.state.store.get_setting("rpc_backoff_until", 0),
                ),
            )
            raise HTTPException(
                429,
                {"message": "Telegram requested a pause.", "retry_after": exc.seconds},
                headers={"Retry-After": str(exc.seconds)},
            ) from None
        except AUTHORIZATION_ERRORS as exc:
            owner, name = (
                getattr(call, "__self__", None),
                getattr(call, "__name__", "operation"),
            )
            candidate = name in {
                "configure",
                "import_new_session",
                "start_phone",
                "start_qr",
                "send_code",
                "confirm_code",
                "confirm_password",
                "cancel_qr",
                "sign_out",
                "test_network",
            }
            if not candidate and (
                owner is collector
                or getattr(owner, "collector", None) is collector
                or (args and args[0] is collector)
            ):
                collector.handle_authorization_error(exc, name, client=client)
            raise HTTPException(
                400, "Telegram authorization expired. Sign in again."
            ) from None
        except RPCError as exc:
            raise HTTPException(400, describe(exc)) from None
        except (ProtectedSession, KeyInUse, interactions.AccountRestricted) as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        except (TimeoutError, OSError, ConnectionError) as exc:
            raise HTTPException(503, describe(exc)) from None

    async def operation(self, call, *args, qr_request=None):
        collector = self.app.state.collector
        collector.foreground += 1
        try:
            return await self.guarded_operation(call, *args, qr_request=qr_request)
        finally:
            collector.foreground -= 1
            collector.close_when_idle()

    async def guarded_operation(self, call, *args, qr_request=None):
        self.require_live()
        async with self.op_lock:
            self.require_live()
            if self.app.state.collector.export_claim and getattr(
                call, "__name__", ""
            ) in {
                "configure",
                "import_new_session",
                "start_phone",
                "start_qr",
                "send_code",
                "confirm_code",
                "confirm_password",
                "sign_out",
                "forget_session",
                "set_network",
                "set_route_policy",
                "apply",
                "dialogs",
                "save_profile",
                "preview",
                "execute",
                "run_queued",
                "check_current",
                "test_network",
                "control",
                "update_profile",
                "update_privacy",
                "update_global",
                "set_avatar",
                "remove_avatar",
            }:
                raise HTTPException(
                    409,
                    "This account is busy. Pause its current task before another Telegram operation.",
                )
            collector = self.app.state.collector
            if not collector.running and getattr(call, "__name__", "") in {
                "dialogs",
                "save_profile",
                "preview",
                "execute",
                "run_queued",
            }:
                owner = "manual:" + secrets.token_hex(16)
                if not collector.reserve_export(owner):
                    raise HTTPException(
                        409,
                        "This account is busy. Pause its current task before another Telegram operation.",
                    )
                try:
                    return await self.perform_operation(call, *args)
                finally:
                    try:
                        await collector.avatar_history.close()
                    finally:
                        collector.release_export(owner)
            if qr_request is not None:
                principal = await self.identify(qr_request, await bearer(qr_request))
                await self.authenticate(qr_request, principal)
                self.qr_access_session = principal.session_id
                self.qr_access_candidate = None
                try:
                    result = await self.perform_operation(call, *args)
                    self.qr_access_candidate = collector.login_client
                    await self.authenticate(qr_request, await self.identify(qr_request, await bearer(qr_request)))
                    return result
                except BaseException:
                    await collector.cancel_login()
                    collector.phase = collector.resting_phase()
                    self.qr_access_session = None
                    self.qr_access_candidate = None
                    raise
            return await self.perform_operation(call, *args)

    def queue_action(self, run_at, body):

        async def run():
            store = self.app.state.store
            while interactions.waiting(store, body.request_id):
                wait = (
                    max(run_at, store.get_setting("rpc_backoff_until", 0)) - time.time()
                )
                if wait <= 0:
                    try:
                        await self.operation(
                            interactions.run_queued, self.app.state.collector, body
                        )
                    except HTTPException as exc:
                        interactions.abandon(store, str(exc.detail), body.request_id)
                    return
                await asyncio.sleep(wait)

        task = asyncio.create_task(run())
        self.action_tasks.add(task)
        task.add_done_callback(self.action_tasks.discard)
