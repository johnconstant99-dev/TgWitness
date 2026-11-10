from .. import persona
from .. import tuning
from ..account_import import check_session
from ..account_import import import_accounts
from ..account_import import session_key
from ..app import AccountImport
from ..app import AccountPassword
from ..app import Code
from ..app import Credentials
from ..app import EndSession
from ..app import ExportPlan
from ..app import IndependentSession
from ..app import MultiExportStart
from ..app import Password
from ..app import Phone
from ..app import PhoneLogin
from ..app import ProfileCreate
from ..app import ProfileGroup
from ..app import ProfileGroupAssign
from ..app import ProfileImport
from ..app import client_languages
from ..app import panel_language
from ..network import NetworkConfig
from ..profiles import GROUP_SECTIONS
from ..profiles import JournalNotExported
from ..profiles import Profiles
from ..proxy_catalog import NoProxyAvailable
from ..failures import describe
from .dependencies import current_context
from contextlib import suppress
from cryptography.exceptions import InvalidSignature
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi.responses import FileResponse
import asyncio
import base64
import io

IMPORT_REFUSED = ("This server runs an attested deployment, so it does not collect on an imported key: that key also "
                  "exists outside this server and the recipient cannot tell who else holds it. Use the same file for "
                  "an independent login instead, or sign in by phone or QR. Either way the key is created here and "
                  "the attestation covers it.")


def refuse_imported_session():
    from .. import assurance

    if assurance.attested_deployment():
        raise HTTPException(409, IMPORT_REFUSED)


async def profiles_list(request: Request, *, ctx=Depends(current_context)):
    from ..operator_privacy import status_parts

    principal, listed = (request.state.principal, [])
    for entry in ctx.app.state.profiles.summary():
        if not principal.opens(entry["id"]):
            continue
        allowed = principal.chats(entry["id"])
        if allowed is not None:
            workspace = ctx.app.state.profiles.entries[entry["id"]].get("app")
            current, parts, targets = (
                ctx.scoped_status(workspace, allowed, entry["collector"])
                if workspace
                else (None, None, [])
            )
            entry = {
                **entry,
                "stats": None,
                "sources_enabled": sum((bool(t["enabled"]) for t in targets)),
                "collector": current,
                "health": parts,
                "sources_total": len(targets),
            }
        current, parts = status_parts(
            principal, entry["collector"], entry["health"], allowed
        )
        listed.append({**entry, "collector": current, "health": parts})
    return {
        "profiles": listed,
        "limit": Profiles.MAX_PROFILES,
        "model": "independent account collectors and signing identities",
    }


async def profiles_create(body: ProfileCreate, *, ctx=Depends(current_context)):
    ctx.require_live()
    if not body.label.strip():
        raise HTTPException(422, "Enter an account label.")
    try:
        return await ctx.app.state.profiles.create(body.label.strip(), body.group)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def profile_groups(request: Request, *, ctx=Depends(current_context)):
    return ctx.groups_view(request.state.principal)


async def profile_group_create(body: ProfileGroup, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        await ctx.app.state.profiles.save_group(
            None, body.label.strip(), body.template, body.sections
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return ctx.groups_view()


async def profile_group_update(
    group_id: str, body: ProfileGroup, *, ctx=Depends(current_context)
):
    ctx.require_live()
    try:
        await ctx.app.state.profiles.save_group(
            group_id, body.label.strip(), body.template, body.sections
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return ctx.groups_view()


async def profile_group_delete(group_id: str, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        await ctx.app.state.profiles.delete_group(group_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return ctx.groups_view()


async def profile_group_apply(group_id: str, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        return {
            **await ctx.app.state.profiles.apply_group(group_id),
            **ctx.groups_view(),
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def profile_group_assign(
    profile_id: str, body: ProfileGroupAssign, *, ctx=Depends(current_context)
):
    ctx.require_live()
    try:
        await ctx.app.state.profiles.assign(profile_id, body.group)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return ctx.groups_view()


async def profiles_import(
    body: ProfileImport, request: Request, *, ctx=Depends(current_context)
):
    ctx.require_live()
    if not body.new_session:
        refuse_imported_session()
    if (body.api_id is None) != (body.api_hash is None):
        raise HTTPException(
            422, "Provide both API ID and API hash, or leave both empty."
        )
    try:
        account = await asyncio.to_thread(
            import_accounts,
            [f.model_dump() for f in body.files],
            body.passcode,
            body.new_session,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    if not account.get("session"):
        raise HTTPException(
            400,
            "These files hold no login session. Add the .session or TData of the account.",
        )
    if bool(account.get("api_id")) != bool(account.get("api_hash")):
        raise HTTPException(
            422,
            "Session found, but its application settings are incomplete. Supply both API ID and API hash in the JSON, or select the session file without this JSON to use the built-in app settings.",
        )
    registry = ctx.app.state.profiles
    expected, key = (account.get("expected_user_id"), session_key(account["session"]))
    holder = registry.holder(expected, key)
    if holder:
        raise HTTPException(
            409,
            "This Telegram account already has a workspace: " + holder["label"] + ".",
        )
    owner = object()
    release = release_account = None
    try:
        release = registry.reserve_session(key, owner)
        if expected is not None:
            release_account = registry.reserve_account(expected, owner)
    except ValueError as exc:
        if release:
            release()
        raise HTTPException(409, str(exc)) from None
    entry = child = None
    label = body.label.strip() or (
        body.files[0].name.rsplit(".", 1)[0][:80] or "Imported account"
    )
    try:
        entry = await registry.create(label, body.group)
        child = registry.entries[entry["id"]]["app"]
        if child is None:
            raise ValueError("The new workspace could not start.")
        collector = child.state.collector
        registry.transfer_session(key, owner, collector, expected)
        async with child.state.operation_lock:
            if child.state.closing:
                raise ValueError("The new workspace could not start.")
            if body.route:
                from ..guided_connection import adopt_route

                await adopt_route(child, body.route, body.route_consent)
            connect = (
                collector.import_new_session
                if body.new_session
                else collector.configure
            )
            extra = (
                (account.get("formats", []), account.get("two_factor_password", ""))
                if body.new_session
                else ()
            )
            outcome = await asyncio.wait_for(
                connect(
                    body.api_id or account.get("api_id"),
                    body.api_hash or account.get("api_hash"),
                    account["session"],
                    expected,
                    account.get("client_profile"),
                    client_languages(request),
                    *extra,
                ),
                tuning.value(ctx.app.state.store, "operation_timeout_seconds"),
            )
            account_info = child.state.store.get_setting("account", {}) or {}
            if outcome["step"] == "authorized":
                with suppress(Exception):
                    await asyncio.wait_for(collector.avatar(account_info.get("id")), 20)
                await collector.stop()
    except (Exception, asyncio.CancelledError) as exc:
        retained = bool(
            entry
            and child
            and body.new_session
            and (
                child.state.vault.read("independent_login")
                or child.state.vault.read("credentials").get("session")
            )
        )
        if entry is not None and (not retained):
            with suppress(Exception):
                await registry.delete(entry["id"], require_export=False)
        if isinstance(exc, asyncio.CancelledError):
            raise
        reason = (
            str(exc)
            if isinstance(exc, (ValueError, NoProxyAvailable))
            else "Telegram did not answer in time. Try again later."
            if isinstance(exc, TimeoutError)
            else describe(exc)
        )
        if retained:
            return {
                "profile": entry,
                "step": "retry",
                "error": reason,
                "formats": account.get("formats", []),
            }
        raise HTTPException(400, "Not imported: " + reason) from None
    finally:
        if release_account:
            release_account()
        release()
    return {
        "profile": entry,
        **outcome,
        "account": {
            "id": account_info.get("id"),
            "username": account_info.get("username"),
            "name": account_info.get("name"),
        },
        "formats": account.get("formats", []),
    }


async def profiles_check(
    body: ProfileImport, request: Request, *, ctx=Depends(current_context)
):
    ctx.require_live()
    if (body.api_id is None) != (body.api_hash is None):
        raise HTTPException(
            422, "Provide both API ID and API hash, or leave both empty."
        )
    try:
        account = await asyncio.to_thread(
            import_accounts, [f.model_dump() for f in body.files], body.passcode
        )
    except (ValueError, OSError) as exc:
        return {"state": "invalid", "message": str(exc)}
    if not account.get("session"):
        return {
            "state": "invalid",
            "message": "These files hold no login session. Add the .session or TData of the account.",
        }
    if bool(account.get("api_id")) != bool(account.get("api_hash")):
        return {
            "state": "invalid",
            "message": "Session found, but its application settings are incomplete. Supply both API ID and API hash in the JSON, or select the session file without this JSON to use the built-in app settings.",
        }
    registry, key = (ctx.app.state.profiles, session_key(account["session"]))
    holder = registry.holder(account.get("expected_user_id"), key)
    if holder:
        return {
            "state": "duplicate",
            "message": "This Telegram account already has a workspace: "
            + holder["label"]
            + ".",
        }
    try:
        release = registry.reserve_session(key, object())
    except ValueError as exc:
        return {"state": "duplicate", "message": str(exc)}
    tunnel = None
    try:
        route = NetworkConfig(kind="direct") if body.route == "direct" else None
        if body.route == "warp":
            if getattr(ctx.app.state, "check_tunnel", None) is None:
                from ..guided_connection import CheckTunnel

                ctx.app.state.check_tunnel = CheckTunnel(
                    ctx.app.state.connection.portable
                )
            try:
                route = await ctx.app.state.check_tunnel.acquire(body.route_consent)
            except (ValueError, OSError) as exc:
                return {"state": "unchecked", "message": describe(exc)}
            tunnel = ctx.app.state.check_tunnel
        result = await check_session(
            ctx.app.state.collector,
            account,
            body.api_id,
            body.api_hash,
            client_languages(request),
            route,
        )
    finally:
        if tunnel:
            await tunnel.release()
        release()
    holder = (
        registry.holder(result["account"]["id"]) if result["state"] == "alive" else None
    )
    if holder:
        return {
            "state": "duplicate",
            "message": "This Telegram account already has a workspace: "
            + holder["label"]
            + ".",
        }
    return {**result, "formats": account.get("formats", [])}


async def multi_export_start(
    request: Request, body: MultiExportStart, *, ctx=Depends(current_context)
):
    if not ctx.opens_chat_everywhere(
        request.state.principal, body.chat_id, [body.lead, *body.profiles]
    ):
        raise HTTPException(
            403, "This access does not open this chat in every chosen account."
        )
    return await ctx.operation(
        ctx.app.state.multi_export.start,
        body.chat_id,
        body.profiles,
        body.lead,
        panel_language(request),
        body.selection.model_dump(),
        body.transport,
        body.username,
    )


async def multi_export_plan(
    request: Request, body: ExportPlan, *, ctx=Depends(current_context)
):
    from .. import export_plan

    ctx.require_live()
    principal = request.state.principal

    def allowed(profile_id, chat_id):
        return principal.opens(profile_id) and (chat_id is None or principal.chats(profile_id) is None
                                                or chat_id in principal.chats(profile_id))

    try:
        return await ctx.operation(export_plan.plan, ctx.app.state.profiles,
                                   ctx.app.state.multi_export, body.link, allowed)
    except export_plan.AccessDenied as exc:
        raise HTTPException(403, str(exc)) from None


async def multi_export_current(
    request: Request, chat_id: int | None = None, *, ctx=Depends(current_context)
):
    return (
        ctx.app.state.multi_export.public(chat_id=chat_id)
        if ctx.multi_visible(request, chat_id=chat_id)
        else {"phase": "none"}
    )


async def multi_export_jobs(request: Request, *, ctx=Depends(current_context)):
    return {
        "jobs": [
            job
            for job in ctx.app.state.multi_export.list_jobs()
            if ctx.multi_visible(request, job["id"])
        ]
    }


async def multi_export_poll(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    return (
        ctx.app.state.multi_export.poll(export_id)
        if ctx.multi_visible(request, export_id)
        else {"phase": "unknown"}
    )


async def multi_export_pause(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    if not ctx.multi_visible(request, export_id):
        raise HTTPException(
            403, "This access does not open every participating account."
        )
    return await ctx.app.state.multi_export.pause(export_id)


async def multi_export_resume(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    if not ctx.multi_visible(request, export_id):
        raise HTTPException(
            403, "This access does not open every participating account."
        )
    return await ctx.operation(ctx.app.state.multi_export.resume, export_id)


async def multi_export_cancel(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    if not ctx.multi_visible(request, export_id):
        raise HTTPException(
            403, "This access does not open this chat in every chosen account."
        )
    return await ctx.operation(ctx.app.state.multi_export.cancel, export_id)


async def multi_export_download(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    path = (
        ctx.app.state.multi_export.result_path(export_id)
        if ctx.multi_visible(request, export_id)
        else None
    )
    if not path:
        raise HTTPException(404, "No finished export is available to download.")
    return FileResponse(
        path,
        filename=ctx.app.state.multi_export.public(export_id).get(
            "filename", "tgwitness-chat-export.zip"
        ),
        media_type="application/zip",
    )


async def profiles_rename(
    profile_id: str, body: ProfileCreate, *, ctx=Depends(current_context)
):
    ctx.require_live()
    if not body.label.strip():
        raise HTTPException(422, "Enter an account label.")
    try:
        return await ctx.app.state.profiles.rename(profile_id, body.label.strip())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def profiles_delete(profile_id: str, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        return await ctx.app.state.profiles.delete(profile_id)
    except JournalNotExported as exc:
        raise HTTPException(409, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


async def configure(
    body: Credentials, request: Request, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.configure,
        body.api_id,
        body.api_hash,
        body.session,
        body.expected_user_id,
        body.client_profile,
        client_languages(request),
    )


async def start_phone(
    body: PhoneLogin, request: Request, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.start_phone,
        body.phone,
        body.api_id,
        body.api_hash,
        body.client_profile,
        client_languages(request),
    )


async def independent_session(
    body: IndependentSession, request: Request, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.import_new_session,
        body.api_id,
        body.api_hash,
        body.session,
        body.expected_user_id,
        body.client_profile,
        client_languages(request),
        body.formats,
        body.two_factor_password,
    )


async def import_account(body: AccountImport, *, ctx=Depends(current_context)):
    ctx.require_live()
    if not body.new_session:
        refuse_imported_session()
    try:
        result = await asyncio.to_thread(
            import_accounts,
            [item.model_dump() for item in body.files],
            body.passcode,
            body.new_session,
        )
        if not result["has_authorization"]:
            raise ValueError(
                "No session — only application settings. Add a .session or TData file, or sign in by phone or QR."
            )
        if bool(result.get("api_id")) != bool(result.get("api_hash")):
            raise ValueError(
                "Session found, but its application settings are incomplete. Supply both API ID and API hash in the JSON, or select the session file without this JSON to use the built-in app settings."
            )
        return result
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


async def import_preview(body: AccountImport, *, ctx=Depends(current_context)):
    ctx.require_live()
    from ..account_import import preview

    return await asyncio.to_thread(
        preview, [item.model_dump() for item in body.files], body.passcode
    )


async def start_qr(
    body: Credentials, request: Request, *, ctx=Depends(current_context)
):
    import qrcode
    from qrcode.image.svg import SvgPathImage

    result = await ctx.operation(
        ctx.app.state.collector.start_qr,
        body.api_id,
        body.api_hash,
        body.client_profile,
        client_languages(request),
        qr_request=request,
    )
    url = result.pop("url")
    output = io.BytesIO()
    qrcode.make(url, image_factory=SvgPathImage, border=4).save(output)
    return {
        **result,
        "image": "data:image/svg+xml;base64,"
        + base64.b64encode(output.getvalue()).decode("ascii"),
    }


async def poll_qr(login_id: str, *, ctx=Depends(current_context)):
    return ctx.app.state.collector.poll_qr(login_id)


async def cancel_qr(login_id: str, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.cancel_qr, login_id)


async def phone(body: Phone, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.send_code, body.phone)


async def code(body: Code, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.confirm_code, body.code)


async def password(body: Password, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.confirm_password, body.password)


async def logout(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.sign_out)


async def forget_session(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.forget_session)


async def account_sessions(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.account_sessions)


async def end_account_session(body: EndSession, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.end_session, body.hash)


async def end_other_account_sessions(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.terminate_all_other_sessions)


async def make_only_account_session(*, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.collector.make_only_session)


async def change_account_password(
    body: AccountPassword, *, ctx=Depends(current_context)
):
    return await ctx.operation(
        ctx.app.state.collector.change_password,
        body.current_password,
        body.new_password,
        body.hint,
    )


async def account_read(*, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.read, ctx.app.state.collector)


async def account_profile(body: persona.Profile, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.update_profile, ctx.app.state.collector, body)


async def account_privacy(body: persona.Privacy, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.update_privacy, ctx.app.state.collector, body)


async def account_global(body: persona.Global, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.update_global, ctx.app.state.collector, body)


async def account_avatar(body: persona.Avatar, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.set_avatar, ctx.app.state.collector, body)


async def account_avatar_remove(*, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(persona.remove_avatar, ctx.app.state.collector)


async def account_avatar_view(*, ctx=Depends(current_context)):
    ctx.require_live()
    found = await ctx.operation(persona.photo, ctx.app.state.collector)
    if found is None:
        raise HTTPException(404, "The account has no profile photo.")
    data, media_type = found
    return Response(data, media_type=media_type, headers={"Cache-Control": "no-store"})


class AccountsOperations:
    def end_qr_session(self, session_id):
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if current is not self.login_loop:
            if not self.login_loop.is_closed():
                self.login_loop.call_soon_threadsafe(self.end_qr_session, session_id)
            return
        if self.qr_access_session != session_id:
            return
        collector = self.app.state.collector
        candidate = self.qr_access_candidate
        if candidate is None or collector.login_client is not candidate:
            return
        if collector.qr_task:
            collector.qr_task.cancel()

        async def cleanup():
            async with self.op_lock:
                if self.qr_access_session == session_id and collector.login_client is candidate:
                    await collector.cancel_login()
                    collector.phase = collector.resting_phase()
                    self.qr_access_session = None
                    self.qr_access_candidate = None

        task = asyncio.create_task(cleanup())
        self.action_tasks.add(task)
        task.add_done_callback(self.action_tasks.discard)

    def groups_view(self, principal=None):
        registry = self.app.state.profiles
        groups = []
        for group in registry.groups():
            members = registry.members(group["id"])
            if principal and (not principal.admin):
                members = [pid for pid in members if principal.opens(pid)]
                if not members:
                    continue
                if not principal.opens(group.get("template") or ""):
                    group = {**group, "template": None}
            groups.append({**group, "members": members})
        return {"groups": groups, "sections": list(GROUP_SECTIONS)}

    def opens_chat_everywhere(self, principal, chat_id, profile_ids):
        return all(
            (
                principal.opens(pid)
                and (principal.chats(pid) is None or chat_id in principal.chats(pid))
                for pid in profile_ids
            )
        )

    def multi_visible(self, request, export_id=None, chat_id=None):
        try:
            state = self.app.state.multi_export.public(export_id, chat_id)
        except (ValueError, KeyError, OSError, InvalidSignature):
            raise HTTPException(404, "Unknown or invalid distributed export.") from None
        if not state.get("id"):
            return True
        return not state or self.opens_chat_everywhere(
            request.state.principal,
            state["chat_id"],
            [state["lead"], *(w["profile_id"] for w in state["workers"])],
        )
