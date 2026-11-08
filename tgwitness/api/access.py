from .. import health
from .. import witness_api
from ..access import AdminSettings
from ..access import GrantSettings
from ..access import POLICY
from ..access import Refused
from ..access import check as access_check
from ..app import AccessLogin
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
import ipaddress
import secrets


bearer = HTTPBearer(auto_error=False)


async def identify(
    request: Request,
    credential: HTTPAuthorizationCredentials = Depends(bearer),
    *,
    ctx=Depends(current_context),
):
    principal = None
    if credential:
        if ctx.local_demo_access(request) and secrets.compare_digest(
            credential.credentials.encode(), ctx.app.state.local_demo_token.encode()
        ):
            principal = ctx.app.state.access.principal({"owner": "admin", "id": None})
        else:
            try:
                principal = ctx.app.state.access.resolve(
                    credential.credentials, ctx.client_address(request)
                )
            except Refused as exc:
                raise HTTPException(403, str(exc)) from None
    if principal is None:
        ctx.reject_access(
            request,
            "Enter the panel access token from panel-token.txt in your data directory.",
        )
    request.state.principal, request.state.audit = (principal, (ctx.app, principal))
    return principal


async def authenticate(
    request: Request, principal=Depends(identify), *, ctx=Depends(current_context)
):
    route = request.scope.get("route")
    rule = POLICY.get(request.method + " " + route.path) if route else None
    try:
        access_check(principal, ctx.profile_id, rule, request.path_params)
    except Refused as exc:
        raise HTTPException(403, str(exc)) from None
    return principal


async def authenticate_witness(
    request: Request,
    credential: HTTPAuthorizationCredentials = Depends(bearer),
    *,
    ctx=Depends(current_context),
):
    entry = (
        witness_api.match(ctx.app.state.vault, credential.credentials)
        if credential
        else None
    )
    if not entry:
        ctx.reject_access(request, "Unknown witness token.")
    return entry


async def access_login(
    request: Request, body: AccessLogin, *, ctx=Depends(current_context)
):
    try:
        result = ctx.app.state.access.login(
            body.token.strip(),
            ctx.client_address(request),
            request.headers.get("user-agent"),
        )
    except Refused as exc:
        raise HTTPException(403, str(exc)) from None
    if result is None:
        ctx.reject_access(
            request,
            "Unknown access token. Use the panel token from panel-token.txt or a token issued by the administrator.",
        )
    session, principal = result
    return {"session": session, "me": principal.public()}


async def access_logout(principal=Depends(identify), *, ctx=Depends(current_context)):
    if principal.session_id:
        ctx.app.state.access.end(principal.session_id, "signed out")
    return {"signed_out": True}


async def access_me(principal=Depends(identify), *, ctx=Depends(current_context)):
    return principal.public()


async def access_overview(request: Request, *, ctx=Depends(current_context)):
    return ctx.access_state(request)


async def access_issue(
    request: Request, body: GrantSettings, *, ctx=Depends(current_context)
):
    try:
        token, grant = ctx.app.state.access.issue(ctx.known_workspaces(body))
    except Refused as exc:
        raise HTTPException(422, str(exc)) from None
    return {"token": token, "id": grant["id"], **ctx.access_state(request)}


async def access_change(
    request: Request,
    grant_id: str,
    body: GrantSettings,
    *,
    ctx=Depends(current_context),
):
    try:
        ctx.app.state.access.change(grant_id, ctx.known_workspaces(body))
    except Refused as exc:
        raise HTTPException(422, str(exc)) from None
    return ctx.access_state(request)


async def access_revoke(
    request: Request, grant_id: str, *, ctx=Depends(current_context)
):
    try:
        ctx.app.state.access.revoke(grant_id)
    except Refused as exc:
        raise HTTPException(404, str(exc)) from None
    return ctx.access_state(request)


async def access_end_session(
    request: Request, session_id: str, *, ctx=Depends(current_context)
):
    if not ctx.app.state.access.end(session_id, "ended by the administrator"):
        raise HTTPException(404, "This session has already ended.")
    return ctx.access_state(request)


async def access_admin(
    request: Request, body: AdminSettings, *, ctx=Depends(current_context)
):
    ctx.app.state.access.set_admin(body)
    return ctx.access_state(request)


async def access_rotate_token(request: Request, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        token, ended = ctx.app.state.access.rotate_token()
    except Refused as exc:
        raise HTTPException(409, str(exc)) from None
    session, principal = ctx.app.state.access.login(
        token, ctx.client_address(request), None
    )
    return {
        "token": token,
        "session": session,
        "me": principal.public(),
        "sessions_ended": ended,
    }


async def access_console(after: int = 0, *, ctx=Depends(current_context)):
    console = ctx.app.state.access.console
    if after > console.counter:
        after = 0
    lines = console.after(after)
    return {"lines": lines, "last": lines[-1]["n"] if lines else after}


class AccessOperations:
    def local_demo_access(self, request):
        if (
            not self.demo
            or not self.allow_profiles
            or (not self.app.state.store.get_setting("demo", False))
            or (len(self.app.state.profiles.entries) != 1)
            or self.app.state.vault.read("credentials").get("session")
        ):
            return False
        return self.direct_local(request)

    def direct_local(self, request):
        try:
            if (
                not request.client
                or not ipaddress.ip_address(request.client.host).is_loopback
            ):
                return False
            host = request.url.hostname
            if host != "localhost" and (not ipaddress.ip_address(host).is_loopback):
                return False
        except ValueError:
            return False
        if any(
            (
                name in request.headers
                for name in (
                    "forwarded",
                    "x-forwarded-for",
                    "x-forwarded-host",
                    "x-forwarded-proto",
                    "x-real-ip",
                    "cf-connecting-ip",
                )
            )
        ):
            return False
        if request.headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
            return False
        origin = request.headers.get("origin")
        return origin is None or origin == str(request.url).split("/api/", 1)[0]

    def reject_access(self, request, detail):
        raise HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})

    def client_address(self, request):
        return request.client.host if request.client else "unknown"

    def visible_chats(self, request):
        return request.state.principal.chats(self.profile_id)

    def visible_targets(self, request):
        allowed = self.visible_chats(request)
        return [
            t
            for t in self.app.state.store.targets()
            if allowed is None or t["chat_id"] in allowed
        ]

    def require_chat(self, request, chat_id):
        allowed = self.visible_chats(request)
        if allowed is not None and chat_id not in allowed:
            raise HTTPException(403, "This chat is not open to this access.")

    def scoped_status(self, workspace, allowed, current=None):
        current = dict(current or workspace.state.collector.status())
        if allowed is not None:
            store = workspace.state.store
            current["source_status"] = {
                chat: status
                for chat, status in current.get("source_status", {}).items()
                if int(chat) in allowed
            }
            current["media_jobs"] = store.media_stats(allowed)
            current["media_pending"] = sum(
                (
                    n
                    for state, n in current["media_jobs"].items()
                    if state in ("queued", "running", "retry")
                )
            )
            current["oldest_pending_media_at"] = store.media_oldest(allowed)
            recheck = current.get("recheck")
            current["recheck"] = None
            if recheck and (records := store.events(kind="recheck.completed", limit=1)):
                results = [
                    r
                    for r in records[0]["payload"].get("chats", [])
                    if r.get("chat_id") in allowed
                ]
                if results:
                    current["recheck"] = {
                        "at": recheck.get("at") or records[0]["observed_at"],
                        "chats": len(results),
                        "errors": sum(("error" in r for r in results)),
                        **{
                            key: sum((r.get(key, 0) for r in results))
                            for key in ("recovered", "edited", "missing", "checked")
                        },
                    }
            if (
                current.get("chat_export")
                and current["chat_export"].get("chat_id") not in allowed
            ):
                current["chat_export"] = None
            if current.get("scope"):
                current["scope"] = {
                    **current["scope"],
                    "exclude": [
                        chat
                        for chat in current["scope"].get("exclude", [])
                        if chat in allowed
                    ],
                }
        targets = [
            t
            for t in workspace.state.store.targets()
            if allowed is None or t["chat_id"] in allowed
        ]
        parts = health.collector_of(
            workspace.state,
            current,
            enabled_sources=sum((bool(t["enabled"]) for t in targets)),
        )
        return (current, parts, targets)

    def require_live(self):
        if self.app.state.closing:
            raise HTTPException(
                503, "This workspace is closing. Wait for it to finish."
            )
        if self.app.state.store.get_setting("demo", False):
            raise HTTPException(
                409,
                "This is a synthetic demo. Start a separate data directory for real observation.",
            )

    def require_external(self, enabled):
        if enabled and (not self.app.state.collector.route_policy()["outside_enabled"]):
            raise HTTPException(
                409,
                "This feature needs external requests. Allow them in Settings first.",
            )

    def known_workspaces(self, settings):
        unknown = set(settings.workspaces) - set(self.app.state.profiles.entries)
        if unknown:
            raise HTTPException(422, "Unknown workspace.")
        if set(settings.groups) - {g["id"] for g in self.app.state.profiles.groups()}:
            raise HTTPException(422, "Unknown account group.")
        from ..showcase import validate_scope

        validate_scope(self.app.state.profiles, settings)
        return settings

    def access_state(self, request):
        return {
            **self.app.state.access.state(request.state.principal.session_id),
            "groups": [
                {
                    "id": g["id"],
                    "label": g["label"],
                    "members": self.app.state.profiles.members(g["id"]),
                }
                for g in self.app.state.profiles.groups()
            ],
        }
