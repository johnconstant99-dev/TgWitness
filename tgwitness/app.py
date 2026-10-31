import asyncio
import base64
import io
import ipaddress
import json
import logging
import secrets
from secrets import token_bytes as secrets_token
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator
from starlette.background import BackgroundTask
from telethon.errors import FloodWaitError, RPCError

from . import __version__
from .access import POLICY, AccessControl, AdminSettings, Console, GrantSettings, Refused, check as access_check
from .collector import Collector
from .demo import seed_demo
from .evidence import LIMITS, checkpoint, encrypt_export, export_file, producer, retain_checkpoint, cleanup_exports
from . import i18n
from .security import InstanceLock, Vault
from .profiles import Profiles, ProfileDispatch
from .multi_export import MultiExport
from .provenance import run_receipt
from .middleware import RequestLimit, request_limit
from .account_import import import_accounts, IMPORT_REQUEST_LIMIT
from .anchor import request_archive
from .anchoring import EvidenceMode, anchor_loop, evidence_settings, request_anchor
from . import replica
from . import alerts
from .network import NetworkConfig, RoutePolicy, parse_mtproxy_link
from .proxy_catalog import ProxyPool, PublicCatalog, feed_network
from .monitoring import Capture, Monitoring, capture_settings, monitoring_settings
from .scope import (EXCLUDE_LIMIT, WIDE_WARNING, Recheck, ScopeUpdate, recheck_settings, scope_settings,
                    unexclude)
from . import assurance
from . import health
from . import netclient
from . import source_check
from . import dossier
from . import report
from . import tuning
from . import witness_api
from . import interactions
from .store import Store, canonical
from .verify import fingerprint


class Credentials(BaseModel):
    api_id: int | None = Field(default=None, gt=0, le=2147483647)
    api_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{32}$")
    session: str = Field(default="", max_length=4096)
    expected_user_id: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def complete_api_pair(self):
        if (self.api_id is None) != (self.api_hash is None):
            raise ValueError("Provide both API ID and API hash, or use this workspace's saved credentials.")
        return self


class PhoneLogin(Credentials):
    phone: str = Field(pattern=r"^\+[0-9]{7,16}$")


class AccountFile(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=IMPORT_REQUEST_LIMIT)


class AccountImport(BaseModel):
    files: list[AccountFile] = Field(min_length=1, max_length=4)
    passcode: str = Field(default="", max_length=512)


class Phone(BaseModel):
    phone: str = Field(pattern=r"^\+[0-9]{7,16}$")


class Code(BaseModel):
    code: str = Field(min_length=3, max_length=12, pattern=r"^[0-9 -]+$")


class Password(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class SourceCheck(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    ref: str = Field(min_length=1, max_length=200)


class AlertUpdate(alerts.AlertSettings):

    urls: list[str] | None = Field(default=None, max_length=20)
    add_urls: list[str] = Field(default=[], max_length=20)


class ExportPassword(BaseModel):

    password: str = Field(min_length=12, max_length=256)


class Target(BaseModel):
    chat_id: int
    enabled: bool
    priority: bool | None = None


class TargetPriority(BaseModel):
    chat_id: int
    priority: bool


class DossierSwitch(BaseModel):
    enabled: bool


class WitnessTokenCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class ProxyLink(BaseModel):
    link: str = Field(min_length=1, max_length=2048)


class ReplicaUpdate(replica.ReplicaSettings):

    access_key: str = Field(default="", max_length=256, pattern=r"^\S*$")
    secret_key: str = Field(default="", max_length=256, pattern=r"^\S*$")


class Snapshot(BaseModel):
    chat_id: int
    limit: int = Field(default=100, ge=1, le=10000)


class ParametersUpdate(BaseModel):

    values: dict[str, bool | int | float | list[str] | None] = Field(max_length=200)


class ChatExport(BaseModel):
    chat_id: int


class MultiExportStart(BaseModel):
    chat_id: int
    lead: str = Field(default="default", max_length=64)
    profiles: list[str] = Field(default_factory=list, max_length=256)


class ProfileCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class RoutePolicyUpdate(RoutePolicy):

    outside_proxy: NetworkConfig | None = None
    remove_outside_proxy: bool = False


class AccessLogin(BaseModel):
    token: str = Field(min_length=1, max_length=512)


def panel_language(request):
    """The language the panel is shown in; reports set to "Same as the panel" use it."""
    return i18n.pick(request.cookies.get(i18n.COOKIE), request.headers.get("accept-language"))


def create_app(data_dir=None, demo=False, client_factory=None, token_override=None, allow_profiles=True,
               account_guard=None, proxy_pool=None, access=None, profile_id="default"):
    root = Path(data_dir or "data").resolve()
    failures = defaultdict(deque)
    bearer = HTTPBearer(auto_error=False)
    op_lock = asyncio.Lock()
    export_lock = asyncio.Lock()
    public_proxies = PublicCatalog(root)

    shared_pool = proxy_pool or ProxyPool(public_proxies)

    console = None if access else Console()

    @asynccontextmanager
    async def lifespan(app):
        if console:
            console.attach()
        instance = InstanceLock(root)
        store = None
        resume_task = None
        anchor_task = None
        replica_task = None
        alert_task = None
        host_task = None
        pool_task = None
        collector = None
        journal_ready = False
        profiles = None
        try:
            cleanup_exports(root)
            vault = Vault(root)
            if token_override:
                vault.token = token_override
            store = Store(root)
            store.bind(vault)
            await asyncio.to_thread(store.verify, vault.public_key)
            if demo:
                if store.stats()["total"] and not store.get_setting("demo", False):
                    raise RuntimeError("Refusing to mix synthetic data into a real journal.")
                seed_demo(store)
            collector = Collector(store, vault, **({"client_factory": client_factory} if client_factory else {}))
            collector.account_guard = account_guard
            collector.proxy_pool = shared_pool
            app.state.store, app.state.vault, app.state.collector = store, vault, collector
            app.state.access = access or AccessControl(vault, store, console)
            if not access:
                def workspace_label(pid):
                    registry = getattr(app.state, "profiles", None)
                    if registry and pid in registry.entries:
                        return registry.entries[pid]["label"]
                    if registry and pid in registry.opening:
                        return registry.opening[pid]
                    if pid == "default":
                        return store.get_setting("profile_label", "Main account")
                    return next((p["label"] for p in store.get_setting("profiles", []) if p["id"] == pid), pid)
                app.state.access.labels = workspace_label
            store.listeners.append(app.state.access.journal_listener(profile_id))


            app.state.local_demo_token = secrets.token_urlsafe(32)
            app.state.run_receipt = run_receipt(store, vault)

            selected = assurance.mode()
            app.state.assurance = None
            if selected and not demo:
                provider = await asyncio.to_thread(assurance.provider_record, selected)
                app.state.assurance = {"mode": selected, "provider": provider}
                app.state.run_receipt["host"] = await asyncio.to_thread(
                    assurance.snapshot, selected, provider, detail=True)
            collector.run_id = app.state.run_receipt["run_id"]
            previous = store.stats()["head"]
            process_event = store.append("process.started", {"version": __version__, "previous_observation": previous,
                                             "run": app.state.run_receipt,
                                             "coverage": "No collection while process was offline."})
            app.state.run_event_seq = process_event["seq"]
            retain_checkpoint(store, vault)
            journal_ready = True
            app.state.anchor_wakeup, app.state.anchor_status = asyncio.Event(), {"busy": False}
            app.state.replica_wakeup, app.state.replica_status = asyncio.Event(), {"busy": False}
            app.state.host_status = {}  # the assurance loop's latest host measurement
            app.state.alert_wakeup = asyncio.Event()
            if not store.get_setting("demo", False):

                alert_task = asyncio.create_task(alerts.alert_loop(
                    store, vault, collector.outside_route, app.state.alert_wakeup, profile_id))
                anchor_task = asyncio.create_task(anchor_loop(
                    store, collector.outside_route, app.state.anchor_wakeup, app.state.anchor_status))
                replica_task = asyncio.create_task(replica.replica_loop(
                    store, vault, collector.outside_route, app.state.replica_wakeup, app.state.replica_status))
                if app.state.assurance:
                    host_task = asyncio.create_task(assurance.assurance_loop(
                        store, app.state.assurance["mode"], app.state.assurance["provider"],
                        status=app.state.host_status))
                if proxy_pool is None:
                    shared_pool.intervals = lambda: {"lists": tuning.value(store, "proxy_lists_minutes") * 60,
                                                     "probe": tuning.value(store, "proxy_probe_minutes") * 60}
                    shared_pool.outside = collector.outside_route
                    pool_task = asyncio.create_task(shared_pool.run())

            async def resume():
                try:
                    async with op_lock:
                        await collector.start()
                except Exception as exc:
                    collector.phase, collector.last_error = "resume_failed", type(exc).__name__
                    store.append("coverage.gap", {"reason": "resume_failed", "error_type": type(exc).__name__})

            if store.get_setting("resume", False) and not store.get_setting("demo", False):
                resume_task = asyncio.create_task(resume())
            if allow_profiles:
                def child_factory(path, **options):
                    return create_app(path, client_factory=client_factory, proxy_pool=shared_pool,
                                      access=app.state.access, profile_id=Path(path).name, **options)
                profiles = Profiles(app, root, child_factory)
                app.state.profiles = profiles
                await profiles.open()
                app.state.multi_export = MultiExport(profiles)
            yield
        finally:
            try:
                if getattr(app.state, "media_analysis", None):
                    await app.state.media_analysis.close()
                if getattr(app.state, "multi_export", None):
                    await app.state.multi_export.close()
                if profiles:
                    await profiles.close()
                for task in (resume_task, anchor_task, replica_task, alert_task, host_task, pool_task):
                    if task:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
                if collector:
                    await collector.stop(shutdown=True)
                if store and journal_ready:
                    store.append("process.stopped", {"reason": "graceful shutdown"})
                    retain_checkpoint(store, vault)
            finally:
                if store:
                    store.close()
                instance.close()
                if console:
                    console.detach()

    app = FastAPI(title="TgWitness", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestLimit, max_body=16384)

    @app.middleware("http")
    async def headers(request, call_next):
        if request.headers.get("content-length", "").isdigit() and int(request.headers["content-length"]) > request_limit(request.url.path):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        audit = getattr(request.state, "audit", None)
        if audit and audit[0] is app:

            path = request.url.path
            if (request.method != "GET" or response.status_code == 403
                    or any(part in path for part in ("/export", "/download", "/media/", "/replica/key", "/anchor-request"))):
                logging.getLogger("tgwitness.access").info(
                    "%s · %s %s → %d · %s", audit[1].label, request.method, path, response.status_code,
                    request.client.host if request.client else "unknown")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        response.headers["Cache-Control"] = "no-store"
        return response


    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(status_code=422, content={"detail": [
            {"field": ".".join(str(p) for p in err["loc"]), "message": err["msg"]}
            for err in exc.errors()]})

    def local_demo_access(request):
        if (not demo or not allow_profiles or not app.state.store.get_setting("demo", False)
                or len(app.state.profiles.entries) != 1
                or app.state.vault.read("credentials").get("session")):
            return False
        try:
            if not request.client or not ipaddress.ip_address(request.client.host).is_loopback:
                return False
            host = request.url.hostname
            if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
                return False
        except ValueError:
            return False
        if any(name in request.headers for name in ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto")):
            return False
        if request.headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
            return False
        origin = request.headers.get("origin")
        return origin is None or origin == str(request.url).split("/api/", 1)[0]

    @app.get("/locale.js")
    async def locale(request: Request):
        guide = request.query_params.get("scope") == "guide"
        languages = i18n.GUIDE_LANGUAGES if guide else i18n.LANGUAGES
        requested = request.query_params.get("lang")
        choice = requested if requested in languages else request.cookies.get(i18n.COOKIE)
        lang = i18n.pick(choice, request.headers.get("accept-language"), languages)
        return Response(i18n.script(lang, guide=guide), media_type="text/javascript; charset=utf-8")

    @app.get("/api/demo-access")
    async def demo_access(request: Request):
        if not local_demo_access(request):
            return {"available": False}
        return {"available": True, "token": app.state.local_demo_token}

    def reject_access(request, detail):


        address = request.client.host if request.client else "unknown"
        now = time.monotonic()
        if address not in failures and len(failures) >= 4096:
            failures.clear()
        queue = failures[address]
        while queue and queue[0] < now - 60:
            queue.popleft()
        if len(queue) >= 15:
            raise HTTPException(429, "Too many failed access attempts. Wait one minute.",
                                headers={"Retry-After": "60"})
        queue.append(now)
        raise HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})

    def client_address(request):
        return request.client.host if request.client else "unknown"

    async def identify(request: Request, credential: HTTPAuthorizationCredentials = Depends(bearer)):
        """Who is asking: the panel token, a session started with any token, or the local demo."""
        principal = None
        if credential:
            if local_demo_access(request) and secrets.compare_digest(
                    credential.credentials.encode(), app.state.local_demo_token.encode()):
                principal = app.state.access.principal({"owner": "admin", "id": None})
            else:
                try:
                    principal = app.state.access.resolve(credential.credentials, client_address(request))
                except Refused as exc:
                    raise HTTPException(403, str(exc)) from None
        if principal is None:
            reject_access(request, "Enter the panel access token from panel-token.txt in your data directory.")
        request.state.principal, request.state.audit = principal, (app, principal)
        return principal

    async def authenticate(request: Request, principal=Depends(identify)):
        """An issued access may use only the routes, workspaces and chats it was given."""
        route = request.scope.get("route")
        rule = POLICY.get(request.method + " " + route.path) if route else None
        try:
            access_check(principal, profile_id, rule, request.path_params)
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        return principal

    def visible_chats(request):
        """None for every chat of this workspace, otherwise the chat IDs the access opens."""
        return request.state.principal.chats(profile_id)

    def require_chat(request, chat_id):
        allowed = visible_chats(request)
        if allowed is not None and chat_id not in allowed:
            raise HTTPException(403, "This chat is not open to this access.")

    async def authenticate_witness(request: Request, credential: HTTPAuthorizationCredentials = Depends(bearer)):
        """Witness tokens open only the signed journal head; the panel token is not accepted here."""
        entry = witness_api.match(app.state.vault, credential.credentials) if credential else None
        if not entry:
            reject_access(request, "Unknown witness token.")
        return entry

    def require_live():
        if app.state.store.get_setting("demo", False):
            raise HTTPException(409, "This is a synthetic demo. Start a separate data directory for real observation.")

    async def operation(call, *args):
        require_live()
        async with op_lock:
            try:
                return await asyncio.wait_for(call(*args), tuning.value(app.state.store, "operation_timeout_seconds"))
            except FloodWaitError as exc:
                app.state.store.set_setting("rpc_backoff_until", max(time.time() + exc.seconds,
                    app.state.store.get_setting("rpc_backoff_until", 0)))
                raise HTTPException(429, {"message": "Telegram requested a pause.", "retry_after": exc.seconds},
                                    headers={"Retry-After": str(exc.seconds)}) from None
            except RPCError as exc:
                raise HTTPException(400, "Telegram rejected the request: " + type(exc).__name__) from None
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
            except (TimeoutError, OSError, ConnectionError) as exc:
                raise HTTPException(503, "Connection unavailable: " + type(exc).__name__) from None

    @app.get("/api/status", dependencies=[Depends(authenticate)])
    async def status(request: Request):
        store, vault = app.state.store, app.state.vault
        allowed = visible_chats(request)
        collector_status = app.state.collector.status()
        return {"version": __version__, "demo": store.get_setting("demo", False),
                "collector": collector_status, "stats": store.stats(allowed),
                "health": health.collector_of(app.state, collector_status),
                "history": app.state.collector.history.status() if allowed is None else None,
                "targets": [t for t in store.targets() if allowed is None or t["chat_id"] in allowed],
                "capture": capture_settings(store),
                "monitoring": monitoring_settings(store), "scope": scope_settings(store),
                "recheck": recheck_settings(store),
                "dossiers": [c for c in dossier.enabled_chats(store) if allowed is None or c in allowed],
                "parameters": tuning.values(store),
                "fingerprint": fingerprint(vault.public_key), "limitations": LIMITS,
                "protection": {"vault_key_mode": vault.key_mode, "secrets_encrypted": True,
                               "journal_encrypted_by_app": False, "media_encrypted_by_app": False},
                "run_id": app.state.run_receipt["run_id"], "chats_limited": allowed is not None}

    if allow_profiles:
        @app.get("/api/profiles", dependencies=[Depends(authenticate)])
        async def profiles_list(request: Request):
            principal, listed = request.state.principal, []
            for entry in app.state.profiles.summary():
                if not principal.opens(entry["id"]):
                    continue
                if principal.chats(entry["id"]) is not None:
                    entry = {**entry, "stats": None, "sources_enabled": None,
                             "sources_total": len(principal.chats(entry["id"]))}
                listed.append(entry)
            return {"profiles": listed, "limit": Profiles.MAX_PROFILES,
                    "model": "independent account collectors and signing identities"}

        @app.post("/api/profiles", dependencies=[Depends(authenticate)])
        async def profiles_create(body: ProfileCreate):
            require_live()
            if not body.label.strip():
                raise HTTPException(422, "Enter an account label.")
            try:
                return await app.state.profiles.create(body.label.strip())
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

        def opens_chat_everywhere(principal, chat_id, profile_ids):
            return all(principal.opens(pid) and (principal.chats(pid) is None or chat_id in principal.chats(pid))
                       for pid in profile_ids)

        def multi_visible(request):
            """An issued access sees a multi-account export only if it opens that chat in each of its accounts."""
            state = app.state.multi_export.state
            return not state or opens_chat_everywhere(request.state.principal, state["chat_id"],
                                                      [state["lead"], *(w["profile_id"] for w in state["workers"])])

        @app.post("/api/multi-export/start", dependencies=[Depends(authenticate)])
        async def multi_export_start(request: Request, body: MultiExportStart):
            if not opens_chat_everywhere(request.state.principal, body.chat_id, [body.lead, *body.profiles]):
                raise HTTPException(403, "This access does not open this chat in every chosen account.")
            return await operation(app.state.multi_export.start, body.chat_id, body.profiles, body.lead,
                                   panel_language(request))

        @app.get("/api/multi-export/current", dependencies=[Depends(authenticate)])
        async def multi_export_current(request: Request):
            return app.state.multi_export.public() if multi_visible(request) else {"phase": "none"}

        @app.get("/api/multi-export/{export_id}", dependencies=[Depends(authenticate)])
        async def multi_export_poll(request: Request, export_id: str):
            return app.state.multi_export.poll(export_id) if multi_visible(request) else {"phase": "unknown"}

        @app.post("/api/multi-export/{export_id}/cancel", dependencies=[Depends(authenticate)])
        async def multi_export_cancel(request: Request, export_id: str):
            if not multi_visible(request):
                raise HTTPException(403, "This access does not open this chat in every chosen account.")
            return await app.state.multi_export.cancel(export_id)

        @app.get("/api/multi-export/{export_id}/download", dependencies=[Depends(authenticate)])
        async def multi_export_download(request: Request, export_id: str):
            path = app.state.multi_export.result_path(export_id) if multi_visible(request) else None
            if not path:
                raise HTTPException(404, "No finished export is available to download.")
            return FileResponse(path, filename="tgwitness-chat-export.zip", media_type="application/zip",
                                background=BackgroundTask(path.unlink, missing_ok=True))

        @app.patch("/api/profiles/{profile_id}", dependencies=[Depends(authenticate)])
        async def profiles_rename(profile_id: str, body: ProfileCreate):
            require_live()
            if not body.label.strip():
                raise HTTPException(422, "Enter an account label.")
            try:
                return await app.state.profiles.rename(profile_id, body.label.strip())
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

        @app.delete("/api/profiles/{profile_id}", dependencies=[Depends(authenticate)])
        async def profiles_delete(profile_id: str):
            require_live()
            try:
                return await app.state.profiles.delete(profile_id)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

    @app.get("/api/events", dependencies=[Depends(authenticate)])
    async def get_events(request: Request, chat_id: int | None = None, message_id: int | None = None,
                         kind: str | None = None, before: int | None = None,
                         search: str | None = None, limit: int = 100):
        if not 1 <= limit <= 500 or (search and len(search) > 200):
            raise HTTPException(422, "Limit must be 1–500; search must be at most 200 characters.")
        if chat_id is not None:
            require_chat(request, chat_id)
        records = app.state.store.events(chat_id, message_id, kind, before, limit, search,
                                         chat_ids=visible_chats(request))
        return {"events": records, "next_before": records[-1]["seq"] if len(records) == limit else None}

    @app.post("/api/auth/configure", dependencies=[Depends(authenticate)])
    async def configure(body: Credentials):
        return await operation(app.state.collector.configure, body.api_id, body.api_hash, body.session, body.expected_user_id)

    @app.post("/api/auth/phone/start", dependencies=[Depends(authenticate)])
    async def start_phone(body: PhoneLogin):
        return await operation(app.state.collector.start_phone, body.phone, body.api_id, body.api_hash)

    @app.post("/api/auth/import", dependencies=[Depends(authenticate)])
    async def import_account(body: AccountImport):
        require_live()
        async with op_lock:
            if app.state.collector.running:
                raise HTTPException(400, "Pause observation before importing another account.")
            try:
                return await asyncio.to_thread(import_accounts, [item.model_dump() for item in body.files], body.passcode)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

    @app.post("/api/auth/qr/start", dependencies=[Depends(authenticate)])
    async def start_qr(body: Credentials):
        import qrcode
        from qrcode.image.svg import SvgPathImage
        result = await operation(app.state.collector.start_qr, body.api_id, body.api_hash)
        url = result.pop("url")
        output = io.BytesIO()
        qrcode.make(url, image_factory=SvgPathImage, border=4).save(output)
        return {**result, "image": "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode("ascii")}

    @app.get("/api/auth/qr/{login_id}", dependencies=[Depends(authenticate)])
    async def poll_qr(login_id: str):
        return app.state.collector.poll_qr(login_id)

    @app.post("/api/auth/qr/{login_id}/cancel", dependencies=[Depends(authenticate)])
    async def cancel_qr(login_id: str):
        return await operation(app.state.collector.cancel_qr, login_id)

    async def approved_route(request, config):
        """A proxy resolving inside this machine or its network (a local Tor or SOCKS5 proxy) may be set only
        by the main administrator; the saved route remembers that. A request's own local_proxy is ignored."""
        if config is None or config.kind not in ("socks5", "http", "mtproxy"):
            return config and config.model_copy(update={"local_proxy": False})
        try:
            addresses = await netclient.resolve(config.host, config.port)
        except OSError:
            addresses = []
        inside = any(netclient.internal(a) for a in addresses)
        if inside and not (request.state.principal.admin or netclient.private_allowed()):
            raise HTTPException(403, "This proxy is inside this machine or its network. Only the main administrator can set it.")
        return config.model_copy(update={"local_proxy": inside})

    @app.post("/api/network", dependencies=[Depends(authenticate)])
    async def network(request: Request, body: NetworkConfig):
        return await operation(app.state.collector.set_network, await approved_route(request, body))

    @app.get("/api/network/policy", dependencies=[Depends(authenticate)])
    async def network_policy():
        return app.state.collector.policy_state()

    @app.post("/api/network/policy", dependencies=[Depends(authenticate)])
    async def network_policy_set(request: Request, body: RoutePolicyUpdate):
        return await operation(app.state.collector.set_route_policy,
                               RoutePolicy(exposure=body.exposure, outside_enabled=body.outside_enabled),
                               await approved_route(request, body.outside_proxy), body.remove_outside_proxy)

    def download_route():
        if feed_network():
            return {"download_route": "proxy", "download_problem": None}
        route = app.state.collector.outside_route()
        return {"download_route": "proxy" if route.kind in ("socks5", "http") else route.kind,
                "download_problem": str(route.error) if route.kind == "none" else None}

    @app.get("/api/network/catalog", dependencies=[Depends(authenticate)])
    async def network_catalog():
        try:
            return {**public_proxies.public(), **download_route()}
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None

    @app.post("/api/network/catalog/refresh", dependencies=[Depends(authenticate)])
    async def network_catalog_refresh():
        result = await operation(public_proxies.refresh, app.state.collector.outside_route())
        return {**result, **download_route()}

    @app.post("/api/network/catalog/{proxy_id}", dependencies=[Depends(authenticate)])
    async def network_catalog_apply(proxy_id: str):
        try:
            catalog = public_proxies.catalog()
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None
        if not any(row["id"] == proxy_id for row in catalog["proxies"]):
            raise HTTPException(404, "Unknown public proxy. Refresh the list.")
        async def apply():
            if app.state.collector.running:
                raise ValueError("Pause observation before changing the Telegram route.")
            route = await public_proxies.selected_route(proxy_id)
            return await app.state.collector.set_network(route)
        return await operation(apply)

    @app.post("/api/network/parse-link", dependencies=[Depends(authenticate)])
    async def network_parse_link(body: ProxyLink):
        try:
            return parse_mtproxy_link(body.link).model_dump()
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/network/test", dependencies=[Depends(authenticate)])
    async def network_test():
        return await operation(app.state.collector.test_network)

    @app.post("/api/auth/phone", dependencies=[Depends(authenticate)])
    async def phone(body: Phone):
        return await operation(app.state.collector.send_code, body.phone)

    @app.post("/api/auth/code", dependencies=[Depends(authenticate)])
    async def code(body: Code):
        return await operation(app.state.collector.confirm_code, body.code)

    @app.post("/api/auth/password", dependencies=[Depends(authenticate)])
    async def password(body: Password):
        return await operation(app.state.collector.confirm_password, body.password)

    @app.post("/api/auth/logout", dependencies=[Depends(authenticate)])
    async def logout():
        return await operation(app.state.collector.sign_out)

    @app.get("/api/dialogs", dependencies=[Depends(authenticate)])
    async def dialogs():
        return await operation(app.state.collector.dialogs)

    @app.post("/api/targets", dependencies=[Depends(authenticate)])
    async def target(request: Request, body: Target):
        require_live()
        require_chat(request, body.chat_id)
        collector, store = app.state.collector, app.state.store
        async with op_lock:
            existing = next((t for t in store.targets() if t["chat_id"] == body.chat_id), None)
            entry = collector.dialog_cache.get(body.chat_id) or existing
            if not entry:
                raise HTTPException(400, "Refresh the group list and select an available target.")
            with store.transaction():

                store.set_target(body.chat_id, entry["title"], entry["kind"], body.enabled, origin="manual",
                                 priority=body.priority)
                included = body.enabled and unexclude(store, body.chat_id)
                store.append("target.changed", {"title": entry["title"], "enabled": body.enabled,
                                               **({"removed_from_scope_exclusions": True} if included else {}),
                                               "coverage": "No observations promised while target is disabled."},
                             body.chat_id)
        return {"targets": store.targets()}

    @app.post("/api/targets/priority", dependencies=[Depends(authenticate)])
    async def target_priority(request: Request, body: TargetPriority):
        require_live()
        require_chat(request, body.chat_id)
        store = app.state.store
        existing = next((t for t in store.targets() if t["chat_id"] == body.chat_id), None)
        if not existing:
            raise HTTPException(404, "This chat is not among the sources.")
        with store.transaction():
            store.set_target(body.chat_id, existing["title"], existing["kind"], bool(existing["enabled"]),
                             priority=body.priority)
            store.append("target.priority", {"title": existing["title"], "priority": body.priority,
                                            "recheck": recheck_settings(store)}, body.chat_id)
        return {"targets": store.targets()}

    @app.delete("/api/targets/{chat_id}", dependencies=[Depends(authenticate)])
    async def target_remove(chat_id: int):
        require_live()
        store = app.state.store
        async with op_lock:
            existing = next((t for t in store.targets() if t["chat_id"] == chat_id), None)
            if not existing:
                raise HTTPException(404, "This chat is not among the sources.")
            scope = scope_settings(store)
            exclude = scope["mode"] != "selected" and chat_id not in scope["exclude"]
            if exclude and len(scope["exclude"]) >= EXCLUDE_LIMIT:
                raise HTTPException(409, "The scope already excludes 5,000 chats, the most it keeps. Pause this "
                                         "chat instead, or switch the scope to chosen chats to remove it.")
            with store.transaction():
                store.remove_target(chat_id)
                if exclude:

                    store.set_setting("scope", {**scope, "exclude": [*scope["exclude"], chat_id]})
                removed_dossier = dossier.remove(store, chat_id)
                store.append("target.removed", {
                    "title": existing["title"], "dossier_removed": removed_dossier,
                    "excluded_from_scope": scope["mode"] != "selected",
                    "journal": "records already saved for this chat stay in the append-only journal"}, chat_id)
        return {"targets": store.targets()}

    @app.post("/api/capture", dependencies=[Depends(authenticate)])
    async def capture(body: Capture):
        require_live()
        with app.state.store.transaction():
            app.state.store.set_setting("capture", body.model_dump())
            app.state.store.append("capture.changed", capture_settings(app.state.store))
        return capture_settings(app.state.store)

    def scope_state():
        collector = app.state.collector
        return {"settings": scope_settings(app.state.store), "recheck": recheck_settings(app.state.store),
                "folders": [{"id": f["id"], "title": f["title"]} for f in collector.folders.values()],
                "warning": WIDE_WARNING}

    @app.get("/api/scope", dependencies=[Depends(authenticate)])
    async def get_scope():
        return scope_state()

    @app.post("/api/scope", dependencies=[Depends(authenticate)])
    async def set_scope(body: ScopeUpdate):
        require_live()
        store, collector = app.state.store, app.state.collector
        previous, current = scope_settings(store), body.model_dump(exclude={"acknowledged"})
        current["exclude"] = sorted(set(current["exclude"]))
        widening = current["mode"] != "selected" and (previous["mode"] != current["mode"]
                                                      or previous["folder_id"] != current["folder_id"])
        if widening and not body.acknowledged:
            raise HTTPException(409, WIDE_WARNING)
        if current["mode"] == "folder" and current["folder_id"] is None:
            raise HTTPException(422, "Choose a Telegram folder. Load chats first if the list is empty.")
        if current != previous:
            with store.transaction():
                store.set_setting("scope", current)
                store.append("scope.changed", {
                    "before": previous, "after": current,
                    "acknowledged": body.acknowledged if widening else None,
                    "warning": WIDE_WARNING if current["mode"] != "selected" else None,
                    "coverage": "applies to updates from now on; earlier history is not fetched"})
            if collector.running:
                await operation(collector.apply_scope)
        return scope_state()

    @app.post("/api/recheck", dependencies=[Depends(authenticate)])
    async def set_recheck(body: Recheck):
        require_live()
        store = app.state.store
        with store.transaction():
            for key, value in body.model_dump().items():
                store.set_setting(key, value)
            store.append("recheck.changed", {**body.model_dump(), "meaning": "minutes between rechecks of "
                                             "priority sources and of every other source; 0 turns a tier off"})
        return scope_state()

    def outside_state():
        """How requests outside Telegram leave this workspace, and why not when they cannot."""
        route = app.state.collector.outside_route()
        return {"route": route.kind, "route_problem": str(route.error) if route.kind == "none" else None}

    def timestamps_health(outside):
        store = app.state.store
        last, success = store.get_setting("evidence_last", None), store.get_setting("evidence_success", None)
        if success is None and last and any(r.get("ok") for r in last.get("results", [])):  # saved before 0.7
            success = {"at": last["at"], "verified_at": last["at"] if any(
                r.get("ok") and r.get("kind") == "rfc3161" for r in last["results"]) else None}
        return health.timestamps(evidence_settings(store), last, success, store.get_setting("evidence_failure", None),
                                 app.state.anchor_status, outside["route_problem"], health.now_utc())

    def replica_health(outside):
        store = app.state.store
        last, success = store.get_setting("replica_last", None), store.get_setting("replica_success", None)
        if success is None and last and not last.get("error"):  # saved before 0.7
            success = {"at": last["at"], "journal_seq": last.get("journal_seq")}
        return health.replica(replica.replica_settings(store), last, success, app.state.replica_status,
                              outside["route_problem"], (store.stats()["head"] or {}).get("seq", 0), health.now_utc())

    def server_health():
        return health.server(app.state.assurance, app.state.run_receipt.get("host"), app.state.host_status,
                             health.now_utc())

    def evidence_state():
        store, outside = app.state.store, outside_state()
        return {"settings": evidence_settings(store), "last": store.get_setting("evidence_last", None),
                "busy": app.state.anchor_status["busy"], **outside, "health": timestamps_health(outside),
                "defaults": EvidenceMode().model_dump(exclude={"enabled"})}

    @app.get("/api/evidence", dependencies=[Depends(authenticate)])
    async def get_evidence():
        return evidence_state()

    @app.post("/api/evidence", dependencies=[Depends(authenticate)])
    async def set_evidence(body: EvidenceMode):
        require_live()
        store, vault = app.state.store, app.state.vault
        was = evidence_settings(store)["enabled"]
        with store.transaction():
            store.set_setting("evidence", body.model_dump())
            store.append("evidence.changed", {**body.model_dump(), "fingerprint": fingerprint(vault.public_key)})
        if body.enabled and not was:
            request_anchor(store, vault, app.state.anchor_wakeup)
        return evidence_state()

    @app.post("/api/evidence/anchor", dependencies=[Depends(authenticate)])
    async def evidence_anchor():
        require_live()
        if not evidence_settings(app.state.store)["enabled"]:
            raise HTTPException(409, "Turn on evidence mode first.")
        request_anchor(app.state.store, app.state.vault, app.state.anchor_wakeup)
        return evidence_state()

    def source_state():
        last, receipt = app.state.store.get_setting("source_check", None), app.state.run_receipt
        return {"last": last, "version": __version__, "source_tree_sha256": receipt["source_tree_sha256"],
                "files": len(receipt["source_files"]), **outside_state(),

                "current": bool(last) and last["source_tree_sha256"] == receipt["source_tree_sha256"]}

    @app.get("/api/source-check", dependencies=[Depends(authenticate)])
    async def get_source_check():
        return source_state()

    @app.post("/api/source-check", dependencies=[Depends(authenticate)])
    async def run_source_check(body: SourceCheck):
        require_live()
        try:
            result = await source_check.check(body.repository, body.ref.strip(), app.state.collector.outside_route())
        except source_check.NotFound:
            raise HTTPException(422, "GitHub has no such public repository or version. Check the address and the tag, branch or commit.")
        except source_check.Limited:
            raise HTTPException(503, "GitHub is limiting requests from this address. Try again in an hour.")
        except netclient.HTTPError:
            raise HTTPException(502, "GitHub could not be reached through this workspace's connection route.")
        except ValueError:
            raise HTTPException(422, "Enter a GitHub repository as github.com/owner/name.")
        except (netclient.RouteError, OSError, asyncio.TimeoutError):
            raise HTTPException(502, "GitHub could not be reached through this workspace's connection route.")
        store = app.state.store
        with store.transaction():
            store.set_setting("source_check", result)
            store.append("source.checked", {**result, "meaning": "git blob ids of the running program files "
                                            "compared with the files of this commit on GitHub"})
        return source_state()

    def replica_state():
        store, vault, outside = app.state.store, app.state.vault, outside_state()
        settings, secrets = replica.replica_settings(store), vault.read("replica")
        return {"settings": settings, "has_credentials": bool(secrets.get("access_key")),
                "has_key": bool(secrets.get("key")), "last": store.get_setting("replica_last", None),
                "busy": app.state.replica_status["busy"], **outside, "health": replica_health(outside),
                "location": replica.workspace_prefix(settings, vault.public_key)}

    @app.get("/api/replica", dependencies=[Depends(authenticate)])
    async def get_replica():
        return replica_state()

    @app.get("/api/health", dependencies=[Depends(authenticate)])
    async def get_health():
        """What each part is doing now, apart from whether it is switched on (health.py)."""
        outside = outside_state()
        return {"checked_at": health.iso(health.now_utc()), "collector": health.collector_of(app.state),
                "timestamps": timestamps_health(outside), "replica": replica_health(outside),
                "server": server_health()}

    @app.post("/api/replica", dependencies=[Depends(authenticate)])
    async def set_replica(body: ReplicaUpdate):
        require_live()
        store, vault = app.state.store, app.state.vault
        secrets = dict(vault.read("replica"))
        if body.access_key or body.secret_key:
            if not (body.access_key and body.secret_key):
                raise HTTPException(422, "Enter both the access key ID and the secret access key.")
            secrets.update(access_key=body.access_key, secret_key=body.secret_key)
        settings = body.model_dump(exclude={"access_key", "secret_key"})
        if settings["enabled"] and not (settings["endpoint"] and settings["bucket"] and secrets.get("access_key")):
            raise HTTPException(422, "Enter the endpoint, bucket and access keys before turning the copy on.")
        secrets.setdefault("key", base64.b64encode(secrets_token(32)).decode())
        vault.save("replica", secrets)
        with store.transaction():
            store.set_setting("replica", settings)
            store.append("replica.changed", {**settings, "encrypted": True})
        if settings["enabled"]:
            app.state.replica_wakeup.set()
        return replica_state()

    def alert_state():
        urls = app.state.vault.read("alerts").get("urls", [])
        return {"settings": alerts.alert_settings(app.state.store), "destinations": [alerts.describe(u) or "?" for u in urls],
                "last": app.state.store.get_setting("alerts_last", None),
                **outside_state()}

    @app.get("/api/alerts", dependencies=[Depends(authenticate)])
    async def get_alerts():
        return alert_state()

    @app.post("/api/alerts", dependencies=[Depends(authenticate)])
    async def set_alerts(request: Request, body: AlertUpdate):
        require_live()
        store, vault = app.state.store, app.state.vault
        saved = vault.read("alerts").get("urls", [])
        urls = list(saved) if body.urls is None else [u.strip() for u in body.urls if u.strip()]
        urls += [u for u in dict.fromkeys(u.strip() for u in body.add_urls) if u and u not in urls]
        for url in urls:
            if len(url) > 2048 or not alerts.describe(url):
                raise HTTPException(422, "Apprise does not recognise one of the destination addresses. Check it against the Apprise wiki.")

        if (any(alerts.own_socket(u) for u in urls if u not in saved)
                and not (request.state.principal.admin or netclient.private_allowed())):
            raise HTTPException(403, "Only the main administrator can add destinations that connect without HTTP "
                                     "(IRC, MQTT, XMPP, syslog and similar).")
        problem = alerts.route_problem(urls, app.state.collector.outside_route())
        if body.enabled and problem:
            raise HTTPException(422, problem)
        if body.enabled and not urls:
            raise HTTPException(422, "Add at least one destination before turning notifications on.")
        settings = body.model_dump(exclude={"urls", "add_urls"})
        vault.save("alerts", {"urls": urls})
        with store.transaction():
            store.set_setting("alerts", settings)
            store.append("alerts.changed", {**settings, "destinations": len(urls),
                                            "services": sorted({u.split("://", 1)[0].lower() for u in urls}),
                                            "content": "chat names, counts and excerpts of changed messages"
                                                       if settings["include_text"] else
                                                       "chat names and counts only, never message text"})
        app.state.alert_wakeup.set()
        return alert_state()

    @app.post("/api/alerts/test", dependencies=[Depends(authenticate)])
    async def test_alerts():
        require_live()
        store, urls = app.state.store, app.state.vault.read("alerts").get("urls", [])
        if not urls:
            raise HTTPException(409, "Save at least one destination first.")
        words = i18n.words(alerts.alert_settings(store)["language"])
        result = await asyncio.to_thread(
            alerts.deliver, urls, alerts.tr(words, "TgWitness · {name}: test", name=alerts.workspace_name(store)),
            alerts.tr(words, "Notifications from this workspace reach this destination."), app.state.collector.outside_route())
        if result["error"]:
            raise HTTPException(502, result["error"])
        return result

    @app.post("/api/replica/sync", dependencies=[Depends(authenticate)])
    async def replica_sync():
        require_live()
        if not replica.replica_settings(app.state.store)["enabled"]:
            raise HTTPException(409, "Turn on the off-site copy first.")
        app.state.replica_wakeup.set()
        return replica_state()

    @app.post("/api/replica/test", dependencies=[Depends(authenticate)])
    async def replica_test():
        require_live()
        store, vault = app.state.store, app.state.vault
        settings, secrets = replica.replica_settings(store), vault.read("replica")
        if not (settings["endpoint"] and settings["bucket"] and secrets.get("access_key")):
            raise HTTPException(409, "Save the endpoint, bucket and access keys first.")
        s3 = replica.client(settings, secrets, app.state.collector.outside_route())
        name = replica.workspace_prefix(settings, vault.public_key) + "/connection-test.tgwr"
        try:

            headers = replica.lock_headers(settings, 1 if settings["retention_days"] else 0)
            started_at = datetime.now(timezone.utc)
            await asyncio.wait_for(replica.upload(s3, base64.b64decode(secrets["key"]), name,
                                                  lambda: io.BytesIO(b"TgWitness connection test"),
                                                  headers), 60)
            lock = await asyncio.wait_for(replica.lock_report(s3, name, {**settings, "retention_days": min(
                settings["retention_days"], 1)}, headers, started_at), 60)
        except Exception as exc:
            raise HTTPException(502, "Storage did not accept a test object: " + (
                str(exc)[:200] if isinstance(exc, ValueError) else type(exc).__name__)) from None
        return {"ok": True, "object": name, "object_lock": lock}

    @app.get("/api/replica/key", dependencies=[Depends(authenticate)])
    async def replica_key():
        if not app.state.vault.read("replica").get("key"):
            raise HTTPException(404, "Save the off-site copy settings first; the key is created then.")
        return Response(json.dumps(replica.key_file(app.state.store, app.state.vault), indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="tgwitness-replica-key.json"'})

    @app.post("/api/monitoring", dependencies=[Depends(authenticate)])
    async def monitoring(body: Monitoring):
        require_live()
        async with op_lock:
            store = app.state.store
            with store.transaction():
                previous = monitoring_settings(store)
                current = body.model_dump()
                if previous != current:
                    store.set_setting("monitoring", current)
                    store.append("monitoring.changed", {
                        "before": previous, "after": current,
                        "applies_to": "subsequent live updates for selected sources in this account profile",
                        "coverage": "disabled categories are intentionally not recorded; no backfill",
                        "history_snapshots": "explicit snapshots remain separate; embedded metadata is not redacted",
                    })
        return current

    @app.post("/api/collector/{action}", dependencies=[Depends(authenticate)])
    async def control(action: Literal["start", "stop"]):
        collector = app.state.collector
        await operation(collector.start if action == "start" else collector.stop)
        return collector.status()

    @app.post("/api/snapshot", dependencies=[Depends(authenticate)])
    async def snapshot(request: Request, body: Snapshot):
        require_chat(request, body.chat_id)
        if body.limit > tuning.value(app.state.store, "snapshot_max"):
            raise HTTPException(422, "The snapshot is larger than this workspace allows. Raise the limit in Parameters.")
        return await operation(app.state.collector.snapshot, body.chat_id, body.limit)

    @app.get("/api/history", dependencies=[Depends(authenticate)])
    async def history_status():
        return app.state.collector.history.status()

    @app.post("/api/history/{action}", dependencies=[Depends(authenticate)])
    async def history_action(action: str):
        if action not in ("start", "pause", "resume", "cancel"):
            raise HTTPException(404, "Unknown history action.")
        return await operation(getattr(app.state.collector.history, action))

    @app.get("/api/history/report", dependencies=[Depends(authenticate)])
    async def history_report():
        try:
            report = app.state.collector.history.report()
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None
        return Response(canonical(report), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="tgwitness-history-report.json"'})

    @app.get("/api/parameters", dependencies=[Depends(authenticate)])
    async def get_parameters():
        return tuning.described(app.state.store)

    @app.post("/api/parameters", dependencies=[Depends(authenticate)])
    async def set_parameters(body: ParametersUpdate):
        require_live()
        store = app.state.store
        try:
            saved, before, after = tuning.changes(store, body.values)
        except tuning.Invalid as exc:
            raise HTTPException(422, {"message": str(exc), "parameter": exc.key}) from None
        if after:
            with store.transaction():
                store.set_setting("parameters", saved)
                store.append("parameters.changed", {
                    "before": before, "after": after,
                    "applies": "from the next use of each value; Telegram client timeouts and retries from "
                               "the next connection"})
            app.state.alert_wakeup.set()
        return tuning.described(store)

    @app.get("/api/chats", dependencies=[Depends(authenticate)])
    async def chats(request: Request):
        store = app.state.store
        overview = store.chat_overview()
        listed = [{**t, "enabled": bool(t["enabled"]), **overview.pop(t["chat_id"], {})} for t in store.targets()]
        listed += [{"chat_id": chat_id, "title": None, "kind": None, "enabled": False, **extra}
                   for chat_id, extra in overview.items()]
        allowed = visible_chats(request)
        return {"chats": [c for c in listed if allowed is None or c["chat_id"] in allowed]}

    @app.post("/api/interactions/preview", dependencies=[Depends(authenticate)])
    async def interaction_preview(body: interactions.Preview):
        return await operation(interactions.preview, app.state.collector, body)

    @app.post("/api/interactions", dependencies=[Depends(authenticate)])
    async def interaction_action(request: Request, body: interactions.Action):
        if visible_chats(request) is not None:
            if body.action == "open":
                raise HTTPException(403, "This access opens only chosen chats; this part of the workspace is closed to it.")
            require_chat(request, body.chat_id)
        return await operation(interactions.execute, app.state.collector, body)

    @app.get("/api/chats/{chat_id}/messages", dependencies=[Depends(authenticate)])
    async def chat_messages(chat_id: int, before_id: int | None = None, limit: int = 60):
        if not 1 <= limit <= 200:
            raise HTTPException(422, "Limit must be 1–200.")
        return app.state.store.chat_messages(chat_id, before_id, limit)

    @app.get("/api/chats/{chat_id}/authors", dependencies=[Depends(authenticate)])
    async def chat_authors(chat_id: int):
        return app.state.store.chat_authors(chat_id)

    def profile_view(event):
        if not event:
            return {"profile": None}
        return {"profile": {k: v for k, v in event["payload"].items() if k != "raw"},
                "seq": event["seq"], "observed_at": event["observed_at"]}

    @app.get("/api/chats/{chat_id}/profile", dependencies=[Depends(authenticate)])
    async def chat_profile(chat_id: int):
        saved = app.state.store.events(chat_id, None, "source.profile", None, 1, None)
        return profile_view(saved[0] if saved else None)

    @app.post("/api/chats/{chat_id}/profile", dependencies=[Depends(authenticate)])
    async def chat_profile_save(chat_id: int):
        return profile_view(await operation(app.state.collector.save_profile, chat_id))

    def dossier_title(chat_id):
        if not app.state.store.get_setting("dossiers", {}).get(str(chat_id)):
            raise HTTPException(409, "Turn on people profiles for this chat first.")
        return next((t["title"] for t in app.state.store.targets() if t["chat_id"] == chat_id), None)

    @app.post("/api/chats/{chat_id}/dossier", dependencies=[Depends(authenticate)])
    async def dossier_switch(chat_id: int, body: DossierSwitch):
        require_live()
        dossier.set_enabled(app.state.store, chat_id, body.enabled)
        return {"enabled": body.enabled, "dossiers": dossier.enabled_chats(app.state.store)}

    @app.get("/api/chats/{chat_id}/dossier", dependencies=[Depends(authenticate)])
    async def dossier_view(chat_id: int):
        title = dossier_title(chat_id)
        return await asyncio.to_thread(dossier.signed, app.state.store, app.state.vault, chat_id, title, producer())

    async def dossier_file(chat_id, password=None):
        title = dossier_title(chat_id)
        value = await asyncio.to_thread(dossier.signed, app.state.store, app.state.vault, chat_id, title, producer())
        directory = root / "temporary-exports"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / ("tgwitness-export-dossier-" + secrets.token_hex(8) + ".json")
        path.write_bytes(json.dumps(value, ensure_ascii=False, indent=1).encode("utf-8"))
        if password is not None:
            path = await asyncio.to_thread(encrypt_export, path, "json", password,
                                           "tgwitness-dossier-" + str(chat_id) + ".json")
        return path

    @app.get("/api/chats/{chat_id}/dossier/export", dependencies=[Depends(authenticate)])
    async def dossier_export(chat_id: int):
        path = await dossier_file(chat_id)
        return FileResponse(path, filename="tgwitness-dossier-" + str(chat_id) + ".json", media_type="application/json",
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.post("/api/chats/{chat_id}/dossier/export", dependencies=[Depends(authenticate)])
    async def dossier_export_encrypted(chat_id: int, body: ExportPassword):
        path = await dossier_file(chat_id, body.password)
        return FileResponse(path, filename="tgwitness-dossier-" + str(chat_id) + "-encrypted.zip",
                            media_type="application/zip", background=BackgroundTask(path.unlink, missing_ok=True))

    @app.get("/api/witness", dependencies=[Depends(authenticate)])
    async def witness_state():
        return witness_api.state(app.state.vault, app.state.store)

    @app.post("/api/witness/tokens", dependencies=[Depends(authenticate)])
    async def witness_token(body: WitnessTokenCreate):
        require_live()
        if not body.label.strip():
            raise HTTPException(422, "Enter a name for this witness.")
        token, entry = witness_api.create(app.state.vault, app.state.store, body.label.strip())
        return {"token": token, "id": entry["id"], **witness_api.state(app.state.vault, app.state.store)}

    @app.delete("/api/witness/tokens/{token_id}", dependencies=[Depends(authenticate)])
    async def witness_revoke(token_id: str):
        require_live()
        try:
            witness_api.revoke(app.state.vault, app.state.store, token_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from None
        return witness_api.state(app.state.vault, app.state.store)

    @app.get("/api/witness/head")
    async def witness_head(request: Request, entry=Depends(authenticate_witness)):
        return witness_api.head(app.state.store, app.state.vault, entry, request.headers,
                                request.client.host if request.client else None, app.state.collector.status())

    @app.get("/api/notifications", dependencies=[Depends(authenticate)])
    async def notifications(request: Request):
        lang = i18n.pick(request.cookies.get(i18n.COOKIE), request.headers.get("accept-language"))
        items, allowed = alerts.panel_items(app.state.store, i18n.words(lang),
                                            tuning.value(app.state.store, "panel_notifications")), visible_chats(request)
        return {"items": [i for i in items if allowed is None or i.get("chat_id") in allowed]}

    @app.get("/api/chats/{chat_id}/scale", dependencies=[Depends(authenticate)])
    async def chat_scale(chat_id: int):
        return await operation(app.state.collector.chat_scale, chat_id)

    @app.get("/api/avatar/{peer_id}", dependencies=[Depends(authenticate)])
    async def avatar(request: Request, peer_id: int):
        if app.state.store.get_setting("demo", False):
            raise HTTPException(404)
        allowed = visible_chats(request)
        if allowed is not None and peer_id not in allowed and not app.state.store.sender_in_chats(peer_id, allowed):
            raise HTTPException(404)
        path = await app.state.collector.avatar(peer_id)
        if not path:
            raise HTTPException(404)
        return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})

    @app.post("/api/chat-export/start", dependencies=[Depends(authenticate)])
    async def chat_export_start(request: Request, body: ChatExport):
        require_chat(request, body.chat_id)
        return await operation(app.state.collector.start_export, body.chat_id,
                               report.resolved(app.state.store, panel_language(request)))

    @app.get("/api/report-options", dependencies=[Depends(authenticate)])
    async def get_report_options():
        return report.saved(app.state.store).model_dump()

    @app.post("/api/report-options", dependencies=[Depends(authenticate)])
    async def set_report_options(body: report.ReportOptions):
        # Recorded, signed, in every export manifest and report seal; not a journal event of its own.
        return report.save(app.state.store, body).model_dump()

    def export_visible(request):
        state, allowed = app.state.collector.export_state, visible_chats(request)
        return allowed is None or not state or state["chat_id"] in allowed

    @app.get("/api/chat-export/{export_id}", dependencies=[Depends(authenticate)])
    async def chat_export_poll(request: Request, export_id: str):
        return app.state.collector.poll_export(export_id) if export_visible(request) else {"phase": "unknown"}

    @app.post("/api/chat-export/{export_id}/cancel", dependencies=[Depends(authenticate)])
    async def chat_export_cancel(request: Request, export_id: str):
        if not export_visible(request):
            raise HTTPException(403, "This chat is not open to this access.")
        return await operation(app.state.collector.cancel_export, export_id)

    @app.get("/api/chat-export/{export_id}/download", dependencies=[Depends(authenticate)])
    async def chat_export_download(request: Request, export_id: str):
        path = app.state.collector.export_result_path(export_id) if export_visible(request) else None
        if not path:
            raise HTTPException(404, "No finished chat export is available to download.")
        return FileResponse(path, filename="tgwitness-chat-export.zip", media_type="application/zip",
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.get("/api/checkpoint", dependencies=[Depends(authenticate)])
    async def get_checkpoint():
        return checkpoint(app.state.store, app.state.vault)

    @app.get("/api/run-receipt", dependencies=[Depends(authenticate)])
    async def get_run_receipt():
        statement = {"format": "tgwitness-run-receipt-v1", "run": app.state.run_receipt,
                     "journal_event_seq": app.state.run_event_seq}
        return {"statement": statement, "signature": app.state.vault.sign(canonical(statement)),
                "public_key": app.state.vault.public_key}

    @app.get("/api/assurance")
    async def assurance_statement(challenge: str = ""):
        """Public in high-assurance mode only: the signing key and the host it was created on.
        No message content, sources or account data; absent from ordinary installations."""
        if not app.state.assurance:
            raise HTTPException(404)
        if challenge and (len(challenge) != 32 or any(c not in "0123456789abcdef" for c in challenge)):
            raise HTTPException(422, "challenge must be 32 lowercase hexadecimal characters")
        return await asyncio.to_thread(
            assurance.statement, app.state.vault, app.state.run_receipt, app.state.run_event_seq,
            app.state.assurance["mode"], app.state.assurance["provider"], challenge or None)

    @app.get("/api/anchor-request", dependencies=[Depends(authenticate)])
    async def anchor_request():
        return Response(request_archive(checkpoint(app.state.store, app.state.vault)),
                        media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="tgwitness-timestamp-request.zip"'})

    @app.post("/api/verify", dependencies=[Depends(authenticate)])
    async def verify():
        try:
            return await asyncio.to_thread(app.state.store.verify, app.state.vault.public_key)
        except Exception:
            raise HTTPException(409, "Journal integrity verification failed. Preserve the directory for inspection.") from None

    async def build_export(fmt, request, password=None):
        options = report.resolved(app.state.store, panel_language(request))
        async with export_lock:
            try:
                path = await asyncio.to_thread(export_file, app.state.store, app.state.vault, fmt, options)
                if password is not None:
                    path = await asyncio.to_thread(encrypt_export, path, fmt, password)
            except Exception as exc:
                app.state.store.append("export.failed", {"format": fmt, "error_type": type(exc).__name__})
                raise HTTPException(409, "Export failed integrity, size, or file checks. Inspect local data and limits.") from None
        from .webhooks import export_completed
        await export_completed(app.state.store, app.state.vault, profile_id)
        app.state.alert_wakeup.set()
        return path

    @app.get("/api/export/{fmt}", dependencies=[Depends(authenticate)])
    async def export(request: Request, fmt: Literal["zip", "jsonl", "csv", "html"]):
        path = await build_export(fmt, request)
        media_types = {"zip": "application/zip", "jsonl": "application/x-ndjson",
                       "csv": "text/csv", "html": "text/html"}
        return FileResponse(path, filename="tgwitness-evidence." + fmt, media_type=media_types[fmt],
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.post("/api/export/{fmt}", dependencies=[Depends(authenticate)])
    async def export_encrypted(request: Request, fmt: Literal["zip", "jsonl", "csv", "html"], body: ExportPassword):

        path = await build_export(fmt, request, body.password)
        return FileResponse(path, filename="tgwitness-evidence-" + fmt + "-encrypted.zip", media_type="application/zip",
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.get("/api/media/{digest}", dependencies=[Depends(authenticate)])
    async def media(request: Request, digest: str):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise HTTPException(404)
        allowed = visible_chats(request)
        if allowed is not None and not app.state.store.media_in_chats(digest, allowed):
            raise HTTPException(404)
        path = root / "media" / digest
        if not path.is_file():
            raise HTTPException(404)

        return FileResponse(path, media_type="application/octet-stream", filename=digest)

    from .webhook_api import register as register_webhooks
    register_webhooks(app, authenticate, profile_id)

    if allow_profiles:

        @app.post("/api/access/login")
        async def access_login(request: Request, body: AccessLogin):
            try:
                result = app.state.access.login(body.token.strip(), client_address(request),
                                                request.headers.get("user-agent"))
            except Refused as exc:
                raise HTTPException(403, str(exc)) from None
            if result is None:
                reject_access(request, "Unknown access token. Use the panel token from panel-token.txt "
                                       "or a token issued by the administrator.")
            session, principal = result
            return {"session": session, "me": principal.public()}

        @app.post("/api/access/logout")
        async def access_logout(principal=Depends(identify)):
            if principal.session_id:
                app.state.access.end(principal.session_id, "signed out")
            return {"signed_out": True}

        @app.get("/api/access/me")
        async def access_me(principal=Depends(identify)):
            return principal.public()

        def known_workspaces(settings):
            unknown = set(settings.workspaces) - set(app.state.profiles.entries)
            if unknown:
                raise HTTPException(422, "Unknown workspace.")
            return settings

        def access_state(request):
            return app.state.access.state(request.state.principal.session_id)

        @app.get("/api/access", dependencies=[Depends(authenticate)])
        async def access_overview(request: Request):
            return access_state(request)

        @app.post("/api/access/grants", dependencies=[Depends(authenticate)])
        async def access_issue(request: Request, body: GrantSettings):
            try:
                token, grant = app.state.access.issue(known_workspaces(body))
            except Refused as exc:
                raise HTTPException(422, str(exc)) from None
            return {"token": token, "id": grant["id"], **access_state(request)}

        @app.patch("/api/access/grants/{grant_id}", dependencies=[Depends(authenticate)])
        async def access_change(request: Request, grant_id: str, body: GrantSettings):
            try:
                app.state.access.change(grant_id, known_workspaces(body))
            except Refused as exc:
                raise HTTPException(422, str(exc)) from None
            return access_state(request)

        @app.delete("/api/access/grants/{grant_id}", dependencies=[Depends(authenticate)])
        async def access_revoke(request: Request, grant_id: str):
            try:
                app.state.access.revoke(grant_id)
            except Refused as exc:
                raise HTTPException(404, str(exc)) from None
            return access_state(request)

        @app.delete("/api/access/sessions/{session_id}", dependencies=[Depends(authenticate)])
        async def access_end_session(request: Request, session_id: str):
            if not app.state.access.end(session_id, "ended by the administrator"):
                raise HTTPException(404, "This session has already ended.")
            return access_state(request)

        @app.post("/api/access/admin", dependencies=[Depends(authenticate)])
        async def access_admin(request: Request, body: AdminSettings):
            app.state.access.set_admin(body)
            return access_state(request)

        @app.get("/api/access/console", dependencies=[Depends(authenticate)])
        async def access_console(after: int = 0):
            console = app.state.access.console
            if after > console.counter:
                after = 0
            lines = console.after(after)
            return {"lines": lines, "last": lines[-1]["n"] if lines else after}

        from .archive_api import register as register_archive
        register_archive(app, authenticate)
        from .analysis_api import register as register_analysis
        register_analysis(app, authenticate)
        from .media_analysis_api import register as register_media_analysis
        register_media_analysis(app, authenticate)
        app.mount("/profiles", ProfileDispatch(app), name="profiles")
    app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="panel")
    return app
