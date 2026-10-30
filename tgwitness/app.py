import asyncio
import base64
import io
import ipaddress
import json
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
from .network import NetworkConfig, parse_mtproxy_link
from .proxy_catalog import PublicCatalog
from .monitoring import Capture, Monitoring, capture_settings, monitoring_settings
from .scope import (EXCLUDE_LIMIT, WIDE_WARNING, Recheck, ScopeUpdate, recheck_settings, scope_settings,
                    unexclude)
from . import assurance
from . import dossier
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


class AlertUpdate(alerts.AlertSettings):
    # Write-only: None keeps the saved destinations; saved addresses are only shown masked.
    urls: list[str] | None = Field(default=None, max_length=20)
    add_urls: list[str] = Field(default=[], max_length=20)  # appended to the saved (or given) destinations


class ExportPassword(BaseModel):
    # ZIP AES derives its key with 1,000 PBKDF2-SHA1 rounds, so length is what protects the file.
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
    # Write-only: empty keeps the saved keys; saved keys are never sent back to the browser.
    access_key: str = Field(default="", max_length=256, pattern=r"^\S*$")
    secret_key: str = Field(default="", max_length=256, pattern=r"^\S*$")


class Snapshot(BaseModel):
    chat_id: int
    limit: int = Field(default=100, ge=1, le=10000)  # the workspace's own maximum is a panel parameter


class ParametersUpdate(BaseModel):
    # Only the parameters to change; null restores a default.
    values: dict[str, bool | int | float | list[str] | None] = Field(max_length=200)


class ChatExport(BaseModel):
    chat_id: int


class MultiExportStart(BaseModel):
    chat_id: int
    lead: str = Field(default="default", max_length=64)
    profiles: list[str] = Field(default_factory=list, max_length=256)


class ProfileCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


def create_app(data_dir=None, demo=False, client_factory=None, token_override=None, allow_profiles=True,
               account_guard=None):
    root = Path(data_dir or "data").resolve()
    failures = defaultdict(deque)
    bearer = HTTPBearer(auto_error=False)
    op_lock = asyncio.Lock()
    export_lock = asyncio.Lock()
    public_proxies = PublicCatalog(root)

    @asynccontextmanager
    async def lifespan(app):
        instance = InstanceLock(root)
        store = None
        resume_task = None
        anchor_task = None
        replica_task = None
        alert_task = None
        host_task = None
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
            app.state.store, app.state.vault, app.state.collector = store, vault, collector
            # This capability never exposes the real panel token (including an env override).
            # It is accepted only for a directly accessed, isolated synthetic demo.
            app.state.local_demo_token = secrets.token_urlsafe(32)
            app.state.run_receipt = run_receipt(store, vault)
            # High-assurance deployments only: the host measured into the signed start record.
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
            app.state.alert_wakeup = asyncio.Event()
            if not store.get_setting("demo", False):
                alert_task = asyncio.create_task(alerts.alert_loop(
                    store, vault, collector.network_config, app.state.alert_wakeup))
                anchor_task = asyncio.create_task(anchor_loop(
                    store, collector.network_config, app.state.anchor_wakeup, app.state.anchor_status))
                replica_task = asyncio.create_task(replica.replica_loop(
                    store, vault, collector.network_config, app.state.replica_wakeup, app.state.replica_status))
                if app.state.assurance:
                    host_task = asyncio.create_task(assurance.assurance_loop(
                        store, app.state.assurance["mode"], app.state.assurance["provider"]))

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
                    return create_app(path, client_factory=client_factory, **options)
                profiles = Profiles(app, root, child_factory)
                app.state.profiles = profiles
                await profiles.open()
                app.state.multi_export = MultiExport(profiles)
            yield
        finally:
            try:
                if getattr(app.state, "multi_export", None):
                    await app.state.multi_export.close()
                if profiles:
                    await profiles.close()
                for task in (resume_task, anchor_task, replica_task, alert_task, host_task):
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

    app = FastAPI(title="TgWitness", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestLimit, max_body=16384)

    @app.middleware("http")
    async def headers(request, call_next):
        if request.headers.get("content-length", "").isdigit() and int(request.headers["content-length"]) > request_limit(request.url.path):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        response.headers["Cache-Control"] = "no-store"
        return response

    # FastAPI's default validation error echoes input, which can contain credentials.
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
        # A noisy client behind the same proxy must not lock out valid tokens.
        # Both authentication paths share this bounded failure accounting.
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

    async def authenticate(request: Request, credential: HTTPAuthorizationCredentials = Depends(bearer)):
        accepted = credential and (secrets.compare_digest(credential.credentials.encode(), app.state.vault.token.encode())
                    or (local_demo_access(request) and secrets.compare_digest(
                        credential.credentials.encode(), app.state.local_demo_token.encode())))
        if not accepted:
            reject_access(request, "Enter the panel access token from panel-token.txt in your data directory.")

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
    async def status():
        store, vault = app.state.store, app.state.vault
        return {"version": __version__, "demo": store.get_setting("demo", False),
                "collector": app.state.collector.status(), "stats": store.stats(),
                "targets": store.targets(), "capture": capture_settings(store),
                "monitoring": monitoring_settings(store), "scope": scope_settings(store),
                "recheck": recheck_settings(store), "dossiers": dossier.enabled_chats(store),
                "parameters": tuning.values(store),
                "fingerprint": fingerprint(vault.public_key), "limitations": LIMITS,
                "protection": {"vault_key_mode": vault.key_mode, "secrets_encrypted": True,
                               "journal_encrypted_by_app": False, "media_encrypted_by_app": False},
                "run_id": app.state.run_receipt["run_id"]}

    if allow_profiles:
        @app.get("/api/profiles", dependencies=[Depends(authenticate)])
        async def profiles_list():
            return {"profiles": app.state.profiles.summary(), "limit": Profiles.MAX_PROFILES,
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

        @app.post("/api/multi-export/start", dependencies=[Depends(authenticate)])
        async def multi_export_start(body: MultiExportStart):
            return await operation(app.state.multi_export.start, body.chat_id, body.profiles, body.lead)

        @app.get("/api/multi-export/current", dependencies=[Depends(authenticate)])
        async def multi_export_current():
            return app.state.multi_export.public()

        @app.get("/api/multi-export/{export_id}", dependencies=[Depends(authenticate)])
        async def multi_export_poll(export_id: str):
            return app.state.multi_export.poll(export_id)

        @app.post("/api/multi-export/{export_id}/cancel", dependencies=[Depends(authenticate)])
        async def multi_export_cancel(export_id: str):
            return await app.state.multi_export.cancel(export_id)

        @app.get("/api/multi-export/{export_id}/download", dependencies=[Depends(authenticate)])
        async def multi_export_download(export_id: str):
            path = app.state.multi_export.result_path(export_id)
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
    async def get_events(chat_id: int | None = None, message_id: int | None = None,
                         kind: str | None = None, before: int | None = None,
                         search: str | None = None, limit: int = 100):
        if not 1 <= limit <= 500 or (search and len(search) > 200):
            raise HTTPException(422, "Limit must be 1–500; search must be at most 200 characters.")
        records = app.state.store.events(chat_id, message_id, kind, before, limit, search)
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

    @app.post("/api/network", dependencies=[Depends(authenticate)])
    async def network(body: NetworkConfig):
        return await operation(app.state.collector.set_network, body)

    @app.get("/api/network/catalog", dependencies=[Depends(authenticate)])
    async def network_catalog():
        try:
            return public_proxies.public()
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None

    @app.post("/api/network/catalog/refresh", dependencies=[Depends(authenticate)])
    async def network_catalog_refresh():
        return await operation(public_proxies.refresh)

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
    async def target(body: Target):
        require_live()
        collector, store = app.state.collector, app.state.store
        async with op_lock:
            existing = next((t for t in store.targets() if t["chat_id"] == body.chat_id), None)
            entry = collector.dialog_cache.get(body.chat_id) or existing
            if not entry:
                raise HTTPException(400, "Refresh the group list and select an available target.")
            with store.transaction():
                # An operator's choice is final: the observation scope never re-enables or pauses it.
                store.set_target(body.chat_id, entry["title"], entry["kind"], body.enabled, origin="manual",
                                 priority=body.priority)
                included = body.enabled and unexclude(store, body.chat_id)
                store.append("target.changed", {"title": entry["title"], "enabled": body.enabled,
                                               **({"removed_from_scope_exclusions": True} if included else {}),
                                               "coverage": "No observations promised while target is disabled."},
                             body.chat_id)
        return {"targets": store.targets()}

    @app.post("/api/targets/priority", dependencies=[Depends(authenticate)])
    async def target_priority(body: TargetPriority):
        require_live()
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
                    # Otherwise folder or account mode would add it again with its next message.
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

    def evidence_state():
        store = app.state.store
        return {"settings": evidence_settings(store), "last": store.get_setting("evidence_last", None),
                "busy": app.state.anchor_status["busy"], "route": app.state.collector.network_config().kind,
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
            request_anchor(store, vault, app.state.anchor_wakeup)  # the key fingerprint is anchored first
        return evidence_state()

    @app.post("/api/evidence/anchor", dependencies=[Depends(authenticate)])
    async def evidence_anchor():
        require_live()
        if not evidence_settings(app.state.store)["enabled"]:
            raise HTTPException(409, "Turn on evidence mode first.")
        request_anchor(app.state.store, app.state.vault, app.state.anchor_wakeup)
        return evidence_state()

    def replica_state():
        store, vault = app.state.store, app.state.vault
        settings, secrets = replica.replica_settings(store), vault.read("replica")
        return {"settings": settings, "has_credentials": bool(secrets.get("access_key")),
                "has_key": bool(secrets.get("key")), "last": store.get_setting("replica_last", None),
                "busy": app.state.replica_status["busy"], "route": app.state.collector.network_config().kind,
                "location": replica.workspace_prefix(settings, vault.public_key)}

    @app.get("/api/replica", dependencies=[Depends(authenticate)])
    async def get_replica():
        return replica_state()

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
                "route": app.state.collector.network_config().kind}

    @app.get("/api/alerts", dependencies=[Depends(authenticate)])
    async def get_alerts():
        return alert_state()

    @app.post("/api/alerts", dependencies=[Depends(authenticate)])
    async def set_alerts(body: AlertUpdate):
        require_live()
        store, vault = app.state.store, app.state.vault
        urls = vault.read("alerts").get("urls", []) if body.urls is None else [u.strip() for u in body.urls if u.strip()]
        urls += [u for u in dict.fromkeys(u.strip() for u in body.add_urls) if u and u not in urls]
        for url in urls:
            if len(url) > 2048 or not alerts.describe(url):
                raise HTTPException(422, "Apprise does not recognise one of the destination addresses. Check it against the Apprise wiki.")
        problem = alerts.route_problem(urls, app.state.collector.network_config())
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
            alerts.tr(words, "Notifications from this workspace reach this destination."), app.state.collector.network_config())
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
        s3 = replica.client(settings, secrets, app.state.collector.network_config())
        name = replica.workspace_prefix(settings, vault.public_key) + "/connection-test.tgwr"
        try:
            # With retention set, the test object is locked for one day only, then read back.
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
    async def snapshot(body: Snapshot):
        if body.limit > tuning.value(app.state.store, "snapshot_max"):
            raise HTTPException(422, "The snapshot is larger than this workspace allows. Raise the limit in Parameters.")
        return await operation(app.state.collector.snapshot, body.chat_id, body.limit)

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
    async def chats():
        store = app.state.store
        overview = store.chat_overview()
        listed = [{**t, "enabled": bool(t["enabled"]), **overview.pop(t["chat_id"], {})} for t in store.targets()]
        listed += [{"chat_id": chat_id, "title": None, "kind": None, "enabled": False, **extra}
                   for chat_id, extra in overview.items()]
        return {"chats": listed}

    @app.post("/api/interactions/preview", dependencies=[Depends(authenticate)])
    async def interaction_preview(body: interactions.Preview):
        return await operation(interactions.preview, app.state.collector, body)

    @app.post("/api/interactions", dependencies=[Depends(authenticate)])
    async def interaction_action(body: interactions.Action):
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
        return {"items": alerts.panel_items(app.state.store, i18n.words(lang),
                                            tuning.value(app.state.store, "panel_notifications"))}

    @app.get("/api/chats/{chat_id}/scale", dependencies=[Depends(authenticate)])
    async def chat_scale(chat_id: int):
        return await operation(app.state.collector.chat_scale, chat_id)

    @app.get("/api/avatar/{peer_id}", dependencies=[Depends(authenticate)])
    async def avatar(peer_id: int):
        if app.state.store.get_setting("demo", False):
            raise HTTPException(404)
        path = await app.state.collector.avatar(peer_id)
        if not path:
            raise HTTPException(404)
        return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})

    @app.post("/api/chat-export/start", dependencies=[Depends(authenticate)])
    async def chat_export_start(body: ChatExport):
        return await operation(app.state.collector.start_export, body.chat_id)

    @app.get("/api/chat-export/{export_id}", dependencies=[Depends(authenticate)])
    async def chat_export_poll(export_id: str):
        return app.state.collector.poll_export(export_id)

    @app.post("/api/chat-export/{export_id}/cancel", dependencies=[Depends(authenticate)])
    async def chat_export_cancel(export_id: str):
        return await operation(app.state.collector.cancel_export, export_id)

    @app.get("/api/chat-export/{export_id}/download", dependencies=[Depends(authenticate)])
    async def chat_export_download(export_id: str):
        path = app.state.collector.export_result_path(export_id)
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

    async def build_export(fmt, password=None):
        async with export_lock:
            try:
                path = await asyncio.to_thread(export_file, app.state.store, app.state.vault, fmt)
                if password is not None:
                    path = await asyncio.to_thread(encrypt_export, path, fmt, password)
            except Exception as exc:
                app.state.store.append("export.failed", {"format": fmt, "error_type": type(exc).__name__})
                raise HTTPException(409, "Export failed integrity, size, or file checks. Inspect local data and limits.") from None
        return path

    @app.get("/api/export/{fmt}", dependencies=[Depends(authenticate)])
    async def export(fmt: Literal["zip", "jsonl", "csv", "html"]):
        path = await build_export(fmt)
        media_types = {"zip": "application/zip", "jsonl": "application/x-ndjson",
                       "csv": "text/csv", "html": "text/html"}
        return FileResponse(path, filename="tgwitness-evidence." + fmt, media_type=media_types[fmt],
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.post("/api/export/{fmt}", dependencies=[Depends(authenticate)])
    async def export_encrypted(fmt: Literal["zip", "jsonl", "csv", "html"], body: ExportPassword):
        # The password arrives in the request body and is never stored or written to the journal.
        path = await build_export(fmt, body.password)
        return FileResponse(path, filename="tgwitness-evidence-" + fmt + "-encrypted.zip", media_type="application/zip",
                            background=BackgroundTask(path.unlink, missing_ok=True))

    @app.get("/api/media/{digest}", dependencies=[Depends(authenticate)])
    async def media(digest: str):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise HTTPException(404)
        path = root / "media" / digest
        if not path.is_file():
            raise HTTPException(404)
        # Send as an attachment, never execute active content inside the panel origin.
        return FileResponse(path, media_type="application/octet-stream", filename=digest)

    if allow_profiles:
        app.mount("/profiles", ProfileDispatch(app), name="profiles")
    app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="panel")
    return app
