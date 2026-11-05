import argparse
import asyncio
import errno
import hashlib
import io
import json
import logging
import secrets
import shutil
import time
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .collector import Collector, WitnessClient
from .account_export import AccountExport, AccountExportOptions, file_sha
from .evidence import BundleSizeLimit, export_file
from .middleware import KEEP_ALIVE_SECONDS, RequestLimit
from .monitoring import Capture, capture_settings, normalize_capture
from .export_preflight import preview_capture
from .provenance import run_receipt
from .sealed_crypto import recipient_id
from .sealed_parts import EncryptedParts, PART_BYTES, SEALED_RESULT
from .security import InstanceLock, Vault, private_write
from .store import Store, canonical
from .workers import complete_in_thread

STATIC = Path(__file__).with_name("static")
TERMINAL = {"sealed", "cancelled", "failed"}


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictBody):
    api_id: int | None = Field(default=None, strict=True, gt=0, le=2147483647)
    api_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{32}$")

    @field_validator("api_id", "api_hash", mode="before")
    @classmethod
    def empty_field(cls, value):
        return None if isinstance(value, str) and not value.strip() else value

    @model_validator(mode="after")
    def complete_pair(self):
        if (self.api_id is None) != (self.api_hash is None):
            raise ValueError("Supply both API credentials or leave both empty")
        return self


class Phone(Login):
    phone: str = Field(pattern=r"^\+[0-9]{7,16}$")


class Code(StrictBody):
    code: str = Field(min_length=3, max_length=12, pattern=r"^[0-9 -]+$")


class Password(StrictBody):
    password: str = Field(min_length=1, max_length=512)


class Selection(StrictBody):
    mode: Literal["chat", "account"] = "chat"
    chat_id: int | None = Field(default=None, strict=True)
    capture: Capture = Field(default_factory=lambda: Capture.model_validate({
        **normalize_capture(None), "include_avatars": False, "messages_first": True}))
    account_options: AccountExportOptions | None = None

    @model_validator(mode="after")
    def scope(self):
        if self.mode == "chat" and (self.chat_id is None or self.account_options is not None):
            raise ValueError("Select a chat and its capture settings.")
        if self.mode == "account" and (self.chat_id is not None or self.account_options is None):
            raise ValueError("Supply account export options, including any selected chat IDs.")
        if self.mode == "account" and "capture" in self.model_fields_set:
            raise ValueError("Account export uses account_options; capture settings do not apply.")
        if self.account_options is not None and not self.account_options.messages_first:
            raise ValueError("Restricted account exports preserve messages before attachments.")
        return self


class Session:
    def __init__(self, root, output, config, client_factory):
        self.root, self.output, self.config = Path(root), Path(output), config

        if self.root.exists() and any(self.root.iterdir()):
            raise ValueError("A sealed capture requires a new empty data directory")
        if self.output.exists() and any(self.output.iterdir()):
            raise ValueError("A sealed capture requires a new empty output directory")
        if len(config["token"]) != 43 or not 60 <= config["seconds"] <= 7200:
            raise ValueError("Invalid sealed session configuration")
        self.recipient = recipient_id(config["recipient"])
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.instance_lock = InstanceLock(self.root)
        self.vault, self.store = Vault(self.root), Store(self.root)
        self.store.bind(self.vault)
        self.vault.save("network", {"kind": "direct"})
        self.store.set_setting("route_policy", {"exposure": "tunnel", "outside_enabled": False})
        self.store.set_setting("parameters", {"dialog_limit": 20000, "export_max_gib": 4})
        self.collector = Collector(self.store, self.vault, client_factory)
        self.account_export = AccountExport(self.collector, self.store, self.vault)
        self.account_export.packaging_copies = 2
        self.account_job = None
        receipt = run_receipt(self.store, self.vault)
        self.collector.run_id = receipt["run_id"]
        self.store.append("collector.started", receipt)
        self.store.append("sealed.started", {"format": "tgwitness-sealed-run-v1",
            "recipient_sha256": self.recipient, "context": config["context"],
            "deadline_seconds": config["seconds"], "session_import_allowed": False,
            "meaning": "Fresh Telegram login; selected chat or account data. Runtime trust depends on the external attestation."})
        self.lock = asyncio.Lock()
        self.phase, self.reason = "login", None
        self.revocation = None
        self.started, self.closed = time.monotonic(), False
        self.monitor_task = None
        self.finish_task = None

    def status(self):
        return {"phase": self.phase, "login": self.collector.phase, "reason": self.reason,
                "authorized": bool(self.store.get_setting("account", None)),
                "remaining_seconds": max(0, int(self.config["seconds"] - (time.monotonic() - self.started))),
                "history": self.collector.history.status(), "media": self.store.media_stats(),
                "capture": capture_settings(self.store),
                "account_export": self.account_export.public(self.account_job) if self.account_job else None,
                "recipient_sha256": self.recipient, "context": self.config["context"], "revocation": self.revocation}

    def require_login(self):
        if self.phase != "login" or self.store.get_setting("account", None):
            raise ValueError("This capsule already has an account or has finished")

    def require_selection(self, chat_id):
        if self.phase != "login" or not self.store.get_setting("account", None):
            raise ValueError("Authorize a fresh Telegram session first")
        if chat_id is not None and chat_id not in self.collector.dialog_cache:
            raise ValueError("Select a chat from this account's dialog list")

    async def preview(self, selection):
        self.require_selection(selection.chat_id)
        if selection.mode == "account":
            from .export_preflight import preview
            result = await preview(self.account_export, selection.account_options.model_dump())
        else:
            result = await preview_capture(self.collector, selection.chat_id,
                                       normalize_capture(selection.capture.model_dump()),
                                       self.status()["remaining_seconds"])
        result["remaining_seconds"] = self.status()["remaining_seconds"]
        result["can_start"] = result["can_start"] and result["remaining_seconds"] > 0
        return result

    async def begin_selection(self, selection):
        if selection.mode == "chat":
            return await self.begin(selection.chat_id, selection.capture)
        self.require_selection(None)
        if self.status()["remaining_seconds"] <= 0:
            raise ValueError("No capture time remains.")
        options = selection.account_options.model_dump()
        self.store.append("sealed.selection", {"mode": "account", "options": options,
            "free_disk_bytes": shutil.disk_usage(self.root).free, "remaining_seconds": self.status()["remaining_seconds"],
            "transport": options["transport"], "total_size_and_duration": "unknown"})
        job = await self.account_export.start(options)
        self.account_job = job["id"]
        self.phase = "collecting"

    async def resume(self):
        if self.phase != "collecting":
            raise ValueError("No capture to resume.")
        if self.account_job:
            return await self.account_export.resume(self.account_job)
        return await self.collector.history.resume()

    async def begin(self, chat_id, capture=None):
        self.require_selection(chat_id)
        settings = normalize_capture((capture or Selection(chat_id=chat_id).capture).model_dump())
        free = shutil.disk_usage(self.root).free
        if free < self.collector.param("media_min_free_mb") * 1024**2 or self.status()["remaining_seconds"] <= 0:
            raise ValueError("Not enough free disk or capture time")
        self.store.set_setting("capture", settings)
        self.store.append("sealed.selection", {"chat_id": chat_id, "capture": settings,
            "free_disk_bytes": free, "remaining_seconds": self.status()["remaining_seconds"],
            "transport": "regular", "total_size_and_duration": "unknown"})
        chat = self.collector.dialog_cache[chat_id]
        self.store.set_target(chat_id, chat["title"], chat["kind"], True)
        await self.collector.history.start()
        self.phase = "collecting"

    async def revoke(self):
        results = []
        clients = [c for c in (self.collector.client, self.collector.login_client) if c is not None]
        for client in clients:
            try:
                async def logout():
                    if not client.is_connected():
                        await client.connect()
                    return bool(await client.log_out())
                results.append("revoked" if await asyncio.wait_for(logout(), 15) else "not_confirmed")
            except Exception:
                results.append("not_confirmed")
        self.vault.save("credentials", {})
        return "not_confirmed" if "not_confirmed" in results else "revoked" if results else "no_session"

    def write_parts(self, source=None):
        with EncryptedParts(self.output, self.vault, self.config) as outgoing:
            if source is not None:
                with source.open("rb") as incoming:
                    for block in iter(lambda: incoming.read(1024**2), b""):
                        outgoing.write(block)
            else:
                export_file(self.store, self.vault, "zip", compact=True, output_stream=outgoing,
                            max_uncompressed_bytes=1024 * 1024**3)

    async def finish(self, reason, cancel=False):
        if self.phase in TERMINAL:
            return
        had_capture = self.phase == "collecting"
        self.phase, self.reason = "sealing", reason
        try:
            acquisition_error = None
            if self.account_job:
                try:
                    await self.account_export.pause(self.account_job)
                    if not cancel:
                        job = await self.account_export.finalize_partial(self.account_job, "Capture ended: " + reason)
                        path = self.account_export.result_path(self.account_job)
                        self.store.append("sealed.account_export", {"job_id": self.account_job, "file": "account-export.zip",
                            "sha256": file_sha(path), "bytes": path.stat().st_size, "complete_within_scope": job["phase"] == "done",
                            "coverage": job["coverage"], "counts": job["counts"]})
                except Exception as exc:
                    acquisition_error = exc
            pending = self.collector.login_client
            before_stop = await self.revoke() if pending is not None else "no_session"
            stop_error = None
            try:
                await self.collector.stop(shutdown=True)
            except Exception as exc:
                stop_error = exc
            after_stop = await self.revoke()
            outcomes = (before_stop, after_stop)
            revoked = ("not_confirmed" if "not_confirmed" in outcomes else
                       "revoked" if "revoked" in outcomes else "no_session")
            self.revocation = revoked
            self.store.append("sealed.finished", {"reason": reason, "revocation": revoked,
                "history": self.collector.history.status(), "media": self.store.media_stats(),
                "account_export": self.account_export.public(self.account_job) if self.account_job else None,
                "meaning": "Partial reads, skipped attachments and failed downloads remain visible in this journal."})
            if acquisition_error:
                raise acquisition_error
            if stop_error:
                raise stop_error
            if cancel or not had_capture:
                self.phase = "cancelled"
                private_write(self.output / "result.json", canonical({"phase": self.phase}))
                return
            try:
                archive = await complete_in_thread(partial(export_file, self.store, self.vault, "zip", compact=bool(self.account_job)))
            except (BundleSizeLimit, OSError) as exc:
                disk_full = isinstance(exc, OSError) and (exc.errno in (errno.ENOSPC, errno.EDQUOT)
                                                         or getattr(exc, "winerror", None) == 112)
                if not isinstance(exc, BundleSizeLimit) and not disk_full:
                    raise
                # export_file has removed the failed temporary ZIP. Reuse the
                # complete journal and every preserved file; never drop evidence
                # silently to make the second attempt fit.
                self.store.append("sealed.packaging", {"mode": "compact",
                    "reason": "disk_full" if disk_full else "archive_size_limit",
                    "full_journal": True, "preserved_media_omitted": False})
                try:
                    archive = await complete_in_thread(partial(export_file, self.store, self.vault, "zip", compact=True))
                except (BundleSizeLimit, OSError) as compact_error:
                    if isinstance(compact_error, OSError) and not (compact_error.errno in (errno.ENOSPC, errno.EDQUOT)
                            or getattr(compact_error, "winerror", None) == 112):
                        raise
                    await complete_in_thread(self.write_parts)
                    archive = None

            if archive is not None and archive.stat().st_size > PART_BYTES:
                await complete_in_thread(self.write_parts, archive)
                archive.unlink()
                archive = None
            if archive is not None:
                shutil.move(str(archive), self.output / "evidence.zip")
            self.phase = "sealed"
            private_write(self.output / "result.json", canonical({"phase": "sealed"} if archive is not None else SEALED_RESULT))
        except Exception as exc:
            self.phase, self.reason = "failed", type(exc).__name__
            (self.output / "evidence.zip").unlink(missing_ok=True)
            private_write(self.output / "result.json", canonical({"phase": "failed"}))

    async def monitor(self):
        while self.phase not in TERMINAL:
            await asyncio.sleep(.2)
            async with self.lock:
                if self.phase in TERMINAL:
                    return
                if time.monotonic() - self.started >= self.config["seconds"]:
                    await self.finish("deadline")
                elif self.phase == "collecting":
                    if self.account_job:
                        if self.account_export.public(self.account_job).get("ready"):
                            await self.finish("account_export_finished")
                        elif self.account_export.storage_pressure():
                            await self.finish("storage_limit")
                        continue
                    state = self.collector.history.status()
                    pending = sum(n for k, n in self.store.media_stats().items() if k in ("queued", "retry", "running"))
                    if state["phase"] in ("complete", "incomplete") and not pending:
                        await self.finish("history_and_media_finished")

    async def close(self):
        if self.closed:
            return
        if self.finish_task:
            await asyncio.shield(self.finish_task)
        if self.monitor_task and self.phase == "sealing":

            await asyncio.shield(self.monitor_task)
        if self.monitor_task:
            self.monitor_task.cancel()
            await asyncio.gather(self.monitor_task, return_exceptions=True)
        async with self.lock:
            if self.phase not in TERMINAL:
                await self.finish("server_shutdown", cancel=True)
            await self.collector.stop(shutdown=True)
            await self.account_export.close()
            self.store.close()
            self.instance_lock.close()
            self.closed = True


def create_app(root, output, config, client_factory=WitnessClient):
    @asynccontextmanager
    async def lifespan(app):
        session = Session(root, output, config, client_factory)
        app.state.session = session
        session.monitor_task = asyncio.create_task(session.monitor())
        try:
            yield
        finally:
            await session.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestLimit, max_body=8192, path_limits=False)
    token_digest = hashlib.sha256(config["token"].encode()).digest()

    @app.middleware("http")
    async def restricted(request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            supplied = request.headers.get("authorization", "")
            good = supplied.startswith("Bearer ") and secrets.compare_digest(
                hashlib.sha256(supplied[7:].encode()).digest(), token_digest)
            if not good:
                return JSONResponse({"detail": "Access denied"}, status_code=401,
                                    headers={"Cache-Control": "no-store"})
            origin = request.headers.get("origin")
            if origin and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
                return JSONResponse({"detail": "Origin denied"}, status_code=403)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        return JSONResponse({"detail": "Invalid request fields"}, status_code=422)

    async def operation(call, *args, login=False, fresh=False):
        session = app.state.session
        async with session.lock:
            if session.phase in TERMINAL or session.phase == "sealing":
                raise HTTPException(409, "This capsule has finished")
            try:
                if login:
                    session.require_login()
                if fresh and session.collector.login_client is not None:
                    raise ValueError("Finish the existing login attempt or cancel this capsule")
                return await asyncio.wait_for(call(*args), 120)
            except Exception as exc:

                raise HTTPException(400, "Operation failed: " + type(exc).__name__) from None

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "sealed.html")

    @app.get("/sealed.js")
    async def script():
        return FileResponse(STATIC / "sealed.js", media_type="text/javascript")

    @app.get("/sealed.css")
    async def styles():
        return FileResponse(STATIC / "sealed.css", media_type="text/css")

    @app.get("/style.css")
    async def workspace_styles():
        return FileResponse(STATIC / "style.css", media_type="text/css")

    @app.get("/theme.js")
    async def workspace_theme():
        return FileResponse(STATIC / "theme.js", media_type="text/javascript")

    @app.get("/mark.svg")
    async def workspace_mark():
        return FileResponse(STATIC / "mark.svg", media_type="image/svg+xml")

    @app.get("/api/status")
    async def status():
        return app.state.session.status()

    @app.post("/api/phone")
    async def phone(body: Phone, request: Request):
        from .client_identity import language_defaults
        languages = language_defaults(request.headers.get("x-tgwitness-language"),
                                      request.headers.get("x-tgwitness-system-language") or request.headers.get("accept-language"))
        return await operation(app.state.session.collector.start_phone, body.phone,
                               body.api_id, body.api_hash, None, languages, login=True, fresh=True)

    @app.post("/api/code")
    async def code(body: Code):
        return await operation(app.state.session.collector.confirm_code, body.code, login=True)

    @app.post("/api/password")
    async def password(body: Password):
        return await operation(app.state.session.collector.confirm_password, body.password, login=True)

    @app.post("/api/qr")
    async def qr(body: Login, request: Request):
        import qrcode
        from qrcode.image.svg import SvgPathImage
        from .client_identity import language_defaults
        languages = language_defaults(request.headers.get("x-tgwitness-language"),
                                      request.headers.get("x-tgwitness-system-language") or request.headers.get("accept-language"))
        result = await operation(app.state.session.collector.start_qr, body.api_id, body.api_hash,
                                 None, languages, login=True, fresh=True)
        output = io.BytesIO()
        qrcode.make(result.pop("url"), image_factory=SvgPathImage).save(output)
        return {**result, "svg": output.getvalue().decode()}

    @app.get("/api/qr/{login_id}")
    async def qr_status(login_id: str):
        return app.state.session.collector.poll_qr(login_id)

    @app.get("/api/dialogs")
    async def dialogs():
        if app.state.session.phase != "login":
            raise HTTPException(409, "Chat selection is already fixed")
        return await operation(app.state.session.collector.dialogs)

    @app.post("/api/collect")
    async def collect(body: Selection):
        await operation(app.state.session.begin_selection, body)
        return app.state.session.status()

    @app.post("/api/preflight")
    async def preflight(body: Selection):
        return await operation(app.state.session.preview, body)

    @app.post("/api/resume")
    async def resume():
        return await operation(app.state.session.resume)

    @app.post("/api/finish")
    async def finish():
        session = app.state.session
        async with session.lock:
            if session.phase != "collecting" or session.finish_task:
                raise HTTPException(409, "No active collection to finish")
            async def finalize():
                async with session.lock:
                    await session.finish("user_finish")
            session.finish_task = asyncio.create_task(finalize())
        return JSONResponse({"phase": "sealing"}, status_code=202)

    @app.post("/api/cancel")
    async def cancel():
        session = app.state.session
        async with session.lock:
            await session.finish("user_cancel", cancel=True)
        return {"phase": session.phase}

    return app


def main():
    import uvicorn
    parser = argparse.ArgumentParser(description="Disposable restricted Telegram capture server")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())

    logging.disable(logging.CRITICAL)
    uvicorn.run(create_app(args.data, args.out, config), host="0.0.0.0", port=8787,
                access_log=False, log_level="critical", proxy_headers=False, timeout_keep_alive=KEEP_ALIVE_SECONDS)


if __name__ == "__main__":
    main()
