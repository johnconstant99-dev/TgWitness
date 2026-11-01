"""Restricted, single-account/single-chat capture application for disposable runners.

This deliberately does not mount the normal administration app. Configuration is
supplied by the pinned runner, never by an HTTP request. No import, file upload,
network configuration, arbitrary RPC, signing, or plaintext download API exists.
"""
import argparse
import asyncio
import hashlib
import io
import json
import logging
import secrets
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .collector import Collector, WitnessClient
from .evidence import export_file
from .middleware import KEEP_ALIVE_SECONDS, RequestLimit
from .provenance import run_receipt
from .sealed_crypto import recipient_id
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
    chat_id: int


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
        receipt = run_receipt(self.store, self.vault)
        self.collector.run_id = receipt["run_id"]
        self.store.append("collector.started", receipt)
        self.store.append("sealed.started", {"format": "tgwitness-sealed-run-v1",
            "recipient_sha256": self.recipient, "context": config["context"],
            "deadline_seconds": config["seconds"], "session_import_allowed": False,
            "meaning": "Fresh Telegram login; one selected chat. Runtime trust depends on the external attestation."})
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
                "recipient_sha256": self.recipient, "context": self.config["context"], "revocation": self.revocation}

    def require_login(self):
        if self.phase != "login" or self.store.get_setting("account", None):
            raise ValueError("This capsule already has an account or has finished")

    async def begin(self, chat_id):
        if self.phase != "login" or not self.store.get_setting("account", None):
            raise ValueError("Authorize a fresh Telegram session first")
        if chat_id not in self.collector.dialog_cache:
            raise ValueError("Select a chat from this account's dialog list")
        chat = self.collector.dialog_cache[chat_id]
        self.store.set_target(chat_id, chat["title"], chat["kind"], True)
        await self.collector.start()
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

    async def finish(self, reason, cancel=False):
        if self.phase in TERMINAL:
            return
        had_capture = self.phase == "collecting"
        self.phase, self.reason = "sealing", reason
        try:

            pending = self.collector.login_client
            before_stop = await self.revoke() if pending is not None else "no_session"
            await self.collector.stop(shutdown=True)
            after_stop = await self.revoke()
            outcomes = (before_stop, after_stop)
            revoked = ("not_confirmed" if "not_confirmed" in outcomes else
                       "revoked" if "revoked" in outcomes else "no_session")
            self.revocation = revoked
            self.store.append("sealed.finished", {"reason": reason, "revocation": revoked,
                "history": self.collector.history.status(), "media": self.store.media_stats(),
                "meaning": "Partial reads, skipped attachments and failed downloads remain visible in this journal."})
            if cancel or not had_capture:
                self.phase = "cancelled"
                private_write(self.output / "result.json", canonical({"phase": self.phase}))
                return
            archive = await complete_in_thread(export_file, self.store, self.vault, "zip")

            shutil.move(str(archive), self.output / "evidence.zip")
            self.phase = "sealed"
            private_write(self.output / "result.json", canonical({"phase": "sealed"}))
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
    async def phone(body: Phone):
        return await operation(app.state.session.collector.start_phone, body.phone,
                               body.api_id, body.api_hash, login=True, fresh=True)

    @app.post("/api/code")
    async def code(body: Code):
        return await operation(app.state.session.collector.confirm_code, body.code, login=True)

    @app.post("/api/password")
    async def password(body: Password):
        return await operation(app.state.session.collector.confirm_password, body.password, login=True)

    @app.post("/api/qr")
    async def qr(body: Login):
        import qrcode
        from qrcode.image.svg import SvgPathImage
        result = await operation(app.state.session.collector.start_qr, body.api_id, body.api_hash, login=True, fresh=True)
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
        await operation(app.state.session.begin, body.chat_id)
        return app.state.session.status()

    @app.post("/api/resume")
    async def resume():
        return await operation(app.state.session.collector.history.resume)

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
