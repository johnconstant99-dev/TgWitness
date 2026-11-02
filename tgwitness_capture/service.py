import asyncio
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool

from . import __version__
from .adapters import BrowserCapture, sqlite_snapshot
from .export import export_zip
from .format import canonical, decode, digest
from .journal import Journal, durable_write
from .video import VideoCapture


@dataclass
class Config:
    kind: str = "browser"
    operator: str = "local-operator"
    route_label: str = "operator-managed route; not independently verified"
    public_origin: str = ""
    browser_cdp_url: str = "http://127.0.0.1:9222"
    browser_url_prefix: str = ""
    ayugram_db: str = ""
    client_version: str = "not supplied"
    poll_seconds: float = 2
    snapshot_seconds: float = 60
    heartbeat_seconds: float = 10
    video_input_args: list | None = None
    ffmpeg_executable: str = "ffmpeg"

    @classmethod
    def load(cls, path):
        raw = decode(Path(path).read_bytes()) if path else {}
        if not isinstance(raw, dict) or set(raw) - {field.name for field in fields(cls)}:
            raise ValueError("Unknown capture configuration field")
        config = cls(**raw)
        if config.kind not in {"browser", "ayugram"}:
            raise ValueError("kind must be browser or ayugram")
        for name in ("poll_seconds", "snapshot_seconds", "heartbeat_seconds"):
            value = getattr(config, name)
            if type(value) not in (int, float) or not 0.25 <= value <= 86400:
                raise ValueError("Invalid capture interval")
        for name in ("operator", "route_label", "public_origin", "browser_cdp_url", "browser_url_prefix", "ayugram_db", "client_version", "ffmpeg_executable"):
            if not isinstance(getattr(config, name), str):
                raise ValueError("Invalid configuration string")
        if urlsplit(config.browser_cdp_url).scheme not in {"http", "https", "ws", "wss"}:
            raise ValueError("Invalid CDP endpoint")
        if config.browser_url_prefix and not config.browser_url_prefix.startswith(("http://", "https://")):
            raise ValueError("Browser URL prefix must be HTTP(S)")
        if config.public_origin:
            origin = urlsplit(config.public_origin)
            if origin.scheme not in {"http", "https"} or not origin.netloc or origin.path or origin.query or origin.fragment or origin.username:
                raise ValueError("public_origin must be an HTTP(S) origin without a path")
        if config.video_input_args is not None and (not isinstance(config.video_input_args, list)
                or not all(isinstance(arg, str) and "\x00" not in arg for arg in config.video_input_args)):
            raise ValueError("video_input_args must be a list of FFmpeg input arguments")
        return config


class SettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool | None = None
    screenshots: StrictBool | None = None
    pages: StrictBool | None = None
    database: StrictBool | None = None
    video: StrictBool | None = None


class TargetChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str


class Recorder:
    def __init__(self, root, config):
        self.config = config
        self.journal = Journal(root)
        self.lock = asyncio.Lock()
        self.settings = {"enabled": False, "screenshots": config.kind == "browser",
                         "pages": config.kind == "browser", "database": config.kind == "ayugram", "video": False}
        self.browser = BrowserCapture(config.browser_cdp_url, config.browser_url_prefix)
        self.video = VideoCapture(self.journal, config.video_input_args, config.ffmpeg_executable)
        self.last_attempt = 0
        self.last_heartbeat = 0
        self.last_success = None
        self.last_error = None
        self.task = None
        self.closing = False
        self.tokens = {}
        try:
            for role in ("control", "witness"):
                path = self.journal.root / (role + "-token.txt")
                if not path.exists():
                    durable_write(path, secrets.token_urlsafe(32).encode(), exclusive=True)
                value = path.read_text().strip()
                if len(value) < 32:
                    raise ValueError("Capture token is too short")
                self.tokens[role] = value
            records = self.journal.events()
            previous = [event for event in records if event["kind"] == "service.started"]
            if previous and previous[-1]["payload"]["kind"] != config.kind:
                raise ValueError("Use a separate data directory for each observer kind")
            package = Path(__file__).parent
            source_hash = digest(canonical({path.relative_to(package).as_posix(): digest(path.read_bytes())
                                 for path in sorted(package.rglob("*"))
                                 if path.is_file() and path.suffix in {".py", ".js", ".css", ".html"}}))
            self.journal.append("service.started", {"kind": config.kind, "version": __version__,
                                "source_tree_sha256": source_hash, "code_measurement": "self-reported; compare with a trusted build",
                                "operator_label": config.operator, "operator_identity": "shared token; self-reported label",
                                "route_label": config.route_label, "route_verified": False,
                                "previous_shutdown_clean": self.journal.last_shutdown_clean,
                                "settings": self.settings.copy(), "startup_capture": "disabled",
                                "poll_seconds": config.poll_seconds, "snapshot_seconds": config.snapshot_seconds,
                                "pending_files_present": any(self.journal.pending.iterdir())})
        except BaseException:
            self.journal.close()
            raise

    def status(self):
        return {"kind": self.config.kind, "version": __version__, "settings": self.settings.copy(),
                "observer_id": self.journal.observer_id, "fingerprint": self.journal.fingerprint,
                "seq": self.journal.seq, "head_hash": self.journal.head, "last_success": self.last_success,
                "last_error": self.last_error or self.video.error, "video_available": self.video.available,
                "video_running": self.video.process is not None, "last_video_segment": self.video.last_segment_at,
                "selected_target": self.browser.target_id, "route_label": self.config.route_label,
                "external_anchor": "not established by this service; retain checkpoints or use a separate witness"}

    async def configure(self, patch):
        async with self.lock:
            changed = {key: value for key, value in patch.items() if value is not None}
            new = {**self.settings, **changed}
            if self.config.kind == "browser" and new["database"]:
                raise ValueError("Database capture belongs to the independent AyuGram recorder")
            if self.config.kind == "ayugram" and (new["pages"] or new["screenshots"]):
                raise ValueError("Browser capture belongs to the independent browser recorder")
            if new["enabled"]:
                if not any(new[key] for key in ("pages", "screenshots", "database", "video")):
                    raise ValueError("Select at least one capture function")
                if new["video"] and not self.video.available:
                    raise ValueError("FFmpeg screen input is not configured or available")
                if new["database"] and not Path(self.config.ayugram_db).is_file():
                    raise ValueError("Configure an existing AyuGram SQLite database")
                if new["pages"] or new["screenshots"]:
                    if not self.browser.target_id and not self.browser.prefix:
                        raise ValueError("Select a browser tab after completing manual login")
            old = self.settings.copy()
            if not new["enabled"]:
                self.settings["enabled"] = False
            if self.video.process is not None and not (new["enabled"] and new["video"]):
                await asyncio.to_thread(self.video.stop)
            if new["enabled"] and new["video"] and self.video.process is None:
                self.video.start()
            self.settings = new
            if not old["enabled"] and new["enabled"]:
                self.last_attempt = 0
                self.browser.last_state = None
            self.journal.append("capture.settings_changed", {"before": old, "after": new.copy(),
                                "operator_label": self.config.operator})
            return self.status()

    async def capture(self, force=False):
        if not self.settings["enabled"]:
            raise ValueError("Capture is disabled; log in manually before enabling it")
        if self.config.kind == "browser" and not (self.settings["pages"] or self.settings["screenshots"]):
            return None
        if self.config.kind == "ayugram" and not self.settings["database"]:
            return None
        attempt = uuid.uuid4().hex
        if force:
            self.journal.append("capture.requested", {"capture_id": attempt, "operator_label": self.config.operator})
        try:
            if self.config.kind == "browser":
                result = await asyncio.wait_for(self.browser.capture(self.journal, self.settings,
                                                self.config.snapshot_seconds, force), timeout=45)
            else:
                result = await asyncio.to_thread(sqlite_snapshot, self.journal,
                                                self.config.ayugram_db, self.config.client_version)
            if result is not None:
                metadata, artifacts, observed = result
                event = self.journal.append("capture.partial" if metadata.get("errors") or metadata.get("navigation_changed_during_capture")
                                            else "capture.saved", {**metadata, "capture_id": attempt}, artifacts, observed)
                self.last_success = event["recorded_at"]
                self.last_error = None
                return event
        except Exception as exc:
            self.last_error = type(exc).__name__
            self.journal.append("capture.failed", {"capture_id": attempt, "error": self.last_error,
                                "coverage": "attempt did not produce a complete capture"})
            raise

    async def tick(self):
        async with self.lock:
            now = time.monotonic()
            self.video.poll()
            if not self.settings["enabled"]:
                return
            interval = self.config.snapshot_seconds if self.config.kind == "ayugram" else self.config.poll_seconds
            if now - self.last_attempt >= interval:
                self.last_attempt = now
                try:
                    await self.capture()
                except Exception:
                    pass  # The failed attempt is a signed event, not a successful observation.
            if now - self.last_heartbeat >= self.config.heartbeat_seconds:
                self.journal.append("capture.heartbeat", {"last_success": self.last_success,
                                    "last_error": self.last_error or self.video.error, "video_running": self.video.process is not None,
                                    "last_video_segment": self.video.last_segment_at})
                self.last_heartbeat = now

    async def run(self):
        while not self.closing:
            try:
                await self.tick()
            except Exception as exc:
                # A full disk / failed journal must stop collection, not report healthy coverage.
                self.settings["enabled"] = False
                self.last_error = "RecorderStopped:" + type(exc).__name__
                await asyncio.to_thread(self.video.abort)
            await asyncio.sleep(min(self.config.poll_seconds, 1))

    async def close(self):
        self.closing = True
        try:
            if self.task:
                # Let an in-flight SQLite backup / export finish before closing its journal.
                await self.task
            async with self.lock:
                await asyncio.to_thread(self.video.stop)
                await self.browser.close()
                self.journal.append("service.stopped", {"capture_was_enabled": self.settings["enabled"]})
        finally:
            self.video.abort()
            self.journal.close()


def create_app(root, config=None):
    config = config or Config()

    @asynccontextmanager
    async def lifespan(app):
        recorder = Recorder(root, config)
        app.state.recorder = recorder
        recorder.task = asyncio.create_task(recorder.run())
        try:
            yield
        finally:
            await recorder.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    static = Path(__file__).parent / "static"

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("authorization", "")
            recorder = request.app.state.recorder
            roles = ("control", "witness") if request.url.path == "/api/checkpoint" and request.method == "GET" else ("control",)
            if not any(secrets.compare_digest(supplied, "Bearer " + recorder.tokens[role]) for role in roles):
                return JSONResponse({"detail": "Capture token required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and origin != (config.public_origin or str(request.base_url).rstrip("/")):
                return JSONResponse({"detail": "Cross-origin control is disabled"}, status_code=403)
            if request.headers.get("content-length", "0").isdigit() and int(request.headers.get("content-length", "0")) > 16384:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})
        return response

    @app.get("/")
    async def index():
        return FileResponse(static / "index.html", headers={"Content-Security-Policy":
                            "default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"})

    @app.get("/static/{name}")
    async def asset(name: str):
        if name not in {"app.js", "style.css"}:
            raise HTTPException(404)
        return FileResponse(static / name)

    @app.get("/api/status")
    async def status():
        return app.state.recorder.status()

    @app.post("/api/settings")
    async def settings(patch: SettingsPatch):
        try:
            return await app.state.recorder.configure(patch.model_dump(exclude_unset=True))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.get("/api/targets")
    async def targets():
        recorder = app.state.recorder
        if config.kind != "browser":
            raise HTTPException(400, "This observer records an AyuGram database")
        async with recorder.lock:
            try:
                return [{"target_id": target, "url": url} for _, target, url in await recorder.browser.targets()]
            except Exception:
                raise HTTPException(503, "Browser CDP connection unavailable") from None

    @app.post("/api/target")
    async def target(choice: TargetChoice):
        recorder = app.state.recorder
        async with recorder.lock:
            if recorder.settings["enabled"] or config.kind != "browser":
                raise HTTPException(409, "Pause browser capture before selecting a tab")
            try:
                available = await recorder.browser.targets()
            except Exception:
                raise HTTPException(503, "Browser CDP connection unavailable") from None
            if choice.target_id not in {target for _, target, _ in available}:
                raise HTTPException(400, "Unknown browser tab")
            recorder.browser.target_id = choice.target_id
            recorder.browser.last_state = None
            recorder.journal.append("capture.target_selected", {"target_id": choice.target_id,
                                     "operator_label": config.operator})
            return recorder.status()

    @app.post("/api/snapshot")
    async def snapshot():
        recorder = app.state.recorder
        async with recorder.lock:
            if not recorder.settings["enabled"]:
                raise HTTPException(409, "Enable capture after manual login")
            try:
                event = await recorder.capture(force=True)
            except Exception:
                raise HTTPException(503, "Capture failed; the journal records the failed attempt") from None
            return {"event": event, "status": recorder.status()}

    @app.get("/api/events")
    async def events():
        return app.state.recorder.journal.events(100)

    @app.get("/api/checkpoint")
    async def checkpoint(challenge: str = ""):
        if len(challenge) > 128 or any(c not in "0123456789abcdef" for c in challenge):
            raise HTTPException(400, "Challenge must be at most 128 hexadecimal characters")
        return app.state.recorder.journal.checkpoint(challenge)

    @app.post("/api/export")
    async def export():
        recorder = app.state.recorder
        async with recorder.lock:
            if recorder.settings["enabled"]:
                raise HTTPException(409, "Pause capture to export a fixed boundary")
            destination = recorder.journal.root / "exports" / (uuid.uuid4().hex + ".zip")
            try:
                await asyncio.to_thread(export_zip, recorder.journal, destination)
            except Exception:
                raise HTTPException(503, "Export verification failed; no package was released") from None
            return FileResponse(destination, media_type="application/zip", filename="capture-" + config.kind + ".zip")

    return app
