"""Trusted Live control plane; separate from TgWitness's API collector."""
import asyncio
import secrets
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from .continuity import LIMITS, STYLE_HASH, analyze, parse_export, render
from .export import export_zip
from .format import canonical, digest, utcnow
from .journal import Journal, durable_write
from .trusted_model import Choice, ExportChoice, Scroll, SetupInput, VisualNote
from .trusted_runtime import LinuxClient, connector_config
from .video import VideoCapture


class TrustedRecorder:
    def __init__(self, root, config, runtime=None):
        self.options = config.trusted or {}
        self.connectors = connector_config(self.options.get("connectors"))
        self.runtime = runtime or LinuxClient(self.options)
        self.journal = Journal(root)
        self.lock = asyncio.Lock()
        self.choice = None
        self.phase = "configured"
        self.error = None
        self.report = None
        self.chat = None
        self.visual = []
        self.frames = set()
        self.profile = None
        self.last_scroll = 0
        self.next_scroll = 0
        self.last_frame = 0
        self.last_health = 0
        self.last_beacon = 0
        self.beacon_status = "not_observed"
        self.closing = False
        self.stop_requested = False
        self.task = None
        self.case_id = None
        self.video = VideoCapture(self.journal, config.video_input_args, config.ffmpeg_executable, overlay=True)
        self.tokens = {}
        try:
            for role in ("control", "witness"):
                path = self.journal.root / (role + "-token.txt")
                if not path.exists():
                    durable_write(path, secrets.token_urlsafe(32).encode(), exclusive=True)
                self.tokens[role] = path.read_text().strip()
                if len(self.tokens[role]) < 32:
                    raise ValueError("Token too short")
            previous = [event for event in self.journal.events() if event["kind"] == "service.started"]
            if previous and previous[-1]["payload"].get("kind") != "trusted":
                raise ValueError("Use a separate journal for Trusted Live")
            if any(event["kind"] == "trusted.configured" for event in self.journal.events()):
                self.phase = "archived"
            package = Path(__file__).parent
            source_hash = digest(canonical({path.relative_to(package).as_posix(): digest(path.read_bytes())
                                           for path in sorted(package.rglob("*"))
                                           if path.is_file() and path.suffix in {".py", ".js", ".css", ".html"}}))
            self.journal.append("service.started", {"kind": "trusted", "capture": "disabled",
                                "source_tree_sha256": source_hash, "measurement": "self-reported; not a TEE attestation",
                                "previous_shutdown_clean": self.journal.last_shutdown_clean,
                                "assurance": "local signatures; external checkpoint retention required", "limits": LIMITS})
        except BaseException:
            self.journal.close()
            raise

    def event(self, kind, payload=None, artifacts=None):
        return self.journal.append("trusted." + kind, {"case_id": self.case_id, **(payload or {})}, artifacts)

    def status(self):
        return {"kind": "trusted", "phase": self.phase, "choice": self.choice.model_dump() if self.choice else None,
                "case_id": self.case_id, "observer_id": self.journal.observer_id, "fingerprint": self.journal.fingerprint,
                "seq": self.journal.seq, "head_hash": self.journal.head, "settings": {"enabled": self.phase == "collecting"},
                "connectors": {name: {key: value[key] for key in ("label", "mode", "protocol")} for name, value in self.connectors.items()},
                "last_error": self.error, "video_available": self.video.available,
                "video_running": self.video.process is not None, "has_report": self.report is not None,
                "visual_annotations": len(self.visual), "limits": LIMITS,
                "drand": self.beacon_status,
                "network_witness": "not verified here; query provider independently with a read-only token",
                "external_anchor": "retain checkpoints on an independent witness; drand alone is not an upper time bound"}

    async def begin(self, choice):
        if self.phase != "configured":
            raise ValueError("This runtime accepts one case; finish and recreate it for another account")
        if choice.connector not in self.connectors:
            raise ValueError("Choose a configured connector")
        if not self.video.available:
            raise ValueError("Configure screen video and FFmpeg before connecting an account")
        self.choice, self.case_id = choice, uuid.uuid4().hex
        profile_root = Path(self.options.get("profile_root", "/session")).resolve()
        if profile_root == self.journal.root or self.journal.root in profile_root.parents or profile_root in self.journal.root.parents:
            raise ValueError("Profile and evidence must have separate storage roots")
        self.profile = profile_root / ("trusted-" + self.case_id)
        self.event("configured", {"choice": choice.model_dump(), "connector": self.connectors[choice.connector],
                                 "pace": "operator-driven, serial wheel steps; no claim of human indistinguishability"})
        try:
            measurement = await asyncio.to_thread(self.runtime.launch, choice, self.connectors[choice.connector], self.profile)
            if self.stop_requested:
                raise ValueError("Kill switch activated")
            self.event("client_started", measurement)
            self.phase = "setup"
        except Exception:
            await asyncio.to_thread(self.runtime.stop)
            self.phase = "failed"
            self.event("start_failed", {"coverage": "no live collection"})
            raise
        return self.status()

    async def start(self):
        if self.phase not in {"setup", "paused"}:
            raise ValueError("Prepare the official client first")
        await asyncio.to_thread(self.runtime.route, self.connectors[self.choice.connector])
        await asyncio.to_thread(self.runtime.arm)
        if self.stop_requested:
            raise ValueError("Kill switch activated; finish this runtime")
        self.video.start()
        try:
            self.event("collection_started", {"guard": "wheel-only inputs through this control plane",
                                              "client_side_effects": "read receipts and presence may change",
                                              "export_procedure": "operator prepares native export during setup/paused phase"})
        except BaseException:
            self.video.abort()
            raise
        self.phase = "collecting"
        self.error = None
        self.last_health = 0
        return self.status()

    async def pause(self, reason="operator"):
        if self.phase == "collecting":
            self.phase = "paused"
            await asyncio.to_thread(self.video.stop)
            self.event("collection_paused", {"reason": reason})
        return self.status()

    async def emergency(self, reason="operator_kill_switch"):
        self.stop_requested = True
        self.phase = "failed"
        self.error = reason
        try:
            await asyncio.to_thread(self.runtime.stop)
        finally:
            self.video.abort()
        self.event("stopped", {"reason": reason, "logout": "not_confirmed"})
        return self.status()

    async def scroll(self, value):
        if self.phase != "collecting" or self.choice.method == "export":
            raise ValueError("Visual capture must be running")
        if time.monotonic() < self.next_scroll:
            raise ValueError("Wait for the reading pause before the next scroll")
        try:
            await asyncio.to_thread(self.runtime.route, self.connectors[self.choice.connector])
            if self.stop_requested:
                raise ValueError("Kill switch activated")
            await asyncio.to_thread(self.runtime.scroll, value.direction)
        except Exception:
            await self.emergency("route_or_focus_lost")
            raise
        self.last_scroll = time.monotonic()
        self.next_scroll = self.last_scroll + secrets.SystemRandom().uniform(self.choice.pause_min, self.choice.pause_max)
        self.event("scrolled", {"direction": value.direction, "steps": 1})
        return self.status()

    async def frame(self):
        if self.phase not in {"setup", "paused", "collecting"}:
            raise ValueError("Client is not running")
        raw = await asyncio.to_thread(self.runtime.frame)
        if self.phase == "collecting" and not self.stop_requested and time.monotonic() - self.last_frame >= 2:
            artifact = self.journal.artifact(raw, "trusted_viewport", "image/png")
            self.event("frame", {"source": "owned_display", "message_ids": "not_extracted"}, [artifact])
            self.frames.add(artifact["sha256"])
            self.last_frame = time.monotonic()
        return raw

    async def setup_input(self, value):
        if self.phase not in {"setup", "paused"}:
            raise ValueError("Keyboard and clicks are blocked during capture; pause to use manual setup")
        await asyncio.to_thread(self.runtime.setup_input, value)
        return self.status()

    def export_files(self):
        root = Path(self.options.get("export_root", "/exports")).resolve()
        return sorted(path.relative_to(root).as_posix() for path in root.glob("**/result.json")
                      if path.is_file() and not path.is_symlink() and root in path.resolve().parents)[:100]

    def import_export(self, name):
        if not self.choice or self.choice.method not in {"export", "hybrid"} or self.phase not in {"collecting", "paused"}:
            raise ValueError("Start an export or hybrid session first")
        root = Path(self.options.get("export_root", "/exports")).resolve(strict=True)
        candidate = root / name
        path = candidate.resolve(strict=True)
        if root not in path.parents or path.name != "result.json" or candidate.is_symlink() or not path.is_file():
            raise ValueError("Select result.json from the isolated exports inbox")
        stat = path.stat()
        if stat.st_size > 64 * 1024**2 or time.time() - stat.st_mtime < 2:
            raise ValueError("Export is too large or still being written; wait for Desktop to finish")
        with path.open("rb") as source:
            raw = source.read(64 * 1024**2 + 1)
        after = path.stat()
        if (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Export changed during import")
        chat = parse_export(raw)
        if self.chat and (chat["id"], chat["type"]) != (self.chat["id"], self.chat["type"]):
            raise ValueError("Use a separate case for a different chat")
        original = self.journal.artifact(raw, "desktop_export_original", "application/json")
        self.event("export_received", {"chat_id": chat["id"], "chat_type": chat["type"],
                                       "scope": "JSON only; attachment files are not imported",
                                       "provenance": "file from isolated inbox; generation by Telegram is not cryptographically authenticated",
                                       "source_mtime": stat.st_mtime}, [original])
        self.chat = chat
        return self.update_report()

    def annotate(self, value):
        if self.phase not in {"collecting", "paused"} or self.choice.method == "export":
            raise ValueError("A visual session is required")
        if value.frame_sha256 not in self.frames:
            raise ValueError("Reference a preserved frame from this case")
        if len(self.visual) >= 10000:
            raise ValueError("Visual annotation limit reached")
        item = {**value.model_dump(), "observed_at": utcnow(), "basis": "operator_transcription"}
        self.event("visual_annotation", item)
        self.visual.append(item)
        return self.update_report() if self.chat else self.status()

    def update_report(self):
        self.report = analyze(self.chat, self.visual)
        artifacts = [self.journal.artifact(canonical(self.report), "continuity_report", "application/json"),
                     self.journal.artifact(render(self.chat, self.report), "annotated_chat", "text/html")]
        self.event("continuity_analyzed", {"findings": len(self.report["findings"]), "deletions_proven": False}, artifacts)
        return self.report

    async def finish(self):
        if self.phase in {"completed", "archived"}:
            return self.status()
        await self.pause("finalization")
        await asyncio.to_thread(self.runtime.stop)
        self.phase = "cleanup_pending"
        if self.profile and self.profile.exists():
            parent = Path(self.options.get("profile_root", "/session")).resolve()
            resolved = self.profile.resolve()
            if resolved.parent != parent or resolved.name != "trusted-" + self.case_id:
                raise ValueError("Unexpected profile path; refusing cleanup")
            await asyncio.to_thread(shutil.rmtree, resolved)
        self.event("completed", {"profile_cleanup": "removed", "server_logout": "not_confirmed; revoke the session in Telegram Devices",
                                 "export_present": self.chat is not None, "video_required": True,
                                 "video_segments_present": any(event["kind"] == "video.segment" for event in self.journal.events()),
                                 "history_completeness": "not_established"})
        self.phase = "completed"
        return self.status()

    async def tick(self):
        if self.phase != "collecting":
            return
        self.video.poll()
        if self.video.process is None or self.video.error:
            raise ValueError("Procedure video interrupted")
        if time.monotonic() - self.last_health >= 5:
            route = await asyncio.to_thread(self.runtime.route, self.connectors[self.choice.connector])
            if self.stop_requested:
                return
            self.event("heartbeat", {"route": route, "video_running": True, "last_video_segment": self.video.last_segment_at})
            self.last_health = time.monotonic()
        if time.monotonic() - self.last_beacon >= 60:
            from .trusted_anchor import observe
            try:
                beacon = await asyncio.to_thread(observe, self.connectors[self.choice.connector])
                self.event("beacon.drand", beacon)
                self.beacon_status = "relay_confirmed; no upper time bound"
            except Exception as exc:
                self.beacon_status = "unavailable"
                self.event("beacon_unavailable", {"error": type(exc).__name__, "scope": "no drand bound for this interval"})
            self.last_beacon = time.monotonic()

    async def run(self):
        while not self.closing:
            async with self.lock:
                try:
                    await self.tick()
                except Exception as exc:
                    try:
                        await self.emergency(type(exc).__name__)
                    except Exception:
                        self.phase, self.error = "failed", "JournalOrRuntimeFailure"
            await asyncio.sleep(0.5)

    async def close(self):
        self.closing = True
        if self.task:
            await self.task
        try:
            await self.finish()
            self.journal.append("service.stopped", {"kind": "trusted"})
        finally:
            self.video.abort()
            await asyncio.to_thread(self.runtime.stop)
            self.journal.close()


def create_app(root, config, runtime=None):
    @asynccontextmanager
    async def lifespan(app):
        recorder = TrustedRecorder(root, config, runtime)
        app.state.recorder = recorder
        recorder.task = asyncio.create_task(recorder.run())
        try:
            yield
        finally:
            await recorder.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    static = Path(__file__).parent / "static"

    @app.middleware("http")
    async def auth(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            rec = app.state.recorder
            roles = ("control", "witness") if request.method == "GET" and request.url.path == "/api/checkpoint" else ("control",)
            supplied = request.headers.get("authorization", "")
            if not any(secrets.compare_digest(supplied, "Bearer " + rec.tokens[role]) for role in roles):
                return JSONResponse({"detail": "Recorder token required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and origin != (config.public_origin or str(request.base_url).rstrip("/")):
                return JSONResponse({"detail": "Cross-origin request refused"}, status_code=403)
            total, chunks = 0, []
            async for chunk in request.stream():
                total += len(chunk)
                if total > 65536:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                                 "Content-Security-Policy": "default-src 'self'; style-src 'self' 'sha256-" + STYLE_HASH + "'; img-src 'self' blob:; frame-src blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"})
        return response

    async def act(function, *args):
        rec = app.state.recorder
        async with rec.lock:
            try:
                if asyncio.iscoroutinefunction(function):
                    return await function(*args)
                return await asyncio.to_thread(function, *args)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
            except Exception as exc:
                try:
                    await rec.emergency(type(exc).__name__)
                except Exception:
                    pass
                raise HTTPException(503, "Runtime stopped; check its state before continuing") from None

    @app.get("/")
    async def index():
        return FileResponse(static / "trusted.html")

    @app.get("/favicon.ico")
    async def favicon():
        return Response(status_code=204)

    @app.get("/static/{name}")
    async def asset(name: str):
        if name not in {"trusted.js", "trusted.css"}:
            raise HTTPException(404)
        return FileResponse(static / name)

    @app.get("/api/status")
    async def status():
        return app.state.recorder.status()

    @app.post("/api/begin")
    async def begin(choice: Choice):
        return await act(app.state.recorder.begin, choice)

    @app.post("/api/start")
    async def start():
        return await act(app.state.recorder.start)

    @app.post("/api/pause")
    async def pause():
        return await act(app.state.recorder.pause)

    @app.post("/api/stop")
    async def stop():
        rec = app.state.recorder
        rec.stop_requested = True
        await asyncio.to_thread(rec.runtime.stop)
        rec.video.abort()
        return await act(rec.emergency)

    @app.post("/api/finish")
    async def finish():
        return await act(app.state.recorder.finish)

    @app.post("/api/scroll")
    async def scroll(value: Scroll):
        return await act(app.state.recorder.scroll, value)

    @app.post("/api/input")
    async def setup_input(value: SetupInput):
        return await act(app.state.recorder.setup_input, value)

    @app.get("/api/frame")
    async def frame():
        raw = await act(app.state.recorder.frame)
        return Response(raw, media_type="image/png", headers={"X-Frame-SHA256": digest(raw)})

    @app.get("/api/exports")
    async def exports():
        return await act(app.state.recorder.export_files)

    @app.post("/api/import")
    async def import_export(value: ExportChoice):
        return await act(app.state.recorder.import_export, value.name)

    @app.post("/api/annotate")
    async def annotate(value: VisualNote):
        return await act(app.state.recorder.annotate, value)

    @app.get("/api/continuity")
    async def continuity():
        return app.state.recorder.report

    @app.get("/api/transcript")
    async def transcript():
        rec = app.state.recorder
        if rec.chat is None:
            raise HTTPException(404, "No Desktop export imported")
        return Response(render(rec.chat, rec.report), media_type="text/html")

    @app.get("/api/events")
    async def events():
        return app.state.recorder.journal.events(100)

    @app.get("/api/checkpoint")
    async def checkpoint(challenge: str = ""):
        if len(challenge) > 128 or any(c not in "0123456789abcdef" for c in challenge):
            raise HTTPException(400, "Invalid challenge")
        return app.state.recorder.journal.checkpoint(challenge)

    @app.post("/api/export")
    async def export():
        rec = app.state.recorder
        async with rec.lock:
            if rec.phase not in {"paused", "completed", "failed", "cleanup_pending", "archived"}:
                raise HTTPException(409, "Pause capture before exporting a fixed boundary")
            path = rec.journal.root / "exports" / (uuid.uuid4().hex + ".zip")
            try:
                await asyncio.to_thread(export_zip, rec.journal, path)
            except Exception:
                raise HTTPException(503, "Export verification failed; no archive released") from None
            return FileResponse(path, media_type="application/zip", filename="trusted-live.zip")

    return app
