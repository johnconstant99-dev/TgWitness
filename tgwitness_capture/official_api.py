"""Named official-client operations only; authentication is the recorder middleware."""
import asyncio
from typing import Literal

from fastapi import HTTPException
from fastapi.responses import Response, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .official import PaceWait


class Password(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    password: SecretStr = Field(min_length=1, max_length=1024)


class Chat(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    handle: str = Field(pattern=r"^[a-f0-9]{32}$")


class Scroll(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    direction: Literal["older", "newer"] = "older"


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["passive", "paced"]
    min_pause_seconds: float = Field(ge=2, le=120)
    max_pause_seconds: float = Field(ge=2, le=300)
    scroll_pixels: int = Field(ge=80, le=600)
    max_steps: int = Field(ge=1, le=5000)
    session_minutes: int = Field(ge=1, le=120)


def routes(app):
    @app.exception_handler(RequestValidationError)
    async def invalid_body(request, exc):
        if request.url.path.startswith("/api/official/"):
            return JSONResponse({"detail": "Invalid official-client parameters"}, status_code=422)
        return await request_validation_exception_handler(request, exc)

    async def operation(name, *args):
        recorder = app.state.recorder
        async with recorder.lock:
            try:
                return await asyncio.wait_for(getattr(recorder.official, name)(*args), timeout=60)
            except PaceWait:
                raise HTTPException(429, "Wait for the configured pause before scrolling again") from None
            except Exception as exc:
                if recorder.settings["enabled"]:
                    await recorder.stop_official(type(exc).__name__)
                raise HTTPException(409, "Official client operation stopped; check the procedure state") from None

    @app.post("/api/official/open")
    async def open_client():
        return await operation("open")

    @app.post("/api/official/plan")
    async def plan(body: Plan):
        recorder = app.state.recorder
        async with recorder.lock:
            if recorder.official.phase != "created":
                raise HTTPException(409, "Choose settings before opening the client")
            from .official import OfficialOptions
            try:
                options = OfficialOptions.model_validate({**recorder.official.options.model_dump(), **body.model_dump()})
            except ValueError:
                raise HTTPException(422, "Invalid pacing range") from None
            recorder.official.options = options
        return recorder.status()

    @app.get("/api/official/login")
    async def login():
        return {"state": await operation("login_state")}

    @app.get("/api/official/screen")
    async def screen():
        return Response(await operation("screen"), media_type="image/jpeg", headers={"Cache-Control": "no-store"})

    @app.post("/api/official/password")
    async def password(body: Password):
        await operation("password", body.password.get_secret_value())
        return {"submitted": True}

    @app.get("/api/official/chats")
    async def chats():
        return await operation("chats")

    @app.post("/api/official/chat")
    async def chat(body: Chat):
        await operation("select_chat", body.handle)
        return app.state.recorder.status()

    @app.post("/api/official/scroll")
    async def scroll(body: Scroll):
        await operation("scroll", body.direction)
        return app.state.recorder.status()

    @app.post("/api/official/stop")
    async def stop():
        recorder = app.state.recorder
        recorder.official.stop_requested = True
        recorder.official.reason = "OperatorStop"
        async with recorder.lock:
            await recorder.stop_official("OperatorStop")
        return recorder.status()

    @app.post("/api/official/finish")
    async def finish():
        recorder = app.state.recorder
        recorder.official.stop_requested = True
        async with recorder.lock:
            recorder.settings["enabled"] = False
            await asyncio.to_thread(recorder.video.stop)
            await recorder.official.pause()
            try:
                await asyncio.wait_for(recorder.official.finish(), timeout=50)
            except Exception:
                await recorder.official.close()
                raise HTTPException(503, "Client closed; logout could not be confirmed") from None
        return recorder.status()
