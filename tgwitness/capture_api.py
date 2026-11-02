from typing import Literal

import requests
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from .capture_connections import Connection
from .downloads import TemporaryDownload, build_file
from .workers import complete_in_thread

Kind = Literal["browser", "ayugram"]


class CaptureSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool | None = None
    screenshots: StrictBool | None = None
    pages: StrictBool | None = None
    database: StrictBool | None = None
    video: StrictBool | None = None


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str = Field(min_length=1, max_length=256)


def register(app, authenticate, require_live):
    async def admin(request: Request, who=Depends(authenticate)):
        if not who.admin:
            raise HTTPException(403, "Only the main administrator can control independent recorders.")

    async def action(function, *args, file=False):
        require_live()
        async with app.state.capture.lock:
            try:
                if file:
                    return await build_file(lambda: function(*args))
                return await complete_in_thread(function, *args)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
            except (OSError, requests.RequestException):
                raise HTTPException(502, "Recorder unavailable. Check its address, certificate and network connection.") from None
            except Exception:
                raise HTTPException(502, "Invalid recorder response; no archive was released.") from None

    @app.get("/api/capture", dependencies=[Depends(admin)])
    async def connections():
        return await complete_in_thread(app.state.capture.public)

    @app.post("/api/capture/{kind}/connection", dependencies=[Depends(admin)])
    async def connection(kind: Kind, body: Connection):
        return await action(app.state.capture.save, kind, body)

    @app.get("/api/capture/{kind}/status", dependencies=[Depends(admin)])
    async def status(kind: Kind):
        return await action(app.state.capture.request, kind)

    @app.get("/api/capture/{kind}/targets", dependencies=[Depends(admin)])
    async def targets(kind: Kind):
        return await action(app.state.capture.request, kind, "targets")

    @app.get("/api/capture/{kind}/events", dependencies=[Depends(admin)])
    async def events(kind: Kind):
        return await action(app.state.capture.request, kind, "events")

    @app.get("/api/capture/{kind}/checkpoint", dependencies=[Depends(admin)])
    async def checkpoint(kind: Kind):
        result = await action(app.state.capture.request, kind, "checkpoint")
        return JSONResponse(result, headers={"Content-Disposition": 'attachment; filename="capture-' + kind + '-checkpoint.json"'})

    @app.post("/api/capture/{kind}/target", dependencies=[Depends(admin)])
    async def target(kind: Kind, body: Target):
        return await action(app.state.capture.request, kind, "target", body.model_dump())

    @app.post("/api/capture/{kind}/settings", dependencies=[Depends(admin)])
    async def settings(kind: Kind, body: CaptureSettings):
        patch = body.model_dump(exclude_none=True)
        if not patch:
            raise HTTPException(422, "Choose at least one capture setting.")
        return await action(app.state.capture.request, kind, "settings", patch)

    @app.post("/api/capture/{kind}/snapshot", dependencies=[Depends(admin)])
    async def snapshot(kind: Kind):
        return await action(app.state.capture.request, kind, "snapshot", {})

    @app.post("/api/capture/{kind}/export", dependencies=[Depends(admin)])
    async def export(kind: Kind):
        path = await action(app.state.capture.export, kind, file=True)
        return TemporaryDownload(path, media_type="application/zip", filename="capture-" + kind + ".zip")
