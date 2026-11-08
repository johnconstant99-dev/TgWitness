import re
from typing import Literal

import requests
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from .capture_connections import Connection
from .downloads import TemporaryDownload, build_file
from .workers import complete_in_thread

Kind = Literal["browser", "ayugram", "trusted"]


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


TELEGRAM_WEB = "https://web.telegram.org/k/#"


class OpenAddress(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: str | None = Field(default=None, max_length=2048)
    telegram: str | None = Field(default=None, max_length=40)
    chat_id: int | None = Field(default=None, ge=-(2**63), le=2**63 - 1)
    title: str | None = Field(default=None, max_length=256)
    wait_seconds: float | None = Field(default=None, ge=0, le=30)
    purpose: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def one_target(self):
        if (self.url is None) == (self.telegram is None):
            raise ValueError("Give either an address or a Telegram @username or ID.")
        if self.telegram is not None and not re.fullmatch(r"@?[A-Za-z][A-Za-z0-9_]{3,31}|-?\d{1,20}", self.telegram):
            raise ValueError("Use a Telegram @username or numeric ID.")
        return self

    def address(self):
        if self.url is not None:
            return self.url
        value = self.telegram
        return TELEGRAM_WEB + (value if value[0] in "@-" or value.isdigit() else "@" + value)

    def subject(self):
        found = {"telegram": self.telegram, "chat_id": self.chat_id, "title": self.title}
        return {key: value for key, value in found.items() if value is not None} or None


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

    @app.post("/api/capture/{kind}/open", dependencies=[Depends(admin)])
    async def open_address(kind: Kind, body: OpenAddress):
        wait = body.wait_seconds if body.wait_seconds is not None else (8 if body.telegram else 5)
        return await action(app.state.capture.open, kind, body.address(), wait, body.purpose, body.subject(),
                            body.chat_id)

    @app.get("/api/capture/{kind}/object/{sha256}", dependencies=[Depends(admin)])
    async def stored_object(kind: Kind, sha256: str):
        data = await action(app.state.capture.object, kind, sha256)
        image = data.startswith(b"\x89PNG\r\n\x1a\n")
        return Response(data, media_type="image/png" if image else "application/octet-stream",
                        headers={"Content-Disposition": ("inline" if image else "attachment") + '; filename="' + sha256 + '"',
                                 "Content-Security-Policy": "default-src 'none'; sandbox"})

    @app.post("/api/capture/{kind}/export", dependencies=[Depends(admin)])
    async def export(kind: Kind):
        path = await action(app.state.capture.export, kind, file=True)
        return TemporaryDownload(path, media_type="application/zip", filename="capture-" + kind + ".zip")
