from .. import action_protocol
from .. import case_package
from .. import documentation
from .. import opsec
from .. import report
from ..app import panel_language
from ..downloads import TemporaryDownload
from ..downloads import build_file
from ..store import canonical
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi.responses import Response
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from typing import Literal
import asyncio
import base64


class PackageChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    encryption: Literal["none", "generated", "own"] = "none"
    passphrase: str | None = Field(default=None, max_length=512)


async def opsec_view(*, ctx=Depends(current_context)):
    return {
        "latest": await asyncio.to_thread(opsec.latest, ctx.app.state.store),
        "settings": opsec.settings(ctx.app.state.store),
    }


async def opsec_check(*, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(opsec.check, ctx.app.state.collector)


async def opsec_settings(body: opsec.Settings, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await asyncio.to_thread(opsec.save_settings, ctx.app.state.store, body)


async def action_protocol_view(
    request: Request,
    chat_id: int | None = Query(None, ge=-(2**63), le=2**63 - 1),
    *,
    ctx=Depends(current_context),
):
    return await ctx.protocol_model(request, chat_id)


async def action_protocol_page(
    request: Request,
    chat_id: int | None = Query(None, ge=-(2**63), le=2**63 - 1),
    *,
    ctx=Depends(current_context),
):
    value = await ctx.protocol_model(request, chat_id)
    say = report.Words(panel_language(request))
    images = await ctx.recorder_images(
        [step for episode in value["episodes"] for step in episode["steps"]]
    )
    return Response(
        action_protocol.render_html(value, say, images),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": 'inline; filename="tgwitness-action-protocol.html"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; sandbox",
        },
    )


async def documentation_list(request: Request, *, ctx=Depends(current_context)):
    return {
        "sessions": documentation.listing(
            ctx.app.state.store, ctx.visible_chats(request)
        )
    }


async def documentation_start(
    request: Request, body: documentation.Start, *, ctx=Depends(current_context)
):
    ctx.require_live()
    return await ctx.documentation_call(
        documentation.create,
        ctx.app.state.store,
        body,
        request.state.principal.owner,
        ctx.visible_chats(request),
        None,
        await ctx.recorder_video(),
    )


async def documentation_view(
    request: Request, session_id: str, *, ctx=Depends(current_context)
):
    session = ctx.documented(request, session_id)
    model = await ctx.documentation_call(
        documentation.current_model,
        ctx.app.state.store,
        session,
        ctx.visible_chats(request),
    )
    await ctx.recheck_export_scope(request, set(session["chat_ids"]) or None)
    return {
        "session": {k: v for k, v in session.items() if k != "fixed"},
        "fixed": {k: v for k, v in session["fixed"].items() if k != "model"}
        if session["fixed"]
        else None,
        "document": model,
    }


async def documentation_control(
    request: Request,
    session_id: str,
    action: Literal["pause", "resume", "stop", "restart", "fix", "revise"],
    *,
    ctx=Depends(current_context),
):
    ctx.require_live()
    (ctx.documented if action == "revise" else ctx.editable)(request, session_id)
    if action == "fix":
        return await ctx.documentation_call(
            documentation.fix,
            ctx.app.state.store,
            ctx.app.state.vault,
            session_id,
            ctx.visible_chats(request),
        )
    if action == "revise":
        return await ctx.documentation_call(
            documentation.revise,
            ctx.app.state.store,
            session_id,
            request.state.principal.owner,
            ctx.visible_chats(request),
        )
    return await ctx.documentation_call(
        documentation.control, ctx.app.state.store, session_id, action
    )


async def documentation_delete(
    request: Request, session_id: str, *, ctx=Depends(current_context)
):
    ctx.require_live()
    ctx.editable(request, session_id)
    await ctx.documentation_call(documentation.delete, ctx.app.state.store, session_id)
    return {"deleted": session_id}


async def documentation_mark(
    request: Request,
    session_id: str,
    body: documentation.Mark,
    *,
    ctx=Depends(current_context),
):
    ctx.require_live()
    ctx.editable(request, session_id)
    return await ctx.documentation_call(
        documentation.add_mark,
        ctx.app.state.store,
        session_id,
        body,
        await ctx.recorder_video(),
    )


async def documentation_mark_edit(
    request: Request,
    session_id: str,
    mark_id: str,
    body: documentation.Mark,
    *,
    ctx=Depends(current_context),
):
    ctx.require_live()
    ctx.editable(request, session_id)
    return await ctx.documentation_call(
        documentation.edit_mark, ctx.app.state.store, session_id, mark_id, body
    )


async def documentation_mark_delete(
    request: Request, session_id: str, mark_id: str, *, ctx=Depends(current_context)
):
    ctx.require_live()
    ctx.editable(request, session_id)
    await ctx.documentation_call(
        documentation.remove_mark, ctx.app.state.store, session_id, mark_id
    )
    return {"deleted": mark_id}


async def documentation_keys(
    request: Request,
    session_id: str,
    labels: str | None = Query(None, max_length=200),
    *,
    ctx=Depends(current_context),
):
    ctx.documented(request, session_id)
    who = request.state.principal
    if not (who.admin or who.may("board.manage")):
        raise HTTPException(
            403, "Only a board manager can release keys to hidden content."
        )
    keys = await asyncio.to_thread(
        ctx.app.state.vault.read, documentation.KEYS_NAME + session_id
    )
    if not keys:
        raise HTTPException(404, "This document has no sealed content.")
    if labels:
        chosen = set(labels.split(","))
        keys = {key: value for key, value in keys.items() if key != "master"}
        keys["labels"] = {
            label: value for label, value in keys["labels"].items() if label in chosen
        }
        if not keys["labels"]:
            raise HTTPException(404, "No sealed content has these reasons.")
    ctx.app.state.store.append(
        "documentation.keys_released",
        {
            "session_id": session_id,
            "statement_sha256": keys["statement_sha256"],
            "scope": "all" if "master" in keys else sorted(keys["labels"]),
            "access": who.label,
        },
    )
    return Response(
        canonical(keys),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="tgwitness-documentation-'
            + session_id[:8]
            + '-keys.json"'
        },
    )


async def documentation_appearance(
    request: Request,
    session_id: str,
    body: documentation.Appearance,
    *,
    ctx=Depends(current_context),
):
    ctx.require_live()
    ctx.editable(request, session_id)
    return await ctx.documentation_call(
        documentation.set_appearance, ctx.app.state.store, session_id, body
    )


async def documentation_package(
    request: Request, session_id: str, *, ctx=Depends(current_context)
):
    session = ctx.documented(request, session_id)
    if not session["fixed"]:
        raise HTTPException(409, "Fix the document before preparing a case package.")
    await ctx.recheck_export_scope(request, set(session["chat_ids"]) or None)
    return await ctx.case_download(request, session, None)


async def documentation_package_choice(
    request: Request,
    session_id: str,
    body: PackageChoice,
    *,
    ctx=Depends(current_context),
):
    session = ctx.documented(request, session_id)
    if not session["fixed"]:
        raise HTTPException(409, "Fix the document before preparing a case package.")
    await ctx.recheck_export_scope(request, set(session["chat_ids"]) or None)
    secret = (
        case_package.passphrase()
        if body.encryption == "generated"
        else body.passphrase
        if body.encryption == "own"
        else None
    )
    if body.encryption == "own" and (not secret):
        raise HTTPException(422, "Enter the passphrase for the encrypted package.")
    response = await ctx.case_download(request, session, secret)
    if body.encryption == "generated":
        response.headers["X-TgWitness-Passphrase"] = secret
    return response


async def documentation_document(
    request: Request,
    session_id: str,
    suffix: Literal["html", "slides", "md", "json", "vtt", "srt", "undercover"],
    *,
    ctx=Depends(current_context),
):
    session = ctx.documented(request, session_id)
    model = await ctx.documentation_call(
        documentation.current_model,
        ctx.app.state.store,
        session,
        ctx.visible_chats(request),
    )
    await ctx.recheck_export_scope(request, set(session["chat_ids"]) or None)
    say = report.Words(panel_language(request))
    fixed = session["fixed"]
    name = "tgwitness-documentation-" + session_id[:8]
    if suffix == "json":
        body = canonical(
            {"document": model, "signed": fixed["signed"] if fixed else None}
        )
        return Response(
            body,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="' + name + '.json"'},
        )
    if suffix == "undercover":
        from .. import undercover

        return Response(
            undercover.render_html(undercover.record(model), session["title"], say),
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": 'inline; filename="' + name + '-undercover.html"',
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; sandbox",
            },
        )
    if suffix in ("vtt", "srt"):
        return Response(
            documentation.subtitles(
                model, say, documentation.appearance_of(session), suffix,
                int(request.query_params.get("recording") or 1),
            ),
            media_type="text/vtt; charset=utf-8" if suffix == "vtt" else "application/x-subrip; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="' + name + "." + suffix + '"'},
        )
    if suffix == "md":
        return Response(
            documentation.render_markdown(
                model, say, fixed, documentation.appearance_of(session)
            ),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="' + name + '.md"'},
        )
    supplied = await ctx.recorder_files(
        [block["step"] for block in model["blocks"] if block["type"] == "step"]
    )
    found = await asyncio.to_thread(
        case_package.collect_files, model, supplied, ctx.root / "media"
    )
    images = {
        sha256: "data:"
        + case_package.kind(data)[0]
        + ";base64,"
        + base64.b64encode(data).decode("ascii")
        for sha256, data in found.items()
        if case_package.kind(data)[0].startswith("image/")
    }
    render = (
        documentation.render_slides if suffix == "slides" else documentation.render_html
    )
    return Response(
        render(model, say, fixed, images, documentation.appearance_of(session)),
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": 'inline; filename="'
            + name
            + ("-slides" if suffix == "slides" else "")
            + '.html"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; sandbox",
        },
    )


class DocumentationOperations:
    async def protocol_model(self, request, chat_id):
        if chat_id is not None:
            self.require_chat(request, chat_id)
        value = await asyncio.to_thread(
            action_protocol.collect,
            self.app.state.store,
            chat_id,
            self.visible_chats(request),
        )
        await self.recheck_export_scope(
            request,
            {e["chat_id"] for e in value["episodes"]}
            | ({chat_id} if chat_id is not None else set()),
        )
        return value

    async def recorder_files(self, steps, limit=30, budget=48 * 1024 * 1024):
        capture = getattr(self.app.state, "capture", None)
        wanted = [
            item["sha256"]
            for step in steps
            if step.get("type") == "visual" and (not step.get("hidden"))
            for item in step.get("files") or []
            if item.get("mime_type") == "image/png"
        ]
        found = {}
        for sha256 in list(dict.fromkeys(wanted))[:limit] if capture else []:
            try:
                data = await asyncio.to_thread(capture.object, "browser", sha256)
            except Exception:
                continue
            if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) <= budget:
                budget -= len(data)
                found[sha256] = data
        return found

    async def recorder_images(self, steps):
        return {
            sha256: "data:image/png;base64," + base64.b64encode(data).decode("ascii")
            for sha256, data in (await self.recorder_files(steps)).items()
        }

    def documented(self, request, session_id):
        try:
            session = documentation.load(self.app.state.store, session_id)
        except KeyError:
            raise HTTPException(404, "Documentation not found.") from None
        allowed = self.visible_chats(request)
        try:
            documentation.require_scope(session, allowed)
        except ValueError as exc:
            raise HTTPException(403, str(exc)) from None
        return session

    async def recorder_video(self):
        capture = getattr(self.app.state, "capture", None)
        if capture is None:
            return None

        def read():
            from tgwitness_capture.format import check_event

            if not capture.public()["connections"]["browser"]["enabled"]:
                return None
            current = capture.request("browser")
            status, body = (current["status"], current["checkpoint"]["body"])
            if not status.get("video_running"):
                return None
            started = next(
                (
                    item
                    for item in reversed(capture.request("browser", "events"))
                    if isinstance(item, dict) and item.get("kind") == "video.started"
                ),
                None,
            )
            if started is None:
                return None
            check_event(started, body["public_key"], body["observer_id"])
            return {
                "recorder": status["fingerprint"],
                "observer_id": body["observer_id"],
                "recording_started_at": started["observed_at"],
                "video_started_event": started["hash"],
            }

        try:
            async with capture.lock:
                return await asyncio.wait_for(asyncio.to_thread(read), 15)
        except Exception:
            return None

    def editable(self, request, session_id):
        session = self.documented(request, session_id)
        who = request.state.principal
        if not (
            who.admin or who.may("board.manage") or session.get("owner") == who.owner
        ):
            raise HTTPException(
                403,
                "Only the author of this documentation or a board manager can change it.",
            )
        return session

    async def documentation_call(self, function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except KeyError:
            raise HTTPException(404, "Documentation or note not found.") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    async def case_download(self, request, session, secret):
        steps = [
            block["step"]
            for block in session["fixed"]["model"]["blocks"]
            if block["type"] == "step"
        ]
        supplied = await self.recorder_files(steps)
        say = report.Words(panel_language(request))
        try:
            path = await build_file(
                lambda: case_package.build(
                    session,
                    say,
                    supplied,
                    self.root / "media",
                    None,
                    self.app.state.store.root / "checkpoints",
                    secret,
                )
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        self.app.state.store.append(
            "documentation.package_prepared",
            {
                "session_id": session["id"],
                "statement_sha256": session["fixed"]["statement_sha256"],
                "encrypted": secret is not None,
                "access": request.state.principal.label,
            },
        )
        return TemporaryDownload(
            path,
            media_type="application/zip",
            filename="tgwitness-case-"
            + session["id"][:8]
            + (".encrypted" if secret else "")
            + ".zip",
            headers={"Cache-Control": "no-store"},
        )
