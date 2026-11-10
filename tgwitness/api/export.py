from .. import app as application
from .. import handover
from .. import pdf_report
from .. import report
from .. import report_profiles
from ..access import POLICY
from ..access import Refused
from ..access import check as access_check
from ..account_export import AccountExportOptions
from ..app import ChatExport
from ..app import ExportPassword
from ..app import HandoverRequest
from ..app import panel_language
from ..app import report_options
from ..disclosure import DisclosurePolicy
from ..downloads import RetainedDownload
from ..downloads import TemporaryDownload
from ..downloads import build_file
from ..evidence import encrypt_export
from ..workers import complete_in_thread
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic import Field
from typing import Literal
import asyncio
import json
import secrets


class DisclosureConfirmation(BaseModel):
    model_config = {"extra": "forbid"}
    preview_id: str = Field(min_length=16, max_length=100)


async def account_export_jobs(*, ctx=Depends(current_context)):
    jobs = ctx.app.state.account_export.list_jobs()
    for job in jobs:
        job["disclosures"] = ctx.app.state.disclosures.list(job["id"])
    return {
        "jobs": jobs,
        "defaults": AccountExportOptions().model_dump(),
        "capabilities": {
            "takeout": True,
            "regular": True,
            "resumable": True,
            "signed_capture_pages": True,
            "minimized_disclosure": True,
        },
    }


async def account_export_start(
    body: AccountExportOptions, *, ctx=Depends(current_context)
):
    from ..report_studio import presentation

    if "report_presentation" not in body.model_fields_set:
        body.report_presentation = presentation(report.saved(ctx.app.state.store))
    return await ctx.operation(ctx.app.state.account_export.start, body.model_dump())


async def account_export_preflight(
    body: AccountExportOptions, sample: bool = True, *, ctx=Depends(current_context)
):
    from ..export_preflight import preview

    async def inspect_settings():
        return await preview(
            ctx.app.state.account_export, body.model_dump(), sample=sample
        )

    return await ctx.operation(inspect_settings)


async def account_export_status(export_id: str, *, ctx=Depends(current_context)):
    try:
        state = ctx.app.state.account_export.public(export_id)
        if state["phase"] == "unknown":
            raise HTTPException(404, "Unknown account export.")
        return {**state, "disclosures": ctx.app.state.disclosures.list(export_id)}
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None


async def account_export_pause(export_id: str, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.account_export.pause, export_id)


async def account_export_resume(export_id: str, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.account_export.resume, export_id)


async def account_export_finish(export_id: str, *, ctx=Depends(current_context)):
    return await ctx.operation(ctx.app.state.account_export.finish, export_id)


async def account_export_remove(export_id: str, *, ctx=Depends(current_context)):

    async def remove():
        if ctx.account_downloads.get(export_id):
            raise HTTPException(
                409,
                "Wait for the active download to finish before removing this export.",
            )
        if ctx.app.state.disclosures.busy(export_id):
            raise HTTPException(
                409,
                "Wait for the disclosure package to finish before removing its source.",
            )
        return await ctx.app.state.account_export.remove(export_id)

    return await ctx.operation(remove)


async def account_export_ticket(
    export_id: str, request: Request, *, ctx=Depends(current_context)
):
    return await ctx.account_job_ticket(request, export_id)


async def account_export_download(
    export_id: str, request: Request, *, ctx=Depends(current_context)
):
    return await ctx.account_job_download(request, export_id)


async def disclosure_preview(
    request: Request,
    export_id: str,
    body: DisclosurePolicy,
    *,
    ctx=Depends(current_context),
):
    from ..report_studio import presentation

    if "report_presentation" not in body.model_fields_set:
        body.report_presentation = presentation(
            report.saved(ctx.app.state.store), include_guidance=False
        )
    ctx.require_live()
    principal = request.state.principal
    async with ctx.op_lock:
        try:
            ctx.require_live()
            return await complete_in_thread(
                ctx.app.state.disclosures.preview,
                export_id,
                body.model_dump(),
                principal.session_id or principal.owner,
            )
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from None


async def disclosure_create(
    request: Request,
    export_id: str,
    body: DisclosureConfirmation,
    *,
    ctx=Depends(current_context),
):
    ctx.require_live()
    principal = request.state.principal
    async with ctx.op_lock:
        try:
            ctx.require_live()
            return await ctx.app.state.disclosures.create(
                export_id, body.preview_id, principal.session_id or principal.owner
            )
        except (ValueError, OSError, KeyError) as exc:
            raise HTTPException(409, str(exc)) from None


async def disclosure_ticket(
    export_id: str,
    disclosure_id: str,
    request: Request,
    *,
    ctx=Depends(current_context),
):
    return await ctx.account_job_ticket(request, export_id, disclosure_id)


async def disclosure_download(
    export_id: str,
    disclosure_id: str,
    request: Request,
    *,
    ctx=Depends(current_context),
):
    return await ctx.account_job_download(request, export_id, disclosure_id)


async def chat_export_start(
    request: Request, body: ChatExport, *, ctx=Depends(current_context)
):
    ctx.require_chat(request, body.chat_id)
    record = await ctx.operation(
        ctx.app.state.collector.start_export,
        body.chat_id,
        report_options(ctx.app.state.store, request, body.language),
        body.files,
    )
    ctx.chat_export_owners.clear()
    ctx.chat_export_owners[record["id"]] = request.state.principal.owner
    return record


async def report_guidance_catalog(*, ctx=Depends(current_context)):
    from ..jurisdiction_guidance import catalog

    return catalog()


async def get_report_options(*, ctx=Depends(current_context)):
    return report.saved(ctx.app.state.store).model_dump()


async def set_report_options(
    body: report.ReportOptions, *, ctx=Depends(current_context)
):
    return report.save(ctx.app.state.store, body).model_dump()


async def get_report_profiles(*, ctx=Depends(current_context)):
    return {
        "profiles": report_profiles.catalog(ctx.app.state.store),
        "fields": sorted(report_profiles.LAYOUT_FIELDS),
    }


async def save_report_profile(
    body: report_profiles.Profile, *, ctx=Depends(current_context)
):
    try:
        return report_profiles.save(ctx.app.state.store, body)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


async def delete_report_profile(profile_id: str, *, ctx=Depends(current_context)):
    try:
        report_profiles.remove(ctx.app.state.store, profile_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    return {"removed": True}


async def report_preview_css(*, ctx=Depends(current_context)):
    return Response(report.CSS, media_type="text/css")


async def report_preview(
    request: Request, body: report.ReportOptions, *, ctx=Depends(current_context)
):
    from ..report_studio import preview

    options = body.model_dump()
    if options["language"] == "auto":
        options["language"] = panel_language(request)
    async with ctx.export_lock:
        return await complete_in_thread(preview, ctx.app.state.store, options)


async def preview_report(body: report.ReportOptions, *, ctx=Depends(current_context)):

    def preview():
        with ctx.app.state.store.snapshot() as snapshot:
            result = report.report_selection.analyze(
                snapshot,
                body.selection,
                scratch_root=ctx.app.state.store.root / "temporary-exports",
            )
            keys = result.pop("changed_keys")
            total = result.pop("changed_total")
            messages = (
                report.report_history.preview(
                    snapshot.events(),
                    keys,
                    predicate=report.report_selection.compile_selection(body.selection),
                )
                if keys
                else []
            )
            result["changes"] = {
                "messages": messages,
                "total": total,
                "listed": len(messages),
                "truncated": total > len(messages),
            }
        result["analytics"] = report.report_analytics.selected(
            result["analytics"], body.model_dump()
        )
        result["unsigned"] = True
        return result

    async with ctx.export_lock:
        return await complete_in_thread(preview)


async def chat_export_poll(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    return (
        ctx.app.state.collector.poll_export(export_id)
        if ctx.export_visible(request, export_id)
        else {"phase": "unknown"}
    )


async def chat_export_cancel(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    if not ctx.export_visible(request, export_id):
        raise HTTPException(
            403, "Only the access that started this chat export can cancel it."
        )
    return await ctx.operation(ctx.app.state.collector.cancel_export, export_id)


async def chat_export_download(
    request: Request, export_id: str, *, ctx=Depends(current_context)
):
    from .. import export_history

    collector = ctx.app.state.collector
    path = (
        collector.export_result_path(export_id)
        if ctx.export_visible(request, export_id)
        else None
    )
    if not path:
        raise HTTPException(404, "No finished chat export is available to download.")
    filename = collector.export_state["filename"]
    entry = ctx.prepared_chat_exports.get(export_id)
    if entry is None:
        entry = await asyncio.to_thread(
            export_history.prepared,
            ctx.app.state.store,
            path,
            "zip",
            False,
            owner=request.state.principal.owner,
            workspace=ctx.profile_id,
            required_permissions=["view", "export"],
            chat_ids=[(collector.export_state or {}).get("chat_id")],
        )
        ctx.prepared_chat_exports[export_id] = entry
    if not entry.get("cache_warning"):
        try:
            copy = await build_file(
                lambda: export_history.download_copy(ctx.app.state.store, entry["id"])[0]
            )
        except ValueError:
            ctx.prepared_chat_exports.pop(export_id, None)
        else:
            return TemporaryDownload(
                copy,
                filename=filename,
                media_type="application/zip",
                headers=export_history.headers(entry),
            )
    return FileResponse(
        path,
        filename=filename,
        media_type="application/zip",
        headers=export_history.headers(entry),
    )


async def export(
    request: Request,
    fmt: Literal["zip", "jsonl", "csv", "html", "json", "pdf"],
    language: str | None = None,
    *,
    ctx=Depends(current_context),
):
    path, headers = await ctx.build_export(fmt, request, language=language)
    media_types = {
        "zip": "application/zip",
        "jsonl": "application/x-ndjson",
        "csv": "text/csv",
        "html": "text/html",
        "json": "application/json",
        "pdf": "application/pdf",
    }
    name = (
        "tgwitness-report." + fmt
        if fmt in ("json", "pdf")
        else "tgwitness-evidence." + fmt
    )
    return TemporaryDownload(
        path, filename=name, media_type=media_types[fmt], headers=headers
    )


async def export_encrypted(
    request: Request,
    fmt: Literal["zip", "jsonl", "csv", "html", "json", "pdf"],
    body: ExportPassword,
    language: str | None = None,
    *,
    ctx=Depends(current_context),
):
    path, headers = await ctx.build_export(fmt, request, body.password, language, body.encryption)
    return TemporaryDownload(
        path,
        filename="tgwitness-evidence-" + fmt + "-encrypted." + body.encryption,
        media_type="application/zip" if body.encryption == "zip" else "application/octet-stream",
        headers=headers,
    )


async def export_handover(
    request: Request, body: HandoverRequest, *, ctx=Depends(current_context)
):
    for chat in body.chats:
        ctx.require_chat(request, chat)
    if body.case_board != "off" and (not request.state.principal.may("board.read")):
        raise HTTPException(403, "Reading Case Board requires board.read.")
    from .. import export_history

    options = report_options(ctx.app.state.store, request, body.language)
    selection = handover.Options.model_validate(
        body.model_dump(exclude={"password", "language", "encryption"})
    )
    receipt, summary = ({}, {})
    principal = request.state.principal
    permissions = ["view", "export"] + (
        ["board.read"] if body.case_board != "off" else []
    )

    def build():
        path, recorded = handover.export(
            ctx.app.state.store, ctx.app.state.vault, selection, options
        )
        try:
            summary.update(recorded)
            if body.password is not None:
                path = encrypt_export(
                    path, "zip", body.password, "tgwitness-handover.zip", mode=body.encryption
                )
            receipt.update(
                export_history.prepared(
                    ctx.app.state.store,
                    path,
                    "handover",
                    body.password is not None,
                    owner=principal.owner,
                    workspace=ctx.profile_id,
                    required_permissions=permissions,
                    chat_ids=body.chats,
                    encryption=body.encryption,
                )
            )
            return path
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    async with ctx.export_lock, ctx.app.state.storage.lock:
        try:
            path = await build_file(build)
        except (handover.RemoteAttachment, handover.MissingAttachment) as exc:
            raise HTTPException(409, str(exc)) from None
        except handover.EmptySelection as exc:
            raise HTTPException(422, str(exc)) from None
        except Exception as exc:
            ctx.app.state.store.append(
                "export.failed",
                {"format": "handover", "error_type": type(exc).__name__},
            )
            raise HTTPException(
                409,
                "Export failed integrity, size, or file checks. Inspect local data and limits.",
            ) from None
    try:
        await ctx.recheck_export_scope(request, set(body.chats))
        ctx.require_prepared_access(request, receipt)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    principal = request.state.principal
    ctx.app.state.store.append(
        "handover.exported",
        {
            **summary,
            "file_sha256": receipt.get("sha256"),
            "encrypted": body.password is not None,
            "by": {"access_id": principal.owner, "label": principal.label},
            "meaning": "a minimised extract was prepared; its contents are not repeated here",
        },
    )
    return TemporaryDownload(
        path,
        filename="tgwitness-handover"
        + ("-encrypted" if body.password else "")
        + ("." + body.encryption if body.password else ".zip"),
        media_type="application/octet-stream" if body.password and body.encryption == "tgwpw" else "application/zip",
        headers=export_history.headers(receipt),
    )


async def prepared_exports(request: Request, *, ctx=Depends(current_context)):
    from ..export_history import listing

    return listing(
        ctx.app.state.store,
        principal=request.state.principal,
        profile_id=ctx.profile_id,
    )


async def export_ticket(
    export_id: str, request: Request, *, ctx=Depends(current_context)
):
    from ..export_history import locate

    try:
        async with ctx.export_lock:
            ctx.prepared_access(request, export_id)
            await complete_in_thread(locate, ctx.app.state.store, export_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    await ctx.identify_download(
        request, request.headers.get("authorization", "").partition(" ")[2]
    )
    ctx.prepared_access(request, export_id)
    return ctx.issue_download_ticket(
        request, export_id, "exports/" + export_id + "/download"
    )


async def export_again(
    export_id: str, request: Request, *, ctx=Depends(current_context)
):
    from ..export_history import download_copy, headers

    credential = await ctx.authorize_download(request, export_id)
    receipt = {}

    def prepare_download():
        path, metadata = download_copy(ctx.app.state.store, export_id)
        receipt.update(metadata)
        return path

    try:
        async with ctx.export_lock:
            ctx.prepared_access(request, export_id)
            path = await build_file(prepare_download)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    try:
        try:
            who = await ctx.identify_download(request, credential)
            if who is None:
                raise Refused("This access has expired.")
            access_check(
                who, ctx.profile_id, POLICY["GET /api/exports/{export_id}/download"], {}
            )
            ctx.require_prepared_access(request, receipt)
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        extension = (
            "tgwpw" if receipt.get("encrypted") and receipt.get("encryption") == "tgwpw" else "zip"
            if receipt["encrypted"] or receipt["format"] in ("handover", "group")
            else receipt["format"]
        )
        return TemporaryDownload(
            path,
            filename="tgwitness-"
            + ctx.profile_id[:8]
            + "-"
            + export_id[:8]
            + "."
            + extension,
            media_type="application/octet-stream",
            headers={**headers(receipt), "Cache-Control": "no-store"},
        )
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class ExportOperations:
    def account_download_path(self, export_id, disclosure_id=None):
        try:
            path = (
                self.app.state.disclosures.result_path(export_id, disclosure_id)
                if disclosure_id
                else self.app.state.account_export.result_path(export_id)
            )
        except ValueError:
            path = None
        if not path:
            raise HTTPException(
                404,
                "No finished disclosure is available."
                if disclosure_id
                else "No finished account export is available.",
            )
        return path

    async def account_job_ticket(self, request, export_id, disclosure_id=None):
        async with self.op_lock:
            if self.app.state.closing:
                raise HTTPException(
                    503, "This workspace is closing. Wait for it to finish."
                )
            await self.identify_download(
                request, request.headers.get("authorization", "").partition(" ")[2]
            )
            self.account_download_path(export_id, disclosure_id)
            target = f"account-export/{export_id}" + (
                f"/disclosures/{disclosure_id}" if disclosure_id else ""
            )
            return self.issue_download_ticket(request, target, target + "/download")

    async def account_job_download(self, request, export_id, disclosure_id=None):
        target = f"account-export/{export_id}" + (
            f"/disclosures/{disclosure_id}" if disclosure_id else ""
        )
        credential = await self.authorize_download(request, target)
        async with self.op_lock:
            if self.app.state.closing:
                raise HTTPException(
                    503, "This workspace is closing. Wait for it to finish."
                )
            await self.identify_download(request, credential)
            path = self.account_download_path(export_id, disclosure_id)
            headers = {
                "Cache-Control": "private, no-store",
                "X-TgWitness-Download-Ticket": target + "/ticket",
            }
            if not disclosure_id:
                state = self.app.state.account_export.public(export_id)
                if state.get("archive_sha256"):
                    headers["ETag"] = '"' + state["archive_sha256"] + '"'
            self.account_downloads[export_id] = (
                self.account_downloads.get(export_id, 0) + 1
            )
            released = False

            def release():
                nonlocal released
                if not released:
                    released = True
                    remaining = self.account_downloads.get(export_id, 1) - 1
                    if remaining:
                        self.account_downloads[export_id] = remaining
                    else:
                        self.account_downloads.pop(export_id, None)

            try:
                return RetainedDownload(
                    path,
                    release=release,
                    filename="tgwitness-minimized-disclosure.zip"
                    if disclosure_id
                    else "tgwitness-account-export.zip",
                    media_type="application/zip",
                    headers=headers,
                )
            except BaseException:
                release()
                raise

    def export_visible(self, request, export_id):
        state, allowed, principal = (
            self.app.state.collector.export_state,
            self.visible_chats(request),
            request.state.principal,
        )
        if state and allowed is not None and (state["chat_id"] not in allowed):
            return False
        return (
            principal.admin or self.chat_export_owners.get(export_id) == principal.owner
        )

    async def build_export(self, fmt, request, password=None, language=None, encryption="zip"):
        from .. import export_history

        receipt = {}
        options = report_options(self.app.state.store, request, language)
        principal = request.state.principal
        include_board = principal.may("board.read")
        permissions = ["view", "export"] + (["board.read"] if include_board else [])

        def build():
            path = application.export_file(
                self.app.state.store,
                self.app.state.vault,
                fmt,
                options,
                include_board=include_board,
            )
            try:
                if password is not None:
                    path = encrypt_export(path, fmt, password, mode=encryption)
                receipt.update(
                    export_history.prepared(
                        self.app.state.store,
                        path,
                        fmt,
                        password is not None,
                        owner=principal.owner,
                        workspace=self.profile_id,
                        required_permissions=permissions,
                        encryption=encryption,
                    )
                )
                return path
            except BaseException:
                path.unlink(missing_ok=True)
                raise

        head = self.app.state.store.stats()["head"]["seq"]
        async with self.export_lock, self.app.state.storage.lock:
            if fmt == "zip":
                try:
                    self.app.state.storage.require_local_media()
                except ValueError as exc:
                    raise HTTPException(409, str(exc)) from None
            try:
                path = await build_file(build)
            except pdf_report.MissingFont as exc:
                raise HTTPException(409, str(exc)) from None
            except Exception as exc:
                self.app.state.store.append(
                    "export.failed", {"format": fmt, "error_type": type(exc).__name__}
                )
                raise HTTPException(
                    409,
                    "Export failed integrity, size, or file checks. Inspect local data and limits.",
                ) from None
        try:
            from ..webhooks import export_completed

            await export_completed(
                self.app.state.store, self.app.state.vault, self.profile_id
            )
            self.app.state.alert_wakeup.set()
            await self.recheck_export_scope(request, None)
            self.require_prepared_access(request, receipt)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        if fmt == "zip":
            export_history.evidence_exported(self.app.state.store, head)
        return (path, export_history.headers(receipt))

    async def identify_download(self, request, credential):
        try:
            principal = await self.identify(
                request,
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=credential),
            )
            await self.authenticate(request, principal)
            return principal
        except HTTPException as exc:
            if exc.status_code == 401:
                raise HTTPException(403, "This access has expired.") from None
            raise

    async def recheck_export_scope(self, request, original_chats):
        await self.identify_download(
            request, request.headers.get("authorization", "").partition(" ")[2]
        )
        current = self.visible_chats(request)
        if current is not None and (
            original_chats is None or not set(original_chats) <= current
        ):
            raise HTTPException(403, "This chat is not open to this access.")

    def require_prepared_access(self, request, entry):
        from ..export_history import permitted

        if not permitted(entry, request.state.principal, self.profile_id):
            raise HTTPException(403, "This export is not open to this access.")

    def prepared_access(self, request, export_id):
        from ..export_history import metadata

        entry = metadata(self.app.state.store, export_id)
        if entry is None:
            raise HTTPException(404, "This prepared export is unavailable.")
        self.require_prepared_access(request, entry)
        return entry

    def issue_download_ticket(self, request, target, api_path):
        now = application.time.monotonic()
        for key, value in list(self.prepared_tickets.items()):
            if value[0] < now:
                self.prepared_tickets.pop(key, None)
        owner = request.state.principal.owner
        if len(self.prepared_tickets) >= 1000:
            raise HTTPException(429, "Too many pending downloads. Retry in a minute.")
        if sum(value[3] == owner for value in self.prepared_tickets.values()) >= 10:
            raise HTTPException(
                429, "Too many pending downloads for this access. Retry in a minute."
            )
        ticket = secrets.token_urlsafe(32)
        self.prepared_tickets[ticket] = (
            now + 120,
            target,
            request.headers.get("authorization", "").partition(" ")[2],
            owner,
        )
        path = (
            ("" if self.profile_id == "default" else "/profiles/" + self.profile_id)
            + "/api/"
            + api_path
        )
        response = Response(
            json.dumps({"url": path}),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
        response.set_cookie(
            "tgwitness-download",
            ticket,
            max_age=120,
            path=path,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https"
            or request.url.hostname not in ("127.0.0.1", "localhost", "::1"),
        )
        return response

    async def authorize_download(self, request, target):
        if request.headers.get("authorization"):
            scheme, _, credential = request.headers["authorization"].partition(" ")
            if scheme.lower() != "bearer":
                raise HTTPException(401, "Use a Bearer access token.")
            who = await self.identify(
                request,
                HTTPAuthorizationCredentials(scheme="Bearer", credentials=credential),
            )
            await self.authenticate(request, who)
        else:
            entry = self.prepared_tickets.pop(
                request.cookies.get("tgwitness-download", ""), None
            )
            if (
                not entry
                or entry[0] < application.time.monotonic()
                or entry[1] != target
            ):
                raise HTTPException(
                    403,
                    "This download link expired. Choose Download again in the panel.",
                )
            credential = entry[2]
            await self.identify_download(request, credential)
        return credential
