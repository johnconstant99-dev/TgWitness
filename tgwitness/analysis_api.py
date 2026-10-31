import asyncio
import re

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import ai
from .access import Refused
from .analysis import Analysis, Generate, Question, ReportEdit, prompt, report_from, retrieve, verified_claims, verify_sources
from .archive import ArchiveQuery, ArchiveReader
from .store import utcnow


class SaveReport(BaseModel):
    plan_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def register(app, authenticate):
    service = Analysis()
    reads = asyncio.Semaphore(2)

    def reader(request):
        return ArchiveReader(app.state.profiles, request.state.principal)

    def workspace(request, key):
        return reader(request).workspace(ArchiveQuery(tool="list_chats", workspace=key))

    async def reauthorize(request):
        token = request.headers.get("authorization", "").partition(" ")[2]
        who = app.state.access.resolve(token, request.client.host if request.client else "unknown")
        if who is None:
            raise Refused("This access is no longer available.")
        await authenticate(request, who)
        request.state.principal = who

    async def execute(function, *args):
        try:
            return await function(*args)
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError:
            raise HTTPException(504, "The operation timed out. Narrow the selection or retry.") from None
        except OSError:
            raise HTTPException(502, "The configured processing service could not be reached.") from None
        except ai.netclient.RouteError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/analysis/provider", dependencies=[Depends(authenticate)])
    async def provider(request: Request, workspace_id: str = "default"):
        try:
            return ai.public(workspace(request, workspace_id))
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None

    @app.post("/api/analysis/provider", dependencies=[Depends(authenticate)])
    async def configure(request: Request, body: ai.ProviderSettings, workspace_id: str = "default"):
        if not request.state.principal.admin:
            raise HTTPException(403, "Only the main administrator can configure AI.")
        return ai.configure(workspace(request, workspace_id), body)

    @app.post("/api/analysis/provider/test", dependencies=[Depends(authenticate)])
    async def connection(request: Request, workspace_id: str = "default"):
        if not request.state.principal.admin:
            raise HTTPException(403, "Only the main administrator can configure AI.")
        async def test():
            state = workspace(request, workspace_id)
            _, generation = await service.provider.complete(state, [
                {"role": "system", "content": 'Return JSON {"ok":true}.'},
                {"role": "user", "content": "Synthetic connection check. No archive data."}])
            return {"ok": True, "messages_read": 0, "generation": generation}
        return await execute(test)

    @app.post("/api/analysis/preview", dependencies=[Depends(authenticate)])
    async def preview(request: Request, body: Question):
        async def search():
            scoped = reader(request)
            state = workspace(request, body.workspace)
            config = ai.settings(state)
            async with asyncio.timeout(10):
                async with reads:
                    result = await asyncio.to_thread(retrieve, scoped, body, config["context_chars"])
            return service.remember(request.state.principal, body, result, config)
        return await execute(search)

    @app.post("/api/analysis/context", dependencies=[Depends(authenticate)])
    async def context(request: Request, body: ArchiveQuery):
        async def read_context():
            if body.tool not in ("get_message_context", "get_message_versions"):
                raise ValueError("Choose message context or saved versions.")
            async with asyncio.timeout(8):
                async with reads:
                    return await asyncio.to_thread(reader(request).read, body)
        return await execute(read_context)

    @app.post("/api/analysis/generate", dependencies=[Depends(authenticate)])
    async def generate(request: Request, body: Generate):
        async def answer():
            if not body.consent:
                raise ValueError("Review and explicitly approve the selected data before processing.")
            plan = service.plan(body.plan_id, request.state.principal)
            if plan.get("generating") or plan.get("answer"):
                raise ValueError("This preview has already been submitted. Search again for a new request.")
            selected = [s for s in plan["sources"] if s["id"] in body.source_ids]
            if set(body.source_ids) != {s["id"] for s in selected}:
                raise ValueError("Select only sources from this preview.")
            await reauthorize(request)
            await asyncio.to_thread(verify_sources, reader(request), selected + plan["coverage"]["events"])
            state = workspace(request, plan["workspace"])
            plan["generating"] = True
            try:
                output, generation = await service.provider.complete(state,
                    prompt(plan["question"], selected, plan["coverage"]), plan["provider_fingerprint"])
                await reauthorize(request)
                await asyncio.to_thread(verify_sources, reader(request), selected + plan["coverage"]["events"])
                claims = verified_claims(output, selected)
                plan["selected"] = selected
                plan["answer"] = {"claims": claims, "generation": {**generation, "at": utcnow()},
                                  "not_found": not bool(claims), "sources": selected, "coverage": plan["coverage"]}
                return plan["answer"]
            finally:
                plan["generating"] = False
        return await execute(answer)

    def get_report(request, state, ident):
        if not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise Refused("Report is unavailable.")
        report = state.vault.read("analysis-report-" + ident)
        if not report or (report["owner"] != request.state.principal.owner and not request.state.principal.admin):
            raise Refused("Report is unavailable.")
        verify_sources(reader(request), report["sources"] + report["coverage"]["events"])
        return report

    @app.post("/api/analysis/reports", dependencies=[Depends(authenticate)])
    async def save(request: Request, body: SaveReport):
        async def write():
            plan = service.plan(body.plan_id, request.state.principal)
            if not plan.get("answer"):
                raise ValueError("Generate and review an answer first.")
            state = workspace(request, plan["workspace"])
            await asyncio.to_thread(verify_sources, reader(request), plan["selected"])
            if plan.get("report_id"):
                return get_report(request, state, plan["report_id"])
            entries = state.store.get_setting("analysis_reports", [])
            if len(entries) >= 100:
                raise ValueError("The workspace report limit has been reached.")
            report = report_from(plan)
            state.vault.save("analysis-report-" + report["id"], report)
            entries.append({k: report[k] for k in ("id", "title", "created_at", "owner")})
            state.store.set_setting("analysis_reports", entries)
            plan["report_id"] = report["id"]
            return report
        return await execute(write)

    @app.get("/api/analysis/reports", dependencies=[Depends(authenticate)])
    async def reports(request: Request, workspace_id: str = "default"):
        async def listed():
            state = workspace(request, workspace_id)
            result = []
            for entry in state.store.get_setting("analysis_reports", []):
                try:
                    report = await asyncio.to_thread(get_report, request, state, entry["id"])
                    result.append({k: report[k] for k in ("id", "title", "created_at")})
                except Refused:
                    pass
            return {"reports": result}
        return await execute(listed)

    @app.get("/api/analysis/reports/{report_id}", dependencies=[Depends(authenticate)])
    async def report(request: Request, report_id: str, workspace_id: str = "default"):
        async def load():
            return await asyncio.to_thread(get_report, request, workspace(request, workspace_id), report_id)
        return await execute(load)

    @app.patch("/api/analysis/reports/{report_id}", dependencies=[Depends(authenticate)])
    async def edit(request: Request, report_id: str, body: ReportEdit, workspace_id: str = "default"):
        async def revise():
            state = workspace(request, workspace_id)
            report = await asyncio.to_thread(get_report, request, state, report_id)
            if len(report["analyst_revisions"]) >= 100:
                raise ValueError("The report revision limit has been reached.")
            report["title"] = body.title
            report["analyst_revisions"].append({**body.model_dump(), "at": utcnow(),
                                               "author": request.state.principal.label, "category": "analyst_note"})
            state.vault.save("analysis-report-" + report_id, report)
            return report
        return await execute(revise)

    @app.get("/api/analysis/reports/{report_id}/download", dependencies=[Depends(authenticate)])
    async def download(request: Request, report_id: str, workspace_id: str = "default"):
        async def export():
            report = await asyncio.to_thread(get_report, request, workspace(request, workspace_id), report_id)
            report.pop("owner", None)
            return JSONResponse(report, headers={"Content-Disposition": 'attachment; filename="tgwitness-analysis.json"'})
        return await execute(export)
