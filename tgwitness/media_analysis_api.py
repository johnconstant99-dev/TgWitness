import re

from fastapi import Depends, HTTPException, Request

from .access import Refused
from .archive import ArchiveQuery, ArchiveReader
from .media_analysis import MediaJob, MediaQueue, authorize, available


def register(app, authenticate):
    queue = MediaQueue()
    app.state.media_analysis = queue

    def reader(request):
        return ArchiveReader(app.state.profiles, request.state.principal)

    def state_for(request, workspace):
        return reader(request).workspace(ArchiveQuery(tool="list_chats", workspace=workspace))

    def visible(request, state, ident):
        if not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise Refused("Media result is unavailable.")
        entry = next((e for e in queue.recover(state) if e["id"] == ident), None)
        if not entry:
            raise Refused("Media result is unavailable.")
        authorize(reader(request), MediaJob(**entry["request"]))
        return entry

    async def run(action):
        try:
            return await action()
        except Refused as exc:
            raise HTTPException(403, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/analysis/media", dependencies=[Depends(authenticate)])
    async def listing(request: Request, workspace_id: str = "default", query: str = "", kind: str = "", offset: int = 0):
        async def listed():
            if len(query) > 200 or kind not in ("", "ocr", "transcription") or not 0 <= offset <= 100:
                raise ValueError("Choose a valid recognition filter and page.")
            state = state_for(request, workspace_id)
            result = []
            for entry in queue.recover(state):
                try:
                    visible(request, state, entry["id"])
                except (Refused, ValueError):
                    continue
                if kind and entry["request"]["engine"] != kind:
                    continue
                artifact = state.vault.read("media-analysis-" + entry["id"]) if entry["status"] == "completed" else None
                if query and (not artifact or query.casefold() not in artifact["text"].casefold()):
                    continue
                result.append({k: v for k, v in entry.items() if k != "owner"} | {
                    "excerpt": artifact["text"][:300] if artifact else None})
            return {"available": available(), "processing": "local-container", "jobs": result[offset:offset + 20],
                    "next_offset": offset + 20 if len(result) > offset + 20 else None}
        return await run(listed)

    @app.post("/api/analysis/media", dependencies=[Depends(authenticate)])
    async def start(request: Request, body: MediaJob):
        async def create():
            return queue.start(reader(request), body, request.state.principal.owner)
        return await run(create)

    @app.get("/api/analysis/media/{job_id}", dependencies=[Depends(authenticate)])
    async def result(request: Request, job_id: str, workspace_id: str = "default"):
        async def load():
            state = state_for(request, workspace_id)
            entry = visible(request, state, job_id)
            return {"job": {k: v for k, v in entry.items() if k != "owner"},
                    "result": state.vault.read("media-analysis-" + job_id) if entry["status"] == "completed" else None}
        return await run(load)

    @app.post("/api/analysis/media/{job_id}/{action}", dependencies=[Depends(authenticate)])
    async def change(request: Request, job_id: str, action: str, workspace_id: str = "default"):
        async def act():
            state = state_for(request, workspace_id)
            entry = visible(request, state, job_id)
            if entry["owner"] != request.state.principal.owner and not request.state.principal.admin:
                raise Refused("Only the job owner or administrator can change this job.")
            if action == "cancel" and entry["status"] in ("queued", "running"):
                await queue.cancel(job_id, state)
                return {"cancelled": True}
            if action == "retry" and entry["status"] in ("failed", "interrupted", "cancelled"):
                return queue.start(reader(request), MediaJob(**entry["request"]), request.state.principal.owner, job_id)
            raise ValueError("This media job does not support the selected action.")
        return await run(act)
