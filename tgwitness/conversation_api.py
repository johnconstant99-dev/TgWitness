import asyncio

from fastapi import Depends, HTTPException, Request

from . import ai, conversation
from .conversation import Assist, Create, Edit, Generate, Goal, Step


def register(app, authenticate, require_live, visible_chats):
    assistant = conversation.Assistant()

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except KeyError:
            raise HTTPException(404, "Plan, goal or step not found.") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    def store():
        return app.state.store

    @app.get("/api/conversation", dependencies=[Depends(authenticate)])
    async def plans(request: Request):
        chats = visible_chats(request)
        return {"plans": await call(conversation.listing, store(), chats),
                "templates": {key: {"title": title, "goals": list(goals)}
                              for key, (title, goals) in conversation.TEMPLATES.items()},
                "ai": ai.enabled(app.state)}

    @app.post("/api/conversation", dependencies=[Depends(authenticate)])
    async def start(request: Request, body: Create):
        require_live()
        return await call(conversation.create, store(), body, request.state.principal.owner, visible_chats(request))

    @app.get("/api/conversation/{plan_id}", dependencies=[Depends(authenticate)])
    async def plan(request: Request, plan_id: str):
        def build():
            return conversation.view(store(), conversation.visible(conversation.load(store(), plan_id), visible_chats(request)))
        return await call(build)

    @app.put("/api/conversation/{plan_id}", dependencies=[Depends(authenticate)])
    async def edit(request: Request, plan_id: str, body: Edit, revision: int | None = None):
        require_live()
        return await call(conversation.edit, store(), plan_id, body, visible_chats(request), revision)

    @app.delete("/api/conversation/{plan_id}", dependencies=[Depends(authenticate)])
    async def delete(request: Request, plan_id: str, revision: int | None = None):
        require_live()
        return await call(conversation.delete, store(), plan_id, visible_chats(request), revision)

    @app.post("/api/conversation/{plan_id}/goals", dependencies=[Depends(authenticate)])
    async def add_goal(request: Request, plan_id: str, body: Goal, revision: int | None = None):
        require_live()
        return await call(conversation.add_goal, store(), plan_id, body, visible_chats(request), revision)

    @app.put("/api/conversation/{plan_id}/goals/{goal_id}", dependencies=[Depends(authenticate)])
    async def update_goal(request: Request, plan_id: str, goal_id: str, body: Goal, revision: int | None = None):
        require_live()
        return await call(conversation.update_goal, store(), plan_id, goal_id, body, visible_chats(request), revision)

    @app.delete("/api/conversation/{plan_id}/goals/{goal_id}", dependencies=[Depends(authenticate)])
    async def remove_goal(request: Request, plan_id: str, goal_id: str, revision: int | None = None):
        require_live()
        return await call(conversation.remove_goal, store(), plan_id, goal_id, visible_chats(request), revision)

    @app.post("/api/conversation/{plan_id}/steps", dependencies=[Depends(authenticate)])
    async def add_step(request: Request, plan_id: str, body: Step, revision: int | None = None):
        require_live()
        return await call(conversation.add_step, store(), plan_id, body, visible_chats(request), revision)

    @app.put("/api/conversation/{plan_id}/steps/{step_id}", dependencies=[Depends(authenticate)])
    async def update_step(request: Request, plan_id: str, step_id: str, body: Step, revision: int | None = None):
        require_live()
        return await call(conversation.update_step, store(), plan_id, step_id, body, visible_chats(request), revision)

    @app.post("/api/conversation/{plan_id}/steps/{step_id}/move", dependencies=[Depends(authenticate)])
    async def move_step(request: Request, plan_id: str, step_id: str, offset: int, revision: int | None = None):
        require_live()
        if offset not in (-1, 1):
            raise HTTPException(422, "Move a step one place up or down.")
        return await call(conversation.move_step, store(), plan_id, step_id, offset, visible_chats(request), revision)

    @app.delete("/api/conversation/{plan_id}/steps/{step_id}", dependencies=[Depends(authenticate)])
    async def remove_step(request: Request, plan_id: str, step_id: str, revision: int | None = None):
        require_live()
        return await call(conversation.remove_step, store(), plan_id, step_id, visible_chats(request), revision)

    @app.post("/api/conversation/{plan_id}/assist/preview", dependencies=[Depends(authenticate)])
    async def assist_preview(request: Request, plan_id: str, body: Assist):
        require_live()

        def build():
            found = conversation.visible(conversation.load(store(), plan_id), visible_chats(request))
            return assistant.preview(app.state, found, body, request.state.principal.owner)
        return await call(build)

    @app.post("/api/conversation/{plan_id}/assist", dependencies=[Depends(authenticate)])
    async def assist(request: Request, plan_id: str, body: Generate):
        require_live()
        found = await call(lambda: conversation.visible(conversation.load(store(), plan_id), visible_chats(request)))
        try:
            return await assistant.generate(app.state, found, body, request.state.principal.owner)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError:
            raise HTTPException(504, "The AI provider did not answer in time. Try again with less context.") from None
        except ai.netclient.RouteError as exc:
            raise HTTPException(422, str(exc)) from None
        except OSError:
            raise HTTPException(502, "The AI provider could not be reached.") from None
