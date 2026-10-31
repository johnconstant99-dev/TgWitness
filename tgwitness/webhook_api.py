from fastapi import Depends, HTTPException, Request

from . import webhooks


def register(app, authenticate, workspace_id):
    @app.get("/api/integrations/webhooks", dependencies=[Depends(authenticate)])
    async def overview():
        data = webhooks.state(app.state.store)
        return {"connections": [webhooks.public(h) for h in app.state.vault.read("webhooks").get("entries", [])],
                "pending": len(data["pending"]), "history": data["history"], "last_error": data["last_error"]}

    @app.post("/api/integrations/webhooks", dependencies=[Depends(authenticate)])
    async def create(body: webhooks.HookSettings):
        try:
            async with webhooks.lock(app.state.store):
                return webhooks.create(app.state.store, app.state.vault, body)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.delete("/api/integrations/webhooks/{hook_id}", dependencies=[Depends(authenticate)])
    async def remove(hook_id: str):
        async with webhooks.lock(app.state.store):
            entries = app.state.vault.read("webhooks").get("entries", [])
            app.state.vault.save("webhooks", {"entries": [h for h in entries if h["id"] != hook_id]})
            data = webhooks.state(app.state.store)
            data["pending"] = [job for job in data["pending"] if job["destination"] != hook_id]
            app.state.store.set_setting("webhook_delivery", data)
        return {"removed": True}

    @app.post("/api/integrations/webhooks/{hook_id}/test", dependencies=[Depends(authenticate)])
    async def test(request: Request, hook_id: str):
        try:
            result = await webhooks.enqueue_test(app.state.store, app.state.vault, workspace_id, hook_id)
            app.state.alert_wakeup.set()
            return result
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
