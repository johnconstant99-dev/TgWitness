import asyncio

from fastapi import Depends, HTTPException, Request

from . import ai, translation
from .translation import Generate, Request as TranslationRequest


def register(app, authenticate, require_live, visible_chats):
    translator = translation.Translator()

    def allowed(request, chat_id):
        chats = visible_chats(request)
        if chats is not None and chat_id not in chats:
            raise HTTPException(403, "This chat is not open to this access.")
        return chats

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/translations", dependencies=[Depends(authenticate)])
    async def translations(request: Request, chat_id: int, target: str | None = None):
        allowed(request, chat_id)
        found = await call(translation.latest, app.state.store, chat_id, target)
        return {"items": {str(seq): item for seq, item in found.items()}, "ai": ai.enabled(app.state)}

    @app.get("/api/translations/languages", dependencies=[Depends(authenticate)])
    async def languages(request: Request, chat_id: int, target: str = "en"):
        allowed(request, chat_id)
        if translation.language_name(target.lower()) is None:
            raise HTTPException(422, "Choose a supported two-letter target language.")
        return await call(translation.languages, app.state.store, chat_id, 500, target.lower())

    @app.post("/api/translations/preview", dependencies=[Depends(authenticate)])
    async def preview(request: Request, body: TranslationRequest):
        from .operator_privacy import connection_details, hide_addresses

        require_live()
        chats = allowed(request, body.chat_id)
        result = await call(translator.preview, app.state, body, request.state.principal.owner)
        if not connection_details(request.state.principal, chats):
            provider = result["provider"]
            result["provider"] = {**provider, "route_host": "", "route_port": None,
                                  "route_error": hide_addresses(provider.get("route_error") or "")}
        return result

    @app.post("/api/translations", dependencies=[Depends(authenticate)])
    async def generate(request: Request, body: Generate):
        require_live()
        try:
            return await translator.generate(app.state, body, request.state.principal.owner, visible_chats(request))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except TimeoutError:
            raise HTTPException(504, "The AI provider did not answer in time. Translate fewer messages.") from None
        except ai.netclient.RouteError as exc:
            raise HTTPException(422, str(exc)) from None
        except OSError:
            raise HTTPException(502, "The AI provider could not be reached.") from None
