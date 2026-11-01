"""Document URLs for the panel; API requests keep their own access checks."""

import re

from starlette.exceptions import HTTPException


DOCUMENTS = (
    "/start", "/chats", "/journal", "/sources", "/parameters", "/account", "/accounts",
    "/access", "/system-log", "/integrations", "/exports", "/extras", "/analysis", "/sealed",
    *("/extras/" + card for card in ("alerts", "evidence", "cloud", "bot", "github")),
)


def register(app, static):
    async def document(request):
        for name, value in request.path_params.items():
            if (not re.fullmatch(r"-?[0-9]{1,19}", value)
                    or not -(2**63) <= int(value) < 2**63
                    or int(value) == 0 or name == "seq" and int(value) < 0):
                raise HTTPException(404)
        return await static.get_response("index.html", request.scope)

    for path in (*DOCUMENTS, "/chats/{chat_id}", "/journal/event/{seq}"):
        app.add_route(path, document, methods=["GET", "HEAD"], name="panel-document")
