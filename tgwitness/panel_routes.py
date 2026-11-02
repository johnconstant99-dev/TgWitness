import re

from starlette.exceptions import HTTPException


DOCUMENTS = (
    "/settings", "/first-run", "/board",
    "/start", "/chats", "/journal", "/sources", "/parameters", "/account", "/accounts",
    "/access", "/system-log", "/integrations", "/exports", "/extras", "/analysis", "/sealed",
    *("/extras/" + card for card in ("alerts", "evidence", "cloud", "bot", "github", "setup", "storage")),
    *("/first-run/" + str(step) for step in range(1, 8)),
)


def register(app, static):
    async def document(request):
        for name, value in request.path_params.items():
            if (not re.fullmatch(r"-?[0-9]{1,19}", value)
                    or not -(2**63) <= int(value) < 2**63
                    or int(value) == 0 or name == "seq" and int(value) < 0):
                raise HTTPException(404)
        return await static.get_response("index.html", request.scope)

    async def group_document(request):
        if not re.fullmatch(r"[a-f0-9]{32}", request.path_params["group_id"]):
            raise HTTPException(404)
        return await static.get_response("index.html", request.scope)

    for path in (*DOCUMENTS, "/chats/{chat_id}", "/journal/event/{seq}"):
        app.add_route(path, document, methods=["GET", "HEAD"], name="panel-document")
    app.add_route("/groups/{group_id}", group_document, methods=["GET", "HEAD"], name="panel-group-document")
