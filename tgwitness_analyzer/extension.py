import asyncio

from fastapi import Depends, HTTPException, Query, Request, Response

from . import NAME, VERSION, graphs, insights, linking

WITNESS_ONLY = "The analyzer is off while this workspace is set up as a witness."
MAX_CHATS = 50
LOWEST, HIGHEST = -(2**63), 2**63 - 1
SVG_POLICY = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def register(context):
    app = context.app
    for route in ("insights", "graph", "graph.svg", "graph.gexf", "linking"):
        context.allow("GET /api/analyzer/" + route, "view", "body")

    def chosen(request, chat_ids):
        if context.goal() == "evidence":
            raise HTTPException(409, WITNESS_ONLY)
        chats = set(chat_ids)
        if not chats or len(chats) > MAX_CHATS or any(not LOWEST <= chat <= HIGHEST for chat in chats):
            raise HTTPException(422, "Choose between 1 and " + str(MAX_CHATS) + " chats.")
        for chat in sorted(chats):
            context.require_chat(request, chat)
        return chats

    def parts(kinds):
        found = tuple(dict.fromkeys(value.strip() for value in kinds.split(",") if value.strip()))
        if not found or any(value not in graphs.KINDS for value in found):
            raise HTTPException(422, "Use kinds from: " + ", ".join(graphs.KINDS) + ".")
        return found

    def title(chats):
        names = [row.get("title") for row in context.reader.targets() if row.get("chat_id") in chats and row.get("title")]
        if len(chats) == 1 and names:
            return "Connections · " + names[0]
        return "Connections in " + str(len(chats)) + " chats"

    async def model(request, chat_ids, kinds):
        chats, wanted = chosen(request, chat_ids), parts(kinds)
        value = await asyncio.to_thread(graphs.collect, context.reader, chats, wanted)
        await context.recheck(request, chats)
        return chats, value

    @app.get("/api/analyzer/insights", dependencies=[Depends(context.authenticate)])
    async def chat_insights(request: Request, chat_id: int = Query(ge=LOWEST, le=HIGHEST),
                            offset_minutes: int = Query(0, ge=-720, le=840)):
        if context.goal() == "evidence":
            raise HTTPException(409, WITNESS_ONLY)
        context.require_chat(request, chat_id)
        value = await asyncio.to_thread(insights.collect, context.reader, chat_id, offset_minutes)
        await context.recheck(request, {chat_id})
        return value

    @app.get("/api/analyzer/graph", dependencies=[Depends(context.authenticate)])
    async def connection_graph(request: Request, chat_id: list[int] = Query(), kinds: str = Query(",".join(graphs.KINDS))):
        return (await model(request, chat_id, kinds))[1]

    @app.get("/api/analyzer/graph.svg", dependencies=[Depends(context.authenticate)])
    async def connection_picture(request: Request, chat_id: list[int] = Query(),
                                 kinds: str = Query(",".join(graphs.KINDS))):
        chats, value = await model(request, chat_id, kinds)
        picture = await asyncio.to_thread(graphs.svg, value, title(chats))
        return Response(picture, media_type="image/svg+xml",
                        headers={"Content-Security-Policy": SVG_POLICY, "X-Content-Type-Options": "nosniff",
                                 "Cache-Control": "no-store"})

    @app.get("/api/analyzer/graph.gexf", dependencies=[Depends(context.authenticate)])
    async def connection_export(request: Request, chat_id: list[int] = Query(),
                                kinds: str = Query(",".join(graphs.KINDS))):
        chats, value = await model(request, chat_id, kinds)
        return Response(graphs.gexf(value, title(chats)), media_type="application/gexf+xml",
                        headers={"Content-Disposition": 'attachment; filename="tgwitness-graph.gexf"',
                                 "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.get("/api/analyzer/linking", dependencies=[Depends(context.authenticate)])
    async def account_linking(request: Request, chat_id: list[int] = Query(),
                              min_messages: int = Query(linking.MIN_MESSAGES, ge=5, le=10000),
                              min_z: float = Query(linking.MIN_Z, ge=0, le=10),
                              limit: int = Query(50, ge=1, le=linking.MAX_PAIRS),
                              offset_minutes: int = Query(0, ge=-720, le=840)):
        chats = chosen(request, chat_id)
        value = await asyncio.to_thread(linking.candidates, context.reader, chats, min_messages, min_z, limit,
                                        offset_minutes)
        await context.recheck(request, chats)
        return value

    return {"id": "analyzer", "name": NAME, "version": VERSION,
            "features": ["chat_insights", "graphs", "graph_svg", "graph_gexf", "account_linking"]}
