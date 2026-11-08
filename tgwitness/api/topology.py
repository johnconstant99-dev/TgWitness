from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..topology import snapshot
from .dependencies import current_context


async def topology(request: Request, *, ctx=Depends(current_context)):
    if not request.state.principal.admin:
        raise HTTPException(403, "Only the main administrator can view the network topology.")
    try:
        after = max(0, int(request.query_params.get("after", "0")))
    except ValueError:
        after = 0
    return JSONResponse(snapshot(ctx, request, after), headers={"Cache-Control": "no-store"})
