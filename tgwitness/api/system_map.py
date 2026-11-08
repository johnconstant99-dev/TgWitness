from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..system_map import snapshot
from .dependencies import current_context


async def system_map(request: Request, *, ctx=Depends(current_context)):
    if not request.state.principal.admin:
        raise HTTPException(403, "Only the main administrator can view the system map.")
    return JSONResponse(snapshot(ctx, request), headers={"Cache-Control": "no-store"})
