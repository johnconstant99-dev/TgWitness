from .. import witness_api
from ..app import WitnessTokenCreate
from .access import authenticate_witness
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request


async def witness_state(*, ctx=Depends(current_context)):
    return witness_api.state(ctx.app.state.vault, ctx.app.state.store)


async def witness_token(body: WitnessTokenCreate, *, ctx=Depends(current_context)):
    ctx.require_live()
    if not body.label.strip():
        raise HTTPException(422, "Enter a name for this witness.")
    token, entry = witness_api.create(
        ctx.app.state.vault, ctx.app.state.store, body.label.strip()
    )
    return {
        "token": token,
        "id": entry["id"],
        **witness_api.state(ctx.app.state.vault, ctx.app.state.store),
    }


async def witness_revoke(token_id: str, *, ctx=Depends(current_context)):
    ctx.require_live()
    try:
        witness_api.revoke(ctx.app.state.vault, ctx.app.state.store, token_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from None
    return witness_api.state(ctx.app.state.vault, ctx.app.state.store)


async def witness_head(
    request: Request,
    entry=Depends(authenticate_witness),
    *,
    ctx=Depends(current_context),
):
    return witness_api.head(
        ctx.app.state.store,
        ctx.app.state.vault,
        entry,
        request.headers,
        request.client.host if request.client else None,
        ctx.app.state.collector.status(),
    )
