from .. import secret_chats as secret
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from pydantic import BaseModel
from pydantic import Field


class SecretChatSettings(BaseModel):
    enabled: bool
    accept_incoming: bool = False


class SecretChatCreate(BaseModel):
    user: str = Field(min_length=1, max_length=64, pattern=r"^(@?[A-Za-z][A-Za-z0-9_]{3,31}|[0-9]{1,20})$")


class SecretChatText(BaseModel):
    text: str = Field(min_length=1, max_length=4096)


def chats_of(ctx):
    return secret.of(ctx.app.state.collector)


async def connected(ctx, call, *args, **kwargs):
    collector = ctx.app.state.collector
    if not secret.available():
        raise HTTPException(400, secret.UNAVAILABLE)
    if chats_of(ctx).manager is None:
        await collector.restore()
    return await call(*args, **kwargs)


async def view(*, ctx=Depends(current_context)):
    return chats_of(ctx).view()


async def update_settings(body: SecretChatSettings, *, ctx=Depends(current_context)):
    ctx.require_live()
    if body.enabled and not secret.available():
        raise HTTPException(400, secret.UNAVAILABLE)
    store, collector = ctx.app.state.store, ctx.app.state.collector
    with store.transaction():
        store.set_setting(secret.SETTING, body.model_dump())
        store.append("secret_chat.settings", body.model_dump())
    if body.enabled:
        await ctx.operation(collector.restore)
    else:
        await chats_of(ctx).detach()
        collector.close_when_idle()
    return chats_of(ctx).view()


async def create(body: SecretChatCreate, *, ctx=Depends(current_context)):
    ctx.require_live()
    user = int(body.user) if body.user.isdigit() else body.user.removeprefix("@")
    return await ctx.operation(connected, ctx, chats_of(ctx).create, user)


async def accept(chat_id: int, *, ctx=Depends(current_context)):
    ctx.require_live()
    return await ctx.operation(connected, ctx, chats_of(ctx).accept, chat_id)


async def send(chat_id: int, body: SecretChatText, *, ctx=Depends(current_context)):
    ctx.require_live()
    return {"random_id": await ctx.operation(connected, ctx, chats_of(ctx).send, chat_id, body.text)}


async def close(chat_id: int, *, ctx=Depends(current_context)):
    ctx.require_live()
    await ctx.operation(connected, ctx, chats_of(ctx).close, chat_id)
    return chats_of(ctx).view()
