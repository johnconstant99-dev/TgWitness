from .. import __version__
from .. import cloud_wizard
from .dependencies import current_context
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import Response
import asyncio


async def cloud_status(request: Request, *, ctx=Depends(current_context)):
    return {
        **ctx.cloud_jobs.status(),
        "local": ctx.direct_local(request),
        "version": __version__,
    }


async def cloud_check(
    request: Request, body: cloud_wizard.Check, *, ctx=Depends(current_context)
):
    ctx.require_cloud(request)
    try:
        return await asyncio.to_thread(ctx.cloud_jobs.check, body)
    except cloud_wizard.WizardError as exc:
        return ctx.cloud_error(exc)


async def cloud_deploy(
    request: Request, body: cloud_wizard.Deploy, *, ctx=Depends(current_context)
):
    ctx.require_cloud(request)
    try:
        return ctx.cloud_jobs.deploy(body)
    except cloud_wizard.WizardError as exc:
        return ctx.cloud_error(exc)


async def cloud_destroy(
    request: Request, body: cloud_wizard.Destroy, *, ctx=Depends(current_context)
):
    ctx.require_cloud(request)
    try:
        return ctx.cloud_jobs.destroy(body)
    except cloud_wizard.WizardError as exc:
        return ctx.cloud_error(exc)


async def cloud_address(
    request: Request, body: cloud_wizard.Address, *, ctx=Depends(current_context)
):
    ctx.require_cloud(request)
    try:
        return await asyncio.to_thread(ctx.cloud_jobs.address, body.name)
    except cloud_wizard.WizardError as exc:
        return ctx.cloud_error(exc)


async def cloud_file(
    request: Request, name: str, filename: str, *, ctx=Depends(current_context)
):
    ctx.require_cloud(request)
    try:
        path, media = ctx.cloud_jobs.file(name, filename)
    except cloud_wizard.WizardError as exc:
        raise HTTPException(404, str(exc)) from None
    return Response(
        path.read_bytes(),
        media_type=media,
        headers={
            "Content-Disposition": 'attachment; filename="'
            + name
            + "-"
            + filename
            + '"'
        },
    )


class CloudOperations:
    def require_cloud(self, request):
        self.require_live()
        if not self.direct_local(request):
            raise HTTPException(
                403,
                "Servers are started from TgWitness on your own computer. Open the panel there at 127.0.0.1; cloud tokens are never sent to a panel over the network.",
            )

    def cloud_error(self, exc):
        return {"error": {"message": str(exc), "technical": exc.technical}}
