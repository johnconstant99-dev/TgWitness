import asyncio
import configparser
import json
from string import ascii_letters, digits

from fastapi import Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import netclient, operator_bot, services, storage
from .workers import complete_in_thread


class Update(storage.Settings):
    rclone_config: str = Field(default="", max_length=65536)
    confirm_offload: bool = False


class BotUpdate(operator_bot.Settings):
    token: str = Field(default="", max_length=250)


class RecoveryImport(BaseModel):
    recovery: dict


def register(app, authenticate, require_live):
    async def admin(request: Request, who=Depends(authenticate)):
        if not who.admin:
            raise HTTPException(403, "Only the main administrator can manage storage or the operator bot.")

    async def action(fn):
        try:
            return await fn()
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        except netclient.RouteError:
            raise HTTPException(422, "The external route is unavailable. Check Connection settings before retrying.") from None
        except (OSError, TimeoutError):
            raise HTTPException(502, "The operation could not finish. Local files are kept; check the service and retry.") from None

    def idle():
        require_live()
        if app.state.storage.lock.locked() or (getattr(app.state.storage, "task", None) and not app.state.storage.task.done()):
            raise HTTPException(409, "Wait for the current storage operation to finish.")

    @app.get("/api/services/notifications", dependencies=[Depends(authenticate)])
    async def notification_catalog():
        return services.notifications()

    @app.get("/api/storage", dependencies=[Depends(admin)])
    async def get_storage():
        return app.state.storage.public()

    @app.post("/api/storage", dependencies=[Depends(admin)])
    async def set_storage(body: Update):
        idle()
        async with app.state.storage.lock:
            return await save_storage(body)

    async def save_storage(body):
        manager, store, vault = app.state.storage, app.state.store, app.state.vault
        saved = body.model_dump(exclude={"rclone_config", "confirm_offload"})
        if saved["purpose"] == "offload" and not body.confirm_offload:
            raise HTTPException(422, "Confirm that local files may be removed after a verified remote copy.")
        secret = dict(vault.read("storage"))
        config_replaced = False
        try:
            if body.rclone_config:
                storage.parse_config(body.rclone_config)
                before, after = configparser.ConfigParser(interpolation=None), configparser.ConfigParser(interpolation=None)
                before.read_string(secret.get("config", ""))
                after.read_string(body.rclone_config)
                config_replaced = dict(before) != dict(after)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        if body.rclone_config:
            secret["config"] = body.rclone_config
        try:
            if saved["enabled"] and saved["backend"] == "rclone":
                storage.Rclone(store.root, secret.get("config", ""), saved["remote_path"], app.state.collector.outside_route())
            if saved["enabled"] and saved["backend"] == "s3":
                storage.S3Backend(store, vault, app.state.collector.outside_route())
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        try:
            destination = manager.destination(saved, secret.get("config", ""))
            obsolete = await complete_in_thread(manager.obsolete_copies, destination, config_replaced)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        manager.discard_copies(obsolete)
        vault.save("storage", secret)
        try:
            manager.key()
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        store.set_setting("storage", saved)
        store.append("storage.settings", saved)
        return manager.public()

    @app.post("/api/storage/install", dependencies=[Depends(admin)])
    async def install_helper():
        idle()
        if app.state.collector.outside_route().kind != "direct":
            raise HTTPException(422, "Select Direct for external requests before downloading the rclone helper.")
        await action(lambda: asyncio.to_thread(storage.install, app.state.store.root))
        return app.state.storage.public()

    @app.post("/api/storage/test", dependencies=[Depends(admin)])
    async def test():
        idle()
        return await action(app.state.storage.test)

    @app.post("/api/storage/copy", dependencies=[Depends(admin)])
    async def copy():
        idle()
        app.state.storage.task = asyncio.create_task(app.state.storage.sync())
        return {"started": True}

    @app.post("/api/storage/restore", dependencies=[Depends(admin)])
    async def restore():
        idle()
        async def run():
            try:
                await app.state.storage.restore_all()
            except Exception as exc:
                app.state.store.set_setting("storage_last", {"error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__})
        app.state.storage.task = asyncio.create_task(run())
        return {"started": True}

    @app.get("/api/storage/recovery", dependencies=[Depends(admin)])
    async def recovery():
        return Response(json.dumps(app.state.storage.recovery(), indent=2), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="tgwitness-storage-recovery.json"',
                                 "Cache-Control": "no-store"})

    @app.post("/api/storage/recovery", dependencies=[Depends(admin)])
    async def import_recovery(body: RecoveryImport):
        idle()
        try:
            async with app.state.storage.lock:
                return await complete_in_thread(app.state.storage.import_recovery, body.recovery)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/operator-bot", dependencies=[Depends(admin)])
    async def get_bot():
        return app.state.operator_bot.public()

    @app.post("/api/operator-bot", dependencies=[Depends(admin)])
    async def set_bot(body: BotUpdate):
        require_live()
        vault, store = app.state.vault, app.state.store
        secret = dict(vault.read("operator_bot"))
        if body.token:
            bot_id, separator, key = body.token.partition(":")
            if (not separator or not 1 <= len(bot_id) <= 20 or not 20 <= len(key) <= 200
                    or any(char not in digits for char in bot_id)
                    or any(char not in ascii_letters + digits + "_-" for char in key)):
                raise HTTPException(422, "Paste the bot token from BotFather.")
            secret["token"] = body.token
        if body.enabled and (not secret.get("token") or not body.chat_id or not body.user_ids or any(n <= 0 for n in body.user_ids)):
            raise HTTPException(422, "Set the bot token, destination chat and allowed Telegram user IDs.")
        if body.token and body.token != vault.read("operator_bot").get("token"):
            store.set_setting("operator_bot_offset", 0)
        vault.save("operator_bot", secret)
        store.set_setting("operator_bot", body.model_dump(exclude={"token"}))
        store.append("operator_bot.settings", {"enabled": body.enabled, "commands": body.commands, "allowed_users": len(body.user_ids)})
        return app.state.operator_bot.public()

    @app.post("/api/operator-bot/test", dependencies=[Depends(admin)])
    async def bot_test():
        require_live()
        cfg = app.state.operator_bot.public()["settings"]
        await action(lambda: app.state.operator_bot.call("sendMessage", {"chat_id": cfg["chat_id"],
                           "text": app.state.operator_bot.status_text(), "disable_web_page_preview": True}))
        return {"ok": True}
