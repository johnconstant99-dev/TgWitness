"""An operator-owned Telegram bot with an explicit chat AND user allowlist.

No Telegram account session is used. Incoming commands never contain a program,
URL or file path to execute. Message content is not returned by this bot.
"""
import asyncio
import json
import re
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import alerts, netclient
from .store import utcnow


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    chat_id: str = Field(default="", pattern=r"^$|^-?\d{1,20}$")
    user_ids: list[int] = Field(default_factory=list, max_length=20)
    commands: Literal["status", "manage"] = "status"


class OperatorBot:
    def __init__(self, state):
        self.state = state
        self.started = int(time.time())
        self.cooldown = {}

    def public(self):
        return {"settings": Settings.model_validate(self.state.store.get_setting("operator_bot", {})).model_dump(),
                "has_token": bool(self.state.vault.read("operator_bot").get("token")),
                "last": self.state.store.get_setting("operator_bot_last")}

    async def call(self, method, payload, token=None):
        token = token or self.state.vault.read("operator_bot").get("token", "")
        if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,200}", token):
            raise ValueError("Save a valid bot token from BotFather.")
        _, _, data = await netclient.request("POST", "https://api.telegram.org/bot" + token + "/" + method,
            self.state.collector.outside_route(), {"Content-Type": "application/json"}, json.dumps(payload).encode(),
            timeout=35, limit=512 * 1024)
        answer = json.loads(data)
        if not answer.get("ok"):
            raise ValueError("Telegram refused the bot request. Check its token and permissions.")
        return answer.get("result")

    def status_text(self):
        store = self.state.store
        status = self.state.collector.status()
        stats = store.stats()
        head = stats.get("head") or {}
        return ("TgWitness · " + alerts.workspace_name(store) + "\n"
                + "Collection: " + ("running" if status.get("running") else "paused") + "\n"
                + "Connection: " + ("connected" if status.get("connected") else "disconnected") + "\n"
                + "Journal records: " + str(head.get("seq", 0)) + "\n"
                + "Enabled chats: " + str(sum(bool(t["enabled"]) for t in store.targets())) + "\n"
                + "Pending files: " + str(status.get("media_pending", 0)) + "\n"
                + "Checked: " + utcnow())

    async def handle(self, update):
        cfg = self.public()["settings"]
        msg = update.get("message") or {}
        sender, chat = (msg.get("from") or {}).get("id"), (msg.get("chat") or {}).get("id")
        if (not cfg["enabled"] or str(chat) != cfg["chat_id"] or sender not in cfg["user_ids"]
                or msg.get("sender_chat") or msg.get("forward_origin") or msg.get("forward_from")
                or msg.get("forward_date") or msg.get("via_bot") or msg.get("date", 0) < self.started - 30):
            return None
        parsed = re.fullmatch(r"(/(?:start|help|status|stats|pause|resume|copy))(?:@[A-Za-z0-9_]{5,32})?", str(msg.get("text", "")).strip())
        if not parsed:
            return None
        command = parsed[1]
        if time.monotonic() - self.cooldown.get(sender, 0) < 3:
            return None
        self.cooldown[sender] = time.monotonic()
        if command in ("/start", "/help"):
            return "Your TgWitness bot\n/status — current state\n/stats — journal summary\n" + (
                "/pause — stop collection\n/resume — resume collection\n/copy — run a storage copy"
                if cfg["commands"] == "manage" else "Control commands are disabled in the panel.")
        if command == "/status":
            return self.status_text()
        if command == "/stats":
            return "TgWitness · last 24 hours\n" + alerts.summary(self.state.store, {})
        if cfg["commands"] != "manage":
            return "Enable control commands in the panel to use this command."
        if command in ("/pause", "/resume"):
            token = self.state.vault.read("operator_bot").get("token")
            # Use the same operation boundary as the panel. Starting/stopping
            # while a login, route change or another start is in flight can leave
            # the collector's connection and background workers inconsistent.
            async with self.state.operation_lock:
                if self.public()["settings"] != cfg or self.state.vault.read("operator_bot").get("token") != token:
                    return None
                await (self.state.collector.stop() if command == "/pause" else self.state.collector.start())
        else:
            manager = self.state.storage
            if manager.lock.locked() or (manager.task and not manager.task.done()):
                return "A storage task is already running. Use /status or check Storage in the panel."
            if manager.public()["settings"]["enabled"]:
                manager.task = asyncio.create_task(manager.sync())
            elif self.state.store.get_setting("replica", {}).get("enabled"):
                self.state.replica_wakeup.set()
            else:
                return "Enable and test a storage destination in the panel first."
        self.state.store.append("operator_bot.command", {"command": command})
        return ("Storage copy requested. Check the result in Storage.\n" if command == "/copy" else "Done.\n") + self.status_text()

    async def loop(self):
        while True:
            cfg = self.public()["settings"]
            if not cfg["enabled"]:
                await asyncio.sleep(5)
                continue
            try:
                token = self.state.vault.read("operator_bot").get("token", "")
                offset = self.state.store.get_setting("operator_bot_offset", 0)
                updates = await self.call("getUpdates", {"offset": offset, "timeout": 20, "limit": 20,
                                                         "allowed_updates": ["message"]}, token)
                if self.public()["settings"] != cfg or self.state.vault.read("operator_bot").get("token") != token:
                    continue
                for update in updates:
                    # A previous command/reply awaits I/O. Settings or the bot
                    # token may have changed meanwhile: old updates must never
                    # acquire the replacement bot's permissions or cursor.
                    if self.public()["settings"] != cfg or self.state.vault.read("operator_bot").get("token") != token:
                        break
                    # Persist consumption before executing: a crash cannot replay a control command.
                    self.state.store.set_setting("operator_bot_offset", update["update_id"] + 1)
                    answer = await self.handle(update)
                    if answer and self.public()["settings"] == cfg and self.state.vault.read("operator_bot").get("token") == token:
                        await self.call("sendMessage", {"chat_id": cfg["chat_id"], "text": answer[:4000],
                                                       "disable_web_page_preview": True}, token)
                self.state.store.set_setting("operator_bot_last", {"at": utcnow(), "error": None})
            except Exception as exc:
                self.state.store.set_setting("operator_bot_last", {"at": utcnow(), "error": type(exc).__name__})
                await asyncio.sleep(15)
