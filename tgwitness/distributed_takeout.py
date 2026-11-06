"""Private Takeout lifecycle for a public-chat history acquisition."""
import copy

from telethon import errors
from telethon.tl import functions as f, types as t

from .account_export_transport import WrappedClient
from .store import utcnow


class HistoryTakeout:
    def __init__(self, collector, export_id, account_id, megagroup):
        self.collector, self.export_id, self.account_id = collector, export_id, account_id
        self.megagroup = megagroup
        self.name = "distributed-takeout-" + export_id
        self.secret = collector.vault.read(self.name)
        self.client = None

    def save(self):
        self.collector.vault.save(self.name, self.secret)

    def public(self):
        return {"transport": "takeout", "scope": "planned public-chat history; attachments and context use regular requests",
                "generations": copy.deepcopy(self.secret.get("generations", []))}

    def invalidate(self):
        self.secret.pop("takeout_id", None)
        if self.secret.get("generations"):
            self.secret["generations"][-1].update(invalidated_at=utcnow())
        self.save()

    async def open(self):
        client = self.collector.client
        users = await client(f.users.GetUsersRequest([t.InputUserSelf()]))
        if len(users) != 1 or users[0].id != self.account_id:
            raise ValueError("The connected account differs from this export's signed account.")
        if self.secret.get("account_id", self.account_id) != self.account_id:
            raise ValueError("The saved Takeout belongs to another account.")
        takeout = self.secret.get("takeout_id")
        if takeout:
            try:
                await WrappedClient(client, takeout)(f.users.GetUsersRequest([t.InputUserSelf()]))
            except errors.TakeoutInvalidError:
                self.invalidate()
                raise
            self.secret["generations"][-1]["last_reused_at"] = utcnow()
        else:
            result = await client(f.account.InitTakeoutSessionRequest(
                message_megagroups=True if self.megagroup else None,
                message_channels=None if self.megagroup else True))
            self.secret.update(account_id=self.account_id, takeout_id=result.id)
            generations = self.secret.setdefault("generations", [])
            generations.append({"generation": len(generations) + 1, "opened_at": utcnow()})
            self.save()  # Retain the handle even if the next request is interrupted.
        wrapped = WrappedClient(client, self.secret["takeout_id"])
        try:
            ranges = await wrapped(f.messages.GetSplitRangesRequest())
        except errors.TakeoutInvalidError:
            self.invalidate()
            raise
        last = dict(min_id=ranges[-1].min_id, max_id=ranges[-1].max_id) if ranges else None
        if "message_range" in self.secret and last != self.secret["message_range"]:
            raise ValueError("Telegram's Takeout range changed. Preserve this export and start a new one.")
        self.secret["message_range"] = last
        self.secret["generations"][-1]["message_range"] = last
        self.save()
        self.client = WrappedClient(client, self.secret["takeout_id"], last)
        self.collector.store.append("chat_export.started", {"export_id": self.export_id,
            "mode": "distributed_takeout_history", "account_id": self.account_id, **self.public()})
        return self.client

    async def finish(self):
        if not self.secret.get("takeout_id"):
            return
        try:
            await WrappedClient(self.collector.client, self.secret["takeout_id"])(
                f.account.FinishTakeoutSessionRequest(success=True))
        except errors.TakeoutInvalidError:
            self.invalidate()
            return
        self.secret.pop("takeout_id", None)
        self.secret["generations"][-1]["closed_at"] = utcnow()
        self.save()
