import json

from telethon.tl import functions as f

from .account_export_transport import Transport, WrappedClient
from .monitoring import capture_settings
from .scope import kind_of


class HistoryTransport:
    def __init__(self, history, run):
        self.history, self.collector, self.run = history, history.collector, run
        self.store, self.vault = history.store, history.collector.vault
        self.transport = None
        self.ranges = [None]
        self.source_ranges = {}

    def saved(self, kind):
        with self.store.lock:
            row = self.store.db.execute("SELECT payload FROM events WHERE kind=? "
                "AND json_extract(payload,'$.history_run_id')=? ORDER BY seq DESC LIMIT 1",
                (kind, self.run["id"])).fetchone()
        return json.loads(row[0]) if row else None

    async def open(self):
        async def network(call):
            return await self.history.network(call, self.run["id"])
        me = await network(self.collector.client.get_me)
        if me.id != self.run["account_id"]:
            raise ValueError("The connected account differs from the signed history plan.")
        plan = self.saved("history.takeout.plan")
        if plan is None:
            kinds = set()
            with self.store.lock:
                ids = [r[0] for r in self.store.db.execute(
                    "SELECT chat_id FROM history_sources WHERE run_id=?", (self.run["id"],))]
            for cid in ids:
                kind = kind_of(await network(lambda: self.collector.resolve_target(cid)))
                if not kind:
                    raise ValueError("Cannot identify the selected source's Takeout scope.")
                kinds.add(kind)
            capture = capture_settings(self.store)
            options = dict(transport="takeout", chat_kinds=sorted(kinds),
                include_contacts=False, include_profile_photos=False, include_stories=False,
                include_other_data=False, media_types=[k for k, rule in capture["types"].items()
                    if capture["download_media"] and rule["enabled"]],
                max_media_file_mib=max(r["max_mb"] for r in capture["types"].values()),
                media_action=capture["media_action"], media_rules=capture["types"],
                oversized_media=capture["oversized_media"])
            plan = {"history_run_id": self.run["id"], "options": options}
            self.store.append("history.takeout.plan", plan)
        self.transport = Transport(self.collector, self.vault, "history-" + self.run["id"], plan["options"])
        await network(self.transport.open)
        ranges = [dict(min_id=r.min_id, max_id=r.max_id)
                  for r in await network(lambda: self.transport.client(f.messages.GetSplitRangesRequest()))] or [None]
        previous = self.saved("history.takeout.ranges")
        if previous and previous["ranges"] != ranges:
            raise ValueError("Takeout ranges changed. End this run and start a new acquisition.")
        if previous is None:
            with self.store.lock:
                ids = [r[0] for r in self.store.db.execute(
                    "SELECT chat_id FROM history_sources WHERE run_id=?", (self.run["id"],))]
            source_ranges = {str(cid): [] for cid in ids}
            for index, split in enumerate(ranges):
                client = self.transport.ranged({"telegram_range": split})
                dialogs = client.iter_dialogs(limit=None, folder=None, ignore_migrated=False).__aiter__()
                while True:
                    try:
                        dialog = await network(lambda: anext(dialogs))
                    except StopAsyncIteration:
                        break
                    indices = source_ranges.get(str(dialog.id))
                    if indices is not None and index not in indices:
                        indices.append(index)
            previous = {"history_run_id": self.run["id"], "ranges": ranges, "source_ranges": source_ranges}
            self.store.append("history.takeout.ranges", previous)
        self.ranges = ranges
        self.source_ranges = previous["source_ranges"]

    def indices(self, chat_id):
        return self.source_ranges.get(str(chat_id), [])

    def client(self, index):
        return self.transport.ranged({"telegram_range": self.ranges[index]})

    def for_media(self, event):
        acquisition = event["payload"].get("acquisition", {})
        if acquisition.get("source_mode") != "takeout":
            return self.collector.client
        split = acquisition.get("telegram_range")
        if split not in self.ranges:
            raise ValueError("Attachment range differs from the signed Takeout inventory.")
        return self.transport.ranged({"telegram_range": split})

    def invalidate(self):
        if self.transport:
            self.transport.invalidate()

    async def finish(self, success):
        if self.transport is None:
            self.transport = Transport(self.collector, self.vault, "history-" + self.run["id"], {})
            if self.transport.secret.get("takeout_id"):
                me = await self.collector.client.get_me()
                if me.id != self.run["account_id"]:
                    raise ValueError("Cannot finish Takeout with a different account.")
                self.transport.client = WrappedClient(self.collector.client, self.transport.secret["takeout_id"])
        await self.transport.finish(success)
