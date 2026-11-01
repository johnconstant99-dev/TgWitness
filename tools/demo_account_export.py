"""Generate a labelled, offline account/disclosure sample in a fresh demo directory."""
import asyncio
from pathlib import Path

from tgwitness.account_export import AccountExport
from tgwitness.demo import seed_demo
from tgwitness.disclosure import Disclosures
from tgwitness.security import Vault
from tgwitness.store import Store


class SyntheticCollector:
    export_claim = None

    def reserve_export(self, owner):
        if self.export_claim:
            return False
        self.export_claim = owner
        return True

    def release_export(self, owner):
        if self.export_claim == owner:
            self.export_claim = None

    async def restore(self):
        raise RuntimeError("Synthetic account samples never connect to Telegram")


class SyntheticTransport:
    account_id = 70000

    def __init__(self, collector, vault, job_id, options):
        self.store = collector.store

    async def open(self):
        if not self.store.get_setting("demo", False):
            raise ValueError("Synthetic transport requires a fictional demo")

    async def discover(self):
        chats, tasks = [], []
        for target in self.store.targets():
            cid = target["chat_id"]
            events = self.store.events(chat_id=cid, kind="message.new", limit=100)
            highest = max(event["message_id"] for event in events)
            chats.append({"id": cid, "title": target["title"], "kind": target["kind"],
                          "archived": False, "left": False, "ranges": [0], "selected": True})
            tasks.append({"id": f"messages:{cid}:0", "category": "messages", "chat_id": cid,
                          "newest_message_id": highest, "cursor_start": highest+1, "own_only": False,
                          "telegram_range": None})
        return chats, tasks, ["SYNTHETIC DEMONSTRATION: fictional messages, no Telegram connection or acquisition."]

    async def page(self, task, cursor):
        rows = []
        events = self.store.events(chat_id=task["chat_id"], kind="message.new", limit=100)
        for event in sorted(events, key=lambda event: event["message_id"], reverse=True):
            if event["message_id"] >= cursor:
                continue
            payload = event["payload"]
            assert payload.get("synthetic") is True
            sender = payload["sender_id"]
            rows.append(({"category": "messages", "id": event["message_id"], "chat_id": task["chat_id"],
                          "from_id": sender, "outgoing": False, "date": payload["sent_at"],
                          "text": payload["text"], "synthetic": True,
                          "sender": {"id": sender, "first_name": f"Fictional participant {sender-70000}"}}, None))
        return rows, min((row["id"] for row, _ in rows), default=cursor), True

    async def finish(self, success):
        pass


def build_demo_account_exports(directory):
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("Account demo generation requires a new empty directory")
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    try:
        seed_demo(store)
        store.set_setting("account", {"id": SyntheticTransport.account_id})
        collector = SyntheticCollector()
        collector.store = store
        exports = AccountExport(collector, store, vault)
        exports.transport_factory = SyntheticTransport
        async def build():
            job = await exports.start({"transport": "regular", "purpose": "SYNTHETIC DEMO — no Telegram connection",
                                       "include_profile": False, "include_contacts": False, "media_types": []})
            await asyncio.wait_for(asyncio.shield(exports.task), 15)
            assert exports.public(job["id"])["ready"], exports.public(job["id"])
            disclosures = Disclosures(exports, vault)
            preview = disclosures.preview(job["id"], {"purpose": "SYNTHETIC DEMO — selected messages for review",
                "sender_ids": [70001], "identity_mode": "pseudonymize_all", "include_media": False}, "demo-builder")
            result = await disclosures.create(job["id"], preview["preview_id"], "demo-builder")
            await disclosures.close()
            await exports.close()
            return job["id"], result["id"]
        return asyncio.run(build())
    finally:
        store.set_setting("account", None)
        store.close()
