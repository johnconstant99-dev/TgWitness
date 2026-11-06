import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telethon.tl import types

from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store

DATE = datetime(2026, 11, 5, tzinfo=timezone.utc)


def message(mid, photo=False):
    media = types.MessageMediaPhoto(photo=types.Photo(
        id=mid, access_hash=1, file_reference=b"r", date=DATE, dc_id=2,
        sizes=[types.PhotoSize(type="x", w=10, h=10, size=1000)])) if photo else None
    return types.Message(id=mid, peer_id=types.PeerUser(7), date=DATE, message="text " + str(mid), media=media)


class Client:
    def __init__(self, rows):
        self.rows, self.order = rows, []

    def iter_messages(self, entity, offset_id=0, min_id=0, **options):
        async def pages():
            for row in sorted(self.rows, key=lambda m: -m.id):
                self.order.append(("message", row.id))
                yield row
        return pages()

    async def get_messages(self, entity, ids=None, **options):
        self.order.append(("files", tuple(ids)))
        return [next((r for r in self.rows if r.id == i), None) for i in ids]


async def check(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        collector = Collector(store, vault)
        rows = [message(1), message(2, photo=True), message(3), message(4, photo=True)]
        collector.client = Client(rows)

        async def hashes(item, **options):
            return {"status": "complete", "parts": [], "size": 1000}
        collector.attachment_hashes = hashes
        entity = types.User(id=7)
        for files, status in (("hashes", "hashes_only"), ("skip", "skipped_by_export_option")):
            collector.client.order.clear()
            scratch, record = root / (files + ".jsonl"), {}
            media = root / (files + "-media")
            media.mkdir()
            assert await collector.stream_history(entity, scratch, record, media, files) == 4
            order = collector.client.order
            assert all(kind == "message" for kind, _ in order[:4]), "Messages are read before any file"
            assert (order[4:] == [("files", (4, 2))]) if files == "hashes" else not order[4:], order
            entries = {e["id"]: e for e in map(json.loads, scratch.read_text(encoding="utf-8").splitlines())}
            assert entries[2]["file_status"] == entries[4]["file_status"] == status, entries
            assert "file_status" not in entries[1] and record.get("stage") is None
            assert record.get("files_total") == 2
    finally:
        store.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="export-files-") as temporary:
        asyncio.run(check(Path(temporary)))
    print("Chat exports read every message first, then files in their own stage: download, fingerprints or none.")
