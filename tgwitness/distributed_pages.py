"""Bounded, signed checkpoints of decoded history, independent of RPC page boundaries."""
import hashlib
import os
import shutil

from telethon import utils

from .account_export import durable_write, linked, read_json, sync_directory
from .collector import message_record, unparsed_record
from .store import canonical, utcnow
from .verify import verify_distributed_pages
from .workers import complete_in_thread

FORMAT = "tgwitness-distributed-pages-v1"
PAGE_MESSAGES = 100
PAGE_BYTES = 4 * 1024**2


class RangePages:
    def __init__(self, directory, job, task):
        self.directory, self.job, self.task = directory, job, task
        self.root = directory / "pages" / str(task["low"])
        self.path = directory / "chunks" / (str(task["low"]) + ".jsonl")
        self.state = self.verify()

    def envelopes(self):
        if linked(self.root) or linked(self.root.parent):
            raise ValueError("Checkpoint directories must not be links.")
        paths = sorted(self.root.glob("*.json"), key=lambda p: int(p.stem) if p.stem.isdigit() else -1)
        for seq, path in enumerate(paths, 1):
            if path.name != str(seq) + ".json":
                raise ValueError("Checkpoint receipt sequence is incomplete.")
            yield read_json(path)

    def verify(self):
        if linked(self.path):
            raise ValueError("Checkpoint data must not be a link.")
        # Data without a receipt is an uncommitted tail, never reusable progress.
        with self.path.open("rb") if self.path.exists() else open(os.devnull, "rb") as stream:
            return verify_distributed_pages(stream, self.envelopes(), self.job, self.task)

    def commit(self, data, count, cursor, terminal, profile, vault, generation, captured_from):
        if linked(self.root) or linked(self.root.parent) or linked(self.path):
            raise ValueError("Checkpoint paths must not be links.")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        sync_directory(self.root.parent)
        before = self.state
        seq = before["pages"] + 1
        receipt_path = self.root / (str(seq) + ".json")
        if receipt_path.exists():
            raise ValueError("Refusing to overwrite a committed checkpoint.")
        # Trim only bytes beyond the verified prefix. Never rewrite a committed page.
        with self.path.open("r+b" if self.path.exists() else "w+b") as stream:
            stream.seek(before["byte_end"])
            stream.truncate()
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(self.path.parent)
        worker = next(w for w in self.job["workers"] if w["profile_id"] == profile)
        value = {"format": FORMAT, "job_id": self.job["id"], "plan_sha256": hashlib.sha256(canonical(self.job)).hexdigest(),
                 "chat_id": self.job["chat_id"], "low": self.task["low"], "high": self.task["high"],
                 "profile_id": profile, "account_id": worker["account_id"], "seq": seq,
                 "previous_receipt_sha256": before["head_sha256"], "cursor_before": before["cursor"],
                 "cursor_after": cursor, "byte_start": before["byte_end"], "byte_end": before["byte_end"] + len(data),
                 "count": count, "sha256": hashlib.sha256(data).hexdigest(), "terminal": terminal,
                 "captured_from": captured_from, "captured_until": utcnow(),
                 "transport": self.job.get("transport", "regular"), "transport_generation": generation}
        envelope = {"statement": value, "public_key": vault.public_key, "signature": vault.sign(canonical(value))}
        encoded = canonical(envelope)
        durable_write(receipt_path, encoded)
        self.state = {"pages": seq, "count": before["count"] + count, "cursor": cursor,
                      "byte_end": value["byte_end"], "head_sha256": hashlib.sha256(encoded).hexdigest(),
                      "terminal": terminal, "profile_id": profile, "transport_generation": generation}

    async def fetch(self, collector, entity, profile, on_commit, on_wait, transport=None,
                    page_timeout=None, attempts=8):
        if self.state["profile_id"] not in (None, profile):
            raise ValueError("An interrupted range must resume with its original observer.")
        if self.state["terminal"]:
            if self.path.stat().st_size != self.state["byte_end"]:
                def trim():
                    with self.path.open("r+b") as stream:
                        stream.truncate(self.state["byte_end"])
                        stream.flush()
                        os.fsync(stream.fileno())
                await complete_in_thread(trim)
            return
        generation = transport.secret["generations"][-1]["generation"] if transport else None
        pending, size, cursor, captured_from = [], 0, self.state["cursor"], utcnow()

        async def flush(terminal):
            nonlocal pending, size, captured_from
            if shutil.disk_usage(self.directory).free < collector.param("media_min_free_mb") * 1024**2 + size:
                raise ValueError("Insufficient free disk space for another checkpoint.")
            previous = self.state["pages"]
            try:
                await complete_in_thread(self.commit, b"".join(pending), len(pending), cursor, terminal,
                                         profile, collector.vault, generation, captured_from)
            finally:
                # complete_in_thread drains writes even when pause cancels the caller.
                if self.state["pages"] != previous:
                    on_commit(self.state)
            pending, size, captured_from = [], 0, utcnow()

        async def append(record):
            nonlocal size, cursor
            mid = record["id"]
            if type(mid) is not int or not self.task["low"] <= mid < cursor:
                raise ValueError("Checkpoint messages are outside their range or repeated.")
            encoded = canonical(record) + b"\n"
            if len(encoded) > 64 * 1024**2:
                raise ValueError("Checkpoint message exceeds the supported record size.")
            if pending and size + len(encoded) > PAGE_BYTES:
                await flush(False)
            pending.append(encoded)
            size, cursor = size + len(encoded), mid
            if len(pending) >= PAGE_MESSAGES:
                await flush(False)

        async def write(message):
            if utils.get_peer_id(message.peer_id) != utils.get_peer_id(entity):
                raise ValueError("History returned a message from a different source.")
            collector.remember(getattr(message, "sender", None))
            await append(message_record(message))

        async def unparsed(number, error):
            await append(unparsed_record(number, error))

        await collector.iterate_history(entity, write, min_id=self.task["low"] - 1,
            offset_id=self.state["cursor"], on_wait=on_wait, history_client=transport.client if transport else None,
            page_timeout=page_timeout, attempts=attempts, on_unparsed=unparsed)
        await flush(True)  # Iterator exhaustion, even after an exactly full checkpoint.
