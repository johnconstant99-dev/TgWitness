import asyncio
import base64
import bisect
import json

from telethon import errors
from telethon.extensions import BinaryReader

from .store import ZERO, canonical, utcnow


class ObservedPage(list):
    def __init__(self, rows, seen_count, started):
        super().__init__(rows)
        self.seen_count, self.started = seen_count, started


class StagedTransport:
    def __init__(self, network, export, job):
        self.network, self.export, self.job = network, export, job
        self.root = export.directory(job["job_id"])
        self.pages, self.progress, self.lookup, self.head, self.messages, self.bytes = [], {}, {}, ZERO, 0, 0
        self.tasks = {task["id"]: task for task in export.inventory["tasks"]}
        self.intervals = {task: ([], []) for task in self.tasks}

    def __getattr__(self, name):
        return getattr(self.network, name)

    def path(self, seq, private=False):
        return self.root / ("attachment-queue" if private else "history-pages") / (
            f"{seq:08d}" + (".enc" if private else ".json"))

    def checked(self, path):
        from .account_export import read_json, sha
        envelope = read_json(path)
        page = self.export.verify_signed(envelope)
        if (page.get("format") != "tgwitness-account-history-page-v1"
                or page.get("seq") != len(self.pages) + 1
                or path.name != f"{page['seq']:08d}.json"
                or page.get("previous_sha256") != self.head
                or page.get("inventory_sha256") != self.export.inventory_hash
                or any(page.get(k) != self.job[k] for k in ("job_id", "account_id", "options_sha256"))):
            raise ValueError("Saved history page identity or chain changed.")
        task = self.tasks.get(page.get("task_id"))
        previous = self.progress.get(page.get("task_id"))
        if (task is None or previous and previous["terminal"]
                or page.get("cursor_before") != (previous["cursor_after"] if previous else task["cursor_start"])
                or type(page.get("terminal")) is not bool or not isinstance(page.get("rows"), list)
                or page.get("outcome") not in ("ok", "failed")
                or type(page.get("seen_count")) is not int or page["seen_count"] < len(page["rows"])
                or task["category"] == "messages" and (page["cursor_after"] > page["cursor_before"]
                    or page["cursor_after"] == page["cursor_before"] and not page["terminal"])):
            raise ValueError("Saved history pagination changed.")
        self.head = sha(canonical(envelope))
        reference = {k: v for k, v in page.items() if k not in ("rows", "deferred_media")}
        reference["page_sha256"] = self.head
        self.pages.append(reference)
        self.progress[task["id"]] = reference
        self.lookup[(task["id"], page["cursor_before"])] = reference
        if task["category"] == "messages":
            starts, pages = self.intervals[task["id"]]
            starts.append(-page["cursor_before"])
            pages.append(reference)
        self.messages += len(page["rows"]) if task["category"] == "messages" else 0
        self.bytes += path.stat().st_size
        for row in page["rows"]:
            if row.get("category") != task["category"] or not self.export.selected(row, self.job["options"]):
                raise ValueError("Saved history contains records outside the selected scope.")
            if task["category"] == "messages":
                if (row.get("chat_id") != task["chat_id"]
                        or not page["cursor_after"] <= row["id"] < page["cursor_before"]
                        or row["id"] > task["newest_message_id"]):
                    raise ValueError("Saved history contains a message outside its page boundary.")
                self.export.index.execute("INSERT INTO staged_messages VALUES (?,?)", (row["chat_id"], row["id"]))
        return page

    def state(self, complete=False):
        self.export.current["acquisition"] = {"phase": "attachments" if complete else "history",
            "messages_preserved": self.messages, "bytes_preserved": self.bytes,
            "pages_preserved": len(self.pages), "history_complete": complete}
        self.export.current["counts"]["messages_preserved"] = self.messages
        self.export.persist()

    def recover(self):
        from .account_export import linked, sha
        for name in ("history-pages", "attachment-queue"):
            folder = self.root / name
            if linked(folder):
                raise ValueError("Saved history directories must not be filesystem links.")
            folder.mkdir(mode=0o700, exist_ok=True)
        self.export.index.execute("DROP TABLE IF EXISTS staged_messages")
        self.export.index.execute("CREATE TABLE staged_messages (chat INTEGER, message INTEGER, PRIMARY KEY(chat,message))")
        for path in sorted((self.root / "history-pages").glob("*.json")):
            self.checked(path)
        self.export.index.commit()
        with self.export.store.lock:
            committed = self.export.store.db.execute("SELECT payload FROM events WHERE kind='account_export.history_page' "
                "AND json_extract(payload,'$.job_id')=? ORDER BY seq DESC LIMIT 1", (self.job["job_id"],)).fetchone()
        if committed:
            boundary = json.loads(committed[0])
            if (not 0 < boundary["seq"] <= len(self.pages)
                    or sha(self.path(boundary["seq"]).read_bytes()) != boundary["page_sha256"]):
                raise ValueError("Saved history was rolled back before its journal commitment.")
        self.state()

    def save(self, task, cursor, after, terminal, observed, started, *, error=None):
        from .account_export import attachment_policy, durable_write, sha
        rows, descriptors, deferred, page_ids = [], [], [], set()
        for row, media in observed:
            if not self.export.selected(row, self.job["options"]):
                continue
            if task["category"] == "messages":
                key = (row["chat_id"], row["id"])
                if key in page_ids or self.export.index.execute("SELECT 1 FROM staged_messages WHERE chat=? AND message=?", key).fetchone():
                    continue
                page_ids.add(key)
            media = media if isinstance(media, list) else [media] if media is not None else []
            rows.append(row)
            descriptors.append([base64.b64encode(bytes(item)).decode("ascii") for item in media])
            pending = []
            for item in media:
                info, action, _ = attachment_policy(item, task, self.job["options"])
                pending.append({"metadata": info, "action": action})
            deferred.append(pending)
        seq = len(self.pages) + 1
        queue = canonical({"job_id": self.job["job_id"], "seq": seq, "media": descriptors})
        page = {"format": "tgwitness-account-history-page-v1", "public_key": self.export.vault.public_key,
            **{k: self.job[k] for k in ("job_id", "account_id", "options_sha256")},
            "inventory_sha256": self.export.inventory_hash, "seq": seq, "previous_sha256": self.head,
            "task_id": task["id"], "cursor_before": cursor, "cursor_after": after, "terminal": terminal,
            "rows": rows, "deferred_media": deferred, "seen_count": len(observed),
            "queue_sha256": sha(queue), "captured_from": started,
            "captured_until": utcnow(), "outcome": "failed" if error else "ok", "error": error}
        self.export.ensure_storage(extra_records=len(canonical(page)) + len(queue))
        durable_write(self.path(seq, True), self.export.vault.fernet.encrypt(queue))
        data = canonical(self.export.signed(page))
        durable_write(self.path(seq), data)
        self.checked(self.path(seq))
        self.export.index.commit()
        self.export.store.append("account_export.history_page", {"job_id": self.job["job_id"],
            "seq": seq, "page_sha256": sha(data), "messages_preserved": self.messages})
        self.state()

    async def prepare(self):
        from .workers import complete_in_thread
        await complete_in_thread(self.recover)
        for task in self.export.inventory["tasks"]:
            previous = self.progress.get(task["id"])
            if previous and previous["terminal"]:
                continue
            cursor = previous["cursor_after"] if previous else task["cursor_start"]
            while True:
                self.export.ensure_storage()
                started = utcnow()
                self.export.current["current_chat"] = task["chat_id"]
                try:
                    if task.get("discovery_error"):
                        self.save(task, cursor, cursor, True, [], started, error=task["discovery_error"])
                        break
                    observed, after, terminal = await self.export.retry(lambda: self.network.page(task, cursor))
                    if not terminal and after == cursor or task["category"] == "messages" and after > cursor:
                        raise ValueError("Telegram pagination made no progress or moved forward.")
                    self.save(task, cursor, after, terminal, observed, started)
                except errors.TakeoutInvalidError:
                    raise
                except errors.RPCError as exc:
                    self.save(task, cursor, cursor, True, [], started, error=type(exc).__name__)
                    break
                except ValueError as exc:
                    if task["category"] != "other_data" or self.job["options"]["transport"] != "regular":
                        raise
                    self.save(task, cursor, cursor, True, [], started, error=str(exc))
                    break
                if terminal:
                    break
                cursor = after
                await asyncio.sleep(0)
        self.state(complete=True)

    def reference(self, task, cursor):
        reference = self.lookup.get((task["id"], cursor))
        if reference is None and task["category"] == "messages":
            starts, pages = self.intervals[task["id"]]
            position = bisect.bisect_right(starts, -cursor) - 1
            if position >= 0 and pages[position]["cursor_after"] < cursor < pages[position]["cursor_before"]:
                reference = pages[position]
        return reference

    @staticmethod
    def slice(page, task, cursor):
        indexes = [i for i, row in enumerate(page["rows"]) if task["category"] != "messages" or row["id"] < cursor]
        processed = len(page["rows"]) - len(indexes)
        chunked = task["category"] == "messages" and len(indexes) > 10
        if chunked:
            indexes = indexes[:10]
        after = page["rows"][indexes[-1]]["id"] if chunked else page["cursor_after"]
        return indexes, after, False if chunked else page["terminal"], len(indexes) if chunked else page["seen_count"] - processed

    async def page(self, task, cursor):
        from .account_export import linked, read_json, sha
        reference = self.reference(task, cursor)
        if reference is None:
            raise ValueError("The frozen history page is unavailable.")
        envelope = read_json(self.path(reference["seq"]))
        if sha(canonical(envelope)) != reference["page_sha256"]:
            raise ValueError("The frozen history page changed during attachment processing.")
        page = self.export.verify_signed(envelope)
        if page["outcome"] == "failed":
            raise errors.RPCError(None, page["error"], 400)
        path = self.path(page["seq"], True)
        if linked(path) or path.stat().st_size > 96 * 1024**2:
            raise ValueError("Invalid attachment queue file.")
        data = self.export.vault.fernet.decrypt(path.read_bytes())
        queue = json.loads(data)
        if (sha(data) != page["queue_sha256"] or queue.get("job_id") != self.job["job_id"]
                or queue.get("seq") != page["seq"] or len(queue.get("media", [])) != len(page["rows"])):
            raise ValueError("The saved attachment queue changed after acquisition.")
        indexes, after, terminal, seen = self.slice(page, task, cursor)
        rows = []
        for index in indexes:
            record, encoded = page["rows"][index], queue["media"][index]
            media = []
            for item in encoded:
                with BinaryReader(base64.b64decode(item, validate=True)) as reader:
                    media.append(reader.tgread_object())
            rows.append((json.loads(json.dumps(record)), media))
        return ObservedPage(rows, seen, page["captured_from"]), after, terminal
