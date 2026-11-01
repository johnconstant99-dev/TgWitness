"""Offline export recovery and scale checks using fictional account data only."""
import asyncio
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tgwitness.account_export import AccountExport
from tgwitness.demo import seed_demo
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_account_export
from tools.demo_account_export import SyntheticCollector, SyntheticTransport


class Counted(list):
    def __init__(self, values):
        super().__init__(values)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def check_progress_scale():
    # Sealing each page must scan tasks once, not once per selected chat.
    export = object.__new__(AccountExport)
    chats = [{"id": i + 1, "selected": True} for i in range(400)]
    tasks = Counted({"id": f"messages:{chat['id']}", "chat_id": chat["id"]} for chat in chats)
    export.inventory = {"chats": chats, "tasks": tasks, "discovery_complete": True, "gaps": []}
    export.progress = {f"messages:{i + 1}": {"terminal": True, "outcome": "ok" if i % 2 else "failed"}
                       for i in range(400)}
    export.counts, export.failures, export.current = {"messages": 12}, 200, {}
    export.update_counts()
    assert export.current["counts"]["chats_done"] == 200
    assert export.current["coverage"]["tasks_done"] == 200
    assert export.current["coverage"]["failures"] == 200
    assert tasks.iterations <= 2, f"Progress scanned all tasks {tasks.iterations} times"


async def check_recovery(root):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    try:
        seed_demo(store)
        store.set_setting("account", {"id": SyntheticTransport.account_id})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)
        export.transport_factory = SyntheticTransport
        original_package = export.package
        packaging_attempts = 0
        receipt_iterations = None

        def interrupted_package(job):
            nonlocal packaging_attempts, receipt_iterations
            packaging_attempts += 1
            if packaging_attempts == 1:
                open_member = zipfile.ZipFile.open
                writes = 0

                def fail_second_member(archive, name, mode="r", *args, **kwargs):
                    nonlocal writes
                    if mode == "w":
                        writes += 1
                        if writes == 2:
                            raise OSError("synthetic disk interruption during ZIP write")
                    return open_member(archive, name, mode, *args, **kwargs)

                with patch.object(zipfile.ZipFile, "open", fail_second_member):
                    original_package(job)
                raise AssertionError("Injected ZIP write failure was ignored")
            export.receipts = Counted(export.receipts)
            original_package(job)
            receipt_iterations = export.receipts.iterations

        export.package = interrupted_package
        try:
            started = await export.start({"transport": "regular", "purpose": "FICTIONAL TEST",
                "include_profile": False, "include_contacts": False, "media_types": []})
            await asyncio.wait_for(export.task, 20)
            job_id = started["id"]
            assert export.public(job_id)["phase"] == "paused"
            assert not export.public(job_id)["ready"]
            assert export.result_path(job_id) is None
            assert not (export.directory(job_id) / "export.zip").exists()
            assert not (export.directory(job_id) / "export.zip.part").exists()
            sealed_before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in (export.directory(job_id) / "receipts").glob("*.json")}

            await export.resume(job_id)
            await asyncio.wait_for(export.task, 20)
            state = export.public(job_id)
            assert state["ready"] and state["phase"] == "partial", state
            sealed_after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (export.directory(job_id) / "receipts").glob("*.json")}
            assert sealed_after == sealed_before, "Resume replaced a signed receipt"
            assert packaging_attempts == 2
            assert receipt_iterations == 1, f"HTML packaging rescanned {receipt_iterations} receipt lists"

            archive_path = export.result_path(job_id)
            result = verify_account_export(archive_path, fingerprint(vault.public_key))
            assert result["receipt_count"] == len(sealed_before)
            assert result["counts"]["messages"] == 18
            assert not result["complete_within_scope"]  # Synthetic discovery gap remains visible.
            with zipfile.ZipFile(archive_path) as archive:
                for chat_id in (-100100001, -100100002, -100100003):
                    html = archive.read(f"chats/{chat_id}.html").decode()
                    rendered = [int(value) for value in re.findall(r'data-message-id="(\d+)"', html)]
                    records = []
                    for name in sorted(n for n in archive.namelist() if n.startswith("data/") and n.endswith(".jsonl")):
                        records.extend(json.loads(line) for line in archive.read(name).splitlines())
                    expected = [row["id"] for row in records if row["category"] == "messages" and row["chat_id"] == chat_id]
                    assert rendered == expected, (chat_id, rendered, expected)
        finally:
            await export.close()
    finally:
        store.close()


def main():
    check_progress_scale()
    with tempfile.TemporaryDirectory(prefix="tgwitness-export-recovery-") as temporary:
        asyncio.run(check_recovery(Path(temporary)))
    print("Account export recovery and linear receipt scans: PASS")


if __name__ == "__main__":
    main()
