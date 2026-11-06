import asyncio
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from telethon import errors
from telethon.tl import functions as f

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.test_distributed_export import CHAT, close_entries, coordinator, message
from tools.test_distributed_takeout import setup
from tgwitness import distributed_export, distributed_pages
from tgwitness.account_export import durable_write
from tgwitness.distributed_pages import RangePages
from tgwitness.store import canonical
from tgwitness.verify import fingerprint, verify_distributed_work


async def stop_after_acquisition(*args):
    raise ValueError("Acquisition checked without rendering")


async def paused_page(tmp_path, count=201):
    manager, entries = setup(tmp_path, [message(i) for i in range(1, count + 1)])
    collector = entries["account0"]["app"].state.collector
    collector.client.block_after = 1
    state = await manager.start(CHAT, ["account0"], "account0", transport="takeout")
    await asyncio.wait_for(collector.client.blocked.wait(), 10)
    await manager.pause(state["id"])
    return manager, entries, collector, manager.directory(state["id"])


def test_restart_reuses_a_signed_page_inside_the_same_chunk(tmp_path):
    async def scenario():
        manager, entries, collector, directory = await paused_page(tmp_path)
        try:
            assert manager.state["captured"] == 100 and manager.state["ranges_done"] == 0
            receipt = directory / "pages" / "1" / "1.json"
            saved = receipt.read_bytes()
            first = json.loads(saved)["statement"]
            assert (first["cursor_before"], first["cursor_after"]) == (202, 102)
            collector.client.block_after = None
            collector.client.requests.clear()
            restored = distributed_export.DistributedExport(manager.profiles)
            restored.finish_selection = stop_after_acquisition
            await restored.resume(manager.state["id"])
            await asyncio.wait_for(restored.task, 10)
            assert restored.state["error"] == "Acquisition checked without rendering"
            reads = [r for r, w in collector.client.requests if isinstance(r, f.messages.GetHistoryRequest)]
            assert [r.offset_id for r in reads] == [102, 2]
            assert receipt.read_bytes() == saved
            assert restored.state["performance"]["reused_messages"] == 100
            assert restored.state["performance"]["new_messages"] == 101
            assert restored.state["captured"] == 201
            rows = [json.loads(line)["id"] for line in (directory / "chunks" / "1.jsonl").read_bytes().splitlines()]
            assert rows == list(range(201, 0, -1))
            assert collector.client.inits == 1 and collector.export_claim is None
            checked = verify_distributed_work(directory, fingerprint(collector.vault.public_key))
            assert checked["captured"] == 201 and checked["pages"] == 3 and checked["complete_within_plan"]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["unsigned_tail", "receipt_write", "disk_full", "process_exit"])
def test_crash_tail_never_advances_the_saved_cursor(tmp_path, monkeypatch, failure):
    async def scenario():
        manager, entries, collector, directory = await paused_page(tmp_path)
        try:
            path = directory / "chunks" / "1.jsonl"
            original = path.read_bytes()
            if failure == "process_exit":
                # A real subprocess exits after flushing data, before any receipt.
                script = """import os, sys
with open(sys.argv[1], 'ab') as stream:
    stream.write(b'{"id":101,"text":"uncommitted crash tail"}\\n')
    stream.flush()
    os.fsync(stream.fileno())
os._exit(23)
"""
                child = subprocess.run([sys.executable, "-c", script, str(path)], capture_output=True, timeout=10)
                assert child.returncode == 23, child.stderr
            elif failure == "unsigned_tail":
                with path.open("ab") as stream:
                    stream.write(b'{"id":101,"text":"uncommitted"}\n{truncated')
            else:
                old_write = distributed_pages.durable_write
                def failing(path, data):
                    if path.name == "2.json":
                        raise OSError(28, "synthetic disk full")
                    return old_write(path, data)
                if failure == "receipt_write":
                    monkeypatch.setattr(distributed_pages, "durable_write", failing)
                else:
                    real_usage = distributed_pages.shutil.disk_usage
                    monkeypatch.setattr(distributed_pages.shutil, "disk_usage",
                                        lambda p: real_usage(p)._replace(free=0))
                collector.client.block_after = None
                await manager.resume(manager.state["id"])
                await asyncio.wait_for(manager.task, 10)
                assert manager.state["phase"] == "failed" and manager.state["captured"] == 100
                monkeypatch.undo()
            assert path.read_bytes().startswith(original)
            collector.client.block_after = None
            collector.client.requests.clear()
            restored = distributed_export.DistributedExport(manager.profiles)
            restored.finish_selection = stop_after_acquisition
            await restored.resume(manager.state["id"])
            await asyncio.wait_for(restored.task, 10)
            assert restored.state["captured"] == 201 and restored.state["ranges_done"] == 1
            assert path.read_bytes().startswith(original) and b"uncommitted" not in path.read_bytes()
            reads = [r for r, _ in collector.client.requests if isinstance(r, f.messages.GetHistoryRequest)]
            assert reads[0].offset_id == 102
            assert restored.state["performance"]["reused_messages"] == 100
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("damage", ["data", "signature", "plan", "cursor", "chain", "observer", "generation", "missing_page"])
def test_damaged_checkpoint_stops_before_any_telegram_request(tmp_path, monkeypatch, damage):
    async def scenario():
        manager, entries, collector, directory = await paused_page(tmp_path)
        try:
            receipt = directory / "pages" / "1" / "1.json"
            envelope = json.loads(receipt.read_bytes())
            value = envelope["statement"]
            if damage == "data":
                path = directory / "chunks" / "1.jsonl"
                path.write_bytes(path.read_bytes().replace(b"English", b"Changed"))
            elif damage == "missing_page":
                receipt.unlink()
            else:
                key, replacement = {"signature": ("count", 99), "plan": ("plan_sha256", "f" * 64),
                    "cursor": ("cursor_after", 103), "chain": ("previous_receipt_sha256", "f" * 64),
                    "observer": ("account_id", -1), "generation": ("transport_generation", 0)}[damage]
                value[key] = replacement
                if damage != "signature":
                    envelope["signature"] = collector.vault.sign(canonical(value))
                receipt.write_bytes(canonical(envelope))
            collector.client.requests.clear()
            collector.resolve_for_export.reset_mock()
            await manager.resume(manager.state["id"])
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["phase"] == "failed" and not collector.client.requests
            collector.resolve_for_export.assert_not_awaited()
            assert collector.export_claim is None
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_pause_drains_inflight_checkpoint_before_releasing_account(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = setup(tmp_path, [message(i) for i in range(1, 202)])
        collector = entries["account0"]["app"].state.collector
        entered, release = threading.Event(), threading.Event()
        old_write = distributed_pages.durable_write
        def blocked(path, data):
            if path.name == "2.json":
                entered.set()
                assert release.wait(10)
            return old_write(path, data)
        monkeypatch.setattr(distributed_pages, "durable_write", blocked)
        try:
            state = await manager.start(CHAT, ["account0"], "account0", transport="takeout")
            assert await asyncio.to_thread(entered.wait, 10)
            pausing = asyncio.create_task(manager.pause(state["id"]))
            await asyncio.sleep(.05)
            assert not pausing.done() and collector.export_claim == state["id"]
            release.set()
            await asyncio.wait_for(pausing, 10)
            assert collector.export_claim is None and manager.state["captured"] == 200
            restored = distributed_export.DistributedExport(manager.profiles)
            restored.finish_selection = stop_after_acquisition
            collector.client.requests.clear()
            await restored.resume(state["id"])
            await asyncio.wait_for(restored.task, 10)
            assert restored.state["captured"] == 201
            assert restored.state["performance"]["reused_messages"] == 200
            assert restored.state["performance"]["new_messages"] == 1
        finally:
            release.set()
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_partial_range_cannot_move_to_another_account(tmp_path):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 202)])
        manager.launch = lambda: None
        try:
            await manager.start(CHAT, list(entries), "account0")
            manager.prepare_chunks()
            task = manager.db.execute("SELECT * FROM tasks").fetchone()
            pages = RangePages(manager.directory(manager.state["id"]), manager.job, task)
            collector = entries["account0"]["app"].state.collector
            data = b'{"id":201}\n'
            pages.commit(data, 1, 201, False, "account0", collector.vault, None, manager.job["started_at"])
            manager.db.close()
            manager.prepare_chunks()
            assert [r[0] for r in manager.db.execute("SELECT profile FROM eligible")] == ["account0"]
            other = entries["account1"]["app"].state.collector
            with pytest.raises(ValueError, match="original observer"):
                await pages.fetch(other, manager.entities["account1"], "account1", lambda _: None, lambda _: None)
            assert not other.client.reads
        finally:
            if manager.db:
                manager.db.close()
                manager.db = None
            manager.release(manager.state["id"])
            close_entries(entries)
    asyncio.run(scenario())


def test_old_chunk_plan_still_resumes_without_page_migration(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 7)], count=1)
        manager.launch = lambda: None
        monkeypatch.setattr(distributed_export, "CHUNK", 2)
        try:
            await manager.start(CHAT, ["account0"], "account0")
            manager.job.pop("checkpoint_format")
            directory = manager.directory(manager.state["id"])
            durable_write(directory / "job.json", canonical(manager.signed(manager.job)))
            manager.prepare_chunks()
            await manager.work(manager.state["workers"][0])
            assert manager.state["captured"] == 6
            assert not list((directory / "pages").iterdir())
            saved = {p.name: p.read_bytes() for p in (directory / "receipts").glob("*.json")}
            manager.db.close()
            manager.prepare_chunks()
            assert manager.state["captured"] == 6 and manager.state["ranges_done"] == 3
            assert saved == {p.name: p.read_bytes() for p in (directory / "receipts").glob("*.json")}
        finally:
            if manager.db:
                manager.db.close()
                manager.db = None
            manager.release(manager.state["id"])
            close_entries(entries)
    asyncio.run(scenario())


def test_standalone_verifier_checks_paused_prefix_without_vault_or_database(tmp_path):
    async def scenario():
        manager, entries, collector, directory = await paused_page(tmp_path)
        try:
            with (directory / "chunks" / "1.jsonl").open("ab") as stream:
                stream.write(b"unsigned")
            # Run the bundled standalone module, which imports no application code.
            command = [sys.executable, "-I", str(Path(distributed_export.__file__).with_name("verify.py")),
                       str(directory), "--fingerprint", fingerprint(collector.vault.public_key), "--json"]
            child = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=15)
            assert child.returncode == 0, child.stdout + child.stderr
            result = json.loads(child.stdout)
            assert result["verified"] and result["signer_pinned"]
            assert result["result"]["captured"] == 100 and result["result"]["unsigned_tail_bytes"] == 8
            assert not result["result"]["complete_within_plan"]
            command[-2] = "f" * 64
            rejected = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=15)
            assert rejected.returncode == 1 and "fingerprint" in rejected.stdout
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("count", [0, 100, 200, 201])
def test_empty_and_full_checkpoints_preserve_terminal_state(tmp_path, count):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, max(count, 1) + 1)], count=1)
        manager.launch = lambda: None
        collector = entries["account0"]["app"].state.collector
        try:
            state = await manager.start(CHAT, ["account0"], "account0")
            if not count:
                collector.client.messages = []
            manager.prepare_chunks()
            await manager.work(manager.state["workers"][0])
            assert manager.state["captured"] == count and manager.state["ranges_done"] == 1
            checked = verify_distributed_work(manager.directory(state["id"]), fingerprint(collector.vault.public_key))
            assert checked["complete_within_plan"] and checked["pages"] == count // 100 + 1
            reads = list(collector.client.reads)
            manager.db.close()
            manager.prepare_chunks()
            await manager.work(manager.state["workers"][0])
            assert collector.client.reads == reads
        finally:
            if manager.db:
                manager.db.close()
                manager.db = None
            manager.release(manager.state["id"])
            close_entries(entries)
    asyncio.run(scenario())


def test_checkpoint_prefix_survives_a_full_flood_wait(tmp_path, monkeypatch):
    async def scenario():
        manager, entries = setup(tmp_path, [message(i) for i in range(1, 202)])
        collector = entries["account0"]["app"].state.collector
        collector.client.flood_type = errors.FloodWaitError
        manager.finish_selection = stop_after_acquisition
        waits = []
        original_sleep = asyncio.sleep
        async def sleep(seconds):
            if seconds > 0:
                waits.append(seconds)
                assert manager.state["captured"] == 100
                checked = verify_distributed_work(manager.directory(manager.state["id"]), fingerprint(collector.vault.public_key))
                assert checked["captured"] == 100
            await original_sleep(0)
        monkeypatch.setattr(asyncio, "sleep", sleep)
        try:
            await manager.start(CHAT, ["account0"], "account0", transport="takeout")
            await asyncio.wait_for(manager.task, 10)
            assert waits == [61] and manager.state["captured"] == 201
            assert collector.store.get_setting("rpc_backoff_until") > 0
            reads = [r for r, w in collector.client.requests if isinstance(r, f.messages.GetHistoryRequest) and w]
            assert [r.offset_id for r in reads] == [202, 102, 102, 2]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_new_takeout_generation_does_not_rewrite_committed_pages(tmp_path):
    async def scenario():
        manager, entries, collector, directory = await paused_page(tmp_path)
        try:
            first = (directory / "pages" / "1" / "1.json").read_bytes()
            collector.client.invalid = True
            await manager.resume(manager.state["id"])
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["phase"] == "paused" and manager.state["captured"] == 100
            collector.client.invalid, collector.client.block_after = False, None
            manager.finish_selection = stop_after_acquisition
            await manager.resume(manager.state["id"])
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["captured"] == 201 and collector.client.inits == 2
            assert (directory / "pages" / "1" / "1.json").read_bytes() == first
            generations = [json.loads(p.read_bytes())["statement"]["transport_generation"]
                           for p in sorted((directory / "pages" / "1").glob("*.json"))]
            assert generations == [1, 2, 2]
            assert verify_distributed_work(directory)["complete_within_plan"]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


@pytest.mark.parametrize("damage", ["duplicate", "wrong_source", "outside_range"])
def test_bad_iterator_records_cannot_seal_a_range(tmp_path, damage):
    async def scenario():
        manager, entries = coordinator(tmp_path, [message(i) for i in range(1, 202)], count=1)
        collector = entries["account0"]["app"].state.collector
        async def bad(*args, **kwargs):
            for i in range(201, 101, -1):
                yield message(i)
            broken = message(201 if damage == "duplicate" else 999 if damage == "outside_range" else 101)
            if damage == "wrong_source":
                broken.peer_id.channel_id = 43
            yield broken
        collector.client.iter_messages = bad
        try:
            await manager.start(CHAT, ["account0"], "account0")
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["phase"] == "failed" and manager.state["captured"] == 100
            assert manager.state["ranges_done"] == 0
            checked = verify_distributed_work(manager.directory(manager.state["id"]))
            assert checked["captured"] == 100 and not checked["complete_within_plan"]
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


def test_chunk_footer_cannot_claim_a_different_takeout_generation(tmp_path):
    async def scenario():
        manager, entries = setup(tmp_path, [message(1)])
        collector = entries["account0"]["app"].state.collector
        manager.finish_selection = stop_after_acquisition
        try:
            state = await manager.start(CHAT, ["account0"], "account0", transport="takeout")
            await asyncio.wait_for(manager.task, 10)
            directory = manager.directory(state["id"])
            path = directory / "receipts" / "1.json"
            envelope = json.loads(path.read_bytes())
            envelope["statement"]["transport_generation"] = 2
            envelope["signature"] = collector.vault.sign(canonical(envelope["statement"]))
            path.write_bytes(canonical(envelope))
            with pytest.raises(ValueError, match="differs"):
                verify_distributed_work(directory)
            collector.client.requests.clear()
            await manager.resume(state["id"])
            await asyncio.wait_for(manager.task, 10)
            assert manager.state["phase"] == "failed" and "differs" in manager.state["error"]
            assert not collector.client.requests
        finally:
            await manager.close()
            close_entries(entries)
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
