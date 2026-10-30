"""Synthetic ingestion/storage/export benchmark, NOT a Telegram delivery guarantee."""
import argparse
import asyncio
import json
import platform
import shutil
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from telethon.tl import types
from tgwitness.collector import Collector
from tgwitness.evidence import export_file
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_bundle


async def benchmark(count, chats, output):
    directory = Path(tempfile.mkdtemp(prefix="capacity-", dir=output))
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    collector = Collector(store, vault)
    collector.running = True
    store.set_setting("account", {"id": 70000, "username": "synthetic"})
    for chat in range(chats):
        store.set_target(-1000000000000 - (chat + 1), "Private synthetic " + str(chat + 1), "supergroup", True)
    latencies = []
    start = time.perf_counter()
    try:
        for i in range(count):
            channel = i % chats + 1
            message = types.Message(
                id=i // chats + 1, peer_id=types.PeerChannel(channel),
                date=datetime.now(timezone.utc), message="Synthetic evidence text " + str(i) + " " + "x" * 400,
                from_id=types.PeerUser(70001))
            update = types.UpdateNewChannelMessage(message=message, pts=i + 1, pts_count=1)
            before = time.perf_counter()
            await collector.on_new(SimpleNamespace(chat_id=-1000000000000-channel, message=message,
                                                    original_update=update))
            latencies.append((time.perf_counter() - before) * 1000)
            if i % 1000 == 0:
                await asyncio.sleep(0)
        duration = time.perf_counter() - start
        assert store.stats()["counts"]["message.new"] == count
        tracemalloc.start()
        export_start = time.perf_counter()
        archive = export_file(store, vault, "zip")
        export_seconds = time.perf_counter() - export_start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        verification = verify_bundle(archive, expected_fingerprint=__import__(
            "tgwitness.verify", fromlist=["fingerprint"]).fingerprint(vault.public_key))
        assert verification["events"] == count
        final_archive = directory / "capacity-evidence.zip"
        shutil.copyfile(archive, final_archive)
        archive.unlink()
        receipt = {
            "kind": "synthetic_local_benchmark", "platform": platform.platform(),
            "python": platform.python_version(), "selected_chats": chats, "message_events": count,
            "input_text_characters": 400, "media_downloads": False, "network": False,
            "ingest_seconds": round(duration, 3), "observed_events_per_second": round(count / duration, 1),
            "handler_p50_ms": round(statistics.median(latencies), 3),
            "handler_p95_ms": round(sorted(latencies)[int(len(latencies)*.95)], 3),
            "handler_max_ms": round(max(latencies), 3),
            "export_seconds_with_tracemalloc": round(export_seconds, 3),
            "export_peak_traced_python_mib": round(peak / 1024**2, 2),
            "archive_bytes": final_archive.stat().st_size,
            "verified_events": verification["events"],
            "limitations": "Synthetic serial handlers on this host only; no real MTProto delivery, concurrent accounts, network, or media. Python traced allocations are not process RSS.",
        }
        (output / "capacity-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt, indent=2))
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--chats", type=int, default=100)
    args = parser.parse_args()
    if args.events < 100 or not 1 <= args.chats <= 1000:
        parser.error("Use at least 100 events and 1–1000 synthetic chats.")
    output = ROOT / "test-results"
    output.mkdir(exist_ok=True)
    asyncio.run(benchmark(args.events, args.chats, output))


if __name__ == "__main__":
    main()
