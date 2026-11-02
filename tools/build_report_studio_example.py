"""Build three signed report designs from an explicitly fictional month of activity."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import shutil
import sys
import tempfile
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import evidence, report
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle

NAMES = ("Alex Morgan", "Sam Rivera", "Jordan Lee", "Taylor Quinn", "Casey Reed", "Robin Ellis", "Drew Parker", "Avery Stone")
CHATS = ("Project Meridian", "Delivery review", "Research notes", "Operations", "Partner updates")


def seed(store):
    rng = random.Random(261102)
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    events = [(start, "observation.started", {"parameters": {"heartbeat_seconds": 3600}}, None, None)]
    store.set_setting("demo", True)
    for index, title in enumerate(CHATS):
        store.set_target(-10020000 - index, "DEMO · " + title, "supergroup", True)
    for hour in range(1, 28 * 24):
        if 18 * 24 + 10 < hour < 18 * 24 + 15:
            continue
        at = start + timedelta(hours=hour)
        kind = "coverage.gap" if hour == 18 * 24 + 10 else "connection.restored" if hour == 18 * 24 + 15 else "collector.heartbeat"
        events.append((at, kind, {"interval_seconds": 3600, "reason": "synthetic_transport_pause"}, None, None))
    number = 0
    for day in range(28):
        for _ in range(8 + rng.randrange(38) + (18 if 12 <= day <= 18 else 0)):
            hour = rng.choices(range(24), weights=[1] * 7 + [3, 7, 10, 12, 9, 5, 8, 12, 12, 9, 6, 5, 3, 2, 1, 1, 1])[0]
            if day == 18 and 10 <= hour < 15:
                continue
            at = start + timedelta(days=day, hours=hour, minutes=rng.randrange(60), seconds=rng.randrange(60))
            person = rng.choices(range(8), weights=[30, 23, 16, 12, 8, 6, 3, 2])[0]
            chat = rng.choices(range(5), weights=[40, 25, 18, 12, 5])[0]
            number += 1
            payload = {"text": f"SYNTHETIC · Review note {number}. Fictional material for report design review.",
                       "sender_id": 71000 + person,
                       "sender_observation": {"id": 71000 + person, "display_name": "DEMO · " + NAMES[person]}}
            events.append((at, "message.new", payload, -10020000 - chat, number))
            if number % 97 == 0:
                events.append((at + timedelta(minutes=5), "message.edited", {**payload, "text": "SYNTHETIC · Revised review note."}, -10020000 - chat, number))
            if number % 151 == 0:
                events.append((at + timedelta(minutes=8), "message.deleted", {"deleted_by": None}, -10020000 - chat, number))
    events.append((start + timedelta(days=28), "observation.stopped", {"reason": "synthetic_demo_end"}, None, None))
    for at, kind, payload, chat, mid in sorted(events, key=lambda event: event[0]):
        with patch("tgwitness.store.utcnow", return_value=at.isoformat()):
            store.append(kind, {"synthetic": True, **payload}, chat, mid, payload.get("sender_id"), at.isoformat() if mid else None)


def build(output, language="en"):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Choose a new empty directory. Signed examples are immutable.")
    output.mkdir(parents=True, exist_ok=True)
    receipts = {}
    with tempfile.TemporaryDirectory(prefix="tgwitness-studio-") as scratch:
        vault, store = Vault(Path(scratch)), Store(Path(scratch))
        store.bind(vault)
        try:
            seed(store)
            for template in ("dossier", "analytical", "editorial"):
                options = {**report.resolved(), "language": language, "design": template, "template": "activity", "theme": "light", "timeline": False,
                    "case_title": "Project Meridian\u00a0— Activity review", "case_id": "DEMO / MRD–2026.10",
                    "organization": "Fictional Research Office", "examiner": "Synthetic analyst",
                    "notes": "SYNTHETIC EXAMPLE · Every message, participant and observation is fictional. No Telegram connection or external timestamp service was used.",
                    "chart_limit": 5, "selection": {"id_gaps": False}}
                bundle = evidence.export_file(store, vault, "zip", options)
                checked = verify_bundle(bundle, fingerprint(vault.public_key))
                assert checked["key_pinned"] and checked["report_pdf"]
                folder = output / template
                folder.mkdir()
                shutil.copyfile(bundle, folder / "dossier.zip")
                with zipfile.ZipFile(bundle) as archive:
                    archive.extractall(folder)
                receipts[template] = {"fingerprint": fingerprint(vault.public_key), "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(), "synthetic": True}
        finally:
            store.close()
    (output / "example.json").write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
    return receipts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--language", choices=("en", "ru", "de"), default="en")
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.language), indent=2))
