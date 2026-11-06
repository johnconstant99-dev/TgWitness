"""An unsuccessful recheck is an observation of absence, not a deletion notice."""
import asyncio
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest
from telethon.tl import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, report
from tgwitness.collector import Collector
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_report


@pytest.fixture
def journal(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        yield store, vault
    finally:
        store.close()


def seed(store, deletion=False, recovered=False):
    store.append("message.new", {"text": "SYNTHETIC retained text", "sender_id": 7}, 55123, 1, 7)
    store.append("message.missing_on_recheck", {"meaning": "Synthetic empty response"}, 55123, 1)
    if recovered:
        store.append("message.recovered", {"text": "SYNTHETIC retained text", "sender_id": 7}, 55123, 1, 7)
    if deletion:
        store.append("message.deleted", {"deleted_by": None, "deletion_time": None}, 55123, 2)


@pytest.mark.parametrize("deletion", [False, True])
def test_signed_json_counts_only_received_deletion_notices(journal, deletion):
    store, vault = journal
    seed(store, deletion=deletion)
    before = list(store.all_events())
    path = evidence.export_file(store, vault, "json", {"language": "en"})
    assert verify_report(path, fingerprint(vault.public_key))["key_pinned"]
    data = json.loads(path.read_text(encoding="utf-8"))["report"]
    assert data["summary"]["categories"]["deleted"] == int(deletion)
    assert data["summary"]["categories"]["missing"] == 1
    assert list(store.all_events()) == before


def test_html_viewer_distinguishes_missing_from_deleted(journal):
    store, vault = journal
    seed(store, deletion=True)
    path = evidence.export_file(store, vault, "html", {"language": "en"})
    assert verify_report(path, fingerprint(vault.public_key))["key_pinned"]
    html = path.read_text(encoding="utf-8")
    blocks = re.findall(r'<script type="application/json" class="tgw-file"[^>]*>(.*?)</script>', html, re.S)
    items = [item for block in blocks for item in json.loads(block)
             if isinstance(item, dict) and "k" in item]
    missing = next(item for item in items if item["k"] == "message.missing_on_recheck")
    deleted = next(item for item in items if item["k"] == "message.deleted")
    assert missing["c"] == "missing" and deleted["c"] == "deleted"
    assert report.viewer_meta(report.Words("en"), "journal", {})["cats"]["missing"] == "Missing on recheck"


def test_reappearance_does_not_turn_past_absence_into_a_deletion(journal):
    store, vault = journal
    seed(store, recovered=True)
    assert store.message_state(55123, 1)["missing"] is False
    assert store.message_state(55123, 1)["deleted"] is False
    path = evidence.export_file(store, vault, "json", {"language": "en"})
    data = json.loads(path.read_text(encoding="utf-8"))["report"]
    assert data["summary"]["categories"]["deleted"] == 0
    assert data["summary"]["categories"]["missing"] == 1
    assert [row["kind"] for row in data["changes"]["messages"][0]["gone"]] == ["message.missing_on_recheck"]


def test_unscoped_notice_does_not_claim_that_a_known_disabled_chat_was_never_saved(journal):
    store, vault = journal
    store.set_target(55123, "Synthetic disabled chat", "private", False)
    store.append("message.new", {"text": "SYNTHETIC saved before pause"}, 55123, 1)
    collector = Collector(store, vault)
    collector.running = True
    raw = types.UpdateDeleteMessages(messages=[1, 999], pts=2, pts_count=2)
    asyncio.run(collector.on_delete(SimpleNamespace(chat_id=None, deleted_ids=[1, 999], original_update=raw)))
    events = list(store.all_events())
    unscoped = next(event for event in events if event["kind"] == "deletion.unscoped")
    assert unscoped["payload"]["message_ids"] == [1, 999]
    assert unscoped["payload"]["raw"] == raw.to_dict()
    assert unscoped["chat_id"] is None
    assert "no saved message" not in unscoped["payload"]["scope"]
    assert not any(event["kind"] == "message.deleted" for event in events)
    store.verify(vault.public_key)
