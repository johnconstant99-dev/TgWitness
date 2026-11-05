"""Desktop field/ordering compatibility and safe offline HTML on real archives."""
import asyncio
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.account_export import AccountExport
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.telegram_export import DesktopExport, rich_text, peer_id
from tgwitness.verify import fingerprint, verify_account_export
from tools.demo_account_export import SyntheticCollector
from tools.test_file_hash_export import ExportTransport


def test_utf16_entities_do_not_split_emoji_or_duplicate_nested_text():
    text = "Hello 🙂 link"
    value, entities = rich_text(text, [
        {"_": "MessageEntityBold", "offset": 6, "length": 2},
        {"_": "MessageEntityItalic", "offset": 7, "length": 1},
        {"_": "MessageEntityTextUrl", "offset": 9, "length": 4, "url": "https://example.com"}])
    assert "".join(p if isinstance(p, str) else p["text"] for p in value) == text
    assert entities[1] == {"type": "bold", "text": "🙂"}
    assert entities[-1]["href"] == "https://example.com"
    assert peer_id(-1000000000055) == "channel55"
    assert peer_id(-55) == "chat55"


def test_desktop_account_sections_have_native_shapes_and_session_fields(tmp_path):
    at = "2026-11-04T01:02:03+00:00"
    records = {
        "profile": [{"category": "profile", "data": {"users": [{"id": 44, "first_name": "Test", "phone": "15550001111"}],
                     "full_user": {"about": "Fictional account"}}}],
        "contacts": [{"category": "contacts", "data": {"first_name": "Contact", "phone": "15550002222", "date": at}}],
        "sessions": [{"category": "sessions", "type": "telegram", "data": {"date_created": at, "date_active": at,
                      "ip": "192.0.2.1", "app_name": "Test client", "app_version": "1.0", "device_model": "Test device"}},
                     {"category": "sessions", "type": "web", "data": {"date_created": at, "domain": "example.invalid"}}],
        "profile_photos": [{"category": "profile_photos", "data": {"date": at}, "attachments": []}],
        "stories": [{"category": "stories", "data": {"date": at, "expire_date": at, "pinned": True}, "attachments": []}],
    }
    receipts = []
    for category, rows in records.items():
        filename = category + ".jsonl"
        (tmp_path / filename).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        receipts.append({"statement": {"category": category, "data_file": filename}})
    view = DesktopExport(tmp_path, {"chats": []}, receipts,
        {"job_id": "synthetic", "account_id": 44, "options": {"include_contacts": True}}, {})
    try:
        value = json.loads(b"".join(view.json()))
        assert value["personal_information"]["bio"] == "Fictional account"
        assert value["contacts"]["list"][0]["phone_number"] == "15550002222"
        assert len(value["sessions"]["list"]) == len(value["web_sessions"]["list"]) == 1
        assert value["sessions"]["list"][0]["last_ip"] == "192.0.2.1"
        assert value["web_sessions"]["list"][0]["domain_name"] == "example.invalid"
        assert isinstance(value["profile_pictures"], list) and "photo" in value["profile_pictures"][0]
        assert isinstance(value["stories"], list) and value["stories"][0]["pinned"]
    finally:
        view.close()


def test_native_html_pages_bound_source_bytes_without_truncating_large_records(tmp_path):
    rows = [{"category": "messages", "chat_id": 11, "id": i, "text": "<" * (150 * 1024)} for i in range(1, 12)]
    (tmp_path / "messages.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    view = DesktopExport(tmp_path, {"chats": [{"id": 11, "kind": "private", "title": "Synthetic", "selected": True}]},
        [{"statement": {"category": "messages", "data_file": "messages.jsonl"}}],
        {"job_id": "synthetic", "account_id": 44, "options": {}}, {})
    try:
        pages = [(name, b"".join(chunks)) for name, chunks in view.html() if name.startswith("chats/")]
        assert len(pages) == 4
        assert sum(body.count(b"&lt;") for _, body in pages) == 11 * 150 * 1024
        assert all(body.count(b"<article ") <= 3 for _, body in pages)
        assert b'messages2.html' in pages[0][1]
    finally:
        view.close()


@pytest.mark.parametrize("format", ["tgwitness", "telegram_json", "telegram_html", "telegram_both"])
def test_selected_desktop_format_has_ordered_messages_hash_references_and_no_duplicate_media(tmp_path, format):
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting("account", {"id": 70000})
        collector = SyntheticCollector()
        collector.store = store
        export = AccountExport(collector, store, vault)

        class Network(ExportTransport):
            async def page(self, task, cursor):
                rows, after, terminal = await super().page(task, cursor)
                for row, _ in rows:
                    row["text"] = '<script>alert("x")</script> 🙂'
                return rows, after, terminal

        export.transport_factory = Network
        try:
            job = await export.start({"transport": "regular", "include_profile": False, "include_contacts": False,
                "media_action": "hashes_only", "export_format": format})
            await asyncio.wait_for(export.task, 10)
            assert export.public()["ready"], export.public()
            path = export.result_path(job["id"])
            verify_account_export(path, fingerprint(vault.public_key))
            with zipfile.ZipFile(path) as archive:
                assert ("result.json" in archive.namelist()) == (format in ("telegram_json", "telegram_both"))
                assert ("export_results.html" in archive.namelist()) == (format in ("telegram_html", "telegram_both"))
                if "result.json" in archive.namelist():
                    desktop = json.loads(archive.read("result.json"))
                    chat = desktop["chats"]["list"][0]
                    assert chat["id"] == 11 and chat["type"] == "personal_chat"
                    assert [m["id"] for m in chat["messages"]] == [1, 2]
                    assert all(m["tgwitness_media"][0]["outcome"] == "hashed" for m in chat["messages"])
                    assert all(m["date_unixtime"].isdigit() for m in chat["messages"])
                if "export_results.html" in archive.namelist():
                    page = archive.read("chats/chat_001/messages.html").decode()
                    assert "<script>" not in page and "&lt;script&gt;" in page
                    assert page.index('id="message1"') < page.index('id="message2"')
                assert not any(n.startswith("media/") for n in archive.namelist())
        finally:
            await export.close()
            store.close()
    asyncio.run(run())
