"""Read-only archive views: one day in a named time zone, pinned messages, chat counts, topics, image previews."""
import asyncio
import base64
import hashlib
import io
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.access import Principal, Refused  # noqa: E402
from tgwitness.archive import MCP_TOOLS, ArchiveQuery, ArchiveReader  # noqa: E402
from tgwitness.archive_views import day_bounds  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402

CHAT, FORUM, OTHER = -1001000000001, -1001000000002, -1001000000003


def reader(store, chats=None):
    principal = (Principal(True, "Synthetic admin") if chats is None else
                 Principal(False, "Synthetic reviewer", {"id": "s", "workspaces": {"default": chats},
                                                         "all_workspaces": False, "permissions": ["view"],
                                                         "expires_at": None}))
    state = SimpleNamespace(store=store, collector=SimpleNamespace(running=False))
    return ArchiveReader(SimpleNamespace(entries={"default": {"app": SimpleNamespace(state=state), "label": "S"}}),
                         principal)


def image(color):
    from PIL import Image
    buffer = io.BytesIO()
    Image.new("RGB", (2000, 1200), color).save(buffer, "PNG")
    return buffer.getvalue()


@pytest.fixture
def store(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    for chat in (CHAT, FORUM, OTHER):
        store.set_target(chat, "Synthetic", "supergroup", True)
    for number, sent in ((1, "2026-10-24T21:30:00+00:00"), (2, "2026-10-25T21:30:00+00:00"),
                         (3, "2026-10-25T22:30:00+00:00"), (4, "2026-10-25T03:00:00+00:00")):
        store.append("message.snapshot" if number == 4 else "message.new",
                     {"text": "message " + str(number), "sent_at": sent}, CHAT, number)
    store.append("message.new", {"text": "", "sent_at": "2026-10-26T10:00:00+00:00",
                                 "service_action": "MessageActionPinMessage", "reply_to_message_id": 3}, CHAT, 5)
    store.append("message.unpinned", {"unpinned_by": None, "raw": {"_": "UpdatePinnedChannelMessages", "messages": [3]}}, CHAT)
    store.append("chat.state", {"state": {"title": "Synthetic", "pinned": [2, 77], "pinned_total": 2},
                                "changes": {}, "errors": {}}, CHAT)
    topic = {"_": "MessageReplyHeader", "forum_topic": True, "reply_to_msg_id": 10}
    store.append("message.new", {"text": "", "service_action": "MessageActionTopicCreate",
                                 "raw": {"action": {"_": "MessageActionTopicCreate", "title": "Payments"}}}, FORUM, 10)
    store.append("message.new", {"text": "", "service_action": "MessageActionTopicEdit",
                                 "raw": {"action": {"_": "MessageActionTopicEdit", "title": "Payouts", "closed": True},
                                         "reply_to": topic}}, FORUM, 20)
    store.append("message.new", {"text": "in topic", "raw": {"reply_to": topic}}, FORUM, 21)
    store.append("message.new", {"text": "general"}, FORUM, 22)
    yield store
    store.close()


def test_day_bounds_follow_daylight_saving():
    start, end = day_bounds("2026-10-25", "Europe/Kyiv")
    assert (start.isoformat(), end.isoformat()) == ("2026-10-24T21:00:00+00:00", "2026-10-25T22:00:00+00:00")
    with pytest.raises(ValueError, match="IANA"):
        day_bounds("2026-10-25", "Mars/Olympus")
    with pytest.raises(ValueError, match="date"):
        day_bounds("25.10.2026", "UTC")


def test_messages_of_one_day_use_telegram_time(store):
    result = reader(store).read(ArchiveQuery(tool="get_messages_by_date", chat_id=CHAT, date="2026-10-25",
                                             timezone="Europe/Kyiv"))
    assert sorted(i["source"]["message_id"] for i in result["items"]) == [1, 2, 4]
    assert all(i["time_basis"] == "telegram" for i in result["items"]) and result["complete"]
    first = reader(store).read(ArchiveQuery(tool="get_messages_by_date", chat_id=CHAT, date="2026-10-25",
                                            timezone="Europe/Kyiv", limit=1))
    assert len(first["items"]) == 1 and first["next_before"]
    with pytest.raises(ValueError, match="Choose a chat"):
        reader(store).read(ArchiveQuery(tool="get_messages_by_date", date="2026-10-25"))


def test_pinned_messages_and_pin_notices(store):
    result = reader(store).read(ArchiveQuery(tool="get_pinned_messages", chat_id=CHAT))
    assert result["snapshot"]["pinned"] == [2, 77]
    assert result["items"][0]["source"]["message_id"] == 2 and result["items"][1] == {
        "message_id": 77, "saved": False, "note": "Pinned, but no saved version of this message is in the archive."}
    assert [(p["action"], p["message_ids"]) for p in result["pin_events"]] == [("unpinned", [3]), ("pinned", [3])]


def test_chat_counts_carry_gap_summary_within_access(store):
    stats = reader(store).read(ArchiveQuery(tool="get_chat_stats", chat_id=CHAT))
    assert stats["saved_messages"] == 5 and stats["chat_state"]["title"] == "Synthetic"
    assert stats["gap_summary"]["chats"][0]["chat_id"] == CHAT
    scoped = reader(store, [FORUM]).read(ArchiveQuery(tool="get_chat_stats"))
    assert scoped["saved_messages"] == 4 and scoped["gap_summary"]["account"]["status"] == "not_applicable"
    with pytest.raises(Refused):
        reader(store, [FORUM]).read(ArchiveQuery(tool="get_chat_stats", chat_id=CHAT))
    assert reader(store).read(ArchiveQuery(tool="get_chat_stats", chat_id=CHAT, gaps=False))["gap_summary"] is None


def test_topics_come_from_saved_service_messages(store):
    result = reader(store).read(ArchiveQuery(tool="get_topics", chat_id=FORUM))
    topics = {t["topic_id"]: t for t in result["topics"]}
    assert result["forum"] and topics[10]["title"] == "Payouts" and topics[10]["closed"] is True
    assert [t["title"] for t in topics[10]["titles"]] == ["Payments", "Payouts"]
    assert topics[10]["messages_saved"] == 1 and topics[1]["messages_saved"] == 1
    assert not reader(store).read(ArchiveQuery(tool="get_topics", chat_id=CHAT))["forum"]


def test_chat_counts_reconstruct_compact_snapshots(store):
    from tgwitness import chat_state
    chat_state.record(store, CHAT, {"participants_count": 10, "admins_count": 1}, {})
    chat_state.record(store, CHAT, {"participants_count": 12, "admins_count": 1}, {})
    chat_state.record(store, CHAT, {"participants_count": 12, "admins_count": 2}, {})
    result = reader(store).read(ArchiveQuery(tool="get_chat_stats", chat_id=CHAT))
    assert result["chat_state"]["participants_count"] == 12
    assert result["chat_state"]["admins_count"] == 2


def test_topics_include_references_without_creation_and_ignore_replayed_history(store):
    store.append("message.snapshot", {"service_action": "MessageActionTopicCreate",
                                      "raw": {"action": {"title": "Payments"}}}, FORUM, 10)
    store.append("message.new", {"raw": {"reply_to": {"forum_topic": True, "reply_to_msg_id": 80}}}, FORUM, 81)
    result = reader(store).read(ArchiveQuery(tool="get_topics", chat_id=FORUM))
    topics = {t["topic_id"]: t for t in result["topics"]}
    assert topics[10]["title"] == "Payouts"
    assert len(topics[10]["titles"]) == 2
    assert topics[80]["messages_saved"] == 1


def test_date_scan_can_resume_after_a_page_with_no_matching_messages(store, monkeypatch):
    from tgwitness import archive_views
    for number in range(100, 1200):
        store.append("message.new", {"sent_at": "2026-11-01T00:00:00Z"}, CHAT, number)
    ticks = iter((0, 0, 2))
    monkeypatch.setattr(archive_views.time, "monotonic", lambda: next(ticks))
    query = ArchiveQuery(tool="get_messages_by_date", chat_id=CHAT, date="2026-10-25")
    result = archive_views.by_date(store, query, lambda workspace, event: {}, budget=1)
    assert not result["complete"] and not result["items"] and result["next_before"]
    monkeypatch.undo()
    continued = reader(store).read(query.model_copy(update={"before": result["next_before"]}))
    assert continued["items"] and continued["complete"]


def save_media(store, chat, data):
    digest = hashlib.sha256(data).hexdigest()
    (store.root / "media").mkdir(exist_ok=True)
    (store.root / "media" / digest).write_bytes(data)
    store.append("media.saved", {"media_sha256": digest, "size": len(data), "mime_type": "image/png"}, chat, 30)
    return digest


def test_media_preview_is_bounded_verified_and_scoped(store):
    digest = save_media(store, CHAT, image("red"))
    result = reader(store).read(ArchiveQuery(tool="get_media", media_sha256=digest))
    preview = base64.b64decode(result["preview"]["data_base64"])
    assert result["verified"] and preview[:2] == b"\xff\xd8" and len(preview) <= 36000
    assert result["source"]["event_seq"] and result["media_sha256"] == digest
    assert max(result["preview"]["width"], result["preview"]["height"]) <= 1024
    with pytest.raises(ValueError, match="not available"):
        reader(store, [OTHER]).read(ArchiveQuery(tool="get_media", media_sha256=digest))
    (store.root / "media" / digest).write_bytes(b"tampered")
    tampered = reader(store).read(ArchiveQuery(tool="get_media", media_sha256=digest))
    assert tampered["verified"] is False and "preview" not in tampered
    other = save_media(store, CHAT, b"%PDF-1.4 synthetic")
    assert "preview" not in reader(store).read(ArchiveQuery(tool="get_media", media_sha256=other))


def test_unreadable_or_large_images_return_metadata(store, monkeypatch):
    from tgwitness import archive_views
    broken = save_media(store, CHAT, b"\x89PNG\r\n\x1a\n" + b"broken" * 10)
    result = reader(store).read(ArchiveQuery(tool="get_media", media_sha256=broken))
    assert result["verified"] and "preview" not in result
    valid = save_media(store, CHAT, image("blue"))
    monkeypatch.setattr(archive_views, "IMAGE_BYTES", 8)
    result = reader(store).read(ArchiveQuery(tool="get_media", media_sha256=valid))
    assert not result["verified"] and "preview" not in result


def test_topic_listing_marks_truncation(store):
    for number in range(1000, 1210):
        store.append("message.new", {"raw": {"reply_to": {"forum_topic": True, "reply_to_msg_id": number}}}, FORUM, number + 5000)
    result = reader(store).read(ArchiveQuery(tool="get_topics", chat_id=FORUM))
    assert len(result["topics"]) == 20 and result["topics_total"] == 212 and not result["complete"]
    found = {t["topic_id"] for t in result["topics"]}
    while result["next_offset"] is not None:
        result = reader(store).read(ArchiveQuery(tool="get_topics", chat_id=FORUM, offset=result["next_offset"]))
        found.update(t["topic_id"] for t in result["topics"])
    assert result["complete"] and len(found) == 212


def test_every_mcp_tool_declares_output_and_media_returns_an_image(store):
    from mcp import Client
    from tgwitness.mcp_server import build_server
    digest = save_media(store, CHAT, image("blue"))

    async def request(token, query=None, address=None):
        if query is None:
            return {"tools": list(MCP_TOOLS)}
        return reader(store).read(ArchiveQuery.model_validate(query))

    async def scenario():
        async with Client(build_server(SimpleNamespace(request=request), "tgw_mcp_synthetic")) as client:
            tools = (await client.list_tools()).tools
            assert {t.name for t in tools} == set(MCP_TOOLS)
            assert all(t.output_schema for t in tools), [t.name for t in tools if not t.output_schema]
            assert all(t.annotations.read_only_hint for t in tools)
            media = await client.call_tool("get_media", {"media_sha256": digest})
            assert [c.type for c in media.content][:1] == ["image"] and not media.is_error
            assert media.structured_content["media_sha256"] == digest and "data_base64" not in str(media.structured_content)
            day = await client.call_tool("get_messages_by_date", {"chat_id": CHAT, "date": "2026-10-25",
                                                                  "timezone": "Europe/Kyiv"})
            assert not day.is_error and len(day.structured_content["items"]) == 3
    asyncio.run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
