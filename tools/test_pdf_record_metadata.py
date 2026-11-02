"""Printed evidence must keep permitted message context and distinguish hashes/times."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import pdf_report, report


SAY = report.Words("en")


class ReadingCopy:
    def __init__(self):
        self.lines = []

    def text(self, text, **kwargs):
        self.lines.append(str(text))

    def heading(self, text):
        self.lines.append(str(text))

    def gap(self, *args):
        pass

    def diff(self, before, after):
        self.lines.extend((before, after))

    @property
    def body(self):
        return "\n".join(self.lines)


def event(kind="message.new", **payload):
    return {"seq": 7, "kind": kind, "chat_id": -10001, "message_id": 21,
            "actor_id": 999, "observed_at": "2026-10-12T10:05:00Z", "source_at": None,
            "hash": "a" * 64, "payload": {"text": "A synthetic observation.", **payload}}


def rendered(*events):
    copy = ReadingCopy()
    pdf_report.records(copy, SAY, iter(events), {-10001: "Example chat"}, {})
    return copy.body


def details():
    return {"reply_to_message_id": 11, "reply_to_top_id": 4, "reply_to_peer_id": -10002,
            "quote_text": "The previous instruction.",
            "forwarded_from": {"from_id": -10003, "from_name": "Example source", "date": "2026-10-01T08:00:00Z",
                               "channel_post": 31, "post_author": "Example signature", "saved_from_id": -10004,
                               "saved_from_message_id": 41, "imported": True},
            "text_entities": [{"type": "text_link", "text": "project.example", "href": "https://other.example/target",
                               "deceptive": True}, {"type": "mention_name", "text": "Example participant", "user_id": 45},
                              {"type": "link", "text": "https://plain.example/notice"}],
            "buttons": {"rows": [[{"type": "url", "text": "Open notice", "url": "https://project.example/notice"},
                                     {"type": "copy", "text": "Copy reference", "copy_text": "EXAMPLE-014"}]]},
            "via_bot_id": 51, "author": "Example editor", "views": 0, "forwards": 0, "replies": 0,
            "reactions": [{"reaction": "👍", "count": 3}], "auto_delete_seconds": 86400,
            "protected": True, "album_id": 91,
            "media_info": {"kind": "MessageMediaDocument", "file_name": "example-video.mp4", "mime_type": "video/mp4",
                           "size": 4096, "width": 1920, "height": 1080, "duration_seconds": 32,
                           "document_id": 71, "self_destruct_seconds": 60}}


def test_ordinary_record_prints_three_independent_time_bases_and_sender_id_only():
    output = rendered(event(sender_id=42, sent_at="2026-10-12T08:00:00-01:00", edited_at="2026-10-12T10:02:00Z"))
    assert "Observed: 2026-10-12 10:05:00 UTC" in output
    assert "Sent: 2026-10-12 09:00:00 UTC" in output
    assert "Edited: 2026-10-12 10:02:00 UTC" in output
    assert "User 42" in output
    assert "999" not in output, "actor_id must never be substituted for the message sender"


def test_ordinary_transcript_preserves_reply_forward_entities_buttons_and_reach():
    output = rendered(event(details=details()))
    for expected in ("Reply to: #11", "Reply thread: #4", "Chat of the original message: -10002", "The previous instruction.",
                     "Example source", "ID -10003", "Original message: #31", "Saved from chat: -10004",
                     "Saved from message: #41", "Imported message", "2026-10-01 08:00:00 UTC",
                     "https://other.example/target", "different address", "user ID 45", "https://plain.example/notice",
                     "Open notice", "https://project.example/notice", "EXAMPLE-014", "via bot ID 51",
                     "views: 0", "forwards: 0", "replies: 0", "👍 3", "1 d", "saving and forwarding restricted"):
        assert expected in output, expected


def test_ordinary_transcript_preserves_media_metadata_and_album():
    output = rendered(event(details=details()))
    for expected in ("example-video.mp4", "video/mp4", "1920 × 1080", "32 s", "Media ID: 71",
                     "Self-destruct timer: 1 min", "Album ID: 91"):
        assert expected in output, expected


def test_saved_attachment_hash_is_distinct_from_the_journal_record_hash():
    output = rendered(event("media.saved", media_sha256="b" * 64, original_name="example.pdf", mime_type="application/pdf", size=2048))
    assert "File SHA-256: " + "b" * 64 in output
    assert "Record hash · SHA-256 " + "a" * 64 in output
    assert output.count("b" * 64) == 1


@pytest.mark.parametrize("permitted", [{}, None, []])
def test_explicit_withheld_details_never_recover_private_raw_metadata(permitted):
    source = event(details=permitted, text=None, text_withheld=True,
                   raw={"message": "PRIVATE RAW MESSAGE", "fwd_from": {"from_name": "PRIVATE FORWARD"},
                        "reply_to": {"reply_to_msg_id": 778899, "quote_text": "PRIVATE QUOTE"},
                        "media": {"_": "MessageMediaWebPage", "webpage": {"url": "https://private.example/secret"}}})
    source["minimised"] = ["raw", "text"]
    original = deepcopy(source)
    output = rendered(source)
    assert "Text withheld in this extract" in output
    assert "PRIVATE" not in output and "private.example" not in output and "778899" not in output
    assert source == original


def test_permitted_alias_is_not_replaced_by_an_identity_from_raw():
    source = event(sender_id=None, sender_observation={"display_name": "Participant 01"},
                   details={"forwarded_from": {"from_id": "Participant 02"}},
                   raw={"from_id": {"_": "PeerUser", "user_id": 123456789}, "fwd_from": {"from_name": "PRIVATE NAME"}})
    source["minimised"] = ["raw", "sender"]
    output = rendered(source)
    assert "Participant 01" in output and "Participant 02" in output
    assert "PRIVATE NAME" not in output and "123456789" not in output


def test_old_payload_without_projection_uses_only_supported_normalized_metadata():
    source = event(reply_to_message_id=81, raw={"message": "Example", "views": 0,
        "reply_to": {"_": "MessageReplyHeader", "reply_to_msg_id": 81, "reply_to_top_id": 70},
        "media": {"_": "MessageMediaDocument", "document": {"id": 23, "size": 1024, "mime_type": "text/plain",
             "access_hash": "PRIVATE ACCESS HASH", "file_reference": "PRIVATE FILE REFERENCE",
             "attributes": [{"_": "DocumentAttributeFilename", "file_name": "example.txt"}]}}})
    output = rendered(source)
    assert "example.txt" in output and "views: 0" in output
    assert "Reply to: #81" in output and "Reply thread: #70" in output
    assert "PRIVATE" not in output


def test_histories_keep_sent_and_edited_times_and_legacy_generic_time():
    newer = {"seq": 2, "kind": "message.edited", "observed_at": "2026-10-12T10:05:00Z", "text": "Changed text",
             "sent_at": "2026-10-12T09:00:00Z", "edited_at": "2026-10-12T10:02:00Z",
             "telegram_at": "2026-10-12T10:02:00Z", "details": details(), "sender": {}, "sender_id": None}
    older = {"seq": 1, "kind": "message.new", "observed_at": "2026-10-12T09:01:00Z", "text": "Original text",
             "telegram_at": "2026-10-12T09:00:00Z", "details": {}, "sender": {}, "sender_id": None}
    copy = ReadingCopy()
    pdf_report.changes(copy, SAY, {"messages_changed": 1, "listed": 1,
        "messages": [{"chat_id": -10001, "message_id": 21, "versions": [older, newer], "gone": []}]}, {})
    assert "Sent: 2026-10-12 09:00:00 UTC" in copy.body
    assert "Edited: 2026-10-12 10:02:00 UTC" in copy.body
    assert "Telegram time: 2026-10-12 09:00:00 UTC" in copy.body
    assert "Original text" in copy.body and "Changed text" in copy.body and "example-video.mp4" in copy.body


def test_unknown_times_and_reactions_are_not_invented_and_false_reply_ids_are_rejected():
    output = rendered(event(sent_at=None, edited_at=None, details={"reply_to_message_id": True, "replies": 0}))
    assert "Sent:" not in output and "Edited:" not in output and "Telegram time:" not in output
    assert "Reply to:" not in output and "replies: 0" in output and "reactions:" not in output


def test_quote_metadata_keeps_false_zero_and_literal_targets_without_pdf_actions():
    source = event(details={"forum_topic": False, "quote_text": "Quoted <script>example</script>", "quote_offset": 0,
                            "quote_entities": [{"type": "text_link", "text": "Example target",
                                                "href": "javascript:example()"},
                                               {"type": "mention_name", "text": "Participant 01", "user_id": "P01"}]})
    original = deepcopy(source)
    output = rendered(source)
    for expected in ("Forum topic: No", "Quote offset (UTF-16): 0", "Quoted <script>example</script>",
                     "Example target", "javascript:example()", "Participant 01", "user ID P01"):
        assert expected in output, expected
    pdf = pdf_report.document(SAY, "Synthetic quote metadata")
    pdf.add_page()
    pdf_report.records(pdf_report.Layout(pdf, SAY), SAY, iter((source,)), {}, {})
    document = bytes(pdf.output())
    assert document.startswith(b"%PDF-")
    assert b"/URI" not in document and b"/JavaScript" not in document
    assert source == original


def test_missing_quote_metadata_is_not_invented_and_boolean_offset_is_not_zero():
    assert "Forum topic:" not in rendered(event(details={"forum_topic": None}))
    output = rendered(event(details={"forum_topic": True, "quote_text": "A saved quote", "quote_offset": False}))
    assert "Forum topic: Yes" in output and "Quote offset (UTF-16)" not in output
    assert "Links behind the text" not in output


def test_real_native_pdf_wraps_long_permitted_metadata_without_mutating_records():
    source = event(details=details(), sent_at="2026-10-12T09:00:00Z", edited_at="2026-10-12T10:02:00Z")
    source["payload"]["details"]["quote_text"] = "مثال آمن للمراجعة · Synthetic quote " * 80
    source["payload"]["details"]["text_entities"][0]["href"] = "https://example.invalid/" + "long-path/" * 100
    original = deepcopy(source)
    pdf = pdf_report.document(SAY, "Synthetic metadata regression")
    pdf.add_page()
    layout = pdf_report.Layout(pdf, SAY)
    pdf_report.records(layout, SAY, iter([source] * 3), {}, {})
    assert pdf.get_y() <= pdf.page_break_trigger + 1
    assert len(pdf.pages) >= 2
    assert bytes(pdf.output()).startswith(b"%PDF-")
    assert source == original


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
