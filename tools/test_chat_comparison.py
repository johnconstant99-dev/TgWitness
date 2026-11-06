import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tgwitness import verify


def row():
    return {"id": 42, "type": "message", "from_id": 1001, "from": "Fixture sender",
            "date": "2026-11-05T10:00:00+00:00", "date_unixtime": 1793872800,
            "text": "Yes", "reply_to_message_id": 10, "edited": None}


def archive(path, rows, *, account=7, chat=-1000000000042, verify_contents=True):
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    data = ('{\n"messages": [\n' + ',\n'.join(json.dumps(r, ensure_ascii=False) for r in rows)
            + '\n]\n}\n').encode("utf-8")
    manifest = {"format": "tgwitness-chat-export-v1", "public_key": public,
                "account": {"id": account}, "chat": {"id": chat},
                "exported_at": "2026-11-06T00:00:00+00:00", "message_count": len(rows),
                "files": {"chat.json": hashlib.sha256(data).hexdigest()}}
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("chat.json", data)
        bundle.writestr("manifest.json", verify.canonical(manifest))
        bundle.writestr("manifest.sig", base64.b64encode(key.sign(verify.canonical(manifest))))
    pin = verify.fingerprint(public)
    if verify_contents:
        assert verify.verify_chat_export(path, pin)["key_pinned"]
    return path, pin


def compared(tmp_path, first, second, **second_scope):
    a, a_pin = archive(tmp_path / "first.zip", [first])
    b, b_pin = archive(tmp_path / "second.zip", [second], **second_scope)
    return verify.compare_chat_exports(a, b, a_pin, b_pin)


@pytest.mark.parametrize(("field", "value"), [
    ("reply_to_message_id", 20),
    ("from_id", 1002),
    ("date", "2026-11-05T20:00:00+00:00"),
    ("date_unixtime", 1793908800),
    ("text", "No"),
    ("from", "Different saved display name"),
    ("reply_to", {"reply_to_msg_id": 20, "quote_text": "A different question"}),
    ("text_entities", [{"type": "text_link", "text": "Yes", "href": "https://example.invalid/a"}]),
    ("forwarded_from", {"from_id": 999}),
    ("future_field", {"nested": [1, "captured but not yet interpreted"]}),
], ids=lambda value: value if isinstance(value, str) and len(value) < 25 else None)
def test_same_number_compares_every_saved_field(tmp_path, field, value):
    before = row()
    after = {**before, field: value}
    result = compared(tmp_path, before, after)
    assert len(result["changed"]) == 1 and result["unchanged"] == 0, result
    assert result["changed"][0]["changed_fields"] == [field]
    assert result["first"]["key_pinned"] and result["second"]["key_pinned"]


@pytest.mark.parametrize("structured", [False, True])
def test_text_after_preview_boundary_is_compared(tmp_path, structured):
    before, after = row(), row()
    before["text"], after["text"] = "x" * 300 + " received", "x" * 300 + " declined"
    if structured:
        before["text"] = ["x" * 300, {"type": "bold", "text": " received"}]
        after["text"] = ["x" * 300, {"type": "bold", "text": " declined"}]
    result = compared(tmp_path, before, after)
    assert len(result["changed"]) == 1 and result["unchanged"] == 0, result
    assert result["changed"][0]["changed_fields"] == ["text"]
    assert len(result["changed"][0]["first"]["text"]) == 300


def test_identical_json_ignores_object_key_order(tmp_path):
    before = row()
    before["future_field"] = {"a": 1, "b": 2}
    after = dict(reversed(list(before.items())))
    after["future_field"] = {"b": 2, "a": 1}
    result = compared(tmp_path, before, after)
    assert result["unchanged"] == 1 and result["changed"] == []


@pytest.mark.parametrize(("first", "second"), [(None, "missing"), (True, 1), ([1, 2], [2, 1])])
def test_presence_json_type_and_array_order_matter(tmp_path, first, second):
    before, after = row(), row()
    before["future_field"] = first
    if second != "missing":
        after["future_field"] = second
    result = compared(tmp_path, before, after)
    assert len(result["changed"]) == 1 and result["unchanged"] == 0, result


def test_content_matching_uses_complete_text(tmp_path):
    before, after = row(), row()
    before["text"], after["text"] = "x" * 300 + "A", "x" * 300 + "B"
    result = compared(tmp_path, before, after, account=8)
    assert len(result["only_first"]) == len(result["only_second"]) == 1, result
    assert result["matched"] == 0 and result["unchanged"] == 0


def test_content_correspondence_is_not_full_record_equality(tmp_path, capsys):
    before, after = row(), row()
    after.update(id=99, reply_to_message_id=20, date="2026-11-05T10:00:01+00:00", date_unixtime=1793872801)
    result = compared(tmp_path, before, after, account=8)
    assert result["method"] == "content" and result["matched"] == 1
    assert result["unchanged"] == 0 and len(result["changed"]) == 1
    verify.print_comparison(result)
    output = capsys.readouterr().out
    assert "Matched: 1" in output and "Unchanged:" not in output


def test_missing_scope_identity_does_not_assert_number_match(tmp_path):
    a, pin_a = archive(tmp_path / "a.zip", [row()], account=None)
    b, pin_b = archive(tmp_path / "b.zip", [row()], account=None)
    result = verify.compare_chat_exports(a, b, pin_a, pin_b)
    assert result["method"] == "content" and result["matched"] == 1
    assert result["unchanged"] == 1  # Equal saved records do not establish a numbered message match.


def test_duplicate_message_numbers_are_rejected(tmp_path):
    a, pin_a = archive(tmp_path / "a.zip", [row(), {**row(), "text": "Conflicting duplicate"}], verify_contents=False)
    b, pin_b = archive(tmp_path / "b.zip", [row()])
    with pytest.raises(ValueError, match="Duplicate message ID"):
        verify.compare_chat_exports(a, b, pin_a, pin_b)


@pytest.mark.parametrize("account", [7, 8])
def test_unparsed_records_are_not_silently_dropped(tmp_path, account):
    before = {**row(), "type": "unparsed", "unparsed": {"constructor": "11111111"}}
    after = {**before, "unparsed": {"constructor": "22222222"}}
    result = compared(tmp_path, before, after, account=account)
    assert result["first"]["messages"] == result["second"]["messages"] == 1
    if account == 7:
        assert result["unchanged"] == 0 and result["changed"][0]["changed_fields"] == ["unparsed"]
    else:
        assert result["matched"] == 0
        assert len(result["only_first"]) == len(result["only_second"]) == 1


def test_cli_names_metadata_difference_and_runs_standalone(tmp_path):
    a, pin_a = archive(tmp_path / "a.zip", [row()])
    b, pin_b = archive(tmp_path / "b.zip", [{**row(), "reply_to_message_id": 20}])
    command = [sys.executable, "-I", str(Path(verify.__file__)), str(a), "--compare", str(b),
               "--fingerprint", pin_a, "--compare-fingerprint", pin_b]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    assert "Changed: 1" in result.stdout and "Unchanged: 0" in result.stdout
    assert "reply_to_message_id" in result.stdout


def test_signatures_and_pins_still_checked_before_comparison(tmp_path):
    a, pin_a = archive(tmp_path / "a.zip", [row()])
    b, pin_b = archive(tmp_path / "b.zip", [row()])
    with pytest.raises(ValueError, match="independently trusted fingerprint"):
        verify.compare_chat_exports(a, b, pin_b, pin_b)
    with zipfile.ZipFile(b) as bundle:
        files = {name: bundle.read(name) for name in bundle.namelist()}
    manifest = json.loads(files["manifest.json"])
    manifest["account"]["id"] = 999
    files["manifest.json"] = verify.canonical(manifest)
    with zipfile.ZipFile(b, "w") as bundle:
        for name, data in files.items():
            bundle.writestr(name, data)
    with pytest.raises(InvalidSignature):
        verify.compare_chat_exports(a, b, pin_a, pin_b)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
