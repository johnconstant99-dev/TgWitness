import base64
import hashlib
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tgwitness.demo import seed_demo
from tgwitness.store import canonical
from tgwitness.verify import verify_bundle, verify_report


DEMO = Path(__file__).resolve().parents[1] / "website/demo"


def test_demo_keeps_named_authors_and_real_versions(journal):
    store, vault = journal
    seed_demo(store)
    chat = store.chat_messages(-100100002)["messages"]
    assert len({item["sender"]["name"] for item in chat}) == 4
    assert all(item["sender"]["name"] for item in chat)
    edited = next(item for item in chat if item["edited"])
    assert len(edited["versions"]) == 2
    assert "harbor-check.example" in edited["versions"][0]["text"]
    assert "harbor-help.example" in edited["versions"][1]["text"]
    assert all(item["text"] for item in chat if item["deleted"])
    assert store.get_setting("demo") is True
    assert "fictional" in store.get_setting("report_options")["notes"]
    store.verify(vault.public_key)
    count = store.stats()["total"]
    seed_demo(store)
    assert store.stats()["total"] == count


def test_published_demo_downloads_match_the_signed_records():
    answers = json.loads((DEMO / "fixtures.json").read_text(encoding="utf-8"))
    status = json.loads(answers["/api/status"]["text"])
    assert status["demo"] is True
    assert status["collector"]["has_session"] is False
    assert status["collector"]["disk_free_bytes"] is None
    for answer in answers.values():
        if "file" not in answer:
            continue
        path = DEMO / answer["file"]
        assert path.resolve().is_relative_to((DEMO / "downloads").resolve())
        content = path.read_bytes()
        assert len(content) == answer["bytes"]
        assert hashlib.sha256(content).hexdigest() == answer["sha256"]

    archive = DEMO / answers["/api/export/zip"]["file"]
    checkpoint = DEMO / answers["/api/checkpoint"]["file"]
    checked = verify_bundle(archive, checkpoint=json.loads(checkpoint.read_text(encoding="utf-8")))
    assert checked["fingerprint"] == status["fingerprint"]
    assert checked["head_hash"] == status["stats"]["head"]["hash"]
    captured_check = json.loads(answers["/api/verify"]["text"])
    for key in ("events", "head_hash", "fingerprint"):
        assert checked[key] == captured_check[key]
    verify_report(DEMO / answers["/api/export/html"]["file"], expected_fingerprint=checked["fingerprint"])
    with zipfile.ZipFile(archive) as bundle:
        records = bundle.read("events.jsonl")
        assert records == (DEMO / answers["/api/export/jsonl"]["file"]).read_bytes()
        events = [json.loads(line) for line in records.splitlines()]
        assert any(event["kind"] == "demo.created" and event["payload"]["synthetic"] for event in events)
        assert "fictional" in json.loads(bundle.read("manifest.json"))["case"]["notes"]
        for name in bundle.namelist():
            data = bundle.read(name)
            assert b"-----BEGIN " + b"PRIVATE KEY-----" not in data
            assert b"demo-capture-" not in data
            assert b"C:\\\\Users\\\\Administrator" not in data
    receipt = json.loads((DEMO / answers["/api/run-receipt"]["file"]).read_text(encoding="utf-8"))
    Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt["public_key"])).verify(
        base64.b64decode(receipt["signature"]), canonical(receipt["statement"]))
