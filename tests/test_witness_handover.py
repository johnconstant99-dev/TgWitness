"""Adversarial handovers using disposable journals and keys; no live services."""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tgwitness.evidence import checkpoint, export_file
from tgwitness.store import Store
from tgwitness.verify import check_channel, cross_check_witness, fingerprint, verify_bundle, verify_witness
from tgwitness.witness import Witness, export as export_witness


@pytest.fixture
def handover(journal, tmp_path):
    store, vault = journal
    paths = []

    async def fetch():
        return {"checkpoint": checkpoint(store, vault)}

    witness = Witness(tmp_path / "witness", "https://collector.invalid", "synthetic-token", fetch=fetch)
    asyncio.run(witness.run(ticks=1))

    def capture():
        asyncio.run(witness.tick())

    def bundles():
        evidence = export_file(store, vault, "zip")
        paths.append(evidence)
        witness_zip = tmp_path / "witness.zip"
        export_witness(tmp_path / "witness", witness_zip)
        return evidence, witness_zip

    yield store, vault, witness, capture, bundles
    witness.close()
    for path in paths:
        path.unlink(missing_ok=True)


def cli(evidence, witness=None, witness_key=None, *extra):
    args = [sys.executable, str(Path(__file__).resolve().parents[1] / "tgwitness/verify.py"), str(evidence)]
    if witness:
        args += ["--witness", str(witness)]
    if witness_key:
        args += ["--witness-fingerprint", witness_key]
    return subprocess.run([*args, *extra], capture_output=True, text=True, errors="replace")


def test_unwitnessed_tail_cannot_pass_required_witness_handover(handover):
    store, _vault, witness, capture, bundles = handover
    store.append("message.new", {"text": "first synthetic record"}, 123, 1)
    capture()
    store.append("message.new", {"text": "not yet witnessed"}, 123, 2)
    evidence, witness_zip = bundles()
    result = cross_check_witness(verify_witness(witness_zip), evidence, verify_bundle(evidence))
    assert result["verified_through_event"] == 1
    assert result["unwitnessed_events"] == 1
    assert result["export_head_witnessed"] is False
    ordinary = cli(evidence, witness_zip, witness.fingerprint)
    assert ordinary.returncode == 0
    assert "1 trailing record(s) have no matching witness checkpoint" in ordinary.stdout
    strict = cli(evidence, witness_zip, witness.fingerprint, "--require-witness")
    assert strict.returncode == 1 and "exported journal head" in strict.stderr

    capture()
    evidence, witness_zip = bundles()
    strict = cli(evidence, witness_zip, witness.fingerprint, "--require-witness")
    assert strict.returncode == 0, strict.stderr
    assert '"export_head_witnessed": true' in strict.stdout


def test_later_checkpoints_do_not_expand_the_verified_export_period(handover):
    store, _vault, _witness, capture, bundles = handover
    store.append("message.new", {"text": "included"}, 123, 1)
    capture()
    evidence, _ = bundles()
    store.append("message.new", {"text": "outside this export"}, 123, 2)
    capture()
    _, witness_zip = bundles()
    seen = verify_witness(witness_zip)

    for i, anchor in enumerate(seen["anchors"]):
        anchor["at"] = f"2026-10-30T12:0{i}:00+00:00"
    result = cross_check_witness(seen, evidence, verify_bundle(evidence))
    assert result["after_export"] == 1
    assert result["witnessed"][-1]["to"] == seen["anchors"][-2]["at"]
    assert result["verified_through_event"] == 1
    assert result["export_head_witnessed"] is True


def test_copied_collector_key_cannot_rewrite_a_retained_witness_prefix(handover, tmp_path):
    store, vault, witness, capture, bundles = handover
    store.append("message.new", {"text": "original synthetic observation"}, 123, 1)
    retained = checkpoint(store, vault)
    capture()
    _, witness_zip = bundles()
    (tmp_path / "forged").mkdir()
    forged_store = Store(tmp_path / "forged")
    forged_store.bind(vault)
    forged_store.append("message.new", {"text": "fabricated replacement"}, 123, 1)
    forged = export_file(forged_store, vault, "zip")
    try:
        verified = verify_bundle(forged, fingerprint(vault.public_key))
        assert verified["key_pinned"]
        with pytest.raises(ValueError, match="disagrees with the retained checkpoint"):
            verify_bundle(forged, fingerprint(vault.public_key), retained)
        checked = cross_check_witness(verify_witness(witness_zip), forged, verified)
        assert len(checked["conflicts"]) == 1
        assert checked["export_head_witnessed"] is False
        shown = cli(forged, witness_zip, witness.fingerprint, "--require-witness")
        assert shown.returncode == 1 and "differs from what the witness saw" in shown.stderr
    finally:
        forged_store.close()
        forged.unlink()


@pytest.mark.parametrize("missing", ["witness", "fingerprint"])
def test_required_witness_needs_archive_and_independently_pinned_key(handover, missing):
    store, _vault, witness, capture, bundles = handover
    store.append("message.new", {"text": "synthetic"}, 123, 1)
    capture()
    evidence, witness_zip = bundles()
    shown = cli(evidence, None if missing == "witness" else witness_zip,
                None if missing == "fingerprint" else witness.fingerprint, "--require-witness")
    assert shown.returncode != 0
    assert "requires --witness and --witness-fingerprint" in shown.stderr


def test_empty_channel_file_does_not_satisfy_requested_external_posts(handover, tmp_path):
    store, _vault, witness, capture, bundles = handover
    store.append("message.new", {"text": "synthetic"}, 123, 1)
    capture()

    anchor = witness.store.events(kind="witness.anchor")[0]
    witness.store.append("witness.posted", {"record": anchor["seq"], "message_id": 101})
    evidence, witness_zip = bundles()
    channel = tmp_path / "channel.json"
    channel.write_text(json.dumps({"messages": []}), encoding="utf-8")
    shown = cli(evidence, witness_zip, witness.fingerprint, "--require-witness", "--channel", str(channel))
    assert shown.returncode == 1 and "channel" in shown.stderr.lower()


def test_signed_post_does_not_authenticate_a_changed_export_date(handover, tmp_path):
    _store, _vault, witness, _capture, bundles = handover
    event = witness.store.events(kind="witness.anchor")[0]
    channel = tmp_path / "channel.json"
    text = witness.post_text(event)
    _, witness_zip = bundles()
    seen = verify_witness(witness_zip, witness.fingerprint)
    for date in ("2026-10-30T12:00:00", "2001-01-01T00:00:00"):
        channel.write_text(json.dumps({"messages": [{"id": 1, "date": date, "text": text}]}), encoding="utf-8")
        checked = check_channel(seen, channel)
        assert checked["matching"] == 1
        assert checked["post_date_verification"] == "not-performed"
        assert checked["telegram_post_dates"][event["seq"]] == date


def test_channel_must_include_a_post_for_the_actual_export_boundary(handover, tmp_path):
    store, _vault, witness, capture, bundles = handover
    early = witness.store.events(kind="witness.anchor")[0]
    store.append("message.new", {"text": "synthetic later record"}, 123, 1)
    capture()
    evidence, witness_zip = bundles()
    channel = tmp_path / "channel.json"
    channel.write_text(json.dumps({"messages": [{"id": 1, "text": witness.post_text(early)}]}), encoding="utf-8")
    shown = cli(evidence, witness_zip, witness.fingerprint, "--require-witness", "--channel", str(channel))
    assert shown.returncode == 1 and "export boundary" in shown.stderr


def test_collector_cannot_count_its_own_key_as_independent_witness(journal, tmp_path):
    store, vault = journal
    store.append("message.new", {"text": "synthetic"})
    root = tmp_path / "self-witness"
    root.mkdir()

    (root / "witness-key.json").write_text(json.dumps({"format": "tgwitness-witness-key-v1",
                                                    **vault.read("signing")}), encoding="utf-8")
    self_witness = Store(root)
    try:
        self_witness.bind(vault)
        boundary = checkpoint(store, vault)["statement"]
        self_witness.append("witness.anchor", {"status": "ok", "collector_fingerprint": fingerprint(vault.public_key),
                                              "event_count": boundary["event_count"], "head_hash": boundary["head_hash"]})
    finally:
        self_witness.close()
    witness_zip = tmp_path / "self-witness.zip"
    export_witness(root, witness_zip)
    evidence = export_file(store, vault, "zip")
    try:
        shown = cli(evidence, witness_zip, fingerprint(vault.public_key), "--require-witness")
        assert shown.returncode == 1 and "different trusted signing keys" in shown.stderr
    finally:
        evidence.unlink()
