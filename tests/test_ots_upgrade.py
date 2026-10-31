import asyncio
import hashlib
import os
import time
import zipfile

import pytest

from tgwitness import anchoring, netclient
from tgwitness.evidence import export_file, retain_checkpoint
from tgwitness.network import NetworkConfig, NoRoute
from tgwitness.verify import OTS_BITCOIN, OTS_MAGIC, OTS_PENDING, ots_summary, verify_bundle

URI = "https://calendar.example"
SETTINGS = {"ots_calendars": [URI]}


def attestation(tag, payload):
    return b"\x00" + tag + anchoring.ots_integer(len(payload)) + payload


def pending(uri=URI):
    data = uri.encode()
    return attestation(OTS_PENDING, anchoring.ots_integer(len(data)) + data)


BITCOIN = attestation(OTS_BITCOIN, anchoring.ots_integer(850000))


def receipt(journal, tree=None, old=True):
    store, vault = journal
    if not store.stats()["total"]:
        store.append("test", {"synthetic": True})
    retain_checkpoint(store, vault)
    stem, source, _ = anchoring.latest_checkpoint(store)
    digest = hashlib.sha256(source.read_bytes()).digest()
    folder = store.root / "checkpoints" / "anchors"
    folder.mkdir(exist_ok=True)
    path = folder / (stem + ".calendar.example.ots")
    path.write_bytes(OTS_MAGIC + b"\x01\x08" + digest + (tree if tree is not None else pending()))
    if old:
        os.utime(path, (time.time() - 7200,) * 2)
    return path, digest


def run(store, settings=SETTINGS):
    return asyncio.run(anchoring.upgrade_pending_ots(store, NetworkConfig(kind="direct"), settings))


def test_upgrade_uses_computed_leaf_commitment_preserves_receipt_and_verifies(journal, monkeypatch):
    store, vault = journal
    path, digest = receipt(journal, b"\xf0\x03abc\x08" + pending())
    original = path.read_bytes()
    leaf = hashlib.sha256(digest + b"abc").hexdigest()
    calls = []

    async def answer(method, url, network, headers, **kwargs):
        calls.append(url)
        assert method == "GET" and url == URI + "/timestamp/" + leaf
        assert network.kind == "direct" and kwargs["limit"] == 10000
        return 200, {}, b"\x08" + BITCOIN

    monkeypatch.setattr(anchoring, "request", answer)
    result = run(store)
    assert len(result) == 1 and result[0]["ok"]
    assert result[0]["status"] == "bitcoin-unverified"
    assert ots_summary(path.read_bytes(), digest)["status"] == "bitcoin-unverified"
    assert path.with_suffix(".ots.pending").read_bytes() == original
    record = store.events(kind="anchor.upgraded")[0]
    assert record["payload"]["before_sha256"] == hashlib.sha256(original).hexdigest()
    assert record["payload"]["after_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record["signature"] and "structure only" in record["payload"]["verification"]
    bundle = export_file(store, vault, "zip")
    assert verify_bundle(bundle)["events"] == store.stats()["total"]
    with zipfile.ZipFile(bundle) as archive:
        assert archive.read("anchors/" + path.name) == path.read_bytes()
        assert archive.read("anchors/" + path.name + ".pending") == original
    run(store)
    assert len(calls) == 1


@pytest.mark.parametrize("answer", [pending(), b"invalid", b"\xff" + pending(), BITCOIN + b"trailing"])
def test_pending_or_invalid_answer_never_replaces_receipt(journal, monkeypatch, answer):
    store, _ = journal
    path, _ = receipt(journal)
    original = path.read_bytes()

    async def respond(*args, **kwargs):
        return 200, {}, answer

    monkeypatch.setattr(anchoring, "request", respond)
    result = run(store)
    assert path.read_bytes() == original and not path.with_suffix(".ots.pending").exists()
    assert not store.events(kind="anchor.upgraded")
    if answer != pending():
        assert result and not result[0]["ok"]


def test_failure_and_recent_receipt_do_not_replace_or_retry_immediately(journal, monkeypatch):
    store, _ = journal
    path, _ = receipt(journal, old=False)
    calls = []

    async def fail(*args, **kwargs):
        calls.append(args)
        raise OSError("Synthetic calendar unavailable")

    monkeypatch.setattr(anchoring, "request", fail)
    assert run(store) == [] and not calls
    os.utime(path, (time.time() - 7200,) * 2)
    original = path.read_bytes()
    assert run(store)[0]["ok"] is False
    assert path.read_bytes() == original and len(calls) == 1


@pytest.mark.parametrize("uri", ["https://169.254.169.254/latest", "https://localhost", "http://calendar.example",
                                  "https://evil.example", "https://calendar.opentimestamps.org.evil.example"])
def test_proof_calendar_is_not_an_arbitrary_fetch_target(journal, monkeypatch, uri):
    store, _ = journal
    path, _ = receipt(journal, pending(uri))
    original = path.read_bytes()

    async def forbidden(*args, **kwargs):
        raise AssertionError("Unapproved calendar was contacted")

    monkeypatch.setattr(anchoring, "request", forbidden)
    assert run(store) == []
    assert path.read_bytes() == original


def test_configured_calendar_still_obeys_network_ssrf_guard(journal, monkeypatch):
    store, _ = journal
    monkeypatch.delenv("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", raising=False)
    path, _ = receipt(journal)
    original = path.read_bytes()

    async def private_dns(host, port):
        return ["127.0.0.1"]

    async def no_connect(*args, **kwargs):
        raise AssertionError("Private destination was connected")

    monkeypatch.setattr(netclient, "resolve", private_dns)
    monkeypatch.setattr(asyncio, "open_connection", no_connect)
    result = run(store)
    assert result and not result[0]["ok"] and "inside this machine" in result[0]["error"]
    assert path.read_bytes() == original


def test_upgrade_keeps_no_fallback_policy(journal, monkeypatch):
    store, _ = journal
    path, _ = receipt(journal)
    original = path.read_bytes()
    result = asyncio.run(anchoring.upgrade_pending_ots(store, NoRoute("Route unavailable"), SETTINGS))
    assert result and not result[0]["ok"] and result[0]["error"] == "Route unavailable"
    assert path.read_bytes() == original


def test_wrong_digest_and_excessive_tree_are_rejected_before_network(journal, monkeypatch):
    store, _ = journal
    path, _ = receipt(journal)

    async def forbidden(*args, **kwargs):
        raise AssertionError("Invalid proof triggered network access")

    monkeypatch.setattr(anchoring, "request", forbidden)
    for data in (OTS_MAGIC + b"\x01\x08" + b"x" * 32 + pending(), b"x" * (anchoring.OTS_TREE_LIMIT + 1)):
        path.write_bytes(data)
        os.utime(path, (time.time() - 7200,) * 2)
        assert run(store)[0]["ok"] is False
        assert path.read_bytes() == data


def test_tree_merge_preserves_both_branches_and_rejects_mismatched_commitment():
    digest = bytes(range(32))
    first = anchoring.OTSReader(b"\xff" + pending() + b"\x08" + pending()).tree(digest)
    second = anchoring.OTSReader(b"\x08" + BITCOIN).tree(digest)
    anchoring.ots_merge(first, second)
    encoded = anchoring.ots_tree_bytes(first)
    assert ots_summary(OTS_MAGIC + b"\x01\x08" + digest + encoded, digest)["status"] == "bitcoin-unverified"
    with pytest.raises(ValueError, match="commitments differ"):
        anchoring.ots_merge(first, anchoring.OTSReader(pending()).tree(b"x" * 32))
