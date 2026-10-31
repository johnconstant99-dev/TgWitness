"""Adversarial continuity checks; synthetic journals, no Telegram or live servers."""
import asyncio
import hashlib
import sqlite3

import pytest

from tgwitness.capture_proof import capture_head
from tgwitness.continuity import Tree, index_event
from tgwitness.evidence import export_file
from tgwitness.store import Store, canonical
from tgwitness.verify import (MERKLE_EMPTY, MerkleFrontier, cross_check_witness, fingerprint,
                             verify_bundle, verify_consistency, verify_inclusion, verify_witness)
from tgwitness.witness import Witness, export
from test_witness import collector  # noqa: F401


def reference_root(leaves):
    """Direct definition, independently of the database and streaming algorithm."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return hashlib.sha256(b"\x01" + reference_root(leaves[:split]) + reference_root(leaves[split:])).digest()


def test_rfc_tree_roots_inclusion_and_every_small_consistency_range():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE event_tree(start INTEGER,size INTEGER,hash BLOB,PRIMARY KEY(start,size))")
    tree, frontier, leaves = Tree(db), MerkleFrontier(), []
    roots = [MERKLE_EMPTY]
    try:
        for size in range(1, 66):
            digest = hashlib.sha256(str(size).encode()).digest()
            leaves.append(digest)
            index_event(db, size, digest.hex())
            frontier.append(digest.hex())
            roots.append(reference_root(leaves))
            assert tree.root(0, size) == frontier.root() == roots[size]
            for index in range(size):
                proof = tree.inclusion(index, size)
                verify_inclusion(leaves[index].hex(), index, size, roots[size], proof)
                with pytest.raises(ValueError):
                    verify_inclusion("f" * 64, index, size, roots[size], proof)
                with pytest.raises(ValueError):
                    verify_inclusion(leaves[index].hex(), index, size, roots[size], proof + ["f" * 64])
            for first in range(size + 1):
                proof = tree.consistency(first, size)
                verify_consistency(first, size, roots[first], roots[size], proof)
                with pytest.raises(ValueError):
                    verify_consistency(first, size, roots[first], roots[size], proof + ["f" * 64])
                if proof:
                    with pytest.raises(ValueError):
                        verify_consistency(first, size, roots[first], roots[size], proof[:-1])
                    changed = ["f" * 64, *proof[1:]]
                    with pytest.raises(ValueError):
                        verify_consistency(first, size, roots[first], roots[size], changed)
                if first:
                    with pytest.raises(ValueError):
                        verify_consistency(first, size, b"f" * 32, roots[size], proof)
        assert db.execute("SELECT count(*) FROM event_tree").fetchone()[0] < 2 * len(leaves)
    finally:
        db.close()


def test_event_and_merkle_index_roll_back_together_and_migrate_old_database(journal, monkeypatch):
    store, vault = journal
    for i in range(7):
        store.append("message.new", {"text": f"synthetic {i}"})
    with store.snapshot() as snapshot:
        expected = Tree(snapshot.connection).root(0, 7)
    original = index_event

    def failed(connection, *args):
        original(connection, *args)
        raise OSError("synthetic disk failure")

    monkeypatch.setattr("tgwitness.continuity.index_event", failed)
    with pytest.raises(OSError):
        store.append("message.new", {})
    assert store.stats()["total"] == 7
    assert store.db.execute("SELECT max(start) FROM event_tree WHERE size=1").fetchone()[0] == 6
    monkeypatch.setattr("tgwitness.continuity.index_event", original)
    store.db.execute("DROP TABLE event_tree")  # Represents a database from the previous release.
    store.db.commit()
    reopened = Store(store.root)
    try:
        reopened.bind(vault)
        with reopened.snapshot() as snapshot:
            assert Tree(snapshot.connection).root(0, 7) == expected
        reopened.append("message.new", {})
        with reopened.snapshot() as snapshot:
            proof = Tree(snapshot.connection).consistency(7, 8)
            verify_consistency(7, 8, expected, Tree(snapshot.connection).root(0, 8), proof)
    finally:
        reopened.close()


@pytest.mark.parametrize("attack", ["remove", "null", "new_key_signature", "different_nonce", "empty_path", "changed_path",
                                  "wrong_start", "changed_history", "invented_tree", "old_collector"])
def test_rewrite_or_downgrade_never_advances_retained_boundary(journal, tmp_path, monkeypatch, attack):
    store, vault = journal
    for i in range(3):
        store.append("message.new", {"text": f"private synthetic {i}"}, 123, i)
    current, posts = {"attack": False}, []
    forged_root = tmp_path / "forged"
    forged_root.mkdir()
    forged = Store(forged_root)
    forged.bind(vault)  # Attacker owns the collector key, but not the witness key.
    for i in range(5):
        forged.append("message.new", {"text": f"fabricated {i}"}, 123, i)

    async def request(method, url, network, headers, **kwargs):
        source = forged if current["attack"] and attack == "changed_history" else store
        answer = capture_head(source, vault, {}, headers["X-TgWitness-Challenge"],
                              int(headers["X-TgWitness-Consistency-From"]))
        assert "private synthetic" not in str(answer)
        if current["attack"]:
            value = answer["continuity"]
            if attack in ("remove", "old_collector"):
                del answer["continuity"]
            elif attack == "null":
                answer["continuity"] = None
            elif attack == "new_key_signature":
                value["signature"] = vault.sign(b"wrong signed statement")
            elif attack == "different_nonce":
                value["statement"]["challenge"] = "a" * 32
                value["signature"] = vault.sign(canonical(value["statement"]))
            elif attack == "empty_path":
                value["proof"]["consistency"] = []
            elif attack == "changed_path":
                value["proof"]["consistency"][0] = "f" * 64
            elif attack == "wrong_start":
                value["proof"]["from_count"] = 0
            elif attack == "invented_tree":
                value["statement"]["root"] = "f" * 64
                value["signature"] = vault.sign(canonical(value["statement"]))
        return 200, {}, canonical(answer)

    async def send(text):
        posts.append(text)
        return len(posts)

    monkeypatch.setattr("tgwitness.witness.request", request)
    witness = Witness(tmp_path / "w", "https://collector.invalid", "synthetic-token", send=send, post="problems",
                      pinned=fingerprint(vault.public_key))
    try:
        first = asyncio.run(witness.tick())
        assert first["payload"]["continuity_status"] == "baseline"
        retained = witness.store.get_setting("last_tree")
        for i in range(3, 5):
            store.append("message.new", {"text": f"private synthetic {i}"}, 123, i)
        current["attack"] = True
        failed = asyncio.run(witness.tick())
        assert failed["payload"]["status"] == "invalid"
        assert witness.store.get_setting("last_tree") == retained
        assert witness.store.get_setting("last_seen")["event_count"] == 3
        assert len(posts) == 1
        witness.close()
        witness = Witness(tmp_path / "w", "https://collector.invalid", "synthetic-token", send=send, post="problems")
        current["attack"] = False
        recovered = asyncio.run(witness.tick())
        assert recovered["payload"]["status"] == "ok"
        assert recovered["payload"]["continuity_status"] == "extended"
        assert witness.store.get_setting("last_tree")["event_count"] == 5
        assert recovered["payload"]["capture_delta"]["message.new"] == 2
    finally:
        witness.close()
        forged.close()
    archive = tmp_path / "witness.zip"
    export(tmp_path / "w", archive)
    seen = verify_witness(archive)
    assert [a["status"] for a in seen["anchors"]] == ["ok", "invalid", "ok"]
    evidence = export_file(store, vault, "zip")
    try:
        checked = cross_check_witness(seen, evidence, verify_bundle(evidence))
        assert not checked["conflicts"]
        assert checked["continuity_verified_through_event"] == 5
        assert checked["export_head_witnessed"]
    finally:
        evidence.unlink()


def test_snapshot_proof_is_atomic_and_legacy_key_has_explicit_baseline(journal, tmp_path, monkeypatch):
    from contextlib import contextmanager

    store, vault = journal
    store.append("message.new", {})
    witness = Witness(tmp_path / "w", "https://collector.invalid", "synthetic-token")
    try:
        witness.check(capture_head(store, vault, {}))  # Retained pre-upgrade checkpoint.
        original = store.snapshot

        @contextmanager
        def racing():
            with original() as snapshot:
                store.append("message.new", {})
                yield snapshot

        monkeypatch.setattr(store, "snapshot", racing)
        answer = capture_head(store, vault, {}, "b" * 32, 1)
        checked = witness.check(answer)
        assert checked["event_count"] == 1 and store.stats()["total"] == 2
        assert checked["continuity_status"] == "baseline"
        monkeypatch.setattr(store, "snapshot", original)
        next_answer = capture_head(store, vault, {}, "c" * 32, 1)
        assert witness.check(next_answer)["continuity_status"] == "extended"
    finally:
        witness.close()


def test_merkle_cache_is_not_trusted_when_verifying_export(journal, tmp_path):
    store, vault = journal
    for i in range(3):
        store.append("message.new", {"text": str(i)})
    # An attacker can edit this cache and sign its root. The real event stream
    # must nevertheless match that root during offline verification.
    store.db.execute("UPDATE event_tree SET hash=? WHERE start=0 AND size=2", (b"f" * 32,))
    store.db.commit()

    async def fetch():
        return capture_head(store, vault, {}, "a" * 32, 0)

    witness = Witness(tmp_path / "w", "https://collector.invalid", "synthetic-token", fetch=fetch)
    try:
        assert asyncio.run(witness.tick())["payload"]["status"] == "ok"  # First baseline has no prior root.
    finally:
        witness.close()
    archive = tmp_path / "witness.zip"
    export(tmp_path / "w", archive)
    evidence = export_file(store, vault, "zip")
    try:
        checked = cross_check_witness(verify_witness(archive), evidence, verify_bundle(evidence))
        assert len(checked["conflicts"]) == 1
        assert not checked["export_head_witnessed"]
    finally:
        evidence.unlink()


def test_api_continuity_is_read_only_content_free_and_bounded(request):
    client, app = request.getfixturevalue("collector")
    token = client.post("/api/witness/tokens", json={"label": "synthetic verifier"}).json()["token"]
    app.state.store.append("message.new", {"text": "private synthetic marker"}, 123, 1)
    headers = {"Authorization": "Bearer " + token, "X-TgWitness-Challenge": "a" * 32,
               "X-TgWitness-Consistency-From": "0"}
    response = client.get("/api/witness/head", headers=headers)
    assert response.status_code == 200 and response.json()["continuity"]
    assert "private synthetic marker" not in response.text
    for bad in ("-1", "1.2", "9" * 100, "9223372036854775808"):
        assert client.get("/api/witness/head", headers={**headers, "X-TgWitness-Consistency-From": bad}).status_code == 400
    assert client.get("/api/events", headers=headers).status_code == 401


def test_failed_first_witness_commit_retains_neither_pin_nor_tree(journal, tmp_path, monkeypatch):
    store, vault = journal
    store.append("message.new", {})

    async def fetch():
        return capture_head(store, vault, {}, "b" * 32, 0)

    witness = Witness(tmp_path / "w", "https://collector.invalid", "synthetic-token", fetch=fetch)
    original = witness.store.append

    def fail_anchor(kind, *args, **kwargs):
        if kind == "witness.anchor":
            raise OSError("synthetic failed witness write")
        return original(kind, *args, **kwargs)

    try:
        monkeypatch.setattr(witness.store, "append", fail_anchor)
        assert asyncio.run(witness.tick())["kind"] == "witness.no_response"
        assert witness.pinned is None
        assert witness.store.get_setting("last_tree") is None
        assert witness.store.get_setting("last_seen") is None
        assert witness.store.get_setting("collector_fingerprint") is None
        monkeypatch.setattr(witness.store, "append", original)
        assert asyncio.run(witness.tick())["payload"]["continuity_status"] == "baseline"
    finally:
        witness.close()
