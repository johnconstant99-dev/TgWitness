import asyncio
import copy
from contextlib import contextmanager
import json

import pytest
from fastapi.testclient import TestClient

from tgwitness.capture_proof import capture_head
from tgwitness.evidence import export_file
from tgwitness.proof import ProofWatcher, create_app, load_config
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, verify_capture, verify_public_proof
from tgwitness.witness import InvalidAnswer, Witness
from tools.verify_live_probe import check_probe


def seeded(root, nonce="TGW-PROBE." + "b" * 24):
    vault, store = Vault(root), Store(root)
    store.bind(vault)
    store.append("message.new", {"text": nonce + " first"}, -100123, 50)
    store.append("message.edited", {"text": nonce + " edited"}, -100123, 50)
    store.append("message.deleted", {}, -100123, 50)
    store.append("collector.heartbeat", {"private_marker": "not-for-public"})
    return store, vault


def test_counters_are_bound_to_prefix_and_authenticated(journal):
    store, vault = journal
    store.append("message.new", {"text": "private text"}, 9, 1)
    store.append("collector.heartbeat", {"account": "private identity"})
    answer = capture_head(store, vault, {"running": True, "connected": True}, "a" * 32)
    statement = verify_capture(answer["capture"], answer["checkpoint"]["statement"])
    assert statement["event_count"] == 2 and statement["counts"]["message.new"] == 1
    assert sum(statement["counts"].values()) == 1
    assert "private" not in json.dumps(answer) and "chat_id" not in json.dumps(answer)
    changed = copy.deepcopy(answer)
    changed["capture"]["statement"]["counts"]["message.new"] += 1
    with pytest.raises(Exception):
        verify_capture(changed["capture"], changed["checkpoint"]["statement"])
    store.append("message.new", {}, 9, 2)
    with pytest.raises(ValueError, match="differs"):
        verify_capture(answer["capture"], capture_head(store, vault, {})["checkpoint"]["statement"])


def test_capture_snapshot_does_not_mix_concurrent_writes(journal, monkeypatch):
    store, vault = journal
    store.append("message.new", {})
    original = store.snapshot
    @contextmanager
    def racing_snapshot():
        with original() as snapshot:
            store.append("message.new", {})
            yield snapshot
    monkeypatch.setattr(store, "snapshot", racing_snapshot)
    answer = capture_head(store, vault, {})
    captured = verify_capture(answer["capture"], answer["checkpoint"]["statement"])
    assert captured["event_count"] == 1 and captured["counts"]["message.new"] == 1
    assert store.stats()["total"] == 2


def test_failed_anchor_commit_does_not_advance_counter_baseline(journal, tmp_path, monkeypatch):
    store, vault = journal
    async def fetch():
        return capture_head(store, vault, {})
    witness = Witness(tmp_path / "w", "http://collector", "secret", pinned=fingerprint(vault.public_key), fetch=fetch)
    try:
        asyncio.run(witness.tick())
        previous = witness.store.get_setting("last_seen")
        store.append("message.new", {})
        original = witness.store.append
        def fail_anchor(kind, *args, **kwargs):
            if kind == "witness.anchor":
                raise OSError("synthetic write failure")
            return original(kind, *args, **kwargs)
        monkeypatch.setattr(witness.store, "append", fail_anchor)
        assert asyncio.run(witness.tick())["kind"] == "witness.no_response"
        assert witness.store.get_setting("last_seen") == previous
        monkeypatch.setattr(witness.store, "append", original)
        assert asyncio.run(witness.tick())["payload"]["capture_delta"]["message.new"] == 1
    finally:
        witness.close()


def test_witness_counts_deltas_and_rejects_replayed_challenge(journal, tmp_path, monkeypatch):
    store, vault = journal
    answers = []
    async def fetch():
        return capture_head(store, vault, {})
    witness = Witness(tmp_path / "w", "http://collector", "secret", fetch=fetch)
    try:
        first = asyncio.run(witness.tick())
        assert first["payload"]["capture_delta"] is None
        store.append("collector.heartbeat", {})
        second = asyncio.run(witness.tick())
        assert second["payload"]["capture_delta"]["message.new"] == 0
        store.append("message.new", {"text": "do not publish"})
        third = asyncio.run(witness.tick())
        assert third["payload"]["capture_delta"]["message.new"] == 1
        post = witness.post_text(third)
        assert "Captured: 1 new" in post and "do not publish" not in post and len(post) < 4096
        async def request(method, url, network, headers, **kwargs):
            answer = capture_head(store, vault, {}, headers["X-TgWitness-Challenge"],
                                  int(headers["X-TgWitness-Consistency-From"]))
            answers.append(answer)
            return 200, {}, canonical(answer)
        monkeypatch.setattr("tgwitness.witness.request", request)
        assert asyncio.run(witness.http_fetch())["capture"]
        async def replay(*args, **kwargs):
            return 200, {}, canonical(answers[0])
        monkeypatch.setattr("tgwitness.witness.request", replay)
        with pytest.raises(InvalidAnswer, match="challenge"):
            asyncio.run(witness.http_fetch())
    finally:
        witness.close()


def test_public_monitor_isolated_accounts_no_secrets_and_offline_verification(tmp_path):
    store, vault = seeded(tmp_path / "collector")
    config = {"title": "Synthetic proof", "interval": 1, "workspaces": [
        {"id": alias, "label": label, "root": tmp_path / alias, "collector": "http://hidden-host",
         "pinned": fingerprint(vault.public_key), "token": "private-token", "interval": 1}
        for alias, label in (("account-a", "Account A"), ("account-b", "<script>bad</script>"))]}
    class Local(ProofWatcher):
        async def http_fetch(self):
            if self.alias == "account-b":
                raise ConnectionError("private-host-and-credentials")
            answer = capture_head(store, vault, {"running": True, "connected": True})
            answer["checkpoint"]["unexpected_private_field"] = "do-not-forward-extensions"
            answer["checkpoint"]["fingerprint"] = "do-not-forward-extensions"
            return answer
    app = create_app(config, Local)
    evidence = export_file(store, vault, "zip")
    try:
        with TestClient(app) as client:
            # Wait for both immediate polling tasks, without touching Telegram.
            import time
            for _ in range(100):
                status = client.get("/api/proof").json()
                if all(r["proof"] for r in status["workspaces"]):
                    break
                time.sleep(.01)
            a, b = status["workspaces"]
            assert a["proof"]["statement"]["status"] == "ok" and b["proof"]["statement"]["status"] == "no_response"
            assert client.get("/healthz").status_code == 200
            serialized = json.dumps(status)
            for secret in ("private-token", "hidden-host", "private-host-and-credentials", "not-for-public", "TGW-PROBE", "do-not-forward-extensions"):
                assert secret not in serialized
            assert client.post("/api/proof").status_code == 405
            assert client.get("/api/proof/missing").status_code == 404
            downloaded = client.get("/api/proof/account-a")
            proof = tmp_path / "proof.json"
            proof.write_bytes(downloaded.content)
            checked = verify_public_proof(proof, fingerprint(vault.public_key), a["witness_fingerprint"], evidence)
            assert checked["evidence_counters_checked"] and checked["counts"]["message.new"] == 1
            with pytest.raises(ValueError, match="trusted fingerprint"):
                verify_public_proof(proof, "0" * 64)
            # A collector can sign false counters, but recounting the export exposes them.
            value = downloaded.json()
            capture = value["statement"]["capture"]
            capture["statement"]["counts"].update({"message.new": 0, "message.edited": 2})
            capture["signature"] = vault.sign(canonical(capture["statement"]))
            value["signature"] = app.state.watchers[0].key.sign(canonical(value["statement"]))
            proof.write_text(json.dumps(value), encoding="utf-8")
            with pytest.raises(ValueError, match="counters differ"):
                verify_public_proof(proof, fingerprint(vault.public_key), a["witness_fingerprint"], evidence)
    finally:
        evidence.unlink()
        store.close()


def test_configuration_rejects_duplicate_keys_and_path_aliases(tmp_path):
    (tmp_path / "token.txt").write_text("synthetic-token", encoding="utf-8")
    row = {"id": "account-a", "collector": "http://collector:8787", "collector_fingerprint": "a" * 64, "token_file": "token.txt"}
    path = tmp_path / "proof.json"
    def write(rows):
        path.write_text(json.dumps({"workspaces": rows}), encoding="utf-8")
    write([row])
    assert load_config(path)["workspaces"][0]["root"].is_relative_to(tmp_path)
    write([row, {**row, "id": "account-b"}])
    with pytest.raises(ValueError, match="distinct"):
        load_config(path)
    write([{**row, "id": "../outside"}])
    with pytest.raises(ValueError, match="aliases"):
        load_config(path)
    write([{**row, "collector": "https://user:password@example.org"}])
    with pytest.raises(ValueError, match="without credentials"):
        load_config(path)


def test_proof_reports_channel_failure_without_disclosing_error(journal, tmp_path):
    store, vault = journal
    watcher = ProofWatcher({"id": "account-a", "label": "A", "root": tmp_path / "w",
                            "collector": "http://collector", "pinned": fingerprint(vault.public_key), "token": "secret"})
    async def fetch():
        return capture_head(store, vault, {})
    async def failed(text):
        raise RuntimeError("private failure detail")
    async def posted(text):
        return 123
    watcher.fetch = fetch
    try:
        watcher.send = failed
        asyncio.run(watcher.tick())
        assert watcher.latest["statement"]["broadcast"] == {"status": "failed"}
        assert "private failure" not in json.dumps(watcher.latest)
        watcher.send = posted
        asyncio.run(watcher.tick())
        assert watcher.latest["statement"]["broadcast"] == {"status": "posted", "message_id": 123}
    finally:
        watcher.close()


def test_controlled_probe_requires_live_message_edit_deletion_and_distinct_keys(tmp_path):
    entries, stores, paths = [], [], []
    nonce = "TGW-PROBE." + "b" * 24
    try:
        for name in ("a", "b"):
            store, vault = seeded(tmp_path / name, nonce)
            stores.append(store)
            path = export_file(store, vault, "zip")
            paths.append(path)
            entries.append((name, path, fingerprint(vault.public_key)))
        report = check_probe(nonce, entries)
        assert report["passed"] and report["distinct_workspaces"] == 2
        assert report["workspaces"][0]["delete_seq"] == 3
        with pytest.raises(ValueError, match="same workspace"):
            check_probe(nonce, [entries[0], entries[0]])
        with pytest.raises(ValueError, match="exactly one"):
            check_probe("TGW-PROBE." + "c" * 24, entries)
        stores[0].append("message.new", {"text": nonce + " duplicate"}, -100123, 51)
        duplicate = export_file(stores[0], Vault(tmp_path / "a"), "zip")
        paths.append(duplicate)
        with pytest.raises(ValueError, match="exactly one"):
            check_probe(nonce, [("a", duplicate, entries[0][2])])
    finally:
        for path in paths:
            path.unlink(missing_ok=True)
        for store in stores:
            store.close()


@pytest.mark.parametrize("missing", ["live", "edit", "delete"])
def test_probe_rejects_history_only_and_incomplete_sequences(tmp_path, missing):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    nonce = "TGW-PROBE." + "b" * 24
    store.append("message.snapshot" if missing == "live" else "message.new", {"text": nonce + " first"}, -100123, 1)
    if missing != "edit":
        store.append("message.edited", {"text": nonce + " edited"}, -100123, 1)
    if missing != "delete":
        store.append("message.deleted", {}, -100123, 1)
    archive = export_file(store, vault, "zip")
    try:
        with pytest.raises(ValueError):
            check_probe(nonce, [("account", archive, fingerprint(vault.public_key))])
    finally:
        archive.unlink()
        store.close()
