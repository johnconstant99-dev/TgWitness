import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tgwitness.app import create_app
from tgwitness.evidence import checkpoint, export_file
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import WITNESS_TOKEN, check_channel, cross_check_witness, verify_bundle, verify_witness
from tgwitness.witness import Witness, export, proxy_config
from test_collector import CHAT, FakeClient


@pytest.fixture
def collector(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path / "collector", client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        yield c, app


@pytest.mark.parametrize("endpoint", ["/api/status", "/api/witness/head"])
def test_failed_tokens_cannot_lock_out_authorized_requests_at_shared_address(collector, endpoint):
    client, _ = collector
    token = client.post("/api/witness/tokens", json={"label": "Valid witness"}).json()["token"]
    invalid = {"Authorization": "Bearer wrong"}
    for _ in range(15):
        assert client.get(endpoint, headers=invalid).status_code == 401
    assert client.get(endpoint, headers=invalid).status_code == 429
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/witness/head", headers={"Authorization": "Bearer " + token}).status_code == 200

    assert client.get(endpoint, headers=invalid).status_code == 429


def test_witness_token_reads_only_the_journal_head(collector):
    c, app = collector
    created = c.post("/api/witness/tokens", json={"label": "Partner server"}).json()
    token = created["token"]
    assert token.startswith("tgww_") and token not in json.dumps(app.state.vault.read("witness"))
    assert c.get("/api/witness/head").status_code == 401
    witness = {"Authorization": "Bearer " + token, "X-TgWitness-Witness": "ab" * 32, "X-TgWitness-Interval": "10"}
    assert c.get("/api/status", headers=witness).status_code == 401
    assert c.get("/api/export/zip", headers=witness).status_code == 401
    head = c.get("/api/witness/head", headers=witness).json()
    assert head["checkpoint"]["statement"]["format"] == "tgwitness-checkpoint-v1"
    assert head["producer"]["project"] == "PhishDestroy"
    state = c.get("/api/witness").json()
    assert state["tokens"][0]["last_poll"]["witness"] == "ab" * 32 and state["tokens"][0]["overdue"] is False
    assert app.state.store.events(kind="witness.seen")[0]["payload"]["witness_fingerprint"] == "ab" * 32
    c.get("/api/witness/head", headers=witness)
    assert len(app.state.store.events(kind="witness.seen")) == 1
    assert c.delete("/api/witness/tokens/" + created["id"]).status_code == 200
    assert c.get("/api/witness/head", headers=witness).status_code == 401


def test_witness_records_posts_and_cross_checks(collector, tmp_path):
    c, app = collector
    token = c.post("/api/witness/tokens", json={"label": "Partner"}).json()["token"]
    store, vault = app.state.store, app.state.vault
    posts, answers = [], {}

    async def fetch():
        if answers.get("next"):
            value = answers.pop("next")
            if isinstance(value, Exception):
                raise value
            return value
        return c.get("/api/witness/head", headers={"Authorization": "Bearer " + token}).json()

    async def send(text):
        posts.append(text)
        return 100 + len(posts)

    async def run():
        witness = Witness(tmp_path / "witness", "https://collector.example", token, "@witness", "bot-token",
                          interval=10, fetch=fetch, send=send)
        try:
            await witness.run(ticks=1)
            first = checkpoint(store, vault)
            for i in range(3):
                store.append("message.new", {"text": str(i)}, CHAT, i)
            await witness.tick()
            answers["next"] = ConnectionError("refused")
            await witness.tick()
            answers["next"] = {"checkpoint": first}
            await witness.tick()
            other = Vault(tmp_path / "impostor")
            answers["next"] = {"checkpoint": checkpoint(store, other)}
            await witness.tick()
            answers["next"] = {"checkpoint": {**first, "signature": first["signature"][::-1]}}
            await witness.tick()
        finally:
            witness.close()
    asyncio.run(run())
    witness_zip = tmp_path / "witness.zip"
    export(tmp_path / "witness", witness_zip)
    seen = verify_witness(witness_zip)
    assert [a["status"] for a in seen["anchors"]] == ["ok", "ok", "rollback", "key_changed", "invalid"]
    assert seen["no_response"][0]["error"] == "ConnectionError" and len(seen["posted"]) == 6
    assert "no answer from the collector" in posts[2] and "JOURNAL GOT SHORTER" in posts[3]
    assert all(WITNESS_TOKEN.search(text) for text in posts)

    bundle = export_file(store, vault, "zip")
    try:
        result = verify_bundle(bundle)
        check = cross_check_witness(seen, bundle, result)
        assert check["consistent"] == 2 and not check["conflicts"] and check["no_response"] == 1
        assert [a["status"] for a in check["anomalies"]] == ["rollback"]
        assert check["other_keys"] == 1 and check["invalid_answers"] == 1

        forged = {**seen, "anchors": [{**seen["anchors"][1], "head_hash": "0" * 64}]}
        assert len(cross_check_witness(forged, bundle, result)["conflicts"]) == 1


        channel = tmp_path / "result.json"
        messages = [{"id": 101 + i, "date": "2026-03-01T12:0" + str(i) + ":00", "text": text} for i, text in enumerate(posts)]
        channel.write_text(json.dumps({"messages": messages}), encoding="utf-8")
        report = check_channel(seen, channel)
        assert report["matching"] == 6 and not report["invalid_signatures"] and not report["posted_but_not_found"]
        assert len(report["telegram_post_dates"]) == 6
        verifier = [sys.executable, str(Path("tgwitness") / "verify.py"), str(bundle), "--witness", str(witness_zip),
                    "--witness-fingerprint", seen["fingerprint"], "--channel", str(channel)]
        shown = subprocess.run(verifier, capture_output=True, text=True, errors="replace")
        assert shown.returncode == 0 and "Witnessed from" in shown.stdout
        assert "unpinned" not in shown.stdout
        assert "No retained checkpoint supplied" in shown.stdout and "witness key is not pinned" not in shown.stdout
        unpinned = subprocess.run(verifier[:5], capture_output=True, text=True, errors="replace")
        assert unpinned.returncode == 0 and "witness key is not pinned" in unpinned.stdout

        impostor_vault = Vault(tmp_path / "impostor-journal")
        impostor = Store(tmp_path / "impostor-journal")
        impostor.bind(impostor_vault)
        impostor.append("message.new", {"text": "x"}, CHAT, 1)
        foreign = export_file(impostor, impostor_vault, "zip")
        try:
            shown = subprocess.run([sys.executable, str(Path("tgwitness") / "verify.py"), str(foreign), "--witness",
                                    str(witness_zip), "--witness-fingerprint", seen["fingerprint"]],
                                   capture_output=True, text=True, errors="replace")
            assert shown.returncode == 0 and "Witnessed from" not in shown.stdout
            assert "nothing here is witnessed" in shown.stdout and "unpinned" in shown.stdout
        finally:
            impostor.close()
            foreign.unlink()

        messages[0]["text"] = messages[0]["text"].replace("TGW1.", "TGW1.A")
        del messages[1]
        channel.write_text(json.dumps({"messages": messages}), encoding="utf-8")
        report = check_channel(seen, channel)
        assert report["invalid_signatures"] == [101] and len(report["posted_but_not_found"]) == 2
        assert subprocess.run(verifier, capture_output=True, text=True, errors="replace").returncode == 1
    finally:
        bundle.unlink()


def test_witness_pins_the_collector_key_and_parses_proxies(tmp_path):
    async def nothing():
        raise ConnectionError("down")

    witness = Witness(tmp_path / "w", "http://collector:8787", "t", pinned="aa" * 32, fetch=nothing)
    assert witness.send is None
    asyncio.run(witness.tick())
    witness.close()
    with pytest.raises(ValueError, match="another collector key"):
        Witness(tmp_path / "w", "http://collector:8787", "t", pinned="bb" * 32).close()
    route = proxy_config("socks5://user:p%40ss@proxy.example:1080")
    assert (route.kind, route.host, route.port, route.password) == ("socks5", "proxy.example", 1080, "p@ss")
    with pytest.raises(ValueError):
        proxy_config("ftp://proxy")
