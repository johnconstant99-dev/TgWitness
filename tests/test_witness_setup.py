import argparse
import asyncio
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tgwitness.evidence import checkpoint
from tgwitness.proof import load_config as proof_config
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import WITNESS_TOKEN, check_channel, fingerprint, verify_witness
from tgwitness.witness import Witness, export, http_address, load_config, resolve


def test_config_preflight_uses_paths_beside_json_and_never_creates_a_key(tmp_path, monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("TGWITNESS_WITNESS_"):
            monkeypatch.delenv(name)
    config_dir = tmp_path / "operator"
    config_dir.mkdir()
    (config_dir / "witness-token.txt").write_text("synthetic-read-only-secret")
    (config_dir / "bot-token.txt").write_text("synthetic-bot-secret")
    path = config_dir / "witness.json"
    data = {"collector": "https://collector.invalid/profiles/example", "collector_fingerprint": "a" * 64,
            "token_file": "witness-token.txt", "bot_token_file": "bot-token.txt", "channel": "@test_proof",
            "interval": 5, "post": "all", "proxy": "socks5://fixture:private@proxy.invalid:1080"}
    path.write_text(json.dumps(data))
    options = resolve(argparse.Namespace(config=str(path)), load_config(path))
    assert options["token"] == "synthetic-read-only-secret"
    assert options["data_dir"] == config_dir / "witness-data"
    command = [sys.executable, "-m", "tgwitness.witness", "run", "--config", str(path), "--check-config"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"valid": True, "key_pinned": True, "posting": True,
        "interval_minutes": 5, "post_policy": "all", "route": "socks5", "network_checked": False}
    assert "secret" not in result.stdout and "private" not in result.stdout
    assert not (config_dir / "witness-data").exists()
    (config_dir / "bot-token.txt").unlink()
    assert subprocess.run(command, capture_output=True, timeout=20).returncode == 1


@pytest.mark.parametrize("url", ["tg://proxy?secret=private", "https://user:private@host", "https://host/?token=private", "https://host/#private"])
def test_witness_http_addresses_cannot_be_mtproxy_links_or_embed_secrets(url):
    with pytest.raises(ValueError) as error:
        http_address(url)
    assert "private" not in str(error.value)


def test_proof_accepts_own_bot_api_and_http_proxy(tmp_path):
    (tmp_path / "reader.txt").write_text("read-only-fixture")
    (tmp_path / "bot.txt").write_text("bot-fixture")
    path = tmp_path / "proof.json"
    path.write_text(json.dumps({"workspaces": [{"id": "account-a", "collector": "http://collector:8787",
        "collector_fingerprint": "a" * 64, "token_file": "reader.txt", "bot_token_file": "bot.txt",
        "channel": "@fixture_proof", "bot_api": "http://bot-api:8081", "proxy": "http://proxy:80"}]}))
    row = proof_config(path)["workspaces"][0]
    assert row["network"].host == "proxy" and row["network"].port == 80
    assert row["bot_api"] == "http://bot-api:8081" and row["bot_token"] == "bot-fixture"


def test_bot_api_http_publishes_signed_anchors_and_records_failure(tmp_path):
    received, mode = [], {"fail": False}

    class BotAPI(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.path, data))
            result = {"ok": False, "description": "fixture unavailable"} if mode["fail"] else {
                "ok": True, "result": {"message_id": len(received)}}
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), BotAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    vault = Vault(tmp_path / "collector")
    store = Store(vault.root)
    store.bind(vault)
    store.append("fixture", {})

    async def fetch():
        return {"checkpoint": checkpoint(store, vault)}

    witness = Witness(tmp_path / "witness", "http://collector.invalid", "reader", "@fixture_proof", "fixture-token",
                      pinned=fingerprint(vault.public_key), fetch=fetch, bot_api="http://127.0.0.1:" + str(server.server_port))
    try:
        asyncio.run(witness.tick())
        mode["fail"] = True
        asyncio.run(witness.tick())
        assert received[0][0] == "/botfixture-token/sendMessage"
        assert received[0][1]["chat_id"] == "@fixture_proof"
        assert WITNESS_TOKEN.search(received[0][1]["text"])
        assert "fixture-token" not in json.dumps(witness.store.all_events())
    finally:
        witness.close()
        store.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    archive = tmp_path / "witness.zip"
    export(tmp_path / "witness", archive)
    checked = verify_witness(archive)
    assert len(checked["posted"]) == len(checked["post_failures"]) == 1
    channel = tmp_path / "channel.json"
    channel.write_text(json.dumps({"messages": [{"id": 1, "text": received[0][1]["text"], "date": "2026-10-29T12:00:00"}]}))
    assert check_channel(checked, channel)["matching"] == 1
