import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from check_browser import RunningApp
from test_group_settings import session
from tgwitness import group_overview

CHANNEL = -1001234567890


def test_overview(tmp_path):
    with RunningApp(tmp_path) as server:
        call = session(server)
        registry = server.app.state.profiles
        gid = call("POST", "profile-groups", {"label": "Harbor case"})["groups"][0]["id"]
        alpha = call("POST", "profiles", {"label": "Alpha", "group": gid})["id"]
        beta = call("POST", "profiles", {"label": "Beta", "group": gid})["id"]
        lone = call("POST", "profiles", {"label": "Lone", "group": gid})["id"]
        call("POST", "profiles", {"label": "Outsider"})
        store = {pid: registry.entries[pid]["app"].state.store for pid in (alpha, beta, lone)}
        store[alpha].set_setting("account", {"id": 101, "username": "alpha_watch"})
        for pid in (alpha, beta):
            store[pid].set_target(CHANNEL, "Harbor channel", "channel", pid == alpha)
        store[lone].set_target(-1009, "Only Lone", "channel", True)
        store[alpha].append("observation.started", {"parameters": {"heartbeat_seconds": 60}})
        store[alpha].append("message.new", {"text": "hello"}, chat_id=CHANNEL, message_id=7)
        result = call("GET", "profile-groups/" + gid + "/overview")
        assert result["group"] == {"id": gid, "label": "Harbor case", "goal": None}
        rows = {m["id"]: m for m in result["members"]}
        assert set(rows) == {alpha, beta, lone}
        assert rows[alpha]["username"] == "alpha_watch" and rows[alpha]["account_id"] == 101
        assert rows[alpha]["last_message"]["kind"] == "message.new" and rows[beta]["last_message"] is None
        assert rows[alpha]["route"]["mode"] and rows[alpha]["route"]["latency_ms"] is None
        assert rows[beta]["account_kind"] is None
        [chat] = result["chats"]
        assert chat["chat_id"] == CHANNEL and sorted(chat["seen_by"]) == sorted([alpha, beta])
        assert chat["recorded_by"] == [alpha]
        assert chat["coverage"]["observed"] and chat["coverage"]["interruptions"] == 0
        store[alpha].append("observation.stopped", {"reason": "operator"})
        [chat] = call("GET", "profile-groups/" + gid + "/overview")["chats"]
        assert chat["coverage"]["interruptions"] == 0
        call("GET", "profile-groups/" + "0" * 32 + "/overview", status=400)


def test_group_export(tmp_path):
    import base64
    import hashlib
    import io
    import json
    import zipfile
    import requests
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from tgwitness.store import canonical
    with RunningApp(tmp_path) as server:
        call = session(server)
        registry = server.app.state.profiles
        gid = call("POST", "profile-groups", {"label": "Harbor case"})["groups"][0]["id"]
        call("GET", "profile-groups/" + gid + "/export", status=409)
        alpha = call("POST", "profiles", {"label": "Alpha", "group": gid})["id"]
        beta = call("POST", "profiles", {"label": "Beta", "group": gid})["id"]
        registry.entries[alpha]["app"].state.store.append("message.new", {"text": "hi"}, chat_id=CHANNEL, message_id=1)
        token = requests.post(server.url + "/api/access/login", json={"token": server.app.state.vault.token}).json()["session"]
        response = requests.get(server.url + "/api/profile-groups/" + gid + "/export", headers={"Authorization": "Bearer " + token})
        assert response.status_code == 200, response.text
        assert response.headers["X-TgWitness-Export-ID"]
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        manifest = json.loads(archive.read("manifest.json"))
        signed = json.loads(archive.read("manifest.signature.json"))
        assert signed["public_key"] == server.app.state.vault.public_key
        Ed25519PublicKey.from_public_bytes(base64.b64decode(signed["public_key"])).verify(
            base64.b64decode(signed["signature"]), canonical(manifest))
        assert manifest["format"] == "tgwitness-group-export-v1" and manifest["group"]["id"] == gid
        assert {a["workspace_id"] for a in manifest["accounts"]} == {alpha, beta}
        for account in manifest["accounts"]:
            inner = archive.read(account["file"])
            assert hashlib.sha256(inner).hexdigest() == account["sha256"]
            assert any(name.endswith(".jsonl") for name in zipfile.ZipFile(io.BytesIO(inner)).namelist())
        kinds = [r[0] for r in server.app.state.store.db.execute("SELECT kind FROM events")]
        assert "profile_group.exported" in kinds
        call("GET", "profile-groups/" + "0" * 32 + "/export", status=400)


def test_interruptions():
    t = datetime(2026, 11, 1, tzinfo=timezone.utc)
    hour, allowed = timedelta(hours=1), timedelta(minutes=3)
    periods = [(t, t + 2 * hour), (t + 3 * hour, t + 4 * hour), (t + 4 * hour + timedelta(minutes=1), t + 5 * hour)]
    holes = group_overview.interruptions(periods, t, t + 5 * hour, allowed)
    assert holes == [(t + 2 * hour, t + 3 * hour)]
    assert group_overview.interruptions(periods, t, t + 6 * hour, allowed)[-1] == (t + 5 * hour, t + 6 * hour)
    assert group_overview.interruptions([], t, t + hour, allowed) == [(t, t + hour)]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
