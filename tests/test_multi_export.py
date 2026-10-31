import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient
from telethon.errors import FloodWaitError
from telethon.helpers import TotalList

from tgwitness.app import create_app
from tgwitness.store import canonical
from tgwitness.verify import chat_messages, verify_chat_export
from test_collector import CHAT, FakeClient, telegram_message
from test_profiles import authorize

NEWEST = 4500


def present(message_id):
    return message_id % 45 != 0


class RangeClient(FakeClient):
    flooded = set()
    broken = set()

    async def get_messages(self, entity, limit):
        page = TotalList([telegram_message(NEWEST)] if limit else [])
        page.total = sum(1 for i in range(1, NEWEST + 1) if present(i))
        return page

    async def iter_messages(self, entity, limit=None, offset_id=0, min_id=0):
        if self.account_id in RangeClient.broken:
            raise RuntimeError("synthetic account failure")
        top = offset_id - 1 if offset_id else NEWEST
        for n, message_id in enumerate(range(top, min_id, -1)):
            if n == 5 and self.account_id == 125 and 125 not in RangeClient.flooded:
                RangeClient.flooded.add(125)
                raise FloodWaitError(request=None)
            if present(message_id):
                yield telegram_message(message_id, text="message " + str(message_id))


def run_export(tmp_path, broken=()):
    RangeClient.flooded, RangeClient.broken = set(), set(broken)
    app = create_app(tmp_path, client_factory=RangeClient)
    client = TestClient(app)
    client.__enter__()
    client.headers["Authorization"] = "Bearer " + app.state.vault.token
    ids = ["default"]
    authorize(client, "/api")
    for n, api_id in enumerate((124, 125)):
        profile_id = client.post("/api/profiles", json={"label": "Account " + str(n)}).json()["id"]
        ids.append(profile_id)
        authorize(client, "/profiles/" + profile_id + "/api", api_id=api_id)
    started = client.post("/api/multi-export/start", json={"chat_id": CHAT, "lead": "default", "profiles": ids})
    assert started.status_code == 200, started.text
    export_id = started.json()["id"]
    for _ in range(400):
        state = client.get("/api/multi-export/" + export_id).json()
        if state["phase"] != "running":
            break
        time.sleep(0.05)
    return app, client, export_id, state


def test_accounts_split_ranges_and_sign_their_parts(tmp_path):
    app, client, export_id, state = run_export(tmp_path)
    try:
        expected = sum(1 for i in range(1, NEWEST + 1) if present(i))
        assert state["phase"] == "done", state
        assert state["captured"] == expected and state["ranges_done"] == 3
        assert all(w["state"] == "done" for w in state["workers"])
        assert 125 in RangeClient.flooded
        assert client.get("/api/status").json()["collector"]["running"]
        bundle = tmp_path / "multi.zip"
        bundle.write_bytes(client.get("/api/multi-export/" + export_id + "/download").content)
        result = verify_chat_export(bundle, client.get("/api/status").json()["fingerprint"])
        assert result["message_count"] == expected
        assert sum(p["messages"] for p in result["parts"]) == expected
        assert {p["account_id"] for p in result["parts"]} <= {44, 124, 125} and len(result["parts"]) >= 2
        with zipfile.ZipFile(bundle) as archive:
            ids = [m["id"] for m in chat_messages(archive)]
        assert ids == sorted(ids, reverse=True) and len(set(ids)) == len(ids) == expected
        kinds = [e["kind"] for e in app.state.store.all_events()]
        assert "chat_export.started" in kinds and "chat_export.completed" in kinds
    finally:
        client.__exit__(None, None, None)


def test_failed_account_ranges_are_fetched_by_the_others(tmp_path):
    app, client, export_id, state = run_export(tmp_path, broken={125})
    try:
        assert state["phase"] == "done", state
        assert state["captured"] == sum(1 for i in range(1, NEWEST + 1) if present(i))
        failed = [w for w in state["workers"] if w["account_id"] == 125]
        assert failed and failed[0]["state"] == "failed" and failed[0]["captured"] == 0
    finally:
        client.__exit__(None, None, None)


def test_lead_account_cannot_alter_what_others_fetched(tmp_path):
    app, client, export_id, state = run_export(tmp_path)
    try:
        bundle = tmp_path / "multi.zip"
        bundle.write_bytes(client.get("/api/multi-export/" + export_id + "/download").content)
        with zipfile.ZipFile(bundle) as archive:
            items = {name: archive.read(name) for name in archive.namelist()}
        items["chat.json"] = items["chat.json"].replace(b'"message 4499"', b'"forged text"', 1)
        manifest = json.loads(items["manifest.json"])
        import hashlib
        manifest["files"]["chat.json"] = hashlib.sha256(items["chat.json"]).hexdigest()
        items["manifest.json"] = canonical(manifest)
        items["manifest.sig"] = app.state.vault.sign(items["manifest.json"]).encode()
        forged = io.BytesIO()
        with zipfile.ZipFile(forged, "w") as archive:
            for name, data in items.items():
                archive.writestr(name, data)
        bundle.write_bytes(forged.getvalue())
        with pytest.raises(ValueError, match="differ from what the account signed"):
            verify_chat_export(bundle, client.get("/api/status").json()["fingerprint"])
    finally:
        client.__exit__(None, None, None)
