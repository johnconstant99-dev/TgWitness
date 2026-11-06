"""Independent settings requirements must fail closed without hiding partial exports."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.sealed import create_app
from tgwitness.sealed_crypto import keypair
from tgwitness.sealed_selection import Selection, checked_selection, selection_hash
from tgwitness.sealed_verify import verify
from tools.browser_fixtures import CapsuleClient, config
from tools.test_file_hash_export import ExportTransport
from tools.test_sealed_account import login


@pytest.mark.parametrize("scope,ids", [("selected", []), ("all", [11])])
def test_ambiguous_account_scope_is_rejected(scope, ids):
    with pytest.raises(ValueError, match="Selected scope requires"):
        Selection(mode="account", account_scope=scope, account_options={"chat_ids": ids})


def test_legacy_defaults_and_canonical_settings():
    selection = Selection(mode="account", account_options={"chat_ids": [12, 11, 12]})
    assert selection.account_scope == "selected"
    assert selection.settings()["account_options"]["chat_ids"] == [11, 12]
    assert Selection.model_validate(selection.settings()).settings() == selection.settings()
    chat = Selection(chat_id=11).settings()
    result = checked_selection([{"chat_id": 11, "capture": chat["capture"], "transport": "regular"}], {}, chat)
    assert result["mode"] == "journal" and result["expected_selection_matched"]
    with pytest.raises(ValueError, match="complete account export"):
        checked_selection([{"chat_id": 11, "capture": chat["capture"], "transport": "regular"}], {}, require_complete=True)


@pytest.mark.parametrize("ids", [[], [11], [11, 12]])
@pytest.mark.parametrize("transport", ["takeout", "regular"])
def test_signed_full_and_selected_account_settings(tmp_path, ids, transport):
    class Network(ExportTransport):
        account_id = 44

        async def discover(self):
            chats, tasks = [], []
            for chat_id in (11, 12):
                selected = not self.options["chat_ids"] or chat_id in self.options["chat_ids"]
                chats.append({"id": chat_id, "title": "Synthetic " + str(chat_id), "kind": "private",
                              "selected": selected, "archived": False, "left": False})
                if selected:
                    tasks.append({"id": f"messages:{chat_id}:0", "category": "messages", "chat_id": chat_id,
                                  "cursor_start": 3, "newest_message_id": 2, "own_only": False, "telegram_range": None})
            return chats, tasks, []

        async def page(self, task, cursor):
            rows, cursor, done = await super().page(task, cursor)
            return [({**row, "chat_id": task["chat_id"]}, media) for row, media in rows], cursor, done

    async def run():
        cfg = config(keypair())
        app = create_app(tmp_path / "data", tmp_path / "out", cfg, CapsuleClient)
        async with app.router.lifespan_context(app):
            session = app.state.session
            session.account_export.transport_factory = Network
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                    headers={"Authorization": "Bearer " + cfg["token"]}) as client:
                await login(client, session, "phone")
                rejected = await client.post("/api/collect", json={"mode": "account", "account_scope": "selected",
                                                                  "account_options": {"chat_ids": []}})
                assert rejected.status_code == 422 and session.account_job is None
                selection = Selection(mode="account", account_scope="selected" if ids else "all", account_options={
                    "transport": transport, "chat_ids": ids, "media_action": "hashes_only",
                    "include_profile": False, "include_contacts": False}).settings()
                response = await client.post("/api/collect", json=selection)
                assert response.status_code == 200, response.text
                assert (await client.post("/api/collect", json=selection)).status_code == 400
                await asyncio.wait_for(asyncio.shield(session.monitor_task), 20)
                assert session.phase == "sealed", session.reason
                return selection

    selection = asyncio.run(run())
    expected = tmp_path / "expected.json"
    expected.write_text(json.dumps(selection), encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"format": "tgwitness-sealed-policy-v1",
        "workflow": "phishdestroy/TgWitness/.github/workflows/sealed-collector.yml",
        "releases": [{"collector_sha": "a" * 40, "workflow_sha": "b" * 40}]}))
    external = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='[{"synthetic":true}]')
    args = (tmp_path / "out/evidence.zip", tmp_path / "synthetic-attestation.jsonl", "user/fork", policy)
    result = verify(*args, run=external, expected_selection=expected, require_complete=True)
    assert result["expected_selection_matched"] and result["mode"] == transport
    assert result["selection"] == selection and result["selection_sha256"] == selection_hash(selection)
    assert result["journal"]["account_export"]["counts"]["messages"] == (2 if ids == [11] else 4)
    changed = deepcopy(selection)
    changed["account_options"]["transport"] = "regular" if transport == "takeout" else "takeout"
    expected.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="independently expected"):
        verify(*args, run=external, expected_selection=expected)
    with zipfile.ZipFile(args[0]) as archive:
        events = [json.loads(line)["payload"] for line in archive.read("events.jsonl").splitlines()
                  if json.loads(line)["kind"] == "sealed.selection"]
    altered = deepcopy(events)
    altered[0]["selection_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest mismatch"):
        checked_selection(altered, result["journal"])
    altered = deepcopy(result["journal"])
    altered["account_export"]["options"]["own_messages_only"] = True
    with pytest.raises(ValueError, match="differs from the signed"):
        checked_selection(events, altered)
    partial = deepcopy(result["journal"])
    partial["account_export"]["complete_within_scope"] = False
    assert checked_selection(events, partial)["complete_within_scope"] is False
    with pytest.raises(ValueError, match="complete account export"):
        checked_selection(events, partial, require_complete=True)
    with pytest.raises(ValueError, match="exactly one"):
        checked_selection(events * 2, result["journal"])
