import copy
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import board, evidence, report
from tgwitness.access import Principal, Refused
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import board_replay, fingerprint, verify_bundle, verify_board_document


ADMIN = Principal(True, "Admin")


def grant(chats, permissions=("view", "board.read", "board.write"), identifier="a" * 16):
    return Principal(False, "Analyst", {"id": identifier, "permissions": list(permissions),
        "all_workspaces": False, "workspaces": {"default": chats}})


@pytest.fixture
def case(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        yield store, vault, board.Board(store)
    finally:
        store.close()


def bookmark(service, event, who=ADMIN, **extra):
    return service.append("bookmark", {"target": {"event_hash": event["hash"]}, **extra}, who)


def test_chain_revisions_and_no_journal_writes(case):
    store, vault, service = case
    source = store.append("message.new", {"text": "immutable"}, -1001, 1)
    record = bookmark(service, source, note="An opinion")
    revised = bookmark(service, source, id=record["payload"]["id"], supersedes=record["hash"], note="Revised opinion")
    assert revised["previous_hash"] == record["hash"]
    service.append("remove", {"card_id": record["payload"]["id"]}, ADMIN)
    replay = board_replay(board.records(store.db), vault.public_key)
    assert replay["items"][0]["removed"]
    assert len(store.all_events()) == 1 and store.all_events()[0] == source
    altered = copy.deepcopy(record)
    altered["payload"]["note"] = "Forgery"
    with pytest.raises(ValueError, match="chain"):
        board_replay([altered], vault.public_key)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store.db.execute("UPDATE annotations SET record='{}'")
    store.db.rollback()


@pytest.mark.parametrize("text,start,length", [("A😀Z", 1, 1), ("עברית 😀 e\u0301", 8, 2), ("a👩‍💻z", 1, 3)])
def test_unicode_offsets_bound_to_exact_version(case, text, start, length):
    store, vault, service = case
    event = store.append("message.new", {"text": text}, -1001, 1)
    payload = {"target": {"event_hash": event["hash"]}, "range": {"start": start, "length": length, "quote": text[start:start+length]}}
    saved = service.append("highlight", payload, ADMIN)
    assert saved["payload"]["range"]["version"] == event["hash"]
    store.append("message.edited", {"text": "changed"}, -1001, 1)
    detail = service.detail(store.db, ADMIN, saved["payload"]["id"])
    assert detail["target"] == event
    payload["range"]["start"] += 1
    with pytest.raises(ValueError, match="quote"):
        service.append("highlight", payload, ADMIN)


def test_chat_scope_enforced_for_every_reference(case):
    store, vault, service = case
    a = store.append("message.new", {"text": "allowed"}, -1001, 1)
    b = store.append("message.new", {"text": "private"}, -1002, 1)
    analyst = grant([-1001])
    visible = bookmark(service, a, analyst)
    hidden = bookmark(service, b)
    with pytest.raises(Refused):
        bookmark(service, b, analyst)
    with pytest.raises(ValueError, match="metadata"):
        service.append("bookmark", {"target": {"event_hash": a["hash"], "chat_id": -1002}}, ADMIN)
    with pytest.raises(Refused):
        service.append("slice", {"query": {"chat_ids": [-1001, -1002]}}, analyst)
    with pytest.raises(Refused):
        service.append("comment", {"parent_id": hidden["payload"]["id"], "text": "Guess"}, analyst)
    with pytest.raises(KeyError):
        service.detail(store.db, analyst, hidden["payload"]["id"])
    assert [x["id"] for x in service.read(store.db, analyst)["items"]] == [visible["payload"]["id"]]
    with pytest.raises(Refused):
        service.append("status", {"card_id": visible["payload"]["id"], "state": "confirmed"}, analyst)
    with pytest.raises(Refused):
        bookmark(service, a, grant([-1001], ("view", "board.read")))


def test_slice_all_kinds_and_late_deletion(case):
    store, vault, service = case
    kinds = ["message.new", "message.snapshot", "message.edited", "reaction.snapshot", "membership.update",
             "button.pressed", "media.skipped", "message.recovered", "message.missing_on_recheck"]
    with patch("tgwitness.store.utcnow", return_value="2026-11-02T14:05:00Z"):
        for i, kind in enumerate(kinds, 1):
            store.append(kind, {"text": kind}, -1001, i)
        item = service.append("slice", {"query": {"chat_id": -1001, "from": "2026-11-02T14:00:00Z", "to": "2026-11-02T14:20:00Z"}}, ADMIN)
        store.append("message.deleted", {}, -1001, 2)
    result = service.slice(store.db, ADMIN, item["payload"]["id"], limit=3)
    assert result["current"]["record_count"] == 10
    assert result["diff"] == {"added": 1, "removed": 0}
    assert result["next_offset"] == 3
    assert set(result["current"]["counts"]) == set(kinds) | {"message.deleted"}


def test_signed_zip_board_and_retained_checkpoint(case):
    store, vault, service = case
    source = store.append("message.new", {"text": "Evidence, not a note"}, -1001, 1)
    card = bookmark(service, source, title="Exhibit", note="Team interpretation")
    service.append("comment", {"parent_id": card["payload"]["id"], "text": "Review this"}, ADMIN)
    service.append("slice", {"query": {"chat_id": -1001}}, ADMIN)
    checkpoint = evidence.checkpoint(store, vault)
    store.append("message.deleted", {}, -1001, 1)
    archive = evidence.export_file(store, vault, "zip", report.resolved())
    verified = verify_bundle(archive, fingerprint(vault.public_key), checkpoint)
    assert verified["board"]["annotations_head"]["seq"] == 3
    assert verified["board"]["slice_changes"][0]["added"] == 1
    assert not verified["board"]["dangling"]
    with zipfile.ZipFile(archive) as incoming:
        assert len(incoming.read("annotations.jsonl").splitlines()) == 3
        state = json.loads(incoming.read("case-board.json"))["statement"]["state"]
        assert state["items"][0]["note"] == "Team interpretation"


def test_reaction_counts_do_not_invent_actor_actions():
    def snapshot(seq, count, recent):
        return {"seq": seq, "observed_at": f"2026-11-02T14:0{seq}:00Z", "payload": {"raw": {"reactions": {
            "results": [{"reaction": {"emoticon": "👍"}, "count": count}], "recent_reactions": recent}}}}
    delta = board.reaction_delta(snapshot(1, 3, [{"user_id": 4}]), snapshot(2, 2, []))
    assert delta["count_changes"][0]["delta"] == -1
    assert delta["exact_change_time"] is None and delta["complete_actor_list"] is False
    assert delta["recent_actor_observations"] == []


def test_journal_groups_and_search_reproduce_saved_predicate(case):
    store, vault, service = case
    store.append('message.new', {'text': 'ÉTUDE 😀'}, -1001, 1)
    store.append('message.snapshot', {'text': 'not a match'}, -1001, 2)
    store.append('membership.update', {}, -1001)
    card = service.append('slice', {'query': {'chat_id': -1001, 'kinds': ['messages','membership'], 'search':'e\u0301tude'}}, ADMIN)
    assert card['payload']['query']['kinds'] == ['message.new','message.snapshot','message.recovered','membership.*']
    assert card['payload']['snapshot']['record_count'] == 1
    with store.snapshot() as snapshot:
        window = service.journal_window(snapshot.connection, ADMIN, card['payload']['id'])
        assert len(window['events']) == 1 and window['events'][0]['payload']['text'] == 'ÉTUDE 😀'
    archive = evidence.export_file(store,vault,'zip',report.resolved())
    assert not verify_bundle(archive)['board']['slice_changes']


def test_detached_board_document_checks_both_signed_prefixes(case, tmp_path):
    store, vault, service = case
    source = store.append('message.new', {'text':'source'}, -1001,1)
    bookmark(service, source)
    signed = board.export_state(store.db, vault)
    path = tmp_path / 'case-board.json'
    path.write_bytes(canonical(signed))
    archive = evidence.export_file(store,vault,'zip',report.resolved())
    assert verify_board_document(path, fingerprint(vault.public_key), archive)['annotations_checked']
    signed['statement']['journal_head']['hash'] = 'f'*64
    signed['signature'] = vault.sign(canonical(signed['statement']))
    path.write_bytes(canonical(signed))
    with pytest.raises(ValueError, match='journal boundary'):
        verify_board_document(path, fingerprint(vault.public_key), archive)


def test_published_schemas_match_validated_api_models():
    from tgwitness.board_models import MODELS
    directory = Path(__file__).resolve().parents[1] / 'tgwitness' / 'schemas'
    for kind, model in MODELS.items():
        published = json.loads((directory / ('board-' + kind + '.json')).read_text(encoding='utf-8'))
        assert published == {'$schema': 'https://json-schema.org/draft/2020-12/schema',
            '$id': 'urn:tgwitness:board:' + kind + ':v1', **model.model_json_schema(by_alias=True)}


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
