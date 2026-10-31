"""Network-response replay and downgrade checks using disposable collector keys."""
import asyncio
import copy

import pytest

from tgwitness.capture_proof import capture_head
from tgwitness.store import canonical
from tgwitness.verify import fingerprint, verify_witness
from tgwitness.witness import Witness, export


@pytest.mark.parametrize("attack", ["remove_capture", "null_capture", "empty_capture", "old_challenge", "edit_challenge"])
def test_replayed_response_never_advances_or_receives_an_ok_witness_post(journal, tmp_path, monkeypatch, attack):
    store, vault = journal
    store.append("message.new", {"text": "synthetic first record"}, 123, 1)
    replies, posts = [], []
    mode = {"replay": False}

    async def request(method, url, network, headers, **kwargs):
        if not mode["replay"]:
            answer = capture_head(store, vault, {}, headers["X-TgWitness-Challenge"],
                                  int(headers["X-TgWitness-Consistency-From"]))
            replies.append(copy.deepcopy(answer))
        else:
            answer = copy.deepcopy(replies[0])
            if attack == "remove_capture":
                answer.pop("capture")
            elif attack == "null_capture":
                answer["capture"] = None
            elif attack == "empty_capture":
                answer["capture"] = {}
            elif attack == "edit_challenge":

                answer["capture"]["statement"]["challenge"] = headers["X-TgWitness-Challenge"]
        return 200, {}, canonical(answer)

    async def send(text):
        posts.append(text)
        return len(posts)

    monkeypatch.setattr("tgwitness.witness.request", request)
    witness = Witness(tmp_path / "witness", "https://collector.invalid", "synthetic-token",
                      pinned=fingerprint(vault.public_key), send=send, post="problems")
    try:
        asyncio.run(witness.run(ticks=1))
        before = witness.store.get_setting("last_seen")
        assert before["event_count"] == 1
        store.append("message.new", {"text": "synthetic new record"}, 123, 2)
        mode["replay"] = True
        failed = asyncio.run(witness.tick())
        assert failed["kind"] == "witness.anchor"
        assert failed["payload"]["status"] == "invalid"
        assert witness.store.get_setting("last_seen") == before
        assert len(posts) == 1 and "ANSWER FAILED VERIFICATION" in posts[0]


        mode["replay"] = False
        recovered = asyncio.run(witness.tick())
        assert recovered["payload"]["status"] == "ok"
        assert recovered["payload"]["capture_delta"]["message.new"] == 1
        assert witness.store.get_setting("last_seen")["event_count"] == 2
    finally:
        witness.close()
    archive = tmp_path / "witness.zip"
    export(tmp_path / "witness", archive)
    checked = verify_witness(archive)
    assert [a["status"] for a in checked["anchors"]] == ["ok", "invalid", "ok"]


def test_freshness_is_required_on_the_first_network_answer(journal, tmp_path, monkeypatch):
    store, vault = journal
    saved = capture_head(store, vault, {})

    async def request(*args, **kwargs):
        return 200, {}, canonical({"checkpoint": saved["checkpoint"]})

    monkeypatch.setattr("tgwitness.witness.request", request)
    witness = Witness(tmp_path / "witness", "https://collector.invalid", "synthetic-token")
    try:
        event = asyncio.run(witness.tick())
        assert event["payload"]["status"] == "invalid"
        assert witness.pinned is None
        assert witness.store.get_setting("last_seen") is None
        assert witness.store.get_setting("collector_fingerprint") is None
    finally:
        witness.close()


@pytest.mark.parametrize("count,head", [(1, "z" * 64), (0, "a" * 64), (1, "0" * 64)])
def test_signed_but_impossible_checkpoint_is_not_accepted(journal, tmp_path, count, head):
    store, vault = journal

    async def fetch():
        answer = capture_head(store, vault, {})
        statement = answer["checkpoint"]["statement"]
        statement.update(event_count=count, head_hash=head)
        return {"checkpoint": {"statement": statement, "signature": vault.sign(canonical(statement))}}

    witness = Witness(tmp_path / "witness", "https://collector.invalid", "synthetic-token", fetch=fetch)
    try:
        event = asyncio.run(witness.tick())
        assert event["payload"]["status"] == "invalid"
        assert witness.store.get_setting("last_seen") is None
    finally:
        witness.close()
