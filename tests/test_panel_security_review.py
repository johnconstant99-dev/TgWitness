import hashlib

import pytest

from tgwitness import live_stream
from test_access import HARBOR, OTHER, issue, login, panel as panel


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
def test_stream_reauthorization_accepts_the_same_bearer_schemes_as_login(panel, monkeypatch, scheme):
    app, admin = panel
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    browser, response = login(app, token)
    browser.headers["Authorization"] = scheme + " " + response.json()["session"]

    async def once(store, after, authorize, disconnected):
        assert authorize() == {HARBOR}
        yield ": authorized\n\n"

    monkeypatch.setattr(live_stream, "stream", once)
    assert browser.get("/api/status").status_code == 200
    result = browser.get("/api/stream")
    assert result.status_code == 200
    assert ": authorized\n\n" in result.text
    assert "access-ended" not in result.text


def test_batch_target_failure_rolls_back_targets_journal_and_derived_index(panel, monkeypatch):
    app, client = panel
    store = app.state.store
    before_targets = store.targets()
    before_stats = store.stats()
    before_scoped = store.stats(chat_ids={HARBOR})
    before_events = store.events()
    append = store.append

    def failing_append(kind, payload, chat_id=None, *args, **kwargs):
        if kind == "target.changed" and chat_id == OTHER:
            raise RuntimeError("synthetic write failure")
        return append(kind, payload, chat_id, *args, **kwargs)

    monkeypatch.setattr(store, "append", failing_append)
    with pytest.raises(RuntimeError, match="synthetic write failure"):
        client.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER], "enabled": False})
    assert store.targets() == before_targets
    assert store.stats() == before_stats
    assert store.stats(chat_ids={HARBOR}) == before_scoped
    assert store.events() == before_events
    assert not live_stream.notifications(store, before_stats["head"]["seq"], None)
    assert store.verify(app.state.vault.public_key)


def test_media_range_keeps_chat_scope_and_rechecks_revoked_access(panel):
    app, admin = panel
    data = b"\xff\xd8\xff\xe0" + b"synthetic saved image bytes"
    digest = hashlib.sha256(data).hexdigest()
    directory = app.state.store.root / "media"
    directory.mkdir(exist_ok=True)
    (directory / digest).write_bytes(data)
    app.state.store.append("media.saved", {"media_sha256": digest}, HARBOR, 1)
    token, grant_id = issue(admin, workspaces={"default": [HARBOR]})
    browser, _ = login(app, token)
    path = "/api/media/" + digest + "?inline=1"
    response = browser.get(path, headers={"Range": "bytes=4-12"})
    assert response.status_code == 206
    assert response.content == data[4:13]
    assert response.headers["content-range"] == f"bytes 4-12/{len(data)}"
    assert response.headers["cache-control"] == "no-store"
    token, _ = issue(admin, workspaces={"default": [OTHER]})
    other, _ = login(app, token)
    assert other.get(path, headers={"Range": "bytes=4-12"}).status_code == 404
    assert admin.delete("/api/access/grants/" + grant_id).status_code == 200
    assert browser.get(path, headers={"Range": "bytes=4-12"}).status_code == 401
