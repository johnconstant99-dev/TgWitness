import asyncio
import hashlib
from pathlib import Path

import pytest

from tgwitness import dossier
from test_access import HARBOR, OTHER, issue, login, panel as panel


def caches(store):
    store.set_setting("dossiers", {str(HARBOR): {"generation": "a"}, str(OTHER): {"generation": "b"}})
    result = [dossier.cache_path(store, chat) for chat in (HARBOR, OTHER)]
    for path in result:
        path.parent.mkdir(exist_ok=True)
        path.write_text("cached dossier", encoding="utf-8")
    return result


def test_batch_remove_preserves_records_files_and_running_jobs(panel):
    app, client = panel
    store = app.state.store
    store.set_setting("scope", {"mode": "account"})
    paths = caches(store)
    for chat, number in ((HARBOR, 20), (HARBOR, 21), (OTHER, 22)):
        store.append("message.new", {"text": "attachment"}, chat, number,
                     media_job={"account_id": 44, "descriptor": b"x", "max_bytes": 10})
    running = store.claim_media(44)
    retry = store.claim_media(44)
    store.finish_media(retry, "retry", {"error_type": "synthetic"}, delay=100)
    data = b"preserved attachment"
    digest = hashlib.sha256(data).hexdigest()
    (store.root / "media").mkdir(exist_ok=True)
    blob = store.root / "media" / digest
    blob.write_bytes(data)
    store.append("media.saved", {"media_sha256": digest}, HARBOR, 1)
    before = store.all_events()
    response = client.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER, HARBOR], "remove": True})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["removed"] == 2 and result["excluded"] == 2
    assert result["targets"] == [] and result["cache_cleanup_pending"] == []
    assert result["media"] == {"pending": "cancelled", "running": "may_finish", "saved": "kept"}
    assert store.all_events()[:len(before)] == before
    assert blob.read_bytes() == data and not any(path.exists() for path in paths)
    assert store.get_setting("dossiers", {}) == {}
    assert set(store.get_setting("scope")["exclude"]) == {HARBOR, OTHER}
    assert store.media_stats() == {"failed": 2, "running": 1}
    assert all(event["payload"]["error_type"] == "source_removed" for event in store.events(kind="media.failed"))
    assert {event["chat_id"] for event in store.events(kind="target.removed")} == {HARBOR, OTHER}
    app.state.collector.dialog_cache = {
        HARBOR: {"title": "Harbor", "kind": "supergroup"}, OTHER: {"title": "Other", "kind": "supergroup"}}
    assert asyncio.run(app.state.collector.apply_scope(refresh=False)) == {"added": 0, "paused": 0, "resumed": 0}
    assert store.targets() == []
    store.finish_media(running, "done", {"media_sha256": digest})
    assert store.media_stats() == {"failed": 2, "done": 1}
    store.verify(app.state.vault.public_key)


def test_batch_remove_validates_action_sources_and_permissions_before_writes(panel):
    app, client = panel
    store = app.state.store
    for body in (
        {"chat_ids": [HARBOR], "remove": True, "enabled": False},
        {"chat_ids": [HARBOR], "remove": True, "priority": False},
        {"chat_ids": [HARBOR], "remove": "true"},
        {"chat_ids": [], "remove": True},
        {"chat_ids": [HARBOR] * 501, "remove": True},
    ):
        assert client.post("/api/targets/batch", json=body).status_code == 422
    before = store.stats()["head"]
    assert client.post("/api/targets/batch", json={
        "chat_ids": [HARBOR, 999], "remove": True}).status_code == 404
    assert store.stats()["head"] == before and len(store.targets()) == 2
    token, _ = issue(client, permissions=["sources"], workspaces={"default": [HARBOR]})
    scoped, _ = login(app, token)
    before = store.stats()["head"]
    assert scoped.post("/api/targets/batch", json={
        "chat_ids": [HARBOR, OTHER], "remove": True}).status_code == 403
    assert store.stats()["head"] == before and len(store.targets()) == 2
    response = scoped.post("/api/targets/batch", json={"chat_ids": [HARBOR], "remove": True})
    assert response.status_code == 200 and response.json()["removed"] == 1
    assert str(OTHER) not in response.text
    assert [target["chat_id"] for target in store.targets()] == [OTHER]


def test_batch_exclusions_are_counted_once_and_checked_for_the_whole_selection(panel):
    app, client = panel
    store = app.state.store
    store.set_setting("scope", {"mode": "account", "exclude": list(range(1, 5000))})
    before = store.stats()["head"]
    body = {"chat_ids": [HARBOR, OTHER, HARBOR], "remove": True}
    assert client.post("/api/targets/batch", json=body).status_code == 409
    assert store.stats()["head"] == before and len(store.targets()) == 2
    store.set_setting("scope", {"mode": "account", "exclude": [*range(1, 4999), HARBOR]})
    response = client.post("/api/targets/batch", json=body)
    assert response.status_code == 200 and response.json()["excluded"] == 1
    assert len(store.get_setting("scope")["exclude"]) == 5000


@pytest.mark.parametrize("batch", [True, False])
def test_failed_removal_rolls_back_settings_jobs_and_keeps_dossier_caches(panel, monkeypatch, batch):
    app, client = panel
    store = app.state.store
    store.set_setting("scope", {"mode": "account"})
    paths = caches(store)
    store.append("message.new", {"text": "queued"}, HARBOR, 20,
                 media_job={"account_id": 44, "descriptor": b"x", "max_bytes": 10})
    before, targets = store.all_events(), store.targets()
    append = store.append
    failures = []

    def fail(kind, *args, **kwargs):
        if kind == "target.removed":
            failures.append(kind)
            if len(failures) == (2 if batch else 1):
                raise OSError("Synthetic journal failure")
        return append(kind, *args, **kwargs)

    monkeypatch.setattr(store, "append", fail)
    with pytest.raises(OSError, match="Synthetic"):
        if batch:
            client.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER], "remove": True})
        else:
            client.delete("/api/targets/" + str(HARBOR))
    assert store.all_events() == before and store.targets() == targets
    assert store.media_stats() == {"queued": 1}
    assert store.get_setting("scope") == {"mode": "account"}
    assert set(store.get_setting("dossiers")) == {str(HARBOR), str(OTHER)}
    assert all(path.read_text(encoding="utf-8") == "cached dossier" for path in paths)
    store.verify(app.state.vault.public_key)


def test_cache_cleanup_failure_does_not_disguise_a_committed_removal(panel, monkeypatch):
    app, client = panel
    store = app.state.store
    paths = caches(store)
    unlink = Path.unlink

    def blocked(path, *args, **kwargs):
        if path == paths[0]:
            raise PermissionError("Synthetic file in use")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", blocked)
    response = client.post("/api/targets/batch", json={"chat_ids": [HARBOR, OTHER], "remove": True})
    assert response.status_code == 200, response.text
    assert response.json()["cache_cleanup_pending"] == [HARBOR]
    assert response.json()["removed"] == 2
    assert store.targets() == [] and store.get_setting("dossiers") == {}
    assert paths[0].exists() and not paths[1].exists()
    assert client.get("/api/chats/" + str(HARBOR) + "/dossier").status_code == 409
    store.verify(app.state.vault.public_key)
