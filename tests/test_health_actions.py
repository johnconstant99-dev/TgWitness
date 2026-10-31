import asyncio
import sqlite3

import pytest

from test_access import HARBOR, OTHER, issue, login, panel as panel
from test_collector import CHAT, media_message
from test_reliability import prepared
from tgwitness import alerts, health
from tgwitness.monitoring import capture_settings


def job(store, message, state="queued"):
    record = store.append("message.new", {"text": "Synthetic attachment"}, HARBOR, message,
                          media_job={"account_id": 44, "descriptor": b"synthetic", "max_bytes": 20})
    with store.transaction():
        store.db.execute("UPDATE media_jobs SET state=? WHERE message_event=?", (state, record["seq"]))
    return record


def test_clear_waiting_queue_keeps_running_failures_future_jobs_and_saved_files(journal):
    store, vault = journal
    store.set_target(HARBOR, "Synthetic", "supergroup", True)
    records = [job(store, i, state) for i, state in enumerate(("running", "failed", "done", "queued", "retry"))]
    through = records[-1]["seq"]
    future = job(store, 20)
    preserved = store.root / "media" / ("a" * 64)
    preserved.parent.mkdir(exist_ok=True)
    preserved.write_bytes(b"saved evidence")
    old = store.all_events()
    assert store.clear_media_queue(through) == 2
    assert store.media_stats() == {"running": 1, "failed": 1, "done": 1, "cancelled": 2, "queued": 1}
    assert store.all_events()[:len(old)] == old and preserved.read_bytes() == b"saved evidence"
    receipts = store.events(kind="media.skipped")
    assert {e["payload"]["message_event"] for e in receipts} == {r["seq"] for r in records[-2:]}
    assert all(e["payload"]["reason"] == "waiting download cancelled by operator" for e in receipts)
    assert store.claim_media(44)["message_event"] == future["seq"]
    assert store.clear_media_queue(through) == 0
    store.recover_media()
    assert store.media_stats()["cancelled"] == 2
    store.verify(vault.public_key)


def test_clear_queue_rolls_back_jobs_and_receipts_if_journal_write_fails(journal):
    store, _ = journal
    for i in range(3):
        last = job(store, i)
    before = store.stats()["head"]
    with store.transaction():
        store.db.execute("CREATE TRIGGER reject_cancel BEFORE INSERT ON events "
                         "WHEN NEW.kind='media.skipped' AND NEW.message_id=1 "
                         "BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.clear_media_queue(last["seq"])
    assert store.media_stats() == {"queued": 3} and store.stats()["head"] == before


@pytest.mark.parametrize("lane", ("urgent", "bulk"))
def test_downloads_off_do_not_claim_previously_queued_jobs(journal, lane):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        await collector.capture_message(media_message(size=4 if lane == "urgent" else 3*1024**2), "message.new", CHAT)
        store.set_setting("capture", {"download_media": False})
        collector.running = True
        task = asyncio.create_task(collector.download_worker(lane))
        try:
            await asyncio.sleep(.08)
            assert store.media_stats() == {"queued": 1}
        finally:
            collector.running = False
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_switching_downloads_off_finishes_inflight_only_then_resumes(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        await collector.restore()
        await collector.capture_message(media_message(id=1), "message.new", CHAT)
        await collector.capture_message(media_message(id=2), "message.new", CHAT)
        entered, release = asyncio.Queue(), asyncio.Event()
        async def download(media, file, progress_callback):
            await entered.put(True)
            await release.wait()
            file.write(b"data")
            return file
        collector.client.download_media = download
        collector.running = True
        task = asyncio.create_task(collector.download_worker())
        try:
            await asyncio.wait_for(entered.get(), 2)
            store.set_setting("capture", {"download_media": False})
            release.set()
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(entered.get(), .1)
            assert store.media_stats() == {"done": 1, "queued": 1}
            store.set_setting("capture", {"download_media": True})
            collector.media_wakeup.set()
            await asyncio.wait_for(entered.get(), 2)
        finally:
            collector.running = False
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await collector.stop(shutdown=True)
    asyncio.run(run())


def test_disabled_media_receipts_are_optional_without_suppressing_policy_records(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_setting("capture", {"download_media": False})
        assert capture_settings(store)["record_disabled_media"] is True
        await collector.capture_message(media_message(id=1), "message.new", CHAT)
        store.set_setting("capture", {"download_media": False, "record_disabled_media": False})
        await collector.capture_message(media_message(id=2), "message.new", CHAT)
        assert len(store.events(kind="message.new")) == 2 and len(store.events(kind="media.skipped")) == 1
        assert store.media_stats() == {}
        store.set_setting("capture", {"download_media": True, "record_disabled_media": False,
                                      "types": {"document": {"enabled": False, "max_mb": 20}}})
        await collector.capture_message(media_message(id=3), "message.new", CHAT)
        assert len(store.events(kind="media.skipped")) == 2
        assert "type not collected" in store.events(kind="media.skipped")[0]["payload"]["reason"]
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_clear_api_requires_settings_whole_workspace_and_valid_cutoff(panel):
    app, admin = panel
    record = job(app.state.store, 1)
    for settings in ({}, {"permissions": ["settings"], "workspaces": {"default": [HARBOR]}}):
        token, _ = issue(admin, **settings)
        client, _ = login(app, token)
        assert client.post("/api/media/queue/clear", json={"through_seq": record["seq"]}).status_code == 403
    for value in (True, -1, 2**53, "1", 1.5):
        assert admin.post("/api/media/queue/clear", json={"through_seq": value}).status_code == 422
    assert admin.post("/api/media/queue/clear", json={"through_seq": record["seq"] + 1000}).status_code == 409
    response = admin.post("/api/media/queue/clear", json={"through_seq": record["seq"]})
    assert response.status_code == 200 and response.json()["cancelled"] == 1, response.text


def test_legacy_capture_save_preserves_explicit_suppression(panel):
    app, admin = panel
    response = admin.post("/api/capture", json={"download_media": False, "record_disabled_media": False})
    assert response.status_code == 200 and response.json()["record_disabled_media"] is False
    assert admin.post("/api/capture", json={"download_media": True}).json()["record_disabled_media"] is False
    assert app.state.store.events(kind="capture.changed")[0]["payload"]["record_disabled_media"] is False


def test_ignoring_sources_changes_health_and_panel_only_and_is_scope_checked(panel):
    app, admin = panel
    collector, store = app.state.collector, app.state.store
    collector.source_status = {str(c): {"state": "access_unconfirmed"} for c in (HARBOR, OTHER)}
    for chat in (HARBOR, OTHER):
        store.append("source.access_unconfirmed", {}, chat)
    token, _ = issue(admin, permissions=["sources"], workspaces={"default": [HARBOR]})
    client, _ = login(app, token)
    assert client.post("/api/targets/ignore-unconfirmed", json={"chat_ids": [HARBOR, OTHER], "ignored": True}).status_code == 403
    assert not store.get_setting("ignored_source_warnings", [])
    response = client.post("/api/targets/ignore-unconfirmed", json={"chat_ids": [HARBOR], "ignored": True})
    assert response.status_code == 200, response.text
    assert set(response.json()["source_status"]) == {str(HARBOR)}
    status = client.get("/api/status").json()
    assert set(status["collector"]["source_status"]) == {str(HARBOR)}
    assert status["collector"]["source_status"][str(HARBOR)] == {"state": "access_unconfirmed", "ignored": True}
    assert status["health"]["sources"]["counts"] == {
        "enabled": 1, "checked": 1, "visible": 0, "added": 0, "unconfirmed": 0, "ignored": 1, "unconfirmed_total": 1}
    assert status["health"]["sources"]["state"] == "off"
    assert status["health"]["sources"]["reason"] == "ignored_unconfirmed"
    assert client.get("/api/notifications").json()["items"] == []
    assert len(alerts.collect(store, 0, {}, {})[1]) == 2  # External notification delivery is unchanged.
    assert len(store.events(kind="source.access_unconfirmed")) == 2
    assert client.post("/api/targets/ignore-unconfirmed", json={"chat_ids": [HARBOR], "ignored": False}).status_code == 200
    assert not store.get_setting("ignored_source_warnings", [])
    assert len(client.get("/api/notifications").json()["items"]) == 1


def test_ignore_all_or_nothing_rejects_unknown_or_currently_visible_sources(panel):
    app, admin = panel
    app.state.collector.source_status = {str(HARBOR): {"state": "access_unconfirmed"},
                                       str(OTHER): {"state": "visible_in_dialogs"}}
    for ids, expected in (([HARBOR, -999], 404), ([HARBOR, OTHER], 409)):
        response = admin.post("/api/targets/ignore-unconfirmed", json={"chat_ids": ids, "ignored": True})
        assert response.status_code == expected, response.text
        assert not app.state.store.get_setting("ignored_source_warnings", [])


def test_ignore_clears_only_after_successful_positive_dialog_visibility(journal):
    async def run():
        store, _ = journal
        collector = await prepared(journal)
        store.set_target(OTHER, "Not visible", "supergroup", True)
        store.set_setting("ignored_source_warnings", [CHAT, OTHER])
        collector.source_status = {str(c): {"state": "access_unconfirmed"} for c in (CHAT, OTHER)}
        old_warning = store.append("source.access_unconfirmed", {}, CHAT)
        await collector.restore()
        original = collector.client.iter_dialogs
        async def failed(limit):
            async for dialog in original(limit):
                yield dialog
                raise OSError("synthetic partial read")
        collector.client.iter_dialogs = failed
        with pytest.raises(OSError):
            await collector.dialogs()
        assert store.get_setting("ignored_source_warnings") == [CHAT, OTHER]
        assert not store.get_setting("resolved_source_warnings", {})
        collector.client.iter_dialogs = original
        await collector.dialogs()
        assert store.get_setting("ignored_source_warnings") == [OTHER]
        status = collector.status()
        assert status["source_status"][str(CHAT)]["state"] == "visible_in_dialogs"
        assert not status["source_status"][str(CHAT)].get("ignored")
        assert status["source_status"][str(OTHER)]["ignored"] is True
        result = health.sources(status, 2)
        assert result["state"] == "working" and result["reason"] == "visible_with_ignored"
        assert store.get_setting("resolved_source_warnings")[str(CHAT)] > old_warning["seq"]
        assert alerts.panel_items(store, {}, allowed_chats={CHAT}) == []
        new_warning = store.append("source.access_unconfirmed", {}, CHAT)
        assert [item["seq"] for item in alerts.panel_items(store, {}, allowed_chats={CHAT})] == [new_warning["seq"]]
        assert len(alerts.collect(store, 0, {}, {})[1]) == 2  # Signed history and external delivery remain unchanged.
        await collector.stop(shutdown=True)
    asyncio.run(run())


def test_status_and_workspace_chooser_limit_health_to_permitted_chats(panel):
    app, admin = panel
    store, collector = app.state.store, app.state.collector
    collector.source_status = {str(HARBOR): {"state": "visible_in_dialogs"},
                               str(OTHER): {"state": "access_unconfirmed"}}
    job(store, 8, "queued")
    store.append("message.new", {"text": "Hidden"}, OTHER, 9,
                 media_job={"account_id": 44, "descriptor": b"hidden", "max_bytes": 20})
    with store.transaction():
        store.db.execute("UPDATE media_jobs SET state='failed' WHERE chat_id=?", (OTHER,))
    store.append("recheck.completed", {"chats": [
        {"chat_id": HARBOR, "checked": 2, "edited": 1},
        {"chat_id": OTHER, "checked": 900, "recovered": 10, "error": "HiddenError"}],
        "checked": 902, "errors": 1})
    collector.recheck_state = {"chats": 2, "checked": 902, "errors": 1}
    collector.export_state = {"id": "allowed-export", "chat_id": HARBOR, "captured": 3}
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    client, _ = login(app, token)
    for data in (client.get("/api/status").json(), client.get("/api/profiles").json()["profiles"][0]):
        assert set(data["collector"]["source_status"]) == {str(HARBOR)}
        assert data["collector"]["media_jobs"] == {"queued": 1}
        assert data["collector"]["media_pending"] == 1
        assert data["health"]["sources"]["counts"]["enabled"] == 1
        assert data["health"]["sources"]["counts"]["unconfirmed"] == 0
        assert data["health"]["media"]["counts"] == {"pending": 1, "retry": 0, "failed": 0}
        assert data["collector"]["chat_export"] == collector.export_state
        assert data["collector"]["recheck"] | {"at": None} == {
            "at": None, "chats": 1, "errors": 0, "recovered": 0, "edited": 1, "missing": 0, "checked": 2}
    profile = client.get("/api/profiles").json()["profiles"][0]
    assert (profile["sources_total"], profile["sources_enabled"]) == (1, 1)
    collector.export_state = {"id": "hidden-export", "chat_id": OTHER, "captured": 100}
    for data in (client.get("/api/status").json(), client.get("/api/profiles").json()["profiles"][0]):
        assert data["collector"]["chat_export"] is None
    assert store.media_stats(set()) == {} and store.media_oldest(set()) is None
    assert admin.get("/api/status").json()["collector"]["media_jobs"] == {"queued": 1, "failed": 1}
    assert admin.get("/api/profiles").json()["profiles"][0]["sources_total"] == 2


def test_queue_clear_is_confined_to_the_current_workspace(panel):
    app, admin = panel
    main_job = job(app.state.store, 1)
    profile_id = admin.post("/api/profiles", json={"label": "Other account"}).json()["id"]
    store = app.state.profiles.entries[profile_id]["app"].state.store
    other_job = job(store, 2)
    response = admin.post(f"/profiles/{profile_id}/api/media/queue/clear", json={"through_seq": other_job["seq"]})
    assert response.status_code == 200 and response.json()["cancelled"] == 1, response.text
    assert store.media_stats() == {"cancelled": 1}
    assert app.state.store.media_stats() == {"queued": 1}
    assert app.state.store.events(before=main_job["seq"] + 1, limit=1)[0]["seq"] == main_job["seq"]


@pytest.mark.parametrize("body", (
    {"chat_ids": [True], "ignored": True}, {"chat_ids": [HARBOR], "ignored": "true"},
    {"chat_ids": [0], "ignored": True}, {"chat_ids": [2**53], "ignored": True},
))
def test_ignore_source_input_is_strict(panel, body):
    _, admin = panel
    assert admin.post("/api/targets/ignore-unconfirmed", json=body).status_code == 422
