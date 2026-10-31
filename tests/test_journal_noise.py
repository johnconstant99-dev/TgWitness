from test_access import HARBOR, OTHER, issue, login, panel as panel


def test_hide_routine_records_before_limit_without_hiding_failures_or_evidence(panel):
    app, admin = panel
    store = app.state.store
    important = []
    for kind, payload in (("message.edited", {"text": "Changed instruction"}),
                          ("media.failed", {"reason": "download failed"}),
                          ("media.skipped", {"reason": "attachment type not collected by policy: video"})):
        important.append(store.append(kind, payload, HARBOR, 8))
    for _ in range(6):
        store.append("collector.heartbeat", {"running": True})
        store.append("host.state", {"state": {"ssh_listening": False}})
        store.append("media.skipped", {"reason": "media download disabled"}, HARBOR, 9)
    original = store.all_events()
    response = admin.get("/api/events", params={"hide_system": "true", "limit": 2})
    assert response.status_code == 200
    assert [event["seq"] for event in response.json()["events"]] == [event["seq"] for event in important[-1:0:-1]]
    rest = admin.get("/api/events", params={"hide_system": "true", "kind": "message.edited,media",
                    "before": response.json()["next_before"]}).json()["events"]
    assert [event["seq"] for event in rest] == [important[0]["seq"]]
    assert admin.get("/api/events", params={"limit": 1}).json()["events"][0]["kind"] == "media.skipped"
    assert store.all_events() == original
    assert store.verify(app.state.vault.public_key)["events"] == len(original)


def test_routine_filter_keeps_scope_and_explicit_record_access(panel):
    app, admin = panel
    store = app.state.store
    allowed = store.append("media.skipped", {"reason": "media download disabled"}, HARBOR, 1)
    store.append("message.edited", {"text": "Private hidden record"}, OTHER, 2)
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    client, _ = login(app, token)
    visible = client.get("/api/events", params={"hide_system": "true", "kind": "media"}).json()["events"]
    assert visible == []
    direct = client.get("/api/events", params={"before": allowed["seq"]+1, "limit": 1}).json()["events"]
    assert direct[0]["seq"] == allowed["seq"]
    all_records = client.get("/api/events", params={"hide_system": "false"}).json()["events"]
    assert all(record["chat_id"] == HARBOR for record in all_records)
