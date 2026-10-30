from fastapi.testclient import TestClient

from tgwitness import alerts
from tgwitness.app import create_app
from test_alerts import enable, receiver, run  # noqa: F401  (receiver is a fixture)
from test_collector import FakeClient


def test_text_excerpts_only_when_turned_on_and_new_chats_are_announced(journal, receiver):  # noqa: F811
    store, vault = journal
    store.set_target(-1001, "Harbor Community", "supergroup", True)
    run(store, vault)
    enable(store, vault, [receiver.url()], problems=False, daily=False, changes=True)
    store.append("message.new", {"text": "Pay to the new wallet now"}, chat_id=-1001, message_id=5)
    store.append("message.deleted", {}, chat_id=-1001, message_id=5)
    store.append("source.discovered", {"title": "Fresh bot", "kind": "bot"}, chat_id=4242)
    assert run(store, vault)["notifications"] == 1
    body = receiver.requests[-1]["body"]["message"]
    assert "New chat under observation: Fresh bot" in body and "Pay to the new wallet" not in body
    enable(store, vault, [receiver.url()], problems=False, daily=False, changes=True, include_text=True)
    store.append("message.edited", {"text": "Pay to " + "x" * 300}, chat_id=-1001, message_id=5)
    assert run(store, vault)["notifications"] == 1
    body = receiver.requests[-1]["body"]["message"]
    assert "Harbor Community · edited #5: Pay to xxx" in body and body.endswith("…")


def test_busy_chat_is_grouped_and_cannot_push_problems_out_of_the_panel_list(journal, monkeypatch):
    store, vault = journal
    monkeypatch.setattr("tgwitness.store.utcnow", lambda: "2026-10-29T12:30:00.000+00:00")  # one hour
    store.set_target(-1001, "Harbor Community", "supergroup", True)
    store.append("coverage.gap", {"reason": "authorization_required"})
    for i in range(1, 121):
        store.append("message.deleted", {}, chat_id=-1001, message_id=i)
    store.append("message.edited", {"text": "x"}, chat_id=-1001, message_id=200)
    for _ in range(40):  # completed copies are not problems and must not hide the sign-out
        store.append("replica.completed", {})
    words = alerts.i18n.words("en")
    items = alerts.panel_items(store, words, limit=10)
    assert [i["level"] for i in items] == ["change", "problem"]
    assert items[0]["text"] == "Harbor Community: 120 deleted, 1 edited, 0 not found" and items[0]["records"] == 121
    assert items[1]["text"] == "Telegram signed this account out. Sign in again to resume observation."


def test_panel_lists_problems_and_changes_in_the_panel_language(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        store = app.state.store
        store.set_target(-1001, "Harbor Community", "supergroup", True)
        store.append("storage.low", {"free_bytes": 1024})
        store.append("message.deleted", {}, chat_id=-1001, message_id=9)
        store.append("collector.heartbeat", {})
        items = c.get("/api/notifications").json()["items"]
        assert [(i["kind"], i["level"]) for i in items] == [("message.deleted", "change"), ("storage.low", "problem")]
        assert items[0]["text"] == "Message #9 deleted in Harbor Community" and items[0]["chat_id"] == -1001
        c.cookies.set("tgwitness-lang", "ru")
        translated = c.get("/api/notifications").json()["items"][1]["text"]
        expected = alerts.tr(alerts.i18n.words("ru"), "Disk almost full: {size} free. Photo and file downloads are paused.",
                             size="1.0 KB")
        assert translated == expected
