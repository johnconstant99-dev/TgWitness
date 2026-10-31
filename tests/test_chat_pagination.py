"""Adjacent chat windows stay ordered, bounded and scoped to the allowed chat."""
import pytest

from test_access import HARBOR, OTHER, issue, login, panel  # noqa: F401


def test_chat_windows_walk_both_directions_without_skips(journal):
    store, _ = journal
    wanted = [1, 4, 9, 25, 80, 81, 99]
    for chat in (HARBOR, OTHER):
        for mid in wanted:
            store.append("message.new", {"text": f"{chat}:{mid}"}, chat, mid)
    page = store.chat_messages(HARBOR, limit=3)
    assert [m["message_id"] for m in page["messages"]] == [80, 81, 99]
    assert page["next_before"] == 80 and page["next_after"] is None
    older = store.chat_messages(HARBOR, before_id=page["next_before"], limit=3)
    assert [m["message_id"] for m in older["messages"]] == [4, 9, 25]
    assert older["next_before"] == 4 and older["next_after"] == 25
    newer = store.chat_messages(HARBOR, after_id=older["next_after"], limit=2)
    assert [m["message_id"] for m in newer["messages"]] == [80, 81]
    assert newer["next_before"] == 80 and newer["next_after"] == 81
    first = store.chat_messages(HARBOR, before_id=4, limit=3)
    assert first["next_before"] is None and first["next_after"] == 1
    assert store.chat_messages(HARBOR, after_id=99)["messages"] == []
    assert all(m["text"].startswith(str(HARBOR)) for m in newer["messages"])
    with pytest.raises(ValueError):
        store.chat_messages(HARBOR, before_id=9, after_id=1)
    with pytest.raises(ValueError):
        store.chat_messages(HARBOR, limit=201)


def test_chat_forward_api_enforces_bounds_and_chat_access(panel):  # noqa: F811
    app, admin = panel
    for mid in range(2, 215):
        app.state.store.append("message.new", {"text": str(mid)}, HARBOR, mid)
    token, _ = issue(admin, workspaces={"default": [HARBOR]})
    browser, _ = login(app, token)
    response = browser.get(f"/api/chats/{HARBOR}/messages?after_id=1&limit=200")
    assert response.status_code == 200
    data = response.json()
    assert [m["message_id"] for m in data["messages"]] == list(range(2, 202))
    assert data["next_after"] == 201
    assert browser.get(f"/api/chats/{OTHER}/messages?after_id=1").status_code == 403
    assert browser.get(f"/api/chats/{HARBOR}/messages?after_id=1&before_id=30").status_code == 422
    assert browser.get(f"/api/chats/{HARBOR}/messages?limit=201").status_code == 422
