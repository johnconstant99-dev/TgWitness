import asyncio
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import interactions, middleware, security
from tgwitness.store import Store


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL regression")
def test_acl_repairs_explicit_grants_and_does_not_trust_marker(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    target = child / "synthetic.txt"
    target.write_text("synthetic")
    (tmp_path / ".owner-only").write_text("old marker")
    for path in (tmp_path, target):
        subprocess.run(["icacls", str(path), "/grant:r", "*S-1-1-0:R", "/Q"],
                       capture_output=True, check=True, timeout=30)
    assert not security.owner_only_state(tmp_path)[0]
    security.owner_only(tmp_path)
    assert security.owner_only_state(tmp_path)[0]
    (child / "new.txt").write_text("synthetic")
    assert security.owner_only_state(tmp_path)[0]
    subprocess.run(["icacls", str(target), "/grant:r", "*S-1-1-0:R", "/Q"],
                   capture_output=True, check=True, timeout=30)
    assert not security.owner_only_state(tmp_path)[0]
    security.owner_only(tmp_path)
    assert security.owner_only_state(tmp_path)[0]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows filesystem-link regression")
def test_acl_does_not_follow_directory_link(tmp_path):
    root, outside = tmp_path / "data", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Creating directory symlinks requires Windows privilege")
    from tgwitness.windows_acl import paths
    with pytest.raises(OSError, match="filesystem link"):
        list(paths(root))
    with patch("tgwitness.security.LOG.warning") as warning:
        security.owner_only(root)
        assert warning.called
    assert not security.owner_only_state(root)[0]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL inheritance regression")
@pytest.mark.parametrize("nested", [False, True])
def test_acl_repairs_non_inheritable_directory_grant(tmp_path, nested):
    from tgwitness.windows_acl import WindowsAcl
    security.owner_only(tmp_path)
    folder = tmp_path / "protected-child" if nested else tmp_path
    folder.mkdir(exist_ok=True)
    sid = security.windows_sid()
    acl = WindowsAcl(sid)
    try:
        acl.sddl = "D:P(A;;FA;;;" + sid + ")"
        acl.restrict(folder)
    finally:
        acl.close()
    assert not security.owner_only_state(tmp_path)[0]
    security.owner_only(tmp_path)
    (folder / "new.txt").write_text("synthetic")
    assert security.owner_only_state(tmp_path)[0]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows hardlink ACL regression")
def test_acl_external_hardlink_is_unchanged_and_internal_links_work(tmp_path):
    root, outside = tmp_path / "data", tmp_path / "outside.txt"
    root.mkdir()
    outside.write_text("synthetic")
    link = root / "linked.txt"
    os.link(outside, link)
    def shown(path):
        return subprocess.run(["icacls", str(path)], capture_output=True, check=True, timeout=30).stdout
    before = shown(outside), shown(root)
    security.owner_only(root)
    assert (shown(outside), shown(root)) == before
    assert not security.owner_only_state(root)[0]
    link.unlink()
    original = root / "original.txt"
    original.write_text("synthetic")
    os.link(original, link)
    security.owner_only(root)
    assert security.owner_only_state(root)[0]


def scope(path="/api/auth/import"):
    return {"type": "http", "path": path, "root_path": "", "method": "POST", "headers": []}


def test_body_timeouts_and_disconnect_release_reservations():
    async def run():
        app = AsyncMock()
        limit = middleware.RequestLimit(app)
        for path in ("/api/auth/import", "/api/profiles/import", "/api/status", "/mcp"):
            replies, first = [], True
            async def receive():
                nonlocal first
                if first:
                    first = False
                    return {"type": "http.request", "body": b"synthetic", "more_body": True}
                await asyncio.Event().wait()
            async def send(message):
                replies.append(message)
            with patch.object(middleware, "BODY_TIMEOUT", .03), patch.object(middleware, "MCP_BODY_TIMEOUT", .02):
                await limit(scope(path), receive, send)
            assert replies[0]["status"] == 408 and limit.pending_bodies == limit.pending_bytes == 0
        await limit(scope(), AsyncMock(return_value={"type": "http.disconnect"}), AsyncMock())
        assert limit.pending_bodies == limit.pending_bytes == 0
        app.assert_not_awaited()
    asyncio.run(run())


def test_body_admission_is_bounded_and_cancellation_releases_capacity():
    async def run():
        app, gate, entered = AsyncMock(), asyncio.Event(), asyncio.Event()
        limit = middleware.RequestLimit(app, max_body=32, path_limits=False)
        async def receive():
            entered.set()
            await gate.wait()
            return {"type": "http.request", "body": b"ok", "more_body": False}
        for bodies, size in ((1, 100), (8, 32)):
            with patch.object(middleware, "MAX_PENDING_BODIES", bodies), patch.object(middleware, "MAX_PENDING_BODY_BYTES", size):
                entered.clear()
                waiting = asyncio.create_task(limit(scope(), receive, AsyncMock()))
                await entered.wait()
                replies = []
                async def send(message):
                    replies.append(message)
                rejected_receive = AsyncMock()
                await limit(scope(), rejected_receive, send)
                assert replies[0]["status"] == 503
                rejected_receive.assert_not_awaited()
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting
                assert limit.pending_bodies == limit.pending_bytes == 0
        gate.set()
        await limit(scope(), receive, AsyncMock())
        assert app.await_count == 1 and limit.pending_bodies == limit.pending_bytes == 0
    asyncio.run(run())


def test_legitimate_chunked_body_is_replayed_and_size_still_enforced():
    async def run():
        captured = []
        async def app(request_scope, receive, send):
            captured.append((await receive())["body"])
        limit = middleware.RequestLimit(app, max_body=12, path_limits=False)
        for chunks, expected in (([b"123", b"456"], 200), ([b"1234567", b"8901234"], 413)):
            index, replies = 0, []
            async def receive():
                nonlocal index
                await asyncio.sleep(.005)
                index += 1
                return {"type": "http.request", "body": chunks[index - 1], "more_body": index < len(chunks)}
            async def send(message):
                replies.append(message)
            await limit(scope(), receive, send)
            if expected == 413:
                assert replies[0]["status"] == 413
        assert captured == [b"123456"] and limit.pending_bodies == limit.pending_bytes == 0
    asyncio.run(run())


@pytest.mark.parametrize("active,legacy", [("evidence", "copy"), (None, "evidence")])
@pytest.mark.parametrize("body", [
    {"action": "send", "chat_id": 123, "text": "synthetic"},
    {"action": "open", "preview_id": "a" * 32},
    {"action": "press", "chat_id": 123, "message_id": 1, "keyboard_event": 1, "row": 0, "column": 0},
])
def test_evidence_goal_refuses_all_mutating_actions_before_telegram(tmp_path, active, legacy, body):
    store = Store(tmp_path)
    try:
        store.set_setting("setup", {"goal": legacy})
        if active:
            store.set_setting("goal_preset", {"goal": active})
        collector = SimpleNamespace(store=store, restore=AsyncMock())
        request = interactions.Action(request_id="synthetic-request", **body)
        with pytest.raises(ValueError, match="Telegram actions"):
            asyncio.run(interactions.execute(collector, request))
        collector.restore.assert_not_awaited()
        assert not store.get_setting("interaction.action.synthetic-request", None)
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
