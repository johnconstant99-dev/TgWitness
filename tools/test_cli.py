"""Command-line archive access: local and panel modes, scoped tokens, statistics and export."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import activity, archive_api, cli  # noqa: E402
from tgwitness.access import Principal, Refused  # noqa: E402
from tgwitness.archive import MCP_TOOLS, TOOLS, ArchiveQuery, ArchiveReader  # noqa: E402
from tgwitness.security import InstanceLock, Vault  # noqa: E402
from tgwitness.store import Store  # noqa: E402

CHAT, OTHER = -1001000000001, -1001000000002
LONG = "Длинное сообщение " * 300


def fill(store):
    store.set_target(CHAT, "Synthetic sellers", "supergroup", True)
    store.set_target(OTHER, "Synthetic other", "supergroup", True)
    for message, sender, sent, text, username in (
            (1, 7, "2026-10-05T09:15:00+00:00", "Оплата переводом, пишите @fixture_seller", "fixture_seller"),
            (2, 7, "2026-10-05T09:45:00+00:00", "Второй перевод через pay.example-pay.test", "fixture_seller"),
            (3, 8, "2026-10-07T21:00:00+00:00", "Evening message", None),
            (4, 8, "2026-10-07T21:30:00+00:00", "This will be deleted", None)):
        store.append("message.new", {"text": text, "sender_id": sender, "sent_at": sent,
                                     "sender_observation": {"display_name": "Sender " + str(sender), "username": username}},
                     CHAT, message, sender)
    store.append("message.edited", {"text": "Оплата только переводом", "sender_id": 7}, CHAT, 1, 7)
    store.append("message.deleted", {}, CHAT, 4)
    store.append("message.missing_on_recheck", {}, CHAT, 3)
    store.append("message.new", {"text": "Other chat: visit other.example.org", "sender_id": 9,
                                 "sent_at": "2026-10-06T12:00:00+00:00"}, OTHER, 1, 9)
    store.append("message.new", {"text": LONG, "sender_id": 9, "sent_at": "2026-10-06T12:05:00+00:00"}, OTHER, 2, 9)


@pytest.fixture
def workspace(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    fill(store)
    store.close()
    return tmp_path


def run(capsys, *args):
    code = cli.main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def document(capsys, *args):
    code, out, err = run(capsys, *args, "--json")
    assert code == 0, err
    return json.loads(out)


def reader(store, chats):
    principal = (Principal(True, "Synthetic admin") if chats is None else
                 Principal(False, "Synthetic reviewer", {"id": "synthetic", "workspaces": {"default": chats},
                                                         "all_workspaces": False, "permissions": ["view"],
                                                         "expires_at": None}))
    state = type("State", (), {"store": store, "collector": type("Collector", (), {"running": False})()})()
    registry = type("Registry", (), {"entries": {"default": {"app": type("App", (), {"state": state})(),
                                                             "label": "Synthetic"}}})()
    return ArchiveReader(registry, principal)


def test_activity_counts_saved_observations(workspace):
    store = Store(workspace)
    try:
        result = activity.activity(store, chat_id=CHAT)
        assert result["complete"] and result["messages"] == 4 and result["senders"] == 2
        assert result["by_hour_utc"][9] == 2 and result["by_hour_utc"][21] == 2 and sum(result["by_hour_utc"]) == 4
        assert result["by_weekday_utc"][0] == 2 and result["by_weekday_utc"][2] == 2, "Monday first"
        assert result["edited"] == {"messages": 1, "share": 0.25, "versions": 1}
        assert result["deleted"]["messages"] == 1 and result["missing_on_recheck"]["messages"] == 1
        assert [p["sender_id"] for p in result["participants"]] == [7, 8]
        assert result["participants"][0]["username"] == "fixture_seller" and result["participants"][0]["edited"] == 1
        assert result["participants"][1]["deleted"] == 1
        assert result["domains"] == [{"domain": "pay.example-pay.test", "messages": 1}]
        assert result["handles"] == [{"handle": "@fixture_seller", "messages": 1}], "A handle edited out still counts"
        assert result["first_message_at"] == "2026-10-05T09:15:00+00:00"
        assert result["peaks"]["days"][0]["messages"] == 2
        assert result["journal_head"]["hash"] == store.stats()["head"]["hash"]
        later = activity.activity(store, chat_id=CHAT, since=datetime(2026, 10, 6, tzinfo=timezone.utc))
        assert later["messages"] == 2 and later["by_hour_utc"][21] == 2, "The period selects message time"
        one = activity.activity(store, chat_id=CHAT, sender_id=7)
        assert one["messages"] == 2 and one["edited"]["messages"] == 1 and one["deleted"]["messages"] == 0
        everything = activity.activity(store)
        assert everything["messages"] == 6 and {d["domain"] for d in everything["domains"]} == {
            "pay.example-pay.test", "other.example.org"}
        cut = activity.activity(store, chat_id=CHAT, budget=0)
        assert not cut["complete"] and cut["partial"]["records_before_seq_not_read"]
    finally:
        store.close()


def test_activity_marks_unconfirmed_collection(workspace):
    vault, store = Vault(workspace), Store(workspace)
    store.bind(vault)
    try:
        beats = [store.append("collector.heartbeat", {"connected": True, "interval_seconds": 60}) for _ in range(2)]
        when = [datetime.fromisoformat(beat["observed_at"]).timestamp() for beat in beats]
        with store.snapshot() as snapshot:
            result = activity.unconfirmed(snapshot.connection, when[0] - 3600, when[1] + 7200, time.monotonic() + 5)
        assert result["complete"] and result["intervals"] == 2
        assert 3500 < result["longest"][0]["seconds"] <= 3600 and result["unconfirmed_seconds"] >= 3600 + 7000
        store.append("coverage.gap", {"reason": "transport_disconnected"})
        store.append("coverage.gap", {"reason": "recheck_visibility_uncertain"}, CHAT)
        full = reader(store, None).read(ArchiveQuery(tool="get_activity_stats", chat_id=CHAT))
        assert full["coverage"]["gap_records"]["count"] == 2 and "collector_liveness" in full["coverage"]
        scoped = reader(store, [CHAT]).read(ArchiveQuery(tool="get_activity_stats", chat_id=CHAT))
        assert scoped["coverage"]["gap_records"]["count"] == 1, "Workspace gaps stay with full-workspace access"
        assert "collector_liveness" not in scoped["coverage"] and "journal_head" not in scoped
        assert not scoped["coverage"]["workspace_gaps_visible"] and scoped["messages"] == 4
        whole = reader(store, [CHAT]).read(ArchiveQuery(tool="get_activity_stats"))
        assert whole["messages"] == 4, "Without a chat, statistics cover only permitted chats"
        with pytest.raises(Refused):
            reader(store, [CHAT]).read(ArchiveQuery(tool="get_activity_stats", chat_id=OTHER))
    finally:
        store.close()


def test_local_commands(workspace, capsys):
    base = ("--data-dir", str(workspace))
    found = document(capsys, "search", "перевод", *base)
    assert found["ranked"] and {item["source"]["message_id"] for item in found["items"]} == {1, 2}
    assert all(item["source"]["chat_id"] == CHAT and item["untrusted_content"] for item in found["items"])
    exact = document(capsys, "search", "Оплата", "--exact", *base)
    assert not exact.get("ranked") and {item["kind"] for item in exact["items"]} == {"message.new", "message.edited"}
    near = document(capsys, "context", str(CHAT), "2", *base)
    assert {item["source"]["message_id"] for item in near["items"]} == {1, 2, 3, 4}
    chats = document(capsys, "messages", *base)
    assert {item["chat_id"] for item in chats["items"]} == {CHAT, OTHER}
    names = document(capsys, "messages", "--workspaces", *base)
    assert names["items"] == [{"workspace": "default", "name": "Main account"}]
    listed = document(capsys, "messages", str(CHAT), "--limit", "2", *base)
    assert len(listed["items"]) == 2 and listed["next_before"]
    versions = document(capsys, "messages", str(CHAT), "--message", "1", *base)
    assert [item["kind"] for item in versions["items"]] == ["message.edited", "message.new"]
    counted = document(capsys, "stats", "--chat", str(CHAT), "--since", "2026-10-06", *base)
    assert counted["messages"] == 2 and counted["workspace"] == "default"
    code, text, _ = run(capsys, "stats", "--chat", str(CHAT), *base)
    assert code == 0 and "4 messages from 2 senders" in text and "@fixture_seller (1)" in text
    code, text, _ = run(capsys, "search", "перевод", *base)
    assert code == 0 and text.startswith("#") and "chat " + str(CHAT) in text

    target = workspace.parent / "export.jsonl"
    summary = document(capsys, "export", "--output", str(target), *base)
    rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert summary["records"] == len(rows) == 9 and summary["format"] == "jsonl"
    assert [row["source"]["event_seq"] for row in rows] == sorted(row["source"]["event_seq"] for row in rows)
    long = next(row for row in rows if row["source"]["message_id"] == 2 and row["source"]["chat_id"] == OTHER)
    assert long["text"] == LONG and not long["text_truncated"], "An export keeps the whole text"
    assert summary["journal_head"]["seq"] == max(row["source"]["event_seq"] for row in rows)
    assert not target.with_name(target.name + ".partial").exists()
    code, _, err = run(capsys, "export", "--output", str(target), *base)
    assert code == 2 and "exists" in err
    leftover = workspace.parent / "again.jsonl.partial"
    leftover.write_text("", encoding="utf-8")
    code, _, err = run(capsys, "export", "--output", str(workspace.parent / "again.jsonl"), *base)
    assert code == 2 and "interrupted export" in err and leftover.exists()
    code, out, _ = run(capsys, "export", "--chat", str(OTHER), *base)
    assert code == 0 and [json.loads(line)["source"]["message_id"] for line in out.splitlines()] == [1, 2]


def test_exit_codes_and_clean_stdout(workspace, capsys, monkeypatch):
    base = ("--data-dir", str(workspace))
    monkeypatch.delenv("TGWITNESS_MCP_TOKEN", raising=False)
    assert run(capsys, "search", "перевод", "--since", "2026-10-06T10:00", *base)[0] == 2, "A time needs a timezone"
    assert run(capsys, "search", "перевод", "--before", "5", *base)[0] == 2
    assert run(capsys, "messages", str(CHAT), "--workspace", "missing", *base)[0] == 1
    assert run(capsys, "messages", "--data-dir", str(workspace), "--url", "http://127.0.0.1:1")[0] == 2
    monkeypatch.setenv("TGWITNESS_MCP_TOKEN", "not-a-token")
    assert run(capsys, "messages", "--url", "http://127.0.0.1:1")[0] == 2
    monkeypatch.setenv("TGWITNESS_MCP_TOKEN", "tgw_mcp_" + "a" * 43)
    assert run(capsys, "messages", "--url", "http://example.org")[0] == 2, "Remote panels need HTTPS"
    code, out, err = run(capsys, "messages", "--url", "http://127.0.0.1:1")
    assert code == 1 and out == "" and "Could not reach" in err
    monkeypatch.delenv("TGWITNESS_MCP_TOKEN")
    with patch.object(Store, "__init__", side_effect=AssertionError("must not open")):
        lock = InstanceLock(workspace)
        try:
            code, out, err = run(capsys, "search", "перевод", *base)
            assert code == 3 and out == "" and "--url" in err
        finally:
            lock.close()
    process = subprocess.run([sys.executable, "-m", "tgwitness", "stats", "--chat", str(CHAT), "--json", *base],
                             capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=120)
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["messages"] == 4


def test_output_is_utf8_on_any_pipe(monkeypatch):
    import io
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    cli.utf8_output()
    print("我 перевод ✅")
    stream.flush()
    assert buffer.getvalue().decode("utf-8").strip() == "我 перевод ✅"


def test_tool_lists():
    assert set(TOOLS) - set(MCP_TOOLS) == {"export_messages"} and "get_activity_stats" in MCP_TOOLS
    from tgwitness.archive import ConnectionSettings, Connections

    class Saved:
        def __init__(self):
            self.data = {}

        def read(self, name):
            return self.data.get(name, {})

        def save(self, name, value):
            self.data[name] = value
    connections = Connections(Saved())
    token, _ = connections.issue(ConnectionSettings(name="Legacy", workspaces={"default": [CHAT]},
                                                    expires_in_seconds=3600))
    del connections.entries[0]["tools"]
    assert connections.resolve(token, tool="search_messages").grant["tools"] == list(TOOLS[:7])
    for tool in ("get_activity_stats", "export_messages"):
        with pytest.raises(Refused):
            connections.resolve(token, tool=tool)


@contextmanager
def panel(path):
    import uvicorn
    from tgwitness.app import create_app
    from tgwitness.proxy_catalog import ProxyPool
    from tools.browser_fixtures import FakeClient
    from tools.check_session_reservations import idle, pinned, probe
    with patch.object(ProxyPool, "run", idle), patch.object(ProxyPool, "pin", staticmethod(pinned)), \
            patch.object(ProxyPool, "probe", staticmethod(probe)):
        app = create_app(path, client_factory=FakeClient)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False, timeout_graceful_shutdown=5))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 45
            while not server.started:
                assert thread.is_alive() and time.monotonic() < deadline, "Test panel did not start"
                time.sleep(.05)
            yield app, "http://127.0.0.1:" + str(sock.getsockname()[1])
        finally:
            server.should_exit = True
            thread.join(timeout=30)
            sock.close()


def test_panel_mode_uses_scoped_connection(tmp_path, capsys, monkeypatch):
    with panel(tmp_path) as (app, url):
        fill(app.state.store)
        admin = {"Authorization": "Bearer " + app.state.vault.token}
        tools = [tool for tool in TOOLS if tool != "get_activity_stats"]
        issued = requests.post(url + "/api/integrations/mcp", headers=admin, timeout=10, json={
            "name": "CLI test", "workspaces": {"default": [CHAT]}, "tools": tools,
            "expires_in_seconds": 3600}).json()
        monkeypatch.setenv("TGWITNESS_MCP_TOKEN", issued["token"])
        base = ("--url", url)
        found = document(capsys, "search", "перевод", *base)
        assert {item["source"]["chat_id"] for item in found["items"]} == {CHAT}
        assert set(found["index"]) == {"complete"}, "Scoped access sees no journal totals"
        assert {item["chat_id"] for item in document(capsys, "messages", *base)["items"]} == {CHAT}
        code, out, err = run(capsys, "messages", str(OTHER), *base)
        assert code == 4 and out == "" and "403" in err
        assert run(capsys, "stats", "--chat", str(CHAT), *base)[0] == 4, "A tool outside the connection is refused"
        target = tmp_path.parent / (tmp_path.name + "-remote.jsonl")
        summary = document(capsys, "export", "--output", str(target), *base)
        rows = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        assert summary["records"] == len(rows) == 7 and {row["source"]["chat_id"] for row in rows} == {CHAT}
        assert "journal_head" not in summary
        assert requests.post(url + "/api/archive/query", timeout=10, json={"tool": "export_messages"},
                             headers={"Authorization": "Bearer " + issued["token"]}).status_code == 422
        requests.delete(url + "/api/integrations/mcp/" + issued["connection"]["id"], headers=admin, timeout=10)
        code, out, _ = run(capsys, "search", "перевод", *base)
        assert code == 4 and out == ""

        full = requests.post(url + "/api/integrations/mcp", headers=admin, timeout=10, json={
            "name": "CLI statistics", "workspaces": {"default": None}, "expires_in_seconds": 3600}).json()
        monkeypatch.setenv("TGWITNESS_MCP_TOKEN", full["token"])
        counted = document(capsys, "stats", "--chat", str(CHAT), *base)
        assert counted["messages"] == 4 and "collector_liveness" in counted["coverage"]
        assert set(full["connection"]["tools"]) == set(MCP_TOOLS), "Bulk export is granted only when chosen"
        assert run(capsys, "export", *base)[0] == 4


@pytest.mark.parametrize("after_record", [False, True])
def test_export_revocation_before_first_record_or_completion(tmp_path, after_record):
    entered, release = threading.Event(), threading.Event()
    record = {"source": {"chat_id": CHAT}, "text": "Synthetic streamed record"}
    def controlled(reader, query):
        def lines():
            if after_record:
                yield record
            entered.set()
            assert release.wait(15), 'Test did not release the export read'
            if not after_record:
                yield record
            yield {"export_complete": {"records": 1}}
        return lines()
    with panel(tmp_path) as (app, url), patch.object(ArchiveReader, 'export', controlled):
        manager = archive_api.connections(app)
        token, entry = manager.issue(archive_api.ConnectionSettings(
            name='Synthetic revocation', workspaces={'default': [CHAT]}, tools=['export_messages'], expires_in_seconds=3600))
        response = requests.post(url + '/api/archive/export', headers={'Authorization': 'Bearer ' + token},
                                 json={'tool': 'export_messages'}, stream=True, timeout=20)
        try:
            assert response.status_code == 200 and entered.wait(10)
            manager.revoke(entry['id'])
            release.set()
            rows = [json.loads(line) for line in response.iter_lines() if line]
            assert rows == ([record] if after_record else []), 'A revoked stream emitted more data or completion'
        finally:
            release.set()
            response.close()


def test_export_iteration_holds_archive_worker_budget(tmp_path):
    with panel(tmp_path) as (app, url):
        import asyncio
        budget = app.state.archive_slots = asyncio.Semaphore(1)
        def controlled(reader, query):
            def lines():
                assert budget.locked(), 'Lazy export reads escaped the archive worker budget'
                yield {"export_complete": {"records": 0}}
            return lines()
        manager = archive_api.connections(app)
        token, _ = manager.issue(archive_api.ConnectionSettings(
            name='Synthetic worker limit', workspaces={'default': [CHAT]}, tools=['export_messages'], expires_in_seconds=3600))
        with patch.object(ArchiveReader, 'export', controlled):
            response = requests.post(url + '/api/archive/export', headers={'Authorization': 'Bearer ' + token},
                                     json={'tool': 'export_messages'}, timeout=15)
        assert response.status_code == 200
        assert response.json() == {"export_complete": {"records": 0}}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
