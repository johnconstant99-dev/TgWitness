import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from tgwitness import alerts, i18n
from tgwitness.app import create_app
from tgwitness.network import NetworkConfig
from test_collector import FakeClient

DIRECT = NetworkConfig(kind="direct")


class Receiver:
    """A local HTTP endpoint (or forward proxy) that records what Apprise sends."""

    def __init__(self, status=200):
        self.requests, receiver = [], self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                receiver.requests.append({"path": self.path, "body": json.loads(body or b"{}")})
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, path="hook"):
        return "json://127.0.0.1:%d/%s" % (self.port, path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def enable(store, vault, urls, **settings):
    store.set_setting("alerts", {"enabled": True, "problems": True, "changes": True, "daily": False, **settings})
    vault.save("alerts", {"urls": urls})


def run(store, vault, network=DIRECT, now=None):
    return asyncio.run(alerts.alert_pass(store, vault, network, now))


def test_deliver_reaches_an_http_destination(receiver):
    result = alerts.deliver([receiver.url()], "Title", "Body", DIRECT)
    assert result == {"sent": 1, "failed": 0, "error": None}
    assert receiver.requests[0]["path"] == "/hook"
    assert receiver.requests[0]["body"]["title"] == "Title"
    assert receiver.requests[0]["body"]["message"] == "Body"


@pytest.mark.parametrize("accepted", [True, False])
def test_deliver_understands_apprise_1_results(monkeypatch, accepted):
    import apprise
    monkeypatch.setattr(apprise.Apprise, "notify", lambda self, **kwargs: accepted)
    result = alerts.deliver(["json://127.0.0.1:9/a", "json://127.0.0.1:9/b"], "Title", "Body", DIRECT)
    assert result == ({"sent": 2, "failed": 0, "error": None} if accepted else
                      {"sent": 0, "failed": 2, "error": "The service did not accept the notification."})


def test_deliver_goes_only_through_the_workspace_proxy(receiver):

    proxy = NetworkConfig(kind="http", host="127.0.0.1", port=receiver.port)
    result = alerts.deliver(["json://203.0.113.9:9/hook"], "Title", "Body", proxy)
    assert result["sent"] == 1
    assert receiver.requests[0]["path"] == "http://203.0.113.9:9/hook"


def test_routes_that_cannot_carry_notifications_are_refused():
    mtproxy = NetworkConfig(kind="mtproxy", host="proxy.example", port=443, secret="00" * 16)
    socks = NetworkConfig(kind="socks5", host="127.0.0.1", port=1080)
    assert "MTProxy" in alerts.deliver(["json://127.0.0.1:9/x"], "T", "B", mtproxy)["error"]
    assert alerts.route_problem(["mailto://user:pass@example.com"], socks)
    assert alerts.route_problem(["json://example.com/x"], socks) is None
    assert alerts.route_problem(["mailto://user:pass@example.com"], DIRECT) is None
    assert alerts.proxy_url(socks) == "socks5h://127.0.0.1:1080"


def test_problems_and_changes_are_sent_once_without_message_text(journal, receiver):
    store, vault = journal
    store.set_target(-1001, "Harbor Community", "supergroup", True)
    store.append("storage.low", {"free_bytes": 1024})
    run(store, vault)
    enable(store, vault, [receiver.url()])
    store.append("storage.low", {"free_bytes": 512 * 1024 * 1024})
    store.append("message.deleted", {"text": "SECRET MESSAGE TEXT"}, chat_id=-1001, message_id=5)
    store.append("message.edited", {"text": "SECRET MESSAGE TEXT"}, chat_id=-1001, message_id=6)
    assert run(store, vault) == {"notifications": 2, "error": None}
    bodies = [r["body"]["title"] + "\n" + r["body"]["message"] for r in receiver.requests]
    assert "Disk almost full: 512.0 MB free." in bodies[0] and "1.0 KB" not in bodies[0]
    assert "Harbor Community: 1 deleted, 1 edited, 0 not found" in bodies[1]
    assert not any("SECRET" in body for body in bodies)
    assert run(store, vault) == {"notifications": 0, "error": None}
    assert len(receiver.requests) == 2


def test_failed_delivery_keeps_the_records_for_the_next_pass(journal):
    store, vault = journal
    failing = Receiver(status=500)
    try:
        run(store, vault)
        enable(store, vault, [failing.url()])
        store.append("storage.low", {"free_bytes": 1024})
        cursor = store.get_setting("alerts_cursor")
        assert run(store, vault)["error"]
        assert store.get_setting("alerts_cursor") == cursor
        assert store.get_setting("alerts_last")["error"]
    finally:
        failing.close()


def test_daily_summary_once_per_day_in_the_chosen_language(journal, receiver):
    store, vault = journal
    store.set_target(-1001, "Harbor Community", "supergroup", True)
    store.append("message.new", {}, chat_id=-1001, message_id=1)
    store.append("message.deleted", {}, chat_id=-1001, message_id=1)
    enable(store, vault, [receiver.url()], problems=False, changes=False, daily=True, daily_hour=0, language="ru")
    assert run(store, vault)["notifications"] == 1
    words = i18n.words("ru")
    title = alerts.tr(words, "TgWitness · {name}: last 24 hours", name="TgWitness")
    assert title != "TgWitness · TgWitness: last 24 hours"
    assert receiver.requests[0]["body"]["title"] == title
    assert receiver.requests[0]["body"]["message"] == alerts.tr(
        words, "{chat}: {new} new, {edited} edited, {deleted} deleted, {missing} not found",
        chat="Harbor Community", new=1, edited=0, deleted=1, missing=0)
    assert run(store, vault)["notifications"] == 0


def test_ssh_or_a_login_on_a_deployed_server_is_a_problem_and_closing_them_is_not(journal):
    store, _vault = journal
    quiet = {"boot_id": "b", "ssh_listening": False, "ssh_processes": 0, "sessions": 0, "logins": 0}
    store.append("host.state", {"mode": "hetzner", "instance_id": 42, "before": quiet,
                                **{**quiet, "ssh_listening": True, "ssh_processes": 1, "sessions": 1, "logins": 2}})
    store.append("host.state", {"mode": "hetzner", "instance_id": 42,
                                "before": {**quiet, "ssh_listening": True, "logins": 2}, **{**quiet, "logins": 2}})
    items = [i for i in alerts.panel_items(store, {}) if i["kind"] == "host.state"]
    assert [i["text"] for i in items] == ["Server access detected: port 22 accepts connections; SSH server processes "
                                          "started; logged-in sessions: 1; new logins recorded: 2"]
    words = i18n.words("ru")
    _cursor, problems, *_ = alerts.collect(store, 0, {}, words)
    assert len(problems) == 1 and problems[0].startswith(words["Server access detected: {details}"].split("{")[0])
    assert words["port 22 accepts connections"] in problems[0]


def test_long_lists_are_capped():
    lines = [str(i) for i in range(alerts.MAX_LINES + 5)]
    assert alerts.capped(lines, {}).splitlines()[-1] == "…and 5 more."


def test_api_keeps_destinations_write_only_and_masked(tmp_path, monkeypatch, receiver):
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token
        secret_url = "json://user:supersecret@127.0.0.1:%d/hook" % receiver.port
        assert c.post("/api/alerts", json={"enabled": True, "urls": ["notaservice://x"]}).status_code == 422
        assert c.post("/api/alerts", json={"enabled": True, "urls": []}).status_code == 422
        refused = c.post("/api/alerts", json={"enabled": True, "daily": False, "urls": [secret_url]})

        assert refused.status_code == 422 and "Hide IP" in refused.text
        assert c.post("/api/network/policy", json={"exposure": "tunnel", "outside_enabled": True}).status_code == 200
        assert c.post("/api/network", json={"kind": "direct"}).status_code == 200
        saved = c.post("/api/alerts", json={"enabled": True, "daily": False, "urls": [secret_url]})
        assert saved.status_code == 200
        assert len(saved.json()["destinations"]) == 1
        assert "supersecret" not in saved.text and "supersecret" not in c.get("/api/alerts").text
        changed = app.state.store.events(kind="alerts.changed")[0]
        assert "supersecret" not in json.dumps(changed) and changed["payload"]["services"] == ["json"]

        assert c.post("/api/alerts", json={"enabled": True, "daily": False}).json()["destinations"] == saved.json()["destinations"]

        assert c.post("/api/alerts", json={"enabled": True, "add_urls": ["notaservice://x"]}).status_code == 422
        added = c.post("/api/alerts", json={"enabled": True, "daily": False, "add_urls": ["ntfys://tgw-topic", secret_url]})
        assert len(added.json()["destinations"]) == 2 and "add_urls" not in app.state.store.get_setting("alerts")
        assert len(c.post("/api/alerts", json={"enabled": True, "daily": False, "urls": [secret_url]}).json()["destinations"]) == 1
        assert c.post("/api/alerts/test").json()["sent"] == 1
        assert receiver.requests[-1]["body"]["message"] == "Notifications from this workspace reach this destination."


def test_notifications_never_reach_this_machine_or_its_network(monkeypatch, receiver):
    monkeypatch.delenv("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", raising=False)
    for url in (receiver.url(), "json://localhost:%d/hook" % receiver.port, "json://169.254.169.254/latest"):
        result = alerts.deliver([url], "Title", "Body", DIRECT)
        assert result["sent"] == 0 and "public internet" in result["error"], (url, result)

    proxy = NetworkConfig(kind="http", host="127.0.0.1", port=receiver.port, local_proxy=True)
    result = alerts.deliver(["json://169.254.169.254/latest"], "Title", "Body", proxy)
    assert result["sent"] == 0 and "public internet" in result["error"]
    assert receiver.requests == []

    import requests
    assert requests.post("http://127.0.0.1:%d/after" % receiver.port, json={}).status_code == 200
