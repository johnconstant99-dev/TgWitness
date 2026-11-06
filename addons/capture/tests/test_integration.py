import json
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from tgwitness.capture_api import register
from tgwitness.capture_connections import CaptureConnections, Connection, endpoint
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness_capture.service import Config, create_app
from tgwitness_capture.verify import verify_zip


@contextmanager
def recorder_server(path):
    path.mkdir(parents=True, exist_ok=True)
    source = path / "client.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE messages (id INTEGER, body TEXT)")
        db.execute("INSERT INTO messages VALUES (1, 'Synthetic independent observation')")
    app = create_app(path / "recorder", Config(kind="ayugram", ayugram_db=str(source)))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False, timeout_graceful_shutdown=5))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        token = (path / "recorder/control-token.txt").read_text()
        fingerprint = app.state.recorder.status()["fingerprint"]
        yield SimpleNamespace(app=app, url="http://127.0.0.1:" + str(sock.getsockname()[1]),
                              token=token, fingerprint=fingerprint, source=source)
    finally:
        server.should_exit = True
        thread.join(30)
        sock.close()
        assert not thread.is_alive()


@pytest.fixture
def manager(tmp_path):
    root = tmp_path / "main"
    vault = Vault(root)
    store = Store(root)
    store.bind(vault)
    try:
        yield CaptureConnections(store, vault)
    finally:
        store.close()


def binding(recorder, **changes):
    return Connection(**{**dict(enabled=True, url=recorder.url, token=recorder.token, fingerprint=recorder.fingerprint), **changes})


def test_endpoint_and_token_boundaries():
    for value in ("http://127.0.0.1:8791", "http://[::1]:8791", "http://capture-browser:8791", "https://recorder.example"):
        assert endpoint(value) == value
    for value in ("http://192.168.1.1", "https://user:secret@host", "file:///tmp/a", "https://host/path", "https://host?q=x", "https://host/#secret", "https://ho st", "https://host:0"):
        with pytest.raises(ValueError):
            endpoint(value)
    with pytest.raises(ValueError):
        Connection(token="secret\n" + "a" * 32)


def test_bearer_token_never_follows_redirect(manager):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(307)
            self.send_header("Location", "/token-sink")
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = {"url": "http://127.0.0.1:" + str(server.server_port), "token": "x" * 32}
        with pytest.raises(ValueError, match="307"):
            manager._request(connection, "GET", "status")
        assert seen == ["/api/status"]
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()


def test_vault_isolation_and_default_no_requests(manager, monkeypatch, tmp_path):
    monkeypatch.setattr(manager, "_request", lambda *a, **kw: pytest.fail("Unexpected outbound request"))
    assert all(not c["configured"] for c in manager.public()["connections"].values())
    secret = "different-control-token-" + "a" * 32
    saved = Connection(enabled=True, url="http://127.0.0.1:8791", fingerprint="a" * 64, token=secret)
    public = manager.save("browser", saved)
    assert secret not in json.dumps(public)
    assert secret.encode() not in (manager.store.root / "capture_connections.enc").read_bytes()
    assert secret.encode() not in (manager.store.root / "journal.sqlite3-wal").read_bytes()
    assert manager.vault.read("capture_connections")["browser"]["token"] == secret
    manager.save("browser", saved.model_copy(update={"token": "", "enabled": False}))
    with pytest.raises(ValueError, match="Enable"):
        manager.request("browser")
    with pytest.raises(ValueError, match="control token"):
        manager.save("browser", saved.model_copy(update={"url": "http://127.0.0.1:8792", "token": ""}))
    other = Vault(tmp_path / "other-workspace")
    assert other.read("capture_connections") == {}


def test_real_recorder_control_export_and_wrong_pin(manager, tmp_path):
    with recorder_server(tmp_path / "external") as recorder:
        manager.save("ayugram", binding(recorder, fingerprint="0" * 64))
        with pytest.raises(ValueError, match="identity"):
            manager.request("ayugram", "settings", {"enabled": True})
        assert not recorder.app.state.recorder.settings["enabled"]
        manager.save("ayugram", binding(recorder))
        assert not manager.request("ayugram")["status"]["settings"]["enabled"]
        manager.request("ayugram", "settings", {"enabled": True})
        manager.request("ayugram", "snapshot", {})
        with pytest.raises(ValueError, match="Pause"):
            manager.export("ayugram")
        manager.save("ayugram", binding(recorder, enabled=False))
        assert recorder.app.state.recorder.settings["enabled"], "Disconnect must not stop an independent recorder"
        manager.save("ayugram", binding(recorder))
        manager.request("ayugram", "settings", {"enabled": False})
        exported = manager.export("ayugram")
        try:
            result = verify_zip(exported, recorder.fingerprint)
            assert result["valid"] and result["events"] >= 4
        finally:
            exported.unlink()
        manager.save("browser", binding(recorder))
        with pytest.raises(ValueError, match="kind"):
            manager.request("browser", "settings", {"enabled": True})
        assert not recorder.app.state.recorder.settings["enabled"]


def test_tampered_export_not_released_and_checkpoint_rollback(manager, tmp_path, monkeypatch):
    with recorder_server(tmp_path / "external") as recorder:
        manager.save("ayugram", binding(recorder))
        original = manager._request

        def corrupt(connection, method, path, body=None, *, destination=None):
            if destination:
                destination.write(b"not an authentic archive")
            else:
                return original(connection, method, path, body)

        monkeypatch.setattr(manager, "_request", corrupt)
        app = FastAPI()
        app.state.capture = manager
        async def admin():
            return SimpleNamespace(admin=True)
        register(app, admin, lambda: None)
        with TestClient(app) as client:
            assert client.post("/api/capture/ayugram/export").status_code == 502
        saved = manager.vault.read("capture_connections")
        checkpoint = recorder.app.state.recorder.journal.checkpoint()
        checkpoint["body"]["seq"] += 100
        saved["ayugram"]["checkpoint"] = checkpoint
        manager.vault.save("capture_connections", saved)
        with pytest.raises(ValueError, match="continuity"):
            manager.request("ayugram")


@pytest.mark.parametrize("is_admin,demo,status", [(False, False, 403), (True, True, 409)])
def test_admin_and_demo_boundaries(manager, monkeypatch, is_admin, demo, status):
    monkeypatch.setattr(manager, "_request", lambda *a, **kw: pytest.fail("Unexpected outbound request"))
    app = FastAPI()
    app.state.capture = manager
    async def principal():
        return SimpleNamespace(admin=is_admin)
    def require_live():
        if demo:
            raise HTTPException(409, "Demo is read-only")
    register(app, principal, require_live)
    with TestClient(app) as client:
        assert client.get("/api/capture/ayugram/status").status_code == status


def test_integrated_panel_real_capture_export_and_layout(tmp_path, request):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for the integrated panel scenario")
    from playwright.sync_api import expect, sync_playwright
    from tools.check_browser import RunningApp, unlock, navigate_panel, launch_browser, check_layout

    with recorder_server(tmp_path / "external") as recorder, RunningApp(tmp_path / "workspace") as main:
        assert requests.get(main.url + "/api/capture").status_code == 401
        with sync_playwright() as runtime:
            browser = launch_browser(runtime)
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            page.add_init_script("window.showSaveFilePicker = undefined")
            errors = []
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            unlock(page, main)
            navigate_panel(page, "witness")
            page.locator("#extras-open-capture").click()
            expect(page.locator("#capture-ayugram-status")).to_contain_text("Connection disabled")
            assert "/extras" in page.url and "capture" in page.url
            page.locator("#capture-ayugram-enabled").check()
            page.locator("#capture-ayugram-url").fill(recorder.url)
            page.locator("#capture-ayugram-pin").fill(recorder.fingerprint)
            page.locator("#capture-ayugram-token").fill(recorder.token)
            page.locator("#capture-ayugram form button").click()
            expect(page.locator("#capture-ayugram-check")).to_be_enabled()
            page.locator("#capture-ayugram-check").click()
            expect(page.locator("#capture-ayugram-status")).to_contain_text("Capture paused")
            expect(page.locator("#capture-ayugram-toggle")).to_be_enabled()
            assert not page.locator("#capture-ayugram-video").is_checked()
            page.locator("#capture-ayugram-toggle").click()
            expect(page.locator("#capture-ayugram-status")).to_contain_text("Capture running")
            expect(page.locator("#capture-ayugram-snapshot")).to_be_enabled()
            page.locator("#capture-ayugram-snapshot").click()
            expect(page.locator("#capture-ayugram .capture-events")).to_contain_text("capture.saved")
            expect(page.locator("#capture-ayugram-toggle")).to_be_enabled()
            page.locator("#capture-ayugram-toggle").click()
            expect(page.locator("#capture-ayugram-export")).to_be_enabled()
            with page.expect_download(timeout=20000) as item:
                page.locator("#capture-ayugram-export").click()
                dialog = page.locator("dialog.panel-dialog[open]")
                expect(dialog).to_be_visible()
                from tools.browser_helpers import answer_panel_dialog
                answer_panel_dialog(page)
            exported = tmp_path / "through-main-panel.zip"
            item.value.save_as(exported)
            assert verify_zip(exported, recorder.fingerprint)["valid"]
            expect(page.locator("#capture-ayugram-export")).to_be_enabled()
            page.evaluate("window.scrollTo(0,0)")
            page.wait_for_timeout(400)
            check_layout(page)
            page.screenshot(path=str(tmp_path / "integrated-capture.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0,0)")
            check_layout(page)
            page.screenshot(path=str(tmp_path / "integrated-capture-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1100})
            pending = []
            page.route("**/api/capture/ayugram/status", lambda route: pending.append(route))
            page.locator("#capture-ayugram-check").click()
            page.wait_for_timeout(150)
            assert pending
            second = page.evaluate("""async()=>{const p=await json('profiles',{label:'Isolated capture workspace'},{root:true});
                await loadProfiles();return p.id;}""")
            page.locator('#profile-select').select_option(second)
            pending[0].fulfill(status=200, json={"status": {"fingerprint": recorder.fingerprint}})
            expect(page.locator("#capture-ayugram-status")).to_contain_text("Connection disabled")
            expect(page.locator("#capture-ayugram-pin")).to_have_value("")
            assert recorder.fingerprint not in page.locator("#capture-connections").inner_text()
            assert not errors
            browser.close()
