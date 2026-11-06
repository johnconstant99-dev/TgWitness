import asyncio
import functools
import json
import socket
import tempfile
import threading
import time
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import uvicorn
from playwright.sync_api import expect, sync_playwright

from check_browser import ROOT, launch_browser, check_layout, RunningApp
from tools.browser_fixtures import ScopeClient, config
from tgwitness.sealed import create_app
from tgwitness.sealed_package import connection, package
from tgwitness.verify import verify_bundle
from check_sealed_login import RecordingClient, main as check_login
from tgwitness import api_pool
from tools.test_file_hash_export import CONTENT, ExportTransport
from tgwitness.sealed_selection import Selection
from tgwitness.sealed_parts import EncryptedParts


class QuietFiles(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class RunningCapsule(RunningApp):
    def __init__(self, root, cfg, client_factory=RecordingClient):
        self.app = create_app(root / "data", root / "out", cfg, client_factory)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.url = "http://127.0.0.1:" + str(self.sock.getsockname()[1])
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="error", access_log=False,
                                                   timeout_graceful_shutdown=5))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)


def account_capture(context, root, record):
    from telethon.errors import TakeoutInitDelayError
    approved = [False]

    class PreviewClient(RecordingClient):
        async def iter_dialogs(self, limit, ignore_migrated=False):
            async for dialog in ScopeClient.iter_dialogs(self, limit):
                yield dialog

    class Network(ExportTransport):
        account_id = 44
        async def open(self):
            if not approved[0]:
                raise TakeoutInitDelayError(None, capture=3600)

        async def download(self, media, stream, progress, task):
            await progress(1, len(CONTENT))
            await asyncio.sleep(3)
            stream.write(CONTENT)
            return stream

    cfg = config(record)
    with RunningCapsule(root, cfg, PreviewClient) as runner:
        runner.app.state.session.account_export.transport_factory = Network
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            page.goto(runner.url + "/#access=" + cfg["token"])
            expect(page.locator("#login")).to_be_visible()
            expect(page.locator("#language")).to_have_value("en")
            page.locator("#custom-api summary").click()
            page.locator("#api-id").fill("123")
            page.locator("#api-hash").fill("a" * 32)
            page.locator("#phone").fill("+15550001111")
            page.locator("#send-code").click()
            page.locator("#code").fill("22222")
            page.locator("#confirm-code").click()
            expect(page.locator("#password-box")).to_be_visible()
            page.locator("#password").fill("fictional-test-password")
            page.locator("#confirm-password").click()
            expect(page.locator("#selection")).to_be_visible()
            expect(page.locator("#export-scope")).to_have_value("account")
            expect(page.locator("#collect")).to_be_enabled()
            expect(page.locator("#export-mode")).to_have_value("takeout")
            expect(page.locator("#export-format")).to_have_value("telegram_both")
            expect(page.locator("#media-action")).to_have_value("download")
            expect(page.locator("#account-profile")).to_be_checked()
            expect(page.locator("#account-contacts")).to_be_checked()
            page.locator("#account-profile").uncheck()
            page.locator("#account-contacts").uncheck()
            page.locator("#export-mode").select_option("regular")
            expect(page.locator("#account-other")).to_be_disabled()
            expect(page.locator("#takeout-notice")).to_be_hidden()
            page.locator("#export-scope").select_option("chat")
            expect(page.locator("#collect")).to_be_disabled()
            page.route("**/api/dialogs", lambda route: route.fulfill(json={"dialogs": [
                {"chat_id": 11, "title": "Synthetic first"}, {"chat_id": 12, "title": "<img src=x onerror=alert(1)>"}]}))
            page.locator("#refresh").click()
            expect(page.locator("#chats option")).to_have_count(2)
            expect(page.locator("#collect")).to_be_disabled()
            page.locator("#chats").select_option(["11", "12"])
            expect(page.locator("#collect")).to_be_enabled()
            page.locator("#language").select_option("ru")
            expect(page.locator("#mode-description")).to_contain_text("не перечисляет")
            assert page.locator("#chats").evaluate("el => Array.from(el.selectedOptions, o => o.value)") == ["11", "12"]
            assert page.locator("#chats img").count() == 0
            page.locator("#export-mode").select_option("journal")
            expect(page.locator("#account-options")).to_be_hidden()
            expect(page.locator("#export-scope")).to_be_disabled()
            expect(page.locator("#export-format")).to_be_disabled()
            page.locator("#export-mode").select_option("takeout")
            page.locator("#export-scope").select_option("account")
            page.locator("#language").select_option("en")
            page.unroute("**/api/dialogs")
            page.locator("#from-date").fill("2026-11-01")
            page.locator("#through-date").fill("2026-11-04")
            with page.expect_response(lambda response: response.url.endswith("/api/preflight")) as assessment:
                page.locator("#preflight").click()
            assert assessment.value.ok, assessment.value.text()
            expect(page.locator("#save-selection")).to_be_enabled()
            page.locator("#total-budget").fill("3")
            expect(page.locator("#save-selection")).to_be_disabled()
            page.locator("#preflight").click()
            expect(page.locator("#save-selection")).to_be_enabled()
            with page.expect_download() as saved:
                page.locator("#save-selection").click()
            saved.value.save_as(root / "expected-selection.json")
            agreed = Selection.model_validate(json.loads((root / "expected-selection.json").read_bytes())).settings()
            assert agreed["account_options"]["transport"] == "takeout"
            assert agreed["account_options"]["max_total_gib"] == 3 and agreed["account_scope"] == "all"
            for width in (320, 390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
                page.screenshot(path=str(ROOT / "test-results/sealed-experience" / f"runner-account-{width}.png"), full_page=True)
            page.locator("#collect").click()
            expect(page.locator("#status")).to_contain_text("3600 seconds", timeout=15000)
            expect(page.locator("#status")).to_contain_text("another device")
            expect(page.locator("#resume")).to_have_text("Check export approval")
            approved[0] = True
            page.locator("#resume").click()
            expect(page.locator("#capture-transfer")).to_contain_text("Current file", timeout=10000)
            expect(page.locator("#complete")).to_be_visible(timeout=20000)
            expect(page.locator("#complete-summary")).to_contain_text("Export completed within the selected scope")
            page.locator("#language").select_option("ru")
            expect(page.locator("#complete-summary")).to_contain_text("Выгрузка выбранных данных завершена")
            expect(page.locator("#complete-summary")).to_contain_text("Отзыв сессии Telegram подтверждён")
            expect(page.locator("#status")).to_contain_text("Сбор завершён")
            result = verify_bundle(root / "out/evidence.zip")["account_export"]
            assert result["counts"]["messages"] == 2 and result["complete_within_scope"]
            with zipfile.ZipFile(root / "out/evidence.zip") as z, z.open("account-export.zip") as nested, zipfile.ZipFile(nested) as a:
                assert {"result.json", "export_results.html"} <= set(a.namelist())
                assert any(name.startswith("media/") for name in a.namelist())
            assert result["options"] == agreed["account_options"]
            assert not errors, errors
        finally:
            page.close()


def custom_qr_capture(context, root, record):
    cfg = config(record)
    pair = (123, "0123456789abcdef" * 2)
    with RunningCapsule(root, cfg) as runner:
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            page.goto(runner.url + "/#access=" + cfg["token"])
            expect(page.locator("#login")).to_be_visible()
            page.locator("#language").select_option("en")
            page.locator("#custom-api summary").click()
            page.locator("#api-id").fill(str(pair[0]))
            page.locator("#api-hash").fill(pair[1])
            page.set_viewport_size({"width": 390, "height": 1000})
            check_layout(page)
            page.locator("#qr").click()
            expect(page.locator("#qr-image")).to_be_visible()
            candidate = runner.app.state.session.collector.login_client
            assert candidate.pair == pair
            assert candidate.options["lang_code"] == "en"
            assert candidate.options["system_lang_code"] == page.evaluate("navigator.language")
            candidate.loop.call_soon_threadsafe(candidate.scan.set)
            expect(page.locator("#selection")).to_be_visible()
            page.locator("#export-mode").select_option("journal")
            expect(page.locator("#api-hash")).to_have_value("")
            page.locator("#refresh").click()
            expect(page.locator("#collect")).to_be_enabled()
            page.locator("#media-action").select_option("download")
            page.locator("#collect").click()
            expect(page.locator("#complete")).to_be_visible(timeout=15000)
            assert verify_bundle(root / "out" / "evidence.zip")["events"] > 3
            with zipfile.ZipFile(root / "out" / "evidence.zip") as archive:
                assert all(pair[1].encode() not in archive.read(name) for name in archive.namelist())
            assert not errors, errors
        finally:
            page.close()


def credential_controls(page):
    expect(page.locator("#api-id")).to_be_hidden()
    page.locator("#custom-api summary").click()
    page.locator("#api-id").fill("123")
    page.locator("#phone").fill("+15550001111")
    captured = []

    def refused(route):
        captured.append((route.request.url.rsplit("/", 1)[-1], route.request.post_data_json))
        route.fulfill(status=400, content_type="application/json", body='{"detail":"Synthetic login rejected"}')

    page.route("**/api/phone", refused)
    page.route("**/api/qr", refused)
    try:
        page.locator("#send-code").click()
        expect(page.locator("#error")).to_have_text(page.locator("#api-error").text_content())
        assert not captured
        page.locator("#api-hash").fill("0123456789abcdef" * 2)
        for button, method in (("send-code", "phone"), ("qr", "qr")):
            with page.expect_response(lambda response: response.url.endswith("/api/" + method)):
                page.locator("#" + button).click()
            expect(page.locator("#error")).to_have_text("Synthetic login rejected")
            expected = {"api_id": 123, "api_hash": "0123456789abcdef" * 2}
            if method == "phone":
                expected["phone"] = "+15550001111"
            assert captured[-1] == (method, expected)
        page.locator("#api-id").fill("")
        page.locator("#api-hash").fill("")
        with page.expect_response(lambda response: response.url.endswith("/api/qr")):
            page.locator("#qr").click()
        assert captured[-1] == ("qr", {})
        expect(page.locator("#error")).to_have_text("Synthetic login rejected")
        page.locator("#custom-api summary").click()
    finally:
        page.unroute("**/api/phone", refused)
        page.unroute("**/api/qr", refused)


def status_recovery(context, url, screenshots):
    """Status failures recover without hiding action errors or losing final coverage."""
    page = context.new_page()
    errors, requests = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    state = {"phase": "collecting", "authorized": True, "history": {"phase": "running", "captured": 42},
             "media": {}, "remaining_seconds": 120, "context": {}, "account_export": None}
    offline = [False]

    def status(route):
        requests.append(route.request.url)
        if offline[0] == "unauthorized":
            route.fulfill(status=401, json={"detail": "Synthetic access expired"})
        elif offline[0]:
            route.abort()
        else:
            route.fulfill(json=state)

    page.route("**/api/status", status)
    try:
        page.goto(url + "/sealed.html#access=synthetic-status-test")
        expect(page.locator("#progress")).to_be_visible()
        offline[0] = True
        expect(page.locator("#error")).to_contain_text("Connection unavailable")
        offline[0] = False
        expect(page.locator("#error")).to_be_empty()

        offline[0] = "unauthorized"
        expect(page.locator("#error")).to_have_text("Synthetic access expired")
        offline[0] = False
        expect(page.locator("#error")).to_be_empty()

        state["account_export"] = {"phase": "failed", "error": "Synthetic export failed"}
        expect(page.locator("#error")).to_have_text("Synthetic export failed")
        state["account_export"] = {"phase": "running", "error": None}
        expect(page.locator("#error")).to_be_empty()

        # A successful action followed by a failed status request must also recover.
        def resume(route):
            offline[0] = True
            state["account_export"] = {"phase": "running", "error": None}
            route.fulfill(json={})
        state["account_export"] = {"phase": "paused"}
        page.route("**/api/resume", resume)
        expect(page.locator("#resume")).to_be_visible()
        page.locator("#resume").click()
        expect(page.locator("#error")).to_contain_text("Connection unavailable")
        offline[0] = False
        expect(page.locator("#error")).to_be_empty()

        # Background polling must not erase a rejected operator action.
        page.route("**/api/finish", lambda route: route.fulfill(status=409, json={"detail": "Synthetic action rejected"}))
        page.locator("#finish").click()
        expect(page.locator("#error")).to_have_text("Synthetic action rejected")
        with page.expect_response("**/api/status"):
            pass
        expect(page.locator("#error")).to_have_text("Synthetic action rejected")
        page.unroute("**/api/finish")
        page.route("**/api/finish", lambda route: route.fulfill(json={}))
        page.locator("#finish").click()
        expect(page.locator("#error")).to_be_empty()

        state.update(phase="sealed", authorized=False, account_export=None, revocation="not_confirmed",
                     history={"phase": "incomplete", "captured": 42, "unavailable": 2},
                     media={"done": 5, "hashed": 3, "skipped": 1, "failed": 1, "retry": 2})
        expect(page.locator("#complete")).to_be_visible()
        summary = page.locator("#complete-summary")
        expect(summary).to_contain_text("Partial capture")
        expect(summary).to_contain_text("Messages preserved：42，unavailable：2")
        expect(summary).to_contain_text("saved：5，hashes only：3，skipped：1，failed：1，unfinished：2")
        assert page.evaluate("sessionStorage.getItem('sealed-access')") is None
        completed_requests = len(requests)
        page.locator("#language").select_option("ru")
        expect(page.locator("#status")).to_contain_text("Сбор завершён")
        expect(summary).to_contain_text("Неполный сбор")
        expect(page.locator("#error")).to_contain_text("Отзыв сессии не подтверждён")
        assert len(requests) == completed_requests
        for width in (320, 390, 1440):
            page.set_viewport_size({"width": width, "height": 1000})
            check_layout(page)
        page.screenshot(path=str(screenshots / "runner-partial-summary.png"), full_page=True)
        assert not errors, errors
    finally:
        page.close()


def main():
    asyncio.run(check_login())
    screenshots = ROOT / "test-results" / "sealed-experience"
    screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tgwitness-sealed-browser-") as temporary, sync_playwright() as p:
        root = Path(temporary)
        files = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietFiles, directory=str(ROOT / "tgwitness/static")))
        files_thread = threading.Thread(target=files.serve_forever, daemon=True)
        files_thread.start()
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 1000}, reduced_motion="reduce")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        server = thread = sock = None
        try:
            status_recovery(context, f"http://127.0.0.1:{files.server_port}", screenshots)
            page.goto(f"http://127.0.0.1:{files.server_port}/capture.html?lang=ru")
            expect(page.locator("html")).to_have_attribute("lang", "ru")
            expect(page.locator("#instructions")).to_have_attribute("href",
                "https://phishdestroy.github.io/TgWitness/ru/docs/capture/")
            expect(page.locator("[data-capture-story]")).to_have_attribute("data-running", "false")
            for scene in range(5):
                page.locator(f'[data-story-frame="{scene}"]').click()
                expect(page.locator(".story-visual")).to_have_attribute("data-scene", str(scene))
            for scenario, valid in (("message", "false"), ("collector", "false"), ("original", "true")):
                page.locator(f'[data-story-scenario="{scenario}"]').click()
                expect(page.locator(".story-verdict")).to_have_attribute("data-valid", valid)
            page.locator('[data-story-frame="0"]').click()
            page.locator(".story-player").scroll_into_view_if_needed()
            page.clock.install()
            page.locator("[data-story-play]").click()
            expect(page.locator("[data-capture-story]")).to_have_attribute("data-running", "true")
            page.clock.run_for(7600)
            expect(page.locator(".story-visual")).to_have_attribute("data-scene", "1")
            page.locator("[data-story-play]").click()
            page.clock.run_for(8000)
            expect(page.locator(".story-visual")).to_have_attribute("data-scene", "1")
            page.clock.resume()
            page.locator("[data-story-start]").click()
            expect(page.locator("#capture-setup")).to_be_focused()
            page.locator('[data-story-frame="0"]').click()
            for theme in ("light", "dark"):
                page.locator(f'[data-theme-choice="{theme}"]').click()
                expect(page.locator("html")).to_have_attribute("data-theme", theme)
                for width in (1280, 390, 320):
                    page.set_viewport_size({"width":width,"height":1000})
                    check_layout(page)
                    page.screenshot(path=str(screenshots / f"wizard-{theme}-{width}.png"), full_page=True, animations="disabled")
            page.set_viewport_size({"width":1280,"height":1000})
            with page.expect_download() as download:
                page.locator('[data-capture-action="generate"]').click()
            key_path = root / "sealed-key.json"
            download.value.save_as(key_path)
            record = json.loads(key_path.read_bytes())
            expect(page.locator('[data-capture-action="next"]')).to_be_disabled()
            page.locator("#capture-key-saved").check()
            page.locator('[data-capture-action="next"]').click()
            assert page.locator("#recipient").input_value() == record["recipient"]
            page.locator("#capture-repository").fill("synthetic/TgWitness")
            page.screenshot(path=str(screenshots / "wizard-github.png"), full_page=True, animations="disabled")
            expect(page.locator("#capture-workflow-link")).to_have_attribute("href",
                "https://github.com/synthetic/TgWitness/actions/workflows/sealed-witness.yml")
            page.locator('[data-capture-action="next"]').click()
            cfg = config(record)
            connection(cfg, "https://synthetic.trycloudflare.com", root / "connection.tgwsealed")
            page.locator("#connection-file").set_input_files(root / "connection.tgwsealed")
            expect(page.locator("#open-connection")).to_be_visible()
            assert cfg["token"] in page.locator("#open-connection").get_attribute("href")
            for width in (1280, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
            app = create_app(root / "data", root / "out", cfg, RecordingClient)
            RecordingClient.attempts = []
            RecordingClient.fail_ids = set()
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            url = "http://127.0.0.1:" + str(sock.getsockname()[1])
            server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
            thread.start()
            deadline = time.monotonic() + 60
            while not server.started:
                if time.monotonic() > deadline:
                    raise RuntimeError("Synthetic server did not start")
                time.sleep(.05)
            capture = context.new_page()
            capture.on("pageerror", lambda error: errors.append(str(error)))
            capture.goto(url + "/#access=" + cfg["token"])
            expect(capture.locator("#login")).to_be_visible()
            assert "#" not in capture.url
            credential_controls(capture)
            assert not RecordingClient.attempts
            capture.locator("#language").select_option("ru")
            capture.screenshot(path=str(screenshots / "runner-login.png"), full_page=True, animations="disabled")
            capture.locator("#phone").fill("+15550001111")
            capture.locator("#send-code").click()
            capture.locator("#code").fill("12345")
            capture.locator("#confirm-code").click()
            expect(capture.locator("#selection")).to_be_visible()
            capture.locator("#export-mode").select_option("journal")
            saved_profile = app.state.session.vault.read("credentials")["client_profile"]
            assert saved_profile["lang_code"] == "ru"
            assert saved_profile["system_lang_code"] == capture.evaluate("navigator.language")
            pair, = RecordingClient.attempts
            assert pair in api_pool.POOL
            capture.locator("#refresh").click()
            expect(capture.locator("#collect")).to_be_enabled()
            capture.locator("#media-action").select_option("hashes_only")
            capture.locator("#preflight").click()
            expect(capture.locator("#preflight-result")).to_contain_text("Общий размер и длительность пока неизвестны")
            assert app.state.session.store.get_setting("capture", None) is None
            capture.locator("#media-rules").locator("..").locator("summary").click()
            for width in (1280, 390, 320):
                capture.set_viewport_size({"width": width, "height": 1000})
                check_layout(capture)
            capture.set_viewport_size({"width": 1280, "height": 1000})
            capture.locator("#language").select_option("en")
            capture.screenshot(path=str(screenshots / "runner-hash-settings.png"), full_page=True, animations="disabled")
            capture.locator("#media-rules").locator("..").locator("summary").click()
            capture.screenshot(path=str(screenshots / "runner-hash-preflight.png"), full_page=True, animations="disabled")
            capture.locator("#language").select_option("ru")
            capture.locator("#media-action").select_option("download")
            capture.locator("#collect").click()
            expect(capture.locator("#status")).to_contain_text("Сбор завершён", timeout=15000)
            expect(capture.locator("#complete-summary")).to_contain_text("Чтение истории в выбранном объёме завершено")
            capture.locator("#language").select_option("en")
            expect(capture.locator("#complete-summary")).to_contain_text("History reading completed within the selected scope")
            assert not capture.evaluate("sessionStorage.getItem('sealed-access')")
            check_layout(capture)
            fixture = root / "synthetic-attestation.jsonl"
            fixture.write_text('{"synthetic":true}\n')
            package(cfg, root / "out", fixture)
            page.reload()
            page.locator("#key-file").set_input_files(key_path)
            expect(page.locator("#capture-key-saved")).to_be_checked()
            page.locator('[data-capture-action="result"]').click()
            with page.expect_download() as download:
                page.locator("#result-file").set_input_files(root / "out" / "delivery.tgwsealed")
            delivery = root / "delivery.zip"
            download.value.save_as(delivery)
            with zipfile.ZipFile(delivery) as archive:
                assert archive.read("evidence.zip") == (root / "out" / "evidence.zip").read_bytes()
            assert verify_bundle(root / "out" / "evidence.zip")["events"] > 3
            part_output = root / "browser-parts"
            part_output.mkdir()
            with EncryptedParts(part_output, app.state.session.vault, cfg, part_bytes=8192) as outgoing:
                with (root / "out/evidence.zip").open("rb") as incoming:
                    for block in iter(lambda: incoming.read(1024**2), b""):
                        outgoing.write(block)
            with page.expect_download() as part_download:
                page.locator("#result-file").set_input_files(part_output / "delivery-000001.tgwsealed")
            assert part_download.value.suggested_filename == "evidence.zip.part000001"
            saved_part = root / part_download.value.suggested_filename
            part_download.value.save_as(saved_part)
            assert saved_part.read_bytes() == (root / "out/evidence.zip").read_bytes()[:8192]
            custom_qr_capture(context, root / "custom-capture", record)
            account_capture(context, root / "account-capture", record)
            with RunningApp(root / "workspace-demo", demo=True) as workspace:
                panel=context.new_page()
                panel.on("pageerror", lambda error: errors.append(str(error)))
                panel.goto(workspace.url + "?lang=ru")
                expect(panel.locator("#workspace")).to_be_visible()
                panel.locator('[data-view="evidence"]').click()
                panel.locator('#export-task-journal').click()
                if panel.locator('#export-more-formats').get_attribute('open') is None:
                    panel.locator('#export-more-formats > summary').click()
                panel.locator("#export-sealed").click()
                expect(panel.locator("#view-sealed")).to_be_visible()
                assert panel.url.startswith(workspace.url)
                panel.locator("#key-file").set_input_files(key_path)
                expect(panel.locator("#capture-key-saved")).to_be_checked()
                panel.locator('[data-capture-action="next"]').click()
                expect(panel.locator("#recipient")).to_have_value(record["recipient"])
                for width in (1440,390,320):
                    panel.set_viewport_size({"width":width,"height":1000})
                    check_layout(panel)
                    panel.screenshot(path=str(screenshots / f"workspace-{width}.png"), full_page=True, animations="disabled")
                panel.set_viewport_size({"width":1440,"height":1000})
                panel.locator("#top-lock").click()
                expect(panel.locator("#gate")).to_be_visible()
                panel.locator("#open-demo").click()
                expect(panel.locator("#workspace")).to_be_visible()
                panel.locator('[data-view="evidence"]').click()
                panel.locator('#export-task-journal').click()
                if panel.locator('#export-more-formats').get_attribute('open') is None:
                    panel.locator('#export-more-formats > summary').click()
                panel.locator("#export-sealed").click()
                expect(panel.locator('[data-capture-action="generate"]')).to_be_visible()
                expect(panel.locator('[data-capture-action="next"]')).to_be_disabled()
                panel.close()
            assert not errors, errors
        finally:
            if server:
                server.should_exit = True
                thread.join(timeout=40)
                sock.close()
            context.close()
            browser.close()
            files.shutdown()
            files.server_close()
            files_thread.join(timeout=5)
    print("Sealed browser acceptance passed: local keys, encrypted connection, restricted capture, media, recovery and browser decryption.")


if __name__ == "__main__":
    main()
