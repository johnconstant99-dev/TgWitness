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
from tools.browser_fixtures import config
from tgwitness.sealed import create_app
from tgwitness.sealed_package import connection, package
from tgwitness.verify import verify_bundle
from check_sealed_login import RecordingClient, main as check_login
from tgwitness import api_pool


class QuietFiles(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class RunningCapsule(RunningApp):
    def __init__(self, root, cfg):
        self.app = create_app(root / "data", root / "out", cfg, RecordingClient)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.url = "http://127.0.0.1:" + str(self.sock.getsockname()[1])
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="error", access_log=False,
                                                   timeout_graceful_shutdown=5))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)


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
            candidate.loop.call_soon_threadsafe(candidate.scan.set)
            expect(page.locator("#selection")).to_be_visible()
            expect(page.locator("#api-hash")).to_have_value("")
            page.locator("#refresh").click()
            expect(page.locator("#collect")).to_be_enabled()
            page.locator("#collect").click()
            expect(page.locator("#complete")).to_be_visible(timeout=15000)
            assert verify_bundle(root / "out" / "evidence.zip")["events"] > 3
            with zipfile.ZipFile(root / "out" / "evidence.zip") as archive:
                assert all(pair[1].encode() not in archive.read(name) for name in archive.namelist())
            assert not errors, errors
        finally:
            page.close()


def credential_controls(page):
    """Check browser validation and exact payloads; offline acceptance checks the real login paths."""
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


def main():
    # This check runs in the sealed/browser [dev] environment, which includes httpx.
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
            deadline = time.monotonic() + 60  # slow starts under load; ready returns at once
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
            pair, = RecordingClient.attempts
            assert pair in api_pool.POOL
            capture.locator("#refresh").click()
            expect(capture.locator("#collect")).to_be_enabled()
            capture.locator("#collect").click()
            expect(capture.locator("#status")).to_contain_text("Сбор завершён", timeout=15000)
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
            custom_qr_capture(context, root / "custom-capture", record)
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
