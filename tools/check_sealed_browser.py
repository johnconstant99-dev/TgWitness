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
from test_sealed import CapsuleClient, config
from tgwitness.sealed import create_app
from tgwitness.sealed_package import connection, package
from tgwitness.verify import verify_bundle


class QuietFiles(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
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
                "https://github.com/phishdestroy/TgWitness/blob/main/docs/ru/SEALED-ACTIONS.md")
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
            app = create_app(root / "data", root / "out", cfg, CapsuleClient)
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            url = "http://127.0.0.1:" + str(sock.getsockname()[1])
            server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
            thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
            thread.start()
            deadline = time.monotonic() + 15
            while not server.started:
                if time.monotonic() > deadline:
                    raise RuntimeError("Synthetic server did not start")
                time.sleep(.05)
            capture = context.new_page()
            capture.on("pageerror", lambda error: errors.append(str(error)))
            capture.goto(url + "/#access=" + cfg["token"])
            expect(capture.locator("#login")).to_be_visible()
            assert "#" not in capture.url
            capture.locator("#language").select_option("ru")
            capture.screenshot(path=str(screenshots / "runner-login.png"), full_page=True, animations="disabled")
            capture.locator("#api-id").fill("123")
            capture.locator("#api-hash").fill("a" * 32)
            capture.locator("#phone").fill("+15550001111")
            capture.locator("#send-code").click()
            capture.locator("#code").fill("12345")
            capture.locator("#confirm-code").click()
            expect(capture.locator("#selection")).to_be_visible()
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
            with RunningApp(root / "workspace-demo", demo=True) as workspace:
                panel=context.new_page()
                panel.on("pageerror", lambda error: errors.append(str(error)))
                panel.goto(workspace.url + "?lang=ru")
                expect(panel.locator("#workspace")).to_be_visible()
                panel.locator('[data-view="evidence"]').click()
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
