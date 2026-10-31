"""Browser-generated keys -> fresh login -> capture -> encrypted download -> browser decrypt.

All Telegram messages and the attestation fixture are synthetic. A real GitHub
certificate is deliberately not claimed by this offline test.
"""
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

from check_browser import ROOT, launch_browser, check_layout
from test_sealed import CapsuleClient, config
from tgwitness.sealed import create_app
from tgwitness.sealed_package import connection, package
from tgwitness.verify import verify_bundle


class QuietFiles(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix="tgwitness-sealed-browser-") as temporary, sync_playwright() as p:
        root = Path(temporary)
        files = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietFiles, directory=str(ROOT / "website")))
        files_thread = threading.Thread(target=files.serve_forever, daemon=True)
        files_thread.start()
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 1000})
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        server = thread = sock = None
        try:
            page.goto(f"http://127.0.0.1:{files.server_port}/sealed.html?lang=ru")
            expect(page.locator("html")).to_have_attribute("lang", "ru")
            expect(page.locator("#instructions")).to_have_attribute("href",
                "https://github.com/phishdestroy/TgWitness/blob/main/docs/ru/SEALED-ACTIONS.md")
            with page.expect_download() as download:
                page.locator("#generate").click()
            key_path = root / "sealed-key.json"
            download.value.save_as(key_path)
            record = json.loads(key_path.read_bytes())
            assert page.locator("#recipient").input_value() == record["recipient"]
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
            # A reloaded helper can recover using only the previously saved private key.
            page.reload()
            page.locator("#key-file").set_input_files(key_path)
            expect(page.locator("#recipient")).to_have_value(record["recipient"])
            with page.expect_download() as download:
                page.locator("#result-file").set_input_files(root / "out" / "delivery.tgwsealed")
            delivery = root / "delivery.zip"
            download.value.save_as(delivery)
            with zipfile.ZipFile(delivery) as archive:
                assert archive.read("evidence.zip") == (root / "out" / "evidence.zip").read_bytes()
            assert verify_bundle(root / "out" / "evidence.zip")["events"] > 3
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
