import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tgwitness_capture.adapters import BrowserCapture
from tgwitness_capture.export import export_zip
from tgwitness_capture.journal import Journal
from tgwitness_capture.verify import verify_zip


def test_real_chromium_snapshot_and_change_detection(tmp_path, request):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for the real local browser test")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'<!doctype html><title>Synthetic capture fixture</title><p id="message">Original message</p>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        debug_port = sock.getsockname()[1]

    async def exercise():
        from playwright.async_api import async_playwright
        journal = Journal(tmp_path / "browser")
        adapter = BrowserCapture(f"http://127.0.0.1:{debug_port}", "")
        try:
            async with async_playwright() as runtime:
                browser = await runtime.chromium.launch(args=[f"--remote-debugging-port={debug_port}"])
                page = await browser.new_page(viewport={"width": 1280, "height": 720})
                await page.goto(f"http://127.0.0.1:{server.server_port}")
                targets = await adapter.targets()
                assert len(targets) == 1
                adapter.target_id = targets[0][1]
                settings = {"screenshots": True, "pages": True}
                first = await adapter.capture(journal, settings, 60)
                assert first[0]["errors"] == []
                assert {a["role"] for a in first[1]} == {"viewport", "rendered_page", "derived_rendered_text"}
                journal.append("capture.saved", first[0], first[1], first[2])
                assert await adapter.capture(journal, settings, 60) is None
                await page.locator("#message").evaluate("el => el.textContent = 'Edited message'")
                edited = await adapter.capture(journal, settings, 60)
                journal.append("capture.saved", edited[0], edited[1], edited[2])
                await page.locator("#message").evaluate("el => el.remove()")
                deleted = await adapter.capture(journal, settings, 60)
                assert deleted is not None
                journal.append("capture.saved", deleted[0], deleted[1], deleted[2])
                destination = tmp_path / "browser.zip"
                export_zip(journal, destination)
                assert verify_zip(destination, journal.fingerprint)["events"] == 3
                await adapter.close()
                assert await page.title() == "Synthetic capture fixture"
                await browser.close()
        finally:
            await adapter.close()
            journal.close()

    try:
        asyncio.run(exercise())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
