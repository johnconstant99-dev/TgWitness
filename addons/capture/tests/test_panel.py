import io
import socket
import sqlite3
import threading
import time

import pytest
import uvicorn

from tgwitness_capture.format import decode
from tgwitness_capture.service import Config, create_app
from tgwitness_capture.verify import verify_zip


def test_real_panel_controls_export_and_mobile_layout(tmp_path, request):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for the real panel test")
    from playwright.sync_api import expect, sync_playwright
    source = tmp_path / "ayudata.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE messages (id INTEGER, text TEXT)")
        db.execute("INSERT INTO messages VALUES (1, 'Fictional observation for UI acceptance')")
    data = tmp_path / "panel"
    app = create_app(data, Config(kind="ayugram", ayugram_db=str(source), snapshot_seconds=60))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            errors = []
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            page.goto(f"http://127.0.0.1:{port}")
            page.locator("#token").fill((data / "control-token.txt").read_text())
            page.locator("#login-form button").click()
            page.locator("#workspace").wait_for(state="visible")
            assert not page.locator("#video").is_checked()
            page.locator("#toggle").click()
            expect(page.locator("#snapshot")).to_be_enabled()
            page.locator("#snapshot").click()
            page.locator('#events [data-kind="capture.saved"]').first.wait_for()
            page.locator("#toggle").click()
            expect(page.locator("#export")).to_be_enabled()
            with page.expect_download() as download_info:
                page.locator("#checkpoint").click()
            checkpoint_path = tmp_path / "checkpoint.json"
            download_info.value.save_as(checkpoint_path)
            # Wait for action completion before the next button can start a request.
            page.wait_for_timeout(300)
            with page.expect_download() as download_info:
                page.locator("#export").click()
            exported_path = tmp_path / "capture.zip"
            download_info.value.save_as(exported_path)
            result = verify_zip(io.BytesIO(exported_path.read_bytes()), page.locator("#fingerprint").inner_text(),
                                decode(checkpoint_path.read_bytes()), require_final_anchor=True)
            assert result["valid"]
            page.screenshot(path=str(tmp_path / "capture-panel.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("() => document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(tmp_path / "capture-panel-mobile.png"), full_page=True)
            assert not errors
            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=60)
        assert not thread.is_alive()
