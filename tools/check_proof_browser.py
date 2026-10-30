"""One synthetic collector server, three profiles and a separate proof monitor. No Telegram."""
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

import httpx
import uvicorn
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from check_browser import RunningApp, launch_browser, check_layout
from tgwitness.proof import create_app
from tgwitness.verify import fingerprint, verify_public_proof


@contextmanager
def monitor_server(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = "http://127.0.0.1:" + str(sock.getsockname()[1])
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Proof monitor did not start")
            time.sleep(.05)
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        sock.close()


def main():
    out = ROOT / "test-results/proof"
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="proof-ui-", dir=ROOT / "test-results") as scratch:
        root = Path(scratch)
        with RunningApp(root / "collector") as collector:
            with httpx.Client(base_url=collector.url, timeout=30, headers={"Authorization": "Bearer " + collector.app.state.vault.token}) as client:
                profiles = ["default"]
                for label in ("Synthetic account B", "Synthetic account C"):
                    response = client.post("/api/profiles", json={"label": label})
                    response.raise_for_status()
                    profiles.append(response.json()["id"])
                rows = []
                for i, profile in enumerate(profiles):
                    app = collector.app.state.profiles.entries[profile]["app"]
                    store, vault = app.state.store, app.state.vault
                    for n in range(12 + i * 5):
                        store.append("message.new", {"text": "Synthetic private content"}, -100123, n + 1)
                    store.append("message.edited", {"text": "Synthetic edit"}, -100123, 1)
                    store.append("message.deleted", {}, -100123, 2)
                    # Report synthetic collection health; no Telegram connection is opened.
                    original = app.state.collector.status
                    app.state.collector.status = lambda original=original: {**original(), "running": True, "connected": True}
                    prefix = "" if profile == "default" else "/profiles/" + profile
                    response = client.post(prefix + "/api/witness/tokens", json={"label": "Synthetic proof check"})
                    response.raise_for_status()
                    rows.append({"id": "account-" + chr(97 + i), "label": "Account " + chr(65 + i),
                                 "collector": collector.url + prefix, "root": root / ("proof-" + str(i)),
                                 "token": response.json()["token"], "pinned": fingerprint(vault.public_key),
                                 "interval": 1, "timeout": 10})
            monitor = create_app({"title": "Демонстрационный стенд · вымышленные события", "interval": 1, "workspaces": rows})
            with monitor_server(monitor) as url, sync_playwright() as p:
                browser = launch_browser(p)
                context = browser.new_context(locale="ru-RU", viewport={"width": 1440, "height": 1100}, reduced_motion="reduce")
                page = context.new_page()
                errors, external = [], []
                page.on("pageerror", lambda exc: errors.append(str(exc)))
                page.on("request", lambda req: external.append(req.url) if urlsplit(req.url).hostname != "127.0.0.1" else None)
                page.goto(url)
                expect(page.locator(".account")).to_have_count(3)
                expect(page.locator(".badge.good")).to_have_count(3, timeout=30000)
                expect(page.locator("#total-active")).to_have_text("3")
                assert "Synthetic private content" not in page.content()
                first = page.locator(".account").first
                first.locator("summary").click()
                expect(first.locator("details")).to_have_attribute("open", "")
                page.evaluate("render()")
                expect(first.locator("details")).to_have_attribute("open", "")
                with page.expect_download() as download:
                    first.locator(".download").click()
                proof = out / "synthetic-proof.json"
                download.value.save_as(proof)
                checked = verify_public_proof(proof, rows[0]["pinned"], monitor.state.watchers[0].fingerprint)
                assert checked["capture_signature_verified"] and checked["counts"]["message.new"] == 12
                first.locator("summary").click()
                for lang in ("ru", "en"):
                    if lang == "en":
                        page.locator("#language").click()
                    expect(page.locator("html")).to_have_attribute("lang", lang)
                    for width in (1440, 768, 390, 320):
                        page.set_viewport_size({"width": width, "height": 1000})
                        check_layout(page)
                        if lang == "ru" and width in (1440, 390):
                            page.screenshot(path=str(out / f"dashboard-{width}.png"), full_page=True)
                page.evaluate("reachable=false;render()")
                expect(page.locator("#connection")).to_contain_text("unreachable")
                expect(page.locator("#total-active")).to_have_text("—")
                expect(page.locator(".badge.good")).to_have_count(0)
                assert not errors and not external, (errors, external)
                browser.close()
    receipt = {"passed": True, "synthetic_only": True, "profiles_on_one_collector": 3,
               "languages": ["ru", "en"], "widths": [1440, 768, 390, 320],
               "signed_proof_download_verified": True, "offline_state": True,
               "javascript_errors": errors, "external_requests": external}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
