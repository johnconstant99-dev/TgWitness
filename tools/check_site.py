"""Check the built public site in Chromium, with no Telegram or external requests."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    output = ROOT / "test-results/site"
    output.mkdir(parents=True, exist_ok=True)
    errors, external, failed = [], [], []
    with tempfile.TemporaryDirectory(prefix="public-site-", dir=ROOT / "test-results") as scratch:

        shutil.copytree(ROOT / "dist/site", Path(scratch) / "TgWitness")
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=scratch))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/TgWitness/"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
                context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce")
                context.grant_permissions(["clipboard-read", "clipboard-write"])

                def route_request(route):
                    if urlsplit(route.request.url).hostname != "127.0.0.1":
                        external.append(route.request.url)
                        route.abort()
                    else:
                        route.continue_()
                context.route("**/*", route_request)
                page = context.new_page()
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
                page.goto(url, wait_until="networkidle")
                expect(page.get_by_role("heading", level=1)).to_contain_text("Messages change.")
                assert page.evaluate("getComputedStyle(document.documentElement).scrollBehavior") == "auto"
                assert not page.locator("input, form").count(), "Public page must not solicit account credentials"
                assert not page.evaluate("document.body.textContent.includes('@@')"), "Unresolved build placeholder"

                for href in page.locator('a[href^="#"]').evaluate_all("nodes => nodes.map(n => n.getAttribute('href'))"):
                    assert href == "#" or page.locator(href).count() == 1, f"Broken anchor: {href}"
                for tab, panel in (("tour-chats", "panel-chats"), ("tour-journal", "panel-journal"), ("tour-edits", "panel-edits"), ("tour-exports", "panel-exports")):
                    page.locator("#" + tab).click()
                    expect(page.locator("#" + panel)).to_be_visible()
                    page.wait_for_function("id => { const im=document.querySelector('#'+id+' img'); return im.complete && im.naturalWidth > 0; }", arg=panel)
                page.locator("#tour-journal").focus()
                page.keyboard.press("End")
                expect(page.locator("#tour-exports")).to_be_focused()
                page.keyboard.press("ArrowRight")
                expect(page.locator("#tour-chats")).to_be_focused()
                expect(page.locator("#panel-chats")).to_be_visible()
                page.locator('[data-record-step="0"]').click()
                expect(page.locator("#record-caption")).to_contain_text("first observation")
                page.locator('[data-record-step="2"]').click()
                expect(page.locator("#record-caption")).to_contain_text("history remains")
                expect(page.locator(".motion-toggle")).to_be_hidden()
                screenshot = page.locator("#panel-chats .screenshot-open")
                screenshot.click()
                expect(page.locator(".screenshot-dialog")).to_be_visible()
                page.keyboard.press("Escape")
                expect(page.locator(".screenshot-dialog")).to_be_hidden()
                expect(screenshot).to_be_focused()
                page.locator(".installation-details>summary").focus()
                page.keyboard.press("Enter")
                expect(page.locator(".installation-details")).to_have_attribute("open", "")
                for tab, panel in (("tab-unix", "setup-unix"), ("tab-docker", "setup-docker"), ("tab-windows", "setup-windows")):
                    page.locator("#" + tab).click()
                    expect(page.locator("#" + panel)).to_be_visible()
                page.locator('[data-copy="windows-command"]').click()
                assert page.evaluate("navigator.clipboard.readText()") == ".\\Start.cmd"

                page.evaluate("() => { navigator.clipboard.writeText = async () => { throw new Error('synthetic denial'); }; }")
                page.locator('[data-copy="clone-command"]').click()
                expect(page.locator("#copy-status")).to_contain_text("copy it manually")
                assert page.evaluate("window.getSelection().toString()") == page.locator("#clone-command").text_content()
                page.locator(".installation-details>summary").click()
                page.get_by_text("Can it recover messages deleted before capture?", exact=True).click()
                expect(page.locator(".faq details[open]")).to_contain_text("cannot reconstruct")
                page.get_by_text("Can it recover messages deleted before capture?", exact=True).click()

                page.reload(wait_until="networkidle")
                for width in (1440, 1024, 768, 390, 320):
                    page.set_viewport_size({"width": width, "height": 1000})
                    page.evaluate("window.getSelection().removeAllRanges(); window.scrollTo(0,0); document.activeElement.blur();")
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), f"Overflow at {width}px"
                    for button in page.locator('nav a, .button, [role="tab"]:visible').all():
                        box = button.bounding_box()
                        assert box and box["x"] >= -1 and box["x"] + box["width"] <= width + 1, f"Off-screen control at {width}px"
                    if width in (1440, 390):
                        page.screenshot(path=str(output / f"site-{width}.png"), full_page=True)
                        page.screenshot(path=str(output / f"hero-{width}.png"))
                nojs = browser.new_context(java_script_enabled=False, viewport={"width": 390, "height": 844})
                nojs.route("**/*", route_request)
                fallback = nojs.new_page()
                fallback.goto(url)
                fallback.locator(".installation-details>summary").click()
                fallback.locator("#s3 .presentation-details>summary").click()
                expect(fallback.locator("#s3 .s3-features")).to_be_visible()
                for panel in ("panel-chats", "panel-journal", "panel-edits", "panel-exports", "setup-windows", "setup-unix", "setup-docker"):
                    expect(fallback.locator("#" + panel)).to_be_visible()


                demo = context.new_page()
                demo.on("pageerror", lambda error: errors.append("demo: " + str(error)))
                demo.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
                demo.goto(url + "demo/?lang=ru", wait_until="networkidle")
                expect(demo.locator("#workspace")).to_be_visible()
                demo.locator('[data-view="evidence"]').click()
                expect(demo.locator("#export-sealed")).to_be_visible()
                demo.locator("#export-sealed").click()
                expect(demo.locator("#view-sealed")).to_be_visible()
                expect(demo.locator('[data-capture-action="generate"]')).to_be_visible()
                assert demo.url.startswith(url + "demo/")
                demo.locator('[data-view="chats"]').click()
                expect(demo.locator("#chats-list .chat-item")).to_have_count(3)
                expect(demo.locator('[data-view="observations"]')).to_contain_text("Журнал")
                demo.locator('[data-view="observations"]').click()
                expect(demo.locator("#events-body tr").first).to_be_visible()
                assert demo.evaluate("fetch('/api/collector/start', {method: 'POST'}).then(r => r.status)") == 403
                demo.close()
                from check_home_browser import check_home
                check_home(browser, url, output, route_request, errors)
                from check_modes_browser import check_modes
                check_modes(browser, url, output, errors, external, failed)
                assert errors == [], errors
                assert external == [], external
                assert failed == [], failed
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    receipt = {"result": "passed", "widths": [1440, 1024, 768, 390, 320], "project_subpath": True,
               "keyboard_tabs": True, "clipboard_and_denial": True, "no_javascript_fallback": True,
               "reduced_motion": True, "message_history_controls": True, "screenshot_dialog": True, "online_demo_read_only": True,
               "external_requests": external, "javascript_errors": errors, "failed_requests": failed}
    (output / "checks.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
