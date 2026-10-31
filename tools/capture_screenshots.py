"""Capture panel screenshots from synthetic data. Never connects to Telegram.

python tools/capture_screenshots.py            # review set in test-results/screens
python tools/capture_screenshots.py --docs     # README images in docs/assets
"""
import argparse
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_browser import ROOT, RunningApp, launch_browser, unlock
from tools.browser_fixtures import QRClient


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--docs", action="store_true", help="write the README images to docs/assets")
    args = parser.parse_args()
    output = ROOT / ("docs/assets" if args.docs else "test-results/screens")
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="screens-", dir=ROOT / "test-results"))
    desktop = {"width": 1440, "height": 900}

    def shoot(page, name, full_page=False):
        page.wait_for_timeout(150)
        page.screenshot(path=str(output / name), full_page=full_page)
        print("saved", (output / name).relative_to(ROOT))

    with RunningApp(run / "demo", demo=True) as demo, RunningApp(run / "live", client_factory=QRClient) as live, \
            sync_playwright() as p:
        browser = launch_browser(p)
        page = browser.new_page(viewport=desktop, reduced_motion="reduce")


        unlock(page, demo)
        page.locator('[data-view="chats"]').click()
        expect(page.locator("#chat-feed .msg").first).to_be_visible()
        shoot(page, "chats.png")
        page.locator('[data-view="observations"]').click()
        expect(page.locator("#events-body tr").first).to_be_visible()
        page.locator("#journal-overview > summary").click()
        shoot(page, "workspace.png")

        dark = browser.new_page(viewport=desktop, reduced_motion="reduce", color_scheme="dark")
        dark.goto(demo.url)
        expect(dark.locator("#chat-feed .msg").first).to_be_visible()
        shoot(dark, "chats-dark.png")
        dark.locator('[data-view="observations"]').click()
        expect(dark.locator("#events-body tr").first).to_be_visible()
        dark.locator("#journal-overview > summary").click()
        shoot(dark, "workspace-dark.png")
        dark.close()
        page.get_by_role("button", name="Edits", exact=True).click()
        page.locator("#events-body tr").first.click()
        expect(page.locator(".detail-block.after")).to_be_visible()
        shoot(page, "detail.png")
        page.keyboard.press("Escape")
        page.get_by_role("button", name="All events", exact=True).click()
        page.locator('[data-view="sources"]').click()
        page.locator("#source-options > summary").click()

        page.evaluate("document.querySelectorAll('#view-sources [disabled]').forEach(n => n.disabled = false)")
        shoot(page, "sources.png", full_page=not args.docs)
        page.locator('[data-view="evidence"]').click()
        if not args.docs:
            page.locator("#verification-details > summary").click()
            page.locator("#verify-journal").click()
            expect(page.locator("#verification-result")).to_contain_text("event signatures")
            page.locator("#toast").evaluate("n => n.hidden = true")
        shoot(page, "exports.png", full_page=not args.docs)
        page.locator('[data-view="observations"]').click()
        if not args.docs:
            for name, size in (("mobile.png", (390, 844)), ("tablet.png", (768, 1024))):
                page.set_viewport_size({"width": size[0], "height": size[1]})
                shoot(page, name)
        page.set_viewport_size(desktop)
        page.locator("#top-lock").click()
        if not args.docs:
            shoot(page, "gate.png")


        unlock(page, live)
        expect(page.locator("#phone")).to_be_visible()
        shoot(page, "connection.png")
        if not args.docs:
            for method in ("files", "key"):
                page.locator('[data-auth-method="' + method + '"]').click()
                shoot(page, "connection-" + method + ".png")
            page.locator('[data-auth-method="phone"]').click()
            page.locator("#entry-settings").click()
            shoot(page, "connection-settings.png", full_page=True)
            page.locator("#entry-settings").click()
            for width in (390, 320):
                page.set_viewport_size({"width": width, "height": 844})
                shoot(page, "connection-" + str(width) + ".png")
            page.set_viewport_size(desktop)
        page.locator("#api-details > summary").click()
        page.locator("#api-id").fill("123")
        page.locator("#api-hash").fill("a" * 32)
        page.locator('[data-auth-method="qr"]').click()
        page.locator("#start-qr").click()
        expect(page.locator("#qr-image")).to_be_visible()
        shoot(page, "qr-login.png")
        page.locator("#qr-cancel").click()
        if not args.docs:
            page.goto(live.url + "/guide.html")
            shoot(page, "guide.png")
        browser.close()


if __name__ == "__main__":
    main()
