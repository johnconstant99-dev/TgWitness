from playwright.sync_api import sync_playwright, expect

from tools.check_browser import RunningApp, unlock, navigate_panel
from tools.browser_helpers import launch_browser, check_layout


def test_connection_flags_are_not_safety_claims(tmp_path):
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        server.app.state.store.set_setting("client_checks", {"official_app": False,
            "checked_at": "2026-11-05T12:00:00+00:00", "checks": [
                {"name": "layer_match", "status": "warning", "detail": "Review the schema baseline."}]})
        browser = launch_browser(p)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            unlock(page, server)
            navigate_panel(page, "connection")
            expect(page.locator("#seen-by-list")).to_contain_text("official_app=False")
            expect(page.locator("#seen-by-list")).to_contain_text("does not report account restrictions")
            expect(page.locator("#seen-by-list")).to_contain_text("Review the schema baseline.")
            page.evaluate("state.status.collector.client_checks.official_app=null;renderSeenBy()")
            expect(page.locator("#seen-by-list")).to_contain_text("Official-app flag unavailable")
            page.set_viewport_size({"width": 390, "height": 844})
            check_layout(page)
        finally:
            browser.close()
