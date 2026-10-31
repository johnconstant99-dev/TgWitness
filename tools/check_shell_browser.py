"""Navigation breakpoints, focus and Russian labels against a synthetic panel."""
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, check_layout, launch_browser, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="panel-shell-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        store.set_target(-1001, "Synthetic source", "supergroup", True)
        store.append("message.new", {"text": "The conversation gets the space.", "sender_id": 42}, -1001, 1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, app)
            page.locator('.sidebar [data-view="observations"]').click()
            output = Path("build/ux-review/after/05-shell")
            output.mkdir(parents=True, exist_ok=True)
            for width, rail in ((1440, 240), (1024, 200), (768, 200), (390, None), (320, None)):
                page.set_viewport_size({"width": width, "height": 1000 if width >= 768 else 844})
                if rail:
                    assert round(page.locator(".sidebar").bounding_box()["width"]) == rail
                    expect(page.locator("#navigation-toggle")).to_be_hidden()
                else:
                    expect(page.locator(".sidebar")).to_be_hidden()
                    expect(page.locator("#navigation-toggle")).to_be_visible()
                    assert page.locator(".topbar").bounding_box()["height"] <= 72
                    page.locator("#navigation-toggle").click()
                    expect(page.locator(".sidebar")).to_have_attribute("aria-modal", "true")
                    expect(page.locator(".mobile-nav-close")).to_be_focused()
                    expect(page.locator("#collector-toggle")).to_be_visible()
                    expect(page.locator(".sidebar .language-select")).to_be_visible()
                    page.keyboard.press("Shift+Tab")
                    assert page.evaluate("()=>document.querySelector('.sidebar').contains(document.activeElement)")
                    page.keyboard.press("Escape")
                    expect(page.locator("#navigation-toggle")).to_be_focused()
                    page.locator("#navigation-toggle").click()
                    page.locator('.sidebar [data-view="sources"]').click()
                    expect(page.locator(".sidebar")).to_be_hidden()
                    expect(page.locator("#view-sources")).to_be_visible()
                    page.locator("#navigation-toggle").click()
                    page.locator('.sidebar [data-view="observations"]').click()
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    check_layout(page)
                    if width in (1440, 390):
                        page.screenshot(path=str(output / f"journal-{width}-{theme}.png"))
            # Linux's wider fallback font exposed both a health-bar overflow
            # and a live-status control clipped inside the journal card.
            page.set_viewport_size({"width": 320, "height": 844})
            page.evaluate("document.documentElement.style.setProperty('--font','\"DejaVu Sans\", sans-serif')")
            page.locator('.journal .live-toggle').evaluate("button=>button.textContent='Live: reconnecting'")
            check_layout(page)
            for selector in ('.health-chip', '.journal #refresh', '.journal .live-toggle'):
                for control in page.locator(selector).all():
                    rect = control.bounding_box()
                    assert rect and 0 <= rect['x'] and rect['x'] + rect['width'] <= 320, (selector, rect)
                    assert rect['height'] >= 44, (selector, rect)
            heading = page.locator('.journal .card-heading h2').bounding_box()
            refresh = page.locator('.journal #refresh').bounding_box()
            live = page.locator('.journal .live-toggle').bounding_box()
            assert heading['y'] + heading['height'] <= refresh['y'], (heading, refresh)
            assert abs(refresh['y'] - live['y']) <= 1, (refresh, live)
            page.screenshot(path=str(output / 'journal-320-linux-font.png'))
            page.evaluate("document.documentElement.style.removeProperty('--font')")
            page.goto(app.url + "/journal?ws=default&lang=ru")
            expect(page.locator("#workspace")).to_be_visible()
            expect(page.locator("html")).to_have_attribute("lang", "ru")
            for width in (1440, 1024, 390):
                page.set_viewport_size({"width": width, "height": 1000 if width >= 768 else 844})
                if width < 768:
                    page.locator("#navigation-toggle").click()
                clipped = page.locator(".sidebar").evaluate("""root => [...root.querySelectorAll('.nav,.sidebar-help,select')]
                    .filter(item=>item.checkVisibility()&&item.scrollWidth>item.clientWidth+2).map(item=>item.textContent)""")
                assert not clipped, clipped
                check_layout(page)
                page.screenshot(path=str(output / f"navigation-ru-{width}.png"))
                if width < 768:
                    page.keyboard.press("Escape")
            assert not errors, errors
            browser.close()
    print("Panel shell passed: five widths, mobile focus/navigation and unclipped Russian labels.")


if __name__ == "__main__":
    main()
