"""Exercise quick navigation with synthetic data, keyboard, locales and narrow screens."""
import json
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import ROOT, RunningApp, launch_browser


def main():
    output = ROOT / "test-results/quick-navigation"
    output.mkdir(parents=True, exist_ok=True)
    errors, external = [], []
    with tempfile.TemporaryDirectory(prefix="quick-navigation-") as scratch:
        from pathlib import Path
        with RunningApp(Path(scratch), demo=True) as server, sync_playwright() as p:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 900}, reduced_motion="reduce")
            page = context.new_page()
            page.on("pageerror", lambda e: errors.append(str(e)))

            def route(request):
                if request.request.url.startswith(server.url + "/"):
                    request.continue_()
                else:
                    external.append(request.request.url)
                    request.abort()

            page.route("**/*", route)
            page.goto(server.url)
            expect(page.locator("#chat-feed .msg").first).to_be_visible()
            dialog, search = page.locator("#quick-dialog"), page.locator("#quick-search")
            page.locator("#quick-open").click()
            expect(dialog).to_be_visible()
            expect(search).to_be_focused()
            expect(dialog.get_by_role("option")).to_have_count(9)
            page.keyboard.press("ArrowUp")
            expect(search).to_have_attribute("aria-activedescendant", "quick-option-access")
            page.keyboard.press("ArrowDown")
            expect(search).to_have_attribute("aria-activedescendant", "quick-option-chats")
            search.fill("access")
            expect(dialog.get_by_role("option")).to_have_count(1)
            page.keyboard.press("Enter")
            expect(page.locator("#view-access")).to_be_visible()
            page.keyboard.press("Control+k")
            search.fill("exports")
            expect(dialog.get_by_role("option")).to_have_count(1)
            page.keyboard.press("Enter")
            expect(dialog).not_to_be_visible()
            expect(page.locator("#view-evidence")).to_be_visible()
            expect(page.locator('[data-view="evidence"]')).to_have_attribute("aria-current", "page")
            expect(page.locator("#view-evidence h1")).to_be_focused()

            page.keyboard.press("Control+k")
            search.fill("<img src=x onerror=alert(1)>")
            expect(page.locator("#quick-empty")).to_be_visible()
            expect(page.locator("#quick-results img")).to_have_count(0)
            page.keyboard.press("Enter")
            expect(dialog).to_be_visible()
            page.keyboard.press("Escape")
            expect(dialog).not_to_be_visible()
            page.locator("#quick-open").click()
            page.keyboard.press("Escape")
            expect(page.locator("#quick-open")).to_be_focused()

            for query in ("bot", "GitHub", "proof"):
                page.keyboard.press("Control+k")
                search.fill(query)
                expect(dialog.get_by_role("option")).to_have_count(1)
                page.keyboard.press("Enter")
                expect(page.locator("#view-witness")).to_be_visible()
                expect(page.locator("#witness-form")).to_be_hidden()

            for theme in ("light", "dark"):
                page.emulate_media(color_scheme=theme)
                for width in (1440, 390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    if width < 600:
                        page.locator(".top-actions [data-quick-open]").click()
                    else:
                        page.keyboard.press("Control+k")
                    expect(dialog).to_be_visible()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    bounds = dialog.bounding_box()
                    assert bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width
                    page.screenshot(path=str(output / f"{theme}-{width}.png"))
                    page.keyboard.press("Tab")
                    assert page.evaluate("document.activeElement.closest('#quick-dialog') !== null")
                    page.keyboard.press("Escape")

            for lang, query in (("ru", "журнал"), ("ar", "observations")):
                context.add_cookies([{"name": "tgwitness-lang", "value": lang, "url": server.url}])
                page.reload()
                expect(page.locator("#workspace")).to_be_visible()
                page.keyboard.press("Control+k")
                search.fill(query)
                expect(dialog.get_by_role("option")).to_have_count(1)
                page.keyboard.press("Enter")
                expect(page.locator("#view-observations")).to_be_visible()
                page.keyboard.press("Control+k")
                # Locking via an API failure or another control must close the top-layer dialog.
                page.evaluate("lock()")
                expect(dialog).not_to_be_visible()
                expect(page.locator("#gate")).to_be_visible()
                page.keyboard.press("Control+k")
                expect(dialog).not_to_be_visible()
            assert not errors, errors
            assert not external, external
            browser.close()
    receipt = {"passed": True, "page_errors": errors, "external_requests": external,
               "scenarios": ["keyboard and pointer navigation", "search and empty state", "focus restoration",
                             "lock closes dialog", "light and dark at 320/390/1440px", "Russian and RTL"]}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
