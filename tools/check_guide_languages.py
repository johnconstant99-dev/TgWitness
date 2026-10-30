"""Exercise both bundled guides in the application and under a Pages project path."""
from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import i18n
from tools.check_browser import RunningApp, check_layout, launch_browser
from tools.check_site import QuietHandler
from tools.i18n_keys import script_keys

PAGES = ("guide.html", "dedicated-account.html")
HEROES = ("From account connection to a verifiable journal",
          'Use a separate account. <span class="accent">Never your main one.</span>')


def check_inventory(browser):
    inventory = json.loads((i18n.GUIDE_LOCALES / "keys.json").read_text(encoding="utf-8"))
    found = []
    for name in PAGES:
        page = browser.new_page()
        page.route("**/*", lambda route: route.abort())
        page.set_content((ROOT / "tgwitness/static" / name).read_text(encoding="utf-8"))
        # List the original markup before translation rewrites inline links.
        source = (ROOT / "tgwitness/static/i18n.js").read_text(encoding="utf-8")
        page.add_script_tag(content=source.split("translatePage();\n")[0])
        keys = page.evaluate("pageKeys()")
        assert keys == inventory["pages"][name], name
        found.extend(keys)
        page.close()
    found.extend(script_keys((ROOT / "tgwitness/static/guide.js").read_text(encoding="utf-8")))
    assert set(found) == set(inventory["keys"])


def check_guides(browser, base, output, label):
    context = browser.new_context(viewport={"width": 320, "height": 900}, reduced_motion="reduce", locale="en-US")
    failures, external, errors = [], [], []
    context.route("**/*", lambda route: route.continue_() if urlsplit(route.request.url).hostname == "127.0.0.1"
                  else (external.append(route.request.url), route.abort()))
    page = context.new_page()
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("response", lambda response: failures.append(response.url) if response.status >= 400 else None)
    for lang in i18n.GUIDE_LANGUAGES:
        # An explicit shared URL must beat a previously selected, different language.
        context.add_cookies([{"name": i18n.COOKIE, "value": "ru" if lang != "ru" else "de",
                             "domain": urlsplit(base).hostname, "path": "/"}])
        for name, hero in zip(PAGES, HEROES):
            page.goto(base + name + "?lang=" + lang)
            expect(page.locator("html")).to_have_attribute("lang", lang)
            expect(page.locator("html")).to_have_attribute("dir", "rtl" if lang in ("ar", "fa", "ur", "he") else "ltr")
            expect(page.locator(".language-select option")).to_have_count(26)
            expect(page.locator(".language-select")).to_have_value(lang)
            expected = i18n.guide_words(lang).get(hero, hero)
            expected = page.evaluate("s=>{const p=document.createElement('div');p.innerHTML=s;return p.textContent}", expected)
            expect(page.locator("h1")).to_have_text(expected)
            warning_title = "Parallel session warning" if name == "guide.html" else "Copied session keys can be revoked"
            expect(page.locator("#session-warning h3")).to_have_text(i18n.guide_words(lang).get(warning_title, warning_title))
            expect(page.locator("#session-warning code")).to_have_text("AUTH_KEY_DUPLICATED")
            if name == "dedicated-account.html":
                rental_title = "Rented +888 numbers (Fragment)"
                expect(page.locator("#fragment-rental h3")).to_have_text(i18n.guide_words(lang).get(rental_title, rental_title))
                market_title = "Ready-made accounts from marketplaces"
                expect(page.locator("#marketplace-accounts h3")).to_have_text(i18n.guide_words(lang).get(market_title, market_title))
            links = page.locator('a[href*="guide.html"], a[href*="dedicated-account.html"]').evaluate_all("nodes=>nodes.map(n=>n.href)")
            assert links and all(link.startswith(base) and "lang=" + lang in link for link in links), (label, lang, links)
            page.locator("details").evaluate_all("nodes=>nodes.forEach(n=>n.open=true)")
            for theme in ("light", "dark"):
                page.emulate_media(color_scheme=theme)
                expect(page.locator("html")).to_have_attribute("data-theme", theme)
                check_layout(page)
            anchors = ("session-warning", "fragment-rental", "marketplace-accounts") if name == "dedicated-account.html" else ("session-warning",)
            for anchor in anchors:
                target = page.locator("#" + anchor)
                target.evaluate("node=>node.scrollIntoView({block:'start'})")
                heading, nav = target.locator("h3").bounding_box(), page.locator(".section-nav").bounding_box()
                assert heading and nav and heading["y"] >= nav["y"] + nav["height"], (label, lang, anchor, "heading hidden by navigation")
            assert page.evaluate("getComputedStyle(document.documentElement).scrollBehavior") == "auto"
        print(label, lang, "both guides: translated, 320 px, light/dark, links", flush=True)
    # Picker interaction, persistent choice, and a real round trip between the guides.
    page.goto(base + "guide.html?lang=en#login")
    page.locator(".language-select").focus()
    page.locator(".language-select").select_option("de")
    expect(page.locator("html")).to_have_attribute("lang", "de")
    assert "lang=de" in page.url and page.url.endswith("#login")
    page.goto(base + "guide.html")
    expect(page.locator("html")).to_have_attribute("lang", "de")
    target = page.locator('a[href*="dedicated-account.html"]').first.get_attribute("href")
    page.goto(target)
    expect(page.locator("html")).to_have_attribute("lang", "de")
    page.locator('.top-nav a[href*="guide.html"]').click()
    expect(page.locator("html")).to_have_attribute("lang", "de")
    for lang in ("de", "he", "zh-Hant", "am"):
        page.set_viewport_size({"width": 1440, "height": 1060})
        page.goto(base + "guide.html?lang=" + lang)
        check_layout(page)
        page.screenshot(path=str(output / f"{label}-{lang}.png"))
    assert not errors and not failures and not external, (errors, failures, external)
    context.close()
    # Script and region negotiation without either a saved choice or a query string.
    for locale, lang in (("de-DE", "de"), ("zh-TW", "zh-Hant"), ("he-IL", "he")):
        context = browser.new_context(locale=locale)
        page = context.new_page()
        page.goto(base + "guide.html")
        expect(page.locator("html")).to_have_attribute("lang", lang)
        context.close()
    context = browser.new_context(java_script_enabled=False, viewport={"width": 320, "height": 900})
    page = context.new_page()
    for name in PAGES:
        page.goto(base + name)
        expect(page.locator("h1")).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (label, name, "no JS overflow")
    context.close()


def main():
    output = ROOT / "test-results/guide-languages"
    output.mkdir(parents=True, exist_ok=True)
    os.environ.pop("TGWITNESS_TOKEN", None)
    with tempfile.TemporaryDirectory(prefix="guide-languages-", dir=ROOT / "test-results") as scratch:
        shutil.copytree(ROOT / "dist/site", Path(scratch) / "TgWitness")
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=scratch))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with RunningApp(Path(scratch) / "application", demo=True) as app, sync_playwright() as pw:
                browser = launch_browser(pw)
                check_inventory(browser)
                check_guides(browser, app.url + "/", output, "application")
                check_guides(browser, f"http://127.0.0.1:{server.server_port}/TgWitness/demo/", output, "pages")
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
    print("Guide languages passed: 26 languages, both guides, application and Pages; no external requests.")


if __name__ == "__main__":
    main()
