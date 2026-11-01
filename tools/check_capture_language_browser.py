"""Capture-language inputs remain supported tags and cannot create executable markup."""
import json
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import expect, sync_playwright

from check_browser import launch_browser


def main():
    static = Path(__file__).resolve().parents[1] / "tgwitness" / "static"
    attack = '\"><img src=x onerror="window.captureXss=true">'
    cases = [("en", "en"), ("ru", "ru"), ("pt-BR", "pt"), ("zh_TW", "zh-Hant"),
             (attack, "en"), ("__proto__", "en"), ("constructor", "en")]
    with sync_playwright() as playwright:
        browser = launch_browser(playwright)
        page = browser.new_page()
        errors, external = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def local_document(route):
            if route.request.url.startswith("https://capture.example.test/?lang="):
                route.fulfill(content_type="text/html", body='<main data-capture-wizard></main>')
            else:
                external.append(route.request.url)
                route.abort()

        page.route("**/*", local_document)
        for supplied, expected in cases:
            page.goto("https://capture.example.test/?lang=" + quote(supplied, safe=""))
            page.add_script_tag(path=str(static / "cloud-capture-locales.js"))
            page.add_script_tag(path=str(static / "cloud-capture.js"))
            root = page.locator("[data-capture-wizard]")
            expect(root).to_have_attribute("lang", expected)
            expect(page.locator("#capture-language")).to_have_value(expected)
            suffix = "" if expected == "en" else expected + "/"
            expect(page.locator("#instructions")).to_have_attribute(
                "href", "https://phishdestroy.github.io/TgWitness/" + suffix + "docs/capture/")
            expect(root.locator("img,iframe,script")).to_have_count(0)
            assert not page.evaluate("Boolean(window.captureXss)")

        # A forged DOM option/change must pass the same boundary as the initial URL input.
        page.evaluate("""value=>{const select=document.querySelector('#capture-language');
          select.append(new Option(value,value));select.value=value;
          select.dispatchEvent(new Event('change',{bubbles:true}));}""", attack)
        expect(page.locator("[data-capture-wizard]")).to_have_attribute("lang", "en")
        expect(page.locator("#capture-language")).to_have_value("en")
        expect(page.locator("[data-capture-wizard] img,iframe")).to_have_count(0)
        assert not page.evaluate("Boolean(window.captureXss)")

        # English is the source; a missing translation falls back to that source.
        page.evaluate("""()=>{
          delete window.TGW_CAPTURE_LOCALES.ru['Full instructions'];
          const select=document.querySelector('#capture-language');select.value='ru';
          select.dispatchEvent(new Event('change',{bubbles:true}));
        }""")
        expect(page.locator("#instructions")).to_have_text("Full instructions")
        page.evaluate("""()=>{
          window.TGW_CAPTURE_LOCALES.en={'Full instructions':'Not the source text'};
          const select=document.querySelector('#capture-language');select.value='en';
          select.dispatchEvent(new Event('change',{bubbles:true}));
        }""")
        expect(page.locator("#instructions")).to_have_text("Full instructions")
        assert not errors, errors
        assert not external, external
        browser.close()
    print(json.dumps({"passed": True, "language_cases": len(cases), "forged_change": True,
                      "english_source_and_fallback": True,
                      "page_errors": errors, "external_requests": external}))


if __name__ == "__main__":
    main()
