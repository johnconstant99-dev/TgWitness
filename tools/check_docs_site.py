"""Exercise public guides and visual examples without importing the collector."""
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

if __package__:
    from .build_site import NOTICE_LANGUAGES, NOTICE_PAGES, page_languages
    from .site_content import GUIDES, REFERENCE
    from .site_i18n import LANGUAGES
else:
    from build_site import NOTICE_LANGUAGES, NOTICE_PAGES, page_languages
    from site_content import GUIDES, REFERENCE
    from site_i18n import LANGUAGES

ROOT = Path(__file__).resolve().parents[1]


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def check_examples(page, base):
    page.goto(base + "docs/concepts/", wait_until="networkidle")
    journey = page.locator('[data-lab="journey"]')
    expect(journey).to_have_attribute("data-step", "0")
    for step in (1, 2, 3):
        journey.locator('[data-next]').click()
        expect(journey).to_have_attribute("data-step", str(step))
        expect(journey.locator('[data-record-count]')).to_contain_text(str(step))
    expect(journey.locator('[data-chat-message]')).to_have_text("Message deleted")
    expect(journey.locator('li:not(.is-pending)')).to_have_count(3)
    journey.locator('[data-reset]').click()
    journey.locator('[data-play]').click()

    expect(journey).to_have_attribute("data-step", "3")
    assert "is-playing" not in journey.get_attribute("class")

    chain = page.locator('[data-lab="hash"]')
    expect(chain).to_have_attribute("data-hash-mode", "original")
    original_head = chain.locator('[data-retained-head]').get_attribute("title")
    original_second = chain.locator('[data-stored-digest]').text_content()
    encoded = chain.locator('[data-canonical]').text_content()
    event = json.loads(encoded)
    assert set(event) == {"seq", "observed_at", "source_at", "kind", "chat_id", "message_id", "actor_id", "payload", "previous_hash"}
    assert event['payload']['text'] == "Meet at 11:00"
    assert event['previous_hash'] == chain.locator('[data-hash-node="1"] [data-hash-value]').get_attribute("title")
    assert encoded == json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    assert hashlib.sha256(encoded.encode()).hexdigest() == original_second
    for mode in ("edited", "rebuilt", "truncated", "original"):
        chain.locator(f'[data-hash-mode="{mode}"]').click()
        expect(chain).to_have_attribute("data-hash-mode", mode)
        assert chain.locator('[data-retained-head]').get_attribute("title") == original_head
        encoded = chain.locator('[data-canonical]').text_content()
        recomputed = hashlib.sha256(encoded.encode()).hexdigest()
        assert recomputed == chain.locator('[data-calculated-digest]').text_content()
        stored = chain.locator('[data-stored-digest]').text_content()
        if mode == "edited":
            assert stored == original_second and recomputed != stored
            expect(chain.locator('[data-boundary-verdict]')).to_contain_text("prefix fails")
        elif mode == "rebuilt":
            assert stored == recomputed and stored != original_second
            assert chain.locator('[data-hash-node="3"] [data-hash-value]').get_attribute("title") != original_head
            expect(chain.locator('[data-boundary-verdict]')).to_contain_text("Head differs")
        elif mode == "truncated":
            expect(chain.locator('.is-removed')).to_have_count(1)
            expect(chain.locator('[data-boundary-verdict]')).to_contain_text("2 supplied records < 3")
        else:
            assert stored == original_second
            expect(chain.locator('.is-removed, .is-broken, .is-rebuilt')).to_have_count(0)
    chain.evaluate("node => { for (let i=0; i<5; i++) { node.querySelector('[data-hash-mode=rebuilt]').click(); node.querySelector('[data-hash-mode=original]').click(); } }")
    expect(chain).to_have_attribute("data-hash-mode", "original")
    expect(chain.locator('[data-stored-digest]')).to_have_text(original_second)


    page.emulate_media(reduced_motion="no-preference")
    journey.locator('[data-reset]').click()
    journey.locator('[data-play]').click()
    expect(journey.locator('[data-play]')).to_have_text("Pause")
    journey.locator('[data-play]').click()
    step = journey.get_attribute("data-step")
    page.wait_for_timeout(1750)
    assert journey.get_attribute("data-step") == step
    journey.locator('[data-play]').click()
    expect(journey).to_have_attribute("data-step", "3", timeout=5000)
    journey.locator('[data-reset]').click()
    journey.locator('[data-play]').click()
    page.locator('#layers').scroll_into_view_if_needed()
    expect(journey.locator('[data-play]')).not_to_have_text("Pause")
    page.emulate_media(reduced_motion="reduce")

    page.goto(base + "docs/witness/", wait_until="networkidle")
    witness = page.locator('[data-lab="witness"]')
    for mode, text in (("rollback", "Rollback:"), ("fork", "Fork:"), ("offline", "No response:"), ("ok", "Accepted:")):
        button = witness.locator(f'[data-witness-mode="{mode}"]')
        button.focus()
        page.keyboard.press("Enter")
        expect(button).to_have_attribute("aria-pressed", "true")
        expect(witness.locator('[data-witness-status]')).to_contain_text(text)

    page.goto(base + "docs/cases/", wait_until="networkidle")
    case = page.locator('[data-lab="investigation"]')
    expect(page.get_by_role("heading", level=1)).to_contain_text("all chats")
    expect(case.locator('[data-case-node]')).to_have_count(4)
    for mode, count, phrase in (("person", 2, "sender ID, 71001"), ("link", 4, "four"),
                                ("file", 2, "SHA-256"), ("all", 4, "Four chats")):
        button = case.locator(f'[data-case-mode="{mode}"]')
        button.focus()
        page.keyboard.press("Enter")
        expect(button).to_have_attribute("aria-pressed", "true")
        expect(case.locator('[data-case-node]:not(.is-muted)')).to_have_count(count)
        if mode == "link":
            expect(case.locator('[data-case-status]')).to_contain_text("#146")
            expect(case.locator('[data-case-status]')).to_contain_text("#205")
        else:
            expect(case.locator('[data-case-status]')).to_contain_text(phrase)
    expect(page.locator('#history')).to_have_text("2. Acquire history and preserve the files")
    history = page.locator('.case-table tbody tr').filter(has_text="History across enabled chats")
    expect(history).to_contain_text("pause/resume and a signed progress report")
    expect(history.locator('a')).to_have_attribute("href", "../reference/history/")
    expect(page.locator('.guide-content')).to_contain_text("does not currently provide one global search")

    page.goto(base + "docs/security/", wait_until="networkidle")
    lab = page.locator('[data-lab="security"]')
    expect(lab.locator('[data-security-status]')).to_have_text("Default: only the Telegram connection leaves this machine.")
    expect(lab.locator('.route.is-on')).to_have_count(1)
    for flow in ("replica", "timestamp"):
        button = lab.locator(f'[data-flow-toggle="{flow}"]')
        button.focus()
        page.keyboard.press("Enter")
        expect(button).to_have_attribute("aria-pressed", "true")
        expect(lab.locator(f'.route[data-flow="{flow}"]')).to_have_class(re.compile(r"\bis-on\b"))
    expect(lab.locator('[data-security-status]')).to_contain_text("off-site copy, checkpoint hashes for timestamps")
    lab.locator('[data-flow-toggle="replica"]').click()
    expect(lab.locator('.route.is-on')).to_have_count(2)
    checklist = page.locator('[data-lab="hardening"]')
    toggles = checklist.locator('.check-toggle')
    expect(toggles).to_have_count(8)
    for index in range(8):
        toggles.nth(index).click()
    expect(checklist.locator('[data-checklist-count]')).to_have_text("8 of 8 done")
    expect(checklist).to_have_class(re.compile(r"\bis-complete\b"))
    toggles.first.click()
    expect(toggles.first).to_have_attribute("aria-pressed", "false")
    expect(checklist.locator('[data-checklist-count]')).to_have_text("7 of 8 done")


    page.goto(base + "docs/reference/how-it-works/", wait_until="networkidle")
    figures = page.locator('[data-diagram]')
    expect(figures).to_have_count(3)
    for index in range(3):
        figure = figures.nth(index)
        figure.scroll_into_view_if_needed()
        assert "will-draw" not in (figure.get_attribute("class") or "")
        expect(figure.locator('svg[role="img"] desc')).not_to_be_empty()
        expect(figure.locator('.flow-steps li').first).to_be_attached()
    page.emulate_media(reduced_motion="no-preference")
    page.reload(wait_until="networkidle")
    figure = page.locator('[data-diagram]').nth(1)
    figure.scroll_into_view_if_needed()
    expect(figure).to_have_class(re.compile(r"\bis-drawn\b"))
    expect(figure).to_have_class(re.compile(r"\bis-live\b"), timeout=5000)
    page.emulate_media(reduced_motion="reduce")


def main():
    output = ROOT / "test-results/docs-site"
    output.mkdir(parents=True, exist_ok=True)
    errors, external, failed = [], [], []
    widths = (1440, 1024, 768, 390, 320)
    with tempfile.TemporaryDirectory(prefix="docs-site-", dir=ROOT / "test-results") as scratch:
        shutil.copytree(ROOT / "dist/site", Path(scratch) / "TgWitness")
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=scratch))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}/TgWitness/"

        def route_request(route):
            if urlsplit(route.request.url).hostname != "127.0.0.1":
                external.append(route.request.url)
                route.abort()
            else:
                route.continue_()

        def track(page):
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
                context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                context.grant_permissions(["clipboard-read", "clipboard-write"])
                context.route("**/*", route_request)
                page = context.new_page()
                track(page)
                paths = [("", "docs/"), *((slug, f"docs/{slug}/") for slug in GUIDES), ("reference", "docs/reference/"),
                         *((slug, f"docs/reference/{slug}/") for slug in REFERENCE)]
                for slug, path in paths:
                    page.goto(base + path, wait_until="networkidle")
                    assert page.locator("html").get_attribute("lang") == "en"
                    expect(page.get_by_role("heading", level=1)).to_be_visible()
                    expect(page.locator("#guide-search")).to_be_visible()
                    if slug != "capture":
                        assert not page.locator('input:not([type="search"]),form').count()
                    expect(page.locator('link[rel=alternate][hreflang]')).to_have_count(len(page_languages(path)) + 1)
                    assert not page.evaluate("document.body.textContent.includes('@@')")
                    assert page.evaluate("getComputedStyle(document.documentElement).scrollBehavior") == "auto"
                    assert not page.locator(".will-reveal, .will-draw").count(), path
                    if slug:
                        expect(page.locator('.sidebar [aria-current="page"]')).to_have_count(1)
                    else:
                        expect(page.locator(".guide-card")).to_have_count(len(GUIDES) + 1)
                        expect(page.locator('.guide-card[href="../guides/modes.html"]')).to_be_visible()
                    for width in widths:
                        page.set_viewport_size({"width": width, "height": 1000})
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (path, width)
                    if slug in ("", "proxies", "concepts", "witness", "cases", "security", "reference", "how-it-works"):
                        for width in (1440, 390):
                            page.set_viewport_size({"width": width, "height": 1000})
                            page.screenshot(path=str(output / f"en-{slug or 'guides'}-{width}.png"), full_page=True)
                            for lab in page.locator('[data-lab]').all():
                                lab.screenshot(path=str(output / f"lab-{lab.get_attribute('data-lab')}-{width}.png"))
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.goto(base + "docs/", wait_until="networkidle")
                field = page.locator("#guide-search")
                for term, target in (("proxy", "proxies"), ("hash chain", "concepts"), ("use cases", "cases")):
                    field.fill(term)
                    first = page.locator(".search-result").first
                    field.press("ArrowDown")
                    expect(first).to_be_focused()
                    page.keyboard.press("Enter")
                    expect(page).to_have_url(base + f"docs/{target}/")
                page.locator("#guide-search").fill('<img src=x onerror="window.searchInjection=true">')
                expect(page.locator("#search-results")).to_be_hidden()
                assert not page.evaluate("Boolean(window.searchInjection)")
                page.locator(".search-clear").click()
                expect(page.locator("#guide-search")).to_have_value("")
                expect(page.locator("#guide-search")).to_be_focused()

                page.goto(base + "docs/start/", wait_until="networkidle")
                command = page.locator("pre").first.locator("code").text_content()
                page.locator(".copy-control").first.click()
                expect(page.locator(".copy-control").first).to_have_text("Copied")
                assert page.evaluate("navigator.clipboard.readText()").replace("\r\n", "\n") == command
                page.evaluate("() => { navigator.clipboard.writeText = async () => { throw new Error('synthetic denial'); }; }")
                page.locator(".copy-control").first.click()
                expect(page.locator(".guide-footer [role=status]")).to_contain_text("manually")
                assert page.evaluate("window.getSelection().toString()") == command

                check_examples(page, base)


                page.emulate_media(color_scheme="light")
                page.goto(base + "docs/", wait_until="networkidle")
                expect(page.locator("html")).to_have_attribute("data-theme", "light")
                page.locator("[data-theme-toggle]").click()
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                page.reload(wait_until="networkidle")
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                expect(page.locator("[data-theme-toggle]")).to_have_attribute("aria-pressed", "true")
                assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(10, 17, 32)"
                page.locator("[data-theme-toggle]").click()
                expect(page.locator("html")).to_have_attribute("data-theme", "light")


                for lang in [code for code in NOTICE_LANGUAGES if code != "en"]:
                    locales = ("", "docs/", "docs/cases/", "docs/security/", "docs/reference/how-it-works/", *NOTICE_PAGES) if lang in LANGUAGES else NOTICE_PAGES
                    for local in locales:
                        path = lang + "/" + local
                        page.set_viewport_size({"width": 1440, "height": 1000})
                        page.goto(base + path, wait_until="networkidle")
                        html_tag = page.locator("html")
                        expect(html_tag).to_have_attribute("lang", NOTICE_LANGUAGES[lang][1])
                        expect(html_tag).to_have_attribute("dir", NOTICE_LANGUAGES[lang][2])
                        expect(page.get_by_role("heading", level=1)).to_be_visible()
                        assert not page.evaluate("document.body.textContent.includes('@@')"), path
                        expect(page.locator(".lang-list a")).to_have_count(len(page_languages(local)))
                        expect(page.locator('.lang-list a[aria-current]')).to_have_attribute("hreflang", NOTICE_LANGUAGES[lang][1])
                        if local:
                            expect(page.locator("#guide-search")).to_be_visible()
                        if local == "docs/cases/":
                            expect(page.locator('.language-notice')).to_have_count(0)
                            case = page.locator('[data-lab="investigation"]')
                            case.locator('[data-case-mode="person"]').click()
                            expect(case.locator('[data-case-mode="person"]')).to_have_attribute('aria-pressed', 'true')

                            page.locator('.lang-menu > summary').click()
                            target = 'de' if lang != 'de' else 'fr'
                            expect(page.locator(f'.lang-list a[hreflang="{target}"]')).to_have_attribute('href', f'../../../{target}/docs/cases/')
                            page.locator('.lang-menu > summary').click()
                        if local in ("docs/reference/license/", "docs/reference/notice/"):
                            expect(page.locator('.language-notice')).to_have_count(0 if lang in LANGUAGES else 1)
                            expect(page.locator('.wiki-body [translate="no"]')).to_have_count(0)
                            assert page.locator('.wiki-body').evaluate('el => getComputedStyle(el).direction') == NOTICE_LANGUAGES[lang][2]
                            page.locator('#guide-search').fill('Taylor')
                            expect(page.locator('.search-result').first).to_be_visible()
                            page.locator('#guide-search').fill('')
                        for width in (1440, 390, 320):
                            page.set_viewport_size({"width": width, "height": 1000})
                            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (path, width)
                        if local in ("", "docs/security/") and lang in ("ru", "ar", "zh", "hi"):
                            for width in (1440, 390):
                                page.set_viewport_size({"width": width, "height": 1000})
                                page.screenshot(path=str(output / f"{lang}-{local.strip('/').replace('/', '-') or 'home'}-{width}.png"), full_page=True)
                page.set_viewport_size({"width": 1440, "height": 1000})
                page.goto(base + "ru/docs/", wait_until="networkidle")
                page.locator("#guide-search").fill("прокси")
                expect(page.locator(".search-result").first).to_be_visible()
                page.goto(base + "ar/docs/security/", wait_until="networkidle")
                lab = page.locator('[data-lab="security"]')
                lab.locator('[data-flow-toggle="witness"]').click()
                expect(lab.locator('.route[data-flow="witness"]')).to_have_class(re.compile(r"\bis-on\b"))
                assert "Telegram" in lab.locator("[data-security-status]").text_content()


                unavailable = context.new_page()
                track(unavailable)
                unavailable.add_init_script("Object.defineProperty(crypto, 'subtle', {value:undefined});")
                unavailable.goto(base + "docs/concepts/", wait_until="networkidle")
                expect(unavailable.locator('[data-hash-status]')).to_contain_text("Web Crypto")
                expect(unavailable.locator('[data-hash-mode="original"]')).to_be_hidden()
                unavailable.close()

                nojs = browser.new_context(java_script_enabled=False, viewport={"width": 390, "height": 844})
                nojs.route("**/*", route_request)
                fallback = nojs.new_page()
                track(fallback)
                for slug in ("", "start", "concepts", "cases", "witness", "reference/license", "reference/notice"):
                    fallback.goto(base + "docs/" + (slug + "/" if slug else ""))
                    expect(fallback.locator(".search")).to_be_hidden()
                    assert not fallback.locator('[data-enhanced]:visible').count()
                    if not slug:
                        expect(fallback.locator(".guide-card")).to_have_count(len(GUIDES) + 1)
                    else:
                        expect(fallback.locator(".next-guide")).to_be_visible()
                    if slug == "concepts":
                        expect(fallback.locator('.formula-card')).to_have_count(2)
                        expect(fallback.locator('[data-event]')).to_have_count(3)
                    if slug == "cases":
                        expect(fallback.locator('[data-case-node]')).to_have_count(4)
                        expect(fallback.locator('#scope')).to_be_visible()
                        expect(fallback.locator('.case-timeline li')).to_have_count(6)
                    assert fallback.evaluate("document.documentElement.scrollWidth <= innerWidth")
                for lang in NOTICE_LANGUAGES:
                    for local in NOTICE_PAGES:
                        for scheme in ('light', 'dark'):
                            fallback.emulate_media(color_scheme=scheme, reduced_motion='reduce')
                            fallback.set_viewport_size({'width': 320, 'height': 844})
                            fallback.goto(base + (lang + '/' if lang != 'en' else '') + local)
                            expect(fallback.locator('h1')).to_be_visible()
                            expect(fallback.locator('.wiki-body')).to_be_visible()
                            expect(fallback.locator('.lang-list a')).to_have_count(len(NOTICE_LANGUAGES))
                            expect(fallback.locator('.search')).to_be_hidden()
                            assert fallback.evaluate('getComputedStyle(document.body).backgroundColor') == (
                                'rgb(10, 17, 32)' if scheme == 'dark' else 'rgb(247, 248, 250)')
                            assert fallback.evaluate('document.documentElement.scrollWidth <= innerWidth'), (lang, local, scheme)
                            if lang in ('he', 'am', 'fr') and local.endswith('/notice/'):
                                fallback.screenshot(path=str(output / f'{lang}-notice-320-{scheme}-nojs.png'), full_page=True)
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    assert not errors, errors
    assert not external, external
    assert not failed, failed
    receipt = {"result": "passed", "guide_pages": len(GUIDES) + 1, "reference_pages": len(REFERENCE) + 1, "language": "en", "widths": widths,
               "search_keyboard_and_empty_state": True, "copy_and_denial": True,
               "no_javascript_fallback": True, "project_subpath": True,
               "message_playback_pause_and_reduced_motion": True, "sha256_matches_python": True,
               "tamper_rebuild_truncation_and_missing_crypto": True,
               "witness_scenarios_keyboard": True,
               "investigation_map_keyboard_and_static_fallback": True,
               "security_map_and_checklist_keyboard": True, "diagrams_drawn_and_described": True,
               "languages": list(LANGUAGES), "notice_languages": list(NOTICE_LANGUAGES), "theme_toggle_persists": True,
               "external_requests": external, "javascript_errors": errors, "failed_requests": failed}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
