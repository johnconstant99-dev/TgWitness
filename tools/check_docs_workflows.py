"""Check the four documentation examples, their controls and static fallbacks."""
import argparse
import json
import os
from pathlib import Path
import shutil

from playwright.sync_api import expect, sync_playwright

if __package__:
    from .site_i18n import LANGUAGES
    from .site_test_server import site_server
else:
    from site_i18n import LANGUAGES
    from site_test_server import site_server

ROOT = Path(__file__).resolve().parents[1]
PAGES = {"case-board": "board", "reports": "report", "handover": "handover", "groups": "groups"}


def english_fixture(destination):
    """Use the actual new guide fragments before the multilingual site is built."""
    destination.mkdir(parents=True, exist_ok=True)
    for asset in ("docs.css", "learn.css", "workflows.css", "workflows.js"):
        shutil.copyfile(ROOT / "website" / asset, destination / asset)
    for slug in PAGES:
        fragment = (ROOT / "website/guides/en" / (slug + ".html")).read_text(encoding="utf-8")
        folder = destination / "docs" / slug
        folder.mkdir(parents=True, exist_ok=True)
        page = ('<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{slug} example fixture</title>'
                '<link rel="stylesheet" href="../../docs.css">'
                '<link rel="stylesheet" href="../../learn.css">'
                '<link rel="stylesheet" href="../../workflows.css">'
                '<script defer src="../../workflows.js"></script></head>'
                '<body><main class="docs-main" style="max-width:760px;margin:0 auto;padding:16px">'
                f'<h1>{slug}</h1>{fragment}</main></body></html>')
        (folder / "index.html").write_text(page, encoding="utf-8")
    return destination


def current_text(lab):
    return " ".join(lab.locator('[data-workflow-step][aria-current="step"]').inner_text().split())


def check_layout(page, lab, label):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), label
    assert not lab.evaluate("""root => [...root.querySelectorAll('*')].flatMap(node => {
        const box = node.getBoundingClientRect();
        return box.width && (box.left < -1 || box.right > innerWidth + 1) ? [node.tagName] : [];
    })"""), label
    assert lab.get_attribute("aria-labelledby"), label
    for button in lab.locator("button:visible").all():
        assert button.inner_text().strip(), label
        assert button.bounding_box()["height"] >= 43, label
    for group in lab.locator("fieldset:visible").all():
        assert group.locator("legend").inner_text().strip(), label
    low_contrast = lab.evaluate("""root => {
        const rgb = text => text.match(/[\\d.]+/g).map(Number);
        const luminance = values => values.slice(0,3).map(v => {
            v /= 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4;
        }).reduce((sum, v, i) => sum + v * [.2126,.7152,.0722][i], 0);
        const background = node => {
            const layers = [];
            for (; node; node = node.parentElement) layers.push(rgb(getComputedStyle(node).backgroundColor));
            return layers.reverse().reduce((under, over) => {
                const alpha = over.length === 4 ? over[3] : 1;
                return over.slice(0,3).map((value, i) => value * alpha + under[i] * (1 - alpha));
            }, [255,255,255]);
        };
        return [...root.querySelectorAll('*')].flatMap(node => {
            if (!node.getClientRects().length || node.closest('[hidden], [aria-hidden=true]') ||
                ![...node.childNodes].some(child => child.nodeType === 3 && child.textContent.trim())) return [];
            const style = getComputedStyle(node), a = luminance(rgb(style.color)), b = luminance(background(node));
            const ratio = (Math.max(a,b) + .05) / (Math.min(a,b) + .05);
            const large = parseFloat(style.fontSize) >= 24 || parseFloat(style.fontSize) >= 18.66 && parseInt(style.fontWeight) >= 700;
            return ratio + .01 < (large ? 3 : 4.5) ? [{text:node.textContent.slice(0,60),ratio}] : [];
        });
    }""")
    assert not low_contrast, (label, low_contrast)


def check_sequence(page, lab):
    expect(lab).to_have_attribute("data-step", "0")
    expect(lab).to_have_attribute("data-playing", "false")
    expect(lab.locator("[data-workflow-controls]")).to_be_visible()
    expect(lab.locator("[data-workflow-step]")).to_have_count(4)
    expect(lab.locator("[data-workflow-node]")).to_have_count(4)
    assert lab.locator("[data-workflow-status]").inner_text() == current_text(lab)
    page.clock.install()
    page.clock.fast_forward(12000)
    expect(lab).to_have_attribute("data-step", "0")  # No autoplay.
    next_button = lab.locator("[data-workflow-next]")
    next_button.focus()
    expect(next_button).to_be_focused()
    assert next_button.evaluate("node => getComputedStyle(node).outlineStyle") == "solid"
    next_button.press("Space")
    expect(lab).to_have_attribute("data-step", "1")
    assert lab.locator("[data-workflow-status]").inner_text() == current_text(lab)
    play = lab.locator("[data-workflow-play]")
    play.press("Enter")
    expect(lab).to_have_attribute("data-playing", "true")
    page.clock.fast_forward(2401)
    expect(lab).to_have_attribute("data-step", "2")
    play.press("Enter")
    expect(lab).to_have_attribute("data-playing", "false")
    page.clock.fast_forward(12000)
    expect(lab).to_have_attribute("data-step", "2")
    next_button.press("Enter")
    expect(lab).to_have_attribute("data-step", "3")
    expect(next_button).to_be_disabled()
    expect(lab.locator(".workflow-node.is-complete")).to_have_count(3)
    play.click()
    expect(lab).to_have_attribute("data-step", "0")
    expect(lab).to_have_attribute("data-playing", "true")
    for step in (1, 2, 3):
        page.clock.fast_forward(2401)
        expect(lab).to_have_attribute("data-step", str(step))
    expect(lab).to_have_attribute("data-playing", "false")
    expect(next_button).to_be_disabled()
    play.click()
    page.evaluate("window.dispatchEvent(new Event('pagehide'))")
    expect(lab).to_have_attribute("data-playing", "false")
    page.clock.fast_forward(8000)
    expect(lab).to_have_attribute("data-step", "0")
    page.emulate_media(reduced_motion="no-preference")
    play.click()
    page.emulate_media(reduced_motion="reduce")
    expect(lab).to_have_attribute("data-playing", "false")
    next_button.click()
    assert lab.locator(".workflow-node.is-current").evaluate(
        "node => getComputedStyle(node).animationName") == "none"
    lab.locator("[data-workflow-reset]").click()
    expect(lab).to_have_attribute("data-step", "0")
    expect(next_button).to_be_enabled()


def check_choices(lab, kind):
    if kind == "report":
        preview = lab.locator("[data-workflow-design]")
        choices = lab.locator('[data-workflow-choices="design"]')
        choices.locator('[data-workflow-choice="reading_series"]').press("Enter")
        expect(lab).to_have_attribute("data-step", "1")
        expect(lab).to_have_attribute("data-playing", "false")
        expect(preview).to_be_visible()
        expect(preview).to_have_attribute("data-workflow-design", "reading_series")
        expect(choices.locator('[aria-pressed="true"]')).to_have_count(1)
        content = lab.locator('[data-workflow-choices="contents"]')
        for button in content.locator("button").all():
            value = button.get_attribute("data-workflow-choice")
            button.press("Space")
            expect(lab).to_have_attribute("data-step", "1")
            expect(lab.locator("[data-workflow-content]:visible")).to_have_count(1)
            expect(lab.locator(f'[data-workflow-content="{value}"]')).to_be_visible()
        lab.locator("[data-workflow-reset]").click()
        expect(preview).to_have_attribute("data-workflow-design", "classic")
    if kind == "handover":
        original = lab.locator('[data-workflow-node="0"]').inner_text()
        choices = lab.locator('[data-workflow-choices="identity"]')
        for value in ("pseudonymize", "omit", "keep"):
            choices.locator(f'[data-workflow-choice="{value}"]').press("Enter")
            expect(lab).to_have_attribute("data-step", "1")
            expect(lab).to_have_attribute("data-playing", "false")
            expect(lab.locator("[data-workflow-identity-value]:visible")).to_have_count(1)
            expect(lab.locator(f'[data-workflow-identity-value="{value}"]')).to_be_visible()
            assert lab.locator('[data-workflow-node="0"]').inner_text() == original
        choices.locator('[data-workflow-choice="omit"]').click()
        lab.locator("[data-workflow-reset]").click()
        expect(lab.locator('[data-workflow-identity-value="keep"]')).to_be_visible()


def mobile_step_measurements(page, lab, kind):
    """The active sample must remain beside its controls during real playback."""
    page.clock.install()
    measurements = []

    def measure():
        value = lab.evaluate("""root => {
            const box = node => {
                const r = node.getBoundingClientRect();
                return {top:r.top,bottom:r.bottom,height:r.height};
            };
            return {step:Number(root.dataset.step),height:innerHeight,
                current:box(root.querySelector('.workflow-node.is-current')),
                controls:box(root.querySelector('[data-workflow-controls]')),
                scene:box(root.querySelector('[data-workflow-scene]'))};
        }""")
        current = value["current"]
        # The persistent original can start above the viewport when the browser
        # centres controls under a long translated original/copy pair. It remains
        # readable by scrolling; every subsequent active copy/stage is in view.
        if kind == "handover" and value["step"] == 0:
            assert current["bottom"] > 0, value
        else:
            assert current["top"] >= -1 and current["bottom"] <= value["height"] + 1, value
        if measurements:
            assert abs(value["controls"]["top"] - measurements[0]["controls"]["top"]) < 1, value
            assert abs(value["scene"]["height"] - measurements[0]["scene"]["height"]) < 1, value
        expect(lab.locator("[data-workflow-node]:visible")).to_have_count(2 if kind == "handover" else 1)
        if kind == "handover":
            expect(lab.locator('[data-workflow-node="0"]')).to_be_visible()
        measurements.append(value)

    lab.locator("[data-workflow-play]").click()
    for step in range(4):
        if step:
            page.clock.fast_forward(2401)
        expect(lab).to_have_attribute("data-step", str(step))
        measure()
    expect(lab).to_have_attribute("data-playing", "false")
    lab.locator("[data-workflow-reset]").click()
    lab.locator("[data-workflow-next]").click()
    expect(lab).to_have_attribute("data-step", "1")
    measure()
    check_choices(lab, kind)
    return measurements


def run(browser, base, output, fixture, source_assets=False):
    errors, external, failed, writes = [], [], [], []

    def route_request(route):
        if not route.request.url.startswith(base):
            external.append(route.request.url)
            route.abort()
        elif source_assets and route.request.url.rsplit("/", 1)[-1] in {"workflows.js", "workflows.css"}:
            route.fulfill(path=ROOT / "website" / route.request.url.rsplit("/", 1)[-1])
        else:
            if route.request.method not in {"GET", "HEAD"}:
                writes.append(route.request.url)
            route.continue_()

    def context(**options):
        ctx = browser.new_context(**options)
        ctx.route("**/*", route_request)
        ctx.on("page", lambda page: (
            page.on("pageerror", lambda error: errors.append(str(error))),
            page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)))
        return ctx

    for slug, kind in PAGES.items():
        ctx = context(viewport={"width": 1280, "height": 960}, reduced_motion="reduce")
        page = ctx.new_page()
        page.goto(base + f"docs/{slug}/", wait_until="networkidle")
        lab = page.locator(f'[data-workflow="{kind}"]')
        expect(lab.locator("[data-workflow-node]:visible")).to_have_count(4)
        check_sequence(page, lab)
        check_choices(lab, kind)
        for direction in ("ltr", "rtl"):
            page.locator("html").evaluate("(node, direction) => node.dir = direction", direction)
            for width in (320, 768, 1280):
                page.set_viewport_size({"width": width, "height": 960})
                for theme in ("light", "dark"):
                    page.locator("html").evaluate("(node, theme) => node.dataset.theme = theme", theme)
                    check_layout(page, lab, (slug, direction, width, theme))
                if width == 320:
                    lab.screenshot(path=str(output / f"{slug}-{direction}-320.png"))
        ctx.close()

    step_measurements = []
    for lang in (("en",) if fixture else ("en", "de", "ar")):
        for slug, kind in PAGES.items():
            ctx = context(viewport={"width": 320, "height": 844}, reduced_motion="reduce")
            page = ctx.new_page()
            page.goto(base + ("" if lang == "en" else lang + "/") + f"docs/{slug}/", wait_until="networkidle")
            values = mobile_step_measurements(page, page.locator(f'[data-workflow="{kind}"]'), kind)
            step_measurements.append({"language": lang, "page": slug, "states": values})
            ctx.close()
    (output / "mobile-step-measurements.json").write_text(json.dumps(step_measurements, indent=2) + "\n", encoding="utf-8")

    languages = ("en",) if fixture else tuple(LANGUAGES)
    for lang in languages:
        prefix = "" if lang == "en" else lang + "/"
        ctx = context(viewport={"width": 320, "height": 960}, reduced_motion="reduce")
        page = ctx.new_page()
        for slug, kind in PAGES.items():
            page.goto(base + prefix + f"docs/{slug}/", wait_until="networkidle")
            lab = page.locator(f'[data-workflow="{kind}"]')
            expect(lab).to_have_attribute("data-step", "0")
            expected_progress = page.evaluate("""() => {
                const words = JSON.parse(document.getElementById('site-dict')?.textContent || '{}');
                return (words['Step {n} of {total}'] || 'Step {n} of {total}').replace('{n}', '1').replace('{total}', '4');
            }""")
            expect(lab.locator("[data-workflow-progress]")).to_have_text(expected_progress)
            for theme in ("light", "dark"):
                page.locator("html").evaluate("(node, theme) => node.dataset.theme = theme", theme)
                check_layout(page, lab, (lang, slug, theme))
        ctx.close()
        print(f"Workflow examples: {lang} mobile/light/dark passed", flush=True)

    for lang in (("en",) if fixture else ("en", "ar")):
        ctx = context(viewport={"width": 320, "height": 960}, java_script_enabled=False)
        page = ctx.new_page()
        for slug, kind in PAGES.items():
            page.goto(base + ("" if lang == "en" else lang + "/") + f"docs/{slug}/", wait_until="networkidle")
            lab = page.locator(f'[data-workflow="{kind}"]')
            expect(lab.locator("[data-workflow-controls]")).to_be_hidden()
            expect(lab.locator("[data-workflow-node]:visible")).to_have_count(4)
            expect(lab.locator("[data-workflow-step]:visible")).to_have_count(4)
            for group in lab.locator("[data-workflow-choices]").all():
                expect(group).to_be_hidden()
            if kind == "report":
                expect(lab.locator("[data-workflow-content]:visible")).to_have_count(2)
            if kind == "handover":
                expect(lab.locator("[data-workflow-identity-value]:visible")).to_have_count(3)
            check_layout(page, lab, (slug, lang, "no JavaScript"))
        ctx.close()
    assert not errors and not external and not failed and not writes, (errors, external, failed, writes)
    return {"passed": True, "english_fixture": fixture, "source_assets": source_assets, "pages": list(PAGES), "languages": list(languages),
            "keyboard": True, "play_pause_reset": True, "no_autoplay": True, "reduced_motion": True,
            "static_fallback": True, "mobile_rtl_dark": True, "text_contrast": True, "original_unchanged": True,
            "mobile_current_step": True, "mobile_controls_stable": True,
            "javascript_errors": errors, "external_requests": external, "failed_requests": failed, "writes": writes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--english-fixture", action="store_true")
    parser.add_argument("--source-assets", action="store_true", help="Check source workflow JS/CSS over the existing translated site before rebuilding.")
    parser.add_argument("--site-root", type=Path, default=ROOT / "dist/site")
    parser.add_argument("--output", type=Path, default=ROOT / "test-results/docs-workflows")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    site = english_fixture(args.output / "english-site") if args.english_fixture else args.site_root
    with site_server(site) as base, sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)
        receipt = run(browser, base, args.output, args.english_fixture, args.source_assets)
        browser.close()
    name = "english-receipt.json" if args.english_fixture else "receipt.json"
    (args.output / name).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
