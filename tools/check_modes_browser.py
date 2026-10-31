"""Browser acceptance for the keyed capability guide, called by check_site.py."""
import hashlib
import json
from urllib.parse import urlsplit

from playwright.sync_api import expect

try:
    from .site_modes import LANGUAGES
except ImportError:
    from site_modes import LANGUAGES


def check_modes(browser, url, output, errors, external, failed):
    checks = []
    cases = [(lang, 320, theme, False) for lang in LANGUAGES for theme in ("light", "dark")]
    cases += [(lang, 1440, theme, True) for lang in ("en", "ru") for theme in ("light", "dark")]
    cases += [("ru", 320, "dark", True)]
    for lang, width, theme, javascript in cases:
        context = browser.new_context(viewport={"width": width, "height": 1000}, java_script_enabled=javascript,
                                      color_scheme=theme, reduced_motion="reduce")

        def route(request):
            if urlsplit(request.request.url).hostname != "127.0.0.1":
                external.append(request.request.url)
                request.abort()
            else:
                request.continue_()

        context.route("**/*", route)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append("modes: " + str(error)))
        page.on("response", lambda response: failed.append(response.url) if response.status >= 400 else None)
        page.goto(url + ("" if lang == "en" else lang + "/") + "guides/modes.html", wait_until="networkidle")
        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), (lang, width, theme)
        assert page.locator(".m-ladder>li").count() == 7
        assert page.locator(".m-scope").count() == 4
        assert page.locator(".m-scenarios>article").count() == 5
        assert page.locator(".m-limit").count() == 24
        assert page.locator(".m-section-head .m-number").all_text_contents() == [f"{n:02d}" for n in range(1, 11)]
        assert page.locator(".lang-list a").count() == len(LANGUAGES)
        assert not page.evaluate("document.body.innerText.includes('{{modes.') || document.body.innerText.includes('@@')")
        assert page.evaluate("getComputedStyle(document.querySelector('.m-flow-pulse')).animationName") == "none"

        color = page.evaluate("getComputedStyle(document.body).backgroundColor")
        assert color == ("rgb(10, 17, 32)" if theme == "dark" else "rgb(247, 248, 250)"), (lang, theme, color)

        low_contrast = page.evaluate("""() => {
          const rgb=s=>s.match(/[\\d.]+/g).map(Number);
          const lum=c=>c.slice(0,3).map(x=>{x/=255;return x<=.04045?x/12.92:((x+.055)/1.055)**2.4}).reduce((a,x,i)=>a+x*[.2126,.7152,.0722][i],0);
          return [...document.querySelectorAll('.m-wrap *, .m-header a, .m-footer p')].flatMap(el=>{
            if(!el.getClientRects().length || ['SVG','PATH','CODE','PRE','INPUT'].includes(el.tagName.toUpperCase()) || ![...el.childNodes].some(n=>n.nodeType===3&&n.textContent.trim()))return [];
            const cs=getComputedStyle(el); let bg=el;
            while(bg&&rgb(getComputedStyle(bg).backgroundColor)[3]===0)bg=bg.parentElement;
            if(!bg)return [];
            const a=lum(rgb(cs.color)),b=lum(rgb(getComputedStyle(bg).backgroundColor));
            const ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
            const large=parseFloat(cs.fontSize)>=24 || parseFloat(cs.fontSize)>=18.66&&parseInt(cs.fontWeight)>=700;
            return ratio+0.01<(large?3:4.5)?[{text:el.textContent.slice(0,50),ratio}]:[];
          });
        }""")
        assert not low_contrast, (lang, theme, low_contrast[:5])
        if javascript:
            field = page.locator("[data-edit-record]")
            expect(field).to_be_visible()
            saved = page.locator("[data-stored]").text_content()
            original = field.input_value()
            await_original = page.locator("[data-calculated]").text_content()
            assert saved == await_original and len(saved) == 64
            field.fill("Meet at 12:30")
            expect(page.locator('[data-lab="modesHash"]')).to_have_attribute("data-state", "error")
            changed = page.locator("[data-calculated]").text_content()
            assert changed != saved and len(changed) == 64

            first = {"seq": 1, "observed_at": "2026-01-01T10:00:00.000+00:00", "source_at": None,
                     "kind": "message.new", "chat_id": -100123, "message_id": 42, "actor_id": None,
                     "payload": {"text": "Meet at 10:00"}, "previous_hash": "0" * 64}
            def digest(value):
                return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            second = {**first, "seq": 2, "kind": "message.edited", "payload": {"text": "Meet at 12:30"}, "previous_hash": digest(first)}
            assert changed == digest(second)
            field.fill(original)
            expect(page.locator('[data-lab="modesHash"]')).to_have_attribute("data-state", "ok")

            selected = page.locator('input[name="scope-example"]').first
            selected.focus()
            page.keyboard.press("ArrowRight")
            expect(page.locator('input[name="scope-example"]').nth(1)).to_be_checked()
            switch = page.get_by_role("switch").first
            switch.focus()
            page.keyboard.press("Space")
            expect(switch).not_to_be_checked()

            command = page.locator(".m-command").first
            command.locator("summary").focus()
            expect(command.locator("pre")).to_be_visible()
            if width == 1440:
                page.evaluate("scrollTo(0,0)")
                page.screenshot(path=str(output / f"modes-{lang}-{theme}-hero.png"))
                page.locator("#levels").screenshot(path=str(output / f"modes-{lang}-{theme}-levels.png"))
            page.locator("[data-theme-toggle]").click()
            assert page.locator("html").get_attribute("data-theme") == ("light" if theme == "dark" else "dark")
        else:
            expect(page.locator("[data-edit-record]")).to_be_hidden()
            command = page.locator(".m-command").first
            command.locator("summary").click()
            assert command.get_attribute("open") is not None
            expect(command.locator("pre")).to_be_visible()
            if lang == "ru" and theme == "dark":
                page.evaluate("scrollTo(0,0)")
                page.screenshot(path=str(output / "modes-ru-mobile-no-js.png"))
        checks.append({"language": lang, "width": width, "theme": theme, "javascript": javascript, "passed": True})
        context.close()
        print(f"Modes: {lang}, {width}px, {theme}, JS={javascript} passed", flush=True)
    (output / "modes-checks.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
