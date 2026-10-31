"""Navigation breakpoints, focus and Russian labels against a synthetic panel."""
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, check_layout, launch_browser, unlock


def lifecycle_checks(browser, app, output):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    context.add_init_script(r"""(() => {
      const probe=window.shellAcceptance={events:[],resizeQueue:[],policyQueue:[],holdResize:false};
      const match=window.matchMedia.bind(window);
      window.matchMedia=query=>{
        const media=match(query);
        if(query==='(max-width: 767px)'){
          const add=media.addEventListener.bind(media);
          media.addEventListener=(type,listener,options)=>add(type,event=>{
            const fire=()=>listener.call(media,event);
            if(type==='change'&&probe.holdResize)probe.resizeQueue.push(fire);else fire();
          },options);
        }
        return media;
      };
      const fetch=window.fetch.bind(window);
      window.fetch=async(...args)=>{
        const response=await fetch(...args);
        if(sessionStorage.getItem('acceptance-shell-policy')==='1'&&String(args[0]).endsWith('/api/network/policy'))
          await new Promise(resolve=>probe.policyQueue.push(resolve));
        return response;
      };
      window.addEventListener('tgwitness:route',event=>probe.events.push(event.detail?.reason));
    })();""")
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    unlock(page, app)
    page.wait_for_function("()=>window.TgWitnessRouter?.started")
    page.evaluate("shellAcceptance.holdResize=true")
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_function("()=>shellAcceptance.resizeQueue.length>0")
    toggle, sidebar = page.locator("#navigation-toggle"), page.locator(".sidebar")
    destination = page.locator('.sidebar [data-view="witness"]')
    toggle.click()
    destination.focus()
    page.evaluate("shellAcceptance.holdResize=false;shellAcceptance.resizeQueue.splice(0).forEach(f=>f())")
    expect(toggle).to_have_attribute("aria-expanded", "true")
    expect(sidebar).to_be_visible()
    expect(destination).to_be_focused()
    page.keyboard.press("Escape")
    expect(sidebar).to_be_hidden()
    expect(toggle).to_be_focused()
    toggle.click()
    page.set_viewport_size({"width": 1440, "height": 1000})
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(toggle).to_be_hidden()
    assert not page.locator("#workspace main").evaluate("node=>node.inert")

    page.set_viewport_size({"width": 390, "height": 844})
    page.evaluate("sessionStorage.setItem('acceptance-shell-policy','1')")
    page.goto(app.url + "/account?ws=default")
    expect(page.locator("#workspace")).to_be_visible()
    page.wait_for_function("()=>shellAcceptance.policyQueue.length>0")
    toggle.click()
    destination.focus()
    page.evaluate("sessionStorage.removeItem('acceptance-shell-policy');shellAcceptance.policyQueue.splice(0).forEach(f=>f())")
    page.wait_for_function("()=>shellAcceptance.events.includes('initial')")
    expect(toggle).to_have_attribute("aria-expanded", "true")
    expect(sidebar).to_be_visible()
    expect(destination).to_be_focused()
    destination.click()
    expect(page.locator("#view-witness")).to_be_visible()
    expect(sidebar).to_be_hidden()
    toggle.click()
    page.evaluate("lock()")
    expect(page.locator("#gate")).to_be_visible()
    expect(toggle).to_have_attribute("aria-expanded", "false")
    assert not page.locator("#workspace main").evaluate("node=>node.inert")
    assert not errors, errors
    context.close()
    (output / "lifecycle.json").write_text(json.dumps({"delayed_resize_keeps_open_menu_and_focus": True,
        "delayed_initial_route_keeps_open_menu_and_focus": True, "desktop_navigation_and_lock_close_menu": True,
        "page_errors": errors}, indent=2) + "\n", encoding="utf-8")


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
            lifecycle_checks(browser, app, output)
            browser.close()
    print("Panel shell passed: five widths, mobile focus/navigation, unclipped Russian labels and delayed startup/resize.")


if __name__ == "__main__":
    main()
