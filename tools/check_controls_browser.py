"""Settings keep later edits; connection retries read status only."""
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, hold_api_response, launch_browser, release_api_response, unlock


def main():
    output = Path('build/ux-review/after/35-36-controls')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='controls-ui-') as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.add_init_script("""(()=>{const set=window.setInterval;window.setInterval=(fn,ms,...args)=>ms===5000?0:set(fn,ms,...args);})();""")
            unlock(page, server)
            page.evaluate("()=>navigate('witness')")
            page.locator('#extras-open-evidence').click()
            interval = page.locator('#evidence-interval')
            expect(interval).not_to_have_value('')
            interval.fill('13')
            expect(page.locator('#evidence-form .form-draft-bar')).to_be_visible()
            hold_api_response(page, '/api/evidence')
            interval.press('Control+s')
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            interval.fill('14')
            release_api_response(page)
            expect(page.locator('#evidence-form > button[type=submit]')).to_be_enabled()
            expect(interval).to_have_value('14')
            expect(page.locator('#evidence-form .form-draft-bar')).to_be_visible()
            assert server.app.state.store.get_setting('evidence')['interval_minutes'] == 13
            page.locator('#evidence-form .form-draft-bar .quiet').click()
            expect(interval).to_have_value('13')
            expect(page.locator('#evidence-form .form-draft-bar')).to_be_hidden()
            interval.fill('19')
            page.evaluate("async()=>{await navigate('chats');await navigate('witness');selectExtra('evidence');}")
            expect(interval).to_have_value('19')
            await_path = '**/api/status'
            page.route(await_path, lambda route: route.fulfill(status=502, json={'detail': 'Synthetic tunnel failure'}))
            page.evaluate("()=>refreshStatus().catch(()=>{})")
            expect(page.locator('#panel-connection-notice')).to_be_visible()
            page.unroute(await_path)
            page.locator('#panel-connection-notice button').click()
            expect(page.locator('#panel-connection-notice')).to_be_hidden()
            expect(interval).to_have_value('19')
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                for theme in ('light', 'dark'):
                    page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                    interval.scroll_into_view_if_needed()
                    page.screenshot(path=str(output / f'{width}-{theme}.png'))
                    assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth+1')
            hold_api_response(page, '/api/parameters')
            page.evaluate("()=>{void navigate('parameters');}")
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            expect(page.locator('#view-parameters')).to_have_attribute('aria-busy', 'true')
            release_api_response(page)
            expect(page.locator('#view-parameters')).not_to_have_attribute('aria-busy', 'true')
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>[...panelRoots.values()].every(root=>!root.querySelector('.form-draft-bar:not([hidden])'))")
            assert not errors, errors
            browser.close()
    print('Keyboard save, late-edit preservation, discard, recovery, loading and layouts passed.')


if __name__ == '__main__':
    main()
