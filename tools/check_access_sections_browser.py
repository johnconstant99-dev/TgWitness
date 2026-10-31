"""Access presets, drafts and the separately scoped process log."""
import copy
import re
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, hold_api_response, launch_browser, release_api_response, unlock


def check_console(page, server, output, errors):
    page.evaluate("()=>navigate('access')")
    page.locator('#access-console-open').click()
    expect(page.locator('#view-system-log')).to_be_visible()
    expect(page).to_have_url(re.compile(re.escape(server.url) + r'/system-log(?:\?ws=default)?$'))
    expect(page.locator('#console-state')).to_contain_text('log lines')
    page.evaluate("""()=>{const original=window.fetch;window.consoleFetch=original;
      window.fetch=async(...args)=>{const response=await original(...args);
        if(String(args[0]).includes('/api/access/console?'))await new Promise(resolve=>window.releaseConsole=resolve);
        return response;};window.delayedConsole=loadConsole().then(()=>null,error=>error.name);}""")
    page.wait_for_function("()=>typeof releaseConsole==='function'")
    page.evaluate("()=>navigate('access')")
    assert page.evaluate("async()=>{window.fetch=consoleFetch;releaseConsole();return await delayedConsole;}") == 'StaleView'
    page.goto(server.url + '/system-log')
    expect(page.locator('#view-system-log')).to_be_visible()
    expect(page.locator('#console-state')).to_contain_text('log lines')
    page.evaluate('()=>scrollTo(0,0)')
    page.screenshot(path=str(output / 'system-log-1440.png'), full_page=True)
    token = page.evaluate("""()=>json('access/grants',{label:'Read only reviewer',workspaces:{default:null},
      permissions:['view']},{root:true}).then(r=>r.token)""")
    page.locator('#top-lock').click()
    assert not page.evaluate("()=>$('access-console').textContent"), 'Lock retained process log lines'
    page.locator('#panel-token').fill(token)
    page.locator('#unlock-form button').click()
    expect(page.locator('#workspace')).to_be_visible()
    expect(page.locator('.sidebar [data-view="system-log"]')).to_be_hidden()
    status = page.evaluate("()=>fetch('/api/access/console',{headers:{Authorization:'Bearer '+state.token}}).then(response=>response.status)")
    assert status == 403, status
    assert not errors, errors
    print('System log: navigation, stale reads, refresh, lock and read-only denial passed.', flush=True)


def main(console_only=False):
    output = Path('build/ux-review/after/30')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='access-sections-') as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.add_init_script("""(()=>{const set=window.setInterval;window.setInterval=(fn,ms,...args)=>
              ms===5000?0:set(fn,ms,...args);})();""")
            unlock(page, server)
            print("Access: unlocked", flush=True)
            if console_only:
                check_console(page, server, output, errors)
                browser.close()
                return
            base = page.evaluate("()=>json('profiles',undefined,{root:true})")
            profiles = copy.deepcopy(base['profiles'])
            for index in range(1, 14):
                item = copy.deepcopy(profiles[0])
                item.update(id=f'{index:032x}', label=f'Case workspace {index:02d}')
                profiles.append(item)
            page.route('**/api/profiles', lambda route: route.fulfill(json={**base, 'profiles': profiles}))
            page.evaluate('()=>loadProfiles()')
            grant = page.evaluate("""()=>json('access/grants',{label:'Existing custom access',
              workspaces:{default:null},permissions:['view','export','interact']},{root:true})""")
            grant_id = grant['grants'][0]['id']
            hold_api_response(page, '/api/access')
            page.evaluate("()=>{void navigate('access');}")
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#access-label').fill('Draft during refresh')
            release_api_response(page)
            expect(page.locator('#access-label')).to_have_value('Draft during refresh')
            page.locator('#access-preset').select_option('operator')
            assert page.evaluate("()=>accessSettings().permissions") == ['view', 'export', 'sources', 'settings']
            page.locator('#access-permissions input[value=interact]').check()
            expect(page.locator('#access-preset')).to_have_value('custom')
            page.locator('#access-workspace-search').fill('workspace 12')
            expect(page.locator('#access-workspaces .access-workspace:visible')).to_have_count(1)
            page.locator('#access-workspace-search').fill('')
            page.locator('#access-workspace-picked').check()
            expect(page.locator('#access-workspaces .access-workspace:visible')).to_have_count(1)
            assert page.evaluate("()=>Object.keys(accessSettings().workspaces)") == ['default']
            page.locator('#access-workspace-picked').uncheck()
            page.locator('#access-expiry-preset').select_option('7')
            assert page.evaluate('()=>Math.abs(accessSettings().expires_at-Date.now()/1000-7*86400)<120')
            page.evaluate('()=>loadAccess()')
            expect(page.locator('#access-expiry-preset')).to_have_value('7')
            expect(page.locator('#access-label')).to_have_value('Draft during refresh')

            print('Access: presets and searchable scope passed', flush=True)
            page.locator('#access-list .access-row').get_by_role('button', name='Edit', exact=True).click()
            expect(page.locator('#access-preset')).to_have_value('custom')
            assert page.evaluate('()=>accessSettings().permissions') == ['view', 'export', 'interact']
            page.locator('#access-label').fill('Saved first draft')
            hold_api_response(page, '/api/access/grants/' + grant_id)
            page.locator('#access-submit').click()
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#access-label').fill('Newer unsaved label')
            release_api_response(page)
            expect(page.locator('#access-submit')).to_be_enabled()
            expect(page.locator('#access-label')).to_have_value('Newer unsaved label')
            assert page.evaluate("()=>json('access',undefined,{root:true}).then(r=>r.grants[0].label)") == 'Saved first draft'

            print('Access: late grant save preserved newer draft', flush=True)
            page.locator('#access-tab-grants').focus()
            page.keyboard.press('ArrowRight')
            expect(page.locator('#access-panel-sessions')).to_be_visible()
            expect(page.locator('#access-sessions-list .access-row')).to_have_count(1)
            page.keyboard.press('ArrowRight')
            expect(page.locator('#access-panel-limits')).to_be_visible()
            page.locator('#admin-idle').fill('42')
            hold_api_response(page, '/api/access/admin')
            page.locator('#access-admin-form button').click()
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#admin-idle').fill('43')
            release_api_response(page)
            expect(page.locator('#access-admin-form button')).to_be_enabled()
            page.evaluate('()=>loadAccess()')
            expect(page.locator('#admin-idle')).to_have_value('43')
            page.locator('#access-tab-grants').click()
            expect(page.locator('#access-label')).to_have_value('Newer unsaved label')
            for theme in ('light', 'dark'):
                page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                for width in (1440, 390):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    page.evaluate('()=>scrollTo(0,0)')
                    page.screenshot(path=str(output / f'access-{theme}-{width}.png'), full_page=True)
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'), (theme, width)
            page.set_viewport_size({'width': 1440, 'height': 1000})
            print('Access: tabs, limit draft and layouts passed', flush=True)
            check_console(page, server, output, errors)
            browser.close()
    print('Access: explicit rights, expiry, workspace search, preserved drafts, tabs and scoped System log passed.')


if __name__ == '__main__':
    main(console_only="--console-only" in sys.argv)
