"""Workspace overview and bulk actions with fictional collector states only."""
import copy
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, hold_api_response, launch_browser, release_api_response, unlock


def main():
    output = Path('build/ux-review/after/29')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='accounts-overview-') as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, calls = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.add_init_script("""(()=>{const set=window.setInterval;window.setInterval=(fn,ms,...args)=>
              ms===5000?0:set(fn,ms,...args);})();""")
            unlock(page, server)
            base = page.evaluate("()=>json('profiles',undefined,{root:true})")
            profiles = []
            for index in range(12):
                item = copy.deepcopy(base['profiles'][0])
                item.update(id='default' if index == 0 else f'{index:032x}', label=f'Research {index:02d}',
                            sources_enabled=3, sources_total=4, group=None)
                item['stats']['total'] = 1000 + index
                item['collector'].update(has_session=index != 0, running=index in (1, 2), connected=index in (1, 2),
                                         media_pending=index, account={'id': 1000 + index, 'username': f'observer_{index}'})
                item['health']['state'] = 'working'
                for key in ('connection', 'intake', 'sources', 'media'):
                    item['health'][key]['state'] = 'working'
                profiles.append(item)
            profiles[2]['health']['sources'].update(state='degraded', reason='some_unconfirmed')
            profiles[2]['health']['state'] = 'degraded'
            profiles[11]['error_type'] = 'SyntheticUnavailable'

            page.route('**/api/profiles', lambda route: route.fulfill(json={**base, 'profiles': profiles}))

            def change(route):
                calls.append(route.request.url)
                pid = route.request.url.split('/profiles/')[1].split('/')[0]
                record = next(item for item in profiles if item['id'] == pid)
                record['collector']['running'] = route.request.url.endswith('/start')
                record['collector']['connected'] = record['collector']['running']
                route.fulfill(json={'ok': True})

            page.route('**/profiles/*/api/collector/*', change)
            page.evaluate("()=>navigate('accounts')")
            expect(page.locator('[data-count=workspaces] strong')).to_have_text('12')
            expect(page.locator('.account-card:visible')).to_have_count(10)
            expect(page.locator('#accounts-page')).to_have_text('1–10 of 12')
            page.locator('#accounts-next').click()
            expect(page.locator('.account-card:visible')).to_have_count(2)
            page.locator('#accounts-filter').select_option('attention')
            expect(page.locator('.account-card:visible')).to_have_count(2)
            page.locator('#accounts-filter').select_option('all')
            page.locator('#accounts-search').fill('observer_1')
            expect(page.locator('.account-card:visible')).to_have_count(3)
            page.locator('#accounts-search').fill('')
            page.locator('#accounts-sort').select_option('name')
            first = page.locator('.account-card[data-profile=default]')
            expect(first.locator('[data-action=connect]')).to_be_visible()
            assert page.evaluate("""async()=>{const card=document.querySelector('.account-card[data-profile=default]'),
              field=card.querySelector('.fleet-card-group');field.focus();await loadProfiles();
              return field.isConnected&&document.activeElement===field;}"""), 'Poll replaced focused group selector'
            page.locator('#accounts-filter').select_option('collecting')
            page.locator('#accounts-select-page').check()
            page.once('dialog', lambda dialog: dialog.dismiss())
            page.locator('#accounts-pause').click()
            assert not calls, 'Cancelled confirmation dispatched an action'
            page.once('dialog', lambda dialog: dialog.accept())
            page.locator('#accounts-pause').click()
            expect(page.locator('#accounts-result')).to_contain_text('2 workspaces updated.')
            assert len(calls) == 2 and all(url.endswith('/stop') for url in calls)
            page.locator('#accounts-filter').select_option('offline')
            page.locator('#accounts-search').fill('Research 01')
            page.locator('#accounts-select-page').check()
            page.once('dialog', lambda dialog: dialog.accept())
            page.locator('#accounts-resume').click()
            expect(page.locator('#accounts-result')).to_contain_text('1 workspaces updated.')
            assert calls[-1].endswith('/start')
            page.locator('#accounts-search').fill('')
            page.locator('#accounts-filter').select_option('all')
            expect(page.locator('#accounts-clear')).to_be_disabled()
            for theme in ('light', 'dark'):
                page.evaluate("theme=>{document.documentElement.dataset.theme=theme;}", theme)
                for width in (1440, 390):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    page.evaluate('()=>scrollTo(0,0)')
                    page.screenshot(path=str(output / f'accounts-{theme}-{width}.png'), full_page=True)
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'), (theme, width)
            page.set_viewport_size({'width': 1440, 'height': 1000})
            profiles[1]['collector'].update(running=True, connected=True)
            profiles[2]['collector'].update(running=True, connected=True)
            page.evaluate('()=>loadProfiles()')
            page.locator('#accounts-filter').select_option('collecting')
            page.locator('#accounts-select-page').check()
            hold_api_response(page, '/api/collector/stop')
            before = len(calls)
            page.once('dialog', lambda dialog: dialog.accept())
            page.locator('#accounts-pause').click()
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#top-lock').click()
            release_api_response(page)
            assert len(calls) == before + 1, 'Lock did not stop the remaining bulk dispatches'
            page.locator('#panel-token').fill(server.app.state.vault.token)
            page.locator('#unlock-form button').click()
            page.evaluate("()=>navigate('accounts')")
            expect(page.locator('#accounts-selected')).to_have_text('0 selected')
            profiles[0]['health']['sources']['state'] = 'degraded'
            page.evaluate('()=>loadProfiles()')
            page.locator('.account-card[data-profile=default] .account-problems [data-part=sources]').click()
            expect(page.locator('#view-sources')).to_be_visible()
            assert not errors, errors
            browser.close()
    print('Accounts overview: filters, paging, preserved controls, scoped bulk actions, lock and layouts passed.')


if __name__ == '__main__':
    main()
