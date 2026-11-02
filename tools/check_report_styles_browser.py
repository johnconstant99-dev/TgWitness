from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.access import GrantSettings
from tools.check_browser import RunningApp, check_layout, launch_browser, release_api_response, unlock
from tools.check_report_builder_browser import save
from tools.check_settings_browser import hold_report_response


DESIGNS = ('classic', 'quire', 'meridian', 'atlas', 'ledger', 'horizon')


def data_choices(page):
    return page.evaluate("()=>{const value=reportDraft();delete value.design;return value;}")


def main():
    output = Path('test-results/report-styles')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='report-styles-') as scratch, RunningApp(Path(scratch)) as app:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, writes = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: writes.append(request.url)
                    if request.method == 'POST' and request.url.endswith('/api/report-options') else None)
            unlock(page, app)
            page.locator('.sidebar [data-view=evidence]').click()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-classic')).to_be_checked()
            expect(page.locator('#report-design-classic')).to_be_enabled()
            expect(page.locator('.report-design')).to_have_count(8)
            expect(page.locator('.report-designs')).to_contain_text('HTML and PDF')
            page.locator('#report-case-title').fill('Fictional case design review')
            page.locator('#report-notes').fill('Keep the original questions and record references.')
            page.locator('#report-selection-chosen').check()
            for key, value in (('chats', '-1001'), ('senders', '101')):
                field = page.locator('#report-selection-' + key)
                field.evaluate("el=>{el.closest('details').open=true;}")
                field.fill(value)
            page.locator('#report-selection-from').fill('2026-10-01')
            page.locator('#report-selection-to').fill('2026-10-03')
            page.locator('#report-kind-missing').uncheck()
            original = data_choices(page)
            for design in DESIGNS:
                previous = len(writes)
                page.locator('#report-design-' + design).check()
                assert data_choices(page) == original, f'{design} changed contents or scope'
                assert len(writes) == previous, 'Choosing an appearance must not save automatically'
                saved = save(page)
                assert saved['design'] == design
                assert saved['selection']['chats'] == [-1001]
            page.reload()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-horizon')).to_be_checked()
            expect(page.locator('#report-case-title')).to_have_value('Fictional case design review')

            page.locator('#report-template-brief').check()
            expect(page.locator('#report-design-horizon')).to_be_checked()
            assert page.evaluate('reportDraft().selection') == original['selection']
            brief = data_choices(page)
            page.get_by_role('radio', name='Editorial', exact=True).check()
            assert data_choices(page) == brief
            expect(page.locator('#report-template-brief')).to_be_checked()
            page.locator('#report-activity-chart').uncheck()
            expect(page.locator('#report-design-quire')).to_be_checked()
            expect(page.locator('#report-template-custom')).to_be_checked()
            save(page)

            page.locator('#report-design-classic').check()
            page.locator('#report-design-classic').focus()
            page.keyboard.press('ArrowRight')
            expect(page.locator('#report-design-quire')).to_be_focused()
            expect(page.locator('#report-design-quire')).to_be_checked()
            page.keyboard.press('ArrowRight')
            expect(page.locator('#report-design-meridian')).to_be_checked()
            page.locator('#report-open-downloads').click()
            expect(page.locator('#report-status')).to_contain_text('Save your changes')
            expect(page.locator('#report-form')).to_be_visible()
            page.locator('.sidebar [data-view=chats]').click()
            page.locator('.sidebar [data-view=evidence]').click()
            expect(page.locator('#report-design-meridian')).to_be_checked()
            page.locator('#report-form .form-draft-bar .quiet').click()
            expect(page.locator('#report-design-quire')).to_be_checked()
            expect(page.locator('#report-form')).to_have_attribute('data-dirty', 'false')

            second = page.evaluate("""async()=>{
                const other=await json('profiles',{label:'Other layout case'}, {root:true});
                await json('report-options',{design:'ledger',case_title:'Second case'}, {profile:other.id});
                await loadProfiles();return other.id;
            }""")
            hold_report_response(page)
            page.evaluate('()=>{window.pendingDesignLoad=loadReportSettings();}')
            expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
            page.evaluate('id=>switchProfile(id)', second)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-ledger')).to_be_checked()
            release_api_response(page)
            page.evaluate('window.pendingDesignLoad')
            expect(page.locator('#report-design-ledger')).to_be_checked()
            expect(page.locator('#report-case-title')).to_have_value('Second case')
            page.evaluate("switchProfile('default')")
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-quire')).to_be_checked()

            page.locator('#report-design-meridian').check()
            hold_report_response(page)
            page.locator('#report-form button[type=submit]').click()
            expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
            page.evaluate('id=>switchProfile(id)', second)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-ledger')).to_be_checked()
            release_api_response(page)
            page.wait_for_function("!document.querySelector('#report-form button[type=submit]').hasAttribute('aria-busy')")
            expect(page.locator('#report-design-ledger')).to_be_checked()
            page.evaluate("switchProfile('default')")
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-meridian')).to_be_checked()

            def legacy_options(route):
                response = route.fetch()
                value = response.json()
                value.pop('design', None)
                route.fulfill(response=response, json=value)

            page.route('**/api/report-options', legacy_options)
            page.reload()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-design-classic')).to_be_checked()
            page.unroute('**/api/report-options', legacy_options)

            for width in (320, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme in ('light', 'dark'):
                    for direction in ('ltr', 'rtl'):
                        page.evaluate("({theme,direction})=>{document.documentElement.dataset.theme=theme;document.documentElement.dir=direction;}",
                                      {'theme': theme, 'direction': direction})
                        page.locator('.report-designs').scroll_into_view_if_needed()
                        check_layout(page)
                        page.locator('.report-designs').screenshot(path=str(output / f'{width}-{theme}-{direction}.png'))

            page.evaluate('lock()')
            assert page.evaluate("()=>$('report-design-classic').checked&&$('report-design-classic').matches(':disabled')")

            token, _ = app.app.state.access.issue(GrantSettings(label='Read-only layout review',
                                                               permissions=['view'], workspaces={'default': None}))
            context = browser.new_context(viewport={'width': 1440, 'height': 1000})
            restricted = context.new_page()
            restricted.goto(app.url)
            restricted.locator('#panel-token').fill(token)
            restricted.get_by_role('button', name='Open workspace').click()
            expect(restricted.locator('#workspace')).to_be_visible()
            expect(restricted.locator('.sidebar [data-view=evidence]')).to_be_hidden()
            restricted.evaluate("navigate('evidence')")
            expect(restricted.locator('#report-form')).not_to_be_visible()
            context.close()
            assert not errors, errors
            browser.close()
    print('Report styles passed: all six persisted, design/content/scope independence, keyboard, draft and discard, legacy default, late loads/saves, workspace isolation, restricted access, lock and eight light/dark/RTL layouts.')


if __name__ == '__main__':
    main()
