from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, check_layout, launch_browser, unlock


def save(page):
    with page.expect_response(lambda response: response.request.method == 'POST'
                              and response.url.endswith('/api/report-options')) as response:
        page.locator('#report-form button[type=submit]').click()
    assert response.value.status == 200, response.value.status
    expect(page.locator('#report-status')).to_contain_text('Saved.')
    return response.value.json()


def main():
    output = Path('test-results/report-builder')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='report-builder-') as scratch, RunningApp(Path(scratch)) as app:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, writes = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: writes.append(request.url)
                    if '/api/report-options' in request.url and request.method == 'POST' else None)
            unlock(page, app)
            page.locator('.sidebar [data-view=evidence]').click()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-template-dossier')).to_be_enabled()
            expect(page.locator('#report-template-dossier')).to_be_checked()
            expect(page.locator('#report-participant-labels')).to_have_value('aliases')
            expect(page.locator('#report-outline')).to_contain_text('Participant activity')

            page.locator('#report-case-title').fill('Fictional review')
            page.locator('.report-examination summary').click()
            authored = {
                'question': 'Did the stated delivery date change?',
                'method': 'Compared saved versions in records #7 and #12.\nNo external sources reviewed.',
                'findings': 'Record #7 states 20 November. Record #12 states 27 November.',
                'conclusion': 'The recorded date differs. The identity of the editor remains unconfirmed.',
            }
            for key, value in authored.items():
                page.locator('#report-review-' + key).fill(value)
            baseline = len(writes)
            page.locator('#report-template-brief').check()
            expect(page.locator('#report-timeline')).not_to_be_checked()
            expect(page.locator('#report-participant-chart')).not_to_be_checked()
            expect(page.locator('#report-activity-chart')).to_be_checked()
            expect(page.locator('#report-outline')).not_to_contain_text('Participant activity')
            expect(page.locator('#report-outline')).to_contain_text('Examination notes')
            assert len(writes) == baseline, 'Template selection must not save automatically'
            for key, value in authored.items():
                expect(page.locator('#report-review-' + key)).to_have_value(value)
            expect(page.locator('#report-case-title')).to_have_value('Fictional review')
            brief = save(page)
            assert brief['template'] == 'brief' and brief['activity_chart']
            assert not any(brief[key] for key in ('participant_chart', 'hourly_chart', 'chat_chart', 'timeline', 'media_previews'))
            assert brief['review_findings'] == authored['findings']

            page.reload()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-template-brief')).to_be_checked()
            expect(page.locator('#report-review-findings')).to_have_value(authored['findings'])
            page.locator('#report-template-brief').focus()
            page.keyboard.press('ArrowRight')
            expect(page.locator('#report-template-activity')).to_be_checked()
            for key in ('activity', 'hourly', 'participant', 'chat'):
                expect(page.locator('#report-' + key + '-chart')).to_be_checked()
            expect(page.locator('#report-timeline')).not_to_be_checked()
            expect(page.locator('#report-participant-labels')).to_have_value('aliases')

            page.locator('#report-participant-labels').select_option('ids')
            expect(page.locator('#report-template-custom')).to_be_checked()
            page.locator('#report-hourly-chart').uncheck()
            page.locator('#report-chart-limit').fill('15')
            page.locator('#report-template-custom').check()
            expect(page.locator('#report-hourly-chart')).not_to_be_checked()
            assert save(page)['chart_limit'] == 15

            page.locator('#report-template-dossier').check()
            expect(page.locator('#report-participant-labels')).to_have_value('aliases')
            expect(page.locator('#report-chart-limit')).to_have_value('10')
            expect(page.locator('#report-review-findings')).to_have_value(authored['findings'])
            page.locator('#report-form .form-draft-bar .quiet').click()
            expect(page.locator('#report-template-custom')).to_be_checked()
            expect(page.locator('#report-participant-labels')).to_have_value('ids')
            expect(page.locator('#report-chart-limit')).to_have_value('15')
            expect(page.locator('#report-hourly-chart')).not_to_be_checked()
            expect(page.locator('#report-outline')).not_to_contain_text('Activity by weekday and hour')
            expect(page.locator('#report-form')).to_have_attribute('data-dirty', 'false')

            page.locator('#report-chart-limit').fill('31')
            baseline = len(writes)
            page.locator('#report-form button[type=submit]').click()
            assert not page.locator('#report-chart-limit').evaluate('(el)=>el.checkValidity()')
            page.evaluate("""()=>{$('report-form').dispatchEvent(new SubmitEvent('submit',{
                bubbles:true,cancelable:true,submitter:$('report-form').querySelector('button[type=submit]')}));}""")
            assert len(writes) == baseline
            page.locator('#report-chart-limit').fill('15')

            second = page.evaluate("""async()=>{
                const second=await json('profiles',{label:'Other synthetic case'},{root:true});
                await json('report-options',{case_title:'Other case',template:'dossier',timeline:false,review_findings:'Other workspace only'},
                    {profile:second.id});await loadProfiles();return second.id;
            }""")
            page.evaluate('id=>switchProfile(id)', second)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-case-title')).to_have_value('Other case')
            expect(page.locator('#report-template-custom')).to_be_checked()
            expect(page.locator('#report-timeline')).not_to_be_checked()
            expect(page.locator('#report-review-findings')).to_have_value('Other workspace only')
            expect(page.locator('.report-examination')).not_to_have_attribute('open', '')
            corrected = save(page)
            assert corrected['template'] == 'custom' and corrected['timeline'] is False
            page.evaluate("switchProfile('default')")
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-template-custom')).to_be_checked()
            expect(page.locator('#report-review-findings')).to_have_value(authored['findings'])
            expect(page.locator('#report-chart-limit')).to_have_value('15')

            for width in (320, 390, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme in ('light', 'dark'):
                    page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                    page.locator('#report-form').scroll_into_view_if_needed()
                    check_layout(page)
                    page.screenshot(path=str(output / f'{width}-{theme}.png'), full_page=True)
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>['question','method','findings','conclusion'].every(key=>!$('report-review-'+key).value)")
            assert page.evaluate("()=>!$('report-outline').textContent")
            assert not errors, errors
            browser.close()
    print('Report builder passed: presets, keyboard, authored notes, save/reload, custom choices, discard, validation, workspace separation, lock and eight layouts.')


if __name__ == '__main__':
    main()
