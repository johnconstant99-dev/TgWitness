"""Actual report selection, preview, draft lifecycle and workspace isolation."""
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import (RunningApp, check_layout, hold_api_response,
                                 launch_browser, release_api_response, unlock)


def seed(store):
    rows = [
        ('2026-10-01', 'target.changed', -1001, None, {'title': 'Fictional Redwood'}),
        ('2026-10-01', 'target.changed', -1002, None, {'title': 'Fictional Harbor'}),
        ('2026-10-01', 'message.snapshot', -1001, 1, {'sender_id': 101, 'text': 'password: correcthorse123'}),
        ('2026-10-02', 'message.new', -1001, 4, {'sender_id': 202, 'text': 'Excluded author <script>boom()</script> password: originalsecret123'}),
        ('2026-10-02', 'message.edited', -1001, 4, {'sender_id': 202, 'text': 'A saved change password: editedsecret123'}),
        ('2026-10-03', 'message.deleted', -1001, 4, {}),
        ('2026-10-02', 'message.snapshot', -1002, 20, {'sender_id': 101, 'text': 'Other chat sample'}),
        ('2026-10-02', 'message.recovered', -1001, 6, {'sender_id': 101, 'text': 'Recovered context'}),
        ('2026-10-03', 'message.deleted', -1002, 21, {}),
        ('2026-11-02', 'message.missing_on_recheck', -1001, 6, {}),
    ]
    for day, kind, chat, message, payload in rows:
        with patch('tgwitness.store.utcnow', return_value=day + 'T12:30:00+00:00'):
            store.append(kind, payload, chat, message)


def preview(page, button='#report-preview-run'):
    with page.expect_response(lambda response: response.request.method == 'POST'
                              and response.url.endswith('/api/report-preview')) as response:
        page.locator(button).click()
    assert response.value.status == 200, response.value.text()
    expect(page.locator('#report-preview-status')).to_contain_text('Preview ready.')
    expect(page.locator('#report-preview-run')).to_be_enabled()
    return response.value.json()


def save(page):
    with page.expect_response(lambda response: response.request.method == 'POST'
                              and response.url.endswith('/api/report-options')) as response:
        page.locator('#report-form button[type=submit]').click()
    assert response.value.status == 200, response.value.text()
    expect(page.locator('#report-status')).to_contain_text('Saved.')
    return response.value.json()


def main():
    output = Path('test-results/report-selection')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='report-selection-browser-') as scratch, RunningApp(Path(scratch)) as app:
        seed(app.app.state.store)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, scans, writes = [], [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: scans.append(request.url)
                    if request.url.endswith('/api/report-preview') else None)
            page.on('request', lambda request: writes.append(request.url)
                    if request.method == 'POST' and request.url.endswith('/api/report-options') else None)
            unlock(page, app)
            page.evaluate("navigate('evidence')")
            expect(page.locator('#export-readable-report [data-export=pdf]')).to_be_visible()
            expect(page.locator('#export-readable-report [data-export=json]')).to_be_visible()
            page.locator('[data-go-reports=data]').click()
            expect(page.locator('#report-fields')).to_be_enabled()
            expect(page.locator('#report-data-title')).to_be_focused()
            assert not scans, 'Opening the form must not scan the journal automatically'
            expect(page.locator('#report-selection-from')).to_be_disabled()
            page.locator('#report-selection-chosen').check()
            initial = preview(page, '#report-load-catalog')
            assert initial['unsigned'] is True
            assert len(initial['catalog']['chats']) == 2
            expect(page.locator('#report-chat-catalog [data-report-choice]')).to_have_count(2)
            expect(page.locator('#report-sender-catalog [data-report-choice]')).to_have_count(2)
            assert not writes, 'Preview must not save the draft'

            page.locator('#report-chat-catalog [data-id="-1001"]').check()
            page.locator('#report-sender-catalog [data-id="101"]').check()
            page.locator('#report-selection-from').fill('2026-10-01')
            page.locator('#report-selection-to').fill('2026-10-02')
            expect(page.locator('#report-preview-stale')).to_be_visible()
            assert len(scans) == 1, 'Changing filters must not trigger repeated full scans'
            selected = preview(page)
            assert selected['counts']['selected_records'] == 2
            assert selected['counts']['message_observations'] == 2
            assert selected['counts']['participants'] == 1
            assert selected['counts']['chats'] == 1
            assert [row['message_id'] for row in selected['messages']['rows']] == [1, 6]
            assert selected['id_gaps']['ids_total'] == 3
            assert selected['id_gaps']['rows'][0]['after']['sender_id'] == 202
            expect(page.locator('.report-message-table tbody tr')).to_have_count(2)
            expect(page.locator('.report-message-table')).not_to_contain_text('correcthorse123')
            expect(page.locator('.report-message-table')).to_contain_text('•••••')
            expect(page.locator('.report-message-table')).not_to_contain_text('Excluded author')
            expect(page.locator('.report-gap-table')).to_contain_text('Excluded author <script>boom()</script>')
            assert page.locator('#report-preview-result script').count() == 0
            expect(page.locator('.report-heat-table tbody tr')).to_have_count(7)
            assert not writes

            page.locator('#report-selection-to').fill('2026-09-30')
            before = len(scans)
            page.locator('#report-preview-run').click()
            assert not page.locator('#report-selection-to').evaluate('(el)=>el.checkValidity()')
            assert len(scans) == before
            page.locator('#report-selection-to').fill('2026-10-02')
            page.locator('#report-selection-from').fill('2026-10-02')
            assert preview(page)['counts']['selected_records'] == 1, 'Both dates include the same UTC day'

            # Catalog search is transient; it must not mark a fresh preview stale.
            page.locator('[data-report-search=chats]').fill('Harbor')
            expect(page.locator('#report-chat-catalog [data-report-choice]')).to_have_count(1)
            expect(page.locator('#report-preview-stale')).to_be_hidden()
            page.locator('[data-report-search=chats]').fill('')
            page.locator('#report-selection-senders').evaluate("el=>{el.closest('details').open=true;}")
            page.locator('#report-selection-senders').fill('999999')
            empty = preview(page)
            assert empty['counts']['selected_records'] == 0
            expect(page.locator('.report-preview-empty')).to_be_visible()
            expect(page.locator('#report-sender-catalog [data-id="999999"]')).to_be_checked()
            expect(page.locator('#report-sender-count')).to_have_text('1 selected')

            # Edit-only and deletion-only queries retain the actual earlier source text.
            page.locator('#report-selection-senders').fill('')
            page.locator('#report-selection-from').fill('2026-10-01')
            page.locator('#report-selection-to').fill('2026-10-03')
            for choice in page.locator('[data-report-kind]').all():
                choice.uncheck()
            page.locator('#report-kind-edited').check()
            edits = preview(page)
            assert edits['counts']['selected_records'] == 1
            assert len(edits['changes']['messages']) == 1
            expect(page.locator('.report-change-pair')).to_have_count(1)
            expect(page.locator('.report-change-pair')).to_contain_text('Before')
            expect(page.locator('.report-change-pair')).to_contain_text('After')
            expect(page.locator('.report-preview-changes')).to_contain_text('Context outside the selected filters')
            expect(page.locator('.report-preview-changes')).not_to_contain_text('originalsecret123')
            expect(page.locator('.report-preview-changes')).not_to_contain_text('editedsecret123')
            page.locator('#report-kind-edited').uncheck()
            page.locator('#report-kind-deleted').check()
            page.locator('#report-selection-from').fill('2026-10-03')
            deleted = preview(page)
            assert deleted['counts']['selected_records'] == 1
            assert deleted['changes']['messages'][0]['gone'][0]['previous_version_seq'] is not None
            expect(page.locator('.report-change-gone')).to_contain_text('A saved change')
            expect(page.locator('.report-change-gone')).not_to_contain_text('editedsecret123')
            expect(page.locator('.report-change-gone')).to_contain_text('•••••')
            page.locator('#report-selection-chats').evaluate("el=>{el.closest('details').open=true;}")
            page.locator('#report-selection-chats').fill('-1002')
            preview(page)
            expect(page.locator('.report-change-gone')).to_contain_text('No message content was saved before this observation.')

            page.locator('#report-template-brief').check()
            page.locator('#report-selection-gaps').uncheck()
            brief = preview(page)
            assert not any(key in brief['analytics'] for key in ('participants', 'hourly', 'chats'))
            assert brief['id_gaps']['enabled'] is False
            expect(page.locator('.report-heat-table')).to_have_count(0)
            expect(page.locator('.report-gap-table')).to_have_count(0)
            page.locator('#report-template-dossier').check()
            page.locator('#report-selection-gaps').check()
            page.locator('#report-selection-chats').fill('-1001')
            page.locator('#report-selection-senders').fill('101')
            page.locator('#report-selection-from').fill('2026-10-01')
            page.locator('#report-selection-to').fill('2026-10-02')
            page.locator('#report-kind-new').uncheck()
            page.locator('#report-kind-edited').uncheck()
            page.locator('#report-kind-deleted').uncheck()
            page.locator('#report-kind-missing').uncheck()
            page.locator('#report-kind-snapshot').check()
            page.locator('#report-kind-recovered').check()
            assert preview(page)['counts']['selected_records'] == 2
            page.locator('#report-open-downloads').click()
            expect(page.locator('#report-form')).to_be_visible()
            expect(page.locator('#report-status')).to_contain_text('Save your changes')
            saved = save(page)
            assert saved['selection']['chats'] == [-1001]
            assert saved['selection']['kinds'] == ['message.snapshot', 'message.recovered']
            page.reload()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-selection-chosen')).to_be_checked()
            expect(page.locator('#report-selection-chats')).to_have_value('-1001')
            expect(page.locator('#report-selection-from')).to_have_value('2026-10-01')
            expect(page.locator('#report-kind-new')).not_to_be_checked()
            expect(page.locator('#report-preview-result')).to_be_empty()
            preview(page)

            # A failed preview retains the prior result, shows an error and retries explicitly.
            page.route('**/api/report-preview', lambda route: route.fulfill(status=503, json={'detail': 'Synthetic preview outage'}))
            page.locator('#report-preview-run').click()
            expect(page.locator('#report-preview-status')).to_contain_text('Could not build the preview.')
            expect(page.locator('#report-preview-retry')).to_be_visible()
            page.unroute('**/api/report-preview')
            preview(page, '#report-preview-retry')

            # A late response cannot replace choices edited while a scan was in flight.
            hold_api_response(page, '/api/report-preview')
            page.locator('#report-preview-run').click()
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#report-selection-to').fill('2026-10-03')
            release_api_response(page)
            expect(page.locator('#report-preview-status')).to_contain_text('Choices changed while')
            expect(page.locator('#report-preview-stale')).to_be_visible()
            page.locator('#report-selection-to').fill('2026-10-02')
            preview(page)
            save(page)

            second = page.evaluate("""async()=>{
                const second=await json('profiles',{label:'Other synthetic preview'}, {root:true});
                await loadProfiles();return second.id;
            }""")
            hold_api_response(page, '/api/report-preview')
            page.locator('#report-preview-run').click()
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.evaluate('id=>switchProfile(id)', second)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-fields')).to_be_enabled()
            expect(page.locator('#report-selection-all')).to_be_checked()
            release_api_response(page)
            expect(page.locator('#report-preview-result')).to_be_empty()
            expect(page.locator('#report-selection-chats')).to_have_value('')
            expect(page.locator('#report-chat-catalog')).not_to_contain_text('Redwood')
            page.evaluate("switchProfile('default')")
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-selection-chats')).to_have_value('-1001')
            preview(page)

            page.locator('#report-selection-senders').evaluate("el=>{el.closest('details').open=true;}")
            page.locator('#report-selection-senders').fill('')
            page.locator('#report-selection-to').fill('2026-10-03')
            for choice in page.locator('[data-report-kind]').all():
                choice.check()
            preview(page)

            for width in (320, 390, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme in ('light', 'dark'):
                    page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                    page.locator('#report-data').scroll_into_view_if_needed()
                    check_layout(page)
                    page.screenshot(path=str(output / f'{width}-{theme}-data.png'))
                    page.locator('#report-preview-title').scroll_into_view_if_needed()
                    page.screenshot(path=str(output / f'{width}-{theme}-preview.png'))
                    page.locator('.report-preview-changes').scroll_into_view_if_needed()
                    page.screenshot(path=str(output / f'{width}-{theme}-changes.png'))
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>!$('report-preview-result').textContent&&!$('report-selection-chats').value")
            assert not errors, errors
            browser.close()
    print('Report selection passed: real filters, inclusive dates, gap context, masked samples, empty data, no automatic writes/scans, retry, stale responses, persistence, workspace isolation, lock and six layouts.')


if __name__ == '__main__':
    main()
