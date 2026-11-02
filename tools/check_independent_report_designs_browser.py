from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import zipfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.verify import fingerprint, verify_bundle
from tools.check_browser import (
    RunningApp, answer_panel_dialog, check_layout, hold_api_response,
    launch_browser, release_api_response, unlock,
)
from tools.check_report_builder_browser import save


DESIGNS = ('reading_series', 'ledger_margin')
LAYOUTS = {
    'reading_series': '.reading-series-shell > .reading-series-rail',
    'ledger_margin': '.ledger-margin-folio .ledger-margin-chapter > .ledger-margin-rail',
}
LEGACY = ('classic', 'quire', 'meridian', 'atlas', 'ledger', 'horizon')
CHAT = -100333


def seed(store):
    store.set_setting('demo', False)
    store.set_target(CHAT, 'Fictional workshop', 'supergroup', True)
    store.set_target(CHAT - 1, 'Outside report scope', 'supergroup', True)
    start = datetime(2026, 10, 12, 9, tzinfo=timezone.utc)
    events = [('observation.started', {'parameters': {'heartbeat_seconds': 60}}, None, None)]
    for index in range(1, 7):
        events.append(('message.new', {
            'text': f'Fictional workshop note {index}', 'sender_id': 101 + index % 2,
            'sent_at': (start + timedelta(minutes=index)).isoformat(),
        }, CHAT, index))
    events.extend([
        ('message.edited', {'text': 'Fictional workshop starts at 15:00 UTC', 'sender_id': 102,
                            'sent_at': (start + timedelta(minutes=1)).isoformat(), 'edited_at': (start + timedelta(minutes=7)).isoformat()}, CHAT, 1),
        ('message.edited', {'text': 'Fictional workshop uses the north entrance', 'sender_id': 102,
                            'sent_at': (start + timedelta(minutes=1)).isoformat(), 'edited_at': (start + timedelta(minutes=8)).isoformat()}, CHAT, 1),
        ('message.deleted', {'deleted_by': None}, CHAT, 2),
        ('message.new', {'text': 'Outside scope: do not show in this report', 'sender_id': 103}, CHAT - 1, 1),
        ('observation.stopped', {'reason': 'synthetic test complete'}, None, None),
    ])
    for index, (kind, payload, chat, message) in enumerate(events):
        observed = (start + timedelta(minutes=index)).isoformat()
        with patch('tgwitness.store.utcnow', return_value=observed):
            store.append(kind, {'synthetic': True, **payload}, chat, message, payload.get('sender_id'))


def open_settings(page):
    page.evaluate("navigate('evidence')")
    page.locator('#exports-tab-settings').click()
    expect(page.locator('#report-fields')).to_be_enabled()


def contents(page):
    return page.evaluate('()=>{const draft=reportDraft();delete draft.design;return draft;}')


def preview(page, design, title):
    expect(page.locator('#report-preview-frame')).to_have_attribute('data-report-design', design, timeout=30000)
    frame = page.frame_locator('#report-preview-frame')
    expect(frame.locator('html')).to_have_attribute('data-report-design', design)
    expect(frame.locator('h1')).to_contain_text(title)
    expect(frame.locator(LAYOUTS[design]).first).to_be_visible()
    expect(page.locator('#report-design-preview-status')).to_contain_text('not signed')
    return frame


def main():
    output = Path('test-results/independent-report-designs')
    output.mkdir(parents=True, exist_ok=True)
    receipts = []
    with tempfile.TemporaryDirectory(prefix='independent-report-designs-') as scratch, RunningApp(Path(scratch)) as app:
        seed(app.app.state.store)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            page.add_init_script('window.showSaveFilePicker=undefined')
            errors, writes = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: writes.append(request.url)
                    if request.method == 'POST' and '/api/report-options' in request.url else None)
            unlock(page, app)
            open_settings(page)
            for design in (*LEGACY, *DESIGNS):
                expect(page.locator('#report-design-' + design)).to_have_count(1)
            expect(page.locator('#report-design-classic')).to_be_checked()
            title = 'Fictional workshop review'
            page.locator('#report-case-title').fill(title)
            page.locator('#report-notes').fill('Only the selected workshop is included in this report.')
            page.locator('#report-language').select_option('en')
            page.locator('#report-selection-chosen').check()
            page.locator('#report-selection-chats').evaluate("e=>e.closest('details').open=true")
            page.locator('#report-selection-chats').fill(str(CHAT))
            page.locator('#report-selection-from').fill('2026-10-12')
            page.locator('#report-selection-to').fill('2026-10-12')
            page.locator('.report-examination summary').click()
            page.locator('#report-review-question').fill('How did the recorded workshop details change?')
            original = contents(page)

            for design in DESIGNS:
                previous_writes = len(writes)
                page.locator('#report-design-' + design).check()
                assert contents(page) == original, 'A design changed selected data, content or notes'
                frame = preview(page, design, title)
                assert len(writes) == previous_writes, 'Preview must not save the draft'
                assert page.evaluate("json('report-options')")['design'] != design
                page.locator('#report-preview-frame').screenshot(path=str(output / (design + '-preview.png')))
                saved = save(page)
                assert saved['design'] == design and saved['selection']['chats'] == [CHAT]
                page.reload()
                open_settings(page)
                expect(page.locator('#report-design-' + design)).to_be_checked()
                assert contents(page) == original
                preview(page, design, title)

                page.locator('#report-open-downloads').click()
                expect(page.locator('#exports-tab-downloads')).to_have_attribute('aria-selected', 'true')
                with page.expect_download(timeout=60000) as transfer:
                    page.locator('#export-journal-panel [data-export=zip]').click()
                    answer_panel_dialog(page)
                destination = output / (design + '.zip')
                transfer.value.save_as(destination)
                verified = verify_bundle(destination, fingerprint(app.app.state.vault.public_key))
                assert verified['key_pinned'] and verified['report_pdf']
                with zipfile.ZipFile(destination) as archive:
                    html = archive.read('report.html').decode('utf-8')
                    material = json.loads(archive.read('report.json'))['report']
                    assert material['presentation']['design'] == design
                    assert f'data-report-design="{design}"' in html
                    assert ('reading-series-shell' if design == 'reading_series' else 'ledger-margin-folio') in html
                    assert title in html and 'Fictional workshop' in html
                    assert 'Outside scope: do not show in this report' not in html
                    assert archive.read('report.pdf').startswith(b'%PDF-')
                    (output / (design + '.html')).write_text(html, encoding='utf-8')
                receipts.append({'design': design, 'saved': True, 'reload': True, 'signed_export_verified': True})
                open_settings(page)

            page.locator('#report-template-brief').check()
            expect(page.locator('#report-design-ledger_margin')).to_be_checked()
            assert page.evaluate('reportDraft().selection') == original['selection']
            page.locator('#report-template-dossier').check()
            expect(page.locator('#report-design-ledger_margin')).to_be_checked()

            second = page.evaluate("""async()=>{
                const other=await json('profiles',{label:'Separate reading case'},{root:true});
                await json('report-options',{design:'reading_series',case_title:'Second workspace'}, {profile:other.id});
                await loadProfiles();return other.id;
            }""")
            hold_api_response(page, '/api/report-design-preview')
            page.locator('#report-case-title').fill('PRIVATE OLD WORKSPACE DRAFT')
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.evaluate('id=>switchProfile(id)', second)
            open_settings(page)
            expect(page.locator('#report-design-reading_series')).to_be_checked()
            expect(page.locator('#report-case-title')).to_have_value('Second workspace')
            release_api_response(page)
            frame = preview(page, 'reading_series', 'Second workspace')
            expect(frame.locator('body')).not_to_contain_text('PRIVATE OLD WORKSPACE DRAFT')
            page.evaluate("switchProfile('default')")
            open_settings(page)
            expect(page.locator('#report-design-ledger_margin')).to_be_checked()
            expect(page.locator('#report-case-title')).to_have_value(title)

            for width in (320, 390, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                for theme, direction in (('light', 'ltr'), ('dark', 'rtl')):
                    page.evaluate("v=>{document.documentElement.dataset.theme=v.theme;document.documentElement.dir=v.direction;}",
                                  {'theme': theme, 'direction': direction})
                    page.locator('.report-designs').scroll_into_view_if_needed()
                    check_layout(page)
                    page.locator('.report-designs').screenshot(path=str(output / f'picker-{width}-{theme}-{direction}.png'))
            assert not errors, errors
            browser.close()
    (output / 'verification.json').write_text(json.dumps(receipts, indent=2) + '\n', encoding='utf-8')
    print('Independent report layouts: real preview, unchanged data and notes, saved options, reload, signed HTML/PDF exports, stale-preview/workspace isolation and responsive picker passed.')


if __name__ == '__main__':
    main()
