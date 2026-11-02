"""Synthetic downloads: progress, exact receipt, report drafts and compact layouts."""
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, hold_api_response, launch_browser, release_api_response, unlock


def main():
    output = Path('build/ux-review/after/32-exports')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='export-ui-') as scratch, RunningApp(Path(scratch)) as server:
        server.app.state.store.append('message.new', {'text': 'Synthetic export'}, -1001, 1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            page.add_init_script("window.showSaveFilePicker=undefined")
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("()=>navigate('evidence')")
            expect(page.locator('#exports-history-status')).to_contain_text('No exports')
            expect(page.locator('#export-task-journal')).to_have_attribute('aria-pressed', 'true')
            expect(page.locator('#export-journal-panel')).to_be_visible()
            expect(page.locator('#export-account-panel')).to_be_hidden()
            expect(page.locator('#report-form')).to_be_hidden()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-fields')).to_be_enabled()
            page.locator('#report-case-title').fill('Unsaved investigation')
            page.locator('#exports-tab-downloads').click()
            expect(page.locator('[data-export=jsonl]')).to_be_hidden()
            page.locator('#export-more-formats > summary').click()
            expect(page.locator('[data-export=jsonl]')).to_be_visible()
            page.evaluate("""()=>{window.showSaveFilePicker=async()=>{
              throw new DOMException('Synthetic picker cancellation','AbortError');};}""")
            page.locator('[data-export=jsonl]').click()
            expect(page.locator('#exports-progress-label')).to_have_text('Download cancelled.')
            expect(page.locator('#exports-progress-bar')).to_be_hidden()
            expect(page.locator('#exports-next')).to_be_hidden()
            page.evaluate('()=>{window.showSaveFilePicker=undefined;}')
            hold_api_response(page, '/api/export/jsonl')
            with page.expect_download() as transfer:
                page.locator('[data-export=jsonl]').click()
                page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
                expect(page.locator('#exports-progress-bar')).to_be_visible()
                assert page.locator('#exports-progress-bar').evaluate('bar=>!bar.hasAttribute("value")')
                release_api_response(page)
            path = Path(transfer.value.path())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            expect(page.locator('#exports-progress-label')).to_have_text('Export saved.')
            expect(page.locator('#exports-next-copy')).to_contain_text('compatible tool')
            expect(page.locator('#exports-next-encrypted')).to_be_hidden()
            expect(page.locator('.export-receipt')).to_have_count(1)
            page.locator('.export-receipt summary').click()
            expect(page.locator('.export-receipt code')).to_have_text(digest)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-case-title')).to_have_value('Unsaved investigation')
            page.evaluate("async()=>{await navigate('chats');await navigate('evidence');}")
            expect(page.locator('#report-case-title')).to_have_value('Unsaved investigation')
            page.locator('#exports-tab-downloads').click()
            with page.expect_download():
                page.locator('#export-journal-panel [data-export=zip]').click()
            expect(page.locator('#exports-next-copy')).to_contain_text('report.html')
            expect(page.locator('#exports-next-copy')).to_contain_text('independently obtained')
            page.locator('#export-task-account').click()
            expect(page.locator('#exports-progress')).to_be_hidden()
            page.locator('#export-task-journal').click()
            expect(page.locator('#exports-next')).to_be_visible()
            page.locator('#export-encrypt-on').check()
            page.locator('#export-password').fill('Synthetic test password only')
            with page.expect_download():
                page.locator('[data-export=html]').click()
            expect(page.locator('#exports-next-copy')).to_contain_text('HTML report')
            expect(page.locator('#exports-next-encrypted')).to_be_visible()
            page.locator('#exports-tab-downloads').focus()
            page.keyboard.press('ArrowRight')
            expect(page.locator('#exports-tab-settings')).to_be_focused()
            expect(page.locator('#report-case-title')).to_have_value('Unsaved investigation')
            page.keyboard.press('Home')
            expect(page.locator('#exports-tab-downloads')).to_be_focused()
            page.locator('#export-encrypt-on').uncheck()
            page.locator('#exports-tab-settings').click()
            page.locator('#report-timeline').uncheck()
            expect(page.locator('#report-raw')).to_be_disabled()
            expect(page.locator('#report-heartbeats')).to_be_disabled()
            expect(page.locator('#report-media')).to_be_enabled()
            page.locator('#report-timeline').check()
            for control in ('raw', 'media', 'heartbeats'):
                page.locator('#report-' + control).uncheck()
            page.locator('#report-part-size').fill('601')
            with page.expect_response(lambda response: response.request.method == 'POST'
                                      and response.url.endswith('/api/report-options')) as saved:
                page.locator('#report-form button[type=submit]').click()
            assert saved.value.status == 200 and saved.value.json()['part_size'] == 601
            page.locator('#exports-tab-downloads').click()
            with page.expect_download() as configured:
                page.locator('#export-journal-panel [data-export=zip]').click()
            with zipfile.ZipFile(configured.value.path()) as archive:
                document = archive.read('report.html').decode('utf-8')
                options = json.loads(re.search(r'id="viewer-meta">(.*?)</script>', document)[1])
                assert not any(options[name] for name in ('raw_records', 'media_previews', 'group_heartbeats'))
                assert 'report.pdf' in archive.namelist()
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                for theme in ('light', 'dark'):
                    page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                    page.screenshot(path=str(output / f'{width}-{theme}.png'), full_page=True)
                    assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth+1')
            page.route('**/api/export/csv', lambda route: route.fulfill(status=503, json={'detail': 'Synthetic export outage'}))
            page.locator('[data-export=csv]').click()
            expect(page.locator('#exports-progress-label')).to_have_text('Download failed. Retry the export.')
            expect(page.locator('#exports-next')).to_be_hidden()
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>!panelRoots.get('evidence').querySelector('#exports-history-list').textContent")
            assert not errors, errors
            browser.close()
    print('Export progress, exact receipts, format-aware handoff, encryption, failure, keyboard tabs, drafts, lock and four layouts passed.')


if __name__ == '__main__':
    main()
