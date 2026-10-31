"""Synthetic downloads: progress, exact receipt, report drafts and compact layouts."""
import hashlib
from pathlib import Path
import tempfile

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
            expect(page.locator('#report-form')).to_be_hidden()
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-fields')).to_be_enabled()
            page.locator('#report-case-title').fill('Unsaved investigation')
            page.locator('#exports-tab-downloads').click()
            page.evaluate("""()=>{window.showSaveFilePicker=async()=>{
              throw new DOMException('Synthetic picker cancellation','AbortError');};}""")
            page.locator('[data-export=jsonl]').click()
            expect(page.locator('#exports-progress-label')).to_have_text('Download cancelled.')
            expect(page.locator('#exports-progress-bar')).to_be_hidden()
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
            expect(page.locator('.export-receipt')).to_have_count(1)
            page.locator('.export-receipt summary').click()
            expect(page.locator('.export-receipt code')).to_have_text(digest)
            page.locator('#exports-tab-settings').click()
            expect(page.locator('#report-case-title')).to_have_value('Unsaved investigation')
            page.evaluate("async()=>{await navigate('chats');await navigate('evidence');}")
            expect(page.locator('#report-case-title')).to_have_value('Unsaved investigation')
            page.locator('#exports-tab-downloads').click()
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                for theme in ('light', 'dark'):
                    page.evaluate('theme=>document.documentElement.dataset.theme=theme', theme)
                    page.screenshot(path=str(output / f'{width}-{theme}.png'), full_page=True)
                    assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth+1')
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>!panelRoots.get('evidence').querySelector('#exports-history-list').textContent")
            assert not errors, errors
            browser.close()
    print('Export progress, receipts, drafts, lock and four layouts passed.')


if __name__ == '__main__':
    main()
