"""Ctrl+K searches parameter metadata and record numbers without resetting drafts."""
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock
from check_refresh_browser import hold_once, release


def main():
    output = Path('build/ux-review/after/37-quick-search')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='quick-search-') as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        store.set_target(-1001, 'Research archive', 'supergroup', True)
        record = store.append('message.new', {'text': 'Preserved case note'}, -1001, 1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, parameter_reads = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: parameter_reads.append(request.url) if request.url.endswith('/api/parameters') else None)
            unlock(page, server)
            page.evaluate("()=>navigate('chats')")

            # Closing a palette with a pending schema request must not populate a later view.
            hold_once(page, '/api/parameters')
            page.evaluate("()=>{quickDialog.showModal();renderQuick();window.heldRefresh=loadQuickCatalog();quickSearch.focus();}")
            expect(page.locator('html')).to_have_attribute('data-refresh-held', 'true')
            page.locator('#quick-search').fill('dialog_limit')
            page.keyboard.press('Escape')
            release(page)
            assert page.evaluate('()=>quickCatalog.length===0')

            page.route('**/api/parameters', lambda route: route.fulfill(status=503, json={'detail': 'Synthetic failure'}))
            page.keyboard.press('Control+k')
            expect(page.locator('#quick-dialog')).to_contain_text('Parameter search is unavailable.')
            assert page.locator('#quick-results > :not([role="option"])').count() == 0
            page.keyboard.press('Escape')
            page.unroute('**/api/parameters')

            page.keyboard.press('Control+k')
            query = page.locator('#quick-search')
            query.fill('dialog_limit')
            parameter = page.locator('[data-action="parameter-dialog_limit"]')
            expect(parameter).to_be_visible()
            query.fill('Chats read')
            expect(parameter).to_be_visible()
            query.fill('Media')
            expect(page.locator('[data-action^="parameter-"]').first).to_be_visible()
            assert 'Media' in page.locator('[data-action^="parameter-"]').first.inner_text()
            query.fill('dialog_limit')
            for width, height in ((1440, 1000), (390, 844)):
                page.set_viewport_size({'width': width, 'height': height})
                assert page.locator('#quick-dialog').bounding_box()['width'] <= width
                page.screenshot(path=str(output / f'palette-{width}.png'), animations='disabled')
            page.set_viewport_size({'width': 1440, 'height': 1000})
            query.press('ArrowDown')
            query.press('ArrowUp')
            query.press('Enter')
            field = page.locator('#parameter-dialog_limit')
            expect(field).to_be_focused()
            assert '/parameters' in page.url and '#collection' in page.url
            field.fill('1234')
            page.evaluate("()=>navigate('chats')")
            page.keyboard.press('Control+k')
            query.fill('dialog_limit')
            parameter.click()
            expect(field).to_have_value('1234')
            expect(field).to_be_focused()

            page.keyboard.press('Control+k')
            query.fill('#' + str(record['seq']))
            expect(page.locator('[data-action="record-' + str(record['seq']) + '"]')).to_be_visible()
            query.press('Enter')
            expect(page.locator('#detail-content')).to_contain_text('Preserved case note')
            assert '/journal/event/' + str(record['seq']) in page.url
            page.keyboard.press('Escape')
            page.keyboard.press('Control+k')
            query.fill('Research archive')
            expect(page.locator('[data-action="chat--1001"]')).to_be_visible()
            query.fill('@synthetic_bot')
            expect(page.locator('[data-action="telegram"]')).to_be_visible()
            page.keyboard.press('Escape')

            # Switch to an actual issued, read-only session; cached admin metadata stays hidden.
            page.evaluate("""async()=>{const grant=await json('access/grants',{label:'Synthetic reader',permissions:['view'],workspaces:{default:null}},{root:true});
              state.token=(await json('access/login',{token:grant.token},{root:true,token:''})).session;await unlock();}""")
            before = len(parameter_reads)
            page.keyboard.press('Control+k')
            query.fill('dialog_limit')
            expect(page.locator('[data-action^="parameter-"]')).to_have_count(0)
            expect(page.locator('[data-action="journal"]')).to_be_visible()
            assert len(parameter_reads) == before
            page.evaluate('lock()')
            assert page.evaluate('()=>quickCatalog.length===0&&quickResults.childElementCount===0')
            assert not errors, errors
            browser.close()
    print('Quick search passed: schema labels/keys/groups, draft-preserving focus, #record links, stale reads and permission changes.')


if __name__ == '__main__':
    main()
