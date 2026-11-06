"""Real local exports"""
import argparse
import hashlib
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, answer_panel_dialog, launch_browser, unlock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', choices=('chromium', 'firefox', 'webkit'), default='chromium')
    engine = parser.parse_args().browser
    output = Path('build/ux-review/account-safety') / engine
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='safe-exports-') as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        store.append('message.new', {'text': 'Synthetic export receipt'}, -1001, 1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright) if engine == 'chromium' else getattr(playwright, engine).launch(headless=True)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            second = page.evaluate("""async()=>{const p=await json('profiles',{label:'Second account'},{root:true});
              await loadProfiles();return p.id;}""")
            page.evaluate("()=>navigate('evidence')")
            expect(page.locator('#workspace-identity')).to_be_visible()
            page.evaluate('id=>switchProfile(id)', second)
            second_url = page.url
            page.evaluate('state.accountExportDirty=true')
            page.go_back()
            answer_panel_dialog(page, accept=False)
            expect(page).to_have_url(second_url)
            expect(page.locator('#profile-select')).to_have_value(second)
            expect(page.locator('#workspace-context-alert')).to_be_hidden()
            assert page.evaluate('state.accountExportDirty'), 'Cancel must retain the unsaved draft'
            with page.expect_response(lambda response: response.url.endswith('/api/collector/stop')) as stopped:
                page.evaluate("()=>json('collector/stop',{},{profile:'default'})")
            assert stopped.value.status == 200
            assert '/profiles/' not in stopped.value.url
            page.evaluate("async()=>{state.accountExportDirty=false;await switchProfile('default');}")

            page.evaluate("id=>{$('profile-select').value=id;}", second)
            blocked = page.evaluate("async()=>{try{await api('export/zip');return false;}catch{return true;}}")
            assert blocked
            expect(page.locator('#workspace-context-alert')).to_be_visible()
            assert page.locator('.content').evaluate('el=>el.inert')
            page.screenshot(path=str(output / 'workspace-mismatch.png'), full_page=True)
            page.locator('#workspace-context-alert button').click()
            expect(page.locator('#workspace-context-alert')).to_be_hidden()
            expect(page.locator('#profile-select')).to_have_value('default')

            page.evaluate("""()=>{window.reviewAbort=0;window.reviewResult=null;
              window.showSaveFilePicker=async()=>({createWritable:()=>new Promise(resolve=>{
                window.releaseReviewWriter=()=>resolve({write:async()=>{},close:async()=>{},
                  abort:async()=>{window.reviewAbort++;}});})});
              download('export/zip','stale.zip',true).then(ok=>window.reviewResult={ok},
                error=>window.reviewResult={error:error.name});}""")
            answer_panel_dialog(page)
            page.wait_for_function('()=>typeof releaseReviewWriter===\'function\'')
            page.evaluate('id=>switchProfile(id)',second)
            stale_requests=[]
            def track_stale(request):
                if '/api/export/zip' in request.url:
                    stale_requests.append(request.url)
            page.on('request',track_stale)
            page.evaluate('releaseReviewWriter()')
            page.wait_for_function('()=>reviewResult!==null')
            assert not stale_requests, stale_requests
            assert page.evaluate('reviewAbort') == 1
            assert page.evaluate('reviewResult.error') == 'StaleView'
            page.remove_listener('request',track_stale)
            page.evaluate("()=>switchProfile('default')")

            original_url = page.url
            page.evaluate("""()=>{window.reviewAbort=0;window.reviewResult=null;
              window.showSaveFilePicker=async()=>({createWritable:async()=>({write:async()=>{},
                close:async()=>{},abort:async()=>{window.reviewAbort++;}})});} """)

            def change_link_before_response(route):
                # A status reply can arrive while the link names another account.
                # Deliver that observation explicitly instead of relying on poll timing.
                page.evaluate("""id=>{history.pushState({},'', '/exports?ws='+id);
                  try{TgWitnessWorkspace.acceptStatus({workspace_id:'default'});}
                  catch(error){window.reviewStatusError=error.message;}}""", second)
                route.fulfill(body=b'abc', headers={'Content-Length': '3', 'Content-Type': 'application/zip'})

            page.route('**/api/export/zip', change_link_before_response)
            page.evaluate("""()=>{download('export/zip','synthetic.zip',true).then(
              ok=>window.reviewResult={ok},error=>window.reviewResult={error:error.message});}""")
            answer_panel_dialog(page)
            page.wait_for_function('()=>window.reviewResult!==null')
            assert page.evaluate('reviewAbort') == 1
            assert page.evaluate('Boolean(reviewResult.error)')
            assert page.evaluate('Boolean(window.reviewStatusError)')
            expect(page.locator('#workspace-context-alert')).to_be_visible()
            page.unroute('**/api/export/zip')
            page.evaluate("url=>{history.replaceState({},'',url);TgWitnessWorkspace.sync();}", original_url)
            # Restoring the link does not clear a recorded status mismatch.
            expect(page.locator('#workspace-context-alert')).to_be_visible()
            page.locator('#workspace-context-alert button').click()
            expect(page.locator('#workspace-context-alert')).to_be_hidden()
            expect(page.locator('#profile-select')).to_have_value('default')

            cases = [
                'window.showSaveFilePicker=undefined',
                "window.showSaveFilePicker=async()=>{throw new DOMException('Denied','SecurityError')}",
                "window.showSaveFilePicker=async()=>({createWritable:async()=>{throw new DOMException('Denied','NotAllowedError')}})",
                "window.showSaveFilePicker=async()=>({createWritable:async()=>({write:async()=>{throw new DOMException('Disk failure','NotAllowedError')},abort:async()=>{}})})",
            ]
            for index, script in enumerate(cases):
                page.evaluate('()=>{' + script + ';}')
                with page.expect_download() as saved:
                    page.locator('#export-journal-panel [data-export=zip]').click()
                    expect(page.locator('dialog.panel-dialog[open]')).to_contain_text('Main account')
                    answer_panel_dialog(page)
                file = Path(saved.value.path())
                digest = hashlib.sha256(file.read_bytes()).hexdigest()
                expect(page.locator('.export-receipt')).to_have_count(index + 1)
                receipt = page.evaluate("async()=>(await json('exports/history')).exports[0]")
                assert receipt['sha256'] == digest and receipt['bytes'] == file.stat().st_size and receipt['available']
                cache = Path(scratch) / 'prepared-exports' / receipt['id']
                assert cache.is_file() and hashlib.sha256(cache.read_bytes()).hexdigest() == digest

            page.evaluate('window.showSaveFilePicker=undefined')
            with page.expect_download() as again:
                page.locator('.export-receipt').first.get_by_role('button', name='Download again').click()
                answer_panel_dialog(page)
            assert hashlib.sha256(Path(again.value.path()).read_bytes()).hexdigest() == digest
            assert page.request.get(server.url + '/api/exports/' + receipt['id'] + '/download').status in (401, 403)
            ticket = page.evaluate("id=>json('exports/'+id+'/ticket',{})", receipt['id'])
            assert page.request.get(server.url + ticket['url']).status == 200
            assert page.request.get(server.url + ticket['url']).status == 403

            job, disclosure = 'a' * 32, 'b' * 32
            archive = Path(scratch) / 'synthetic-account.zip'
            archive.write_bytes(b'Synthetic account export transport bytes\n' * (450 * 1024))
            job_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            store.set_setting('parameters', {'browser_buffer_mib': 16})
            page.evaluate('refreshStatus()')
            assert archive.stat().st_size > 16 * 1024**2
            endpoints = ['account-export/' + job,
                         'account-export/' + job + '/disclosures/' + disclosure]
            with patch.object(server.app.state.account_export, 'result_path', return_value=archive), \
                    patch.object(server.app.state.account_export, 'public', return_value={'archive_sha256': job_digest}), \
                    patch.object(server.app.state.disclosures, 'result_path', return_value=archive):
                for endpoint in endpoints:
                    requested = []

                    def track_ticket(request):
                        if request.url.endswith('/' + endpoint + '/ticket'):
                            requested.append(request)

                    page.on('request', track_ticket)
                    page.evaluate('window.showSaveFilePicker=undefined')
                    with page.expect_download() as job_download:
                        page.evaluate("""path=>{window.reviewResult=null;
                          download(path+'/download','synthetic-account.zip',true).then(
                            ok=>window.reviewResult={ok},error=>window.reviewResult={error:error.message});}""", endpoint)
                        answer_panel_dialog(page)
                    assert hashlib.sha256(Path(job_download.value.path()).read_bytes()).hexdigest() == job_digest
                    page.wait_for_function('()=>reviewResult!==null')
                    assert page.evaluate('reviewResult.ok'), page.evaluate('reviewResult')
                    assert len(requested) == 1 and requested[0].method == 'POST'
                    page.remove_listener('request', track_ticket)
                    assert archive.is_file(), 'Native fallback must retain the finished job archive'
                    assert page.request.get(server.url + '/api/' + endpoint + '/download').status == 403
            assert len(page.evaluate("async()=>(await json('exports/history')).exports")) == len(cases)
            store.set_setting('parameters', {})
            page.evaluate('refreshStatus()')
            for ws in ('../other', 'missing', second):
                response = page.request.get(server.url + '/api/access?ws=' + ws,
                                            headers={'Authorization': 'Bearer ' + server.app.state.vault.token})
                assert response.status == 404
            page.route('**/api/status', lambda route: route.fulfill(json={
                **page.evaluate('state.status'), 'workspace_id': second}))
            assert page.evaluate('async()=>{try{await refreshStatus();return false;}catch{return true;}}')
            expect(page.locator('#workspace-context-alert')).to_be_visible()
            page.unroute('**/api/status')
            page.locator('#workspace-context-alert button').click()
            expect(page.locator('#workspace-context-alert')).to_be_hidden()
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                expect(page.locator('#workspace-identity')).to_be_visible()
                page.screenshot(path=str(output / f'prepared-exports-{width}.png'), full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            assert not errors, errors
            browser.close()
    print(engine + ': workspace mismatch blocking, status ownership, file API fallbacks, large account/disclosure downloads, retained hashes and ticket isolation passed.')


if __name__ == '__main__':
    main()
