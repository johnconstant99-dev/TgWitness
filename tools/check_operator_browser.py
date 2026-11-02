import json
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import (RunningApp, answer_panel_dialog, hold_api_response,
                           launch_browser, release_api_response, unlock)
from tgwitness.operator_guide import write


def check_rotation_streams(browser, server):
    for delivery in ('before-response', 'after-response', 'failed-rotation'):
        page = browser.new_page(viewport={'width': 1440, 'height': 1050}, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.add_init_script("""(() => {
          const original=window.fetch,encoder=new TextEncoder();
          const probe=window.operatorStream={old:null,resumed:false,currentEnded:false};
          window.fetch=async(...args)=>{
            if(!new URL(String(args[0]),location.href).pathname.endsWith('/api/stream'))return original(...args);
            if(!probe.old){
              const old=probe.old={signal:args[1].signal,cancelled:false};
              const stream=new ReadableStream({
                start(controller){old.deliver=()=>controller.enqueue(encoder.encode('event: access-ended\\ndata: {}\\n\\n'));
                  controller.enqueue(encoder.encode(': connected\\n\\n'));},
                cancel(){old.cancelled=true;}
              });
              return new Response(stream,{headers:{'Content-Type':'text/event-stream'}});
            }
            const response=await original(...args);
            if(!response.ok)return response;
            probe.resumed=true;
            const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';
            return new Response(new ReadableStream({
              async pull(controller){
                const {value,done}=await reader.read();
                if(done){controller.close();return;}
                buffer+=decoder.decode(value,{stream:true});
                if(buffer.includes('event: access-ended'))probe.currentEnded=true;
                controller.enqueue(value);
              },
              cancel(){return reader.cancel();}
            }),{status:response.status,headers:response.headers});
          };
        })();""")
        try:
            unlock(page, server)
            page.evaluate("navigate('access')")
            page.locator('#access-tab-limits').click()
            page.wait_for_function('()=>!!window.operatorStream.old')
            old_key, old_session = server.app.state.vault.token, page.evaluate('state.token')
            if delivery == 'before-response':
                hold_api_response(page, '/api/access/token')
            elif delivery == 'failed-rotation':
                page.route('**/api/access/token', lambda route: route.fulfill(
                    status=503, json={'detail': 'Synthetic key service failure'}))
            page.locator('#panel-key-rotate').click()
            answer_panel_dialog(page)
            if delivery == 'before-response':
                page.wait_for_function('()=>!!window.releaseAcceptanceResponse')
            elif delivery == 'failed-rotation':
                expect(page.locator('#toast')).to_have_text('Synthetic key service failure')
                expect(page.locator('#panel-key-rotate')).to_be_enabled()
                assert server.app.state.vault.token == old_key
            else:
                expect(page.locator('#panel-key-result')).to_be_visible()
                expect(page.locator('#panel-key-rotate')).to_be_enabled()
            page.evaluate('operatorStream.old.deliver()')
            page.wait_for_function('()=>operatorStream.old.cancelled')
            expect(page.locator('#workspace')).to_be_visible()
            assert page.evaluate('operatorStream.old.signal.aborted')
            if delivery == 'before-response':
                release_api_response(page)
            elif delivery == 'failed-rotation':
                assert page.evaluate('state.token') == old_session
                assert not page.evaluate("$('workspace').inert")
                assert page.request.get(server.url + '/api/status', headers={
                    'Authorization': 'Bearer ' + old_session}).status == 200
                page.wait_for_function('()=>operatorStream.resumed')
                page.unroute('**/api/access/token')
                page.evaluate('operatorStream.resumed=false')
                page.locator('#panel-key-rotate').click()
                answer_panel_dialog(page)
            expect(page.locator('#panel-key-result')).to_be_visible()
            expect(page.locator('#panel-key-rotate')).to_be_enabled()
            session = page.evaluate('state.token')
            assert session != old_session and session
            assert page.locator('#panel-key-new').input_value() == server.app.state.vault.token
            assert page.evaluate("sessionStorage.getItem('tgwitness-token')===state.token && !$('workspace').inert")
            assert page.request.get(server.url + '/api/status', headers={
                'Authorization': 'Bearer ' + session}).status == 200
            page.wait_for_function('()=>operatorStream.resumed')
            assert page.request.post(server.url + '/api/access/logout', headers={
                'Authorization': 'Bearer ' + session}).status == 200
            page.wait_for_function('()=>operatorStream.currentEnded')
            expect(page.locator('#gate')).to_be_visible()
            assert page.evaluate("state.token==='' && sessionStorage.getItem('tgwitness-token')===null")
            assert not errors, errors
        finally:
            page.close()


def main():
    output = Path('test-results/operator-security')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='operator-browser-') as tmp, RunningApp(Path(tmp) / 'data') as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1050}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            old_key = server.app.state.vault.token
            old_session = page.evaluate('state.token')
            page.evaluate("navigate('access')")
            page.locator('#access-tab-limits').click()
            page.locator('#panel-key-rotate').click()
            answer_panel_dialog(page, accept=False)
            assert server.app.state.vault.token == old_key
            page.locator('#panel-key-rotate').click()
            answer_panel_dialog(page)
            expect(page.locator('#panel-key-result')).to_be_visible()
            key = page.locator('#panel-key-new').input_value()
            assert key != old_key and key == server.app.state.vault.token
            expect(page.locator('#panel-key-rotate')).to_be_enabled()
            for token in (old_key, old_session):
                assert page.request.get(server.url + '/api/status', headers={'Authorization': 'Bearer ' + token}).status == 401
            assert page.evaluate("json('status').then(r=>!!r.collector && state.me.admin)")
            assert not errors, errors
            page.locator('#panel-key-hide').click()
            assert page.locator('#panel-key-new').input_value() == ''
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), page.evaluate("""()=>({width:innerWidth,overflow:[...document.querySelectorAll('body *')].filter(e=>e.checkVisibility()&&e.getBoundingClientRect().right>innerWidth+1).map(e=>[e.tagName,e.id,e.className,e.getBoundingClientRect().right]).slice(0,20)})""")
                page.screenshot(path=str(output / f'access-{width}.png'), full_page=True)
            page.reload()
            expect(page.locator('#workspace')).to_be_visible()
            assert page.evaluate('state.token') != old_session
            assert page.locator('#panel-token').get_attribute('autocomplete') == 'off'
            missing = page.locator('script[src]:not([integrity]):not([src$="/locale.js"]), link[rel=stylesheet]:not([integrity])').evaluate_all('(nodes)=>nodes.map(n=>n.outerHTML)')
            assert not missing, missing
            metadata = json.loads(page.locator('script[type=importmap]').text_content())
            assert '/components/shell.js?v=3' in metadata['integrity']
            page.close()
            check_rotation_streams(browser, server)

            for asset in ('app.js', 'components/shell.js', 'style.css'):
                context = browser.new_context()
                broken = context.new_page()
                messages, intercepted = [], []
                broken.on('console', lambda message: messages.append(message.text))
                def tamper(route):
                    intercepted.append(route.request.url)
                    css = asset.endswith('.css')
                    route.fulfill(body='body{--tampered:yes}' if css else 'window.tampered=true;',
                                  content_type='text/css' if css else 'text/javascript')
                broken.route('**/' + asset + '*', tamper)
                with broken.expect_console_message(predicate=lambda message: 'integrity' in message.text.lower() or 'digest' in message.text.lower()):
                    broken.goto(server.url)
                assert intercepted, asset
                assert any('integrity' in message.lower() or 'digest' in message.lower() for message in messages), (asset, messages)
                assert not broken.evaluate('!!window.tampered')
                assert broken.evaluate("getComputedStyle(document.body).getPropertyValue('--tampered')") == ''
                context.close()

            guide = write(Path(tmp) / 'local guide', windows=False)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(guide.as_uri())
            expect(page.get_by_role('heading', name='Your workspace. Your controls.')).to_be_visible()
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                page.screenshot(path=str(output / f'guide-{width}.png'), full_page=True)
            page.locator('button[data-copy]').first.click()
            expect(page.locator('button[data-copy]').first).not_to_have_text('Copy')
            assert not errors, errors
            browser.close()
    print('Operator browser passed: key rotation, late and early old-stream denial ignored, failed rotation retry, current-session revocation, responsive controls, script/module/style tampering blocked and offline guide.')


if __name__ == '__main__':
    main()
