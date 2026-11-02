"""Guided connection flow against a local synthetic server, including narrow screens."""
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from check_browser import RunningApp, launch_browser, navigate_panel, unlock
from check_guided_connection import CHECK
from playwright.sync_api import expect, sync_playwright


def main():
    with tempfile.TemporaryDirectory() as folder, patch('tgwitness.guided_connection.probe', AsyncMock(return_value=CHECK)):
        with RunningApp(Path(folder)) as server, sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={'width':1440,'height':1100}, locale='en-US')
            errors=[]
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            navigate_panel(page, 'connection')
            expect(page.locator('#connect-guide')).to_be_visible()
            page.locator('#connect-toggle').click()
            expect(page.locator('[data-connect-mode]')).to_have_count(5)
            page.locator('[data-connect-mode="proxy"]').click()
            page.locator('#connect-proxy-url').fill('socks5://name:private@proxy.example.org:1080')
            page.locator('#connect-host').click()
            expect(page.locator('#connect-host')).to_have_value('proxy.example.org')
            expect(page.locator('#connect-password')).to_have_value('private')
            expect(page.locator('#connect-proxy-url')).to_have_value('')
            page.locator('[data-connect-mode="direct"]').click()
            page.locator('#connect-preview').click()
            expect(page.locator('#connect-review')).to_contain_text('Direct')
            failed_once=[]
            def transient_failure(route):
                if not failed_once:
                    failed_once.append(True)
                    route.fulfill(status=503, content_type='application/json', body='{"detail":"Temporary synthetic failure"}')
                else:
                    route.continue_()
            page.route('**/api/connection', transient_failure)
            page.locator('#connect-prepare').click()
            expect(page.locator('#connect-apply')).to_be_visible(timeout=15000)
            page.unroute('**/api/connection', transient_failure)
            expect(page.locator('#connect-review')).to_contain_text(CHECK['exit_ip'])
            assert server.app.state.collector.network_config().kind == 'mtproxy_auto'
            page.locator('#connect-apply').click()
            page.get_by_role('button',name='Apply connection',exact=True).click()
            expect(page.locator('#connect-progress')).to_contain_text('Connection updated',timeout=15000)
            assert server.app.state.collector.network_config().kind == 'direct'
            assert not server.app.state.collector.running
            # No raw proxy password from the unsaved form appears in rendered result text.
            assert 'private' not in page.locator('#connect-review').inner_text()
            output=Path('test-results/guided-connection')
            output.mkdir(parents=True,exist_ok=True)
            page.locator('[data-connect-mode="warp"]').click()
            page.locator('#connect-guide').screenshot(path=str(output/'desktop.png'))
            page.set_viewport_size({'width':390,'height':844})
            expect(page.locator('[data-connect-mode="warp"]')).to_be_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            page.locator('#connect-guide').screenshot(path=str(output/'mobile.png'))
            assert not errors, errors
            browser.close()
    print('Guided connection browser flow passed')


if __name__=='__main__':
    main()
