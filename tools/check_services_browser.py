"""Service discovery and storage purpose navigation, without sending external requests."""
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, unlock


def main():
    output = Path('build/ux-review/services')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='services-ui-') as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("async()=>{await navigate('witness');selectExtra('alerts');}")
            expect(page.locator('#services-catalog .service-choice').first).to_be_visible()
            count = page.locator('#services-catalog .service-choice').count()
            assert count > 100
            page.locator('#services-search').fill('Discord')
            expect(page.locator('#services-catalog .service-choice')).to_have_count(1)
            page.locator('#services-catalog .service-choice').click()
            expect(page.locator('#service-setup')).to_be_visible()
            assert page.locator('#service-setup input[type=password]').count() > 0
            page.locator('#services-search').fill('Telegram')
            page.locator('#services-catalog .service-choice').click()
            expect(page.locator('#service-setup h3')).to_contain_text('Telegram')
            assert page.locator('#service-setup svg use').get_attribute('href') == server.url + '/services-icons.svg#telegram'
            page.screenshot(path=str(output / 'notification-providers.png'), full_page=True)
            page.evaluate("selectExtra('storage')")
            expect(page.locator('#replica-form')).to_be_visible()
            page.locator('#replica-provider').select_option('wasabi')
            expect(page.locator('#replica-endpoint')).to_have_value('https://s3.us-east-1.wasabisys.com')
            page.locator('[data-storage-mode=evidence]').click()
            expect(page.locator('#storage-lock-help')).to_be_visible()
            page.locator('[data-storage-mode=offload]').click()
            expect(page.locator('#storage-form')).to_be_visible()
            expect(page.locator('#replica-form')).to_be_hidden()
            expect(page.locator('#storage-status')).to_contain_text('Ready to configure')
            # Purpose navigation never connects or removes local data on its own.
            assert not server.app.state.vault.read('storage')
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                page.screenshot(path=str(output / f'storage-{width}.png'), full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            page.evaluate("selectExtra('bot')")
            page.locator('#witness-publisher').select_option('discord')
            expect(page.locator('#witness-discord-help')).to_be_visible()
            expect(page.locator('#witness-channel')).to_be_hidden()
            page.locator('#witness-address').fill('https://collector.example.org')
            with page.expect_download() as config:
                page.locator('#witness-setup-form button[type=submit]').click()
            import json
            saved = json.loads(Path(config.value.path()).read_text())
            assert saved['discord_webhook_file'] == 'discord-webhook.txt'
            assert 'bot_token_file' not in saved and 'channel' not in saved
            assert not errors, errors
            browser.close()
    print(f'Services UI passed: {count} installed providers, private credential fields, storage purposes, Wasabi preset, Discord witness config, desktop/mobile.')


if __name__ == '__main__':
    main()
