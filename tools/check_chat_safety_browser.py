import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import requests
from playwright.sync_api import expect, sync_playwright

from tools.browser_fixtures import CHAT, SHOP_BOT, InteractionClient, message, offer, saved_session
from tools.check_browser import RunningApp, hold_api_response, launch_browser, release_api_response, unlock


class SafetyClient(InteractionClient):
    async def iter_messages(self, entity, limit=None, **kwargs):
        for number in range(1, min(limit or 3, 3) + 1):
            yield message(CHAT, number, f'Synthetic history message {number}')


def approve(page, *, remember=False):
    dialog = page.locator('dialog.chat-action-confirm[open]')
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text('@synthetic')
    if remember:
        dialog.locator('#chat-action-remember').check()
    dialog.locator('[data-confirm-action="true"]').click()
    expect(dialog).to_have_count(0)


def main():
    output = ROOT / 'test-results' / 'chat-safety'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='chat-safety-') as temporary, RunningApp(
            Path(temporary), client_factory=SafetyClient) as server:
        headers = {'Authorization': 'Bearer ' + server.app.state.vault.token}
        response = requests.post(server.url + '/api/auth/configure', headers=headers,
                                 json={'api_id': 123, 'api_hash': 'a' * 32, 'session': saved_session()}, timeout=15)
        response.raise_for_status()
        requests.post(server.url + '/api/interactions/read-only', headers=headers, json={'enabled': False},
                      timeout=15).raise_for_status()
        store = server.app.state.store
        store.set_setting('parameters', {'action_message_seconds': 0, 'action_button_seconds': 0})
        store.set_target(SHOP_BOT, 'Synthetic shop bot', 'bot', True)
        store.set_target(CHAT, 'Empty research chat', 'supergroup', True)
        secret = 'Password: TopSecret-1234; card 4111 1111 1111 1111; token ' + 'sk-' + 'proj-' + 'abcdefghijklmnopqrstuvwxyz'
        asyncio.run(server.app.state.collector.capture_message(offer(text=secret), 'message.new', SHOP_BOT))
        before = store.events(chat_id=SHOP_BOT, limit=20)
        errors, actions, snapshots, reveals = [], [], [], []
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            page.on('pageerror', lambda error: errors.append(str(error)))

            def request(request):
                if request.method == 'POST':
                    for suffix, target in [('/api/interactions', actions), ('/api/snapshot', snapshots), ('/api/privacy/reveal', reveals)]:
                        if request.url.endswith(suffix):
                            target.append(request.post_data_json)

            page.on('request', request)
            unlock(page, server)
            page.evaluate('(id)=>navigate("chats").then(()=>openChat(id))', SHOP_BOT)
            expect(page.locator('#chat-read-only')).to_be_checked()
            expect(page.locator('#chat-compose')).to_be_hidden()
            expect(page.locator('#chat-compose-open')).to_be_hidden()
            expect(page.locator('#chat-feed button', has_text='Press button')).to_have_count(0)
            expect(page.locator('#msg-10 .bubble-text')).not_to_contain_text('TopSecret-1234')
            expect(page.locator('.chat-item-preview').filter(has_text='Password:')).not_to_contain_text('TopSecret-1234')
            assert page.locator('#chat-feed [title*="TopSecret"]').count() == 0
            assert page.evaluate('TgWitnessPrivacy.preview("card 4111 1111 1111 1112")') == 'card 4111 1111 1111 1112'
            assert '•••••' in page.evaluate('TgWitnessPrivacy.preview("пароль: секретный123")')
            assert 'abcdef' not in page.evaluate('TgWitnessPrivacy.preview("api_key=abcdef123456")')
            assert page.evaluate('TgWitnessPrivacy.preview("ordinary text <b>literal</b>")') == 'ordinary text <b>literal</b>'

            page.route('**/api/privacy/reveal', lambda route: route.fulfill(status=503, json={'detail': 'Unavailable'}))
            reveal = page.locator('#msg-10 .secret-reveal').first
            reveal.click()
            expect(reveal).to_be_enabled()
            expect(page.locator('#msg-10 .bubble-text')).not_to_contain_text('TopSecret-1234')
            page.unroute('**/api/privacy/reveal')
            reveal.click()
            expect(page.locator('#msg-10 .bubble-text')).to_contain_text('TopSecret-1234')
            assert reveals[-1] == {'chat_id': SHOP_BOT, 'message_id': 10}
            reveal.click()
            expect(page.locator('#msg-10 .bubble-text')).not_to_contain_text('TopSecret-1234')
            recorded = store.events(kind='panel.secret_revealed', limit=20)
            assert recorded and all('TopSecret' not in json.dumps(row) for row in recorded)
            assert store.events(chat_id=SHOP_BOT, kind='message.new', limit=20)[0]['hash'] == before[0]['hash']

            page.locator('#chat-mask-secrets').uncheck()
            expect(page.locator('#msg-10 .bubble-text')).to_contain_text('TopSecret-1234')
            expect(page.locator('.chat-item-preview').filter(has_text='Password:')).not_to_contain_text('TopSecret-1234')
            page.locator('#chat-mask-secrets').check()
            expect(page.locator('#msg-10 .bubble-text')).not_to_contain_text('TopSecret-1234')
            assert store.events(kind='panel.secret_revealed', limit=20)[0]['payload']['reason'] == 'display_preference'
            page.evaluate('(seq)=>openRecord(seq)', before[0]['seq'])
            page.locator('.journal-json summary').click()
            expect(page.locator('.journal-json code')).not_to_contain_text('TopSecret-1234')
            expect(page.locator('#detail-content')).not_to_contain_text('TopSecret-1234')
            expect(page.locator('.journal-json code')).to_contain_text(before[0]['hash'])
            page.locator('#close-detail').click()
            page.evaluate('(id)=>navigate("chats").then(()=>openChat(id))', SHOP_BOT)

            page.locator('#chat-read-only').uncheck()
            page.locator('#chat-compose-open').click()
            page.locator('#chat-message').fill('Synthetic approved message')
            page.locator('#chat-send').click()
            expect(page.locator('dialog.chat-action-confirm')).to_be_visible()
            assert not actions
            page.locator('[data-confirm-action="false"]').click()
            assert not actions
            page.locator('#chat-send').click()
            hold_api_response(page, '/api/chats')
            approve(page, remember=True)
            expect(page.locator('#interaction-result')).to_contain_text('Action completed')
            assert len(actions) == 1
            expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
            press = page.locator('#msg-10 .msg-button', has_text='I paid').get_by_role('button')
            expect(press).to_be_disabled()
            release_api_response(page)
            expect(press).to_be_enabled()
            press.click()
            expect(page.locator('#interaction-result')).to_contain_text('Recorded answer')
            assert len(actions) == 2
            assert actions[-1]['action'] == 'press'
            expect(page.locator('dialog.chat-action-confirm')).to_have_count(0)
            expect(press).to_be_enabled()
            page.evaluate('()=>{window.originalSafetyNow=Date.now;Date.now=()=>originalSafetyNow()+601000;}')
            page.locator('#msg-10 .msg-button', has_text='I paid').get_by_role('button').click()
            expect(page.locator('dialog.chat-action-confirm')).to_be_visible()
            page.locator('[data-confirm-action="false"]').click()
            page.evaluate('()=>{Date.now=originalSafetyNow;delete window.originalSafetyNow;}')
            assert len(actions) == 2, 'Remembered consent must expire after ten minutes'
            page.locator('#chat-read-only').check()
            expect(page.locator('#chat-compose')).to_be_hidden()
            expect(page.locator('#chat-feed button', has_text='Press button')).to_have_count(0)

            page.evaluate('(id)=>openChat(id)', CHAT)
            expect(page.locator('#chat-read-only')).to_be_checked()
            page.route('**/api/snapshot', lambda route: route.fulfill(status=503, json={'detail': 'Telegram is temporarily unavailable. Retry.'}))
            page.locator('#chat-feed').get_by_role('button', name='Load last 100 messages').click()
            expect(page.locator('#chat-history-feedback')).to_contain_text('Could not load messages')
            assert snapshots[-1] == {'chat_id': CHAT, 'limit': 100}
            stale_retry = page.locator('#chat-history-feedback').get_by_role('button', name='Retry').element_handle()
            page.evaluate('(id)=>openChat(id)', SHOP_BOT)
            expect(page.locator('#chat-history-feedback')).to_have_count(0)
            stale_retry.evaluate('button=>button.click()')
            page.evaluate('(id)=>openChat(id)', CHAT)
            stale_retry.evaluate('button=>button.click()')
            assert len(snapshots) == 1, 'A stale retry must not acquire history in another or reopened chat'
            page.locator('#chat-feed').get_by_role('button', name='Load last 100 messages').click()
            expect(page.locator('#chat-history-feedback')).to_contain_text('Could not load messages')
            page.unroute('**/api/snapshot')
            page.locator('#chat-history-feedback').get_by_role('button', name='Retry').click()
            expect(page.locator('#chat-feed .msg')).to_have_count(3)
            expect(page.locator('#toast')).to_contain_text('Loaded 3 messages.')
            expect(page.locator('#chat-history-feedback')).to_have_count(0)
            page.locator('#chat-load-history').click()
            expect(page.locator('#chat-load-history')).to_be_enabled()
            assert snapshots[-1] == {'chat_id': CHAT, 'limit': 100}
            assert len(snapshots) == 4

            page.evaluate('(id)=>openChat(id)', SHOP_BOT)
            expect(page.locator('#chat-read-only')).to_be_checked()
            page.reload()
            expect(page.locator('#chat-read-only')).to_be_checked()
            expect(page.locator('#chat-compose')).to_be_hidden()
            page.evaluate('()=>beginChat(null)')
            page.locator('.chat-open summary').click()
            page.locator('#chat-link').fill('https://t.me/+invite_hash')
            page.locator('#chat-preview-button').click()
            expect(page.locator('#chat-link-preview')).to_contain_text('Preview group')
            page.locator('#chat-link-preview button').click()
            expect(page.locator('dialog.chat-action-confirm')).to_contain_text('Open or join as @synthetic?')
            expect(page.locator('#chat-action-remember')).to_be_hidden()
            page.locator('[data-confirm-action="false"]').click()
            assert len(actions) == 2
            page.evaluate('(id)=>openChat(id)', SHOP_BOT)
            expect(page.locator('#chat-read-only')).to_be_checked()
            assert page.locator('.chat-day').first.evaluate('el=>getComputedStyle(el).position') == 'relative'
            for width, height in [(1440, 1000), (390, 844)]:
                page.set_viewport_size({'width': width, 'height': height})
                page.evaluate('()=>{document.querySelector(".chats-shell").dataset.panel="chat";show("toast",false);}')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
                page.screenshot(path=str(output / f'chat-read-only-{width}.png'), animations='disabled')
            assert not errors, errors
            browser.close()
    print('PASS: read-only, named consent, masked previews/reveals, unchanged originals, empty history/retry, responsive layout')


if __name__ == '__main__':
    main()
