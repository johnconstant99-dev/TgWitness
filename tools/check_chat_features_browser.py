"""Synthetic conversation controls and archive navigation; no Telegram requests."""
from pathlib import Path
import json
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock
from check_refresh_browser import hold_once, release


def static_chat_pages(browser):
    page = browser.new_page()
    messages = [{'message_id': number, 'text': str(number)} for number in (1, 4, 9, 25, 80, 81, 99)]
    fixture = {'/api/chats/-1001/messages': {'text': json.dumps({'messages': messages, 'next_before': None}), 'type': 'application/json'}}
    script = Path('website/demo/mock.js').read_text(encoding='utf-8')

    def content(route):
        path = route.request.url.rsplit('/', 1)[-1]
        if path == 'mock.js':
            route.fulfill(body=script, content_type='text/javascript')
        elif path == 'fixtures.json':
            route.fulfill(json=fixture)
        else:
            route.fulfill(body='<script src="/mock.js"></script>', content_type='text/html')

    page.route('https://synthetic.invalid/**', content)
    page.goto('https://synthetic.invalid/')
    result = page.evaluate("async()=> (await fetch('/api/chats/-1001/messages?after_id=4&limit=2')).json()")
    assert [item['message_id'] for item in result['messages']] == [9, 25]
    assert result['next_before'] == 9 and result['next_after'] == 25
    result = page.evaluate("async()=> (await fetch('/api/chats/-1001/messages?before_id=25&limit=2')).json()")
    assert [item['message_id'] for item in result['messages']] == [4, 9]
    page.close()


def capture(page, point):
    output = Path('build/ux-review/after') / point
    output.mkdir(parents=True, exist_ok=True)
    for width, height in ((1440, 1000), (390, 844)):
        page.set_viewport_size({'width': width, 'height': height})
        page.evaluate("()=>{document.querySelector('.chats-shell').dataset.panel='chat';show('toast',false);const feed=document.querySelector('#chat-feed');feed.scrollTop=feed.scrollHeight;}")
        assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth&&document.documentElement.scrollHeight<=innerHeight+1')
        page.mouse.move(0, 0)
        page.screenshot(path=str(output / f'chats-{width}.png'), animations='disabled')
    page.set_viewport_size({'width': 1440, 'height': 1000})


def hold_profile_read(page):
    hold_once(page, '/api/chats/-1001/profile')
    page.evaluate("""()=>{
      window.profileReadOriginal=window.loadChatProfile;
      window.loadChatProfile=(...args)=>{
        const pending=window.profileReadOriginal(...args);
        window.heldProfileRead??=pending;return pending;
      };
    }""")


def release_profile_read(page):
    page.evaluate("""async()=>{
      window.releaseRefresh();await window.heldProfileRead.catch(()=>{});
      window.loadChatProfile=window.profileReadOriginal;
      delete window.profileReadOriginal;delete window.heldProfileRead;
      delete document.documentElement.dataset.refreshHeld;
    }""")


def main():
    with tempfile.TemporaryDirectory(prefix='chat-features-') as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        store.set_setting('capture', {'download_media': False})
        store.set_target(-1001, 'Research archive', 'supergroup', True)
        for mid in range(1, 501):
            store.append('message.new', {'text': f'Preserved message {mid}', 'sender_id': 44,
                'sender_observation': {'id': 44, 'display_name': 'Researcher', 'username': 'research_author'},
                'sent_at': f'2026-10-{20 + mid // 100:02}T10:00:00+00:00',
                'has_media': mid % 10 == 0, 'reply_to_message_id': 1 if mid == 500 else None}, -1001, mid, 44)
        store.append('message.edited', {'text': 'Edited reply', 'sender_id': 44, 'reply_to_message_id': 498}, -1001, 499, 44)
        store.set_target(-1002, 'Second archive', 'supergroup', True)
        store.append('message.new', {'text': 'Different source'}, -1002, 700)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, snapshots, connected, ai_calls = [], [], {'value': False, 'ai': False}, []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: ai_calls.append(request.url) if '/api/analysis/' in request.url and request.method == 'POST' else None)

            def status(route):
                response = route.fetch()
                body = response.json()
                body['collector']['has_session'] = connected['value']
                body['collector']['account'] = {'id': 44, 'username': 'synthetic_researcher'} if connected['value'] else None
                body['analysis']['enabled'] = connected['ai']
                route.fulfill(response=response, json=body)

            def snapshot(route):
                snapshots.append(route.request.post_data_json)
                route.fulfill(json={'captured': 0})

            page.route('**/api/status', status)
            page.route('**/api/snapshot', snapshot)
            unlock(page, server)
            # Opening a chat starts its profile read in the background. Leaving for
            # settings can cancel that read before it fills the profile cache.
            hold_profile_read(page)
            page.evaluate("async()=>{await navigate('chats');await openChat(-1001);}")
            expect(page.locator('html')).to_have_attribute('data-refresh-held', 'true')
            expect(page.locator('#chat-sub')).to_contain_text('Group')
            expect(page.locator('#chat-compose')).to_be_hidden()
            expect(page.locator('#chat-load-history')).to_be_disabled()
            expect(page.locator('#chat-status').get_by_role('button', name='Connect account')).to_be_enabled()
            expect(page.locator('#chat-status').get_by_role('button', name='Start observation')).to_have_count(0)
            expect(page.locator('#chat-export-start')).to_have_attribute('aria-label', 'Export chat')
            expect(page.locator('.chat-mode-chips')).to_contain_text('Files off')
            page.locator('[data-recording="files"]').click()
            expect(page.locator('#capture-form')).to_be_visible()
            release_profile_read(page)
            assert page.evaluate('()=>state.chatProfile===null'), 'A cancelled profile read populated the cache'
            page.evaluate("()=>navigate('chats')")
            expect(page.locator('.chat-media-notice')).to_have_count(1)
            expect(page.locator('#msg-500 .reply-unavailable')).to_have_text('Reply to #1 · outside this loaded window')
            expect(page.locator('#msg-500 .reply-quote')).to_have_count(0)
            expect(page.locator('#msg-500 .media-missing')).to_have_attribute('aria-label', 'Attachment file not saved')
            expect(page.locator('.sender-details > summary').first).to_have_attribute('title', '@research_author')
            page.locator('.sender-details > summary').first.click()
            expect(page.locator('.sender-facts').first).to_contain_text('ID 44')
            page.locator('.sender-details > summary').first.click()
            page.locator('[data-chat-filter="edited"]').click()
            page.locator('#msg-499 .reply-quote').click()
            expect(page.locator('[data-chat-filter="all"]')).to_have_attribute('aria-pressed', 'true')
            expect(page.locator('#msg-498')).to_be_visible()
            page.locator('.chat-media-notice').get_by_role('button', name='File saving settings').click()
            expect(page.locator('#capture-form')).to_be_visible()
            page.evaluate("()=>navigate('chats')")
            expect(page.locator('.chat-filters [data-chat-filter]')).to_have_count(4)
            expect(page.locator('.chat-filters [data-chat-view]')).to_have_count(0)
            expect(page.locator('[data-chat-view="ai"]')).to_have_count(0)
            page.locator('[data-chat-filter="media"]').click()
            expect(page.locator('#chat-feed .msg')).to_have_count(6)
            assert page.locator('#chat-feed .msg').evaluate_all('rows=>rows.every(row=>row.querySelector(".media-missing"))')
            page.locator('[data-chat-view="people"]').click()
            expect(page.locator('#chat-feed .people')).to_be_visible()
            expect(page.locator('.chat-filter-row')).to_be_hidden()
            page.locator('[data-chat-view="profile"]').click()
            expect(page.locator('.chat-profile-view')).to_be_visible()
            expect(page.locator('.chat-profile-view')).to_contain_text('Profile not saved yet')
            # Repeated paints share the active read. Reentry gets a fresh read even
            # while an older request for the same chat has not settled yet.
            hold_profile_read(page)
            page.evaluate('()=>openChat(-1001)')
            expect(page.locator('html')).to_have_attribute('data-refresh-held', 'true')
            page.locator('[data-chat-view="profile"]').click()
            page.evaluate('()=>{renderChatFeed();renderChatFeed();renderChatFeed();}')
            expect(page.locator('.chat-profile-view')).to_contain_text('Loading…')
            assert page.evaluate('()=>window.refreshRequests') == 1, 'Profile renders started duplicate requests'
            page.locator('[data-recording="files"]').click()
            expect(page.locator('#capture-form')).to_be_visible()
            page.evaluate("()=>navigate('chats')")
            expect(page.locator('.chat-profile-view')).to_contain_text('Profile not saved yet')
            assert page.evaluate('()=>window.refreshRequests') == 2, 'Reentry reused the cancelled profile read'
            release_profile_read(page)
            expect(page.locator('.chat-profile-view')).to_contain_text('Profile not saved yet')
            page.route('**/api/chats/-1001/profile', lambda route: route.fulfill(status=503, json={'detail': 'Synthetic failure'}))
            page.evaluate('()=>loadChatProfile().catch(()=>{})')
            expect(page.locator('.chat-profile-view')).to_contain_text('Could not load data')
            expect(page.locator('.chat-profile-view')).not_to_contain_text('Profile not saved yet')
            page.unroute('**/api/chats/-1001/profile')
            page.locator('.chat-profile-view').get_by_role('button', name='Retry').click()
            expect(page.locator('.chat-profile-view')).to_contain_text('Profile not saved yet')
            page.locator('[data-chat-view="messages"]').click()
            expect(page.locator('[data-chat-filter="media"]')).to_have_attribute('aria-pressed', 'true')
            page.locator('[data-chat-filter="all"]').click()
            connected['ai'] = True
            page.evaluate('()=>refreshStatus()')
            page.locator('[data-chat-view="ai"]').click()
            expect(page.locator('#ask-chats input:checked')).to_have_value('-1001')
            expect(page.locator('#ask-question')).to_be_focused()
            assert not page.evaluate('()=>window.TgWitnessAnalysis.focusChat(999999)')
            expect(page.locator('#ask-chats input:checked')).to_have_value('-1001')
            assert not ai_calls, ai_calls
            connected['ai'] = False
            page.evaluate("async()=>{await refreshStatus();await navigate('chats');}")
            expect(page.locator('[data-chat-view="ai"]')).to_have_count(0)
            connected['value'] = True
            page.evaluate('()=>refreshStatus()')
            expect(page.locator('#chat-load-history')).to_be_enabled()
            page.locator('#chat-history-limit').select_option('250')
            page.locator('#chat-load-history').click()
            expect(page.locator('#chat-load-history')).to_be_enabled()
            assert snapshots == [{'chat_id': -1001, 'limit': 250}]
            page.evaluate("async()=>{await openChat(-1001);await loadChatMessages('older');await loadChatMessages('older');}")
            page.locator('#msg-360').scroll_into_view_if_needed()
            offset = page.locator('#msg-360').evaluate('row=>row.getBoundingClientRect().top-document.querySelector("#chat-feed").getBoundingClientRect().top')
            page.evaluate("()=>loadChatMessages('older')")
            expect(page.locator('#chat-feed .msg')).to_have_count(200)
            now = page.locator('#msg-360').evaluate('row=>row.getBoundingClientRect().top-document.querySelector("#chat-feed").getBoundingClientRect().top')
            assert abs(now - offset) <= 2, (offset, now)
            previous = page.evaluate('()=>state.chatMessages.map(message=>message.message_id)')
            store.append('message.new', {'text': 'New arrival while reading history'}, -1001, 501)
            page.evaluate('()=>refreshChats(true)')
            assert page.evaluate('()=>state.chatMessages.map(message=>message.message_id)') == previous
            page.locator('[data-chat-page="latest"]').click()
            expect(page.locator('#msg-501')).to_be_visible()
            assert page.evaluate('()=>state.chatNextAfter===null')
            seen = set(page.evaluate('()=>state.chatMessages.map(message=>message.message_id)'))
            for _ in range(12):
                if page.evaluate('()=>state.chatNextBefore===null'):
                    break
                page.evaluate("()=>loadChatMessages('older')")
                values = page.evaluate('()=>state.chatMessages.map(message=>message.message_id)')
                assert values == sorted(set(values)) and len(values) <= 200
                seen.update(values)
            assert page.evaluate('()=>state.chatNextBefore===null&&state.chatMessages[0].message_id===1')
            for _ in range(12):
                if page.evaluate('()=>state.chatNextAfter===null'):
                    break
                page.evaluate("()=>loadChatMessages('newer')")
                values = page.evaluate('()=>state.chatMessages.map(message=>message.message_id)')
                assert values == sorted(set(values)) and len(values) <= 200
                seen.update(values)
            assert seen == set(range(1, 502)) and page.evaluate('()=>state.chatMessages.at(-1).message_id===501')
            assert page.locator('.chat-day').first.evaluate('day=>getComputedStyle(day).position') == 'sticky'
            hold_once(page, '/messages?limit=60&before_id=' + str(page.evaluate('()=>state.chatNextBefore')))
            page.evaluate("()=>{window.heldRefresh=loadChatMessages('older');}")
            expect(page.locator('html')).to_have_attribute('data-refresh-held', 'true')
            page.evaluate('()=>openChat(-1002)')
            release(page)
            expect(page.locator('#chat-feed .msg')).to_have_count(1)
            expect(page.locator('#msg-700')).to_contain_text('Different source')
            page.evaluate('()=>openChat(-1001)')
            capture(page, '16-chat-window')
            static_chat_pages(browser)
            assert not errors, errors
            browser.close()
    print('Chats passed: controls, views, cancelled profile recovery, shared profile reads, profile Retry, AI scope, 200-message window, bidirectional paging, anchored scroll, stale responses and static demo.')


if __name__ == '__main__':
    main()
