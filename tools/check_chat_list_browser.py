"""Chat search, filters, sorting and shared priority against a synthetic archive."""
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock


def ids(page):
    return page.locator('#chats-list .chat-item').evaluate_all('rows=>rows.map(row=>Number(row.dataset.chat))')


def main():
    output = Path('build/ux-review/after/12-chat-list')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='chat-list-') as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        for cid, title, kind, enabled, origin in [(-1001, 'Zulu channel', 'channel', True, None),
                (-1002, 'Alpha group', 'supergroup', True, None), (2001, 'Basket bot', 'bot', True, 'scope'),
                (2002, 'Delta person', 'user', False, None), (-1003, 'Charlie excluded', 'channel', True, None)]:
            store.set_target(cid, title, kind, enabled, origin=origin, priority=False)
            for mid in range(1, 4):
                store.append('message.new', {'text': f'Preserved message {mid}', 'sender_id': 44}, cid, mid, 44)
        store.append('message.deleted', {}, -1002, 1)
        store.append('message.deleted', {}, -1002, 2)
        store.append('message.edited', {'text': 'Preserved edit', 'sender_id': 44}, -1001, 1, 44)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))

            def status(route):
                response = route.fetch()
                value = response.json()
                value['scope']['exclude'] = [-1003]
                value['collector'].setdefault('source_status', {})['2001'] = {'state': 'access_unconfirmed'}
                route.fulfill(response=response, json=value)

            page.route('**/api/status', status)
            unlock(page, server)
            page.evaluate("async()=>{await navigate('chats');await openChat(-1001);}")
            expect(page.locator('#chats-list .chat-item')).to_have_count(5)
            assert page.locator('#chats-list button button').count() == 0
            search = page.locator('#chat-search')
            search.fill('2001')
            assert ids(page) == [2001]
            search.press('Escape')
            page.locator('#chat-list-sort').select_option('name')
            assert ids(page) == [-1002, 2001, -1003, 2002, -1001]
            page.locator('#chat-list-sort').select_option('deleted')
            assert ids(page)[0] == -1002
            page.locator('#chat-list-sort').select_option('edited')
            assert ids(page)[0] == -1001
            expect(page.locator('[data-chat="-1001"] .pill-edited')).to_have_attribute('title', '1 edited')
            page.locator('.chat-list-filters summary').click()
            for kind, expected in [('channel', {-1001, -1003}), ('group', {-1002}), ('bot', {2001}), ('private', {2002})]:
                page.locator('#chat-list-kind').select_option(kind)
                assert set(ids(page)) == expected
            page.locator('#chat-list-kind').select_option('')
            for condition, expected in [('auto', [2001]), ('unconfirmed', [2001]), ('excluded', [-1003]), ('paused', [2002])]:
                page.locator('#chat-list-state').select_option(condition)
                assert ids(page) == expected
            page.locator('#chat-list-state').select_option('')
            row = page.locator('[data-chat="-1002"]')
            row.locator('.chat-priority').click()
            expect(row.locator('.chat-priority')).to_have_attribute('aria-pressed', 'true')
            assert next(target for target in store.targets() if target['chat_id'] == -1002)['priority']
            assert page.evaluate('()=>state.chat') != -1002, 'Marking priority opened a different chat'
            page.locator('#chat-list-state').select_option('priority')
            assert ids(page) == [-1002]
            page.evaluate("async()=>{await navigate('sources');await sourcesReady;sourcesView.showTab('chats');}")
            expect(page.locator('[data-source-action="star"][data-chat-id="-1002"]')).to_have_attribute('aria-pressed', 'true')
            page.evaluate("()=>navigate('chats')")
            expect(page.locator('#chat-list-state')).to_have_value('priority')
            assert ids(page) == [-1002]
            assert page.evaluate("""async()=>{const sort=document.querySelector('#chat-list-sort'),row=document.querySelector('.chat-choice');
              sort.focus();await refreshStatus();await refreshChats(true);return row.isConnected&&sort.isConnected&&document.activeElement===sort;}""")
            page.locator('#chat-list-state').select_option('')
            page.locator('#chat-list-sort').select_option('activity')
            store.append('message.new', {'text': 'Latest activity', 'sender_id': 44}, -1001, 4, 44)
            page.evaluate('()=>refreshChats(true)')
            assert ids(page)[0] == -1001
            search.fill('nothing matches')
            expect(page.locator('#chats-list')).to_contain_text('No chats match your search.')
            page.locator('#chats-list').get_by_role('button', name='Clear filters').click()
            expect(search).to_have_value('')
            expect(page.locator('#chats-list .chat-item')).to_have_count(5)

            for width, height in ((1440, 1000), (390, 844)):
                page.set_viewport_size({'width': width, 'height': height})
                if width == 390:
                    page.locator('#chat-back').click()
                page.locator('.chat-list-filters').evaluate('element=>element.open=true')
                assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth')
                page.screenshot(path=str(output / f'list-{width}.png'), animations='disabled')
            page.evaluate("()=>{state.me={...state.me,admin:false,permissions:['view']};renderChatsList();}")
            assert page.locator('.chat-priority:not([disabled])').count() == 0
            page.evaluate('lock()')
            assert page.evaluate("()=>$('chat-search').value===''&&$('chat-list-state').value===''&&$('chats-list').childElementCount===0")
            assert not errors, errors
            browser.close()
    print('Chat list passed: search, type/state filters, sorting, keyed controls, shared priority and read-only state.')


if __name__ == '__main__':
    main()
