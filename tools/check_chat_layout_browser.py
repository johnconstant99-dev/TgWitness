"""Chat list and conversation scroll independently across tablet and phone widths."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.check_browser import RunningApp, launch_browser, unlock


def layout(page):
    return page.evaluate("""()=>{
      const list=document.querySelector('.chats-sidebar'),feed=document.querySelector('#chat-feed'),
        header=document.querySelector('.chat-header'),search=document.querySelector('.chat-search');
      return {width:innerWidth,height:innerHeight,documentHeight:document.documentElement.scrollHeight,
        documentWidth:document.documentElement.scrollWidth,listVisible:list.checkVisibility(),
        feedHeight:feed.clientHeight,headerTop:header.getBoundingClientRect().top,
        searchTop:search.getBoundingClientRect().top,windowY:scrollY};
    }""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--before', action='store_true')
    args = parser.parse_args()
    output = ROOT / 'build/ux-review' / ('before' if args.before else 'after') / '11-chats'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='chat-layout-') as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        for number in range(1, 22):
            cid = -1000 - number
            store.set_target(cid, f'Research channel {number:02d}', 'supergroup', True)
            for message_id in range(1, 101 if number == 1 else 3):
                store.append('message.new', {'text': f'Observed message {message_id}: evidence stays in this workspace.',
                             'sender_id': 44, 'sender_observation': {'id': 44, 'display_name': 'Synthetic author'}},
                             cid, message_id, 44)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, results = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("async()=>{await navigate('chats');await openChat(-1001);}")
            expect(page.locator('#chat-feed .msg').first).to_be_visible()
            for theme in ('light', 'dark'):
                page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                for width, height in ((1440, 1000), (800, 1000), (768, 1000), (767, 844), (390, 844), (320, 720)):
                    page.set_viewport_size({'width': width, 'height': height})
                    page.evaluate("()=>{document.querySelector('.chats-shell').dataset.panel='chat';scrollTo(0,0);}")
                    original = layout(page)
                    page.evaluate("()=>{document.querySelector('#chat-feed').scrollTop=200;}")
                    scrolled = layout(page)
                    original['theme'] = theme
                    original['url'] = page.url
                    original['headerMoved'] = abs(scrolled['headerTop'] - original['headerTop']) > 1
                    if not args.before:
                        assert original['documentWidth'] <= width + 1, original
                        assert original['documentHeight'] <= height + 1, original
                        assert original['feedHeight'] >= 100, original
                        assert not original['headerMoved'], original
                        assert original['listVisible'] == (width >= 768), original
                    if width >= 768:
                        page.evaluate("()=>document.querySelector('#chats-list').scrollTop=180")
                        after_list = layout(page)
                        if not args.before:
                            assert abs(after_list['searchTop'] - original['searchTop']) <= 1, after_list
                            assert after_list['windowY'] == 0, after_list
                    else:
                        page.locator('#chat-back').click()
                        expect(page.locator('#chat-search')).to_be_focused()
                        expect(page.locator('.chats-sidebar')).to_be_visible()
                        expect(page.locator('.chat-pane')).to_be_hidden()
                        page.locator('#chat-search').fill('Research channel 01')
                        page.locator('#chats-list .chat-item').click()
                        expect(page.locator('.chat-pane')).to_be_visible()
                        expect(page.locator('#chat-feed .msg').first).to_be_visible()
                        page.locator('#chat-search').evaluate("element=>{element.value='';element.dispatchEvent(new Event('input',{bubbles:true}));}")
                    if width in (1440, 390):
                        page.evaluate("()=>{document.querySelector('#chats-list').scrollTop=0;const feed=document.querySelector('#chat-feed');feed.scrollTop=feed.scrollHeight;}")
                        page.wait_for_function("""()=>{const feed=document.querySelector('#chat-feed'),bounds=feed.getBoundingClientRect();
                          return [...feed.querySelectorAll('.msg')].some(message=>{const rect=message.getBoundingClientRect();
                            return rect.bottom>bounds.top&&rect.top<bounds.bottom;});}""")
                        page.screenshot(path=str(output / f'chats-{width}-{theme}.png'), animations='disabled')
                    results.append(original)
            assert not errors, errors
            browser.close()
    (output / 'layout.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print('Chat layout baseline captured.' if args.before else 'Chat layout passed: independent scroll, stationary headers, tablet columns and phone navigation.')


if __name__ == '__main__':
    main()
