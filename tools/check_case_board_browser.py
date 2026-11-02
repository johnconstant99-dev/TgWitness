"""Synthetic Case Board workflow, exact highlights, threads, slices, scopes and responsive UI."""
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, check_layout, launch_browser, unlock
from tgwitness.access import Principal
from tgwitness.board import Board


def main():
    output = Path("test-results/case-board")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-board-browser-") as temporary, RunningApp(Path(temporary)) as server:
        store = server.app.state.store
        store.set_setting("demo", False)
        store.set_target(-100100, "Meridian · Project discussion", "channel", True)
        event = store.append("message.new", {"text": "Delivery 😀 confirmed. Review the amended schedule before Friday.",
            "sender_id": 101, "sender_observation": {"display_name": "Alex Morgan"}}, -100100, 10, actor_id=101)
        store.append("message.edited", {"text": "Delivery 😀 postponed. Review the amended schedule before Friday.", "sender_id": 101}, -100100, 10)
        store.append("membership.update", {"user_id": 102}, -100100, actor_id=101)
        store.append("message.new", {"text": "Keep the original schedule with the amendment.", "sender_id": 102}, -100100, 11, actor_id=102)
        service, admin = Board(store), Principal(True, "Admin")
        collection = service.append("collection", {"title": "01 · Delivery timeline", "description": "Fictional training case. Observations and team interpretation are kept separate.", "chat_ids": [-100100]}, admin)
        card = service.append("bookmark", {"target": {"event_hash": event["hash"]}, "title": "Original delivery commitment", "labels": ["timeline", "review"], "note": "Compare the initial commitment with the preserved edit. This is an analyst note."}, admin)
        service.append("move", {"card_id": card["payload"]["id"], "collection_id": collection["payload"]["id"]}, admin)
        service.append("highlight", {"target": {"event_hash": event["hash"]}, "range": {"start": 9, "length": 1, "quote": "😀"}, "title": "Exact Unicode selection", "note": "One Unicode code point, tied to the first saved version."}, admin)
        slice_ = service.append("slice", {"query": {"chat_id": -100100}, "title": "Every recorded action in the source"}, admin)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1600, "height": 1100}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("async()=>{await navigate('chats');await openChat(-100100);}")
            expect(page.locator('#msg-10')).to_be_visible()
            page.locator('#msg-10').get_by_role('button', name='To board', exact=True).click()
            expect(page.locator('#toast')).to_contain_text('Added to Case Board')
            page.locator('#msg-10 .bubble-text').evaluate("""el=>{
              const walker=document.createTreeWalker(el,NodeFilter.SHOW_TEXT);let node;
              while(node=walker.nextNode()){const at=node.textContent.indexOf('😀');if(at<0)continue;
                const range=document.createRange();range.setStart(node,at);range.setEnd(node,at+2);
                const selection=getSelection();selection.removeAllRanges();selection.addRange(range);
                el.dispatchEvent(new MouseEvent('mouseup',{bubbles:true}));break;}
            }""")
            page.get_by_role('button',name='Highlight → board',exact=True).click()
            page.locator('.board-dialog').get_by_label('Note',exact=True).fill('Unicode selection created from the current saved edit.')
            page.locator('.board-dialog').get_by_role('button',name='Add to board',exact=True).click()
            expect(page.locator('.board-dialog')).to_have_count(0)
            page.evaluate('getSelection().removeAllRanges()')
            page.locator('#msg-10 .bubble-text').click(modifiers=['Shift'])
            page.locator('#msg-11 .bubble-text').click(modifiers=['Shift'])
            expect(page.locator('.board-dialog')).to_be_visible()
            page.get_by_role('button',name='Preview all actions',exact=True).click()
            expect(page.locator('.board-preview-summary')).to_contain_text('message.edited')
            page.locator('.board-dialog').get_by_role('button',name='Add to board',exact=True).click()
            expect(page.locator('.board-dialog')).to_have_count(0)
            page.evaluate("()=>navigate('board')")
            expect(page.locator('.board-feed .board-card')).to_have_count(6)
            page.locator(f'[data-card-id="{card["payload"]["id"]}"] .board-card-actions').get_by_role('button', name='Comment', exact=True).click()
            page.locator('.board-comment-form textarea').fill('Follow-up: check the next preserved version, not a screenshot.')
            service.append('comment', {'parent_id':card['payload']['id'],'text':'Live update from another investigation session.'},admin)
            expect(page.locator('.board-comments')).to_contain_text('Live update from another', timeout=15000)
            expect(page.locator('.board-comment-form textarea')).to_have_value('Follow-up: check the next preserved version, not a screenshot.')
            page.get_by_role('button', name='Post comment', exact=True).click()
            expect(page.locator('.board-comments')).to_contain_text('Follow-up: check')
            page.locator('.board-thread-heading').get_by_role('button', name='Close').click()
            page.locator(f'[data-card-id="{slice_["payload"]["id"]}"] .board-card-actions').get_by_role('button', name='Open', exact=True).click()
            expect(page.locator('#board-slice-context')).to_contain_text('Every recorded action')
            expect(page.locator('#events-body')).to_contain_text('Participant update')
            service.append('bookmark', {'target':{'event_hash':event['hash']}, 'title':'Live bookmark while viewing the journal'},admin)
            expect(page.locator('#board-unread')).to_be_visible(timeout=15000)
            page.evaluate("()=>navigate('board')")
            expect(page.locator('.board-feed .board-card')).to_have_count(7)
            for width in (1600, 1024, 390, 320):
                page.set_viewport_size({"width": width, "height": 1100 if width > 1000 else 844})
                page.evaluate('scrollTo(0,0)')
                page.screenshot(path=str(output / f'board-{width}.png'))
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), width
            page.set_viewport_size({"width": 1600, "height": 1100})
            page.get_by_role('button', name='Presentation', exact=True).click()
            expect(page.locator('.board-presentation')).to_be_visible()
            expect(page.locator('.board-presentation .board-card-actions')).to_have_count(0)
            page.locator('.board-dialog-heading').get_by_role('button', name='Close').click()
            page.locator('.language-select:visible').select_option('ru')
            expect(page.locator('#view-board h1')).to_have_text('Доска дела')
            page.reload()
            expect(page.locator('#view-board h1')).to_have_text('Доска дела')
            expect(page.locator('.board-feed .board-card')).to_have_count(7)
            page.screenshot(path=str(output / 'board-ru.png'))
            check_layout(page)
            page.emulate_media(color_scheme='dark')
            expect(page.locator('html')).to_have_attribute('data-theme','dark')
            check_layout(page)
            page.screenshot(path=str(output / 'board-dark.png'))
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>panelRoots.get('board').querySelector('.board-feed').textContent") == ''
            assert not errors, errors
            browser.close()
    print('Case Board bookmarks, Unicode highlights, Shift slices, live drafts/unread, comments, exact navigation, presentation, EN/RU, lock and 4 responsive layouts PASS')


if __name__ == '__main__':
    main()
