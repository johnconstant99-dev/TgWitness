import json
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, check_layout, launch_browser, unlock
from case_board_i18n import check_translations
from tgwitness import i18n
from tgwitness.access import Principal
from tgwitness.board import Board


def presentation_privacy():
    from check_browser import hold_api_response, release_api_response

    first_secret = 'sk-' + 'SYNTHETIC_FIRST_FIXTURE_123456789'
    second_secret = 'sk-' + 'SYNTHETIC_SECOND_FIXTURE_123456789'
    with tempfile.TemporaryDirectory(prefix='case-board-privacy-') as temporary, RunningApp(Path(temporary)) as server, sync_playwright() as playwright:
        store = server.app.state.store
        store.set_target(-100100, 'Synthetic privacy source', 'channel', True)
        service, admin = Board(store), Principal(True, 'Admin')
        first = store.append('message.new', {'text': 'Synthetic credential ' + first_secret,
            'raw': {'token': 'short-synthetic-fixture'}}, -100100, 1)
        second = store.append('message.new', {'text': 'Another synthetic credential ' + second_secret}, -100100, 2)
        for event in (first, second):
            service.append('bookmark', {'target': {'event_hash': event['hash']}}, admin)
        service.append('slice', {'query': {'chat_id': -100100, 'search': first_secret}}, admin)
        browser = launch_browser(playwright)
        page = browser.new_page(viewport={'width': 1280, 'height': 900}, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        unlock(page, server)
        page.evaluate("()=>navigate('board')")
        expect(page.locator('.board-feed .board-card')).to_have_count(3)
        assert first_secret not in page.locator('.board-feed').inner_text(), 'Normal cards must mask detected secrets'
        page.get_by_role('button', name='Presentation', exact=True).click()
        dialog = page.locator('.board-presentation')
        dialog.get_by_role('button', name='Source context', exact=True).click()
        source = dialog.locator('.board-source-json')
        expect(source.get_by_role('button', name='Show', exact=True)).to_be_visible()
        assert first_secret not in source.inner_text() and 'short-synthetic-fixture' not in source.inner_text(), 'Source JSON bypassed masking'
        assert first['hash'] in source.inner_text(), 'Masking must preserve source integrity metadata'
        reveals = lambda: [event for event in store.all_events() if event['kind'] == 'panel.secret_revealed']
        assert not reveals(), 'Merely opening source context must not reveal a secret'

        def reject_reveal(route):
            route.fulfill(status=503, json={'detail': 'Synthetic reveal audit failure'})
        page.route('**/api/privacy/reveal', reject_reveal)
        source.get_by_role('button', name='Show', exact=True).click()
        expect(source.locator('.secret-reveal-error')).to_be_visible()
        assert first_secret not in source.inner_text(), 'A failed reveal audit exposed source data'
        assert not reveals()
        page.unroute('**/api/privacy/reveal', reject_reveal)
        source.locator('.secret-reveal').click()
        expect(source.get_by_role('button', name='Hide', exact=True)).to_be_visible()
        assert first_secret in source.inner_text() and 'short-synthetic-fixture' in source.inner_text(), 'An explicitly audited reveal did not show the source'
        assert len(reveals()) == 1 and reveals()[0]['payload']['message_id'] == 1
        source.get_by_role('button', name='Hide', exact=True).click()
        assert first_secret not in source.inner_text()

        hold_api_response(page, '/api/privacy/reveal')
        page.evaluate("window.previousBoardReveal=document.querySelector('.board-source-json .secret-reveal')")
        source.get_by_role('button', name='Show', exact=True).click()
        expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
        dialog.get_by_role('button', name='Next', exact=True).click()
        expect(source).to_contain_text(second['hash'])
        release_api_response(page)
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        assert first_secret not in dialog.inner_text() and second_secret not in dialog.inner_text(), 'A stale reveal response exposed another presentation step'
        page.evaluate('()=>previousBoardReveal.click()')
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        assert len(reveals()) == 2, 'A detached reveal control sent a new audit request'
        dialog.get_by_role('button', name='Next', exact=True).click()
        expect(source.locator('code')).to_contain_text('search')
        assert first_secret not in source.inner_text(), 'A saved slice query bypassed presentation masking'
        expect(source.locator('.secret-reveal')).to_have_count(0)
        dialog.get_by_role('button', name='Previous', exact=True).click()
        expect(source).to_contain_text(second['hash'])
        hold_api_response(page, '/api/privacy/reveal')
        source.get_by_role('button', name='Show', exact=True).click()
        expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
        page.evaluate('()=>lock()')
        release_api_response(page)
        expect(page.locator('.board-presentation')).to_have_count(0)
        assert second_secret not in page.locator('body').inner_text(), 'A delayed reveal survived panel locking'
        assert store.all_events()[1]['hash'] == first['hash'] and store.all_events()[1]['payload'] == first['payload'], 'Presentation changed preserved source data'
        assert not errors, errors
        browser.close()
    print('Case Board source masking, audited reveal, failure/retry, stale controls and lock isolation PASS')


def main():
    print(check_translations())
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
            for lang in ('ru', 'de', 'ar'):
                words = json.loads((i18n.LOCALES / (lang + '.json')).read_text(encoding='utf-8'))
                def translated_count(key, count):
                    text = words[key]
                    if isinstance(text, dict):
                        form = page.evaluate('([lang,n])=>new Intl.PluralRules(lang).select(n)', [lang, count])
                        text = text.get(form, text['other'])
                    return text.replace('{n}', str(count))
                page.emulate_media(color_scheme='light')
                page.locator('.language-select:visible').select_option(lang)
                expect(page.locator('html')).to_have_attribute('lang', lang)
                expect(page.locator('html')).to_have_attribute('dir', 'rtl' if lang == 'ar' else 'ltr')
                expect(page.locator('#view-board h1')).to_have_text(words['Case Board'])
                page.reload()
                expect(page.locator('#view-board h1')).to_have_text(words['Case Board'])
                expect(page.locator('.board-feed .board-card')).to_have_count(7)
                expect(page.locator('.board-feed-heading > span').first).to_have_text(translated_count('{n} cards', 7))
                expect(page.locator(f'[data-card-id="{card["payload"]["id"]}"] .board-comment-count')).to_have_text(translated_count('{n} comments', 2))
                for key in ('Connect the observations. Keep your reasoning separate.', 'Private to this case. Nothing here is sent to Telegram.'):
                    assert words[key] != key, (lang, key, 'Untranslated prose')
                    expect(page.locator('#view-board')).to_contain_text(words[key])
                page.locator('.board-filters input[type=search]').fill('synthetic-no-matching-board-card')
                expect(page.locator('.board-empty h2')).to_have_text(words['Build a trail of reasoning'])
                page.locator('.board-filters input[type=search]').fill('')
                expect(page.locator('.board-feed .board-card')).to_have_count(7)
                page.locator('.board-heading').get_by_role('button', name=words['Slice by time'], exact=True).click()
                expect(page.locator('.board-dialog h2')).to_have_text(words['Save a range slice'])
                expect(page.locator('.board-dialog').get_by_role('button', name=words['Preview all actions'], exact=True)).to_be_visible()
                expect(page.locator('.board-kind-options')).to_contain_text(words['Messages, edits and deletions'])
                page.locator('.board-dialog').get_by_label(words['Chat IDs, separated by commas'], exact=True).fill('-100100')
                page.locator('.board-dialog').get_by_role('button', name=words['Preview all actions'], exact=True).click()
                expect(page.locator('.board-preview-summary > strong')).to_have_text(translated_count('{n} records', 4))
                page.locator('.board-dialog-heading').get_by_role('button', name=words['Close'], exact=True).click()
                for width in (320, 1600):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    check_layout(page)
                page.screenshot(path=str(output / f'board-{lang}.png'))
                page.emulate_media(color_scheme='dark')
                expect(page.locator('html')).to_have_attribute('data-theme','dark')
                check_layout(page)
                page.screenshot(path=str(output / f'board-{lang}-dark.png'))
            page.evaluate('()=>lock()')
            assert page.evaluate("()=>panelRoots.get('board').querySelector('.board-feed').textContent") == ''
            assert not errors, errors
            browser.close()
    print('Case Board bookmarks, Unicode highlights, Shift slices, live drafts/unread, comments, exact navigation, presentation, raw translation inventory, EN/RU/DE/AR, lock and responsive layouts PASS')


if __name__ == '__main__':
    main()
    presentation_privacy()
