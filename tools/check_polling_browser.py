"""Polling must update saved facts without replacing controls or losing local drafts."""
import json
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, hold_api_response, launch_browser, navigate_panel, release_api_response, unlock
from tgwitness import dossier


def main():
    output = Path("build/ux-review/after/03-polling")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="polling-check-") as scratch, RunningApp(Path(scratch)) as server:
        store = server.app.state.store
        store.set_target(-1001, "Synthetic investigation", "supergroup", True)
        first_seq = None
        for number in range(1, 81):
            record = store.append("message.new", {"text": f"Preserved invoice {number}", "sender_id": 44,
                         "sender_observation": {"id": 44, "display_name": "Synthetic author"}}, -1001, number, 44)
            if first_seq is None:
                first_seq = record["seq"]
        dossier.set_enabled(store, -1001, True)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors, captures = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            # Exercise refreshes deterministically, without a competing five-second timer.
            page.add_init_script("""(()=>{const set=window.setInterval;window.setInterval=(fn,ms,...args)=>
              ms===5000?0:set(fn,ms,...args);})();""")
            unlock(page, server)
            page.evaluate("()=>navigate('accounts')")
            expect(page.locator('.account-card[data-profile="default"] .fleet-card-group')).to_be_visible()
            assert page.evaluate("""async()=>{
              const card=document.querySelector('.account-card'),group=card.querySelector('.fleet-card-group'),
                rename=card.querySelector('[data-action=rename]'),option=document.querySelector('#profile-select option');
              group.focus();await loadProfiles();
              return card.isConnected&&group.isConnected&&rename.isConnected&&option.isConnected&&document.activeElement===group;
            }"""), "Account refresh replaced a control or its focused group selector"
            page.evaluate("""async()=>{
              const result=await json('profile-groups',{label:'Research group'},{root:true});
              await json('profiles/default/group',{group:result.groups[0].id},{root:true,method:'PUT'});await loadProfiles();
            }""")
            page.locator('#accounts-groups').evaluate("element=>element.open=true")
            page.locator('.fleet-group-settings').evaluate("element=>element.open=true")
            template = page.locator('.fleet-group-settings select')
            template.select_option("default")
            assert page.evaluate("""async()=>{const input=document.querySelector('.fleet-group-settings select');
              input.focus();const panel=input.closest('details');await loadProfiles();
              return input.isConnected&&panel.isConnected&&panel.open&&input.value==='default'&&document.activeElement===input;}"""), "Group settings draft moved or reset"
            store.append("message.new", {"text": "Updated count", "sender_id": 44}, -1001, 81, 44)
            page.evaluate("()=>loadProfiles()")
            expect(page.locator('.account-card[data-profile="default"] .account-meta')).to_contain_text(f"{store.stats()['total']} events")

            hold_api_response(page, "/api/access")
            page.evaluate("()=>{void navigate('access');}")
            page.wait_for_function("()=>typeof releaseAcceptanceResponse==='function'")
            page.locator('#access-label').fill("Unsaved analyst draft")
            release_api_response(page)
            page.wait_for_function("()=>state.access!==null")
            expect(page.locator('#access-label')).to_have_value("Unsaved analyst draft")
            page.locator('[data-access-tab=limits]').click()
            page.locator('#admin-idle').fill("42")
            page.locator('[data-access-tab=grants]').click()
            assert page.evaluate("""async()=>{const field=document.querySelector('#access-label');field.focus();field.setSelectionRange(3,9);
              await loadAccess();return document.activeElement===field&&field.selectionStart===3&&field.selectionEnd===9
                &&field.value==='Unsaved analyst draft'&&document.querySelector('#admin-idle').value==='42';}"""), "Access refresh erased a draft or selection"
            page.evaluate("async()=>{await navigate('accounts');await navigate('access');}")
            expect(page.locator('#access-label')).to_have_value("Unsaved analyst draft")
            expect(page.locator('#admin-idle')).to_have_value("42")
            page.locator('[data-access-tab=sessions]').click()
            expect(page.locator('#access-sessions-list .access-row').first).to_be_visible()
            assert page.evaluate("""async()=>{const row=document.querySelector('#access-sessions-list .access-row'),button=row.querySelector('button');
              button.focus();await loadAccess(true);return row.isConnected&&button.isConnected&&document.activeElement===button;}"""), "Session refresh replaced a live control"

            page.evaluate("()=>navigate('chats')")
            expect(page.locator('#chat-feed .msg').first).to_be_visible()
            assert page.evaluate("""async()=>{const row=document.querySelector('#chat-feed .msg'),filter=document.querySelector('[data-chat-filter=all]');
              filter.focus();await refreshChats(true);return row.isConnected&&filter.isConnected&&document.activeElement===filter;}"""), "Unchanged conversation or filter was recreated"
            page.locator('[data-chat-view="people"]').click()
            password = page.locator('#chat-feed input[type="password"]')
            expect(password).to_be_visible()
            password.fill("synthetic-unsaved-password")
            page.evaluate("()=>{window.savedPassword=document.querySelector('#chat-feed input[type=password]');savedPassword.focus();savedPassword.setSelectionRange(3,9);}")
            store.append("message.new", {"text": "A new observed message", "sender_id": 44}, -1001, 82, 44)
            page.evaluate("()=>refreshChats(true)")
            expect(page.locator('.people-table tbody tr td').nth(1)).to_have_text("82")
            assert page.evaluate("()=>savedPassword.isConnected&&document.activeElement===savedPassword&&savedPassword.selectionStart===3&&savedPassword.selectionEnd===9")
            expect(password).to_have_value("synthetic-unsaved-password")

            # A navigation-aborted read is expected cancellation; a real 503 remains an error.
            page.evaluate("()=>navigate('observations')")
            page.evaluate("""()=>{const original=window.fetch;window.fetch=async(...args)=>{
              const response=await original(...args);if(String(args[0]).includes('/api/events?'))await new Promise(resolve=>window.releaseRead=()=>{window.fetch=original;resolve();});
              return response;};window.pendingRead=refreshEvents().then(()=>null,error=>error.name);}""")
            page.wait_for_function("()=>typeof releaseRead==='function'")
            page.evaluate("()=>navigate('accounts')")
            assert page.evaluate("async()=>{releaseRead();return await pendingRead;}") == "StaleView"
            expect(page.locator('#toast.error')).to_be_hidden()
            page.route('**/api/access', lambda route: route.fulfill(status=503, json={"detail": "Synthetic temporary failure"}))
            page.evaluate("()=>navigate('access')")
            expect(page.locator('#toast.error')).to_contain_text("Synthetic temporary failure")
            page.unroute('**/api/access')

            # Source form values are read through their controller root even when detached.
            page.evaluate("()=>navigate('sources')")
            page.evaluate("()=>{for(const radio of $('scope-form').querySelectorAll('[name=scope-mode]'))radio.checked=radio.value==='account';}")
            page.evaluate("()=>navigate('chats')")
            assert page.evaluate("()=>scopeDraft().mode") == "account"
            page.evaluate("()=>{clearTimeout(toastTimer);show('toast',false);}")

            for width, height in ((1440, 1000), (390, 844)):
                page.set_viewport_size({"width": width, "height": height})
                navigate_panel(page, 'chats')
                if width == 390:
                    assert page.evaluate("()=>!document.activeElement.closest('[inert]')"), "Focus remained inside the closed mobile menu"
                page.locator('[data-chat-view="people"]').click()
                expect(page.locator('.people-table')).to_be_visible()
                page.screenshot(path=str(output / f"people-{width}.png"), animations="disabled")
                captures.append({"width": width, "url": page.url})

            page.evaluate("seq=>openRecord(seq)", first_seq)
            expect(page.locator('#detail-content')).to_contain_text('Preserved invoice')
            page.evaluate("lock()")
            assert page.evaluate("()=>$('detail-content').childElementCount===0&&$('chat-feed').childElementCount===0&&$('access-label').value===''")
            assert not errors, errors
            browser.close()
    (output / 'routes.json').write_text(json.dumps(captures, indent=2), encoding='utf-8')
    print('Polling checks passed: keyed controls, drafts, late responses, updated counts, conversation state and private cleanup.')


if __name__ == '__main__':
    main()
