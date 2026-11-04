"""Exercise participant observations using a synthetic local workspace."""
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock
from check_refresh_browser import hold_once


def main():
    with tempfile.TemporaryDirectory(prefix="people-timeline-") as scratch, RunningApp(Path(scratch)) as server:
        store, now = server.app.state.store, datetime.now(timezone.utc)
        for chat, name, uid in ((-1001, "First source", 91), (-1002, "Other source", 95)):
            store.set_target(chat, name, "supergroup", True)
            store.append("message.new", {"sender_id": uid, "sent_at": (now-timedelta(days=12)).isoformat(),
                "text": "Synthetic history", "sender_observation": {"display_name": name}}, chat, 1, uid)
        store.append("actor.profile", {"user_id": 91, "profile": {"display_name": "Renamed researcher", "username": "new_name"},
                     "source": "telegram_update"}, -1001, actor_id=91)
        store.append("actor.status", {"user_id": 91, "status": {"state": "online", "expires": (now+timedelta(minutes=5)).isoformat()},
                     "source": "telegram_update"}, -1001, actor_id=91)
        store.append("membership.service", {"action": {"_": "MessageActionChatAddUser", "users": [92, 93]}}, -1001, 2, 44)
        store.append("actor.profile", {"user_id": 93, "profile": {"display_name": "Deleted participant", "flags": {"deleted": True}},
                     "source": "received_entity"}, -1001, actor_id=93)
        store.append("membership.service", {"action": {"_": "MessageActionChatDeleteUser", "user_id": 92}}, -1001, 3, 44)
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            page.evaluate("async()=>{await navigate('chats');await openChat(-1001);}")
            page.locator('[data-chat-view="activity"]').click()
            rows = page.locator('.people-timeline tbody tr')
            expect(rows).to_have_count(3)
            expect(page.locator('[data-person-id="91"]')).to_have_text("Renamed researcher")
            expect(rows.filter(has_text="Renamed researcher")).to_contain_text("Online observed")
            expect(rows.filter(has_text="Renamed researcher")).to_contain_text("No recent messages observed")
            page.locator('[data-person-id="91"]').click()
            expect(page.locator('.people-timeline-events')).to_contain_text("First source")
            expect(page.locator('.people-timeline-events')).to_contain_text("Renamed researcher")
            expect(page.locator('.people-timeline-events')).to_contain_text("Status observed")
            expect(page.locator('.people-timeline')).to_contain_text("does not show which chat")
            page.get_by_role('button', name='Back to participants').click()
            page.locator('#people-timeline-filter').select_option('quiet')
            expect(rows).to_have_count(1)
            page.locator('#people-timeline-filter').select_option('departed')
            expect(rows).to_have_count(1)
            expect(rows).to_contain_text('Removed')
            page.locator('#people-timeline-filter').select_option('never_posted')
            expect(rows).to_have_count(2)
            page.locator('#people-timeline-filter').select_option('deleted')
            expect(rows).to_have_count(1)
            page.locator('[data-person-id="93"]').click()
            expect(page.locator('.people-timeline')).to_contain_text('exact deletion time are unknown')
            output = Path('build/ux-review/people-timeline')
            output.mkdir(parents=True, exist_ok=True)
            for width in (390, 1440):
                page.set_viewport_size({'width': width, 'height': 1000})
                page.evaluate("()=>document.querySelector('.chats-shell').dataset.panel='chat'")
                assert page.evaluate('()=>document.documentElement.scrollWidth<=innerWidth')
                page.screenshot(path=str(output / f'{width}.png'))
            page.get_by_role('button', name='Back to participants').click()
            page.locator('#people-timeline-filter').select_option('all')
            expect(rows).to_have_count(3)
            hold_once(page, '/api/chats/-1001/people?offset=0&limit=100&quiet_days=7&mode=all')
            page.locator('.people-timeline-toolbar').get_by_role('button', name='Refresh').click()
            expect(page.locator('html')).to_have_attribute('data-refresh-held', 'true')
            page.evaluate('()=>openChat(-1002)')
            page.locator('[data-chat-view="activity"]').click()
            expect(page.locator('[data-person-id="95"]')).to_have_text('Other source')
            page.evaluate('()=>window.releaseRefresh()')
            expect(page.locator('[data-person-id="91"]')).to_have_count(0)
            page.evaluate("()=>navigate('sources')")
            page.locator('#sources-tab-recording').click()
            expect(page.locator('#monitor-presence')).not_to_be_checked()
            expect(page.locator('#monitor-profiles')).to_be_checked()
            page.locator('#monitor-presence').check()
            page.locator('#recording-save').click()
            expect(page.locator('#recording-save')).to_be_disabled()
            assert store.get_setting('monitoring')['presence'] is True
            assert store.get_setting('monitoring')['profiles'] is True
            page.evaluate("async()=>{await navigate('chats');await openChat(-1001);}")
            expect(page.locator('.chat-mode-chips')).to_contain_text('Everything')
            page.evaluate('()=>lock()')
            expect(page.get_by_role('heading', name='Open your workspace')).to_be_visible()
            assert not page.evaluate("()=>document.querySelector('#chat-feed')?.textContent")
            assert not errors, errors
            browser.close()
    print('Participant timeline passed: profiles, presence, quiet/departed/deleted filters, source isolation, stale responses, recording settings, mobile layout and lock.')


if __name__ == '__main__':
    main()
