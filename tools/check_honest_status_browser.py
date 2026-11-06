from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, navigate_panel, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="honest-status-") as scratch, RunningApp(Path(scratch)) as app:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", locale="en-US")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            now = datetime.now(timezone.utc)
            until = (now + timedelta(minutes=20)).isoformat()
            mode = {"running": True}

            def status(route):
                response = route.fetch()
                value = response.json()
                running = mode["running"]
                value["collector"].update(running=running, connected=running, has_session=True,
                                          phase="observing" if running else "paused")
                value["health"]["connection"].update(
                    state="degraded" if running else "off", reason="telegram_pause" if running else "paused",
                    telegram_pause_until=until, telegram_pause_method="messages.getHistory")
                value["health"]["intake"].update(state="failed" if running else "off",
                    reason="updates_diverted" if running else "paused", diverted_since=now.isoformat(),
                    last_heartbeat=now.isoformat())
                route.fulfill(response=response, json=value)

            def profiles(route):
                response = route.fetch()
                value = response.json()
                for profile in value["profiles"]:
                    profile["collector"].update(has_session=True, running=False, phase="offline",
                                                authorization_required=False)
                    profile["health"]["connection"].update(state="failed", reason="signed_out",
                                                           cause="session_duplicated")
                route.fulfill(response=response, json=value)

            page.route("**/api/status", status)
            unlock(page, app)
            expect(page.locator(".health-chip")).to_have_count(4)
            page.locator('[data-health-part="connection"]').click()
            part = page.locator("#health-part-connection")
            expect(part).to_contain_text("Telegram paused this account's requests until")
            expect(part).to_contain_text("(method messages.getHistory)")
            expect(part).to_contain_text("Observation waits and resumes on its own.")
            page.locator("#health-tab-intake").click()
            expect(page.locator("#health-part-intake")).to_contain_text(
                "Updates are going to another session: Telegram's update counter grows, but nothing reaches this one.")
            expect(page.locator('[data-health-part="intake"]')).to_have_attribute("data-state", "failed")
            page.keyboard.press("Escape")

            mode["running"] = False
            page.evaluate("()=>refreshStatus()")
            page.locator('[data-health-part="connection"]').click()
            expect(part).to_contain_text("Observation is paused.")
            expect(part).to_contain_text("(method messages.getHistory)")
            expect(part).not_to_contain_text("Observation waits")
            page.keyboard.press("Escape")

            page.route("**/api/profiles", profiles)
            navigate_panel(page, "connection")
            page.evaluate("()=>loadProfiles()")
            expect(page.locator('#profiles-list .target-row[data-profile="default"]')).to_contain_text("Sign-in required")
            expect(page.locator('#profiles-list .target-row[data-profile="default"]')).not_to_contain_text("offline")
            assert not errors, errors
            browser.close()
    print("Health dialog names the Telegram pause method and end time, shows diverted updates, and lost accounts "
          "read 'Sign-in required' in the workspace list PASS")


if __name__ == "__main__":
    main()
