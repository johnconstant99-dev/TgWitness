"""Account recovery actions distinguish rejected sessions, paused accounts and transport failures."""
import copy
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="account-states-") as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", locale="en-US")
            errors, changes = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            for label in ("Expired account", "Paused account", "Connection failed", "Collecting account", "Reconnecting account"):
                page.evaluate("label=>json('profiles',{label},{root:true})", label)
            base = page.evaluate("()=>json('profiles',undefined,{root:true})")
            status = page.evaluate("()=>json('status',undefined,{root:true})")
            profiles = copy.deepcopy(base["profiles"])
            scenarios = (
                ("empty", False, False, False, "offline", False),
                ("sign_in", True, False, False, "authorization_required", True),
                ("paused", True, False, False, "paused", False),
                ("failed", True, False, False, "resume_failed", False),
                ("collecting", True, True, True, "observing", False),
                ("reconnecting", True, True, False, "reconnecting", False),
            )
            for record, (kind, saved, running, connected, phase, required) in zip(profiles, scenarios):
                record.update(sources_enabled=1, sources_total=1)
                record["collector"].update(has_session=saved, running=running, connected=connected, phase=phase,
                    authorization_required=required, last_error="TimeoutError" if kind == "failed" else None)
                for part in ("connection", "intake", "sources", "media"):
                    record["health"][part].update(state="off", reason="paused")
                record["health"]["state"] = "off"
                if kind in ("sign_in", "failed", "reconnecting"):
                    record["health"]["connection"].update(state="failed" if kind != "reconnecting" else "degraded",
                        reason={"sign_in": "signed_out", "failed": "resume_failed", "reconnecting": "reconnecting"}[kind])
            page.route("**/api/profiles", lambda route: route.fulfill(json={**base, "profiles": profiles}))

            def current_status(route):
                profile_id = route.request.url.split("/profiles/", 1)[1].split("/", 1)[0] if "/profiles/" in route.request.url else "default"
                profile = next(item for item in profiles if item["id"] == profile_id)
                route.fulfill(json={**status, "collector": profile["collector"], "health": profile["health"],
                    "targets": [{"chat_id": -1000000000123, "title": "Synthetic source", "enabled": True, "kind": "supergroup"}]})

            page.route("**/api/status", current_status)
            page.on("request", lambda request: changes.append(request.url) if request.method == "POST" and
                    ("/api/collector/" in request.url or "/api/auth/" in request.url) else None)
            page.evaluate("()=>navigate('accounts')")
            expect(page.locator('[data-count="workspaces"] strong')).to_have_text("6")
            for counter in ("collecting", "sign_in", "empty", "paused"):
                expect(page.locator(f'[data-count="{counter}"] strong')).to_have_text("1")

            cards = {scenario[0]: page.locator(f'.account-card[data-profile="{record["id"]}"]')
                     for record, scenario in zip(profiles, scenarios)}
            for kind, card in cards.items():
                expect(card).to_have_attribute("data-account-state", kind)
            expect(cards["sign_in"].locator('[data-action="connect"]')).to_have_text("Sign in again")
            expect(cards["sign_in"].locator('[data-action="toggle"]')).to_be_hidden()
            expect(cards["sign_in"].locator('[data-field="observation"] dd')).to_have_text("Sign-in required")
            expect(cards["empty"].locator('[data-action="connect"]')).to_be_visible()
            expect(cards["paused"].locator('[data-action="toggle"]')).to_be_enabled()
            expect(cards["failed"].locator('[data-action="toggle"]')).to_be_enabled()
            expect(cards["failed"].locator('[data-action="connect"]')).to_have_count(0)
            expect(cards["failed"].locator('[data-field="observation"] dd')).to_have_text("Needs attention")

            # Starting a replacement login does not invalidate a still-valid saved session.
            profiles[2]["collector"]["phase"] = "login_required"
            page.evaluate("()=>loadProfiles()")
            expect(cards["paused"]).to_have_attribute("data-account-state", "paused")
            expect(page.locator('[data-count="sign_in"] strong')).to_have_text("1")
            profiles[2]["collector"]["phase"] = "paused"

            # Counters are keyboard-operable filters; expired sessions must not enter batch Start.
            page.locator('[data-count="sign_in"]').focus()
            page.keyboard.press("Enter")
            expect(page.locator(".account-card:visible")).to_have_count(1)
            page.locator("#accounts-select-page").check()
            expect(page.locator("#accounts-resume")).to_be_disabled()
            expect(page.locator("#accounts-pause")).to_be_disabled()
            page.locator('[data-count="paused"]').click()
            expect(page.locator(".account-card:visible")).to_have_count(1)
            expect(cards["paused"]).to_be_visible()
            page.locator('[data-count="workspaces"]').click()
            assert page.evaluate("""async()=>{const button=document.querySelector('[data-count="paused"]');
              button.focus();await loadProfiles();return button.isConnected&&document.activeElement===button;}""")

            # Recovery stays in the original workspace and opens sign-in without replaying a mutation.
            cards["sign_in"].locator('[data-action="connect"]').click()
            expect(page.locator("#view-connection")).to_be_visible()
            expect(page.locator("#credentials-form")).to_be_visible()
            expect(page.locator("#authorized-state")).to_be_hidden()
            assert page.evaluate("state.profile") == profiles[1]["id"]
            assert not changes, "Recovery navigation dispatched an authentication or collector mutation"

            # Strings resembling an authorization error do not override structured transport state.
            profiles[3]["collector"]["last_error"] = "Telegram authorization expired. Sign in again."
            page.evaluate("()=>navigate('accounts')")
            expect(cards["failed"]).to_have_attribute("data-account-state", "failed")
            expect(cards["failed"].locator('[data-action="connect"]')).to_have_count(0)
            # A newly validated session removes the recovery action without clearing the workspace.
            profiles[1]["collector"].update(authorization_required=False, phase="ready")
            profiles[1]["health"]["connection"].update(state="off", reason="paused")
            page.evaluate("()=>loadProfiles()")
            expect(page.locator('[data-count="sign_in"] strong')).to_have_text("0")
            expect(page.locator('[data-count="paused"] strong')).to_have_text("2")
            expect(cards["sign_in"].locator('[data-action="connect"]')).to_have_count(0)
            page.set_viewport_size({"width": 390, "height": 900})
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
            assert not errors, errors
            browser.close()
    print("Account states: expired/paused/empty/transport states, recovery route, safe batch actions and counter filters PASS")


if __name__ == "__main__":
    main()
