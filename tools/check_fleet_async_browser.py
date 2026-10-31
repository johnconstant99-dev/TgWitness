"""Group form drafts and pending writes survive asynchronous account refreshes."""
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import (RunningApp, hold_api_response, launch_browser,
                           release_api_response, unlock)


def main(fleet_source=None):
    with tempfile.TemporaryDirectory(prefix="fleet-async-") as scratch, RunningApp(
            Path(scratch)) as server, sync_playwright() as p:
        browser = launch_browser(p)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        if fleet_source is not None:
            page.route("**/fleet.js*", lambda route: route.fulfill(body=fleet_source, content_type="text/javascript"))
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        unlock(page, server)
        expect(page.locator("#unlock-form button")).to_be_enabled()
        profile = page.evaluate("json('profiles',{label:'Second account'},{root:true})")
        group = page.evaluate("json('profile-groups',{label:'Case team',template:'default'},{root:true}).then(r=>r.groups[0])")
        page.locator('[data-view="accounts"]').click()
        page.evaluate("loadProfiles()")
        panel = page.locator(".fleet-group-settings")
        template = page.locator("#fleet-template-" + group["id"])
        reports = panel.locator('input[value="reports"]')
        panel.locator("summary").click()
        template.select_option(profile["id"])
        reports.uncheck()
        template.focus()
        page.evaluate("loadProfiles()")
        expect(template).to_have_value(profile["id"])
        expect(reports).not_to_be_checked()
        expect(panel).to_have_attribute("open", "")
        expect(template).to_be_focused()
        assert page.locator(".account-card").count() == 2

        # A failed poll must retain the last good groups and the unsaved form.
        page.route("**/api/profile-groups", lambda route: route.fulfill(
            status=503, json={"detail": "Synthetic group refresh failure"}))
        page.evaluate("TgWitnessFleet.load()")
        expect(template).to_have_value(profile["id"])
        expect(reports).not_to_be_checked()
        expect(page.locator("#toast")).to_contain_text("Synthetic group refresh failure")
        page.unroute("**/api/profile-groups")

        # The first response is delayed after the server has produced it.
        page.evaluate("""() => {
          const real=window.fetch;let held=false;
          window.releaseOldGroups=null;
          window.fetch=async(...args)=>{
            const result=await real(...args);
            if(!held&&String(args[0]).endsWith('/api/profile-groups')){
              held=true;await new Promise(resolve=>window.releaseOldGroups=resolve);
            }
            return result;
          };
          window.restoreGroupFetch=()=>window.fetch=real;
          window.oldGroups=TgWitnessFleet.load();
        }""")
        page.wait_for_function("() => window.releaseOldGroups !== null")
        page.evaluate("async id=>{await json('profile-groups/'+id,{label:'Fresh case name',template:'default'},{root:true,method:'PATCH'});await TgWitnessFleet.load();}", group["id"])
        page.evaluate("async()=>{window.releaseOldGroups();await window.oldGroups;window.restoreGroupFetch();}")
        expect(page.locator(".fleet-group-head h2")).to_contain_text("Fresh case name")
        expect(template).to_have_value(profile["id"])

        hold_api_response(page, "/api/profile-groups/" + group["id"])
        save = panel.get_by_role("button", name="Save group settings", exact=True)
        save.click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        expect(template).to_be_disabled()
        page.evaluate("loadProfiles()")
        expect(save).to_be_disabled()
        expect(template).to_have_value(profile["id"])
        release_api_response(page)
        expect(save).to_be_enabled()
        saved = page.evaluate("json('profile-groups').then(r=>r.groups[0])")
        assert saved["template"] == profile["id"]
        assert "reports" not in saved["sections"]
        assert saved["label"] == "Fresh case name"

        # A failed move restores the last server-confirmed selection.
        move = page.locator('.account-card[data-profile="' + profile["id"] + '"] .fleet-card-group')
        move_path = "**/api/profiles/" + profile["id"] + "/group"
        page.route(move_path, lambda route: route.fulfill(status=503, json={"detail": "Synthetic move failure"}))
        move.select_option(group["id"])
        expect(page.locator("#toast")).to_contain_text("Synthetic move failure")
        expect(move).to_have_value("")
        expect(move).to_be_enabled()
        page.unroute(move_path)
        hold_api_response(page, "/api/profiles/" + profile["id"] + "/group")
        move.select_option(group["id"])
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        expect(move).to_be_disabled()
        page.evaluate("loadProfiles()")
        expect(move).to_be_disabled()
        release_api_response(page)
        expect(move).to_have_value(group["id"])
        expect(move).to_be_enabled()
        assert page.locator(".fleet-group .account-card").count() == 1

        # Responses from different moves may arrive in the opposite order.
        third = page.evaluate("json('profiles',{label:'Third account'},{root:true})")
        page.evaluate("loadProfiles()")
        other = page.locator('.account-card[data-profile="' + third["id"] + '"] .fleet-card-group')
        hold_api_response(page, "/api/profiles/" + profile["id"] + "/group")
        move.select_option("")
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        other.select_option(group["id"])
        expect(other).to_be_enabled()
        release_api_response(page)
        expect(move).to_be_enabled()
        expect(other).to_have_value(group["id"])
        assert page.locator(".fleet-group .account-card").count() == 1

        # Successful saves become the new baseline; later polls may update it.
        page.evaluate("async id=>{await json('profile-groups/'+id,{label:'Fresh case name',template:'default',sections:['parameters','reports']},{root:true,method:'PATCH'});await loadProfiles();}", group["id"])
        expect(template).to_have_value("default")
        expect(reports).to_be_checked()
        template.select_option(profile["id"])
        page.locator("#top-lock").click()
        page.locator("#panel-token").fill(server.app.state.vault.token)
        page.locator("#unlock-form button").click()
        expect(page.locator("#workspace")).to_be_visible()
        expect(page.locator("#unlock-form button")).to_be_enabled()
        page.locator('[data-view="accounts"]').click()
        expect(template).to_have_value("default")
        expect(panel).not_to_have_attribute("open", "")
        page.evaluate("""() => {
          const real=window.fetch;let held=false;
          window.releaseGroupCreate=null;
          window.fetch=async(...args)=>{
            const result=await real(...args);
            if(!held&&String(args[0]).endsWith('/api/profile-groups')&&args[1]?.method==='POST'){
              held=true;await new Promise(resolve=>window.releaseGroupCreate=resolve);
            }
            return result;
          };
          window.restoreGroupFetch=()=>window.fetch=real;
        }""")
        page.once("dialog", lambda dialog: dialog.accept("Queued case"))
        page.locator("#fleet-group-new").click()
        page.wait_for_function("() => window.releaseGroupCreate !== null")
        page.evaluate("loadProfiles()")
        expect(page.locator("#fleet-group-new")).to_be_disabled()
        page.evaluate("()=>{window.releaseGroupCreate();window.restoreGroupFetch();}")
        expect(page.locator("#fleet-group-new")).to_be_enabled()
        expect(page.locator(".fleet-group-head h2", has_text="Queued case")).to_have_count(1)
        assert not errors, errors
        browser.close()
    print("Fleet async passed: drafts, focus, refresh errors, latest groups, overlapping saves/moves and lock cleanup.")


if __name__ == "__main__":
    main()
