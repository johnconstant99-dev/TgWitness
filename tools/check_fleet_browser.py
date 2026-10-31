"""Bulk account import, groups and shared proxies with synthetic sessions."""
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import (ROOT, RunningApp, hold_api_response, launch_browser,
                           release_api_response, unlock)
from test_collector import saved_session
from check_fleet_async_browser import main as check_async_groups


def account_files(name, api_id):
    return [
        {"name": name + ".txt", "mimeType": "text/plain", "buffer": saved_session().encode()},
        {"name": name + ".json", "mimeType": "application/json",
         "buffer": json.dumps({"api_id": api_id, "api_hash": "a" * 32}).encode()},
    ]


def main():
    output = ROOT / "test-results" / "fleet-browser"
    output.mkdir(parents=True, exist_ok=True)
    errors, imported = [], []
    with tempfile.TemporaryDirectory(prefix="fleet-browser-") as scratch, RunningApp(
            Path(scratch)) as server, sync_playwright() as p:
        browser = launch_browser(p)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.on("request", lambda req: imported.append(req.url) if req.url.endswith("/api/profiles/import") else None)
        unlock(page, server)
        page.locator('[data-view="accounts"]').click()
        page.locator("#fleet-import-open").click()
        page.locator("#fleet-group").select_option("__new")
        page.locator("#fleet-group-name").fill("Investigation team")
        page.locator("#fleet-files").set_input_files([
            *account_files("alpha", 501), *account_files("beta", 502),
            {"name": "invalid.txt", "mimeType": "text/plain", "buffer": b"not a session"},
        ])
        expect(page.locator("#fleet-results li")).to_have_count(3)
        page.locator("#fleet-api").fill("wrong")
        page.locator("#fleet-import-start").click()
        expect(page.locator("#toast")).to_contain_text("API pair")
        assert not page.evaluate("json('profile-groups').then(r=>r.groups.length)")
        page.locator("#fleet-api").fill("")
        page.locator("#fleet-import-start").click()
        expect(page.locator("#fleet-results .ok")).to_have_count(2, timeout=30000)
        expect(page.locator("#fleet-results .bad")).to_have_count(1)
        expect(page.locator("#fleet-groups .fleet-group")).to_have_count(1)
        expect(page.locator(".account-card")).to_have_count(3)
        assert len(server.app.state.profiles.entries) == 3
        group = page.evaluate("json('profile-groups').then(r=>r.groups[0])")
        profiles = page.evaluate("json('profiles').then(r=>r.profiles)")
        alpha = next(item["id"] for item in profiles if item["label"] == "alpha")
        page.evaluate("json('parameters',{values:{snapshot_max:777}})")
        page.locator("#accounts-groups").evaluate("element=>element.open=true")
        page.locator(".fleet-group-settings summary").click()
        page.locator("#fleet-template-" + group["id"]).select_option("default")
        page.get_by_role("button", name="Save group settings", exact=True).click()
        page.get_by_role("button", name="Apply to members", exact=True).click()
        expect(page.locator("#toast")).to_contain_text("Settings copied to 2")
        assert all(server.app.state.profiles.entries[pid]["app"].state.store.get_setting("parameters")["snapshot_max"] == 777
                   for pid in group["members"])
        page.evaluate("async id=>{await json('profiles/'+id,{label:'Alpha renamed'},{root:true,method:'PATCH'});await loadProfiles();}", alpha)
        expect(page.locator('.account-card[data-profile="' + alpha + '"] h2')).to_have_text("Alpha renamed")
        expect(page.locator(".account-card")).to_have_count(3)
        page.locator("#fleet-import-close").click()
        for width in (1440, 390, 320):
            page.set_viewport_size({"width": width, "height": 1000})
            page.screenshot(path=str(output / ("groups-" + str(width) + ".png")), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (width, page.evaluate("[...document.querySelectorAll('*')].filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,id:e.id,cls:e.className,right:e.getBoundingClientRect().right})).slice(-15)"))

        page.set_viewport_size({"width": 1440, "height": 1000})
        page.locator("#fleet-import-open").click()
        page.locator("#fleet-group").select_option(group["id"])
        page.locator("#fleet-files").set_input_files([*account_files("gamma", 503), *account_files("delta", 504)])
        page.locator("#fleet-passcode").fill("temporary passcode")
        before = len(imported)
        hold_api_response(page, "/api/profiles/import")
        page.locator("#fleet-import-start").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        expect(page.locator("#fleet-group")).to_be_disabled()
        expect(page.locator("#fleet-import-close")).to_be_disabled()
        page.locator("#top-lock").click()
        expect(page.locator("#fleet-passcode")).to_have_value("")
        expect(page.locator("#fleet-api")).to_have_value("")
        release_api_response(page)
        page.locator("#panel-token").fill(server.app.state.vault.token)
        page.locator("#unlock-form button").click()
        expect(page.locator("#unlock-form button")).to_be_enabled()
        expect(page.locator("#workspace")).to_be_visible()
        page.locator('[data-view="accounts"]').click()
        expect(page.locator(".account-card")).to_have_count(4)
        assert len(imported) == before + 1, "Locking must stop the remaining import queue"
        assert not any(e["label"] == "delta" for e in server.app.state.profiles.entries.values())

        page.locator("#profile-select").select_option(alpha)
        expect(page.locator("#workspace")).to_have_js_property("inert", False)
        expect(page.locator("#workspace")).to_be_visible()
        page.locator('[data-view="connection"]').click()
        if page.locator("#entry-settings").get_attribute("aria-expanded") != "true":
            page.locator("#entry-settings").click()
        page.locator("#proxy-pool > summary").click()
        page.locator("#pool-sources summary").first.click()
        page.locator(".pool-paste summary").click()
        page.locator("#pool-paste").fill("tg://proxy?server=7.7.7.7&port=443&secret=" + "a7" * 16)
        page.locator("#pool-paste-add").click()
        expect(page.locator("#pool-own .pool-source-item")).to_have_count(1)
        page.locator("#pool-search").fill("7.7.7.7")
        expect(page.locator("#pool-rows .pool-row")).to_have_count(1)
        page.locator("#pool-rows button").click()
        expect(page.locator("#route-detail")).to_contain_text("7.7.7.7")
        assert server.app.state.profiles.entries[alpha]["app"].state.collector.network_config().host == "7.7.7.7"
        for width in (1440, 390, 320):
            page.set_viewport_size({"width": width, "height": 1000})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), width
            page.screenshot(path=str(output / ("proxies-" + str(width) + ".png")), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.locator('[data-view="accounts"]').click()
        page.locator("#fleet-import-open").click()
        page.locator("#fleet-files").set_input_files(account_files("finished", 505))
        page.locator("#fleet-import-start").click()
        expect(page.locator("#fleet-results .ok")).to_have_count(1)
        expect(page.locator("#fleet-import-close")).to_be_enabled()
        expect(page.locator("#fleet-import-start")).to_be_disabled()
        assert not errors, errors
        browser.close()
    check_async_groups()
    print("Fleet passed: bulk imports, failure cleanup, group settings, fresh cards, lock isolation, shared proxies and mobile layout.")


if __name__ == "__main__":
    main()
