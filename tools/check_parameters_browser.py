"""Parameter drafts and field validation against a synthetic local workspace."""
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import (ROOT, RunningApp, launch_browser,
                           release_api_response, unlock)
from tgwitness import tuning


def open_reset(page):
    page.locator("#parameters-menu > summary").click()
    page.locator("#parameters-reset").click()
    expect(page.locator("#parameters-reset-dialog")).to_be_visible()


def hold_parameter_save(page):
    page.evaluate("""() => {
      window.acceptanceFetch=window.fetch;window.releaseAcceptanceResponse=null;
      window.fetch=async(...args)=>{
        const response=await window.acceptanceFetch(...args);
        if(args[1]?.method==='POST'&&String(args[0]).endsWith('/api/parameters'))
          await new Promise(resolve=>{window.releaseAcceptanceResponse=resolve;
            document.documentElement.dataset.acceptanceHeld='true';});
        return response;
      };
    }""")


def main():
    output = ROOT / "build" / "ux-review" / "after"
    for point in (21, 22, 23, 24):
        (output / str(point)).mkdir(parents=True, exist_ok=True)
    errors = []
    with tempfile.TemporaryDirectory(prefix="parameters-browser-") as scratch, RunningApp(
            Path(scratch)) as server, sync_playwright() as playwright:
        browser = launch_browser(playwright)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        page.on("pageerror", lambda error: errors.append(str(error)))
        unlock(page, server)
        page.evaluate("navigate('parameters')")
        page.evaluate("parametersReady")
        expect(page.locator("#parameters-groups .parameters-group")).to_have_count(8)
        expect(page.locator("#parameters-save")).to_be_disabled()
        for item in tuning.PARAMETERS:
            field = page.locator("#parameter-" + item.key)
            expect(field).to_have_count(1)
            if item.kind == "int":
                expect(field).to_have_attribute("min", str(item.low))
                expect(field).to_have_attribute("max", str(item.high))
        page.locator("#parameters-search").fill("MTProxy")
        expect(page.locator(".parameters-group:visible")).to_have_count(1)
        expect(page.locator("#parameters-group-proxies")).to_be_visible()
        page.locator("#parameters-search").fill("nothing matches this")
        expect(page.locator("#parameters-empty")).to_be_visible()
        page.locator("#parameters-clear-search").click()
        expect(page.locator("#parameters-search")).to_be_focused()
        nav = page.locator('[data-parameter-group="recheck"]')
        nav.focus()
        page.keyboard.press("Enter")
        expect(nav).to_have_attribute("aria-current", "location")
        assert page.locator("#parameters-group-recheck").bounding_box()["y"] >= (
            page.locator("#parameters-toolbar").bounding_box()["y"]
            + page.locator("#parameters-toolbar").bounding_box()["height"] - 1)

        page.locator("#parameter-dialog_limit").fill("5000")
        expect(page.locator("#parameter-dialog_limit-impact")).to_be_visible()
        page.locator("#parameter-recheck_max_chats").fill("0")
        expect(page.locator("#parameter-recheck_max_chats")).to_have_attribute("aria-invalid", "true")
        expect(page.locator("#parameter-recheck_max_chats-parameter-error")).to_contain_text("1 to 1,000")
        expect(page.locator("#parameters-save")).to_be_disabled()
        expect(page.locator("#parameters-unsaved")).to_contain_text("Fix 1 invalid")
        page.locator("#parameters-search").fill("Media")
        page.locator("#parameters-review-invalid").click()
        expect(page.locator("#parameter-recheck_max_chats")).to_be_focused()
        page.locator('[data-parameter-reset="recheck_max_chats"]').click()
        expect(page.locator("#parameter-recheck_max_chats")).to_have_value("30")
        expect(page.locator("#parameter-recheck_max_chats")).not_to_have_attribute("aria-invalid", "true")
        expect(page.locator("#parameters-change-count")).to_have_text("1 unsaved change")
        page.locator("#parameter-dialog_limit").focus()
        page.evaluate("loadParameters()")
        expect(page.locator("#parameter-dialog_limit")).to_have_value("5000")
        expect(page.locator("#parameter-dialog_limit")).to_be_focused()
        page.locator("#parameters-discard").click()
        expect(page.locator("#parameter-dialog_limit")).to_have_value("1000")

        # A newer server catalog can change labels/bounds without discarding this browser's edits.
        page.locator("#parameter-dialog_limit").fill("4100")
        page.locator("#parameter-dialog_limit").focus()
        catalog = page.evaluate("json('parameters')")
        catalog["groups"][0]["items"][0]["help"] += " Synthetic catalog update."
        page.route("**/api/parameters", lambda route: route.fulfill(content_type="application/json",
                   body=json.dumps(catalog)), times=1)
        page.evaluate("loadParameters()")
        expect(page.locator("#parameter-dialog_limit")).to_have_value("4100")
        expect(page.locator("#parameter-dialog_limit")).to_be_focused()
        page.locator("#parameter-heartbeat_seconds").fill("90")
        catalog["groups"][0]["items"] = [item for item in catalog["groups"][0]["items"]
                                        if item["key"] != "heartbeat_seconds"]
        page.route("**/api/parameters", lambda route: route.fulfill(content_type="application/json",
                   body=json.dumps(catalog)), times=1)
        page.evaluate("loadParameters()")
        expect(page.locator("#parameter-dialog_limit")).to_have_value("4100")
        expect(page.locator("#parameters-catalog-warning")).to_contain_text("90")
        expect(page.locator("#parameters-catalog-warning")).to_contain_text("not saved")
        page.evaluate("loadParameters()")
        page.locator("#parameters-discard").click()
        expect(page.locator("#parameters-catalog-warning")).to_be_hidden()
        expect(page.locator("#parameter-dialog_limit")).to_have_value("1000")

        # Python validates the pattern; its structured error is attached to the right field.
        page.locator("#parameter-dossier_patterns").fill("missing colon")
        page.locator("#parameters-save").click()
        expect(page.locator("#parameter-dossier_patterns-parameter-error")).to_contain_text("colon")
        expect(page.locator("#parameter-dossier_patterns")).to_be_focused()
        page.locator("#parameter-dossier_patterns").fill(r"Domain: [a-z]+\.test")
        page.locator("#parameter-dialog_limit").fill("2500")
        page.locator("#parameter-recheck_max_chats").fill("4")
        page.locator("#parameter-dossier_wallets").uncheck()
        hold_parameter_save(page)
        page.locator("#parameters-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.locator("#parameter-dialog_limit").fill("3500")
        page.locator("#parameter-dossier_wallets").check()
        release_api_response(page)
        expect(page.locator("#parameters-save")).to_be_enabled()
        expect(page.locator("#parameters-change-count")).to_have_text("2 unsaved changes")
        expect(page.locator("#parameter-dialog_limit")).to_have_value("3500")
        expect(page.locator("#parameter-dossier_wallets")).to_be_checked()
        saved = server.app.state.store.get_setting("parameters")
        assert saved["dialog_limit"] == 2500 and not saved["dossier_wallets"]
        page.locator("#parameters-discard").click()
        expect(page.locator("#parameter-dialog_limit")).to_have_value("2500")
        expect(page.locator("#parameter-dossier_wallets")).not_to_be_checked()
        open_reset(page)
        expect(page.locator("#parameters-reset-list li")).to_have_count(4)
        expect(page.locator("#parameters-reset-list")).to_contain_text("2500 chats")
        assert server.app.state.store.get_setting("parameters")["dialog_limit"] == 2500
        for theme in ("light", "dark"):
            page.locator("html").evaluate("(root,value)=>root.dataset.theme=value", theme)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 844})
                page.screenshot(path=str(output / "23" / f"defaults-{width}-{theme}.png"))
        page.locator("#parameters-reset-cancel").click()
        expect(page.locator("#parameter-dialog_limit")).to_have_value("2500")
        open_reset(page)
        page.locator("#parameters-reset-apply").click()
        expect(page.locator("#parameters-change-count")).to_have_text("4 unsaved changes")
        assert server.app.state.store.get_setting("parameters")["dialog_limit"] == 2500
        page.locator("#parameters-save").click()
        expect(page.locator("#parameters-change-count")).to_have_text("No unsaved changes")
        assert server.app.state.store.get_setting("parameters") == {}

        page.locator("#parameter-dialog_limit").fill("5000")
        page.locator("#parameter-startup_buffer").fill("20000")
        page.locator("#parameter-proxy_rotate_hours").fill("1")
        expect(page.locator("#parameter-proxy_rotate_hours-impact")).to_contain_text("reconnects")
        page.locator("#parameters-floodwait > summary").click()
        expect(page.locator("#parameters-floodwait p")).to_contain_text("Changing proxies does not remove")
        for theme in ("light", "dark"):
            page.locator("html").evaluate("(root,value)=>root.dataset.theme=value", theme)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 844})
                page.locator('[data-parameter-group="collection"]').click()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                page.screenshot(path=str(output / "21" / f"parameters-{width}-{theme}.png"))
                page.locator("#parameters-group-collection").screenshot(path=str(output / "24" / f"collection-{width}-{theme}.png"))
                page.locator("#parameter-recheck_max_chats").fill("0")
                page.locator("#parameters-group-recheck").screenshot(path=str(output / "22" / f"validation-{width}-{theme}.png"))
                page.locator('[data-parameter-reset="recheck_max_chats"]').click()
                page.locator("#parameters-group-proxies").screenshot(path=str(output / "24" / f"proxies-{width}-{theme}.png"))
        page.set_viewport_size({"width": 1440, "height": 1000})

        # A saved response in another view is applied on return, without losing newer edits.
        hold_parameter_save(page)
        page.locator("#parameters-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.locator("#parameter-dialog_limit").fill("6000")
        page.evaluate("navigate('observations')")
        release_api_response(page)
        expect(page.locator("#view-observations")).to_be_visible()
        page.evaluate("navigate('parameters')")
        expect(page.locator("#parameter-dialog_limit")).to_have_value("6000")
        expect(page.locator("#parameters-change-count")).to_have_text("1 unsaved change")
        second = page.evaluate("json('profiles',{label:'Parameters B'}).then(result=>result.id)")
        page.evaluate("loadProfiles()")
        hold_parameter_save(page)
        page.locator("#parameters-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.evaluate("id=>switchProfile(id)", second)
        release_api_response(page)
        expect(page.locator("#parameter-dialog_limit")).to_have_value("1000")
        expect(page.locator("#parameters-change-count")).to_have_text("No unsaved changes")
        assert server.app.state.profiles.entries[second]["app"].state.store.get_setting("parameters") is None
        token = page.evaluate("""id=>json('access/grants',{label:'Read-only parameters',permissions:['view'],
          workspaces:{[id]:null}},{root:true}).then(result=>result.token)""", second)
        readonly = browser.new_page(viewport={"width": 1440, "height": 1000})
        readonly.goto(server.url)
        readonly.locator("#panel-token").fill(token)
        readonly.get_by_role("button", name="Open workspace").click()
        expect(readonly.locator("#workspace")).to_be_visible()
        expect(readonly.locator('[data-view="parameters"]')).to_be_hidden()
        assert readonly.evaluate("""async()=>{try{await json('parameters',{values:{dialog_limit:999}});return 200;}
          catch(error){return error.status;}}""") == 403
        readonly.close()
        page.locator("#parameter-dialog_limit").fill("3000")
        hold_parameter_save(page)
        page.locator("#parameters-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.evaluate("lock()")
        release_api_response(page)
        expect(page.locator("#gate")).to_be_visible()
        expect(page.locator("#parameters-groups .parameter-row")).to_have_count(0)
        expect(page.locator("#parameters-save")).to_be_disabled()
        assert not errors, errors
        server.app.state.store.verify(server.app.state.vault.public_key)
        browser.close()
    print("Parameters: canonical bounds, keyboard search, inline errors, defaults, drafts, delayed replies and layouts passed.")


if __name__ == "__main__":
    main()
