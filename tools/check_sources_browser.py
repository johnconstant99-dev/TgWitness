"""Sources tabs and recording drafts against a synthetic local workspace."""
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import (ROOT, RunningApp, hold_api_response, launch_browser, navigate_panel,
                           release_api_response, unlock)
from tools.browser_fixtures import saved_session


def seed(server):
    store, vault = server.app.state.store, server.app.state.vault
    vault.save("credentials", {"api_id": 123, "api_hash": "a" * 32, "session": saved_session()})
    for number in range(21):
        store.set_target(-1000000001000 - number, "Investigation source " + str(number + 1).zfill(2),
                         "supergroup" if number % 3 else "channel", number % 4 != 0,
                         priority=number % 5 == 0)


def check_targets(page, server):
    output = ROOT / "build" / "ux-review" / "after" / "18"
    output.mkdir(parents=True, exist_ok=True)
    page.locator("#sources-tab-chats").click()
    rows = page.locator("#target-list tr")
    expect(rows).to_have_count(10)
    expect(page.locator("#target-page-count")).to_have_text("1–10 of 21")
    page.locator("#target-select-page").check()
    page.locator("#target-next").click()
    expect(page.locator("#target-selection-count")).to_have_text("10 selected")
    expect(page.locator("#target-page-count")).to_have_text("11–20 of 21")
    page.locator("#target-next").click()
    expect(rows).to_have_count(1)
    expect(rows.locator("strong")).to_have_text("Investigation source 21")
    page.locator("#target-selection-clear").click()
    page.locator("#target-search").fill("source 01")
    expect(rows).to_have_count(1)
    check = rows.locator(".source-select")
    check.check()
    check.focus()
    page.evaluate("refreshStatus()")
    expect(check).to_be_focused()
    expect(check).to_be_checked()
    page.locator("#target-bulk-action").select_option("enable")
    page.locator("#target-bulk-apply").click()
    expect(rows.locator(".source-state")).to_have_text("Enabled")
    expect(page.locator("#target-bulk-actions")).to_be_hidden()
    star = rows.locator('[data-source-action="star"]')
    expect(star).to_have_attribute("aria-pressed", "true")
    star.click()
    expect(star).to_have_attribute("aria-pressed", "false")
    page.locator("#target-search").fill("")
    page.locator("#target-kind").select_option("channels")
    expect(rows).to_have_count(7)
    page.locator("#target-sort").select_option("name-desc")
    expect(rows.locator("strong").first).to_have_text("Investigation source 19")
    page.locator("#target-select-matching").click()
    expect(page.locator("#target-selection-count")).to_have_text("7 selected")
    page.locator("#target-bulk-action").select_option("pause")
    page.locator("#target-bulk-apply").click()
    expect(page.locator("#target-card")).to_have_attribute("aria-busy", "false")
    assert rows.locator(".source-state").all_text_contents() == ["Paused"] * 7
    page.locator("#target-filter").select_option("enabled")
    expect(rows).to_have_count(0)
    expect(page.locator("#target-empty")).to_be_visible()
    page.locator("#target-clear-filters").click()
    page.locator("#target-sort").select_option("name")

    # A failed update keeps the selection and can be retried without another click per row.
    page.locator("#target-search").fill("source 02")
    page.locator("#target-select-page").check()
    page.locator("#target-bulk-action").select_option("priority")
    page.route("**/api/targets/batch", lambda route: route.fulfill(status=503,
               content_type="application/json", body='{"detail":"Try again"}'), times=1)
    page.locator("#target-bulk-apply").click()
    expect(page.locator("#source-action-result")).to_have_text("Try again")
    expect(page.locator("#target-selection-count")).to_have_text("1 selected")
    page.locator("#target-bulk-apply").click()
    expect(rows.locator('[data-source-action="star"]')).to_have_attribute("aria-pressed", "true")

    # Exclusions merge into a newer unsaved Scope draft instead of replacing it.
    page.evaluate("""async()=>{await json('scope',{...state.status.scope,mode:'account',acknowledged:true});
        await refreshStatus();await loadScope();}""")
    page.locator("#sources-tab-scope").click()
    page.locator("#scope-new-profile").check()
    page.locator("#sources-tab-chats").click()
    page.locator("#target-select-page").check()
    page.locator("#target-bulk-action").select_option("exclude")
    page.locator("#target-bulk-apply").click()
    expect(rows.locator(".source-state")).to_have_text("Excluded")
    expect(page.locator("#target-card")).to_have_attribute("aria-busy", "false")
    page.locator("#sources-tab-scope").click()
    expect(page.locator("#scope-new-profile")).to_be_checked()
    expect(page.locator("#scope-exclude")).to_contain_text("Investigation source 02")
    page.locator("#sources-tab-chats").click()
    rows.locator(".source-state").click()
    expect(rows.locator(".source-state")).to_have_text("Enabled")
    expect(page.locator("#target-card")).to_have_attribute("aria-busy", "false")
    assert page.evaluate("state.scopeDirty && !state.scopeExclude.includes(-1000000001001)")

    # Removing membership never removes signed history.
    store = server.app.state.store
    saved = store.append("message.new", {"text": "retained evidence"}, chat_id=-1000000001001,
                         message_id=7)
    page.locator("#target-select-page").check()
    page.locator("#target-bulk-action").select_option("remove")
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#target-bulk-apply").click()
    expect(rows).to_have_count(0)
    expect(page.locator("#sources-tab-count")).to_have_text("20")
    assert store.events(chat_id=-1000000001001, message_id=7)[0]["seq"] == saved["seq"]
    page.locator("#target-clear-filters").click()
    page.evaluate("state.scopeDirty=false;loadScope()")
    expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
    checks = []
    for theme in ("light", "dark"):
        page.locator("html").evaluate("(root,theme)=>root.dataset.theme=theme", theme)
        for width in (1440, 390):
            page.set_viewport_size({"width": width, "height": 844})
            page.evaluate("""async()=>{scrollTo({top:0,left:0,behavior:'instant'});
              await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));}""")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (theme, width)
            height = page.locator("#view-sources").bounding_box()["height"]
            assert height <= 3 * 844, (theme, width, height)
            page.screenshot(path=str(output / f"chats-{width}-{theme}.png"), full_page=True)
            checks.append({"theme": theme, "width": width, "height": height})
    (output / "checks.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")


def check_export_location(page):
    output = ROOT / "build" / "ux-review" / "after" / "19"
    output.mkdir(parents=True, exist_ok=True)
    navigate_panel(page, "evidence")
    expect(page.locator("#view-sources #snapshot-form")).to_have_count(0)
    expect(page.locator("#view-sources #chat-export-form")).to_have_count(0)
    page.locator("#export-chat-tools > summary").click()
    expect(page.locator("#snapshot-form")).to_be_visible()
    expect(page.locator("#chat-export-source option").first).to_have_text("Choose a chat")
    requests = []

    def snapshot(route):
        requests.append(route.request.post_data_json)
        route.fulfill(content_type="application/json", body='{"captured":3}')

    page.route("**/api/snapshot", snapshot, times=1)
    source = page.locator("#snapshot-source").input_value()
    page.locator("#snapshot-limit").fill("17")
    page.locator("#snapshot-form button").click()
    expect(page.locator("#toast")).to_contain_text("Saved 3 history observations")
    assert requests == [{"chat_id": int(source), "limit": 17}]
    page.locator("#chat-export-source").select_option(source)
    page.evaluate("refreshStatus()")
    expect(page.locator("#chat-export-source")).to_have_value(source)
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 844})
        page.locator("#export-chat-tools").scroll_into_view_if_needed()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        page.locator("#export-chat-tools").screenshot(path=str(output / f"chat-tools-{width}.png"))
    navigate_panel(page, "sources")


def check_dialog_refresh(page, server):
    output = ROOT / "build" / "ux-review" / "after" / "20"
    output.mkdir(parents=True, exist_ok=True)
    requests = []
    page.on("request", lambda request: requests.append(request.url)
            if request.method == "POST" and "/api/snapshot" in request.url else None)
    page.route("**/api/dialogs", lambda route: route.fulfill(status=503,
               content_type="application/json", body='{"detail":"Synthetic refresh failure"}'), times=1)
    page.locator("#load-dialogs").click()
    expect(page.locator("#dialog-refresh-status")).to_contain_text("Synthetic refresh failure")
    expect(page.locator("#dialog-refresh-retry")).to_be_visible()
    dialogs = [{"chat_id": -1000000090000 - number, "title": f"Available source {number + 1:02}",
                "kind": "supergroup", "visibility": "private_or_unlisted"} for number in range(21)]
    server.app.state.collector.dialog_cache = {item["chat_id"]: item for item in dialogs}
    body = {"dialogs": dialogs, "folders": [], "limit": 1000, "may_be_truncated": False}
    page.route("**/api/dialogs", lambda route: route.fulfill(content_type="application/json",
                                                           body=json.dumps(body)))
    hold_api_response(page, "/api/dialogs")
    page.locator("#dialog-refresh-retry").click()
    expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
    expect(page.locator("#load-dialogs")).to_be_disabled()
    expect(page.locator("#dialog-refresh-progress")).to_be_visible()
    page.locator("#sources-tab-recording").click()
    release_api_response(page)
    expect(page.locator("#sources-panel-recording")).to_be_visible()
    expect(page.locator("#dialog-refresh-progress")).to_be_hidden()
    expect(page.locator("#dialog-refresh-status")).to_contain_text("Last refreshed in this session:")
    expect(page.locator("#dialog-refresh-retry")).to_be_hidden()
    assert not requests, requests
    page.locator("#sources-tab-chats").click()
    expect(page.locator("#target-card")).to_be_hidden()
    expect(page.locator("#dialog-list .target-row")).to_have_count(10)
    page.locator("#dialog-next").click()
    expect(page.locator("#dialog-page-count")).to_have_text("11–20 of 21")
    page.locator("#dialog-next").click()
    expect(page.locator("#dialog-list .target-row")).to_have_count(1)
    page.locator("#dialog-prev").click()
    page.locator("#dialog-prev").click()
    page.locator("#dialog-list .source-select").nth(1).check()
    selected = page.locator("#dialog-list .source-select").nth(1)
    selected.focus()
    page.evaluate("refreshStatus()")
    expect(selected).to_be_checked()
    expect(selected).to_be_focused()
    page.locator("#dialog-add-selected").click()
    expect(page.locator("#dialog-list button").nth(1)).to_have_text("Selected")
    expect(page.locator("#dialog-list button").nth(1)).to_be_disabled()
    expect(page.locator("#sources-tab-count")).to_have_text("21")

    # A late refresh cannot navigate away from the journal or discard the old list on failure.
    hold_api_response(page, "/api/dialogs")
    page.locator("#load-dialogs").click()
    expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
    navigate_panel(page, "observations")
    release_api_response(page)
    expect(page.locator("#view-observations")).to_be_visible()
    navigate_panel(page, "sources")
    expect(page.locator("#available-card")).to_be_visible()
    page.route("**/api/dialogs", lambda route: route.fulfill(status=503,
               content_type="application/json", body='{"detail":"Retry later"}'), times=1)
    page.locator("#load-dialogs").click()
    expect(page.locator("#dialog-refresh-status")).to_contain_text("Retry later")
    expect(page.locator("#dialog-list .target-row")).to_have_count(10)
    page.locator("#dialog-refresh-retry").click()
    expect(page.locator("#dialog-refresh-retry")).to_be_hidden()
    expect(page.locator("#dialog-refresh-progress")).to_be_hidden()
    expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 844})
        page.evaluate("""async()=>{scrollTo({top:0,left:0,behavior:'instant'});
          await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));}""")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert page.locator("#view-sources").bounding_box()["height"] <= 3 * 844
        page.screenshot(path=str(output / f"refresh-{width}.png"), full_page=True)
    page.locator("#finish-source-selection").click()
    expect(page.locator("#target-card")).to_be_visible()


def main():
    output = ROOT / "build" / "ux-review" / "after" / "17"
    output.mkdir(parents=True, exist_ok=True)
    errors, writes = [], []
    with tempfile.TemporaryDirectory(prefix="sources-browser-") as scratch, RunningApp(
            Path(scratch)) as server, sync_playwright() as playwright:
        seed(server)
        browser = launch_browser(playwright)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: writes.append(request.url) if request.method == "POST"
                and any(request.url.endswith("/api/" + name)
                        for name in ("recording", "monitoring", "capture", "recheck")) else None)
        unlock(page, server)
        page.evaluate("sourcesReady")
        navigate_panel(page, "sources")
        expect(page.locator("#sources-panel-scope")).to_be_visible()
        expect(page.locator("#sources-tab-count")).to_have_text("21")
        page.locator("#sources-tab-scope").focus()
        page.keyboard.press("ArrowRight")
        expect(page.locator("#sources-tab-chats")).to_be_focused()
        page.keyboard.press("ArrowRight")
        expect(page.locator("#sources-panel-recording")).to_be_visible()
        expect(page.locator("#recording-save")).to_be_disabled()
        page.locator("#monitor-reactions").uncheck()
        page.locator("#max-media").fill("50")
        page.locator(".media-rules-details").evaluate("details=>details.open=true")
        page.locator("#media-max-video").fill("7")
        page.locator(".media-rules-details").evaluate("details=>details.open=false")
        page.locator("#recheck-priority").fill("33")
        page.locator("#max-media").focus()
        page.evaluate("refreshStatus()")
        expect(page.locator("#max-media")).to_have_value("50")
        expect(page.locator("#max-media")).to_be_focused()
        expect(page.locator("#monitor-reactions")).not_to_be_checked()
        expect(page.locator("#recheck-priority")).to_have_value("33")
        page.locator("#sources-tab-scope").click()
        page.locator("#sources-tab-recording").click()
        expect(page.locator("#max-media")).to_have_value("50")
        expect(page.locator("#recording-change-count")).to_contain_text("unsaved")
        hold_api_response(page, "/api/recording")
        page.locator("#recording-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.locator("#max-media").fill("20")
        page.locator("#monitor-edits").uncheck()
        release_api_response(page)
        expect(page.locator("#recording-save")).to_be_enabled()
        expect(page.locator("#max-media")).to_have_value("20")
        expect(page.locator("#monitor-edits")).not_to_be_checked()
        assert server.app.state.store.get_setting("capture")["max_media_mb"] == 50
        assert server.app.state.store.get_setting("capture")["types"]["video"]["max_mb"] == 7
        assert server.app.state.store.get_setting("recheck_minutes") == 33
        page.locator("#recording-save").click()
        expect(page.locator("#recording-save")).to_be_disabled()
        expect(page.locator("#recording-change-count")).to_have_text("No unsaved changes")
        assert server.app.state.store.get_setting("capture")["max_media_mb"] == 20
        assert len(writes) == 2 and all(url.endswith("/api/recording") for url in writes), writes
        page.locator("#monitor-edits").check()
        page.locator("#recording-discard").click()
        expect(page.locator("#monitor-edits")).not_to_be_checked()
        expect(page.locator("#recording-discard")).to_be_disabled()
        expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
        page.locator("#max-media").fill("2001")
        page.locator("#recording-save").click()
        assert not page.locator("#max-media").evaluate("field=>field.checkValidity()")
        assert len(writes) == 2
        page.locator("#recording-discard").click()
        expect(page.locator("#max-media")).not_to_have_attribute("aria-invalid", "true")
        expect(page.locator("#max-media-field-error")).to_have_count(0)

        checks = []
        for theme in ("light", "dark"):
            page.locator("html").evaluate("(root,theme)=>root.dataset.theme=theme", theme)
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 844})
                for tab in ("scope", "recording"):
                    page.locator("#sources-tab-" + tab).click()
                    page.evaluate("""async()=>{scrollTo({top:0,left:0,behavior:'instant'});
                      await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));}""")
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (theme, width, tab)
                    height = page.locator("#view-sources").bounding_box()["height"]
                    assert height <= 3 * 844, (theme, width, tab, height)
                    page.screenshot(path=str(output / f"{tab}-{width}-{theme}.png"), full_page=True)
                    checks.append({"theme": theme, "width": width, "tab": tab, "height": height})

        check_targets(page, server)
        check_export_location(page)
        check_dialog_refresh(page, server)
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.locator("#sources-tab-recording").click()
        second = page.evaluate("json('profiles',{label:'Independent workspace'}).then(value=>value.id)")
        second_capture = server.app.state.profiles.entries[second]["app"].state.store.get_setting("capture")
        assert second_capture is not None and not second_capture["types"]["animation"]["enabled"]
        page.evaluate("loadProfiles()")
        page.locator("#sources-tab-chats").click()
        page.locator("#target-search").fill("source 03")
        page.locator("#target-select-page").check()
        page.locator("#target-bulk-action").select_option("pause")
        hold_api_response(page, "/api/targets/batch")
        page.locator("#target-bulk-apply").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.locator("#profile-select").select_option(second)
        expect(page.locator("#workspace")).to_have_js_property("inert", False)
        release_api_response(page)
        page.locator("#sources-tab-chats").click()
        expect(page.locator("#target-list tr")).to_have_count(0)
        expect(page.locator("#target-bulk-actions")).to_be_hidden()
        expect(page.locator("#source-action-result")).to_have_text("")
        page.locator("#profile-select").select_option("default")
        expect(page.locator("#workspace")).to_have_js_property("inert", False)
        page.locator("#sources-tab-recording").click()
        page.locator("#max-media").fill("35")
        hold_api_response(page, "/api/recording")
        page.locator("#recording-save").click()
        expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
        page.locator("#profile-select").select_option(second)
        expect(page.locator("#workspace")).to_have_js_property("inert", False)
        release_api_response(page)
        page.locator("#sources-tab-recording").click()
        expect(page.locator("#max-media")).to_have_value("20")
        expect(page.locator("#monitor-edits")).to_be_checked()
        expect(page.locator("#recording-save")).to_be_disabled()
        assert server.app.state.profiles.entries[second]["app"].state.store.get_setting("capture") == second_capture
        token = page.evaluate("""json('access/grants',{label:'Source operator',permissions:['sources'],
            workspaces:{default:null}},{root:true}).then(value=>value.token)""")
        limited = browser.new_page(viewport={"width": 1440, "height": 1000})
        limited.on("pageerror", lambda error: errors.append(str(error)))
        limited.goto(server.url)
        limited.locator("#panel-token").fill(token)
        limited.get_by_role("button", name="Open workspace").click()
        expect(limited.locator("#workspace")).to_be_visible()
        limited.evaluate("sourcesReady")
        navigate_panel(limited, "sources")
        limited.locator("#sources-tab-recording").click()
        expect(limited.locator("#monitor-messages")).to_be_disabled()
        expect(limited.locator("#download-media")).to_be_disabled()
        expect(limited.locator("#recheck-priority")).to_be_enabled()
        limited.locator("#recheck-priority").fill("45")
        hold_api_response(limited, "/api/recording")
        limited.locator("#recording-save").click()
        expect(limited.locator("html")).to_have_attribute("data-acceptance-held", "true")
        limited.locator("#top-lock").click()
        release_api_response(limited)
        expect(limited.locator("#gate")).to_be_visible()
        assert limited.evaluate("""()=>{
          const root=panelRoots.get('sources');
          return !root.isConnected&&root.querySelector('#recording-save').disabled;
        }""")
        assert limited.evaluate("()=>panelRoots.get('sources').querySelector('#target-list').textContent") == ""
        assert server.app.state.store.get_setting("recheck_minutes") == 45
        limited.close()
        assert not errors, errors
        server.app.state.store.verify(server.app.state.vault.public_key)
        (output / "checks.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
        browser.close()
    print("Sources: atomic save, newer drafts, polling focus, workspace isolation and 390/1440px layouts passed.")


if __name__ == "__main__":
    main()
