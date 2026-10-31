"""Header health actions, pause confirmation and stable workspace options."""
import json
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="health-controls-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        store.set_target(-1001, "Synthetic unconfirmed source", "supergroup", True)
        store.append("message.new", {"text": "Synthetic evidence", "sender_id": 42}, -1001, 1)
        output = Path("build/ux-review/after/06-health")
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors, writes = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))

            def status(route):
                response = route.fetch()
                value = response.json()
                value["collector"].update(running=True, connected=True, has_session=True,
                    source_status={"-1001": {"state": "access_unconfirmed"}})
                value["capture"]["download_media"] = False
                value["health"]["sources"].update(state="degraded", reason="some_unconfirmed",
                    counts={"enabled": 1, "checked": 1, "visible": 0, "added": 0, "unconfirmed": 1})
                value["health"]["media"].update(state="off", reason="disabled",
                    counts={"pending": 3, "retry": 1, "failed": 0})
                route.fulfill(response=response, json=value)

            page.route("**/api/status", status)

            def mutation(route):
                writes.append((route.request.url.rsplit("/api/", 1)[-1], route.request.post_data_json))
                route.fulfill(status=200, content_type="application/json", body=json.dumps({"cancelled": 3}))

            for path in ("collector/stop", "media/queue/clear", "capture", "targets/ignore-unconfirmed"):
                page.route("**/api/" + path, mutation)
            unlock(page, app)
            expect(page.locator(".health-chip")).to_have_count(4)
            page.evaluate("window.healthOption=document.querySelector('#profile-select option:checked')")
            page.evaluate("loadProfiles()")
            assert page.evaluate("window.healthOption===document.querySelector('#profile-select option:checked')")

            page.once("dialog", lambda dialog: dialog.dismiss())
            page.locator("#collector-toggle").click()
            assert not writes
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#collector-toggle").click()
            expect(page.locator("#collector-toggle")).to_be_enabled()
            assert writes[0][0] == "collector/stop"

            page.locator('[data-health-part="sources"]').click()
            expect(page.locator("#health-dialog")).to_be_visible()
            page.locator('[data-health-action="show-sources"]').click()
            expect(page.locator("#health-dialog")).to_be_hidden()
            expect(page.locator("#view-sources")).to_be_visible()
            expect(page.locator("#target-filter")).to_have_value("unconfirmed")
            expect(page.locator("#target-list tr")).to_have_count(1)
            page.locator('[data-health-part="sources"]').click()
            page.locator('[data-health-action="ignore-sources"]').click()
            page.wait_for_function("()=>!document.querySelector('[data-health-action=ignore-sources]').disabled")
            assert any(path == "targets/ignore-unconfirmed" and body == {"chat_ids": [-1001], "ignored": True}
                       for path, body in writes)
            page.keyboard.press("Escape")

            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000 if width == 1440 else 844})
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    page.locator('[data-health-part="media"]').click()
                    expect(page.locator("#health-dialog")).to_be_visible()
                    check_layout(page)
                    bounds = page.locator("#health-dialog").bounding_box()
                    assert bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width + 1
                    page.screenshot(path=str(output / f"attachments-{width}-{theme}.png"))
                    page.keyboard.press("Escape")

            page.locator('[data-health-part="media"]').click()
            before = len(writes)
            page.once("dialog", lambda dialog: dialog.dismiss())
            page.locator('[data-health-action="clear-queue"]').click()
            assert len(writes) == before
            cutoff = page.evaluate("state.status.stats.head.seq")
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator('[data-health-action="clear-queue"]').click()
            page.wait_for_function("()=>!document.querySelector('[data-health-action=clear-queue]').disabled")
            assert writes[-1] == ("media/queue/clear", {"through_seq": cutoff})
            page.locator('[data-health-action="disabled-receipts"]').click()
            page.wait_for_function("()=>!document.querySelector('[data-health-action=disabled-receipts]').disabled")
            assert writes[-1][0] == "capture" and writes[-1][1]["record_disabled_media"] is False
            page.keyboard.press("Escape")
            navigate_panel(page, "observations")
            expect(page.locator("#health-dialog")).to_be_hidden()
            page.locator('[data-health-part="connection"]').click()
            page.evaluate("lock()")
            expect(page.locator("#health-dialog")).to_be_hidden()
            assert not errors, errors
            browser.close()
    print("Health controls passed: scoped actions, confirmations, queue cutoff, stable options and 1440/390 layouts.")


if __name__ == "__main__":
    main()
