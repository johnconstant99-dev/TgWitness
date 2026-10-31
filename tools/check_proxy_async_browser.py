"""Proxy polling and settings races, using local synthetic responses only."""
import copy
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import ROOT, RunningApp, launch_browser, unlock


def hold_next(page, suffix):
    page.evaluate("""suffix => {
      const original = window.fetch;
      window.proxyOriginalFetch = original;
      let held = false;
      window.fetch = async (...args) => {
        const response = await original(...args);
        if (!held && String(args[0]).endsWith(suffix)) {
          held = true;
          await new Promise(resolve => {
            window.releaseProxyResponse = resolve;
            document.documentElement.dataset.proxyHeld = 'true';
          });
        }
        return response;
      };
    }""", suffix)


def release(page):
    page.evaluate("""() => {
      window.fetch = window.proxyOriginalFetch;
      window.releaseProxyResponse();
      delete document.documentElement.dataset.proxyHeld;
    }""")


def main(proxy_script=None):
    output = ROOT / "test-results/proxy-async-browser"
    output.mkdir(parents=True, exist_ok=True)
    errors, loads, saves, uploads = [], [], [], []
    with tempfile.TemporaryDirectory(prefix="proxy-async-") as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            if proxy_script is not None:
                page.route("**/proxies.js*", lambda route: route.fulfill(body=proxy_script, content_type="application/javascript"))
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            expect(page.locator("#unlock-form button")).to_be_enabled()
            page.wait_for_function("state.status !== null")
            snapshot = page.evaluate("json('network/proxies')")
            snapshot["settings"]["github_token"] = True
            snapshot["summary"].update(checking=False, median_ms=40)
            snapshot["rows"] = []

            def proxies(route):
                loads.append(1)
                route.fulfill(json=copy.deepcopy(snapshot))

            def settings(route):
                body = route.request.post_data_json
                saves.append(body)
                snapshot["settings"].update(body)
                route.fulfill(json=copy.deepcopy(snapshot))

            def upload(route):
                body = route.request.post_data_json
                uploads.append(body["label"])
                source = {"id": "synthetic-" + str(len(uploads)), "kind": "list", "label": body["label"],
                          "enabled": True, "compatible": 1}
                snapshot["sources"].append(source)
                snapshot["settings"]["custom"].append(source)
                reply = copy.deepcopy(snapshot)
                reply["added"] = {"compatible": 1}
                route.fulfill(json=reply)

            page.route("**/api/network/proxies", proxies)
            page.route("**/api/network/sources", settings)
            page.route("**/api/network/sources/list", upload)
            page.route("**/api/network/github-token", lambda route: route.fulfill(json=copy.deepcopy(snapshot)))
            page.locator('[data-view="connection"]').click()
            page.locator("#entry-settings").click()
            expect(page.locator("#pool-stats")).to_contain_text("40")
            page.locator("#pool-sources > summary").click()
            query = page.locator("#pool-github-query")
            query.fill("a query still being edited")
            page.locator("#pool-github-max").fill("37")
            page.locator("#pool-countries").uncheck()
            page.evaluate("TgWitnessProxies.load()")
            expect(query).to_have_value("a query still being edited")
            expect(page.locator("#pool-github-max")).to_have_value("37")
            expect(page.locator("#pool-countries")).not_to_be_checked()

            # An older HTTP response must not overwrite a later dashboard refresh.
            hold_next(page, "/api/network/proxies")
            page.evaluate("void TgWitnessProxies.load()")
            expect(page.locator("html")).to_have_attribute("data-proxy-held", "true")
            snapshot["summary"]["median_ms"] = 900
            page.evaluate("TgWitnessProxies.load()")
            expect(page.locator("#pool-stats")).to_contain_text("900")
            release(page)
            page.wait_for_timeout(100)
            expect(page.locator("#pool-stats")).to_contain_text("900")
            expect(query).to_have_value("a query still being edited")

            # Keep edits made after Save was pressed; polling cannot re-enable its button.
            hold_next(page, "/api/network/sources")
            page.locator("#pool-save").click()
            expect(page.locator("html")).to_have_attribute("data-proxy-held", "true")
            query.fill("the next edit")
            page.evaluate("TgWitnessProxies.load()")
            expect(page.locator("#pool-save")).to_be_disabled()
            release(page)
            expect(page.locator("#pool-save")).to_be_enabled()
            expect(query).to_have_value("the next edit")
            assert saves[-1]["github"]["query"] == "a query still being edited"
            page.locator("#pool-save").click()
            expect(page.locator("#pool-save")).to_be_enabled()
            assert saves[-1]["github"]["query"] == "the next edit"
            assert saves[-1]["github"]["max_files"] == 37
            assert saves[-1]["countries"] is False

            # Two file selections queue their changes rather than racing a shared catalog.
            hold_next(page, "/api/network/sources/list")
            page.locator("#pool-files").set_input_files({"name": "first.txt", "mimeType": "text/plain", "buffer": b"synthetic list"})
            expect(page.locator("html")).to_have_attribute("data-proxy-held", "true")
            page.locator("#pool-files").set_input_files({"name": "second.txt", "mimeType": "text/plain", "buffer": b"synthetic list"})
            assert uploads == ["first.txt"], "A second catalog mutation started before the first finished"
            release(page)
            expect(page.locator("#pool-own .pool-source-item")).to_have_count(2)
            assert uploads == ["first.txt", "second.txt"]

            hold_next(page, "/api/network/github-token")
            page.locator("#pool-token").fill("synthetic pending token")
            page.locator("#pool-token-save").click()
            expect(page.locator("html")).to_have_attribute("data-proxy-held", "true")
            page.locator("#pool-token").fill("synthetic replacement token")
            release(page)
            expect(page.locator("#pool-token-save")).to_be_enabled()
            expect(page.locator("#pool-token")).to_have_value("synthetic replacement token")

            # A refresh already in flight when the page closes must not restart polling.
            snapshot["summary"]["checking"] = True
            hold_next(page, "/api/network/proxies")
            page.evaluate("void TgWitnessProxies.load()")
            expect(page.locator("html")).to_have_attribute("data-proxy-held", "true")
            page.locator('[data-view="chats"]').click()
            before = len(loads)
            release(page)
            page.wait_for_timeout(4400)
            assert len(loads) == before, "Hidden proxy dashboard continued polling"

            # Locking discards a draft and token; reopening starts with server values.
            page.locator('[data-view="connection"]').click()
            page.locator("#entry-settings").click()
            expect(query).to_have_value("the next edit")
            query.fill("unsaved private query")
            page.locator("#pool-token").fill("synthetic pending token")
            page.locator("#top-lock").click()
            expect(page.locator("#pool-token")).to_have_value("")
            page.locator("#panel-token").fill(server.app.state.vault.token)
            page.locator("#unlock-form button").click()
            expect(page.locator("#unlock-form button")).to_be_enabled()
            page.locator('[data-view="connection"]').click()
            page.locator("#entry-settings").click()
            expect(query).to_have_value("the next edit")
            assert not errors, errors
            browser.close()
    receipt = {"passed": True, "errors": errors, "checks": [
        "drafts survive polling", "old responses discarded", "edits during save retained",
        "pending save remains disabled", "hidden dashboard stops polling", "lock clears drafts and secrets",
        "list uploads serialized", "new token input preserved while saving",
    ]}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
