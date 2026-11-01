"""Active-screen mounting, draft retention and workspace cleanup with synthetic data."""
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, navigate_panel, unlock


def main():
    output = Path("build/ux-review/after/02-views")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="view-lifecycle-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        store.set_target(-1001, "Synthetic investigation", "supergroup", True)
        for number in range(1, 31):
            store.append("message.new", {"text": f"Preserved invoice {number}", "sender_id": 44}, -1001, number, 44)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors, requests, captures = [], [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))
            try:
                unlock(page, app)
            except AssertionError as exc:
                if errors:
                    raise AssertionError(f"Unlock failed with browser errors: {errors}") from exc
                raise
            expect(page.locator(".view")).to_have_count(1)
            expect(page.locator("#view-connection")).to_be_visible()
            assert not any("/api/parameters" in url or "/api/events?" in url for url in requests), requests

            navigate_panel(page, "parameters")
            field = page.locator('#parameters-groups input[type="number"]').first
            expect(field).to_be_visible()
            field_id = field.get_attribute("id")
            old = field.input_value()
            field.fill(str(max(1, int(float(old)) - 1)))
            draft = field.input_value()
            navigate_panel(page, "observations")
            expect(page.locator("#events-body tr").first).to_be_visible()
            assert page.evaluate("()=>!$('view-parameters').isConnected")
            page.evaluate("""()=>{
              window.inactiveMutations=[];
              window.inactiveObserver=new MutationObserver(items=>inactiveMutations.push(...items.map(item=>item.target.id)));
              for(const root of panelRoots.values())if(!root.isConnected)inactiveObserver.observe(root,{childList:true,subtree:true,attributes:true,characterData:true});
            }""")
            page.evaluate("async()=>{await refreshStatus();await refreshStatus();}")
            inactive = page.evaluate("()=>inactiveMutations")
            assert inactive == [], f"Status polling touched a detached screen: {inactive}"
            page.evaluate("()=>inactiveObserver.disconnect()")
            navigate_panel(page, "parameters")
            expect(page.locator("#" + field_id)).to_have_value(draft)

            navigate_panel(page, "evidence")
            page.locator('#exports-tab-settings').click()
            expect(page.locator("#report-case-title")).to_be_visible()
            expect(page.locator("#report-case-title")).to_be_enabled()
            page.locator("#report-case-title").fill("Unsaved local case")
            navigate_panel(page, "chats")
            expect(page.locator("#chat-feed .msg").first).to_be_visible()
            assert page.evaluate("()=>document.querySelectorAll('.view').length") == 1
            navigate_panel(page, "evidence")
            expect(page.locator("#report-case-title")).to_be_visible()
            expect(page.locator("#report-case-title")).to_have_value("Unsaved local case")

            for width, height in ((1440, 1000), (390, 844)):
                page.set_viewport_size({"width": width, "height": height})
                navigate_panel(page, "observations")
                expect(page.locator("#events-body tr").first).to_be_visible()
                assert page.evaluate("()=>document.documentElement.scrollWidth<=innerWidth")
                for view in ("observations", "chats"):
                    navigate_panel(page, view)
                    if view == "chats":
                        expect(page.locator("#chat-feed .msg").first).to_be_visible()
                        page.wait_for_function("""()=>{const feed=document.querySelector('#chat-feed'),bounds=feed.getBoundingClientRect();
                          return [...feed.querySelectorAll('.msg')].some(item=>{const rect=item.getBoundingClientRect();
                            return rect.bottom>bounds.top&&rect.top<bounds.bottom;});}""")
                    else:
                        expect(page.locator("#events-body tr").first).to_be_visible()
                    page.screenshot(path=str(output / f"{view}-{width}.png"), animations="disabled")
                    captures.append({"width": width, "view": view, "url": page.url,
                                     "attached_views": page.locator(".view").count()})

            # Reset clears private text even in a detached screen before another account loads.
            second = page.evaluate("""async()=>{const result=await json('profiles',{label:'Separate case'},{root:true});
              await loadProfiles();return result.id;}""")
            page.evaluate("id=>switchProfile(id)", second)
            assert page.evaluate("()=>$('report-case-title').value") == ""
            assert page.evaluate("()=>$('parameters-groups').children.length") == 0
            assert page.evaluate("()=>!$('events-body').textContent.includes('Preserved invoice')")
            assert page.evaluate("()=>!$('chat-feed').textContent.includes('Preserved invoice')")
            expect(page.locator(".view")).to_have_count(1)
            page.evaluate("lock()")
            expect(page.locator(".view")).to_have_count(0)

            forwarded_errors, patched_statuses = [], []

            def saved_route(route):
                response = route.fetch()
                if response.status != 200:
                    forwarded_errors.append({"status": response.status, "body": response.text()})
                    route.fulfill(response=response)
                    return
                status = response.json()
                assert isinstance(status, dict) and isinstance(status.get("collector"), dict), (
                    "Successful status response has no collector object"
                )
                status["collector"]["network"] = {"kind": "socks5", "host": "synthetic-proxy.example", "port": 1080}
                patched_statuses.append(response.status)
                route.fulfill(response=response, json=status)

            # Re-unlock the same page, retaining the controller cache. No proxy is contacted.
            page.route("**/api/status", saved_route)
            # A late poll after locking legitimately returns an error, not the status schema.
            # Exercise that branch deterministically and preserve its HTTP status and body.
            locked_response = page.evaluate("""async()=>{
              const response=await fetch('/api/status');
              return {status:response.status,body:await response.text()};
            }""")
            assert locked_response["status"] == 401, locked_response["status"]
            assert locked_response in forwarded_errors, "The interceptor changed the unauthorized response"
            assert set(json.loads(locked_response["body"])) == {"detail"}
            expect(page.locator("#workspace")).to_be_hidden()
            expect(page.locator(".view")).to_have_count(0)
            for _ in range(2):
                page.locator("#panel-token").fill(app.app.state.vault.token)
                page.locator('#unlock-form button[type="submit"]').click()
                expect(page.locator("#workspace")).to_be_visible()
                navigate_panel(page, "connection")
                expect(page.locator("#network-kind")).to_have_value("socks5")
                expect(page.locator("#network-host")).to_have_value("synthetic-proxy.example")
                page.evaluate("lock()")
            assert len(patched_statuses) >= 2, patched_statuses
            assert not errors, errors
            browser.close()
    (output / "routes.json").write_text(json.dumps(captures, indent=2), encoding="utf-8")
    print("View lifecycle passed: active DOM only, no hidden status rendering, draft retention, mobile navigation and workspace cleanup.")


if __name__ == "__main__":
    main()
