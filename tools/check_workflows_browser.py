"""Task chooser, private export handoff and permission boundaries; synthetic accounts only."""
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, navigate_panel, unlock
from check_account_export_browser import DEFAULTS


def hold_configure(page):
    """Hold only this button's first real response; later view loads must finish normally."""
    page.evaluate("""() => {
      const probe={fetch:window.fetch,busy:window.busy,armed:false,held:false,pending:null};
      window.workflowResponseProbe=probe;
      window.fetch=async(...args)=>{
        const response=await probe.fetch.apply(window,args);
        if(probe.armed&&!probe.held&&new URL(String(args[0]),location.href).pathname==='/api/account-export'){
          probe.held=true;
          await new Promise(resolve=>{probe.release=resolve;});
        }
        return response;
      };
      window.busy=(button,work)=>{
        if(button?.id!=='account-export-configure')return probe.busy(button,work);
        probe.armed=true;probe.pending=probe.busy(button,work);return probe.pending;
      };
    }""")
    page.locator("#account-export-configure").click()
    try:
        page.wait_for_function("()=>typeof window.workflowResponseProbe?.release==='function'")
    except Exception as error:
        state = page.evaluate("""()=>({armed:workflowResponseProbe.armed,held:workflowResponseProbe.held,
          view:state.view,current:viewContexts.get('evidence')?.current(),signedIn:accountSignedIn(),
          open:$('account-export-dialog').open,busy:$('account-export-configure').getAttribute('aria-busy')})""")
        raise AssertionError("Configure request was not held: " + json.dumps(state)) from error
    expect(page.locator("#account-export-dialog")).to_be_hidden()


def release_configure(page):
    # Await the original click handler, not a timer or an assertion made before its continuation.
    page.evaluate("""async()=>{
      const probe=window.workflowResponseProbe;
      window.fetch=probe.fetch;window.busy=probe.busy;
      probe.release();await probe.pending;delete window.workflowResponseProbe;
    }""")
    expect(page.locator("#account-export-dialog")).to_be_hidden()


def main():
    errors, outbound, writes, checks = [], [], [], []
    with tempfile.TemporaryDirectory(prefix="workflow-browser-") as scratch, RunningApp(Path(scratch)) as server:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            context = browser.new_context(viewport={"width": 1440, "height": 1000},
                                          locale="en-US", reduced_motion="reduce")

            def external(route):
                if urlsplit(route.request.url).hostname not in ("127.0.0.1", "localhost"):
                    outbound.append(urlsplit(route.request.url).hostname)
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", external)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: writes.append((request.method, urlsplit(request.url).path))
                    if request.method not in ("GET", "HEAD", "OPTIONS") else None)
            unlock(page, server, start=True)
            expect(page.locator("#view-start")).to_be_visible()
            expect(page.locator("#workflow-account-card")).to_be_visible()
            expect(page.locator("#workflow-investigation-card")).to_be_visible()
            expect(page.locator("#view-start h1")).to_contain_text("What")
            before = list(writes)
            page.locator('[data-workflow="account"]').click()
            expect(page.locator("#view-connection")).to_be_visible()
            expect(page.locator("#workflow-handoff")).to_be_visible()
            expect(page.locator("#workflow-continue")).to_be_hidden()
            expect(page.locator("#credentials-form")).to_be_visible()
            assert writes == before, "Choosing a task wrote to the backend"
            assert not server.app.state.collector.running
            checks.append("English chooser and disconnected export handoff make no backend writes")

            # Real local auth endpoints, backed by FakeClient; no credential or session fixture injection.
            page.locator("#phone").fill("+15550001111")
            page.locator("#auth-continue").click()
            expect(page.locator("#code-form")).to_be_visible()
            page.locator("#code").fill("11111")
            page.locator("#code-form button[type=submit]").click()
            expect(page.locator("#authorized-state")).to_be_visible()
            expect(page.locator("#workflow-continue")).to_be_visible()
            expect(page.locator('#authorized-state [data-open="sources"]')).to_be_hidden()
            assert not server.app.state.collector.running
            before = list(writes)
            page.locator("#workflow-continue").click()
            expect(page.locator("#account-export-dialog")).to_be_visible()
            expect(page.locator("#export-account-panel")).to_be_visible()
            expect(page.locator("#account-export-start")).to_be_enabled()
            assert writes == before, "Opening export settings started an operation"
            assert not server.app.state.collector.running
            checks.append("phone login continues into export settings without starting observation or export")

            page.locator("#account-export-purpose").fill("Personal backup, synthetic test")
            page.locator(".account-export-message-filters > summary").click()
            page.locator("#account-export-senders").fill("invalid-sender")
            page.locator(".account-export-message-filters > summary").click()
            page.locator("#account-export-start").click()
            expect(page.locator("#account-export-senders")).to_be_visible()
            expect(page.locator("#account-export-senders")).to_be_focused()
            expect(page.locator("#account-export-senders")).to_have_attribute("aria-invalid", "true")
            assert writes == before, "Invalid hidden filter caused a write"
            page.locator("#account-export-senders").fill("42,55")
            page.locator("#account-export-phrases").fill("Synthetic literal\nSecond phrase")
            page.locator("#account-export-advanced > summary").click()
            page.locator("#account-export-contacts").uncheck()
            page.locator("#account-export-transport").select_option("regular")
            page.locator("#account-export-advanced > summary").click()
            expect(page.locator("#account-export-advanced-summary")).to_contain_text("Regular session")
            expect(page.locator("#account-export-advanced-summary")).not_to_contain_text("Contacts")
            page.locator("#account-export-dismiss").click()
            expect(page.locator("#account-export-dialog")).to_be_hidden()
            navigate_panel(page, "start")
            page.locator('[data-workflow="investigation"]').click()
            expect(page.locator("#view-sources")).to_be_visible()
            navigate_panel(page, "start")
            page.locator('[data-workflow="account"]').click()
            expect(page.locator("#account-export-dialog")).to_be_visible()
            expect(page.locator("#account-export-purpose")).to_have_value("Personal backup, synthetic test")
            expect(page.locator("#account-export-senders")).to_have_value("42,55")
            expect(page.locator("#account-export-phrases")).to_have_value("Synthetic literal\nSecond phrase")
            expect(page.locator("#account-export-transport")).to_have_value("regular")
            expect(page.locator("#account-export-contacts")).not_to_be_checked()
            page.locator("#account-export-dismiss").click()
            assert writes == before, "Returning between workflows changed observation or export state"
            checks.append("closed invalid filters reopen; advanced selections and export draft survive task changes")

            page.locator('[data-export-tab="settings"]').click()
            page.locator("#report-case-title").fill("Unsaved synthetic report")
            navigate_panel(page, "start")
            page.locator('[data-workflow="account"]').click()
            expect(page.locator("#account-export-dialog")).to_be_visible()
            page.locator("#account-export-dismiss").click()
            page.locator('[data-export-tab="settings"]').click()
            expect(page.locator("#report-case-title")).to_have_value("Unsaved synthetic report")
            assert writes == before, "Report draft was saved implicitly"
            checks.append("unsaved report settings survive workflow navigation")

            jobs = [{"id": "synthetic-paused", "phase": "paused", "active": False, "ready": False,
                     "created_at": "2026-11-01T12:00:00Z", "counts": {"messages_exported": 12},
                     "coverage": {}, "omissions": []}]
            page.route(server.url + "/api/account-export", lambda route: route.fulfill(json={
                "jobs": jobs, "defaults": DEFAULTS, "capabilities": {"can_start": True}}))
            page.locator('[data-export-tab="downloads"]').click()
            page.locator("#export-task-journal").click()
            page.evaluate("()=>loadAccountExport()")
            expect(page.locator("#exports-job-link")).to_be_visible()
            expect(page.locator("#exports-job-summary")).to_contain_text("review: 1")
            page.locator('#exports-job-link [data-export-task="account"]').click()
            expect(page.locator('[data-account-export-action="resume"]')).to_be_visible()
            expect(page.locator("#account-export-jobs")).to_contain_text("Paused")
            assert writes == before, "Finding an existing export changed it"
            checks.append("paused durable jobs remain reachable from saved-observation exports")

            hold_configure(page)
            navigate_panel(page, "start")
            navigate_panel(page, "evidence")
            expect(page.locator("#export-account-panel")).to_be_visible()
            release_configure(page)
            assert writes == before, "A stale configure response changed backend state"
            checks.append("delayed configure response cannot reopen a dialog after leaving and reentering exports")

            second = page.evaluate("()=>json('profiles',{label:'Synthetic second workspace'},{root:true})")
            page.evaluate("()=>loadProfiles()")
            before = list(writes)  # Creating the synthetic workspace above is the explicit fixture write.
            hold_configure(page)
            page.evaluate("id=>switchProfile(id,{discardConfirmed:true})", second["id"])
            assert page.evaluate("state.profile") == second["id"]
            release_configure(page)
            assert page.evaluate("$('account-export-purpose').value") == ""
            assert page.evaluate("state.accountExportJobs.length") == 0
            page.evaluate("()=>switchProfile('default',{discardConfirmed:true})")
            assert page.evaluate("state.profile") == "default"
            assert writes == before, "Switching workspaces changed observation or export state"
            checks.append("late configure response cannot reopen or copy drafts/jobs into another workspace")

            # An explicit URL must win over the default task chooser, including a full reload.
            page.goto(server.url + "/journal?ws=default")
            expect(page.locator("#view-observations")).to_be_visible()
            expect(page.locator("#view-start")).to_have_count(0)
            assert urlsplit(page.url).path == "/journal"
            checks.append("explicit journal deep link survives authenticated reload")

            for width in (320, 390, 1440):
                page.set_viewport_size({"width": width, "height": 1000})
                navigate_panel(page, "start")
                expect(page.locator("#workflow-account-card")).to_be_visible()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), width
                if width < 768:
                    toggle = page.locator("#navigation-toggle")
                    toggle.click()
                    summary = page.locator("#nav-more > summary")
                    expect(summary).to_be_visible()
                    summary.focus()
                    expect(summary).to_be_focused()
                    if page.locator("#nav-more").get_attribute("open") is not None:
                        page.keyboard.press("Enter")
                        expect(page.locator("#nav-more")).not_to_have_attribute("open", "")
                    page.keyboard.press("Enter")
                    expect(page.locator("#nav-more")).to_have_attribute("open", "")
                    # Every Tab stays within the modal navigation; Escape restores the trigger.
                    for _ in range(24):
                        page.keyboard.press("Tab")
                        assert page.evaluate("document.querySelector('.sidebar').contains(document.activeElement)")
                    page.keyboard.press("Escape")
                    expect(toggle).to_have_attribute("aria-expanded", "false")
                    expect(toggle).to_be_focused()
                    toggle.click()
                    page.locator('.sidebar [data-view="connection"]').click()
                    expect(page.locator("#view-connection")).to_be_visible()
                    expect(toggle).to_have_attribute("aria-expanded", "false")
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), width
            checks.append("320/390/1440 layouts, expanded navigation keyboard trap and Escape focus")

            # Grants use the real backend; no status/permission response mocks.
            for label, permissions, scope in (
                ("Read only", ["view"], None),
                ("Journal exporter", ["view", "export"], None),
                ("One chat", ["view", "export"], [-1000000000123]),
            ):
                grant = page.evaluate("""body=>json('access/grants',body,{root:true})""", {
                    "label": label, "workspaces": {"default": scope}, "permissions": permissions})
                reviewer = browser.new_context(viewport={"width": 1440, "height": 1000}, locale="en-US")
                reviewer.route("**/*", external)
                restricted = reviewer.new_page()
                restricted.on("pageerror", lambda error: errors.append(str(error)))
                restricted.goto(server.url + "/start?ws=default")
                restricted.locator("#panel-token").fill(grant["token"])
                restricted.locator("#unlock-form button[type=submit]").click()
                expect(restricted.locator("#workspace")).to_be_visible()
                restricted.wait_for_function("window.TgWitnessRouter?.started")
                expect(restricted.locator("#workflow-account-card")).to_be_hidden()
                assert restricted.evaluate("()=>json('account-export').then(()=>0,e=>e.status)") == 403
                restricted.evaluate("()=>navigate('evidence')")
                expect(restricted.locator("#account-export-card")).to_be_hidden()
                expect(restricted.locator("#export-task-account")).to_be_hidden()
                if label == "Journal exporter":
                    expect(restricted.locator("#view-evidence")).to_be_visible()
                    expect(restricted.locator("#export-journal-panel")).to_be_visible()
                else:
                    expect(restricted.locator("#view-chats")).to_be_visible()
                reviewer.close()
            checks.append("read-only, non-admin exporter and chat-limited grants cannot access account-wide export")
            assert not server.app.state.collector.running
            assert not any(path.endswith(("/collector/start", "/collector/stop", "/account-export/start"))
                           for _, path in writes), writes
            assert not outbound, outbound
            assert not errors, errors
            print(json.dumps({"passed": True, "checks": checks}, indent=2))
            browser.close()


if __name__ == "__main__":
    main()
