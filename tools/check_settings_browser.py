"""Synthetic report-settings lifecycle: workspace boundaries, drafts and retry."""
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import (RunningApp, check_layout, launch_browser,
                                 release_api_response, unlock)


def hold_report_response(page):
    page.evaluate("""()=>{
        window.acceptanceFetch=window.fetch;window.releaseAcceptanceResponse=null;
        window.fetch=async(...args)=>{
            const response=await window.acceptanceFetch(...args);
            if(String(args[0])==='/api/report-options')await new Promise(resolve=>{
                window.releaseAcceptanceResponse=resolve;document.documentElement.dataset.acceptanceHeld='true';
            });
            return response;
        };
    }""")


def main():
    with tempfile.TemporaryDirectory(prefix="report-settings-") as scratch, RunningApp(Path(scratch)) as app:
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            writes = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: writes.append(request.url) if "/api/report-options" in request.url and request.method == "POST" else None)
            unlock(page, app)
            expect(page.locator("#unlock-form button")).to_be_enabled()
            second = page.evaluate("""async()=>{
                const second=await json('profiles',{label:'Second synthetic case'},{root:true});
                await json('report-options',{case_title:'Case A',notes:'Private notes A'});
                await json('report-options',{case_title:'Case B',notes:'Private notes B'},{profile:second.id});
                await loadProfiles();return second.id;
            }""")
            page.locator('.sidebar [data-view="evidence"]').click()
            expect(page.locator("#report-case-title")).to_have_value("Case A")
            page.evaluate("id=>switchProfile(id)", second)
            expect(page.locator("#report-case-title")).to_have_value("Case B", timeout=2000)
            expect(page.locator("#report-notes")).to_have_value("Private notes B")
            page.locator("#report-case-title").fill("Unsaved case B")
            page.locator('.sidebar [data-view="chats"]').click()
            page.locator('.sidebar [data-view="evidence"]').click()
            expect(page.locator("#report-case-title")).to_have_value("Unsaved case B")

            page.evaluate("switchProfile('default')")
            expect(page.locator("#report-case-title")).to_have_value("Case A")
            hold_report_response(page)
            page.evaluate("()=>{window.reportLoad=loadReportSettings();}")
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.evaluate("id=>switchProfile(id)", second)
            expect(page.locator("#report-case-title")).to_have_value("Case B")
            release_api_response(page)
            page.evaluate("window.reportLoad")
            expect(page.locator("#report-case-title")).to_have_value("Case B")

            page.evaluate("switchProfile('default')")
            page.locator("#report-case-title").fill("Saved case A")
            hold_report_response(page)
            page.locator('#report-form button[type="submit"]').click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            failure_path = "**/profiles/" + second + "/api/report-options"

            def unavailable(route):
                route.fulfill(status=503, content_type="application/json", body='{"detail":"Synthetic settings outage"}')

            page.route(failure_path, unavailable)
            page.evaluate("id=>switchProfile(id)", second)
            expect(page.locator("#report-case-title")).to_have_value("")
            expect(page.locator("#report-case-title")).to_be_disabled()
            expect(page.locator("#report-status")).to_contain_text("Synthetic settings outage")
            release_api_response(page)
            page.wait_for_function("!document.querySelector('#report-form button[type=submit]').hasAttribute('aria-busy')")
            expect(page.locator('#report-form button[type="submit"]')).to_be_disabled()
            baseline = len(writes)
            page.evaluate("""()=>{$('report-form').dispatchEvent(new SubmitEvent('submit',{
                bubbles:true,cancelable:true,submitter:$('report-form').querySelector('button[type="submit"]')}));}
            """)
            assert len(writes) == baseline
            page.unroute(failure_path, unavailable)
            page.locator("#report-status").get_by_role("button", name="Retry", exact=True).click()
            expect(page.locator("#report-case-title")).to_have_value("Case B")
            expect(page.locator("#report-case-title")).to_be_enabled()
            page.locator('#report-form button[type="submit"]').click()
            expect(page.locator("#report-status")).to_contain_text("Saved.")
            saved = page.evaluate("json('report-options')")
            assert saved["case_title"] == "Case B" and saved["notes"] == "Private notes B"

            for width in (1440, 390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    check_layout(page)
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.evaluate("lock()")
            assert page.evaluate("()=>$('report-case-title').value") == ""
            assert page.evaluate("()=>$('report-notes').value") == ""
            assert page.evaluate("()=>$('report-case-title').matches(':disabled')")
            expect(page.locator("#report-form")).to_have_count(0)
            assert not errors, errors
            browser.close()
    print("Report settings passed: workspace separation, local drafts, late loads/saves, failed load retry, lock clearing and mobile layouts.")


if __name__ == "__main__":
    main()
