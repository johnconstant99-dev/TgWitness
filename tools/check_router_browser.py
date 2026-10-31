"""Named routes and browser history against a synthetic local archive."""
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlencode, urlsplit, parse_qs

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import RunningApp, launch_browser, release_api_response, unlock


def main():
    with tempfile.TemporaryDirectory(prefix="router-ui-") as scratch, RunningApp(Path(scratch)) as app:
        store = app.app.state.store
        for cid, title in ((-1001, "Case one"), (-1002, "Case two")):
            store.set_target(cid, title, "supergroup", True)
            store.append("message.new", {"text": "Invoice draft", "sender_id": 44}, cid, 1, 44)
        event = store.append("message.edited", {"text": "Invoice revised", "sender_id": 44}, -1001, 1, 44)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce",
                                    permissions=["clipboard-read", "clipboard-write"])
            errors, requests = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))
            unlock(page, app)
            expect(page).to_have_url(app.url + "/account?ws=default")
            second = page.evaluate("""async()=>{const profile=await json('profiles',{label:'Second case'},{root:true});
                await loadProfiles();return profile.id;}""")
            second_store = app.app.state.profiles.entries[second]["app"].state.store
            second_store.set_target(-2001, "Separate archive", "supergroup", True)
            second_event = second_store.append("message.new", {"text": "Only in second case", "sender_id": 66}, -2001, 1, 66)

            page.locator('.sidebar [data-view="observations"]').click()
            expect(page).to_have_url(app.url + "/journal?ws=default")
            page.locator('[data-filter="message.edited"]').click()
            page.locator("#journal-source-toggle").click()
            page.locator('.journal-source-option[data-source="-1001"]').click()
            page.locator("#event-search").fill("Invoice")
            page.wait_for_function("()=>state.search==='Invoice'&&new URL(location.href).searchParams.get('q')==='Invoice'")
            filters = parse_qs(urlsplit(page.url).query)
            assert filters == {"ws": ["default"], "kind": ["message.edited"], "source": ["-1001"], "q": ["Invoice"]}
            page.evaluate("seq=>openRecord(seq)", event["seq"])
            expect(page.locator("#detail-drawer")).to_be_visible()
            assert urlsplit(page.url).path == "/journal/event/" + str(event["seq"])
            page.locator("#detail-drawer").get_by_role("button", name="Link to this record", exact=True).click()
            copied = page.evaluate("navigator.clipboard.readText()")
            assert "/journal/event/" + str(event["seq"]) in copied and "ws=default" in copied
            page.go_back()
            expect(page.locator("#detail-drawer")).to_be_hidden()
            expect(page.locator("#event-search")).to_have_value("Invoice")
            expect(page.locator("#source-filter")).to_have_value("-1001")
            page.go_forward()
            expect(page.locator("#detail-drawer")).to_be_visible()
            page.locator("#close-detail").click()
            expect(page.locator("#detail-drawer")).to_be_hidden()

            # Reload a named path, including all journal filters and a timezone-bearing bound.
            date_url = app.url + "/journal?" + urlencode({**{key: values[0] for key, values in filters.items()}, "since": event["observed_at"]})
            page.goto(date_url)
            expect(page.locator("#view-observations")).to_be_visible()
            page.wait_for_function("()=>state.eventSince!==''&&state.events.some(event=>event.kind==='message.edited')")
            assert any("/api/events?" in url and "since=" in url for url in requests)
            expect(page.locator("#event-search")).to_have_value("Invoice")

            page.locator('.sidebar [data-view="parameters"]').click()
            expect(page.locator("#parameters-nav a").first).to_be_visible()
            page.locator("#parameters-nav a").first.click()
            section = urlsplit(page.url).fragment
            assert section and not section.startswith("parameters-group-")
            page.reload()
            expect(page.locator("#view-parameters")).to_be_visible()
            expect(page.locator("#parameters-group-" + section)).to_be_visible()
            page.locator('.sidebar [data-view="witness"]').click()
            expect(page).to_have_url(app.url + "/extras?ws=default")
            page.locator("#extras-open-evidence").click()
            expect(page).to_have_url(app.url + "/extras/evidence?ws=default")
            page.go_back()
            expect(page.locator("#extras-overview")).to_be_visible()
            page.go_forward()
            expect(page.locator("#extras-evidence")).to_be_visible()

            page.locator('.sidebar [data-view="chats"]').click()
            page.evaluate("openChat(-1001)")
            expect(page).to_have_url(app.url + "/chats/-1001?ws=default")
            page.evaluate("openChat(-1002)")
            page.go_back()
            page.wait_for_function("()=>state.chat===-1001")
            page.go_forward()
            page.wait_for_function("()=>state.chat===-1002")
            page.reload()
            page.wait_for_function("()=>state.chat===-1002&&state.chatInfo!==null")

            # An explicit workspace in a deep link must be chosen before fetching its record.
            page.goto(app.url + "/journal/event/" + str(second_event["seq"]) + "?ws=" + second)
            expect(page.locator("#detail-drawer")).to_contain_text("Only in second case")
            assert page.evaluate("state.profile") == second
            page.goto(app.url + "/?workspace=default&event=" + str(event["seq"]) + "#journal")
            expect(page.locator("#detail-drawer")).to_contain_text("Invoice revised")
            assert urlsplit(page.url).path == "/journal/event/" + str(event["seq"])
            assert parse_qs(urlsplit(page.url).query)["ws"] == ["default"]
            page.goto(app.url + "/#observations")
            expect(page.locator("#view-observations")).to_be_visible()
            assert urlsplit(page.url).path == "/journal"

            # Back during a delayed workspace restore must win over its late status response.
            page.evaluate("navigate('sources')")
            page.evaluate("id=>switchProfile(id)", second)
            expect(page).to_have_url(app.url + "/sources?ws=" + second)
            page.go_back()
            page.wait_for_function("()=>state.profile==='default'&&!document.getElementById('workspace').inert")
            page.evaluate("""id=>{
              window.acceptanceFetch=window.fetch;window.releaseAcceptanceResponse=null;
              window.fetch=async(...args)=>{const response=await window.acceptanceFetch(...args);
                if(String(args[0])==='/profiles/'+id+'/api/status')await new Promise(resolve=>{
                  window.releaseAcceptanceResponse=resolve;document.documentElement.dataset.acceptanceHeld='true';});
                return response;};
            }""", second)
            page.go_forward()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.go_back()
            page.wait_for_function("()=>state.profile==='default'&&!document.getElementById('workspace').inert")
            release_api_response(page)
            expect(page).to_have_url(app.url + "/sources?ws=default")
            expect(page.locator("#view-sources")).to_be_visible()
            assert page.evaluate("state.profile") == "default"

            # The same module uses a query route on Pages, retaining its real document path.
            codec = page.evaluate("""async()=>{const {parseRoute,routeURL}=await import('/router.js');
              const url=routeURL({view:'observations',workspace:'default',seq:42,q:'invoice'},
                {base:'https://phishdestroy.github.io/TgWitness/demo/?lang=de',staticDemo:true});
              return {url:url.href,parsed:parseRoute(url,{staticDemo:true}),bad:parseRoute('https://example.test/parameters#%bad')};
            }""")
            assert urlsplit(codec["url"]).path == "/TgWitness/demo/"
            assert parse_qs(urlsplit(codec["url"]).query)["route"] == ["/journal/event/42"]
            assert codec["parsed"]["seq"] == 42 and codec["parsed"]["q"] == "invoice"
            fallback = browser.new_page()
            fallback.add_init_script("window.TGW_ONLINE_DEMO=true")
            unlock(fallback, app)
            fallback.locator('.sidebar [data-view="sources"]').click()
            assert urlsplit(fallback.url).path == "/"
            assert parse_qs(urlsplit(fallback.url).query)["route"] == ["/sources"]
            fallback.reload()
            expect(fallback.locator("#view-sources")).to_be_visible()
            fallback.close()
            assert not errors, errors
            browser.close()
    print("Router passed: named paths, reload, filters, record links, Back/Forward, workspace races, legacy fragments and Pages fallback.")


if __name__ == "__main__":
    main()
