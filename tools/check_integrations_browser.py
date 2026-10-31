"""MCP connection creation, secret handling and source links with synthetic records."""
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import sync_playwright, expect

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import (RunningApp, launch_browser, unlock, check_layout,
                                 hold_api_response, release_api_response, navigate_panel)


def main():
    with tempfile.TemporaryDirectory(prefix="integration-check-") as scratch, RunningApp(Path(scratch)) as app:
        app.app.state.store.set_target(-1001, "Synthetic archive", "supergroup", True)
        record = app.app.state.store.append("message.new", {"text": "A verifiable source"}, chat_id=-1001, message_id=1)
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, app)
            hold_api_response(page, "/api/events?limit=200&include_count=true&hide_system=true")
            page.evaluate("()=>{window.pendingIntegrationJournal=navigate('observations');}")
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            navigate_panel(page, "integrations")
            expect(page.locator("#mcp-list")).to_contain_text("No archive connections")
            release_api_response(page)
            page.evaluate("window.pendingIntegrationJournal")
            expect(page.locator("#view-integrations")).to_be_visible()
            page.locator("#mcp-name").fill("Synthetic client")
            page.locator("#mcp-scope summary").first.click()
            page.locator('#mcp-scope input[value="-1001"]').check()
            page.locator('#mcp-form button[type="submit"]').click()
            expect(page.locator("#mcp-created")).to_be_visible()
            token = page.locator("#mcp-token").input_value()
            assert token.startswith("tgw_mcp_")
            assert page.locator("#mcp-token").get_attribute("type") == "password"
            with page.expect_download() as download:
                page.locator("#mcp-download").click()
            data = Path(download.value.path()).read_text()
            config = json.loads(data)
            assert token not in data
            assert config["inputs"][0]["password"] is True
            assert config["servers"]["tgwitness"]["type"] == "http"
            for theme in ("light", "dark"):
                page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                page.wait_for_timeout(350)
                check_layout(page)
                page.mouse.move(900, 20)
                page.evaluate("scrollTo(0,0)")
                dest = Path("test-results/integrations")
                dest.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(dest / (theme + ".png")), full_page=True,
                                mask=[page.locator("#mcp-token")], mask_color="#64748b", animations="disabled")
            navigate_panel(page, "chats")
            expect(page.locator("#view-integrations")).to_have_count(0)
            assert page.evaluate("$('mcp-token').value") == ""
            navigate_panel(page, "integrations")
            expect(page.locator("#mcp-list")).to_contain_text("Synthetic client")
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator('#mcp-list button', has_text="Revoke").click()
            expect(page.locator("#mcp-list")).to_contain_text("Revoked")
            page.goto(app.url + "/?workspace=default&event=" + str(record["seq"]) + "#journal")
            expect(page.locator("#detail-drawer")).to_be_visible()
            expect(page.locator("#detail-drawer")).to_contain_text("A verifiable source")
            for language in ("en", "de", "ru", "he"):
                page.goto(app.url + "/?lang=" + language)
                prefix = "" if language == "en" else language + "/"
                links = page.evaluate("""async()=>{await viewReady;return [...panelRoots.values()].flatMap(root=>
                    [...root.querySelectorAll('[data-site-doc]')].map(link=>({key:link.dataset.siteDoc,href:link.getAttribute('href')})));}""")
                assert len(links) == 4
                for link in links:
                    assert link["href"] == ("https://phishdestroy.github.io/TgWitness/"
                                            + prefix + "docs/reference/" + link["key"] + "/"), (language, link)
            assert not errors, errors
            browser.close()
    print("Integration UI passed: scoped credential, secret-free configuration, revocation and source link.")


if __name__ == "__main__":
    main()
