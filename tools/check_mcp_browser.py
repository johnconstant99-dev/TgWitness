"""Synthetic MCP setup, drafts, credentials and client configurations. No AI calls."""
import json
from pathlib import Path
import sys
import tempfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_browser import (RunningApp, check_layout, hold_api_response,
                                 launch_browser, release_api_response, unlock)


def main():
    with tempfile.TemporaryDirectory(prefix="mcp-ui-") as scratch, RunningApp(Path(scratch)) as app:
        app.app.state.store.set_target(-1001, "Synthetic archive", "supergroup", True)
        app.app.state.store.append("message.new", {"text": "Never sent to an AI"}, chat_id=-1001, message_id=1)
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            page.context.grant_permissions(["clipboard-read", "clipboard-write"])
            errors, writes = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: writes.append((request.url, request.method, request.post_data_json))
                    if "/api/mcp/" in request.url and request.method != "GET" else None)
            unlock(page, app)
            second = page.evaluate("""async()=>{const result=await json('profiles',{label:'Another case'},{root:true});
                await loadProfiles();return result.id;}""")
            page.locator('.sidebar [data-view="integrations"]').click()
            expect(page.locator("#mcp-fields")).to_be_enabled()
            page.locator("#mcp-name").fill("Analyst laptop")
            page.locator("#mcp-scope summary").first.click()
            chat = page.locator('#mcp-scope input[value="-1001"]')
            chat.check()
            page.locator("#mcp-preset").select_option("overview")
            page.locator("#mcp-duration").select_option("168")
            page.evaluate("window.TgWitnessIntegrations.load()")
            page.evaluate("window.TgWitnessIntegrations.refresh()")
            expect(page.locator("#mcp-name")).to_have_value("Analyst laptop")
            expect(chat).to_be_checked()
            expect(page.locator("#mcp-preset")).to_have_value("overview")
            expect(page.locator("#mcp-tools input:checked")).to_have_count(3)
            expect(page.locator("#mcp-duration")).to_have_value("168")

            # A missing runtime explains how to recover and preserves the draft.
            def unavailable(route):
                response = route.fetch()
                value = response.json()
                value.update(available=False, problem="Install MCP support in this Python environment and restart TgWitness.",
                             install_command="python -m pip install '.[mcp]'")
                route.fulfill(response=response, json=value)
            page.route("**/api/mcp", unavailable)
            page.locator("#mcp-refresh").click()
            expect(page.locator("#mcp-unavailable")).to_be_visible()
            expect(page.locator('#mcp-form button[type="submit"]')).to_be_disabled()
            expect(page.locator("#mcp-install-command")).to_contain_text("pip install")
            page.locator("#mcp-copy-install").click()
            assert "pip install" in page.evaluate("navigator.clipboard.readText()")
            expect(chat).to_be_checked()
            page.unroute("**/api/mcp", unavailable)
            page.locator("#mcp-recheck").click()
            expect(page.locator("#mcp-unavailable")).to_be_hidden()
            expect(page.locator("#mcp-fields")).to_be_enabled()
            expect(page.locator("#mcp-name")).to_have_value("Analyst laptop")
            page.locator('#mcp-form button[type="submit"]').click()
            expect(page.locator("#mcp-created")).to_be_visible()
            token = page.locator("#mcp-token").input_value()
            assert token.startswith("tgw_mcp_")
            page.locator("#mcp-copy-token").click()
            assert page.evaluate("navigator.clipboard.readText()") == token
            creation = next(body for url, method, body in writes if url.endswith("/mcp/connections") and method == "POST")
            assert creation["workspaces"] == {"default": [-1001]}
            assert set(creation["tools"]) == {"list_workspaces", "list_chats", "get_capture_status"}

            # Refresh is allowed to change usage counters, never inputs or the shown-once secret.
            page.evaluate("window.TgWitnessIntegrations.load()")
            page.evaluate("window.TgWitnessIntegrations.refresh()")
            expect(page.locator("#mcp-token")).to_have_value(token)
            expect(chat).to_be_checked()
            for client in ("vscode", "cursor", "claude-code", "windsurf", "other", "claude-desktop"):
                page.locator("#mcp-client").select_option(client)
                config_text = page.locator("#mcp-config").inner_text()
                config = json.loads(config_text)
                assert token not in config_text
                if client == "vscode":
                    assert config["inputs"][0]["password"] is True
                    assert config["servers"]["tgwitness"]["headers"]["Authorization"] == "Bearer ${input:tgwitness-token}"
                elif client == "cursor":
                    assert config["mcpServers"]["tgwitness"]["headers"]["Authorization"] == "Bearer ${env:TGWITNESS_MCP_TOKEN}"
                elif client == "claude-code":
                    assert config["mcpServers"]["tgwitness"]["headers"]["Authorization"] == "Bearer ${TGWITNESS_MCP_TOKEN}"
                elif client == "windsurf":
                    assert config["mcpServers"]["tgwitness"]["serverUrl"] == app.url + "/mcp"
                    assert "<PASTE_TOKEN_HERE>" in config_text
                elif client == "claude-desktop":
                    expect(page.locator("#mcp-mode")).to_be_disabled()
                    assert config["mcpServers"]["tgwitness"]["args"] == ["-m", "tgwitness.mcp_server", "--url", app.url + "/mcp"]
                    assert config["mcpServers"]["tgwitness"]["env"]["TGWITNESS_MCP_TOKEN"] == "<PASTE_TOKEN_HERE>"
                else:
                    assert config["url"] == app.url + "/mcp"
            page.locator("#mcp-client").select_option("vscode")
            page.locator("#mcp-mode").select_option("http")
            page.locator("#mcp-url").fill("https://synthetic-test.trycloudflare.com/mcp")
            expect(page.locator("#mcp-url-warning")).to_be_visible()
            page.locator("#mcp-url").fill("http://remote.invalid/mcp")
            expect(page.locator("#mcp-check")).to_be_disabled()
            page.locator("#mcp-url").fill(app.url + "/mcp")
            expect(page.locator("#mcp-url-warning")).to_be_hidden()
            with page.expect_download() as download:
                page.locator("#mcp-download").click()
            assert token not in Path(download.value.path()).read_text()
            assert token not in page.evaluate("JSON.stringify([localStorage,sessionStorage])")
            page.locator("#mcp-copy-config").click()
            copied = page.evaluate("navigator.clipboard.readText()")
            assert token not in copied and json.loads(copied)["servers"]["tgwitness"]["type"] == "http"

            # Handshake is real, using only the local synthetic archive; no tool call.
            page.locator("#mcp-check").click()
            expect(page.locator("#mcp-check-result")).to_contain_text("No messages were read.", timeout=20000)
            expect(page.locator("#mcp-check-result")).to_contain_text("3 tools")
            expect(page.locator("#mcp-check-result")).to_contain_text("list_workspaces")
            assert "Never sent to an AI" not in page.locator("#mcp-check-result").inner_text()

            for width in (1440, 390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                for theme in ("light", "dark"):
                    page.evaluate("theme=>document.documentElement.dataset.theme=theme", theme)
                    check_layout(page)
                    if width in (1440, 390):
                        dest = Path("test-results/mcp")
                        dest.mkdir(parents=True, exist_ok=True)
                        page.evaluate("scrollTo(0,0)")
                        page.screenshot(path=str(dest / f"{width}-{theme}.png"), full_page=True,
                                        mask=[page.locator("#mcp-token")], animations="disabled")
            page.set_viewport_size({"width": 1440, "height": 1000})
            rotate = page.locator("#mcp-list button", has_text="Rotate token")
            count = len(writes)
            page.once("dialog", lambda dialog: dialog.dismiss())
            rotate.click()
            assert len(writes) == count
            page.once("dialog", lambda dialog: dialog.accept())
            rotate.click()
            expect(page.locator("#mcp-token")).not_to_have_value(token)
            rotated = page.locator("#mcp-token").input_value()
            assert rotated.startswith("tgw_mcp_")
            assert page.request.get(app.url + "/api/archive/identity", headers={"Authorization": "Bearer " + token}).status == 401
            page.locator("#mcp-list details summary").click()
            expect(page.locator("#mcp-list")).to_contain_text("Requests:")
            expect(page.locator("#mcp-list")).to_contain_text("Last address:")

            # A completed check from A must not appear in B after switching.
            hold_api_response(page, "/api/mcp/check")
            page.locator("#mcp-check").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true", timeout=20000)
            page.locator("#mcp-url").fill("http://remote.invalid/mcp")
            expect(page.locator("#mcp-check")).to_be_disabled()
            release_api_response(page)
            page.wait_for_function("!document.getElementById('mcp-check').hasAttribute('aria-busy')")
            expect(page.locator("#mcp-check")).to_be_disabled()
            expect(page.locator("#mcp-check-result")).to_have_text("")
            page.locator("#mcp-url").fill(app.url + "/mcp")
            hold_api_response(page, "/api/mcp/check")
            page.locator("#mcp-check").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true", timeout=20000)
            page.evaluate("id=>switchProfile(id)", second)
            expect(page.locator("#mcp-token")).to_have_value("")
            expect(page.locator("#mcp-created")).to_be_hidden()
            expect(page.locator("#mcp-name")).to_have_value("")
            expect(page.locator("#mcp-scope input:checked")).to_have_count(0)
            release_api_response(page)
            expect(page.locator("#mcp-check-result")).to_have_text("")
            page.once("dialog", lambda dialog: dialog.dismiss())
            page.locator("#mcp-list button", has_text="Revoke").click()
            expect(page.locator("#mcp-list")).not_to_contain_text("Revoked")
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#mcp-list button", has_text="Revoke").click()
            expect(page.locator("#mcp-list")).to_contain_text("Revoked")
            assert page.request.get(app.url + "/api/archive/identity", headers={"Authorization": "Bearer " + rotated}).status == 401
            page.evaluate("switchProfile('default')")
            page.locator("#mcp-name").fill("Delayed issue")
            page.locator("#mcp-scope summary").first.click()
            page.locator('#mcp-scope input[value="-1001"]').check()
            hold_api_response(page, "/api/mcp/connections")
            page.locator('#mcp-form button[type="submit"]').click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.evaluate("id=>switchProfile(id)", second)
            release_api_response(page)
            expect(page.locator("#mcp-token")).to_have_value("")
            expect(page.locator("#mcp-created")).to_be_hidden()
            expect(page.locator("#mcp-name")).to_have_value("")
            page.evaluate("lock()")
            expect(page.locator("#mcp-token")).to_have_value("")
            expect(page.locator("#mcp-name")).to_have_value("")
            assert not errors, errors
            browser.close()
    print("MCP UI passed: persistent drafts, availability recovery, scoped tools, six client configs, diagnostics, rotation/revocation, workspace isolation and mobile.")


if __name__ == "__main__":
    main()
