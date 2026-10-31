"""Mini-client acceptance against a synthetic Telegram transport; no live account is used."""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if (ROOT / ".playwright").is_dir():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".playwright"))

import requests
from playwright.sync_api import expect, sync_playwright

from tools.check_browser import RunningApp, launch_browser, hold_api_response, release_api_response
from tests.test_interactions import InteractionClient
from tests.test_collector import CHAT, saved_session
from tests.test_investigation import offer
from tests.test_scope import SHOP_BOT
from tgwitness.evidence import export_file
from tgwitness.verify import verify_bundle


def main():
    output = ROOT / "test-results" / "interactions-browser"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as temporary, RunningApp(
            Path(temporary), client_factory=InteractionClient) as server:
        headers = {"Authorization": "Bearer " + server.app.state.vault.token}
        response = requests.post(server.url + "/api/auth/configure", headers=headers,
                                 json={"api_id": 123, "api_hash": "a" * 32, "session": saved_session()}, timeout=10)
        response.raise_for_status()
        store = server.app.state.store
        store.set_target(SHOP_BOT, "Synthetic shop bot", "bot", True)
        asyncio.run(server.app.state.collector.capture_message(offer(), "message.new", SHOP_BOT))
        errors = []
        with sync_playwright() as p:
            browser = launch_browser(p)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, locale="en-US", reduced_motion="reduce")
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(server.url)
            page.locator("#panel-token").fill(server.app.state.vault.token)
            page.locator("#unlock-form button").click()
            try:
                expect(page.locator("#workspace")).to_be_visible()
            except AssertionError:
                print("Browser errors:", errors)
                print("Login error:", page.locator("#login-error").inner_text())
                page.screenshot(path=str(output / "failure.png"), full_page=True)
                raise
            page.locator('[data-view="chats"]').click()
            expect(page.locator("#chat-message")).to_be_enabled()
            page.locator("#chat-message").fill("<b>plain text from the panel</b>")
            page.locator("#chat-send").click()
            expect(page.locator("#interaction-result")).to_contain_text("Action completed")
            expect(page.locator("#chat-feed .bubble-text").last).to_have_text("<b>plain text from the panel</b>")
            assert page.locator("#chat-feed .bubble-text b").count() == 0
            page.locator("#msg-10 .bubble-meta button", has_text="Reply").click()
            page.locator("#chat-message").fill("reply from panel")
            page.locator("#chat-send").click()
            expect(page.locator("#chat-feed .reply-quote")).to_have_count(1)
            page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button").click()
            expect(page.locator("#interaction-result")).to_contain_text("Recorded answer")
            expect(page.locator("#interaction-result")).to_contain_text("https://example.test/receipt")
            press = page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button")
            expect(press).to_be_enabled()
            callbacks = len(server.app.state.collector.client.callbacks)

            page.evaluate("""() => {
              const original=window.fetch;let arm=true,fail=false;
              window.fetch=async(...args)=>{
                if(fail&&String(args[0]).endsWith('/api/status')){
                  fail=false;throw new TypeError('Synthetic status connection failure');
                }
                const result=await original(...args);
                if(arm&&String(args[0]).endsWith('/api/interactions')){arm=false;fail=true;}
                return result;
              };
            }""")
            press.click()
            expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
            expect(page.locator("#interaction-result")).to_contain_text("Chat refresh failed")
            expect(page.locator("#toast")).to_be_hidden()
            assert len(server.app.state.collector.client.callbacks) == callbacks + 1

            expect(press).to_be_enabled()
            press.click()
            expect(page.locator("#interaction-result")).to_contain_text("Recorded answer")
            expect(page.locator("#chat-send")).to_be_enabled()
            assert len(server.app.state.collector.client.callbacks) == callbacks + 1
            page.locator(".chat-open summary").click()
            page.locator("#chat-link").fill("https://t.me/+invite_hash")
            page.locator("#chat-preview-button").click()
            expect(page.locator("#chat-link-preview")).to_contain_text("Preview group")
            assert not server.app.state.collector.client.joined
            page.locator("#chat-link").fill("@shop_bot")
            expect(page.locator("#chat-link-preview button")).to_have_count(0)
            page.locator("#chat-link").fill("https://t.me/+invite_hash")
            page.locator("#chat-preview-button").click()
            expect(page.locator("#chat-link-preview")).to_contain_text("Preview group")
            page.evaluate("""path=>{
              const original=window.fetch;let fail=true;
              window.fetch=async(...args)=>{
                if(fail&&String(args[0]).endsWith(path)){
                  fail=false;throw new TypeError('Synthetic new-chat connection failure');
                }
                return original(...args);
              };
            }""", "/api/chats/" + str(CHAT) + "/messages?limit=60")
            page.locator("#chat-link-preview button").click()
            expect(page.locator("#chat-name")).to_have_text("Channel 123")
            expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
            expect(page.locator("#interaction-result")).to_contain_text("Chat refresh failed")
            expect(page.locator("#chat-link-preview button")).to_have_count(0)
            expect(page.locator("#toast")).to_be_hidden()
            assert len(server.app.state.collector.client.joined) == 1
            expect(page.locator("#chat-feed")).to_contain_text("Could not load data")
            expect(page.locator("#chat-send")).to_be_disabled()
            page.locator("#chat-feed").get_by_role("button", name="Retry", exact=True).click()
            expect(page.locator("#chat-send")).to_be_enabled()
            expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
            assert len(server.app.state.collector.client.joined) == 1
            page.locator(".chat-item", has_text="Synthetic shop bot").click()
            page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button").click()
            expect(page.locator("#interaction-result")).to_contain_text("Recorded answer")

            assert page.locator('#interaction-result a[href^="https:"]').count() == 0
            expect(page.locator("#chat-message")).to_be_enabled()
            page.locator("#chat-message").fill("Draft intended for the bot")
            sent = len(server.app.state.collector.client.sent)
            hold_api_response(page, "/api/chats/" + str(CHAT) + "/messages?limit=60")
            page.locator(".chat-item", has_text="Channel 123").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            expect(page.locator("#chat-name")).to_have_text("Channel 123")
            expect(page.locator("#chat-message")).to_have_value("")
            expect(page.locator("#chat-message")).to_be_disabled()
            expect(page.locator("#chat-send")).to_be_disabled()

            page.eval_on_selector("#chat-compose", "form=>form.dispatchEvent(new Event('submit',{cancelable:true}))")
            assert len(server.app.state.collector.client.sent) == sent
            release_api_response(page)
            expect(page.locator("#chat-message")).to_be_enabled()
            page.locator("#chat-message").fill("Message intended for the group")
            page.locator("#chat-send").click()
            expect(page.locator("#chat-send")).to_be_enabled()
            assert server.app.state.collector.client.sent[-1][0] == 123

            page.locator(".chat-item", has_text="Synthetic shop bot").click()
            expect(page.locator("#chat-message")).to_be_enabled()
            hold_api_response(page, "/api/chats/" + str(CHAT) + "/messages?limit=60")
            page.locator(".chat-item", has_text="Channel 123").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.locator(".chat-item", has_text="Synthetic shop bot").click()
            expect(page.locator("#chat-name")).to_have_text("Synthetic shop bot")
            expect(page.locator("#chat-message")).to_be_enabled()
            release_api_response(page)
            expect(page.locator("#chat-name")).to_have_text("Synthetic shop bot")
            expect(page.locator("#chat-feed")).not_to_contain_text("Message intended for the group")
            for width, height in [(1440, 1000), (390, 844), (320, 800)]:
                page.set_viewport_size({"width": width, "height": height})
                for theme in ("light", "dark"):
                    page.locator(f'#workspace [data-theme-choice="{theme}"]').click()
                    expect(page.locator("html")).to_have_attribute("data-theme", theme)
                    page.locator("#chat-compose").scroll_into_view_if_needed()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    page.screenshot(path=str(output / f"chat-{width}-{theme}.png"), full_page=True)

            page.locator("#chat-message").fill("private unfinished draft")
            page.locator("#top-lock").click()
            expect(page.locator("#gate")).to_be_visible()
            assert page.locator("#chat-message").input_value() == ""

            page.reload()
            page.locator("#panel-token").fill(server.app.state.vault.token)
            page.locator("#unlock-form button").click()
            page.locator('[data-view="chats"]').click()
            expect(page.locator("#chat-send")).to_have_text("Send")
            expect(page.locator("#chat-message")).to_have_attribute("placeholder", "Write a message…")
            expect(page.locator("#chat-compose-account")).to_contain_text("Sending as")
            assert not errors, errors
            browser.close()
        archive = export_file(store, server.app.state.vault, "zip")
        verified = verify_bundle(archive)
        assert verified["events"] > 10
        receipt = {"checks": ["send plain text", "reply", "callback answer and URL", "preview before join",
                              "join and observe", "light/dark at 1440/390/320", "lock clears draft",
                              "English controls", "signed evidence verifies", "no browser errors",
                              "refresh failure preserves receipt and request ID", "chat switch blocks sending",
                              "stale chat response ignored", "join receipt survives destination load failure"],
                   "events_verified": verified["events"]}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
