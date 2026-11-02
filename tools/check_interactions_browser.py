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

from tools.check_browser import RunningApp, launch_browser, hold_api_response, release_api_response, lock_panel, navigate_panel, unlock
from tools.browser_fixtures import InteractionClient
from tools.browser_fixtures import CHAT, saved_session
from tools.browser_fixtures import offer
from tools.browser_fixtures import SHOP_BOT
from tgwitness.evidence import export_file
from tgwitness.verify import verify_bundle


def open_composer(page):
    allow_writes(page)
    if page.locator("#chat-compose-open").is_visible():
        page.locator("#chat-compose-open").click()
    expect(page.locator("#chat-compose")).to_be_visible()


def allow_writes(page):
    if page.locator('#chat-read-only').is_checked():
        page.locator('#chat-read-only').uncheck()


def confirm_action(page):
    """Legacy transport checks still exercise the explicit per-chat consent gate."""
    page.wait_for_function("()=>document.querySelector('dialog.chat-action-confirm[open]')||!actionBusy&& !document.querySelector('#chat-send')?.hasAttribute('aria-busy')")
    dialog = page.locator('dialog.chat-action-confirm[open]')
    if dialog.count():
        if dialog.locator('#chat-action-remember').is_visible():
            dialog.locator('#chat-action-remember').check()
        dialog.locator('[data-confirm-action="true"]').click()


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
            # Sending acts as the account in the chat: closed until asked for, with a warning when opened.
            expect(page.locator("#chat-compose")).to_be_hidden()
            expect(page.locator('#chat-read-only')).to_be_checked()
            allow_writes(page)
            expect(page.locator("#chat-compose-open")).to_contain_text("Write as")
            open_composer(page)
            expect(page.locator("#chat-compose-warning")).to_contain_text("Chat members will see this message")
            page.locator("#chat-message").fill("<b>plain text from the panel</b>")
            page.locator("#chat-send").click()
            confirm_action(page)
            expect(page.locator("#interaction-result")).to_contain_text("Action completed")
            try:
                expect(page.locator("#chat-feed .bubble-text").last).to_have_text("<b>plain text from the panel</b>")
            except AssertionError:
                print('Receipt:', page.locator('#interaction-result').inner_text(), 'Errors:', errors)
                print('Chat messages:', page.evaluate('state.chatMessages.map(m=>({id:m.message_id,text:m.text,captured:m.captured}))'))
                raise
            assert page.locator("#chat-feed .bubble-text b").count() == 0
            page.locator("#msg-10 .bubble-meta button", has_text="Reply").click()
            page.locator("#chat-message").fill("reply from panel")
            page.locator("#chat-send").click()
            confirm_action(page)
            expect(page.locator("#chat-feed .reply-quote")).to_have_count(1)
            page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button").click()
            expect(page.locator("#interaction-result")).to_contain_text("Recorded answer")
            expect(page.locator("#interaction-result")).to_contain_text("https://example.test/receipt")
            press = page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button")
            expect(page.locator("#chat-send")).to_be_enabled()
            expect(press).to_be_enabled()
            callbacks = len(server.app.state.collector.client.callbacks)

            page.evaluate("""() => {
              const original=window.fetch;let arm=true,fail=false;
              window.interactionRefreshFailure={hits:0,backgroundFailed:false,
                restore(){window.fetch=original;delete window.interactionRefreshFailure;}};
              window.fetch=async(...args)=>{
                if(fail&&String(args[0]).endsWith('/api/status')){
                  window.interactionRefreshFailure.hits++;
                  throw new TypeError('Synthetic status connection failure');
                }
                const result=await original(...args);
                if(arm&&String(args[0]).endsWith('/api/interactions')){
                  arm=false;fail=true;
                  // A competing poll must not consume the post-action outage fixture.
                  await refreshStatus().catch(()=>{window.interactionRefreshFailure.backgroundFailed=true;});
                }
                return result;
              };
            }""")
            press.click()
            try:
                expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
                expect(page.locator("#interaction-result")).to_contain_text("Chat refresh failed")
                expect(page.locator("#toast")).to_be_hidden()
                assert page.evaluate("interactionRefreshFailure.backgroundFailed")
                assert page.evaluate("interactionRefreshFailure.hits") >= 2
                assert len(server.app.state.collector.client.callbacks) == callbacks + 1
            finally:
                page.evaluate("interactionRefreshFailure.restore()")

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
              const original=window.fetch;
              window.interactionJoinFailure={restore(){window.fetch=original;delete window.interactionJoinFailure;}};
              window.fetch=async(...args)=>{
                if(String(args[0]).endsWith(path)){
                  throw new TypeError('Synthetic new-chat connection failure');
                }
                return original(...args);
              };
            }""", "/api/chats/" + str(CHAT) + "/messages?limit=60")
            page.locator("#chat-link-preview button").click()
            confirm_action(page)
            expect(page.locator("#chat-name")).to_have_text("Channel 123")
            expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
            expect(page.locator("#interaction-result")).to_contain_text("Chat refresh failed")
            expect(page.locator("#chat-link-preview button")).to_have_count(0)
            expect(page.locator("#toast")).to_be_hidden()
            assert len(server.app.state.collector.client.joined) == 1
            expect(page.locator("#chat-feed")).to_contain_text("Could not load data")
            expect(page.locator("#chat-send")).to_be_disabled()
            page.evaluate("interactionJoinFailure.restore()")
            page.locator("#chat-feed").get_by_role("button", name="Retry", exact=True).click()
            expect(page.locator("#chat-send")).to_be_enabled()
            expect(page.locator("#interaction-result")).to_contain_text("Action completed and recorded.")
            assert len(server.app.state.collector.client.joined) == 1
            page.locator(".chat-item", has_text="Synthetic shop bot").click()
            allow_writes(page)
            page.locator("#msg-10 .msg-button", has_text="I paid").get_by_role("button").click()
            confirm_action(page)
            expect(page.locator("#interaction-result")).to_contain_text("Recorded answer")

            assert page.locator('#interaction-result a[href^="https:"]').count() == 0
            expect(page.locator("#chat-message")).to_be_enabled()
            open_composer(page)
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
            open_composer(page)
            page.locator("#chat-message").fill("Message intended for the group")
            with page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith("/api/interactions")
                    and response.request.post_data_json.get("action") == "send"
                    and response.request.post_data_json.get("chat_id") == CHAT
                    and response.request.post_data_json.get("text") == "Message intended for the group") as group_send:
                page.locator("#chat-send").click()
                expect(page.locator('dialog.chat-action-confirm[open]')).to_be_visible()
                # Polling during consent must not make a pending send look completed.
                page.evaluate("refreshStatus()")
                expect(page.locator("#chat-send")).to_have_attribute("aria-busy", "true")
                expect(page.locator("#chat-send")).to_be_disabled()
                assert len(server.app.state.collector.client.sent) == sent
                confirm_action(page)
            assert group_send.value.ok and group_send.value.json()["status"] == "succeeded"
            expect(page.locator("#chat-send")).to_be_enabled()
            assert len(server.app.state.collector.client.sent) == sent + 1
            assert server.app.state.collector.client.sent[-1][0] == 123
            assert server.app.state.collector.client.sent[-1][1] == "Message intended for the group"

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
            open_composer(page)
            for width, height in [(1440, 1000), (390, 844), (320, 800)]:
                page.set_viewport_size({"width": width, "height": height})
                for theme in ("light", "dark"):
                    if width < 768:
                        page.locator("#navigation-toggle").click()
                    page.locator(f'#workspace [data-theme-choice="{theme}"]').click()
                    expect(page.locator("html")).to_have_attribute("data-theme", theme)
                    if width < 768:
                        page.locator(".mobile-nav-close").click()
                    page.locator("#chat-compose").scroll_into_view_if_needed()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    page.screenshot(path=str(output / f"chat-{width}-{theme}.png"), full_page=True)

            page.locator("#chat-message").fill("private unfinished draft")
            lock_panel(page)
            expect(page.locator("#gate")).to_be_visible()
            assert page.evaluate("""()=>{const root=panelRoots.get('chats');
              return !root.isConnected&&root.querySelector('#chat-message').value==='';}""")

            unlock(page, server)
            navigate_panel(page, "chats")
            expect(page.locator("#chat-send")).to_have_text("Send")
            expect(page.locator("#chat-message")).to_have_attribute("placeholder", "Write a message…")
            expect(page.locator("#chat-compose-account")).to_contain_text("Sending as")
            # The Evidence goal records without acting: the panel and the API both refuse to send.
            sent = len(server.app.state.collector.client.sent)
            server.app.state.store.set_setting("setup", {"goal": "evidence"})
            page.evaluate("refreshStatus()")
            expect(page.locator('#chat-read-only')).to_be_disabled()
            expect(page.locator('.chat-safety-hint')).to_contain_text("Sending is off")
            refused = page.evaluate("""chat=>json('interactions',{request_id:'evidence-goal-refusal-check',action:'send',
                chat_id:chat,text:'must not be sent'}).then(()=>'sent',error=>error.message)""", CHAT)
            assert "Evidence for a case" in refused, refused
            assert len(server.app.state.collector.client.sent) == sent
            server.app.state.store.set_setting("setup", None)
            assert not errors, errors
            browser.close()
        archive = export_file(store, server.app.state.vault, "zip")
        verified = verify_bundle(archive)
        assert verified["events"] > 10
        receipt = {"checks": ["send plain text", "reply", "callback answer and URL", "preview before join",
                              "join and observe", "light/dark at 1440/390/320", "lock clears draft",
                              "English controls", "signed evidence verifies", "no browser errors",
                              "refresh failure preserves receipt and request ID", "chat switch blocks sending",
                              "stale chat response ignored", "join receipt survives destination load failure",
                              "status poll preserves pending consent", "group send confirms exact recipient and text"],
                   "events_verified": verified["events"]}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
