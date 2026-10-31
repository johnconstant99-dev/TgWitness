"""Slow responses must not rewind the workspace or interrupt reading saved edits."""
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser


def hold_once(page, path):
    page.evaluate("""path => {
      const original = window.fetch;
      let held = false;
      window.refreshRequests = 0;
      window.fetch = async (...args) => {
        const matches = String(args[0]).endsWith(path);
        if (matches) window.refreshRequests++;
        const response = await original(...args);
        if (matches && !held) {
          held = true;
          await new Promise(resolve => {
            window.releaseRefresh = () => { window.fetch = original; resolve(); };
            document.documentElement.dataset.refreshHeld = 'true';
          });
        }
        return response;
      };
    }""", path)


def release(page):
    page.evaluate("async () => {window.releaseRefresh(); await window.heldRefresh;}")


def main():
    with tempfile.TemporaryDirectory(prefix="refresh-check-") as scratch, RunningApp(
            Path(scratch), demo=True) as server, sync_playwright() as p:
        browser = launch_browser(p)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script("""(() => {
          const interval = window.setInterval;
          window.setInterval = (callback, delay, ...args) => {
            if (delay === 5000) {window.acceptancePoll = callback; return 0;}
            return interval(callback, delay, ...args);
          };
        })();""")
        with page.expect_response(
            lambda response: "/api/chats/" in urlsplit(response.url).path
            and urlsplit(response.url).path.endswith("/messages")
            and response.request.method == "GET", timeout=20000,
        ) as initial_messages:
            page.goto(server.url)
        assert initial_messages.value.ok, initial_messages.value.status
        try:
            expect(page.locator("#chat-feed .msg").first).to_be_visible()
        except AssertionError:
            print("Demo startup:", page.evaluate("""()=>({error:$('login-error').textContent,view:state.view,
              revision:state.workspaceRevision,opened:state.opened,authenticated:!!state.token,accessStarted})"""), errors, flush=True)
            raise

        hold_once(page, "/api/status")
        page.evaluate("window.heldRefresh = refreshStatus(); void 0")
        expect(page.locator("html")).to_have_attribute("data-refresh-held", "true")
        server.app.state.store.append("message.new", {"text": "Newer observation", "synthetic": True},
                                      chat_id=-100100002, message_id=900)
        page.evaluate("refreshStatus()")
        assert page.evaluate("()=>(state.status.stats.counts['message.new']||0)+(state.status.stats.counts['message.snapshot']||0)") == 19
        release(page)
        assert page.evaluate("()=>(state.status.stats.counts['message.new']||0)+(state.status.stats.counts['message.snapshot']||0)") == 19
        page.evaluate("()=>navigate('observations')")
        expect(page.locator("#stat-messages")).to_have_text("19")
        page.evaluate("()=>navigate('chats')")

        page.evaluate("delete document.documentElement.dataset.refreshHeld")
        hold_once(page, "/api/status")
        page.evaluate("window.heldRefresh = window.acceptancePoll(); void 0")
        expect(page.locator("html")).to_have_attribute("data-refresh-held", "true")
        page.evaluate("window.acceptancePoll()")
        assert page.evaluate("window.refreshRequests") == 1, "Background refreshes overlap"
        release(page)

        page.locator('[data-demo-filter="edited"]').click()
        versions = page.locator("#chat-feed .versions")
        expect(versions).to_be_visible()
        version_button = page.locator("#chat-feed button.pill-edited").first
        version_button.focus()
        before = versions.inner_text()
        page.evaluate("loadChatMessages('refresh')")
        expect(versions).to_be_visible()
        assert versions.inner_text() == before
        expect(page.locator("#chat-feed button.pill-edited").first).to_be_focused()
        page.locator("#chat-feed button.pill-edited").first.click()
        page.evaluate("loadChatMessages('refresh')")
        expect(versions).to_have_count(0)

        edited = page.locator('#chat-status [data-chat-filter="edited"]')
        edited.focus()
        page.evaluate("refreshStatus()")
        expect(edited).to_be_focused()
        assert not errors, errors
        browser.close()
    print("Slow-response checks passed: newest status, one poll, edit comparison and keyboard focus.")


if __name__ == "__main__":
    main()
