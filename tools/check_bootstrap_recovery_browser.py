"""Temporary bootstrap failures preserve sessions; actual denial still signs out."""
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tgwitness.access import Refused
from tools.check_browser import RunningApp, launch_browser, unlock


def valid_session(server, token):
    try:
        return server.app.state.access.resolve(token, "127.0.0.1") is not None
    except Refused:
        return False


def main():
    with tempfile.TemporaryDirectory(prefix="bootstrap-recovery-") as scratch, \
            RunningApp(Path(scratch)) as server, sync_playwright() as playwright:
        browser = launch_browser(playwright)
        page = browser.new_page()
        errors, logouts = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: logouts.append(request.method)
                if urlsplit(request.url).path == "/api/access/logout" else None)
        unlock(page, server)
        token = page.evaluate("state.token")

        for outcome in (503, 429, "network"):
            def outage(route):
                if outcome == "network":
                    route.abort("failed")
                else:
                    route.fulfill(status=outcome, content_type="application/json",
                                  body='{"detail":"Synthetic temporary status outage"}')

            page.route("**/api/status", outage)
            page.reload()
            expect(page.locator("#bootstrap-retry")).to_be_visible()
            expect(page.locator("#workspace")).to_be_hidden()
            assert page.evaluate("sessionStorage.getItem('tgwitness-token')") == token
            assert valid_session(server, token) and not logouts
            page.unroute("**/api/status", outage)
            page.locator("#bootstrap-retry").click()
            expect(page.locator("#workspace")).to_be_visible()
            assert page.evaluate("state.token") == token

        # The session created by the first login also survives an unavailable
        # initial status response, before unlock() has rendered the workspace.
        fresh_context = browser.new_context()
        fresh = fresh_context.new_page()
        fresh.route("**/api/status", lambda route: route.fulfill(status=503,
            content_type="application/json", body='{"detail":"Synthetic initial status outage"}'))
        fresh.goto(server.url)
        fresh.locator("#panel-token").fill(server.app.state.vault.token)
        fresh.locator("#unlock-form button").click()
        expect(fresh.locator("#bootstrap-retry")).to_be_visible()
        first_token = fresh.evaluate("sessionStorage.getItem('tgwitness-token')")
        assert first_token and valid_session(server, first_token)
        fresh.unroute("**/api/status")
        fresh.locator("#bootstrap-retry").click()
        expect(fresh.locator("#workspace")).to_be_visible()
        assert fresh.evaluate("state.token") == first_token
        fresh_context.close()

        # Language navigation uses the same stored session and retains its
        # requested language even if the new document encounters an outage.
        page.route("**/api/status", lambda route: route.fulfill(status=503,
            content_type="application/json", body='{"detail":"Synthetic language reload outage"}'))
        page.evaluate("setLanguage('ru')")
        expect(page).to_have_url(re.compile(r"[?&]lang=ru(?:&|$)"))
        expect(page.locator("#bootstrap-retry")).to_be_visible()
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')") == token
        assert valid_session(server, token) and not logouts
        page.unroute("**/api/status")
        page.locator("#bootstrap-retry").click()
        expect(page.locator("#workspace")).to_be_visible()
        expect(page.locator("html")).to_have_attribute("lang", "ru")

        # An explicit authorization denial must still clear and end the session.
        page.route("**/api/status", lambda route: route.fulfill(status=401,
            content_type="application/json", body='{"detail":"Synthetic authorization ended"}'))
        with page.expect_response(lambda response: urlsplit(response.url).path == "/api/access/logout"):
            page.reload()
        expect(page.locator("#workspace")).to_be_hidden()
        expect(page.locator("#bootstrap-retry")).to_have_count(0)
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')") is None
        assert not valid_session(server, token)
        page.unroute("**/api/status")

        page.locator("#panel-token").fill(server.app.state.vault.token)
        page.locator("#unlock-form button").click()
        expect(page.locator("#workspace")).to_be_visible()
        revoked = page.evaluate("state.token")
        principal = server.app.state.access.resolve(revoked, "127.0.0.1")
        panel_url = page.url
        # Revoke while this document is closed so SSE cannot consume the
        # revocation first: this assertion exercises bootstrap authorization.
        page.goto("about:blank")
        server.app.state.access.end(principal.session_id, "Synthetic administrator revocation")
        page.goto(panel_url)
        expect(page.locator("#login-error")).not_to_be_empty()
        expect(page.locator("#workspace")).to_be_hidden()
        expect(page.locator("#bootstrap-retry")).to_have_count(0)
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')") is None
        assert not errors, errors
        browser.close()
    print("Bootstrap recovery passed: 503/429/network retry, first login, language navigation, 401 and revoked access.")


if __name__ == "__main__":
    main()
