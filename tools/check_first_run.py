"""Check the first setup (settings_hub.py, views/settings-hub.js) beyond tools/test_settings_hub.py.

Every string of the setup and of Settings is translated in each panel language. A new workspace walks the
setup in a browser: each step has its own address and browser Back and Forward move between steps; the
account step asks whether the account is separate, and a main account records only chosen chats (also
refused by the server); Start shows the live check of the collector before leaving; the IP mode change is
in the signed journal. Every step at 360, 600, 1024 and 1440 pixels in English and Russian, at 360 and
1440 in German and right-to-left Arabic, without horizontal overflow.
"""
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

# Product names stay as they are in every language.
NAMES = {"Cloudflare WARP", "GitHub Actions"}
STEPS = range(1, 8)


def setup_keys():
    """The setup's strings: tr() calls plus the literal tables the setup passes through tr()."""
    from i18n_keys import script_keys
    source = (ROOT / "tgwitness/static/views/settings-hub.js").read_text(encoding="utf-8")
    keys = script_keys(source)
    for pattern in (r"\[\s*'[a-z_]+'\s*,\s*'[^']*'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\]",
                    r"(?:message|button|select)\('([^']+)'", r"names=\[([^\]]+)\]"):
        for match in re.finditer(pattern, source):
            for group in match.groups():
                keys += re.findall(r"'([^']+)'", group) if "'" in group else [group]
    for table in (r"const label=\(value\)=>tr\(\{(.*?)\}\[value\]", r"const explanations=\{(.*?)\};"):
        keys += re.findall(r":'([^']+)'", re.search(table, source, re.S).group(1))
    keys += re.findall(r"\['[a-z]+','([^']+)'", re.search(r"const summaries=\[(.*?)\];", source, re.S).group(1))
    # Words that identify values in code (" ", capitals or punctuation mark interface text).
    return [key for key in dict.fromkeys(keys) if re.search(r"[A-Z ]|…", key) and key not in NAMES]


def check_translations():
    from tgwitness import i18n
    keys = setup_keys()
    for lang in i18n.LANGUAGES[1:]:
        words = json.loads((ROOT / "tgwitness/locales" / (lang + ".json")).read_text(encoding="utf-8"))
        missing = [key for key in keys if key not in words]
        assert not missing, (lang, missing[:5])
    return f"ok  translations: {len(keys)} setup strings in {len(i18n.LANGUAGES) - 1} languages, none left in English"


def unlock(page, server):
    page.goto(server.url)
    page.locator("#panel-token").fill(server.app.state.vault.token)
    page.locator("#unlock-form button").click()


def clipped(page):
    """Elements past the screen edge, except inside their own scrolling box."""
    return page.evaluate("""() => [...document.querySelectorAll('#view-first-run *')].filter(e => {
        const r = e.getBoundingClientRect();
        if (!r.width || (r.right <= innerWidth + 1 && r.left >= -1)) return false;
        for (let p = e.parentElement; p && p.id !== 'view-first-run'; p = p.parentElement)
          if (['auto', 'scroll'].includes(getComputedStyle(p).overflowX)) return false;
        return true;
    }).map(e => e.className || e.tagName).slice(0, 5)""")


def check_browser(directory, output):
    from check_browser import RunningApp, launch_browser
    from check_guided_connection import CHECK
    from playwright.sync_api import expect, sync_playwright
    from tgwitness import i18n
    errors, external = [], []
    # A fresh synthetic check: the setup accepts a connection checked within the last five minutes.
    probe = patch("tgwitness.guided_connection.probe",
                  AsyncMock(side_effect=lambda *args, **kwargs: {**CHECK, "checked_at": int(time.time())}))
    async def no_tunnel(*args, **kwargs):
        raise ValueError("No public proxy answers. Try WARP or your own proxy.")
    # The automatic route fails here without downloading a tunnel; the direct route is then chosen.
    tunnel = patch("tgwitness.portable_routes.PortableRoutes.prepare", no_tunnel)
    with probe, tunnel, RunningApp(directory / "panel") as server, sync_playwright() as p:
        store = server.app.state.store
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, locale="en-US", reduced_motion="reduce")
        page = context.new_page()
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.on("request", lambda request: external.append(request.url)
                if urlsplit(request.url).hostname != "127.0.0.1" else None)
        address = lambda step: server.url + f"/first-run/{step}?ws=default"
        nxt = page.locator("#first-run-next")
        unlock(page, server)
        expect(page.locator("#view-first-run")).to_be_visible(timeout=20000)
        expect(page).to_have_url(address(1))
        nxt.click()
        expect(page).to_have_url(address(2))
        page.locator('[data-answer="standard"]').click()
        nxt.click()
        page.locator('[data-answer="watch"]').click()
        nxt.click()
        expect(page).to_have_url(address(4))
        page.go_back()
        expect(page).to_have_url(address(3))
        expect(page.locator('[data-answer="watch"]')).to_have_attribute("aria-pressed", "true")
        page.go_forward()
        expect(page).to_have_url(address(4))

        # The automatic route is tried first on its own; a direct route is chosen once that attempt ends.
        expect(page.locator("#hub-connection-result")).to_have_class(re.compile("failed|working"), timeout=60000)
        page.locator('[data-answer="direct"]').click()
        deadline = time.monotonic() + 30
        while server.app.state.collector.network_config().kind != "direct" and time.monotonic() < deadline:
            page.wait_for_timeout(250)
        assert server.app.state.collector.network_config().kind == "direct", "the checked direct route is applied"
        expect(page.locator("#hub-connection-result")).to_contain_text("25 ms", timeout=20000)
        expect(nxt).to_be_enabled(timeout=20000)
        nxt.click()

        expect(page).to_have_url(address(5))
        page.locator('[data-auth-method="phone"]').first.click()
        page.locator("#phone").fill("+15550001111")
        page.locator("#auth-continue").click()
        page.locator("#code").fill("11111")
        page.locator("#code-form button[type=submit]").click()
        expect(page.locator(".first-run-body .notice.success")).to_be_visible(timeout=15000)
        expect(nxt).to_be_disabled()
        page.locator('[data-answer="main"]').click()
        expect(page.locator(".first-run-body .notice.warning")).to_contain_text("Only chosen chats can be recorded")
        nxt.click()

        expect(page).to_have_url(address(6))
        expect(page.locator('[data-answer="account"]')).to_be_disabled()
        expect(page.locator('[data-answer="folder"]')).to_be_disabled()
        expect(page.locator(".wizard-chats label")).to_have_count(2)
        page.locator(".wizard-chats label", has_text="Synthetic group").locator("input").check()
        nxt.click()
        expect(page).to_have_url(address(7))
        expect(page.locator(".setup-summary")).to_be_visible()
        nxt.click()
        expect(page.locator(".first-run-live .first-run-check")).to_have_count(4, timeout=20000)
        expect(page.get_by_text("Done! What next:")).to_be_visible(timeout=60000)
        page.screenshot(path=str(output / "live-1280.png"), full_page=True)
        assert server.app.state.collector.running, "Start starts recording"
        assert [t["chat_id"] for t in store.targets() if t["enabled"]] == [-1000000000123]
        kinds = {row["kind"] for row in store.db.execute("SELECT kind FROM events")}
        assert {"network.connection_applied", "settings.changed", "sources.selected"} <= kinds, kinds
        labels = page.evaluate("Object.keys(labels)")
        assert {"settings.changed", "sources.selected", "network.connection_applied"} <= set(labels)

        # The server keeps the main-account rule for later edits too.
        headers = {"Authorization": "Bearer " + page.evaluate("state.token")}
        refused = requests.post(server.url + "/api/settings/scope", json={"scope": "account"}, headers=headers, timeout=20)
        assert refused.status_code == 409, refused.text
        plan = requests.post(server.url + "/api/settings/goal/preview", json={"goal": "evidence"}, headers=headers, timeout=20).json()
        before = store.db.execute("SELECT count(*) FROM events WHERE kind='network.policy_changed'").fetchone()[0]
        applied = requests.post(server.url + "/api/settings/goal", json={"goal": "evidence", "revision": plan["revision"]},
                                headers=headers, timeout=60)
        assert applied.ok, applied.text
        after = store.db.execute("SELECT count(*) FROM events WHERE kind='network.policy_changed'").fetchone()[0]
        assert after == before + 1, "hiding this server's address is a signed journal record"

        # Every step, four widths, English and Russian; German and Arabic at the edges.
        for lang, widths in (("en", (360, 600, 1024, 1440)), ("ru", (360, 600, 1024, 1440)),
                             ("de", (360, 1440)), ("ar", (360, 1440))):
            context.add_cookies([{"name": i18n.COOKIE, "value": lang, "url": server.url}])
            page.goto(address(7).replace("?ws=default", "?ws=default&lang=" + lang))
            expect(page.locator("#view-first-run .first-run-shell")).to_be_visible(timeout=20000)
            for width in widths:
                page.set_viewport_size({"width": width, "height": 900})
                for step in STEPS:
                    # Moving within the page, as the step list does; reloading every page would hit the request limit.
                    page.evaluate("step=>settingsHub.load(step)", step)
                    assert page.evaluate("settingsHub.step") == step, (lang, width, step)
                    page.wait_for_timeout(200)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (lang, width, step)
                    assert not clipped(page), (lang, width, step, clipped(page))
                    if width in (360, 1440):
                        page.screenshot(path=str(output / f"step{step}-{lang}-{width}.png"), full_page=True)
            if lang == "ru":
                expect(page.locator("#view-first-run h1")).to_have_text(i18n.words("ru")["Review your choices"])
        browser.close()
    assert not errors, errors
    assert not external, external
    return "ok  browser: step addresses and Back, account question, main account limits, live check, journal; en ru de ar"


def main():
    output = ROOT / "test-results" / "first-run-check"
    output.mkdir(parents=True, exist_ok=True)
    print(check_translations())
    with tempfile.TemporaryDirectory() as tmp:
        print(check_browser(Path(tmp), output))
    print("first-run checks passed")


if __name__ == "__main__":
    main()
