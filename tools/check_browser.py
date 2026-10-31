"""Synthetic end-to-end browser acceptance. Never connects to Telegram."""
import asyncio
import json
import hashlib
import os
import zipfile
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from tgwitness import api_pool, i18n
from tgwitness.app import create_app
from tgwitness.proxy_catalog import ProxyPool
from tgwitness.verify import verify_bundle
from test_collector import FakeClient, saved_session


async def _listed(route, operator=False):
    return route


async def _answers(route):
    return 40


async def _idle(self):
    await asyncio.Event().wait()


ProxyPool.pin, ProxyPool.probe, ProxyPool.run = staticmethod(_listed), staticmethod(_answers), _idle


def launch_browser(p):


    return p.chromium.launch(headless=True, channel=os.environ.get("TGWITNESS_BROWSER_CHANNEL") or None)


class RunningApp:
    def __init__(self, path, demo=False, client_factory=FakeClient):
        self.app = create_app(path, demo=demo, client_factory=client_factory)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.url = "http://127.0.0.1:" + str(self.sock.getsockname()[1])
        self.server = uvicorn.Server(uvicorn.Config(self.app, log_level="error", access_log=False,
                                                   timeout_graceful_shutdown=5))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Local test server failed to start")
            time.sleep(.05)
        return self

    def __exit__(self, *args):
        self.server.should_exit = True
        self.thread.join(timeout=30)
        if self.thread.is_alive():
            raise RuntimeError("Local test server did not finish shutdown")
        self.sock.close()


def unlock(page, server):
    page.goto(server.url)
    if server.app.state.store.get_setting("demo",False):
        expect(page.locator("#workspace")).to_be_visible()
        expect(page.locator("#gate")).not_to_be_visible()

        expect(page.locator("#view-chats")).to_be_visible()
        expect(page.locator("#chats-list .chat-item")).to_have_count(3)
        expect(page.locator("#chat-feed .msg").first).to_be_visible()
        expect(page.locator("#chat-feed .msg.deleted").first).to_be_visible()
        expect(page.locator("#chat-status")).to_contain_text("Demo with fictional messages")
        page.locator('#chat-status .filter', has_text="Deleted").click()
        expect(page.locator("#chat-feed .msg:not(.deleted)")).to_have_count(0)
        page.locator('#chat-status .filter', has_text="All").click()

        page.locator('#chat-status .filter', has_text="People").click()
        expect(page.locator("#chat-feed .people-table tbody tr")).to_have_count(4)
        page.locator("#chat-feed .people-table tbody tr").first.click()
        expect(page.locator("#chat-status .chat-author-chip")).to_contain_text("Showing only messages from")
        expect(page.locator("#chat-feed .msg").first).to_be_visible()
        page.locator("#chat-status .chat-author-chip button").click()
        expect(page.locator("#chat-status .chat-author-chip")).to_have_count(0)
        page.locator('[data-view="connection"]').click()
        expect(page.locator("#demo-account-state")).to_be_visible()
        expect(page.locator("#credentials-form")).not_to_be_visible()
        expect(page.locator("#demo-account-state")).to_contain_text("python start.py")
        page.locator('#demo-account-state [data-open="observations"]').click()
        return
    page.locator("#panel-token").fill(server.app.state.vault.token)
    page.get_by_role("button", name="Open workspace").click()
    expect(page.locator("#workspace")).to_be_visible()


def check_layout(page, connection=False):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal overflow"
    for button in page.locator(".sidebar .nav:visible").all():
        bounds = button.bounding_box()
        assert bounds and bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= page.viewport_size["width"] + 1
    if connection:
        for selector in ("#phone", "#auth-continue"):
            bounds = page.locator(selector).bounding_box()
            assert bounds and bounds["y"]+bounds["height"] <= page.viewport_size["height"], "Phone login requires initial scrolling"
    if page.locator("#view-observations").is_visible() and page.locator("#events-body tr").count():
        row = page.locator("#events-body tr").first
        assert row.locator("td").nth(2).is_visible() or row.locator(".event-mobile-meta").is_visible(), \
            "Timeline timestamps disappeared at this width"


    failures = page.evaluate("""() => {
      const rgba=s=>(s.match(/[\\d.]+/g)||[]).map(Number);
      const blend=(fg,bg)=>fg.slice(0,3).map((v,i)=>v*(fg[3]??1)+bg[i]*(1-(fg[3]??1)));
      const luminance=c=>c.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
      const result=[];
      for(const el of document.querySelectorAll('body *')){
        if(![...el.childNodes].some(n=>n.nodeType===3&&n.textContent.trim())||!el.checkVisibility({checkVisibilityCSS:true})||el.closest('[disabled]'))continue;
        const cs=getComputedStyle(el);if(cs.visibility!=='visible')continue;
        let chain=[],n=el,skip=false;
        while(n){const s=getComputedStyle(n);chain.unshift(s);if(Number(s.opacity)<1||/url\\(/.test(s.backgroundImage))skip=true;n=n.parentElement;}
        if(skip)continue;
        let bg=[255,255,255];for(const s of chain)bg=blend(rgba(s.backgroundColor),bg);
        const color=blend(rgba(cs.color),bg), a=luminance(color),b=luminance(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
        const large=parseFloat(cs.fontSize)>=24||(parseFloat(cs.fontSize)>=18.66&&Number(cs.fontWeight)>=700);
        if(ratio<(large?3:4.5))result.push({text:el.textContent.trim().slice(0,65),selector:el.id||el.className,ratio:+ratio.toFixed(2),color:cs.color});
      }
      return result;
    }""")
    assert not failures, failures


def hold_api_response(page, path):
    """Keep the real API response, but let the UI change before its promise resolves."""
    page.evaluate("""path => {
      window.acceptanceFetch=window.fetch;window.releaseAcceptanceResponse=null;
      window.fetch=async(...args)=>{
        const response=await window.acceptanceFetch(...args);
        if(String(args[0]).endsWith(path))await new Promise(resolve=>{
          window.releaseAcceptanceResponse=resolve;document.documentElement.dataset.acceptanceHeld="true";
        });
        return response;
      };
    }""", path)


def release_api_response(page):
    page.evaluate("""() => {
      window.fetch=window.acceptanceFetch;window.releaseAcceptanceResponse();
      delete document.documentElement.dataset.acceptanceHeld;
      delete window.acceptanceFetch;delete window.releaseAcceptanceResponse;
    }""")


def check_reading_states(browser, server):
    page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    page.goto(server.url)
    expect(page.locator("#chat-feed .msg").first).to_be_visible()
    names = page.locator(".sender-details")
    expect(names.first.locator(".sender-facts")).to_be_hidden()
    names.first.locator("summary").click()
    expect(names.first.locator(".sender-facts")).to_be_visible()
    expect(page.locator("#chat-feed")).to_have_attribute("data-pattern", "plain")
    page.locator("#chat-pattern").click()
    page.reload()
    expect(page.locator("#chat-feed")).to_have_attribute("data-pattern", "dots")
    page.locator("#chat-pattern").click()
    page.route("**/messages?*", lambda route: route.fulfill(status=503, json={"detail": "Synthetic failure"}))
    page.locator("#chats-list .chat-item").nth(1).click()
    expect(page.locator('#chat-feed [data-state="error"]')).to_be_visible()
    page.unroute("**/messages?*")
    page.locator('#chat-feed .ui-state button').click()
    expect(page.locator("#chat-feed .msg").first).to_be_visible()
    original = page.locator("#chat-feed .bubble-text").all_text_contents()
    page.route("**/messages?*", lambda route: route.fulfill(status=503, json={"detail": "Synthetic failure"}))
    page.evaluate('loadChatMessages("refresh")')
    assert page.locator("#chat-feed .bubble-text").all_text_contents() == original
    expect(page.locator("#chat-feed .refresh-notice")).to_be_visible()
    page.unroute("**/messages?*")
    page.locator("#chat-feed .refresh-notice button").click()
    expect(page.locator("#chat-feed .refresh-notice")).to_have_count(0)
    page.evaluate('state.chatAuthor=999999;renderChatFeed()')
    expect(page.locator('#chat-feed [data-state="filtered-empty"]')).to_be_visible()
    page.locator('#chat-feed .ui-state button').click()
    assert page.locator("#chat-feed .bubble-text").all_text_contents() == original
    for theme in ("light", "dark"):
        page.emulate_media(color_scheme=theme)
        for view in ("chats", "sources", "parameters"):
            page.locator(f'[data-view="{view}"]').first.click()
            if view == "sources":
                page.locator("#source-options").evaluate("n=>n.open=true")
                page.locator(".media-rules-details").evaluate("n=>n.open=true")
            check_layout(page)
    page.close()


def check_languages(browser, server):
    """Every shipped string has a translation or explicit English fallback; language choice works."""
    context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce")
    page, errors, keys = context.new_page(), [], []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    panel_scripts = ("app.js", "integrations.js", "analysis.js", "media-analysis.js", "webhooks.js", "proxies.js", "fleet.js")
    for script in panel_scripts:
        page.route("**/" + script + "*", lambda route: route.abort())
    page.goto(server.url + "/")
    keys += page.evaluate("pageKeys()")


    shipped = (ROOT / "tgwitness/static/i18n.js").read_text(encoding="utf-8").split("translatePage();\n")[0]
    page.route("**/i18n.js*", lambda route: route.fulfill(body=shipped, content_type="text/javascript"))
    for name in ("/guide.html", "/dedicated-account.html"):
        page.goto(server.url + name)
        keys += page.evaluate("pageKeys()")
    page.unroute("**/i18n.js*")
    journal = page.locator('[data-view="observations"]').first
    page.goto(server.url)
    english = " ".join(journal.inner_text().split()[:-1])
    for script in panel_scripts:
        page.unroute("**/" + script + "*")

    context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
    page.goto(server.url + "/?lang=de")
    expect(page.locator("html")).to_have_attribute("lang", "de")
    for lang in i18n.LANGUAGES[1:]:
        words = i18n.words(lang)
        missing = sorted({key for key in keys if key not in words})
        assert not missing, (lang, missing[:5])
        context.add_cookies([{"name": i18n.COOKIE, "value": lang, "url": server.url}])
        page.goto(server.url)
        expect(page.locator("html")).to_have_attribute("lang", lang)
        expect(page.locator("html")).to_have_attribute("dir", "rtl" if lang in ("ar", "fa", "ur", "he") else "ltr")
        expect(journal).to_contain_text(words[english])
        expect(page.locator("#chat-feed .msg").first).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), lang
        page.goto(server.url + "/guide.html")
        expect(page.locator("html")).to_have_attribute("lang", lang)
        page.goto(server.url + "/dedicated-account.html")
        expect(page.locator("html")).to_have_attribute("lang", lang)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), lang
    assert not errors, errors
    context.close()


def check_themes(browser, server):
    """The dark theme keeps text contrast on every view; a chosen theme overrides the system one and persists;
    motion can be kept on when the system asks for less."""
    context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce", color_scheme="dark")
    page, errors = context.new_page(), []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    html, sidebar = page.locator("html"), page.locator(".sidebar .theme-pick")
    page.goto(server.url)
    expect(page.locator("#view-chats")).to_be_visible()
    expect(html).to_have_attribute("data-theme", "dark")
    expect(sidebar.locator('[data-theme-choice="system"]')).to_have_attribute("aria-pressed", "true")
    for view in ("chats", "observations", "sources", "evidence", "witness", "parameters", "connection", "accounts"):
        page.locator('[data-view="%s"]' % view).first.click()
        expect(page.locator("#view-" + view)).to_be_visible()
        check_layout(page)
    page.locator('[data-view="observations"]').first.click()
    page.locator("#events-body tr").first.click()
    expect(page.locator("#detail-drawer")).to_be_visible()
    check_layout(page)
    page.keyboard.press("Escape")
    page.screenshot(path=str(ROOT / "test-results" / "dark.png"))
    sidebar.locator('[data-theme-choice="light"]').click()
    expect(html).to_have_attribute("data-theme", "light")
    expect(sidebar.locator('[data-theme-choice="light"]')).to_have_attribute("aria-pressed", "true")
    page.reload()
    expect(html).to_have_attribute("data-theme", "light")
    sidebar.locator('[data-theme-choice="system"]').click()
    expect(html).to_have_attribute("data-theme", "dark")
    page.emulate_media(color_scheme="light")
    expect(html).to_have_attribute("data-theme", "light")
    page.emulate_media(color_scheme="dark")
    expect(html).to_have_attribute("data-theme", "dark")

    motion, view = page.locator(".sidebar [data-motion-toggle]"), page.locator("#view-chats")
    expect(motion).to_have_attribute("aria-pressed", "false")
    assert view.evaluate("n => getComputedStyle(n).animationDuration") != "0.3s"
    motion.click()
    expect(html).to_have_attribute("data-motion", "always")
    page.reload()
    expect(motion).to_have_attribute("aria-pressed", "true")
    expect(view).to_be_visible()
    assert view.evaluate("n => getComputedStyle(n).animationDuration") == "0.3s"
    motion.click()
    expect(html).not_to_have_attribute("data-motion", "always")
    page.emulate_media(reduced_motion="no-preference")
    expect(motion).to_be_hidden()
    page.emulate_media(reduced_motion="reduce")
    page.locator("#top-lock").click()
    expect(page.locator("#gate")).to_be_visible()
    check_layout(page)
    page.locator('.login-card [data-theme-choice="dark"]').click()
    expect(page.locator('.login-card [data-theme-choice="dark"]')).to_have_attribute("aria-pressed", "true")
    page.goto(server.url + "/guide.html")
    expect(html).to_have_attribute("data-theme", "dark")
    check_layout(page)
    page.goto(server.url + "/dedicated-account.html")
    expect(html).to_have_attribute("data-theme", "dark")
    check_layout(page)
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(server.url)
    expect(page.locator("#view-chats")).to_be_visible()
    check_layout(page)
    assert not errors, errors
    context.close()


def main():
    output = ROOT / "test-results"
    output.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="browser-", dir=output))
    errors, outbound = [], []
    with RunningApp(run / "demo", demo=True) as demo, RunningApp(run / "live") as live:
        with sync_playwright() as p:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 1060}, reduced_motion="reduce")
            context.add_init_script("window.showSaveFilePicker=undefined")
            page = context.new_page()
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            page.on("request", lambda req: outbound.append(req.url) if urlsplit(req.url).hostname not in (
                "127.0.0.1", None) else None)
            unlock(page, demo)
            expect(page.locator("#stat-edits")).to_have_text("3")
            expect(page.locator("#stat-deletes")).to_have_text("3")
            check_layout(page)
            page.screenshot(path=str(output / "desktop.png"), full_page=True)
            for width in (850, 768, 601, 600, 390, 320):
                page.set_viewport_size({"width": width, "height": 1060})
                check_layout(page)
                expect(page.locator("#events-body tr").first.locator(".event-mobile-meta")).to_contain_text(
                    demo.app.state.store.stats()["head"]["observed_at"][:10])
                if width == 768:
                    page.screenshot(path=str(output / "tablet.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1060})
            page.get_by_role("button", name="Edits", exact=True).click()
            expect(page.locator("#events-body tr")).to_have_count(3)
            page.locator("#events-body tr").first.click()
            expect(page.locator(".detail-block.before")).to_be_visible()
            expect(page.locator(".detail-block.after")).to_be_visible()
            page.screenshot(path=str(output / "detail.png"), full_page=True)
            page.keyboard.press("Escape")
            expect(page.locator("#detail-drawer")).not_to_be_visible()
            page.get_by_role("button", name="Deletions", exact=True).click()
            page.locator("#events-body tr").first.click()
            expect(page.locator("#detail-content")).to_contain_text("Last captured content")
            expect(page.locator("#detail-content")).to_contain_text("Deleter not supplied")
            page.keyboard.press("Escape")
            page.get_by_role("button", name="Membership", exact=True).click()
            expect(page.locator("#events-body tr")).to_have_count(1)
            page.get_by_role("button", name="All events", exact=True).click()
            page.locator("#event-search").fill("Reference archive")
            expect(page.locator("#events-body tr")).to_have_count(4)
            page.locator("#event-search").fill("")
            page.locator('[data-view="evidence"]').click()
            if not page.locator("#verification-details").get_attribute("open") == "":
                page.locator("#verification-details > summary").click()
            page.locator("#verify-journal").click()
            expect(page.locator("#verification-result")).to_contain_text("event signatures")
            with page.expect_download() as pending:
                page.get_by_role("button", name="Download signed ZIP").click()
            bundle = output / "browser-evidence.zip"
            pending.value.save_as(bundle)
            assert verify_bundle(bundle)["events"] > 25

            page.evaluate("""() => {window.savedChunks=[];window.writerClosed=false;window.writerAborted=false;
              window.showSaveFilePicker=async()=>({createWritable:async()=>({
                write:async bytes=>window.savedChunks.push(Array.from(bytes)),
                close:async()=>{window.writerClosed=true},abort:async()=>{window.writerAborted=true}
              })});}""")
            page.get_by_role("button", name="Download signed ZIP").click()
            expect(page.locator("#toast")).to_have_text("Evidence export saved.")
            assert page.evaluate("window.writerClosed")
            streamed = output / "browser-streamed-evidence.zip"
            streamed.write_bytes(bytes(page.evaluate("window.savedChunks.flat()")))
            assert verify_bundle(streamed)["events"] > 25
            assert not page.evaluate("window.writerAborted")
            requests_before = []
            page.on("request", lambda req: requests_before.append(req.url) if "/api/export/" in req.url else None)
            page.evaluate("() => {window.showSaveFilePicker=async()=>{throw new DOMException('Cancelled','AbortError')};}")
            page.get_by_role("button", name="Download signed ZIP").click()
            expect(page.get_by_role("button", name="Download signed ZIP")).to_be_enabled()
            assert not requests_before, "Cancelled file chooser must not start an export"
            page.evaluate("""() => {window.writerAborted=false;
              window.showSaveFilePicker=async()=>({createWritable:async()=>({
                write:async()=>{throw new Error('Synthetic disk full')},
                close:async()=>{throw new Error('Failed stream must not be closed')},
                abort:async()=>{window.writerAborted=true}
              })});}""")
            page.get_by_role("button", name="Download signed ZIP").click()
            expect(page.locator("#toast")).to_have_text("Synthetic disk full")
            assert page.evaluate("window.writerAborted")
            page.evaluate("window.showSaveFilePicker=undefined")
            page.route("**/api/export/jsonl", lambda route: route.fulfill(status=200,
                       headers={"Content-Length":str(128*1024**2+1), "Content-Type":"application/x-ndjson"}, body=b""))
            page.locator('[data-export="jsonl"]').click()
            expect(page.locator("#toast")).to_contain_text("cannot stream this large export")
            page.unroute("**/api/export/jsonl")
            check_layout(page)
            with page.expect_download() as pending:
                page.locator("#save-checkpoint").click()
            anchor = output / "browser-checkpoint.json"
            pending.value.save_as(anchor)
            checkpoint = json.loads(anchor.read_text())
            verify_bundle(bundle, checkpoint["fingerprint"], checkpoint)
            with page.expect_download() as pending:
                page.get_by_role("button", name="Prepare timestamp request").click()
            request_path = output / "browser-timestamp-request.zip"
            pending.value.save_as(request_path)
            with zipfile.ZipFile(request_path) as archive:
                data = archive.read("checkpoint.json")
                assert hashlib.sha256(data).digest() in archive.read("timestamp.tsq")
                verify_bundle(bundle, checkpoint["fingerprint"], json.loads(data))
            page.screenshot(path=str(output / "evidence.png"), full_page=True)
            page.locator('[data-view="sources"]').click()
            expect(page.locator("#target-list .target-row")).to_have_count(3)
            expect(page.locator("#load-dialogs")).to_be_disabled()
            page.locator('[data-view="observations"]').click()
            page.set_viewport_size({"width": 390, "height": 844})
            expect(page.locator("#view-observations")).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            check_layout(page)
            page.screenshot(path=str(output / "mobile.png"), full_page=True)

            demo.app.state.store.append("message.new", {
                "text": '<img src=x onerror="window.sourceExecuted=true"><script>window.sourceExecuted=true</script>',
                "synthetic": True}, -100100001, 999)
            page.locator("#refresh").click()
            expect(page.locator("#events-body")).to_contain_text("<img src=x")
            assert not page.evaluate("Boolean(window.sourceExecuted)")
            page.locator("#top-lock").click()
            expect(page.locator("#gate")).to_be_visible()
            assert page.evaluate("sessionStorage.getItem('tgwitness-token')") is None
            page.set_viewport_size({"width": 1440, "height": 1060})

            unlock(page, live)
            expect(page.locator("#empty-events")).not_to_be_visible()
            expect(page.locator("#view-connection")).to_be_visible()
            expect(page.locator("#protection-summary")).to_contain_text("Not encrypted by TgWitness")
            check_layout(page, connection=True)
            page.screenshot(path=str(output / "connection.png"), full_page=True)
            for width in (390, 320):
                page.set_viewport_size({"width":width,"height":844})
                check_layout(page, connection=True)
                page.screenshot(path=str(output / ("connection-mobile-"+str(width)+".png")), full_page=True)
            page.set_viewport_size({"width":1440,"height":1060})
            page.locator("#entry-settings").click()
            page.locator("#network-details > summary").click()
            page.locator("#network-kind").select_option("socks5")
            page.locator("#network-host").fill("127.0.0.1")
            page.locator("#network-port").fill("1080")
            page.locator("#network-username").fill("synthetic-user")
            page.locator("#network-password").fill("synthetic-proxy-secret")
            page.locator('#network-form button[type="submit"]').click()
            expect(page.locator("#route-summary")).to_have_text("SOCKS5 proxy")
            expect(page.locator("#network-password")).to_have_value("")
            page.screenshot(path=str(output / "connection-proxy.png"), full_page=True)
            page.set_viewport_size({"width":390,"height":844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            page.screenshot(path=str(output / "connection-mobile.png"), full_page=True)
            page.set_viewport_size({"width":1440,"height":1060})
            page.locator("#phone").fill("+15550001111")

            expect(page.locator("#api-state")).to_have_text("Built-in")
            page.locator("#api-details > summary").click()
            page.locator("#api-id").fill("123")
            page.locator("#auth-continue").click()
            expect(page.locator("#code-form")).not_to_be_visible()
            expect(page.locator("#phone")).to_have_value("+15550001111")
            page.locator("#api-hash").fill("a"*32)
            expect(page.locator("#api-state")).to_have_text("Entered")
            page.locator("#auth-continue").click()
            expect(page.locator("#code-form")).to_be_visible()
            page.locator("#code").fill("22222")
            page.locator("#code-form button").click()
            expect(page.locator("#password-form")).to_be_visible()
            page.locator("#password").fill("synthetic-test-password")
            page.locator("#password-form button").click()
            expect(page.locator("#authorized-state")).to_be_visible()
            expect(page.locator("#authorized-account")).to_contain_text("@synthetic · ID ")
            expect(page.locator("#account-summary")).not_to_be_visible()
            page.locator("#network-test").click()
            expect(page.locator("#network-result")).to_contain_text("Telegram transport connected")
            page.get_by_role("button", name="Choose sources").click()

            expect(page.locator("#available-card")).to_be_visible()
            expect(page.locator("#load-dialogs")).to_have_text("Reload chats")
            page.get_by_role("button", name="Add source").first.click()
            expect(page.locator("#target-list .target-row")).to_have_count(1)
            page.locator("#finish-source-selection").click()
            expect(page.locator("#available-card")).not_to_be_visible()
            page.locator("#source-options > summary").click()
            page.locator('[data-monitor-preset="changes"]').click()
            expect(page.locator("#monitoring-unsaved")).to_contain_text("Unsaved changes")
            page.locator('#monitoring-form button[type="submit"]').click()
            expect(page.locator("#monitoring-current")).to_have_text("Saved for this account: messages, edits, deletions.")
            expect(page.locator("#monitor-reactions")).not_to_be_checked()
            page.locator("#download-media").check()
            page.locator("#max-media").fill("50")
            page.locator("#monitor-messages").focus()
            page.evaluate("refreshStatus()")
            expect(page.locator("#download-media")).to_be_checked()
            expect(page.locator("#max-media")).to_have_value("50")
            expect(page.locator("#capture-unsaved")).to_contain_text("Unsaved changes")
            hold_api_response(page, "/api/capture")
            page.locator("#capture-form button").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.locator("#download-media").uncheck()
            page.locator("#max-media").fill("20")
            release_api_response(page)
            expect(page.locator("#capture-form button")).to_be_enabled()
            expect(page.locator("#capture-unsaved")).to_contain_text("Unsaved changes")
            expect(page.locator("#download-media")).not_to_be_checked()
            expect(page.locator("#max-media")).to_have_value("20")
            page.locator("#capture-form button").click()
            expect(page.locator("#capture-unsaved")).to_have_text("")
            saved = live.app.state.store.get_setting("capture")
            assert (saved["download_media"], saved["max_media_mb"]) == (False, 20)

            assert len(saved["types"]) == 8 and all(r == {"enabled": True, "max_mb": 20} for r in saved["types"].values())
            check_layout(page)
            expect(page.locator("#toast")).not_to_be_visible(timeout=10000)
            page.locator("#monitoring-form").screenshot(path=str(output / "monitoring.png"))
            for width in (390,320):
                page.set_viewport_size({"width":width,"height":844})
                check_layout(page)
            page.locator("#monitoring-form").screenshot(path=str(output / "monitoring-mobile.png"))
            page.set_viewport_size({"width":1440,"height":1060})
            page.locator("#collector-toggle").click()
            expect(page.locator("#collector-toggle")).to_have_text("Pause observation")
            page.locator("#snapshot-form button").click()
            expect(page.locator("#toast")).to_contain_text("Saved 3 history observations", timeout=15000)
            page.locator("#collector-toggle").click()
            expect(page.locator("#collector-toggle")).to_have_text("Start observation")

            page.locator('[data-view="parameters"]').click()
            expect(page.locator("#parameters-groups .parameters-group")).to_have_count(8)
            page.locator("#parameter-recheck_max_chats").fill("0")
            page.locator('#parameters-form button[type="submit"]').click()
            expect(page.locator("#parameters-form .form-error")).to_contain_text("Chats per recheck pass")
            page.locator("#parameter-recheck_max_chats").fill("5")
            page.locator("#parameter-dossier_phones").uncheck()
            page.locator("#parameter-dossier_patterns").fill("Domain: [a-z0-9-]+\\.top\\b")
            expect(page.locator("#parameters-unsaved")).to_contain_text("Unsaved changes")
            page.locator('#parameters-form button[type="submit"]').click()
            expect(page.locator("#parameters-unsaved")).to_have_text("")
            expect(page.locator(".parameter-row.changed")).to_have_count(3)
            assert live.app.state.store.get_setting("parameters") == {
                "recheck_max_chats": 5, "dossier_phones": False, "dossier_patterns": ["Domain: [a-z0-9-]+\\.top\\b"]}
            assert live.app.state.store.events(kind="parameters.changed")
            for width in (390, 320):
                page.set_viewport_size({"width": width, "height": 844})
                check_layout(page)
            page.set_viewport_size({"width": 1440, "height": 1060})
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#parameters-reset").click()
            expect(page.locator(".parameter-row.changed")).to_have_count(0)
            assert live.app.state.store.get_setting("parameters") == {}
            page.reload()
            expect(page.locator("#workspace")).to_be_visible()
            page.locator('[data-view="connection"]').click()
            page.locator("#entry-settings").click()
            page.locator("#manage-profiles").click()
            page.locator("#profile-label").fill("Private groups · Account B")
            with page.expect_response(lambda r: r.url.endswith("/api/profiles") and r.request.method == "POST") as created_profile:
                page.locator("#profile-create-form button").click()
            assert created_profile.value.ok, "Profile creation request failed"
            expect(page.locator("#profile-select")).not_to_have_value("default")
            second_profile = page.locator("#profile-select").input_value()
            expect(page.locator("#credentials-form")).to_be_visible()
            expect(page.locator("#route-summary")).to_have_text("Automatic MTProxy")
            expect(page.locator("#monitor-reactions")).to_be_checked()
            page.locator('[data-auth-method="files"]').click()
            session_path = run / "synthetic.tgwitness-session"
            session_path.write_text(saved_session(), encoding="ascii")
            page.locator("#session-file").set_input_files(session_path)

            page.locator("#auth-continue").click()
            expect(page.locator("#authorized-state")).to_be_visible()
            child_vault = live.app.state.profiles.entries[second_profile]["app"].state.vault
            assert child_vault.read("credentials")["api_id"] in api_pool.POOL_IDS, "Expected a built-in pool pair"
            page.get_by_role("button", name="Choose sources").click()
            expect(page.locator("#available-card")).to_be_visible()
            page.get_by_role("button", name="Add source").first.click()
            page.locator("#collector-toggle").click()
            expect(page.locator("#collector-toggle")).to_have_text("Pause observation")
            page.locator("#profile-select").select_option("default")
            expect(page.locator("#collector-toggle")).to_have_text("Start observation")
            expect(page.locator("#stat-messages")).to_have_text("3")

            page.locator('[data-view="accounts"]').click()
            expect(page.locator("#nav-accounts")).to_have_text("2")
            expect(page.locator("#accounts-list .account-card")).to_have_count(2)
            expect(page.locator("#accounts-list")).to_contain_text("@synthetic")
            expect(page.locator("#accounts-list")).to_contain_text("Collecting")

            expect(page.locator("#accounts-list .danger")).to_have_count(1)
            page.locator('[data-view="evidence"]').click()
            if not page.locator("#verification-details").get_attribute("open") == "":
                page.locator("#verification-details > summary").click()
            page.locator("#verify-journal").click()
            expect(page.locator("#verification-result")).to_contain_text("event signatures")
            live.app.state.store.append("collector.heartbeat", {"meaning": "Synthetic subsequent observation"})
            page.evaluate("refreshStatus()")
            expect(page.locator("#verification-result")).to_contain_text("journal has changed since this check")
            page.locator("#profile-select").select_option(second_profile)
            expect(page.locator("#collector-toggle")).to_have_text("Pause observation")
            expect(page.locator("#stat-messages")).to_have_text("0")
            expect(page.locator("#verification-result")).to_have_text("")

            hold_api_response(page, "/api/verify")
            page.locator("#verify-journal").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.locator("#profile-select").select_option("default")
            expect(page.locator("#stat-messages")).to_have_text("3")
            page.locator("#profile-select").select_option(second_profile)
            expect(page.locator("#stat-messages")).to_have_text("0")
            release_api_response(page)
            expect(page.locator("#verify-journal")).to_be_enabled()
            expect(page.locator("#verification-result")).to_have_text("")
            page.locator('[data-view="evidence"]').click()
            if not page.locator("#verification-details").get_attribute("open") == "":
                page.locator("#verification-details > summary").click()
            with page.expect_download() as pending:
                page.locator("#save-run-receipt").click()
            receipt_path = output / "browser-run-receipt.json"
            pending.value.save_as(receipt_path)
            signed = json.loads(receipt_path.read_text())
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from tgwitness.store import canonical
            Ed25519PublicKey.from_public_bytes(base64.b64decode(signed["public_key"])).verify(
                base64.b64decode(signed["signature"]), canonical(signed["statement"]))
            page.locator("#collector-toggle").click()
            expect(page.locator("#collector-toggle")).to_have_text("Start observation")
            page.goto(live.url + "/guide.html")
            expect(page.locator("html")).to_have_attribute("lang", "en")
            expect(page.get_by_role("heading", name="3. Export and verify")).to_be_visible()
            for width in (1440,390,320):
                page.set_viewport_size({"width":width,"height":844})
                check_layout(page)
            page.screenshot(path=str(output / "guide-mobile.png"), full_page=True)
            page.goto(live.url + "/dedicated-account.html")
            expect(page.locator("#api h2")).to_have_text("Why TgWitness works through public app hash/app ID pairs")
            for width in (1440,390,320):
                page.set_viewport_size({"width":width,"height":844})
                check_layout(page)
            check_languages(browser, demo)
            check_themes(browser, demo)
            check_reading_states(browser, demo)
            assert not errors, errors
            receipt = {"passed": True, "page_errors": errors, "external_requests": outbound,
                       "scenarios": ["access gate", "filters", "edit comparison", "deleted content", "membership",
                                     "search", "signature verification", "signed ZIP", "checkpoint", "RFC 3161 request download",
                                     "demo isolation", "mobile layout", "HTML injection safety", "lock",
                                     "built-in API state and incomplete pair validation", "mock code + 2FA login", "select source", "start",
                                     "history snapshot", "pause", "reload", "create second account profile",
                                     "accounts management panel", "independent account state", "profile-specific data", "signed run receipt",
                                     "proxy settings and credential clearing", "profile-specific route",
                                     "storage protection status", "mobile connection settings", "session file login",
                                     "native writable export stream", "file picker cancellation",
                                     "failed writable abort", "128 MiB browser fallback limit", "English local guide",
                                     "local demo entry without token input", "audited monitoring presets", "independent monitoring policies",
                                     "solid text contrast", "320/390px navigation and visible first login field",
                                     "601/768/850px timeline timestamps", "attachment drafts survive status refresh",
                                     "edits during attachment save remain unsaved", "verification cleared on account switch",
                                     "late verification response discarded after switching away and back",
                                     "verification identifies its journal boundary",
                                     "static strings covered by translations or explicit English fallbacks", "right-to-left layout",
                                     "dark theme contrast on every view", "saved theme choice overrides and follows the system"]}
            (output / "browser-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            browser.close()
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
