import asyncio
import json
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient
import uvicorn

from tgwitness_capture.format import canonical
from tgwitness_capture.journal import Journal
from tgwitness_capture.official import GuardStopped, OfficialBrowser, OfficialOptions, PaceWait, URL, official_url
from tgwitness_capture.service import Config, create_app


@pytest.mark.parametrize("url", ["https://web.telegram.org.evil/a/", "http://web.telegram.org/a/",
                                 "https://evil@web.telegram.org/a/", "https://web.telegram.org/k/",
                                 "https://web.telegram.org/a/?redirect=evil", "https://web.telegram.org:8443/a/"])
def test_origin_is_exact(url):
    assert not official_url(url)
    assert official_url(URL + "#123")


@pytest.mark.parametrize("change", [{"proxy_server": "http://user:secret@host:3128"},
                                    {"proxy_server": "http://host:3128/path"},
                                    {"max_pause_seconds": 2.0, "min_pause_seconds": 3.0},
                                    {"proxy_server": "direct"}, {"max_steps": True},
                                    {"egress": "socks5"}, {"expected_ip": "not-an-ip"},
                                    {"egress": "direct"}, {"proxy_server": ""}])
def test_invalid_or_unsafe_configuration(change):
    with pytest.raises(ValueError):
        OfficialOptions.model_validate({"proxy_server": "http://gateway:3128", **change})


def test_direct_requires_explicit_selection_and_rejects_proxy_secrets():
    with pytest.raises(ValueError, match="proxy endpoint"):
        OfficialOptions()
    direct = OfficialOptions(egress="direct")
    assert direct.receipt()["direct_fallback"] is False
    assert direct.proxy_server == ""
    for key in ("proxy_username_env", "proxy_password_env"):
        with pytest.raises(ValueError, match="cannot include proxy"):
            OfficialOptions(egress="direct", **{key: "PRIVATE_PROXY_SECRET"})


def test_named_api_authentication_validation_and_frozen_plan(tmp_path):
    config = Config(official={"proxy_server": "http://gateway:3128"})
    with TestClient(create_app(tmp_path, config)) as client:
        recorder = client.app.state.recorder
        control = {"Authorization": "Bearer " + recorder.tokens["control"]}
        witness = {"Authorization": "Bearer " + recorder.tokens["witness"]}
        assert client.post("/api/official/open").status_code == 401
        assert client.post("/api/official/open", headers=witness).status_code == 401
        assert client.get("/api/checkpoint", headers=witness).status_code == 200
        assert client.post("/api/official/evaluate", headers=control, json={"js": "sendMessage()"}).status_code == 404
        assert client.post("/api/official/scroll", headers=control, json={"direction": "send"}).status_code == 422
        secret = "SENSITIVE-NOT-FOR-ERROR-OUTPUT"
        response = client.post("/api/official/password", headers=control, json={"password": [secret]})
        assert response.status_code == 422 and secret not in response.text
        assert secret not in canonical(recorder.journal.events()).decode()
        settings = {"enabled": True, "video": False}
        assert client.post("/api/settings", headers=control, json=settings).status_code == 400
        plan = {"mode": "paced", "min_pause_seconds": 3.0, "max_pause_seconds": 5.0,
                "scroll_pixels": 200, "max_steps": 20, "session_minutes": 10}
        response = client.post("/api/official/plan", headers=control, json=plan)
        assert response.status_code == 200
        assert response.json()["official"]["options"]["mode"] == "paced"
        assert not response.json()["settings"]["enabled"]
        recorder.official.phase = "login"
        assert client.post("/api/official/plan", headers=control, json=plan).status_code == 409
        assert "official.js" in client.get("/").text


@pytest.mark.parametrize("direct", [False, True])
def test_egress_change_and_unavailable_probe_stop(tmp_path, direct):
    class Reply:
        status, url = 200, "https://www.cloudflare.com/cdn-cgi/trace"
        ip = "203.0.113.7"

        async def body(self):
            return ("ip=" + self.ip + "\nwarp=on\n").encode()

        async def dispose(self):
            pass

    class Request:
        async def get(self, *args, **kwargs):
            return response

    response = Reply()
    journal = Journal(tmp_path)
    options = OfficialOptions(egress="direct") if direct else OfficialOptions(proxy_server="http://gateway:3128")
    adapter = OfficialBrowser(options, journal)
    adapter.context = type("Context", (), {"request": Request()})()

    async def exercise():
        await adapter.check_route()
        assert adapter.exit_ip == "203.0.113.7"
        response.ip = "203.0.113.8"
        with pytest.raises(GuardStopped, match="EgressAddressChanged"):
            await adapter.check_route()
        response.status = 503
        with pytest.raises(GuardStopped, match="EgressCheckUnavailable"):
            await adapter.check_route()

    try:
        asyncio.run(exercise())
    finally:
        journal.close()


@pytest.mark.parametrize("direct", [False, True])
def test_official_panel_login_selection_export_and_languages(tmp_path, request, direct):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for the real panel test")
    from playwright.sync_api import expect, sync_playwright
    from tgwitness_capture.verify import verify_zip
    root = tmp_path / "panel"
    route = {"egress": "direct"} if direct else {"proxy_server": "http://127.0.0.1:9"}
    app = create_app(root, Config(official={**route, "require_video": False, "drand": False}))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning", timeout_graceful_shutdown=5))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.05)
        assert server.started
        adapter = app.state.recorder.official
        adapter.headless = True
        real_route = adapter._route
        client_loop = None

        async def fixture_route(route):
            nonlocal client_loop
            client_loop = asyncio.get_running_loop()
            class FixtureRoute:
                request = route.request

                async def continue_(self):
                    body = FIXTURE.replace('<body>', '<body><div id="auth-password-form">Two-step verification</div>').replace(
                        '<div id="LeftColumn">', '<div id="LeftColumn" style="display:none">')
                    await route.fulfill(status=200, content_type="text/html", body=body)

                async def abort(self, error):
                    await route.abort(error)
            await real_route(FixtureRoute())

        async def probe():
            adapter.exit_ip = "203.0.113.7"
            adapter.checked_route = time.monotonic()

        adapter._route, adapter.check_route = fixture_route, probe
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto("http://127.0.0.1:" + str(sock.getsockname()[1]))
            page.locator("#token").fill((root / "control-token.txt").read_text())
            page.locator("#login-form button").click()
            expect(page.locator("#workspace")).to_be_visible()
            if direct:
                expect(page.locator("#route")).to_contain_text("public IP")
            page.locator("#language").select_option("ru")
            expect(page.locator("h1")).to_have_text("Свидетель в официальном клиенте")
            if direct:
                expect(page.locator("#route")).to_contain_text("внешний IP")
            page.locator("#plan-form button").click()
            expect(page.locator("#client-section")).to_be_visible(timeout=15000)
            expect(page.locator("#login-state")).to_contain_text("password", timeout=15000)
            expect(page.locator("#chats-refresh")).to_be_disabled()
            expect(page.locator("#chat-select")).to_be_disabled()
            asyncio.run_coroutine_threadsafe(adapter.page.evaluate("""() => {
                document.getElementById('auth-password-form').remove();
                document.getElementById('LeftColumn').style.display='';
            }"""), client_loop).result(timeout=10)
            expect(page.locator("#chats-refresh")).to_be_enabled(timeout=10000)
            expect(page.locator("#chat-select")).to_be_disabled()
            page.locator("#chats-refresh").click()
            expect(page.locator("#chats option")).to_have_count(1)
            page.locator("#chat-select").click()
            expect(page.locator("#toggle")).to_be_enabled()
            page.locator("#toggle").click()
            expect(page.locator("#snapshot")).to_be_enabled()
            page.locator("#snapshot").click()
            expect(page.locator("#events")).to_contain_text("capture.saved")
            page.locator("#toggle").click()
            expect(page.locator("#snapshot")).to_be_disabled()
            with page.expect_download() as saved:
                page.locator("#selection").click()
            selected = tmp_path / "selected.json"
            saved.value.save_as(selected)
            # Observe action completion instead of overlapping two API commands.
            expect(page.locator("#export")).to_be_enabled()
            with page.expect_download() as saved:
                page.locator("#export").click()
            archive = tmp_path / "official.zip"
            saved.value.save_as(archive)
            result = verify_zip(archive, expected_settings=json.loads(selected.read_bytes()))
            assert result["official"]["settings_checked"]
            assert "procedure_not_finished" in result["official"]["reasons"]
            page.screenshot(path=str(tmp_path / "official-panel-ru.png"), full_page=True)
            for language in ("en", "ru"):
                page.locator("#language").select_option(language)
                for width in (320, 390, 1440):
                    page.set_viewport_size({"width": width, "height": 900})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.set_viewport_size({"width": 390, "height": 900})
            page.screenshot(path=str(tmp_path / "official-panel-mobile.png"), full_page=True)
            assert not errors
            assert "Alice <script>" in page.locator("#selected").inner_text()
            browser.close()
    finally:
        server.should_exit = True
        thread.join(45)
        sock.close()
        assert not thread.is_alive()


# Synthetic DOM using the reviewed official client's public element boundaries.
# This is not a Telegram login or a claim to have exercised a real account.
FIXTURE = """<!doctype html><html><head><meta charset="utf-8"><title>Synthetic official-client fixture</title>
<style>.MessageList{height:350px;width:700px;overflow:auto}.Message{height:160px}body{margin:0}</style></head><body>
<div id="LeftColumn"><div class="chat-list"><div class="Chat"><a class="ListItem-button" href="#123"><span class="title">Alice &lt;script&gt;</span></a></div></div></div>
<div id="MiddleColumn"><div class="MessageList"><div class="messages-container">
<div class="Message" data-message-id="1"><b class="sender-name">Alice</b><div class="text-content">Original message <img class="emoji" alt="🧪"><br>Second line <span>nested <img class="emoji" alt="👩🏽‍💻"></span><span style="display:none">HIDDEN<img class="emoji" alt="⛔"></span><img alt="DECORATIVE"></div><div class="embedded-message">Reply <img class="emoji" alt="🧪"></div><div class="Reactions"><img class="emoji" alt="👍"> 1</div><span class="time" title="2026-11-05 12:00">12:00</span></div>
<div class="Message" data-message-id="2"><div class="text-content">Second message</div></div>
<div class="Message" data-message-id="3"><div class="text-content">Third message</div></div>
</div></div><div class="Composer"><div contenteditable="true" id="composer"></div><button id="send">Send</button></div></div>
<script>window.sent=0;document.getElementById('send').onclick=()=>window.sent++;</script></body></html>"""


def test_owned_browser_guard_scroll_capture_and_unknown_dialog(tmp_path, request):
    if not request.config.getoption("--capture-browser"):
        pytest.skip("Use --capture-browser for real Chromium validation")
    journal = Journal(tmp_path / "official")
    adapter = OfficialBrowser(OfficialOptions(proxy_server="http://127.0.0.1:9", require_video=False, drand=False), journal, headless=True)

    async def probe():
        adapter.exit_ip = "203.0.113.7"
        adapter.checked_route = __import__("time").monotonic()

    real_route = adapter._route

    async def fixture_route(route):
        class FixtureRoute:
            request = route.request

            async def continue_(self):
                await route.fulfill(status=200, content_type="text/html", body=FIXTURE)

            async def abort(self, error):
                await route.abort(error)
        await real_route(FixtureRoute())

    adapter.check_route = probe
    adapter._route = fixture_route

    async def exercise():
        await adapter.open()
        assert await adapter.login_state() == "ready"
        chats = await adapter.chats()
        assert len(chats) == 1 and chats[0]["title"] == "Alice <script>"
        await adapter.select_chat(chats[0]["handle"])
        await adapter.arm()
        assert (await adapter.page.evaluate("window.__tgwitnessGuard.inspect()"))["armed"]
        await adapter.page.locator("#send").dispatch_event("click")
        await adapter.page.locator("#composer").dispatch_event("keydown", {"key": "Enter"})
        assert await adapter.page.evaluate("window.sent") == 0
        assert await adapter.page.locator(".Composer").evaluate("el=>el.inert")
        with pytest.raises(PaceWait):
            await adapter.scroll("newer")
        adapter.next_step = 0
        await adapter.scroll("newer")
        assert adapter.steps == 1
        markup_before = await adapter.page.locator(".messages-container").inner_html()
        metadata, artifacts, observed = await adapter.capture(journal, {"screenshots": True, "pages": True}, 60, True)
        assert await adapter.page.locator(".messages-container").inner_html() == markup_before
        journal.append("capture.saved", metadata, artifacts, observed)
        messages = next(a for a in artifacts if a["role"] == "rendered_messages")
        values = json.loads((journal.objects / messages["sha256"]).read_bytes())
        assert values[0]["rendered_id"] == "1" and "Original message" in values[0]["rendered_text"]
        assert "Original message 🧪\nSecond line nested 👩🏽‍💻" in values[0]["rendered_text"]
        assert values[0]["reply"] == "Reply 🧪" and values[0]["reactions"] == "👍 1"
        derived = next(a for a in artifacts if a["role"] == "derived_rendered_text")
        derived_text = (journal.objects / derived["sha256"]).read_text(encoding="utf-8")
        assert "Original message 🧪\nSecond line nested 👩🏽‍💻" in derived_text
        for text in (values[0]["rendered_text"], derived_text):
            assert all(hidden not in text for hidden in ("HIDDEN", "⛔", "DECORATIVE"))
        assert not values[0]["telegram_origin_independently_proven"]
        # An emoji-only edit must trigger observation before the periodic snapshot.
        await adapter.page.locator('.text-content img.emoji').first.evaluate("el => el.alt='🔬'")
        changed = await adapter.capture(journal, {"screenshots": True, "pages": True}, 60)
        assert changed is not None and changed[0]["text_sha256"] != metadata["text_sha256"]
        await adapter.pause()
        with pytest.raises(ValueError, match="Start recording"):
            await adapter.scroll()
        await adapter.arm()
        await adapter.page.evaluate("document.body.insertAdjacentHTML('beforeend','<div class=\"Modal open\">Delete?</div>')")
        with pytest.raises(GuardStopped, match="UnexpectedDialog"):
            await adapter.tick()
        assert await adapter.page.locator("#tgwitness-stop-cover").is_visible()
        # A login screen is covered too, before it could become a subsequent snapshot.
        assert len(journal.events()) >= 4

    async def run():
        try:
            await exercise()
        finally:
            await adapter.close()

    try:
        asyncio.run(run())
    finally:
        journal.close()
