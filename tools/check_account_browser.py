"""Browser acceptance of account import and QR login using only synthetic credentials."""
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_browser import RunningApp, unlock, check_layout, hold_api_response, release_api_response, launch_browser
from test_account_import import sqlite_fixture, tdata_fixture
from test_qr_login import QRClient
from test_collector import saved_session
from telethon.sessions import StringSession
from playwright.sync_api import sync_playwright, expect


def main():
    output = ROOT / "test-results/account-browser"
    output.mkdir(parents=True, exist_ok=True)
    errors, outbound, scenarios = [], [], []
    with tempfile.TemporaryDirectory(prefix="account-browser-") as temporary, RunningApp(
            Path(temporary) / "live", client_factory=QRClient) as server, sync_playwright() as p:
        browser = launch_browser(p)
        context = browser.new_context(viewport={"width":1440,"height":1060}, reduced_motion="reduce")
        context.add_init_script("""(() => {
            if (sessionStorage.getItem('acceptance-bootstrap-gated')) return;
            sessionStorage.setItem('acceptance-bootstrap-gated', '1');
            const original = window.fetch.bind(window);
            window.fetch = async (...args) => {
                const response = await original(...args);
                if (String(args[0]) === '/api/demo-access') {
                    await new Promise(resolve => { window.releaseAcceptanceBootstrap = resolve; });
                }
                return response;
            };
        })();""")
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda req: outbound.append(req.url) if urlsplit(req.url).hostname not in (None,"127.0.0.1") else None)
        def open_account():
            if not page.locator('#view-connection').is_visible():
                page.locator('[data-view="connection"]').click()

        def open_settings():
            open_account()
            if page.locator('#entry-settings').get_attribute('aria-expanded') != 'true':
                page.locator('#entry-settings').click()

        def choose_method(method):
            button=page.locator('[data-auth-method="'+method+'"]')
            if button.get_attribute('aria-pressed') != 'true': button.click()

        unlock(page, server)
        expect(page.locator("#phone")).to_be_visible()
        expect(page.locator("#api-id")).not_to_be_visible()
        expect(page.locator("#network-details")).not_to_be_visible()
        expect(page.locator("#api-details summary")).to_be_visible()
        for method in ("phone", "qr", "files", "key"):
            expect(page.locator('[data-auth-method="'+method+'"]')).to_be_visible()
        page.locator("#api-details summary").click()
        expect(page.locator(".api-purpose")).to_contain_text("different from an Auth Key")
        scenarios.append("API ID and Hash directly accessible without opening settings")
        def paste_pair(value):
            page.locator("#api-id").evaluate("""(input, value) => {
                const data = new DataTransfer(); data.setData('text/plain', value);
                input.dispatchEvent(new ClipboardEvent('paste', {clipboardData:data, bubbles:true, cancelable:true}));
            }""", value)

        paste_pair(" 123:" + "a"*32 + " ")
        expect(page.locator("#api-id")).to_have_value("123")
        expect(page.locator("#api-hash")).to_have_value("a"*32)
        assert server.app.state.collector.login_client is None
        for invalid in ("123:short", "123:"+"g"*32, "0:"+"a"*32, "2147483648:"+"a"*32,
                        "123:"+"b"*32+"\n456:"+"c"*32):
            paste_pair(invalid)
            expect(page.locator("#api-pair-result")).to_contain_text("Paste one pair")
            expect(page.locator("#api-id")).to_have_value("123")
            expect(page.locator("#api-hash")).to_have_value("a"*32)
        scenarios += ["single API pair fills both fields without a network request",
                      "malformed or multiple API pairs preserve existing fields"]
        choose_method("files")
        expect(page.locator(".import-formats")).to_contain_text("Telethon or Pyrogram")
        expect(page.locator(".import-formats")).to_contain_text("Often only API settings")
        expect(page.locator("#method-description")).to_contain_text("one session format")
        scenarios.append("file formats explain which session to choose and when JSON is needed")
        page.locator(".import-advanced summary").click()
        metadata = json.dumps({"app_id":123,"app_hash":"a"*32}).encode()
        files = [("telethon.session",sqlite_fixture()), ("pyrogram.session",sqlite_fixture("pyrogram")),
                 ("tdata.zip",tdata_fixture("synthetic-passcode")), ("account.json",metadata)]
        page.locator("#tdata-passcode").fill("synthetic-passcode")
        page.locator("#session-file").set_input_files([
            {"name":name,"mimeType":"application/octet-stream","buffer":data} for name,data in files])
        expect(page.locator("#selected-files")).to_contain_text("telethon.session")
        expect(page.locator("#file-picker-caption")).to_contain_text("4 selected")
        page.locator("#import-account").click()
        expect(page.locator("#import-result")).to_contain_text("TData ZIP")
        expect(page.locator("#api-id")).to_have_value("123")
        expect(page.locator("#api-hash")).to_have_value("a"*32)
        assert server.app.state.collector.login_client is None
        expect(page.locator("#tdata-passcode")).to_have_value("")
        for width in (1440,390,320):
            page.set_viewport_size({"width":width,"height":1060})
            check_layout(page)
        page.screenshot(path=str(output / "import-mobile.png"), full_page=True)
        scenarios += ["four matching formats in one upload", "Desktop passcode", "companion API metadata",
                      "conversion without Telegram login", "import layout at 1440/390/320px"]
        page.set_viewport_size({"width":1440,"height":1060})
        page.locator("#credentials-form button[type=submit]").click()
        expect(page.locator("#authorized-state")).to_be_visible()
        assert not server.app.state.collector.running
        scenarios.append("imported account ID checked during authorization")

        def begin_qr(api_id="123"):
            if page.locator("#authorized-state").is_visible():
                page.locator("#change-account").click()
            expect(page.locator("#credentials-form")).to_be_visible()


            if page.locator("#api-details").get_attribute("open") is None:
                page.locator("#api-details summary").click()
            expect(page.locator("#api-id")).to_be_visible()
            page.locator("#api-id").fill(api_id)
            page.locator("#api-hash").fill("a"*32)
            choose_method("qr")
            page.locator("#start-qr").click()
            expect(page.locator("#qr-state")).to_be_visible()
            expect(page.locator("#qr-image")).to_be_visible()
            return server.app.state.collector.login_client

        def scan(candidate, outcome="authorized"):
            candidate.qr_outcome = outcome
            candidate.loop.call_soon_threadsafe(candidate.scan.set)

        candidate = begin_qr()
        page.wait_for_function("typeof window.releaseAcceptanceBootstrap === 'function'")
        page.evaluate("window.releaseAcceptanceBootstrap()")
        page.wait_for_load_state("networkidle")
        expect(page.locator("#qr-state")).to_be_visible()
        expect(page.locator("#authorized-state")).not_to_be_visible()
        scenarios.append("late startup response cannot replace an active QR sign-in")
        page.screenshot(path=str(output / "qr-desktop.png"), full_page=True)
        page.set_viewport_size({"width":320,"height":844})
        check_layout(page)
        page.screenshot(path=str(output / "qr-mobile.png"), full_page=True)
        scan(candidate, "expired")
        expect(page.locator("#qr-status")).to_contain_text("expired")
        expect(page.locator("#qr-retry")).to_be_visible()
        assert not candidate.connected
        page.locator("#qr-retry").click()
        expect(page.locator("#qr-status")).to_contain_text("Waiting for confirmation")
        candidate = server.app.state.collector.login_client
        scan(candidate, "password")
        expect(page.locator("#password-form")).to_be_visible()
        page.locator("#password").fill("synthetic-password")
        page.locator("#password-form button").click()
        expect(page.locator("#authorized-state")).to_be_visible()
        scenarios += ["locally rendered QR", "QR mobile layout", "QR expiry and retry", "QR plus two-step verification"]

        page.set_viewport_size({"width":1440,"height":1060})
        candidate = begin_qr("999")
        scan(candidate)
        expect(page.locator("#qr-status")).to_contain_text("different Telegram account")
        assert not candidate.connected
        page.locator("#qr-cancel").click()
        expect(page.locator("#credentials-form")).to_be_visible()
        candidate = begin_qr()
        page.locator('[aria-label="Lock workspace"]:visible').first.click()
        expect(page.locator("#gate")).to_be_visible()
        page.wait_for_function("!document.querySelector('#qr-image').getAttribute('src')")
        hold_api_response(page, "/events?limit=60")
        page.locator("#panel-token").fill(server.app.state.vault.token)
        page.locator("#unlock-form button[type=submit]").click()
        expect(page.locator("#workspace")).to_be_visible()
        page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
        expect(page.locator("#authorized-state")).to_be_visible()
        assert not candidate.connected
        open_account()
        candidate = begin_qr()
        release_api_response(page)
        page.wait_for_load_state("networkidle")
        expect(page.locator("#qr-state")).to_be_visible()
        scenarios.append("sign-in is ready before journal loading and is not reset when it completes")
        response = context.request.post(server.url+"/api/profiles",data={"label":"Second synthetic account"},
            headers={"Authorization":"Bearer "+server.app.state.vault.token})
        child = response.json()["id"]
        page.reload()
        expect(page.locator("#workspace")).to_be_visible()

        assert candidate.connected
        open_account()
        candidate2 = begin_qr()
        assert not candidate.connected
        open_settings()
        page.locator("#profile-select").select_option(child)
        expect(page.locator("#profile-select")).to_have_value(child)
        expect(page.locator("#credentials-form")).to_be_visible()
        assert not candidate2.connected
        scenarios += ["wrong-account QR rejected", "lock clears and cancels QR", "new login replaces pending QR",
                      "workspace switch cancels only its pending QR"]
        if not page.locator("#session-file").is_visible():
            choose_method("files")
        if not page.locator("#import-account").is_visible():
            page.locator(".import-advanced summary").click()
        page.locator("#session-file").set_input_files({"name":"metadata.json","mimeType":"application/json","buffer":metadata})
        page.locator("#import-account").click()
        expect(page.locator("#import-result")).to_contain_text("API metadata only")
        expect(page.locator("#session-string")).to_have_value("")
        scenarios.append("JSON metadata alone does not imply authorization")
        page.locator("#auth-continue").click()
        expect(page.locator("#login-note")).to_contain_text("API credentials loaded")
        assert server.app.state.collector.login_client is None
        expect(page.locator("#phone")).to_be_visible()
        expect(page.locator("#api-id")).to_have_value("123")
        expect(page.locator("#api-hash")).to_have_value("a"*32)
        expect(page.locator("#import-details")).not_to_be_visible()
        scenarios.append("metadata-only import points to phone or QR and preserves API fields")
        choose_method("files")
        if not page.locator("#api-id").is_visible():
            open_settings()
            if not page.locator("#api-id").is_visible(): page.locator("#api-details summary").click()
        page.locator("#api-id").fill("")
        hold_api_response(page,"/api/auth/import")
        page.locator("#session-file").set_input_files({"name":"old.json","mimeType":"application/json","buffer":metadata})
        page.locator("#import-account").click()
        page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
        newer = json.dumps({"app_id":456,"app_hash":"b"*32}).encode()
        page.locator("#session-file").set_input_files({"name":"new.json","mimeType":"application/json","buffer":newer})
        release_api_response(page)
        expect(page.locator("#import-account")).to_be_enabled()
        expect(page.locator("#api-id")).to_have_value("")
        assert page.locator("#session-file").evaluate("input=>input.files[0].name") == "new.json"
        page.locator("#import-account").click()
        expect(page.locator("#api-id")).to_have_value("456")
        scenarios.append("late import cannot overwrite newer selected files")
        hold_api_response(page,"/api/auth/import")
        page.locator("#session-file").set_input_files({"name":"old.json","mimeType":"application/json","buffer":metadata})
        page.locator("#import-account").click()
        page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
        choose_method("qr")
        release_api_response(page)
        expect(page.locator("#import-account")).to_be_enabled()
        expect(page.locator("#api-id")).to_have_value("456")
        expect(page.locator("#session-string")).to_have_value("")
        expect(page.locator("#start-qr")).to_be_visible()
        scenarios.append("changing login method discards a late file import")
        choose_method("files")
        hold_api_response(page,"/api/auth/import")
        page.locator("#session-file").set_input_files({"name":"old.json","mimeType":"application/json","buffer":metadata})
        page.locator("#import-account").click()
        page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
        paste_pair("789:"+"c"*32)
        release_api_response(page)
        expect(page.locator("#import-account")).to_be_enabled()
        expect(page.locator("#api-id")).to_have_value("789")
        expect(page.locator("#api-hash")).to_have_value("c"*32)
        scenarios.append("late import cannot replace a newly pasted API pair")
        choose_method("phone")
        page.locator("#phone").fill("+1 (555) 000-1111")
        page.locator("#auth-continue").click()
        expect(page.locator("#code-form")).to_be_visible()
        page.locator("#code").fill("22222")
        page.locator("#code-form button").click()
        page.locator("#password").fill("synthetic-password")
        page.locator("#password-form button").click()
        expect(page.locator("#authorized-state")).to_be_visible()
        page.locator("#change-account").click()
        page.locator("#phone").fill("+15550001111")
        expect(page.locator("#api-id")).not_to_be_visible()
        page.locator("#auth-continue").click()
        expect(page.locator("#code-form")).to_be_visible()
        page.locator("#auth-back").click()
        choose_method("qr")
        page.locator("#start-qr").click()
        expect(page.locator("#qr-image")).to_be_visible()
        page.locator("#qr-cancel").click()
        scenarios += ["phone number goes directly to code and 2FA", "saved API credentials reused for phone and QR"]
        response = context.request.post(server.url+"/api/profiles",data={"label":"Direct file import"},
            headers={"Authorization":"Bearer "+server.app.state.vault.token})
        third = response.json()["id"]
        page.reload()
        expect(page.locator("#workspace")).to_be_visible()
        open_settings()
        page.locator("#profile-select").select_option(third)
        open_account()
        choose_method("files")
        page.locator("#session-file").set_input_files({"name":"metadata.json","mimeType":"application/json","buffer":metadata})
        page.locator("#auth-continue").click()
        expect(page.locator("#phone")).to_be_visible()
        expect(page.locator("#login-note")).to_contain_text("API credentials loaded")
        choose_method("files")
        direct_files = [("telethon.session",sqlite_fixture()), ("pyrogram.session",sqlite_fixture("pyrogram")),
                        ("tdata.zip",tdata_fixture()), ("account.json",metadata)]
        if page.locator("#entry-settings").get_attribute("aria-expanded") == "true": page.locator("#entry-settings").click()
        page.locator("#session-file").set_input_files([
            {"name":name,"mimeType":"application/octet-stream","buffer":data} for name,data in direct_files])
        page.locator("#auth-continue").click()
        expect(page.locator("#credentials-form .form-error")).to_contain_text("already belongs to another profile")
        open_settings()
        page.locator("#profile-select").select_option("default")
        expect(page.locator("#authorized-state")).to_be_visible()
        page.locator("#change-account").click()
        choose_method("files")
        if page.locator("#entry-settings").get_attribute("aria-expanded") == "true": page.locator("#entry-settings").click()
        page.locator("#session-file").set_input_files([
            {"name":name,"mimeType":"application/octet-stream","buffer":data} for name,data in direct_files])
        page.locator("#auth-continue").click()
        expect(page.locator("#authorized-state")).to_be_visible()
        expect(page.locator("#api-details")).not_to_have_attribute("open", "")
        scenarios += ["metadata file directly leads to phone entry", "four matching files connect with one button",
                      "one-button import preserves the cross-profile account guard"]

        page.locator("#change-account").click()
        choose_method("key")
        synthetic = StringSession(saved_session())
        auth_requests = []
        page.on("request", lambda req: auth_requests.append(urlsplit(req.url).path)
                if "/api/auth/" in urlsplit(req.url).path else None)
        def enter_key(user="44"):
            page.locator("#auth-key").fill(synthetic.auth_key.key.hex())
            page.locator("#auth-dc").select_option(str(synthetic.dc_id))
            page.locator("#auth-user-id").fill(user)

        page.locator("#auth-key").fill("ab...cd")
        page.locator("#auth-continue").click()
        expect(page.locator("#credentials-form .form-error")).to_contain_text("512 hexadecimal characters")
        page.locator("#auth-key").fill(synthetic.auth_key.key.hex())
        page.locator("#auth-continue").click()
        expect(page.locator("#credentials-form .form-error")).to_contain_text("DC ID")
        enter_key("9007199254740993")
        page.locator("#auth-continue").click()
        expect(page.locator("#credentials-form .form-error")).to_contain_text("positive whole number")
        assert not auth_requests
        scenarios.append("truncated Auth Keys, missing DC and imprecise user IDs rejected before requests")

        saved = server.app.state.vault.read("credentials")
        enter_key("45")
        page.locator("#auth-continue").click()
        expect(page.locator("#credentials-form .form-error")).to_contain_text("does not match the imported account ID")
        assert server.app.state.vault.read("credentials") == saved
        scenarios.append("direct Auth Key checks supplied user ID and retains the saved account on mismatch")

        for change in ("key", "method", "credentials"):
            choose_method("key")
            enter_key()
            hold_api_response(page, "/api/auth/import")
            before = auth_requests.count("/api/auth/configure")
            page.locator("#auth-continue").click()
            page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
            expect(page.locator("#auth-progress")).to_contain_text("Reading your authorization key")
            if change == "key":
                page.locator("#auth-key").fill("ab" * 256)
            elif change == "method":
                choose_method("phone")
            else:
                page.locator("#api-details summary").click()
                page.locator("#api-id").fill("123")
            release_api_response(page)
            expect(page.locator("#auth-continue")).to_be_enabled()
            expect(page.locator("#session-string")).to_have_value("")
            assert auth_requests.count("/api/auth/configure") == before
        scenarios.append("late Auth Key conversion cannot replace edited keys, methods or API settings")

        page.locator("#api-id").fill("")
        page.locator("#api-details summary").click()
        enter_key()
        hold_api_response(page, "/api/auth/configure")
        page.locator("#auth-continue").click()
        page.wait_for_function("() => window.releaseAcceptanceResponse !== null")
        expect(page.locator("#auth-progress")).to_contain_text("Connecting to Telegram")
        expect(page.locator("#auth-continue")).to_have_attribute("aria-busy", "true")
        release_api_response(page)
        expect(page.locator("#authorized-state")).to_be_visible()
        expect(page.locator("#auth-key")).to_have_value("")
        expect(page.locator("#session-string")).to_have_value("")
        expect(page.locator("#toast")).not_to_be_visible()
        assert not server.app.state.collector.running
        scenarios += ["direct Auth Key plus DC signs in using saved API credentials",
                      "connection progress is visible and successful login clears input secrets"]

        page.locator("#change-account").click()
        choose_method("key")
        enter_key()
        page.locator('[aria-label="Lock workspace"]:visible').first.click()
        expect(page.locator("#auth-key")).to_have_value("")
        expect(page.locator("#auth-dc")).to_have_value("")
        expect(page.locator("#auth-user-id")).to_have_value("")
        scenarios.append("locking the panel clears pasted Auth Key and identity fields")

        page.locator("#panel-token").fill(server.app.state.vault.token)
        page.locator("#unlock-form button[type=submit]").click()
        expect(page.locator("#workspace")).to_be_visible()
        open_account()
        page.locator("#change-account").click()
        for width in (1440, 390, 320):
            page.set_viewport_size({"width":width,"height":844})
            for method in ("phone", "qr", "files", "key"):
                choose_method(method)
                check_layout(page, connection=method == "phone")
                page.screenshot(path=str(output / (method+"-"+str(width)+".png")), full_page=True)
                if method == "files":
                    picker = page.locator(".account-file-picker").bounding_box()
                    formats = page.locator(".import-formats").bounding_box()
                    assert picker["y"] < formats["y"]
                    assert picker["y"] + picker["height"] < 844
                    connect = page.locator("#auth-continue").bounding_box()
                    assert connect["y"] + connect["height"] < 844, (width, connect)
        scenarios.append("all four sign-in tabs fit 320/390/1440px; file picker precedes format guidance")
        choose_method("files")
        page.evaluate("document.documentElement.style.setProperty('--font', 'Arial, sans-serif')")
        for width in (390, 320):
            page.set_viewport_size({"width": width, "height": 844})
            check_layout(page)
            page.screenshot(path=str(output / ("files-fallback-"+str(width)+".png")), full_page=True)
            connect = page.locator("#auth-continue").bounding_box()
            assert connect["y"] >= 0 and connect["y"] + connect["height"] < 844, (width, connect)
        scenarios.append("file-import submit stays visible with fallback font metrics at 320/390px")
        assert not errors and not outbound, {"errors":errors,"outbound":outbound}
        receipt = {"passed":True,"scenarios":scenarios,"page_errors":errors,"external_requests":outbound}
        (output / "receipt.json").write_text(json.dumps(receipt,indent=2),encoding="utf-8")
        print(json.dumps(receipt,indent=2))
        browser.close()


if __name__ == "__main__":
    main()
