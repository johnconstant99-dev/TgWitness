import base64
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import httpx
from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, answer_panel_dialog, check_layout, launch_browser, navigate_panel, unlock
from tools.browser_fixtures import saved_session, sqlite_fixture, tdata_fixture
from tgwitness.account_import import import_accounts, preview


def upload(name, data):
    return {"name": name, "content": base64.b64encode(data).decode()}


def browser_file(name, data):
    return {"name": name, "mimeType": "application/octet-stream", "buffer": data}


def main():
    metadata = json.dumps({"session_file": "", "phone": None, "id": None, "app_id": 456,
                           "app_hash": "a" * 32, "device": "Synthetic laptop", "sdk": "Windows 11",
                           "lang_code": "en", "app_version": "6.0.0 x64"}).encode()
    settings = upload("research.json", metadata)
    no_session = preview([settings])
    assert no_session["state"] == "missing_session" and not no_session["can_connect"]
    assert "app_hash" not in json.dumps(no_session) and "a" * 32 not in json.dumps(no_session)
    for payload in (sqlite_fixture(), sqlite_fixture("pyrogram")):
        result = preview([settings, upload("research.session", payload)])
        assert result["state"] == "ready" and result["can_connect"]
        assert result["client_profile"]["device_model"] == "Synthetic laptop"
        assert "session" not in result and "api_hash" not in result
    assert preview([upload("session.txt", saved_session().encode())])["can_connect"]
    assert preview([upload("tdata.zip", tdata_fixture())])["can_connect"]
    assert not preview([upload("tdata.zip", b"broken zip")])["can_connect"]
    assert "ZIP" in preview([upload("tdata.zip", b"broken zip")])["message"]
    conflicts = [settings, upload("other.json", json.dumps({"app_id": 789, "app_hash": "a" * 32}).encode()),
                 upload("research.session", sqlite_fixture())]
    assert "different API IDs" in preview(conflicts)["message"]
    partial = preview([upload("partial.json", json.dumps({"app_id": 456, "session": saved_session()}).encode())])
    assert partial["state"] == "incomplete" and not partial["can_connect"]
    assert preview([])["state"] == "invalid"
    try:
        import_accounts(conflicts)
    except ValueError as error:
        assert "different API IDs" in str(error)
    else:
        raise AssertionError("Conflicting credentials were merged")

    output = ROOT / "test-results/import-preflight"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="import-preflight-") as temporary, RunningApp(Path(temporary)) as server:
        headers = {"Authorization": "Bearer " + server.app.state.vault.token}
        with httpx.Client(base_url=server.url, headers=headers) as api:
            response = api.post("/api/auth/import/preview", json={"files": [settings]})
            assert response.status_code == 200 and response.json()["state"] == "missing_session"
            assert api.post("/api/auth/import", json={"files": [settings]}).status_code == 422
            partial_files = [upload("partial.json", json.dumps({"app_id": 456, "session": saved_session()}).encode())]
            assert api.post("/api/auth/import", json={"files": partial_files}).status_code == 422
            assert api.post("/api/profiles/import", json={"files": partial_files}).status_code == 422
            assert len(server.app.state.profiles.entries) == 1, "Incomplete settings created a workspace"
            assert api.post("/api/auth/import", json={"files": conflicts}).status_code == 422
            response = api.post("/api/auth/configure", json={"api_id": 123, "api_hash": "b" * 32,
                                                            "session": saved_session(b"o")})
            assert response.status_code == 200, response.text
            previous_credentials = server.app.state.vault.read("credentials")
            previous_key = server.app.state.vault.public_key
            response = api.post("/api/auth/configure", json={"api_id": 456, "api_hash": "b" * 32,
                                                            "session": saved_session(b"f")})
            assert response.status_code == 400 and "different Telegram account" in response.text, response.text
            assert server.app.state.vault.read("credentials") == previous_credentials
            assert server.app.state.store.get_setting("account")["id"] == 44
            assert server.app.state.vault.public_key == previous_key
            assert api.post("/api/auth/import/preview", json={"files": [settings]}).json()["state"] == "missing_session"
            assert api.post("/api/auth/import", json={"files": [settings]}).status_code == 422
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            navigate_panel(page, "connection")
            expect(page.locator("#account-heading")).to_have_text("Connected: @synthetic")
            expect(page.locator("#authorized-account")).to_contain_text("ID 44")
            expect(page.locator("#credentials-form")).not_to_be_visible()
            page.locator("#authorized-state").screenshot(path=str(output / "connected-account-card.png"))
            renewal_metadata = json.dumps({"api_id": 123, "api_hash": "b" * 32}).encode()
            for expired, seed in ((False, b"r"), (True, b"s")):
                if expired:
                    server.app.state.collector.authorization_required = True
                    server.app.state.collector.phase = "authorization_required"
                    page.evaluate("async()=>{await refreshStatus();setAuthStep('credentials');}")
                else:
                    page.locator("#change-account").click()
                page.locator('[data-auth-method="files"]').click()
                page.locator("#session-file").set_input_files([
                    browser_file("replacement.txt", saved_session(seed).encode()),
                    browser_file("replacement.json", renewal_metadata)])
                expect(page.locator("#import-result")).to_have_attribute("data-state", "ready")
                expect(page.locator("#auth-continue")).to_have_text("Connect account")
                expect(page.locator("#import-new-workspace")).to_be_hidden()
                with page.expect_response(lambda response: response.url.endswith('/api/auth/configure')) as renewed:
                    page.locator("#auth-continue").click()
                assert renewed.value.status == 200, renewed.value.text()
                expect(page.locator("#authorized-state")).to_be_visible()
                assert len(server.app.state.profiles.entries) == 1
                assert server.app.state.store.get_setting("account")["id"] == 44
                assert server.app.state.vault.public_key == previous_key
                assert server.app.state.vault.read("credentials")["session"] == saved_session(seed)
            page.locator("#account-add-another").click()
            expect(page.locator("#import-new-workspace")).to_be_visible()
            page.locator("#session-file").set_input_files(browser_file("research.json", metadata))
            expect(page.locator("#import-result")).to_have_attribute("data-state", "missing_session")
            expect(page.locator("#import-result")).to_contain_text("No session")
            expect(page.locator("#auth-continue")).to_be_disabled()
            page.locator("#import-result").screenshot(path=str(output / "missing-session-card.png"))
            for width in (1440, 390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
            page.screenshot(path=str(output / "missing-session-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.locator("#session-file").set_input_files(browser_file("tdata.zip", b"broken zip"))
            expect(page.locator("#import-result")).to_have_attribute("data-state", "invalid")
            expect(page.locator("#import-result")).to_contain_text("ZIP")
            expect(page.locator("#auth-continue")).to_be_disabled()
            page.locator("#session-file").set_input_files([
                browser_file("research.json", metadata), browser_file("research.session", sqlite_fixture())])
            expect(page.locator("#import-result")).to_have_attribute("data-state", "ready")
            expect(page.locator("#import-result")).to_contain_text("Synthetic laptop")
            expect(page.locator("#auth-continue")).to_be_enabled()
            page.screenshot(path=str(output / "session-found-desktop.png"), full_page=True)
            page.locator("#import-result").screenshot(path=str(output / "session-found-card.png"))
            page.locator("#auth-continue").click()
            expect(page.locator("dialog.panel-dialog[open]")).to_contain_text("Add another account")
            expect(page.locator("dialog.panel-dialog[open] input")).to_have_value("research")
            answer_panel_dialog(page, accept=False)
            assert len(server.app.state.profiles.entries) == 1, "Cancel created a workspace"
            page.locator("#auth-continue").click()
            answer_panel_dialog(page, text="New research account")
            try:
                expect(page.locator("#authorized-state")).to_be_visible(timeout=20000)
            except AssertionError:
                print("Import switch diagnostics", page.evaluate("""()=>({profile:state.profile,url:location.pathname+location.search,
                  error:$('toast').textContent,gate:$('login-error').textContent,known:state.profiles.map(p=>p.id)})"""), errors)
                raise
            expect(page.locator("#authorized-account")).to_contain_text("ID 456")
            assert server.app.state.store.get_setting("account")["id"] == 44
            assert len(server.app.state.profiles.entries) == 2
            page.locator("#account-delete-workspace").click()
            expect(page.locator("dialog.panel-dialog[open]")).to_contain_text("signing key")
            expect(page.locator("dialog.panel-dialog[open] button[type=submit]")).to_be_disabled()
            page.locator("dialog.panel-dialog[open] input").fill("wrong name")
            expect(page.locator("dialog.panel-dialog[open] button[type=submit]")).to_be_disabled()
            answer_panel_dialog(page, text="New research account")
            expect(page.locator("#authorized-account")).to_contain_text("ID 44")
            assert len(server.app.state.profiles.entries) == 1
            page.goto(server.url + "/account?lang=ru")
            expect(page.locator("#workspace")).to_be_visible()
            page.locator("#account-add-another").click()
            page.locator("#session-file").set_input_files(browser_file("research.json", metadata))
            expect(page.locator("#import-result")).to_contain_text("Нет сессии")
            expect(page.locator("#auth-continue")).to_be_disabled()
            page.locator("#import-result").screenshot(path=str(output / "missing-session-card-ru.png"))
            assert not errors, errors
            browser.close()
    print("Import preflight: metadata-only blocked; paired sessions, TData and StringSession accepted; conflicts and damaged ZIP explained; session renewal preserves workspace and identity; adding accounts uses separate workspaces; typed deletion passed.")


if __name__ == "__main__":
    main()
