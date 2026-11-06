import asyncio
import base64
import json
import sys
import tempfile
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from check_browser import RunningApp, answer_panel_dialog, check_layout, launch_browser, navigate_panel, unlock
from tgwitness.app import create_app
from tgwitness.profiles import UNEXPORTED, UNREADABLE
from tools.browser_fixtures import FakeClient, saved_session

CONFIRM = "The session stays active in Telegram: deleting does not sign it out."


def import_body(seed, label):
    return {"files": [{"name": label + ".txt", "content": base64.b64encode(saved_session(seed).encode()).decode()}],
            "api_id": 123, "api_hash": "a" * 32, "label": label}


def observe(store, number=1):
    store.append("message.new", {"text": "Synthetic evidence", "sender_id": 55, "raw": {}}, -1000000000123, number, 55)


async def api_checks():
    with tempfile.TemporaryDirectory(prefix="workspace-deletion-") as scratch:
        root = Path(scratch)
        app = create_app(root, client_factory=FakeClient)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                         headers={"Authorization": "Bearer " + app.state.vault.token}) as client:
                registry = app.state.profiles

                async def blocked(pid):
                    listed = (await client.get("/api/profiles")).json()["profiles"]
                    return next(p for p in listed if p["id"] == pid)["deletion_blocked"]

                fresh = (await client.post("/api/profiles", json={"label": "Fresh"})).json()["id"]
                assert await blocked(fresh) is None
                assert (await client.delete("/api/profiles/" + fresh)).status_code == 200

                response = await client.post("/api/profiles/import", json=import_body(b"d", "Imported"))
                assert response.status_code == 200, response.text
                pid = response.json()["profile"]["id"]
                child = registry.entries[pid]["app"]
                assert await blocked(pid) is None, "A journal with only setup records must count as empty"
                observe(child.state.store)
                assert await blocked(pid) == UNEXPORTED
                refused = await client.delete("/api/profiles/" + pid)
                assert refused.status_code == 409 and refused.json()["detail"] == UNEXPORTED, refused.text
                assert registry.entries[pid]["app"] is child and (root / "profiles" / pid / "journal.sqlite3").is_file()
                assert not child.state.closing and not registry.entries[pid].get("deleting")
                assert (await client.get("/profiles/" + pid + "/api/export/jsonl")).status_code == 200
                assert await blocked(pid) == UNEXPORTED, "Only the signed evidence ZIP counts as an export"
                assert (await client.get("/profiles/" + pid + "/api/export/zip")).status_code == 200
                assert await blocked(pid) is None
                observe(child.state.store, 2)
                assert await blocked(pid) == UNEXPORTED, "Records after the export must block deletion again"
                assert (await client.delete("/api/profiles/" + pid)).status_code == 409
                encrypted = await client.post("/profiles/" + pid + "/api/export/zip",
                                              json={"password": "synthetic long password"})
                assert encrypted.status_code == 200, encrypted.text
                assert await blocked(pid) is None
                assert (await client.delete("/api/profiles/" + pid)).status_code == 200
                assert pid not in registry.entries and not (root / "profiles" / pid).exists()

                for label, recorded in (("Broken with records", True), ("Broken empty", False)):
                    sid = (await client.post("/api/profiles", json={"label": label})).json()["id"]
                    entry = registry.entries[sid]
                    if recorded:
                        observe(entry["app"].state.store)
                    await entry["cm"].__aexit__(None, None, None)
                    entry.update(app=None, cm=None, error_type="SyntheticFailure")
                    assert await blocked(sid) == (UNREADABLE if recorded else None)
                    response = await client.delete("/api/profiles/" + sid)
                    assert response.status_code == (409 if recorded else 200), response.text
                    assert (root / "profiles" / sid).exists() == recorded

                rollback = (await client.post("/api/profiles", json={"label": "Rollback"})).json()["id"]
                observe(registry.entries[rollback]["app"].state.store)
                assert (await registry.delete(rollback, require_export=False))["deleted"]


def browser_checks():
    output = ROOT / "test-results" / "workspace-deletion"
    output.mkdir(parents=True, exist_ok=True)
    russian = json.loads((ROOT / "tgwitness" / "locales" / "ru.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="workspace-deletion-browser-") as scratch, RunningApp(Path(scratch)) as server:
        headers = {"Authorization": "Bearer " + server.app.state.vault.token}
        with httpx.Client(base_url=server.url, headers=headers, timeout=30) as api:
            pid = api.post("/api/profiles/import", json=import_body(b"w", "Evidence account")).json()["profile"]["id"]
            observe(server.app.state.profiles.entries[pid]["app"].state.store)
            with sync_playwright() as playwright:
                browser = launch_browser(playwright)
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                unlock(page, server)
                navigate_panel(page, "accounts")
                card = page.locator('.account-card[data-profile="' + pid + '"]')
                expect(card.locator("[data-action=delete]")).to_be_disabled()
                expect(card.locator("[data-action=delete]")).to_have_attribute("title", UNEXPORTED)
                expect(card.locator(".account-delete-blocked")).to_have_count(0)
                card.screenshot(path=str(output / "card-blocked.png"))
                page.evaluate("id=>switchProfile(id)", pid)
                navigate_panel(page, "connection")
                expect(page.locator("#account-delete-workspace")).to_be_visible()
                expect(page.locator("#account-delete-workspace")).to_be_disabled()
                expect(page.locator("#account-delete-reason")).to_have_text(UNEXPORTED)
                page.locator("#account-manage").screenshot(path=str(output / "connection-blocked.png"))
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 1000})
                    check_layout(page)
                page.set_viewport_size({"width": 1440, "height": 1000})
                assert api.get("/profiles/" + pid + "/api/export/zip").status_code == 200
                page.evaluate("()=>loadProfiles()")
                expect(page.locator("#account-delete-workspace")).to_be_enabled()
                expect(page.locator("#account-delete-reason")).to_be_hidden()
                page.locator("#account-delete-workspace").click()
                expect(page.locator("dialog.panel-dialog[open]")).to_contain_text(CONFIRM)
                answer_panel_dialog(page, text="Evidence account")
                expect(page.locator("#toast")).to_contain_text("Workspace deleted.")
                assert pid not in server.app.state.profiles.entries

                other = api.post("/api/profiles/import", json=import_body(b"r", "Russian")).json()["profile"]["id"]
                observe(server.app.state.profiles.entries[other]["app"].state.store)
                page.goto(server.url + "/accounts?lang=ru")
                expect(page.locator("#workspace")).to_be_visible()
                card = page.locator('.account-card[data-profile="' + other + '"]')
                expect(card.locator("[data-action=delete]")).to_have_attribute("title", russian[UNEXPORTED])
                expect(card.locator("[data-action=delete]")).to_be_disabled()
                card.screenshot(path=str(output / "card-blocked-ru.png"))
                assert not errors, errors
                browser.close()


if __name__ == "__main__":
    asyncio.run(api_checks())
    browser_checks()
    print("Workspace deletion: blocked with 409 and a visible reason until a signed evidence ZIP covers the journal; "
          "setup-only journals, rollback and the 'session stays active' confirmation passed.")
