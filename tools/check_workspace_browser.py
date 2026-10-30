"""Workspace isolation with delayed API responses, using synthetic local accounts."""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if (ROOT / ".playwright").is_dir():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".playwright"))

import requests
from playwright.sync_api import expect, sync_playwright
from telethon.helpers import TotalList

from tools.check_browser import RunningApp, hold_api_response, launch_browser, release_api_response
from tests.test_collector import CHAT, FakeClient, saved_session, telegram_message
from tests.test_dossier import ALICE, say
from tgwitness import dossier


class WorkspaceClient(FakeClient):
    async def get_messages(self, entity, limit):
        page = TotalList([telegram_message(1)] if limit else [])
        page.total = 1
        return page


def main():
    output = ROOT / "test-results" / "workspace-browser"
    output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    with tempfile.TemporaryDirectory(dir=output) as temporary, RunningApp(
            Path(temporary), client_factory=WorkspaceClient) as server:
        session = requests.Session()
        session.headers["Authorization"] = "Bearer " + server.app.state.vault.token
        def post(path, body):
            response = session.post(server.url + path, json=body, timeout=15)
            response.raise_for_status()
            return response.json()
        post("/api/auth/configure", {"api_id": 123, "api_hash": "a" * 32, "session": saved_session()})
        child = post("/api/profiles", {"label": "Second workspace"})["id"]
        post("/profiles/" + child + "/api/auth/configure", {
            "api_id": 124, "api_hash": "a" * 32, "session": saved_session()})
        first_store = server.app.state.store
        second_store = server.app.state.profiles.entries[child]["app"].state.store
        for store, label in ((first_store, "First"), (second_store, "Second")):
            store.set_target(CHAT, label + " chat", "supergroup", True)
            say(store, CHAT, 1, ALICE, label + " private evidence", label + " person")
            dossier.set_enabled(store, CHAT, True)
        event = first_store.events(kind="message.new")[0]
        with sync_playwright() as p:
            browser = launch_browser(p)
            def page_for_case():
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", locale="en-US")
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(server.url)
                page.locator("#panel-token").fill(server.app.state.vault.token)
                page.locator("#unlock-form button").click()
                page.locator('[data-view="chats"]').click()
                expect(page.locator("#chat-name")).to_have_text("First chat")
                return page
            def switch(page):
                page.locator("#profile-select").select_option(child)
                expect(page.locator("#chat-name")).to_have_text("Second chat")
            def pending(page, expression):
                page.evaluate("expression=>{window.reviewPromise=eval(expression).catch(()=>{});}", expression)
                expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            def release(page):
                release_api_response(page)
                page.evaluate("window.reviewPromise")

            for action in ("switch", "lock"):
                page = page_for_case()
                hold_api_response(page, "/api/events?before=" + str(event["seq"] + 1) + "&limit=1")
                pending(page, "openRecord(" + str(event["seq"]) + ")")
                if action == "switch":
                    switch(page)
                else:
                    page.locator("#top-lock").click()
                    expect(page.locator("#gate")).to_be_visible()
                release(page)
                expect(page.locator("#detail-drawer")).to_be_hidden()
                checks.append("late journal record ignored after " + action)
                page.close()

            page = page_for_case()
            hold_api_response(page, "/api/chats/" + str(CHAT) + "/dossier")
            pending(page, "openDossier(" + str(ALICE) + ")")
            switch(page)
            release(page)
            expect(page.locator("#detail-drawer")).to_be_hidden()
            page.evaluate("openDossier(" + str(ALICE) + ")")
            expect(page.locator("#detail-content")).to_contain_text("Second person")
            expect(page.locator("#detail-content")).not_to_contain_text("First person")
            checks.append("late dossier cannot populate another workspace's cache")
            page.close()

            page = page_for_case()
            hold_api_response(page, "/api/witness/tokens")
            page.locator('[data-view="witness"]').click()
            page.locator("#extras-open-bot").click()
            page.locator("#witness-label").fill("First workspace witness")
            page.locator("#witness-form button[type=submit]").click()
            expect(page.locator("html")).to_have_attribute("data-acceptance-held", "true")
            page.locator("#profile-select").select_option(child)
            expect(page.locator("#witness-list")).to_contain_text("No witness yet")
            release_api_response(page)
            expect(page.locator("#witness-form button[type=submit]")).to_be_enabled()
            expect(page.locator("#witness-new")).to_be_hidden()
            expect(page.locator("#witness-list")).not_to_contain_text("First workspace witness")
            checks.append("late witness token remains associated with its originating workspace")
            page.close()

            page = page_for_case()
            hold_api_response(page, "/api/chats/" + str(CHAT) + "/scale")
            pending(page, "openExportDialog()")
            switch(page)
            release(page)
            expect(page.locator("#export-dialog")).not_to_be_visible()
            checks.append("late export size response cannot open a dialog for another workspace")
            page.close()

            # A locked data file must leave an actionable error, even when the
            # account being deleted is the one currently selected in the panel.
            doomed = post("/api/profiles", {"label": "Incomplete deletion"})["id"]
            directory = Path(temporary) / "profiles" / doomed
            page = page_for_case()
            page.locator("#profile-select").select_option(doomed)
            page.locator('[data-view="accounts"]').click()
            card = page.locator(".account-card").filter(has=page.get_by_role("heading", name="Incomplete deletion"))
            import shutil
            original_remove = shutil.rmtree

            def locked(path, *args, **kwargs):
                if Path(path) == directory:
                    raise PermissionError("synthetic locked file")
                return original_remove(path, *args, **kwargs)

            with patch("tgwitness.profiles.shutil.rmtree", side_effect=locked):
                page.once("dialog", lambda dialog: dialog.accept())
                card.get_by_role("button", name="Delete", exact=True).click()
                expect(card.locator(".account-badge")).to_have_text("Deletion incomplete")
                expect(card).to_contain_text("Observation remains stopped.")
                expect(page.locator("#profile-select")).to_have_value("default")
                expect(page.locator("#toast")).to_contain_text("Could not delete all workspace files")
            assert directory.exists()
            page.screenshot(path=str(output / "deletion-incomplete.png"))
            page.context.add_cookies([{"name": "tgwitness-lang", "value": "ru", "url": server.url}])
            page.reload()
            page.locator('[data-view="accounts"]').click()
            expect(card.locator(".account-badge")).to_have_text("Удаление не завершено")
            expect(card).to_contain_text("Наблюдение остановлено.")
            page.once("dialog", lambda dialog: dialog.accept())
            card.get_by_role("button", name="Удалить", exact=True).click()
            expect(card).to_have_count(0)
            assert not directory.exists()
            checks.append("failed deletion stays visible in English/Russian, selects a healthy workspace and permits retry")
            page.close()
            assert not errors, errors
            browser.close()
        receipt = {"checks": checks, "page_errors": errors}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
