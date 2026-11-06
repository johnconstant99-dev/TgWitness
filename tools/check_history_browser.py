import asyncio
import tempfile
import threading
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, answer_panel_dialog, check_layout, launch_browser, navigate_panel, unlock
from tools.browser_fixtures import CHAT, FakeClient, media_message, telegram_message
from tgwitness import history, i18n
from tgwitness.verify import verify_history_report


class HistoryClient(FakeClient):
    allow_remaining = threading.Event()

    async def get_messages(self, entity, limit=None, offset_id=0, **kwargs):
        if offset_id:
            while not self.allow_remaining.is_set():
                await asyncio.sleep(.02)
        rows = [media_message(5)] + [telegram_message(i, text=f"History message {i}") for i in (4, 3, 2, 1)]
        return [m for m in rows if not offset_id or m.id < offset_id][:limit]


def main():
    history.PAGE_SIZE = 2
    HistoryClient.allow_remaining.clear()
    with tempfile.TemporaryDirectory(prefix="tgwitness-history-browser-") as temp, sync_playwright() as p:
        root = Path(temp)
        with RunningApp(root / "workspace", client_factory=HistoryClient) as server:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            page, errors = context.new_page(), []
            page.on("pageerror", lambda error: errors.append(str(error)))
            headers = {"Authorization": "Bearer " + server.app.state.vault.token}
            for path, body in (
                ("auth/configure", {"api_id": 123, "api_hash": "a" * 32}),
                ("auth/phone", {"phone": "+15550001111"}),
                ("auth/code", {"code": "12345"}),
            ):
                response = context.request.post(server.url + "/api/" + path, data=body, headers=headers)
                assert response.ok, response.text()
            assert context.request.get(server.url + "/api/dialogs", headers=headers).ok
            for path, body in (("targets", {"chat_id": CHAT, "enabled": True}), ("collector/start", {})):
                response = context.request.post(server.url + "/api/" + path, data=body, headers=headers)
                assert response.ok, response.text()
            unlock(page, server)
            navigate_panel(page, "sources")
            page.locator("#sources-tab-chats").click()
            expect(page.locator("#history-start")).to_be_disabled()
            expect(page.locator("#history-availability")).to_contain_text("This account is busy")
            expect(page.locator("#history-card > .notice")).to_be_visible()
            page.locator("#history-details > summary").click()
            expect(page.locator("#history-details .hint")).to_contain_text("This run only loads the enabled sources listed at its start.")
            page.locator("#history-details > summary").click()
            rejected = context.request.post(server.url + "/api/history/start", data={}, headers=headers)
            assert rejected.status == 400 and "busy" in rejected.text()
            assert context.request.post(server.url + "/api/collector/stop", data={}, headers=headers).ok
            page.reload()
            navigate_panel(page, "sources")
            page.locator("#sources-tab-chats").click()
            page.locator("#history-workers").select_option("3")
            expect(page.locator("#history-availability")).to_be_hidden()
            page.locator("#history-admin").uncheck()
            page.locator("#history-start").click()
            expect(page.locator("#history-progress")).to_contain_text("2 messages", timeout=12000)
            expect(page.locator("#history-transport")).to_be_disabled()
            changed = context.request.post(server.url + "/api/history/resume", data={"transport": "takeout"}, headers=headers)
            assert changed.status == 400
            rejected = context.request.post(server.url + "/api/collector/start", data={}, headers=headers)
            assert rejected.status == 400 and "busy" in rejected.text()
            page.locator("#history-pause").click()
            expect(page.locator("#history-progress")).to_contain_text("History paused")
            page.reload()
            navigate_panel(page, "sources")
            page.locator("#sources-tab-chats").click()
            expect(page.locator("#history-progress")).to_contain_text("History paused")
            expect(page.locator("#history-resume")).to_be_enabled()
            expect(page.locator("#history-workers")).to_have_value("3")
            expect(page.locator("#history-admin")).not_to_be_checked()
            HistoryClient.allow_remaining.set()
            page.locator("#history-resume").click()
            expect(page.locator("#history-progress")).to_contain_text("History reading finished", timeout=12000)
            expect(page.locator("#history-progress")).to_contain_text("5 messages")
            expect(page.locator("#history-media")).to_contain_text("1 saved, 0 pending", timeout=12000)
            with page.expect_download() as download:
                page.locator("#history-report").click()
                answer_panel_dialog(page)
            report = root / "history-report.json"
            download.value.save_as(report)
            response = context.request.get(server.url + "/api/export/zip", headers=headers)
            assert response.ok, response.text()
            bundle = root / "evidence.zip"
            bundle.write_bytes(response.body())
            state = context.request.get(server.url + "/api/status", headers=headers).json()
            checked = verify_history_report(report, state["fingerprint"], bundle)
            subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "tgwitness/verify.py"),
                str(report), "--evidence", str(bundle), "--fingerprint", state["fingerprint"]],
                check=True, capture_output=True, text=True)
            assert checked["evidence_counts_checked"] and checked["captured"] == 5
            assert len(server.app.state.store.events(kind="message.snapshot")) == 5
            assert state["history"]["options"]["media_workers"] == 3
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
            context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
            page.goto(server.url + "/?lang=ru")
            navigate_panel(page, "sources")
            page.locator("#sources-tab-chats").click()
            expect(page.locator("#history-progress")).to_contain_text("Чтение истории завершено")
            check_layout(page)
            assert not errors, errors
            context.close()
            browser.close()
    print("History browser acceptance passed: pause, reload, resume, media, signed handoff, EN/RU and mobile.")


if __name__ == "__main__":
    main()
