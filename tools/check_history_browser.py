"""Offline browser acceptance: history pause, reload, resume, media and signed handoff."""
import asyncio
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, unlock
from test_collector import CHAT, FakeClient, media_message, telegram_message
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
            page.locator("#history-start").click()
            expect(page.locator("#history-progress")).to_contain_text("2 messages", timeout=12000)
            page.locator("#history-pause").click()
            expect(page.locator("#history-progress")).to_contain_text("History paused")
            page.reload()
            navigate_panel(page, "sources")
            page.locator("#sources-tab-chats").click()
            expect(page.locator("#history-progress")).to_contain_text("History paused")
            expect(page.locator("#history-resume")).to_be_enabled()
            HistoryClient.allow_remaining.set()
            page.locator("#history-resume").click()
            expect(page.locator("#history-progress")).to_contain_text("History reading finished", timeout=12000)
            expect(page.locator("#history-progress")).to_contain_text("5 messages")
            expect(page.locator("#history-media")).to_contain_text("1 saved, 0 pending", timeout=12000)
            with page.expect_download() as download:
                page.locator("#history-report").click()
            report = root / "history-report.json"
            download.value.save_as(report)
            response = context.request.get(server.url + "/api/export/zip", headers=headers)
            assert response.ok, response.text()
            bundle = root / "evidence.zip"
            bundle.write_bytes(response.body())
            state = context.request.get(server.url + "/api/status", headers=headers).json()
            checked = verify_history_report(report, state["fingerprint"], bundle)
            assert checked["evidence_counts_checked"] and checked["captured"] == 5
            assert len(server.app.state.store.events(kind="message.snapshot")) == 5
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
