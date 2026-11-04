"""Exercise the real export API/UI against a deterministic local Telegram fixture."""
import asyncio
import json
import tempfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

from playwright.sync_api import expect, sync_playwright
from telethon.tl import types

from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, unlock
from tools.browser_fixtures import CHAT, ENTITIES, FakeClient, telegram_message
from tgwitness import distributed_export, i18n
from tgwitness.verify import fingerprint, verify_chat_export


class ExportClient(FakeClient):
    remaining = threading.Event()
    reads = 0

    @staticmethod
    def rows():
        rows = []
        for mid in range(1, 7):
            row = telegram_message(mid, "This is a sufficiently long English message about the investigation.")
            row.date = datetime(2026, 10, 1 if mid == 1 else 5, tzinfo=timezone.utc)
            if mid in (2, 3):
                row.reply_to = types.MessageReplyHeader(reply_to_msg_id=mid - 1)
            if mid == 3:
                row.message = "Это ответ на английское сообщение для проверки контекста."
            rows.append(row)
        return list(reversed(rows))

    async def get_entity(self, peer):
        return ENTITIES[CHAT]

    async def iter_dialogs(self, limit):
        async for dialog in super().iter_dialogs(limit):
            if dialog.id == CHAT:
                dialog.entity = ENTITIES[CHAT]
            yield dialog

    async def get_messages(self, peer, limit=None, offset_date=None, ids=None, **kwargs):
        rows = self.rows()
        if ids is not None:
            return next((row for row in rows if row.id == ids), None)
        return [row for row in rows if not offset_date or row.date < offset_date][:limit]

    async def iter_messages(self, peer, offset_id=0, min_id=0, **kwargs):
        type(self).reads += 1
        if type(self).reads > 1:
            while not self.remaining.is_set():
                await asyncio.sleep(.02)
        for row in self.rows():
            if min_id < row.id < offset_id:
                yield row


def main():
    ExportClient.remaining.clear()
    ExportClient.reads = 0
    distributed_export.CHUNK = 2
    output = Path("test-results/distributed-export-browser")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tgwitness-export-browser-") as temp, sync_playwright() as p:
        with RunningApp(Path(temp) / "workspace", client_factory=ExportClient) as server:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, timezone_id="UTC", reduced_motion="reduce")
            page, errors = context.new_page(), []
            page.on("pageerror", lambda error: errors.append(str(error)))
            headers = {"Authorization": "Bearer " + server.app.state.vault.token}
            def post(path, body=None):
                return context.request.post(server.url + "/api/" + path, headers=headers, data=body or {})
            for path, body in (("auth/configure", {"api_id": 123, "api_hash": "a" * 32}),
                               ("auth/phone", {"phone": "+15550001111"}), ("auth/code", {"code": "12345"})):
                response = post(path, body)
                assert response.ok, response.text()
            collector = server.app.state.collector
            collector.chat_profile = AsyncMock(return_value=({}, {"role": "member"}, []))
            assert context.request.get(server.url + "/api/dialogs", headers=headers).ok
            assert post("targets", {"chat_id": CHAT, "enabled": True}).ok
            server.app.state.store.append("message.snapshot", {"text": "Synthetic record"}, CHAT, 1)
            collector.running = True
            unlock(page, server)
            page.evaluate("async chat=>{await navigate('chats');await openChat(chat);}", CHAT)
            page.locator("#chat-export-start").click()
            expect(page.locator("#export-dialog-accounts input")).to_be_disabled()
            expect(page.locator("#export-dialog-start")).to_be_disabled()
            rejected = post("multi-export/start", {"chat_id": CHAT, "lead": "default", "profiles": ["default"]})
            assert rejected.status == 400 and "busy" in rejected.text()
            assert collector.running
            page.locator("#export-dialog-cancel").click()
            assert post("collector/stop").ok
            page.locator("#chat-export-start").click()
            page.locator("#export-period").select_option("custom")
            page.locator("#export-from").fill("2026-10-05T00:00")
            page.locator("#export-to").fill("2026-10-07T00:00")
            page.locator("#export-message-language").select_option("en")
            page.locator("#export-reply-mode").select_option("answered")
            page.locator("#export-context").select_option("1")
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
                assert page.locator("#export-dialog").evaluate("e=>e.scrollWidth<=e.clientWidth+1")
            page.screenshot(path=str(output / "export-options-mobile.png"))
            page.set_viewport_size({"width": 1440, "height": 1000})
            page.locator("#export-dialog-start").click()
            expect(page.locator("#export-box")).to_contain_text("Read 1 of 3", timeout=15000)
            rejected = post("collector/start")
            assert rejected.status == 400 and "busy" in rejected.text()
            page.locator("#export-box").get_by_role("button", name="Pause", exact=True).click()
            expect(page.locator("#export-box")).to_contain_text("Export paused")
            page.reload()
            page.evaluate("async chat=>{await navigate('chats');await openChat(chat);}", CHAT)
            page.locator("#chat-export-start").click()
            expect(page.locator("#export-saved-jobs button")).to_have_count(1)
            page.locator("#export-saved-jobs button").click()
            ExportClient.remaining.set()
            page.locator("#export-box").get_by_role("button", name="Resume saved chunks").click()
            expect(page.locator("#export-box")).to_contain_text("Export ready: 3 messages", timeout=60000)
            job = server.app.state.multi_export.public()
            response = context.request.get(server.url + "/api/multi-export/" + job["id"] + "/download", headers=headers)
            assert response.ok, response.text()
            archive = output / "selected-export.zip"
            archive.write_bytes(response.body())
            assert verify_chat_export(archive, fingerprint(server.app.state.vault.public_key))["message_count"] == 3
            with zipfile.ZipFile(archive) as bundle:
                records = json.loads(bundle.read("chat.json"))["messages"]
                assert {r["id"] for r in records if r["selection"]["role"] == "match"} == {2}
                assert json.loads(bundle.read("message-ids.json"))["selection_applied"]
            assert collector.export_claim is None
            context.add_cookies([{"name": i18n.COOKIE, "value": "ru", "url": server.url}])
            preferences = server.app.state.store.get_setting("ui_preferences:admin")
            server.app.state.store.set_setting("ui_preferences:admin", {**preferences, "language": "ru"})
            page.goto(server.url + "/?lang=ru")
            navigate_panel(page, "chats")
            page.evaluate("chat=>openChat(chat)", CHAT)
            page.locator("#chat-export-start").click()
            expect(page.locator("#export-dialog-title")).to_have_text("Выгрузка сообщений чата")
            page.set_viewport_size({"width": 390, "height": 1000})
            check_layout(page)
            page.screenshot(path=str(output / "export-options-ru-mobile.png"))
            assert not errors, errors
            context.close()
            browser.close()
    print("Distributed export browser passed: busy rejection, dates/language/replies/context, pause/reload/resume, verified ZIP, RU and mobile.")


if __name__ == "__main__":
    main()
