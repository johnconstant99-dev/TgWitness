"""Two chat exports on different accounts run at the same time from the panel and save under the chat name."""
import asyncio
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from playwright.sync_api import expect, sync_playwright

from check_browser import RunningApp, launch_browser, unlock
from tools.browser_fixtures import CHAT, ENTITIES, NEWS, FakeClient, message
from tools.browser_helpers import answer_panel_dialog
from tgwitness import distributed_export
from tgwitness.verify import fingerprint, verify_chat_export


class TwoChatClient(FakeClient):
    held = threading.Event()

    async def get_entity(self, peer):
        return ENTITIES[peer]

    async def iter_dialogs(self, limit):
        yield NS(id=CHAT, name="Synthetic group", is_group=True, is_channel=True, entity=ENTITIES[CHAT], folder_id=None)
        yield NS(id=NEWS, name="Scam / News", is_group=False, is_channel=True, entity=ENTITIES[NEWS], folder_id=None)

    @staticmethod
    def rows(peer):
        chat = CHAT if peer.id == ENTITIES[CHAT].id else NEWS
        return [message(chat, mid, "Synthetic message number " + str(mid)) for mid in range(6, 0, -1)]

    async def get_messages(self, peer, limit=None, offset_date=None, ids=None, **kwargs):
        rows = self.rows(peer)
        if ids is not None:
            return next((row for row in rows if row.id == ids), None)
        return [row for row in rows if not offset_date or row.date < offset_date][:limit]

    async def iter_messages(self, peer, offset_id=0, min_id=0, **kwargs):
        while peer.id == ENTITIES[CHAT].id and not self.held.is_set():
            await asyncio.sleep(.02)
        for row in self.rows(peer):
            if min_id < row.id < offset_id:
                yield row


def main():
    TwoChatClient.held.clear()
    distributed_export.CHUNK = 2
    day = datetime.now(timezone.utc).date().isoformat()
    with tempfile.TemporaryDirectory(prefix="tgwitness-parallel-exports-") as temp, sync_playwright() as p:
        with RunningApp(Path(temp) / "workspace", client_factory=TwoChatClient) as server:
            browser = launch_browser(p)
            context = browser.new_context(viewport={"width": 1440, "height": 1000}, timezone_id="UTC",
                                          reduced_motion="reduce", accept_downloads=True)
            page, errors = context.new_page(), []
            page.on("pageerror", lambda error: errors.append(str(error)))
            headers = {"Authorization": "Bearer " + server.app.state.vault.token}

            def post(path, body=None):
                response = context.request.post(server.url + path, headers=headers, data=body or {})
                assert response.ok, (path, response.status, response.text())
                return response.json()

            def get(path):
                response = context.request.get(server.url + path, headers=headers)
                assert response.ok, (path, response.status, response.text())
                return response

            second = post("/api/profiles", {"label": "Second account"})["id"]
            for prefix, api_id in (("/api/", 123), ("/profiles/" + second + "/api/", 124)):
                for path, body in (("auth/configure", {"api_id": api_id, "api_hash": "a" * 32}),
                                   ("auth/phone", {"phone": "+1555000" + str(api_id)}), ("auth/code", {"code": "12345"})):
                    post(prefix + path, body)
                get(prefix + "dialogs")
            apps = {"default": server.app, second: server.app.state.profiles.entries[second]["app"]}
            for app in apps.values():
                app.state.collector.chat_profile = AsyncMock(return_value=({}, {"role": "member"}, []))
            for chat in (CHAT, NEWS):
                post("/api/targets", {"chat_id": chat, "enabled": True})
                server.app.state.store.append("message.snapshot", {"text": "Synthetic record"}, chat, 1)

            unlock(page, server)
            page.evaluate("async chat=>{await navigate('chats');await openChat(chat);}", CHAT)
            page.locator("#chat-export-start").click()
            page.locator("#export-dialog-start").click()
            expect(page.locator("#export-box")).to_contain_text("Exporting Synthetic group", timeout=15000)
            expect(page.locator("#chat-export-start")).to_be_disabled()
            first = get("/api/multi-export/current?chat_id=" + str(CHAT)).json()
            assert first["phase"] == "running" and first["lead"] == "default", first
            expect(page.locator("#export-box")).to_contain_text("Disk space estimated at start")

            page.evaluate("chat=>openChat(chat)", NEWS)
            expect(page.locator("#export-box")).to_be_hidden()
            expect(page.locator("#chat-export-start")).to_be_enabled()
            page.locator("#chat-export-start").click()
            accounts = page.locator("#export-dialog-accounts .export-account")
            expect(accounts.filter(has_text="Busy").locator("input")).to_be_disabled()
            accounts.filter(has_text="Second account").locator("input").check()
            page.locator("#export-dialog-start").click()
            expect(page.locator("#export-box")).to_contain_text("Export ready: 6 messages", timeout=30000)
            assert get("/api/multi-export/" + first["id"]).json()["phase"] == "running"
            assert server.app.state.collector.export_claim == first["id"]
            parallel = get("/api/multi-export/current?chat_id=" + str(NEWS)).json()
            assert parallel["lead"] == second and parallel["filename"] == "Scam_News_" + day + "_1.zip", parallel

            page.evaluate("window.showSaveFilePicker=undefined")
            with page.expect_download() as saved:
                page.locator("#export-box").get_by_role("button", name="Save signed export").click()
                answer_panel_dialog(page)
            assert saved.value.suggested_filename == parallel["filename"], saved.value.suggested_filename
            response = get("/api/multi-export/" + parallel["id"] + "/download")
            assert re.search(r"filename=\"?Scam_News_" + day + r"_1\.zip", response.headers["content-disposition"])
            key = apps[second].state.vault.public_key
            assert verify_chat_export(Path(saved.value.path()), fingerprint(key))["message_count"] == 6

            page.evaluate("chat=>openChat(chat)", CHAT)
            expect(page.locator("#export-box")).to_contain_text("Exporting Synthetic group")
            TwoChatClient.held.set()
            expect(page.locator("#export-box")).to_contain_text("Export ready: 6 messages", timeout=30000)
            done = get("/api/multi-export/" + first["id"]).json()
            assert done["filename"] == "Synthetic_group_" + day + "_1.zip", done
            assert all(app.state.collector.export_claim is None for app in apps.values())
            assert sorted(path.name for path in (Path(temp) / "workspace" / "distributed-exports" / first["id"]).iterdir()) \
                == ["export.zip", "job.json", "status.json"]
            assert not errors, errors
            context.close()
            browser.close()
    print("Parallel exports browser passed: second export on another account while the first runs, busy account "
          "disabled, per-chat progress, disk estimate, archive named after the chat, working files removed.")


if __name__ == "__main__":
    main()
