import asyncio
import base64
import io
import json
import sqlite3
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright
from telethon.crypto import AuthKey
from telethon.errors import (AuthKeyDuplicatedError, AuthKeyNotFound, AuthKeyUnregisteredError,
                             SessionPasswordNeededError, SessionRevokedError, UserDeactivatedBanError)
from telethon.sessions import StringSession
from telethon.tl import functions, types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from check_browser import RunningApp, check_layout, launch_browser, navigate_panel, unlock
from tgwitness.account_import import PASSWORD_PENDING, preview, session_key
from tgwitness.app import create_app
from tgwitness.collector import LOSS_MEANING
from tools.browser_fixtures import FakeClient, saved_session, sqlite_fixture, tdata_fixture

READ_ONLY = {"GetUsersRequest", "GetAppConfigRequest"}
FAILURES = {ord("R"): AuthKeyUnregisteredError, ord("S"): SessionRevokedError, ord("P"): SessionPasswordNeededError,
            ord("B"): UserDeactivatedBanError, ord("D"): AuthKeyDuplicatedError}


class LivenessClient(FakeClient):
    checks = []
    imports = []

    def __init__(self, session, api_id, api_hash, **kwargs):
        super().__init__(session, api_id, api_hash, **kwargs)
        self.seed = session.auth_key.key[0] if session.auth_key else None
        self.calls = []
        (type(self).checks if kwargs.get("receive_updates") is False else type(self).imports).append(self)

    async def connect(self):
        if self.seed == ord("N"):
            raise AuthKeyNotFound()
        await super().connect()

    async def __call__(self, request):
        self.calls.append(type(request).__name__)
        if isinstance(request, functions.users.GetUsersRequest) and self.seed in FAILURES:
            raise FAILURES[self.seed](request)
        if isinstance(request, functions.help.GetAppConfigRequest) and self.seed == ord("F"):
            return types.help.AppConfig(hash=0, config=types.JsonObject([
                types.JsonObjectValue("freeze_since_date", types.JsonNumber(1767225600))]))
        return await super().__call__(request)

    async def log_out(self):
        self.calls.append("log_out")
        return await super().log_out()

    async def sign_in(self, *args, **kwargs):
        self.calls.append("sign_in")
        return await super().sign_in(*args, **kwargs)


def session(prefix, index):
    value = StringSession()
    value.set_dc(2, "149.154.167.51", 443)
    value.auth_key = AuthKey((prefix + bytes([index])) * 128)
    return value.save()


def database(script, rows=()):
    db = sqlite3.connect(":memory:")
    db.executescript(script)
    for statement, values in rows:
        db.execute(statement, values)
    db.commit()
    data = db.serialize()
    db.close()
    return data


def telethon_file(saved):
    source = StringSession(saved)
    return database("CREATE TABLE version(version INTEGER); CREATE TABLE sessions "
                    "(dc_id INTEGER,server_address TEXT,port INTEGER,auth_key BLOB);",
                    [("INSERT INTO version VALUES (8)", ()),
                     ("INSERT INTO sessions VALUES (?,?,?,?)", (source.dc_id, source.server_address, source.port,
                                                                source.auth_key.key))])


NOT_SESSION = database("CREATE TABLE messages(id INTEGER, text TEXT);")
VIEWS = database("CREATE TABLE stored(dc_id INTEGER,server_address TEXT,port INTEGER,auth_key BLOB); "
                 "CREATE VIEW sessions AS SELECT * FROM stored; CREATE VIEW version AS SELECT 8 AS version;")


def settings(api_id):
    return json.dumps({"api_id": api_id, "api_hash": "a" * 32}).encode()


def upload(name, data):
    return {"name": name, "content": base64.b64encode(data).decode()}


def folder_accounts():
    accounts = {}
    for index in range(1, 7):
        accounts["live%02d" % index] = (telethon_file(session(b"a", index)), 600 + index, "alive")
    accounts["live01-copy"] = (telethon_file(session(b"a", 1)), 601, "duplicate")
    accounts["live01-second-key"] = (telethon_file(session(b"a", 7)), 601, "duplicate")
    for index, prefix in enumerate((b"R", b"R", b"R", b"N"), 1):
        accounts["revoked%02d" % index] = (telethon_file(session(prefix, index)), 700 + index, "revoked")
    accounts["frozen"] = (telethon_file(session(b"F", 1)), 801, "frozen")
    accounts["two-step"] = (telethon_file(session(b"P", 1)), 802, "password")
    accounts["banned"] = (telethon_file(session(b"B", 1)), 803, "banned")
    accounts["used-twice"] = (telethon_file(session(b"D", 1)), 804, "duplicate")
    accounts["chat-database"] = (NOT_SESSION, 805, "invalid")
    accounts["view-session"] = (VIEWS, 806, "invalid")
    return accounts


def unit_checks():
    assert "not a Telegram session" in preview([upload("other.session", NOT_SESSION)])["message"]
    views = preview([upload("views.session", VIEWS)])["message"]
    assert "views" in views and "not a Telegram session" not in views, views
    assert preview([upload("broken.session", b"plain text")])["message"] == \
        "This .session file is not a Telegram session: it is not an SQLite database."
    text, sqlite = preview([upload("a.txt", saved_session().encode())]), preview([upload("a.session", sqlite_fixture())])
    assert text["key_id"] == sqlite["key_id"] and len(text["key_id"]) == 16
    assert preview([upload("p.session", sqlite_fixture("pyrogram"))])["expected_user_id"] == 44


async def api_checks():
    with tempfile.TemporaryDirectory(prefix="batch-import-") as scratch:
        app = create_app(Path(scratch), client_factory=LivenessClient)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
                                         headers={"Authorization": "Bearer " + app.state.vault.token}) as client:
                async def check(saved, api_id=501):
                    body = {"files": [upload("a.txt", saved.encode()), upload("a.json", settings(api_id))]}
                    response = await client.post("/api/profiles/check", json=body)
                    assert response.status_code == 200, response.text
                    return response.json()

                expected = {b"a": ("alive", None), b"R": ("revoked", LOSS_MEANING["session_ended"]),
                            b"S": ("revoked", LOSS_MEANING["session_revoked"]), b"P": ("password", PASSWORD_PENDING),
                            b"F": ("frozen", LOSS_MEANING["account_frozen"]),
                            b"B": ("banned", LOSS_MEANING["account_banned"]),
                            b"D": ("duplicate", LOSS_MEANING["session_duplicated"]),
                            b"N": ("revoked", LOSS_MEANING["session_ended"])}
                for prefix, (state, message) in expected.items():
                    result = await check(session(prefix, 1))
                    assert result["state"] == state, (prefix, result)
                    assert message is None or result["message"] == message, (prefix, result)
                alive = await check(session(b"a", 1))
                assert alive["account"] == {"id": 501, "username": "synthetic", "name": "Synthetic"}, alive
                broken = await client.post("/api/profiles/check", json={"files": [upload("x.session", NOT_SESSION)]})
                assert broken.json()["state"] == "invalid" and "not a Telegram session" in broken.json()["message"]
                registry = app.state.profiles
                assert len(registry.entries) == 1, "A check must not create a workspace"
                assert not [e for e in app.state.store.all_events() if e["kind"].startswith("profile.")]
                imported = await client.post("/api/profiles/import", json={
                    "files": [upload("a.txt", session(b"a", 1).encode()), upload("a.json", settings(501))]})
                assert imported.status_code == 200, imported.text
                held = await check(session(b"a", 1))
                assert held["state"] == "duplicate" and "already has a workspace" in held["message"], held
                other = await check(session(b"a", 2), 501)
                assert other["state"] == "duplicate" and "already has a workspace" in other["message"], other
                release = registry.reserve_session(session_key(session(b"a", 3)), object())
                try:
                    busy = await check(session(b"a", 3), 503)
                    assert busy["state"] == "duplicate" and "being imported" in busy["message"], busy
                finally:
                    release()
                assert not [owner for owner in app.state.collector.pool().assigned if owner.startswith("session-check-")]
    assert LivenessClient.checks
    for client in LivenessClient.checks:
        assert set(client.calls) <= READ_ONLY and not client.connected, client.calls


def rows(page):
    return dict(page.evaluate("()=>[...document.querySelectorAll('#fleet-results li')]"
                              ".map(li=>[li.querySelector('strong').textContent,li.dataset.state||'unsupported'])"))


def settled(page, states):
    page.wait_for_function("states=>[...document.querySelectorAll('#fleet-results li[data-state]')]"
                           ".every(li=>!states.includes(li.dataset.state))", arg=states, timeout=120000)


def browser_checks():
    output = ROOT / "test-results" / "batch-import"
    output.mkdir(parents=True, exist_ok=True)
    russian = json.loads((ROOT / "tgwitness" / "locales" / "ru.json").read_text(encoding="utf-8"))
    LivenessClient.checks.clear()
    LivenessClient.imports.clear()
    with tempfile.TemporaryDirectory(prefix="batch-import-browser-") as scratch:
        folder = Path(scratch) / "accounts"
        folder.mkdir()
        accounts = folder_accounts()
        for name, (data, api_id, _) in accounts.items():
            (folder / (name + ".session")).write_bytes(data)
            (folder / (name + ".json")).write_bytes(settings(api_id))
        assert len(list(folder.iterdir())) == 36
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, saved, api_id in (("zipped-live", session(b"z", 1), 901), ("zipped-revoked", session(b"R", 9), 902)):
                bundle.writestr("batch/" + name + ".session", telethon_file(saved))
                bundle.writestr("batch/" + name + ".json", settings(api_id))
            bundle.writestr("__MACOSX/batch/._zipped-live.session", b"metadata")
        (Path(scratch) / "data").mkdir()
        with RunningApp(Path(scratch) / "data", client_factory=LivenessClient) as server, sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            navigate_panel(page, "accounts")
            page.locator("#fleet-import-open").click()
            started = time.monotonic()
            page.locator("#fleet-folder").set_input_files(str(folder))
            expect(page.locator("#fleet-results li")).to_have_count(18)
            settled(page, ["waiting"])
            offline = rows(page)
            assert offline["live01-copy"] == "duplicate" and offline["chat-database"] == "invalid", offline
            assert offline["view-session"] == "invalid" and offline["live01"] == "ready", offline
            expect(page.locator("#fleet-import-start")).to_be_disabled()
            page.locator("#fleet-import-check").click()
            settled(page, ["waiting", "ready", "checking"])
            expect(page.locator("#fleet-import-stop")).to_be_hidden()
            elapsed = time.monotonic() - started
            assert elapsed < 120, elapsed
            table = rows(page)
            assert table == {name: state for name, (_, _, state) in accounts.items()}, table
            chat = page.locator("#fleet-results li", has_text="chat-database")
            expect(chat).to_contain_text("not a Telegram session")
            expect(page.locator("#fleet-results li", has_text="view-session")).to_contain_text("SQLite views")
            expect(page.locator("#fleet-results li", has_text="two-step")).to_contain_text(PASSWORD_PENDING)
            expect(page.locator("#fleet-results li", has_text="frozen")).to_contain_text("froze")
            expect(page.locator("#fleet-import-summary")).to_have_text(
                "Active: 6 · imported: 0 · not usable: 12 · not checked: 0")
            page.locator("#fleet-import").screenshot(path=str(output / "table-desktop.png"))
            for width in (390, 320):
                page.set_viewport_size({"width": width, "height": 1000})
                check_layout(page)
                page.locator("#fleet-import").screenshot(path=str(output / ("table-" + str(width) + ".png")))
            page.set_viewport_size({"width": 1440, "height": 1000})
            assert len(server.app.state.profiles.entries) == 1, "Checking imported accounts"
            page.locator("#fleet-import-start").click()
            expect(page.locator("#fleet-results .fleet-result.ok")).to_have_count(6, timeout=60000)
            expect(page.locator("#fleet-import-stop")).to_be_hidden(timeout=30000)
            labels = sorted(entry["label"] for entry in server.app.state.profiles.entries.values() if entry["id"] != "default")
            assert labels == ["live%02d" % index for index in range(1, 7)], labels

            page.locator("#fleet-files").set_input_files([
                {"name": "accounts.zip", "mimeType": "application/zip", "buffer": archive.getvalue()},
                {"name": "desktop.zip", "mimeType": "application/zip", "buffer": tdata_fixture()}])
            expect(page.locator("#fleet-results li")).to_have_count(3)
            settled(page, ["waiting"])
            assert rows(page) == {"zipped-live": "ready", "zipped-revoked": "ready", "desktop": "ready"}, rows(page)
            hint = page.locator("#fleet-results li", has_text="zipped-live").locator(".hint")
            expect(hint).to_contain_text("zipped-live.session + zipped-live.json")
            page.locator("#fleet-import-check").click()
            settled(page, ["waiting", "ready", "checking"])
            table = rows(page)
            assert table["zipped-live"] == "alive" and table["zipped-revoked"] == "revoked", table

            page.goto(server.url + "/?lang=ru")
            expect(page.locator("#workspace")).to_be_visible()
            navigate_panel(page, "accounts")
            page.locator("#fleet-import-open").click()
            expect(page.locator("#fleet-import-check")).to_have_text(russian["Check sessions"])
            page.locator("#fleet-files").set_input_files([
                {"name": "late.session", "mimeType": "application/octet-stream", "buffer": telethon_file(session(b"R", 7))},
                {"name": "other.session", "mimeType": "application/octet-stream", "buffer": NOT_SESSION}])
            settled(page, ["waiting"])
            page.locator("#fleet-import-check").click()
            settled(page, ["waiting", "ready", "checking"])
            late = page.locator("#fleet-results li", has_text="late")
            expect(late.locator(".fleet-state")).to_have_text(russian["Revoked"])
            expect(late.locator(".fleet-detail")).to_have_text(russian[LOSS_MEANING["session_ended"]])
            expect(page.locator("#fleet-results li", has_text="other").locator(".fleet-detail")).to_have_text(
                russian["This SQLite file is not a Telegram session: it has no sessions and version tables."])
            page.locator("#fleet-import").screenshot(path=str(output / "table-ru.png"))
            assert not errors, errors
            browser.close()
    assert LivenessClient.checks and all(set(client.calls) <= READ_ONLY for client in LivenessClient.checks)
    assert not any("log_out" in client.calls for client in LivenessClient.imports)


if __name__ == "__main__":
    unit_checks()
    asyncio.run(api_checks())
    browser_checks()
    print("Batch import: folder and ZIP pairs, read-only liveness table (live, revoked, duplicate, two-step, frozen, "
          "banned, not a session, views) within two minutes; only live accounts imported.")
