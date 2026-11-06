import asyncio
import base64
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import pytest
from telethon.crypto import AuthKey
from telethon.errors import AuthKeyUnregisteredError, FloodWaitError, PasswordHashInvalidError, SessionPasswordNeededError
from telethon.tl import functions

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tgwitness import client_checks, client_initialization
from tgwitness.account_import import import_accounts, preview, session_key
from tgwitness.collector import Collector
from tgwitness.profiles import Profiles
from tgwitness.security import KeyInUse, KeyLock, Vault
from tgwitness.store import Store
from tgwitness.verify import verify_events
from tools.browser_fixtures import FakeClient, saved_session, sqlite_fixture, tdata_fixture


DONOR = saved_session()
PROFILE = {"device_model": "Synthetic Android", "system_version": "SDK 34",
           "app_version": "12.8.3 (69222)", "lang_pack": "android", "tz_offset": -36000}


class DonorClient(FakeClient):
    def __init__(self, session, api_id, api_hash, **kwargs):
        super().__init__(session, api_id, api_hash, **kwargs)
        self.session, self.api_id, self.account_id = session, api_id, 44
        self.listening = False

    async def connect(self):
        if not self.session.auth_key:
            self.session.set_dc(2, "149.154.167.51", 443)
            self.session.auth_key = AuthKey(bytes([len(self.instances) + 1]) * 256)
            self.session.save()
        key = session_key(self.session.save())
        assert key not in self.active, "The same authorization key connected twice"
        self.active.add(key)
        self.connected = True
        if listener := getattr(self, "connection_listener", None):
            listener("opened")

    async def disconnect(self):
        self.active.discard(session_key(self.session.save()))
        self.connected = False
        if listener := getattr(self, "connection_listener", None):
            listener("closed")

    async def is_user_authorized(self):
        return session_key(self.session.save()) in self.authorized_keys

    async def get_me(self):
        return NS(id=self.account_id, username="synthetic", bot=False, restricted=self.restricted)

    async def __call__(self, request):
        if isinstance(request, functions.users.GetFullUserRequest):
            return NS(full_user=NS(frozen_since_date=1 if self.frozen else None))
        assert isinstance(request, functions.auth.AcceptLoginTokenRequest), type(request).__name__
        type(self).accepts += 1
        candidate = next(c for c in self.instances if c.listening)
        for active in (self, candidate):
            with pytest.raises(KeyInUse):
                KeyLock(session_key(active.session.save()))
        assert self.api_id == 4 and self.tgwitness_client_profile["device_model"] == PROFILE["device_model"]
        assert candidate.api_id == 2040 and candidate.tgwitness_client_profile["lang_pack"] == "tdesktop"
        assert candidate.options["device_model"] != self.options["device_model"]
        if self.failure == "flood":
            raise FloodWaitError(None, 60)
        if self.migrate:
            self.active.remove(session_key(candidate.session.save()))
            candidate.session.set_dc(1, "149.154.175.53", 443)
            candidate.session.auth_key = AuthKey(b"m" * 256)
            candidate.session.save()
            self.active.add(session_key(candidate.session.save()))
        if not self.password:
            self.authorized_keys.add(session_key(candidate.session.save()))
        candidate.scan.set()
        if self.failure == "after_accept":
            raise OSError("synthetic lost reply")
        if self.failure == "cancel":
            raise asyncio.CancelledError()
        return NS()

    async def qr_login(self):
        self.scan = asyncio.Event()

        async def wait(timeout):
            self.listening = True
            try:
                await self.scan.wait()
                assert all(not c.connected for c in self.instances if c.api_id == 4)
                if self.password:
                    raise SessionPasswordNeededError(None)
                return await self.get_me()
            finally:
                self.listening = False
        return NS(token=b"synthetic-token", wait=wait)

    async def sign_in(self, password):
        if password != "synthetic-password":
            raise PasswordHashInvalidError(None)
        self.authorized_keys.add(session_key(self.session.save()))

    async def log_out(self):
        raise AssertionError("Import must never log out or revoke any authorization")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    DonorClient.instances = []
    DonorClient.authorized_keys = {session_key(DONOR)}
    DonorClient.active = set()
    DonorClient.password = DonorClient.migrate = DonorClient.frozen = DonorClient.restricted = False
    DonorClient.failure = None
    DonorClient.accepts = 0
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    vault.save("network", {"kind": "direct"})
    collector = Collector(store, vault, DonorClient)
    monkeypatch.setattr(client_initialization, "post_login", AsyncMock(return_value=[]))
    monkeypatch.setattr(client_checks, "inspect_connection", AsyncMock(return_value={"checks": []}))
    yield collector
    store.close()
    assert not DonorClient.active


async def connect(c, **kwargs):
    return await c.import_new_session(4, "a" * 32, DONOR, 44, PROFILE,
                                      formats=["Telethon SQLite", "Account JSON"], **kwargs)


def test_independent_authorization_and_provenance(workspace):
    async def scenario():
        c = workspace
        try:
            assert await connect(c) == {"step": "authorized"}
            saved = c.vault.read("credentials")
            assert session_key(saved["session"]) != session_key(DONOR)
            assert saved["session_origin"]["donor_api_id"] == 4
            assert saved["client_profile"]["lang_pack"] == "tdesktop"
            assert not c.vault.read("independent_login")
            donor = c.make_client(4, "a" * 32, DONOR, PROFILE)
            await donor.connect()
            assert await donor.is_user_authorized() and await c.client.is_user_authorized()
            await donor.disconnect()
            events = list(reversed(c.store.events()))
            verify_events(events, c.vault.public_key)
            event = next(e for e in events if e["kind"] == "account.authorized")
            assert event["payload"]["session_origin"]["method"] == "qr_from_import"
            assert DONOR not in json.dumps(events) and "synthetic-password" not in json.dumps(events)
        finally:
            await c.stop(shutdown=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["after_accept", "cancel"])
def test_resume_authorized_key_after_migration_and_interruption(workspace, failure):
    async def scenario():
        c = workspace
        DonorClient.migrate, DonorClient.failure = True, failure
        try:
            with pytest.raises(OSError if failure == "after_accept" else asyncio.CancelledError):
                await connect(c)
            pending = c.vault.read("independent_login")
            assert session_key(pending["session"]) == b"m" * 256
            assert not DonorClient.active
            await c.stop(shutdown=True)
            c = Collector(c.store, c.vault, DonorClient)
            DonorClient.failure = None
            assert await connect(c) == {"step": "authorized"}
            assert DonorClient.accepts == 1
            assert session_key(c.vault.read("credentials")["session"]) == b"m" * 256
        finally:
            await c.stop(shutdown=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("password,step", [("", "password"), ("wrong", "password"), ("synthetic-password", "authorized")])
def test_two_factor_prompt_imported_password_and_restart(workspace, password, step):
    async def scenario():
        c = workspace
        DonorClient.password = True
        try:
            result = await connect(c, password=password)
            assert result["step"] == step
            assert not next(x for x in DonorClient.instances if x.api_id == 4).connected
            if step == "password":
                pending = c.vault.read("independent_login")
                assert pending["password_required"]
                assert "synthetic-password" not in json.dumps(pending)
                await c.stop(shutdown=True)
                c = Collector(c.store, c.vault, DonorClient)
                assert await connect(c, password="synthetic-password") == {"step": "authorized"}
                assert DonorClient.accepts == 1
        finally:
            await c.stop(shutdown=True)
    asyncio.run(scenario())


def test_flood_no_retry_and_pending_workspace_ownership(workspace):
    async def scenario():
        c = workspace
        DonorClient.failure = "flood"
        try:
            with pytest.raises(FloodWaitError):
                await connect(c)
            assert DonorClient.accepts == 1 and not DonorClient.active
            app = NS(state=NS(store=c.store, vault=c.vault, collector=c))
            registry = Profiles(app, c.vault.root, None)
            assert registry.holder(44) and registry.holder(key=session_key(DONOR))
            assert registry.holder(key=session_key(c.vault.read("independent_login")["session"]))
            with pytest.raises(ValueError, match="already belongs"):
                registry.check_account(44, object())
            with pytest.raises(ValueError, match="original donor"):
                await c.import_new_session(4, "a" * 32, saved_session(b"z"), 44, PROFILE)
            assert DonorClient.accepts == 1
        finally:
            await c.stop(shutdown=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("flag", ["frozen", "restricted"])
def test_restricted_account_stops_before_creating_key(workspace, flag):
    async def scenario():
        c = workspace
        setattr(DonorClient, flag, True)
        try:
            with pytest.raises(ValueError, match=flag):
                await connect(c)
            assert DonorClient.accepts == 0 and len(DonorClient.instances) == 1
            assert not c.vault.read("independent_login")
        finally:
            await c.stop(shutdown=True)
    asyncio.run(scenario())


def test_json_two_factor_only_explicit_independent_mode():
    raw = json.dumps({"session_str": DONOR, "twoFA": "synthetic-password"}).encode()
    files = [{"name": "synthetic.json", "content": base64.b64encode(raw).decode()}]
    assert "two_factor_password" not in import_accounts(files)
    assert "two_factor_password" not in preview(files)
    assert import_accounts(files, include_password=True)["two_factor_password"] == "synthetic-password"


@pytest.mark.parametrize("mode", ["authorized", "password", "retry"])
@pytest.mark.parametrize("source", ["telethon", "pyrogram", "tdata"])
def test_profile_import_retains_workspace_for_password_or_lost_reply(workspace, monkeypatch, mode, source):
    from tools import check_session_reservations as checks
    monkeypatch.setattr(checks, "RecordingClient", DonorClient)

    async def scenario():
        DonorClient.password = mode == "password"
        DonorClient.failure = "after_accept" if mode == "retry" else None
        raw = json.dumps({"api_id": 4, "api_hash": "a" * 32,
                          "id": 44, **PROFILE}).encode()
        donor = tdata_fixture() if source == "tdata" else sqlite_fixture(source)
        body = {"files": [{"name": "synthetic.json", "content": base64.b64encode(raw).decode()},
                          {"name": "synthetic.zip" if source == "tdata" else "synthetic.session",
                           "content": base64.b64encode(donor).decode()}],
                "new_session": True, "label": "Independent test"}
        async with checks.workspace() as (app, client):
            response = await client.post("/api/profiles/import", json=body)
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["step"] == mode
            assert len(result["formats"]) == 2 and "Account JSON" in result["formats"]
            registry = app.state.profiles
            child = registry.entries[result["profile"]["id"]]["app"]
            assert child is not None
            checks.no_leases(registry)
            assert (await client.post("/api/profiles/import", json=body)).status_code == 409
            if mode != "authorized":
                pending = child.state.vault.read("independent_login")
                assert pending["account_id"] == 44
                if mode == "password":
                    assert await child.state.collector.confirm_password("synthetic-password") == {"step": "authorized"}
                else:
                    DonorClient.failure = None
                    assert await connect(child.state.collector) == {"step": "authorized"}
                assert DonorClient.accepts == 1
    asyncio.run(scenario())


def test_http_independent_login(workspace, monkeypatch):
    from tools import check_session_reservations as checks
    monkeypatch.setattr(checks, "RecordingClient", DonorClient)

    async def scenario():
        async with checks.workspace() as (app, client):
            response = await client.post("/api/auth/session/new", json={
                "api_id": 4, "api_hash": "a" * 32, "session": DONOR,
                "client_profile": PROFILE, "formats": ["Account JSON"]})
            assert response.status_code == 200, response.text
            assert response.json()["step"] == "authorized"
            assert app.state.vault.read("credentials")["session_origin"]["formats"] == ["Account JSON"]
    asyncio.run(scenario())


def test_invalid_donor_does_not_expire_saved_authorization(workspace, monkeypatch):
    from tools import check_session_reservations as checks
    monkeypatch.setattr(checks, "RecordingClient", DonorClient)

    async def scenario():
        async with checks.workspace() as (app, client):
            c = app.state.collector
            await c.configure(4, "a" * 32, DONOR, 44, PROFILE)
            saved = app.state.vault.read("credentials")
            monkeypatch.setattr(DonorClient, "is_user_authorized", AsyncMock(side_effect=AuthKeyUnregisteredError(None)))
            response = await client.post("/api/auth/session/new", json={
                "api_id": 4, "api_hash": "a" * 32, "session": saved_session(b"z"), "client_profile": PROFILE})
            assert response.status_code == 400
            assert app.state.vault.read("credentials") == saved
            assert not c.authorization_required and not c.store.get_setting("account_loss", None)
            assert not app.state.vault.read("independent_login")
    asyncio.run(scenario())


@pytest.mark.parametrize("password", [False, True])
def test_independent_login_browser(workspace, tmp_path, password):
    from playwright.sync_api import expect, sync_playwright
    from tools.check_browser import RunningApp, unlock, navigate_panel
    from tools.browser_helpers import launch_browser, check_layout
    DonorClient.password = password
    raw = json.dumps({"session_str": DONOR, "api_id": 4, "api_hash": "a" * 32,
                      "id": 44, **PROFILE, **({"twoFA": "wrong"} if password else {})}).encode()
    with RunningApp(tmp_path / "panel", client_factory=DonorClient) as server, sync_playwright() as p:
        browser = launch_browser(p)
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            unlock(page, server)
            navigate_panel(page, "connection")
            page.locator('[data-auth-method="files"]').click()
            expect(page.locator("#import-new-session")).not_to_be_checked()
            expect(page.locator("#session-import-warning")).to_contain_text("donor still connects briefly")
            page.locator("#import-new-session").check()
            page.locator("#session-file").set_input_files({"name": "synthetic.json", "mimeType": "application/json", "buffer": raw})
            expect(page.locator("#auth-continue")).to_be_enabled()
            page.locator("#auth-continue").click()
            if password:
                expect(page.locator("#password-form")).to_be_visible()
                page.locator("#password").fill("synthetic-password")
                page.locator('#password-form button[type="submit"]').click()
            expect(page.locator("#authorized-state")).to_be_visible(timeout=20000)
            expect(page.locator("#seen-by-list")).to_contain_text("Independent QR login approved by an imported session")
            assert DonorClient.accepts == 1
            assert session_key(server.app.state.vault.read("credentials")["session"]) != session_key(DONOR)
            page.set_viewport_size({"width": 390, "height": 844})
            check_layout(page)
            assert not errors
        finally:
            browser.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
