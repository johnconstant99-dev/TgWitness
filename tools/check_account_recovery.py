"""Expired authorization is distinct from transport failure; synthetic Telegram clients only."""
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from telethon.errors import AuthKeyUnregisteredError, SessionRevokedError
from telethon import TelegramClient
from telethon.tl import functions

from tgwitness.app import create_app
from tgwitness.collector import AuthorizationRequired
from tgwitness.proxy_catalog import ProxyPool
from tgwitness.telegram_client import WitnessClient
from tools.browser_fixtures import CHAT, FakeClient, media_message, saved_session
from tools.check_session_reservations import idle, pinned, probe, workspace


async def rejects(awaitable, expected):
    try:
        await awaitable
    except expected:
        return
    raise AssertionError("Expected authorization or connection failure")


async def recovery():
    async with workspace() as (app, http):
        collector, store, vault = app.state.collector, app.state.store, app.state.vault
        await collector.configure(123, "a" * 32, saved_session())
        store.set_target(CHAT, "Synthetic source", "supergroup", True)
        credentials = vault.read("credentials")
        identity = vault.public_key
        head = store.stats()["head"]
        collector.client.authorized = False
        await rejects(collector.start(), AuthorizationRequired)
        status = (await http.get("/api/status")).json()
        assert status["collector"]["has_session"] and status["collector"]["authorization_required"]
        assert status["collector"]["phase"] == "authorization_required"
        assert status["health"]["connection"]["reason"] == "signed_out"

        # A rejected replacement cannot erase a known authorization failure or rebind the journal.
        await rejects(collector.configure(124, "a" * 32, saved_session(b"y")), ValueError)
        assert collector.authorization_required and collector.phase == "authorization_required"
        assert vault.read("credentials") == credentials and vault.public_key == identity
        assert store.get_setting("account")["id"] == 44
        assert store.db.execute("SELECT hash FROM events WHERE seq=?", (head["seq"],)).fetchone()[0] == head["hash"]
        assert store.targets(True)[0]["chat_id"] == CHAT

        # An unsuccessful new sign-in and changing its route must retain the known invalid state.
        with patch.object(FakeClient, "is_user_authorized", AsyncMock(return_value=False)):
            await rejects(collector.configure(123, "a" * 32, saved_session(b"z")), ValueError)
        assert collector.authorization_required
        await collector.connect_login(123, "a" * 32)
        await collector.cancel_login()
        assert collector.authorization_required

        # A validated same-account session is the point at which the warning may clear.
        await collector.configure(123, "a" * 32, saved_session(b"z"))
        assert not collector.authorization_required and collector.last_error is None
        assert collector.phase == "ready" and vault.public_key == identity

        for error in (AuthKeyUnregisteredError(None), SessionRevokedError(None)):
            with patch.object(collector.client, "is_user_authorized", AsyncMock(side_effect=error)):
                await rejects(collector.restore(), type(error))
            assert collector.authorization_required and collector.phase == "authorization_required"
            with patch.object(collector.client, "get_me", AsyncMock(side_effect=error)):
                await rejects(collector.restore(), type(error))
            assert collector.authorization_required, "Cached authorization cleared a known rejected session"
            await collector.restore()
            assert not collector.authorization_required and collector.last_error is None

        # Authorization can be rejected by a later RPC after the initial session check.
        with patch.object(collector, "prepare_start", AsyncMock(side_effect=SessionRevokedError(None))):
            await rejects(collector.start(), SessionRevokedError)
        assert collector.authorization_required and collector.phase == "authorization_required"
        await collector.restore()
        await collector.failure(AuthKeyUnregisteredError(None), "synthetic update")
        assert collector.authorization_required
        await collector.restore()

        with patch.object(collector.client, "is_user_authorized", AsyncMock(side_effect=TimeoutError)):
            await rejects(collector.restore(), TimeoutError)
        assert not collector.authorization_required, "Transport failure was mistaken for expired credentials"
        collector.next_reconnect_at = 0
        with patch.object(collector, "restore", AsyncMock(side_effect=ValueError("Invalid route"))):
            await collector.reconnect()
        assert not collector.authorization_required and collector.phase != "authorization_required"


class ExpiredClient(FakeClient):
    async def is_user_authorized(self):
        return False


class RevokedClient(FakeClient):
    async def is_user_authorized(self):
        raise SessionRevokedError(None)


class UnreachableClient(FakeClient):
    async def connect(self):
        raise TimeoutError()


async def restart():
    with tempfile.TemporaryDirectory(prefix="account-recovery-") as scratch, \
            patch.object(ProxyPool, "run", idle), patch.object(ProxyPool, "pin", staticmethod(pinned)), \
            patch.object(ProxyPool, "probe", staticmethod(probe)):
        root = Path(scratch)
        app = create_app(root, client_factory=FakeClient)
        async with app.router.lifespan_context(app):
            await app.state.collector.configure(123, "a" * 32, saved_session())
            app.state.store.set_target(CHAT, "Synthetic source", "supergroup", True)
            app.state.store.set_setting("resume", True)
            identity = app.state.vault.public_key
        for factory, required in ((ExpiredClient, True), (RevokedClient, True), (UnreachableClient, False)):
            app = create_app(root, client_factory=factory)
            async with app.router.lifespan_context(app):
                collector = app.state.collector
                for _ in range(100):
                    if collector.phase in ("authorization_required", "resume_failed"):
                        break
                    await asyncio.sleep(0.02)
                assert collector.phase == ("authorization_required" if required else "resume_failed")
                assert collector.authorization_required == required
                assert app.state.vault.public_key == identity
                assert app.state.store.get_setting("account")["id"] == 44


async def late_rpc_boundaries():
    for operation in ("dialogs", "recheck", "scope", "history", "media"):
        async with workspace() as (app, http):
            collector, store = app.state.collector, app.state.store
            await collector.configure(123, "a" * 32, saved_session())
            store.set_target(CHAT, "Synthetic source", "supergroup", True)
            identity, credentials = app.state.vault.public_key, app.state.vault.read("credentials")
            head = store.stats()["head"]
            collector.running, collector.phase = True, "observing"
            collector.watchdog = asyncio.create_task(asyncio.Event().wait())
            error = SessionRevokedError(None)
            if operation == "dialogs":
                async def rejected_dialogs(*args, **kwargs):
                    raise error
                    yield  # An async iterator: authorization was cached before enumeration.
                with patch.object(collector.client, "iter_dialogs", rejected_dialogs):
                    response = await http.get("/api/dialogs")
                    assert response.status_code == 400
            elif operation == "recheck":
                with patch.object(collector, "recheck_chat", AsyncMock(side_effect=error)):
                    collector.reconciler = asyncio.create_task(collector.recheck_pass())
                    await asyncio.wait_for(collector.reconciler, 3)
                assert collector.recheck_state["errors"] == 1
            elif operation == "scope":
                store.set_setting("scope", {"mode": "account"})
                collector.recheck_wakeup.set()
                with patch.object(collector, "apply_scope", AsyncMock(side_effect=error)):
                    collector.reconciler = asyncio.create_task(collector.recheck_loop())
                    await asyncio.wait_for(collector.reconciler, 3)
            elif operation == "history":
                with patch.object(collector.history, "read_page", AsyncMock(side_effect=error)):
                    await collector.history.start()
                    await asyncio.wait_for(collector.history.task, 3)
                history = collector.history.status()
                assert history["phase"] == "paused" and history["reason"] == "authorization_required"
                assert history["sources_by_phase"] == {"queued": 1}, "Revocation permanently failed resumable history"
            else:
                store.set_setting("capture", {"download_media": True})
                await collector.capture_message(media_message(), "message.new", CHAT)
                assert store.media_stats().get("queued") == 1
                with patch.object(collector.client, "download_media", AsyncMock(side_effect=error)):
                    collector.media_worker = asyncio.create_task(collector.download_worker())
                    await asyncio.wait_for(collector.media_worker, 3)
                assert store.media_stats().get("retry") == 1
                assert not store.media_stats().get("failed"), "Revocation discarded a retryable durable job"
            await asyncio.wait_for(collector.wait_authorization_cleanup(), 3)
            status = (await http.get("/api/status")).json()
            assert status["collector"]["authorization_required"]
            assert not status["collector"]["running"] and not status["collector"]["connected"]
            assert status["collector"]["phase"] == "authorization_required"
            assert status["health"]["connection"]["reason"] == "signed_out"
            assert collector.watchdog.done()
            assert app.state.vault.public_key == identity and app.state.vault.read("credentials") == credentials
            assert store.db.execute("SELECT hash FROM events WHERE seq=?", (head["seq"],)).fetchone()[0] == head["hash"]
            assert not store.events(kind="message.missing_on_recheck")
            assert len(store.events(kind="coverage.gap")) == 1


async def rpc_callback_and_concurrent_cleanup():
    async with workspace() as (app, _):
        collector = app.state.collector
        await collector.configure(123, "a" * 32, saved_session())
        collector.running, collector.phase = True, "observing"
        collector.client_factory = WitnessClient
        candidate = collector.make_client(123, "a" * 32, saved_session(b"z"))
        try:
            with patch.object(TelegramClient, "_call", AsyncMock(side_effect=SessionRevokedError(None))):
                await rejects(candidate._call(None, functions.help.GetConfigRequest()), SessionRevokedError)
                assert not collector.authorization_required and collector.running, "A rejected candidate tainted the saved session"
                collector.client = candidate
                collector.media_worker = asyncio.create_task(collector.supervise(
                    lambda: candidate._call(None, functions.help.GetConfigRequest()), "synthetic RPC worker"))
                await asyncio.wait_for(asyncio.gather(collector.media_worker, return_exceptions=True), 3)
                assert collector.authorization_required and not collector.running
            await asyncio.wait_for(collector.wait_authorization_cleanup(), 3)
            assert collector.media_worker.done()
            assert collector.phase == "authorization_required"
        finally:
            await candidate.disconnect()

    async with workspace() as (app, _):
        collector = app.state.collector
        await collector.configure(123, "a" * 32, saved_session())
        collector.running, collector.phase = True, "observing"
        gate = asyncio.Event()
        async def rejected_worker():
            await gate.wait()
            collector.handle_authorization_error(SessionRevokedError(None), "simultaneous worker")
            await asyncio.sleep(0)
        workers = [asyncio.create_task(rejected_worker()) for _ in range(2)]
        collector.reconciler, collector.media_worker = workers
        gate.set()
        await asyncio.wait_for(asyncio.gather(*workers, return_exceptions=True), 3)
        await asyncio.wait_for(collector.wait_authorization_cleanup(), 3)
        assert all(worker.done() for worker in workers)
        assert len(app.state.store.events(kind="coverage.gap")) == 1
        await collector.configure(123, "a" * 32, saved_session(b"y"))
        assert not collector.authorization_required and collector.client.is_connected()
        await asyncio.sleep(0)
        assert collector.client.is_connected(), "Old cleanup disconnected the newly authorized session"


async def delayed_cleanup_blocks_replacement():
    async with workspace() as (app, _):
        collector = app.state.collector
        await collector.configure(123, "a" * 32, saved_session())
        old = collector.client
        entered, release = asyncio.Event(), asyncio.Event()
        disconnect = old.disconnect
        async def delayed_disconnect():
            entered.set()
            await release.wait()
            await disconnect()
        with patch.object(old, "disconnect", delayed_disconnect):
            collector.handle_authorization_error(SessionRevokedError(None), "delayed cleanup", client=old)
            await asyncio.wait_for(entered.wait(), 3)
            replacement = asyncio.create_task(collector.configure(123, "a" * 32, saved_session(b"y")))
            try:
                await asyncio.sleep(0.02)
                assert not replacement.done(), "Replacement raced the previous connection's cleanup"
            finally:
                release.set()
            await asyncio.wait_for(replacement, 3)
        new = collector.client
        await collector.wait_authorization_cleanup()
        await asyncio.sleep(0)
        assert new is not old and new.is_connected() and not old.is_connected()
        assert not collector.authorization_required and collector.phase == "ready"


async def stale_rpc_cannot_invalidate_replacement():
    for operation in ("avatar identity", "avatar download", "restore"):
        async with workspace() as (app, _):
            collector = app.state.collector
            await collector.configure(123, "a" * 32, saved_session())
            old = collector.client
            collector.people.clear()
            entered, release = asyncio.Event(), asyncio.Event()
            async def delayed_rejection(*args, **kwargs):
                entered.set()
                await release.wait()
                raise SessionRevokedError(None)
            if operation == "avatar download":
                collector.people[44] = await old.get_me()
            method = {"avatar identity": "get_me", "avatar download": "download_profile_photo",
                      "restore": "is_user_authorized"}[operation]
            with patch.object(old, method, delayed_rejection, create=True):
                task = asyncio.create_task(collector.restore() if operation == "restore" else collector.avatar(44))
                try:
                    await asyncio.wait_for(entered.wait(), 3)
                    await collector.configure(123, "a" * 32, saved_session(b"z"))
                    new = collector.client
                    assert new is not old and not collector.authorization_required
                finally:
                    release.set()
                if operation == "restore":
                    await rejects(asyncio.wait_for(task, 3), SessionRevokedError)
                else:
                    assert await asyncio.wait_for(task, 3) is None
            await asyncio.wait_for(collector.wait_authorization_cleanup(), 3)
            assert not collector.authorization_required and collector.client is new and new.is_connected(), operation
            assert not app.state.store.events(kind="coverage.gap"), "A stale connection invalidated the replacement"


async def earlier_success_cannot_erase_new_rejection():
    async with workspace() as (app, _):
        collector = app.state.collector
        await collector.configure(123, "a" * 32, saved_session())
        client = collector.client
        collector.handle_authorization_error(SessionRevokedError(None), "first rejection", client=client)
        await collector.wait_authorization_cleanup()
        entered, release = asyncio.Event(), asyncio.Event()
        me = await client.get_me()
        async def delayed_success():
            entered.set()
            await release.wait()
            return me
        with patch.object(client, "get_me", delayed_success):
            restore = asyncio.create_task(collector.restore())
            try:
                await asyncio.wait_for(entered.wait(), 3)
                collector.handle_authorization_error(SessionRevokedError(None), "new rejection", client=client)
                await asyncio.wait_for(collector.wait_authorization_cleanup(), 3)
            finally:
                release.set()
            await rejects(asyncio.wait_for(restore, 3), AuthorizationRequired)
        assert collector.authorization_required and collector.phase == "authorization_required"
        assert not client.is_connected()
        # A subsequent fresh validation may recover; the stale in-flight success may not.
        await collector.restore()
        assert not collector.authorization_required and client.is_connected()


async def main():
    await asyncio.wait_for(recovery(), 60)
    await asyncio.wait_for(restart(), 60)
    await asyncio.wait_for(late_rpc_boundaries(), 60)
    await asyncio.wait_for(rpc_callback_and_concurrent_cleanup(), 60)
    await asyncio.wait_for(delayed_cleanup_blocks_replacement(), 60)
    await asyncio.wait_for(stale_rpc_cannot_invalidate_replacement(), 60)
    await asyncio.wait_for(earlier_success_cannot_erase_new_rejection(), 60)


if __name__ == "__main__":
    asyncio.run(main())
    print("Account recovery: expired/revoked authorization, late RPC boundaries, worker cleanup, durable media, restart and evidence retention PASS")
