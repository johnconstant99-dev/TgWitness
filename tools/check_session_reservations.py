"""Concurrent workspace authentication checks with synthetic sessions and no Telegram traffic."""
import asyncio
from contextlib import asynccontextmanager
import base64
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.app import create_app
from tgwitness.proxy_catalog import ProxyPool
from tools.browser_fixtures import FakeClient, saved_session


async def idle(self):
    await asyncio.Event().wait()


async def pinned(route, operator=False):
    return route


async def probe(route):
    # Account ownership checks must not depend on a real MTProto handshake.
    return 40


class RecordingClient(FakeClient):
    connections = 0

    async def connect(self):
        type(self).connections += 1
        await super().connect()


@asynccontextmanager
async def workspace():
    with tempfile.TemporaryDirectory(prefix="session-reservations-") as scratch, \
            patch.object(ProxyPool, "run", idle), patch.object(ProxyPool, "pin", staticmethod(pinned)), \
            patch.object(ProxyPool, "probe", staticmethod(probe)):
        app = create_app(Path(scratch), client_factory=RecordingClient)
        async with app.router.lifespan_context(app):
            RecordingClient.connections = 0
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url="http://127.0.0.1",
                                        headers={"Authorization": "Bearer " + app.state.vault.token}) as client:
                yield app, client


def import_body(seed=b"i"):
    return {"files": [{"name": "synthetic.txt", "content": base64.b64encode(saved_session(seed).encode()).decode()}],
            "api_id": 123, "api_hash": "a" * 32, "label": "Synthetic import"}


def no_leases(registry):
    assert not registry.session_reservations
    assert not registry.account_reservations


async def rejected(call):
    try:
        await call
    except ValueError as error:
        assert "already" in str(error) or "being imported" in str(error), type(error).__name__
    else:
        raise AssertionError("A second workspace acquired an account or authorization key already held")


async def import_concurrency():
    async with workspace() as (app, client):
        registry = app.state.profiles
        create = registry.create
        entered, release = asyncio.Event(), asyncio.Event()

        async def held_create(*args):
            entered.set()
            await release.wait()
            return await create(*args)

        with patch.object(registry, "create", held_create):
            first = asyncio.create_task(client.post("/api/profiles/import", json=import_body()))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                second = await client.post("/api/profiles/import", json=import_body())
                assert second.status_code == 409, second.status_code
                assert len(registry.entries) == 1
                assert RecordingClient.connections == 0
            finally:
                release.set()
            result = await first
        assert result.status_code == 200, result.text
        assert len(registry.entries) == 2 and RecordingClient.connections == 1
        child = registry.entries[result.json()["profile"]["id"]]["app"]
        assert not child.state.collector.running and not child.state.collector.client.is_connected()
        no_leases(registry)
        again = await client.post("/api/profiles/import", json=import_body())
        assert again.status_code == 409 and RecordingClient.connections == 1


async def import_cleanup():
    async with workspace() as (app, client):
        registry = app.state.profiles
        entered = asyncio.Event()

        async def held_create(*args):
            entered.set()
            await asyncio.Event().wait()

        with patch.object(registry, "create", held_create):
            pending = asyncio.create_task(client.post("/api/profiles/import", json=import_body()))
            await asyncio.wait_for(entered.wait(), 5)
            pending.cancel()
            try:
                await pending
            except asyncio.CancelledError:
                pass
        no_leases(registry)
        assert len(registry.entries) == 1

        async def failed_create(*args):
            raise ValueError("Synthetic creation failure")

        with patch.object(registry, "create", failed_create):
            result = await client.post("/api/profiles/import", json=import_body())
            assert result.status_code == 400
        no_leases(registry)
        assert len(registry.entries) == 1
        result = await client.post("/api/profiles/import", json=import_body())
        assert result.status_code == 200, result.text
        no_leases(registry)


async def manual_key_concurrency(cancel=False):
    async with workspace() as (app, _):
        registry = app.state.profiles
        child_id = (await registry.create("Other account"))["id"]
        first, second = app.state.collector, registry.entries[child_id]["app"].state.collector
        entered, release = asyncio.Event(), asyncio.Event()
        original = first.ensure_route

        async def held_route():
            entered.set()
            await release.wait()
            await original()

        with patch.object(first, "ensure_route", held_route):
            pending = asyncio.create_task(first.configure(123, "a" * 32, saved_session(b"m")))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                await rejected(second.configure(123, "a" * 32, saved_session(b"m")))
                assert RecordingClient.connections == 0
                if cancel:
                    pending.cancel()
            finally:
                release.set()
            try:
                await pending
            except asyncio.CancelledError:
                assert cancel
        no_leases(registry)
        if cancel:
            await second.configure(123, "a" * 32, saved_session(b"m"))
        else:
            await rejected(second.configure(123, "a" * 32, saved_session(b"m")))
        assert RecordingClient.connections == 1
        no_leases(registry)


async def manual_account_concurrency(cancel=False):
    async with workspace() as (app, _):
        registry = app.state.profiles
        child_id = (await registry.create("Other account"))["id"]
        first, second = app.state.collector, registry.entries[child_id]["app"].state.collector
        entered, release = asyncio.Event(), asyncio.Event()
        original = first.avatar_history.close

        async def held_close():
            entered.set()
            await release.wait()
            await original()

        with patch.object(first.avatar_history, "close", held_close):
            pending = asyncio.create_task(first.configure(123, "a" * 32, saved_session(b"a")))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                await rejected(second.configure(123, "a" * 32, saved_session(b"b")))
                assert not second.store.get_setting("account", {})
                if cancel:
                    pending.cancel()
            finally:
                release.set()
            try:
                await pending
            except asyncio.CancelledError:
                assert cancel
        no_leases(registry)
        if cancel:
            await second.configure(123, "a" * 32, saved_session(b"b"))
            assert second.store.get_setting("account")["id"] == 44
        else:
            assert first.store.get_setting("account")["id"] == 44
        no_leases(registry)


async def capture_default_migration():
    from tgwitness.monitoring import capture_settings

    with tempfile.TemporaryDirectory(prefix="capture-default-migration-") as scratch, \
            patch.object(ProxyPool, "run", idle):
        root = Path(scratch)
        for stage in range(4):
            app = create_app(root, client_factory=RecordingClient)
            async with app.router.lifespan_context(app):
                store = app.state.store
                rules = capture_settings(store)["types"]
                if stage < 2:
                    assert [kind for kind, rule in rules.items() if not rule["enabled"]] == ["animation", "sticker"]
                else:
                    assert all(rule["enabled"] for rule in rules.values())
                if stage == 1:
                    # An older journal could have used its implicit all-enabled defaults without
                    # ever saving a capture setting. Model that exact persisted state for upgrade.
                    with store.transaction():
                        store.db.execute("DELETE FROM settings WHERE key='capture'")
                elif stage == 2:
                    store.set_setting("capture", {"download_media": True, "max_media_mb": 30})
                elif stage == 3:
                    assert {rule["max_mb"] for rule in rules.values()} == {30}


async def checks():
    for check in (import_concurrency, import_cleanup, manual_key_concurrency, manual_account_concurrency):
        await asyncio.wait_for(check(), 60)
    await asyncio.wait_for(manual_key_concurrency(cancel=True), 60)
    await asyncio.wait_for(manual_account_concurrency(cancel=True), 60)
    await asyncio.wait_for(capture_default_migration(), 60)


if __name__ == "__main__":
    asyncio.run(checks())
    print("Session reservations passed: concurrent imports, key and account ownership, cancellation and failure cleanup.")
