import asyncio
import base64
import json
import socket
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tgwitness import netclient, proxy_catalog as catalogs
from tgwitness.app import create_app
from tgwitness.collector import Collector
from tgwitness.network import NetworkConfig, parse_mtproxy_link
from tgwitness.proxy_catalog import NoProxyAvailable, ProxyPool
from test_collector import FakeClient, saved_session


REAL_PROBE, REAL_RUN = catalogs.probe, ProxyPool.run
KEY = "a7" * 16


def row(host):
    route = NetworkConfig(kind="mtproxy", host=host, port=443, secret=KEY)
    return {"id": catalogs.route_id(route), "route": route, "label": "test list"}


class Listed:
    """A fixed catalog in place of the downloaded lists."""
    def __init__(self, *hosts):
        self.rows = [row(host) for host in hosts]
        self.refreshed, self.routes = 0, []

    def catalog(self):
        return {"mode": "bundled", "proxies": self.rows}

    async def refresh(self, network=None):
        self.refreshed += 1
        self.routes.append(network)


def pool_with(monkeypatch, hosts, dead):
    """A pool over these hosts; hosts in the (mutable) dead set fail the handshake."""
    async def handshake(route):
        if route.host in dead:
            raise ConnectionError("no answer")
        return 10 + int(route.host.rsplit(".", 1)[1])
    monkeypatch.setattr(ProxyPool, "probe", staticmethod(handshake))
    return ProxyPool(Listed(*hosts))


class Flaky(FakeClient):
    dead = set()

    async def connect(self):
        if self.options["proxy"][0] in self.dead:
            raise ConnectionError("proxy stopped answering")
        self.connected = True


def test_default_route_is_automatic_mtproxy_and_never_direct_or_http():
    config = NetworkConfig()
    assert config.kind == "mtproxy_auto" and config.telegram_only
    assert config.public()["fallback_to_direct"] is False and config.public()["port"] is None
    with pytest.raises(ValidationError):
        NetworkConfig(kind="mtproxy_auto", host="8.8.8.8")
    with pytest.raises(RuntimeError):
        config.client_options()
    with pytest.raises(netclient.RouteError):
        asyncio.run(netclient.request("GET", "https://example.org/", config))


def test_base64_secrets_and_json_feeds_are_read_like_hex_links():
    raw = bytes.fromhex(KEY)
    plain = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    padded = base64.urlsafe_b64encode(b"\xdd" + raw).decode().rstrip("=")
    tls = base64.urlsafe_b64encode(b"\xee" + raw + b"example.org").decode().rstrip("=")
    assert parse_mtproxy_link(f"tg://proxy?server=8.8.8.8&port=443&secret={plain}").secret == KEY
    assert parse_mtproxy_link(f"tg://proxy?server=8.8.8.8&port=443&secret={padded}").secret == "dd" + KEY
    with pytest.raises(ValueError):
        parse_mtproxy_link(f"tg://proxy?server=8.8.8.8&port=443&secret={tls}")
    source = next(s for s in catalogs.SOURCES if s.get("format") == "json")
    feed = json.dumps([{"query": {"server": "8.8.8.8", "port": "8443", "secret": plain, "name": "@list|\U0001F1E9\U0001F1EA"}},
                       {"query": {"server": "1.1.1.1", "port": "443", "secret": tls}}, "noise", {"link": "x"}])
    entry = catalogs.source_data(source, feed, "2026-10-30T00:00:00+00:00")
    assert entry["proxies"] == ["tg://proxy?server=8.8.8.8&port=8443&secret=" + KEY] and entry["skipped"] == 1
    with pytest.raises(ValueError):
        catalogs.source_data(source, "not json", "2026-10-30T00:00:00+00:00")


def test_workspaces_get_different_working_proxies_and_keep_them(monkeypatch):
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2", "8.8.8.3"], dead={"8.8.8.1"})

    async def run():
        first = await pool.acquire("a")
        second = await pool.acquire("b")
        assert first[1].host == "8.8.8.2" and second[1].host == "8.8.8.3"
        assert pool.resting(row("8.8.8.1")["id"], time.time())
        assert (await pool.acquire("a"))[0] == first[0]
        pool.release("a")
        assert (await pool.acquire("a", preferred=first[0]))[0] == first[0]
        third = await pool.acquire("c")
        assert third[0] == first[0]
    asyncio.run(run())


def test_no_working_proxy_raises_and_never_falls_back_to_direct(monkeypatch):
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], dead={"8.8.8.1", "8.8.8.2"})
    with pytest.raises(NoProxyAvailable):
        asyncio.run(pool.acquire("a"))
    assert pool.exhausted and pool.wakeup.is_set() and "a" not in pool.assigned


def test_failed_proxy_rests_and_the_account_moves_to_the_next_one(journal, monkeypatch):
    store, vault = journal
    dead = set()
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2", "8.8.8.3"], dead)

    async def run():
        collector = Collector(store, vault, Flaky)
        collector.proxy_pool = pool
        await collector.configure(123, "a" * 32, saved_session())
        first = collector.auto_route
        assert collector.client.options["proxy"][0] == first[1].host == "8.8.8.1"
        assert store.events(kind="network.route_assigned")[0]["payload"]["proxy_id"] == first[0]
        collector.running = True
        Flaky.dead = {first[1].host}
        await collector.client.disconnect()
        await collector.reconnect()
        assert collector.client.is_connected()
        moved = collector.auto_route
        assert moved[0] != first[0] and collector.client.options["proxy"][0] == moved[1].host
        assert pool.resting(first[0], time.time())
        rotated = store.events(kind="network.route_rotated")[0]["payload"]
        assert (rotated["from_proxy_id"], rotated["to_proxy_id"], rotated["reason"]) == (first[0], moved[0], "connect_failed")
        assert rotated["fallback_to_direct"] is False and store.get_setting("auto_route") == moved[0]

        for _ in range(3):
            await collector.note_drop()
        assert store.events(kind="network.route_rotated")[0]["payload"]["reason"] == "repeated_disconnect"
        assert collector.auto_route[0] not in (moved[0], first[0])
        await collector.stop()
    try:
        asyncio.run(run())
    finally:
        Flaky.dead = set()


def test_when_every_listed_proxy_fails_observation_waits_instead_of_connecting_directly(journal, monkeypatch):
    store, vault = journal
    dead = set()
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], dead)

    async def run():
        collector = Collector(store, vault, Flaky)
        collector.proxy_pool = pool
        await collector.configure(123, "a" * 32, saved_session())
        collector.running = True
        dead.update({"8.8.8.1", "8.8.8.2"})
        Flaky.dead = dead
        await collector.client.disconnect()
        await collector.reconnect()
        assert collector.running and not collector.client.is_connected() and collector.auto_route is None
        assert collector.client.options["proxy"]
        assert store.events(kind="connection.retry_failed")[0]["payload"]["error_type"] == "NoProxyAvailable"
        assert store.events(kind="network.route_unavailable")[0]["payload"]["fallback_to_direct"] is False

        dead.clear()
        for state in pool.health.values():
            state["cooldown_until"] = 0
        collector.next_reconnect_at = 0
        await collector.reconnect()
        assert collector.client.is_connected() and collector.client.options["proxy"][0] == collector.auto_route[1].host
        await collector.stop()
    try:
        asyncio.run(run())
    finally:
        Flaky.dead = set()


def test_garbage_from_a_listed_address_is_a_failed_route_not_a_lost_login(journal, monkeypatch):
    store, vault = journal
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], set())

    class Garbage(FakeClient):
        async def connect(self):
            if self.options["proxy"][0] == "8.8.8.1":
                raise ValueError("readexactly size can not be less than zero")
            self.connected = True

    async def run():
        collector = Collector(store, vault, Garbage)
        collector.proxy_pool = pool
        await collector.configure(123, "a" * 32, saved_session())
        assert collector.client.options["proxy"][0] == "8.8.8.2"
        assert store.events(kind="network.route_rotated")[0]["payload"]["error_type"] == "ValueError"

        await collector.set_network(NetworkConfig(kind="mtproxy", host="8.8.8.1", port=443, secret=KEY))
        collector.running = True
        await collector.reconnect()
        assert collector.running and collector.phase != "authorization_required"
        assert store.events(kind="connection.retry_failed")[0]["payload"]["error_type"] == "ConnectionError"
        await collector.stop()
    asyncio.run(run())


def test_background_upkeep_checks_the_list_and_downloads_it_while_in_use(monkeypatch):
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], dead={"8.8.8.2"})
    pool.health["removed-from-list"] = {"latency_ms": 5, "checked_at": time.time()}

    async def run():
        task = asyncio.create_task(REAL_RUN(pool))
        await asyncio.sleep(.05)
        assert pool.catalog.refreshed == 0 and not pool.probed_at
        pool.assigned["a"] = row("8.8.8.1")["id"]
        pool.wakeup.set()
        await asyncio.sleep(.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    asyncio.run(run())
    now, alive, broken = time.time(), row("8.8.8.1")["id"], row("8.8.8.2")["id"]
    assert pool.catalog.refreshed == 1 and pool.probed_at
    assert pool.healthy(alive, now) and pool.resting(broken, now) and "removed-from-list" not in pool.health
    assert pool.health[broken]["error_type"] == "ConnectionError"
    assert pool.degrade(broken, "TimeoutError") == 2 * catalogs.COOLDOWN_SECONDS


def test_handshake_check_fails_on_a_closed_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    route = NetworkConfig(kind="mtproxy", host="127.0.0.1", port=port, secret=KEY)
    with pytest.raises(OSError):
        asyncio.run(REAL_PROBE(route))


def test_profiles_share_one_pool_and_get_different_proxies(tmp_path, monkeypatch):
    hosts = ["8.8.8.1", "8.8.8.2"]
    listed = Listed(*hosts)
    monkeypatch.setattr(catalogs.PublicCatalog, "catalog", lambda self: listed.catalog())
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        child = client.post("/api/profiles", json={"label": "Second"}).json()["id"]
        for prefix, api_id in (("", 123), ("/profiles/" + child, 777)):
            assert client.post(prefix + "/api/auth/configure", json={
                "api_id": api_id, "api_hash": "a" * 32, "session": saved_session()}).status_code == 200
        main = client.get("/api/status").json()["collector"]["network"]
        second = client.get("/profiles/" + child + "/api/status").json()["collector"]["network"]
        assert main["kind"] == second["kind"] == "mtproxy_auto"
        assert {main["current"]["host"], second["current"]["host"]} == set(hosts)
        assert main["pool"]["listed"] == 2 and KEY not in json.dumps([main, second])
        assert KEY not in json.dumps(app.state.store.all_events())
        refused = client.post("/api/network", json={"kind": "direct"})
        assert refused.status_code == 400 and "tunnel" in refused.text
        assert client.post("/api/network/policy", json={"exposure": "tunnel", "outside_enabled": True}).status_code == 200
        assert client.post("/api/network", json={"kind": "direct"}).status_code == 200
        assert client.get("/api/status").json()["collector"]["network"]["kind"] == "direct"
        assert app.state.store.get_setting("auto_route") is None
