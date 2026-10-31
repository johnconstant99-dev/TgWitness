import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from telethon.network.connection import ConnectionTcpFull, ConnectionTcpMTProxyRandomizedIntermediate
from telethon.sessions import StringSession

from tgwitness import alerts, netclient
from tgwitness.app import create_app
from tgwitness.collector import Collector
from tgwitness.network import NetworkConfig, NoRoute, RoutePolicy
from tgwitness.proxy_catalog import NoProxyAvailable, ProxyPool
from tgwitness.telegram_client import WitnessClient
from test_collector import FakeClient, saved_session
from test_proxy_pool import KEY, REAL_RUN, Listed, pool_with, row

SOCKS = NetworkConfig(kind="socks5", host="127.0.0.1", port=1080)


class Routed(FakeClient):
    """Fails through dead proxies; connects directly when the route has no proxy."""
    dead = set()

    async def connect(self):
        proxy = self.options.get("proxy")
        if proxy and proxy[0] in self.dead:
            raise ConnectionError("proxy stopped answering")
        self.connected = True


@pytest.fixture
def routed():
    yield Routed
    Routed.dead = set()


async def connected(store, vault, pool, client=Routed):
    collector = Collector(store, vault, client)
    collector.proxy_pool = pool
    await collector.configure(123, "a" * 32, saved_session())
    return collector


def test_modes_default_to_hide_and_a_direct_route_needs_the_tunnel_mode(journal):
    store, vault = journal
    collector = Collector(store, vault, Routed)
    assert collector.route_policy() == {"exposure": "hide", "outside_enabled": True}
    with pytest.raises(ValueError, match="tunnel"):
        asyncio.run(collector.set_network(NetworkConfig(kind="direct")))
    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="fallback")))
    with pytest.raises(ValueError, match="tunnel"):
        asyncio.run(collector.set_network(NetworkConfig(kind="direct")))
    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="tunnel")))
    asyncio.run(collector.set_network(NetworkConfig(kind="direct")))
    with pytest.raises(ValueError, match="directly"):
        asyncio.run(collector.set_route_policy(RoutePolicy(exposure="hide")))
    record = store.events(kind="network.policy_changed")[0]["payload"]
    assert record["exposure"] == "tunnel" and "address" in record["meaning"]


def test_a_workspace_that_chose_direct_before_the_modes_keeps_it(journal):
    store, vault = journal
    vault.save("network", NetworkConfig(kind="direct").model_dump())
    collector = Collector(store, vault, Routed)
    assert collector.route_policy()["exposure"] == "tunnel"
    assert collector.outside_route().kind == "direct"


def test_requests_outside_telegram_follow_the_mode_and_their_own_proxy(journal):
    store, vault = journal
    collector = Collector(store, vault, Routed)
    hidden = collector.outside_route()
    assert hidden.kind == "none" and "Hide IP" in str(hidden.error)
    with pytest.raises(netclient.RouteError, match="Hide IP"):
        asyncio.run(netclient.request("GET", "https://example.org/", hidden))
    assert "Hide IP" in alerts.route_problem(["json://example.org/x"], hidden)
    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="hide"), SOCKS))
    assert collector.outside_route() == SOCKS
    state = collector.policy_state()
    assert state["outside_route"] == "socks5" and state["outside_proxy"]["host"] == "127.0.0.1"
    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="hide", outside_enabled=False)))
    assert "turned off" in str(collector.outside_route().error)
    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="fallback"), remove_outside=True))
    assert collector.outside_proxy() is None and collector.outside_route().kind == "direct"
    with pytest.raises(ValueError):
        asyncio.run(collector.set_route_policy(RoutePolicy(), NetworkConfig(kind="mtproxy", host="8.8.8.8",
                                                                             port=443, secret=KEY)))

    asyncio.run(collector.set_route_policy(RoutePolicy(exposure="hide")))
    asyncio.run(collector.set_network(SOCKS))
    assert collector.outside_route() == SOCKS


def test_hide_ip_waits_without_a_proxy_and_tunnel_connects_directly(journal, monkeypatch, routed):
    store, vault = journal
    pool = pool_with(monkeypatch, ["8.8.8.1"], dead={"8.8.8.1"})

    async def run():
        with pytest.raises(NoProxyAvailable):
            await connected(store, vault, pool)
        assert not store.events(kind="network.route_fallback")
        collector = Collector(store, vault, Routed)
        collector.proxy_pool = pool
        await collector.set_route_policy(RoutePolicy(exposure="tunnel"))
        await collector.configure(123, "a" * 32, saved_session())
        assert collector.client.is_connected() and "proxy" not in collector.client.options
        assert collector.direct_fallback and collector.client.route_id == "direct"
        fallback = store.events(kind="network.route_fallback")[0]["payload"]
        assert fallback["exposure"] == "tunnel" and fallback["fallback_to_direct"] is True
        status = collector.route_status()
        assert status["fallback_to_direct"] is True and status["exposure"] == "tunnel" and status["current"] is None
        assert collector.route_owner in pool.waiting
        await collector.stop()
    asyncio.run(run())


def test_fallback_mode_waits_the_set_minutes_then_connects_directly_and_returns(journal, monkeypatch, routed):
    store, vault = journal
    dead = {"8.8.8.1"}
    pool = pool_with(monkeypatch, ["8.8.8.1"], dead)
    store.set_setting("parameters", {"proxy_fallback_minutes": 5})

    async def run():
        collector = Collector(store, vault, Routed)
        collector.proxy_pool = pool
        await collector.set_route_policy(RoutePolicy(exposure="fallback"))
        with pytest.raises(NoProxyAvailable):
            await collector.configure(123, "a" * 32, saved_session())
        assert collector.unavailable_since and not collector.direct_fallback
        collector.unavailable_since -= 6 * 60
        for state in pool.health.values():
            state["cooldown_until"] = 0
        await collector.configure(123, "a" * 32, saved_session())
        assert collector.direct_fallback and collector.client.is_connected()
        assert store.events(kind="network.route_fallback")[0]["payload"]["without_proxy_seconds"] >= 360

        dead.clear()
        for state in pool.health.values():
            state["cooldown_until"] = 0
        await pool.probe_all()
        collector.running, collector.pool_retry_at = True, 0
        await collector.review_route()
        assert not collector.client.is_connected()
        await collector.reconnect()
        assert collector.client.is_connected() and not collector.direct_fallback
        assert collector.client.options["proxy"][0] == "8.8.8.1"
        assert store.events(kind="network.route_assigned")[0]["payload"]["returned_from_direct"] is True
        assert collector.route_owner not in pool.waiting
        await collector.stop()
    asyncio.run(run())


def test_switching_to_hide_ip_leaves_a_direct_fallback_at_once(journal, monkeypatch, routed):
    store, vault = journal
    pool = pool_with(monkeypatch, ["8.8.8.1"], dead={"8.8.8.1"})

    async def run():
        collector = Collector(store, vault, Routed)
        collector.proxy_pool = pool
        await collector.set_route_policy(RoutePolicy(exposure="tunnel"))
        await collector.configure(123, "a" * 32, saved_session())
        assert collector.direct_fallback
        await collector.set_route_policy(RoutePolicy(exposure="hide"))
        assert not collector.direct_fallback and not collector.client.is_connected()
        collector.running = True
        await collector.reconnect()
        assert not collector.client.is_connected()
        await collector.stop()
    asyncio.run(run())


def test_rotation_parameters_drops_cooldown_and_shared_proxies(journal, monkeypatch, routed):
    store, vault = journal
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], dead=set())
    store.set_setting("parameters", {"proxy_drop_limit": 1, "proxy_cooldown_minutes": 2, "proxy_max_accounts": 1})

    async def run():
        collector = await connected(store, vault, pool)
        first = collector.auto_route[0]
        collector.running = True
        await collector.note_drop()
        rotated = store.events(kind="network.route_rotated")[0]["payload"]
        assert rotated["reason"] == "repeated_disconnect" and rotated["previous_cooldown_seconds"] == 120
        assert collector.auto_route[0] != first

        assert pool.resting(first, time.time())
        with pytest.raises(NoProxyAvailable):
            await pool.acquire("another workspace", share=1)
        assert (await pool.acquire("another workspace", share=0))[0] == collector.auto_route[0]
        await collector.stop()
    asyncio.run(run())


def test_planned_switch_moves_to_another_working_proxy_or_stays(journal, monkeypatch, routed):
    store, vault = journal
    dead = set()
    pool = pool_with(monkeypatch, ["8.8.8.1", "8.8.8.2"], dead)
    store.set_setting("parameters", {"proxy_rotate_hours": 1})

    async def run():
        collector = await connected(store, vault, pool)
        first = collector.auto_route[0]
        await collector.review_route()
        assert collector.auto_route[0] == first
        store.set_setting("auto_route_since", time.time() - 2 * 3600)
        await collector.review_route()
        planned = store.events(kind="network.route_rotated")[0]["payload"]
        assert planned["reason"] == "planned" and planned["previous_cooldown_seconds"] == 0
        assert collector.auto_route[0] != first and not pool.resting(first, time.time())
        assert not collector.client.is_connected()
        second = collector.auto_route[0]
        dead.add("8.8.8.1")
        pool.health.clear()
        store.set_setting("auto_route_since", time.time() - 2 * 3600)
        await collector.review_route()
        assert collector.auto_route[0] == second and pool.assigned[collector.route_owner] == second
        assert time.time() - store.get_setting("auto_route_since") < 60
        await collector.stop()
    asyncio.run(run())


def test_list_downloads_use_the_main_workspace_route_and_intervals(tmp_path, monkeypatch):
    pool = ProxyPool(Listed("8.8.8.1"))
    pool.assigned["a"] = row("8.8.8.1")["id"]

    async def upkeep():
        pool.wakeup.set()
        task = asyncio.create_task(REAL_RUN(pool))
        await asyncio.sleep(.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    pool.outside = lambda: NoRoute(netclient.RouteError("Hide IP mode sends requests outside Telegram only through a proxy."))
    asyncio.run(upkeep())
    assert pool.catalog.refreshed == 0 and "Hide IP" in pool.lists_blocked
    assert pool.describe("a")["pool"]["lists_blocked"] == pool.lists_blocked
    pool.outside, pool.refreshed_at = (lambda: SOCKS), 0
    asyncio.run(upkeep())
    assert pool.catalog.routes == [SOCKS] and pool.lists_blocked is None
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        shared = app.state.collector.proxy_pool
        assert shared.intervals() == {"lists": 3600, "probe": 600}
        assert client.post("/api/parameters", json={"values": {"proxy_lists_minutes": 30,
                                                               "proxy_probe_minutes": 5}}).status_code == 200
        assert shared.intervals() == {"lists": 1800, "probe": 300}
        assert shared.outside().kind == "none"
        policy = client.post("/api/network/policy", json={"exposure": "hide", "outside_enabled": True,
                                                         "outside_proxy": SOCKS.model_dump()}).json()
        assert policy["outside_route"] == "socks5" and "password" not in str(policy)
        assert shared.outside() == SOCKS.model_copy(update={"local_proxy": True})
        assert client.get("/api/evidence").json()["route"] == "socks5"


def test_client_switches_between_mtproxy_and_direct_transports():
    secret = "dd" + KEY
    client = WitnessClient(StringSession(), 1, "a" * 32, connection=ConnectionTcpMTProxyRandomizedIntermediate,
                           proxy=("8.8.8.1", 443, secret))
    assert client._init_request.proxy is not None

    async def run():
        await client.switch_route({})
        assert client._connection is ConnectionTcpFull and client._proxy is None
        assert client._init_request.proxy is None
        await client.switch_route(NetworkConfig(kind="mtproxy", host="8.8.8.2", port=443, secret=KEY).client_options())
        assert client._connection is ConnectionTcpMTProxyRandomizedIntermediate
        assert client._proxy == ("8.8.8.2", 443, secret) and client._init_request.proxy.address == "8.8.8.2"
    asyncio.run(run())
