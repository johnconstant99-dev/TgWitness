import asyncio
import ipaddress
import json

import pytest
from fastapi.testclient import TestClient

from tgwitness import proxy_catalog as catalogs
from tgwitness.app import create_app
from tgwitness.network import NetworkConfig
from test_collector import FakeClient


KEY = "a7" * 16
DATE = "2026-10-29T12:00:00+00:00"


def link(host="8.8.8.8", secret=KEY, port=443):
    return f"tg://proxy?server={host}&port={port}&secret={secret}"


def seed(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_PROXY_CATALOG", raising=False)
    monkeypatch.delenv("TGWITNESS_PROXY_FEED_PROXY", raising=False)
    path = tmp_path / "seed.json"
    snapshot = {"format": catalogs.FORMAT, "sources": [
        catalogs.source_data(source, link(host), DATE)
        for source, host in zip(catalogs.SOURCES, ("8.8.8.8", "1.1.1.1"))]}
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setattr(catalogs, "SEED", path)
    return catalogs.PublicCatalog(tmp_path)


def test_public_data_filters_duplicates_private_addresses_and_unsupported_protocols():
    values = [link(), link(secret="dd" + KEY), link("127.0.0.1"), link("10.3.4.5"), link("169.254.169.254"),
              link("192.0.2.1"), link("localhost"), link("app.local"), link("host.internal"), link("printer"),
              link(secret="ee" + KEY + "6578616d706c652e6f7267"), link("public.example.org"),
              "<script>alert(1)</script>", link(port=0), link() + "&secret=" + KEY, "# comment"]
    rows, skipped = catalogs.parse_feed("\ufeff" + "\n".join(values))
    assert [r["route"].host for r in rows] == ["8.8.8.8", "public.example.org"]
    assert skipped == 12
    assert KEY not in rows[0]["id"]
    rows, _ = catalogs.parse_feed("\n".join(link(port=p) for p in range(1, 500)))
    assert len(rows) == catalogs.MAX_PER_SOURCE


def test_packaged_seed_works_without_network_and_cache_corruption_falls_back(tmp_path, monkeypatch):
    monkeypatch.delenv("TGWITNESS_PROXY_CATALOG", raising=False)
    catalog = catalogs.PublicCatalog(tmp_path)
    bundled = catalog.public()
    assert bundled["mode"] == "bundled" and bundled["proxies"]
    assert len(bundled["sources"]) == len(catalogs.SOURCES)
    assert "secret" not in json.dumps(bundled)
    catalog.cache.write_text("broken private text", encoding="utf-8")
    assert catalog.public() == bundled
    catalog.cache.write_text(json.dumps({"format": catalogs.FORMAT, "sources": [{"id": "solispirit"}]}))
    assert catalog.public() == bundled


def test_refresh_partial_failure_and_no_compatible_result_keep_last_good_data(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    calls = []

    async def fetch(source, network):
        calls.append(source["id"])
        assert network.kind == "direct"
        if source["id"] == "zakky8":
            raise OSError("must not echo network details")
        return link("9.9.9.9")

    monkeypatch.setattr(catalogs, "download", fetch)
    first = asyncio.run(catalog.refresh())
    assert first["refresh"] == {"updated": ["solispirit"], "retained": ["zakky8"]}
    assert {p["host"] for p in first["proxies"]} == {"9.9.9.9", "1.1.1.1"}
    assert first["sources"][1]["fetched_at"] == DATE
    assert first["sources"][0]["fetched_at"] != DATE
    contents = catalog.cache.read_bytes()
    restarted = catalogs.PublicCatalog(tmp_path)
    assert restarted.public()["proxies"] == first["proxies"]

    async def incompatible(source, network):
        return link(secret="ee" + KEY + "6578616d706c652e6f7267")

    monkeypatch.setattr(catalogs, "download", incompatible)
    failed = asyncio.run(restarted.refresh())
    assert not failed["refresh"]["updated"] and len(failed["refresh"]["retained"]) == 2
    assert catalog.cache.read_bytes() == contents
    assert failed["proxies"] == first["proxies"]


def test_concurrent_refreshes_fetch_once_and_atomic_write_failure_preserves_cache(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    calls = []

    async def fetch(source, network):
        calls.append(source["id"])
        await asyncio.sleep(.01)
        return link("9.9.9.9")

    monkeypatch.setattr(catalogs, "download", fetch)

    async def refresh_twice():
        return await asyncio.gather(catalog.refresh(), catalog.refresh())

    results = asyncio.run(refresh_twice())
    assert len(calls) == 2 and results[1]["throttled"]
    contents = catalog.cache.read_bytes()
    restarted = catalogs.PublicCatalog(tmp_path)

    def failed_replace(*args):
        raise PermissionError("cache is read-only")

    monkeypatch.setattr(catalogs.os, "replace", failed_replace)
    with pytest.raises(PermissionError):
        asyncio.run(restarted.refresh())
    assert catalog.cache.read_bytes() == contents
    assert not list(tmp_path.glob(".public-proxies-*.tmp"))


@pytest.mark.parametrize("resolved", [("127.0.0.1",), ("8.8.8.8", "10.0.0.1"), ()])
def test_public_hostname_rejects_nonpublic_dns_answers(tmp_path, monkeypatch, resolved):
    catalog = seed(tmp_path, monkeypatch)
    snapshot = catalogs.read_snapshot(catalogs.SEED)
    snapshot["sources"][0] = catalogs.source_data(catalogs.SOURCES[0], link("public.example.org"), DATE)
    catalog.cache.write_text(json.dumps(snapshot))
    alias = catalog.public()["proxies"][0]["id"]

    async def run():
        async def resolve(*args, **kwargs):
            return [(2, 1, 6, "", (address, 443)) for address in resolved]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        with pytest.raises(ValueError, match="local or reserved"):
            await catalog.selected_route(alias)
    asyncio.run(run())


def test_public_hostname_pins_validated_ip_but_manual_operator_hosts_remain_allowed(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    snapshot = catalogs.read_snapshot(catalogs.SEED)
    snapshot["sources"][0] = catalogs.source_data(catalogs.SOURCES[0], link("public.example.org"), DATE)
    catalog.cache.write_text(json.dumps(snapshot))
    alias = catalog.public()["proxies"][0]["id"]

    async def run():
        async def resolve(*args, **kwargs):
            return [(2, 1, 6, "", ("8.8.8.8", 443))]
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
        route = await catalog.selected_route(alias)
        assert route.host == "8.8.8.8" and route.secret == KEY
    asyncio.run(run())
    override = tmp_path / "operator.json"
    override.write_text(json.dumps({"format": "tgwitness-proxy-catalog-v1", "proxies": [
        {"id": "own", "label": "Own private endpoint", "link": link("127.0.0.1") }]}))
    monkeypatch.setenv("TGWITNESS_PROXY_CATALOG", str(override))
    assert asyncio.run(catalog.selected_route("own")).host == "127.0.0.1"


def test_operator_override_disables_downloads_even_if_empty(tmp_path, monkeypatch):
    catalog = seed(tmp_path, monkeypatch)
    override = tmp_path / "operator.json"
    override.write_text(json.dumps({"format": "tgwitness-proxy-catalog-v1", "proxies": []}))
    monkeypatch.setenv("TGWITNESS_PROXY_CATALOG", str(override))

    async def unexpected(*args):
        pytest.fail("Operator catalog must not contact public subscriptions")
    monkeypatch.setattr(catalogs, "download", unexpected)
    result = asyncio.run(catalog.refresh())
    assert result["mode"] == "operator" and result["proxies"] == []


def test_fixed_https_downloads_are_bounded_and_use_only_the_download_route(monkeypatch):
    monkeypatch.setenv("TGWITNESS_PROXY_FEED_PROXY", "socks5://reader:p%40ss@127.0.0.1:1080")
    route = catalogs.feed_network()
    assert route.kind == "socks5" and route.password == "p@ss"

    async def request(method, url, network, **kwargs):
        assert method == "GET" and url == catalogs.SOURCES[0]["url"] and url.startswith("https://")
        assert network == route and kwargs == {"timeout": 8, "limit": catalogs.MAX_BYTES}
        return 200, {}, link().encode()
    monkeypatch.setattr(catalogs.netclient, "request", request)
    assert asyncio.run(catalogs.download(catalogs.SOURCES[0], route)) == link()
    monkeypatch.setenv("TGWITNESS_PROXY_FEED_PROXY", "tg://proxy?secret=private")
    with pytest.raises(ValueError) as exc:
        catalogs.feed_network()
    assert "private" not in str(exc.value)
    for value in ("http://proxy.example.org:0", "socks5://proxy.example.org:65536", "https://proxy.example.org"):
        monkeypatch.setenv("TGWITNESS_PROXY_FEED_PROXY", value)
        with pytest.raises(ValueError):
            catalogs.feed_network()


def test_catalog_api_refresh_is_authenticated_isolated_and_does_not_switch_route(tmp_path, monkeypatch):
    seed(tmp_path, monkeypatch)
    calls = []

    async def fetch(source, network):
        calls.append(source["id"])
        return link("9.9.9.9")
    monkeypatch.setattr(catalogs, "download", fetch)
    app = create_app(tmp_path / "data", client_factory=FakeClient)
    with TestClient(app) as client:
        assert client.post("/api/network/catalog/refresh", json={}).status_code == 401
        client.headers["Authorization"] = "Bearer " + app.state.vault.token
        before = app.state.collector.network_config()
        initial = client.get("/api/network/catalog").json()
        assert initial["mode"] == "bundled" and not calls
        refreshed = client.post("/api/network/catalog/refresh", json={})
        assert refreshed.status_code == 200 and len(calls) == 2
        assert app.state.collector.network_config() == before == NetworkConfig()
        assert KEY not in refreshed.text
        alias = refreshed.json()["proxies"][0]["id"]
        assert client.post("/api/network/catalog/" + alias, json={}).status_code == 200
        assert app.state.collector.network_config().host == "9.9.9.9"
        assert client.post("/api/network/test", json={}).json()["connected"]  # also before login
        assert not app.state.collector.status()["has_session"]
        child = client.post("/api/profiles", json={"label": "Other"}).json()["id"]
        other = client.get("/profiles/" + child + "/api/network/catalog").json()
        assert other["mode"] == "bundled"
        assert client.get("/profiles/" + child + "/api/status").json()["collector"]["network"]["kind"] == "direct"
        reader = client.post("/api/witness/tokens", json={"label": "Read only"}).json()["token"]
        assert client.post("/api/network/catalog/refresh", json={}, headers={"Authorization": "Bearer " + reader}).status_code == 401
    demo = create_app(tmp_path / "demo", demo=True)
    with TestClient(demo) as client:
        client.headers["Authorization"] = "Bearer " + demo.state.vault.token
        assert client.post("/api/network/catalog/refresh", json={}).status_code == 409
        assert len(calls) == 2


def test_feed_entry_ids_change_with_secret_and_never_depend_on_list_position():
    first = catalogs.parse_feed(link())[0][0]
    second = catalogs.parse_feed(link(secret="b9" * 16))[0][0]
    assert first["id"] != second["id"]
    assert catalogs.parse_feed(link("1.1.1.1") + "\n" + link())[0][1]["id"] == first["id"]
    assert ipaddress.ip_address(first["route"].host).is_global


@pytest.mark.parametrize("address", ["224.0.0.1", "ff02::1", "::1", "::ffff:127.0.0.1", "fe80::1%eth0"])
def test_multicast_and_scoped_addresses_are_not_public_proxy_destinations(address):
    assert not catalogs.public_host(address)
