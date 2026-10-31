"""Audit findings L-1, M-2, M-3 and L-3: internal addresses inside IPv6 forms, proxies pointing inside the
network, notification services with their own sockets, and one AES-GCM nonce per plaintext in the copy."""
import asyncio
import io

import pytest

from tgwitness import alerts, netclient, replica
from tgwitness.collector import Collector
from tgwitness.network import NetworkConfig
from test_access import issue, login, panel  # noqa: F401  (panel is a fixture)
from test_collector import FakeClient


@pytest.fixture
def no_opt_in(monkeypatch):
    monkeypatch.delenv(netclient.PRIVATE_OPT_IN, raising=False)


@pytest.mark.parametrize("address, inside", [
    ("64:ff9b::7f00:1", True), ("64:ff9b::a9fe:a9fe", True), ("::127.0.0.1", True), ("2002:7f00:1::1", True),
    ("::ffff:10.0.0.5", True), ("64:ff9b::808:808", False), ("2002:808:808::1", False), ("8.8.8.8", False),
])
def test_internal_addresses_hidden_in_ipv6_forms(address, inside):
    assert netclient.internal(address) is inside


def test_delegated_access_cannot_point_a_proxy_or_raw_socket_inside(panel, no_opt_in):  # noqa: F811
    app, admin = panel
    token, _ = issue(admin, permissions=["account", "settings"])
    delegate, _ = login(app, token)
    local = {"kind": "socks5", "host": "127.0.0.1", "port": 9050}
    assert delegate.post("/api/network", json=local).status_code == 403
    assert delegate.post("/api/network/policy", json={"exposure": "hide", "outside_enabled": True,
                                                       "outside_proxy": {**local, "host": "10.0.0.5"}}).status_code == 403
    # A request cannot approve itself.
    assert delegate.post("/api/network", json={**local, "host": "8.8.8.8", "local_proxy": True}).status_code == 200
    assert app.state.collector.network_config().local_proxy is False
    assert admin.post("/api/network", json=local).status_code == 200  # a local Tor proxy, set by the administrator
    assert app.state.collector.network_config().local_proxy is True

    assert delegate.post("/api/alerts", json={"add_urls": ["rsyslog://10.0.0.5"]}).status_code == 403
    assert admin.post("/api/alerts", json={"add_urls": ["rsyslog://syslog.example.net"]}).status_code == 200
    assert delegate.post("/api/alerts", json={"daily": False}).status_code == 200  # keeps the administrator's destination
    assert delegate.post("/api/alerts", json={"add_urls": ["json://hooks.example.net/x"]}).status_code == 200


def test_proxy_inside_the_network_is_refused_at_connection_unless_approved(no_opt_in):
    route = NetworkConfig(kind="socks5", host="127.0.0.1", port=9)
    with pytest.raises(netclient.RouteError, match="main administrator"):
        asyncio.run(netclient.open_stream("https://example.org/", route, 5))
    with pytest.raises(OSError):  # approved: it is tried, and nothing listens on port 9
        asyncio.run(netclient.open_stream("https://example.org/", route.model_copy(update={"local_proxy": True}), 5))
    result = alerts.deliver(["json://hooks.example.net/x"], "t", "b", route)
    assert result["sent"] == 0 and "main administrator" in result["error"]


def test_telegram_connects_to_the_checked_proxy_address(journal, no_opt_in):
    store, vault = journal
    collector = Collector(store, vault, FakeClient)
    vault.save("network", {"kind": "socks5", "host": "localhost", "port": 9050, "local_proxy": False})
    with pytest.raises(ValueError, match="main administrator"):
        asyncio.run(collector.ensure_route())
    vault.save("network", {"kind": "socks5", "host": "localhost", "port": 9050})  # saved before the approval existed
    assert collector.network_config().local_proxy is True
    asyncio.run(collector.ensure_route())
    assert collector.route_options()["proxy"]["addr"] in ("127.0.0.1", "::1")


def test_a_file_changing_between_the_two_passes_is_never_encrypted_twice():
    versions = iter([b"a" * (replica.CHUNK + 10), b"a" * replica.CHUNK + b"b" * 10])
    sent = []

    class S3:
        async def put(self, name, body, length, sha, md5, extra):
            async for piece in body:
                sent.append(piece)
    with pytest.raises(replica.MediaUnavailable, match="changed while"):
        asyncio.run(replica.upload(S3(), b"k" * 32, "object", lambda: io.BytesIO(next(versions)), {}))
    # The header and the first chunk, identical to the first pass, went out; the changed chunk did not.
    assert len(sent) == 2
