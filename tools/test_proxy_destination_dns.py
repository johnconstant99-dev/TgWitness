"""Public-only proxy destinations: routed DNS, pinning, TLS identity and thread isolation."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
import socks
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.util import Url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import alerts, netclient
from tgwitness.network import NetworkConfig

HOST, PUBLIC, PROXY = "notify.example", "9.9.9.9", "8.8.8.8"


@pytest.fixture(autouse=True)
def isolated_dns_cache(monkeypatch):
    monkeypatch.delenv(netclient.PRIVATE_OPT_IN, raising=False)
    netclient._dns_cache.clear()
    yield
    netclient._dns_cache.clear()


class Writer:
    def __init__(self, reader, answers):
        self.reader, self.answers, self.body = reader, answers, b""
        self.transport = SimpleNamespace(abort=lambda: None)
    def write(self, data):
        self.body += data
    async def drain(self):
        if self.reader.at_eof() or not self.body:
            return
        path = self.body.split(b" ", 2)[1].decode()
        query = parse_qs(urlsplit(path).query)
        assert set(query) == {"name", "type"} and query["name"] == [HOST]
        assert b"Authorization:" not in self.body
        family = query["type"][0]
        payload = json.dumps({"Status": 0, "Answer": [
            {"type": 1 if ":" not in address else 28, "TTL": 25, "data": address}
            for address in self.answers.get(family, [])]}).encode()
        self.reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode()
                              + b"\r\n\r\n" + payload)
        self.reader.feed_eof()
    def close(self):
        pass
    async def wait_closed(self):
        pass


@pytest.mark.parametrize("kind,tls", [("socks5", False), ("http", False), ("http", True)])
@pytest.mark.parametrize("private_answer", [None, "127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"])
def test_async_proxy_resolves_through_fixed_resolver_and_pins_all_answers(kind, tls, private_answer):
    network = NetworkConfig(kind=kind, host=PROXY, port=1080, tls=tls)
    answers = {"A": [PUBLIC], "AAAA": ["2620:fe::fe"]}
    if private_answer:
        answers["AAAA" if ":" in private_answer else "A"].append(private_answer)
    connected = []
    async def resolve(host, port):
        assert host == PROXY, "Destination hostname reached the local resolver"
        return [PROXY]
    async def connect(route, proxy, target, port, context, hostname, timeout):
        connected.append((route, proxy, target, hostname))
        assert route is network and proxy == PROXY
        if target == "1.1.1.1":
            reader = asyncio.StreamReader()
            return reader, Writer(reader, answers)
        return SimpleNamespace(), SimpleNamespace()
    async def run():
        with patch.object(netclient, "resolve", resolve), patch.object(netclient, "connect_proxy", connect):
            if private_answer:
                with pytest.raises(netclient.RouteError, match="inside this machine"):
                    await netclient.open_stream("https://" + HOST + "/secret?token=synthetic", network, 2)
            else:
                await netclient.open_stream("https://" + HOST + "/secret?token=synthetic", network, 2)
    asyncio.run(run())
    assert sum(target == "1.1.1.1" for _, _, target, _ in connected) == 2
    service = [row for row in connected if row[2] != "1.1.1.1"]
    assert not service if private_answer else service == [(network, PROXY, PUBLIC, HOST)]


def test_dns_failure_onion_and_private_opt_in_do_not_fall_back():
    network = NetworkConfig(kind="socks5", host=PROXY, port=1080)
    resolver = AsyncMock(side_effect=OSError("Synthetic resolver unreachable"))
    connect = AsyncMock(return_value=(None, None))
    async def run():
        with patch.object(netclient, "request", resolver), patch.object(netclient, "proxy_address", AsyncMock(return_value=PROXY)), \
                patch.object(netclient, "connect_proxy", connect), \
                patch.object(netclient, "connect_public", AsyncMock(side_effect=AssertionError("Direct fallback"))):
            with pytest.raises(netclient.RouteError, match="DNS could not be verified"):
                await netclient.open_stream("https://" + HOST, network, 1)
            assert not connect.await_count
            resolver.reset_mock()
            with pytest.raises(netclient.RouteError, match="Onion destinations require"):
                await netclient.open_stream("https://synthetic.onion", network, 1)
            assert not resolver.await_count and not connect.await_count
            with patch.dict(os.environ, {netclient.PRIVATE_OPT_IN: "1"}):
                await netclient.open_stream("https://synthetic.onion", network, 1)
            assert connect.call_args.args[2] == "synthetic.onion" and not resolver.await_count
    asyncio.run(run())


def test_async_proxy_retries_next_verified_address_after_proxy_error():
    network = NetworkConfig(kind="socks5", host=PROXY, port=1080)
    tried = []
    async def connect(route, proxy, target, *args):
        tried.append(target)
        if target == PUBLIC:
            raise netclient.ProxyError("Synthetic host unreachable", error_code=4)
        return "reader", "writer"
    async def run():
        with patch.object(netclient, "proxy_address", AsyncMock(return_value=PROXY)), \
                patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC, "1.0.0.1"])), \
                patch.object(netclient, "connect_proxy", connect):
            assert await netclient.open_stream("https://" + HOST, network, 2) == ("reader", "writer")
    asyncio.run(run())
    assert tried == [PUBLIC, "1.0.0.1"]


def test_dns_cache_is_short_bounded_and_route_specific(monkeypatch):
    async def reply(method, url, network, **kwargs):
        return 200, {}, json.dumps({"Status": 0, "Answer": [{"type": 1, "data": PUBLIC, "TTL": 600}]}).encode()
    now = [10.0]
    monkeypatch.setattr(netclient, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(netclient, "DNS_CACHE_LIMIT", 2)
    resolver = AsyncMock(side_effect=reply)
    first = NetworkConfig(kind="socks5", host=PROXY, port=1080)
    second = first.model_copy(update={"port": 1081})
    async def run():
        with patch.object(netclient, "request", resolver):
            await netclient.public_proxy_addresses(HOST, first, 2)
            await netclient.public_proxy_addresses(HOST, first, 2)
            assert resolver.await_count == 2
            await netclient.public_proxy_addresses(HOST, second, 2)
            assert resolver.await_count == 4
            now[0] += 31
            await netclient.public_proxy_addresses(HOST, first, 2)
            assert resolver.await_count == 6
            await netclient.public_proxy_addresses("another.example", first, 2)
            assert len(netclient._dns_cache) == 2
    asyncio.run(run())


@contextmanager
def guarded(kind="socks5"):
    network = NetworkConfig(kind=kind, host=PROXY, port=1080)
    alerts._install_guard()
    with alerts._routed(alerts.proxy_url(network, PROXY)):
        alerts._guard.get().update(on=True, network=network, pinned={PROXY: [PROXY]})
        yield network


class FakeSocket:
    def __init__(self, *args):
        self.sent, self.destination = [], None
    def settimeout(self, value):
        pass
    def setsockopt(self, *args):
        pass
    def set_proxy(self, *args):
        self.proxy = args
    def connect(self, destination):
        self.destination = destination
    def sendall(self, data):
        self.sent.append(bytes(data))
    def makefile(self, *args, **kwargs):
        return io.BytesIO(b"HTTP/1.1 200 Connection established\r\n\r\n")
    def close(self):
        pass


def test_notification_socks_pin_and_unrelated_thread_keep_original_destination():
    resolved = AsyncMock(return_value=[PUBLIC])
    def lookup(host, port, *args, **kwargs):
        assert host == PROXY, "Local DNS saw a notification destination"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PROXY, port))]
    def connect():
        return socks.create_connection((HOST, 443), proxy_type=socks.SOCKS5, proxy_addr=PROXY,
                                       proxy_port=1080, proxy_rdns=True)
    with patch.object(netclient, "public_proxy_addresses", resolved), patch.object(socks, "socksocket", FakeSocket), \
            patch.object(socket, "getaddrinfo", lookup), guarded():
        assert connect().destination == (PUBLIC, 443)
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(connect).result().destination == (HOST, 443)
    assert resolved.await_count == 1


def test_notification_connect_preserves_tls_identity_and_http_host():
    import urllib3.connection as connection
    sock, identities = FakeSocket(), []
    def wrap(**kwargs):
        identities.append(kwargs["server_hostname"])
        return sock, True
    conn = HTTPSConnection(PROXY, port=1080, proxy=Url(scheme="http", host=PROXY, port=1080))
    conn.set_tunnel(HOST, 443, headers={"Proxy-Authorization": "Basic synthetic"}, scheme="http")
    conn._new_conn = lambda: sock
    with patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC])), \
            patch.object(connection, "_ssl_wrap_socket_and_match_hostname", wrap), guarded("http"):
        conn.connect()
        assert identities == [HOST] and conn._tunnel_host == HOST
        assert b"CONNECT 9.9.9.9:443 " in sock.sent[0]
        assert b"Host: 9.9.9.9:443" in sock.sent[0]
        conn.request("POST", "/private-path?token=synthetic", body=b"synthetic payload", headers={"Host": HOST})
        assert b"Host: notify.example" in b"".join(sock.sent)


def test_notification_socks_preserves_tls_identity_with_numeric_target():
    import urllib3.connection as connection
    from urllib3.contrib.socks import SOCKSHTTPSConnection
    identities = []
    conn = SOCKSHTTPSConnection(host=HOST, port=443, _socks_options={"socks_version": socks.SOCKS5,
        "proxy_host": PROXY, "proxy_port": 1080, "username": None, "password": None, "rdns": True})
    def wrap(**kwargs):
        identities.append(kwargs["server_hostname"])
        return kwargs["sock"], True
    def lookup(host, port, *args, **kwargs):
        assert host == PROXY
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PROXY, port))]
    with patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC])), \
            patch.object(connection, "_ssl_wrap_socket_and_match_hostname", wrap), \
            patch.object(socks, "socksocket", FakeSocket), patch.object(socket, "getaddrinfo", lookup), guarded():
        conn.connect()
        assert conn.sock.destination == (PUBLIC, 443) and identities == [HOST]


def test_notification_socks_retries_unreachable_verified_address():
    tried = []
    class ReachableSocket(FakeSocket):
        def connect(self, destination):
            tried.append(destination[0])
            if destination[0] == PUBLIC:
                raise socks.ProxyError("Synthetic unreachable target")
            super().connect(destination)
    with patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC, "1.0.0.1"])), \
            patch.object(socks, "socksocket", ReachableSocket), patch.object(socket, "getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PROXY, 1080))]), guarded():
        result = socks.create_connection((HOST, 443), proxy_type=socks.SOCKS5, proxy_addr=PROXY, proxy_port=1080)
    assert tried == [PUBLIC, "1.0.0.1"] and result.destination == ("1.0.0.1", 443)


def test_notification_connect_retry_uses_new_socket_and_original_tls_identity():
    import urllib3.connection as connection
    sockets, identities = [], []
    class TunnelSocket(FakeSocket):
        def makefile(self, *args, **kwargs):
            status = b"502 Unreachable" if self is sockets[0] else b"200 Connected"
            return io.BytesIO(b"HTTP/1.1 " + status + b"\r\n\r\n")
    def new_socket():
        sock = TunnelSocket()
        sockets.append(sock)
        return sock
    def wrap(**kwargs):
        identities.append(kwargs["server_hostname"])
        assert kwargs["sock"] is sockets[1]
        return kwargs["sock"], True
    conn = HTTPSConnection(PROXY, port=1080, proxy=Url(scheme="http", host=PROXY, port=1080))
    conn.set_tunnel(HOST, 443, scheme="http")
    conn._new_conn = new_socket
    with patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC, "1.0.0.1"])), \
            patch.object(connection, "_ssl_wrap_socket_and_match_hostname", wrap), guarded("http"):
        conn.connect()
    assert len(sockets) == 2 and identities == [HOST]
    assert b"CONNECT 9.9.9.9:443 " in sockets[0].sent[0]
    assert b"CONNECT 1.0.0.1:443 " in sockets[1].sent[0]
    assert conn._tunnel_host == HOST and "_notification_target" not in conn.__dict__


def test_notification_http_proxy_pins_absolute_target_preserving_service_host_and_payload():
    sock = FakeSocket()
    conn = HTTPConnection(PROXY, port=1080)
    conn.sock = sock
    with patch.object(netclient, "public_proxy_addresses", AsyncMock(return_value=[PUBLIC])), guarded("http"):
        conn.request("POST", "http://" + HOST + ":8080/private?token=synthetic", body=b"synthetic body")
    sent = b"".join(sock.sent)
    assert b"POST http://9.9.9.9:8080/private?token=synthetic " in sent
    assert b"Host: notify.example:8080" in sent and sent.endswith(b"synthetic body")


def test_notification_rejects_private_dns_before_http_transport():
    import requests
    network = NetworkConfig(kind="socks5", host=PROXY, port=1080)
    with patch.object(socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PROXY, 1080))]), \
            patch.object(netclient, "public_proxy_addresses", AsyncMock(side_effect=netclient.RouteError("Synthetic private DNS"))), \
            patch.object(requests.adapters.HTTPAdapter, "send", side_effect=AssertionError("Private target reached transport")):
        result = alerts.deliver(["jsons://" + HOST + "/private"], "Synthetic title", "Synthetic body", network)
    assert result["sent"] == 0 and result["failed"] == 1 and "private DNS" in result["error"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
