"""The HTTP client bounds every read, including chunked bodies, before data arrives (audit A3)."""
import asyncio
from unittest.mock import patch

import pytest

from tgwitness import netclient
from tgwitness.network import NetworkConfig

SIZE = 256 * 1024


def serve_once(response):
    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(response)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


async def fetch(response, **options):
    """Request from a real loopback server; return (result or exception, largest read requested)."""
    requested = []
    original_exact, original_read = asyncio.StreamReader.readexactly, asyncio.StreamReader.read

    async def exact(self, n):
        requested.append(n)
        return await original_exact(self, n)

    async def read(self, n=-1):
        requested.append(n)
        return await original_read(self, n)

    server = await asyncio.start_server(serve_once(response), "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        with patch.object(asyncio.StreamReader, "readexactly", exact), patch.object(asyncio.StreamReader, "read", read):
            try:
                result = await netclient.request("GET", f"http://127.0.0.1:{port}/", NetworkConfig(), **options)
            except Exception as exc:  # returned for the assertions below
                result = exc
    return result, max(requested, default=0)


CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + f"{SIZE:x}\r\n".encode() + b"x" * SIZE + b"\r\n0\r\n\r\n"


@pytest.mark.parametrize("response", [
    CHUNKED,
    b"HTTP/1.1 200 OK\r\nContent-Length: " + str(SIZE).encode() + b"\r\n\r\n" + b"x" * SIZE,
    b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * SIZE,
], ids=["chunked", "content-length", "until-close"])
def test_oversized_response_is_refused_without_a_large_read(response):
    result, largest = asyncio.run(fetch(response, limit=16))
    assert isinstance(result, ValueError) and str(result) == "Response too large"
    assert largest <= 17


def test_streamed_download_arrives_whole_in_bounded_pieces():
    pieces = []

    async def sink(chunk):
        pieces.append(len(chunk))
    result, largest = asyncio.run(fetch(CHUNKED, limit=16, sink=sink))
    assert result[0] == 200 and sum(pieces) == SIZE
    assert largest <= netclient.PIECE


def test_small_chunked_response_and_broken_terminator():
    ok, _ = asyncio.run(fetch(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"))
    assert ok[2] == b"abcde"
    broken, _ = asyncio.run(fetch(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n"))
    assert isinstance(broken, ValueError) and "Malformed" in str(broken)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "172.17.0.2", "192.168.1.10", "169.254.169.254",
                                     "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_internal_addresses_include_metadata_services_and_private_networks(address):
    assert netclient.internal(address)


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_not_internal(address):
    assert not netclient.internal(address)


@pytest.mark.parametrize("url", ["http://127.0.0.1:9/", "http://169.254.169.254/hetzner/v1/userdata",
                                 "http://localhost:8787/api/status", "http://[::1]:9/", "http://2130706433/"])
def test_panel_requests_never_reach_this_machine_or_its_network(monkeypatch, url):
    monkeypatch.delenv(netclient.PRIVATE_OPT_IN, raising=False)
    # glibc resolves the one-number form 2130706433 to 127.0.0.1 (then refused); Windows does not resolve it.
    expected = (netclient.RouteError, OSError) if "2130706433" in url else netclient.RouteError
    with pytest.raises(expected) as caught:
        asyncio.run(netclient.request("GET", url, NetworkConfig(), timeout=5))
    assert "public internet" in str(caught.value) or "2130706433" in url


def test_through_a_proxy_an_internal_address_is_refused_before_connecting(monkeypatch):
    monkeypatch.delenv(netclient.PRIVATE_OPT_IN, raising=False)
    proxy = NetworkConfig(kind="socks5", host="203.0.113.9", port=1080)  # never routed: a connection would hang
    with pytest.raises(netclient.RouteError):
        asyncio.run(netclient.request("GET", "http://169.254.169.254/", proxy, timeout=5))


def test_the_server_environment_or_the_witness_may_allow_internal_addresses(monkeypatch):
    monkeypatch.delenv(netclient.PRIVATE_OPT_IN, raising=False)
    result, _ = asyncio.run(fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", private=True))
    assert result[2] == b"ok"
    monkeypatch.setenv(netclient.PRIVATE_OPT_IN, "1")
    result, _ = asyncio.run(fetch(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
    assert result[2] == b"ok"
