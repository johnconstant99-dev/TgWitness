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
