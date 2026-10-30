"""Minimal HTTP/1.1 client over the workspace route (direct, SOCKS5 or HTTP CONNECT).

Used for timestamp services and S3. It never falls back to a direct connection: MTProxy
carries only Telegram traffic, so other requests are refused on that route.

Addresses entered in the panel reach only the public internet: a request to this machine, its
network or a cloud metadata service (169.254.169.254) is refused, checked on the resolved address
that is then connected (no second lookup). Storage or services in the operator's own network are
allowed only by TGWITNESS_ALLOW_PRIVATE_DESTINATIONS=1 in the server's environment, which the
panel cannot set.
"""
import asyncio
import ipaddress
import os
import socket
import ssl
from contextlib import suppress
from urllib.parse import urlsplit

from python_socks import ProxyType
from python_socks.async_.asyncio import Proxy


PIECE = 64 * 1024  # largest single read from the peer
PRIVATE_OPT_IN = "TGWITNESS_ALLOW_PRIVATE_DESTINATIONS"


class RouteError(Exception):
    pass


class HTTPError(ValueError):
    def __init__(self, status, body=b""):
        super().__init__("HTTP " + str(status))
        self.status, self.body = status, body


def private_allowed():
    return os.environ.get(PRIVATE_OPT_IN, "").strip() == "1"


def internal(address):
    """Loopback, private, link-local (cloud metadata), shared, reserved and multicast addresses."""
    ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


def refuse_internal(host, addresses):
    blocked = [a for a in addresses if internal(a)]
    if blocked:
        raise RouteError(host + " resolves to " + str(blocked[0]) + ", inside this machine or its network. Panel "
                         "requests go only to public internet addresses; for storage or services in your own network "
                         "set " + PRIVATE_OPT_IN + "=1 on the server.")


def literal(host):
    """The host as an address, or None for a name. localhost names count as loopback."""
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return "127.0.0.1"
    with suppress(ValueError):
        return str(ipaddress.ip_address(host))
    return None


async def connect_public(host, port, tls, private):
    """Resolve once, check every address, then connect to those same addresses."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not private:
        refuse_internal(host, addresses)
    failure = OSError("No address for " + host)
    for address in addresses:
        try:
            return await asyncio.open_connection(address, port, ssl=tls, server_hostname=host if tls else None)
        except OSError as exc:
            failure = exc
    raise failure


async def open_stream(url, network, timeout, private=False):
    """private=True only for addresses an operator configured outside the panel (the witness's collector)."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    tls = ssl.create_default_context() if parts.scheme == "https" else None
    private = private or private_allowed()
    if network.kind == "direct":
        return await asyncio.wait_for(connect_public(host, port, tls, private), timeout)
    if network.kind == "mtproxy":
        raise RouteError("MTProxy carries only Telegram traffic; choose Direct, SOCKS5 or HTTP in "
                         "Connection settings for this request.")
    if not private and literal(host):
        refuse_internal(host, [literal(host)])  # names are resolved by the proxy, out of reach here
    proxy = Proxy(ProxyType.SOCKS5 if network.kind == "socks5" else ProxyType.HTTP, network.host,
                  network.port, network.username or None, network.password or None, rdns=True)
    sock = await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    return await asyncio.wait_for(
        asyncio.open_connection(sock=sock, ssl=tls, server_hostname=host if tls else None), timeout)


async def request(method, url, network, headers=None, body=b"", length=None, sink=None,
                  timeout=60, limit=1024 * 1024, private=False):
    """Send one request. body: bytes or an async iterator of bytes (then length is required).

    Returns (status, headers, data); with sink (an async callable) the body is streamed to it
    and data is b"". Non-2xx statuses raise HTTPError carrying the (bounded) response body.
    """
    parts = urlsplit(url)
    reader, writer = await open_stream(url, network, timeout, private)
    try:
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        size = len(body) if isinstance(body, (bytes, bytearray)) else length
        lines = [method + " " + path + " HTTP/1.1", "Host: " + parts.netloc, "User-Agent: TgWitness",
                 "Connection: close"]
        if size or method in ("PUT", "POST"):
            lines.append("Content-Length: " + str(size or 0))
        lines += [k + ": " + v for k, v in (headers or {}).items()]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        if isinstance(body, (bytes, bytearray)):
            writer.write(body)
        else:
            async for chunk in body:
                writer.write(chunk)
                await asyncio.wait_for(writer.drain(), timeout)
        await asyncio.wait_for(writer.drain(), timeout)
        head = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)).decode("latin-1").split("\r\n")
        status = int(head[0].split()[1])
        fields = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:] if h)}
        ok = 200 <= status < 300
        received, data = 0, b""
        # Only a successful response with a sink may exceed the limit; everything else is
        # bounded before it is read, and no single read asks for more than one piece.
        streaming = bool(sink and ok)

        def room(wanted):
            return min(wanted, PIECE) if streaming else min(wanted, PIECE, limit - received + 1)

        async def take(chunk):
            nonlocal received, data
            received += len(chunk)
            if sink and ok:
                await sink(chunk)
            elif received > limit:
                raise ValueError("Response too large")
            else:
                data += chunk

        if method == "HEAD" or status in (204, 304):
            pass
        elif fields.get("transfer-encoding", "").lower() == "chunked":
            while True:
                count = int((await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)).split(b";")[0], 16)
                if count < 0:
                    raise ValueError("Malformed chunked response")
                if count == 0:
                    break
                if not streaming and received + count > limit:
                    raise ValueError("Response too large")
                while count:
                    piece = await asyncio.wait_for(reader.readexactly(min(count, PIECE)), timeout)
                    count -= len(piece)
                    await take(piece)
                if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\r\n":
                    raise ValueError("Malformed chunked response")
        elif "content-length" in fields:
            remaining = int(fields["content-length"])
            if remaining < 0:
                raise ValueError("Malformed Content-Length")
            if not streaming and remaining > limit:
                raise ValueError("Response too large")
            while remaining:
                chunk = await asyncio.wait_for(reader.read(min(remaining, PIECE)), timeout)
                if not chunk:
                    raise ValueError("Connection closed early")
                remaining -= len(chunk)
                await take(chunk)
        else:
            while chunk := await asyncio.wait_for(reader.read(room(PIECE)), timeout):
                await take(chunk)
        if not ok:
            raise HTTPError(status, data[:2000])
        return status, fields, data
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
