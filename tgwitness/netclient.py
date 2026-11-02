import asyncio
import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from collections import OrderedDict
from contextlib import suppress
from urllib.parse import urlencode, urlsplit

from python_socks import ProxyError, ProxyType
from python_socks.async_.asyncio import Proxy


PIECE = 64 * 1024
PRIVATE_OPT_IN = "TGWITNESS_ALLOW_PRIVATE_DESTINATIONS"
NAT64 = ipaddress.ip_network("64:ff9b::/96")
DOH_URL = "https://1.1.1.1/dns-query"
DNS_CACHE_LIMIT, DNS_CACHE_SECONDS = 128, 30
_dns_cache, _dns_lock = OrderedDict(), threading.Lock()


class RouteError(Exception):
    pass


class HTTPError(ValueError):
    def __init__(self, status, body=b""):
        super().__init__("HTTP " + str(status))
        self.status, self.body = status, body


def private_allowed():
    return os.environ.get(PRIVATE_OPT_IN, "").strip() == "1"


def internal(address):
    ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    if ip.version == 6:
        embedded = ip.ipv4_mapped or ip.sixtofour or (
            ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF) if ip in NAT64 else None)
        ip = embedded or ip
    return not ip.is_global or ip.is_multicast or ip.is_reserved


def refuse_internal(host, addresses):
    blocked = [a for a in addresses if internal(a)]
    if blocked:
        raise RouteError(host + " resolves to " + str(blocked[0]) + ", inside this machine or its network. Panel "
                         "requests go only to public internet addresses; for storage or services in your own network "
                         "set " + PRIVATE_OPT_IN + "=1 on the server.")


def literal(host):
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return "127.0.0.1"
    with suppress(ValueError):
        return str(ipaddress.ip_address(host))
    return None


async def resolve(host, port):
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def checked_proxy(network, addresses, private=False):
    blocked = [a for a in addresses if internal(a)]
    if blocked and not (private or private_allowed() or getattr(network, "local_proxy", False)):
        raise RouteError("The proxy " + network.host + " resolves to " + str(blocked[0]) + ", inside this machine "
                         "or its network. Only the main administrator can set such a proxy.")
    return addresses[0]


async def proxy_address(network, private=False):
    return checked_proxy(network, await resolve(network.host, network.port), private)


async def connect_public(host, port, tls, private):
    addresses = await resolve(host, port)
    if not private:
        refuse_internal(host, addresses)
    failure = OSError("No address for " + host)
    for address in addresses:
        try:
            return await asyncio.open_connection(address, port, ssl=tls, server_hostname=host if tls else None)
        except OSError as exc:
            failure = exc
    raise failure


async def public_proxy_addresses(host, network, timeout):
    if address := literal(host):
        refuse_internal(host, [address])
        return [address]
    name = host.rstrip(".").encode("idna").decode("ascii").lower()
    if name.endswith(".onion") or name == "onion":
        raise RouteError("Onion destinations require TGWITNESS_ALLOW_PRIVATE_DESTINATIONS=1 on the server; "
                         "public-only requests cannot verify their destination addresses.")
    if not name or len(name) > 253 or any(not label or len(label) > 63 or
            any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in label) for label in name.split(".")):
        raise RouteError("Invalid destination hostname.")
    route = tuple(getattr(network, key, None) for key in
                  ("kind", "host", "port", "username", "password", "tls", "tls_server_name", "local_proxy"))
    key = (route, name)
    with _dns_lock:
        cached = _dns_cache.get(key)
        if cached and cached[0] > time.monotonic():
            _dns_cache.move_to_end(key)
            return list(cached[1])
        _dns_cache.pop(key, None)

    async def query(kind):
        _, _, body = await request("GET", DOH_URL + "?" + urlencode({"name": name, "type": kind}), network,
            headers={"Accept": "application/dns-json"}, timeout=timeout, limit=64 * 1024)
        value = json.loads(body)
        if not isinstance(value, dict) or value.get("Status") != 0 or value.get("TC"):
            raise ValueError("DNS resolution failed")
        records = value.get("Answer", [])
        if not isinstance(records, list):
            raise ValueError("Invalid DNS response")
        addresses, ttl = [], DNS_CACHE_SECONDS
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid DNS answer")
            ttl = min(ttl, max(0, int(record.get("TTL", 0))))
            if record.get("type") in (1, 28):
                address = ipaddress.ip_address(record["data"])
                if address.version != (4 if record["type"] == 1 else 6):
                    raise ValueError("Invalid DNS address family")
                addresses.append(str(address))
        return addresses, ttl

    try:
        answers = await asyncio.wait_for(asyncio.gather(query("A"), query("AAAA"), return_exceptions=True), timeout)
        for answer in answers:
            if isinstance(answer, BaseException):
                raise answer
        addresses = list(dict.fromkeys(address for rows, _ in answers for address in rows))
        if not addresses:
            raise ValueError("No destination addresses")
        refuse_internal(host, addresses)
    except RouteError:
        raise
    except (OSError, ProxyError, ValueError, TimeoutError, KeyError, TypeError) as exc:
        raise RouteError("Public destination DNS could not be verified through the configured proxy. "
                         "No direct connection was attempted.") from exc
    ttl = min(ttl for _, ttl in answers)
    if ttl:
        with _dns_lock:
            _dns_cache[key] = (time.monotonic() + ttl, tuple(addresses))
            _dns_cache.move_to_end(key)
            while len(_dns_cache) > DNS_CACHE_LIMIT:
                _dns_cache.popitem(last=False)
    return addresses


async def connect_proxy(network, address, target, port, tls, host, timeout):
    if network.kind == "http" and network.tls:
        from .https_proxy import tunnel
        reader, writer = await tunnel(network, target, port, timeout, address)
        if tls:
            try:
                await asyncio.wait_for(writer.start_tls(tls, server_hostname=host), timeout)
            except BaseException:
                writer.close()
                raise
        return reader, writer
    proxy = Proxy(ProxyType.SOCKS5 if network.kind == "socks5" else ProxyType.HTTP, address,
                  network.port, network.username or None, network.password or None, rdns=True)
    sock = await proxy.connect(dest_host=target, dest_port=port, timeout=timeout)
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=tls, server_hostname=host if tls else None), timeout)
    except BaseException:
        sock.close()
        raise


async def open_stream(url, network, timeout, private=False):
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    tls = ssl.create_default_context() if parts.scheme == "https" else None
    private = private or private_allowed()
    if network.kind == "direct":
        return await asyncio.wait_for(connect_public(host, port, tls, private), timeout)
    if network.kind == "none":
        raise RouteError(str(network.error))
    if network.telegram_only:
        raise RouteError("MTProxy carries only Telegram traffic; choose Direct, SOCKS5 or HTTP in "
                         "Connection settings for this request.")
    address = await asyncio.wait_for(proxy_address(network, private), timeout)
    targets = [host] if private else await public_proxy_addresses(host, network, timeout)
    failure = OSError("No address for " + host)
    for target in targets:
        try:
            return await connect_proxy(network, address, target, port, tls, host, timeout)
        except (OSError, ProxyError) as exc:
            failure = exc
    raise failure


async def request(method, url, network, headers=None, body=b"", length=None, sink=None,
                  timeout=60, limit=1024 * 1024, private=False):
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
        closed = False
        try:
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), min(timeout, 2))
                closed = True
        finally:
            if not closed:
                writer.transport.abort()
