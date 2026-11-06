import asyncio
import logging
from collections import defaultdict
from unittest.mock import AsyncMock, Mock

from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate, ConnectionTcpObfuscated
from telethon.sessions import MemorySession

from tgwitness import https_proxy
from tgwitness.network import NetworkConfig
from tgwitness.telegram_client import WitnessClient


def test_transport_choices_and_route_switches():
    async def scenario():
        client = WitnessClient(MemorySession(), 123, "a" * 32)
        client.disconnect = AsyncMock()
        routes = [NetworkConfig(kind="mtproxy", host="proxy.invalid", secret="a" * 32),
                  NetworkConfig(kind="direct"), NetworkConfig(kind="socks5", host="proxy.invalid"),
                  NetworkConfig(kind="http", host="proxy.invalid"),
                  NetworkConfig(kind="http", host="proxy.invalid", tls=True), NetworkConfig(kind="direct")]
        for route in routes:
            options = route.client_options()
            await client.switch_route(options)
            expected = (ConnectionTcpMTProxyRandomizedIntermediate if route.kind == "mtproxy" else
                        https_proxy.HTTPSConnection if route.tls else ConnectionTcpObfuscated)
            assert client._connection is expected
            assert bool(client._init_request.proxy) == (route.kind == "mtproxy")
            assert client._proxy == options.get("proxy")
            if route.kind in ("socks5", "http") and not route.tls:
                assert client._proxy["rdns"] is True
        await client.switch_route({})
        assert client._connection is ConnectionTcpObfuscated and client._proxy is None
    asyncio.run(scenario())


def test_https_connect_initializes_real_obfuscation(monkeypatch):
    async def scenario():
        writer = Mock()
        writer.drain = AsyncMock()
        reader = asyncio.StreamReader()
        tunnel = AsyncMock(return_value=(reader, writer))
        monkeypatch.setattr(https_proxy, "tunnel", tunnel)
        route = NetworkConfig(kind="http", host="proxy.invalid", port=443, tls=True)
        conn = https_proxy.HTTPSConnection("149.154.167.51", 443, 2,
            loggers=defaultdict(lambda: logging.getLogger("synthetic")), proxy=route.model_dump())
        await conn._connect(timeout=5)
        assert len(writer.write.call_args.args[0]) == 64
        conn._send(b"data")
        packet = writer.write.call_args.args[0]
        assert len(packet) == 5 and packet != b"\x01data"
        assert tunnel.await_args.args[1:3] == ("149.154.167.51", 443)
        assert writer.drain.await_count == 1
    asyncio.run(scenario())
