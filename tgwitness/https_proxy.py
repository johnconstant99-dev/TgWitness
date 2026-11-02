import asyncio
import base64
import ssl

from telethon.network.connection import ConnectionTcpFull


async def tunnel(route, host, port, timeout=15, address=None):
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(address or route.host, route.port,
                ssl=ssl.create_default_context(), server_hostname=route.tls_server_name or route.host, limit=16384)
            target = ("[" + host + "]" if ":" in host else host) + ":" + str(port)
            if any(c in target for c in "\r\n"):
                raise ValueError("Invalid CONNECT target")
            lines = ["CONNECT " + target + " HTTP/1.1", "Host: " + target]
            if route.username or route.password:
                token = base64.b64encode((route.username + ":" + route.password).encode()).decode()
                lines.append("Proxy-Authorization: Basic " + token)
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            await writer.drain()
            headers = await reader.readuntil(b"\r\n\r\n")
            status = headers.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                raise OSError("HTTPS proxy refused CONNECT")
            return reader, writer
    except BaseException:
        if writer:
            writer.close()
        raise


class HTTPSConnection(ConnectionTcpFull):
    async def _connect(self, timeout=None, ssl=None):
        from .network import NetworkConfig
        route = NetworkConfig.model_construct(**self._proxy)
        self._reader, self._writer = await tunnel(route, self._ip, self._port, timeout or 15)
        self._codec = self.packet_codec(self)
        self._init_conn()
        await self._writer.drain()
