from collections import OrderedDict, deque
import ipaddress
import math
import os
import time

from starlette.responses import JSONResponse


def networks(value):
    return tuple(ipaddress.ip_network(item.strip(), strict=False)
                 for item in value.split(",") if item.strip())


NAT64 = ipaddress.ip_network("64:ff9b::/96")


def unmapped(ip):
    return ip.ipv4_mapped or ip if ip.version == 6 else ip


def bucket(address):
    try:
        ip = unmapped(ipaddress.ip_address(address))
    except ValueError:
        return address
    if ip.version == 4:
        return str(ip)
    if ip in NAT64:
        return str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return str(ipaddress.ip_network((ip, 64), strict=False))


class RequestSecurity:
    def __init__(self, app, trusted=None, header=None, allowed=None, clock=time.monotonic):
        self.app, self.clock = app, clock
        self.trusted = networks(os.environ.get("TGWITNESS_TRUSTED_PROXIES", "") if trusted is None else trusted)
        self.allowed = networks(os.environ.get("TGWITNESS_PANEL_ALLOWED_IPS", "") if allowed is None else allowed)
        self.header = (header or os.environ.get("TGWITNESS_PROXY_HEADER", "x-forwarded-for")).lower().encode()
        if self.header not in (b"x-forwarded-for", b"cf-connecting-ip"):
            raise ValueError("Choose x-forwarded-for or cf-connecting-ip as the trusted proxy header.")
        self.clients = OrderedDict()

    def client(self, scope):
        peer = (scope.get("client") or ("unknown", 0))[0]
        try:
            address = unmapped(ipaddress.ip_address(peer))
        except ValueError:
            return peer
        if not any(address in net for net in self.trusted):
            return str(address)
        values = [v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == self.header]
        if not values:
            return str(address)
        if len(values) != 1 or len(values[0]) > 2048:
            raise ValueError('Invalid forwarded client address.')
        try:
            chain = [unmapped(ipaddress.ip_address(item.strip())) for item in values[0].split(",")]
        except ValueError:
            raise ValueError('Invalid forwarded client address.') from None
        if self.header == b"cf-connecting-ip":
            if len(chain) != 1:
                raise ValueError('Invalid forwarded client address.')
            return str(chain[0])
        for candidate in reversed(chain):
            if not any(address in net for net in self.trusted):
                break
            address = candidate
        return str(address)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("tgwitness.request_checked"):
            return await self.app(scope, receive, send)
        scope = dict(scope, **{"tgwitness.request_checked": True})
        try:
            address = self.client(scope)
        except ValueError:
            return await JSONResponse({"detail": "Invalid forwarded client address."}, status_code=400,
                                      headers={"Cache-Control": "no-store"})(scope, receive, send)
        scope["client"] = (address, (scope.get("client") or (None, 0))[1])
        if self.allowed and scope.get("path") != "/_tgwitness/ready":
            try:
                permitted = any(ipaddress.ip_address(address) in net for net in self.allowed)
            except ValueError:
                permitted = False
            if not permitted:
                return await JSONResponse({"detail": "This address is not allowed."}, status_code=403,
                                          headers={"Cache-Control": "no-store"})(scope, receive, send)
        if "/api/" not in scope.get("path", ""):
            return await self.app(scope, receive, send)
        now = self.clock()
        key = bucket(address)
        row = self.clients.get(key)
        if row is None:
            if len(self.clients) >= 4096:
                self.clients.popitem(last=False)
            row = self.clients[key] = {"requests": deque(), "failures": deque(), "until": 0,
                                       "strikes": 0, "last_failure": 0}
        self.clients.move_to_end(key)
        for name in ("requests", "failures"):
            while row[name] and row[name][0] <= now - 60:
                row[name].popleft()
        wait = max(0, row["until"] - now)
        if len(row["requests"]) >= 600:
            wait = max(wait, row["requests"][0] + 60 - now)
        if wait:
            return await JSONResponse({"detail": "Too many requests. Wait before trying again."}, status_code=429,
                                      headers={"Retry-After": str(max(1, math.ceil(wait))), "Cache-Control": "no-store"})(scope, receive, send)
        row["requests"].append(now)

        async def checked_send(message):
            if message["type"] == "http.response.start" and message["status"] == 401:
                failed_at = self.clock()
                if failed_at - row["last_failure"] >= 600:
                    row["strikes"] = 0
                row["last_failure"] = failed_at
                row["failures"].append(failed_at)
                if len(row["failures"]) >= 10 or row["strikes"]:
                    row["until"] = failed_at + min(300, 2 ** min(9, row["strikes"]))
                    row["strikes"] = min(10, row["strikes"] + 1)
            await send(message)
        await self.app(scope, receive, checked_send)
