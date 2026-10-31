"""Public MTProxy lists: bundled seed, HTTPS refresh, a last-good cache and the automatic pool.

Remote lists supply data only. They cannot change feed URLs or the selected route.
Operator catalogs keep their existing, exclusive override semantics.
"""
import asyncio
from collections import Counter
from contextlib import suppress
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import tempfile
import time
from urllib.parse import unquote, urlencode, urlsplit

from telethon.network import MTProtoPlainSender
from telethon.tl.functions import ReqPqMultiRequest
from telethon.tl.types import ResPQ

from . import netclient
from .network import NetworkConfig, parse_mtproxy_link, proxy_catalog as operator_catalog


SOURCES = (
    {"id": "solispirit", "label": "SoliSpirit/mtproto",
     "url": "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
     "homepage": "https://github.com/SoliSpirit/mtproto"},
    {"id": "zakky8", "label": "zakky8/mtproto-proxy-pro",
     "url": "https://zakky8.github.io/mtproto-proxy-pro/all_proxies.txt",
     "homepage": "https://github.com/zakky8/mtproto-proxy-pro"},
    {"id": "kort0881", "label": "kort0881/telegram-proxy-collector",
     "url": "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/verified/proxy_all_verified.txt",
     "homepage": "https://github.com/kort0881/telegram-proxy-collector"},
    {"id": "mtp-collector", "label": "3yed-61/MTP-Collector",
     "url": "https://raw.githubusercontent.com/3yed-61/MTP-Collector/main/proxy/mtproto.json",
     "homepage": "https://github.com/3yed-61/MTP-Collector", "format": "json"},
    {"id": "therealwh", "label": "Therealwh/MTPproxyLIST",
     "url": "https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/main/verified/proxy_all_verified.txt",
     "homepage": "https://github.com/Therealwh/MTPproxyLIST"},
    {"id": "khodejav", "label": "KhodeJav/telegram-proxy-collector",
     "url": "https://raw.githubusercontent.com/KhodeJav/telegram-proxy-collector/main/output/proxies.txt",
     "homepage": "https://github.com/KhodeJav/telegram-proxy-collector"},
)
SOURCE_IDS = {source["id"] for source in SOURCES}
SEED = Path(__file__).with_name("public_proxies.json")
FORMAT = "tgwitness-public-proxies-v1"
MAX_BYTES = 1024 * 1024
MAX_PER_SOURCE = 400
REFRESH_SECONDS = 60


FEED_SECONDS = 3600
PROBE_SECONDS = 600
PROBE_TIMEOUT = 8
PROBE_PARALLEL = 16
PICK_BATCH = 8
PICK_LIMIT = 48
COOLDOWN_SECONDS = 600
COOLDOWN_MAX = 6 * 3600
PROBE_DC = (2, "149.154.167.51", 443)


class NoProxyAvailable(ConnectionError):
    """No listed proxy works now; only a workspace whose IP mode allows it then connects directly."""


class _Loggers(dict):
    def __missing__(self, key):
        return PROBE_LOG


PROBE_LOG = logging.getLogger("tgwitness.proxy_probe")
PROBE_LOG.addHandler(logging.NullHandler())
PROBE_LOG.propagate = False


def public_ip(address):
    value = ipaddress.ip_address(address)
    return value.is_global and not value.is_multicast and not value.is_reserved and "%" not in str(value)


def public_host(host):
    """Reject local addresses in external data; domains are also checked on selection."""
    try:
        return public_ip(host)
    except ValueError:
        return ("." in host and not host.endswith((".localhost", ".local", ".internal", ".lan",
                ".home", ".test", ".invalid", ".example", ".onion", ".i2p")))


def route_id(route):

    raw = f"{route.host.lower()}\0{route.port}\0{route.secret[-32:]}"
    return "public-" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def parse_feed(text):
    rows, seen, skipped = [], set(), 0
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        try:
            route = parse_mtproxy_link(line)
            if not public_host(route.host.lower()):
                raise ValueError
        except ValueError:
            skipped += 1
            continue
        route.host = route.host.lower()
        alias = route_id(route)
        if alias in seen:
            continue
        seen.add(alias)
        if len(rows) < MAX_PER_SOURCE:
            rows.append({"id": alias, "route": route})
    return rows, skipped


def feed_text(source, text):
    """Proxy links, one per line; a JSON feed lists the parts of each t.me link."""
    if source.get("format") != "json":
        return text
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("not a list")
    lines = []
    for item in data:
        query = item.get("query") if isinstance(item, dict) else None
        if isinstance(query, dict) and all(isinstance(query.get(k), (str, int)) for k in ("server", "port", "secret")):
            lines.append("tg://proxy?" + urlencode({k: query[k] for k in ("server", "port", "secret")}))
    return "\n".join(lines)


def source_data(source, text, now):
    rows, skipped = parse_feed(feed_text(source, text))
    return {"id": source["id"], "fetched_at": now, "skipped": skipped, "proxies": [
        "tg://proxy?" + urlencode({"server": row["route"].host, "port": row["route"].port,
                                   "secret": row["route"].secret}) for row in rows]}


def feed_network():
    """The proxy set for list downloads in the environment, or None."""
    value = os.environ.get("TGWITNESS_PROXY_FEED_PROXY", "").strip()
    if not value:
        return None
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ("http", "socks5", "socks5h") or not parts.hostname
                or parts.path not in ("", "/") or parts.query or parts.fragment):
            raise ValueError
        return NetworkConfig(kind="http" if parts.scheme == "http" else "socks5", host=parts.hostname,
                             port=parts.port if parts.port is not None else (80 if parts.scheme == "http" else 1080),
                             username=unquote(parts.username or ""), password=unquote(parts.password or ""))
    except ValueError:
        raise ValueError("Public-list downloads need a valid HTTP or SOCKS5 proxy setting.") from None


async def download(source, network):

    async with asyncio.timeout(20):
        _, _, body = await netclient.request("GET", source["url"], network, timeout=8, limit=MAX_BYTES)
    return body.decode("utf-8-sig")


def read_snapshot(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or data.get("format") != FORMAT
            or not isinstance(data.get("sources"), list) or not data["sources"]):
        raise ValueError
    seen = set()
    for entry in data["sources"]:
        if (not isinstance(entry, dict) or entry.get("id") not in SOURCE_IDS or entry["id"] in seen
                or not isinstance(entry.get("proxies"), list) or len(entry["proxies"]) > MAX_PER_SOURCE
                or not all(isinstance(link, str) and len(link) <= 2048 for link in entry["proxies"])
                or not isinstance(entry.get("skipped"), int) or entry["skipped"] < 0):
            raise ValueError
        datetime.fromisoformat(entry["fetched_at"]).astimezone(timezone.utc)
        rows, skipped = parse_feed("\n".join(entry["proxies"]))
        if not rows or skipped:
            raise ValueError
        seen.add(entry["id"])
    return data


class PublicCatalog:
    def __init__(self, root):
        self.cache = Path(root) / "public-proxies.json"
        self.lock = asyncio.Lock()
        self.last_attempt = 0.0
        self.last_result = None

    def snapshot(self):
        for path, mode in ((self.cache, "cache"), (SEED, "bundled")):
            try:
                return read_snapshot(path), mode
            except (OSError, ValueError, TypeError, KeyError):
                continue
        return {"format": FORMAT, "sources": []}, "bundled"

    def catalog(self):
        configured, entries = operator_catalog()
        if configured:
            return {"configured": True, "mode": "operator", "sources": [], "proxies": entries}
        snapshot, mode = self.snapshot()
        entries, seen, sources = [], set(), []
        saved = {row["id"]: row for row in snapshot["sources"]}
        for source in SOURCES:
            entry = saved.get(source["id"])
            rows, _ = parse_feed("\n".join(entry["proxies"])) if entry else ([], 0)
            sources.append({**source, "fetched_at": entry["fetched_at"] if entry else None,
                            "compatible": len(rows), "skipped": entry["skipped"] if entry else 0})
            for row in rows:
                if row["id"] not in seen:
                    seen.add(row["id"])
                    entries.append({**row, "label": source["label"], "source": source["id"]})
        return {"configured": bool(entries), "mode": mode, "sources": sources, "proxies": entries,
                "download_route": "proxy" if os.environ.get("TGWITNESS_PROXY_FEED_PROXY", "").strip() else "direct"}

    def public(self):
        catalog = self.catalog()
        return {**catalog, "proxies": [{"id": row["id"], "label": row["label"],
                "host": row["route"].host, "port": row["route"].port} for row in catalog["proxies"]]}

    async def refresh(self, network=None):
        """Download the lists through the environment's proxy, else the given route (direct by default)."""
        async with self.lock:
            if self.catalog()["mode"] == "operator":
                return self.public()
            loop = asyncio.get_running_loop()
            if self.last_attempt and loop.time() - self.last_attempt < REFRESH_SECONDS:
                return {**self.public(), "refresh": self.last_result, "throttled": True}
            network = feed_network() or network or NetworkConfig(kind="direct")
            if network.kind == "none":
                raise ValueError(str(network.error))
            self.last_attempt = loop.time()
            previous, _ = self.snapshot()
            saved = {entry["id"]: entry for entry in previous["sources"]}
            responses = await asyncio.gather(*(download(source, network) for source in SOURCES), return_exceptions=True)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            updated, failed = [], []
            for source, response in zip(SOURCES, responses):
                if isinstance(response, BaseException):
                    failed.append(source["id"])
                    continue
                try:
                    entry = source_data(source, response, now)
                except ValueError:
                    failed.append(source["id"])
                    continue
                if not entry["proxies"]:
                    failed.append(source["id"])
                    continue
                saved[source["id"]] = entry
                updated.append(source["id"])
            result = {"updated": updated, "retained": failed}
            if updated:
                self._save({"format": FORMAT, "sources": [saved[source["id"]] for source in SOURCES if source["id"] in saved]})
            self.last_result = result
            return {**self.public(), "refresh": result, "throttled": False}

    def _save(self, snapshot):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.cache.parent,
                                             prefix=".public-proxies-", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(snapshot, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.cache)
        finally:
            if temporary:
                with suppress(OSError):
                    temporary.unlink(missing_ok=True)

    async def selected_route(self, alias):
        catalog = self.catalog()
        row = next((row for row in catalog["proxies"] if row["id"] == alias), None)
        if row is None:
            raise ValueError("Unknown public proxy. Refresh the list.")
        return await pinned(row["route"], catalog["mode"] == "operator")


async def pinned(route, operator=False):
    """Pin a public IP so a downloaded hostname cannot rebind to a local service
    between validation and a later Telegram connection. Manual and operator routes are separate."""
    if operator:
        return route
    try:
        address = ipaddress.ip_address(route.host)
        addresses = [str(address)]
    except ValueError:
        try:
            answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
                route.host, route.port, type=socket.SOCK_STREAM), 8)
            addresses = [answer[4][0] for answer in answers]
        except (OSError, TimeoutError):
            raise ValueError("Public proxy address could not be resolved. Choose another server.") from None
    if not addresses or not all(public_ip(address) for address in addresses):
        raise ValueError("Public proxy lists cannot select a local or reserved address.")
    addresses.sort(key=lambda address: ipaddress.ip_address(address).version)
    return route.model_copy(update={"host": addresses[0]})


async def probe(route):
    """Milliseconds for an MTProto handshake (req_pq_multi) through the proxy to Telegram.

    The same obfuscated transport the client uses; no account, session or authorization key is involved.
    Telethon's MTProxy connect always waits 2 s for a refusal, so only the exchange itself is timed.
    """
    options = route.client_options()
    connection = options["connection"](PROBE_DC[1], PROBE_DC[2], PROBE_DC[0], loggers=_Loggers(),
                                       proxy=options["proxy"])
    try:
        await asyncio.wait_for(connection.connect(timeout=PROBE_TIMEOUT), PROBE_TIMEOUT + 3)
        nonce = int.from_bytes(os.urandom(16), "big", signed=True)
        started = time.monotonic()
        answer = await asyncio.wait_for(MTProtoPlainSender(connection, loggers=_Loggers()).send(
            ReqPqMultiRequest(nonce)), PROBE_TIMEOUT)
    finally:
        await connection.disconnect()
    if not isinstance(answer, ResPQ) or answer.nonce != nonce:
        raise ConnectionError("unexpected handshake answer")
    return max(1, round((time.monotonic() - started) * 1000))


class ProxyPool:
    """Automatic MTProxy routes shared by every workspace of one process.

    A workspace keeps its proxy while it works (Telegram distrusts accounts that hop between
    addresses); different workspaces get different proxies while enough work; a proxy that fails
    rests for a cooldown and the workspace moves to the next healthy one. The pool itself never
    connects directly; the workspace's IP mode decides whether a direct fallback is allowed.
    """


    pin = staticmethod(pinned)
    probe = staticmethod(probe)

    def __init__(self, catalog):
        self.catalog = catalog
        self.health = {}
        self.assigned = {}
        self.lock = asyncio.Lock()
        self.wakeup = asyncio.Event()
        self.probed_at = 0.0
        self.refreshed_at = 0.0
        self.exhausted = False

        self.intervals = lambda: {"lists": FEED_SECONDS, "probe": PROBE_SECONDS}
        self.outside = None
        self.lists_blocked = None
        self.waiting = set()

    def entries(self):
        catalog = self.catalog.catalog()
        return catalog["mode"] == "operator", {row["id"]: row for row in catalog["proxies"]}

    def resting(self, alias, now):
        return self.health.get(alias, {}).get("cooldown_until", 0) > now

    def healthy(self, alias, now):
        state = self.health.get(alias, {})
        return bool(state.get("latency_ms")) and now - state.get("checked_at", 0) < 2 * self.intervals()["probe"]

    def degrade(self, alias, error_type, first=COOLDOWN_SECONDS, longest=COOLDOWN_MAX):
        """Set a failed proxy aside; repeated failures rest longer."""
        state = self.health.setdefault(alias, {"failures": 0})
        state["failures"] = state.get("failures", 0) + 1
        cooldown = min(longest, first * 2 ** (state["failures"] - 1))
        state.update(latency_ms=None, checked_at=time.time(), cooldown_until=time.time() + cooldown,
                     error_type=error_type)
        return cooldown

    def succeeded(self, alias, latency_ms=None):
        state = self.health.setdefault(alias, {})
        state.update(failures=0, cooldown_until=0, error_type=None, checked_at=time.time(),
                     latency_ms=latency_ms or state.get("latency_ms") or 1)

    async def check(self, alias, row, operator, quick=False):
        """The pinned route after a successful handshake (quick: recently checked, only resolve), or None;
        a failed proxy then rests."""
        try:
            route = await self.pin(row["route"], operator)
            latency = None if quick else await self.probe(route)
        except Exception as exc:
            self.degrade(alias, type(exc).__name__)
            return None
        if not quick:
            self.succeeded(alias, latency)
        return route

    def order(self, owner, entries, avoid, now, share=0):
        """Candidates: least shared first, then measured latency, then list order; share caps the
        accounts on one proxy (0: no cap)."""
        load = Counter(v for k, v in self.assigned.items() if k != owner)
        position = {alias: number for number, alias in enumerate(entries)}
        usable = [a for a in entries if a not in avoid and not self.resting(a, now) and not (share and load[a] >= share)]
        return sorted(usable, key=lambda a: (load[a], not self.healthy(a, now),
                                             self.health.get(a, {}).get("latency_ms") or 0, position[a]))

    def available(self, owner, share=0):
        """Whether a checked proxy could serve this workspace now, without checking anything."""
        try:
            _, entries = self.entries()
        except ValueError:
            return False
        now = time.time()
        return any(self.healthy(a, now) for a in self.order(owner, list(entries), set(), now, share))

    async def acquire(self, owner, preferred=None, avoid=(), share=0):
        """(proxy id, pinned route) for a workspace; raises NoProxyAvailable."""
        async with self.lock:
            try:
                operator, entries = self.entries()
            except ValueError:
                raise NoProxyAvailable("The proxy catalog is unavailable.") from None
            now = time.time()
            current = self.assigned.get(owner) or preferred
            others = {v for k, v in self.assigned.items() if k != owner}

            if (current in entries and current not in avoid and not self.resting(current, now)
                    and current not in others):
                route = await self.check(current, entries[current], operator, quick=self.healthy(current, now))
                if route:
                    self.assigned[owner] = current
                    return current, route
            candidates = self.order(owner, list(entries), set(avoid), now, share)[:PICK_LIMIT]
            for alias in [a for a in candidates if self.healthy(a, now)][:PICK_BATCH]:
                route = await self.check(alias, entries[alias], operator, quick=True)
                if route:
                    self.assigned[owner] = alias
                    return alias, route
            untested = [a for a in candidates if not self.healthy(a, now)]
            for start in range(0, len(untested), PICK_BATCH):
                batch = untested[start:start + PICK_BATCH]
                routes = await asyncio.gather(*(self.check(a, entries[a], operator) for a in batch))
                found = sorted((self.health[a]["latency_ms"], number, a, r)
                               for number, (a, r) in enumerate(zip(batch, routes)) if r)
                if found:
                    _, _, alias, route = found[0]
                    self.assigned[owner] = alias
                    return alias, route
            self.assigned.pop(owner, None)
            self.exhausted = True
            self.wakeup.set()
            raise NoProxyAvailable("No listed MTProxy answered.")

    def release(self, owner):
        self.assigned.pop(owner, None)

    def keep(self, owner, alias):
        """Leave a workspace on its proxy after a planned switch found no other."""
        self.assigned[owner] = alias

    def describe(self, owner):
        alias = self.assigned.get(owner)
        try:
            _, entries = self.entries()
        except ValueError:
            entries = {}
        now = time.time()
        row, state = entries.get(alias), self.health.get(alias, {})
        current = {"id": alias, "host": row["route"].host, "port": row["route"].port, "source": row["label"],
                   "latency_ms": state.get("latency_ms"), "checked_at": state.get("checked_at")} if row else None
        return {"current": current, "pool": {
            "listed": len(entries), "healthy": sum(self.healthy(a, now) for a in entries),
            "resting": sum(self.resting(a, now) for a in entries),
            "probed_at": self.probed_at or None, "lists_refreshed_at": self.refreshed_at or None,
            "lists_blocked": self.lists_blocked}}

    async def probe_all(self):
        operator, entries = self.entries()
        now = time.time()
        gate = asyncio.Semaphore(PROBE_PARALLEL)

        async def one(alias):
            async with gate:
                await self.check(alias, entries[alias], operator)
        await asyncio.gather(*(one(a) for a in entries if not self.resting(a, now)))
        for alias in set(self.health) - set(entries):
            del self.health[alias]
        self.exhausted = False

    async def run(self):
        """Background upkeep while any workspace uses automatic routes: hourly lists, regular checks."""
        while True:
            with suppress(TimeoutError):
                await asyncio.wait_for(self.wakeup.wait(), 60)
            self.wakeup.clear()
            if not self.assigned and not self.exhausted and not self.waiting:
                continue
            now, intervals = time.time(), self.intervals()
            if now - self.refreshed_at >= intervals["lists"] or (self.exhausted and now - self.refreshed_at >= REFRESH_SECONDS * 10):
                self.refreshed_at = now
                route = self.outside() if self.outside else None

                self.lists_blocked = str(route.error) if route is not None and route.kind == "none" else None
                if not self.lists_blocked:
                    with suppress(Exception):
                        await self.catalog.refresh(route)
            if self.exhausted or now - self.probed_at >= intervals["probe"]:
                self.probed_at = now
                with suppress(Exception):
                    await self.probe_all()
