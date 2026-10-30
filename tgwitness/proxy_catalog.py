"""Public MTProxy lists: bundled seed, explicit HTTPS refresh and a last-good cache.

Remote lists supply data only. They cannot change feed URLs or the selected route.
Operator catalogs keep their existing, exclusive override semantics.
"""
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import tempfile
from urllib.parse import unquote, urlencode, urlsplit

from . import netclient
from .network import NetworkConfig, parse_mtproxy_link, proxy_catalog as operator_catalog


SOURCES = (
    {"id": "solispirit", "label": "SoliSpirit/mtproto",
     "url": "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
     "homepage": "https://github.com/SoliSpirit/mtproto"},
    {"id": "zakky8", "label": "zakky8/mtproto-proxy-pro",
     "url": "https://zakky8.github.io/mtproto-proxy-pro/all_proxies.txt",
     "homepage": "https://github.com/zakky8/mtproto-proxy-pro"},
)
SOURCE_IDS = {source["id"] for source in SOURCES}
SEED = Path(__file__).with_name("public_proxies.json")
FORMAT = "tgwitness-public-proxies-v1"
MAX_BYTES = 1024 * 1024
MAX_PER_SOURCE = 64
REFRESH_SECONDS = 60


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
    # Both accepted spellings use the same padded transport and the same key.
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


def source_data(source, text, now):
    rows, skipped = parse_feed(text)
    return {"id": source["id"], "fetched_at": now, "skipped": skipped, "proxies": [
        "tg://proxy?" + urlencode({"server": row["route"].host, "port": row["route"].port,
                                   "secret": row["route"].secret}) for row in rows]}


def feed_network():
    value = os.environ.get("TGWITNESS_PROXY_FEED_PROXY", "").strip()
    if not value:
        return NetworkConfig()
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
    # Fixed HTTPS endpoints, no redirects, cookies, Telegram credentials or panel token.
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

    async def refresh(self):
        async with self.lock:
            if self.catalog()["mode"] == "operator":
                return self.public()  # The local override disables external subscriptions.
            loop = asyncio.get_running_loop()
            if self.last_attempt and loop.time() - self.last_attempt < REFRESH_SECONDS:
                return {**self.public(), "refresh": self.last_result, "throttled": True}
            network = feed_network()
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
                entry = source_data(source, response, now)
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
        route = row["route"]
        if catalog["mode"] == "operator":
            return route
        # Pin a public IP so a downloaded hostname cannot rebind to a local service
        # between validation and a later Telegram connection. Manual routes are separate.
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
