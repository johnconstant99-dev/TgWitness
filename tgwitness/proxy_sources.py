"""Where the automatic MTProxy pool finds servers beyond the bundled public lists.

The operator switches bundled lists off, adds list URLs, uploads or pastes lists and may store a
GitHub token: downloads from GitHub then authenticate, and a periodic code search collects
published MTProxy lists. The token stays in the vault and is never returned. Countries come from a
public GeoIP service, asked through the same route as the list downloads and cached on disk.
"""
import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import netclient
from .security import private_write

SETTINGS = "proxy-sources.json"
GEO = "proxy-geo.json"
GITHUB_SEARCH_ID = "github-search"
GITHUB_HOSTS = {"github.com", "raw.githubusercontent.com", "api.github.com", "gist.githubusercontent.com",
                "objects.githubusercontent.com"}
TOKEN = re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})")
DEFAULT_QUERY = '"tg://proxy?server=" in:file'
GEO_URLS = ("https://api.country.is/{ip}", "https://ipwho.is/{ip}?fields=country_code")
GEO_DAYS = 30
GEO_BATCH = 150
GEO_RETRY_SECONDS = 6 * 3600
MAX_CUSTOM = 40
MAX_FILE_BYTES = 1024 * 1024


class CustomSource(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(default="", max_length=40)
    kind: Literal["url", "list"] = "url"
    label: str = Field(default="", max_length=80)
    url: str = Field(default="", max_length=500)
    format: Literal["text", "json"] = "text"
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def https(cls, value, info):
        if not value:
            return value
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError("Use an https:// address without credentials.")
        return value


class GitHubSearch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    enabled: bool = False
    query: str = Field(default=DEFAULT_QUERY, min_length=3, max_length=200)
    max_files: int = Field(default=20, ge=1, le=60)


class SourceSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disabled: list[str] = Field(default_factory=list, max_length=60)
    custom: list[CustomSource] = Field(default_factory=list, max_length=MAX_CUSTOM)
    github: GitHubSearch = Field(default_factory=GitHubSearch)
    countries: bool = True
    # Country choice of the automatic route: preferred servers first, avoided ones never.
    prefer: list[str] = Field(default_factory=list, max_length=60)
    avoid: list[str] = Field(default_factory=list, max_length=60)
    only_preferred: bool = False

    def country_rank(self, code):
        """0 preferred, 1 any other allowed country, None not to be used."""
        if code in self.avoid or (self.only_preferred and code not in self.prefer):
            return None
        return 0 if code in self.prefer else 1


def source_id(kind, text):
    return kind + "-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def load(root):
    try:
        return SourceSettings.model_validate_json((Path(root) / SETTINGS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return SourceSettings()


def save(root, settings):
    for item in settings.custom:
        if item.kind == "url" and not item.url:
            raise ValueError("A list address is required.")
        item.id = item.id or source_id(item.kind, item.url or item.label + str(time.time()))
        item.label = item.label or (urlsplit(item.url).netloc + urlsplit(item.url).path)[:80]
    ids = [item.id for item in settings.custom]
    if len(ids) != len(set(ids)):
        raise ValueError("The same list is added twice.")
    settings.prefer = list(dict.fromkeys(code.strip().upper() for code in settings.prefer))
    settings.avoid = list(dict.fromkeys(code.strip().upper() for code in settings.avoid))
    if not all(re.fullmatch(r"[A-Z]{2}", code) for code in settings.prefer + settings.avoid):
        raise ValueError("Use two-letter country codes such as DE or NL.")
    if set(settings.prefer) & set(settings.avoid):
        raise ValueError("A country cannot be preferred and avoided at once.")
    if settings.only_preferred and not settings.prefer:
        raise ValueError("Choose at least one preferred country to use only those.")
    if (settings.prefer or settings.avoid) and not settings.countries:
        raise ValueError("Country choices need country lookups. Switch on Look up server countries.")
    private_write(Path(root) / SETTINGS, settings.model_dump_json(indent=1).encode("utf-8"))
    return settings


def token_problem(value):
    return None if TOKEN.fullmatch(value or "") else "Use a GitHub token that starts with ghp_ or github_pat_."


def github_headers(url, token, raw=False):
    """Authorization only for GitHub's own hosts; a token never goes to another list's server."""
    if not token or urlsplit(url).scheme != "https" or (urlsplit(url).hostname or "").lower() not in GITHUB_HOSTS:
        return None
    headers = {"Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28"}
    if raw:
        headers["Accept"] = "application/vnd.github.raw"
    return headers


async def github_search(token, search, network, limit):
    """[(label, text)] of files that GitHub's code search finds for the query."""
    url = ("https://api.github.com/search/code?per_page=" + str(search.max_files) + "&q=" + quote(search.query))
    headers = {**github_headers(url, token), "Accept": "application/vnd.github+json"}
    async with asyncio.timeout(40):
        _, _, body = await netclient.request("GET", url, network, headers=headers, timeout=15, limit=limit)
    items = json.loads(body).get("items") or []
    found, gate = [], asyncio.Semaphore(4)

    async def fetch(item):
        contents = item.get("url") or ""
        if (urlsplit(contents).hostname or "") != "api.github.com":
            return
        async with gate:
            try:
                async with asyncio.timeout(20):
                    _, _, data = await netclient.request("GET", contents, network,
                                                         headers=github_headers(contents, token, raw=True),
                                                         timeout=10, limit=limit)
            except Exception:
                return
        repository = (item.get("repository") or {}).get("full_name") or "?"
        found.append((repository + "/" + str(item.get("path") or ""), data.decode("utf-8-sig", "replace")))
    await asyncio.gather(*(fetch(item) for item in items[:search.max_files]))
    return found


class Countries:
    """Country codes of proxy addresses, cached for GEO_DAYS; hostnames are resolved first."""
    def __init__(self, root):
        self.path = Path(root) / GEO
        self.lock = asyncio.Lock()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.cache = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.cache = {}

    def of(self, host):
        entry = self.cache.get(host)
        return entry.get("country") if isinstance(entry, dict) else None

    async def address(self, host):
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM), 6)
            return answers[0][4][0] if answers else None
        except (OSError, TimeoutError):
            return None

    async def lookup(self, ip, network):
        for template in GEO_URLS:
            try:
                async with asyncio.timeout(12):
                    _, _, body = await netclient.request("GET", template.format(ip=ip), network, timeout=8,
                                                         limit=64 * 1024)
                data = json.loads(body)
                code = data.get("country") or data.get("country_code")
                if isinstance(code, str) and re.fullmatch(r"[A-Z]{2}", code):
                    return code
            except Exception:
                continue
        return None

    async def locate(self, hosts, network):
        """Look up hosts without a fresh country; returns how many were found."""
        async with self.lock:
            now, found, gate = time.time(), 0, asyncio.Semaphore(6)
            # A host without an answer waits before its next lookup, so the next batch reaches other hosts
            def fresh(entry):
                return isinstance(entry, dict) and now - entry.get("at", 0) <= (
                    GEO_DAYS * 86400 if entry.get("country") else GEO_RETRY_SECONDS)
            stale = [h for h in dict.fromkeys(hosts) if not fresh(self.cache.get(h))]

            async def one(host):
                nonlocal found
                async with gate:
                    ip = await self.address(host)
                    code = await self.lookup(ip, network) if ip else None
                self.cache[host] = {"country": code, "at": now}
                found += bool(code)
            await asyncio.gather(*(one(h) for h in stale[:GEO_BATCH]))
            if stale:
                private_write(self.path, json.dumps(self.cache).encode("utf-8"))
            return found
