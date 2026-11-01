"""Explicit per-account Telegram route; credentials never belong in journal events."""
import base64
import binascii
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import BaseModel, ConfigDict, Field, model_validator
from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate, tcpmtproxy, tcpobfuscated


class OpenSSLCTR:
    """AES-CTR of Telegram's obfuscated transports (MTProxy) through OpenSSL.

    Telethon's AESModeCTR is pure Python: it deciphers a few hundred KB/s per CPU core, so a busy
    MTProxy route held a whole core and the panel waited seconds for every answer. Same continuous
    keystream as Telethon's: encrypting and decrypting are one operation.
    """
    def __init__(self, key, iv):
        self._stream = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def encrypt(self, data):
        return self._stream.update(data)

    decrypt = encrypt


tcpmtproxy.AESModeCTR = tcpobfuscated.AESModeCTR = OpenSSLCTR


TELEGRAM_ONLY = ("mtproxy", "mtproxy_auto")


EXPOSURES = ("hide", "fallback", "tunnel")


class NoRoute:
    """No route for requests outside Telegram: netclient and notifications refuse them with this error."""
    kind, telegram_only = "none", True

    def __init__(self, error):
        self.error = error


class RoutePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exposure: Literal[EXPOSURES] = "hide"
    outside_enabled: bool = True


def hex_secret(value):
    """Telegram links carry an MTProxy key as hex or as base64url; keep the hex form."""
    if re.fullmatch(r"(?:[a-fA-F0-9]{2})+", value):
        return value.lower()
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{22,}={0,2}", value):
        return value
    try:
        return base64.urlsafe_b64decode(value.replace("+", "-").replace("/", "_").rstrip("=") +
                                        "=" * (-len(value.rstrip("=")) % 4)).hex()
    except (binascii.Error, ValueError):
        return value


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


    kind: Literal["direct", "socks5", "http", "mtproxy", "mtproxy_auto"] = "mtproxy_auto"
    host: str = Field(default="", max_length=253)
    port: int = Field(default=1080, ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=255)
    secret: str = Field(default="", max_length=512)


    local_proxy: bool = False

    @model_validator(mode="after")
    def check_route(self):
        if self.kind == "direct":
            if any((self.host, self.username, self.password, self.secret)):
                raise ValueError("Direct mode must not include proxy credentials.")
            return self
        if self.kind == "mtproxy_auto":
            if any((self.host, self.username, self.password, self.secret)):
                raise ValueError("Automatic MTProxy mode chooses its own proxies; leave the proxy fields empty.")
            return self
        self.host = self.host.strip()
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if not self.host or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", p)
                                        for p in self.host.split(".")):
                raise ValueError("Enter a host name or IP address without a URL, path or credentials.")
        if self.kind == "mtproxy":
            self.secret = hex_secret(self.secret.strip())
            if self.username or self.password:
                raise ValueError("MTProxy uses a secret, not a username/password.")
            if not re.fullmatch(r"(?:dd)?[a-fA-F0-9]{32}", self.secret):
                raise ValueError("Use a 32-digit hex secret or dd plus 32 digits. Fake TLS ee secrets are unsupported.")
        elif self.secret:
            raise ValueError("SOCKS5/HTTP do not use an MTProxy secret.")
        return self

    @property
    def telegram_only(self):
        return self.kind in TELEGRAM_ONLY

    def public(self, fallback=False):
        return {"kind": self.kind, "host": self.host,
                "port": self.port if self.kind not in ("direct", "mtproxy_auto") else None,
                "has_credentials": bool(self.username or self.password or self.secret),
                "fallback_to_direct": fallback, "scope": "Telegram client traffic only"}

    def receipt(self, fallback=False):
        return {"kind": self.kind, "has_credentials": bool(self.username or self.password or self.secret),
                "fallback_to_direct": fallback}

    def client_options(self):
        if self.kind == "mtproxy_auto":
            raise RuntimeError("An automatic route is resolved to one proxy by the collector.")
        if self.kind == "direct":
            return {}
        if self.kind == "mtproxy":


            secret = self.secret if len(self.secret) == 34 else "dd" + self.secret
            return {"connection": ConnectionTcpMTProxyRandomizedIntermediate,
                    "proxy": (self.host, self.port, secret)}
        return {"proxy": {"proxy_type": self.kind, "addr": self.host, "port": self.port,
                          "rdns": True, "username": self.username or None, "password": self.password or None}}


def saved_route(raw):
    """A route read back from the vault."""
    if raw and raw.get("host") and "local_proxy" not in raw:
        raw = {**raw, "local_proxy": True}
    return NetworkConfig.model_validate(raw)


def parse_mtproxy_link(link):
    """Parse Telegram's proxy links without opening them or changing the saved route."""
    message = "Use a tg://proxy or https://t.me/proxy link with server, port and secret."
    if not isinstance(link, str) or len(link) > 2048:
        raise ValueError(message)
    try:
        parts = urlsplit(link.strip())
        valid = ((parts.scheme == "tg" and parts.netloc == "proxy" and parts.path in ("", "/")) or
                 (parts.scheme == "https" and parts.netloc in ("t.me", "telegram.me") and parts.path == "/proxy"))
        fields = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=3)
        if not valid or parts.fragment or set(fields) != {"server", "port", "secret"} or any(len(v) != 1 for v in fields.values()):
            raise ValueError(message)
        port = fields["port"][0]
        if not re.fullmatch(r"[0-9]{1,5}", port):
            raise ValueError(message)

        return NetworkConfig(kind="mtproxy", host=fields["server"][0], port=int(port), secret=fields["secret"][0])
    except (TypeError, ValueError):
        raise ValueError("Invalid MTProxy link. Use a valid host, port 1-65535 and a 32-digit hex or dd secret; Fake TLS ee is unsupported.") from None


def proxy_catalog():
    """An operator-provided local catalog, never an unsolicited third-party proxy feed."""
    filename = os.environ.get("TGWITNESS_PROXY_CATALOG")
    if not filename:
        return False, []
    try:
        path = Path(filename)
        if path.stat().st_size > 128 * 1024:
            raise ValueError
        data = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or set(data) != {"format", "proxies"}
                or data["format"] != "tgwitness-proxy-catalog-v1"
                or not isinstance(data["proxies"], list) or len(data["proxies"]) > 32):
            raise ValueError
        result, ids = [], set()
        for row in data["proxies"]:
            if not isinstance(row, dict) or set(row) != {"id", "label", "link"}:
                raise ValueError
            alias, label = row["id"], row["label"]
            if (not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", alias) or alias in ids
                    or not isinstance(label, str) or not 1 <= len(label.strip()) <= 80):
                raise ValueError
            ids.add(alias)
            result.append({"id": alias, "label": label.strip(), "route": parse_mtproxy_link(row["link"])})
        return True, result
    except (OSError, ValueError, TypeError):
        raise ValueError("Public proxy catalog is unavailable. Custom routes still work.") from None
