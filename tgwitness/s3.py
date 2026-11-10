import hashlib
import hmac
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, quote, urlsplit

from .netclient import HTTPError, request

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def canonical_query(query):
    pairs = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in parse_qsl(query, keep_blank_values=True))
    return "&".join(k + "=" + v for k, v in pairs)


def endpoint_allowed(endpoint):
    parts = urlsplit(endpoint)
    if parts.scheme == "https":
        return True
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme != "http" or not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_private
    except ValueError:
        return False


def sign(method, url, headers, payload_hash, access_key, secret_key, region, now=None, service="s3"):
    amz_date = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    parts = urlsplit(url)
    signed_headers = {**{k.lower(): v for k, v in headers.items()}, "host": parts.netloc,
                      "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    canonical = {k.strip(): " ".join(str(v).split()) for k, v in signed_headers.items()}
    names = ";".join(sorted(canonical))
    canonical_request = "\n".join([
        method, parts.path or "/", canonical_query(parts.query),
        "".join(k + ":" + canonical[k] + "\n" for k in sorted(canonical)), names, payload_hash])
    scope = amz_date[:8] + "/" + region + "/" + service + "/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = ("AWS4" + secret_key).encode()
    for part in (amz_date[:8], region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    signed_headers["authorization"] = ("AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope
                                       + ",SignedHeaders=" + names + ",Signature=" + signature)
    signed_headers.pop("host")
    return signed_headers


class S3:
    def __init__(self, endpoint, region, bucket, access_key, secret_key, network, path_style=True):
        self.endpoint, self.region, self.bucket = endpoint.rstrip("/"), region, bucket
        self.access_key, self.secret_key, self.network, self.path_style = access_key, secret_key, network, path_style

    def url(self, key="", query=""):
        parts = urlsplit(self.endpoint)
        path = quote(key, safe="/~-_.")
        if self.path_style:
            base = self.endpoint + "/" + self.bucket
        else:
            base = parts.scheme + "://" + self.bucket + "." + parts.netloc
        return base + "/" + path + ("?" + query if query else "")

    async def call(self, method, url, headers=None, body=b"", length=None, payload_hash=EMPTY_SHA256, sink=None):
        if not endpoint_allowed(self.endpoint):
            raise ValueError("Enter the storage endpoint as https://host (no path or credentials).")
        signed = sign(method, url, headers or {}, payload_hash, self.access_key, self.secret_key, self.region)
        return await request(method, url, self.network, signed, body, length, sink, timeout=120)

    async def put(self, key, body, length, sha256_hex, md5_b64, extra=None):
        headers = {"content-md5": md5_b64, "content-type": "application/octet-stream", **(extra or {})}
        _, response, _ = await self.call("PUT", self.url(key), headers, body, length, sha256_hex)
        return self.metadata(response)

    @staticmethod
    def metadata(headers):
        headers = {k.lower(): v for k, v in headers.items()}
        modified = headers.get("last-modified")
        if modified:
            moment = parsedate_to_datetime(modified)
            if moment.tzinfo is None:
                raise ValueError("S3 Last-Modified lacks a time zone")
            modified = moment.astimezone(timezone.utc).isoformat()
        return {"etag": headers.get("etag"), "version_id": headers.get("x-amz-version-id"),
                "last_modified": modified}

    async def head(self, key, version_id=None):
        query = "versionId=" + quote(version_id, safe="") if version_id else ""
        _, headers, _ = await self.call("HEAD", self.url(key, query))
        return self.metadata(headers)

    async def get(self, key, sink):
        await self.call("GET", self.url(key), sink=sink)

    @staticmethod
    def _xml(data):
        root = ET.fromstring(data)
        ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        return root, ns

    async def object_lock(self):
        try:
            _, _, data = await self.call("GET", self.url("", "object-lock"))
        except HTTPError as exc:
            if exc.status == 404 or b"ObjectLockConfigurationNotFound" in exc.body:
                return {"enabled": False, "default_mode": None, "default_days": None}
            raise
        root, ns = self._xml(data)
        days = root.findtext(".//" + ns + "Days")
        years = root.findtext(".//" + ns + "Years")
        return {"enabled": root.findtext(ns + "ObjectLockEnabled") == "Enabled",
                "default_mode": root.findtext(".//" + ns + "Mode"),
                "default_days": int(days) if days else int(years) * 365 if years else None}

    async def retention(self, key, version_id=None):
        try:
            query = "retention" + ("&versionId=" + quote(version_id, safe="") if version_id else "")
            _, _, data = await self.call("GET", self.url(key, query))
        except HTTPError as exc:
            if exc.status in (400, 404) or b"NoSuchObjectLockConfiguration" in exc.body:
                return None
            raise
        root, ns = self._xml(data)
        return {"mode": root.findtext(ns + "Mode"), "retain_until": root.findtext(ns + "RetainUntilDate")}

    async def list(self, prefix):
        token = None
        seen = set()
        while True:
            query = "list-type=2&prefix=" + quote(prefix, safe="-_.~") + (
                "&continuation-token=" + quote(token, safe="-_.~") if token else "")
            _, _, data = await self.call("GET", self.url("", query))
            root = ET.fromstring(data)
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            for item in root.iter(ns + "Contents"):
                yield item.findtext(ns + "Key"), int(item.findtext(ns + "Size") or 0)
            if root.findtext(ns + "IsTruncated") != "true":
                return
            token = root.findtext(ns + "NextContinuationToken")
            if not token or token in seen:
                raise ValueError("Object storage returned a missing or repeated continuation token")
            seen.add(token)
