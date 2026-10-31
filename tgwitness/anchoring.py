"""Evidence mode: send checkpoint hashes to independent timestamp services automatically.

Only the SHA-256 of a signed checkpoint leaves the machine. RFC 3161 authorities return a
signed time-stamp token at once; OpenTimestamps calendars return a proof that is confirmed
in Bitcoin hours later (`ots upgrade`). Answers are stored beside the checkpoint, travel in
evidence exports, and are checked again by verify.py.
"""
import asyncio
import hashlib
import json
import re
import time
from contextlib import suppress
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .anchor import timestamp_request
from .netclient import RouteError, request
from .evidence import retain_checkpoint
from .security import private_write
from .store import utcnow
from .tsa_roots import trusted_roots
from .verify import OTS_MAGIC, ots_summary, timestamp_reply_summary, timestamp_signature

# HTTPS only; an answer counts once its signature chains to a root in tsa_roots.
DEFAULT_TSA = ["https://freetsa.org/tsr", "https://timestamp.sectigo.com"]
# The earlier default authority answers over plain HTTP only.
REPLACED_TSA = {"http://timestamp.digicert.com": "https://timestamp.sectigo.com"}
# The calendars `ots stamp` uses by default (opentimestamps-client).
DEFAULT_OTS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
               "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"]
LOOP_SECONDS = 30


class EvidenceMode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    tsa_urls: list[str] = Field(default_factory=lambda: list(DEFAULT_TSA), max_length=8)
    ots_calendars: list[str] = Field(default_factory=lambda: list(DEFAULT_OTS), max_length=8)
    interval_minutes: int = Field(default=10, ge=5, le=1440)

    @field_validator("tsa_urls", "ots_calendars")
    @classmethod
    def plain_urls(cls, values):
        clean = []
        for value in values:
            value = value.strip().rstrip("/")
            parts = urlsplit(value)
            if (parts.scheme != "https" or not parts.hostname or parts.username
                    or parts.password or parts.fragment or len(value) > 300):
                raise ValueError("Use https:// addresses without credentials.")
            if value not in clean:
                clean.append(value)
        return clean


def evidence_settings(store):
    saved = dict(store.get_setting("evidence", {}) or {})
    # Saved while plain HTTP was accepted: the same address over HTTPS, which fails visibly if unsupported.
    for key in ("tsa_urls", "ots_calendars"):
        if isinstance(saved.get(key), list):
            saved[key] = [REPLACED_TSA.get(url.strip().rstrip("/"), "https://" + url.strip()[7:])
                          if isinstance(url, str) and url.strip().startswith("http://") else url for url in saved[key]]
    return EvidenceMode.model_validate(saved).model_dump()


async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
    return (await request("POST", url, network, headers, body, timeout=timeout, limit=limit))[2]


def service_name(url):
    """File-name part for a service: host, plus port and path when present (freetsa.org-tsr)."""
    parts = urlsplit(url)
    return re.sub(r"[^a-z0-9.]+", "-", (parts.netloc + parts.path).lower()).strip("-.")


def problem(exc):
    if isinstance(exc, (RouteError, ValueError)):
        return str(exc)[:200]
    return type(exc).__name__


async def anchor_latest(store, network, settings):
    """Stamp the latest retained checkpoint with every service that has not answered for it yet."""
    directory = store.root / "checkpoints"
    latest = directory / "latest.json"
    if not latest.is_file():
        return None
    statement = json.loads(latest.read_bytes())["statement"]
    name = "checkpoint-" + str(statement["event_count"]).zfill(12)
    source = directory / (name + ".json")
    if not source.is_file():
        return None
    data = source.read_bytes()
    digest = hashlib.sha256(data).digest()
    folder = directory / "anchors"
    folder.mkdir(exist_ok=True, mode=0o700)
    results = []
    for url in settings["tsa_urls"]:
        target = folder / (name + "." + service_name(url) + ".tsr")
        if target.exists():
            continue
        try:
            query = timestamp_request(data)
            reply = await post(url, query, {"Content-Type": "application/timestamp-query",
                                            "Accept": "application/timestamp-reply"}, network)
            summary = timestamp_reply_summary(reply, digest, query)
            signed = timestamp_signature(reply, trusted_roots())
            private_write(folder / (name + "." + service_name(url) + ".tsq"), query)
            private_write(target, reply)
            results.append({"service": url, "kind": "rfc3161", "ok": True, "time": summary["time"], **signed})
        except Exception as exc:
            results.append({"service": url, "kind": "rfc3161", "ok": False, "error": problem(exc)})
    for url in settings["ots_calendars"]:
        target = folder / (name + "." + service_name(url) + ".ots")
        if target.exists():
            continue
        try:
            answer = await post(url + "/digest", digest, {"Accept": "application/vnd.opentimestamps.v1"},
                                network, limit=10000)
            proof = OTS_MAGIC + b"\x01\x08" + digest + answer
            summary = ots_summary(proof, digest)
            private_write(target, proof)
            results.append({"service": url, "kind": "opentimestamps", "ok": True, "status": summary["status"]})
        except Exception as exc:
            results.append({"service": url, "kind": "opentimestamps", "ok": False, "error": problem(exc)})
    if not results:
        return None
    record = {"checkpoint": {"file": source.name, "event_count": statement["event_count"],
                             "head_hash": statement["head_hash"], "sha256": digest.hex()},
              "results": results}
    store.append("anchor.completed", {**record, "meaning": "Only this checkpoint hash was sent; answers are "
                                      "stored in checkpoints/anchors and included in evidence exports."})
    store.set_setting("evidence_last", {"at": utcnow(), **record})
    return record


def request_anchor(store, vault, wakeup):
    """Anchor a fresh checkpoint (it carries the signing public key) on the next loop pass."""
    retain_checkpoint(store, vault)
    wakeup.set()


async def anchor_loop(store, network_config, wakeup, status):
    last = 0.0
    while True:
        with suppress(TimeoutError):
            await asyncio.wait_for(wakeup.wait(), LOOP_SECONDS)
        settings = evidence_settings(store)
        if not settings["enabled"]:
            wakeup.clear()
            continue
        if not wakeup.is_set() and time.time() - last < settings["interval_minutes"] * 60:
            continue
        wakeup.clear()
        last = time.time()
        status["busy"] = True
        try:
            await anchor_latest(store, network_config(), settings)
        except Exception as exc:
            store.append("collector.error", {"operation": "evidence anchoring", "error_type": type(exc).__name__})
        finally:
            status["busy"] = False
