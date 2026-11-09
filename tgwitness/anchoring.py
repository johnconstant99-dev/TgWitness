import asyncio
import calendar
import hashlib
import json
import re
import time
import uuid
from contextlib import suppress
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .anchor import timestamp_request
from .netclient import RouteError, request
from .evidence import retain_checkpoint
from .health import next_at
from .security import private_write
from .store import canonical, utcnow
from .tsa_roots import QUALIFIED_TSA, trusted_roots
from .verify import (DRAND_CHAIN, DRAND_GENESIS, DRAND_PERIOD, DRAND_RELAYS, OTS_BITCOIN, OTS_MAGIC, OTS_PENDING,
                     drand_beacon, drand_time, ots_summary, timestamp_reply_summary, timestamp_signature)


DEFAULT_TSA = [QUALIFIED_TSA, "https://freetsa.org/tsr", "https://timestamp.sectigo.com"]

REPLACED_TSA = {"http://timestamp.digicert.com": "https://timestamp.sectigo.com"}

DEFAULT_OTS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
               "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"]
LOOP_SECONDS = 30
OTS_UPGRADE_AGE = 3600
OTS_UPGRADE_FILES = 8
OTS_TREE_LIMIT = 1024 * 1024


class OTSReader:
    def __init__(self, data):
        if len(data) > OTS_TREE_LIMIT:
            raise ValueError("OpenTimestamps size limit exceeded")
        self.data, self.pos, self.left = data, 0, 10000

    def take(self, count):
        end = self.pos + count
        if end > len(self.data):
            raise ValueError("Truncated OpenTimestamps tree")
        value, self.pos = self.data[self.pos:end], end
        return value

    def integer(self):
        value = 0
        for shift in range(0, 35, 7):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128 and value <= 0xffffffff:
                return value
        raise ValueError("OpenTimestamps integer limit exceeded")

    def blob(self, limit):
        count = self.integer()
        if count > limit:
            raise ValueError("OpenTimestamps field limit exceeded")
        return self.take(count)

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError("Trailing OpenTimestamps bytes")

    def tree(self, message, depth=0):
        if depth >= 256 or not message or len(message) > 4096:
            raise ValueError("OpenTimestamps tree limit exceeded")
        node = {"message": message, "attestations": set(), "ops": {}}
        while True:
            self.left -= 1
            if self.left < 0:
                raise ValueError("OpenTimestamps operation limit exceeded")
            tag = self.take(1)[0]
            more = tag == 255
            if more:
                tag = self.take(1)[0]
            if tag == 0:
                kind, payload = self.take(8), self.blob(8192)
                check = OTSReader(payload)
                if kind == OTS_PENDING:
                    uri = check.blob(1000)
                    if not re.fullmatch(rb"[A-Za-z0-9._/:-]+", uri):
                        raise ValueError("Invalid OpenTimestamps calendar URI")
                    check.finish()
                elif kind == OTS_BITCOIN:
                    check.integer()
                    check.finish()
                    if len(message) != 32:
                        raise ValueError("Bitcoin commitment must have 32 bytes")
                node["attestations"].add((kind, payload))
            else:
                argument = self.blob(4096) if tag in (0xf0, 0xf1) else b""
                operation = (tag, argument)
                if operation in node["ops"] or (tag in (0xf0, 0xf1) and not argument):
                    raise ValueError("Repeated or empty OpenTimestamps operation")
                if tag == 0xf0:
                    result = message + argument
                elif tag == 0xf1:
                    result = argument + message
                elif tag == 0xf2:
                    result = message[::-1]
                elif tag == 0xf3:
                    result = message.hex().encode("ascii")
                elif tag in (0x02, 0x03, 0x08):
                    result = hashlib.new({0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256"}[tag], message).digest()
                else:
                    raise ValueError("Unsupported OpenTimestamps upgrade operation")
                node["ops"][operation] = self.tree(result, depth + 1)
            if not more:
                return node


def ots_integer(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def ots_tree_bytes(node):
    branches = [b"\x00" + kind + ots_integer(len(payload)) + payload
                for kind, payload in sorted(node["attestations"])]
    for (tag, argument), child in sorted(node["ops"].items()):
        encoded = bytes([tag]) + (ots_integer(len(argument)) + argument if argument else b"")
        branches.append(encoded + ots_tree_bytes(child))
    if not branches:
        raise ValueError("Empty OpenTimestamps tree")
    return b"".join(b"\xff" + branch for branch in branches[:-1]) + branches[-1]


def ots_merge(target, source):
    if target["message"] != source["message"]:
        raise ValueError("OpenTimestamps commitments differ")
    target["attestations"].update(source["attestations"])
    for operation, child in source["ops"].items():
        if operation in target["ops"]:
            ots_merge(target["ops"][operation], child)
        else:
            target["ops"][operation] = child


def ots_pending(node):
    for kind, payload in node["attestations"]:
        if kind == OTS_PENDING:
            yield node, OTSReader(payload).blob(1000).decode("ascii")
    for child in node["ops"].values():
        yield from ots_pending(child)


def approved_calendar(uri, settings):
    parts = urlsplit(uri)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        return False
    configured = {url.rstrip("/") for url in settings["ots_calendars"]}
    if uri.rstrip("/") in configured:
        return True
    return parts.port in (None, 443) and not parts.path.strip("/") and any(parts.hostname.endswith("." + suffix) for suffix in (
        "calendar.opentimestamps.org", "calendar.eternitywall.com", "calendar.catallaxy.com"))


def old_ots_files(folder, cursor, pattern="checkpoint-*.ots"):
    after, before, now = [], [], time.time()
    for path in folder.glob(pattern):
        try:
            if path.is_symlink() or now - path.stat().st_mtime < OTS_UPGRADE_AGE:
                continue
        except OSError:
            continue
        bucket = after if path.name > cursor else before
        if len(bucket) < OTS_UPGRADE_FILES or path.name < bucket[-1].name:
            bucket.append(path)
            bucket.sort(key=lambda item: item.name)
            del bucket[OTS_UPGRADE_FILES:]
    return (after + before)[:OTS_UPGRADE_FILES]


async def upgrade_pending_ots(store, network, settings, folder=None):
    daily = folder is not None
    folder = folder if daily else store.root / "checkpoints" / "anchors"
    if not folder.is_dir() or folder.is_symlink() or not settings["ots_calendars"]:
        return []
    previous = store.get_setting("evidence_ots_upgrade", {}) or {}
    cursor = previous.get("cursor", "")
    ordered = await asyncio.to_thread(old_ots_files, folder, cursor, "daily-*.ots" if daily else "checkpoint-*.ots")
    outcomes, examined, calls = [], 0, 0
    deadline = time.monotonic() + 60
    for path in ordered:
        if examined >= OTS_UPGRADE_FILES or calls >= 8 or time.monotonic() >= deadline:
            break
        examined += 1
        cursor = path.name
        try:
            if path.is_symlink():
                continue
            if path.stat().st_size > OTS_TREE_LIMIT:
                raise ValueError("OpenTimestamps size limit exceeded")
            original = path.read_bytes()
            stem = path.name.split(".", 1)[0]
            if not re.fullmatch(r"daily-\d{4}-\d{2}-\d{2}" if daily else r"checkpoint-\d{12,}", stem):
                continue
            source = (folder if daily else folder.parent) / (stem + ".json")
            if source.is_symlink() or source.stat().st_size > 64 * 1024:
                raise ValueError("Invalid retained checkpoint")
            digest = hashlib.sha256(source.read_bytes()).digest()
            if ots_summary(original, digest)["status"] != "pending":
                continue
            head = OTS_MAGIC + b"\x01\x08" + digest
            reader = OTSReader(original[len(head):])
            tree = reader.tree(digest)
            reader.finish()
            services = []
            for node, uri in list(ots_pending(tree))[:8]:
                if calls >= 8 or time.monotonic() >= deadline:
                    break
                if not approved_calendar(uri, settings):
                    continue
                calls += 1
                async with asyncio.timeout(min(20, max(0.1, deadline - time.monotonic()))):
                    answer = (await request("GET", uri.rstrip("/") + "/timestamp/" + node["message"].hex(),
                                            network, {"Accept": "application/vnd.opentimestamps.v1"},
                                            timeout=15, limit=10000))[2]
                remote = OTSReader(answer)
                upgraded = remote.tree(node["message"])
                remote.finish()
                ots_merge(node, upgraded)
                services.append(uri)
            candidate = head + ots_tree_bytes(tree)
            summary = ots_summary(candidate, digest)
            if summary["status"] != "bitcoin-unverified":
                continue
            backup = path.with_suffix(".ots.pending")
            if not backup.exists():
                private_write(backup, original)
            if path.read_bytes() != original:
                raise ValueError("OpenTimestamps proof changed during upgrade")
            private_write(path, candidate)
            record = {"file": path.name, "checkpoint": source.name, "services": services,
                      "before_sha256": hashlib.sha256(original).hexdigest(),
                      "after_sha256": hashlib.sha256(candidate).hexdigest(), **summary}
            store.append("anchor.upgraded", record)
            outcomes.append({"ok": True, **record})
        except Exception as exc:
            outcomes.append({"file": path.name, "ok": False, "error": problem(exc)})
    store.set_setting("evidence_ots_upgrade", {"at": utcnow(), "cursor": cursor, "results": outcomes})
    return outcomes


class EvidenceMode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    tsa_urls: list[str] = Field(default_factory=lambda: list(DEFAULT_TSA), max_length=8)
    ots_calendars: list[str] = Field(default_factory=lambda: list(DEFAULT_OTS), max_length=8)
    interval_minutes: int = Field(default=10, ge=5, le=1440)
    drand: bool = False
    devices: bool = False
    gateway: bool = False

    @field_validator("tsa_urls", "ots_calendars")
    @classmethod
    def plain_urls(cls, values):
        clean = []
        for value in values:
            value = value.strip().rstrip("/")
            parts = urlsplit(value)
            if value != QUALIFIED_TSA and (parts.scheme != "https" or not parts.hostname or parts.username
                                           or parts.password or parts.fragment or len(value) > 300):
                raise ValueError("Use https:// addresses without credentials.")
            if value not in clean:
                clean.append(value)
        return clean


def evidence_settings(store):
    saved = dict(store.get_setting("evidence", {}) or {})

    for key in ("tsa_urls", "ots_calendars"):
        if isinstance(saved.get(key), list):
            saved[key] = [REPLACED_TSA.get(url.strip().rstrip("/"), "https://" + url.strip()[7:])
                          if isinstance(url, str) and url.strip().startswith("http://")
                          and url.strip().rstrip("/") != QUALIFIED_TSA else url for url in saved[key]]
    return EvidenceMode.model_validate(saved).model_dump()


async def post(url, body, headers, network, timeout=30, limit=256 * 1024):
    return (await request("POST", url, network, headers, body, timeout=timeout, limit=limit))[2]


def service_name(url):
    parts = urlsplit(url)
    return re.sub(r"[^a-z0-9.]+", "-", (parts.netloc + parts.path).lower()).strip("-.")


def problem(exc):
    if isinstance(exc, (RouteError, ValueError)):
        return str(exc)[:200]
    return type(exc).__name__


def latest_checkpoint(store):
    directory = store.root / "checkpoints"
    latest = directory / "latest.json"
    if not latest.is_file():
        return None
    statement = json.loads(latest.read_bytes())["statement"]
    name = "checkpoint-" + str(statement["event_count"]).zfill(12)
    source = directory / (name + ".json")
    if source.is_file():
        statement = json.loads(source.read_bytes())["statement"]
    return (name, source, statement) if source.is_file() else None


async def ots_stamp(digest: bytes, calendars, folder, name: str, network) -> list[dict]:
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    results = []
    for url in calendars:
        target = folder / (name + "." + service_name(url) + ".ots")
        if target.exists():
            ots_summary(target.read_bytes(), digest)
            results.append({"service": url, "kind": "opentimestamps", "covered": True})
            continue
        received = False
        try:
            answer = await post(url + "/digest", digest, {"Accept": "application/vnd.opentimestamps.v1"},
                                network, limit=10000)
            received = True
            proof = OTS_MAGIC + b"\x01\x08" + digest + answer
            summary = ots_summary(proof, digest)
            private_write(target, proof)
            results.append({"service": url, "kind": "opentimestamps", "ok": True, "status": summary["status"]})
        except Exception as exc:
            results.append({"service": url, "kind": "opentimestamps", "ok": False, "received": received,
                            "error": problem(exc)})
    return results


async def anchor_latest(store, network, settings):
    found = latest_checkpoint(store)
    if not found:
        return None
    name, source, statement = found
    data = source.read_bytes()
    digest = hashlib.sha256(data).digest()
    folder = store.root / "checkpoints" / "anchors"
    folder.mkdir(exist_ok=True, mode=0o700)
    results, covered = [], []
    for url in settings["tsa_urls"]:
        target = folder / (name + "." + service_name(url) + ".tsr")
        if target.exists():
            covered.append({"service": url, "kind": "rfc3161"})
            continue
        received = False
        try:
            query = timestamp_request(data)
            reply = await post(url, query, {"Content-Type": "application/timestamp-query",
                                            "Accept": "application/timestamp-reply"}, network)
            received = True
            summary = timestamp_reply_summary(reply, digest, query)
            signed = timestamp_signature(reply, trusted_roots())
            private_write(folder / (name + "." + service_name(url) + ".tsq"), query)
            private_write(target, reply)
            results.append({"service": url, "kind": "rfc3161", "ok": True, "time": summary["time"], **signed})
        except Exception as exc:
            results.append({"service": url, "kind": "rfc3161", "ok": False, "received": received, "error": problem(exc)})
    for outcome in await ots_stamp(digest, settings["ots_calendars"], folder, name, network):
        if outcome.pop("covered", False):
            covered.append(outcome)
        else:
            results.append(outcome)
    if not results:
        return None
    record = {"checkpoint": {"file": source.name, "event_count": statement["event_count"],
                             "head_hash": statement["head_hash"], "sha256": digest.hex()},
              "results": results, "covered": covered}
    store.append("anchor.completed", {**record, "meaning": "Only this checkpoint hash was sent; answers are "
                                      "stored in checkpoints/anchors and included in evidence exports. "
                                      "covered: services that answered for this checkpoint on an earlier pass."})
    at = utcnow()
    store.set_setting("evidence_last", {"at": at, **record})
    if any(r["ok"] for r in results):
        verified = any(r["ok"] and r["kind"] == "rfc3161" for r in results)
        previous = store.get_setting("evidence_success", None) or {}
        store.set_setting("evidence_success", {"at": at, "checkpoint": record["checkpoint"],
                                               "verified_at": at if verified else previous.get("verified_at")})
    failed = [r for r in results if not r["ok"]]
    if failed:
        store.set_setting("evidence_failure", {"at": at, "errors": [
            {"service": r["service"], "kind": r["kind"], "received": r["received"], "error": r["error"]} for r in failed]})
    return record


async def record_drand(store, network):
    errors = []
    for relay in DRAND_RELAYS:
        try:
            answer = (await request("GET", relay + "/" + DRAND_CHAIN + "/public/latest", network,
                                    {"Accept": "application/json"}, timeout=15, limit=4096))[2]
            beacon = drand_beacon(json.loads(answer))
        except Exception as exc:
            errors.append(urlsplit(relay).hostname + ": " + problem(exc))
            continue
        ahead = DRAND_GENESIS + (beacon["round"] - 1) * DRAND_PERIOD - time.time()
        if ahead > 60:
            errors.append(urlsplit(relay).hostname + ": the round is " + str(round(ahead)) + " s ahead of this clock")
            continue
        event = store.append("beacon.drand", {
            "chain": DRAND_CHAIN, **beacon, "round_time": drand_time(beacon["round"]), "relay": relay,
            "meaning": "Public randomness from drand (League of Entropy). Nobody knew it before round_time, so the "
                       "records after this one were written later. Any drand relay returns the same round."})
        return {"round": beacon["round"], "round_time": drand_time(beacon["round"]), "relay": relay,
                "seq": event["seq"]}
    raise ValueError("No drand relay answered: " + "; ".join(errors))


def device_view(device):
    return {k: v for k, v in device.items() if not (device.get("current") and k == "active_at")}


async def record_devices(store, devices):
    listed = sorted(await devices(), key=lambda d: (not d.get("current"), str(d.get("hash"))))
    digest = hashlib.sha256(canonical([device_view(d) for d in listed])).hexdigest()
    previous = store.get_setting("evidence_devices", None) or {}
    hashes = [str(d.get("hash")) for d in listed]
    payload = {"source": "account.getAuthorizations", "count": len(listed), "list_sha256": digest,
               "changed": previous.get("list_sha256") != digest}
    if payload["changed"]:
        payload["devices"] = listed
        if previous:
            before = previous.get("hashes") or []
            payload.update(added=[h for h in hashes if h not in before], removed=[h for h in before if h not in hashes])
    payload["meaning"] = ("Telegram's list of this account's sessions (Settings, Devices) without IP addresses; "
                          "in full when it changed since the previous list, otherwise only its hash.")
    store.append("account.devices", payload)
    at = utcnow()
    store.set_setting("evidence_devices", {"at": at, "count": len(listed), "list_sha256": digest, "hashes": hashes,
                                           "changed_at": at if payload["changed"] else previous.get("changed_at")})
    return {"count": len(listed), "others": sum(1 for d in listed if not d.get("current")),
            "changed": payload["changed"]}


GATEWAY_GRAPHQL = "https://api.cloudflare.com/client/v4/graphql"
GATEWAY_FIELDS = ("at", "name", "type", "rcode", "decision", "colo")
GATEWAY_LIMIT = 1000
GATEWAY_LAG_SECONDS = 120
GATEWAY_MIN_WINDOW_SECONDS = 60
GATEWAY_RETENTION_SECONDS = 86400
GATEWAY_WINDOW_SECONDS = 3 * 3600


def gateway_query(address):
    source = ", sourceIP: $source" if address else ""
    return ("query($account: String!, $location: String!, $since: Time!, $until: Time!"
            + (", $source: String!" if address else "") + ") { viewer { accounts(filter: {accountTag: $account}) { "
            "cf1GatewayDnsRawGroups(limit: " + str(GATEWAY_LIMIT) + ", filter: {location: $location" + source
            + ", datetime_gt: $since, datetime_leq: $until}, orderBy: [datetime_ASC]) { dimensions { datetime "
            "destination queryType rcode resolverDecision coloName } } } } }")


def gateway_time(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


async def gateway_rows(network, config, since, until):
    variables = {"account": config["account"], "location": str(uuid.UUID(config["location_id"])),
                 "since": gateway_time(since), "until": gateway_time(until)}
    if config.get("address"):
        variables["source"] = config["address"]
    body = json.dumps({"query": gateway_query(config.get("address")), "variables": variables}).encode()
    answer = json.loads((await request("POST", GATEWAY_GRAPHQL, network, {
        "Authorization": "Bearer " + config["token"], "Content-Type": "application/json",
        "Accept": "application/json"}, body=body, timeout=30, limit=4 * 1024 * 1024))[2])
    if answer.get("errors") or not answer.get("data"):
        raise ValueError("Cloudflare: " + "; ".join(str(e.get("message")) for e in answer.get("errors") or []))
    return [row["dimensions"] for row in answer["data"]["viewer"]["accounts"][0]["cf1GatewayDnsRawGroups"]]


async def record_gateway(store, network, config):
    copied, last = 0, None
    for _ in range(GATEWAY_RETENTION_SECONDS // GATEWAY_WINDOW_SECONDS + 1):
        done = await gateway_window(store, network, config)
        if done.get("skipped"):
            break
        copied, last = copied + done["count"], done
        if done["caught_up"]:
            break
    if last is None:
        return {"count": 0, "skipped": True}
    return {"count": copied, "until": last["until"], "seq": last["seq"]}


async def gateway_window(store, network, config):
    now = time.time()
    cursor = store.get_setting("evidence_gateway_cursor", None) or {}
    since = now - GATEWAY_RETENTION_SECONDS
    if cursor.get("location_id") == config["location_id"] and cursor.get("address") == config.get("address"):
        since = max(since, cursor["until"])
    latest = now - GATEWAY_LAG_SECONDS
    until = min(latest, since + GATEWAY_WINDOW_SECONDS - 1)
    if until - since < GATEWAY_MIN_WINDOW_SECONDS:
        return {"count": 0, "until": gateway_time(since), "skipped": True}
    rows, truncated = await gateway_rows(network, config, since, until), False
    if len(rows) >= GATEWAY_LIMIT:
        last = rows[-1]["datetime"]
        whole = [row for row in rows if row["datetime"] < last]
        second = calendar.timegm(time.strptime(last, "%Y-%m-%dT%H:%M:%SZ"))
        if whole:
            rows, until = whole, second - 1
        else:
            until, truncated = second, True
    queries = [[row.get("datetime"), row.get("destination"), row.get("queryType"), row.get("rcode"),
                row.get("resolverDecision"), row.get("coloName")] for row in rows]
    event = store.append("cloudflare.gateway_dns", {
        "source": "Cloudflare Gateway log, GraphQL cf1GatewayDnsRawGroups", "account": config["account"],
        "location_id": config["location_id"], "address": config.get("address") or None,
        "from": gateway_time(since), "until": gateway_time(until), "count": len(queries),
        "fields": list(GATEWAY_FIELDS), "queries": queries, **({"truncated": True} if truncated else {}),
        "meaning": "the DNS queries Cloudflare Gateway logged for this location"
                   + (" from " + config["address"] if config.get("address") else "")
                   + " in this window, as Cloudflare's API returned them; Cloudflare's own copy is kept 24 hours "
                     "on the free plan"})
    store.set_setting("evidence_gateway_cursor", {"location_id": config["location_id"],
                                                  "address": config.get("address"), "until": until})
    return {"count": len(queries), "until": gateway_time(until), "seq": event["seq"], "caught_up": until >= latest}


async def record_extras(store, network, settings, devices, gateway=None):
    saved = dict(store.get_setting("evidence_witnesses", None) or {})
    for name, enabled, work in (("drand", settings["drand"], lambda: record_drand(store, network)),
                                ("devices", settings["devices"] and devices, lambda: record_devices(store, devices)),
                                ("gateway", settings.get("gateway") and gateway,
                                 lambda: record_gateway(store, network, gateway))):
        if not enabled:
            saved.pop(name, None)
            continue
        before = saved.get(name) or {}
        try:
            saved[name] = {"at": utcnow(), "ok": True, **await work()}
        except Exception as exc:
            saved[name] = {"at": utcnow(), "ok": False, "error": problem(exc),
                           "last_ok_at": before["at"] if before.get("ok") else before.get("last_ok_at")}
    store.set_setting("evidence_witnesses", saved)
    return saved


def request_anchor(store, vault, wakeup):
    retain_checkpoint(store, vault)
    wakeup.set()


async def anchor_loop(store, network_config, wakeup, status, devices=None, gateway=None):
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
        status.update(busy=True, error=None)
        try:
            network = network_config()
            record = await anchor_latest(store, network, settings)
            await upgrade_pending_ots(store, network, settings)
            await record_extras(store, network, settings, devices, gateway() if gateway else None)
            status["outcome"] = "anchored" if record else "up_to_date" if latest_checkpoint(store) else "no_checkpoint"
        except Exception as exc:
            status.update(outcome="error", error=type(exc).__name__)
            store.append("collector.error", {"operation": "evidence anchoring", "error_type": type(exc).__name__})
        finally:
            status.update(busy=False, last_pass_at=utcnow(), next_at=next_at(settings["interval_minutes"] * 60))
