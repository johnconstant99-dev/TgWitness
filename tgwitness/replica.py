import argparse
import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .health import next_at
from .netclient import HTTPError, RouteError
from .network import NetworkConfig
from .s3 import S3
from .store import canonical, utcnow
from .verify import fingerprint, media_reference, verify_checkpoint, verify_events

MAGIC = b"TGWR1"
RECIPIENT_MAGIC = b"TGWR2"
CHUNK = 1024 * 1024
SEGMENT_EVENTS = 5000
LOOP_SECONDS = 30
KEY_DERIVATION = "v2"
LEGACY_DERIVATION = "v1"


class ReplicaSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    endpoint: str = Field(default="", max_length=300)
    region: str = Field(default="us-east-1", pattern=r"^[a-z0-9-]{1,40}$")
    bucket: str = Field(default="", pattern=r"^$|^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    prefix: str = Field(default="tgwitness", pattern=r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,199}$")
    path_style: bool = True
    interval_minutes: int = Field(default=5, ge=1, le=1440)
    retention_days: int = Field(default=0, ge=0, le=36500)
    retention_mode: Literal["GOVERNANCE", "COMPLIANCE"] = "GOVERNANCE"
    recipient_public_key: str = Field(default="", max_length=44)
    evidence: bool = False

    @field_validator("recipient_public_key")
    @classmethod
    def recipient_key(cls, value):
        if value:
            try:
                raw = base64.b64decode(value, validate=True)
                if len(raw) != 32 or base64.b64encode(raw).decode() != value:
                    raise ValueError
                X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(raw))
            except ValueError:
                raise ValueError("Use a base64-encoded 32-byte X25519 recipient public key") from None
        return value

    @field_validator("endpoint")
    @classmethod
    def plain_endpoint(cls, value):
        value = value.strip().rstrip("/")
        parts = urlsplit(value)
        if value and (parts.scheme not in ("http", "https") or not parts.hostname or parts.username
                      or parts.password or parts.path or parts.query or parts.fragment):
            raise ValueError("Enter the storage endpoint as https://host (no path or credentials).")
        return value


def replica_settings(store):
    return ReplicaSettings.model_validate(store.get_setting("replica", {})).model_dump()


def workspace_prefix(settings, public_key):
    base = settings["prefix"].strip("/") + "/" + fingerprint(public_key)[:16]
    recipient = settings.get("recipient_public_key")
    return base + "/recipient-" + hashlib.sha256(base64.b64decode(recipient)).hexdigest()[:16] if recipient else base


def replica_prefix(settings, workspace_fingerprint):
    if settings.get("recipient_public_key"):
        recipient = base64.b64decode(settings["recipient_public_key"], validate=True)
        return (settings["prefix"].strip("/") + "/" + workspace_fingerprint[:16]
                + "/recipient-" + hashlib.sha256(recipient).hexdigest()[:16])
    return settings["prefix"].strip("/") + "/hkdf-v2/" + workspace_fingerprint


def derive_key(root_key, workspace_fingerprint, derivation=KEY_DERIVATION):
    if len(root_key) != 32:
        raise ValueError("Replica root key must contain 32 bytes")
    if not isinstance(workspace_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", workspace_fingerprint):
        raise ValueError("Invalid replica workspace fingerprint")
    if derivation == LEGACY_DERIVATION:
        return root_key
    if derivation != KEY_DERIVATION:
        raise ValueError("Unsupported replica key derivation")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"tgwitness-replica-v2|" + workspace_fingerprint.encode()).derive(root_key)


def replica_context(settings, root_key, workspace_fingerprint):
    derivation = LEGACY_DERIVATION if settings.get("recipient_public_key") else KEY_DERIVATION
    key = derive_key(root_key, workspace_fingerprint, derivation)
    base = replica_prefix(settings, workspace_fingerprint)
    identity = {k: settings[k] for k in ("endpoint", "region", "bucket", "path_style")}
    identity.update(prefix=base, encryption_key_hash=hashlib.sha256(key).hexdigest())
    if settings["recipient_public_key"] or settings["evidence"]:
        identity.update(recipient_public_key=settings["recipient_public_key"], evidence=settings["evidence"])
    if derivation != LEGACY_DERIVATION:
        identity["key_derivation"] = derivation
    return key, base, hashlib.sha256(canonical(identity)).hexdigest()


def recipient_envelope(public_key, name):
    recipient = base64.b64decode(public_key, validate=True)
    ephemeral = X25519PrivateKey.generate()
    public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    context = RECIPIENT_MAGIC + public + recipient + name.encode()
    wrapping = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(
        ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient)))
    key, nonce = os.urandom(32), os.urandom(12)
    return key, RECIPIENT_MAGIC + public + nonce + AESGCM(wrapping).encrypt(nonce, key, context)


def load_recipient_key(path):
    with Path(path).open("rb") as source:
        data = source.read(4097)
    if len(data) > 4096:
        raise ValueError("Recipient key file is too large")
    if data.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, X25519PrivateKey):
            raise ValueError("Recipient private key must be X25519")
        return key
    return X25519PrivateKey.from_private_bytes(data if len(data) == 32 else base64.b64decode(data.strip(), validate=True))


def encrypt(key, name, read, nonce_prefix):
    aead, counter, label = AESGCM(key), 0, name.encode()
    yield MAGIC + nonce_prefix
    while True:
        chunk = read(CHUNK)
        last = len(chunk) < CHUNK
        yield aead.encrypt(nonce_prefix + struct.pack(">I", counter), chunk, label + (b"|last" if last else b"|more"))
        counter += 1
        if last:
            return


def decrypt(key, name, read, recipient_key=None):
    magic = read(len(MAGIC))
    if magic == RECIPIENT_MAGIC:
        if recipient_key is None:
            raise ValueError("нужен ключ получателя (use --recipient-key FILE)")
        header = read(92)
        if len(header) != 92:
            raise ValueError("Truncated recipient envelope")
        public, nonce, wrapped = header[:32], header[32:44], header[44:]
        recipient = recipient_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        context = RECIPIENT_MAGIC + public + recipient + name.encode()
        wrapping = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(
            recipient_key.exchange(X25519PublicKey.from_public_bytes(public)))
        key = AESGCM(wrapping).decrypt(nonce, wrapped, context)
        magic = read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Not a TgWitness encrypted object: " + name)
    prefix = read(8)
    if len(prefix) != 8:
        raise ValueError("Truncated encrypted object")
    aead, counter, label = AESGCM(key), 0, name.encode()
    while True:
        block = read(CHUNK + 16)
        last = len(block) < CHUNK + 16
        yield aead.decrypt(prefix + struct.pack(">I", counter), block, label + (b"|last" if last else b"|more"))
        counter += 1
        if last:
            if read(1):
                raise ValueError("Trailing data after the final chunk: " + name)
            return


class MediaUnavailable(ValueError):
    pass


async def upload(s3, key, name, opener, extra, expected_digest=None, recipient_public_key="", receipts=None):
    prefix, chunks = os.urandom(8), []
    envelope = b""
    if recipient_public_key:
        key, envelope = recipient_envelope(recipient_public_key, name)

    def encrypted(read):
        if envelope:
            yield envelope
        yield from encrypt(key, name, read, prefix)

    def digests():
        md5, sha, plain_hash, length = hashlib.md5(), hashlib.sha256(), hashlib.sha256(), 0
        with opener() as source:
            def read(size):
                data = source.read(size)
                plain_hash.update(data)
                chunks.append(hashlib.sha256(data).digest())
                return data
            for piece in encrypted(read):
                md5.update(piece)
                sha.update(piece)
                length += len(piece)
        if expected_digest is not None and plain_hash.hexdigest() != expected_digest:
            raise MediaUnavailable("Preserved media differs from its signed hash")
        return base64.b64encode(md5.digest()).decode(), sha.hexdigest(), length
    md5, sha, length = await asyncio.to_thread(digests)

    async def body():
        with opener() as source:
            seen = iter(chunks)

            def read(size):
                data = source.read(size)
                if hashlib.sha256(data).digest() != next(seen, None):
                    raise MediaUnavailable("The file changed while it was being copied; it is copied on a later pass")
                return data
            for piece in encrypted(read):
                yield piece
                await asyncio.sleep(0)
    receipt = await s3.put(name, body(), length, sha, md5, extra)
    if receipts is not None:
        receipt = receipt or {}
        if not receipt.get("last_modified") and hasattr(s3, "head"):
            try:
                metadata = await s3.head(name, receipt.get("version_id"))
                if receipt.get("etag") and metadata.get("etag") != receipt["etag"]:
                    raise ValueError("S3 HEAD differs from the uploaded object ETag")
                if receipt.get("version_id") and metadata.get("version_id") != receipt["version_id"]:
                    raise ValueError("S3 HEAD differs from the uploaded object version")
                receipt = {**receipt, **metadata}
            except (OSError, RouteError, HTTPError) as exc:
                receipt["metadata_error"] = type(exc).__name__
        receipts.append({"name": name, "etag": receipt.get("etag"), "last_modified": receipt.get("last_modified"),
                         "version_id": receipt.get("version_id"), "ciphertext_sha256": sha,
                         "metadata_error": receipt.get("metadata_error"),
                         "time_verification": "provider response recorded by collector; not an independently signed timestamp"})
    return length


class Sent:
    def __init__(self, root, namespace):
        self.namespace = namespace
        self.db = sqlite3.connect(root / "replica.sqlite3")


        self.db.executescript("CREATE TABLE IF NOT EXISTS sent_v2 (namespace TEXT, name TEXT, bytes INTEGER, at TEXT,"
                              " PRIMARY KEY(namespace,name));"
                              "CREATE TABLE IF NOT EXISTS meta_v2 (namespace TEXT, key TEXT, value INTEGER,"
                              " PRIMARY KEY(namespace,key));")

    def has(self, name):
        return self.db.execute("SELECT 1 FROM sent_v2 WHERE namespace=? AND name=?",
                               (self.namespace, name)).fetchone() is not None

    def add(self, name, size):
        self.db.execute("INSERT OR REPLACE INTO sent_v2 VALUES (?,?,?,?)", (self.namespace, name, size, utcnow()))
        self.db.commit()

    def get(self, key):
        row = self.db.execute("SELECT value FROM meta_v2 WHERE namespace=? AND key=?", (self.namespace, key)).fetchone()
        return row[0] if row else 0

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta_v2 VALUES (?,?,?)", (self.namespace, key, value))
        self.db.commit()

    def close(self):
        self.db.close()


def outbox(store, path):
    if not replica_settings(store)["enabled"]:
        return
    folder = store.root / "replica-outbox"
    folder.mkdir(exist_ok=True, mode=0o700)
    target = folder / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + Path(path).name)
    try:
        os.link(path, target)
    except OSError:
        shutil.copy2(path, target)


def client(settings, secrets, network):
    return S3(settings["endpoint"], settings["region"], settings["bucket"], secrets["access_key"],
              secrets["secret_key"], network, settings["path_style"])


def lock_headers(settings, days=None):
    days = settings["retention_days"] if days is None else days
    if not days:
        return {}
    until = datetime.now(timezone.utc) + timedelta(days=days)
    return {"x-amz-object-lock-mode": settings["retention_mode"],
            "x-amz-object-lock-retain-until-date": until.strftime("%Y-%m-%dT%H:%M:%SZ")}


async def require_evidence_lock(s3, settings):
    if not settings.get("evidence"):
        return
    message = "Доказательственная реплика требует Object Lock в режиме Compliance"
    if settings.get("retention_mode") != "COMPLIANCE" or settings.get("retention_days", 0) < 1:
        raise ValueError(message)
    try:
        enabled = (await s3.object_lock()).get("enabled") is True
    except Exception:
        enabled = False
    if not enabled:
        raise ValueError(message)


async def lock_report(s3, name, settings, requested=None, uploaded_at=None, version_id=None):
    try:
        bucket = await s3.object_lock()
    except Exception as exc:
        bucket = {"enabled": None, "default_mode": None, "default_days": None, "error": type(exc).__name__}
    try:
        applied = await s3.retention(name, version_id) if version_id else await s3.retention(name)
    except Exception as exc:
        applied = {"error": type(exc).__name__}
    wanted = bool(settings["retention_days"] or bucket.get("default_days"))
    locked = False
    until = None
    try:


        now = datetime.now(timezone.utc)
        if settings["retention_days"]:
            headers = requested if requested is not None else lock_headers(settings)
            until = datetime.fromisoformat(headers["x-amz-object-lock-retain-until-date"])
            mode = headers["x-amz-object-lock-mode"]
        else:
            until = (uploaded_at or now) + timedelta(days=bucket.get("default_days") or 0)
            mode = bucket.get("default_mode")
        actual = datetime.fromisoformat(applied["retain_until"])
        locked = bool(mode in ("GOVERNANCE", "COMPLIANCE") and applied["mode"] == mode
                      and actual.tzinfo is not None and until.tzinfo is not None
                      and actual > now and actual >= until - timedelta(seconds=1))
    except (TypeError, ValueError, KeyError):
        pass
    return {"bucket_enabled": bucket.get("enabled"), "default_mode": bucket.get("default_mode"),
            "default_days": bucket.get("default_days"), "object": applied,
            "requested": {"mode": settings["retention_mode"], "days": settings["retention_days"],
                          "retain_until": until.isoformat() if until else None}
            if settings["retention_days"] else None,
            "verified": locked if wanted else None, "checked_at": utcnow()}


async def sync(store, vault, network):
    settings, secrets = replica_settings(store), vault.read("replica")
    if not (settings["enabled"] and settings["endpoint"] and settings["bucket"] and secrets.get("access_key")):
        return None
    s3 = client(settings, secrets, network)
    await require_evidence_lock(s3, settings)
    key, base, namespace = replica_context(settings, base64.b64decode(secrets["key"], validate=True),
                                          fingerprint(vault.public_key))
    sent = Sent(store.root, namespace)
    extra = lock_headers(settings)
    done, uploaded, receipts = {"objects": 0, "bytes": 0}, [], []
    started_at = datetime.now(timezone.utc)

    async def send(name, opener, expected_digest=None):
        size = await upload(s3, key, name, opener, extra, expected_digest,
                            recipient_public_key=settings["recipient_public_key"], receipts=receipts)
        if settings["evidence"]:
            receipt = receipts[-1]
            if not all(receipt.get(k) for k in ("etag", "last_modified", "version_id")):
                raise ValueError("Evidence replica requires the uploaded object version, ETag and Last-Modified")
            receipt["object_lock"] = await lock_report(s3, name, settings, extra, started_at, receipt["version_id"])
            if receipt["object_lock"]["verified"] is not True:
                raise ValueError("Object Lock did not confirm Compliance retention for the uploaded version")
        done["bytes"] += size
        done["objects"] += 1
        sent.add(name, size)
        uploaded.append(name)
    error = None
    try:

        while True:
            seq = sent.get("journal_seq")
            events = store.events_after(seq, SEGMENT_EVENTS)
            if not events or all(e["kind"] == "replica.completed" for e in events):
                break
            data = b"".join(canonical(e) + b"\n" for e in events)
            await send(base + "/journal/" + str(events[0]["seq"]).zfill(12) + "-" + str(events[-1]["seq"]).zfill(12)
                       + ".jsonl.tgwr", lambda data=data: io.BytesIO(data))
            sent.set("journal_seq", events[-1]["seq"])

        unavailable = None
        for seq, digest in store.media_saved_after(sent.get("media_seq")):
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Invalid preserved media hash")
            name = base + "/media/" + hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()[:40] + ".tgwr"
            source = store.root / "media" / digest
            if not sent.has(name):
                try:
                    if not source.is_file():
                        raise MediaUnavailable("Preserved media is missing: " + digest)
                    await send(name, lambda source=source: source.open("rb"), digest)
                except MediaUnavailable as exc:

                    unavailable = unavailable or exc
            if not unavailable:
                sent.set("media_seq", seq)

        folder = store.root / "checkpoints"
        for path in sorted([*folder.glob("checkpoint-*.json"), *(folder / "anchors").glob("*")]) if folder.is_dir() else []:
            covered = re.match(r"checkpoint-(\d+)(?:\.|$)", path.name)
            if covered and int(covered[1]) > sent.get("journal_seq"):
                continue
            name = base + "/checkpoints/" + path.relative_to(folder).as_posix() + ".tgwr"
            if path.is_file() and not sent.has(name):
                await send(name, lambda path=path: path.open("rb"))

        queue = store.root / "replica-outbox"
        for path in sorted(queue.glob("*")) if queue.is_dir() else []:
            name = base + "/exports/" + path.name + ".tgwr"
            if not sent.has(name):
                await send(name, lambda path=path: path.open("rb"))
            path.unlink()
        if unavailable:
            raise unavailable
    except Exception as exc:
        error = str(exc)[:200] if isinstance(exc, (ValueError, RouteError)) else type(exc).__name__
    finally:
        journal_seq = sent.get("journal_seq")
        sent.close()
    lock = None
    if uploaded:
        lock = await lock_report(s3, uploaded[0], settings, extra, started_at)
        if lock["verified"] is False and not error:
            error = "Object Lock was requested but the storage did not lock the uploaded objects"
    status = {"at": utcnow(), **done, "journal_seq": journal_seq, "error": error,
              "object_lock": lock or (store.get_setting("replica_last", None) or {}).get("object_lock")}
    if done["objects"] or error:
        store.append("replica.completed", {**status, "destination": settings["endpoint"] + "/" + settings["bucket"]
                                           + "/" + base, "encrypted": True, "uploaded_objects": receipts})
    store.set_setting("replica_last", status)
    if not error:
        store.set_setting("replica_success", {"at": status["at"], "journal_seq": journal_seq})
    return status


async def replica_loop(store, vault, network_config, wakeup, status):
    last = 0.0
    while True:
        with suppress(TimeoutError):
            await asyncio.wait_for(wakeup.wait(), LOOP_SECONDS)
        settings = replica_settings(store)
        if not settings["enabled"]:
            wakeup.clear()
            continue
        if not wakeup.is_set() and time.time() - last < settings["interval_minutes"] * 60:
            continue
        wakeup.clear()
        last = time.time()
        status.update(busy=True, error=None)
        try:
            await sync(store, vault, network_config())
        except Exception as exc:
            status["error"] = type(exc).__name__
            store.append("collector.error", {"operation": "off-site copy", "error_type": type(exc).__name__})
        finally:
            status.update(busy=False, last_pass_at=utcnow(), next_at=next_at(settings["interval_minutes"] * 60))


def key_file(store, vault):
    settings, secrets = replica_settings(store), vault.read("replica")
    workspace_fingerprint = fingerprint(vault.public_key)
    derivation = LEGACY_DERIVATION if settings.get("recipient_public_key") else KEY_DERIVATION
    return {"format": "tgwitness-replica-key-v1", "key": secrets["key"], "endpoint": settings["endpoint"],
            "region": settings["region"], "bucket": settings["bucket"], "path_style": settings["path_style"],
            "prefix": replica_prefix(settings, workspace_fingerprint), "fingerprint": workspace_fingerprint,
            "key_derivation": derivation}


async def restore(keyinfo, access_key, secret_key, out, network=None, recipient_key=None):
    key = derive_key(base64.b64decode(keyinfo["key"], validate=True), keyinfo["fingerprint"],
                     keyinfo.get("key_derivation", LEGACY_DERIVATION))
    s3 = S3(keyinfo["endpoint"], keyinfo["region"], keyinfo["bucket"], access_key, secret_key,
            network or NetworkConfig(kind="direct"), keyinfo["path_style"])
    base, out = keyinfo["prefix"], Path(out)
    if filesystem_link(out):
        raise ValueError("Restore requires an ordinary empty output directory")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("Restore requires an empty output directory")
    out = out.resolve()

    with TemporaryDirectory(prefix=".restore-", dir=out) as scratch:
        stage = Path(scratch)
        result = await restore_objects(s3, keyinfo, key, base, stage, recipient_key)
        for path in stage.iterdir():
            target = out / path.name
            if target.exists() or filesystem_link(target):
                raise ValueError("Restore output changed during verification")
            path.rename(target)
    return result


def filesystem_link(path):
    if path.is_symlink():
        return True
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except FileNotFoundError:
        return False


def restore_path(out, base, name):
    if not name.startswith(base + "/"):
        raise ValueError("Object is outside the requested backup prefix")
    rel = name[len(base) + 1:-len(".tgwr")]
    parts = rel.split("/")
    if (len(parts) < 2 or parts[0] not in ("journal", "media", "checkpoints", "exports")
            or any(not p or p in (".", "..") or p.endswith((".", " ")) or PureWindowsPath(p).is_reserved()
                   or re.search(r'[\\:<>"|?*\x00-\x1f]', p) for p in parts)):
        raise ValueError("Unsafe backup object path: " + name)
    target = out.joinpath(*parts)
    if not target.resolve().is_relative_to(out.resolve()):
        raise ValueError("Backup object escapes the restore directory")
    for parent in (target, *target.parents):
        if parent == out:
            break
        if filesystem_link(parent):
            raise ValueError("Backup object path contains a filesystem link")
    return parts[0], target


async def restore_objects(s3, keyinfo, key, base, out, recipient_key=None):
    segments, counts = [], {"journal": 0, "media": 0, "checkpoints": 0, "exports": 0}
    async for name, _ in s3.list(base + "/"):
        if not name.endswith(".tgwr") or name == base + "/connection-test.tgwr" \
                or name.startswith(base + "/storage/"):
            continue
        kind, target = restore_path(out, base, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with TemporaryDirectory(prefix=".object-", dir=out) as scratch:
            part, clear = Path(scratch) / "encrypted", Path(scratch) / "clear"
            with part.open("wb") as handle:
                async def sink(chunk):
                    handle.write(chunk)
                await s3.get(name, sink)
            with part.open("rb") as encrypted, clear.open("wb") as plain:
                for piece in decrypt(key, name, encrypted.read, recipient_key):
                    plain.write(piece)
                    digest.update(piece)
            if kind == "media":
                target = out / "media" / digest.hexdigest()
            if target.exists():
                raise ValueError("Duplicate backup object destination")
            clear.replace(target)
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "journal":
            segments.append(target)
    expected, events = 1, []
    for path in sorted(segments):
        match = re.fullmatch(r"(\d+)-(\d+)\.jsonl", path.name)
        if not match:
            raise ValueError("Invalid journal segment name")
        first, last = map(int, match.groups())
        if first < 1 or first > expected:
            raise ValueError("Journal segments are not continuous at record " + str(expected))
        data = path.read_bytes()
        records = [json.loads(line) for line in data.splitlines()]
        if (last < first or len(records) != last - first + 1
                or any(r["seq"] != first + i for i, r in enumerate(records))):
            raise ValueError("Journal segment does not match its declared record range")
        for record in records:
            if record["seq"] < expected:
                if record != events[record["seq"] - 1]:
                    raise ValueError("Conflicting journal records in overlapping backup segments")
            else:
                events.append(record)
                expected += 1
    (out / "events.jsonl").write_bytes(b"".join(canonical(event) + b"\n" for event in events))
    checkpoints = sorted((out / "checkpoints").glob("checkpoint-*.json"))
    public = json.loads(checkpoints[-1].read_bytes())["statement"]["public_key"] if checkpoints else None
    if not public or fingerprint(public) != keyinfo["fingerprint"]:
        raise ValueError("No checkpoint signed by the expected key was found in the copy")
    result = verify_events(events, public)
    hashes = {0: "0" * 64, **{e["seq"]: e["hash"] for e in events}}
    for path in checkpoints:
        verify_checkpoint(json.loads(path.read_bytes()), public, result["events"], hashes.get)
    media = set()
    for event in events:
        reference = media_reference(event)
        if reference is None:
            continue
        digest, size = reference
        path = out / "media" / digest
        if not path.is_file() or (size is not None and path.stat().st_size != size):
            raise ValueError("Preserved media is missing or differs from the signed journal: " + digest)
        media.add(digest)
    return {**result, "objects": counts, "checkpoints_verified": len(checkpoints), "media_verified": len(media)}


def main():
    parser = argparse.ArgumentParser(description="Restore and verify a TgWitness off-site copy.")
    parser.add_argument("command", choices=["restore"])
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--recipient-key", type=Path, help="X25519 private key: PEM, raw 32 bytes, or base64")
    args = parser.parse_args()
    access, secret = os.environ.get("TGWITNESS_S3_ACCESS_KEY"), os.environ.get("TGWITNESS_S3_SECRET_KEY")
    if not (access and secret):
        parser.exit(1, "Set TGWITNESS_S3_ACCESS_KEY and TGWITNESS_S3_SECRET_KEY (read access to the bucket).\n")
    try:
        recipient = load_recipient_key(args.recipient_key) if args.recipient_key else None
        result = asyncio.run(restore(json.loads(args.key_file.read_text()), access, secret, args.out, recipient_key=recipient))
    except Exception as exc:
        parser.exit(1, "RESTORE FAILED: " + type(exc).__name__ + ": " + str(exc) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
