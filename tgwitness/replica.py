"""Off-site copy: journal, files, checkpoints (with timestamps) and chat exports, encrypted, to S3.

Every object is encrypted before it leaves the machine (AES-256-GCM in 1 MiB chunks; the
object name and a final-chunk flag are authenticated, so objects cannot be swapped or
truncated unnoticed). The key stays in this workspace's vault; download it once and keep it
apart, or the copy cannot be read. Journal records keep their own hash chain and signatures,
so a restored copy is verified exactly like an evidence export.

Restore: python -m tgwitness.replica restore --key-file KEY.json --out DIR
(access keys from TGWITNESS_S3_ACCESS_KEY / TGWITNESS_S3_SECRET_KEY).
"""
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
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .health import next_at
from .netclient import RouteError
from .network import NetworkConfig
from .s3 import S3
from .store import canonical, utcnow
from .verify import fingerprint, verify_checkpoint, verify_events

MAGIC = b"TGWR1"
CHUNK = 1024 * 1024
SEGMENT_EVENTS = 5000
LOOP_SECONDS = 30


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
    return settings["prefix"].strip("/") + "/" + fingerprint(public_key)[:16]


def encrypt(key, name, read, nonce_prefix):
    """Ciphertext pieces for plaintext read in chunks; a shorter (possibly empty) chunk is last."""
    aead, counter, label = AESGCM(key), 0, name.encode()
    yield MAGIC + nonce_prefix
    while True:
        chunk = read(CHUNK)
        last = len(chunk) < CHUNK
        yield aead.encrypt(nonce_prefix + struct.pack(">I", counter), chunk, label + (b"|last" if last else b"|more"))
        counter += 1
        if last:
            return


def decrypt(key, name, read):
    head = read(len(MAGIC) + 8)
    if head[:len(MAGIC)] != MAGIC:
        raise ValueError("Not a TgWitness encrypted object: " + name)
    aead, counter, label, prefix = AESGCM(key), 0, name.encode(), head[len(MAGIC):]
    while True:
        block = read(CHUNK + 16)
        last = len(block) < CHUNK + 16
        yield aead.decrypt(prefix + struct.pack(">I", counter), block, label + (b"|last" if last else b"|more"))
        counter += 1
        if last:
            if read(1):
                raise ValueError("Trailing data after the final chunk: " + name)
            return


def encrypted_size(size):
    return len(MAGIC) + 8 + size + 16 * (size // CHUNK + 1)


class MediaUnavailable(ValueError):
    """A preserved file is missing or no longer matches its signed hash."""


async def upload(s3, key, name, opener, extra, expected_digest=None):
    """Encrypt twice (same nonce prefix): first for Content-MD5/SHA-256, then streaming the upload. The
    second pass refuses any chunk that differs from the first, so one nonce never covers two plaintexts."""
    prefix, chunks = os.urandom(8), []

    def digests():
        md5, sha, plain_hash, length = hashlib.md5(), hashlib.sha256(), hashlib.sha256(), 0
        with opener() as source:
            def read(size):
                data = source.read(size)
                plain_hash.update(data)
                chunks.append(hashlib.sha256(data).digest())
                return data
            for piece in encrypt(key, name, read, prefix):
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
            for piece in encrypt(key, name, read, prefix):
                yield piece
                await asyncio.sleep(0)
    await s3.put(name, body(), length, sha, md5, extra)
    return length


class Sent:
    """What has already been copied, kept apart from the append-only journal."""
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
    """Queue a finished chat export for the off-site copy (hard link; copy if linking fails)."""
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
    """Object Lock request headers for an upload; none when no retention is set."""
    days = settings["retention_days"] if days is None else days
    if not days:
        return {}
    until = datetime.now(timezone.utc) + timedelta(days=days)
    return {"x-amz-object-lock-mode": settings["retention_mode"],
            "x-amz-object-lock-retain-until-date": until.strftime("%Y-%m-%dT%H:%M:%SZ")}


async def lock_report(s3, name, settings, requested=None, uploaded_at=None):
    """What the storage actually did about Object Lock for one uploaded object.

    Some S3-compatible services accept the Object Lock headers and silently ignore them, so the
    retention is read back. verified: True when locked as requested, False when retention was
    requested (or is the bucket default) but the object is not locked, None when none is wanted.
    """
    try:
        bucket = await s3.object_lock()
    except Exception as exc:
        bucket = {"enabled": None, "default_mode": None, "default_days": None, "error": type(exc).__name__}
    try:
        applied = await s3.retention(name)
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
    """Copy everything not yet copied. Stops at the first failure; the next pass continues."""
    settings, secrets = replica_settings(store), vault.read("replica")
    if not (settings["enabled"] and settings["endpoint"] and settings["bucket"] and secrets.get("access_key")):
        return None
    s3, key = client(settings, secrets, network), base64.b64decode(secrets["key"])
    base = workspace_prefix(settings, vault.public_key)
    identity = {k: settings[k] for k in ("endpoint", "region", "bucket", "path_style")}
    identity.update(prefix=base, encryption_key_hash=hashlib.sha256(key).hexdigest())
    sent = Sent(store.root, hashlib.sha256(canonical(identity)).hexdigest())
    extra = lock_headers(settings)
    done, uploaded = {"objects": 0, "bytes": 0}, []
    started_at = datetime.now(timezone.utc)

    async def send(name, opener, expected_digest=None):
        size = await upload(s3, key, name, opener, extra, expected_digest)
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
                                           + "/" + base, "encrypted": True})
    store.set_setting("replica_last", status)
    if not error:  # kept apart so that a failed pass does not hide the last complete one
        store.set_setting("replica_success", {"at": status["at"], "journal_seq": journal_seq})
    return status


async def replica_loop(store, vault, network_config, wakeup, status):
    """status: busy, and of the latest pass its time, error and when the next one is due."""
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
    return {"format": "tgwitness-replica-key-v1", "key": secrets["key"], "endpoint": settings["endpoint"],
            "region": settings["region"], "bucket": settings["bucket"], "path_style": settings["path_style"],
            "prefix": workspace_prefix(settings, vault.public_key), "fingerprint": fingerprint(vault.public_key)}


async def restore(keyinfo, access_key, secret_key, out, network=None):
    """Download, decrypt and verify a copy into out/ (events.jsonl, media/, checkpoints/, exports/)."""
    s3 = S3(keyinfo["endpoint"], keyinfo["region"], keyinfo["bucket"], access_key, secret_key,
            network or NetworkConfig(kind="direct"), keyinfo["path_style"])
    key, base, out = base64.b64decode(keyinfo["key"]), keyinfo["prefix"], Path(out)
    if filesystem_link(out):
        raise ValueError("Restore requires an ordinary empty output directory")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("Restore requires an empty output directory")
    out = out.resolve()

    with TemporaryDirectory(prefix=".restore-", dir=out) as scratch:
        stage = Path(scratch)
        result = await restore_objects(s3, keyinfo, key, base, stage)
        for path in stage.iterdir():
            target = out / path.name
            if target.exists() or filesystem_link(target):
                raise ValueError("Restore output changed during verification")
            path.rename(target)
    return result


def filesystem_link(path):
    """Symlinks and Windows reparse points (including junctions), also on Python 3.11."""
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


async def restore_objects(s3, keyinfo, key, base, out):
    segments, counts = [], {"journal": 0, "media": 0, "checkpoints": 0, "exports": 0}
    async for name, _ in s3.list(base + "/"):
        if not name.endswith(".tgwr") or name == base + "/connection-test.tgwr":
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
                for piece in decrypt(key, name, encrypted.read):
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
        if event["kind"] != "media.saved":
            continue
        payload = event["payload"]
        digest, size = payload.get("media_sha256"), payload.get("size")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid media reference in the signed journal")
        path = out / "media" / digest
        if not path.is_file() or (size is not None and (type(size) is not int or path.stat().st_size != size)):
            raise ValueError("Preserved media is missing or differs from the signed journal: " + digest)
        media.add(digest)
    return {**result, "objects": counts, "checkpoints_verified": len(checkpoints), "media_verified": len(media)}


def main():
    parser = argparse.ArgumentParser(description="Restore and verify a TgWitness off-site copy.")
    parser.add_argument("command", choices=["restore"])
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    access, secret = os.environ.get("TGWITNESS_S3_ACCESS_KEY"), os.environ.get("TGWITNESS_S3_SECRET_KEY")
    if not (access and secret):
        parser.exit(1, "Set TGWITNESS_S3_ACCESS_KEY and TGWITNESS_S3_SECRET_KEY (read access to the bucket).\n")
    try:
        result = asyncio.run(restore(json.loads(args.key_file.read_text()), access, secret, args.out))
    except Exception as exc:
        parser.exit(1, "RESTORE FAILED: " + type(exc).__name__ + ": " + str(exc) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
