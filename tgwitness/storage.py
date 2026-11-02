"""Verified media offloading. The signed journal stays local and is never rewritten.

An upload alone never authorizes eviction: read back the complete encrypted object,
compare its SHA-256, commit a recovery receipt, rehash the source, then unlink it.
All helpers, credentials and temporary files stay inside the workspace.
"""
import asyncio
import base64
import configparser
import gzip
import hashlib
import hmac
import io
import json
import os
import platform
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import replica
from .security import private_write
from .store import canonical, utcnow
from .verify import fingerprint

VERSION = "1.75.2"
HASHES = {
    "linux-amd64": "349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702",
    "linux-arm64": "7e1e8d69654941b7b7df84ee74c5f7fb09cce7d5496947fb7bf16b55ff427d10",
    "osx-amd64": "574e1f31cf1c464e5fb0325cb66fcbdeaf1efa1802bd9b17f13c256fd74b6561",
    "osx-arm64": "610ab7d48615135dfc60b763858b11a426a0d3d1160c1bb76fb0ae6011b02edd",
    "windows-amd64": "8a9db2bad1dc79a65b3348fd857069598e2aab7cf4d118b77b1df23055aff818",
}
# These backends do not execute an operator-provided shell command. Composition,
# local filesystem and command-driven SFTP backends are deliberately not accepted.
REMOTE_TYPES = {"mega", "drive", "onedrive", "dropbox", "box", "pcloud", "webdav", "b2", "s3",
                "swift", "azureblob", "google cloud storage", "koofr", "yandex", "protondrive", "jottacloud"}
MAX_RECOVERY_OBJECTS = 100000
MAX_MEDIA_BYTES = 32 * 1024**3


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    backend: Literal["s3", "rclone"] = "rclone"
    purpose: Literal["copy", "offload"] = "copy"
    compress: bool = False
    older_than_days: int = Field(default=7, ge=0, le=36500)
    interval_minutes: int = Field(default=60, ge=5, le=1440)
    batch_files: int = Field(default=100, ge=1, le=1000)
    remote_path: str = Field(default="tgwitness", pattern=r"^[A-Za-z0-9._/-]{1,180}$")

    @model_validator(mode="after")
    def relative_folder(self):
        if any(p in ("", ".", "..") for p in self.remote_path.split("/")):
            raise ValueError("Use a relative folder without empty, dot or parent segments.")
        return self


class ObjectReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    format: Literal["tgwitness-storage-object-v1"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bytes: int = Field(ge=0, le=MAX_MEDIA_BYTES)
    object: str = Field(pattern=r"^media/[a-f0-9]{64}-[a-f0-9]{16}\.tgwr$")
    destination: str = Field(pattern=r"^[a-f0-9]{64}$")
    cipher_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cipher_bytes: int = Field(ge=29, le=33 * 1024**3)
    compressed: bool
    verified_at: str = Field(max_length=50)
    evicted: bool = False


def validate_recovery(value, trusted_fingerprint):
    """Validate the complete manifest before touching a key, receipt or file."""
    if not isinstance(value, dict) or value.get("format") != "tgwitness-storage-recovery-v1":
        raise ValueError("Choose a signed TgWitness storage recovery file.")
    try:
        public_key = base64.b64decode(value["public_key"], validate=True)
        signature = base64.b64decode(value["signature"], validate=True)
        if fingerprint(value["public_key"]) != trusted_fingerprint or value["workspace_fingerprint"] != trusted_fingerprint:
            raise ValueError("The recovery file belongs to a different workspace signing key.")
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical({k: v for k, v in value.items() if k != "signature"}))
        key = base64.b64decode(value["key"], validate=True)
        if len(key) != 32:
            raise ValueError("Invalid storage recovery key.")
        Settings.model_validate(value["settings"])
        replica.ReplicaSettings.model_validate(value.get("s3", {}))
        objects = value["objects"]
        if not isinstance(objects, list) or len(objects) > MAX_RECOVERY_OBJECTS:
            raise ValueError("The recovery manifest has too many objects.")
        seen = set()
        for row in objects:
            ObjectReceipt.model_validate(row)
            if not row["object"].startswith("media/" + hmac.new(key, row["sha256"].encode(), hashlib.sha256).hexdigest() + "-"):
                raise ValueError("The recovery key does not match a saved object receipt.")
            if row["sha256"] in seen:
                raise ValueError("The recovery file lists the same file twice.")
            seen.add(row["sha256"])
    except InvalidSignature:
        raise ValueError("The recovery signature does not match. Keep the original file and obtain a new recovery copy.") from None
    except (KeyError, TypeError):
        raise ValueError("The storage recovery file is incomplete.") from None
    return value


def settings(store):
    return Settings.model_validate(store.get_setting("storage", {})).model_dump()


def safe_file(root, digest):
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Invalid media hash.")
    folder, path = root / "media", root / "media" / digest
    if replica.filesystem_link(folder) or replica.filesystem_link(path):
        raise ValueError("Linked media paths cannot be moved or restored.")
    if path.resolve().parent != folder.resolve():
        raise ValueError("Media path leaves this workspace.")
    return path


def file_hash(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def parse_config(text):
    if len(text) > 65536:
        raise ValueError("The rclone configuration is too large.")
    config = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        config.read_string(text)
    except configparser.Error:
        raise ValueError("Paste one rclone remote section, including its [name] header.") from None
    if len(config.sections()) != 1 or config.defaults():
        raise ValueError("Paste exactly one remote section, without DEFAULT settings.")
    remote = config.sections()[0]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", remote):
        raise ValueError("Use letters, numbers, dashes or underscores for the remote name.")
    options = dict(config[remote])
    kind = options.get("type")
    if kind not in REMOTE_TYPES:
        raise ValueError("Choose a supported cloud remote: " + ", ".join(sorted(REMOTE_TYPES)))
    if any(not re.fullmatch(r"[a-z][a-z0-9_]*", k) or any(s in k for s in ("command", "exec", "_file", "_path")) for k in options):
        raise ValueError("Command and external-file options are not accepted in a cloud remote.")
    if options.get("env_auth", "false").lower() not in ("false", "0", "no", ""):
        raise ValueError("Supply this remote's credentials explicitly; host environment credentials are not used.")
    if any(k in options for k in ("shared_credentials_file", "credentials_file", "application_credentials", "credential_process")):
        raise ValueError("External credential providers are not accepted in a cloud remote.")
    return remote, kind


class Receipts:
    def __init__(self, root):
        if replica.filesystem_link(root / "storage.sqlite3"):
            raise ValueError("Linked storage receipts are not accepted.")
        self.db = sqlite3.connect(root / "storage.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS objects (digest TEXT PRIMARY KEY, receipt TEXT NOT NULL, "
                        "evicted INTEGER NOT NULL DEFAULT 0)")

    def get(self, digest):
        row = self.db.execute("SELECT receipt,evicted FROM objects WHERE digest=?", (digest,)).fetchone()
        return {**json.loads(row[0]), "evicted": bool(row[1])} if row else None

    def save(self, receipt, evicted=False):
        self.db.execute("INSERT OR REPLACE INTO objects VALUES (?,?,?)",
                        (receipt["sha256"], json.dumps(receipt), int(evicted)))
        self.db.commit()

    def evict(self, digest, value=True):
        self.db.execute("UPDATE objects SET evicted=? WHERE digest=?", (int(value), digest))
        self.db.commit()

    def count(self):
        return self.db.execute("SELECT count(*),coalesce(sum(evicted),0) FROM objects").fetchone()

    def rows(self):
        return [self.get(row[0]) for row in self.db.execute("SELECT digest FROM objects ORDER BY digest")]

    def import_all(self, rows):
        with self.db:
            for row in rows:
                value = dict(row)
                evicted = value.pop("evicted", False)
                self.db.execute("INSERT OR REPLACE INTO objects VALUES (?,?,?)",
                                (value["sha256"], json.dumps(value), int(evicted)))

    def discard(self, digests):
        with self.db:
            self.db.executemany("DELETE FROM objects WHERE digest=?", ((digest,) for digest in digests))

    def close(self):
        self.db.close()


def target():
    system = {"Windows": "windows", "Darwin": "osx", "Linux": "linux"}.get(platform.system())
    arch = {"AMD64": "amd64", "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    name = f"{system}-{arch}"
    if name not in HASHES:
        raise ValueError("No pinned rclone helper is available for this operating system.")
    return name


def helper(root):
    name = target()
    return root / "helpers" / f"rclone-{VERSION}-{name}" / ("rclone.exe" if name.startswith("windows") else "rclone")


def safe_helper(root):
    path = helper(root)
    if any(replica.filesystem_link(p) for p in (root / "helpers", path.parent, path, path.with_suffix(".sha256"))):
        raise ValueError("Linked helper paths are not accepted.")
    return path


def install(root):
    name = target()
    archive_name = f"rclone-v{VERSION}-{name}"
    url = f"https://downloads.rclone.org/v{VERSION}/{archive_name}.zip"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "TgWitness"}), timeout=60) as response:
        if not response.url.startswith("https://downloads.rclone.org/"):
            raise ValueError("Unexpected rclone download host.")
        content = response.read(80 * 1024 * 1024 + 1)
    if len(content) > 80 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != HASHES[name]:
        raise ValueError("The rclone download does not match its pinned SHA-256.")
    dest = safe_helper(root)
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        entry = bundle.getinfo(archive_name + "/" + dest.name)
        if entry.file_size > 200 * 1024 * 1024:
            raise ValueError("Invalid rclone executable size.")
        executable = bundle.read(entry)
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_write(dest, executable)
    dest.chmod(0o700)
    private_write(dest.with_suffix(".sha256"), hashlib.sha256(executable).hexdigest().encode("ascii"))
    return dest


class Rclone:
    def __init__(self, root, config, folder, network):
        if network.kind != "direct":
            raise ValueError("rclone needs an explicitly selected Direct route for external requests. "
                             "Use S3 storage to follow a SOCKS5 or HTTP route.")
        self.root, self.config, self.folder = root, config, folder
        self.remote, _ = parse_config(config)

    async def run(self, args, sink=None):
        executable = safe_helper(self.root)
        if not executable.is_file():
            raise ValueError("Install the verified rclone helper first.")
        if file_hash(executable) != executable.with_suffix(".sha256").read_text(encoding="ascii").strip():
            raise ValueError("The rclone helper has changed. Install it again.")
        with tempfile.TemporaryDirectory(prefix="storage-", dir=self.root) as temp:
            config = Path(temp) / "rclone.conf"
            private_write(config, self.config.encode("utf-8"))
            env = {k: v for k, v in os.environ.items()
                   if not k.upper().startswith(("RCLONE_", "AWS_", "AZURE_", "GOOGLE_", "B2_", "SWIFT_"))
                   and k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
            process = await asyncio.create_subprocess_exec(str(executable), "--config", str(config), "--cache-dir", temp,
                "--log-level", "ERROR", "--retries", "2", "--low-level-retries", "2", "--contimeout", "15s",
                "--timeout", "60s", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL, env=env, cwd=temp,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            result = bytearray()
            try:
                async with asyncio.timeout(3600):
                    while chunk := await process.stdout.read(1024 * 1024):
                        if sink:
                            await sink(chunk)
                        elif len(result) + len(chunk) <= 1024 * 1024:
                            result.extend(chunk)
                        else:
                            raise ValueError("The storage helper returned too much output.")
                    code = await process.wait()
                    # A refresh may succeed even when the subsequent transfer fails.
                    refreshed = config.read_text(encoding="utf-8")
                    parse_config(refreshed)
                    self.config = refreshed
                    if code:
                        raise ValueError("The storage service refused the operation. Check its credentials and available space.")
                # OAuth refresh tokens are updated by rclone. Preserve the refreshed
                # configuration in the encrypted vault through the caller.
                return bytes(result)
            finally:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 5)
                    except TimeoutError:
                        process.kill()
                        await process.wait()

    def path(self, name):
        return self.remote + ":" + self.folder + "/" + name

    async def put(self, name, path):
        await self.run(["copyto", str(path), self.path(name), "--immutable"])

    async def get(self, name, sink):
        await self.run(["cat", self.path(name)], sink)


class S3Backend:
    def __init__(self, store, vault, network):
        if network.kind not in ("direct", "socks5", "http"):
            raise ValueError("S3 storage needs an external Direct, SOCKS5 or HTTP route. Configure external requests in Connection settings.")
        self.settings, self.secrets = replica.replica_settings(store), vault.read("replica")
        if not self.settings["endpoint"] or not self.settings["bucket"] or not self.secrets.get("access_key") or not self.secrets.get("secret_key"):
            raise ValueError("Configure the S3 destination first.")
        self.client = replica.client(self.settings, self.secrets, network)
        self.prefix = replica.workspace_prefix(self.settings, vault.public_key) + "/storage/"

    async def put(self, name, path):
        sha, md5 = hashlib.sha256(), hashlib.md5()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                sha.update(chunk)
                md5.update(chunk)

        async def body():
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    yield chunk
                    await asyncio.sleep(0)
        headers = replica.lock_headers(self.settings)
        await self.client.put(self.prefix + name, body(), path.stat().st_size, sha.hexdigest(),
                              base64.b64encode(md5.digest()).decode(), headers)
        lock = await replica.lock_report(self.client, self.prefix + name, self.settings, headers)
        if lock["verified"] is False:
            raise ValueError("The storage did not confirm the requested Object Lock retention.")

    async def get(self, name, sink):
        await self.client.get(self.prefix + name, sink)


class Storage:
    def __init__(self, store, vault, network):
        self.store, self.vault, self.network = store, vault, network
        self.busy, self.task = False, None
        self.lock = asyncio.Lock()

    def public(self):
        receipts = Receipts(self.store.root)
        try:
            total, evicted = receipts.count()
        finally:
            receipts.close()
        secret = self.vault.read("storage")
        try:
            installed, helper_problem = safe_helper(self.store.root).is_file(), None
        except ValueError as exc:
            installed, helper_problem = False, str(exc)
        return {"settings": settings(self.store), "busy": self.busy or bool(self.task and not self.task.done()),
                "copied_files": total, "remote_files": evicted,
                "has_config": bool(secret.get("config")), "has_key": bool(secret.get("key")),
                "rclone_installed": installed, "rclone_version": VERSION, "helper_problem": helper_problem,
                "last": self.store.get_setting("storage_last"), "remote_types": sorted(REMOTE_TYPES)}

    def backend(self, config=None):
        saved = config or settings(self.store)
        if saved["backend"] == "s3":
            return S3Backend(self.store, self.vault, self.network())
        return Rclone(self.store.root, self.vault.read("storage").get("config", ""), saved["remote_path"], self.network())

    def destination(self, saved=None, remote_config=None, replica_config=None):
        saved = saved or settings(self.store)
        if saved["backend"] == "s3":
            values = replica_config if replica_config is not None else replica.replica_settings(self.store)
            identity = {k: values[k] for k in ("endpoint", "region", "bucket", "prefix", "path_style")}
        else:
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(remote_config if remote_config is not None else self.vault.read("storage").get("config", ""))
            # Keep OAuth refresh tokens out of the destination identity.
            identity = {section: {k: v for k, v in config[section].items()
                        if k in ("type", "host", "url", "endpoint", "root_folder_id", "team_drive", "drive_id", "user", "account")}
                        for section in config.sections()}
        return hashlib.sha256(canonical({"backend": saved["backend"], "folder": saved["remote_path"], "identity": identity})).hexdigest()

    def obsolete_copies(self, destination, config_replaced=False):
        """Check a destination change while the caller holds the storage lock.

        Receipts describe one configured destination. Only discard an old copy's
        receipt when its original bytes are safely present here; otherwise it may
        be the only recovery path. Keep this read-only check separate from commit.
        """
        receipts = Receipts(self.store.root)
        try:
            # An operator-supplied OAuth token can belong to another account even
            # when its public remote identity is unchanged. Automatic rclone
            # refreshes use save_refreshed and do not retire recovery receipts.
            obsolete = [row for row in receipts.rows() if config_replaced or row["destination"] != destination]
        finally:
            receipts.close()
        for row in obsolete:
            path = safe_file(self.store.root, row["sha256"])
            try:
                if not path.is_file():
                    raise ValueError("Restore all offloaded files before changing their storage destination.")
                if file_hash(path) != row["sha256"]:
                    raise ValueError("A local file differs from its recorded hash. Restore or repair it before changing the storage destination.")
            except OSError:
                raise ValueError("A local file could not be read. Keep its recovery receipt and retry before changing the storage destination.") from None
        return [row["sha256"] for row in obsolete]

    def discard_copies(self, digests):
        receipts = Receipts(self.store.root)
        try:
            receipts.discard(digests)
        finally:
            receipts.close()

    def key(self):
        secret = dict(self.vault.read("storage"))
        if not secret.get("key"):
            receipts = Receipts(self.store.root)
            try:
                if receipts.count()[0]:
                    raise ValueError("The storage key is missing. Import the original recovery file; a replacement key cannot unlock saved files.")
            finally:
                receipts.close()
            secret["key"] = base64.b64encode(secrets.token_bytes(32)).decode()
            self.vault.save("storage", secret)
        key = base64.b64decode(secret["key"], validate=True)
        if len(key) != 32:
            raise ValueError("Invalid storage key. Import its original recovery file.")
        return key

    def save_refreshed(self, backend):
        if isinstance(backend, Rclone):
            secret = dict(self.vault.read("storage"))
            secret["config"] = backend.config
            self.vault.save("storage", secret)

    def backup_has_media(self, digest):
        cfg = replica.replica_settings(self.store)
        if not cfg["enabled"]:
            return True
        secret = self.vault.read("replica")
        if not secret.get("key"):
            return False
        key = base64.b64decode(secret["key"], validate=True)
        base = replica.workspace_prefix(cfg, self.vault.public_key)
        identity = {k: cfg[k] for k in ("endpoint", "region", "bucket", "path_style")}
        identity.update(prefix=base, encryption_key_hash=hashlib.sha256(key).hexdigest())
        sent = replica.Sent(self.store.root, hashlib.sha256(canonical(identity)).hexdigest())
        try:
            return sent.has(base + "/media/" + hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()[:40] + ".tgwr")
        finally:
            sent.close()

    async def check_object(self, backend, name, expected, size):
        checksum, seen = hashlib.sha256(), 0

        async def sink(chunk):
            nonlocal seen
            seen += len(chunk)
            if seen > size:
                raise ValueError("The remote file is larger than the uploaded file.")
            checksum.update(chunk)
        await backend.get(name, sink)
        if seen != size or checksum.hexdigest() != expected:
            raise ValueError("The downloaded copy differs from the uploaded file. The local file is kept.")

    async def test(self):
        async with self.lock:
            backend = self.backend()
            try:
                with tempfile.TemporaryDirectory(prefix="storage-", dir=self.store.root) as folder:
                    path = Path(folder) / "probe"
                    path.write_bytes(secrets.token_bytes(64))
                    name = "tests/" + secrets.token_hex(16)
                    await backend.put(name, path)
                    await self.check_object(backend, name, file_hash(path), path.stat().st_size)
            finally:
                self.save_refreshed(backend)
            return {"ok": True, "download_verified": True}

    async def copy_one(self, backend, digest, source, saved, receipt_db, destination):
        if source.stat().st_size > MAX_MEDIA_BYTES:
            raise ValueError("This attachment exceeds the 32 GiB storage limit. It remains local.")
        key = self.key()  # A readable receipt is insufficient if its decryption key was lost.
        receipt = receipt_db.get(digest)
        if receipt and not receipt["object"].startswith("media/" + hmac.new(key, digest.encode(), hashlib.sha256).hexdigest() + "-"):
            raise ValueError("The storage key does not match this saved receipt. Restore the original recovery key; the local file is kept.")
        if not receipt and receipt_db.count()[0] >= MAX_RECOVERY_OBJECTS:
            raise ValueError("The workspace reached the 100,000-file storage recovery limit. Existing receipts remain recoverable; new files stay local.")
        if receipt and receipt["destination"] == destination and receipt["compressed"] == saved["compress"]:
            # Recheck the remote even if a previous upload succeeded. A stale
            # receipt is never permission to delete the last surviving copy.
            await self.check_object(backend, receipt["object"], receipt["cipher_sha256"], receipt["cipher_bytes"])
        else:
            name = "media/" + hmac.new(key, digest.encode(), hashlib.sha256).hexdigest() + "-" + secrets.token_hex(8) + ".tgwr"
            with tempfile.TemporaryDirectory(prefix="storage-", dir=self.store.root) as folder:
                packed, encrypted = Path(folder) / "packed", Path(folder) / "object"
                original_hash, original_bytes = hashlib.sha256(), 0
                if saved["compress"]:
                    with source.open("rb") as inp, gzip.open(packed, "wb", compresslevel=6) as out:
                        while chunk := inp.read(1024 * 1024):
                            original_hash.update(chunk)
                            original_bytes += len(chunk)
                            out.write(chunk)
                            await asyncio.sleep(0)
                with (packed if saved["compress"] else source).open("rb") as inp, encrypted.open("wb") as out:
                    def read(size):
                        nonlocal original_bytes
                        chunk = inp.read(size)
                        if not saved["compress"]:
                            original_hash.update(chunk)
                            original_bytes += len(chunk)
                        return chunk
                    for chunk in replica.encrypt(key, name, read, secrets.token_bytes(8)):
                        out.write(chunk)
                        await asyncio.sleep(0)
                if original_hash.hexdigest() != digest:
                    raise ValueError("The local file changed during copying. It was not uploaded or removed.")
                receipt = {"format": "tgwitness-storage-object-v1", "sha256": digest,
                           "bytes": original_bytes, "object": name, "destination": destination,
                           "cipher_sha256": file_hash(encrypted), "cipher_bytes": encrypted.stat().st_size,
                           "compressed": saved["compress"], "verified_at": utcnow()}
                await backend.put(name, encrypted)
                await self.check_object(backend, name, receipt["cipher_sha256"], receipt["cipher_bytes"])
            receipt_db.save(receipt)
            self.store.append("storage.copied", receipt)
        if saved["purpose"] == "offload":
            if not self.backup_has_media(digest):
                raise ValueError("The evidence backup still needs this local file. Finish the off-site copy before freeing its space.")
            # Verify the path and bytes immediately before deleting this exact file.
            checked = safe_file(self.store.root, digest)
            if file_hash(checked) != digest:
                raise ValueError("The local file changed during copying. It is kept.")
            receipt_db.evict(digest)  # recoverable if interrupted before unlink
            checked.unlink()
            self.store.append("storage.offloaded", {"sha256": digest, "bytes": receipt["bytes"],
                                                     "object": receipt["object"], "destination": destination})
            return receipt["bytes"]
        return 0

    async def sync(self):
        async with self.lock:
            self.busy = True
            receipts = Receipts(self.store.root)
            backend = None
            result = {"at": utcnow(), "files": 0, "freed_bytes": 0, "error": None}
            try:
                saved, backend = settings(self.store), self.backend()
                destination, visited = self.destination(), set()
                for _, digest in self.store.media_saved_after(0):
                    if digest in visited:
                        continue
                    visited.add(digest)
                    path = safe_file(self.store.root, digest)
                    if not path.is_file() or (saved["older_than_days"] and path.stat().st_mtime > time.time() - saved["older_than_days"] * 86400):
                        continue
                    old = receipts.get(digest)
                    if saved["purpose"] == "copy" and old and old["destination"] == destination:
                        continue
                    if await asyncio.to_thread(file_hash, path) != digest:
                        raise ValueError("A saved file differs from its journal hash. It was not copied or removed.")
                    result["freed_bytes"] += await self.copy_one(backend, digest, path, saved, receipts, destination)
                    result["files"] += 1
                    self.store.set_setting("storage_last", result)
                    if result["files"] >= saved["batch_files"]:
                        break
                self.save_refreshed(backend)
            except Exception as exc:
                result["error"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            finally:
                self.busy = False
                receipts.close()
                self.save_refreshed(backend)
                self.store.set_setting("storage_last", result)
                if result["files"] or result["error"]:
                    self.store.append("storage.completed", result)
            return result

    async def restore(self, digest):
        async with self.lock:
            self.busy = True
            receipts = Receipts(self.store.root)
            backend = None
            try:
                receipt = receipts.get(digest)
                if not receipt:
                    raise ValueError("No saved storage receipt for this file.")
                if receipt["destination"] != self.destination():
                    raise ValueError("Restore the original destination settings before recovering this file.")
                path = safe_file(self.store.root, digest)
                if path.is_file() and file_hash(path) == digest:
                    receipts.evict(digest, False)
                    return path
                if path.exists():
                    raise ValueError("A local file has different bytes. Keep it separately for review before restoring the verified copy.")
                backend = self.backend()
                with tempfile.TemporaryDirectory(prefix="storage-", dir=self.store.root) as folder:
                    ciphertext, packed, restored = [Path(folder) / s for s in ("cipher", "packed", "restored")]
                    seen = 0
                    with ciphertext.open("wb") as out:
                        async def sink(chunk):
                            nonlocal seen
                            seen += len(chunk)
                            if seen > receipt["cipher_bytes"]:
                                raise ValueError("The remote object exceeds its recorded size.")
                            out.write(chunk)
                        await backend.get(receipt["object"], sink)
                    if file_hash(ciphertext) != receipt["cipher_sha256"] or seen != receipt["cipher_bytes"]:
                        raise ValueError("The remote object differs from its saved checksum.")
                    try:
                        with ciphertext.open("rb") as inp, packed.open("wb") as out:
                            for chunk in replica.decrypt(self.key(), receipt["object"], inp.read):
                                out.write(chunk)
                                await asyncio.sleep(0)
                    except InvalidTag:
                        raise ValueError("The storage key does not unlock this file. Import its original recovery file.") from None
                    unpack = gzip.open if receipt["compressed"] else open
                    total = 0
                    with unpack(packed, "rb") as inp, restored.open("wb") as out:
                        while chunk := inp.read(1024 * 1024):
                            total += len(chunk)
                            if total > receipt["bytes"]:
                                raise ValueError("Recovered file exceeds its recorded size.")
                            out.write(chunk)
                    if total != receipt["bytes"] or file_hash(restored) != digest:
                        raise ValueError("Recovered file does not match its signed journal hash.")
                    path.parent.mkdir(exist_ok=True, mode=0o700)
                    safe_file(self.store.root, digest)
                    restored.replace(path)
                receipts.evict(digest, False)
                self.save_refreshed(backend)
                self.store.append("storage.restored", {"sha256": digest, "bytes": receipt["bytes"]})
                return path
            finally:
                self.busy = False
                receipts.close()
                self.save_refreshed(backend)

    async def restore_all(self):
        saved = settings(self.store)
        if saved["enabled"]:
            self.store.set_setting("storage", {**saved, "enabled": False})
            self.store.append("storage.paused", {"reason": "restore_requested"})
        receipts = Receipts(self.store.root)
        try:
            pending = [r["sha256"] for r in receipts.rows() if r["evicted"]]
        finally:
            receipts.close()
        self.store.set_setting("storage_last", {"at": utcnow(), "operation": "restore", "files": 0, "pending": len(pending), "error": None})
        for index, digest in enumerate(pending):
            await self.restore(digest)
            self.store.set_setting("storage_last", {"at": utcnow(), "operation": "restore", "files": index + 1,
                                                    "pending": len(pending) - index - 1, "error": None})
        return {"restored": len(pending)}

    def require_local_media(self):
        receipts = Receipts(self.store.root)
        try:
            missing = sum(1 for row in receipts.rows() if row["evicted"] and not safe_file(self.store.root, row["sha256"]).is_file())
        finally:
            receipts.close()
        if missing:
            raise ValueError(f"{missing} preserved files are in remote storage. Open Storage → Restore all files, "
                             "then create a full export with its attachments.")

    def recovery(self):
        receipts = Receipts(self.store.root)
        try:
            if receipts.count()[0] > MAX_RECOVERY_OBJECTS:
                raise ValueError("This workspace exceeds the recovery-file object limit; retain a full workspace backup before offloading more files.")
            value = {"format": "tgwitness-storage-recovery-v1", "workspace_fingerprint": fingerprint(self.vault.public_key),
                    "public_key": self.vault.public_key,
                    "settings": settings(self.store), "key": base64.b64encode(self.key()).decode(),
                    "s3": replica.replica_settings(self.store) if settings(self.store)["backend"] == "s3" else {},
                    "objects": receipts.rows(), "instructions": "Keep this file apart. Restore the destination credentials "
                    "and import this recovery file in Storage, then restore all files before a full export. "
                    "For a lost workspace use python -m tgwitness.storage recover --help. "
                    "Credentials are not included. This file contains the storage decryption key; keep it private."}
            value["signature"] = self.vault.sign(canonical(value))
            return value
        finally:
            receipts.close()

    def import_recovery(self, value):
        validate_recovery(value, fingerprint(self.vault.public_key))
        secret = dict(self.vault.read("storage"))
        if secret.get("key") and secret["key"] != value["key"]:
            raise ValueError("This workspace already has a different storage key. Recover into a separate folder with the recovery command.")
        destinations = {row["destination"] for row in value["objects"]}
        if len(destinations) > 1:
            raise ValueError("This recovery file contains several storage destinations. Use the original recovery file for each destination.")
        destination = next(iter(destinations), None) or self.destination(value["settings"],
            replica_config=replica.ReplicaSettings.model_validate(value.get("s3", {})).model_dump())
        # Import also changes the configured destination. A valid older recovery
        # file must not strand newer, remote-only files missing from that file.
        obsolete = self.obsolete_copies(destination)
        current = Receipts(self.store.root)
        try:
            # A receipt for the same plaintext may reference another destination;
            # never overwrite its only recovery path during an import.
            for row in value["objects"]:
                existing = current.get(row["sha256"])
                if existing and existing["object"] != row["object"] and existing["evicted"]:
                    raise ValueError("Restore the workspace's existing offloaded files before importing different receipts.")
            current.discard(obsolete)
            secret["key"] = value["key"]
            self.vault.save("storage", secret)
            self.store.set_setting("storage", {**value["settings"], "enabled": False})
            if value["settings"]["backend"] == "s3":
                self.store.set_setting("replica", {**value["s3"], "enabled": False})
            current.import_all([{**row, "evicted": not safe_file(self.store.root, row["sha256"]).is_file()}
                                for row in value["objects"]])
            self.store.append("storage.recovery_imported", {"files": len(value["objects"])})
        finally:
            current.close()
        return self.public()

    async def loop(self):
        while True:
            await asyncio.sleep(30)
            saved = settings(self.store)
            last = self.store.get_setting("storage_last", {})
            due = not last.get("at") or time.time() - self.store.get_setting("storage_attempt", 0) >= saved["interval_minutes"] * 60
            if saved["enabled"] and due and not self.lock.locked() and not (self.task and not self.task.done()):
                self.store.set_setting("storage_attempt", time.time())
                await self.sync()


async def recover_directory(value, trusted_fingerprint, credentials, output, install_helper=True):
    """Recover attachments after workspace loss, without inventing a replacement journal."""
    from .network import NetworkConfig
    from .security import owner_only
    validate_recovery(value, trusted_fingerprint)
    if output.exists() or replica.filesystem_link(output):
        raise ValueError("Choose a new, empty output directory. Existing folders are never replaced.")
    if value["settings"]["backend"] == "rclone":
        parse_config(credentials)
        vault_data = {"storage": {"key": value["key"], "config": credentials}}
    else:
        try:
            config = json.loads(credentials)
            if set(config) != {"access_key", "secret_key"} or not all(isinstance(s, str) and s for s in config.values()):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError('Supply an S3 JSON credentials file with "access_key" and "secret_key".') from None
        vault_data = {"storage": {"key": value["key"]}, "replica": config}
    output.mkdir(parents=True, mode=0o700)
    owner_only(output)

    class RecoveryStore:
        root = output
        values = {"storage": {**value["settings"], "enabled": False}, "replica": value.get("s3", {})}

        def get_setting(self, name, default=None):
            return self.values.get(name, default)

        def set_setting(self, name, data):
            self.values[name] = data

        def append(self, kind, payload):
            # This is a local recovery log, explicitly not the original signed journal.
            with (output / "recovery-log.jsonl").open("ab") as log:
                log.write(canonical({"at": utcnow(), "kind": kind, "payload": payload, "signed": False}) + b"\n")

    class RecoveryVault:
        public_key = value["public_key"]

        def read(self, name):
            return vault_data.get(name, {})

        def save(self, name, data):
            vault_data[name] = data

    manager = Storage(RecoveryStore(), RecoveryVault(), lambda: NetworkConfig(kind="direct"))
    if any(row["destination"] != manager.destination() for row in value["objects"]):
        raise ValueError("The supplied credentials/configuration describes a different remote. Use the original remote configuration.")
    receipts = Receipts(output)
    try:
        receipts.import_all([{**row, "evicted": True} for row in value["objects"]])
    finally:
        receipts.close()
    private_write(output / "storage-recovery.json", canonical(value))
    if value["settings"]["backend"] == "rclone" and install_helper:
        await asyncio.to_thread(install, output)
    return await manager.restore_all()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Recover original attachment bytes using a signed storage recovery file.")
    parser.add_argument("command", choices=["recover"])
    parser.add_argument("--recovery", required=True, type=Path, help="Private, signed storage recovery JSON")
    parser.add_argument("--fingerprint", required=True, help="Workspace SHA-256 signing-key fingerprint kept separately")
    parser.add_argument("--credentials", required=True, type=Path, help="Original rclone remote section, or S3 access_key/secret_key JSON")
    parser.add_argument("--output", required=True, type=Path, help="New directory for recovered files; existing directories are refused")
    args = parser.parse_args()
    try:
        if args.recovery.stat().st_size > 64 * 1024**2 or args.credentials.stat().st_size > 65536:
            raise ValueError("The recovery or credentials file exceeds its size limit.")
        value = json.loads(args.recovery.read_text(encoding="utf-8"))
        result = asyncio.run(recover_directory(value, args.fingerprint, args.credentials.read_text(encoding="utf-8"), args.output))
        print(f"Recovered {result['restored']} files into {args.output / 'media'}. Original journal and signing keys are not recreated.")
    except (ValueError, OSError, TimeoutError) as exc:
        parser.exit(1, "Recovery stopped: " + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__) + "\n")


if __name__ == "__main__":
    main()
