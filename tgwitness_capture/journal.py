import hashlib
import os
import sqlite3
import tempfile
import threading
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .format import FORMAT, DOMAIN, canonical, check_events, decode, digest, fingerprint, seal, utcnow


def durable_write(path, data, exclusive=False):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Journal:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.guard = (self.root / ".lock").open("a+b")
        self.guard.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                if not self.guard.read(1):
                    self.guard.write(b"0")
                    self.guard.flush()
                self.guard.seek(0)
                msvcrt.locking(self.guard.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.guard.close()
            raise ValueError("Recorder data directory is already in use") from None
        try:
            self._open()
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            self.guard.close()
            raise

    def _open(self):
        keyfile = self.root / "private-key.bin"
        identity = self.root / "identity.json"
        if not keyfile.exists():
            if identity.exists() or (self.root / "journal.sqlite3").exists():
                raise ValueError("Missing signing key; refusing to replace the observer identity")
            key = Ed25519PrivateKey.generate()
            durable_write(keyfile, key.private_bytes(serialization.Encoding.Raw,
                          serialization.PrivateFormat.Raw, serialization.NoEncryption()), exclusive=True)
        self.key = Ed25519PrivateKey.from_private_bytes(keyfile.read_bytes())
        self.public_key = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.fingerprint = fingerprint(self.public_key)
        if not identity.exists():
            if (self.root / "journal.sqlite3").exists():
                raise ValueError("Missing observer identity")
            durable_write(identity, canonical({"observer_id": str(uuid.uuid4()),
                                              "public_key": self.public_key}), exclusive=True)
        saved = decode(identity.read_bytes())
        if saved["public_key"] != self.public_key:
            raise ValueError("Observer key does not match the saved identity")
        self.observer_id = saved["observer_id"]
        self.session_id = str(uuid.uuid4())
        self.objects = self.root / "objects"
        self.objects.mkdir(exist_ok=True, mode=0o700)
        self.pending = self.root / "pending"
        self.pending.mkdir(exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / "journal.sqlite3", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body BLOB NOT NULL)")
        self.db.commit()
        records = self.events()
        self.head = check_events(records, self.public_key, self.observer_id)
        self.seq = len(records)
        self.last_shutdown_clean = not records or records[-1]["kind"] == "service.stopped"

    def events(self, limit=None):
        with self.lock:
            if limit is not None:
                rows = self.db.execute("SELECT body FROM events ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
                return [decode(row[0]) for row in reversed(rows)]
            return [decode(row[0]) for row in self.db.execute("SELECT body FROM events ORDER BY seq")]

    def append(self, kind, payload=None, artifacts=None, observed_at=None):
        with self.lock:
            body = {"format": FORMAT, "observer_id": self.observer_id, "session_id": self.session_id,
                    "seq": self.seq + 1, "kind": kind, "observed_at": observed_at or utcnow(),
                    "recorded_at": utcnow(), "monotonic_ns": time.monotonic_ns(),
                    "previous_hash": self.head, "payload": payload or {}, "artifacts": artifacts or []}
            event_hash = digest(DOMAIN + b"event\x00" + canonical(body))
            event = {**body, "hash": event_hash, "signature": seal(self.key, "event-hash", event_hash)}
            raw = canonical(event)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("Event exceeds metadata size limit")
            with self.db:
                self.db.execute("INSERT INTO events VALUES (?, ?)", (body["seq"], raw))
            self.seq, self.head = body["seq"], event_hash
            return event

    def artifact(self, data, role, media_type):
        with tempfile.TemporaryFile(dir=self.pending) as source:
            source.write(data)
            source.seek(0)
            return self.artifact_stream(source, role, media_type)

    def artifact_stream(self, source, role, media_type, limit=512 * 1024 * 1024):
        hasher = hashlib.sha256()
        size = 0
        fd, name = tempfile.mkstemp(dir=self.pending, suffix=".part")
        try:
            with os.fdopen(fd, "wb") as target:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > limit:
                        raise ValueError("Artifact exceeds configured size limit")
                    hasher.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            value = hasher.hexdigest()
            destination = self.objects / value
            if destination.exists():
                with destination.open("rb") as existing:
                    if hashlib.file_digest(existing, "sha256").hexdigest() != value:
                        raise ValueError("Existing artifact is corrupt")
                os.unlink(name)
            else:
                os.replace(name, destination)
                sync_directory(self.objects)
            return {"sha256": value, "size": size, "role": role, "media_type": media_type}
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def checkpoint(self, challenge=""):
        with self.lock:
            body = {"format": FORMAT, "observer_id": self.observer_id, "public_key": self.public_key,
                    "seq": self.seq, "head_hash": self.head, "created_at": utcnow(), "challenge": challenge}
            return {"body": body, "signature": seal(self.key, "checkpoint", body)}

    def close(self):
        with self.lock:
            self.db.close()
            self.guard.close()
