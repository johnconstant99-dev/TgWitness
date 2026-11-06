import base64
import csv
import json
import logging
import os
import secrets
import subprocess
import time
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LOG = logging.getLogger("tgwitness.security")


def windows_sid():
    row = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                         check=True, timeout=30).stdout
    return next(csv.reader([row.strip()]))[1]


def owner_only(root: Path):
    if os.name != "nt":
        try:
            os.chmod(root, 0o700)
        except OSError:
            LOG.warning("Could not restrict %s to its owner; doctor reports its permissions", root)
        return
    try:
        from .windows_acl import owner_acl
        if not owner_acl(root, windows_sid(), repair=True):
            raise OSError("The filesystem did not retain the owner-only ACL")
    except (OSError, subprocess.SubprocessError, IndexError):
        LOG.warning("Could not limit %s to this account; other local accounts may read it", root)


def owner_only_state(root: Path):
    if os.name != "nt":
        mode = root.stat().st_mode & 0o777
        return mode & 0o077 == 0, "mode " + oct(mode)
    try:
        from .windows_acl import owner_acl
        if owner_acl(root, windows_sid()):
            return True, "verified ACLs for this account only"
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return False, "owner-only ACLs could not be verified (FAT/exFAT volumes keep no permissions)"


def private_write(path: Path, data: bytes):
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(6):
        try:
            os.replace(temp, path)
            break
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in (5, 32, 33) or attempt == 5:
                raise
            time.sleep(.01 * 2**attempt)


class Vault:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        key_path = root / "vault.key"
        protected = [root / "credentials.enc", root / "signing.enc", root / "independent_login.enc"]
        external = os.environ.get("TGWITNESS_VAULT_KEY_FILE")
        marker = root / "vault.external.json"
        self.key_mode = "external" if external or marker.exists() else "local"
        if self.key_mode == "external":
            if not external:
                raise RuntimeError("This vault requires TGWITNESS_VAULT_KEY_FILE. Refusing local key replacement.")
            if key_path.exists() or (not marker.exists() and any(p.exists() for p in protected)):
                raise RuntimeError("External keys require a new data directory; existing local vaults are not migrated automatically.")
            source = Path(external).resolve(strict=True)
            if source.is_relative_to(root.resolve()) or source.stat().st_size > 128:
                raise RuntimeError("Provide a small master-key file outside the data directory.")
            master = source.read_bytes().strip()
            Fernet(master)
            if not marker.exists():
                private_write(marker, json.dumps({"format": "tgwitness-external-vault-v1",
                              "salt": base64.b64encode(os.urandom(32)).decode()}).encode())
            config = json.loads(marker.read_bytes())
            salt = base64.b64decode(config["salt"], validate=True)

            if config["format"] not in ("tgwitness-external-vault-v1", "tgwatch-external-vault-v1") or len(salt) != 32:
                raise RuntimeError("Invalid external vault metadata; restore the original file.")
            key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                       info=b"TgWitness external vault v1").derive(base64.urlsafe_b64decode(master))
            self.fernet = Fernet(base64.urlsafe_b64encode(key))
        else:
            if not key_path.exists():
                if any(p.exists() for p in protected):
                    raise RuntimeError("Vault key missing. Restore it from backup; refusing key replacement.")
                private_write(key_path, Fernet.generate_key())
            self.fernet = Fernet(key_path.read_bytes())
        token_path = root / "panel-token.txt"
        if not token_path.exists():
            private_write(token_path, secrets.token_urlsafe(32).encode())
        self.token = os.environ.get("TGWITNESS_TOKEN") or token_path.read_text().strip()
        if len(self.token) < 24:
            raise RuntimeError("TGWITNESS_TOKEN must contain at least 24 characters.")
        signing_path = root / "signing.enc"
        if not signing_path.exists():
            key = Ed25519PrivateKey.generate()
            self.save("signing", {"private_key": base64.b64encode(key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())).decode()})
        key_data = self.read("signing")["private_key"]
        self.signer = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_data))
        self.public_key = base64.b64encode(self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    def read(self, name):
        path = self.root / (name + ".enc")
        if not path.exists():
            return {}
        return json.loads(self.fernet.decrypt(path.read_bytes()))

    def save(self, name, value):
        private_write(self.root / (name + ".enc"),
                      self.fernet.encrypt(json.dumps(value).encode()))

    def sign(self, value: bytes):
        return base64.b64encode(self.signer.sign(value)).decode()


class InstanceLock:
    def __init__(self, root: Path):

        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        owner_only(root)
        self.stream = (root / ".instance.lock").open("a+b")
        self.stream.seek(0)
        self.stream.write(b"0")
        self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise RuntimeError("This data directory is already open. Use one worker.") from None

    def close(self):
        self.stream.close()


class KeyInUse(ValueError):
    pass


class KeyLock:
    def __init__(self, key: bytes, directory: Path | None = None):
        import hashlib
        import tempfile
        directory = directory or Path(tempfile.gettempdir()) / "tgwitness-keys"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = hashlib.sha256(b"tgwitness-session-key:" + key).hexdigest()
        self.stream = (directory / (name + ".lock")).open("a+b")
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise KeyInUse("This Telegram session is already connected by another TgWitness process or workspace "
                           "on this computer. Close it there first: one session key, one connection.") from None

    def close(self):
        self.stream.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Create an external vault master key without printing it.")
    parser.add_argument("command", choices=["create-master-key"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(Fernet.generate_key())
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        parser.exit(1, "Could not create a new key file. Check the directory and do not overwrite an existing key.\n")
    print("Master key created. Protect it separately and set TGWITNESS_VAULT_KEY_FILE to its path.")


if __name__ == "__main__":
    main()
