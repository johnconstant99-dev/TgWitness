import base64
import csv
import json
import logging
import os
import secrets
import subprocess
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
    """The data directory for this account only, also when it existed before. Unix: mode 0700 (files
    inside are then unreachable whatever their own modes). Windows: one explicit entry for this account,
    inherited by everything inside, and no inherited entries for other users; done once per directory."""
    if os.name != "nt":
        try:
            os.chmod(root, 0o700)
        except OSError:
            LOG.warning("Could not restrict %s to its owner; doctor reports its permissions", root)
        return
    marker = root / ".owner-only"
    if marker.exists():
        return
    try:
        sid = windows_sid()
        subprocess.run(["icacls", str(root), "/inheritance:r", "/grant:r", "*" + sid + ":(OI)(CI)F", "/Q"],
                       capture_output=True, check=True, timeout=60)
        if any(root.iterdir()):
            subprocess.run(["icacls", str(root / "*"), "/reset", "/T", "/C", "/Q"], capture_output=True, check=True,
                           timeout=900)
        # FAT and exFAT accept the command and keep no permissions at all: read them back.
        shown = subprocess.run(["icacls", str(root)], capture_output=True, text=True, timeout=60).stdout
        found = subprocess.run(["icacls", str(root), "/findsid", "*" + sid], capture_output=True, text=True,
                               timeout=60).stdout
        if "No permissions are set" in shown or "SID Found" not in found:
            LOG.warning("%s is on a volume without access control (FAT/exFAT): any local account can read its "
                        "keys. Keep the data directory on NTFS", root)
            return
        marker.write_text("Access to this directory is limited to the account that runs TgWitness.\n")
    except (OSError, subprocess.SubprocessError, IndexError):
        LOG.warning("Could not limit %s to this account; other local accounts may read it", root)


def owner_only_state(root: Path):
    """For doctor: whether only this account can read the data directory, as far as it can tell."""
    if os.name != "nt":
        mode = root.stat().st_mode & 0o777
        return mode & 0o077 == 0, "mode " + oct(mode)
    if (root / ".owner-only").exists():
        return True, "explicit entry for this account only"
    return False, "no owner-only entry (a FAT/exFAT volume keeps no permissions)"


def private_write(path: Path, data: bytes):
    """Atomic replacement. Unix permissions are restricted; on Windows the file inherits the data
    directory's owner-only entry (owner_only)."""
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


class Vault:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        key_path = root / "vault.key"
        protected = [root / "credentials.enc", root / "signing.enc"]
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
            Fernet(master)  # Validate before writing a new salt or vault.
            if not marker.exists():
                private_write(marker, json.dumps({"format": "tgwitness-external-vault-v1",
                              "salt": base64.b64encode(os.urandom(32)).decode()}).encode())
            config = json.loads(marker.read_bytes())
            salt = base64.b64decode(config["salt"], validate=True)
            # tgwatch-*: vaults created before the project was renamed.
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
    """One process per data directory; the OS releases the lock after a crash."""
    def __init__(self, root: Path):
        # This runs before Vault. mkdir(mode=0700) cannot tighten an already-created directory: owner_only does.
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
