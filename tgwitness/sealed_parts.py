"""Bounded encrypted parts for one ZIP, bound by an attested signed manifest."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .sealed_crypto import decrypt_file, encrypt_stream, recipient_id
from .security import private_write
from .store import canonical, utcnow

PART_BYTES = 128 * 1024**2
MAX_PARTS = 8192
MANIFEST = "evidence.parts.json"
SEALED_RESULT = {"phase": "sealed", "delivery": "parts", "subject": MANIFEST}


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            digest.update(block)
    return digest.hexdigest()


class EncryptedParts:
    def __init__(self, output, vault, config, part_bytes=PART_BYTES):
        if not 1 <= part_bytes <= PART_BYTES:
            raise ValueError("Invalid part size")
        self.output, self.vault, self.config, self.part_bytes = Path(output), vault, config, part_bytes
        if (self.output / MANIFEST).exists() or self.output.is_symlink():
            raise ValueError("Choose a new parts output directory")
        self.parts, self.total, self.digest, self.context, self.stream = [], 0, hashlib.sha256(), None, None

    def __enter__(self):
        return self

    def tell(self):
        return self.total

    def open_part(self):
        if len(self.parts) >= MAX_PARTS:
            raise ValueError("Encrypted delivery exceeds the part count limit")
        self.number = len(self.parts) + 1
        self.path = self.output / f"delivery-{self.number:06d}.tgwsealed"
        self.context = encrypt_stream(self.path, self.config["recipient"])
        self.stream = self.context.__enter__()
        self.size, self.part_digest = 0, hashlib.sha256()

    def close_part(self):
        self.context.__exit__(None, None, None)
        self.context, self.stream = None, None
        self.parts.append({"file": f"evidence.zip.part{self.number:06d}", "bytes": self.size,
            "sha256": self.part_digest.hexdigest(), "encrypted_file": self.path.name,
            "encrypted_bytes": self.path.stat().st_size, "encrypted_sha256": file_hash(self.path)})

    def write(self, data):
        view, written = memoryview(data), 0
        while written < len(view):
            if self.stream is None:
                self.open_part()
            piece = view[written:written + min(self.part_bytes - self.size, 1024**2)]
            self.stream.write(piece)
            self.part_digest.update(piece)
            self.digest.update(piece)
            self.size += len(piece)
            self.total += len(piece)
            written += len(piece)
            if self.size == self.part_bytes:
                self.close_part()
        return written

    def flush(self):
        if self.stream:
            self.stream.flush()

    def __exit__(self, kind, error, traceback):
        try:
            if kind:
                if self.context:
                    self.context.__exit__(kind, error, traceback)
                return False
            if self.stream:
                self.close_part()
            if not self.parts:
                raise ValueError("Empty multipart archive")
            statement = {"format": "tgwitness-sealed-parts-v1", "public_key": self.vault.public_key,
                "recipient_sha256": recipient_id(self.config["recipient"]), "context": self.config["context"],
                "created_at": utcnow(), "archive_sha256": self.digest.hexdigest(), "archive_bytes": self.total,
                "parts": self.parts}
            private_write(self.output / MANIFEST, canonical({"statement": statement, "signature": self.vault.sign(canonical(statement))}))
        except BaseException:
            kind = True
            raise
        finally:
            if kind:
                for part in self.parts:
                    (self.output / part["encrypted_file"]).unlink(missing_ok=True)


def load_manifest(path, *, encrypted=False):
    path = Path(path)
    if path.is_symlink() or not 0 < path.stat().st_size <= 8 * 1024**2:
        raise ValueError("Invalid parts manifest file")
    envelope = json.loads(path.read_bytes())
    statement = envelope["statement"]
    if statement.get("format") != "tgwitness-sealed-parts-v1":
        raise ValueError("Unsupported parts manifest")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(statement))
    parts = statement.get("parts")
    if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
        raise ValueError("Invalid part count")
    total = 0
    for number, part in enumerate(parts, 1):
        if (part.get("file") != f"evidence.zip.part{number:06d}"
                or part.get("encrypted_file") != f"delivery-{number:06d}.tgwsealed"
                or type(part.get("bytes")) is not int or not 0 < part["bytes"] <= PART_BYTES
                or type(part.get("encrypted_bytes")) is not int or not part["bytes"] < part["encrypted_bytes"] < part["bytes"] + 16384
                or any(not re.fullmatch(r"[a-f0-9]{64}", part.get(key, "")) for key in ("sha256", "encrypted_sha256"))):
            raise ValueError("Invalid part identity, size or digest")
        total += part["bytes"]
        if encrypted:
            source = path.parent / part["encrypted_file"]
            if source.is_symlink() or source.stat().st_size != part["encrypted_bytes"] or file_hash(source) != part["encrypted_sha256"]:
                raise ValueError("Encrypted part is missing or changed")
    if (type(statement.get("archive_bytes")) is not int or statement["archive_bytes"] != total
            or not re.fullmatch(r"[a-f0-9]{64}", statement.get("archive_sha256", ""))):
        raise ValueError("Parts do not cover the archive")
    return statement


def assemble(manifest, destination, key=None, parts_dir=None, max_gib=64):
    manifest, destination = Path(manifest), Path(destination)
    if destination.exists():
        raise FileExistsError("Choose a new evidence filename")
    statement = load_manifest(manifest)
    if not 1 <= max_gib <= 1024 or statement["archive_bytes"] > max_gib * 1024**3:
        raise ValueError("Archive exceeds the assembly size limit; review --max-gib")
    root = Path(parts_dir) if parts_dir else manifest.parent
    digest, total = hashlib.sha256(), 0
    with tempfile.TemporaryDirectory(prefix="tgwitness-assemble-", dir=destination.parent) as temporary:
        temporary = Path(temporary)
        output = temporary / "evidence.zip"
        with output.open("xb") as outgoing:
            for part in statement["parts"]:
                if key:
                    encrypted = root / part["encrypted_file"]
                    if encrypted.is_symlink() or encrypted.stat().st_size != part["encrypted_bytes"] or file_hash(encrypted) != part["encrypted_sha256"]:
                        raise ValueError("Encrypted part is missing or changed")
                    source = temporary / part["file"]
                    decrypt_file(encrypted, source, key)
                else:
                    source = root / part["file"]
                if source.is_symlink() or source.stat().st_size != part["bytes"]:
                    raise ValueError("Missing or truncated archive part")
                part_digest = hashlib.sha256()
                with source.open("rb") as incoming:
                    for block in iter(lambda: incoming.read(1024**2), b""):
                        part_digest.update(block)
                        digest.update(block)
                        total += len(block)
                        outgoing.write(block)
                if part_digest.hexdigest() != part["sha256"]:
                    raise ValueError("Archive part hash differs from the signed manifest")
                if key:
                    source.unlink()
            if total != statement["archive_bytes"] or digest.hexdigest() != statement["archive_sha256"]:
                raise ValueError("Assembled archive differs from its signed manifest")
            outgoing.flush()
            os.fsync(outgoing.fileno())
        os.link(output, destination)
    return statement


def main():
    parser = argparse.ArgumentParser(description="Assemble an encrypted or locally decrypted multipart evidence ZIP.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--parts-dir", type=Path)
    parser.add_argument("--max-gib", type=int, default=64)
    args = parser.parse_args()
    try:
        assemble(args.manifest, args.out, json.loads(args.key.read_bytes()) if args.key else None, args.parts_dir, args.max_gib)
        print("Assembled evidence.zip. Verify the manifest's GitHub attestation before relying on the archive.")
    except Exception as exc:
        parser.exit(1, "Assembly failed: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
