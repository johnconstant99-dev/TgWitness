"""Recipient encryption for disposable exports; no password or private key on the runner.

RSA-OAEP-SHA256 wraps a fresh AES-256 key. AES-GCM authenticates the complete
header and ciphertext. Large files are streamed; unauthenticated plaintext is
never installed at the requested destination. See docs/SEALED-ACTIONS.md.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"TGWSEAL1\n"
ALGORITHM = "RSA-OAEP-256+A256GCM"
MAX_BYTES = 8 * 1024**3
CHUNK = 1024**2


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def public_key(recipient):
    if not isinstance(recipient, str) or len(recipient) > 2048:
        raise ValueError("Invalid recipient key")
    key = serialization.load_der_public_key(unb64(recipient))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in (3072, 4096) or key.public_numbers().e != 65537:
        raise ValueError("Use a 3072 or 4096 bit RSA recipient key")
    return key


def recipient_id(recipient):
    key = public_key(recipient)
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return {"format": "tgwitness-recipient-key-v1", "recipient": b64(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "private_key": b64(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))}


def private_key(record):
    if record.get("format") != "tgwitness-recipient-key-v1":
        raise ValueError("Invalid private key file")
    key = serialization.load_der_private_key(unb64(record["private_key"]), password=None)
    expected = public_key(record["recipient"])
    if not isinstance(key, rsa.RSAPrivateKey) or key.public_key().public_numbers() != expected.public_numbers():
        raise ValueError("Private and public keys do not match")
    return key


def encrypt_file(source, destination, recipient):
    source, destination = Path(source), Path(destination)
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("Sealed package exceeds 8 GiB")
    key, nonce = os.urandom(32), os.urandom(12)
    header = json.dumps({"algorithm": ALGORITHM, "key": b64(public_key(recipient).encrypt(key, oaep())),
                         "nonce": b64(nonce)}, sort_keys=True, separators=(",", ":")).encode()
    prefix = MAGIC + struct.pack(">I", len(header)) + header
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    # O_EXCL: a failed invocation must never delete or replace another result.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as outgoing, source.open("rb") as incoming:
            outgoing.write(prefix)
            total = 0
            for block in iter(lambda: incoming.read(CHUNK), b""):
                total += len(block)
                if total > MAX_BYTES:
                    raise ValueError("Sealed package exceeds 8 GiB")
                outgoing.write(encryptor.update(block))
            outgoing.write(encryptor.finalize() + encryptor.tag)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def decrypt_file(source, destination, record):
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise FileExistsError("Choose a new output filename")
    if source.stat().st_size > MAX_BYTES + 16384:
        raise ValueError("Sealed package exceeds 8 GiB")
    key = private_key(record)
    temporary = None
    try:
        with source.open("rb") as incoming:
            magic, size = incoming.read(len(MAGIC)), incoming.read(4)
            if magic != MAGIC or len(size) != 4 or not 0 < struct.unpack(">I", size)[0] <= 8192:
                raise ValueError("Invalid sealed package header")
            header = incoming.read(struct.unpack(">I", size)[0])
            info = json.loads(header)
            if set(info) != {"algorithm", "key", "nonce"} or info["algorithm"] != ALGORITHM:
                raise ValueError("Unsupported encryption format")
            nonce = unb64(info["nonce"])
            secret = key.decrypt(unb64(info["key"]), oaep())
            if len(nonce) != 12 or len(secret) != 32:
                raise ValueError("Invalid encryption parameters")
            offset = incoming.tell()
            length = source.stat().st_size - offset - 16
            if length < 0:
                raise ValueError("Truncated sealed package")
            incoming.seek(-16, 2)
            decryptor = Cipher(algorithms.AES(secret), modes.GCM(nonce, incoming.read(16))).decryptor()
            decryptor.authenticate_additional_data(magic + size + header)
            incoming.seek(offset)
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".tgw-unseal-", delete=False) as out:
                temporary = Path(out.name)
                while length:
                    block = incoming.read(min(CHUNK, length))
                    if not block:
                        raise ValueError("Truncated sealed package")
                    length -= len(block)
                    out.write(decryptor.update(block))
                out.write(decryptor.finalize())  # authenticate before exposing the requested output
        created = False
        try:
            fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created = True
            with os.fdopen(fd, "wb") as out, temporary.open("rb") as incoming:
                for block in iter(lambda: incoming.read(CHUNK), b""):
                    out.write(block)
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Generate recipient keys or decrypt a sealed TgWitness package.")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("keygen")
    create.add_argument("key_file", type=Path)
    decrypt = commands.add_parser("decrypt")
    decrypt.add_argument("package", type=Path)
    decrypt.add_argument("--key", type=Path, required=True)
    decrypt.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            record = keypair()
            fd = os.open(args.key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
            print("Public recipient (safe to paste into workflow inputs):\n" + record["recipient"])
        else:
            decrypt_file(args.package, args.out, json.loads(args.key.read_bytes()))
            print("Decrypted. Verify the evidence and attestation before relying on the contents.")
    except Exception as exc:
        parser.exit(1, "Sealed operation failed: " + type(exc).__name__ + "\n")


if __name__ == "__main__":
    main()
