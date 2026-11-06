"""Exercise the encrypted handoff with a bounded disk and interrupted writes."""
import errno
import hashlib
import json
from pathlib import Path
import random
import sys
import zipfile

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, sealed_crypto, sealed_package
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_bundle


@pytest.fixture(scope="module")
def recipient():
    return sealed_crypto.keypair()


@pytest.fixture
def capture(tmp_path):
    data, output = tmp_path / "data", tmp_path / "out"
    output.mkdir()
    vault, store = Vault(data), Store(data)
    store.bind(vault)
    try:
        store.append("message.new", {"text": random.Random(7).randbytes(128 * 1024).hex()}, -42, 1)
        evidence.export_file(store, vault, "zip", compact=True).replace(output / "evidence.zip")
    finally:
        store.close()
    (output / "result.json").write_text(json.dumps({"phase": "sealed"}))
    attestation = output / "attestation.jsonl"
    attestation.write_text("Synthetic test attestation; not a GitHub proof.\n")
    return output, attestation


class LimitedOutput:
    def __init__(self, handle, check):
        self.handle, self.check = handle, check

    def __enter__(self):
        self.handle.__enter__()
        return self

    def __exit__(self, *args):
        return self.handle.__exit__(*args)

    def write(self, block):
        self.check(len(block))
        written = self.handle.write(block)
        self.handle.flush()
        return written

    def flush(self):
        self.handle.flush()


def encrypted_writes(monkeypatch, check):
    fdopen = sealed_crypto.os.fdopen
    monkeypatch.setattr(sealed_crypto.os, "fdopen", lambda *a, **kw: LimitedOutput(fdopen(*a, **kw), check))


def assert_delivery(output, attestation, recipient):
    decoded = output.parent / "decoded.zip"
    sealed_crypto.decrypt_file(output / "delivery.tgwsealed", decoded, recipient)
    with zipfile.ZipFile(decoded) as archive:
        assert set(archive.namelist()) == {"evidence.zip", "attestation.jsonl", "README.txt"}
        assert archive.testzip() is None
        assert archive.read("evidence.zip") == (output / "evidence.zip").read_bytes()
        assert archive.read("attestation.jsonl") == attestation.read_bytes()
    verify_bundle(output / "evidence.zip")


def test_handoff_fits_space_for_one_output_copy(capture, recipient, monkeypatch):
    output, attestation = capture
    usage = lambda: sum(p.stat().st_size for p in output.rglob("*") if p.is_file())
    initial = usage()
    capacity = initial + (output / "evidence.zip").stat().st_size + attestation.stat().st_size + 16384
    peaks = []

    def available(length):
        peaks.append(usage() + length)
        if peaks[-1] > capacity:
            raise OSError(errno.ENOSPC, "Synthetic output disk exhausted")

    with monkeypatch.context() as patch:
        encrypted_writes(patch, available)
        sealed_package.package({"recipient": recipient["recipient"]}, output, attestation)
    assert peaks and max(peaks) <= capacity
    assert {p.name for p in output.iterdir()} == {"evidence.zip", "attestation.jsonl", "result.json", "delivery.tgwsealed"}
    assert_delivery(output, attestation, recipient)


@pytest.mark.parametrize("failure", ["disk", "permission", "interrupted"])
def test_failed_handoff_preserves_evidence_and_can_retry(capture, recipient, monkeypatch, failure):
    output, attestation = capture
    original = hashlib.sha256((output / "evidence.zip").read_bytes()).digest()
    error = {"disk": OSError(errno.ENOSPC, "Synthetic full disk"),
             "permission": PermissionError(errno.EACCES, "Synthetic denied write"),
             "interrupted": KeyboardInterrupt()}[failure]
    total = 0

    def fail(length):
        nonlocal total
        total += length
        if total > 16384:
            raise error

    with monkeypatch.context() as patch:
        encrypted_writes(patch, fail)
        with pytest.raises(type(error)):
            sealed_package.package({"recipient": recipient["recipient"]}, output, attestation)
    assert not (output / "delivery.tgwsealed").exists()
    assert hashlib.sha256((output / "evidence.zip").read_bytes()).digest() == original
    assert json.loads((output / "result.json").read_bytes()) == {"phase": "sealed"}
    assert {p.name for p in output.iterdir()} == {"evidence.zip", "attestation.jsonl", "result.json"}
    sealed_package.package({"recipient": recipient["recipient"]}, output, attestation)
    assert_delivery(output, attestation, recipient)


def test_handoff_never_overwrites_existing_delivery(capture, recipient):
    output, attestation = capture
    destination = output / "delivery.tgwsealed"
    destination.write_bytes(b"existing delivery")
    with pytest.raises(FileExistsError):
        sealed_package.package({"recipient": recipient["recipient"]}, output, attestation)
    assert destination.read_bytes() == b"existing delivery"


def test_streaming_handoff_supports_zip64(capture, recipient, monkeypatch):
    output, attestation = capture
    monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 1024)
    sealed_package.package({"recipient": recipient["recipient"]}, output, attestation)
    assert_delivery(output, attestation, recipient)


@pytest.mark.parametrize("size", [0, 1, 2048, 2049])
def test_stream_roundtrip_and_plaintext_limit(tmp_path, recipient, monkeypatch, size):
    monkeypatch.setattr(sealed_crypto, "MAX_BYTES", 2048)
    monkeypatch.setattr(sealed_crypto, "CHUNK", 127)
    destination = tmp_path / "output.tgwsealed"
    plaintext = random.Random(size).randbytes(size)

    def encrypt():
        with sealed_crypto.encrypt_stream(destination, recipient["recipient"]) as writer:
            for offset in range(0, len(plaintext), 73):
                assert writer.tell() == offset
                assert writer.write(plaintext[offset:offset + 73]) == len(plaintext[offset:offset + 73])

    if size > sealed_crypto.MAX_BYTES:
        with pytest.raises(ValueError, match="exceeds"):
            encrypt()
        assert not destination.exists()
    else:
        encrypt()
        decoded = tmp_path / "decoded"
        sealed_crypto.decrypt_file(destination, decoded, recipient)
        assert decoded.read_bytes() == plaintext


@pytest.mark.parametrize("damage", ["ciphertext", "tag", "truncate"])
def test_corrupt_stream_never_releases_plaintext(tmp_path, recipient, damage):
    encrypted = tmp_path / "encrypted"
    with sealed_crypto.encrypt_stream(encrypted, recipient["recipient"]) as writer:
        writer.write(b"synthetic content " * 100)
    content = bytearray(encrypted.read_bytes())
    if damage == "truncate":
        del content[-8:]
    else:
        content[-40 if damage == "ciphertext" else -1] ^= 1
    encrypted.write_bytes(content)
    decoded = tmp_path / "decoded"
    with pytest.raises(InvalidTag):
        sealed_crypto.decrypt_file(encrypted, decoded, recipient)
    assert not decoded.exists() and not list(tmp_path.glob(".tgw-unseal-*"))
