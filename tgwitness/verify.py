# TgWitness verifier sources SHA-256: 7b897e9629250a09e5cc20774e9960a5c09e77e99cdf52d7127e11fc34a37c3b
"""Standalone verifier"""
import argparse
import base64
import bisect
import hashlib
import io
import json
import math
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import ocsp

FIELDS = ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id",
          "actor_id", "payload", "previous_hash")


OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAX_UNCOMPRESSED_GIB = 4


MAX_MEMBERS = 500_000
MAX_MANIFEST_BYTES = 64 * 1024**2
MAX_SMALL_MEMBER_BYTES = 16 * 1024**2
MAX_RECORD_BYTES = 64 * 1024**2
MAX_JSON_BYTES = 256 * 1024**2
OTS_PENDING, OTS_BITCOIN = bytes.fromhex("83dfe30d2ef90c8e"), bytes.fromhex("0588960d73d71901")
SEAL_OPEN = b'<script type="application/tgwitness-seal+json" id="tgwitness-seal">'
SEAL_CLOSE = b"</script></body></html>\n"
SEAL_WINDOW = 1024 * 1024
DRAND_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_GENESIS, DRAND_PERIOD = 1692803367, 3
DRAND_RELAYS = ("https://drand.cloudflare.com", "https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh")
DRAND_CHECK_LIMIT = 100
GATEWAY_FIELDS = ("at", "name", "type", "rcode", "decision", "colo")


class VerifierTooOld(ValueError):
    def __init__(self, detail=""):
        super().__init__("The archive signature is valid, but this verifier is older than the archive format" +
                         (": " + detail if detail else ""))


class CheckUnavailable(Exception):
    pass


def safe_text(value):
    text = str(value)
    text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))", "", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)
    return re.sub("[\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]",
                  lambda match: "\\u%04x" % ord(match.group()), text)


def authenticate_statement(value, key_field="public_key"):
    statement = value["statement"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(statement[key_field], validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    return statement


def validate_server_hashes(value):
    if (not isinstance(value, dict) or value.get("format") != "telegram-file-hashes-v1"
            or value.get("algorithm") != "sha256"
            or value.get("status") not in ("complete", "partial", "unavailable")
            or type(value.get("downloaded_bytes")) is not int or value["downloaded_bytes"] != 0):
        raise ValueError("Invalid Telegram file-hash manifest")
    ranges, size, covered = value.get("ranges"), value.get("expected_bytes"), value.get("covered_bytes")
    if (not isinstance(ranges, list) or len(ranges) > 65536 or type(covered) is not int or covered < 0
            or size is not None and (type(size) is not int or size <= 0)):
        raise ValueError("Invalid file-hash coverage")
    info = value.get("representation")
    if info is not None and (not isinstance(info, dict) or info.get("kind") not in ("photo", "document")
            or type(info.get("id")) is not int or not isinstance(info.get("variant"), str)
            or info.get("bytes") != size or any(key in info for key in ("access_hash", "file_reference"))):
        raise ValueError("Invalid file-hash representation")
    offset = 0
    for part in ranges:
        if (not isinstance(part, dict) or type(part.get("offset")) is not int
                or type(part.get("length")) is not int or part["offset"] != offset
                or not 0 < part["length"] < 2**31 or not isinstance(part.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", part["sha256"])
                or size is None or offset >= size):
            raise ValueError("Invalid, overlapping or discontinuous file-hash range")
        offset = min(size, offset + part["length"])
    if covered != offset:
        raise ValueError("File-hash coverage differs from recorded ranges")
    if value["status"] == "complete" and (not info or size is None or offset != size or not ranges):
        raise ValueError("Incomplete file hashes claim complete coverage")
    if value["status"] == "partial" and (not info or size is None or not 0 < offset < size):
        raise ValueError("Invalid partial file-hash coverage")
    if value["status"] == "unavailable" and (offset or ranges):
        raise ValueError("Unavailable file hashes claim covered bytes")
    return value


def ends_at_directory(archive):
    handle, position = archive.fp, archive.fp.tell()
    try:
        handle.seek(0, 2)
        end = handle.tell()
        if end < 22:
            return False
        handle.seek(end - 22)
        return handle.read(4) == b"PK\x05\x06"
    finally:
        handle.seek(position)


def contiguous(archive, infos):
    handle, start = archive.fp, archive.fp.tell()
    try:
        position = 0
        for info in sorted(infos, key=lambda item: item.header_offset):
            if info.header_offset != position:
                raise ValueError("Archive has bytes between its members")
            handle.seek(position)
            header = handle.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                raise ValueError("Archive member header is damaged")
            name_length, extra_length = struct.unpack("<HH", header[26:30])
            extra = handle.read(name_length + extra_length)[name_length:]
            wide, at = False, 0
            while at + 4 <= len(extra):
                field, length = struct.unpack("<HH", extra[at:at + 4])
                wide, at = wide or field == 1, at + 4 + length
            position += 30 + name_length + extra_length + info.compress_size
            if info.flag_bits & 8:
                handle.seek(position)
                signed = handle.read(4) == b"PK\x07\x08"
                position += (4 if signed else 0) + (20 if wide else 12)
        if position != archive.start_dir:
            raise ValueError("Archive has bytes between its members")
    finally:
        handle.seek(start)


def open_archive(path, max_gib=None):
    limit = MAX_UNCOMPRESSED_GIB if max_gib is None else max_gib
    if type(limit) not in (int, float) or not math.isfinite(limit) or limit <= 0:
        raise ValueError("Archive size limit must be a positive finite number of GiB")
    archive = zipfile.ZipFile(path)
    try:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError("Archive has more members than the verifier accepts")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate ZIP members")
        if infos and min(info.header_offset for info in infos) != 0:
            raise ValueError("Archive has data before its first member")
        contiguous(archive, infos)
        if archive.comment:
            raise ValueError("Archive carries bytes in its trailing comment")
        if not ends_at_directory(archive):
            raise ValueError("Archive has data after its central directory")
        if sum(info.file_size for info in infos) > limit * 1024**3:
            raise ValueError("Bundle exceeds the verifier's size limit; raise it with --max-gib")
    except BaseException:
        archive.close()
        raise
    return archive


def read_member(archive, name, limit=MAX_SMALL_MEMBER_BYTES):
    if archive.getinfo(name).file_size > limit:
        raise ValueError(name + " exceeds the verifier's size limit for this member")
    with archive.open(name) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(name + " exceeds the verifier's size limit for this member")
    return data


def unique_keys(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Signed JSON contains a duplicate key")
    return value


def strict_json(data):
    return json.loads(data, object_pairs_hook=unique_keys)


def read_manifest(archive):
    manifest = strict_json(read_member(archive, "manifest.json", MAX_MANIFEST_BYTES))
    Ed25519PublicKey.from_public_bytes(base64.b64decode(manifest["public_key"], validate=True)).verify(
        base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
    return manifest


def member_digest(archive, name):
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_lines(stream):
    for line in iter(lambda: stream.readline(MAX_RECORD_BYTES + 1), stream.read(0)):
        if len(line) > MAX_RECORD_BYTES:
            raise ValueError("A record exceeds the verifier's size limit")
        yield line


def read_json_file(path):
    path = Path(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(path.name + " exceeds the verifier's size limit")
    return strict_json(path.read_text(encoding="utf-8"))


import getpass


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


PW_MAGIC = b"TGWPW1\n"
PW_CHUNK = 1024 * 1024
PW_CONTEXT = b"tgwitness-password-v1|"
PW_NAME_LIMIT = 1024


def _pw_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


def _pw_read(stream, size):
    value = stream.read(size)
    if len(value) != size:
        raise ValueError("Truncated password-encrypted file")
    return value


def _pw_record(stream, limit):
    size = int.from_bytes(_pw_read(stream, 4), "big")
    if not 16 <= size <= limit + 16:
        raise ValueError("Invalid password-encrypted record length")
    return _pw_read(stream, size)


def _pw_nonce(prefix, counter):
    if counter >= 2**32:
        raise ValueError("Password-encrypted file exceeds the chunk limit")
    return prefix + counter.to_bytes(4, "big")


def _pw_name(value):
    name = value.encode("utf-8")
    if (not name or len(name) > PW_NAME_LIMIT or value in (".", "..")
            or any(ord(char) < 32 or ord(char) == 127 or char in "/\\" for char in value)):
        raise ValueError("Use a plain filename for the password-encrypted content")
    return name


def _pw_output(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def encrypt_password_file(source, destination, password, inner_name=None):
    source, destination = Path(source), Path(destination)
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password of 12 to 256 characters")
    name = _pw_name(inner_name or source.name)
    salt, prefix = os.urandom(16), os.urandom(8)
    cipher = AESGCM(_pw_key(password, salt))
    created = False
    try:
        with source.open("rb") as plain, _pw_output(destination) as output:
            created = True
            output.write(PW_MAGIC + salt + prefix)
            metadata = cipher.encrypt(_pw_nonce(prefix, 0), name, PW_CONTEXT + b"name")
            output.write(len(metadata).to_bytes(4, "big") + metadata)
            counter = 1
            while True:
                data = plain.read(PW_CHUNK)
                last = len(data) < PW_CHUNK
                aad = PW_CONTEXT + name + (b"|last" if last else b"|more")
                record = cipher.encrypt(_pw_nonce(prefix, counter), data, aad)
                output.write(len(record).to_bytes(4, "big") + record)
                if last:
                    break
                counter += 1
        return destination
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def decrypt_password_file(source, destination, password):
    source, destination = Path(source), Path(destination)
    with source.open("rb") as encrypted, tempfile.TemporaryFile(dir=destination.parent) as plain:
        if _pw_read(encrypted, len(PW_MAGIC)) != PW_MAGIC:
            raise ValueError("Not a TgWitness password-encrypted file")
        salt, prefix = _pw_read(encrypted, 16), _pw_read(encrypted, 8)
        cipher = AESGCM(_pw_key(password, salt))
        name = cipher.decrypt(_pw_nonce(prefix, 0), _pw_record(encrypted, PW_NAME_LIMIT), PW_CONTEXT + b"name")
        try:
            _pw_name(name.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid encrypted filename") from exc
        counter = 1
        while True:
            record = _pw_record(encrypted, PW_CHUNK)
            last = len(record) < PW_CHUNK + 16
            aad = PW_CONTEXT + name + (b"|last" if last else b"|more")
            data = cipher.decrypt(_pw_nonce(prefix, counter), record, aad)
            plain.write(data)
            if last:
                if encrypted.read(1):
                    raise ValueError("Trailing data after password-encrypted content")
                break
            counter += 1
        plain.seek(0)
        created = False
        try:
            with _pw_output(destination) as output:
                created = True
                shutil.copyfileobj(plain, output, PW_CHUNK)
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise
    return destination


def password_command(argv):
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="verify.py unseal-password", description="Open a .tgwpw export; verify the decrypted evidence separately.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="New output file; existing files are never overwritten.")
    parser.add_argument("--password-stdin", action="store_true", help="Read one UTF-8 password line from standard input instead of prompting.")
    args = parser.parse_args(argv)
    password = sys.stdin.readline().rstrip("\r\n") if args.password_stdin else getpass.getpass("Export password: ")
    try:
        decrypt_password_file(args.source, args.out, password)
    except Exception as exc:
        parser.exit(1, "Could not decrypt the export: " + type(exc).__name__ + "\n")
    print("Export decrypted. Run verification on the resulting evidence separately.")
QUALIFIED_TSU = {
    "8751fca3d49938f02aaea3d69983adf3d9f324447b4c00b817c3900198c0fbfd": "EC1 TSU 2021",
    "3917e4995093954bc162568c7188c00a222023166824480e8f84a4e1f3441dc1": "EC2 TSU 2021",
    "61726c187889a606dda86821a1faf3c5ff5f4a116254a2325893655c7e45f64f": "TSU 202301",
    "e69a32ea707c71c1633f7c9cbfc60f902c50081d97473163ebf7098d5df36f30": "TSU 202302",
}
QUALIFIED_PROVIDER = "FPS Policy and Support - BOSA, Kingdom of Belgium"
QUALIFIED_LIST = "https://tsl.belgium.be/tsl-be.xml"
QC_STATEMENTS, QC_COMPLIANCE = "1.3.6.1.5.5.7.1.3", bytes.fromhex("0604008e460101")


def der(data, offset):
    tag, length, start = data[offset], data[offset + 1], offset + 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4:
            raise ValueError("Unsupported DER length")
        length, start = int.from_bytes(data[start:start + count], "big"), start + count
    if start + length > len(data):
        raise ValueError("Truncated DER")
    return tag, start, start + length


def children(data, start, end):
    found, offset = [], start
    while offset < end:
        tag, value_start, value_end = der(data, offset)
        if value_end > end:
            raise ValueError("Truncated DER")
        found.append((tag, offset, value_start, value_end))
        offset = value_end
    return found


def oid(data, start, end):
    parts, value = [], 0
    for byte in data[start:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if not parts:
        raise ValueError("Empty object identifier")
    first = min(parts[0] // 40, 2)
    return ".".join(map(str, [first, parts[0] - 40 * first] + parts[1:]))


SIGNED_DATA, TST_INFO = "1.2.840.113549.1.7.2", "1.2.840.113549.1.9.16.1.4"
CONTENT_TYPE, MESSAGE_DIGEST = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"
SIGNING_CERTIFICATE, SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.12", "1.2.840.113549.1.9.16.2.47"
DIGESTS = {"2.16.840.1.101.3.4.2.1": hashes.SHA256, "2.16.840.1.101.3.4.2.2": hashes.SHA384,
           "2.16.840.1.101.3.4.2.3": hashes.SHA512}
RSA_SIGNATURES = {"1.2.840.113549.1.1.1": None, "1.2.840.113549.1.1.11": hashes.SHA256,
                  "1.2.840.113549.1.1.12": hashes.SHA384, "1.2.840.113549.1.1.13": hashes.SHA512}
ECDSA_SIGNATURES = {"1.2.840.10045.4.3.2": hashes.SHA256, "1.2.840.10045.4.3.3": hashes.SHA384,
                    "1.2.840.10045.4.3.4": hashes.SHA512}


def timestamp_token(reply):
    tag, start, end = der(reply, 0)
    if tag != 0x30 or end != len(reply):
        raise ValueError("Not an RFC 3161 timestamp reply")
    parts = children(reply, start, end)
    status_info = children(reply, parts[0][2], parts[0][3]) if parts and parts[0][0] == 0x30 else []
    if not status_info or status_info[0][0] != 0x02:
        raise ValueError("Not an RFC 3161 timestamp reply")
    status = int.from_bytes(reply[status_info[0][2]:status_info[0][3]], "big")
    if status not in (0, 1):
        raise ValueError("The timestamp authority refused the request (status " + str(status) + ")")
    if len(parts) != 2 or parts[1][0] != 0x30:
        raise ValueError("The timestamp reply carries no token")
    content = children(reply, parts[1][2], parts[1][3])
    if len(content) != 2 or content[0][0] != 0x06 or oid(reply, *content[0][2:]) != SIGNED_DATA or content[1][0] != 0xA0:
        raise ValueError("The timestamp token is not signed data")
    signed_tag, signed_start, signed_end = der(reply, content[1][2])
    signed = children(reply, signed_start, signed_end) if signed_tag == 0x30 else []
    if len(signed) < 4 or signed[2][0] != 0x30 or signed[-1][0] != 0x31:
        raise ValueError("The timestamp token is not signed data")
    encapsulated = children(reply, signed[2][2], signed[2][3])
    if len(encapsulated) != 2 or oid(reply, *encapsulated[0][2:]) != TST_INFO or encapsulated[1][0] != 0xA0:
        raise ValueError("The timestamp token does not hold a TSTInfo")
    info_tag, info_start, info_end = der(reply, encapsulated[1][2])
    if info_tag != 0x04:
        raise ValueError("The timestamp token does not hold a TSTInfo")
    certificates = []
    for tag, _, value_start, value_end in signed[3:-1]:
        if tag == 0xA0:
            certificates += [reply[offset:stop] for _, offset, _, stop in children(reply, value_start, value_end)]
    signers = children(reply, signed[-1][2], signed[-1][3])
    if len(signers) != 1:
        raise ValueError("The timestamp token must have exactly one signer")
    return {"status": status, "tst": reply[info_start:info_end], "certificates": certificates,
            "signer": signers[0], "reply": reply}


def generalized_time(raw):
    found = re.fullmatch(rb"(\d{14})(?:\.\d{1,6})?Z", raw)
    if not found:
        raise ValueError("The timestamp time is not a UTC GeneralizedTime")
    return datetime.strptime(found[1].decode(), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def tst_info(tst):
    tag, start, end = der(tst, 0)
    items = children(tst, start, end) if tag == 0x30 and end == len(tst) else []
    if len(items) < 5 or [t for t, *_ in items[:5]] != [0x02, 0x06, 0x30, 0x02, 0x18]:
        raise ValueError("Malformed TSTInfo")
    imprint = children(tst, items[2][2], items[2][3])
    algorithm = children(tst, imprint[0][2], imprint[0][3])
    if len(imprint) != 2 or imprint[1][0] != 0x04 or not algorithm or algorithm[0][0] != 0x06:
        raise ValueError("Malformed TSTInfo")
    nonce = next((int.from_bytes(tst[s:e], "big", signed=True) for t, _, s, e in items[5:] if t == 0x02), None)
    return {"algorithm": oid(tst, *algorithm[0][2:]), "hash": tst[imprint[1][2]:imprint[1][3]],
            "time": generalized_time(tst[items[4][2]:items[4][3]]), "nonce": nonce}


def query_nonce(query):
    _, start, end = der(query, 0)
    return next((int.from_bytes(query[s:e], "big", signed=True) for t, _, s, e in children(query, start, end)[2:]
                 if t == 0x02), None)


def timestamp_reply_summary(reply, digest, query=None):
    token = timestamp_token(reply)
    info = tst_info(token["tst"])
    if info["algorithm"] != "2.16.840.1.101.3.4.2.1" or info["hash"] != digest:
        raise ValueError("The timestamp does not cover this checkpoint")
    if query is not None and info["nonce"] != query_nonce(query):
        raise ValueError("The timestamp nonce differs from the request")
    return {"status": token["status"], "time": info["time"].strftime("%Y-%m-%dT%H:%M:%SZ")}


def signed_attributes(reply, start, end):
    found = {}
    for _, _, s, e in children(reply, start, end):
        parts = children(reply, s, e)
        if len(parts) != 2 or parts[0][0] != 0x06 or parts[1][0] != 0x31:
            raise ValueError("Malformed signed attribute")
        kind, values = parts
        name = oid(reply, *kind[2:])
        if name in found:
            raise ValueError("Repeated signed attribute")
        found[name] = children(reply, values[2], values[3])
    return found


def signing_certificate_hash(reply, attributes):
    if SIGNING_CERTIFICATE_V2 in attributes:
        name, default = SIGNING_CERTIFICATE_V2, hashes.SHA256
    elif SIGNING_CERTIFICATE in attributes:
        name, default = SIGNING_CERTIFICATE, hashes.SHA1
    else:
        raise ValueError("The timestamp does not name its signing certificate")
    value = attributes[name][0]
    certificates = children(reply, value[2], value[3])
    first = children(reply, certificates[0][2], certificates[0][3])[0]
    identifiers = children(reply, first[2], first[3])
    algorithm = default
    if identifiers[0][0] == 0x30:
        algorithm = DIGESTS.get(oid(reply, *children(reply, identifiers[0][2], identifiers[0][3])[0][2:]))
        identifiers = identifiers[1:]
    if algorithm is None or identifiers[0][0] != 0x04:
        raise ValueError("Unsupported signing certificate reference")
    return algorithm, reply[identifiers[0][2]:identifiers[0][3]], algorithm().name


def certificate_reference_details(algorithm):
    warning = ("The timestamp names its signing certificate by SHA-1 (RFC 2634 SigningCertificate); "
               "prefer authorities that return SigningCertificateV2")
    return {"certificate_reference": algorithm, "warnings": [warning] if algorithm == "sha1" else []}


def timestamp_certificate_reference(reply):
    token = timestamp_token(reply)
    _, _, start, end = token["signer"]
    items = children(reply, start, end)
    attributes = signed_attributes(reply, items[3][2], items[3][3])
    _, _, algorithm = signing_certificate_hash(reply, attributes)
    return certificate_reference_details(algorithm)


def timestamp_signature(reply, roots, *, include_reference=False):
    token = timestamp_token(reply)
    when = tst_info(token["tst"])["time"]
    _, _, start, end = token["signer"]
    items = children(reply, start, end)
    if len(items) < 6 or items[3][0] != 0xA0 or items[4][0] != 0x30 or items[5][0] != 0x04:
        raise ValueError("The timestamp signer has no signed attributes")
    digest = DIGESTS.get(oid(reply, *children(reply, items[2][2], items[2][3])[0][2:]))
    if digest is None:
        raise ValueError("Unsupported timestamp digest algorithm")
    attributes = signed_attributes(reply, items[3][2], items[3][3])
    content_type, message_digest = attributes.get(CONTENT_TYPE), attributes.get(MESSAGE_DIGEST)
    if not content_type or oid(reply, *content_type[0][2:]) != TST_INFO:
        raise ValueError("The signed attributes do not describe a TSTInfo")
    hasher = hashes.Hash(digest())
    hasher.update(token["tst"])
    if not message_digest or reply[message_digest[0][2]:message_digest[0][3]] != hasher.finalize():
        raise ValueError("The signature does not cover this TSTInfo")
    algorithm, named, reference = signing_certificate_hash(reply, attributes)
    raw = {}
    for data in token["certificates"]:
        raw[data] = x509.load_der_x509_certificate(data)
    signer_data = None
    for data in raw:
        hasher = hashes.Hash(algorithm())
        hasher.update(data)
        if hasher.finalize() == named:
            signer_data = data
    if signer_data is None:
        raise ValueError("The reply does not carry the certificate the signature names")
    signer = raw[signer_data]
    try:
        usage = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        usage = None
    if not usage or not usage.critical or list(usage.value) != [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError("The signing certificate is not for time stamping only")
    signed = b"\x31" + reply[items[3][1] + 1:items[3][3]]
    signature = reply[items[5][2]:items[5][3]]
    method = oid(reply, *children(reply, items[4][2], items[4][3])[0][2:])
    key = signer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey) and method in RSA_SIGNATURES:
            key.verify(signature, signed, padding.PKCS1v15(), (RSA_SIGNATURES[method] or digest)())
        elif isinstance(key, ec.EllipticCurvePublicKey) and method in ECDSA_SIGNATURES:
            key.verify(signature, signed, ec.ECDSA(ECDSA_SIGNATURES[method]()))
        else:
            raise ValueError("Unsupported timestamp signature algorithm " + method)
    except InvalidSignature:
        raise ValueError("The timestamp signature is invalid") from None
    trusted = {root.fingerprint(hashes.SHA256()): root for root in roots}
    chain, current = [signer], signer
    while not (len(chain) > 1 and chain[-1].fingerprint(hashes.SHA256()) in trusted):
        if len(chain) > 8:
            raise ValueError("The timestamp certificate chain is too long")
        candidates = list(trusted.values()) + [c for c in raw.values() if c not in chain]
        issuer = None
        for candidate in candidates:
            if candidate.subject != current.issuer:
                continue
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                continue
            issuer = candidate
            break
        if issuer is None:
            raise ValueError("The timestamp certificate does not chain to a trusted root")
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            constraints = None
        if not constraints or not constraints.ca:
            raise ValueError("A certificate in the timestamp chain is not a certificate authority")
        chain.append(issuer)
        current = issuer
    for certificate in chain:
        if not certificate.not_valid_before_utc <= when <= certificate.not_valid_after_utc:
            raise ValueError("A certificate in the timestamp chain was not valid at the stamped time")
        for extension in certificate.extensions:
            if extension.critical and not isinstance(extension.value, (
                    x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage)):
                raise ValueError("Unsupported critical timestamp certificate extension: " + extension.oid.dotted_string)
    for index, certificate in enumerate(chain[1:], 1):
        try:
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            usage = None
        if usage is not None and not usage.key_cert_sign:
            raise ValueError("A timestamp CA certificate does not permit signing certificates")
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        below = sum(child.subject != child.issuer for child in chain[1:index])
        if constraints.path_length is not None and below > constraints.path_length:
            raise ValueError("The timestamp certificate chain exceeds a CA path length constraint")
    root = chain[-1]
    return {"signer": signer.subject.rfc4514_string(), "root": root.subject.rfc4514_string(),
            "root_sha256": root.fingerprint(hashes.SHA256()).hex(),
            "signer_sha256": signer.fingerprint(hashes.SHA256()).hex(),
            **(certificate_reference_details(reference) if include_reference else {})}


def ots_summary(proof, digest, *, commitments=False):
    head = OTS_MAGIC + b"\x01\x08"
    if len(digest) != 32 or proof[:len(head)] != head or proof[len(head):len(head) + 32] != digest:
        raise ValueError("The OpenTimestamps proof is not for this checkpoint")
    if len(proof) > 1024 * 1024:
        raise ValueError("The OpenTimestamps proof exceeds the size limit")

    class Reader:
        def __init__(self, data):
            self.data, self.pos = data, 0

        def take(self, size):
            end = self.pos + size
            if end > len(self.data):
                raise ValueError("Truncated OpenTimestamps proof")
            value, self.pos = self.data[self.pos:end], end
            return value

        def integer(self):
            value = 0
            for shift in range(0, 35, 7):
                byte = self.take(1)[0]
                value |= (byte & 127) << shift
                if not byte & 128:
                    if value > 0xffffffff:
                        break
                    return value
            raise ValueError("OpenTimestamps integer exceeds the limit")

        def blob(self, maximum):
            size = self.integer()
            if size > maximum:
                raise ValueError("OpenTimestamps field exceeds the limit")
            return self.take(size)

        def finish(self):
            if self.pos != len(self.data):
                raise ValueError("Trailing bytes in OpenTimestamps proof")

    reader = Reader(proof[len(head) + 32:])
    kinds, remaining = set(), 10000
    bitcoin = []

    def node(message_size, depth=0, message=None):
        nonlocal remaining
        if depth >= 256:
            raise ValueError("OpenTimestamps tree exceeds the depth limit")
        operations = set()
        while True:
            remaining -= 1
            if remaining < 0:
                raise ValueError("OpenTimestamps tree exceeds the operation limit")
            tag = reader.take(1)[0]
            more = tag == 255
            if more:
                tag = reader.take(1)[0]
            if tag == 0:
                kind = reader.take(8)
                payload = Reader(reader.blob(8192))
                if kind == OTS_BITCOIN:
                    height = payload.integer()
                    payload.finish()
                    if message_size != 32:
                        raise ValueError("OpenTimestamps Bitcoin commitment must be 32 bytes")
                    kinds.add("bitcoin-unverified")
                    if message is not None:
                        bitcoin.append({"height": height, "merkle_root": message.hex()})
                elif kind == OTS_PENDING:
                    uri = payload.blob(1000)
                    payload.finish()
                    if not re.fullmatch(rb"[A-Za-z0-9._/:-]*", uri):
                        raise ValueError("Invalid OpenTimestamps calendar URI")
                    kinds.add("pending")
                else:
                    kinds.add("unknown")
            else:
                argument = b""
                size = message_size
                if tag in (0xf0, 0xf1):
                    argument = reader.blob(4096)
                    if not argument:
                        raise ValueError("Empty OpenTimestamps operation argument")
                    size += len(argument)
                elif tag == 0xf3:
                    size *= 2
                elif tag in (0x02, 0x03, 0x08, 0x67):
                    size = 20 if tag in (0x02, 0x03) else 32
                elif tag != 0xf2:
                    raise ValueError("Unknown OpenTimestamps operation")
                if size > 4096:
                    raise ValueError("OpenTimestamps operation result exceeds the limit")
                operation = (tag, argument)
                if operation in operations:
                    raise ValueError("Repeated OpenTimestamps operation")
                operations.add(operation)
                calculated = None
                if message is not None:
                    if tag == 0xf0:
                        calculated = message + argument
                    elif tag == 0xf1:
                        calculated = argument + message
                    elif tag == 0xf2:
                        calculated = message[::-1]
                    elif tag == 0xf3:
                        calculated = message.hex().encode("ascii")
                    elif tag in (0x02, 0x03, 0x08):
                        try:
                            calculated = hashlib.new({0x02: "sha1", 0x03: "ripemd160", 0x08: "sha256"}[tag], message).digest()
                        except ValueError:
                            pass
                node(size, depth + 1, calculated)
            if not more:
                return

    node(32, message=digest if commitments else None)
    reader.finish()
    status = next(kind for kind in ("bitcoin-unverified", "pending", "unknown") if kind in kinds)
    return {"status": status, "verification": "structure only; run ots verify",
            **({"commitments": bitcoin} if commitments else {})}


BITCOIN_SOURCES = ("https://blockstream.info/api", "https://mempool.space/api")


def bitcoin_fetcher():
    import urllib.request
    cache = {}

    def get(url):
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "TgWitness verify"}), timeout=15) as reply:
            body = reply.read(1025)
        if len(body) > 1024:
            raise ValueError("Excessive Bitcoin header response")
        return body.decode("ascii").strip()

    def fetch(height):
        if height in cache:
            return cache[height]
        found = []
        for source in BITCOIN_SOURCES:
            try:
                tip = int(get(source + "/blocks/tip/height"))
                if tip - height + 1 < 6:
                    return None
                block_hash = get(source + "/block-height/" + str(height))
                hash_bytes(block_hash)
                header = bytes.fromhex(get(source + "/block/" + block_hash + "/header"))
                if len(header) != 80 or hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex() != block_hash:
                    raise ValueError("Bitcoin header hash mismatch")
                bits = int.from_bytes(header[72:76], "little")
                exponent, mantissa = bits >> 24, bits & 0x7fffff
                if bits & 0x800000 or not 3 <= exponent <= 29 or not mantissa:
                    raise ValueError("Invalid Bitcoin proof-of-work target")
                target = mantissa << (8 * (exponent - 3))
                if target > 0xffff << 208 or int(block_hash, 16) > target:
                    raise ValueError("Invalid Bitcoin header proof of work")
                found.append(header)
            except (OSError, UnicodeError):
                raise CheckUnavailable("Bitcoin header sources are unreachable") from None
        if len(set(found)) != 1:
            raise ValueError("Independent Bitcoin header sources disagree")
        cache[height] = found[0]
        return found[0]
    return fetch


def confirm_ots(proof, digest, fetch=None):
    summary = ots_summary(proof, digest, commitments=True)
    fetch = fetch or bitcoin_fetcher()
    confirmed, unreachable = [], False
    for item in summary.pop("commitments"):
        try:
            header = fetch(item["height"])
        except CheckUnavailable:
            unreachable = True
            continue
        if header is None:
            continue
        if len(header) != 80 or header[36:68].hex() != item["merkle_root"]:
            raise ValueError("OpenTimestamps commitment differs from the Bitcoin block Merkle root")
        confirmed.append({"height": item["height"],
                          "time": datetime.fromtimestamp(int.from_bytes(header[68:72], "little"), timezone.utc).isoformat()})
    if confirmed:
        summary.update(status="confirmed", time=min(c["time"] for c in confirmed), blocks=confirmed,
                       verification="proof evaluated; headers with 6 confirmations agreed by two HTTPS explorers",
                       sources=list(BITCOIN_SOURCES))
    elif unreachable:
        summary["check"] = "unavailable"
    return summary


def find_openssl():
    found = shutil.which("openssl")
    if not found and os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),):
            for sub in ("Git/usr/bin/openssl.exe", "Git/ucrt64/bin/openssl.exe", "Git/mingw64/bin/openssl.exe"):
                if os.path.isfile(os.path.join(base, sub)):
                    return os.path.join(base, sub)
    if not found:
        raise ValueError("OpenSSL is required to check timestamp signatures (--tsa-ca)")
    return found


def openssl_verify_timestamp(data, reply, query, ca_path):
    binary = find_openssl()
    with tempfile.TemporaryDirectory() as tmp:
        paths = {}
        for name, content in (("data", data), ("reply.tsr", reply), ("query.tsq", query)):
            if content is not None:
                paths[name] = os.path.join(tmp, name)
                with open(paths[name], "wb") as handle:
                    handle.write(content)
        common = [binary, "ts", "-verify", "-in", paths["reply.tsr"], "-CAfile", str(ca_path)]
        selectors = [["-data", paths["data"]]] + ([["-queryfile", paths["query.tsq"]]] if query is not None else [])
        for selector in selectors:
            done = subprocess.run(common + selector, capture_output=True, timeout=30, check=False)
            if done.returncode:
                raise ValueError("Timestamp signature check failed: " + done.stderr.decode(errors="replace")[-500:])


def qualified_timestamp(reply):
    for data in timestamp_token(reply)["certificates"]:
        certificate = x509.load_der_x509_certificate(data)
        service = QUALIFIED_TSU.get(certificate.fingerprint(hashes.SHA256()).hex())
        if not service:
            continue
        try:
            statements = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(QC_STATEMENTS)).value.value
        except x509.ExtensionNotFound:
            continue
        if QC_COMPLIANCE in statements:
            return {"qualified": {"service": service, "provider": QUALIFIED_PROVIDER, "trusted_list": QUALIFIED_LIST}}
    return {}


def stamp_time(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def revocation_subject(reply, extra=()):
    token = timestamp_token(reply)
    _, _, start, end = token["signer"]
    items = children(reply, start, end)
    if len(items) < 6 or items[3][0] != 0xA0:
        raise ValueError("The timestamp signer has no signed attributes")
    algorithm, named, _ = signing_certificate_hash(reply, signed_attributes(reply, items[3][2], items[3][3]))
    loaded, signer = {}, None
    for data in token["certificates"]:
        loaded[data] = x509.load_der_x509_certificate(data)
    for data in loaded:
        hasher = hashes.Hash(algorithm())
        hasher.update(data)
        if hasher.finalize() == named:
            signer = loaded[data]
    certificates = list(loaded.values())
    if signer is None:
        raise ValueError("The reply does not carry the certificate the signature names")
    for candidate in certificates + list(extra):
        if candidate.subject != signer.issuer:
            continue
        try:
            signer.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        return {"signer": signer, "issuer": candidate, "time": tst_info(token["tst"])["time"]}
    raise ValueError("The issuer of the signing certificate is neither in the reply nor in the given root file")


def ocsp_responder(response, issuer):
    for candidate in [issuer] + list(response.certificates):
        if response.responder_name is not None:
            named = candidate.subject == response.responder_name
        else:
            named = x509.SubjectKeyIdentifier.from_public_key(candidate.public_key()).digest == response.responder_key_hash
        if not named:
            continue
        if candidate.fingerprint(hashes.SHA256()) != issuer.fingerprint(hashes.SHA256()):
            try:
                candidate.verify_directly_issued_by(issuer)
                usage = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                continue
            if (x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING not in usage
                    or not candidate.not_valid_before_utc <= response.produced_at_utc <= candidate.not_valid_after_utc):
                continue
        key = candidate.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(),
                           response.signature_hash_algorithm)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(response.signature_hash_algorithm))
            else:
                continue
        except InvalidSignature:
            continue
        return candidate
    raise ValueError("The OCSP response is not signed by the issuer or by a responder it authorised for OCSP signing")


def revocation_status(kind, data, subject):
    signer, issuer, when, source = subject["signer"], subject["issuer"], subject["time"], kind.upper()
    if kind == "ocsp":
        response = ocsp.load_der_ocsp_response(data)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("The OCSP responder answered " + response.response_status.name)
        found = None
        for single in response.responses:
            query = ocsp.OCSPRequestBuilder().add_certificate(signer, issuer, single.hash_algorithm).build()
            if (single.serial_number, single.issuer_name_hash, single.issuer_key_hash) == (
                    query.serial_number, query.issuer_name_hash, query.issuer_key_hash):
                found = single
        if found is None:
            raise ValueError("The OCSP response does not name this signing certificate")
        ocsp_responder(response, issuer)
        if found.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
            raise ValueError("The OCSP responder does not know this signing certificate")
        revoked = found.revocation_time_utc if found.certificate_status == ocsp.OCSPCertStatus.REVOKED else None
        reason, issued, until = found.revocation_reason, found.this_update_utc, found.next_update_utc
    elif kind == "crl":
        try:
            crl = x509.load_der_x509_crl(data)
        except ValueError:
            crl = x509.load_pem_x509_crl(data)
        if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
            raise ValueError("The CRL is not signed by the issuer of the signing certificate")
        entry = crl.get_revoked_certificate_by_serial_number(signer.serial_number)
        revoked = entry.revocation_date_utc if entry else None
        reason = next((e.value.reason for e in entry.extensions if isinstance(e.value, x509.CRLReason)), None) if entry else None
        issued, until = crl.last_update_utc, crl.next_update_utc
    else:
        raise ValueError("Unknown revocation evidence: " + kind)
    if revoked is not None:
        compromised = reason in (x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise)
        state = "revoked" if revoked <= when or compromised else "revoked_after"
        return {"status": state, "source": source, "revoked_at": stamp_time(revoked),
                "reason": reason.value if reason else None,
                "detail": "signing certificate revoked at " + stamp_time(revoked)
                          + (", before" if revoked <= when else ", after") + " the time stamp"
                          + (", for key compromise" if compromised else "") + " (" + source + ")"}
    if issued < when and (until is None or until < when):
        raise ValueError("The " + source + " answer of " + stamp_time(issued) + " expired before the stamped time")
    if issued > signer.not_valid_after_utc:
        raise ValueError("The " + source + " answer was issued after the signing certificate expired")
    return {"status": "good", "source": source, "as_of": stamp_time(issued),
            "detail": "signing certificate not revoked as of " + stamp_time(issued) + " (" + source + ")"}


def timestamp_revocation(archive, names, base, reply, tsa_ca=None):
    found = [kind for kind in ("ocsp", "crl") if base + "." + kind in names]
    if not found:
        return {"status": "not checked", "detail": "revocation not checked (no OCSP/CRL in the archive)"}
    try:
        extra = x509.load_pem_x509_certificates(Path(tsa_ca).read_bytes()) if tsa_ca else []
    except (OSError, ValueError):
        extra = []
    problems = []
    for kind in found:
        try:
            return revocation_status(kind, read_member(archive, base + "." + kind), revocation_subject(reply, extra))
        except (ValueError, TypeError, IndexError, InvalidSignature, UnsupportedAlgorithm) as exc:
            problems.append(kind.upper() + ": " + str(exc))
    return {"status": "failed", "error": "; ".join(problems), "detail": "revocation check failed: " + "; ".join(problems)}


def verify_anchors(archive, names, public_key, event_count, hash_at, tsa_ca=None, check_bitcoin=False):
    results = []
    for name in sorted(n for n in names if n.startswith("anchors/") and n.endswith(".json")):
        data = read_member(archive, name)
        retained_checkpoint = strict_json(data)
        verify_checkpoint(retained_checkpoint, public_key, event_count, hash_at)
        digest, stem = hashlib.sha256(data).digest(), name[:-len(".json")] + "."
        for proof_name in sorted(n for n in names if n.startswith(stem) and n != name):
            service = proof_name[len(stem):].rsplit(".", 1)[0]
            entry = {"checkpoint": name[len("anchors/"):], "service": service,
                     "event_count": retained_checkpoint["statement"]["event_count"]}
            if proof_name.endswith(".tsr"):
                reply = read_member(archive, proof_name)
                query_name = proof_name[:-4] + ".tsq"
                query = read_member(archive, query_name) if query_name in names else None
                entry.update(kind="rfc3161", **timestamp_reply_summary(reply, digest, query))
                if tsa_ca:
                    openssl_verify_timestamp(data, reply, query, tsa_ca)
                entry["signature"] = "checked against the given root" if tsa_ca else "not checked (use --tsa-ca)"
                if tsa_ca:
                    entry.update(qualified_timestamp(reply))
                try:
                    entry.update(timestamp_certificate_reference(reply))
                except (ValueError, IndexError, TypeError):
                    entry["certificate_reference"] = "unavailable"
                entry["revocation"] = timestamp_revocation(archive, names, proof_name[:-4], reply, tsa_ca)
                if entry["revocation"]["status"] == "revoked":
                    raise ValueError("The " + service + " timestamp is invalid: its " + entry["revocation"]["detail"]
                                     + ("; reason " + entry["revocation"]["reason"] if entry["revocation"]["reason"] else ""))
            elif proof_name.endswith(".ots"):
                proof = read_member(archive, proof_name)
                entry.update(kind="opentimestamps", **(confirm_ots(proof, digest) if check_bitcoin else ots_summary(proof, digest)))
            else:
                continue
            results.append(entry)
    return results


INTEL_SGX_ROOT = base64.b64decode(
    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIwaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3Qg"
    "Q0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT"
    "AlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoM"
    "EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZI"
    "zj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxF"
    "P2sJBK5zlKOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2Nl"
    "cnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInz"
    "g7SVUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYIKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9C"
    "iSDcNoowLuPRLsWGf/Yi7GSX94BgwTwgAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=")
INTEL_SGX_ROOT_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
INTEL_QE_VENDOR = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
INTEL_TD_QE_SIGNER = bytes.fromhex("dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5")
INTEL_PCK_CAS = ("Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA")
SGX_PCK_EXTENSION = "1.2.840.113741.1.13.1"
TDX_BODIES = {2: 584, 3: 648, 4: 885}
TDX_REPORT_FIELDS = (("tee_tcb_svn", 16), ("mr_seam", 48), ("mr_signer_seam", 48), ("seam_attributes", 8),
                     ("td_attributes", 8), ("xfam", 8), ("mrtd", 48), ("mr_config_id", 48), ("mr_owner", 48),
                     ("mr_owner_config", 48), ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48),
                     ("report_data", 64))
TDX_MEASUREMENTS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "report_data")
TDX_STATUSES = ("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded",
                "OutOfDate", "OutOfDateConfigurationNeeded", "Revoked")
TDX_QE_STATUSES = ("UpToDate", "OutOfDate", "Revoked")
TDX_RESERVED_ATTRIBUTES = sum(1 << bit for bit in (*range(1, 4), *range(7, 16), *range(23, 27), *range(32, 62)))
TDX_NOT_CHECKED = ("the code the VM ran: the compose RTMR3 measures and the OS image behind MRTD and RTMR0-2; "
                   "python -m tgwitness.cloud verify compares them")
ATTESTATION_RECORDS = ("tgwitness-attestation-record-v1", "tgwitness-deployment-v1")


class QuoteInvalid(ValueError):
    pass


def tdx_root():
    root = x509.load_der_x509_certificate(INTEL_SGX_ROOT)
    if root.fingerprint(hashes.SHA256()).hex() != INTEL_SGX_ROOT_SHA256:
        raise QuoteInvalid("The pinned Intel SGX Root CA is damaged")
    return root


def tdx_quote(raw):
    if len(raw) < 48:
        raise QuoteInvalid("The quote is truncated")
    version, key_type, tee = struct.unpack_from("<HHI", raw, 0)
    if tee != 0x81:
        raise QuoteInvalid("Not an Intel TDX quote")
    if key_type != 2:
        raise QuoteInvalid("Unsupported attestation key type " + str(key_type))
    if raw[12:28] != INTEL_QE_VENDOR:
        raise QuoteInvalid("The quote was not produced by Intel's quoting enclave")
    if version == 4:
        kind, offset = 2, 48
    elif version == 5:
        if len(raw) < 54:
            raise QuoteInvalid("The quote is truncated")
        kind, size = struct.unpack_from("<HI", raw, 48)
        if TDX_BODIES.get(kind) != size:
            raise QuoteInvalid("Unsupported TD report body " + str(kind) + " of " + str(size) + " bytes")
        offset = 54
    else:
        raise QuoteInvalid("Unsupported quote version " + str(version))
    signed = offset + TDX_BODIES[kind]
    if len(raw) < signed + 4:
        raise QuoteInvalid("The quote is truncated")
    length = struct.unpack_from("<I", raw, signed)[0]
    auth = raw[signed + 4:signed + 4 + length]
    if len(auth) != length or len(auth) < 134 or raw[signed + 4 + length:].strip(b"\0"):
        raise QuoteInvalid("The quote's signature data has the wrong length")
    cert_type, cert_size = struct.unpack_from("<HI", auth, 128)
    cert = auth[134:134 + cert_size]
    if cert_type != 6 or len(cert) != cert_size or len(cert) < 456:
        raise QuoteInvalid("The quote carries no quoting enclave report")
    inner = 450 + struct.unpack_from("<H", cert, 448)[0]
    if len(cert) < inner + 6:
        raise QuoteInvalid("The quote's certification data is truncated")
    chain_type, chain_size = struct.unpack_from("<HI", cert, inner)
    chain = cert[inner + 6:inner + 6 + chain_size]
    if chain_type != 5 or len(chain) != chain_size:
        raise QuoteInvalid("The quote carries no PCK certificate chain")
    fields = TDX_REPORT_FIELDS + ((("tee_tcb_svn2", 16), ("mr_service_td", 48)) if kind in (3, 4) else ())
    report, at = {}, offset
    for name, size in fields:
        report[name], at = raw[at:at + size], at + size
    return {"version": version, "signed": raw[:signed], "report": report, "signature": auth[0:64],
            "attestation_key": auth[64:128], "qe_report": cert[0:384], "qe_signature": cert[384:448],
            "qe_auth": cert[450:inner], "pck_chain": chain.rstrip(b"\0")}


def tdx_signature(key, signature, data, what):
    if len(signature) != 64:
        raise QuoteInvalid(what + ": expected a 64-byte ECDSA P-256 signature")
    try:
        key.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                   data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        raise QuoteInvalid(what + ": the signature is invalid") from None


def tdx_certificates(text):
    data = text.encode() if isinstance(text, str) else bytes(text)
    try:
        return x509.load_pem_x509_certificates(data.rstrip(b"\0"))
    except ValueError:
        raise QuoteInvalid("Unreadable certificate chain") from None


def tdx_time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise QuoteInvalid("Unreadable time " + str(value)[:40]) from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def tdx_crl(data, issuer, at, what):
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        raise QuoteInvalid(what + " is unreadable") from None
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise QuoteInvalid(what + " is not signed by " + issuer.subject.rfc4514_string())
    if crl.last_update_utc > at or crl.next_update_utc is not None and at > crl.next_update_utc:
        raise QuoteInvalid(what + " is not current at " + at.isoformat())
    return crl


def tdx_chain(chain, root, at, what, crls=None):
    chain = list(chain)
    if chain and chain[-1].fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
        chain = chain[:-1]
    if not chain:
        raise QuoteInvalid(what + ": no certificates")
    for index, certificate in enumerate(chain):
        issuer = chain[index + 1] if index + 1 < len(chain) else root
        try:
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature):
            raise QuoteInvalid(what + ": " + certificate.subject.rfc4514_string() + " is not issued by "
                               + issuer.subject.rfc4514_string()) from None
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            constraints = None
        if not constraints or not constraints.ca:
            raise QuoteInvalid(what + ": " + issuer.subject.rfc4514_string() + " is not a certificate authority")
        for checked in (certificate, issuer):
            if not checked.not_valid_before_utc <= at <= checked.not_valid_after_utc:
                raise QuoteInvalid(what + ": " + checked.subject.rfc4514_string() + " is not valid at " + at.isoformat())
        if crls is not None:
            crl = crls.get(issuer.subject.public_bytes())
            if crl is None:
                raise QuoteInvalid(what + ": no revocation list from " + issuer.subject.rfc4514_string())
            if crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None:
                raise QuoteInvalid(what + ": " + certificate.subject.rfc4514_string() + " is revoked")
    return chain


def tdx_pck(certificate):
    try:
        data = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(SGX_PCK_EXTENSION)).value.value
    except x509.ExtensionNotFound:
        raise QuoteInvalid("The PCK certificate has no Intel SGX extension") from None
    found = {}
    try:
        _, start, end = der(data, 0)
        for _, _, item_start, item_end in children(data, start, end):
            parts = children(data, item_start, item_end)
            if len(parts) != 2 or parts[0][0] != 0x06:
                continue
            name, (_, _, value_start, value_end) = oid(data, *parts[0][2:]), parts[1]
            if name == SGX_PCK_EXTENSION + ".2":
                for _, _, c_start, c_end in children(data, value_start, value_end):
                    sub = children(data, c_start, c_end)
                    component, (s_tag, _, s_start, s_end) = oid(data, *sub[0][2:]), sub[1]
                    value = data[s_start:s_end]
                    found["tcb." + component.rsplit(".", 1)[1]] = value if s_tag == 0x04 else int.from_bytes(value, "big")
            else:
                found[name] = data[value_start:value_end]
        return {"cpu_svn": bytes(found["tcb." + str(i)] for i in range(1, 17)), "pce_svn": found["tcb.17"],
                "fmspc": found[SGX_PCK_EXTENSION + ".4"]}
    except (KeyError, TypeError, ValueError, IndexError):
        raise QuoteInvalid("The PCK certificate's Intel SGX extension is incomplete") from None


def tdx_current(document, at, what):
    if not tdx_time(document["issueDate"]) <= at <= tdx_time(document["nextUpdate"]):
        raise QuoteInvalid(what + " is not current at " + at.isoformat() + " (issued " + str(document["issueDate"])
                           + ", next update " + str(document["nextUpdate"]) + ")")


def tdx_document(collateral, name, root, crls, at, what):
    chain = tdx_chain(tdx_certificates(collateral[name + "_issuer_chain"]), root, at, what, crls)
    if len(chain) != 1:
        raise QuoteInvalid(what + " must be signed by a certificate the root issued directly")
    text = collateral[name]
    tdx_signature(chain[0].public_key(), bytes.fromhex(collateral[name + "_signature"]), text.encode(), what)
    return json.loads(text)


def tdx_converge(platform, component):
    if platform not in TDX_STATUSES or component not in TDX_QE_STATUSES:
        raise QuoteInvalid("Unsupported TCB status convergence: " + str(platform) + ", " + str(component))
    if component == "Revoked":
        return "Revoked"
    if component == "OutOfDate" and platform in ("UpToDate", "SWHardeningNeeded"):
        return "OutOfDate"
    if component == "OutOfDate" and platform in ("ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
        return "OutOfDateConfigurationNeeded"
    return platform


def tdx_relaunch(launch, current):
    configuration = ("ConfigurationNeeded", "OutOfDateConfigurationNeeded", "ConfigurationAndSWHardeningNeeded",
                     "TDRelaunchAdvisedConfigurationNeeded")
    if launch in ("OutOfDate", "OutOfDateConfigurationNeeded") and current in (
            "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
        return "TDRelaunchAdvisedConfigurationNeeded" if launch in configuration or current in configuration \
            else "TDRelaunchAdvised"
    return launch


def tdx_components(level, key):
    return [c["svn"] for c in level["tcb"].get(key) or []]


def tdx_module_identity(tcb_info, svn):
    if svn[1] == 0:
        return None
    wanted = "TDX_%02X" % svn[1]
    for identity in tcb_info.get("tdxModuleIdentities") or []:
        if identity["id"].upper() == wanted:
            return identity
    raise QuoteInvalid("TCB Info has no TDX module identity " + wanted)


def tdx_platform_level(tcb_info, cpu_svn, pce_svn, svn):
    skip = 2 if svn[1] > 0 else 0
    levels = sorted(tcb_info["tcbLevels"], reverse=True, key=lambda level: (
        tdx_components(level, "sgxtcbcomponents"), level["tcb"]["pcesvn"], tdx_components(level, "tdxtcbcomponents")))
    for level in levels:
        sgx, td = tdx_components(level, "sgxtcbcomponents"), tdx_components(level, "tdxtcbcomponents")
        if len(sgx) != 16 or len(td) != 16:
            raise QuoteInvalid("TCB Info has a level without 16 SGX and 16 TDX components")
        if all(have >= need for have, need in zip(cpu_svn, sgx)) and pce_svn >= level["tcb"]["pcesvn"] and \
                all(have >= need for have, need in list(zip(svn, td))[skip:]):
            if level["tcbStatus"] not in TDX_STATUSES:
                raise QuoteInvalid("Unrecognized TCB status " + str(level["tcbStatus"]))
            status, advisories, date = level["tcbStatus"], list(level.get("advisoryIDs") or []), level["tcbDate"]
            identity = tdx_module_identity(tcb_info, svn)
            if identity:
                module = next((m for m in identity["tcbLevels"] if svn[0] >= m["tcb"]["isvsvn"]), None)
                if module is None:
                    raise QuoteInvalid("The TDX module ISVSVN " + str(svn[0]) + " is below every module TCB level")
                if module["tcbStatus"] not in TDX_QE_STATUSES:
                    raise QuoteInvalid("Unrecognized TDX module TCB status " + str(module["tcbStatus"]))
                status = tdx_converge(status, module["tcbStatus"])
                advisories += [a for a in module.get("advisoryIDs") or [] if a not in advisories]
                date = min(date, module["tcbDate"], key=tdx_time)
            return status, advisories, date
    raise QuoteInvalid("No TCB level of this platform is listed in Intel's TCB Info")


def tdx_check_module(tcb_info, report):
    base = tcb_info.get("tdxModule")
    if not base:
        raise QuoteInvalid("TDX TCB Info has no tdxModule")
    expected = tdx_module_identity(tcb_info, report["tee_tcb_svn"]) or base
    if bytes.fromhex(expected["mrsigner"]) != report["mr_signer_seam"]:
        raise QuoteInvalid("The TDX module is not signed by the signer Intel lists")
    attributes, mask = bytes.fromhex(expected["attributes"]), bytes.fromhex(expected["attributesMask"])
    for want, bits, have in zip(attributes, mask, report["seam_attributes"]):
        if want & bits != have & bits or have & ~bits & 0xFF:
            raise QuoteInvalid("The TDX module attributes differ from Intel's")


def tdx_check_qe(qe_report, identity):
    if qe_report[128:160] != bytes.fromhex(identity["mrsigner"]):
        raise QuoteInvalid("The quoting enclave is not signed by Intel")
    if qe_report[48] & 0x02:
        raise QuoteInvalid("The quoting enclave runs in debug mode")
    if struct.unpack_from("<H", qe_report, 256)[0] != identity["isvprodid"]:
        raise QuoteInvalid("The quoting enclave has the wrong product ID")
    mask = int.from_bytes(bytes.fromhex(identity["miscselectMask"]), "little")
    if struct.unpack_from("<I", qe_report, 16)[0] & mask != int.from_bytes(bytes.fromhex(identity["miscselect"]),
                                                                           "little") & mask:
        raise QuoteInvalid("The quoting enclave's MISCSELECT differs from Intel's")
    for want, bits, have in zip(bytes.fromhex(identity["attributes"]), bytes.fromhex(identity["attributesMask"]),
                                qe_report[48:64]):
        if want & bits != have & bits:
            raise QuoteInvalid("The quoting enclave's attributes differ from Intel's")
    svn = struct.unpack_from("<H", qe_report, 258)[0]
    for level in identity["tcbLevels"]:
        if svn >= level["tcb"]["isvsvn"]:
            if level["tcbStatus"] not in TDX_QE_STATUSES:
                raise QuoteInvalid("Unrecognized QE TCB status " + str(level["tcbStatus"]))
            return level["tcbStatus"], list(level.get("advisoryIDs") or [])
    raise QuoteInvalid("The quoting enclave's SVN is below every level Intel lists")


def tdx_problems(report):
    attributes, problems = int.from_bytes(report["td_attributes"], "little"), []
    if attributes & 0x01:
        problems.append("the TD runs in debug mode: the host can read its memory and registers")
    if attributes & 0x70:
        problems.append("TD profiling is enabled")
    if attributes & TDX_RESERVED_ATTRIBUTES:
        problems.append("reserved TD attribute bits are set")
    if attributes & (1 << 29):
        problems.append("the TD can be migrated to another machine")
    if attributes & (1 << 17):
        problems.append("service TD extensions are enabled")
    if not attributes & (1 << 28):
        problems.append("SEPT_VE_DISABLE is off")
    if report.get("mr_service_td", bytes(48)) != bytes(48):
        problems.append("a service TD is bound to this TD")
    return problems


def tdx_tcb(quote, chain, collateral, root, at):
    crl_data = [bytes.fromhex(collateral[name]) for name in ("root_ca_crl", "pck_crl")]
    moments = [tdx_time(json.loads(collateral[name])["issueDate"]) for name in ("tcb_info", "qe_identity")]
    at = max([at] + moments + [x509.load_der_x509_crl(data).last_update_utc for data in crl_data])
    crls = {root.subject.public_bytes(): tdx_crl(crl_data[0], root, at, "Intel's root revocation list")}
    pck_ca = tdx_chain(tdx_certificates(collateral["pck_crl_issuer_chain"]), root, at,
                       "The PCK revocation list issuer", crls)[0]
    crls[pck_ca.subject.public_bytes()] = tdx_crl(crl_data[1], pck_ca, at, "The PCK revocation list")
    tcb_info = tdx_document(collateral, "tcb_info", root, crls, at, "Intel's TCB Info")
    identity = tdx_document(collateral, "qe_identity", root, crls, at, "Intel's QE Identity")
    tdx_current(tcb_info, at, "Intel's TCB Info")
    tdx_current(identity, at, "Intel's QE Identity")
    if tcb_info.get("id") != "TDX" or tcb_info.get("version", 0) < 3:
        raise QuoteInvalid("The collateral's TCB Info is not for TDX")
    if identity.get("id") != "TD_QE" or identity.get("version") not in (2, 3):
        raise QuoteInvalid("The collateral's QE Identity is not for the TDX quoting enclave")
    chain = tdx_chain(chain, root, at, "The PCK certificate chain", crls)
    if chain[-1].subject != pck_ca.subject:
        raise QuoteInvalid("The PCK certificate and the revocation list come from different Intel CAs")
    qe_status, qe_advisories = tdx_check_qe(quote["qe_report"], identity)
    platform, report = tdx_pck(chain[0]), quote["report"]
    if bytes.fromhex(tcb_info["fmspc"]) != platform["fmspc"]:
        raise QuoteInvalid("Intel's TCB Info is for another platform (FMSPC)")
    status, advisories, date = tdx_platform_level(tcb_info, platform["cpu_svn"], platform["pce_svn"],
                                                  report["tee_tcb_svn"])
    tdx_check_module(tcb_info, report)
    current = None
    if "tee_tcb_svn2" in report:
        current = tdx_converge(tdx_platform_level(tcb_info, platform["cpu_svn"], platform["pce_svn"],
                                                  report["tee_tcb_svn2"])[0], qe_status)
    status = tdx_converge(status, qe_status)
    advisories += [a for a in qe_advisories if a not in advisories]
    if status == "Revoked" or current == "Revoked":
        raise QuoteInvalid("Intel has revoked this platform's TCB")
    if current:
        status = tdx_relaunch(status, current)
    return {"status": status, "advisory_ids": advisories, "tcb_date": date, "qe_status": qe_status,
            "collateral_issued": tcb_info["issueDate"], "evaluated_at": at.isoformat(),
            "revocation": "PCK chain checked against Intel's revocation lists",
            "detail": "Intel TCB status " + status + (" with " + ", ".join(advisories[:12]) if advisories else "")
                      + "; TCB level of " + str(date) + ", quoting enclave " + qe_status + "; Intel collateral issued "
                      + str(tcb_info["issueDate"]) + ", evaluated at " + at.isoformat()}


def tdx_verify(raw, binding, at, collateral=None):
    root, quote, at = tdx_root(), tdx_quote(raw), tdx_time(at)
    chain = tdx_chain(tdx_certificates(quote["pck_chain"]), root, at, "The PCK certificate chain")
    names = [", ".join(a.value for a in c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)) for c in chain]
    if len(chain) != 2 or names[0] != "Intel SGX PCK Certificate" or names[1] not in INTEL_PCK_CAS:
        raise QuoteInvalid("The quote's certificates are not a PCK certificate under an Intel SGX PCK CA")
    pck, qe = chain[0], quote["qe_report"]
    tdx_signature(pck.public_key(), quote["qe_signature"], qe, "The quoting enclave report")
    if len(quote["qe_auth"]) != 32 or \
            qe[320:384] != hashlib.sha256(quote["attestation_key"] + quote["qe_auth"]).digest() + bytes(32):
        raise QuoteInvalid("The quoting enclave report does not name the key that signed the quote")
    if qe[128:160] != INTEL_TD_QE_SIGNER or struct.unpack_from("<H", qe, 256)[0] != 2 or qe[48] & 0x02:
        raise QuoteInvalid("The quoting enclave report is not from Intel's TDX quoting enclave in production mode")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + quote["attestation_key"])
    except ValueError:
        raise QuoteInvalid("The quote's attestation key is not a P-256 point") from None
    tdx_signature(key, quote["signature"], quote["signed"], "The TD report")
    report = quote["report"]
    problems = tdx_problems(report)
    if problems:
        raise QuoteInvalid("; ".join(problems))
    if report["report_data"] != hashlib.sha512(canonical(binding)).digest():
        raise QuoteInvalid("The quote's report data is not SHA-512 of this record: it vouches for something else")
    platform, tcb = tdx_pck(pck), None
    if collateral:
        try:
            tcb = tdx_tcb(quote, chain, collateral, root, at)
        except QuoteInvalid:
            raise
        except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
            raise QuoteInvalid("Intel's collateral is incomplete or unreadable: " + type(exc).__name__) from None
    return {"quote_version": quote["version"], "pck_ca": names[1], "fmspc": platform["fmspc"].hex(),
            "pck_sha256": pck.fingerprint(hashes.SHA256()).hex(), "qe_svn": struct.unpack_from("<H", qe, 258)[0],
            **{name: report[name].hex() for name in TDX_MEASUREMENTS}, "td_attributes": report["td_attributes"].hex(),
            "tcb": tcb}


def tdx_check(evidence, binding, at, source, binds):
    if evidence.get("error") or not evidence.get("quote"):
        return {"status": "missing", "detail": "no Intel TDX quote",
                **({"error": str(evidence["error"])[:200]} if evidence.get("error") else {})}
    try:
        found = tdx_verify(bytes.fromhex(evidence["quote"]), binding, at, evidence.get("collateral"))
    except (ValueError, KeyError, TypeError, IndexError, struct.error) as exc:
        return {"status": "fail", "detail": str(exc) or type(exc).__name__}
    if found["tcb"] is None:
        found["tcb"] = {"status": "not checked", "detail": "TCB status not checked (no collateral in the " + source + ")",
                        "revocation": "not checked",
                        **({"collector_error": str(evidence["collateral_error"])[:200]}
                           if evidence.get("collateral_error") else {})}
    return {"status": "pass", **found, "binds": binds}


def tdx_summary(quotes):
    return {"status": "pass" if all(q["status"] == "pass" for q in quotes) else "fail", "checked": "offline",
            "root": "Intel SGX Root CA pinned in this verifier", "root_sha256": INTEL_SGX_ROOT_SHA256,
            "quotes": quotes, "not_checked": TDX_NOT_CHECKED}


def tdx_start_binding(run):
    value = {"format": "tgwitness-tdx-start-v1", "public_key": run.get("public_key"), "run_id": run.get("run_id"),
             "source_tree_sha256": run.get("source_tree_sha256"), "host": run.get("host")}
    if "source_policy" in run:
        value["source_policy"] = run["source_policy"]
    return value


def verify_tdx_starts(starts, public_key):
    runs = [(event, event["payload"]["run"] if isinstance(event["payload"].get("run"), dict) else {}) for event in starts]
    if not any(run.get("tdx_start") for _, run in runs):
        return None
    quotes = []
    for event, run in runs:
        evidence = run["tdx_start"] if isinstance(run.get("tdx_start"), dict) else {}
        if evidence.get("quote") and run.get("public_key") != public_key:
            entry = {"status": "fail", "detail": "the quoted start names another key than this journal's"}
        else:
            entry = tdx_check(evidence, tdx_start_binding(run), event["observed_at"], "archive",
                              "the start record: journal key, run, source tree and host")
        quotes.append({"record": event["seq"], "at": event["observed_at"], **entry})
    return tdx_summary(quotes)


def verify_collector_attestation(data, expected_fingerprint=None):
    record = data.get("format") in ATTESTATION_RECORDS
    answer = (data.get("collector") or {}).get("statement") if record else data
    if not isinstance(answer, dict) or "statement" not in answer or "signature" not in answer:
        raise ValueError("The record carries no signed collector statement")
    statement = authenticate_statement(answer)
    if statement.get("format") != "tgwitness-assurance-v1":
        raise VerifierTooOld("Unsupported collector statement format")
    fp = fingerprint(statement["public_key"])
    if statement.get("fingerprint") != fp:
        raise ValueError("The statement's fingerprint does not belong to its key")
    if record and data["collector"].get("fingerprint") not in (None, fp):
        raise ValueError("The record names another collector key than its signed statement")
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    result = {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
              **{name: statement.get(name) for name in ("created_at", "run_id", "run_event_seq", "version",
                                                        "source_tree_sha256", "challenge")}}
    if isinstance(answer.get("tdx"), dict):
        entry = tdx_check(answer["tdx"], statement, statement.get("created_at"), "file",
                          "the signed collector statement: key, challenge, run and host")
        result["tdx"] = tdx_summary([{"at": statement.get("created_at"), **entry}])
    return result


def tdx_lines(tdx):
    if not tdx:
        return []
    lines = []
    for quote in tdx["quotes"]:
        where = "Intel TDX quote" + (" at record " + str(quote["record"]) if "record" in quote else "")
        if quote["status"] != "pass":
            lines.append(where + ": " + quote["status"] + " · " + quote["detail"]
                         + (" (" + quote["error"] + ")" if quote.get("error") else ""))
            continue
        lines.append(where + ": verified offline; signature, quoting enclave and PCK chain to the pinned Intel SGX "
                     "Root CA are valid (quote v" + str(quote["quote_version"]) + ", " + quote["pck_ca"] + ", FMSPC "
                     + quote["fmspc"] + ")")
        lines += [{"report_data": "REPORTDATA"}.get(name, name.upper()) + ": " + quote[name] for name in TDX_MEASUREMENTS]
        lines.append("REPORTDATA is SHA-512 of " + quote["binds"])
        lines.append(quote["tcb"]["detail"])
    lines.append("Not checked offline: " + tdx["not_checked"])
    return lines


def is_format(value, name):
    return value in ("tgwitness-" + name, "tgwatch-" + name)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def fingerprint(public_key):
    return hashlib.sha256(base64.b64decode(public_key, validate=True)).hexdigest()


MERKLE_EMPTY = hashlib.sha256(b"").digest()


def merkle_leaf(event_hash):
    return hashlib.sha256(b"\x00" + bytes.fromhex(event_hash)).digest()


def merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def hash_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Malformed SHA-256 commitment")
    return bytes.fromhex(value)


class MerkleFrontier:
    def __init__(self):
        self.nodes = []
        self.count = 0

    def append(self, event_hash):
        node, level, count = merkle_leaf(event_hash), 0, self.count
        while count & 1:
            node = merkle_node(self.nodes[level], node)
            self.nodes[level] = None
            count >>= 1
            level += 1
        if level == len(self.nodes):
            self.nodes.append(node)
        else:
            self.nodes[level] = node
        self.count += 1

    def root(self):
        result = None
        for node in self.nodes:
            if node is not None:
                result = node if result is None else merkle_node(node, result)
        return result if result is not None else MERKLE_EMPTY


def merkle_path(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Malformed or excessive Merkle proof")
    return [hash_bytes(node) for node in value]


def verify_inclusion(event_hash, index, size, root, path):
    if not 0 <= index < size:
        raise ValueError("Merkle leaf outside tree")
    fn, sn, calculated = index, size - 1, merkle_leaf(event_hash)
    for node in merkle_path(path):
        if sn == 0:
            raise ValueError("Excess Merkle inclusion nodes")
        if fn & 1 or fn == sn:
            calculated = merkle_node(node, calculated)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            calculated = merkle_node(calculated, node)
        fn >>= 1
        sn >>= 1
    if sn != 0 or calculated != root:
        raise ValueError("Event is not included in committed tree")


def verify_consistency(first, second, first_root, second_root, path):
    nodes = merkle_path(path)
    if not 0 <= first <= second:
        raise ValueError("Invalid Merkle tree sizes")
    if first == 0:
        if nodes or first_root != MERKLE_EMPTY or (second == 0 and second_root != MERKLE_EMPTY):
            raise ValueError("Invalid empty-tree consistency proof")
        return
    if first == second:
        if nodes or first_root != second_root:
            raise ValueError("Equal-size Merkle trees differ")
        return
    if not nodes:
        raise ValueError("Missing Merkle consistency proof")
    if first & (first - 1) == 0:
        nodes.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = nodes[0]
    for node in nodes[1:]:
        if sn == 0:
            raise ValueError("Excess Merkle consistency nodes")
        if fn & 1 or fn == sn:
            fr, sr = merkle_node(node, fr), merkle_node(node, sr)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            sr = merkle_node(sr, node)
        fn >>= 1
        sn >>= 1
    if sn != 0 or fr != first_root or sr != second_root:
        raise ValueError("Journal does not extend the previously committed tree")


def verify_continuity(value, checkpoint, previous=None, challenge=None):
    statement, proof = value["statement"], value["proof"]
    if (set(value) != {"statement", "signature", "proof"}
            or set(statement) != {"format", "public_key", "event_count", "head_hash", "root", "challenge"}
            or set(proof) != {"from_count", "consistency", "head_path", "previous_head_path"}
            or statement["format"] != "tgwitness-continuity-v1"):
        raise ValueError("Unexpected continuity proof fields")
    count, start = statement["event_count"], proof["from_count"]
    if any(type(n) is not int or not 0 <= n < 2**63 for n in (count, start)) or start > count:
        raise ValueError("Invalid continuity boundary")
    root = hash_bytes(statement["root"])
    hash_bytes(statement["head_hash"])
    if not isinstance(statement["challenge"], str) or not re.fullmatch(r"[0-9a-f]{32}", statement["challenge"]):
        raise ValueError("Missing continuity challenge")
    if statement["challenge"] != challenge:
        raise ValueError("Continuity challenge differs from this check")
    for field in ("public_key", "event_count", "head_hash"):
        if statement[field] != checkpoint[field]:
            raise ValueError("Continuity proof differs from checkpoint: " + field)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    if count:
        verify_inclusion(statement["head_hash"], count - 1, count, root, proof["head_path"])
    elif root != MERKLE_EMPTY or statement["head_hash"] != "0" * 64 or proof["head_path"]:
        raise ValueError("Invalid empty journal commitment")
    expected = previous["event_count"] if previous else 0
    if start != expected:
        raise ValueError("Continuity proof starts at a different retained boundary")
    if start:
        verify_inclusion(previous["head_hash"], start - 1, count, root, proof["previous_head_path"])
    elif proof["previous_head_path"]:
        raise ValueError("Unexpected previous-head proof for empty journal")
    if previous and previous.get("root"):
        verify_consistency(start, count, hash_bytes(previous["root"]), root, proof["consistency"])
    elif start == 0:
        verify_consistency(0, count, MERKLE_EMPTY, root, proof["consistency"])
    else:


        merkle_path(proof["consistency"])
    return statement


LIVENESS_GAP_SECONDS = 180
CHANNEL_IDS_BELOW = -1000000000000
MESSAGE_KINDS = ("message.new", "message.snapshot", "message.edited", "message.recovered",
                 "message.deleted", "message.missing_on_recheck")
INTERRUPTIONS = {"transport_disconnected": "connection to Telegram lost",
                 "authorization_required": "Telegram signed the account out",
                 "resume_failed": "observation could not resume after a restart"}
SESSION_NOTES = {"updates_diverted": "Telegram's update counter grew while no update reached this session",
                 "session_revoked_externally": "this session left Telegram's session list while its connection kept working",
                 "concurrent_sessions_at_start": "other sessions were signed in when observation started",
                 "probe_ack_missed_live": "the witness answered a probe, but the answer reached this session only "
                                          "from history, not live"}
SESSION_WINDOWS = ("updates_diverted", "session_revoked_externally", "probe_ack_missed_live")
PROBE_KINDS = {"probe.sent": "sent", "probe.acked": "answered live", "probe.unanswered": "unanswered",
               "probe.inconclusive": "inconclusive"}
WITNESS_PROBE_KINDS = {"probe.seen": "seen", "probe.ack_sent": "answered", "probe.ack_failed": "answer failed"}
SOURCE_KINDS = ("message.new", "message.snapshot", "message.recovered", "message.edited")
SOURCE_GROUPS = (("live observation", ("live_update", "update_recovery")),
                 ("history reads", ("history_snapshot", "baseline_snapshot", "new_chat_snapshot", "history_acquisition",
                                    "recheck")),
                 ("panel actions", ("panel_action", "panel_button_check")))
KEY_ORIGINS = {"created": "created by signing in from this workspace", "imported": "imported from an existing session"}
LOGIN_METHODS = {"qr": "QR code", "phone_code": "phone code", "session_import": "session import"}
ACCOUNT_LOSS = {"account_banned": "account banned", "account_deleted": "account deleted",
                "account_frozen": "account frozen", "session_duplicated": "session used in two places",
                "session_revoked": "session revoked", "session_expired": "session expired",
                "session_ended": "session no longer recognised", "not_authorized": "no reason given"}


def missing_ranges(ordered):
    return [(a + 1, b - 1) for a, b in zip(ordered, ordered[1:]) if b - a > 1]


def numbered_per_chat(chat_id):
    return isinstance(chat_id, int) and chat_id < CHANNEL_IDS_BELOW


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Coverage:
    def __init__(self, gap_settings=None, *, chats_selected=False, senders_selected=False):
        self.sequences = Sequences(gap_settings, chats_selected=chats_selected, senders_selected=senders_selected)
        self.periods, self.gaps, self.notes = [], [], []
        self.start = self.alive = self.closed_at = self.close_reason = None
        self.observing = self.active = False
        self.run_id = None
        self.ids, self.titles = {}, {}
        self.first = self.last = None
        self.allowed = LIVENESS_GAP_SECONDS
        self.session = {}
        self.held, self.windows, self.sources, self.sealed_run = {}, [], {}, False

    def open(self, at):
        if self.held:
            self.alive = at
            return
        if self.closed_at is not None:
            self.gaps.append({"from": self.closed_at, "to": at, "reason": self.close_reason})
            self.closed_at = None
        self.start, self.alive, self.observing = at, at, True

    def close(self, at, reason):
        if self.observing:
            self.periods.append({"from": self.start, "to": at})
            self.observing, self.closed_at, self.close_reason = False, at, reason

    def hold(self, reason, at):
        self.close(at, SESSION_NOTES[reason])
        self.held.setdefault(reason, at)

    def release(self, reason, at, resume=False):
        since = self.held.pop(reason, None)
        if since is not None:
            self.windows.append({"from": since, "to": at, "reason": reason})
            if resume and self.active:
                self.open(at)

    def add(self, event):
        at, kind, payload, chat_id = event["observed_at"], event["kind"], event["payload"], event["chat_id"]
        self.first, self.last = self.first or at, at
        if self.observing and kind not in ("observation.started", "process.started"):
            silent = (parse_time(at) - parse_time(self.alive)).total_seconds()
            if silent > self.allowed:
                self.close(self.alive, "no capture heartbeat for " + str(round(silent / 60)) + " min while observing: "
                           "the process stopped, froze or the computer slept")
        heartbeat = (kind == "collector.heartbeat" and self.active
                     and (self.run_id is None or payload.get("run_id") == self.run_id))
        interval = payload.get("interval_seconds") if heartbeat else \
            (payload.get("parameters") or {}).get("heartbeat_seconds") if kind == "observation.started" else None
        if type(interval) is int and interval > 0:
            self.allowed = max(LIVENESS_GAP_SECONDS, 3 * interval)
        changed = (payload.get("after") or {}).get("heartbeat_seconds") if kind == "parameters.changed" else None
        if type(changed) is int and changed > 0:

            self.allowed = max(self.allowed, 3 * changed)
        if kind == "observation.started":
            self.close(self.alive, "observation restarted")
            self.release("updates_diverted", at)
            self.release("probe_ack_missed_live", at)
            self.open(at)
            self.active, self.run_id = True, payload.get("run_id")
        elif kind == "observation.stopped":
            self.close(at, "observation paused by the operator" if payload.get("reason") == "operator"
                       else "observation stopped: " + str(payload.get("reason") or "unknown"))
            self.release("updates_diverted", at)
            self.release("probe_ack_missed_live", at)
            self.active = False
        elif kind == "process.stopped":
            self.close(at, "collector process stopped")
            self.release("updates_diverted", at)
            self.release("probe_ack_missed_live", at)
            self.active = False
        elif kind == "process.started":
            self.close(self.alive, "collector process ended without an orderly stop")
            self.release("updates_diverted", at)
            self.release("probe_ack_missed_live", at)
            self.active = False
        elif kind == "collector.error":
            self.close(self.alive, "collector error: capture may be incomplete")
            self.notes.append({"at": at, "chat_id": chat_id, "reason": "collector_error",
                               "operation": payload.get("operation"), "error_type": payload.get("error_type")})
            if payload.get("observation_stopped") is True:
                self.active = False
        elif kind == "connection.closed" and payload.get("role") in (None, "current"):
            self.close(at, "connection to Telegram closed")
        elif kind == "connection.restored" and payload.get("reason") == "updates_resumed":
            self.release("updates_diverted", at, resume=True)
        elif kind == "connection.restored" and payload.get("reason") == "probe_ack_live":
            self.release("probe_ack_missed_live", at, resume=True)
        elif kind == "account.authorized":
            self.release("session_revoked_externally", at, resume=True)
        elif kind == "coverage.gap":
            reason = payload.get("reason")
            if chat_id is None and reason in INTERRUPTIONS:
                cause = ACCOUNT_LOSS.get(payload.get("cause")) if reason == "authorization_required" else None
                self.close(at, INTERRUPTIONS[reason] + (": " + cause if cause else ""))
                if reason != "transport_disconnected":
                    self.active = False
            elif chat_id is None and reason in SESSION_WINDOWS:
                self.hold(reason, at)
            else:
                self.notes.append({"at": at, "chat_id": chat_id, "reason": reason})
        elif heartbeat:
            if payload.get("connected") is True:
                if not self.observing:
                    self.open(at)
                self.alive = at
            elif payload.get("connected") is False:
                self.close(at, "collector heartbeat reports Telegram disconnected")
        if chat_id is not None and isinstance(payload.get("title"), str) and kind in (
                "target.changed", "source.discovered", "target.removed"):
            self.titles[chat_id] = payload["title"]
        if kind == "scope.applied":
            for added in payload.get("added") or []:
                self.titles[added.get("chat_id")] = added.get("title")
        if kind in MESSAGE_KINDS and numbered_per_chat(chat_id) and isinstance(event["message_id"], int):
            self.ids.setdefault(chat_id, set()).add(event["message_id"])
        self.session_event(at, kind, payload)
        if kind in SOURCE_KINDS or kind == "capture.opened":
            source = "recorder_capture" if kind == "capture.opened" else payload.get("source")
            source = source if isinstance(source, str) else "unlabelled"
            self.sources[source] = self.sources.get(source, 0) + 1
            if self.sealed_run and kind in SOURCE_KINDS:
                self.sources["inside_sealed_run"] = self.sources.get("inside_sealed_run", 0) + 1
        elif kind in ("sealed.started", "sealed.finished"):
            self.sealed_run = kind == "sealed.started"
        self.sequences.add(event, MESSAGE_KINDS)

    def session_event(self, at, kind, payload):
        s = self.session
        if kind == "account.authorized":
            s["key_origin"], s["login_method"], s["authorized_at"] = (payload.get("key_origin"),
                                                                       payload.get("login_method"), at)
        elif kind == "session.import_warning":
            s.setdefault("import_warning_at", at)
        elif kind == "account.security_event":
            counts = s.setdefault("security_events", {})
            name = str(payload.get("event_kind") or "security_notice")
            counts[name] = counts.get(name, 0) + 1
        elif kind == "account.all_other_sessions_terminated":
            s.setdefault("other_sessions_ended", []).append({"at": at, "ended": payload.get("sessions_before")})
        elif kind == "account.password_changed":
            s.setdefault("password_changes", []).append({"at": at, "operation": payload.get("operation")})
        elif kind == "account.phone_call":
            s["phone_calls"] = s.get("phone_calls", 0) + 1
        elif kind in PROBE_KINDS or kind == "coverage.gap" and payload.get("reason") == "probe_ack_missed_live":
            probes = s.setdefault("probes", {})
            name = PROBE_KINDS.get(kind, "answer missed live")
            probes[name] = probes.get(name, 0) + 1
            delay = payload.get("delay_seconds")
            if kind == "probe.acked" and isinstance(delay, (int, float)):
                s["probe_delay_max"] = max(s.get("probe_delay_max", 0), delay)
        elif kind in WITNESS_PROBE_KINDS:
            answers = s.setdefault("probe_answers", {})
            for name in (WITNESS_PROBE_KINDS[kind], "seen live" if kind == "probe.seen" and payload.get("via") == "push"
                         else None):
                if name:
                    answers[name] = answers.get(name, 0) + 1
        elif kind == "session.exclusive_from":
            s.setdefault("only_session", []).append({"from": at, "ended": payload.get("other_sessions_ended"),
                                                    "two_step": payload.get("two_step")})
        elif kind == "session.exclusive_automatic":
            s["only_session_automatic"] = {"at": at, "enabled": payload.get("enabled") is True}
        elif kind == "session.exclusive_postponed":
            s["only_session_postponed"] = s.get("only_session_postponed", 0) + 1
        elif kind == "session.exclusive_ended" and s.get("only_session"):
            s["only_session"][-1]["until"] = at
        elif kind == "session.security_baseline" and payload.get("trigger") == "observation_start" \
                and payload.get("other_sessions") == 0 and type(payload.get("other_sessions")) is int:
            s.setdefault("sessions_at_start", []).append({"at": at, "others": 0})
        elif kind == "coverage.gap" and payload.get("reason") == "concurrent_sessions_at_start":
            count = payload.get("concurrent_sessions")
            if type(count) is not int:
                count = len(payload["sessions"]) if isinstance(payload.get("sessions"), list) else None
            s.setdefault("sessions_at_start", []).append({"at": at, "others": count})
        elif kind == "account.sessions" and self.active and isinstance(payload.get("added"), list) and payload["added"]:
            s.setdefault("sessions_added", []).append({"at": at, "added": len(payload["added"])})

    def result(self, ranges_per_chat=50):
        periods = [dict(p) for p in self.periods]
        if self.observing:
            periods.append({"from": self.start, "to": self.alive, "still_observing": True})
        for period in periods:
            period["seconds"] = round((parse_time(period["to"]) - parse_time(period["from"])).total_seconds())
        gaps = [dict(g) for g in self.gaps]
        if not self.observing and self.closed_at is not None:
            gaps.append({"from": self.closed_at, "to": self.last, "reason": self.close_reason,
                         "not_resumed_by_last_record": True})
        windows = [dict(w) for w in self.windows] + [
            {"from": since, "to": self.last, "reason": reason, "not_resumed_by_last_record": True}
            for reason, since in self.held.items()]
        unobserved = []
        for chat_id, ids in sorted(self.ids.items()):
            ordered = sorted(ids)
            holes = missing_ranges(ordered)
            unobserved.append({"chat_id": chat_id, "title": self.titles.get(chat_id),
                               "observed_from": ordered[0], "observed_to": ordered[-1], "observed": len(ordered),
                               "not_observed": sum(high - low + 1 for low, high in holes),
                               "ranges": [{"low": low, "high": high} for low, high in holes[:ranges_per_chat]],
                               "ranges_total": len(holes)})
        return {"continuous": periods, "gaps": gaps, "session_windows": sorted(windows, key=lambda w: w["from"]),
                "record_sources": dict(sorted(self.sources.items())),
                "notes": self.notes[:200], "notes_total": len(self.notes),
                "unobserved_ids": unobserved, "gap_summary": self.sequences.result(self.titles), "first_record": self.first, "last_record": self.last,
                "meaning": "Observation intervals follow connected capture heartbeats from the same run, within three "
                           "heartbeat intervals (at least three minutes). Each interval ends at its last capture "
                           "confirmation or recorded stop. Session windows, while Telegram's update counter grew "
                           "without updates reaching this session or while Telegram no longer listed it, are gaps. "
                           "Message-number gaps describe the observed numbering range.",
                **({"session": self.session} if self.session else {})}


GAP_DEFAULTS = {"gap_analysis": True, "gap_account_sequence": True, "gap_cluster_min": 1, "gap_clusters_listed": 20,
            "gap_service_estimate": False}
WIDE_TYPES = ("private", "groups", "bots")
GAP_MEANING = ("A gap is a message number between two observed messages that this collector never saw. Telegram assigns "
           "these numbers; a gap may be a message Telegram never showed to this account.")
ESTIMATE_MEANING = ("Estimate from the share of service messages among observed numbers. It does not explain any "
                    "particular gap and is never subtracted from the missing count.")


def account_numbered(chat_id):
    return isinstance(chat_id, int) and chat_id > CHANNEL_IDS_BELOW


def gap_parameters(values=None):
    if values is not None and not isinstance(values, dict):
        raise ValueError("Gap parameters must be an object")
    values = {**GAP_DEFAULTS, **(values or {})}
    for key in ("gap_analysis", "gap_account_sequence", "gap_service_estimate"):
        if type(values[key]) is not bool:
            raise ValueError("Invalid gap parameter: " + key)
    for key, maximum in (("gap_cluster_min", 100000), ("gap_clusters_listed", 200)):
        if type(values[key]) is not int or not 1 <= values[key] <= maximum:
            raise ValueError("Invalid gap parameter: " + key)
    return {key: values[key] for key in GAP_DEFAULTS}


def not_applicable(reason):
    return {"status": "not_applicable", "reason": reason}


NOTICE_KINDS = ("message.deleted", "message.missing_on_recheck")


def summarize_gaps(times, settings, service=0, notices=()):
    ordered = sorted(times)
    if len(ordered) < 2:
        return not_applicable("Fewer than two observed messages; there is no range to measure.")
    holes = [(low + 1, high - 1) for low, high in zip(ordered, ordered[1:]) if high - low > 1]
    span = ordered[-1] - ordered[0] + 1
    missing = sum(high - low + 1 for low, high in holes)
    listed = [hole for hole in holes if hole[1] - hole[0] + 1 >= settings["gap_cluster_min"]]
    largest = sorted(listed, key=lambda hole: (hole[0] - hole[1], hole[0]))[:settings["gap_clusters_listed"]]
    result = {"status": "applicable", "observed_from": ordered[0], "observed_to": ordered[-1], "span": span,
              "observed": len(ordered), "observed_without_content": len(notices),
              "missing": missing, "density": round(missing / span, 6),
              "gap_ranges": len(holes), "largest_gap": max((high - low + 1 for low, high in holes), default=0),
              "clusters_total": len(listed),
              "clusters": [{"low": low, "high": high, "missing": high - low + 1,
                            "after": {"message_id": low - 1, "observed_at": times[low - 1]},
                            "before": {"message_id": high + 1, "observed_at": times[high + 1]}}
                           for low, high in sorted(largest)]}
    if settings["gap_service_estimate"]:
        share = service / len(ordered)
        result["service_estimate"] = {"service_share": round(share, 4),
                                      "expected_service_in_missing": round(missing * share),
                                      "meaning": ESTIMATE_MEANING}
    return result


def wide(scope):
    if not isinstance(scope, dict) or scope.get("mode") != "account":
        return False
    types = scope.get("types") if isinstance(scope.get("types"), dict) else {}
    excluded = [chat for chat in scope.get("exclude") or scope.get("excluded") or [] if account_numbered(chat)]
    return all(types.get(kind) is True for kind in WIDE_TYPES) and scope.get("own_actions") is True and not excluded


def scope_reason(scope):
    if not isinstance(scope, dict) or scope.get("mode") != "account":
        return ("Private chats, bots and ordinary groups share one account-wide numbering. It can be measured only "
                "while whole-account collection is on; this journal has no such period.")
    return ("Private chats, bots, ordinary groups and the account's own messages take numbers from the same "
            "sequence, so the measurement needs a scope recorded as including all of them without excluded chats.")


class Sequences:

    def __init__(self, settings=None, *, chats_selected=False, senders_selected=False):
        self.settings = gap_parameters(settings)
        self.chats_selected, self.senders_selected = chats_selected, senders_selected
        self.channels, self.services, self.content = {}, {}, {}
        self.account, self.account_service, self.account_content, self.window = {}, set(), set(), None
        self.scope, self.wide_since, self.wide_periods = None, None, 0
        self.paused, self.disabled, self.monitoring = False, set(), {}

    def add(self, event, message_kinds):
        if not self.settings["gap_analysis"]:
            return
        kind, chat_id, message_id = event["kind"], event["chat_id"], event["message_id"]
        payload = event["payload"] if isinstance(event["payload"], dict) else {}
        if kind == "scope.changed" and isinstance(payload.get("after"), dict):
            self.set_scope(payload["after"], event["observed_at"])
        elif kind == "scope.applied":
            self.set_scope({**(self.scope or {}), "mode": payload.get("mode"), "types": payload.get("types"),
                            "own_actions": payload.get("own_actions", (self.scope or {}).get("own_actions")),
                            "exclude": payload.get("excluded") or []}, event["observed_at"])
        elif kind in ("observation.stopped", "process.stopped", "process.started"):
            self.paused = True
        elif kind == "observation.started":
            if self.paused and self.wide_since is not None:
                self.wide_periods += 1
            self.paused = False
            if isinstance(payload.get("scope"), dict):
                self.set_scope(payload["scope"], event["observed_at"])
        elif kind == "target.changed" and account_numbered(chat_id):
            if payload.get("enabled") is False:
                self.disabled.add(chat_id)
            else:
                self.disabled.discard(chat_id)
            self.set_scope(self.scope, event["observed_at"])
        elif kind == "monitoring.changed" and isinstance(payload.get("after"), dict):
            self.monitoring = payload["after"]
            self.set_scope(self.scope, event["observed_at"])
        elif kind == "deletion.unscoped":
            for number in payload.get("message_ids") or []:
                if type(number) is int and number > 0:
                    self.account.setdefault(number, event["observed_at"])
        if type(message_id) is not int or message_id <= 0:
            return
        service = kind in ("chat.service", "membership.service")
        if numbered_per_chat(chat_id):
            if kind in message_kinds or service:
                self.channels.setdefault(chat_id, {}).setdefault(message_id, event["observed_at"])
                if kind not in NOTICE_KINDS:
                    self.content.setdefault(chat_id, set()).add(message_id)
            if service:
                self.services.setdefault(chat_id, set()).add(message_id)
        elif account_numbered(chat_id):
            if kind in message_kinds or service:
                self.account.setdefault(message_id, event["observed_at"])
                if kind not in NOTICE_KINDS:
                    self.account_content.add(message_id)
                if kind == "message.new" and self.wide_since is not None and not self.paused:
                    low, high = self.window or (message_id, message_id)
                    self.window = (min(low, message_id), max(high, message_id))
            if service:
                self.account_service.add(message_id)

    def set_scope(self, scope, at):
        self.scope = scope
        recorded = all(self.monitoring.get(kind, True) is not False for kind in ("messages", "membership"))
        if wide(scope) and not self.disabled and recorded:
            if self.wide_since is None:
                self.wide_since, self.wide_periods = at, self.wide_periods + 1
        else:
            self.wide_since = None

    def result(self, titles=None, chat_limit=None):
        titles = titles or {}
        settings = self.settings
        summary = {"parameters": settings, "meaning": GAP_MEANING, "chats": [], "account": None}
        if not settings["gap_analysis"]:
            summary["status"] = "off"
            return summary
        summary["status"] = "on"
        for chat_id in sorted(self.channels)[:chat_limit]:
            entry = {"chat_id": chat_id, "title": titles.get(chat_id), "numbering": "per chat"}
            if self.senders_selected:
                entry.update(not_applicable("Records were selected by sender, so other senders' numbers are absent."))
            else:
                times = self.channels[chat_id]
                entry.update(summarize_gaps(times, settings, len(self.services.get(chat_id, ())),
                                       [n for n in times if n not in self.content.get(chat_id, ())]))
            summary["chats"].append(entry)
        if chat_limit is not None and len(self.channels) > chat_limit:
            summary["chats_truncated"] = len(self.channels) - chat_limit
        summary["account"] = {"numbering": "account-wide: private chats, bots and ordinary groups",
                              **self.account_result()}
        return summary

    def account_result(self):
        if not self.settings["gap_account_sequence"]:
            return not_applicable("Turned off in Parameters → Gap analysis.")
        if self.chats_selected or self.senders_selected:
            return not_applicable("Records were selected by chat or sender; other chats take numbers from the "
                                  "same account-wide sequence.")
        if not self.wide_periods or self.window is None:
            return not_applicable(scope_reason(self.scope))
        low, high = self.window
        inside = {number: at for number, at in self.account.items() if low <= number <= high}
        result = summarize_gaps(inside, self.settings, len(self.account_service.intersection(inside)),
                           [n for n in inside if n not in self.account_content])
        result["window"] = "from the first to the last message that arrived while whole-account collection was on"
        if self.wide_periods > 1:
            result["note"] = ("Whole-account collection was switched off and on again; numbers used while it was off "
                              "appear as gaps.")
        return result


def session_lines(coverage):
    s, lines = coverage.get("session") or {}, []
    if s.get("key_origin"):
        lines.append("Telegram session key: " + KEY_ORIGINS.get(s["key_origin"], str(s["key_origin"]))
                     + (" by " + LOGIN_METHODS.get(s["login_method"], str(s["login_method"])) if s.get("login_method") else "")
                     + " at " + str(s.get("authorized_at")))
    windows = coverage.get("session_windows")
    for reason, label in SESSION_NOTES.items():
        if (windows is not None and reason in SESSION_WINDOWS
                or reason == "concurrent_sessions_at_start" and s.get("sessions_at_start")):
            continue
        found = [n["at"] for n in coverage.get("notes") or [] if n.get("reason") == reason and n.get("chat_id") is None]
        if found:
            lines.append("Session: " + label + " (" + str(len(found)) + "x, first " + found[0] + ")")
    for window in windows or []:
        lines.append("Session window from " + window["from"] + " to " + window["to"] + ": "
                     + SESSION_NOTES.get(window["reason"], str(window["reason"]))
                     + (", not resumed by the last record" if window.get("not_resumed_by_last_record") else ""))
    for item in s.get("sessions_at_start") or []:
        lines.append("Other sessions signed in at observation start: "
                     + ("count not recorded" if item.get("others") is None else str(item["others"])) + " (" + item["at"] + ")")
    added = s.get("sessions_added") or []
    if added:
        lines.append("Sessions added to Telegram's session list during observation: "
                     + str(sum(item["added"] for item in added)) + " in " + str(len(added)) + " record(s), first "
                     + added[0]["at"])
    if s.get("security_events"):
        lines.append("Telegram security notices (777000): " + ", ".join(
            name + " " + str(count) for name, count in sorted(s["security_events"].items())))
    for item in s.get("other_sessions_ended") or []:
        lines.append("All other sessions ended from this workspace at " + item["at"]
                     + (" (" + str(item["ended"]) + " signed in before)" if isinstance(item.get("ended"), int) else ""))
    for item in s.get("password_changes") or []:
        lines.append("Two-step password " + str(item.get("operation") or "set or changed") + " from this workspace at " + item["at"])
    for item in s.get("only_session") or []:
        lines.append("Only session of the account from " + item["from"]
                     + (" until another session appeared at " + item["until"] if item.get("until") else "")
                     + ": other sessions ended" + (" (" + str(item["ended"]) + ")" if isinstance(item.get("ended"), int) else "")
                     + ", two-step password " + ("set from this workspace" if item.get("two_step") == "set_now"
                                                  else "already on"))
    if s.get("only_session_automatic"):
        item = s["only_session_automatic"]
        lines.append("Automatic only-session " + ("on" if item["enabled"] else "off") + " from " + item["at"]
                     + (", postponed by Telegram " + str(s["only_session_postponed"]) + " time(s)"
                        if s.get("only_session_postponed") else ""))
    if s.get("probes"):
        lines.append("Witness probes: " + ", ".join(name + " " + str(count) for name, count in s["probes"].items())
                     + ("; slowest live answer " + str(round(s["probe_delay_max"], 1)) + " s"
                        if s.get("probe_delay_max") is not None else ""))
    if s.get("probe_answers"):
        lines.append("Probes of another workspace answered as its witness: "
                     + ", ".join(name + " " + str(count) for name, count in s["probe_answers"].items()))
    if s.get("phone_calls"):
        lines.append("Phone call updates delivered to this session: " + str(s["phone_calls"]))
    return lines


def source_counts(coverage):
    sources = dict(coverage.get("record_sources") or {})
    groups = [(label, [(name, sources.pop(name)) for name in names if name in sources]) for label, names in SOURCE_GROUPS]
    captures, unlabelled = sources.pop("recorder_capture", 0), sources.pop("unlabelled", 0)
    sealed = sources.pop("inside_sealed_run", 0)
    return [(label, found) for label, found in groups if found], sorted(sources.items()), unlabelled, captures, sealed


def source_lines(coverage):
    groups, other, unlabelled, captures, sealed = source_counts(coverage)
    parts = [label + " " + str(sum(count for _, count in found)) + " ("
             + ", ".join(name + " " + str(count) for name, count in found) + ")" for label, found in groups]
    parts += ["source " + name + " " + str(count) for name, count in other]
    if unlabelled:
        parts.append("no source label " + str(unlabelled))
    lines = ["Message records by source: " + "; ".join(parts)] if parts else []
    if sealed:
        lines.append("Message records between sealed.started and sealed.finished (sealed run): " + str(sealed))
    if captures:
        lines.append("Recorder captures linked into this journal: " + str(captures))
    return lines


def coverage_lines(coverage):
    def span(seconds):
        hours, rest = divmod(int(seconds), 3600)
        return (str(hours) + " h " if hours else "") + str(rest // 60) + " min"
    lines = ["Continuously observed from " + p["from"] + " to " + p["to"] + " (" + span(p["seconds"]) + ")"
             + (", observing at the last capture confirmation" if p.get("still_observing") else "")
             for p in coverage["continuous"]]
    lines += ["Gap from " + g["from"] + " to " + g["to"] + ": " + str(g["reason"]) for g in coverage["gaps"]]
    lines += session_lines(coverage)
    lines += source_lines(coverage)
    for chat in coverage["unobserved_ids"]:
        if chat["not_observed"]:
            lines.append("Chat " + (chat["title"] or str(chat["chat_id"])) + ": IDs " + str(chat["observed_from"])
                         + "-" + str(chat["observed_to"]) + ", " + str(chat["not_observed"])
                         + " ID(s) not observed in " + str(chat["ranges_total"]) + " range(s)")
    gaps, extra = coverage.get("gap_summary") or {}, []
    account = gaps.get("account") if gaps.get("status") == "on" else None
    if account and account.get("status") == "applicable":
        extra.append("Account-wide sequence (private chats, bots, ordinary groups): IDs " + str(account["observed_from"])
                     + "-" + str(account["observed_to"]) + ", " + str(account["missing"]) + " ID(s) not observed in "
                     + str(account["gap_ranges"]) + " range(s)")
    elif account:
        extra.append("Account-wide sequence not measured: " + str(account.get("reason")))
    return (lines or ["No observation period recorded."]) + extra


def drand_time(number):
    return datetime.fromtimestamp(DRAND_GENESIS + (number - 1) * DRAND_PERIOD, timezone.utc).isoformat(
        timespec="milliseconds")


def drand_beacon(value):
    if not isinstance(value, dict) or type(value.get("round")) is not int or value["round"] < 1:
        raise ValueError("drand value without a round number")
    signature, randomness = value.get("signature"), value.get("randomness")
    if not (isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{96}", signature) and isinstance(randomness, str)
            and hashlib.sha256(bytes.fromhex(signature)).hexdigest() == randomness):
        raise ValueError("drand randomness is not the hash of its signature")
    return {"round": value["round"], "randomness": randomness, "signature": signature}


class OutsideRecords:
    def __init__(self):
        self.rounds, self.checks, self.changes = [], [], []
        self.devices, self.largest_gap, self.clock_behind = {}, 0, 0
        self.windows, self.names, self.gaps, self.queries, self.truncated = [], {}, [], 0, 0

    def add(self, event):
        at, kind, payload = event["observed_at"], event["kind"], event["payload"]
        if kind == "beacon.drand":
            beacon = drand_beacon(payload)
            if payload.get("chain") != DRAND_CHAIN or payload.get("round_time") != drand_time(beacon["round"]):
                raise ValueError("drand value from another chain or with a wrong round time at record "
                                 + str(event["seq"]))
            self.clock_behind = max(self.clock_behind,
                                    (parse_time(payload["round_time"]) - parse_time(at)).total_seconds())
            if self.rounds:
                self.largest_gap = max(self.largest_gap,
                                       (parse_time(at) - parse_time(self.rounds[-1]["at"])).total_seconds())
            self.rounds.append({"seq": event["seq"], "at": at, **beacon, "round_time": payload["round_time"]})
        elif kind == "cloudflare.gateway_dns":
            queries, fields = payload.get("queries"), payload.get("fields")
            try:
                window = parse_time(payload["from"]) < parse_time(payload["until"])
            except (KeyError, AttributeError, TypeError, ValueError):
                window = False
            if not (window and isinstance(queries, list) and fields == list(GATEWAY_FIELDS)
                    and payload.get("count") == len(queries)
                    and all(isinstance(q, list) and len(q) == len(GATEWAY_FIELDS) for q in queries)):
                raise ValueError("Cloudflare Gateway log record " + str(event["seq"]) + " is malformed")
            previous = self.windows[-1] if self.windows else None
            if previous and previous["location_id"] == payload.get("location_id") \
                    and previous["address"] == payload.get("address") and payload["from"] != previous["until"]:
                self.gaps.append({"from": previous["until"], "until": payload["from"], "at": at})
            self.windows.append({"seq": event["seq"], "at": at, "from": payload["from"], "until": payload["until"],
                                 "count": len(queries), "location_id": payload.get("location_id"),
                                 "address": payload.get("address")})
            self.queries += len(queries)
            self.truncated += payload.get("truncated") is True
            for query in queries:
                self.names[str(query[1])] = self.names.get(str(query[1]), 0) + 1
        elif kind == "account.devices" and type(payload.get("count")) is int:
            self.checks.append(at)
            listed = payload.get("devices")
            if isinstance(listed, list):
                current = {str(d.get("hash")): d for d in listed if isinstance(d, dict)}
                self.changes.append({"at": at, "count": payload["count"], "devices": list(current.values()),
                                     "added": [current.get(h, {"hash": h}) for h in payload.get("added") or []],
                                     "removed": [self.devices.get(h, {"hash": h}) for h in payload.get("removed") or []]})
                self.devices = current

    def result(self):
        return {"drand": {"rounds": len(self.rounds), "chain": DRAND_CHAIN,
                          "first": self.rounds[0] if self.rounds else None,
                          "last": self.rounds[-1] if self.rounds else None,
                          "largest_gap_seconds": round(self.largest_gap),
                          "clock_behind_seconds": round(self.clock_behind, 1) if self.clock_behind > 0 else 0,
                          "meaning": "Offline checks establish only the recorded beacon's self-consistency, "
                                     "not its BLS signature or a lower time bound. --check-drand compares "
                                     "selected rounds with HTTPS relays. Only authenticated rounds can support "
                                     "a lower time bound for subsequent records; unchecked rounds cannot."},
                "devices": {"checks": len(self.checks), "first_check": self.checks[0] if self.checks else None,
                            "last_check": self.checks[-1] if self.checks else None, "changes": self.changes[:200],
                            "changes_total": len(self.changes),
                            "meaning": "Telegram's list of sessions of this account (Settings, Devices) as the "
                                       "collector received it; IP addresses are not recorded."},
                "gateway": {"windows": len(self.windows), "queries": self.queries,
                            "first": self.windows[0]["from"] if self.windows else None,
                            "last": self.windows[-1]["until"] if self.windows else None,
                            "locations": sorted({w["location_id"] for w in self.windows if w["location_id"]}),
                            "addresses": sorted({w["address"] for w in self.windows if w["address"]}),
                            "names": sorted(self.names.items(), key=lambda item: (-item[1], item[0]))[:100],
                            "names_total": len(self.names), "gaps": self.gaps[:50], "gaps_total": len(self.gaps),
                            "truncated_windows": self.truncated,
                            "meaning": "DNS queries as Cloudflare Gateway logged them and its API returned them to "
                                       "the collector, window after window; a gap is time no copy covers. Cloudflare "
                                       "keeps its own copy 24 hours on the free plan."}}


def device_name(device, active=False):
    if set(device) == {"hash"}:
        return "session " + str(device["hash"])
    parts = [" ".join(str(device.get(k) or "") for k in ("device_model", "platform", "system_version")).strip(),
             " ".join(str(device.get(k) or "") for k in ("app_name", "app_version")).strip(),
             str(device.get("country") or "")]
    if device.get("current"):
        parts.append("this collector")
    elif active and device.get("active_at"):
        parts.append("active " + str(device["active_at"]))
    return ", ".join(p for p in parts if p)


def outside_lines(outside):
    lines, drand, devices = [], outside["drand"], outside["devices"]
    if drand["rounds"]:
        lines.append(str(drand["rounds"]) + " drand round(s) recorded from " + drand["first"]["at"] + " to "
                     + drand["last"]["at"] + "; the longest stretch without a new round is "
                     + str(round(drand["largest_gap_seconds"] / 60)) + " min")
        checked = drand.get("checked")
        if not checked:
            lines.append("drand beacons are self-consistent only: no BLS signature or lower time bound verified. "
                         "Run with --check-drand to compare rounds with HTTPS relays.")
        elif checked["relays"]:
            lines.append("Confirmed by drand relays: " + str(checked["confirmed"]) + " of " + str(checked["asked"])
                         + " round(s) asked (" + ", ".join(checked["relays"]) + ")"
                         + ("" if len(checked["relays"]) > 1 else "; only one operator answered"))
        else:
            lines.append("Rounds could not be compared: no drand relay answered")
        if drand["clock_behind_seconds"] > 1:
            lines.append("Recorded observation times trail recorded drand round times by up to "
                         + str(drand["clock_behind_seconds"])
                         + " s.")
    gateway = outside.get("gateway") or {}
    if gateway.get("windows"):
        lines.append("Cloudflare Gateway DNS log copied in " + str(gateway["windows"]) + " window(s) from "
                     + gateway["first"] + " to " + gateway["last"] + ": " + str(gateway["queries"]) + " quer(ies), "
                     + str(gateway["names_total"]) + " name(s)"
                     + (" from " + ", ".join(gateway["addresses"]) if gateway["addresses"] else ""))
        if gateway["names"]:
            lines.append("Names looked up most: " + ", ".join(name + " (" + str(count) + ")"
                                                               for name, count in gateway["names"][:15]))
        lines += ["Gateway log not copied from " + gap["from"] + " to " + gap["until"] for gap in gateway["gaps"][:10]]
        if gateway.get("truncated_windows"):
            lines.append(str(gateway["truncated_windows"]) + " window(s) held more queries in one second than one "
                         "page of Cloudflare's log: the rest of that second is not in the copy")
    if devices["checks"]:
        lines.append("Telegram device list recorded " + str(devices["checks"]) + " time(s) from "
                     + devices["first_check"] + " to " + devices["last_check"] + "; it changed "
                     + str(max(0, devices["changes_total"] - 1)) + " time(s) after the first list")
        for change in devices["changes"][:20]:
            lines += [change["at"] + ": new session: " + device_name(d) for d in change["added"]]
            lines += [change["at"] + ": session ended: " + device_name(d) for d in change["removed"]]
            if not (change["added"] or change["removed"]):
                lines.append(change["at"] + ": " + str(change["count"]) + " session(s): "
                             + "; ".join(device_name(d, True) for d in change["devices"]))
    return lines


def confirm_drand(rounds, relays=DRAND_RELAYS, limit=DRAND_CHECK_LIMIT, fetch=None):
    import random
    chosen = rounds if len(rounds) <= limit else \
        [rounds[0], rounds[-1]] + random.SystemRandom().sample(rounds[1:-1], limit - 2)
    fetch = fetch or drand_fetcher()
    used = []
    for group in (relays[:1], relays[1:]):
        for relay in group:
            try:
                answers = [(item, drand_beacon(fetch(relay, item["round"]))) for item in chosen]
            except (OSError, ValueError):
                continue
            for item, answer in answers:
                if answer["round"] != item["round"] or answer["randomness"] != item["randomness"]:
                    raise ValueError("drand round " + str(item["round"]) + " at record " + str(item["seq"])
                                     + " differs from " + relay + ": the recorded value is not drand's")
            used.append(relay)
            break
    return {"asked": len(chosen), "confirmed": len(chosen) if used else 0, "relays": used,
            "unavailable": bool(chosen) and not used}


def drand_fetcher():
    import http.client
    from urllib.parse import urlsplit
    connections = {}

    def fetch(relay, number):
        host = urlsplit(relay).hostname
        for attempt in (0, 1):
            connection = connections.get(host) or http.client.HTTPSConnection(host, timeout=20)
            connections[host] = connection
            try:
                connection.request("GET", "/" + DRAND_CHAIN + "/public/" + str(number),
                                   headers={"Accept": "application/json", "User-Agent": "TgWitness verify"})
                reply = connection.getresponse()
                body = reply.read(4096)
                if reply.status != 200:
                    raise OSError(relay + " answered HTTP " + str(reply.status))
                return json.loads(body)
            except (http.client.HTTPException, ConnectionError):
                connection.close()
                connections.pop(host, None)
                if attempt:
                    raise OSError(relay + " closed the connection")
    return fetch


def verify_events(events, public_key):
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
    previous, count = "0" * 64, 0
    previous_time, previous_at = None, None
    chronology = {"regressions": 0, "unparseable": 0, "samples": []}
    for count, event in enumerate(events, 1):
        if set(event) != set(FIELDS) | {"hash", "signature"}:
            raise ValueError("Unexpected or missing fields at event " + str(count))
        if event["seq"] != count or event["previous_hash"] != previous:
            raise ValueError("Broken sequence or hash chain at event " + str(count))
        calculated = hashlib.sha256(canonical({k: event[k] for k in FIELDS})).hexdigest()
        if event["hash"] != calculated:
            raise ValueError("Changed content at event " + str(count))
        key.verify(base64.b64decode(event["signature"], validate=True), bytes.fromhex(calculated))
        anomaly = None
        try:
            observed = parse_time(event["observed_at"])
            if observed.utcoffset() is None:
                raise ValueError("Observation time has no UTC offset")
        except (AttributeError, TypeError, ValueError, OverflowError):
            observed = None
            chronology["unparseable"] += 1
            anomaly = {"seq": count, "observed_at": event["observed_at"], "reason": "unparseable"}
        if observed is not None and previous_time is not None and observed < previous_time:
            chronology["regressions"] += 1
            anomaly = {"seq": count, "observed_at": event["observed_at"], "previous_at": previous_at,
                       "backwards_seconds": (previous_time - observed).total_seconds(), "reason": "regression"}
        if anomaly is not None and len(chronology["samples"]) < 100:
            chronology["samples"].append(anomaly)
        if observed is not None:
            previous_time, previous_at = observed, event["observed_at"]
        if event["kind"] == "media.hashed":
            payload = event["payload"]
            validate_server_hashes(payload.get("server_hashes"))
            if (payload["server_hashes"]["status"] != "complete" or payload.get("downloaded_bytes") != 0
                    or payload.get("media_sha256") is not None):
                raise ValueError("A hash-only record incorrectly claims downloaded file content")
        previous = calculated
    result = {"events": count, "head_hash": previous, "fingerprint": fingerprint(public_key)}
    if chronology["regressions"] or chronology["unparseable"]:
        chronology["meaning"] = ("Observation times are collector-supplied. These anomalies do not invalidate "
                                 "signatures; chronological claims rest on independent time evidence such as a "
                                 "timestamp or a witness record.")
        result["chronology"] = chronology
    return result


def media_reference(event):
    if event["kind"] not in ("media.saved", "actor.avatar_saved", "secret_chat.file"):
        return None
    payload = event["payload"]
    digest, size = payload.get("media_sha256"), payload.get("size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid media reference in the signed journal")
    if size is not None and (type(size) is not int or size < 0):
        raise ValueError("Invalid media size in the signed journal")
    return digest, size


def verify_checkpoint(checkpoint, public_key, event_count, hash_at, check_drand=False):
    statement = checkpoint["statement"]
    if not is_format(statement["format"], "checkpoint-v1") or statement["public_key"] != public_key:
        raise ValueError("Checkpoint format or signing key mismatch")
    if type(statement["event_count"]) is not int or statement["event_count"] < 0:
        raise ValueError("Invalid checkpoint event count")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
        base64.b64decode(checkpoint["signature"], validate=True), canonical(statement))
    if statement["event_count"] > event_count:
        raise ValueError("Journal is shorter than the retained checkpoint")
    if hash_at(statement["event_count"]) != statement["head_hash"]:
        raise ValueError("Journal disagrees with the retained checkpoint")
    anchor = statement.get("drand_anchor")
    if check_drand and anchor and isinstance(anchor.get("round"), int) and isinstance(anchor.get("randomness"), str):
        try:
            confirmed = confirm_drand([{"round": anchor["round"], "randomness": anchor["randomness"],
                                        "seq": statement["event_count"]}])
        except ValueError as exc:
            raise ValueError("Checkpoint drand anchor: " + str(exc)) from exc
        if confirmed["confirmed"] == 0:
            raise ValueError("Checkpoint drand anchor round " + str(anchor["round"])
                             + " could not be confirmed against any drand relay")
    return anchor if anchor else None


def read_sealed(stream):
    digest, window, start = hashlib.sha256(), b"", None
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        start = chunk[:16] if start is None else start
        window += chunk
        if len(window) > 2 * SEAL_WINDOW:
            digest.update(window[:-SEAL_WINDOW])
            window = window[-SEAL_WINDOW:]
    at = window.rfind(SEAL_OPEN)
    if at < 0:
        return None
    if not start.lower().startswith(b"<!doctype html"):
        raise ValueError("This seal belongs to an HTML report, but the file is not one")
    digest.update(window[:at])
    block = window[at + len(SEAL_OPEN):]
    if not block.endswith(SEAL_CLOSE):
        raise ValueError("The report seal is not at the end of the file")
    raw = block[:-len(SEAL_CLOSE)]
    if b"<" in raw:
        raise ValueError("The report seal contains markup")
    return digest.hexdigest(), strict_json(raw)


def check_seal(sealed, public_key=None, expected_fingerprint=None):
    content, seal = sealed
    statement = authenticate_statement(seal)
    if not is_format(statement.get("format"), "report-seal-v1"):
        raise VerifierTooOld("Unsupported report seal")
    key = statement["public_key"]
    if public_key is not None and key != public_key:
        raise ValueError("The report was sealed with a different key than the archive")
    fp = fingerprint(key)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(
        base64.b64decode(seal["signature"], validate=True), canonical(statement))
    if statement.get("content_sha256") != content:
        raise ValueError("The report was changed after it was sealed")
    return {"report_id": statement.get("report_id"), "created_at": statement.get("created_at"),
            "language": statement.get("language"), "case": statement.get("case") or {},
            "subject": statement.get("subject") or {}, "producer": statement.get("producer"), "fingerprint": fp}


def archive_seal(archive, name, public_key):
    with archive.open(name) as stream:
        sealed = read_sealed(stream)
    return check_seal(sealed, public_key) if sealed else None


REPORT_JSON = "report-json-v1"
PDF_SEAL = "2.25.240684792623320047764573196045913242332"
SIGNING_TIME = "1.2.840.113549.1.9.5"


def read_pdf_seal(data):
    ranges = re.findall(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", data)
    if len(ranges) != 1:
        raise ValueError("Not a PDF signed by TgWitness: exactly one signature is expected")
    a, b, c, d = map(int, ranges[0])
    if a != 0 or not 0 < b < c or c + d != len(data) or data[b:b + 1] != b"<" or data[c - 1:c] != b">":
        raise ValueError("The PDF signature does not cover the whole file")
    raw = bytes.fromhex(data[b + 1:c - 1].decode("ascii"))
    content = hashlib.sha256(data[:b] + data[c:]).digest()
    _, start, end = der(raw, 0)
    info = children(raw, start, end)
    if oid(raw, info[0][2], info[0][3]) != SIGNED_DATA:
        raise ValueError("The PDF signature is not CMS signed data")
    _, start, end = der(raw, info[1][2])
    signed = children(raw, start, end)
    certificates = next(item for item in signed if item[0] == 0xA0)
    tag, offset, _, value_end = children(raw, certificates[2], certificates[3])[0]
    der_certificate = raw[offset:value_end]
    certificate = x509.load_der_x509_certificate(der_certificate)
    signer = children(raw, signed[-1][2], signed[-1][3])[0]
    parts = children(raw, signer[2], signer[3])
    attributes = next(item for item in parts if item[0] == 0xA0)
    unsigned = next((item for item in parts if item[0] == 0xA1), None)
    signature = next(item for item in parts if item[0] == 0x04)

    def values(item):
        found = {}
        for _, _, s, e in children(raw, item[2], item[3]):
            kind = children(raw, s, e)
            found[oid(raw, kind[0][2], kind[0][3])] = children(raw, kind[1][2], kind[1][3])[0]
        return found
    signed_attributes = values(attributes)
    digest = signed_attributes.get(MESSAGE_DIGEST)
    if digest is None or raw[digest[2]:digest[3]] != content:
        raise ValueError("The PDF was changed after it was signed")
    certificate.public_key().verify(raw[signature[2]:signature[3]], b"\x31" + raw[attributes[1] + 1:attributes[3]],
                                    ec.ECDSA(hashes.SHA256()))
    seal = values(unsigned).get(PDF_SEAL) if unsigned else None
    if seal is None:
        raise ValueError("The PDF signature carries no TgWitness seal")
    seal = strict_json(raw[seal[2]:seal[3]].decode("utf-8"))
    certificate_sha256 = hashlib.sha256(der_certificate).hexdigest()
    if seal["statement"].get("document_certificate_sha256") != certificate_sha256 \
            or seal["statement"].get("content") != "pdf-byte-range":
        raise ValueError("The seal does not vouch for the certificate that signed this PDF")
    when = signed_attributes.get(SIGNING_TIME)
    names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return content.hex(), seal, {"certificate": names[0].value if names else certificate.subject.rfc4514_string(),
                                 "certificate_subject": certificate.subject.rfc4514_string(),
                                 "certificate_sha256": certificate_sha256,
                                 "signing_time": raw[when[2]:when[3]].decode("ascii") if when else None}


def read_json_seal(data):
    if not isinstance(data, dict) or set(data) != {"format", "report", "seal"} \
            or not is_format(data.get("format"), REPORT_JSON):
        raise ValueError("Not a TgWitness JSON report")
    return hashlib.sha256(canonical(data["report"])).hexdigest(), data["seal"]


def report_companions(archive, manifest, public, describes):
    files, report = manifest["files"], manifest.get("report") or {}
    checked = {"json": None, "parts": 0, "pdf": None}
    if "report.json" in files:
        seal = check_seal(read_json_seal(strict_json(read_member(archive, "report.json", MAX_JSON_BYTES))), public)
        if not describes(seal["subject"]):
            raise ValueError("report.json describes a different export")
        checked["json"] = seal
    for name in ("report.pdf", "chat.pdf"):
        if name in files:
            content, seal, signature = read_pdf_seal(read_member(archive, name, MAX_JSON_BYTES))
            seal = check_seal((content, seal), public)
            if not describes(seal["subject"]):
                raise ValueError(name + " describes a different export")
            checked["pdf"] = {**seal, "file": name, "pdf_signature": signature}
    parts = report.get("parts") or []
    for number, part in enumerate(parts, 1):
        name = part.get("file") if isinstance(part, dict) else None
        if name not in files:
            raise ValueError("A report part named in the manifest is missing: " + str(name))
        seal = archive_seal(archive, name, public)
        subject = (seal or {}).get("subject") or {}
        if not seal or not describes(subject) or subject.get("part") != number or subject.get("parts") != len(parts):
            raise ValueError("Report part " + name + " does not belong to this export")
        checked["parts"] += 1
    return checked


def check_sums(archive, manifest):
    if "SHA256SUMS" not in manifest["files"]:
        return None
    listed = {}
    for line in read_member(archive, "SHA256SUMS", MAX_MANIFEST_BYTES).decode("utf-8").splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest
    if listed != {name: digest for name, digest in manifest["files"].items() if name != "SHA256SUMS"}:
        raise ValueError("SHA256SUMS disagrees with the signed manifest")
    return len(listed)


def verify_report(path, expected_fingerprint=None, evidence=None):
    signature = None
    if Path(path).suffix.lower() == ".json":
        sealed = read_json_seal(read_json_file(path))
    elif Path(path).suffix.lower() == ".pdf":
        if Path(path).stat().st_size > MAX_JSON_BYTES:
            raise ValueError(Path(path).name + " exceeds the verifier's size limit")
        content, seal, signature = read_pdf_seal(Path(path).read_bytes())
        sealed = content, seal
    else:
        with open(path, "rb") as stream:
            sealed = read_sealed(stream)
    if not sealed:
        raise ValueError("This report has no seal: it was made before seals or not by TgWitness")
    seal = check_seal(sealed, None, expected_fingerprint)
    subject = seal["subject"]
    result = {"format": "tgwitness-report-seal-v1", "fingerprint": seal["fingerprint"], "report_seal": seal,
              "producer": seal["producer"], "key_pinned": bool(expected_fingerprint), "evidence_checked": False,
              **({"pdf_signature": signature} if signature else {})}
    if evidence:
        if is_format(bundle_format(evidence), "chat-export-v1"):
            checked = verify_chat_export(evidence, expected_fingerprint)
            matches = checked["chat_json_sha256"] == subject.get("chat_json_sha256")
        elif is_format(bundle_format(evidence), "handover-v1"):
            checked = verify_handover(evidence, expected_fingerprint)
            with open_archive(evidence) as archive:
                matches = read_manifest(archive)["files"].get("records.jsonl") == subject.get("records_sha256") \
                    and checked["head_hash"] == subject.get("head_hash")
        else:
            checked = verify_bundle(evidence, expected_fingerprint)
            count = subject.get("event_count")
            matches = type(count) is int and 0 <= count <= checked["events"] \
                and ("0" * 64 if count == 0 else bundle_hashes(evidence, [count]).get(count)) == subject.get("head_hash")
        if checked["fingerprint"] != seal["fingerprint"] or not matches:
            raise ValueError("The report describes a different archive")
        result["evidence_checked"] = True
    return result


def verify_selection(path, expected_fingerprint=None, evidence=None):
    data = read_json_file(path)
    if isinstance(data.get("statement"), dict) and "signature" in data:
        return verify_board_selection(data, expected_fingerprint, evidence)
    if not isinstance(data, dict) or data.get("format") != "tgwitness-selection-v1":
        raise ValueError("Unsupported selection format")
    if not evidence:
        raise ValueError("A viewer selection requires --evidence with its signed source archive")
    source, items = data.get("source"), data.get("items")
    if not isinstance(source, dict) or not isinstance(items, list) or not items:
        raise ValueError("A selection must contain a source and at least one item")
    kind = source.get("kind")
    if kind == "journal":
        archive_format = bundle_format(evidence)
        kind = "handover" if is_format(archive_format, "handover-v1") else "evidence" if is_format(archive_format, "evidence-v1") else None
    verifier = {"chat": verify_chat_export, "evidence": verify_bundle, "handover": verify_handover}.get(kind)
    if verifier is None:
        raise ValueError("Unsupported selection source kind")
    checked = verifier(evidence, expected_fingerprint)
    seal = checked.get("report_seal") or {}
    if source.get("fingerprint") != checked["fingerprint"] or source.get("report_id") != seal.get("report_id"):
        raise ValueError("Selection describes a different report or signing key")
    subject = seal.get("subject") or {}
    boundary = ("chat_id", "chat_json_sha256") if kind == "chat" else ("head_hash",) if kind == "handover" else ("head_hash", "event_count")
    if canonical({k: source.get(k) for k in boundary}) != canonical({k: subject.get(k) for k in boundary}):
        raise ValueError("Selection describes a different archive boundary")
    if kind == "handover" and (type(source.get("event_count")) is not int or source["event_count"] != checked["journal_events"]):
        raise ValueError("Selection describes a different archive boundary")
    identity = "id" if kind == "chat" else "seq"
    wanted = {}
    for item in items:
        if not isinstance(item, dict) or type(item.get(identity)) is not int or item[identity] < 1:
            raise ValueError("Selection item has an invalid identifier")
        if item[identity] in wanted:
            raise ValueError("Selection contains duplicate identifiers")
        wanted[item[identity]] = item
    member = "chat.json" if kind == "chat" else "records.jsonl" if kind == "handover" else "events.jsonl"
    digest_key = "chat_json_sha256" if kind == "chat" else "records_sha256" if kind == "handover" else "events_sha256"
    matched = set()
    with open_archive(evidence) as archive:
        if member_digest(archive, member) != subject.get(digest_key):
            raise ValueError("Source data changed after archive verification")

        def records():
            with archive.open(member) as stream:
                for line in bounded_lines(stream):
                    yield json.loads(line)

        for record in chat_messages(archive) if kind == "chat" else records():
            number = record.get(identity)
            if number not in wanted:
                continue
            if number in matched:
                raise ValueError("Source has duplicate identifiers for a selected item")
            expected = record
            if kind != "chat":
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
                text = payload.get("text")
                expected = {"seq": number, "hash": record.get("hash"), "kind": record.get("kind"),
                            "observed_at": record.get("observed_at"), "chat_id": record.get("chat_id"),
                            "message_id": record.get("message_id"),
                            "sender_id": payload.get("sender_id", sender.get("id")),
                            "text": text if isinstance(text, str) and text else None}
            if canonical(wanted[number]) != canonical(expected):
                raise ValueError("Selection item differs from signed source: " + str(number))
            matched.add(number)
    if matched != set(wanted):
        raise ValueError("Selection contains items absent from its source archive")
    return {"format": "tgwitness-selection-v1", "fingerprint": checked["fingerprint"],
            "key_pinned": bool(expected_fingerprint), "source_kind": kind, "report_id": source["report_id"],
            "items_checked": len(matched), "evidence_checked": True, "selection_signed": False,
            "producer": checked.get("producer"), "case": checked.get("case") or {}}


ANNOTATION_FIELDS = ("seq", "at", "access_id", "access_label", "kind", "payload", "previous_hash")
ANNOTATION_FORMAT = "tgwitness-annotations-v1"
BOARD_KINDS = {"board." + kind for kind in ("bookmark", "highlight", "slice", "collection", "comment", "status", "move", "remove")}


def verify_board_selection(data, expected_fingerprint=None, evidence=None):
    statement = authenticate_statement(data)
    if statement.get("format") != "tgwitness-board-selection-v1":
        raise VerifierTooOld("Unsupported board selection")
    public = statement["public_key"]
    fp = fingerprint(public)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Selection key differs from trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(data["signature"], validate=True), canonical(statement))
    if not evidence:
        raise ValueError("A board selection requires --evidence with its signed source archive")
    checked = verify_bundle(evidence, expected_fingerprint)
    if checked["fingerprint"] != fp:
        raise ValueError("Selection belongs to a different workspace key")
    items = statement["items"]
    wanted = {item["seq"]: item for item in items}
    if len(wanted) != len(items):
        raise ValueError("Duplicate selection records")
    boundary, matched, at_boundary = statement["journal_head"], set(), "0" * 64
    with open_archive(evidence) as archive, archive.open("events.jsonl") as incoming:
        for line in bounded_lines(incoming):
            event = strict_json(line)
            if event["seq"] == boundary["seq"]:
                at_boundary = event["hash"]
            if event["seq"] in wanted:
                if event["seq"] > boundary["seq"] or event != wanted[event["seq"]]:
                    raise ValueError("Selection item differs from signed source")
                matched.add(event["seq"])
    if matched != set(wanted) or boundary["hash"] != at_boundary or boundary["seq"] > checked["events"]:
        raise ValueError("Selection source boundary or records missing")
    with tempfile.TemporaryDirectory(prefix="tgwitness-selection-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "query.sqlite3"))
        try:
            db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY,hash TEXT,observed_at TEXT,chat_id INTEGER,message_id INTEGER,kind TEXT,actor_id INTEGER,payload TEXT)")
            with open_archive(evidence) as archive, archive.open("events.jsonl") as incoming:
                for line in bounded_lines(incoming):
                    event = strict_json(line)
                    if event["seq"] > boundary["seq"]:
                        break
                    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)", tuple(event[key] for key in
                        ("seq", "hash", "observed_at", "chat_id", "message_id", "kind", "actor_id")) + (canonical(event["payload"]).decode(),))
            board_prepare(db)
            where, args = board_where(statement["query"], boundary["seq"])
            selected = {row[0] for row in db.execute("SELECT seq FROM events WHERE " + where, args)}
            if selected != set(wanted):
                raise ValueError("Selection does not contain the complete signed slice query")
        finally:
            db.close()
    return {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "items_checked": len(matched), "evidence_checked": True, "selection_signed": True,
            "source_kind": "evidence", "report_id": None, "producer": checked.get("producer"), "case": checked.get("case") or {}}


def annotation_hash(record):
    return hashlib.sha256(canonical({"format": ANNOTATION_FORMAT,
        **{key: record[key] for key in ANNOTATION_FIELDS}})).hexdigest()


def board_replay(records, public_key=None):
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)) if public_key else None
    items, history, previous, count, action_ids = {}, [], "0" * 64, 0, set()
    for count, record in enumerate(records, 1):
        if set(record) != set(ANNOTATION_FIELDS) | {"hash", "signature"}:
            raise ValueError("Unexpected annotation fields")
        if type(record["seq"]) is not int or record["seq"] != count or record["previous_hash"] != previous or record["hash"] != annotation_hash(record):
            raise ValueError("Broken annotations chain at " + str(count))
        if (not re.fullmatch(r"admin|[a-f0-9]{16}", record["access_id"]) or
            not isinstance(record["access_label"], str) or not 1 <= len(record["access_label"]) <= 240 or
            datetime.fromisoformat(record["at"]).tzinfo is None):
            raise ValueError("Invalid annotation author or timestamp")
        if key:
            key.verify(base64.b64decode(record["signature"], validate=True), bytes.fromhex(record["hash"]))
        kind, payload = record["kind"], record["payload"]
        if kind not in BOARD_KINDS or not isinstance(payload, dict) or not re.fullmatch(r"[a-f0-9]{32}", payload.get("id", "")):
            raise ValueError("Invalid board annotation")
        previous = record["hash"]
        identifier = payload["id"]
        metadata = {"annotation_seq": count, "annotation_hash": previous, "at": record["at"],
                    "access_id": record["access_id"], "access_label": record["access_label"], "kind": kind}
        if kind in {"board.status", "board.move", "board.remove"}:
            if identifier in action_ids or identifier in items:
                raise ValueError("Duplicate board action identifier")
            action_ids.add(identifier)
            card = items.get(payload.get("card_id"))
            if not card or card.get("removed"):
                raise ValueError("Board action refers to a missing card")
            if kind == "board.status":
                if payload.get("state") not in {"open", "review", "confirmed", "dismissed"}:
                    raise ValueError("Invalid board status")
                card["state"] = payload["state"]
                history.append({**payload, **metadata})
            elif kind == "board.move":
                collection = items.get(payload.get("collection_id"))
                if payload.get("collection_id") and (not collection or collection["kind"] != "board.collection" or collection.get("removed")):
                    raise ValueError("Board move refers to a missing collection")
                card["collection_id"] = payload.get("collection_id")
            else:
                card["removed"] = True
                if card["kind"] == "board.collection":
                    for member in items.values():
                        if member.get("collection_id") == card["id"]:
                            member["collection_id"] = None
            continue
        if identifier in action_ids:
            raise ValueError("Duplicate board action identifier")
        old = items.get(identifier)
        if old:
            if old.get("removed") or payload.get("supersedes") != old["annotation_hash"] or old["kind"] != kind:
                raise ValueError("Invalid board revision")
        elif payload.get("supersedes"):
            raise ValueError("Board revision has no predecessor")
        if kind == "board.comment" and payload.get("parent_id") not in items:
            raise ValueError("Board comment has no parent")
        item = {**payload, **metadata, "state": old.get("state", "open") if old else "open",
                "collection_id": old.get("collection_id") if old else None, "removed": False,
                "created_access_id": old["created_access_id"] if old else record["access_id"],
                "created_access_label": old["created_access_label"] if old else record["access_label"],
                "created_at": old["created_at"] if old else record["at"]}
        items[identifier] = item
        if kind == "board.collection":
            for card_id in payload.get("card_ids", []):
                card = items.get(card_id)
                if not card or card["kind"] not in {"board.bookmark", "board.highlight", "board.slice"} or card.get("removed"):
                    raise ValueError("Collection refers to a missing card")
                card["collection_id"] = identifier
    return {"annotations_head": {"seq": count, "hash": previous}, "items": list(items.values()), "status_history": history}


def board_scope(item, lookup, trail=None):
    trail = set() if trail is None else trail
    while True:
        identifier = item.get("id")
        if identifier in trail:
            raise ValueError("Cyclic board reference")
        trail.add(identifier)
        kind = item["kind"]
        if kind in {"board.bookmark", "board.highlight"}:
            chat = item["target"].get("chat_id")
            return {chat} if chat is not None else None
        if kind == "board.slice":
            query = item["query"]
            if query.get("include_unscoped"):
                return None
            return set(query.get("chat_ids") or [query["chat_id"]])
        if kind == "board.collection":
            return set(item.get("chat_ids", [])) or None
        item = lookup.get(item.get("parent_id") or item.get("card_id"))
        if not item:
            return None


def board_where(query, boundary=None):
    chats = query.get("chat_ids") or [query.get("chat_id")]
    if not chats or any(type(chat) is not int for chat in chats) or len(chats) > 1000:
        raise ValueError("Invalid slice chat scope")
    parts, args = [], list(chats)
    chat_clause = "chat_id IN (" + ",".join("?" * len(chats)) + ")"
    if query.get("include_unscoped"):
        chat_clause = "(" + chat_clause + " OR (chat_id IS NULL AND kind='deletion.unscoped'))"
    parts.append(chat_clause)
    for field, op, name in (("observed_at", ">=", "from"), ("observed_at", "<=", "to")):
        if query.get(name):
            value = query[name]
            if datetime.fromisoformat(value).tzinfo is None:
                raise ValueError("Slice timestamps need a timezone")
            parts.append("julianday(" + field + ") " + op + " julianday(?)")
            args.append(value)
    for name, op in (("from_message_id", ">="), ("to_message_id", "<=")):
        if query.get(name) is not None:
            parts.append("message_id " + op + " ?")
            args.append(query[name])
    kinds = query.get("kinds", "all")
    if kinds != "all":
        if not isinstance(kinds, list) or not 1 <= len(kinds) <= 40:
            raise ValueError("Invalid slice kinds")
        clauses = []
        for kind in kinds:
            if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_*]+)+", kind):
                raise ValueError("Invalid slice kind")
            clauses.append("kind GLOB ?")
            args.append(kind)
        parts.append("(" + " OR ".join(clauses) + ")")
    if actors := query.get("actors"):
        parts.append("actor_id IN (" + ",".join("?" * len(actors)) + ")")
        args.extend(actors)
    if query.get("search"):
        parts.append("instr(board_search(payload),?)>0")
        args.append(board_search(query["search"]))
    if query.get("hide_system"):
        parts.append("kind NOT IN ('collector.heartbeat','host.state') AND NOT (kind='media.skipped' AND COALESCE(json_extract(payload,'$.reason'),'')='media download disabled')")
    if boundary is not None:
        parts.append("seq <= ?")
        args.append(boundary)
    return " AND ".join(parts), args


def board_search(value):
    return unicodedata.normalize("NFC", str(value or "").casefold())


def board_prepare(connection):
    connection.create_function("board_search", 1, board_search, deterministic=True)


def board_slice_summary(connection, query, boundary=None):
    board_prepare(connection)
    where, args = board_where(query, boundary)
    digest, count, first, last = hashlib.sha256(b"["), 0, None, None
    for seq, value in connection.execute("SELECT seq,hash FROM events WHERE " + where + " ORDER BY hash", args):
        digest.update((b"," if count else b"") + canonical(value))
        count += 1
        first, last = min(first or seq, seq), max(last or seq, seq)
    digest.update(b"]")
    counts = dict(connection.execute("SELECT kind,count(*) FROM events WHERE " + where + " GROUP BY kind", args))
    start, end, placed = connection.execute("SELECT min(julianday(observed_at)),max(julianday(observed_at)),count(julianday(observed_at)) FROM events WHERE " + where, args).fetchone()
    bins = [0] * 24
    if start is not None:
        span = max(end-start, 1 / 86400)
        for bucket, total in connection.execute("SELECT min(23,cast((julianday(observed_at)-?)/?*24 AS INTEGER)),count(*) FROM events WHERE " + where + " AND julianday(observed_at) IS NOT NULL GROUP BY 1", (start, span, *args)):
            bins[bucket] = total
    def iso(day):
        return datetime.fromtimestamp((day-2440587.5)*86400, timezone.utc).isoformat(timespec="seconds") if day is not None else None
    return {"record_count": count, "result_hash": digest.hexdigest(), "first_seq": first, "last_seq": last, "counts": counts,
            "timeline": {"from": iso(start), "to": iso(end), "bins": bins, "unplaced": count-placed, "basis": "observed_at UTC"}}


def verify_board(archive, manifest, checkpoint=None):
    files = manifest["files"]
    if not {"annotations.jsonl", "case-board.json"} & set(files):
        if manifest.get("annotations_head") or (checkpoint or {}).get("statement", {}).get("annotations_head"):
            raise ValueError("Missing retained annotations")
        return None
    if not {"annotations.jsonl", "case-board.json"} <= set(files):
        raise ValueError("Incomplete Case Board export")
    public = manifest["public_key"]
    if archive.getinfo("annotations.jsonl").file_size > MAX_JSON_BYTES:
        raise ValueError("Annotations exceed the verifier's 256 MiB replay limit")
    with archive.open("annotations.jsonl") as incoming:
        records = [strict_json(line) for line in bounded_lines(incoming)]
    replay = board_replay(records, public)
    signed = strict_json(read_member(archive, "case-board.json", MAX_JSON_BYTES))
    statement = signed["statement"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(signed["signature"], validate=True), canonical(statement))
    if statement.get("format") != "tgwitness-case-board-v1" or statement.get("public_key") != public:
        raise ValueError("Case Board format or key mismatch")
    if statement.get("state") != replay or manifest.get("annotations_head") != replay["annotations_head"]:
        raise ValueError("Case Board state differs from annotations")
    if statement.get("journal_head") != {"seq": manifest["event_count"], "hash": manifest["head_hash"]}:
        raise ValueError("Case Board journal boundary mismatch")
    retained_heads = [(checkpoint or {}).get("statement", {}).get("annotations_head")]
    for name in files:
        if name.startswith("anchors/") and name.endswith(".json"):
            retained_heads.append(strict_json(read_member(archive, name)).get("statement", {}).get("annotations_head"))
    for retained in (head for head in retained_heads if head):
        seq = retained.get("seq")
        if type(seq) is not int or seq < 0 or seq > len(records) or retained.get("hash") != (records[seq-1]["hash"] if seq else "0" * 64):
            raise ValueError("Annotations disagree with retained checkpoint")
    dangling, changed, slices = [], [], {}
    with tempfile.TemporaryDirectory(prefix="tgwitness-board-verify-") as temporary:
        db = sqlite3.connect(str(Path(temporary) / "journal.sqlite3"))
        try:
            db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY,hash TEXT UNIQUE,observed_at TEXT,chat_id INTEGER,message_id INTEGER,kind TEXT,actor_id INTEGER,payload TEXT)")
            with archive.open("events.jsonl") as incoming:
                for line in bounded_lines(incoming):
                    event = strict_json(line)
                    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)", tuple(event[key] for key in
                        ("seq", "hash", "observed_at", "chat_id", "message_id", "kind", "actor_id")) + (canonical(event["payload"]).decode(),))
            for record in records:
                payload = record["payload"]
                if target := payload.get("target"):
                    row = db.execute("SELECT seq,chat_id,message_id,kind,payload FROM events WHERE hash=?", (target["event_hash"],)).fetchone()
                    if row is None:
                        dangling.append({"id": payload["id"], "event_hash": target["event_hash"]})
                    else:
                        if any(target.get(k) != row[i] for i, k in enumerate(("seq", "chat_id", "message_id", "kind"))):
                            raise ValueError("Board target metadata differs from journal")
                        if record["kind"] == "board.highlight":
                            selection, text = payload["range"], json.loads(row[4]).get(payload["range"]["field"])
                            if (not isinstance(text, str) or selection.get("version") != target["event_hash"] or
                                type(selection.get("start")) is not int or type(selection.get("length")) is not int or
                                selection["start"] < 0 or selection["length"] < 1 or
                                text[selection["start"]:selection["start"]+selection["length"]] != selection["quote"]):
                                raise ValueError("Highlight differs from the exact saved version")
                if record["kind"] == "board.slice":
                    snapshot = payload["snapshot"]
                    boundary = snapshot["journal_head"]
                    row = db.execute("SELECT hash FROM events WHERE seq=?", (boundary["seq"],)).fetchone()
                    if boundary["hash"] != (row[0] if row else "0" * 64 if boundary["seq"] == 0 else None):
                        raise ValueError("Slice creation boundary differs from journal")
                    original = board_slice_summary(db, payload["query"], boundary["seq"])
                    if any(snapshot.get(k) != original[k] for k in ("record_count", "result_hash", "first_seq", "last_seq")):
                        raise ValueError("Slice bookmark snapshot differs from its original journal prefix")
            for item in replay["items"]:
                if item["kind"] != "board.slice" or item["removed"]:
                    continue
                query, snapshot = item["query"], item["snapshot"]
                where, args = board_where(query)
                hashes = [row[0] for row in db.execute("SELECT hash FROM events WHERE " + where + " ORDER BY hash", args)]
                added = [row[0] for row in db.execute("SELECT seq FROM events WHERE " + where + " AND seq>? ORDER BY seq", (*args, snapshot["journal_head"]["seq"]))]
                current = board_slice_summary(db, query)
                expected = {"id": item["id"], "query": query, "snapshot": snapshot, "current": current,
                            "event_hashes": hashes, "added_seq": added, "removed_seq": []}
                name = "board/slices/" + item["id"] + ".json"
                if name not in files or strict_json(read_member(archive, name, MAX_JSON_BYTES)) != expected:
                    raise ValueError("Exported slice differs from journal: " + item["id"])
                slices[item["id"]] = name
                if added:
                    changed.append({"id": item["id"], "added": len(added), "removed": 0,
                                    "message": "slice changed since bookmark: +" + str(len(added)) + "/−0 records"})
        finally:
            db.close()
    if {name for name in files if name.startswith("board/slices/")} != set(slices.values()):
        raise ValueError("Unexpected board slice files")
    return {"annotations_head": replay["annotations_head"], "dangling": dangling, "slice_changes": changed,
            "collections": [{"id": item["id"], "title": item["title"]} for item in replay["items"]
                            if item["kind"] == "board.collection" and not item["removed"]]}


def verify_board_disclosure(archive, manifest):
    if "case-board.json" not in manifest["files"]:
        return None
    signed = strict_json(read_member(archive, "case-board.json", MAX_JSON_BYTES))
    statement, public = authenticate_statement(signed), manifest["public_key"]
    if statement.get("format") != "tgwitness-case-board-handover-v1" or statement.get("public_key") != public:
        raise ValueError("Invalid handover board format or signing key")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(signed["signature"], validate=True), canonical(statement))
    cards = statement["material"]["cards"]
    wanted = {card["target"]["event_hash"]: card for card in cards if card.get("target")}
    matched = set()
    with archive.open("records.jsonl") as incoming:
        for line in bounded_lines(incoming):
            record = strict_json(line)
            if record["hash"] in wanted:
                for card in cards:
                    if card.get("target", {}).get("event_hash") == record["hash"] and card.get("observation") != record:
                        raise ValueError("Board exposes content outside the handover record")
                matched.add(record["hash"])
    if matched != set(wanted):
        raise ValueError("Board refers to a record not disclosed in the handover")
    if "report.json" in manifest["files"]:
        report = strict_json(read_member(archive, "report.json", MAX_JSON_BYTES))
        if report["report"].get("case_board") != statement["material"]:
            raise ValueError("Readable report and board disclosure differ")
    return {"cards": len(cards), "meaning": "Minimised team notes, signed by the collector; not the original annotations chain"}


def verify_board_document(path, expected_fingerprint=None, evidence=None):
    signed = read_json_file(path)
    statement = authenticate_statement(signed)
    if statement.get("format") not in ("tgwitness-case-board-v1", "tgwitness-case-board-disclosure-v1", "tgwitness-case-board-handover-v1"):
        raise VerifierTooOld("Unsupported Case Board document")
    public = statement["public_key"]
    fp = fingerprint(public)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Case Board key differs from trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(signed["signature"], validate=True), canonical(statement))
    if statement["format"] == "tgwitness-case-board-v1" and evidence:
        checked = verify_bundle(evidence, expected_fingerprint)
        if checked["fingerprint"] != fp:
            raise ValueError("Case Board belongs to another workspace key")
        count = statement["state"]["annotations_head"]["seq"]
        with open_archive(evidence) as archive, archive.open("annotations.jsonl") as incoming:
            prefix = []
            for line in bounded_lines(incoming):
                row = strict_json(line)
                if row["seq"] > count:
                    break
                prefix.append(row)
        if board_replay(prefix, public) != statement["state"]:
            raise ValueError("Case Board state differs from its signed annotations prefix")
        boundary = statement["journal_head"]
        source_head = {"seq": 0, "hash": "0" * 64}
        with open_archive(evidence) as archive, archive.open("events.jsonl") as incoming:
            for line in bounded_lines(incoming):
                row = strict_json(line)
                if row["seq"] > boundary["seq"]:
                    break
                source_head = {"seq": row["seq"], "hash": row["hash"]}
        if source_head != boundary:
            raise ValueError("Case Board journal boundary differs from its evidence source")
    elif evidence:
        raise ValueError("Verify a minimized board with its containing handover ZIP")
    return {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "annotations_checked": bool(evidence), "meaning": "Team opinions; signature authenticates the signed document, not the truth of a conclusion"}


def verify_bundle(path, expected_fingerprint=None, checkpoint=None, tsa_ca=None, check_drand=False, max_gib=None,
                  check_bitcoin=False):
    with open_archive(path, max_gib=max_gib) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "evidence-v1"):
            raise VerifierTooOld("Unsupported evidence format")
        public = manifest["public_key"]
        fp = fingerprint(public)
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
            base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        if set(names) != set(manifest["files"]) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing bundle members")
        for name, digest in manifest["files"].items():
            if member_digest(archive, name) != digest:
                raise ValueError("File hash mismatch: " + name)
        sums = check_sums(archive, manifest)

        def describes(subject):
            return (subject.get("event_count") == manifest["event_count"]
                    and subject.get("head_hash") == manifest["head_hash"]
                    and subject.get("events_sha256") == manifest["files"].get("events.jsonl"))
        seal = archive_seal(archive, "report.html", public) if "report.html" in manifest["files"] else None
        if seal and not describes(seal["subject"]):
            raise ValueError("The report seal describes a different journal")
        companions = report_companions(archive, manifest, public, describes)
        gap_settings = None
        if "coverage.json" in manifest["files"]:
            saved_coverage = strict_json(read_member(archive, "coverage.json", MAX_JSON_BYTES))
            saved_gaps = saved_coverage.get("gap_summary") if isinstance(saved_coverage, dict) else None
            if isinstance(saved_gaps, dict):
                gap_settings = saved_gaps.get("parameters")
        observed, outside = Coverage(gap_settings), OutsideRecords()
        hash_files, account_exports, starts = set(), [], []

        def measured(lines):
            for line in lines:
                event = strict_json(line)
                if event["kind"] == "process.started":
                    starts.append(event)
                if event["kind"] == "sealed.account_export":
                    item = event["payload"]
                    if (account_exports or item.get("file") != "account-export.zip"
                            or manifest["files"].get(item["file"]) != item.get("sha256")
                            or archive.getinfo(item["file"]).file_size != item.get("bytes")):
                        raise ValueError("Sealed account export differs from its journal binding")
                    account_exports.append(item)
                if event["kind"] == "media.hashed":
                    digest = hashlib.sha256(canonical(event["payload"].get("server_hashes"))).hexdigest()
                    name = "hashes/" + digest + ".json"
                    if manifest["files"].get(name) != digest:
                        raise ValueError("File-hash manifest differs from the signed journal")
                    hash_files.add(name)
                media = media_reference(event)
                if media:
                    digest, size = media
                    name = "media/" + digest
                    if manifest["files"].get(name) != digest:
                        raise ValueError("Preserved media is missing or differs from the signed journal: " + digest)
                    if size is not None and archive.getinfo(name).file_size != size:
                        raise ValueError("Preserved media size differs from the signed journal: " + digest)
                observed.add(event)
                outside.add(event)
                yield event
        with archive.open("events.jsonl") as stream:
            result = verify_events(measured(bounded_lines(stream)), public)
        if {name for name in manifest["files"] if name.startswith("hashes/")} != hash_files:
            raise ValueError("Unreferenced journal file-hash manifest")
        if ("account-export.zip" in manifest["files"]) != bool(account_exports):
            raise ValueError("Unbound sealed account export")
        if account_exports:
            with archive.open("account-export.zip") as incoming:
                account = verify_account_export(incoming, fp, max_gib=max_gib)
            binding = account_exports[0]
            if account["job_id"] != binding["job_id"] or account["complete_within_scope"] != binding["complete_within_scope"]:
                raise ValueError("Account export coverage differs from its journal binding")
            result["account_export"] = account
        if result["events"] != manifest["event_count"] or result["head_hash"] != manifest["head_hash"]:
            raise ValueError("Manifest does not match journal")
        result["coverage"] = observed.result()
        result["outside"] = outside.result()
        if check_drand and outside.rounds:
            result["outside"]["drand"]["checked"] = confirm_drand(outside.rounds)
        result["producer"] = manifest.get("producer")
        result.update(format=manifest["format"], files_checked=len(manifest["files"]), sha256sums=sums,
                      report_seal=seal, report_json=companions["json"], report_parts=companions["parts"],
                      report_pdf=companions["pdf"], case=manifest.get("case") or {})

        def hash_at(seq):
            if seq == 0:
                return "0" * 64
            with archive.open("events.jsonl") as stream:
                for line in bounded_lines(stream):
                    event = strict_json(line)
                    if event["seq"] == seq:
                        return event["hash"]
            return None
        if checkpoint:
            checkpoint_anchor = verify_checkpoint(checkpoint, public, result["events"], hash_at,
                                                  check_drand=check_drand)
            result["checkpoint_event_count"] = checkpoint["statement"]["event_count"]
            if checkpoint_anchor:
                result["checkpoint_drand_anchor"] = {**checkpoint_anchor, "confirmed_by_relays": bool(check_drand)}
        result["anchors"] = verify_anchors(archive, names, public, result["events"], hash_at, tsa_ca, check_bitcoin)
        result["board"] = verify_board(archive, manifest, checkpoint)
        tdx = verify_tdx_starts(starts, public)
        if tdx:
            result["tdx"] = tdx
        result["key_pinned"] = bool(expected_fingerprint)
        result["checkpoint_checked"] = checkpoint is not None
        result["assurance"] = assurance(result)
        return result


def verify_distributed_pages(stream, envelopes, job, task):
    format_name = "tgwitness-distributed-pages-v1"
    if job.get("checkpoint_format") != format_name:
        raise ValueError("Unsupported distributed checkpoint format.")
    low, high = task["low"], task["high"]
    if type(low) is not int or type(high) is not int or not 0 < low <= high:
        raise ValueError("Invalid checkpoint range.")
    workers = {w["profile_id"]: w for w in job["workers"]}
    eligible = {p for s in job["segments"] if s["low"] <= low <= high <= s["high"] for p in s["profiles"]}
    state = {"pages": 0, "count": 0, "cursor": high + 1, "byte_end": 0, "head_sha256": "0" * 64,
             "terminal": False, "profile_id": None, "transport_generation": None}
    plan_hash = hashlib.sha256(canonical(job)).hexdigest()
    for envelope in envelopes:
        value = envelope["statement"]
        profile = value["profile_id"]
        worker = workers.get(profile)
        if (not worker or profile not in eligible or envelope["public_key"] != worker["public_key"]
                or state["profile_id"] not in (None, profile)):
            raise ValueError("Checkpoint observer differs from the signed plan or preceding pages.")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(worker["public_key"], validate=True)).verify(
            base64.b64decode(envelope["signature"], validate=True), canonical(value))
        if (value.get("format") != format_name or value.get("plan_sha256") != plan_hash
                or value.get("job_id") != job["id"] or value.get("chat_id") != job["chat_id"]
                or value.get("account_id") != worker["account_id"] or value.get("low") != low or value.get("high") != high):
            raise ValueError("Checkpoint scope differs from its signed plan.")
        fields = ("seq", "cursor_before", "cursor_after", "byte_start", "byte_end", "count")
        if any(type(value.get(k)) is not int for k in fields) or type(value.get("terminal")) is not bool:
            raise ValueError("Invalid checkpoint cursor, size or sequence.")
        if (state["terminal"] or value["seq"] != state["pages"] + 1
                or value.get("previous_receipt_sha256") != state["head_sha256"]
                or value["byte_start"] != state["byte_end"] or value["byte_end"] < value["byte_start"]
                or value["cursor_before"] != state["cursor"] or not 0 <= value["count"] <= 100
                or not value["count"] and not value["terminal"]):
            raise ValueError("Broken checkpoint receipt chain.")
        generation = value.get("transport_generation")
        if (value.get("transport") != job.get("transport", "regular")
                or value["transport"] == "takeout" and (type(generation) is not int or generation < 1
                    or state["transport_generation"] is not None and generation < state["transport_generation"])
                or value["transport"] == "regular" and generation is not None):
            raise ValueError("Checkpoint transport differs from the plan or preceding pages.")
        for name in ("captured_from", "captured_until"):
            try:
                if datetime.fromisoformat(value[name]).tzinfo is None:
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise ValueError("Invalid checkpoint observation time.") from None
        digest, cursor, count, end = hashlib.sha256(), state["cursor"], 0, state["byte_end"]
        while end < value["byte_end"]:
            line = stream.readline(MAX_RECORD_BYTES + 1)
            end += len(line)
            if not line or len(line) > MAX_RECORD_BYTES or not line.endswith(b"\n") or end > value["byte_end"]:
                raise ValueError("Checkpoint data differs: truncated or oversized.")
            record = strict_json(line)
            mid = record["id"]
            if type(mid) is not int or not low <= mid < cursor:
                raise ValueError("Checkpoint messages are outside their range or repeated.")
            digest.update(line)
            count, cursor = count + 1, mid
        if digest.hexdigest() != value.get("sha256") or count != value["count"] or cursor != value["cursor_after"]:
            raise ValueError("Checkpoint data differs from its signed receipt.")
        state.update(pages=value["seq"], count=state["count"] + count, cursor=cursor,
                     byte_end=end, head_sha256=hashlib.sha256(canonical(envelope)).hexdigest(),
                     terminal=value["terminal"], profile_id=profile, transport_generation=generation)
    return state


def verify_distributed_work(directory, expected_fingerprint=None, max_gib=None):
    directory = Path(directory)
    def checked(path):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Distributed acquisition paths must not be links.")
        return path

    def signed(path, public=None):
        envelope = read_json_file(checked(path))
        if public is not None and envelope["public_key"] != public:
            raise ValueError("Distributed acquisition signing identity changed.")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(envelope["public_key"], validate=True)).verify(
            base64.b64decode(envelope["signature"], validate=True), canonical(envelope["statement"]))
        return envelope

    checked(directory)
    for name in ("chunks", "pages", "receipts"):
        checked(directory / name)
    plan = signed(directory / "job.json")
    job, public = plan["statement"], plan["public_key"]
    fp = fingerprint(public)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    if (job.get("format") != "tgwitness-distributed-job-v1"
            or job.get("checkpoint_format") != "tgwitness-distributed-pages-v1"
            or type(job.get("chunk_size")) is not int or job["chunk_size"] < 1):
        raise ValueError("This directory does not use the supported distributed checkpoint format.")
    workers = {w["profile_id"]: w for w in job["workers"]}
    if workers[job["lead"]]["public_key"] != public:
        raise ValueError("Acquisition plan was not signed by its lead observer.")
    tasks, previous_high = {}, 0
    for segment in job["segments"]:
        low, high = segment["low"], segment["high"]
        if type(low) is not int or type(high) is not int or not previous_high < low <= high:
            raise ValueError("Invalid or overlapping planned acquisition ranges.")
        previous_high = high
        if (high - low) // job["chunk_size"] + 1 + len(tasks) > MAX_MEMBERS:
            raise ValueError("Too many acquisition ranges to verify.")
        for start in range(low, high + 1, job["chunk_size"]):
            tasks[str(start)] = {"low": start, "high": min(high, start + job["chunk_size"] - 1)}
    states, total_bytes, tails = {}, 0, 0
    for folder in checked(directory / "pages").iterdir():
        if folder.name not in tasks or not checked(folder).is_dir():
            raise ValueError("Checkpoint directory is outside the signed plan.")
        paths = sorted(folder.glob("*.json"), key=lambda p: int(p.stem) if p.stem.isdigit() else -1)
        if len(paths) > MAX_MEMBERS or any(p.name != str(i) + ".json" for i, p in enumerate(paths, 1)):
            raise ValueError("Checkpoint receipt sequence is incomplete.")
        data_path = checked(directory / "chunks" / (folder.name + ".jsonl"))
        size = data_path.stat().st_size if data_path.exists() else 0
        total_bytes += size
        if total_bytes > (max_gib or MAX_UNCOMPRESSED_GIB) * 1024**3:
            raise ValueError("Distributed acquisition exceeds the verification size limit.")
        with data_path.open("rb") if data_path.exists() else io.BytesIO() as stream:
            state = verify_distributed_pages(stream, (read_json_file(checked(p)) for p in paths), job, tasks[folder.name])
        states[folder.name] = state
        tails += size - state["byte_end"]
    completed = 0
    for path in (directory / "receipts").glob("*.json"):
        state = states.get(path.stem)
        if not state or not state["terminal"]:
            raise ValueError("A completed chunk has no terminal checkpoint.")
        value = signed(path, workers[state["profile_id"]]["public_key"])["statement"]
        task = tasks[path.stem]
        summary = {"format": job["checkpoint_format"], **{k: state[k] for k in ("pages", "head_sha256", "count", "byte_end")}}
        if (value.get("checkpoint") != summary or value.get("job_id") != job["id"]
                or value.get("profile_id") != state["profile_id"] or value.get("count") != state["count"]
                or value.get("low") != task["low"] or value.get("high") != task["high"]
                or value.get("transport", "regular") != job.get("transport", "regular")
                or value.get("transport_generation") != state["transport_generation"]):
            raise ValueError("Chunk receipt differs from its signed checkpoints.")
        data_path = checked(directory / "chunks" / (path.stem + ".jsonl"))
        with data_path.open("rb") as stream:
            if data_path.stat().st_size != state["byte_end"] or hashlib.file_digest(stream, "sha256").hexdigest() != value["sha256"]:
                raise ValueError("Completed chunk differs from its signed receipt.")
        completed += 1
    captured = sum(s["count"] for s in states.values())
    status = signed(directory / "status.json", public)["statement"]
    if status["id"] != job["id"] or status["captured"] > captured or status["ranges_done"] > completed:
        raise ValueError("Saved acquisition progress is missing.")
    return {"format": job["checkpoint_format"], "fingerprint": fp, "job_id": job["id"],
            "chat_id": job["chat_id"], "captured": captured, "pages": sum(s["pages"] for s in states.values()),
            "ranges_done": completed, "ranges_total": len(tasks), "unsigned_tail_bytes": tails,
            "complete_within_plan": completed == len(tasks),
            "meaning": "Verified local acquisition prefix of the pages Telegram returned, signed per range. "
                       "Unsigned tails are excluded. Keep receipt heads independently to detect removal of a suffix."}


def verify_chat_export(path, expected_fingerprint=None, max_gib=None):
    with open_archive(path, max_gib=max_gib) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "chat-export-v1"):
            raise VerifierTooOld("Unsupported chat export format")
        public = manifest["public_key"]
        fp = fingerprint(public)
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
            base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        if set(names) != set(manifest["files"]) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing bundle members")
        for name, digest in manifest["files"].items():
            if member_digest(archive, name) != digest:
                raise ValueError("File hash mismatch: " + name)
        parts = verify_parts(archive, manifest) if manifest.get("parts") else None
        attachments = check_attachments(archive, manifest)
        sums = check_sums(archive, manifest)

        def describes(subject):
            return (subject.get("chat_id") == (manifest.get("chat") or {}).get("id")
                    and subject.get("message_count") == manifest.get("message_count")
                    and subject.get("chat_json_sha256") == manifest["files"].get("chat.json"))
        seal = archive_seal(archive, "chat.html", public) if "chat.html" in manifest["files"] else None
        if seal and not describes(seal["subject"]):
            raise ValueError("The report seal describes a different chat export")
        companions = report_companions(archive, manifest, public, describes)
        ids = check_message_ids(archive, manifest) if "message-ids.json" in manifest["files"] else None
        return {"format": manifest["format"], "fingerprint": fp,
                "message_count": manifest.get("message_count"), "producer": manifest.get("producer"),
                "chat": manifest.get("chat"), "key_pinned": bool(expected_fingerprint), "parts": parts,
                "files_checked": len(manifest["files"]), "chat_json_sha256": manifest["files"].get("chat.json"),
                "attachments": attachments, "sha256sums": sums, "report_seal": seal,
                "report_parts": companions["parts"], "report_pdf": companions["pdf"], "message_ids": ids,
                "case": manifest.get("case") or {}}


COMPARE_MEANING = {
    "number": "Both archives record the same chat and account, so messages are matched by their number. "
              "Unchanged means equality of the complete saved message record. Differences may include "
              "observation metadata and do not by themselves prove a Telegram edit.",
    "content": "The archives come from different chats or accounts (for example both sides of a private chat), "
               "or their scope identity is missing. Possible matches use time, sender, full text and file hash. "
               "Unchanged counts identical saved records among these pairs, not proven message identity. "
               "Differences describe the paired records, not necessarily edits of the same Telegram message.",
}


CLOCK_SLACK = 5


def unix_time(row):
    if row.get("date_unixtime") is not None:
        return int(row["date_unixtime"])
    try:
        return int(datetime.fromisoformat(str(row.get("date")).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def chat_rows(path, max_gib=None):
    with open_archive(path, max_gib=max_gib) as archive:
        manifest = read_manifest(archive)
        return manifest, list(chat_messages(archive))


def row_text(row):
    text = row.get("text")
    if isinstance(text, list):
        text = "".join(part if isinstance(part, str) else str(part.get("text", "")) for part in text)
    return text or ""


def row_brief(row):
    return {"id": row.get("id"), "date": row.get("date"), "from": row.get("from"), "from_id": row.get("from_id"),
            "text": row_text(row)[:300], "file_sha256": row.get("file_sha256"), "edited": row.get("edited"),
            "reply_to_message_id": row.get("reply_to_message_id")}


def row_content(row):
    return canonical(row)


def compare_chat_exports(first, second, first_fingerprint=None, second_fingerprint=None, max_gib=None):
    checked = [verify_chat_export(first, first_fingerprint, max_gib),
               verify_chat_export(second, second_fingerprint, max_gib)]
    (first_manifest, first_rows), (second_manifest, second_rows) = (chat_rows(first, max_gib), chat_rows(second, max_gib))
    def same_identity(name):
        value = (first_manifest.get(name) or {}).get("id")
        other = (second_manifest.get(name) or {}).get("id")
        return type(value) is int and type(other) is int and value != 0 and value == other
    same_chat, same_account = same_identity("chat"), same_identity("account")
    method = "number" if same_chat and same_account else "content"
    order = lambda rows: sorted(rows, key=lambda row: (str(row.get("date")), str(row.get("id"))))
    if method == "number":
        def by_number(rows):
            found = {}
            for row in rows:
                number = row.get("id")
                if type(number) is not int or number <= 0:
                    raise ValueError("Invalid message ID in chat comparison")
                if number in found:
                    raise ValueError("Duplicate message ID in chat comparison")
                found[number] = row
            return found
        left, right = by_number(first_rows), by_number(second_rows)
        pairs = [(left[k], right[k]) for k in left.keys() & right.keys()]
        only_first = [left[k] for k in left.keys() - right.keys()]
        only_second = [right[k] for k in right.keys() - left.keys()]
    else:
        def content_key(row):
            return row.get("from_id"), row_text(row), row.get("file_sha256"), row.get("media_type")

        waiting, pairs, only_first = {}, [], []
        only_second = []
        for row in order(second_rows):
            if row.get("type") == "unparsed":
                only_second.append(row)
            else:
                waiting.setdefault(content_key(row), []).append(row)
        for row in order(first_rows):
            if row.get("type") == "unparsed":
                only_first.append(row)
                continue
            candidates = waiting.get(content_key(row), [])
            match = next((c for c in candidates if abs(unix_time(c) - unix_time(row)) <= CLOCK_SLACK), None)
            if match is None:
                only_first.append(row)
            else:
                candidates.remove(match)
                pairs.append((row, match))
        only_second.extend(row for rows in waiting.values() for row in rows)
    changed = []
    for a, b in pairs:
        if row_content(a) != row_content(b):
            fields = sorted(k for k in a.keys() | b.keys()
                            if (k in a) != (k in b) or canonical(a.get(k)) != canonical(b.get(k)))
            changed.append({"first": row_brief(a), "second": row_brief(b), "changed_fields": fields})
    return {"format": "tgwitness-chat-comparison-v1", "method": method, "meaning": COMPARE_MEANING[method],
            "first": {"file": str(first), "fingerprint": checked[0]["fingerprint"], "exported_at": first_manifest.get("exported_at"),
                      "chat_id": (first_manifest.get("chat") or {}).get("id"), "messages": len(first_rows),
                      "key_pinned": checked[0]["key_pinned"]},
            "second": {"file": str(second), "fingerprint": checked[1]["fingerprint"], "exported_at": second_manifest.get("exported_at"),
                       "chat_id": (second_manifest.get("chat") or {}).get("id"), "messages": len(second_rows),
                       "key_pinned": checked[1]["key_pinned"]},
            "only_first": [row_brief(row) for row in order(only_first)],
            "only_second": [row_brief(row) for row in order(only_second)],
            "changed": sorted(changed, key=lambda item: (str(item["first"]["date"]), str(item["first"]["id"]))),
            "matched": len(pairs), "unchanged": len(pairs) - len(changed)}


def print_comparison(result, limit=50):
    import builtins

    def print(*values, **kwargs):
        builtins.print(*(safe_text(v) if isinstance(v, str) else v for v in values), **kwargs)

    first, second = result["first"], result["second"]
    print("Both archives verified. First " + str(first["exported_at"]) + " (" + str(first["messages"]) + " messages, key "
          + first["fingerprint"][:16] + "), second " + str(second["exported_at"]) + " (" + str(second["messages"])
          + " messages, key " + second["fingerprint"][:16] + ").")
    print(result["meaning"])
    for title, name in (("Only in the first archive", "only_first"), ("Only in the second archive", "only_second")):
        rows = result[name]
        print(title + ": " + str(len(rows)))
        for row in rows[:limit]:
            shown = row["text"] or ("file " + str(row["file_sha256"])[:16] if row["file_sha256"] else "")
            print("  #" + str(row["id"]) + " " + str(row["date"]) + " " + str(row["from"] or row["from_id"]) + ": "
                  + " ".join(shown.split())[:120])
    print("Changed: " + str(len(result["changed"])))
    for item in result["changed"][:limit]:
        print("  #" + str(item["first"]["id"]) + ": " + " ".join(item["first"]["text"].split())[:80] + "  ->  "
              + " ".join(item["second"]["text"].split())[:80])
        print("    Fields: " + ", ".join(item["changed_fields"]))
    if result["method"] == "number":
        print("Unchanged: " + str(result["unchanged"]))
    else:
        print("Matched: " + str(result["matched"]) + " (possible correspondence between the two exports)")
    if not (first["key_pinned"] and second["key_pinned"]):
        print("Signer identity is unpinned for at least one archive: compare the fingerprints with copies kept elsewhere.")


def message_id_summary(chat_id, ids):
    holes = missing_ranges(ids)
    return {"chat_id": chat_id, "numbered_per_chat": numbered_per_chat(chat_id),
            "first_id": ids[0] if ids else None, "last_id": ids[-1] if ids else None, "present": len(ids),
            "missing": sum(high - low + 1 for low, high in holes) if numbered_per_chat(chat_id) else None,
            "missing_ranges": [[low, high] for low, high in holes] if numbered_per_chat(chat_id) else []}


def check_message_ids(archive, manifest):
    claimed = strict_json(read_member(archive, "message-ids.json", MAX_JSON_BYTES))
    ids = sorted({m["id"] for m in chat_messages(archive) if type(m.get("id")) is int})
    counted = message_id_summary((manifest.get("chat") or {}).get("id"), ids)
    if {k: claimed.get(k) for k in counted} != counted:
        raise ValueError("message-ids.json disagrees with the messages in chat.json")
    return {k: counted[k] for k in ("first_id", "last_id", "present", "missing")} | {
        "missing_ranges": len(counted["missing_ranges"]), "numbered_per_chat": counted["numbered_per_chat"]}


def verify_handover(path, expected_fingerprint=None):
    with open_archive(path) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "handover-v1"):
            raise VerifierTooOld("Unsupported handover format")
        public = manifest["public_key"]
        fp = fingerprint(public)
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
        key.verify(base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        files = manifest["files"]
        if set(names) != set(files) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing bundle members")
        for name, digest in files.items():
            if member_digest(archive, name) != digest:
                raise ValueError("File hash mismatch: " + name)
            if name.startswith("media/") and name[len("media/"):] != digest:
                raise ValueError("Attachment name differs from its SHA-256: " + name)
        sums = check_sums(archive, manifest)
        journal = manifest["journal"]
        count, head = journal["event_count"], journal["head_hash"]
        if type(count) is not int or count < 1 or not re.fullmatch(r"[0-9a-f]{64}", str(head)):
            raise ValueError("Malformed journal boundary")
        key.verify(base64.b64decode(journal["head_signature"], validate=True), bytes.fromhex(head))
        counts, previous, referenced = {"unchanged": 0, "minimised": 0}, None, set()
        with archive.open("records.jsonl") as stream:
            for line in bounded_lines(stream):
                record = strict_json(line)
                minimised = record.get("minimised")
                if set(record) != set(FIELDS) | {"hash", "signature"} | ({"minimised"} if "minimised" in record else set()):
                    raise ValueError("Unexpected or missing fields at record " + str(record.get("seq")))
                seq = record["seq"]
                if type(seq) is not int or not 1 <= seq <= count or (previous and seq <= previous["seq"]):
                    raise ValueError("Records out of journal order at record " + str(seq))
                if not re.fullmatch(r"[0-9a-f]{64}", str(record["hash"])):
                    raise ValueError("Malformed hash at record " + str(seq))
                if minimised is None:
                    if hashlib.sha256(canonical({k: record[k] for k in FIELDS})).hexdigest() != record["hash"]:
                        raise ValueError("Changed content at record " + str(seq))
                    if previous and previous["seq"] == seq - 1 and record["previous_hash"] != previous["hash"]:
                        raise ValueError("Broken hash chain at record " + str(seq))
                    counts["unchanged"] += 1
                else:
                    if not isinstance(minimised, list) or not minimised or not all(isinstance(x, str) for x in minimised):
                        raise ValueError("A minimised record must name what was withheld: record " + str(seq))
                    counts["minimised"] += 1
                key.verify(base64.b64decode(record["signature"], validate=True), bytes.fromhex(record["hash"]))
                if seq == count and record["hash"] != head:
                    raise ValueError("The last record differs from the journal head")
                if record["kind"] in ("media.saved", "actor.avatar_saved", "secret_chat.file"):
                    digest = (record["payload"] or {}).get("media_sha256")
                    if "media/" + str(digest) in files:
                        referenced.add("media/" + digest)
                previous = record
        if counts != {k: manifest["counts"].get(k) for k in counts}:
            raise ValueError("Record counts differ from the signed manifest")
        if {name for name in files if name.startswith("media/")} - referenced:
            raise ValueError("The extract carries an attachment no record refers to")
        def describes(subject):
            return subject.get("records_sha256") == files.get("records.jsonl") and subject.get("head_hash") == head
        seal = archive_seal(archive, "report.html", public) if "report.html" in files else None
        if seal and not describes(seal["subject"]):
            raise ValueError("The report seal describes a different extract")
        companions = report_companions(archive, manifest, public, describes)
        board_disclosure = verify_board_disclosure(archive, manifest)
    return {"format": manifest["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "board_disclosure": board_disclosure,
            "purpose": manifest.get("purpose"), "records_unchanged": counts["unchanged"],
            "records_minimised": counts["minimised"], "records_left_out": manifest["counts"].get("left_out"),
            "journal_events": count, "head_hash": head, "attachments": len(referenced),
            "files_checked": len(files), "sha256sums": sums, "report_seal": seal,
            "report_json": companions["json"], "report_parts": companions["parts"], "report_pdf": companions["pdf"],
            "case": manifest.get("case") or {}, "producer": manifest.get("producer")}


def check_attachments(archive, manifest):
    files = manifest["files"]
    for name, digest in files.items():
        if name.startswith("media/") and name[len("media/"):] != digest:
            raise ValueError("Attachment name differs from its SHA-256: " + name)
    referenced, hash_files, count, numbers = 0, set(), 0, set()
    for message in chat_messages(archive):
        count += 1
        number = message.get("id")
        if type(number) is int:
            if number in numbers:
                raise ValueError("Duplicate message ID in chat.json: " + str(number))
            numbers.add(number)
        if message.get("server_hashes") is not None:
            hashes = message["server_hashes"]
            validate_server_hashes(hashes)
            digest = hashlib.sha256(canonical(hashes)).hexdigest()
            name = "hashes/" + digest + ".json"
            if (message.get("file_hash_sha256") != digest or files.get(name) != digest or message.get("file")
                    or message.get("file_status") == "hashes_only" and hashes["status"] != "complete"):
                raise ValueError("Chat file-hash reference or completeness mismatch")
            hash_files.add(name)
        name = message.get("file")
        if name is None:
            continue
        if not isinstance(name, str) or files.get(name) is None or files[name] != message.get("file_sha256"):
            raise ValueError("Message #" + str(message.get("id")) + " names an attachment missing from the archive")
        referenced += 1
    if {name for name in files if name.startswith("hashes/")} != hash_files:
        raise ValueError("Unreferenced chat file-hash manifest")
    if type(manifest.get("message_count")) is not int or manifest["message_count"] != count:
        raise ValueError("Chat message count differs from the signed manifest")
    return referenced


def chat_messages(archive):
    with archive.open("chat.json") as stream:
        inside, header, header_bytes, separator = False, [], 0, None
        lines = iter(bounded_lines(io.TextIOWrapper(stream, encoding="utf-8")))
        for raw in lines:
            line = raw.strip()
            if not inside:
                if line == '"messages": [':
                    json.loads("".join(header) + '"messages": []}')
                    inside = True
                else:
                    header_bytes += len(raw.encode("utf-8"))
                    if header_bytes > MAX_JSON_BYTES:
                        raise ValueError("Chat header exceeds the verification limit")
                    header.append(raw)
                continue
            if line.startswith("]"):
                if separator:
                    raise ValueError("Trailing comma after chat message")
                tail = "".join(line.split())
                for rest in lines:
                    tail += "".join(rest.split())
                    if len(tail) > 2:
                        raise ValueError("Unexpected data after chat messages")
                if tail != "]}":
                    raise ValueError("Invalid chat messages terminator")
                return
            if not line:
                continue
            if separator is False:
                raise ValueError("Missing comma between chat messages")
            separator = line.endswith(",")
            message = strict_json(line.removesuffix(","))
            if not isinstance(message, dict):
                raise ValueError("Chat message must be an object")
            yield message
        raise ValueError("Missing or unsupported chat messages array")


def verify_parts(archive, manifest):
    ranges = []
    for part in manifest["parts"]:
        statement = part["statement"]
        if not is_format(statement.get("format"), "chat-part-v1") or statement["chat_id"] != manifest["chat"]["id"]:
            raise ValueError("Part statement does not belong to this chat export")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["fetched_by_public_key"], validate=True)).verify(
            base64.b64decode(part["signature"], validate=True), canonical(statement))
        for item in statement["ranges"]:
            ranges.append((item["low"], item["high"], item, statement))
    ranges.sort(key=lambda r: r[0])
    for before, after in zip(ranges, ranges[1:]):
        if after[0] <= before[1]:
            raise ValueError("Signed ranges overlap")
    lows = [r[0] for r in ranges]
    hashes, counts = [hashlib.sha256() for _ in ranges], [0] * len(ranges)
    for message in chat_messages(archive):
        i = bisect.bisect_right(lows, message["id"]) - 1
        if i < 0 or message["id"] > ranges[i][1]:
            raise ValueError("Message #" + str(message["id"]) + " is outside every signed range")
        hashes[i].update(canonical(message) + b"\n")
        counts[i] += 1
    accounts = {}
    for (low, high, item, statement), digest, count in zip(ranges, hashes, counts):
        if count != item["count"] or digest.hexdigest() != item["sha256"]:
            raise ValueError("Messages " + str(low) + "-" + str(high) + " differ from what the account signed")
        key = statement["fetched_by_public_key"]
        summary = accounts.setdefault(key, {"account_id": statement["account_id"], "fingerprint": fingerprint(key),
                                            "ranges": 0, "messages": 0})
        summary["ranges"] += 1
        summary["messages"] += count
    return list(accounts.values())


def account_export_integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("Invalid account export " + name)
    return value

def account_export_digest(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Invalid account export " + name)
    return value

def account_export_timestamp(value, name):
    if not isinstance(value, str):
        raise ValueError("Invalid account export " + name)
    parsed = parse_time(value)
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("Account export times must have an explicit UTC offset: " + name)
    return parsed

class AccountExportCheck:
    def __init__(self, archive, expected_fingerprint):
        self.archive = archive
        self.expected_fingerprint = expected_fingerprint

    def verify_manifest(self):
        names = self.archive.namelist()
        self.manifest = read_manifest(self.archive)
        if self.manifest.get("format") != "tgwitness-account-export-v1":
            raise VerifierTooOld("Unsupported account export format")
        self.public = self.manifest["public_key"]
        self.fp = fingerprint(self.public)
        if self.manifest.get("fingerprint") != self.fp:
            raise ValueError("Account export fingerprint does not match the signing key")
        if self.expected_fingerprint and self.fp != self.expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        self.key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public, validate=True))
        self.key.verify(base64.b64decode(read_member(self.archive, "manifest.sig"), validate=True), canonical(self.manifest))
        self.files = self.manifest["files"]
        if not isinstance(self.files, dict) or set(names) != set(self.files) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing account export members")
        for name, checksum in self.files.items():
            if (not name or "\\" in name or ":" in name or name.startswith("/")
                    or any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError("Unsafe account export member name")
            if member_digest(self.archive, name) != account_export_digest(checksum, "file hash"):
                raise ValueError("File hash mismatch: " + name)
        for required in ("job.json", "inventory.json", "SHA256SUMS", "verify.py", "README.txt"):
            if required not in self.files:
                raise ValueError("Missing account export member: " + required)
        self.sums = check_sums(self.archive, self.manifest)
        self.account_id = account_export_integer(self.manifest["account_id"], "account ID", 1)
        self.job_id = self.manifest["job_id"]
        if not isinstance(self.job_id, str) or not self.job_id:
            raise ValueError("Invalid account export job ID")
        self.options = self.manifest["options"]
        if not isinstance(self.options, dict):
            raise ValueError("Invalid account export options")
        self.options_hash = hashlib.sha256(canonical(self.options)).hexdigest()
        if account_export_digest(self.manifest["options_sha256"], "options hash") != self.options_hash:
            raise ValueError("Account export options hash mismatch")


    def signed(self, name, kind):
        envelope = strict_json(read_member(self.archive, name))
        statement = envelope["statement"]
        if (statement.get("format") != "tgwitness-account-export-" + kind + "-v1"
                or statement.get("public_key") != self.public or statement.get("job_id") != self.job_id
                or type(statement.get("account_id")) is not int or statement["account_id"] != self.account_id
                or statement.get("options_sha256") != self.options_hash):
            raise ValueError("Account export signed identity/options mismatch: " + name)
        self.key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(statement))
        return statement, hashlib.sha256(canonical(envelope)).hexdigest()


    def verify_inventory(self):
        job, _ = self.signed("job.json", "job")
        if job.get("options") != self.options or job.get("created_at") != self.manifest.get("created_at"):
            raise ValueError("Account export job does not match the manifest")
        account_export_timestamp(job["created_at"], "created_at")
        account_export_timestamp(self.manifest["completed_at"], "completed_at")
        self.inventory, self.inventory_hash = self.signed("inventory.json", "inventory")
        if self.inventory_hash != account_export_digest(self.manifest["inventory_sha256"], "inventory hash"):
            raise ValueError("Account export inventory hash mismatch")
        account_export_timestamp(self.inventory["observed_at"], "inventory observed_at")
        if (type(self.inventory.get("discovery_complete")) is not bool or not isinstance(self.inventory.get("gaps"), list)
                or any(not isinstance(gap, str) for gap in self.inventory["gaps"])):
            raise ValueError("Invalid account export discovery coverage")
        if not isinstance(self.inventory.get("chats"), list) or not isinstance(self.inventory.get("tasks"), list):
            raise ValueError("Invalid account export task inventory")
        self.tasks = {}
        self.chats = {}
        for chat in self.inventory["chats"]:
            cid = chat.get("id")
            if type(cid) is not int or not cid or cid in self.chats or type(chat.get("selected")) is not bool:
                raise ValueError("Invalid or duplicate account export inventory chat")
            if chat["selected"]:
                if self.options.get("chat_ids") and cid not in self.options["chat_ids"]:
                    raise ValueError("Account export selected a chat outside its frozen options")
                if self.options.get("chat_kinds") is not None and chat.get("kind") not in self.options["chat_kinds"]:
                    raise ValueError("Account export selected a chat kind outside its frozen options")
                if self.options.get("include_archived") is False and chat.get("archived"):
                    raise ValueError("Account export selected an excluded archived chat")
            self.chats[cid] = chat
        metadata_categories = {"profile", "contacts", "sessions", "profile_photos", "stories", "other_data"}
        for task in self.inventory["tasks"]:
            task_id, category = task["id"], task["category"]
            if not isinstance(task_id, str) or not task_id or task_id in self.tasks:
                raise ValueError("Duplicate or invalid account export task ID")
            account_export_integer(task["cursor_start"], "initial cursor")
            if category == "messages":
                if type(task.get("chat_id")) is not int or task["chat_id"] == 0:
                    raise ValueError("Invalid message task chat ID")
                if task["chat_id"] not in self.chats or not self.chats[task["chat_id"]]["selected"]:
                    raise ValueError("Account export message task is outside the selected inventory")
                newest = account_export_integer(task["newest_message_id"], "newest message ID")
                if task["cursor_start"] != newest + 1 or type(task.get("own_only")) is not bool:
                    raise ValueError("Invalid message task boundary")
            elif category not in metadata_categories or task.get("chat_id") is not None:
                raise ValueError("Invalid account export task category")
            self.tasks[task_id] = {"statement": task, "cursor": task["cursor_start"], "terminal": False, "ok": True}

        self.inventory_omissions = ["Selected chat has no history task: " + str(cid) for cid, chat in self.chats.items()
                               if chat["selected"] and not any(t["statement"].get("chat_id") == cid for t in self.tasks.values())]
        category_options = {"profile": "include_profile", "contacts": "include_contacts",
                            "sessions": "include_session_metadata", "profile_photos": "include_profile_photos",
                            "stories": "include_stories", "other_data": "include_other_data"}
        for category, option in category_options.items():
            present = any(t["statement"]["category"] == category for t in self.tasks.values())
            if self.options.get(option) is True and not present:
                self.inventory_omissions.append("Selected category has no acquisition task: " + category)
            if self.options.get(option) is False and present:
                raise ValueError("Account export task is excluded by its frozen options")


    def verify_pages(self, temporary):
        self.receipts = []
        for name in self.files:
            if name.startswith("receipts/"):
                found = re.fullmatch(r"receipts/(\d+)\.json", name)
                if not found:
                    raise ValueError("Unexpected account export receipt name")
                self.receipts.append((int(found[1]), name))
        self.receipts.sort()
        self.counts = dict.fromkeys(("records", "messages", "media_saved", "media_skipped", "bytes_saved"), 0)
        self.media_hashed = 0
        self.hash_manifests, self.hash_index = set(), hashlib.sha256()
        seen = sqlite3.connect(Path(temporary) / "seen.sqlite3")
        seen.execute("CREATE TABLE messages (chat INTEGER, id INTEGER, PRIMARY KEY (chat, id)) WITHOUT ROWID")
        self.data_files, self.media_files, self.failed_attachments, self.failed_pages, self.messages_seen = set(), set(), 0, 0, 0
        self.previous = "0" * 64
        self.since = account_export_timestamp(self.options["from_utc"], "from_utc") if self.options.get("from_utc") else None
        self.until = account_export_timestamp(self.options["to_utc"], "to_utc") if self.options.get("to_utc") else None
        try:
            for seq, (number, name) in enumerate(self.receipts, 1):
                self.verify_page(seq, number, name, seen)
        finally:
            seen.close()

    def verify_page(self, seq, number, name, seen):
        receipt, receipt_hash = self.signed(name, "page")
        if (number != seq or type(receipt.get("seq")) is not int or receipt["seq"] != seq
                or receipt.get("previous_receipt_sha256") != self.previous
                or receipt.get("inventory_sha256") != self.inventory_hash):
            raise ValueError("Broken account export receipt chain at " + str(seq))
        self.previous = receipt_hash
        state = self.tasks.get(receipt.get("task_id"))
        if state is None or state["terminal"]:
            raise ValueError("Unknown or already terminal account export task")
        task = state["statement"]
        if (receipt.get("category") != task["category"] or receipt.get("chat_id") != task.get("chat_id")
                or type(receipt.get("chat_id")) is not type(task.get("chat_id"))):
            raise ValueError("Account export receipt task scope mismatch")
        before = account_export_integer(receipt["cursor_before"], "page cursor before")
        after = account_export_integer(receipt["cursor_after"], "page cursor after")
        if before != state["cursor"] or type(receipt.get("terminal")) is not bool:
            raise ValueError("Broken account export task cursor continuity")
        if receipt.get("outcome") not in ("ok", "failed"):
            raise ValueError("Invalid account export receipt outcome")
        account_export_timestamp(receipt["captured_from"], "captured_from")
        account_export_timestamp(receipt["captured_until"], "captured_until")
        count = account_export_integer(receipt["count"], "page record count")
        page_seen = account_export_integer(receipt["seen_count"], "page seen count")
        if page_seen < count:
            raise ValueError("Account export seen count is shorter than the saved page")
        if task["category"] == "messages":
            self.messages_seen += page_seen
        if task["category"] == "messages" and (after > before or (after == before and not receipt["terminal"])):
            raise ValueError("Invalid account export message pagination boundary")
        data_name = receipt["data_file"]
        matched = re.fullmatch(r"data/(\d+)\.jsonl", data_name) if isinstance(data_name, str) else None
        if not matched or int(matched[1]) != seq or data_name in self.data_files or data_name not in self.files:
            raise ValueError("Missing, reused or mismatched account export page data")
        self.data_files.add(data_name)
        if self.files[data_name] != account_export_digest(receipt["data_sha256"], "page data hash"):
            raise ValueError("Account export receipt data hash mismatch")
        actual, last_id = 0, before
        with self.archive.open(data_name) as stream:
            for line in bounded_lines(stream):
                last_id = self.verify_record(line, task, after, last_id, seen)
                actual += 1
        if actual != count:
            raise ValueError("Account export page record count mismatch")
        self.counts["records"] += actual
        state.update(cursor=after, terminal=receipt["terminal"], ok=state["ok"] and receipt["outcome"] == "ok")
        self.failed_pages += receipt["outcome"] == "failed"

    def verify_record(self, line, task, after, last_id, seen):
        record = strict_json(line)
        if not isinstance(record, dict) or line != canonical(record) + b"\n":
            raise ValueError("Account export records must be canonical JSONL")
        if record.get("category") != task["category"]:
            raise ValueError("Account export record category mismatch")
        if task["category"] == "messages":
            message_id = account_export_integer(record["id"], "message ID", 1)
            if (type(record.get("chat_id")) is not int or record["chat_id"] != task["chat_id"]
                    or message_id > task["newest_message_id"]
                    or not after <= message_id < last_id):
                raise ValueError("Account export message outside the signed pagination boundary")
            last_id = message_id
            if (task["own_only"] or self.options.get("own_messages_only")) and record.get("outgoing") is not True:
                raise ValueError("Account export own-message scope mismatch")
            at = account_export_timestamp(record["date"], "message date")
            if (self.since and at < self.since) or (self.until and at >= self.until):
                raise ValueError("Account export message outside the selected date range")
            if self.options.get("sender_ids") and record.get("from_id") not in self.options["sender_ids"]:
                raise ValueError("Account export sender selection mismatch")
            if self.options.get("text_contains") and not any(term.casefold() in (record.get("text") or "").casefold()
                                                         for term in self.options["text_contains"]):
                raise ValueError("Account export text selection mismatch")
            try:
                seen.execute("INSERT INTO messages VALUES (?, ?)", (task["chat_id"], message_id))
            except sqlite3.IntegrityError:
                raise ValueError("Duplicate account export message") from None
            self.counts["messages"] += 1
        self.verify_attachments(record)
        return last_id

    def verify_attachments(self, record):
        attachments = record.get("attachments", [])
        if not isinstance(attachments, list):
            raise ValueError("Invalid account export attachments")
        for attachment_index, attachment in enumerate(attachments):
            outcome = attachment.get("outcome")
            server_hashes = attachment.get("server_hashes")
            if server_hashes is not None:
                validate_server_hashes(server_hashes)
                manifest_digest = hashlib.sha256(canonical(server_hashes)).hexdigest()
                hash_file = "hashes/" + manifest_digest + ".json"
                if self.files.get(hash_file) != manifest_digest:
                    raise ValueError("File-hash manifest differs from its signed message record")
                self.hash_manifests.add(hash_file)
                self.hash_index.update(canonical({"category": record["category"], "chat_id": record.get("chat_id"),
                    "message_id": record.get("id"), "attachment_index": attachment_index, "manifest": hash_file}) + b"\n")
            if outcome == "saved":
                checksum = account_export_digest(attachment["sha256"], "attachment hash")
                media_name = "media/" + checksum
                size = account_export_integer(attachment["bytes"], "attachment byte count")
                if (attachment.get("file") != media_name or self.files.get(media_name) != checksum
                        or self.archive.getinfo(media_name).file_size != size):
                    raise ValueError("Account export attachment bytes/hash mismatch")
                expected = attachment.get("expected_bytes")
                if expected is not None and account_export_integer(expected, "expected attachment bytes") != size:
                    raise ValueError("Account export attachment size differs from observation")
                representation = attachment.get("representation")
                if representation is not None and (not isinstance(representation, dict)
                        or account_export_integer(representation.get("bytes"), "attachment representation bytes") != size):
                    raise ValueError("Account export attachment size differs from its representation")
                self.media_files.add(media_name)
                self.counts["media_saved"] += 1
                self.counts["bytes_saved"] += size
            elif outcome == "hashed":
                if (attachment.get("file") or attachment.get("sha256") or not server_hashes
                        or server_hashes["status"] != "complete"):
                    raise ValueError("Hash-only attachment claims saved bytes or incomplete coverage")
                self.media_hashed += 1
            elif outcome in ("excluded", "failed"):
                if attachment.get("file") or attachment.get("sha256"):
                    raise ValueError("Unsaved account export attachment claims saved bytes")
                self.counts["media_skipped"] += 1
                self.failed_attachments += outcome == "failed"
            else:
                raise ValueError("Invalid account export attachment outcome")

    def finish(self):
        if {name for name in self.files if name.startswith("data/")} != self.data_files:
            raise ValueError("Unreceipted account export page data")
        if {name for name in self.files if name.startswith("media/")} != self.media_files:
            raise ValueError("Unreferenced account export media")
        if self.hash_manifests:
            if self.files.get("hashes/index.jsonl") != self.hash_index.hexdigest():
                raise ValueError("File-hash index differs from signed message references")
            self.hash_manifests.add("hashes/index.jsonl")
        if {name for name in self.files if name.startswith("hashes/")} != self.hash_manifests:
            raise ValueError("Unreferenced account export file-hash manifest")
        if (account_export_integer(self.manifest["receipt_count"], "receipt count") != len(self.receipts)
                or account_export_digest(self.manifest["receipt_head_sha256"], "receipt head") != self.previous):
            raise ValueError("Account export manifest receipt boundary mismatch")
        declared_counts = self.manifest["counts"]
        if "unique_media_bytes" in declared_counts:
            self.counts["unique_media_bytes"] = sum(self.archive.getinfo(name).file_size for name in self.media_files)
        if declared_counts.get("media_hashed", 0) != self.media_hashed:
            raise ValueError("Account export hash-only attachment count mismatch")
        if any(type(declared_counts.get(name)) is not int or declared_counts[name] != count for name, count in self.counts.items()):
            raise ValueError("Account export manifest counts mismatch")
        if "messages_exported" in declared_counts and declared_counts["messages_exported"] != self.counts["messages"]:
            raise ValueError("Account export message summary mismatch")
        if "messages_seen" in declared_counts and declared_counts["messages_seen"] != self.messages_seen:
            raise ValueError("Account export seen-message summary mismatch")
        if "media_hashed" in declared_counts:
            self.counts["media_hashed"] = self.media_hashed
        done = sum(state["terminal"] and state["ok"] for state in self.tasks.values())
        failed_tasks = [name for name, state in self.tasks.items() if not state["ok"]]
        coverage = self.manifest["coverage"]
        if (type(coverage.get("inventory_complete")) is not bool
                or coverage["inventory_complete"] != self.inventory["discovery_complete"]
                or type(coverage.get("tasks_total")) is not int or coverage["tasks_total"] != len(self.tasks)
                or type(coverage.get("tasks_done")) is not int or coverage["tasks_done"] != done
                or type(coverage.get("failures")) is not int
                or coverage["failures"] != len(failed_tasks) + self.failed_attachments + len(self.inventory["gaps"])):
            raise ValueError("Account export coverage summary mismatch")
        complete = (self.inventory["discovery_complete"] and done == len(self.tasks)
                    and not self.inventory["gaps"] and not self.inventory_omissions and not self.failed_attachments and not self.failed_pages)
        if type(self.manifest.get("complete_within_scope")) is not bool or self.manifest["complete_within_scope"] != complete:
            raise ValueError("Account export completeness claim disagrees with acquisition receipts")
        if not isinstance(self.manifest.get("status"), str) or (self.manifest["status"] in ("done", "complete") and not complete):
            raise ValueError("Account export status contradicts its partial acquisition coverage")
        return {"format": self.manifest["format"], "fingerprint": self.fp, "key_pinned": bool(self.expected_fingerprint),
                "job_id": self.job_id, "account_id": self.account_id, "status": self.manifest["status"], "counts": self.counts,
                "options": self.options, "options_sha256": self.manifest["options_sha256"],
                "receipt_count": len(self.receipts), "receipt_head_sha256": self.previous, "files_checked": len(self.files),
                "sha256sums": self.sums, "producer": self.manifest.get("producer"), "coverage": {
                    "inventory_complete": self.inventory["discovery_complete"], "tasks_total": len(self.tasks), "tasks_done": done,
                    "unfinished_tasks": [name for name, state in self.tasks.items() if not state["terminal"]],
                    "failed_tasks": failed_tasks,
                    "failed_pages": self.failed_pages, "failed_attachments": self.failed_attachments,
                    "gaps": self.inventory["gaps"] + self.inventory_omissions},
                "complete_within_scope": complete, "source_completeness_established": False,
                "html_index_signed_by_manifest": "index.html" in self.files,
                "meaning": "Integrity is checked relative to the signing key. Completion covers the frozen selected "
                           "tasks and observed outcomes, not all Telegram data, a simultaneous snapshot or trusted time."}




def verify_account_export(path, expected_fingerprint=None, max_gib=None):
    with open_archive(path, max_gib=max_gib) as archive, tempfile.TemporaryDirectory() as temporary:
        checked = AccountExportCheck(archive, expected_fingerprint)
        checked.verify_manifest()
        checked.verify_inventory()
        checked.verify_pages(temporary)
        return checked.finish()


def account_export_lines(result):
    coverage = result["coverage"]
    lines = ["Account " + str(result["account_id"]) + ": " + str(result["counts"]["messages"])
             + " message(s), " + str(result["receipt_count"]) + " signed capture receipt(s).",
             "Selected acquisition tasks finished: " + str(coverage["tasks_done"]) + " of " + str(coverage["tasks_total"]) + ".",
             "Complete within selected scope." if result["complete_within_scope"] else "Partial acquisition: selected scope is not complete.",
             result["meaning"]]
    if coverage["failed_pages"] or coverage["failed_attachments"]:
        lines.append("Failed pages: " + str(coverage["failed_pages"]) + "; failed attachments: "
                     + str(coverage["failed_attachments"]) + ".")
    lines += ["Inventory gap: " + str(gap) for gap in coverage["gaps"]]
    if result["html_index_signed_by_manifest"]:
        lines.append("The HTML index is protected by the signed archive manifest; a separate browser printout is not signed.")
    return lines


DISCLOSURE_FORMATS = ("tgwitness-account-disclosure-v1", "tgwitness-account-disclosure-v2")
WITHHELD_RULES = ("sender", "text", "period")
WITHHELD_FIELDS = {"id", "state", "rules", "count", "text", "attachments", "redacted_fields"}
REPLY_STATES = ("disclosed", "withheld", "not_in_source")


class AccountDisclosureCheck:
    def __init__(self, archive, expected_fingerprint, source, max_gib):
        self.archive = archive
        self.expected_fingerprint = expected_fingerprint
        self.source = source
        self.max_gib = max_gib

    def verify_manifest(self):
        self.manifest = read_manifest(self.archive)
        if self.manifest.get("format") not in DISCLOSURE_FORMATS:
            raise VerifierTooOld("Unsupported account disclosure format")
        self.marked = self.manifest["format"] == "tgwitness-account-disclosure-v2"
        self.public = self.manifest["public_key"]
        self.fp = fingerprint(self.public)
        if self.manifest.get("fingerprint") != self.fp:
            raise ValueError("Disclosure fingerprint does not match its signing key")
        if self.expected_fingerprint and self.fp != self.expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        self.key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public, validate=True))
        self.key.verify(base64.b64decode(read_member(self.archive, "manifest.sig"), validate=True), canonical(self.manifest))
        self.files = self.manifest["files"]
        if not isinstance(self.files, dict) or set(self.archive.namelist()) != set(self.files) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing disclosure archive members")
        allowed = {"messages.jsonl", "index.html", "analytics.json", "README.txt", "verify.py", "SHA256SUMS",
                   "VERIFY.cmd", "VERIFY.sh", "START_HERE.txt"}
        for name, checksum in self.files.items():
            if name not in allowed and not re.fullmatch(r"media/[0-9a-f]{64}", name):
                raise ValueError("Unexpected disclosure content: " + name)
            if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError("Invalid disclosure file hash")
            if member_digest(self.archive, name) != checksum:
                raise ValueError("File hash mismatch: " + name)
        if "messages.jsonl" not in self.files or "index.html" not in self.files:
            raise ValueError("Missing authoritative disclosure messages or readable index")
        self.sums = check_sums(self.archive, self.manifest)
        for field in ("source_archive_sha256", "source_collector_fingerprint"):
            if not isinstance(self.manifest.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", self.manifest[field]):
                raise ValueError("Invalid disclosure source reference")
        if not isinstance(self.manifest.get("policy"), dict):
            raise ValueError("Disclosure must record its applied policy")

    def verify_messages(self, temporary):
        seen = sqlite3.connect(Path(temporary) / "disclosure.sqlite3")
        seen.execute("CREATE TABLE messages (chat TEXT, id TEXT, state TEXT, PRIMARY KEY(chat,id)) WITHOUT ROWID")
        seen.execute("CREATE TABLE replies (chat TEXT, id TEXT, state TEXT)")
        self.media, self.messages, self.withheld = set(), 0, 0
        try:
            with self.archive.open("messages.jsonl") as stream:
                for line in bounded_lines(stream):
                    row = strict_json(line)
                    if not isinstance(row, dict) or set(row) != {"chat", "message"}:
                        raise ValueError("Invalid disclosure message envelope")
                    chat, message = row["chat"], row["message"]
                    if not isinstance(chat, dict) or not isinstance(message, dict):
                        raise ValueError("Invalid disclosure chat/message")
                    for value in (chat.get("id"), message.get("id")):
                        if type(value) not in (str, int) or not value:
                            raise ValueError("Invalid disclosure chat/message ID")
                    state = message.get("state", "disclosed") if self.marked else "disclosed"
                    if self.marked and state not in ("disclosed", "withheld"):
                        raise ValueError("Invalid disclosure record state")
                    try:
                        seen.execute("INSERT INTO messages VALUES (?,?,?)",
                                     (canonical(chat["id"]).decode(), canonical(message["id"]).decode(), state))
                    except sqlite3.IntegrityError:
                        raise ValueError("Duplicate disclosure message") from None
                    if state == "withheld":
                        rules, count = message.get("rules"), message.get("count")
                        if (set(message) != WITHHELD_FIELDS or message.get("attachments") != []
                                or message.get("redacted_fields") != []
                                or not isinstance(rules, list) or not rules
                                or any(not isinstance(rule, str) or rule not in WITHHELD_RULES for rule in rules)
                                or rules != [rule for rule in WITHHELD_RULES if rule in rules]
                                or message.get("text") != "[withheld by selection \u2014 rule: " + ", ".join(rules) + "]"
                                or type(count) is not int or count < 1):
                            raise ValueError("Invalid withheld-by-selection marker")
                        self.withheld += count
                        continue
                    reply = message.get("reply_to") if self.marked else None
                    if reply is not None:
                        if (not isinstance(reply, dict) or set(reply) != {"id", "state"}
                                or type(reply.get("id")) not in (str, int) or not reply["id"]
                                or reply.get("state") not in REPLY_STATES):
                            raise ValueError("Invalid disclosure reply reference")
                        seen.execute("INSERT INTO replies VALUES (?,?,?)",
                                     (canonical(chat["id"]).decode(), canonical(reply["id"]).decode(), reply["state"]))
                    attachments = message.get("attachments", [])
                    if not isinstance(attachments, list):
                        raise ValueError("Invalid disclosure attachments")
                    for item in attachments:
                        if not isinstance(item, dict):
                            raise ValueError("Invalid disclosure attachment")
                        if item.get("outcome") != "saved":
                            if item.get("file") or item.get("sha256"):
                                raise ValueError("Unsaved disclosure attachment claims saved bytes")
                            continue
                        checksum = item.get("sha256")
                        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                            raise ValueError("Invalid disclosure media hash")
                        name = "media/" + checksum
                        size = item.get("bytes")
                        if (type(size) is not int or size < 0 or item.get("file") != name
                                or self.files.get(name) != checksum or self.archive.getinfo(name).file_size != size):
                            raise ValueError("Disclosure attachment bytes/hash mismatch")
                        self.media.add(name)
                    self.messages += 1
            self.chats = seen.execute("SELECT COUNT(DISTINCT chat) FROM messages WHERE state='disclosed'").fetchone()[0]
            dangling = seen.execute("SELECT count(*) FROM replies r LEFT JOIN messages m ON m.chat=r.chat AND m.id=r.id "
                                    "WHERE (r.state!='not_in_source' AND (m.id IS NULL OR m.state!=r.state)) "
                                    "OR (r.state='not_in_source' AND m.id IS NOT NULL)").fetchone()[0]
            if dangling:
                raise ValueError("A disclosed reply points at a record that is not in this disclosure")
        finally:
            seen.close()

    def finish(self):
        if {name for name in self.files if name.startswith("media/")} != self.media:
            raise ValueError("Unreferenced disclosure media")
        counts = {"messages": self.messages, "chats": self.chats, "media": len(self.media)}
        if self.marked:
            counts["withheld"] = self.withheld
        if (not isinstance(self.manifest.get("counts"), dict) or set(self.manifest["counts"]) != set(counts)
                or any(type(self.manifest["counts"][name]) is not int or self.manifest["counts"][name] != count
                       for name, count in counts.items())):
            raise ValueError("Disclosure manifest counts mismatch")
        source_checked = False
        if self.source is not None:
            with open(self.source, "rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            if checksum != self.manifest["source_archive_sha256"]:
                raise ValueError("Disclosure source archive hash mismatch")
            if self.fp != self.manifest["source_collector_fingerprint"]:
                raise ValueError("The disclosure is signed by a different key than its source archive")
            verify_account_export(self.source, self.manifest["source_collector_fingerprint"], max_gib=self.max_gib)
            source_checked = True
        return {"format": self.manifest["format"], "fingerprint": self.fp, "key_pinned": bool(self.expected_fingerprint),
                "disclosure_id": self.manifest.get("disclosure_id"), "created_at": self.manifest.get("created_at"),
                "counts": counts, "policy": self.manifest["policy"], "files_checked": len(self.files), "sha256sums": self.sums,
                "source_archive_sha256": self.manifest["source_archive_sha256"],
                "source_collector_fingerprint": self.manifest["source_collector_fingerprint"],
                "source_reference_checked": source_checked, "derivation_correctness_established": False,
                "html_index_signed_by_manifest": True, "producer": self.manifest.get("producer"),
                "meaning": "The signature protects this disclosure's bytes and policy statement. "
                           "Source linkage names the original archive and collector key; filtering and redaction follow the stated policy."}





def verify_account_disclosure(path, expected_fingerprint=None, source=None, max_gib=None):
    with open_archive(path, max_gib=max_gib) as archive, tempfile.TemporaryDirectory() as temporary:
        checked = AccountDisclosureCheck(archive, expected_fingerprint, source, max_gib)
        checked.verify_manifest()
        checked.verify_messages(temporary)
        return checked.finish()
def bundle_format(path):
    with open_archive(path) as archive:
        return read_manifest(archive).get("format")


def bundle_hashes(path, seqs):
    wanted, found = set(seqs), {}
    if not wanted:
        return found
    with open_archive(path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = strict_json(line)
            if event["seq"] in wanted:
                found[event["seq"]] = event["hash"]
    return found


CAPTURE_KINDS = ("message.new", "message.edited", "message.deleted", "message.recovered",
                 "message.snapshot", "media.saved", "coverage.gap")


def verify_capture(value, checkpoint):
    statement = authenticate_statement(value)
    if not is_format(statement.get("format"), "capture-v1"):
        raise VerifierTooOld("Unsupported capture proof")
    fields = {"format", "created_at", "public_key", "event_count", "head_hash", "challenge", "counts", "last_message_at", "health"}
    if set(value) != {"statement", "signature"} or set(statement) not in (fields, fields | {"keys"}):
        raise ValueError("Unexpected capture proof fields")
    if set(checkpoint) != {"format", "created_at", "public_key", "event_count", "head_hash"}:
        raise ValueError("Unexpected checkpoint fields")
    if not is_format(statement.get("format"), "capture-v1"):
        raise ValueError("Unsupported capture proof")
    if (type(statement["event_count"]) is not int or statement["event_count"] < 0
            or not isinstance(statement["head_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", statement["head_hash"])):
        raise ValueError("Malformed capture boundary")
    for field in ("public_key", "event_count", "head_hash", "created_at"):
        if statement.get(field) != checkpoint.get(field):
            raise ValueError("Capture proof differs from checkpoint: " + field)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    counts = statement.get("counts")
    if not isinstance(counts, dict) or set(counts) != set(CAPTURE_KINDS):
        raise ValueError("Unexpected capture counters")
    if any(type(n) is not int or n < 0 for n in counts.values()) or sum(counts.values()) > statement["event_count"]:
        raise ValueError("Invalid capture counters")
    if statement.get("last_message_at") is not None:
        parse_time(statement["last_message_at"])
    parse_time(statement["created_at"])
    challenge = statement["challenge"]
    if challenge is not None and (not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{32}", challenge)):
        raise ValueError("Malformed capture challenge")
    health = statement["health"]
    if not isinstance(health, dict) or set(health) != {"running", "connected", "last_heartbeat", "media_pending", "media_failed", "backoff_until"}:
        raise ValueError("Unexpected capture health fields")
    if any(type(health[k]) is not bool for k in ("running", "connected")):
        raise ValueError("Invalid capture health flags")
    if any(type(health[k]) is not int or health[k] < 0 for k in ("media_pending", "media_failed")):
        raise ValueError("Invalid capture queue counts")
    if type(health["backoff_until"]) not in (int, float) or not 0 <= health["backoff_until"] < 1e12:
        raise ValueError("Invalid capture backoff")
    if health["last_heartbeat"] is not None:
        parse_time(health["last_heartbeat"])
    if "keys" in statement:
        keys = statement["keys"]
        if (not isinstance(keys, dict) or set(keys) != {"count", "origin", "authorized_seq"}
                or type(keys["count"]) is not int or not 0 <= keys["count"] <= statement["event_count"]
                or keys["origin"] not in ("created", "imported", "unknown")
                or (keys["count"] == 0 and (keys["authorized_seq"] is not None or keys["origin"] != "unknown"))
                or (keys["count"] > 0 and (type(keys["authorized_seq"]) is not int
                                          or not keys["count"] <= keys["authorized_seq"] <= statement["event_count"]))):
            raise ValueError("Malformed collector key history")
    return statement


def bundle_capture_prefixes(bundle_path, boundaries):
    wanted, result = set(boundaries), {}
    tree = MerkleFrontier()
    counts, last = dict.fromkeys(CAPTURE_KINDS, 0), None
    keys = {"count": 0, "origin": "unknown", "authorized_seq": None}
    if 0 in wanted:
        result[0] = {"head_hash": "0" * 64, "counts": dict(counts), "last_message_at": None,
                     "root": tree.root().hex(), "keys": dict(keys)}
    if not wanted:
        return result
    limit = max(wanted)
    with open_archive(bundle_path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = strict_json(line)
            if event["seq"] > limit:
                break
            tree.append(event["hash"])
            if event["kind"] == "account.authorized":
                origin = event["payload"].get("key_origin")
                keys = {"count": keys["count"] + 1, "authorized_seq": event["seq"],
                        "origin": origin if origin in ("created", "imported") else "unknown"}
            if event["kind"] in counts:
                counts[event["kind"]] += 1
                if event["kind"].startswith("message."):
                    last = max(last or event["observed_at"], event["observed_at"])
            if event["seq"] in wanted:
                result[event["seq"]] = {"head_hash": event["hash"], "counts": dict(counts), "last_message_at": last,
                                        "root": tree.root().hex(), "keys": dict(keys)}
    return result


def check_capture_prefix(value, bundle_path):
    statement = value["statement"]
    prefix = bundle_capture_prefixes(bundle_path, [statement["event_count"]]).get(statement["event_count"])
    if prefix is None or prefix["head_hash"] != statement["head_hash"]:
        raise ValueError("Capture proof head is absent from the evidence")
    if prefix["counts"] != statement["counts"] or prefix["last_message_at"] != statement.get("last_message_at"):
        raise ValueError("Capture counters differ from the evidence records")
    if "keys" in statement and prefix["keys"] != statement["keys"]:
        raise ValueError("Capture key history differs from the evidence records")
    return prefix["counts"]


WITNESS_TOKEN = re.compile(r"TGW1\.([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{40,})")
CHANNEL_POST = re.compile(r'[^"/]+/(\d+)"')
CHANNEL_TEXT = re.compile(r'class="tgme_widget_message_text js-message_text"[^>]*>(.*?)</div>', re.S)
CHANNEL_META = re.compile(r'class="tgme_widget_message_meta"[^>]*>(.*?)</time>', re.S)
CHANNEL_TIME = re.compile(r'<time datetime="([^"]+)"')
TELEGRAM_PAGES = ("t.me", "telegram.me")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class DailyJournal:
    def __init__(self):
        self.tree, self.dates = MerkleFrontier(), {}
        self.previous, self.last_date, self.latest = None, None, None

    def payload(self, date):
        if not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError("Invalid daily seal date")
        datetime.strptime(date, "%Y-%m-%d")
        if self.last_date is not None and date <= self.last_date:
            raise ValueError("Repeated or reversed daily seal")
        before = max((v for k, v in self.dates.items() if k <= date), key=lambda v: v["to_seq"], default=None)
        boundary = before or {"to_seq": 0, "head_hash": "0" * 64, "root": MERKLE_EMPTY.hex()}
        day = self.dates.get(date, {})
        return {"date": date, "from_seq": day.get("from_seq", boundary["to_seq"] + 1),
                **{k: boundary[k] for k in ("to_seq", "head_hash", "root")},
                "checks": dict(day.get("checks", {"no_response": 0})),
                "previous_daily_sha256": self.previous, "drand_round": day.get("drand_round")}

    def add(self, event):
        moment = parse_time(event["observed_at"])
        if moment.tzinfo is None:
            raise ValueError("Witness date has no time zone")
        self.latest = moment if self.latest is None else max(moment, self.latest)
        date = moment.astimezone(timezone.utc).date().isoformat()
        if self.last_date is not None and date <= self.last_date:
            date = self.latest.astimezone(timezone.utc).date().isoformat()
        self.tree.append(event["hash"])
        day = self.dates.setdefault(date, {"from_seq": event["seq"], "checks": {"no_response": 0}})
        day.update(to_seq=event["seq"], head_hash=event["hash"], root=self.tree.root().hex())
        kind, payload = event["kind"], event["payload"]
        if kind in ("witness.anchor", "witness.no_response"):
            status = payload.get("status", "invalid") if kind == "witness.anchor" else "no_response"
            if status not in ("ok", "invalid", "key_changed", "rollback", "fork", "no_response"):
                raise ValueError("Unknown witness check status")
            day["checks"][status] = day["checks"].get(status, 0) + 1
            if payload.get("freshness"):
                day["drand_round"] = payload["freshness"]["drand_round"]
        elif kind == "witness.daily":
            if payload["date"] >= date:
                raise ValueError("Witness sealed an unfinished UTC day")
            self.previous = hashlib.sha256(canonical(event)).hexdigest()
            self.last_date = payload["date"]


def daily_payload(events, date):
    journal = DailyJournal()
    for event in events:
        journal.add(event)
    return journal.payload(date)


def witness_challenge(freshness):
    if not isinstance(freshness, dict):
        raise ValueError("Invalid witness freshness")
    beacon = drand_beacon({"round": freshness.get("drand_round"),
                          "randomness": freshness.get("drand_randomness"),
                          "signature": freshness.get("drand_signature")})
    nonce = freshness.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("Invalid witness freshness nonce")
    return hashlib.sha256(bytes.fromhex(beacon["signature"]) + bytes.fromhex(nonce)).hexdigest()[:32]


def post_statement(event, witness_fingerprint):
    payload = event["payload"]
    statement = {"format": "tgwitness-witness-post-v1", "witness": witness_fingerprint, "seq": event["seq"],
            "at": event["observed_at"], "record_hash": event["hash"],
            "status": payload.get("status") or ("no_response" if event["kind"] == "witness.no_response" else None),
            "collector": payload.get("collector_fingerprint"), "events": payload.get("event_count"),
            "head": payload.get("head_hash")}
    if payload.get("capture"):
        statement.update(capture_sha256=hashlib.sha256(canonical(payload["capture"])).hexdigest(),
                         counts=payload["capture"]["statement"]["counts"], delta=payload.get("capture_delta"))
    if payload.get("freshness") is not None:
        statement["drand_round"] = payload["freshness"]["drand_round"]
    if event["kind"] == "witness.daily":
        statement.update(kind="witness.daily", date=payload["date"], root=payload["root"],
                         drand_round=payload.get("drand_round"), previous_daily_sha256=payload["previous_daily_sha256"])
    return statement


def post_token(statement, signature_b64):
    return "TGW1." + b64url(canonical(statement)) + "." + b64url(base64.b64decode(signature_b64))


def verify_witness(path, expected_fingerprint=None, check_drand=False, check_bitcoin=False):
    with open_archive(path) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "witness-v1"):
            raise VerifierTooOld("Unsupported witness format")
        public = manifest["public_key"]
        fp = fingerprint(public)
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Witness key differs from the independently trusted witness fingerprint")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
            base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        if set(names) != set(manifest["files"]) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing witness bundle members")
        for name, digest in manifest["files"].items():
            if member_digest(archive, name) != digest:
                raise ValueError("File hash mismatch: " + name)
        anchors, silent, posted, failures, statements, interval = [], [], {}, [], {}, None
        retained, collector_keys = {}, {}
        journal, days, seals = DailyJournal(), [], {}

        def observed(stream):
            nonlocal interval
            for line in bounded_lines(stream):
                if not line.strip():
                    continue
                event = json.loads(line)
                yield event
                payload, kind = event["payload"], event["kind"]
                if kind == "witness.daily":
                    expected = journal.payload(payload.get("date"))
                    if canonical(payload) != canonical(expected):
                        raise ValueError("Witness daily root, counts, range or previous seal differs from the journal")
                    checks = payload["checks"]
                    status = "fail" if any(v for k, v in checks.items() if k not in ("ok", "no_response")) else \
                        "ok" if checks.get("ok") else "no_response_only"
                    day = {**payload, "seq": event["seq"], "status": status, "bitcoin": "none", "proofs": []}
                    seals[event["seq"]] = event
                    days.append(day)
                    statements[event["seq"]] = post_statement(event, fp)
                elif kind == "witness.anchored":
                    if payload.get("record") not in seals or not isinstance(payload.get("results"), list):
                        raise ValueError("Witness timestamp record has no preceding daily seal")
                journal.add(event)
                if kind == "witness.started":
                    interval = payload.get("interval_minutes")
                elif kind == "witness.anchor":
                    anchors.append({"seq": event["seq"], "at": event["observed_at"], "status": payload.get("status"),
                                    "collector_fingerprint": payload.get("collector_fingerprint"),
                                    "event_count": payload.get("event_count"), "head_hash": payload.get("head_hash")})
                    if payload.get("capture"):
                        captured = verify_capture(payload["capture"], payload["checkpoint"]["statement"])
                        if (fingerprint(captured["public_key"]) != payload["collector_fingerprint"]
                                or captured["event_count"] != payload["event_count"]
                                or captured["head_hash"] != payload["head_hash"]):
                            raise ValueError("Witness capture proof differs from its anchor")
                        anchors[-1]["capture"] = payload["capture"]
                        if captured.get("keys") is not None:
                            if payload.get("keys") != captured["keys"]:
                                raise ValueError("Witness key history differs from its signed capture")
                            anchors[-1]["keys"] = captured["keys"]
                            collector_keys[payload["collector_fingerprint"]] = key_history_summary(captured["keys"])
                    if "keys" in payload and not payload.get("capture"):
                        raise ValueError("Witness key history has no signed capture")
                    if payload.get("freshness") is not None:
                        fresh = payload["freshness"]
                        challenge = witness_challenge(fresh)
                        if not payload.get("capture") or captured.get("challenge") != challenge:
                            raise ValueError("Witness freshness challenge differs from the signed capture")
                        anchors[-1]["freshness"] = {**fresh, "verified": False, "not_before": None}
                    collector_key = payload.get("collector_fingerprint")
                    changed = payload.get("status") == "key_changed" and "previous_keys" in payload
                    if payload.get("status") == "ok" or changed:
                        prior = retained.get(collector_key)
                        if changed and (not prior or prior.get("keys") is None or prior["keys"] != payload["previous_keys"]
                                        or anchors[-1].get("keys") in (None, prior["keys"])
                                        or payload.get("pinned_fingerprint") != collector_key):
                            raise ValueError("Witness recorded a collector key change that differs from its key history")
                        if not changed and prior and prior.get("keys") is not None and prior["keys"] != anchors[-1].get("keys"):
                            raise ValueError("Witness accepted a changed or removed collector key history")
                        if changed:
                            anchors[-1]["previous_keys"] = payload["previous_keys"]
                        if payload.get("continuity") is not None:
                            if not payload.get("capture"):
                                raise ValueError("Continuity proof has no matching capture proof")
                            committed = verify_continuity(payload["continuity"], payload["checkpoint"]["statement"],
                                                          prior, captured["challenge"])
                            anchors[-1]["continuity"] = payload["continuity"]
                            anchors[-1]["root"] = committed["root"]
                        elif prior and prior.get("root"):
                            raise ValueError("Witness accepted a continuity downgrade")
                        retained[collector_key] = {k: anchors[-1][k] for k in ("event_count", "head_hash", "root", "keys")
                                                  if k in anchors[-1]}
                    statements[event["seq"]] = post_statement(event, fp)
                elif kind == "witness.no_response":
                    silent.append({"seq": event["seq"], "at": event["observed_at"], "error": payload.get("error")})
                    statements[event["seq"]] = post_statement(event, fp)
                elif kind == "witness.posted":
                    posted[payload.get("record")] = payload.get("message_id")
                elif kind == "witness.post_failed":
                    failures.append({"record": payload.get("record"), "error": payload.get("error")})
        with archive.open("events.jsonl") as stream:
            result = verify_events(observed(stream), public)
        proof_files = set()
        for day in days:
            event = seals[day["seq"]]
            digest = hashlib.sha256(canonical(event)).digest()
            stem = "anchors/daily-" + day["date"]
            if stem + ".json" in names:
                proof_files.add(stem + ".json")
                if read_member(archive, stem + ".json") != canonical(event):
                    raise ValueError("Retained witness daily seal differs from its journal record")
            for name in sorted(n for n in names if n.startswith(stem + ".") and n.endswith(".ots")):
                proof_files.add(name)
                proof = read_member(archive, name)
                summary = ots_summary(proof, digest)
                if check_bitcoin:
                    summary = confirm_ots(proof, digest)
                day["proofs"].append({"file": name, **summary})
            if any(p["status"] == "confirmed" for p in day["proofs"]):
                day["bitcoin"] = "confirmed"
                day["bitcoin_block_time"] = min(p["time"] for p in day["proofs"] if p["status"] == "confirmed")
            elif day["proofs"]:
                day["bitcoin"] = "pending"
        if any(n.startswith("anchors/") and n not in proof_files for n in names):
            raise ValueError("Witness timestamp file has no matching daily seal")
        missing_days = []
        if days:
            first, last = (datetime.strptime(d["date"], "%Y-%m-%d").date() for d in (days[0], days[-1]))
            if (last - first).days > 36600:
                raise ValueError("Witness daily range exceeds 100 years")
            dates = {d["date"] for d in days}
            missing_days = [(first + timedelta(days=i)).isoformat() for i in range((last - first).days + 1)
                            if (first + timedelta(days=i)).isoformat() not in dates]
    if result["events"] != manifest["event_count"] or result["head_hash"] != manifest["head_hash"]:
        raise ValueError("Witness manifest does not match its journal")
    bound = [a for a in anchors if a.get("freshness")]
    confirmation = {"asked": 0, "confirmed": 0, "relays": []}
    if check_drand and bound:
        rounds = [{"round": a["freshness"]["drand_round"], "randomness": a["freshness"]["drand_randomness"],
                   "seq": a["seq"]} for a in bound]
        confirmation = confirm_drand(rounds, limit=len(rounds))
        if confirmation["confirmed"] == len(rounds):
            for anchor in bound:
                anchor["freshness"].update(verified=True, not_before=drand_time(anchor["freshness"]["drand_round"]))
    freshness = {"anchors": len(anchors), "drand_bound": len(bound), "confirmed": confirmation["confirmed"],
                 "earliest_not_before": min((a["freshness"]["not_before"] for a in bound
                                              if a["freshness"]["verified"]), default=None),
                 "verification": "relay-confirmed" if confirmation["confirmed"] else "not-performed",
                 "relays": confirmation["relays"], "unavailable": bool(confirmation.get("unavailable"))}
    return {"format": manifest["format"], "fingerprint": fp, "public_key": public, "events": result["events"],
            "head_hash": result["head_hash"], "interval_minutes": interval, "channel": manifest.get("channel"),
            "producer": manifest.get("producer"), "anchors": anchors, "no_response": silent, "posted": posted,
            "post_failures": failures, "statements": statements, "key_pinned": bool(expected_fingerprint),
            "freshness": freshness, "days": days, "missing_days": missing_days, "collector_keys": collector_keys,
            **({"chronology": result["chronology"]} if "chronology" in result else {})}


def key_history_summary(keys):
    return {**keys, "meaning": "Telegram authorizations of the account as the collector recorded them",
            "note": "Imported session: the acquisition starts from an authorization created outside this collector"
            if keys["origin"] == "imported" else None}


def witnessed_periods(witness, key=None):
    limit = (witness.get("interval_minutes") or 10) * 60 * 2.5
    timeline = sorted([(a["at"], a["status"] == "ok" and key in (None, a["collector_fingerprint"]))
                       for a in witness["anchors"]]
                      + [(s["at"], False) for s in witness["no_response"]])
    periods, gaps, start, previous = [], [], None, None
    for at, ok in timeline:
        if ok and start is not None and (parse_time(at) - parse_time(previous)).total_seconds() > limit:
            periods.append({"from": start, "to": previous})
            gaps.append({"from": previous, "to": at, "reason": "no witness record (witness offline)"})
            start = None
        if ok:
            start, previous = start or at, at
        else:
            if start is not None:
                periods.append({"from": start, "to": previous})
                start = None
            gaps.append({"from": at, "to": at, "reason": "the collector did not answer or answered inconsistently"})
    if start is not None:
        periods.append({"from": start, "to": previous})
    return periods, gaps


def witness_moment(value):
    parsed = parse_time(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def cross_check_witness(witness, bundle_path, bundle_result):
    count, key = bundle_result["events"], bundle_result["fingerprint"]
    mine = [a for a in witness["anchors"] if a["collector_fingerprint"] == key]
    explained = {a["seq"] for a in witness["anchors"] if a["status"] == "key_changed" and a.get("previous_keys")}
    comparable = {a["seq"] for a in mine if a["status"] == "ok" or a["seq"] in explained}
    hashes = bundle_hashes(bundle_path, {a["event_count"] for a in mine
                                         if a["seq"] in comparable and 0 < (a["event_count"] or 0) <= count})
    prefixes = bundle_capture_prefixes(bundle_path, {a["event_count"] for a in mine
                                                    if a.get("capture") and a["seq"] in comparable
                                                    and a["event_count"] <= count})
    with open_archive(bundle_path) as archive:
        manifest = read_manifest(archive)
    created = manifest.get("snapshot_at") if isinstance(manifest.get("snapshot_at"), str) else manifest.get("created_at")
    created_at = witness_moment(created) if isinstance(created, str) else None
    consistent, conflicts, later, anomalies, matched, beyond = 0, [], 0, [], [], []
    for anchor in mine:
        if (anchor["event_count"] or 0) > count:
            beyond.append(anchor)
            if created_at and witness_moment(anchor["at"]) < created_at:
                conflicts.append(anchor)
            else:
                later += 1
        elif anchor["status"] != "ok" and anchor["seq"] not in explained:
            anomalies.append(anchor)
        elif ("0" * 64 if anchor["event_count"] == 0 else hashes.get(anchor["event_count"])) == anchor["head_hash"]:
            capture = anchor.get("capture", {}).get("statement")
            prefix = prefixes.get(anchor["event_count"])
            if (capture and (not prefix or any(prefix[k] != capture[k] for k in ("counts", "last_message_at"))
                             or "keys" in capture and prefix["keys"] != capture["keys"])
                    or anchor.get("root") and (not prefix or prefix["root"] != anchor["root"])):
                conflicts.append(anchor)
            else:
                consistent += 1
                matched.append(anchor)
        else:
            conflicts.append(anchor)


    matching_sequences = {a["seq"] for a in matched}
    timeline = []
    for anchor in witness["anchors"]:
        if anchor["collector_fingerprint"] == key and anchor["status"] == "ok":
            if anchor["event_count"] > count:
                continue
            if anchor["seq"] not in matching_sequences:
                anchor = {**anchor, "status": "conflict"}
        timeline.append(anchor)
    periods, gaps = witnessed_periods({**witness, "anchors": timeline}, key)
    verified_through = max((a["event_count"] for a in matched), default=0)
    continuity_through = max((a["event_count"] for a in matched if a.get("root")), default=0)
    invalid = sum(1 for a in witness["anchors"] if a["status"] == "invalid")
    exact = [a for a in matched if a["event_count"] == count]
    fresh = [a for a in exact if a.get("freshness", {}).get("verified")]
    sealed_days = [d for d in witness.get("days", []) if d["bitcoin"] == "confirmed"
                   and any(a["seq"] <= d["to_seq"] for a in exact)]
    late = {a["seq"] for a in beyond if a["status"] != "ok"}
    problems = sorted(a["seq"] for a in witness["anchors"]
                      if a["status"] != "ok" and a["seq"] not in late and a["seq"] not in explained)
    days = []
    for day in witness.get("days", []):
        index = bisect.bisect_left(problems, day["from_seq"])
        if (late or explained) and day["status"] == "fail" and (index == len(problems) or problems[index] > day["to_seq"]):
            day = {**day, "status": "ok" if day["checks"].get("ok") else "no_response_only"}
        days.append(day)
    highest = max((a["event_count"] for a in beyond), default=None)
    return {"witness_fingerprint": witness["fingerprint"], "anchors_for_this_key": len(mine),
            "other_keys": len(witness["anchors"]) - len(mine) - invalid, "invalid_answers": invalid,
            "consistent": consistent, "conflicts": conflicts, "export_created_at": created,
            "after_export": later, "anomalies": anomalies, "no_response": len(witness["no_response"]),
            "seen_after_export": {"event_count": highest, "at": next(a["at"] for a in beyond if a["event_count"] == highest)}
            if beyond else None,
            "witnessed": periods, "witness_gaps": gaps,
            "verified_through_event": verified_through, "unwitnessed_events": count - verified_through,
            "continuity_verified_through_event": continuity_through,
            "export_head_witnessed": any(a["event_count"] == count for a in matched),
            "export_head_witness_records": [a["seq"] for a in matched if a["event_count"] == count],
            "witness_key_pinned": bool(witness.get("key_pinned")),
            "collector_keys": witness.get("collector_keys", {}).get(key),
            "days": days, "missing_days": witness.get("missing_days", []),
            "head_not_before": min((a["freshness"]["not_before"] for a in fresh), default=None),
            "head_bitcoin_block_time": min((d["bitcoin_block_time"] for d in sealed_days), default=None),
            "head_witnessed_at": min((a["at"] for a in exact), default=None),
            "head_witness_record": min((a["seq"] for a in exact), default=None)}


ASSURANCE_TIERS = ("self_attested", "timestamped", "witnessed", "fresh", "witness_anchored", "sealed")
EVIDENCE_PROFILES = ("integrity", "evidence", "attested")
CONDITION_LABELS = {"integrity": "Integrity", "signer": "Signer key", "external_time": "External time",
                    "head_binding": "Witness with its own key", "checkpoint": "Retained checkpoint",
                    "environment": "Attested collection run"}
CONDITION_ROLE = {"integrity": "required", "signer": "required", "external_time": "required",
                  "head_binding": "supporting", "checkpoint": "supporting", "environment": "supporting"}
ROLE_LABELS = {"required": "Required conditions", "supporting": "Supporting records, not part of the minimum"}
CONDITION_SCOPE = {"integrity": "The archive is unchanged since the collector signed it.",
                   "signer": "The signing key is the collector key the recipient retained.",
                   "external_time": "A third party confirms that the covered records existed by the stated time.",
                   "head_binding": "A second key retained the journal head. Who controls that key is a custody fact this verifier cannot check.",
                   "checkpoint": "Records up to the checkpoint match a journal state signed with the collector key. "
                                 "They are bound only if the recipient obtained it before this archive, through another channel.",
                   "environment": "The signing key was created inside the attested collection run."}
MINIMUM_NAMES = {"signer": "confirmed signer key", "external_time": "external time from a third party covering the last record"}


def assurance(result):
    witness = result.get("witness") or {}
    anchors = result.get("anchors") or []
    stamps = [a for a in anchors if a.get("event_count") == result.get("events") and (
        a.get("kind") == "rfc3161" and a.get("signature", "").startswith("checked against") or
        a.get("kind") == "opentimestamps" and a.get("status") == "confirmed")]
    times = [a["time"] for a in stamps]
    times += [witness[name] for name in ("head_bitcoin_block_time", "head_telegram_post_time") if witness.get(name)]
    independent = bool(witness.get("witness_key_pinned") and witness.get("export_head_witnessed")
                       and witness.get("witness_fingerprint") != result.get("fingerprint"))
    days = witness.get("days", result.get("days", []))
    missing = witness.get("missing_days", result.get("missing_days", []))
    bad_witness = bool(witness.get("conflicts") or witness.get("anomalies") or any(d["status"] == "fail" for d in days))
    complete_days = bool(days and not missing and all(d["bitcoin"] == "confirmed" for d in days)
                         and witness.get("head_bitcoin_block_time"))
    runtime = result.get("runtime_attestation") or {}
    tdx = tdx_condition(result["tdx"]) if result.get("tdx") else None
    ladder = [
        {"tier": "self_attested", "status": "pass", "detail": "signature, hashes and applicable chain/manifest checks"},
        {"tier": "timestamped", "status": "pass" if times else "absent",
         "detail": ("external timestamp covering the export head: " + min(times)
                    + "; Bitcoin dates are block-header times; TSA dates depend on the trusted authority")
                   if times else "no authenticated external time covering the export head"},
        {"tier": "witnessed", "status": "fail" if bad_witness else "pass" if independent else "absent",
         "detail": ("witness " + str(witness.get("witness_fingerprint")) + "; records 1.." + str(result.get("events"))
                    + "; witness clock " + str(witness.get("head_witnessed_at"))) if independent else "no pinned witness with its own key at the export head"},
        {"tier": "fresh", "status": "pass" if independent and witness.get("head_not_before") else "absent",
         "detail": "relay-confirmed drand challenge; not before " + str(witness.get("head_not_before"))
                   if witness.get("head_not_before") else "no independently checked drand binding for the export head"},
        {"tier": "witness_anchored", "status": "fail" if bad_witness else "pass" if independent and complete_days else "absent",
         "detail": "Bitcoin-confirmed daily seals: " + str(sum(d["bitcoin"] == "confirmed" for d in days))
                   + "; missing days: " + str(len(missing))},
        {"tier": "sealed", "status": "pass" if runtime.get("verified") is True and runtime.get("key_origin") == "created" else "absent",
         "detail": runtime.get("limitation") or (english(tdx[1], **tdx[2]) if tdx else
                                                 "no independently checked runtime attestation bound to this export and a created key")},
    ]
    tier = "self_attested"
    for row in ladder:
        if row["status"] != "pass":
            break
        tier = row["tier"]
    return {"tier": tier, "ladder": ladder, "scope": "complete exported head; no claim of continuous or complete Telegram observation"}


def assurance_line(result):
    value = result["assurance"]
    if value["tier"] == "self_attested":
        return "ASSURANCE: self_attested · signatures, hashes and record chain"
    witness = result.get("witness") or {}
    detail = (" since #" + str(witness["head_witness_record"]) + " (" + str(witness["head_witnessed_at"]) + ")"
              if witness.get("head_witness_record") else "")
    absent = {row["tier"] for row in value["ladder"] if row["status"] != "pass"}
    limits = [text for tier, text in (("fresh", "not fresh"), ("witness_anchored", "witness not anchored"),
                                    ("sealed", "not sealed")) if tier in absent]
    return "ASSURANCE: " + value["tier"] + detail + (" · " + " · ".join(limits) if limits else "")


def forgery_lines(result):
    lines, anchors = [], result.get("anchors") or []
    tsa = [a for a in anchors if a.get("kind") == "rfc3161" and a.get("time")
           and str(a.get("signature", "")).startswith("checked against")]
    if tsa:
        top = max(a["event_count"] for a in tsa)
        names = sorted({(a.get("qualified") or {}).get("service") or str(a.get("service")) for a in tsa if a["event_count"] == top})
        lines.append("Records 1-" + str(top) + " existed by " + min(a["time"] for a in tsa if a["event_count"] == top)
                     + ": changing them needs a new time stamp signed by " + ", ".join(names) + ".")
    ots = [a for a in anchors if a.get("kind") == "opentimestamps" and a.get("status") == "confirmed" and a.get("blocks")]
    if ots:
        top = max(a["event_count"] for a in ots)
        block = min((b for a in ots if a["event_count"] == top for b in a["blocks"]), key=lambda b: b["height"])
        lines.append("Records 1-" + str(top) + " are committed in Bitcoin block " + str(block["height"]) + " ("
                     + str(block["time"]) + "): changing them means rewriting Bitcoin from that block.")
    ladder = {row["tier"]: row for row in (result.get("assurance") or {}).get("ladder", [])}
    if ladder.get("witnessed", {}).get("status") == "pass":
        lines.append("A separate witness key retained the head (" + ladder["witnessed"]["detail"]
                     + "): changing those records also needs that key.")
    if ladder.get("sealed", {}).get("status") == "pass":
        lines.append("The collector key was created inside an attested Intel TDX VM: signing elsewhere needs a break of Intel TDX.")
    if not lines:
        lines.append("Only the collector key binds this journal: its holder could produce a different journal from the start. "
                     "External time or a witness ties it to a moment.")
    cp = result.get("checkpoint_drand_anchor") or {}
    if isinstance(cp.get("round"), int):
        lines.append("The checkpoint at record " + str(result.get("checkpoint_event_count")) + " was signed no earlier than "
                     + drand_time(cp["round"]) + " (drand round " + str(cp["round"]) + ", "
                     + ("confirmed by relays" if cp.get("confirmed_by_relays") else "run with --check-drand to confirm") + ").")
    return ["Any change to a record breaks the hash chain and the Ed25519 signatures."] + lines


def english(text, **values):
    for name, value in values.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def tdx_condition(tdx):
    failed = next((q for q in tdx["quotes"] if q["status"] != "pass"), None)
    if failed:
        return "missing", "Intel TDX check failed: {detail}", {"detail": (
            "record " + str(failed["record"]) + ": " if "record" in failed else "") + failed["detail"]
            + (" (" + failed["error"] + ")" if failed.get("error") else "")}
    return ("partial", "{count} Intel TDX quote(s) verified offline and bound to the collector key; the code the VM ran "
                       "is not checked here", {"count": len(tdx["quotes"])})


def condition(cid, status, how, text, **values):
    return {"id": cid, "role": CONDITION_ROLE[cid], "status": status, "scope": CONDITION_SCOPE[cid], "how": how,
            "detail": english(text, **values), "text": text, "values": values}


def evidence_conditions(result, kind="evidence"):
    events, fp = result.get("events"), result.get("fingerprint") or ""
    witness, anchors = result.get("witness") or {}, result.get("anchors") or []
    journal = kind == "evidence"
    integrity = (("{records} records, {files} files", {"records": events, "files": result.get("files_checked")})
                 if events is not None and result.get("files_checked") is not None else ("signature and content hashes", {}))
    rows = [condition("integrity", "met", "record signatures, hash chain, manifest and file hashes", integrity[0], **integrity[1]),
            condition("signer", "met" if result.get("key_pinned") else "missing",
                      "--fingerprint with the collector fingerprint the recipient retained",
                      "collector {fingerprint}… matches the fingerprint you supplied" if result.get("key_pinned")
                      else "collector {fingerprint}… not compared with a retained fingerprint", fingerprint=fp[:16])]
    checked = [a for a in anchors if a.get("kind") == "rfc3161" and str(a.get("signature", "")).startswith("checked against")
               or a.get("kind") == "opentimestamps" and a.get("status") == "confirmed"]
    times = [a["time"] for a in checked if a.get("event_count") == events and a.get("time")]
    if witness.get("export_head_witnessed") and not witness.get("conflicts"):
        times += [witness[name] for name in ("head_bitcoin_block_time", "head_telegram_post_time") if witness.get(name)]
    runtime = result.get("runtime_attestation") or {}
    attested = runtime.get("verified") is True and runtime.get("key_origin") == "created"
    if attested and runtime.get("attested_at"):
        times.append(runtime["attested_at"])
    unchecked = [a for a in anchors if a not in checked]
    stamped = max((a.get("event_count") or 0 for a in checked), default=0)
    qualified = next((a["qualified"] for a in checked if a.get("event_count") == events and a.get("qualified")), None)
    if times and qualified:
        status, text, values = ("met", "last exported record existed by {time}; qualified eIDAS time stamp from {service}",
                                {"time": min(times), "service": qualified["service"]})
    elif times:
        status, text, values = "met", "last exported record existed by {time}", {"time": min(times)}
    elif checked:
        status, text, values = "partial", "records 1–{through} existed by {time}", {
            "through": stamped, "time": min(a.get("time") or "?" for a in checked if (a.get("event_count") or 0) == stamped)}
    elif unchecked:
        status, text, values = ("unchecked", "{count} timestamp proof(s) present; check them with --tsa-ca or --check-bitcoin",
                                {"count": len(unchecked)})
    else:
        status, text, values = "missing", "no external timestamp in this archive", {}
    rows.append(condition("external_time", status,
                          "RFC 3161 with --tsa-ca, OpenTimestamps with --check-bitcoin, a witness post read from t.me with --channel, "
                          "witness Bitcoin seals or a checked GitHub attestation"
                          if journal else "in the evidence journal ZIP: --tsa-ca or --check-bitcoin", text, **values))
    drand = ((result.get("outside") or {}).get("drand") or {}).get("checked") or {}
    if drand.get("confirmed"):
        rows[-1]["drand"] = ", ".join(drand.get("relays") or [])
        rows[-1]["detail"] += " · drand rounds confirmed by " + rows[-1]["drand"]
    own_key = bool(witness.get("witness_key_pinned") and witness.get("witness_fingerprint") not in (None, fp)
                   and not witness.get("conflicts"))
    through = (witness.get("verified_through_event") or 0) if own_key else 0
    if journal and through:
        text, values = "records 1–{through} of {total} retained by a witness with its own key", {"through": through, "total": events}
    elif journal:
        text, values = "no witness with its own key", {}
    else:
        text, values = "this archive type carries no journal checkpoints; verify the evidence journal", {}
    rows.append(condition("head_binding", "met" if journal and own_key and witness.get("export_head_witnessed")
                          else "partial" if journal and through else "missing",
                          "--witness with --witness-fingerprint of a key other than the collector key" if journal
                          else "in the evidence journal ZIP: --witness with --witness-fingerprint", text, **values))
    if journal:
        retained = result.get("checkpoint_event_count")
        rows.append(condition("checkpoint", "met" if retained and retained == events else "partial" if retained else "missing",
                              "--checkpoint received before this archive, through another channel",
                              "records 1–{through} of {total} match the checkpoint you supplied" if retained
                              else "no checkpoint supplied", **({"through": retained, "total": events} if retained else {})))
    if result.get("tdx") and not attested:
        status, text, values = tdx_condition(result["tdx"])
        rows.append(condition("environment", status, "compose and OS image: python -m tgwitness.cloud verify", text, **values))
    else:
        rows.append(condition("environment", "met" if attested else "missing",
                              "--sealed-attestation with --sealed-policy for a GitHub Actions run; Intel TDX: python -m tgwitness.cloud verify"
                              if journal else "in the evidence journal ZIP: --sealed-attestation with --sealed-policy",
                              "collection ran in the attested workflow {workflow}" if attested
                              else "no attested collection run checked here",
                              **({"workflow": runtime.get("workflow")} if attested else {})))
    met = {row["id"] for row in rows if row["status"] == "met"}
    missing = [item for item in ("signer", "external_time") if item not in met]
    minimum = not missing
    bound = events if minimum else stamped
    options = [] if "signer" in met else ["--fingerprint FINGERPRINT"]
    if journal and "external_time" in missing:
        options += sorted({"--tsa-ca TSA-ROOT.pem" if a.get("kind") == "rfc3161" else "--check-bitcoin" for a in unchecked
                           if a.get("event_count") == events and (a.get("kind") == "rfc3161" or a.get("status") == "bitcoin-unverified")}) \
            or ["--witness WITNESS.zip", "--channel https://t.me/s/WITNESS_CHANNEL"]
    return {"profile": "attested" if minimum and "environment" in met else "evidence" if minimum else "integrity",
            "minimum_met": minimum, "missing": missing, "records": events,
            "bound_through": bound if "signer" in met else 0, "conditions": rows,
            "next_options": options, "journal_needed": not journal and "external_time" in missing,
            "minimum": "integrity, confirmed signer key, and external time from a third party covering the last exported "
                       "record: RFC 3161, Bitcoin, a witness post read from t.me or an attested collection run"}


def next_lines(evidence, t=None):
    t = t or english
    lines = [t("Next step: run verify.py again with {options}", options=" ".join(evidence["next_options"]))] \
        if evidence.get("next_options") else []
    if evidence.get("journal_needed"):
        lines.append(t("This archive type carries no checkpoints or timestamps: the last record is bound in the evidence "
                       "journal of the same workspace. Verify that ZIP with --fingerprint and --tsa-ca, --check-bitcoin "
                       "or --witness with --channel."))
    return lines


def evidence_line(evidence, t=None):
    t = t or english
    if evidence["minimum_met"]:
        return t("EVIDENCE: minimum met · profile {profile}", profile=evidence["profile"])
    if evidence.get("bound_through"):
        return t("EVIDENCE: minimum met up to record {through} of {total} · later records need a binding",
                 through=evidence["bound_through"], total=evidence.get("records"))
    return t("EVIDENCE: minimum not met · missing: {items}",
             items="; ".join(t(MINIMUM_NAMES.get(item, item)) for item in evidence["missing"]))


def requested_checks_unavailable(args, result):
    missing = []
    witness = result.get("witness") or {}
    if getattr(args, "check_drand", False):
        drand = ((result.get("outside") or {}).get("drand") or {}).get("checked") or {}
        if drand.get("unavailable") or (result.get("freshness") or {}).get("unavailable") \
                or (witness.get("freshness") or {}).get("unavailable"):
            missing.append("--check-drand: no drand relay answered")
    if getattr(args, "check_bitcoin", False):
        proofs = [a for a in result.get("anchors") or [] if a.get("kind") == "opentimestamps"]
        proofs += [p for d in (witness.get("days") or result.get("days") or []) for p in d.get("proofs", [])]
        if any(p.get("check") == "unavailable" for p in proofs):
            missing.append("--check-bitcoin: Bitcoin header sources unreachable")
    return missing


def channel_texts(source):
    source = str(source)
    if source.startswith(("http://", "https://")):
        import urllib.parse
        import urllib.request
        posts, before = [], None
        for _ in range(200):
            url = source + (("&" if "?" in source else "?") + "before=" + str(before) if before else "")
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "TgWitness-verify",
                                                                             "Accept-Language": "en"}),
                                        timeout=30) as response:
                live = all(telegram_page(address) for address in (url, response.geturl()))
                page = response.read(MAX_SMALL_MEMBER_BYTES).decode("utf-8", "replace")
            ids = [int(n) for n in re.findall(r'data-post="[^"/]+/(\d+)"', page)]
            for block in re.split(r'data-post="', page)[1:]:
                number, text, meta = CHANNEL_POST.match(block), CHANNEL_TEXT.search(block), CHANNEL_META.search(block)
                stamp = CHANNEL_TIME.search(meta.group(1)) if live and meta else None
                posts.append((int(number.group(1)) if number else None, stamp.group(1) if stamp else None,
                              (text.group(1) if text else "") if live else block,
                              ("edited" if post_edited(meta.group(1)) else "telegram") if stamp else None))
            if not ids or (before is not None and min(ids) >= before):
                break
            before = min(ids)
        return posts
    if Path(source).stat().st_size > MAX_JSON_BYTES:
        raise ValueError(Path(source).name + " exceeds the verifier's size limit")
    text = Path(source).read_text(encoding="utf-8", errors="replace")
    if source.lower().endswith(".json"):
        data = json.loads(text)
        found = []
        for message in data.get("messages", []):
            body = message.get("text", "")
            if isinstance(body, list):
                body = "".join(part if isinstance(part, str) else part.get("text", "") for part in body)
            found.append((message.get("id"), message.get("date"), body, "supplied"))
        return found
    return [(None, None, text, None)]


def check_channel(witness, source):
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(witness["public_key"], validate=True))
    matching, invalid, differing, foreign, dates, live, edited = set(), [], [], 0, {}, {}, set()
    for message_id, date, text, origin in channel_texts(source):
        for body, signature in WITNESS_TOKEN.findall(text):
            try:
                raw = unb64url(body)
                key.verify(unb64url(signature), raw)
                statement = json.loads(raw)
            except Exception:
                invalid.append(message_id)
                continue
            if statement.get("witness") != witness["fingerprint"]:
                foreign += 1
                continue
            expected = witness["statements"].get(statement.get("seq"))
            if expected != statement:
                differing.append(statement.get("seq"))
            else:
                matching.add(statement["seq"])
                if origin == "edited":
                    edited.add(statement["seq"])
                elif date:
                    dates[statement["seq"]] = date
                    moment = telegram_time(date) if origin == "telegram" else None
                    if moment:
                        live[statement["seq"]] = min(live.get(statement["seq"]) or "~", moment)
    posted = set(witness["posted"])
    return {"matching": len(matching), "matching_records": sorted(matching),
            "invalid_signatures": invalid, "differ_from_journal": differing,
            "other_witnesses": foreign,
            "posted_but_not_found": sorted(posted - matching),
            "never_posted": sorted(set(witness["statements"]) - posted),
            "telegram_post_dates": dates, "telegram_live_dates": live, "edited_posts": sorted(edited),
            "post_date_verification": "read-from-telegram" if live else "supplied" if dates else "not-performed"}


def post_edited(meta):
    head = re.sub(r'<span class="tgme_widget_message_from_author".*?</span>', "",
                  meta.split('<a class="tgme_widget_message_date"')[0], flags=re.S)
    return bool(re.sub(r"<[^>]+>|&nbsp;|[\s,]", "", head))


def telegram_page(address):
    import urllib.parse
    parts = urllib.parse.urlsplit(address)
    return parts.scheme == "https" and parts.hostname in TELEGRAM_PAGES and parts.path.startswith("/s/")


def telegram_time(value):
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return moment.astimezone(timezone.utc).isoformat() if moment.tzinfo else None


def channel_head_time(witnessed, check):
    live = (check or {}).get("telegram_live_dates") or {}
    floor = witnessed.get("head_not_before")
    return min((live[seq] for seq in witnessed.get("export_head_witness_records") or []
                if seq in live and not (floor and witness_moment(live[seq]) < witness_moment(floor))), default=None)


def verify_dossier(path, expected_fingerprint=None, bundle=None):
    value = read_json_file(path)
    statement = authenticate_statement(value)
    if not is_format(statement.get("format"), "dossier-v1"):
        raise VerifierTooOld("Unsupported profile format")
    fp = fingerprint(statement["public_key"])
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(statement["public_key"], validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    result = {"format": statement["format"], "fingerprint": fp, "chat": statement.get("chat"),
              "people": len(statement.get("people", [])), "built_at": statement.get("built_at"),
              "producer": statement.get("producer"), "key_pinned": bool(expected_fingerprint), "records_checked": 0}
    if bundle:
        with open_archive(bundle) as archive:
            if read_manifest(archive)["public_key"] != statement["public_key"]:
                raise ValueError("The evidence export was signed by another workspace key")
        verify_bundle(bundle, fp)
        wanted = {int(seq): digest for seq, digest in statement.get("record_hashes", {}).items()}
        found = bundle_hashes(bundle, wanted)
        for seq, digest in wanted.items():
            if found.get(seq) != digest:
                raise ValueError("Profile fact refers to record " + str(seq) + ", which the export does not contain")
        result["records_checked"] = len(wanted)
    return result


def verify_public_proof(path, collector_fingerprint=None, witness_fingerprint=None, bundle=None):
    value = read_json_file(path)
    statement = authenticate_statement(value, "witness_public_key")
    if not is_format(statement.get("format"), "public-proof-v1"):
        raise VerifierTooOld("Unsupported public proof")
    public = statement["witness_public_key"]
    fp = fingerprint(public)
    if witness_fingerprint and fp != witness_fingerprint:
        raise ValueError("Public proof witness differs from the trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    pin = statement["collector_fingerprint"]
    if collector_fingerprint and pin != collector_fingerprint:
        raise ValueError("Public proof collector differs from the trusted fingerprint")
    capture, checkpoint = statement.get("capture"), statement.get("checkpoint")
    result = {"format": statement["format"], "alias": statement["alias"], "observed_at": statement["observed_at"],
              "status": statement["status"], "collector_fingerprint": pin, "witness_fingerprint": fp,
              "keys_pinned": bool(collector_fingerprint and witness_fingerprint),
              "capture_signature_verified": False, "evidence_counters_checked": False}
    if capture is not None:
        captured = verify_capture(capture, checkpoint["statement"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(captured["public_key"], validate=True)).verify(
            base64.b64decode(checkpoint["signature"], validate=True), canonical(checkpoint["statement"]))
        if statement["status"] == "ok" and fingerprint(captured["public_key"]) != pin:
            raise ValueError("Capture proof was signed by another collector")
        result.update(capture_signature_verified=True, counts=captured["counts"], event_count=captured["event_count"],
                      head_hash=captured["head_hash"], last_message_at=captured.get("last_message_at"))
        if bundle:
            verify_bundle(bundle, pin)
            check_capture_prefix(capture, bundle)
            result["evidence_counters_checked"] = True
    elif statement["status"] == "ok" or bundle:
        raise ValueError("Proof contains no signed capture counters")
    return result


def verify_history_report(path, expected_fingerprint=None, bundle=None):
    value = read_json_file(path)
    statement = authenticate_statement(value)
    if not is_format(statement.get("format"), "history-report-v1"):
        raise VerifierTooOld("Unsupported history progress report")
    public = statement["public_key"]
    fp = fingerprint(public)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    sources = statement["sources"]
    ids = [s["chat_id"] for s in sources]
    if (any(type(cid) is not int for cid in ids) or len(set(ids)) != len(ids)
            or type(statement["sources_total"]) is not int or len(ids) != statement["sources_total"]):
        raise ValueError("History report source list is inconsistent")
    for key in ("captured", "unavailable"):
        if (type(statement[key]) is not int or any(type(s[key]) is not int or s[key] < 0 for s in sources)
                or sum(s[key] for s in sources) != statement[key]):
            raise ValueError("History report counts are inconsistent")
    checkpoint = statement["checkpoint"]
    boundary = checkpoint["statement"]["event_count"]
    if type(boundary) is not int or boundary < 0:
        raise ValueError("Invalid history report checkpoint")
    verify_checkpoint(checkpoint, public, boundary, lambda seq: checkpoint["statement"]["head_hash"])
    checked = False
    if bundle:
        verify_bundle(bundle, fp, checkpoint)
        counts = {cid: {"captured": 0, "unavailable": 0} for cid in ids}
        observed_sources = None
        cursors, cursor_format = {}, None
        with open_archive(bundle) as archive, archive.open("events.jsonl") as stream:
            for line in bounded_lines(stream):
                event = json.loads(line)
                if event["seq"] > boundary:
                    break
                payload = event["payload"]
                if payload.get("history_run_id") != statement["id"]:
                    continue
                if event["kind"] == "history.started":
                    observed_sources = payload["sources"]
                    cursor_format = payload.get("cursor_format")
                    if payload["account_id"] != statement["account_id"]:
                        raise ValueError("History report account differs from the journal")
                    if cursor_format and payload["options"] != statement.get("options"):
                        raise ValueError("History report options differ from the journal")
                elif event["kind"] == "history.cursor":
                    cursors[event["chat_id"]] = event
                elif event["kind"] in ("message.snapshot", "history.message.unavailable"):
                    if event["chat_id"] not in counts:
                        raise ValueError("History report omits an acquired source")
                    key = "captured" if event["kind"] == "message.snapshot" else "unavailable"
                    counts[event["chat_id"]][key] += 1
        if observed_sources is None or set(observed_sources) != set(ids):
            raise ValueError("History report source plan differs from the journal")
        if any(counts[s["chat_id"]] != {key: s[key] for key in ("captured", "unavailable")} for s in sources):
            raise ValueError("History report counts differ from the journal")
        if cursor_format:
            for source in sources:
                cursor = cursors.get(source["chat_id"])
                state = {key: source[key] for key in ("run_id", "chat_id", "title", "position", "phase",
                    "upper_id", "offset_id", "captured", "unavailable", "error", "metadata")}
                state["metadata"] = json.loads(state["metadata"])
                if (cursor is None or source.get("cursor_seq") != cursor["seq"]
                        or source.get("cursor_hash") != cursor["hash"]
                        or canonical(state) != canonical(cursor["payload"]["state"])):
                    raise ValueError("History report cursor differs from the journal")
        checked = True
    return {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "history_run_id": statement["id"], "phase": statement["phase"], "captured": statement["captured"],
            "unavailable": statement["unavailable"], "sources_total": statement["sources_total"],
            "evidence_counts_checked": checked, "checkpoint_event_count": boundary,
            "limitation": "Journal comparison checks the source plan, account, message counters and available signed cursors. "
                          "Other progress fields are retained as signed collector statements. Review source attribution "
                          "and coverage with the acquisition record."}


def producer_line(producer):
    if not producer:
        return "Producer: not named in this (older) archive."
    return ("Producer (signed): " + str(producer.get("software")) + " " + str(producer.get("version")) + " - "
            + str(producer.get("project")) + " - " + str(producer.get("homepage"))
            + (" - commit " + str(producer["commit"]) if producer.get("commit") else "")
            + (" - source files SHA-256 " + str(producer["source_tree_sha256"]) if producer.get("source_tree_sha256") else ""))


def fingerprint_colors(value):
    data = bytes.fromhex(value)
    return [(data[i] * 360 // 256, 68, 40 + data[i + 1] % 24) for i in range(0, 32, 2)]


# BEGIN GENERATED VERIFIER LANGUAGES
# Catalogue SHA-256: 4adc02d2d5afcf6a8756e7cdfcd1587ed0348a2782afd25eb511b5bc107831c4
VERIFIER_LANGUAGE_DATA = (
    "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"
    "i/828utf/9eoxvX8pY9n5qZLm3/mw4+D+EkS2yfXYumGxGQIROmw4AhwVSLfD+LvsSelW94Spw5du6tCTi3pc3ddUiNbBP/xrrCOQXAF+nHpkYo9"
    "d2neGBvOQCnOnnvhrXPv/vblt14emfvjXFGXvBgpZL899/prTa98ntpd4xdpEEZIUyJ4spQMcC+SvurR77bsxGEyR1InenrUVYVBeiM0URwtqqbv"
    "fPCWANaFSjvZ6Tuzm7HZPbU9HQ4OAjJ5t8tDqYvgTK5D2V7kBKd0XdfEMWTTM3LVbl0TgA+aZYSRM9zH98YvvCvrshvyrXhir4potqBiP4gveaH4"
    "x38oTA2OqxPRspRczvGCaU8cm52mrga2sIvvJAPzms3ygfkTNH0Y582z0jBiaGt+4wgbLGlLUlFapg+TpaXkJYOK+GxLV+ka3LS5nM56FBE4yJ6o"
    "a3NTnREZsM5kT7aQy+a0YHWABLAUofgM+uVZD3ACrMw47K6JmUlOva50rZPjSJOR46jAwGtPI2KKQewgbnlMh6izxFAHL8PeaoMHMX7x/MTUlJMi"
    "C0K4P4ijSLen5iBjERT3a010B5qen5vhbts6+wep/DKXDsia9fClidn5qbnhv2PBo4lWVew+SproFP/+vPZ8HbZhidnnLQexUnJDNCnrK7fpVGbj"
    "Tfpnydnena/rfZ9IKci2SJqBNsCisLYK5NGKbKWEx+4tTMaanKtoGjU1+YfJudl3q54q/n60lhDqanC88hpDYL9hQJnqMjOTWesFwLL5NZeooK1I"
    "teyqK9Ty2WozRub0TUmerkobrajIl0v/6/otTyPXTEjr8L7zVq1CXnOFDXMi0cVnuyq7JlK2rzCyl57QVCiBEnjh34CjXahH+8l3HR0tjpPFX3i5"
    "WkaxyAGr3RZunYPWk510Opv1Ct627ogaEDUCKy3vxIcTUzMps8zk3UWGFSTWnT37WuEFgP2Mpkqz2cO++r5a3wRdZW784oXxqemLE9JXW3V0Yzqz"
    "tWeSHFWfPZZBVz29fDJq0zMsnGmR0ejYsfS87d6fWpLzkRv5l7Ps1aL2HqgcP0zJZ9e79J1+d/KiiyBYlT1Zih4oqSpdHOyN0V4SOLqlFTo7Z5B7"
    "vhigw/uJHF5Gx3SVeNtSd04ybhO5xIKEA6/7qeN/FjzYtvF/mKMNJXogYR8g3XTp3rwPzsOgpyGbi++W3HHyvLaNbJJNnAMbyxl8tcnhzfc4kV1o"
    "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"
    "5ZvRsVca+7fQUXzlyv8DX6SJyQ=="
)
# END GENERATED VERIFIER LANGUAGES
import zlib
VERIFIER_LANGUAGES = json.loads(zlib.decompress(base64.b64decode(VERIFIER_LANGUAGE_DATA)))
SAY = {code: entry["words"] for code, entry in VERIFIER_LANGUAGES.items()}


WINDOW_WORDS = {"updates_diverted": "Updates went to another session",
                "session_revoked_externally": "Session revoked externally"}
KINDS = {"evidence": "Evidence archive", "chat": "Chat export", "account": "Account export",
         "account_disclosure": "Account disclosure", "witness": "Witness journal",
         "dossier": "People profiles", "proof": "Public proof", "report": "Sealed report",
         "history": "History report", "handover": "Handover extract", "selection": "Viewer selection",
         "distributed": "Distributed acquisition", "board": "Case Board", "attestation": "Collector attestation"}


def verifier_language(value):
    value = (value or "").strip().lower().replace("_", "-").split(".")[0]
    known = {code.lower(): code for code in VERIFIER_LANGUAGES}
    if value in known:
        return known[value]
    if value.startswith("zh-") and any(part in ("hant", "tw", "hk", "mo") for part in value.split("-")[1:]):
        return "zh-Hant"
    windows = dict(zip(("english", "russian", "ukrainian", "spanish", "portuguese", "turkish", "arabic", "persian",
                        "urdu", "hindi", "indonesian", "vietnamese", "chinese", "french", "german", "italian",
                        "uzbek", "korean", "chinese (traditional)", "malay", "polish", "japanese", "thai", "hebrew", "bengali"),
                       VERIFIER_LANGUAGES))
    base = value.split("-")[0]
    return known.get(base) or windows.get(base)


def console_language(choice=None):
    if choice and choice != "auto":
        selected = verifier_language(choice)
        if selected is None:
            raise ValueError("Unsupported verifier language: " + str(choice))
        return selected
    value = next((os.environ[name] for name in ("LC_ALL", "LC_MESSAGES", "LANG") if os.environ.get(name)), "")
    if not value:
        import locale
        value = locale.getlocale()[0] or ""
    return verifier_language(value) or "en"


def choose_verifier_language(default):
    codes = tuple(VERIFIER_LANGUAGES)
    print("\n" + " / ".join(VERIFIER_LANGUAGES[c]["words"]["Language"] for c in ("en", "ru", "zh", "ar")))
    for index, code in enumerate(codes, 1):
        print(str(index).rjust(2) + ". " + VERIFIER_LANGUAGES[code]["name"] + " [" + code + "]")
    while True:
        entered = input("[" + VERIFIER_LANGUAGES[default]["name"] + "] > ").strip()
        if not entered:
            return default
        if entered.isascii() and entered.isdigit() and 1 <= int(entered) <= len(codes):
            return codes[int(entered) - 1]
        selected = verifier_language(entered)
        if selected:
            return selected
        print(reader_message("language_invalid", default))


def enable_ansi(stream):
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt
        kernel = ctypes.windll.kernel32
        handle, mode = msvcrt.get_osfhandle(stream.fileno()), ctypes.c_uint32()
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode))
                    and kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def reader_message(key, lang):
    return VERIFIER_LANGUAGES[lang]["reader"][key]


class Console:
    WIDTH = 66
    STYLES = {"ok": "1;32", "bad": "1;31", "warn": "1;33", "dim": "2", "bold": "1", "accent": "1;38;5;75",
              "okbar": "1;97;42", "badbar": "1;97;41", "warnbar": "1;30;43"}

    def __init__(self, stream, lang="en", color=True, explain=False):
        self.stream, self.words, self.lang = stream, SAY[lang], lang
        self.explain_enabled = explain
        try:
            "✔✘⚠◷•─│╭╮╰╯█⠋".encode(stream.encoding or "ascii")
            self.glyph = dict(ok="✔", bad="✘", warn="!", wait="◷", dot="•", h="─", v="│", tl="╭", tr="╮",
                              bl="╰", br="╯", block="██", spin="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        except (LookupError, UnicodeEncodeError):
            self.glyph = dict(ok="+", bad="x", warn="!", wait="~", dot="*", h="-", v="|", tl="+", tr="+",
                              bl="+", br="+", block="##", spin="|/-\\")
        self.color = color and enable_ansi(stream)

    def t(self, text, **values):
        text = self.words.get(text, text)
        for name, value in values.items():
            text = text.replace("{" + name + "}", str(value))
        return text

    def paint(self, text, style):
        text = safe_text(text)
        if not self.color or not style:
            return text
        if not hasattr(self, "_paints"):
            self._paints = {}
        token = "TGWSTYLE" + os.urandom(16).hex()
        self._paints[token + "B"] = "\033[" + self.STYLES[style] + "m"
        self._paints[token + "E"] = "\033[0m"
        return token + "B" + text + token + "E"

    def say(self, text=""):
        text = safe_text(text)
        for token, sequence in getattr(self, "_paints", {}).items():
            text = text.replace(token, sequence)
        self.stream.write(text + "\n")

    def number(self, value):
        return format(value, ",").replace(",", " " if self.lang != "en" else ",") if type(value) is int else str(value)

    def banner(self, title=None, tagline=None):
        g, inner = self.glyph, self.WIDTH - 4
        title, brand = title or self.t("TgWitness verifier"), "PhishDestroy"
        tagline = tagline or self.t("Signed Telegram evidence · Ed25519 · SHA-256")
        self.say()
        self.say("  " + self.paint(g["tl"] + g["h"] * inner + g["tr"], "accent"))
        self.say("  " + self.paint(g["v"], "accent") + "  " + self.paint(title, "bold")
                 + " " * max(1, inner - 4 - len(title) - len(brand)) + self.paint(brand, "dim") + "  "
                 + self.paint(g["v"], "accent"))
        self.say("  " + self.paint(g["v"], "accent") + "  " + self.paint(tagline[:inner - 4], "dim")
                 + " " * max(0, inner - 2 - len(tagline[:inner - 4])) + self.paint(g["v"], "accent"))
        self.say("  " + self.paint(g["bl"] + g["h"] * inner + g["br"], "accent"))
        self.say()

    def field(self, label, value):
        self.say("  " + self.paint(self.t(label).ljust(10), "dim") + " " + value)

    def heading(self, label):
        text = self.t(label).upper()
        self.say()
        self.say("  " + self.paint(text, "accent") + " " + self.paint(self.glyph["h"] * (self.WIDTH - 3 - len(text)), "dim"))

    def check(self, state, label, detail=""):
        mark = {"ok": ("ok", "ok"), "bad": ("bad", "bad"), "warn": ("warn", "warn"), "wait": ("wait", "warn"),
                "none": ("dot", "dim")}[state]
        detail = self.t(detail)
        self.say("  " + self.paint(self.glyph[mark[0]], mark[1]) + " " + self.t(label))
        if detail:
            self.say("    " + (self.paint(detail, "dim") if state == "none" else detail))
        if state != "none":
            self.explain(label)

    def explain(self, label):
        meanings = VERIFIER_LANGUAGES[self.lang]["explain"]
        if self.explain_enabled and label in meanings:
            import textwrap
            lines = ([meanings[label]] if self.lang in ("zh", "zh-Hant", "ja", "th", "hi", "bn", "ar", "fa", "ur", "he")
                     else textwrap.wrap(meanings[label], self.WIDTH - 4))
            for line in lines:
                self.say("    " + self.paint(line, "dim"))

    def signer(self, value):
        if not value:
            return
        groups = [value[i:i + 4] for i in range(0, 64, 4)]
        self.field("Signer", self.paint(" ".join(groups[:8]), "bold"))
        self.say("  " + " " * 11 + self.paint(" ".join(groups[8:]), "bold"))
        if self.color:
            import colorsys
            blocks = ""
            for hue, saturation, lightness in fingerprint_colors(value):
                r, g, b = colorsys.hls_to_rgb(hue / 360, lightness / 100, saturation / 100)
                code = 16 + 36 * round(r * 5) + 6 * round(g * 5) + round(b * 5)
                blocks += "\033[38;5;" + str(code) + "m" + self.glyph["block"]
            self.say("  " + " " * 11 + blocks + "\033[0m")

    def verdict(self, ok, reason="", evidence=None):
        evidence = evidence or {}
        state = "bad" if not ok else "ok" if evidence.get("minimum_met") else "warn"
        if not ok:
            label = self.t("VERIFICATION FAILED")
        elif evidence.get("minimum_met"):
            label = self.t("MINIMUM FOR EVIDENCE MET · ATTESTED COLLECTION RUN" if evidence["profile"] == "attested"
                           else "MINIMUM FOR EVIDENCE MET")
        elif evidence.get("bound_through"):
            label = self.t("MINIMUM MET UP TO RECORD {through} OF {total}", through=self.number(evidence["bound_through"]),
                           total=self.number(evidence["records"]))
        else:
            label = self.t("INTEGRITY ONLY · MINIMUM FOR EVIDENCE NOT MET")
        text = " " + self.glyph[state] + "  " + label + " "
        width = sum(0 if unicodedata.category(c) in ("Mn", "Me", "Cf") else 2 if unicodedata.east_asian_width(c) in "WF" else 1
                    for c in text)
        inner = max(self.WIDTH - 4, width)
        self.say()
        if self.color:
            self.say("  " + self.paint(text + " " * (inner + 2 - width), state + "bar"))
        else:
            self.say("  " + self.glyph["tl"] + self.glyph["h"] * inner + self.glyph["tr"])
            self.say("  " + self.glyph["v"] + text + " " * (inner - width) + self.glyph["v"])
            self.say("  " + self.glyph["bl"] + self.glyph["h"] * inner + self.glyph["br"])
        if reason:
            self.say("  " + self.paint(reason, "bad"))

    def spinner(self):
        return Spinner(sys.stderr, self.t("Checking signatures, hashes and the record chain"), self.glyph["spin"])

    def failure(self, path, exc):
        self.field("File", safe_text(path))
        message = safe_text(exc)
        label = ("Key mismatch" if "fingerprint" in message.lower() else
                 "File changed" if "File hash mismatch" in message or "ZIP changed during" in message else
                 "Signature mismatch" if isinstance(exc, InvalidSignature) else None)
        self.verdict(False, self.t(label) if label else reader_message("error", self.lang))
        self.field("Technical details", type(exc).__name__ + ": " + message)
        self.say()

    def case(self, case):
        shown = [(label, case.get(key)) for label, key in (("Title", "title"), ("Case ID", "id"),
                 ("Examiner", "examiner"), ("Organization", "organization")) if case.get(key)]
        if shown:
            self.heading("Case")
            for label, value in shown:
                self.say("  " + self.paint(self.t(label).ljust(14), "dim") + " " + str(value))

    def seal(self, result, name):
        seal = result.get("report_seal")
        if seal:
            self.check("ok", "Report seal", self.t("{name} · intact · language {lang}", name=name, lang=seal["language"]))
        else:
            self.check("none", "Report seal", self.t("not present (older export)"))
        if result.get("sha256sums"):
            self.check("ok", "SHA256SUMS", self.t("matches the signed manifest"))
        else:
            self.check("none", "SHA256SUMS", self.t("not present (older export)"))

    def timestamps(self, anchors):
        self.heading("Timestamps")
        self.explain("Timestamps")
        if not anchors:
            self.say("  " + self.paint(self.t("No independent timestamps: times come from the collector's clock."), "dim"))
            return
        for anchor in anchors:
            point = self.t("checkpoint #{n}", n=self.number(int(anchor["checkpoint"][11:-5]))) \
                if anchor["checkpoint"][11:-5].isdigit() else anchor["checkpoint"]
            if anchor.get("kind") == "rfc3161":
                checked = anchor.get("signature", "").startswith("checked")
                self.check("ok" if checked else "warn", "RFC 3161 · " + anchor["service"],
                           point + " · " + anchor.get("time", "?").replace("T", " ").replace("Z", " UTC"))
                self.say("  " + " " * 27 + self.paint(self.t("signature chained to your root" if checked
                                                               else "signature not checked: add --tsa-ca"), "dim"))
                revocation = anchor.get("revocation") or {}
                status = revocation.get("status")
                if status == "good":
                    self.say("  " + " " * 27 + self.paint(self.t(
                        "signing certificate not revoked as of {time} ({source})", source=revocation["source"],
                        time=revocation["as_of"].replace("T", " ").replace("Z", " UTC")), "dim"))
                elif status == "revoked_after":
                    self.check("warn", "Timestamp warning", self.t(
                        "signing certificate revoked at {time}, after the time stamp ({source})", source=revocation["source"],
                        time=revocation["revoked_at"].replace("T", " ").replace("Z", " UTC")))
                elif status == "failed":
                    self.check("warn", "Timestamp warning", self.t("revocation check failed: {reason}", reason=revocation["error"]))
                elif status:
                    self.say("  " + " " * 27 + self.paint(self.t("revocation not checked (no OCSP/CRL in the archive)"), "dim"))
                if anchor.get("certificate_reference"):
                    self.say("  " + self.t("Signing certificate reference") + ": " + anchor["certificate_reference"])
                for warning in anchor.get("warnings") or []:
                    self.check("warn", "Timestamp warning", self.t(warning))
            else:
                status = anchor.get("status")
                detail = {"pending": "pending: run ots upgrade, then ots verify",
                          "bitcoin-unverified": "Bitcoin attestation present; run ots verify"}.get(
                              status, "unknown attestation type; no verified Bitcoin timestamp")
                self.check("wait" if status == "pending" else "warn", "OpenTimestamps · " + anchor["service"][:10],
                           point + " · " + self.t(detail))

    def lines(self, label, lines, limit=8):
        if not lines:
            return
        self.heading(label)
        self.explain(label)
        for line in lines[:limit]:
            self.say("  " + self.paint(self.glyph["dot"], "dim") + " " + self.t(line))
        if len(lines) > limit:
            self.say("  " + self.paint(self.t("… and {n} more", n=len(lines) - limit), "dim"))

    def coverage(self, coverage):
        self.heading("Coverage")
        self.explain("Coverage")
        periods, gaps = coverage["continuous"], coverage["gaps"]
        self.check("none", "Observation periods", self.number(len(periods)) if periods else "No observation period recorded.")
        for period in periods:
            self.say("    " + str(period["from"]) + " → " + str(period["to"]) + " · "
                     + self.t("Duration") + ": " + str(int(period["seconds"])) + " s")
        self.check("warn" if gaps else "none", "Observation gaps", self.number(len(gaps)))
        for gap in gaps:
            self.say("    " + str(gap["from"]) + " → " + str(gap["to"]))
            self.say("    " + self.t("Reason") + ": " + self.coverage_reason(str(gap["reason"])))
        for window in coverage.get("session_windows") or []:
            self.check("warn", WINDOW_WORDS.get(window["reason"], str(window["reason"])),
                       str(window["from"]) + " → " + str(window["to"])
                       + (" · " + self.t("open at the last record") if window.get("not_resumed_by_last_record") else ""))
        session = coverage.get("session") or {}
        for item in session.get("sessions_at_start") or []:
            self.check("warn" if item.get("others") else "none", "Other sessions at start",
                       ("?" if item.get("others") is None else self.number(item["others"])) + " · " + str(item["at"]))
        if session.get("sessions_added"):
            self.check("warn", "Sessions added during observation",
                       self.number(sum(item["added"] for item in session["sessions_added"]))
                       + " · " + str(session["sessions_added"][0]["at"]))
        groups, other, unlabelled, captures, sealed = source_counts(coverage)
        parts = [self.t(label) + " " + self.number(sum(count for _, count in found)) for label, found in groups]
        parts += [name + " " + self.number(count) for name, count in other]
        parts += [self.t("no source label") + " " + self.number(unlabelled)] if unlabelled else []
        parts += [self.t("inside a sealed run") + " " + self.number(sealed)] if sealed else []
        parts += [self.t("recorder captures") + " " + self.number(captures)] if captures else []
        if parts:
            self.check("none", "Records by source", " · ".join(parts))
        for chat in coverage["unobserved_ids"]:
            if chat["not_observed"]:
                self.check("warn", "Numbers not observed", str(chat.get("title") or chat["chat_id"]) + ": "
                           + str(chat["not_observed"]) + " · ID " + str(chat["observed_from"]) + "–" + str(chat["observed_to"]))
        summary = coverage.get("gap_summary") or {}
        account = summary.get("account") if summary.get("status") == "on" else None
        if account:
            if account.get("status") == "applicable":
                self.check("warn" if account["missing"] else "none", "Account", self.t("Numbers not observed")
                           + ": " + str(account["missing"]) + " · ID " + str(account["observed_from"]) + "–" + str(account["observed_to"]))
            else:
                self.check("none", "Account", self.t("Not checked") + " · " + self.t(str(account.get("reason") or "")))

    def coverage_reason(self, text):
        mapping = {"observation restarted": "Observation started", "observation paused by the operator": "Paused",
                   "collector process stopped": "Stopped", "collector process ended without an orderly stop": "Interrupted",
                   "collector error: capture may be incomplete": "Error", "connection to Telegram closed": "Disconnected",
                   "connection to Telegram lost": "Disconnected", "observation could not resume after a restart": "Interrupted",
                   **{SESSION_NOTES[reason]: word for reason, word in WINDOW_WORDS.items()}}
        if text in mapping:
            return self.t(mapping[text])
        if text.startswith("no capture heartbeat for "):
            minutes = re.search(r"for (\d+) min", text)
            return self.t("Interrupted") + (" · " + minutes[1] + " min" if minutes else "")
        if text.startswith("observation stopped: "):
            return self.t("Stopped") + ": " + text.partition(": ")[2]
        return text

    def outside(self, outside):
        drand, gateway, devices = outside["drand"], outside.get("gateway") or {}, outside["devices"]
        if not (drand["rounds"] or gateway.get("windows") or devices["checks"]):
            return
        self.heading("Live recording and devices")
        if drand["rounds"]:
            self.check("none", "drand", self.t("Recorded") + ": " + str(drand["rounds"]) + " · "
                       + str(drand["first"]["at"]) + " → " + str(drand["last"]["at"]))
            self.field("Gap", str(drand["largest_gap_seconds"]) + " s")
            checked = drand.get("checked")
            self.check("ok" if checked and checked.get("relays") else "warn", "drand",
                       (self.t("Matches") + ": " + str(checked["confirmed"]) + "/" + str(checked["asked"])
                        + " · " + ", ".join(checked["relays"])) if checked and checked.get("relays")
                       else self.t("Not checked") + " · --check-drand")
            if drand["clock_behind_seconds"] > 1:
                self.check("warn", "Time", "drand: +" + str(drand["clock_behind_seconds"]) + " s")
        if gateway.get("windows"):
            self.check("none", "Cloudflare Gateway DNS", self.t("Count") + ": " + str(gateway["queries"]) + " · "
                       + str(gateway["first"]) + " → " + str(gateway["last"]))
            self.field("Source", ", ".join(gateway["addresses"]))
            for gap in gateway["gaps"]:
                self.check("warn", "Gap", str(gap["from"]) + " → " + str(gap["until"]))
            if gateway.get("truncated_windows"):
                self.check("warn", "Partial acquisition", str(gateway["truncated_windows"]))
            for name, count in gateway["names"][:15]:
                self.say("    " + name + ": " + str(count))
        if devices["checks"]:
            self.check("none", "Device list", self.t("Count") + ": " + str(devices["checks"]) + " · "
                       + str(devices["first_check"]) + " → " + str(devices["last_check"]))
            self.field("Changed", str(max(0, devices["changes_total"] - 1)))
            for change in devices["changes"][:20]:
                self.say("    " + str(change["at"]) + " +" + str(len(change["added"])) + " −" + str(len(change["removed"])))

    def account_coverage(self, result):
        coverage = result["coverage"]
        self.heading("Coverage")
        self.explain("Coverage")
        self.field("Account", str(result["account_id"]))
        self.field("Messages", self.number(result["counts"]["messages"]))
        self.field("Scope", str(coverage["tasks_done"]) + "/" + str(coverage["tasks_total"]))
        for field in ("failed_pages", "failed_attachments"):
            if coverage[field]:
                self.check("warn", "Failed", field + ": " + str(coverage[field]))
        for gap in coverage["gaps"]:
            self.check("warn", "Gap", str(gap))

    def tdx(self, tdx):
        self.heading("Intel TDX")
        for quote in tdx["quotes"]:
            where = self.t("record {n}", n=self.number(quote["record"])) + " · " if "record" in quote else ""
            if quote["status"] != "pass":
                self.check("bad", "Intel TDX quote", where + self.t(quote["detail"])
                           + (" · " + quote["error"] if quote.get("error") else ""))
                continue
            self.check("ok", "Intel TDX quote",
                       where + self.t("quote signature, quoting enclave and PCK chain to the pinned Intel root are valid"))
            self.say("    " + self.paint(quote["pck_ca"] + " · FMSPC " + quote["fmspc"] + " · v"
                                         + str(quote["quote_version"]), "dim"))
            for name in TDX_MEASUREMENTS:
                self.field({"report_data": "REPORTDATA"}.get(name, name.upper()), quote[name])
            self.check("ok", "Report data", self.t("SHA-512 of the start record: binds the journal key, run and host"
                                                   if "record" in quote else "SHA-512 of the signed collector statement"))
            tcb = quote["tcb"]
            if tcb["status"] == "not checked":
                self.check("warn", "Intel TCB status", self.t(tcb["detail"]))
            else:
                self.check("ok" if tcb["status"] == "UpToDate" else "warn", "Intel TCB status", tcb["status"] + " · "
                           + self.t("Intel collateral issued {issued}, evaluated at {time}",
                                    issued=tcb["collateral_issued"], time=tcb["evaluated_at"]))
        self.check("warn", "Not checked", self.t("compose and OS image: python -m tgwitness.cloud verify"))

    def show(self, shown, path, result, notes):
        self.say(evidence_line(result["evidence"], self.t) if result.get("evidence") else assurance_line(result))
        self.banner()
        self.field("File", str(path))
        self.field("Type", self.t(KINDS[shown]) + self.paint("  " + str(result.get("format") or ""), "dim"))
        self.signer(result.get("fingerprint"))
        self.heading("Checks")
        if shown == "evidence":
            self.check("ok", "Manifest signature", self.t("Ed25519 · valid"))
            self.check("ok", "File hashes", self.t("{n} files · SHA-256 match", n=self.number(result["files_checked"])))
            head = result["head_hash"]
            self.check("ok", "Record chain", self.t("{n} records · head {hash}", n=self.number(result["events"]),
                                                    hash=head[:8] + "…" + head[-8:]))
            self.seal(result, "report.html")
            if result.get("witness"):
                witness = result["witness"]
                self.check("ok" if witness["consistent"] else "warn", "Witness",
                           self.t("checkpoints match through record {a} of {b}",
                                  a=self.number(witness["verified_through_event"]), b=self.number(result["events"])))
        elif shown == "account_disclosure":
            self.check("ok", "Manifest signature", self.t("Ed25519 · valid"))
            self.check("ok", "File hashes", self.t("{n} files · SHA-256 match", n=self.number(result["files_checked"])))
            self.check("ok" if result["source_reference_checked"] else "warn", "Source reference",
                       "archive hash and collector key checked" if result["source_reference_checked"] else "not supplied (--evidence)")
            self.check("none", "Derivation", "review filtering and redaction against the source archive")
        elif shown == "account":
            self.check("ok", "Manifest signature", self.t("Ed25519 · valid"))
            self.check("ok", "File hashes", self.t("{n} files · SHA-256 match", n=self.number(result["files_checked"])))
            self.check("ok", "Capture receipts", str(result["receipt_count"]) + " · " + result["receipt_head_sha256"][:16] + "…")
            self.check("ok" if result["complete_within_scope"] else "warn", "Coverage",
                       "complete within selected scope" if result["complete_within_scope"] else "partial acquisition")
        elif shown == "chat":
            self.check("ok", "Manifest signature", self.t("Ed25519 · valid"))
            self.check("ok", "File hashes", self.t("{n} files · SHA-256 match", n=self.number(result["files_checked"])))
            self.check("ok", "Messages", self.t("{n} messages · {title}", n=self.number(result.get("message_count")),
                                                title=(result.get("chat") or {}).get("title") or "?"))
            if result.get("parts"):
                self.check("ok", "Accounts", self.t("{n} account(s) signed their message ranges", n=len(result["parts"])))
            self.seal(result, "chat.html")
        elif shown == "handover":
            self.check("ok", "Manifest signature", self.t("Ed25519 · valid"))
            self.check("ok", "File hashes", self.t("{n} files · SHA-256 match", n=self.number(result["files_checked"])))
            self.check("ok", "Unchanged records", self.t("{n} · hash, signature and chain checked",
                                                         n=self.number(result["records_unchanged"])))
            self.check("warn" if result["records_minimised"] else "ok", "Minimised records",
                       self.t("{n} · signature over the original record checked",
                              n=self.number(result["records_minimised"])))
            self.check("none", "Left out", self.t("{n} records of {total} in the journal",
                                                  n=self.number(result["records_left_out"]),
                                                  total=self.number(result["journal_events"])))
            self.seal(result, "report.html")
        elif shown == "selection":
            self.check("ok", "Described archive", self.t("verified and matches the seal"))
            self.check("ok", "Items", str(result["items_checked"]))
            self.check("ok" if result.get("selection_signed") else "none", "Signature",
                       "Signed Case Board selection; exact records matched against the archive" if result.get("selection_signed")
                       else self.t("Unsigned selection; item content matched against the signed archive"))
        elif shown == "report":
            seal = result["report_seal"]
            subject = seal["subject"]
            self.check("ok", "Report seal", self.t("{name} · intact · language {lang}", name=path.name, lang=seal["language"]))
            described = (self.t("{n} records · head {hash}", n=self.number(subject.get("event_count",
                                                                                     subject.get("record_count"))),
                                hash=str(subject.get("head_hash"))[:8] + "…")
                         if "event_count" in subject or "record_count" in subject else
                         self.t("{n} messages · {title}", n=self.number(subject.get("message_count")),
                                title=subject.get("chat_title") or subject.get("chat_id")))
            self.check("none", "Describes", described)
            if result["evidence_checked"]:
                self.check("ok", "Described archive", self.t("verified and matches the seal"))
            else:
                self.check("warn", "Described archive", self.t("not supplied (--evidence)"))
        else:
            self.check("ok", "Signature", self.t("Ed25519 · valid"))
        if shown == "evidence":
            self.timestamps(result.get("anchors") or [])
            self.coverage(result["coverage"])
            self.outside(result["outside"])
            notes = [n for n in notes if n not in coverage_lines(result["coverage"])
                     and n not in outside_lines(result["outside"]) and not n.startswith("No retained checkpoint")]
        elif shown == "account":
            self.account_coverage(result)
            notes = [note for note in notes if note not in account_export_lines(result)]
        elif shown == "account_disclosure":
            self.heading("Details")
            for label, field in (("Messages", "messages"), ("Chats", "chats"), ("Media", "media")):
                self.field(label, self.number(result["counts"][field]))
            self.explain("Minimised records")
        elif shown not in ("chat", "report", "handover"):
            facts = [key + ": " + json.dumps(value, ensure_ascii=False) for key, value in result.items()
                     if isinstance(value, (str, int, bool)) and key != "fingerprint"]
            self.lines("Technical details", facts, limit=12)
        if result.get("tdx"):
            self.tdx(result["tdx"])
            notes = [note for note in notes if note not in tdx_lines(result["tdx"])]
        self.lines("Notes", [self.localized_note(note) for note in notes])
        self.case(result.get("case") or (result.get("report_seal") or {}).get("case") or {})
        self.conditions(result.get("evidence"))
        self.verdict(True, evidence=result.get("evidence"))
        producer = result.get("producer")
        if producer:
            self.say("  " + self.paint(self.t("Produced by") + ": " + str(producer.get("software")) + " "
                                       + str(producer.get("version")) + " · " + str(producer.get("project")) + " · "
                                       + str(producer.get("homepage")), "dim"))
        self.say()

    def conditions(self, evidence):
        if not evidence:
            return
        self.heading("Conditions for evidence")
        needed = {"required": True, "supporting": False}
        role = None
        for row in evidence["conditions"]:
            if row["role"] != role:
                role = row["role"]
                self.say("  " + self.paint(self.t(ROLE_LABELS[role]), "bold"))
            mark = "ok" if row["status"] == "met" else "warn" if row["status"] != "missing" or needed[role] else "dot"
            detail = self.t(row["text"], **row["values"])
            if row.get("drand"):
                detail += " · " + self.t("drand rounds confirmed by {relays}", relays=row["drand"])
            self.say("  " + self.paint(self.glyph[mark], "dim" if mark == "dot" else mark) + " "
                     + self.t(CONDITION_LABELS[row["id"]]) + self.paint(" · " + self.t(row["scope"]), "dim"))
            self.say("    " + detail)
            if row["status"] != "met":
                self.say("    " + self.paint("→ " + self.t(row["how"]), "dim"))
            self.explain({"signer": "Key pinning", "head_binding": "Witness", "checkpoint": "Retained checkpoint"}.get(row["id"], ""))
        self.say()
        self.say("  " + self.paint(evidence_line(evidence, self.t), "ok" if evidence["minimum_met"] else "warn"))
        for line in next_lines(evidence, self.t):
            self.say("  " + line)

    def localized_note(self, note):
        if note in self.words:
            return self.t(note)
        if note.startswith("OpenTimestamps structure only:"):
            return self.t("signature not checked: add --tsa-ca").replace("--tsa-ca", "ots verify")
        if note.startswith("The witness key is not pinned:") or note.startswith("A public proof is signed by its witness:"):
            return self.t("Witness") + ": " + reader_message("key_unconfirmed", self.lang) + " · --witness-fingerprint"
        if note.startswith("Witnessed from "):
            return self.t("Witness") + ": " + note.removeprefix("Witnessed from ").replace(" to ", " → ")
        if match := re.fullmatch(r"Witness checkpoints match through record (\d+) of (\d+)\.", note):
            return self.t("checkpoints match through record {a} of {b}", a=match[1], b=match[2])
        if match := re.fullmatch(r"The witness saw record (\d+) at (.+), beyond this export's last record (\d+)\.", note):
            return self.t("The witness saw record {n} at {time}, beyond this export's last record {count}.",
                          n=match[1], time=match[2], count=match[3])
        if match := re.fullmatch(r"(\d+) trailing record\(s\) have no matching witness checkpoint\.", note):
            return self.t("Witness") + ": " + self.t("Not supplied") + " · " + self.t("Records") + ": " + match[1]
        if note.startswith("The witness has no answer signed by this export's key:"):
            return self.t("Witness") + ": " + self.t("Not supplied")
        if note.startswith("Channel dates are supplied metadata;"):
            return self.t("Time") + ": " + self.t("Not checked") + " · Telegram"
        if note.startswith("Minimised records are authenticated"):
            return VERIFIER_LANGUAGES[self.lang]["explain"]["Minimised records"]
        if note.startswith(("Source reference not checked:", "History report signature only:")):
            return self.t("Described archive") + ": " + self.t("not supplied (--evidence)")
        return self.t("Technical details") + ": " + note if self.lang != "en" else note


class Spinner:
    def __init__(self, stream, text, frames):
        import threading
        self.stream, self.text, self.frames = stream, text, frames
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        index = 0
        while not self.done.wait(0.09):
            self.stream.write("\r  " + self.frames[index % len(self.frames)] + " " + self.text + "…")
            self.stream.flush()
            index += 1

    def __enter__(self):
        if getattr(self.stream, "isatty", lambda: False)():
            self.thread.start()
        return self

    def __exit__(self, *exc):
        self.done.set()
        if self.thread.is_alive():
            self.thread.join()
            self.stream.write("\r" + " " * (len(self.text) + 6) + "\r")
            self.stream.flush()



def matching_archives(directory):
    directory = Path(directory)
    try:
        manifest = directory / "manifest.json"
        if manifest.stat().st_size > MAX_MANIFEST_BYTES:
            return []
        wanted = manifest.read_bytes()
    except OSError:
        return []
    found, scanned = [], 0
    for parent in dict.fromkeys((directory, directory.parent)):
        try:
            for path in parent.iterdir():
                if path.suffix.lower() != ".zip" or not path.is_file():
                    continue
                scanned += 1
                if scanned > 100:
                    return found
                try:
                    with open_archive(path) as archive:
                        if read_member(archive, "manifest.json", MAX_MANIFEST_BYTES) == wanted:
                            found.append(path.resolve())
                except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
        except OSError:
            continue
    return sorted(set(found))


def entered_fingerprint(value):
    value = re.sub(r"[\s:]", "", value).lower()
    if value and not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Expected a SHA-256 fingerprint")
    return value


def file_sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


class Transcript:
    def __init__(self, stream):
        self.stream, self.text = stream, io.StringIO()

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def write(self, value):
        self.text.write(re.sub(r"\x1b\[[0-9;]*m", "", value))
        return self.stream.write(value)


def save_transcript(path, text):
    for directory in (path.parent, Path.home() / "TgWitness-verifications"):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            prefix = "verify-result-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", prefix=prefix,
                                             suffix=".txt", dir=directory, delete=False) as output:
                output.write(text)
                return Path(output.name)
        except OSError:
            continue
    return None


def interactive_verify(args):
    from contextlib import redirect_stdout
    lang = console_language(args.lang)
    if args.choose_language:
        lang = choose_verifier_language(lang)
    args.lang = lang
    say = lambda key: reader_message(key, lang)
    words = SAY[lang]
    print(say("trust"))
    path = Path(args.bundle).expanduser() if args.bundle else None
    if path is None:
        matches = matching_archives(Path(__file__).resolve().parent)
        if len(matches) == 1:
            print(say("found") + safe_text(matches[0]))
            chosen = input(say("confirm") + " ").strip().strip('"')
            path = Path(chosen).expanduser() if chosen else matches[0]
        else:
            chosen = input(say("archive") + " ").strip().strip('"')
            if not chosen:
                print(say("cancelled"))
                return 2
            path = Path(chosen).expanduser()
    path = path.resolve()
    if not path.is_file() or not zipfile.is_zipfile(path):
        print(say("bad_zip"))
        return 2
    fp = args.fingerprint
    while fp is None:
        try:
            fp = entered_fingerprint(input(say("key") + " "))
        except ValueError:
            print(say("bad_key"))
    command = [str(path), "--pretty", "--explain", "--lang", lang, "--max-gib", str(args.max_gib)]
    if fp:
        command += ["--fingerprint", fp]
    for name in ("checkpoint", "tsa_ca", "witness", "witness_fingerprint", "channel", "evidence",
                 "require_tier", "sealed_attestation", "sealed_policy", "sealed_repo"):
        if getattr(args, name):
            command += ["--" + name.replace("_", "-"), str(getattr(args, name))]
    for name in ("require_witness", "check_drand", "check_bitcoin", "strict", "board", "no_color"):
        if getattr(args, name):
            command.append("--" + name.replace("_", "-"))
    transcript, code = Transcript(sys.stdout), 0
    with redirect_stdout(transcript):
        print(say("unsigned"))
        print(say("trust"))
        print(words["Started {time}"].replace("{time}", datetime.now(timezone.utc).isoformat()))
        print("ZIP: " + safe_text(path))
        print(words["TgWitness verifier"] + ": " + safe_text(Path(__file__).resolve()))
        print("TgWitness SHA-256: " + file_sha256(__file__))
        print("Python: " + sys.version.split()[0])
        try:
            digest = file_sha256(path)
            print("ZIP SHA-256: " + digest)
            try:
                main(command)
            except SystemExit as exc:
                code = int(exc.code or 0)
            if file_sha256(path) != digest:
                raise ValueError("ZIP changed during verification; disregard any earlier success result")
        except Exception as exc:
            Console(sys.stdout, lang, not args.no_color).failure(path, exc)
            code = 1
        print(words["Finished"] + " (UTC): " + datetime.now(timezone.utc).isoformat())
        print(say("exit") + ": " + str(code))
    saved = save_transcript(path, transcript.text.getvalue())
    if saved:
        print(say("saved") + " " + safe_text(saved))
    else:
        print(say("not_saved"))
        code = code or 2
    return code


class CheckResult:
    def __init__(self, kind, details, signer_pinned, notes=None):
        self.kind = kind
        self.details = details
        self.signer_pinned = signer_pinned
        self.notes = notes if notes is not None else []


def verification_print(*values, **kwargs):
    import builtins
    builtins.print(*(safe_text(value) if isinstance(value, str) else value for value in values), **kwargs)


def verification_parser():
    parser = argparse.ArgumentParser(description=__doc__, epilog=
        "For a .tgwpw export: verify.py unseal-password SOURCE --out DESTINATION")
    parser.add_argument("bundle", nargs="?",
                        help="Evidence/chat/account/disclosure/witness ZIP, report JSON/HTML, or a stopped distributed acquisition directory")
    parser.add_argument("--fingerprint", help="Public key fingerprint retained independently")
    parser.add_argument("--checkpoint", type=Path, help="Previously retained signed checkpoint JSON")
    parser.add_argument("--tsa-ca", type=Path, help="Root certificate of the timestamp authority (PEM)")
    parser.add_argument("--witness", type=Path, help="Witness journal export to cross-check an evidence ZIP against")
    parser.add_argument("--witness-fingerprint", help="Witness key fingerprint retained independently")
    parser.add_argument("--require-witness", action="store_true",
                        help="Require a pinned witness checkpoint matching the full evidence ZIP's final record")
    parser.add_argument("--channel", help="Witness channel posts: Telegram Desktop result.json, saved page or t.me/s URL; post dates count as external time only from a live https://t.me/s/ page")
    parser.add_argument("--evidence", type=Path,
                        help="With a profile/proof/history JSON, sealed report or disclosure: verify the referenced original archive")
    parser.add_argument("--check-drand", action="store_true",
                        help="Compare the drand rounds in the journal with drand relays (needs internet)")
    parser.add_argument("--check-bitcoin", action="store_true",
                        help="Evaluate OTS proofs against block headers agreed by two HTTPS explorers (needs internet)")
    parser.add_argument("--require", choices=EVIDENCE_PROFILES[1:],
                        help="Exit 2 unless the minimum evidence conditions (evidence), or the minimum and an "
                             "attested collection run (attested), are met")
    parser.add_argument("--require-tier", choices=ASSURANCE_TIERS, help="Exit 2 if the complete export does not reach this tier")
    parser.add_argument("--strict", action="store_true", help="Exit 2 for an unpinned signer, 3 for an authenticated newer format")
    parser.add_argument("--sealed-attestation", type=Path, help="GitHub attestation bundle; checked with the existing gh verifier")
    parser.add_argument("--sealed-policy", type=Path, help="Independently trusted policy listing reviewed workflow and collector commits")
    parser.add_argument("--sealed-repo", default="phishdestroy/TgWitness", help="Repository identity expected in GitHub attestation")
    parser.add_argument("--board", action="store_true", help="Print Case Board collections, dangling references and slice changes")
    parser.add_argument("--compare", type=Path, metavar="SECOND_ZIP",
                        help="Compare two chat exports: messages present in only one of them and changed messages")
    parser.add_argument("--compare-fingerprint", help="Trusted fingerprint of the second archive's signer")
    parser.add_argument("--max-gib", type=int, default=MAX_UNCOMPRESSED_GIB,
                        help="Largest uncompressed archive to read, in GiB (default 4)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--pretty", action="store_true", help="Readable, coloured answer (default at a terminal)")
    output.add_argument("--plain", action="store_true", help="Plain text answer (default when piped)")
    output.add_argument("--json", action="store_true", help="Only a JSON answer, for scripts")
    parser.add_argument("--no-color", action="store_true", help="No colours (also with the NO_COLOR variable)")
    parser.add_argument("--lang", type=lambda value: verifier_language(value) or value,
                        choices=("auto", *VERIFIER_LANGUAGES), help="Language of the readable answer")
    parser.add_argument("--choose-language", action="store_true", help="Show all languages before interactive verification")
    parser.add_argument("--pause", action="store_true", help="Wait for Enter after an interactive check (for launchers)")
    parser.add_argument("--explain", action="store_true", help="Explain what the readable checks mean and do not mean")
    parser.add_argument("--interactive", action="store_true", help="Ask for the original ZIP and trusted key; save a readable transcript")
    return parser


def verification_arguments(parser, argv):
    args = parser.parse_args(argv)
    if bool(args.sealed_attestation) != bool(args.sealed_policy):
        parser.error("--sealed-attestation and --sealed-policy must be supplied together")
    args.implied_checks = set()
    if args.require_tier and ASSURANCE_TIERS.index(args.require_tier) >= ASSURANCE_TIERS.index("fresh") and not args.check_drand:
        args.check_drand = True
        args.implied_checks.add("check_drand")
    if args.require_tier and ASSURANCE_TIERS.index(args.require_tier) >= ASSURANCE_TIERS.index("timestamped") and not args.check_bitcoin:
        args.check_bitcoin = True
        args.implied_checks.add("check_bitcoin")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if args.choose_language and not args.interactive:
        parser.error("--choose-language requires --interactive")
    return args


def verification_interactive(args, parser):
    if args.compare or args.compare_fingerprint or args.json or args.plain:
        parser.error("--interactive produces a readable single-archive check; comparison/JSON/plain options do not apply")
    if args.require_witness and (not args.witness or not args.witness_fingerprint):
        parser.error("--require-witness requires --witness and --witness-fingerprint")
    try:
        code = interactive_verify(args)
    except (EOFError, KeyboardInterrupt):
        verification_print(reader_message("cancelled", console_language(args.lang)))
        code = 2
    if args.pause and not os.environ.get("TGWITNESS_VERIFY_NO_PAUSE"):
        try:
            input(reader_message("pause", console_language(args.lang)) + " ")
        except (EOFError, KeyboardInterrupt):
            pass
    raise SystemExit(code)


def verification_comparison(args, parser, mode):
    unsupported = ["--" + name.replace("_", "-") for name in
                   ("checkpoint", "tsa_ca", "witness", "witness_fingerprint", "require_witness", "channel",
                    "evidence", "check_drand", "check_bitcoin", "require_tier", "sealed_attestation", "board") if getattr(args, name)]
    if unsupported:
        parser.error(", ".join(unsupported) + " cannot be used with --compare; verify the evidence archive separately")
    try:
        compared = compare_chat_exports(args.bundle, args.compare, args.fingerprint, args.compare_fingerprint, args.max_gib)
    except Exception as exc:
        code = 3 if args.strict and isinstance(exc, VerifierTooOld) else 1
        if mode == "json":
            verification_print(json.dumps({"verified": False, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
            raise SystemExit(code)
        verification_print("ASSURANCE: fail")
        parser.exit(code, "VERIFICATION FAILED: " + type(exc).__name__ + ": " + safe_text(exc) + "\n")
    pinned = bool(compared['first']['key_pinned'] and compared['second']['key_pinned'])
    compared['assurance'] = assurance(compared)
    compared['assurance']['scope'] = 'two authenticated chat exports; the comparison covers their contents'
    if mode == "json":
        verification_print(json.dumps({"verified": True, "kind": "comparison", "result": compared,
                          "signer_pinned": pinned, "requirements_met": not args.strict or pinned},
                         indent=2, ensure_ascii=True))
    else:
        verification_print(assurance_line(compared))
        print_comparison(compared)
    if args.strict and not pinned:
        raise SystemExit(2)
    return


def verification_json(args):
    notes = []
    data = read_json_file(args.bundle)
    kind = data.get("statement", {}).get("format")
    if data.get("format") in ATTESTATION_RECORDS or kind == "tgwitness-assurance-v1":
        result = verify_collector_attestation(data, args.fingerprint)
        return CheckResult("attestation", result, bool(args.fingerprint), tdx_lines(result.get("tdx")))
    if "statement" in data and "signature" in data:
        authenticate_statement(data, "public_key" if "public_key" in data["statement"] else "witness_public_key")
        known = {"tgwitness-board-selection-v1", "tgwitness-case-board-v1", "tgwitness-case-board-disclosure-v1",
                 "tgwitness-case-board-handover-v1"}
        if kind not in known and not any(is_format(kind, name) for name in (
                "public-proof-v1", "history-report-v1", "dossier-v1")):
            raise VerifierTooOld("Unsupported signed JSON format")
    if kind == "tgwitness-board-selection-v1":
        shown, result = "selection", verify_selection(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
        notes.append("Signed Case Board selection; exact records matched against the signed journal archive.")
    elif kind in {"tgwitness-case-board-v1", "tgwitness-case-board-disclosure-v1", "tgwitness-case-board-handover-v1"}:
        shown, result = "board", verify_board_document(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
        notes.append(result["meaning"])
    elif data.get("format") == "tgwitness-selection-v1":
        shown, result = "selection", verify_selection(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
        notes.append("The selection is unsigned. Its items match the verified archive; selection time and notes are not authenticated.")
    elif is_format(data.get("format"), REPORT_JSON):
        shown, result = "report", verify_report(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
    elif is_format(kind, "public-proof-v1"):
        shown = "proof"
        result = verify_public_proof(args.bundle, args.fingerprint, args.witness_fingerprint, args.evidence)
        pinned = bool(args.witness_fingerprint)
        if not pinned:
            notes.append("A public proof is signed by its witness: pass --witness-fingerprint to pin that key.")
    elif is_format(kind, "history-report-v1"):
        shown = "history"
        result = verify_history_report(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
        if not args.evidence:
            notes.append("History report signature only: pass --evidence to cross-check the journal and counts.")
    else:
        shown = "dossier"
        result = verify_dossier(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
    return CheckResult(shown, result, pinned, notes)


def verification_archive(args):
    notes = []
    pinned = bool(args.fingerprint or args.witness_fingerprint)
    if (archive_format := bundle_format(args.bundle)) in DISCLOSURE_FORMATS:
        if args.checkpoint or args.witness or args.tsa_ca or args.channel:
            raise ValueError("Journal checkpoint/witness/timestamp options do not apply to disclosure archives")
        shown = "account_disclosure"
        result = verify_account_disclosure(args.bundle, args.fingerprint, args.evidence)
        pinned = bool(args.fingerprint)
        notes.append(result["meaning"])
        if not result["source_reference_checked"]:
            notes.append("Source reference not checked: supply the original account archive with --evidence.")
    elif archive_format == "tgwitness-account-export-v1":
        if args.checkpoint or args.witness or args.tsa_ca or args.channel or args.evidence:
            raise ValueError("Journal checkpoint/witness/timestamp options do not apply to account export receipts")
        shown = "account"
        result = verify_account_export(args.bundle, args.fingerprint)
        pinned = bool(args.fingerprint)
        notes += account_export_lines(result)
    elif is_format(archive_format, "chat-export-v1"):
        shown = "chat"
        result = verify_chat_export(args.bundle, args.fingerprint)
        pinned = bool(args.fingerprint)
    elif is_format(archive_format, "handover-v1"):
        shown = "handover"
        result = verify_handover(args.bundle, args.fingerprint)
        pinned = bool(args.fingerprint)
        notes.append("Minimised records are authenticated by the signature over the original record's hash; "
                     "confirm their content against the complete journal by that hash.")
    elif is_format(archive_format, "witness-v1"):
        shown = "witness"
        result = verify_witness(args.bundle, args.witness_fingerprint or args.fingerprint, args.check_drand, args.check_bitcoin)
        if args.channel:
            result["channel_check"] = check_channel(result, args.channel)
        result.pop("statements")
    else:
        return verification_evidence(args)
    return CheckResult(shown, result, pinned, notes)


def verification_evidence(args):
    notes = []
    result = verify_bundle(args.bundle, args.fingerprint,
                           read_json_file(args.checkpoint) if args.checkpoint else None, args.tsa_ca,
                           args.check_drand, check_bitcoin=args.check_bitcoin)
    notes += coverage_lines(result["coverage"]) + outside_lines(result["outside"]) + tdx_lines(result.get("tdx"))
    pinned = bool(args.fingerprint)
    if any(a.get("kind") == "opentimestamps" and a.get("status") != "confirmed" for a in result.get("anchors", [])):
        notes.append("OpenTimestamps structure only: run ots verify to authenticate the Bitcoin timestamp.")
    if args.witness and not args.witness_fingerprint:
        notes.append("The witness key is not pinned: the witness journal is checked only against itself.")
    if args.witness:
        witness = verify_witness(args.witness, args.witness_fingerprint, args.check_drand, args.check_bitcoin)
        result["witness"] = cross_check_witness(witness, args.bundle, result)
        if args.channel:
            result["witness"]["channel_check"] = check_channel(witness, args.channel)
            result["witness"]["head_telegram_post_time"] = channel_head_time(result["witness"], result["witness"]["channel_check"])
        conflict = (result["witness"]["conflicts"] or [None])[0]
        if conflict and conflict["event_count"] > result["events"]:
            raise ValueError("The witness saw record " + str(conflict["event_count"]) + " at " + conflict["at"]
                             + ", before this export was created at " + str(result["witness"]["export_created_at"])
                             + ", but the export ends at record " + str(result["events"]))
        if conflict:
            raise ValueError("The journal differs from what the witness saw at " + conflict["at"] + " (record "
                             + str(conflict["event_count"]) + ")")
        broken = [a for a in result["witness"]["anomalies"] if a["status"] in ("fork", "rollback", "key_changed")]
        if broken:
            raise ValueError("The witness saw this journal " + broken[0]["status"].replace("_", " ") + " at "
                             + str(broken[0].get("at")) + " (record " + str(broken[0].get("event_count")) + ")")
        if result["witness"]["seen_after_export"]:
            notes.append("The witness saw record " + str(result["witness"]["seen_after_export"]["event_count"]) + " at "
                         + result["witness"]["seen_after_export"]["at"] + ", beyond this export's last record "
                         + str(result["events"]) + ".")
        notes += ["Witnessed from " + p["from"] + " to " + p["to"] for p in result["witness"]["witnessed"]]
        if not result["witness"]["consistent"]:
            notes.append("The witness has no answer signed by this export's key: nothing here is witnessed.")
        notes.append("Witness checkpoints match through record "
                     + str(result["witness"]["verified_through_event"]) + " of " + str(result["events"]) + ".")
        if result["witness"]["unwitnessed_events"]:
            notes.append(str(result["witness"]["unwitnessed_events"])
                         + " trailing record(s) have no matching witness checkpoint.")

        pinned = pinned or bool(args.witness_fingerprint and result["witness"]["consistent"])
    return CheckResult("evidence", result, pinned, notes)


REQUESTED_CHECKS = (("checkpoint", "--checkpoint"), ("witness", "--witness"), ("tsa_ca", "--tsa-ca"),
                    ("require_witness", "--require-witness"), ("sealed_attestation", "--sealed-attestation"),
                    ("channel", "--channel"), ("check_drand", "--check-drand"), ("check_bitcoin", "--check-bitcoin"))
APPLICABLE_CHECKS = {"evidence": {name for name, _ in REQUESTED_CHECKS},
                     "witness": {"channel", "check_drand", "check_bitcoin"}}


def refuse_inapplicable(args, kind):
    implied = getattr(args, "implied_checks", set())
    refused = [flag for name, flag in REQUESTED_CHECKS
               if getattr(args, name, None) and name not in implied and name not in APPLICABLE_CHECKS.get(kind, ())]
    if getattr(args, "evidence", None) and kind in ("evidence", "chat", "handover", "witness", "account", "distributed",
                                                    "attestation"):
        refused.append("--evidence")
    if getattr(args, "compare_fingerprint", None):
        refused.append("--compare-fingerprint without --compare")
    if getattr(args, "witness_fingerprint", None) and kind not in ("evidence", "witness", "proof"):
        refused.append("--witness-fingerprint")
    if kind == "evidence" and not getattr(args, "witness", None):
        refused += [flag + " without --witness" for name, flag in (("witness_fingerprint", "--witness-fingerprint"),
                                                                  ("channel", "--channel")) if getattr(args, name, None)]
    if refused:
        raise ValueError(", ".join(refused) + " cannot be checked against this " + kind
                         + " input; supply the archive and options that check it")


def verification_requirements(args, checked):
    result, notes, shown = checked.details, checked.notes, checked.kind
    refuse_inapplicable(args, shown)
    chronology = result.get("chronology")
    if chronology:
        notes.append("Observation time anomalies: " + str(chronology["regressions"]) + " backward step(s), "
                     + str(chronology["unparseable"]) + " unparseable timestamp(s). " + chronology["meaning"])
    if args.board and result.get("board"):
        notes.append("Case Board annotations: " + str(result["board"]["annotations_head"]["seq"]))
        notes.extend("Collection: " + item["title"] for item in result["board"]["collections"])
        notes.extend(item["message"] for item in result["board"]["slice_changes"])
        notes.extend("Dangling board target: " + item["id"] + " / " + item["event_hash"] for item in result["board"]["dangling"])
    check = result.get("channel_check") or (result.get("witness") or {}).get("channel_check")
    if check and (check["invalid_signatures"] or check["differ_from_journal"]):
        raise ValueError("Channel posts do not match the witness journal")
    if check and check["telegram_live_dates"]:
        notes.append("Channel post dates were read from Telegram at verification time; edited posts are not counted.")
    elif check and check["telegram_post_dates"]:
        notes.append("Channel dates are supplied metadata; witness signatures cover the post content.")
    if args.require_witness:
        witnessed = result.get("witness")
        if not witnessed:
            raise ValueError("--require-witness requires a full evidence ZIP and its witness journal")
        if not witnessed["witness_key_pinned"] or not witnessed["export_head_witnessed"]:
            raise ValueError("No pinned witness checkpoint matches the exported journal head; "
                             "retain a witness checkpoint at the export boundary")
        if witnessed["witness_fingerprint"] == result["fingerprint"]:
            raise ValueError("The collector and the witness must use different trusted signing keys")
        if check and (check["posted_but_not_found"] or not
                      set(check["matching_records"]).intersection(witnessed["export_head_witness_records"])):
            raise ValueError("Requested channel evidence is missing signed witness posts at the export boundary")
        result["witness_required"] = True
    if args.sealed_attestation:
        if shown != "evidence":
            raise ValueError("Runtime attestation requires a full evidence ZIP")
        try:
            from tgwitness.sealed_verify import verify as verify_runtime
        except ImportError:
            raise ValueError("Runtime verification needs the installed TgWitness sealed verifier and gh") from None
        checked_runtime = verify_runtime(args.bundle, args.sealed_attestation, args.sealed_repo,
                                         policy=args.sealed_policy, max_gib=args.max_gib)
        if checked_runtime["journal"]["fingerprint"] != result["fingerprint"]:
            raise ValueError("Runtime attestation names another collector key")
        result["runtime_attestation"] = {k: checked_runtime.get(k) for k in ("verified", "sha256", "workflow", "limitation", "attested_at")}
        result["runtime_attestation"]["key_origin"] = "created"
    result["assurance"] = assurance(result)
    if any(row["status"] == "fail" for row in result["assurance"]["ladder"]):
        raise ValueError("Assurance checks found contradictory witness evidence")
    result["evidence"] = evidence_conditions(result, shown)
    result["requested_checks_unavailable"] = requested_checks_unavailable(args, result)
    return checked


def verify_input(path, policy):
    args = argparse.Namespace(**{**vars(policy), "bundle": Path(path)})
    if args.bundle.is_dir():
        if args.checkpoint or args.witness or args.tsa_ca or args.channel or args.evidence:
            raise ValueError("Journal/report options do not apply to a distributed acquisition directory")
        result = verify_distributed_work(args.bundle, args.fingerprint, args.max_gib)
        checked = CheckResult("distributed", result, bool(args.fingerprint), [result["meaning"]])
    elif args.bundle.suffix.lower() in (".html", ".htm", ".pdf"):
        result = verify_report(args.bundle, args.fingerprint, args.evidence)
        checked = CheckResult("report", result, bool(args.fingerprint))
    elif args.bundle.suffix.lower() == ".json":
        checked = verification_json(args)
    else:
        checked = verification_archive(args)
    return verification_requirements(args, checked)


def verification_failure(args, parser, mode, console, exc):
    code = 3 if args.strict and isinstance(exc, VerifierTooOld) else 1
    if console:
        console.say("ASSURANCE: fail")
        console.failure(args.bundle, exc)
        raise SystemExit(code)
    if mode == "json":
        verification_print(json.dumps({"verified": False, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
        raise SystemExit(code)
    verification_print("ASSURANCE: fail")
    parser.exit(code, "VERIFICATION FAILED: " + type(exc).__name__ + ": " + safe_text(exc) + "\n")


def verification_output(args, checked, console, mode):
    shown, result, pinned, notes = checked.kind, checked.details, checked.signer_pinned, checked.notes
    evidence = result.setdefault("evidence", evidence_conditions(result, shown))
    unmet = bool(args.require_tier and ASSURANCE_TIERS.index(result["assurance"]["tier"]) < ASSURANCE_TIERS.index(args.require_tier))
    unpinned = args.strict and not pinned
    required = getattr(args, "require", None)
    profile_unmet = bool(required and EVIDENCE_PROFILES.index(evidence["profile"]) < EVIDENCE_PROFILES.index(required))
    unavailable = result.get("requested_checks_unavailable") or []
    if unmet:
        notes.append("Required assurance tier was not reached: " + args.require_tier)
    if profile_unmet:
        notes.append("Required evidence profile was not reached: " + required)
    notes += ["Requested check not performed: " + item for item in unavailable]
    failed = unmet or unpinned or profile_unmet or bool(unavailable)
    if console:
        console.show(shown, args.bundle, result, notes)
        if failed:
            raise SystemExit(2)
        return
    if mode == "json":
        verification_print(json.dumps({"verified": True, "kind": shown, "signer_pinned": pinned, "notes": notes, "result": result,
                          "evidence_profile": evidence["profile"], "requirements_met": not failed},
                         indent=2, ensure_ascii=True))
        if failed:
            raise SystemExit(2)
        return
    verification_print(evidence_line(evidence))
    for row in evidence["conditions"]:
        verification_print("  [" + row["status"] + "] " + CONDITION_LABELS[row["id"]] + " (" + row["role"].replace("_", " ")
                           + "): " + row["detail"] + ("" if row["status"] == "met" else " · " + row["how"]))
    for line in next_lines(evidence):
        verification_print(line)
    if shown == "evidence":
        verification_print("What changing this archive would take:")
        for line in forgery_lines(result):
            verification_print("  - " + line)
    verification_print(json.dumps(result, indent=2))
    verification_print(producer_line(result.get("producer")))
    seal = result.get("report_seal")
    if seal:
        verification_print("Report seal verified: " + ("chat.html" if shown == "chat" else "report.html" if shown == "evidence"
                                          else args.bundle.name) + ", language " + str(seal["language"]) + ".")
    if result.get("report_json"):
        verification_print("JSON report seal verified: report.json.")
    pdf = result.get("report_pdf") or (result if result.get("pdf_signature") else None)
    if pdf:
        verification_print("PDF signature and Ed25519 seal verified: " + str(pdf.get("file") or args.bundle.name)
              + " (certificate " + pdf["pdf_signature"]["certificate"] + ").")
    if result.get("report_parts"):
        verification_print("Report parts verified: " + str(result["report_parts"]) + ", each sealed over this export.")
    ids = result.get("message_ids")
    if ids and ids["numbered_per_chat"]:
        verification_print("Message IDs " + str(ids["first_id"]) + "-" + str(ids["last_id"]) + ": " + str(ids["present"])
              + " present, " + str(ids["missing"]) + " absent in " + str(ids["missing_ranges"])
              + " range(s); message-ids.json matches chat.json.")
    if result.get("sha256sums"):
        verification_print("SHA256SUMS matches the signed manifest.")
    for line in notes:
        verification_print(line)
    verification_print("Integrity verified. " + evidence_line(evidence)[len("EVIDENCE: "):].capitalize() + ".")
    if failed:
        raise SystemExit(2)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "unseal-password":
        return password_command(argv[1:])
    parser = verification_parser()
    args = verification_arguments(parser, argv)
    if args.interactive:
        verification_interactive(args, parser)
    if not args.bundle:
        parser.error("bundle is required (or use --interactive)")
    args.bundle = Path(args.bundle)
    if args.require_witness and (not args.witness or not args.witness_fingerprint):
        parser.error("--require-witness requires --witness and --witness-fingerprint")
    globals()["MAX_UNCOMPRESSED_GIB"] = max(1, args.max_gib)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    mode = "json" if args.json else "pretty" if args.pretty or (not args.plain and sys.stdout.isatty()) else "plain"
    if args.compare:
        return verification_comparison(args, parser, mode)
    console = Console(sys.stdout, console_language(args.lang),
                      mode == "pretty" and not args.no_color and not os.environ.get("NO_COLOR"), args.explain) \
        if mode == "pretty" or args.explain and mode == "plain" else None
    spinner = console.spinner() if console else None
    if spinner:
        spinner.__enter__()
    try:
        checked = verify_input(args.bundle, args)
    except Exception as exc:
        if spinner:
            spinner.__exit__(None, None, None)
        verification_failure(args, parser, mode, console, exc)
    if spinner:
        spinner.__exit__(None, None, None)
    return verification_output(args, checked, console, mode)


if __name__ == "__main__":
    main()
