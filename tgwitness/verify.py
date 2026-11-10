# TgWitness verifier sources SHA-256: 17180ba9e20cbf1216ec59b4b10b95f7d381194a43bf180d35cd06a88c2cfb14
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
                           "Source linkage names the original archive and collector key. It does not show that filtering and "
                           "redaction followed that policy."}





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
# Catalogue SHA-256: e3190120ecf5f6156fb544d939badd017b0e16fbfcb804ae316c881a82508aab
VERIFIER_LANGUAGE_DATA = (
    "eNrkvVtzHNeVJvpXMnAeLJ8pwqOe7o44wBNEQhKDF7AJyDPdL44EKgmkUFUJVVZBAhU6oYstWSG1aKtlyu22JKt9ujXuHsWApCiCJAhGuOT34l/w"
    "Lznrum+5sy5AQbY8EbZYqMrc17XXfX/r1bmsM7fw6lwnbWdzC3PLnc1WXm7NNeZeLrrNEn9ZzTc7WRd+kw+NubNb2cY2/KYfGnMX890s6WYb8E7e"
    "2UzSTjNpZrv5RoZPjfixMfff814nK8vkxaLf7aQteDz8pjF3JSt2Wlmy0y2u5S1qMvwGnumvt/IN/Ka4hg+4fzbmVrO0lTVhEDtFt4dT8f5uzD2f"
    "l72iu2cfCL5ozP0wz17OukmZtbKNXl7AmlW/asyd72VtHB//25i7lHbya1nZS0pYu7TX7+IaR74062DnD9+dy8qNbr4OA027G1uwivBr9Tv7XOn8"
    "ju+vwgpu4NJfy7pZZwNfr3wFu5nu4Bhwh7J8p0f7Gn6FfXTz3VRm7vwBc8w7eTsvaTk3mGgi3zXmrtKnZGMrzbEN78/G3NLGRtHv9JJmXm60ipJX"
    "KvIljAS2BmbY7+EabLzUz8tch1XzC/aN2whbRRTm/iXUjIRptqNsJFtpuZWVRKu9LaVeM/apX2nMdYoeUGNWZjCdp4pWEwgnewWH8X1ob8SPjbl2"
    "2tvAhrFR7A8m1xYKgldH/cq9lv2dnVYO3z915gwcuyZuu3Ya/60xZ+bF44cHekWyB7STwIHCbsc84LaA/WzggmXNhSRtNpMzZ3plemYj9Zqpf4rb"
    "wtXeyLq9/Fq+kfb4+W62W2zjXpdJcS15tZe3s9eSp14ticZf+760f5w3432at3rySiNJr/Vgs3Dx8Yuk7KXtnfFDOEZDjTl8aYMOHS9Uci0F3ger"
    "9Wo3S8ui8xp0Nv4Zrx1n0ZOnOkWycnb1yg/OXr2Y5B0airCY7/stT/xWY24n6yDPX0i6/U5S9Mqkv7PZTZtZAx/kb3aBl1zbgx4mf7Yx90ze2yig"
    "u7TXA0LnYckBWjTvm5anebox1+9sd4qX/ad7ezvZIkycn8IDo23ibtFmQT/HfbMxd7mAxWtmuATIA8xP5QJ/TjYKIIpr3aJNK7xRtFDmFN3vwS+t"
    "YmN7Hno/eRsg5Zavnn/2/NmltfMrl5Nnl85fXD6Hgi7ybYPUAeZ9yTp0nJTpLsxufa+H3KiAPvLS62Q725sXLWLq1xpzMHiQ+HB2Xs7hkY5IXXiz"
    "3Ch2UFaMeQBoMYUDmLYCmRH7lvajWC+z7q4QC+xdobIsa8pqj3yiMfdcijSB/4X2+u31rFvS0eHXsiY2EvsaZS1qRwkoYj0StvavxtxKN9/MQS1K"
    "etnGVgfYSQuUqR6cchS7I35szK1FXliLPPcCUzH8qp9wPWjK8OnvScv4e9IvLltGQD/bv/g3lS7yo/kT9MW0s9lPN3HfzMfG3LNAm/AN/QPjxT7X"
    "sM9z/a7RPPQjynTkaCTO6QNIclQWUDzTv6pxUP/mIz7VuZZ32/S1/Yzz3nB+cf9CPY6kLClv/AnoXwhvVejrWdFNnxWN9KrRhq4aHegSKHYwV2pI"
    "Pxrdp7QaTyntSXO4GnvUGf0Df5nDjd/ZP3B2wGh4Zc1H1PFK+gb/ob2hIfC/SG9KD+cMFaw6Cuuqo6fCumzBjnnaXvU72OHsGtB0H7fDfMRx92hS"
    "/C+PKzl/ToaGnxpzy6+k7ZwtDvMR6X4T1JrrSgfen6D9d4tmf4P4CCr/zl/Qnug1jhJd+Qq1QBDGrHSRgmf/srqp+Tn4AuwH0PpwteGbXjfdIAsi"
    "/Epm+0yRdps6Yf4DVruXsl1C/+IuMjOjXZSPvOuy3zxiXHMeLX2CuXa7BS0c/Qsj5/klq88vnfmrv/lbHHrwDfSdMjPif4HuSGVAyuMPZv524rJe"
    "pawUU3YzT4ms8V/RqndAzvVUX+Y/1CoxtgjuXpQzX4ly5hWH6Za4WjTU2LfYbr+kn+UDrnOxs8OzlU9gs3VA8+r2d7gl9y+yNYANdEiQsIFh/5Rd"
    "AzJjHU63z36BZ7gD1jSvpn6EfdxUG1eUAtyyyJd8CqG9NZBloAu1E9XRk9/fS5abf/U3f/P0/4Mf7fZO+QJQjP1yN23lONLKV8yLxMARlqR/wRif"
    "X4KmVl+4tIr92z8ac692XkvIPne6TMhggSdH/MhvCi/Bn7eyFBYVe3xN3qz5kd9sC2vFX2ErgNXoa7Ff+J2UKfup8vtqRoGSlHf1jaSLR6yUZiZ8"
    "GFtO0bKA3oD2gQngp5YIvORV/MQjG/8UaEDmEJW8TtBpt+hvbqmp+Wr6Glkz69jmNE8DRW6R3kTkV6Yvm2dwrtZGWc/2CrJuQUVj1gf6WSste+Z5"
    "WpbXUD+adYuNOaNAo4Xtmb1s1Y/+3V2/5P96teOvEX/TmPvj6/9OrxOtFCT8Kl8xvSDhAck1rAuAniJr2FGKJn7UtGofIumBEyhUrTM+haD5Kd7x"
    "zxYZv0Uvbb2mxpv1w032HGoEcgaMI2wxyXtZG7R44KWwtrwXsC+bMGHYWsdVYUXyLFox/NLKVre57BU8WzqlWHt2ODNqqDEnn4gCeNvVtkHLxtnK"
    "CR8k+z3PXkbeCZJKHardrJnS6Pz1YW+fndbx323MXYBRtPNS+bf3p0iIDaOSeH862qTbQuRL0UYS0Jg66Mfc6ali4n6FOmIOxkbRJGXOfCbdvkma"
    "Qplcg4VT6ceafvQXlv+b3by3J9KfPwst0eIb3zf9gb3D6pGZxQqZ/zdzU91OYGx9ox6XOYpiz/pWGs57yjWP8yb3qa4mpJe8DJ7GL8Uvme/keKK6"
    "qOx32Jw90evV3l9OwYjvZikqQ0BRsNZ8LMgxkhnaRprr9juxAUzbAp4LYnShS5b5bMN4RYnkr3n6zHHfbMydOXMNBpx1d7ooRNDzECyb+3N8+aD/"
    "WbSCYykpqnHGdT9RY+aXnaKVb+zRAUiT5/Le8/31ZGmDTwWs4mKC9N9K1s79j4VkZ6+3BQ2caSe9TRHk8xutot+0frVvu0eQXcJ0jWRqJK+SEim6"
    "JIqtcY+4vmnmsyxgDDmM/Bk9Ubotrzr78hrqCeQZBXstBZbKC5GaHXI3kdxVJ2+lMUeKkzIMdDUmG2m3m2foUlIRnTiq4KIsJVGRsQ2szJ9te3om"
    "y+TpP77+T6+KAvoayM+czvD6njWdJn0SaIBVQuvg5CgfKuPGqcvObxhUW+mRgwmgFsFn+vXMOvthkWRm3CLGXdDst0KBWyXVyS4wxWAmea4x1+yS"
    "oIZhNtE7Ko4pWpZu1kr3SlzCCR4y1Et8M+0Yl72y1ZeL7va1VvFy8qp+es0S6zQvgZT84flzy5fPLi+AeO/k7X4bzCMybSRqm7wqH7CHKR7GOejc"
    "SldGR79G3xDGKkkb6QEzWEdnPy4UhaPT7l6yCUu2A1bKVooKdCdT8+7Myyh1OuSjhVM3n5yHcwnTXweFJUsxGgmNdFogq7ZwhC9vFa3sjLzryifY"
    "SdQaaUv1DAE3wSNV9sEwY9/xPDmuviNDja5qozJOjYVKT2DbYXjEGOG9dFsHXdrARJli/Ct7qY+8BIymgr6VabSRFXeyDCg8Zc++8bljMA+0pFaf"
    "swxaLbRazIEt+uiuw1+zJg+6ZsG/c7OInTQUIXKAQLcuKaz2KppTZfywjXq+MbcUV7rQH1jzC3q/X+rnXfpFFW/yhFe/bcxdOn/5/KUXLiXPrlxN"
    "dGzJpeU1dCfW/VT/Fk5iaW1teXVt+VxyduXixeWzFLi6+sLlEQ2Oesv2hQ++cCVZW0muLp9duXousaJq5Vk1kZ1eJnsebJDLa8vPXT2/9vfJyuWL"
    "f49jiY7z8sqarMuULzTmLoOcSWCrdji+ymJ7fmePbT6Waa8WO7QlOIPpnvf9sswlysAvq9/6z26mO+GD9FVjjtxA7BQykYWo6jDhgySVa+wHE8/e"
    "yroilyd6sk7K9Xcwlqk+LLPnjhuFXHwY8lfFB9kBcAOMicLxqxWJJ2+5MSfyO9TXkn84f2VhjKp07FfH9jqhKTF+DJM2ZHPP6Oe8x3yddYnan5Cz"
    "iSq+4YY4Yt825lb7O0iWyMqNNULJPmm3J4xddxedDFM8DVwZxTQQAf66p/oemu1pT8xHOLQ2JueeCBJQPbKt8WygJJxlazi2MkMWT6a8sV0cvyF5"
    "7eeT/75VkIHVLVrSlzgf0mSjX/aKJpiO6GsjhUTjIqjZmBwUHvu315uJ68pJpLWxfmR2taemY1oX9dRELHvMbkjWtmAYqNGto+7Oilp+LbD0i3WZ"
    "V94DtQ4M6swzEhrGv5/CaLdw3Fsw8Kw1bwPQ350hN+Y8s4jVqjQg0V12YWKfTsgApnv8d0da925MwfXI7BV9N9XhpC0AhT17NvlvT//t076l2UhW"
    "drKODfbrrx6fbcBMNeyyU9DE0qZopfPtzL5DC90wz2pSErLIMiFvjQo68do4/BQp6s99iHW+B0dQGk4BPMwOKSIMZtUSaSAj+hn1K/r3vB/Nn57z"
    "EAaVElfjAwVMrlM9vuS6m1ljYyX7+J7GC/UJ2sAVctga5S5TatkUnIdW5sSNTEB7GpL1OHHASGbQCFGc86PTes0P6Msf4QN0w8qw/16Soc9LUa6y"
    "cKjbWtFoyFJGx1G5k25k88kP1aMI8hl2X7fcJUy0yC3PCfgLa58BwTjC8C97fpwXBB+ZtzZTzKt8OaNkfmWzJjsERsBqjmT24nQXkwwscyB5fL8k"
    "Gc8O6X6nx7GiU+5gUstvMXmpn7Y45J+dP7e06mZO0zBeRZsy35jCSJymzcbcCzs6e4zLFIYPlLAxLCbHPYE3U+iTSQlX3aVFUcf6HxtzBYjaRLRz"
    "X/+p+wUsb7f3Ep8pJfOs7hczwhKz8mEMzT5pTk7yqx3oiGes3gyLXWoKWPU72H08l37zla8ac1vmgk5Kngb/b8z2RRLluHZJeb7u38QXJcLdSteJ"
    "8YffKBcnE4Duw9hYofsdyj+KT6ZJKdeK+mwqV7/FCLXKTl+hin/P0WmKjwFlFpQQGH5jIp+vdmwgJeF8FnrCBjYb9ApuDTCqVrrLEa4rZy9IMooY"
    "Bzt5B5UZ7gjvc9Ah1fSw2bdp7ufAYUnt/Rz6i/LLzvzN039l2CmSpVD0Ajk1Ss/UA5WkQY4aHMZWQSnUJ26iOgo2j5xgPFpN6NeNdFf/rNnfs8/Q"
    "t/3SbrD9CmSy+aNy+wKbRXcPjLt6a+N4703ZH4Zlpu6MX9L5u7+XZR9TKPnf1xogV9NWn7wLJnHMLNK07/E9gqJkIl1ZTfJ2uplNFOw+5os2Xhmc"
    "W4wumpS14tq1Vt7hxlmpUDvdVbUX5SvJhfjhJY7G+cstHsw/Ra8utwquH/H1gtc89lXzCPHmKtuLfPkasr60iemzr4KAx2wZzsbpshdHAl2oZc0n"
    "54r+eis7s9HKoVO60fL38xvtJoZ7kmY33fSz5lAxKzqwHHlvPlnpgKq9sbL6g4t5p/8KcYZyS9sotyj5BBabk4EkxFEmV5g0/tv800//F84k6O7t"
    "9ArQi3a29qhb4ovA6VIYmPE3zSeXC7zAsolLjNlYIO5xr2CUYAu2ilSul8Dq/0h3Msgc4ogd+lyyjtnteRZUvW5/w0ZjQGFbXVu6uvaj55evLs/3"
    "XoHJmruNOLrn1y5dlDuw0H3m7DmrvDDpLq+vTXVz76HgMu6koKE+ZZaYE2iAXL6/YEO5dPMYzvGCaRwmT9u20sVeQN6q6qRN4ttsy2Immqs9G6Ot"
    "zHbSLnCA1l7ylDTfylBCSXy4b+940GDW0+aPuMkX4KD/7V/DMF+B5d6As45ZDymSVdYtFxPS5EvN0iO9B7NFWq3iZV5obOl6vkOaEZ4keJSVTVKL"
    "nNVhB2+aXONbn7DLzpJjS6Vk5//QU6NNLhxfn1qga2ssZ9xcyt34S/OJnBGSSjto+qT+Fcz5hJw49LWENOlaVnunDyug5KdjO8seUvyTbzA6PZ0t"
    "djRxrOy3ek5rL4PcLV6mu10pmE2tlrbFn8VQ0tE386ZJjMHrEPhe0e/t9Nn5jm3zcPk+WaoX+s5wv2f+b6RuOBEmk8zfBVh4EEz/7w9MFv4Zd+3K"
    "H8CSpd1WTlEV29d2tkObBETzo753fUjyBXnE9h7RDl5EoLgz2m5Ek8hz8XJzxl7PvBekNLbydt4rfxT+kvzXBcwW52xF3rYSzkVZ4sr91QI6xzTE"
    "CkN+qS+ZGmwtdplHKRPHuBL50+yDfAxBhrR42THHLnl6wacoZt00brl34m2ZfXs9M/vWRE5MX/Ywu8/zqJhdE3aVNneRGnA9l5o8F00/Anu8W424"
    "WGchxey7/VKDEmzBod45n+DhPnNmK2vtzCfGj5m2ykJC8ujDXF29uGg8jt6kYbjKV+h89qCrFHhAxlEjCtEz62+IAzzO513upC5qGTCbIfPJlRaw"
    "GfICsprxA2UTQsZWiuH2AWUZj6H9he1pvkvwo7xj7ngwT6VbhdCjuW3AeQzYHBIZvkyDEpaY2tEHQ6Y9gKlTZCBZB12ixcyF4is73QKdI03KAwS6"
    "3M06ObpKsP1rqHhIxrDw9B/BxudkHz6XOYnechvU4/WVYYjTGAnMshqhLz6q2Y6w5gvwsSr1Tc7tfLJKskLzvpmo0JGDTLyDd+fwVpthKJnhqbxL"
    "8+bwqtNJWGBTIRqUq8IiiamgA6VVNA4lmyxB+4VJPBtbGs8V54sqYmyyvEzOhmZTQoaU0YH5QpQuIoqKXjj9EZzCSrov3QhejJ2x0h4ydVBin+Yg"
    "wctBEEBRJPi+r2towSDNClLk8DVkgTstQll4NY6egSujN5QcFAKM6PAk3HRd66PFk8EpnGgZZN09UkQatQEuuRlqw4RVN9185WLUsmnYC/Xo7SZK"
    "KpYTJ2whgGxYpKAGkh97i6SxdWCV2zo7aHe+CqexnG5sOZ5JDd/hzfmc9lf8Fc1FJ5dDxIaFq2jQOvkJsMR/mBOJ+x+7nJcbAWjXc77C7M9qPNK+"
    "5PqtoY0mg0+ofsgRvkyk9bX8layshILZOQb/aRdohs8nS+JLL+HoOEHvrhc3hXWko8YAEu1il9Vy0NVwdZoM4fByCi/MVyBH1qg1+ka9zaASGjqG"
    "hzSSrrKQ4i54mwfXX5OQ0+AA5Q438WmnZzt0qAc7mo/fEibC5KeUM2jKjukWM3OCw2JuvCdyodmkwqXrhGdiMuJ0zKg4ySFI/avvizAZ0BFyVajd"
    "nDj9BV9A6KD58Bb0UmcCHhRu8IisBlx2YkpsESXxiCctDaXEGuQFkOdK4qhvNNhjMD4uOu+hAC0ZLosSyxxoLz5xzVtXvL9jlApyW1m6lixymyFr"
    "rubFCV7XQTORQW631aOsr2quh3OnnZiQXoJMd3bgFKINyyTc73aRHpBP55xkWh8zMeESmEcLxyPHWV4uBUTKJwlLty1hIDFoInU548w7zg0bckeq"
    "ZwTGfK3fai3IvU5i3DkLPDKBmnok8q4rhNR4qvRLm2i4Y3BVj1qXiYfX9rCbDgWQcIvwUgxuJeiuzUXpXllD7uZ8uxe5DDCGrvG6BJ+wX9CAZYQt"
    "uaWfcGpxa89EZJLzUVgRwxWUIDbMjMIuq+nz3lMclpmPY1HRhXJOerVb79wJJyuE4ER8ltFpmru5xWZGosH0bGTMa+hC6jv4Z8PfPHnryRtP3hg+"
    "GB4M70dh0IafDY+GXw0fDw/gsf3hoydvupBow8+evA6/3x7ehX+hkXHgaMOb0NHt4f6TG8nwHjRHzT55PxkeJDSSN6m5+/gJH4sipg1vwqOvDx/B"
    "6w8TGNRtaPIrGMCbw7vDh09uRBHUeJxPfgyPPoS+4LkP8B2ac4ClBo++NbyFjz15Bzo5Gt5N4NEjmN0+Dlm6eV+GeBSBWxt+TDO7C+/j47BosGzv"
    "De8nMII3n7zz5Oe0hhUQtuGn+is8OLyV0NK8Ce+8DqM+iIOyDT+Ehm/RMzA+eGV4Lxk+prm+MTyk/l5/8i58/YAWUwHbhl/C/O7CA3dxQ5+8V4fd"
    "5m4+7tIhTeYA1vEujW3fY+LDz4O9eL8G1W34qaUnXZp9GOhPkDgChDd9Fp4CgsCm41Bvw8/pmYe8Do9oMWT9cBthBeIHbvgrHDRv05O3caWRpnhJ"
    "90MkOCF3WGXcepjpIybl2+4u1HBiWB0gImz1ybtPfi4Tv+scA9rjQM8d/jss5GOaA83LPsy0G8WRG/4G+ngD+3ryHkzsgClY1vrJT2CtoTFoDuj8"
    "kWxiPcqcNIY0dZeOzEMz+PtmpSoKIBCOkD+SjSF76usYCHQBm4GFeOxwJViKRgLEc/fJT/EzMZO3nXU7qK7bSHw6Gu8bwGTe5EMO6wRklzyFc6Vz"
    "czdh6qfNlO2/A6v9FvQDoxsPYwfjwNk8hlF9xUQNLfqT0qNxWD11R8PDMWB38PjdhFgQ7xq8PzXmnTsa3MTHzhbc5QMGbDEhbo7rfgf/eECHAHqn"
    "84Ff4ZLD0rxJ4yc+JGQwGWReOAqeWDiUBWbRt2Cit4E1A/eZDaBebPD+Nh3IkI5oX+4Rj3rE/OdUcfYmGpk/KG2czsUbSMhIWsir6YjcpsUkkQB/"
    "To3F520KHVHs/R6zbV4kOB9Iig+RoTx5fwYofbaLOGHAkb3tSBZ84hEdNm1zWtA+aPxrknB0Zhf45D8mrvCIhMhdvwWjMByeBNCPjz2dQdxf0jtw"
    "hl8TP35EDF5aXKwb0gzw/uhYs+hjPiQyACXM49qxPbmxWD2wqFbdd6lP++P9mRFE4PAT6Aw5/20+EMNDFn/cLQjjkOi59wXzNfF2ILAb+DjNMCGh"
    "htz50Ag/1a/qEQVBGv4G9JgPh7+Af381/FkCI/tFIt/+8/Aj+P6T4c+ODzLo6eikv9x+ckPP3pMPSLrASH+C8gp2zVE+kGPeRw2Q5M8D1Ithhkc4"
    "u3+kNRIWXpnoWIBCQ4NHTLxPPkjwMJKmxOMgKjhEPvETGieQai1uIS87sbt3qrrHePxC0kdQj0YafY/4M+r4YgUQmQoLsZoCLtV7FtpQdJBbqALV"
    "YxwSzTmtu4tN86Vx7FdgD0E75F6RLKum0DgoxOEv4bmfsEpKneFqwhePaMHuioV3l82lu3bSNUCJw3+d9G0Ln0gz99gDGUeEpYi/0bFmPEWg+P0K"
    "oCI+U+UUR1VwRXnQVW7oMQdlcfi/ifofWJTF4eeKsYiHxUdZhOE8ZFaJNoslWRd1kXYfV+MAd9dBX4TzfCTG4l3HJnTAGMUcVKXuKABl5MNbYZxH"
    "FYxGnXfd0xa1kUwNT710ABzBzJTz5qA4Dv8/ZAQw/fc8KEdn6Ae+74u6gNMAPMESg4PsOPyZa2NQs4LwqF1ZlEegNpAgoYdz+Osa3cR36NrpRE+1"
    "RYOEXYb9VYKyXoEDOpPviI59wwOIlL3hcy90QQNYrTWSa0Ajzelgm7vW/nOAJHm/bxuurPusqJLw+74qd3g8PYBJ+FGYTcJWGxGtAzY5/BIMxDf4"
    "GBEpBJCTsK6vA/fntlGNeVtWxwefJDq455zCCP7k8GeqgY3wpFRAKcm14VhVibpTYhCVlYcjNm4EtZJe48V/wAbNQxQEDm/BEx9iWQIlHdk3dG0V"
    "1BK3hcjpoRx1g21JhOKJRItyCSMRlcPDuhz+UknGbL+CXsIG/RTW9Ja4HKrYlxqHcxTgfQcAE3dOVQLTuEHDhF/R2r3v4WH6h9qBxRx+Qab+ew4y"
    "Jh5fWJ0D+OHHDm/xgDKJdz4SScesF+1pcdrwvAx+Jok4350TR9KkwdTqCnFETTpLHutggb0vRHfk4msK22BuQHQPS/vQrKFF3YQtij/ig3BSe0hx"
    "t80pCpA40TVY4QMVPE6lPNJWY6CcxM5JcJDFLuwkBs8JuirpS47NDsuXmGePA9YZepKVAdY7V8Whabo4HqonO3qlSVfM71ci2sN/IycSqNBCs7hv"
    "xwf9dFtZSAS9UB/yfUCopY9DAvW9WKZBs6MH7HYYjw1KXTvC22nsmDChAbuFiTVCd9ZtHCGYX6REHqFUJ+5AC3CP+MB7Sc3AjgEtSnr6vcSKXG0Q"
    "fxTj6MFx0UbRzeXzLdW51eFY3VzxljnSntokAj8tVNKqQz7RL4YP/QAM9gLyWXxWf3z9I89NZD6Sy5t8rO5EXFvxH0WtOCLv1H7ylIzn+5OAmlYc"
    "OJWldHylxsFMcrSKd1rdpUC6JH/88c2RQKhIpHfRW2+IcFokVPZK+2dBwl1v+579YOYkLE+AkVrp0NqH7Htx96/qUJ0SONXnTELU8gJqfV/biB3p"
    "qbMBUSWduuIzj0RkFpmIvhKTCTV+DOsBrTpRMFwAsXDV9hzllLdKFbvjZ4bFWhWTkRkRN2G73Oigi8GhVF3pyJuVuHrC4U8M3MoU7SmVdE5EO6k4"
    "i+KUfRJU14qnmcO66PengAwH8XAF1D/wgJRBfmlfvT3kzXuD9N/bKh6efECLc+A5UyKbHYDDgh7Lk2c3d5xhfeV7QLlhdGDbSPEDaT5Al1WLOfEN"
    "yDqg2TBoGx9THHxW4uTkHUWuWXEcBmi0pMF/lYiX1SqWYnnX4tMOf0vy5Ig0shtRHdCzt13UWoqJPpQfXWeNB2Fr9+RxmMAgprCPagsa7yNS/h5R"
    "gM+6gE+EcOuavo8k4AJDuAFjewNl0RsJ8SJlQfthCCc4TfDkDNBv40tzQFKfuMab9ce5EdIsudEfMM3QEROPsbUtD5ByyRsMUuAdu8GzQdKtmwxR"
    "vDgmUOt5RPHc15EzoNLwpoml3ja+6DtGQUMHLLMWkwpwMszdMDLnyctGqAzYWHajEv0lxvaTuJlyGvi8SKIRLhUhjGiM4TCy9Xiu/nwQfGGCYX/q"
    "B/JpAc6wP4RTgPOtmHj6SiMJjEl+cTy8b0TzNNRTVYrukEtgNpi/PoVUm1LBZLV92Io6IooLylkDArMhgwJbgpqelvNIA8hvcJJWxApE+5b1rrvI"
    "F129d9+Pg0qagu1htG90cmhhTwn0H6eklndtnIJ4H+XDPThNwOH6idXHYhfUjo2vGjsSbL+S13d8aOKaRAFWDUUruF+fLzEpaDEpqG/BGxiF5Dfi"
    "ER1U09+Rg3HvxIjGehT97AAysG/Xy8PD2UIdw1odkDpwCCtwWB3K703qoujzk6AgewabEeLqKt2v0/6+QyjJw38xjuy7EgN58l4joQ3FwD0l+gxv"
    "Ae/RhyQQ8hhW8z0yZkQEvz+8B+f/A8kvffIu/pGgYqRRaYrxfFCJncwnw188+Tlrql+TQamGCLmIMTOFKAd7eECJEqxnmdAVM3JPbWAV+w3NGwt6"
    "xDQW9SodBu6DhDzqD3SrH9vAvvDoJ2/+5SA2j9n8xpitZxF/S/j9XeNzD/2sqOwEW0AeVGyMA6smc0FyjB1PkuscPNJMDt+Ck6Qz2dAnbxkNy9KR"
    "zcKAEXzNvMlkhjSIT7lWxmGQqcGZiG6I5EDlBNMZflCfMCl0DmWy3FZ75vbJQKZDNveISb3K60j90dQXSSibBIUabMoIv+Ysakdj9dOY4wDVw0+B"
    "Bm74VjcTyFuufT4atHr46+Evh5/A/389/O3w18nwIyDa/43/fIq5TsOP4f//OvwFfPm/hp/Dpw8x/+nD4X8OP4MH/gUzoYafHBvfegZ9017gY/gg"
    "PoSJWj+D3z6B5/45oTY+g9Y/H/4qgf/8HH7/DSVrTYuSHY41HAeOWrv7JfT0S6ch+OLjkwBo07RwFX6Fffw7LcmnNNtP5N//ResQDJHS1Kp7NS26"
    "NnRA7IGkz7sUhQGVan94Z8GhWPLRoXJnmwMa5MgpGuIT4G9PkOUVx+OWF5HfvYdnNWF/TRgSPpgGp9sPmjy54SeKfy0KS+UmTI2Ovu/p6JNDe8eV"
    "u1HMIiGvyd14urV6rr4lKPBxKmMkpmaPjBuEkIiI7ochRFeMwNwOVfw8Usf1AadSSjLCCaDEgaLwvr1vEo6w+RYmMG5mhjF+nMFN5EqZDHZc7P6K"
    "onLopaTWXpGuZLLIsXowQXbJVIjlww9Fl2ZXSSg0/ZjabXX4OhTMmTozRTIf/isxLgyD3kjMhbEjoeCKaUl6RgOUHUoSgTHJ/kbz0UY6DPx3Va/z"
    "rOJvHxsddkgX4L7jxPZc0TjiO8REjmhOoZ8GzJ1fccK3R0AYQZKbQMZNZHog1/k/8pr+mCNODZOH7fBcpHSXUg/oboB7O6vh6LnMpr9yefbtaF6O"
    "khraZ+S2cENkZKF9R6Hc3QRU4fbVU33EtxC83IsjoXpzhcumwfMZuSHxPn/vG5F4r5K2lx0fpsQnoCA90lD6QZh/z8Eez0a+nYh1izKJvePDu42E"
    "sq3phEUiJu6XRMpiPX9FiRcmB8PzWjpeJMxkBQq+o4djn2d9Uvx5z0dG/Qe3KtihqmyKHGkuo2IzVi0hs2jvamu+HvUB7pmjMJ02iH2cmpgNxDkg"
    "Xg7R21eOy/rJW98xrHtOfqBLjuz3FMO7dtT1LwQTqVzaNrepG+oCfEfv5MoVbGibZjmqD5l4rHW5wODsh3PnSO6Exy4p3R1154qXb6bY+4H0TZ7m"
    "PIW4VuuH3Hz3jrcCeBgbk2tZo2H7xTNevXhPrZv0PuZsE/R2SkD/pIvGmrLOYYll25v+xG5cue5EgJ1b9LMoAMAa9xk/5jCN+j1unqdRIKDhCqC7"
    "Vik5mfyZVQGBqc7OSC0h5Ov3Ha4+Rv24O6oIwfiMRL0na/vf/z+gRsHwy3FhVz9UPVnwVdi6q4w8Ci6ALiQxL40HTOI6AfbZqvINBvZm1wU47aH4"
    "GqfxOvmUeIh3NFRyJLf9MDwlie+gT35WiXoas8PnHCZLEfE+3uWblkfQ8NvkaPO3idwIdbtk/AwObzEt3aW2vs3CC3hLkCNcjxWRhUwenhcHBPaV"
    "W5J7n/A/DgImRYEQ9xYByifviq+fT3iwyIAVdcmDYiZXx3Sgp5eVF1/7P61CDxH6DVKwvbFP4W/U0cD8xOpHo5NChJUGvTPGX2mkfF8mQYQ7XTkJ"
    "jE54V2cwPgSj/akcbF+gUDCRjtC4OhPDz/XJCm4D3199RGy8vuIEvaXwKkeJ8bWMyJEfWY1i+JHMQy7ZyuiY9F83+WKSiXR3wioVdppkYRmADFlM"
    "oePwMMR95rFqFr5t/pjCwv4VLTJ5IgUuKN3oNqvXVS/73Ui9C/JXOVE9HxgprH4R3Pi5obhIoiY/pJeqJTE0PugkeQQTImkcq5NBnN9YsJx5fIff"
    "psD6myYQF6+e4Sco3qviR0XTE0cU2PCChHJ5M6bLVpHna+4j48Lbh5+ip78fVuMIr5ScUk2OIKeNumg4MEOVPqr3LbBHGz14QBv2WLGNbBoJodnA"
    "yvFA6m6Sya1pt6gHCi97yBwApOSpq8tXVq6unVtaW/r+bOt9+P5nj1IWAlAI9hKq97LiA3MjQ5wxSDrKMQuDRF1qSs0wJo+915KoWzNk+DlR9Zs4"
    "RPqFnjlB5ZBKg9PhyTht00iOXVRkinGYfNCRozhuwZGwLYm9sa6AYELmfditt2n7DPDa7KqPaG4T6sb30MX6+Z9xDZK/I05n+mxEPEpsfmCC20Pa"
    "PLrgVjEx5LEH5oCCiRGeCzc/Ek2hrxpedBRPFd0IvU+uZyTbD4e/boyL7bIlfGOy0iYVUDb7jtv2fREg++OLnggdv+QvZE3hEwWmI/b9FqLYsDrD"
    "s6NqGsCEkdd9bbMBvkYjnp500OSNA1CSAPAEviuPsW5nPNv+zaD70s2HXsGUCAJTff2U4Scm3cmroALH3y2gkpClccsmvN3l5CrrnoiEheYxgePA"
    "2ppineiVdFYFD1QcMKEcGHv7AYMfuD9HCrFULrgENB+pwyJ3jNTDyxsX1mWpEBcWCjnjCdIaAvZpwCvUgtCeDKTlX4fE1UG/xlNuimOFGtBYEp6L"
    "VhMqrPuxqi5yezaMwHnm+zxm9LAVI5A6Qm6PdYTWtJHR2QowhAZQuYFjnZpRHx2aLF/ZvDwpEcNjVSSD2zLSWNIsH4KKM9zm6Ac1ZYDfuBP727/G"
    "lB8FBtqHF99mX4nA6oj7hlC6yDRwE+YJc0lSXb9iw0G0cnN5zKQQIciXX5NGMFJlIxi80TF5naSk2PGG9TSkRurVA3T4MMcIaNItYFO5SBd6GSo3"
    "HYKqNvHLrbyXj8e0DdTlMMfQc4FfPLb+Cv8EGX9FYhFJNBX05xrIfMPz9tJlDGjlfXyXk0TDkjkEZWPg/47E8eDeERO68yc2jwl3Mlw6Dswr2J0M"
    "f9KdT4b+QQPPHRS28Eigypx6O3R0HDyVCKOxMGDuhcZ9rwIPLG8wAgEvMBtqFhJlb6w2D7GrryQCXL1ySuk46sEcWamH0UNQxFFe07vsRHh94gHG"
    "K/pUYZ/NIYhwAKfWDyGpWDFLXEbzTdBDZwwudJ4QOCzt1JFTD2j0pVK/QpA8+18XIgfs7eo9URvnu6/3LKh+kJvvSmF4toCQGn/qBAOdYIYpK9SI"
    "p/hylvxDa4k5bXHivTdeZCqPqock1CWevE91iapgmzGFyy1VFDuB3gK7J9AOilQI4pi+uLYZMM79pYi6y/dVncpGiJ3kK0duAlWwhQuR62CTpXbF"
    "osAiPsIR3lc7H6nhfUnHAAomWq27nkSc6XDeFFZCCDkYgI2d8x2Fr0mDNBqeKbVU2T8Ti/Z1eKOWBdK7Uopp+AtJGxElMg5h7OkGqnBMrE5WdQh2"
    "q31ViZrfifgCOaYh9whssq9N8lDZqsWffAbpqutGFQ6utqgNcNfcQa5En++PrxUVKC727oM5z2RvGRAZvRJBYxEkMbeSFOJWxUYZil3JiybcboyC"
    "qVSLrO99T4hzQ3cpUEHJayIwbyQVbwVbmg85T0wxnCl0/xb7h038ySlVpfADlXJVjGfmEtPRCMU0hgckm/+Q4gp6tYTVw5+zHl5DS45WJmvk+ZWc"
    "+GFQBcvLFT3Qy4QVra8eP4gUI4vEoUATGtY7UOXBOpF9sWsNVVenlEaqKlvNjEylraomwrvAx/lA+ccDVY580nFbTabCZODdpJ9toKvBITnNtfHS"
    "pw8iQCACHLKPdGLDEyKJHvGFInFg8/m4W1PQi9IvGSL2vYqrZLEW/XYcjFMjzIatpLzwBMICAkYMCMcI8qTiOYKeF5a8P25eXSy5doLyYQEWiKKi"
    "jcxllK3luxDqKg5QCOj8uakdwnP1ajmZlQ/U94J8TSxnEpzRoLYDORGGs8fUIQOOV+2oBobFQCscGiA2DQ7V+KgrNS8WuXzILY5fhQzirnXMsjuU"
    "7tD91IzAGZS8EClvpjOKFEpxQx/v+b4bjhWy0MZZMDXOOxdqYt4Sp3VKP/15BKxKVBIVG3S8b/shlbvVEmnfGflQc63gV+OVTM28qwASi57qB6id"
    "5Py7DbtRNrHchfLDAx8khKHA1tPiwMbQmaqQVYVDe5n/fqzoK3EP4ubf9i7KSKzLJjewBYH3gBzyeORIPYa34R+rleHcIjcOlIKD5hZnUmFK0D5q"
    "YEGqoQNlwYmGFD3wjor+4i4sND/uSId+R/9Qu6Ofr0cnVofiO7TqD/X8PZ4Amfwg8IQ1wtuvJu8zRAtKLBAwJzMG+Ir+dQMMOyjwQXDtuuGlpeFI"
    "RXA/qgM8X7T2pplIgK6ujcCDt+X+8KH7OJZB8hvhSyU+UHRQwce1w+oE8KiToano77hpEpPeipEz5NuKdjg+/xVb2sOx4AX1qhZIEnzg0z30qq3Q"
    "F9FaK0eY+xssAOlLb4wuyRcBj3QV5zgw3gRKVZSrhaYlTkaCziBZ4vzNphv7oGqx7OcpmGH97rqQBNJDIpc5vAsPVT0xKBxoxPtR5C6+x7nN1XYC"
    "9Ef7mB5TE53oAxPWPNVxRDbipPmH4VbT/L42ot/2zZXbJj+90fAEaxOvU7qSJYDqXbJoWa1JgNVrnNxJtUjFguXTb7h5fEbLUvzDg5rYaaA9Ce2O"
    "rvsV8cyOAfB0lO39xI1dvmPdWCZBDZ9eVMycGA7mG5VJqA7+UFlNIDAFPtECOvBg1GEYQn9EZuwDhpD0eyOaOJnEyriMrF0UO4LvO2Yx1nNRs9hS"
    "AJtYQWJvLeU4CyQuMw+AHr6qKfBI7iAPp0KyJX2wdEIjNQCAXlG6iBQ9qIbs8A678bXdrWJ+cjXI/rZbDfK3QqcfEyN4X/JvYjUhn9w0tPkWC0u/"
    "KqSw5NtPbk5YF9LkEiZITAErwK/Yur+ZCEoiuSelSMqTjyerE0mDfgD/vT2yRiQ88BA6EunKvcgk9d14xUiY7DsCMm158GT1IQ84XRTXK14b8mP+"
    "Tcgxgc9iTcCnD+pqQ6KfFHfAGid3SO/kugZeQchfeFC4B/UFIe3Oi2kMHYhpTOmevgJBTx8RWP/YQpAHpgykLHOsDGRN8cfP2N1FaTWPKGNPvZtf"
    "y8ylGkPkQH4sweG7CsrAAQZHp4Tx3K+WgiRF8Yi74NfqRNTHyIEpkxAd8jfH1Xz8F+n1A2iZbGRrovPC1FV9xETmB5Jv8CYyqZvQzo+p60N0B8BW"
    "fawURMYEkKw4Gw+8fOVxFSGxI+bZN0W039Wk+QNxmDxiFyKrED8ZUSBSC1sSfRMJHatAZMBxiEdYJnUTAelZRp2Bvh6pes/QVfsJE46suV9pU9Z8"
    "dMVIInQOuOCJSJ4yBSJpYe+6Gfnjy0PKucEV5k/7Tz7y5iMlJUhixQ7h+NqQtz39cvrakHYsDePP/OPr/2xy2JQJan1IL6P2rlch0rqApqgK6bIh"
    "r9glEwDFs6Qq5FcmajnzmpB0fNi4dyWiiQiTwNFLIgLFbQqCHH7LZSJrBxsbpy0WiaKGY0Rc+o5AE5CPHOKBJf3rGMUiq8e1OopHpijbbadw5I1Z"
    "FI4c1VmEkpzEX2QHyMLJKU8H87jFJM2zLgYSMcH3gyqScrsEfjxhIclPJN9asgVuOpkcjhhzikm6ieCzLCOpisEhBz3l2t89IjDmpWod3lhMQu7K"
    "oHPhJlFDlkQZZIoO2yG0/YwBzZlZZUnefeOueagWMt0wpLNBtfxYcX1rQT4Z1guz+YhszjfEMZaQn/grwot5pA48/OUWXbnaZye5Eakjy01ioclf"
    "gAL4tldwEkHMPoPv/udJy006kkhMD2X+fIWWk0s8tQrPjFSbpJyYxDGCDhOQvO/bSwHOhCerNRlmCiGyDRtVX/PVwNukCr8unJdBM2ASbvWZt8YX"
    "n2RVKabqTFGEEro9Yuf1Y3VwhcqnutOZZwtB72vih1+OEjWwEeUov2Bns4mG3KaF/QlpFrJVkvE9oh5laG5NUI/yU1qfO6iBqiXHxhvVlWRLCUmC"
    "LXR84uaYWpR17wQVKC1ncapP0oNSe/Jf0eNcV32yyvrr6k96ClRQffLXvGFO9cmPTfXJjyrVJ/+VtSee0FSVJ8lSfR9NWuc1r+4k+YQ+MtVEb9dU"
    "oIxKgngFyhqxERSg/JgI8w7XStRT+jnpqOrBEANWHAjmGIUVKR0LaUxFys+Mumz9kI+idSkV5PTgGFUpv1AJg5RoVKAg6vOZuPzEEHOKUGK6xh3Z"
    "r9cjpSidBp0ylB95FL9aY5CPKj15D5vmWE3VAHWLTn5qL/n41SY/DmGz/HqTb0s+padqUtoYcjops3IQ1KD8xaQ1KKHBe2LBxmpQsqfeObK1VShR"
    "fXO8M2LcBZUnf+Gaawq7+1a07qT/aGBUu3c2WdmuK0NJlHJjeAdN9ntBAUpmedaQrtai/KnWqpB1dqtRfkbefgm3R+pR3ibOiuToVqMkKvcrUX5s"
    "KcivQ/mZ6HEPJ6xESRr0W24lytAD41eirLRv61F+OtqH4ZenFIbhlqdEFWCSopR1JSk/CtxLYwpS1usP/g7X1Kj8vFZjoLHek1yMunqV9wgY+sDZ"
    "QqdS5ceVH8MalYqQOqJK5YdqVY2pU+nR5MwqVXpM54SVKn1XC59ADaodnLwgJdowlG17QI7FWBFK1Ja0cOrNkxShxB/dlmgE91g+O0MeWXnSr/Hm"
    "tBIiKU5QfJLaelyV1WAzHL/+JDUaeDRR7/fHHLjQHmqgiNwZgT1gDJtwlMcoRln/1AwqT970YuuysRI/Y+MSbSFnIbju5OlWnVS/P9l8fI3QGQNX"
    "mzzyq00aP5NTWPeRaxUaIepZi55rFX6bst5kxNfDDuG4C9Yk+rxNmthkRSeDkpPJyJqT1DvqXzOoOek4SatebjbsogbPyepOVlc0dNdi8pbAd3gW"
    "YgDILABxxytESQeetCmD+BWEd2/OuBBl4J4nB9SPSSG7o4G1RQrKsr6VaG6KV/uN/AO3KYeOVu5eEmn40NGkZl5+0o0ahhEH4pOicB44CueiqTYZ"
    "GBcNJOWjOFvCuYXTmLgMJQtJT6MUGjegFoHjLE7qJytEWfFiS/TYlKKkiBsfac0NveMavHV7TuKLVr9mv8MKlNb1YVmWKvbvWyAB1iRq60veC3T8"
    "eH3JMX150YWaMpOhxr+f2AwkcwFGrb1JCk4+GltwkpJdbiPZvktu1qOqGehXmeQ8AFTTHP9KXY3JakJEvMrkx8bk+qm4stm7OIMqk6zimFTce3zF"
    "32xqwtBGJmsY2eF9U0UnOOmP9JLdQ7lYJFVXZlt90gtDUU7i25xSFzvBDbxx9UCNvFviSr2T2IQmXfmZF5b0w2W38LaNhvIct4M8aPz8RKKW2XDO"
    "1tvk2H/IKhkn674VOPVPUmXSd8x7wrBRFf+StMU/BnFk4Vo/idsip1JpklwfzE5uUfKFREBCOpyCFP58ykzSleGxZSYpHHv6ZSbtI76w1udMFtrB"
    "+AKThkTChAtVpFXhIWEwm9KSIUnUFJeMCFcmsiA2xSK2QnmnUGCSahff93FORXsRDH/J7DpQuR1aEwcW5fSogkS6GKg5fOsmnhwsJ3k2hSVZTL5l"
    "cqXr0hxOp76kDWsfqSEaTNSLDHsB2uiSPflYnAcCLmJKfhzRbTRN1qdc6hMUnbSmLGXy1OQXkD/C6gxq+brpGPyFiXaT6jFRPcpqDKkuL4Dozlav"
    "xDWlHhqjXjhp3UqOI6EpYiSklb/k8X3ApU40S74idA85nfRIst5lpTnr/W2SdDdnVNySku1ukhhVxwyNkAnnoDpcp94lb8Ik9S7rFtstd1KrjX6X"
    "ql5+plFRyahT2H4tfsg55Jw5SOFRwlPDRdcSiAek00g6wpOPOLOCGK1b8RLzZ40kvk1pzwZCZnQsZz4ZvkN5UIIZtS/7TVzkBqc54D24n8r1Fzw1"
    "DdVm+NYE0csDCxhyL0LuxxnaIt/NvB/wfknT/AmxNKSVjxSo4sDk1HB6wl9QBc3xhNQYSUSqxVD2Gf/4OB5pHr8vLkU6RTU5H+ZIzOiPKEmX72BK"
    "J7fNFRWgoEoRTUt1H4SehTdpQ29JOU3Cd7gxvNOgJPsbrOWId7iaaxIW1KRAEwpGylS76RTUvC1Gjb3SoOU0UU6ctJzmWMYqKYJV7hrkjU1YXvPj"
    "ShYaufLEcovbbfUVNtFZggv/E3WTJMR9jiQaPrqu5tvw+tvw78+odiN8RhhHrM746fCfhr+UipG22OXbww/5gV/BV59QEctPT1Jacwbd0z5gztlH"
    "VH4T89I+Gt7EOpJc7PLnmKKGjfyM6k7+2/HqaupApa6mP4KwruZv3ZIQJ62q+bZU1fwlVtXEP96GHj6h/9qamsdZRym9Ge7l1KU3P+HYMzEz1RNI"
    "IXoQTTx1im++qwUL7okffcL6myxBxD8cD1jXVeGkgd1hG4JDcLdHtELHbvJ6nG5Y6WYlK9/wPT+LwDdtbh+nBCeh+b45IrmYvDFf+Rjf0zqOvrWC"
    "nMqNpSBnqIJ/FUo856wF5Tgpp4esmiBoYEQXzP+WTSgNbhlwktQJKnLC4LCQhvVs1Zf1QDG2MIHhN7OCnMcY20Q+pwnrcbInTlUedo846br1kBlV"
    "v/6YgOj0NTg/4isdmk5TE3CSZFe6oEX3Pd8X2qyoE3rqHsnV6Nc50+t0inRGSnSG9hzmhduw2b53Wyk4JxW3i1ohNjWVuJnj9Tf56H+C2py2ysX9"
    "wMkvDlyNV4yqz0l2179F6nOyOSNmj1eX820F5eGqnOo61mdvRxOIvJKaId9GF+HBX0RJzf3h1/V1NTl2aXJLqikRYluLXK3cn27UXlpzc/+r/n3E"
    "WPNycL6n98rwBKhNbUpoctXFA4GHeID94ibzEaqEBPzsu9vi66MSZk5aiRdXtjhXxDx+qhQ8qwKa92qCgrLkPs9wcmLc2637yjN8+76q9bgJkqda"
    "OTOeQvNI8Liq9TI9//t3rlqmFJiZvFpm/QuRapn+lahIlUwM+vLMRrXrVMj0W0z0DMkFcfZyuEBdBqF034eht4rqyCtlMKrTLpcZhiTcQpnViA+D"
    "Yeg9QALJGav0jC+MKS57p+X98c2eUgVM0v7GVsDkcXLah9GFmO242GxeKH5GNTBFyfXjHuPU3HGzO6W6l37GtrndfFyRcSo1L+sPQL3stvyYpUN9"
    "nUuWS6QOSPbjVHUuK1UuPTX1/4gql7OO/bJnOnbVdITUj97WV8N91OGzpSxJlTvUP9zgmg8pxcYUwT5XAqyse/vHvzbiykUoaSJBygiuwIiClmqn"
    "O0xD23ryEYVyv/2Clowp9JaJFOzLzFgtDgpaviUI8lbSkw3oFLP0c47CjMQDc3vapB+qo4szNoJxYOhh1D3RUytj+ensnHOLSQX1QF/ft1f29s1x"
    "0QKVLPSmLlHpFqjkuAvp8YoYZ7n/8QpUxsAZYAWMyTC6UKViHrHJemTA9vwE+8PghsDoYpVv44wwjmHmYzwP9gISK/DTlamkSJwidjwyGUVK3CPd"
    "yeMLVN6r4AGR8lVfnvLu6B6rJSptyXrC3nEQmj6OFqnk4+YWplSxWleY0iBu+Kbf6KKUZAy6V8XsjeDxhSkpLU0vIx64LigXvqpanJKBfEYUp7Sl"
    "KTHLt6pgxgpT1loXUxSmPNWylM41By1KKcBGlfbZk+HnY1aKUkJ7unchgI5TlFJvkxH1xMpQ8qYJwNK3UoDSMBSlhgXXk4Muznj1SfIZuaAjyGdO"
    "Wn0ydotBK08e1FLen6Te5JTQM6dedzI2HjRvnLjE6NHMsP4k4TkKOpFXfdJeWZh1/Umc33e5/mQVJCesP8lSlgyC71nwLvWI1noAIuUn2ftoAoKq"
    "lJkbiFR/sj4W+uSGhcOZtP6kr+xCJ6MrUB5NVoFSqHniKpR883p0FUoEL+HDQhaAXCpBM88tbOO71hgRwDwolSitv8G/I6S1KH8b1KJ0ArT3x9Wi"
    "/CzIGPIrUqI/wa9JuR+vSHlQG1VBMFfCcTmyFSmJRFSNuM1ua3t19aZXj01qEXKQzLVJolUpnQsxUbio49emrNz74kqAVsbWEPio2pT/Ez2vglVk"
    "9jVWm3K/SiFvcT5kUJ3yYER1ymo4y7HJYYo/462V6pRCgmjW0BjFqonVpvzQ8eJXKlNGvGhHUnz7MKhJyZBaB1yZjG3mmzU1KWsyYusqUspkqCKl"
    "aOlSkZKyNjWq7NWiPLC1KAnyEsZzX2tREmauFPEh8+WevEQR27AWJdWuoninOdWSuy7HpnKooxUokUR9qhtTfTJ0DMQuQdyP1qCM3GuNVKAM26ca"
    "lIY1uk4Hqj/kuBrCU2KdDQkjZyQ6UPfqqOt5lQqU3xtTgNLACB4p5pouwB2nMmCs/CQmCdcXnyTO6I7nNvG8WPnJz4kXuoBeMW5yvBKUzp7GIABi"
    "RSjFv/IWVt25Gbt3SqWwhM2PK0NJhqaaipTo+PoUQ6wrQ1lz6pMROFRuKcpA2mo5yncJnF7NLGUxum+TFKN8VF+MMvYsV6isHEJSXuWWqWb4hhUq"
    "b0qFSska3RcL6Sv1aNU5TcMg4H6kZqWXvrVvtlrtuDfNXeX9JIbZ6edI3BI5FDYrJStrXvewPSslK6tn1itZ6UDfWzVQilaS8MI6C6ZopSR8OA7n"
    "mF4QLVkZZBxVdnKhyk/H5j7ZQCy77wVlxoe0ZIufBK5bnFJTIzQ7yPX/k8oJCv3Y8pRHmPwRpok7RSorO2bLVFo130WxdIR5tUTl/5aUDC1RWUH1"
    "DBSE+/EClQcjcnZcZcKUTgwyKX3XmTCuB2QQqWrg3IuulKUMWWZVfyd8fwMdrxPhBbpvlXc3IDxxUUqrNZiilHJkuSilueSOMRunJCXne5mSlB/y"
    "9pkxkpffNV6qa8vygRWlm2g61i3nr0Rg3jAmocCkHzhZeCKxNe2H3D4SiXTpSS/I8oJbFjlZecpPq8R0u1Y7rVEwwwN56AZpOGvAyOu6aHBYgvIT"
    "lu6ciah6RQ0eyn0vD3Q+0QxLSZczW3ZgsdiRj/jQIgcGgkJCdWxWHYlQfmCZyb6FEnPLUKo8IS0X/vBLUEpcM1KVW6tvvcU5ESSLcJU+sFrgB/5S"
    "oQFrjjwFplDZFdkXRiR9EE7J+mJfp5Ml7NwYrIX7wTdN7EFWjO7avGvSISynGlWEkgAMAhzfSIbbYhQfdzS4U6Qapa1oYcBPvLIF4um013G/osXm"
    "GkY2dYlZSE2Vygqwb3idePQFVST/iQpVOr5zUwEuyGWrQBTgDjlFKO97lXHMbTsuvqxnqFGvMdV5u0aFsN1E1rpWj8TgxUsR42tZhgOOJ9JpwR2F"
    "cGtUsoVNgt3EpQNuLvJZ+erJ+2coTXbfQsLsJ4HfV+XgT/l006GuRYWJ17jUmfrZCc7dVVcW+IFus9V6bU3C14tetcuq/8X01Iijn8g5Mj9xTsbb"
    "nG7qV4lgxh6UvPxzkjmTl7X0lNKgkuW+eHs4ScHJRGULb1/OPRW05L3g8M5jD+QxTC2hduUE+aUsBTrYTVJ0a9MThrSbH+8VsZTMDj9v+ZEYJxKT"
    "lziCkZWOzRNg5DIfF9iboH6JKchzGEDDkcQSDiZajWiX1LB7zz+SDihuXkdPVLgwpg1nGV0UlNuM8OPI23FH2Tgra46yN5+wquVvVU34Sool/f4/"
    "Q8zj3z/kuXNlOAXIcQW7d+GYZVg9Jrot++RcEGvEb64K8qNl4LSuFmPHrYlZh/KoiysVMXWXbwcQco2wkgopErAaj6LpA2pOP7n5+4eLASlKmqyP"
    "X2dPlOPLuaF1y6J3kKW8T6XtMXUzKQrPLF7rBSFtjFcSRlxfiYiDSS6waKFyny9UJbCTez2FC0TucFn/sVu8QRHuXA0Rvwrq1iCDqVZWeVsNI/7Z"
    "WOrEryMVOKca9phKnRZw0/evVesGjVc0o8zata0ZVeMNQQOmzlzGfdOgFsa88kHa9dR8vkozt60/4zCSx85pX+4VqEr6e7U+J4da7o44Z/olR4e/"
    "9gxXXh4iFAZWOLL4iE7xTlZYRuDzjM+urGSNPq64Yd3eEgM0OR3ziHNaajwRTk0YBGHpPt8OqC2PVrm+V11cBzdSsqFEnDVGRBBkphbifIGu+2gy"
    "s5TyfGygrW3Go9lLKb/jApjWxq3JejXunyMHDcEt2ajSyTmkgZbrI6U6JeujToIYQO6bzj1Afza8vh6Gji3GerToro+LVRrl80H5mionc5RTY69U"
    "QLnwv4cG+P7IqkVBzVFiMRVK8fQ6MxOSzOai2GPJgI0ltNryoiIDvLoONkmU3QTVizOejfqBPYMmoufMYnqsKdNUHO24rsbohwEgxyNTYxRBrj00"
    "cMsQFGP/oApkWL1v7uUR+urJm2HxPe/X1wVg+7CK/8olSbPSKUm6XO6kg1tFK1qG9Nm82047vcwtPYrlDbrFerqRFyAdx5Udfa6b4qODO50k6yTN"
    "vIuJN8keFlbcKRC/f7coo7VFz+VpNy8STMsBiZ5v0mPVkqJXsi7jssOD/bKP75TV+qFXuv1sPU12Bg/w6zRSMfR851rRJcycVittFrEKofoI9MSZ"
    "qXnaitcFXcXPPOlm1kp287LoOqVAl1uUQUcDjbpqaNnpVYKizOH3wtNH1nhJamp+cnkIXDv8rVcEhT758w6NL17s86p8znEQSStNrvUzoYLqUeCv"
    "6Em8PrtO0/IKefIf2l9MQF3NNrEYZlHyNfT8OmxBWXVonE2bWUd6khfqanWey3f7rc1UNwEnsYGTSEcW3lxq0l/yljyWN9OKcQo73Cpoh3KmiuMV"
    "1bRnSYaJYdlU4Uj3aNTROY+sldkp9LcseYq/lh7wLMMJ6Y4vkIk68AZmK28UcHJdQuQx0hEZVQQTc6zR65Zk5Q6QBQaym8XUZTCpL8zopVVopnjl"
    "t59008GX1ycuZcmniZIzebWbKTwzuAVNzqZepXmjWZg9xP64ciJ8CQcogwnij6daizI6EDMK2EVtCjjDTn/wu1JORht4B42ul2ftnWL6apPX0lZr"
    "cIfINaRofp3+nEFZSac1f0fpxa10z76cEd3yu8WxKkfiAVpIshezjX4vdd9I9vDyM+I15J0+j6ZxkqqRZ3XfzKrp+3qOF3kYGzOqENnLd4hCNsKO"
    "sdpMAee+WERM7AphOCPT7BRijrOo+HiZ94+6LJ0+tWHaDmiwBb9uFV34L2z9RtbMWMh2s1bxonzaKHZylOLd+gqOzy5dvLiSLF9OLi4l+sTZ84N/"
    "unz8oo0XYUjMv0Hidzb6rbSTgDySFzdBN2miWCOOiieFLinAPBHhKBz02IKMUmQKtwRRQ2jig8/b6yDu+WFUz5hLx0supq6og0c2WJsZX2PxsjJ2"
    "kUfIWpB9DR7o40Qn0gq1b2sqorYJI8PDuQ7rs1HUF1a8PHjQzlAl6JghNUW3cMsoXoR/iEQDjXJk8UQs/NZCrbE3+N0G/FiUpu4GqbRrE73jlUY8"
    "Z8+OVkW8XJiaiKuDLysFEVedU9StFkE063wNVqyV93gznSKI55t50U5tCcRzmZZAXPLrH+JH1b5M0cNLBa6UU+wQdC1UkAq/xOFVs8lBSUP5zD/4"
    "RQxxYvI3TcxWLTwrWgWqlqVTuHDwBlMu3o7aaSk/cmoVikpbepUKrzoKkeNbupR1yvTFrPTLEp4l7a+09QilSVuOcA2YYujBvRRwI99Lf7YAwkXl"
    "15YfvJTuDR6UePjLBOtHdPQvpxIh/JuWXvlBpa2g9CBpLjU1B63KjIx6I4UFpIVwKg2utOE0NAunxODa4Mtev1V4dQUvz//+AckCIAy/eCB/RJZU"
    "LRyof+pG+fUCl1vpekGcYYdejhQLtEYK8HG0zspKlcBlV3VtMkxqrERg+Jyr60dqAS7zp0IeRf6ZbaZh2b+1dL2VdQtdmdKp+HceTn9e+JX+lB/b"
    "Cn/PF0wXpgjIpaIpyplT24//HVXSr2m1GKei33MiTtw6fs8CDfF+2wJ+Z3UhtFIf/2vL9OnJStr9Fspq/Dao13cFmuKFYIQqt0Dfs2oZxgvzLcWl"
    "TLz8Hq+rbIsrP9xSe8vYTr9MveJ6cH6yDk/dL6onf7V3+MegnB7zbPiLF7JSRo8GxAo8nudYGb1nUWaQvVpXPu+HqigV3ZPVzGMnhugYTeZKJ6yT"
    "tzv4XCjGz5F4nq3Wph5YJv/jV8fTVvB3VwZMUx3PmL/4M1qE6xku+6QF8doiFU5YAo8ZCz6L8DAiAUFsl/RYQWvWtgLoeHXsCvpI4v24ZewuwlB2"
    "8NyWzsFN1Krv4FaD2kTaMi8rvY4G6inVrFtuqSMPtOPC7xlbdU5YgwAeyFGRAEcZPEDGVNjnWWdOE8+1MVVVOnsmk70kdHWgC7CIlp7bCRhh0kHZ"
    "ObLY3B5/Mfi8PFalOX6UDfk99QUZq7coT1ZKbpX0S9scufqM79Gst7YzZaU4e2DJ78FPslXeJOfuzKrDOf5WVIZY8VxM6FpshyUDzSgTx6so1lwK"
    "BectOy9sSo/1/CyrvgU+4V6gXmif5aKzbtQ+/PtSP3OOrj/YaUq60X533A3PWvyWo2SI21GsU8+cPmE1t6vwbmlWAJvo8gnE/oBnohc56+i28FoF"
    "O+OQYlCfDUV7N9tJSaxk1sKuFmNTzbPt6mPROmyRNq+JSh4pubamf/DIxeBPg/JqZwd3msgEmwiP1GLfcn1RNfqFIy2oPjGXtPqyW05NPkOXYRG1"
    "s2Yvr9l4Tlg3DdVVxUg5Uam0Zbtb5JID4XitiydQ11um08xKWAMkbZ/IkhYfwMGdGZRCu+j4WcSXXNaStw6miXIKqIECUMQnOuJ+mE3ds+qggLlA"
    "E4M7iN+C+0N2CTn8HJtGRyoHw/h605OVNHuWXVZugKHhRB1YAjnu/z3lGK5ueArVyhrqKNvqY0wOZMZm3iOPzJSb9udToQwnFHZIp7rfCff7WyxQ"
    "5my7PuTs7JjaZOLwtERhJO7MSpGNbCUqynE5A6ox5JCeQs2xZfTgqk/dYX4UIcg6WUQTbxotaNE4Aa1m5HhF5qeqIIZqv9UfIs8PvgQFIDBnZ18v"
    "7Pl0z5QJk3mQYRSEEzS6AQtMOkl/8Lv1FIfGB0V7OEH9Lzeo4HQs75I2intndamJanpdBanMM+LH1dmJX+4gnZ6wKNfFkNkDkXMYCkQEa9DXWv0X"
    "OTsCEyzgoxv7m0W5rfbgyw5aXRv99g76COgNSraYpIiWL99Qotk1+m6VycITRcOE9copBNHgqA6OeY8+bnb7OxSngOm1ONiFMZeMGREMNrPabJvC"
    "JMjze0Uzta7K+WS1aBE32+ln5ENoogsCJSSGuiriH2kvFZ7it4QUPficYNCQ3S1qfEmMOayqsc7HId/YKjRk85dTjmrUhjWi+8W7CES9k6MfVB1F"
    "ricZ1hjIOOloTEri5mgqIMJ/n7xZDTr8sIuokuDPWVM8n51sIytBDiWI6tUivAI3fEbPFzLVPUpyKJrq2aep0DThFJYnK/XE8pKONClNesjhvWtp"
    "q5d2JivgtOypKrV6aW3JJteqoaUBmUf2zIhaTVeX/+6F86vn11ZWk0uDf4TH4MO55eTK1ReWn1lKzr5w6crF8+dWVo9djGl1mRtZTpYvag/JlaWr"
    "S8nFpVXpZhWbuHJ15ezy6gp2jlWTrpy/yIHj5Ozy1TWKI59bOUaNJe1SZ5I8v7S6toSDubr83PnVtasrzpvQ9wmKKq2uXFxJ5K1zS+fwjcsrSXQB"
    "zKrrUshKHKNOEpikfYrhA/sri4VkFxQ0RAHUBIuu0wTK//HFkK5k3cGXdFCCeHO8+NHFdBP4cSmGfPD8xEWOliMOSXFEoj9FdCwQJhvZcUoZLb3U"
    "H3zp67XiqkGDs2onjDQKv416RTJO1RIcphJxMZvOrEdwkTif1VmN6zfDb4F7YCYiCVJJqtAdO0FdomXPp4QILM2Y6r0wWgedWSmiKYYzmVE5ugaR"
    "JI/Si2Wf5Z51lsWvNIYhQN+8nq6+kI1cc5YLyn/K222QIATax4zKlNSkHimRTCEcV0QJzQRWzryI0Auwo1l3A/2yqq4a2ex4ZTuoFMAaUlKzMarE"
    "P0iJfnhO9BB+uyWAXuigQgKMoqlOJvZDrtNJdMJmlsTmk7/r54PfdbR31CD15Qxdf6Rp0ubTOHJeFFIrd53gJqadku6qTKv7Ha3f4xvRho3tVM+A"
    "65Lvky3pL60JEAY5X36SmlH9TdpYmVdcWi3Mgur1dwtK4i1N4piwDUxIBGVyV5I6C2S3QBtp66Slc1y/sMm442PZd49LFxj2TiFperGw3UyK4Sz7"
    "vr9KM14sr+o7RLpFM89Lqfou1cBxHSOVEfKPwQD7HbVonLsUSSsbfMl5ejROfVOGSRHQ0n3eSfwsSBgHmaM2G9Q6L2dah8YNJraSp5HATIMNIUZt"
    "1MomdscQnY6SeaOrzmhy4+g2TqnEDO9MrC2as2EpObKKnt7XqIvezaKmzBTaythJnEYpGb6FgrrodIxyVgVjfOkxllob1chuRdAo20KSK7qS2Ts/"
    "qj6MSR71XrF5utWMrr/02jDH8NF38ko2+gLuT9X+I48beW/IBup4Vo89E3ylKy/b+AonQlsPriwBxQHKzDtgLMxg6XfEaeKvy96oVQmOIVq+EqD+"
    "dkuzUHY8KsfiPMP0pPWWDQdnnCxPRxH+LDNWd0DHLTpephuvbrvgTA7mdzoemtiimM+0rR1R15E3RjptohLAQZbTKLoyvbNgsRqroF4cy56M56lq"
    "qODag+nQp0xFmfq1Pq0s3mvposlQ6nXAUWVTVvkxvVNkFMO2JIHW10lJ12Ene3o2IrphfTmUFfKA4whp4AStLwm4k1Q/WTUv4pWvnAI3NsoeuIFi"
    "RU6uOr6JLmWgZJ14WRO3Mee6a6SUCUr7flc4gnubNKxhkm6YdAk4nPhjtH4JeoqzXg6CgnUAM8pY1RL+KJ1vIvdR7SBWn8RcMAmj1HxVNh1RhWSJ"
    "/rBJT74yUsWGZ3z9posJH1QZcXMGT6nGiJcDJzVG5JPbsns5E3tgMxHjNHg5EZp4UY4qd1PCkZJs27JSQ+ScRHLMbdJTrCDSDEQTn6UFtT197ZG1"
    "ukaQjrJHaWPY7PHqhTDPbmbQjwbGJDRYTyVurZBlNrPxO13fExQKcVpzbxQW5kYhvC0vm93MQh342GVBTtz7SUqAnI20zXdG6LJo8DZrNrMr/ZHx"
    "O8waVlf+jOt+aK+mL5dFOT4widgBv35FDoqcKvwprTXMFpPU8fpzJkTGDrsNyRYkh5tmAEA7P7w0WQWPZ+sv5joZReNqdggpvlRlz/GSHXTDJt/k"
    "MCZOgyoePJ/CN81iHZMxEZwBdt6B9gW9pQsyqdfN5AWbvlwW6/Dt4Het+WS54xXf4CXJRlTcWM1MFMEvtoHKsFdrgwbq+jORQw8+7+XQLZtTmNma"
    "wlKCXVBmdFk27cKUOuLoDSpk+HmQbI3Z5iOVMS5maaUQhpoE3cQRDliUwF7x3fCX2St5cbXfY57qredT7KaV9ea2dahEibGqFgv2riLb07SnK3hj"
    "Aa9+Xd9g4dcX/QOli1e24nnxxDn+CTHUU9KrykwSuJ6S7prZiynl/5sUktK9VxiUnjhvh/G3f42mK6hQGcaQtrJXgD43cgr1L1KCRdYFJkepP2SD"
    "YQJA01yX8KtJrOpVWjLZvVVk06CD6kFHfGJpdwf1L6CPfsfbLbdyxFVH+Hp2i7kiHNSIqH/BJLsrhRrewfYichgMeOJxHHyJdk5yMXZ7mjcUj8lO"
    "EdZ1uCxJKbAzPL6ua9zOJ2ehD0nhxbIHAj1A9zN20erqpGGJhrP0Gc8AjCaYkWWBrazHGcCmHgM7VqQTshB5QKRqx2ovvEhejjSgfpJio+osrGbG"
    "g9iR0I/pVAE0sjJeTeHZKK06FROu9FswcK7CQmlAYNh1OVIiJQ5iCeJ+EYTKE1j6YMOD5WHNThPC0TMEYp4I4K+CLBAiXM7HIJLCACIZxeK1k3oG"
    "icPFdoomqQgat+93QvFiW6HKBKGFzreaCWjHLUfgkJpQADQevkukjvsDpkrXDUB5Xr6gwICPWQTWImWfIEdYiIV11H3cMD7fPVHrm5LIlnauM2Nl"
    "O5wdOYIdZG13PB0dpJ3M1Akwnvwe3tjFqJsRT6YsQGW5HO97SS4ZtOM9rlmpBbCa437RnfgOyWwWfg30qmSdzbRW2PnMWKw+xv/xZo9zaxWol5R9"
    "w/kUwl9Oni/f+9A6XtxX33kxHpTf4ep9k30FTW3YEyDX5FiuICZA6uLwv4B9Xqe33dn604IJgVJC3Ig4pnryKC/fcaDygW2ne9ACECiegrTpAuXL"
    "zZIKTv6KrLkTkArc9EbGSbyC3GDeepOUCXzZAez9JWgBKSpwz1s9ChE9vEsY8wnfIyZpYWAjOCWOsiF74vyUJFN0GpnBy54b6eJB1i9z0qEVCYw/"
    "xYKBV9m5c8RyacNJC1MfoThOOaDeARV08Dvg3610g32EwXWmPaSMdiGuni5xbyRRTm6rQZVHP2ANfggnp8TuUZoIUyPIDnAAyySxUFCxMCyPvnfD"
    "AYowfmfCvzaewjTjhGAngnq/qC4MveorGZ8+jtNeEArBS6x824OzD3HsehGgMSaCrWgQTuoAi4+RUOxrlX6qwRC6V6B3imkv8025KBaFpVoEwZa2"
    "iKU6xC4OOXSJyMkgn6skam64V5KRw2IC73wUfyy1zpPSXCkKPdLEEcnHtpj8/j9NWtvvH/rGnbbUwBf0jidyx0JvzMs9NvIyVaHQT5OtxNOAXqiG"
    "jhQ/oUnp/Ls5+4LVr8wpPOgMYwNGRKXjgiI9PNPVA+0rt9vBl2TZxqnm4VhdLOGQCQ9N1RTclJzxK8hiA4GQ9yg+Y1LMaKhV5PFla2qByrpL0oNC"
    "4uY8bWadTOEt/BVX8mKbFQnB3EDd86JCOB/livU06/oEkSozc0E5AAwn2SVoJLCmlHPOzIvzu0sHQ0e4e0vyIU0istxeCM826t1u4rNJkNZsLTqQ"
    "nTDsRQYzc20UlnAQPCAfhOfGUcgmCdsvbV60vJYieiJHcfVJQRTygFpe6AifJdKm9aKDQUneLs9tZiHbbWZtTOfqTpfr5RHtWXOsq11Wom6SUrhH"
    "KkhErfQArxrwXCTNIwjj1QJXv2DTFthYiggzvXnsxvGZV5Jyi/qSN6T55IVOwDMl/8nJkNDEp5GL668nKAaU+Ffhp4Ic0C46eRHgSBNH1vyWFG+T"
    "AVfPKD8DjgYHqzjytTgqJluNxtq4MLXDZoNlOHs1dOmesqyjITzU2Ouwmf10AdKngbB4zToutg8liIkO25E5UgoBaqGUh2syqjfSFioSXXxEkCQ9"
    "x6KKGz7b3Rj4pmsCqzbBPM29Ml6BCEgyX1Vjg7Fgp/Kizw9LeymICKhLSJFssQsZbijKGeHSoFzJStYfwqFLFyWantp0L10n7b/D6uUYZDnmz0rC"
    "rDG5qpiOxburZuHcPDAKNV9r0IMvpnKjozTKblqF4RH1kaxjechF0/FY5Z6IerG8/FvzjPqLd9QN6u8VGGt/sz/4jzKK+8u34QefM0iDgf5Vb+Tg"
    "i8HdiaB/d/HR38JqIugHSMVsEtxf6lb1aGAfna10BPYvLcwOtFGkUeDfYnck7u/VrAUTvUMZlulGtwb613kKg7X4iaDrarB/edJNnHTZF3ggFwAY"
    "/u3Ugv8u4f2dlCF1C3Nxu4r/yytTCwEMlDIGAjijvLU6+N/BfzD+LzLlE2P/0oKcHPs3nwr7V3aBgTrH4P7SH/KCPIUmbQz3lza2awjieMC/zkn6"
    "LWckmV2372Y0+Oi8R+L/oqvRxf7lTtppTiIs30wngf/VfN4MD6+hQhnnePRf7BGkeSdDQMSpYX/tagj2L4r5wW+gO9SY8smxf52GaEg2T3VBvYCn"
    "AwIcdowNkJGUtb9VDGBnHNUhYCoimHYlUvQGCLn2eiEXS2Hd2e0wNRSw9V0a2uaO+c9raWur6M8ICVgbDbY2eaqEKZp38fIVs8PjoAALCPArHGgs"
    "PBhgzAxp03UL0MEa8uMxMYA5V6ZZ1KD/viK+9hkDAKe2V4TC28oE+xcRmHyC+AGRQwX9t5gR+u8q9Og50VwidFpHj31BISxSE0Dfw70Hcb8LSiXr"
    "ccyeB3c2c2LV0B1obSOggPXbwTuDt1bg64vPr7xwfBTgpdLl5erTaycGCLhMW6jnATcD5kdeg5Kux5tRjsX+hY0C3VES+Dk5C6Mf8Ktg/46D/nWk"
    "3VTIv1lnq9/GX+japXPrktuyN5ot4O/FdKNPgEJjUX6xhVPB+d2K4fzmI2F+t8bA/PI5MTi/rNwI0m/eriD9Xvb4UxHB+vXE5aQwv1dSQhgNkH5V"
    "16pH+j2L+tBm1j450i+Ne8P93cX6VRWCVUkX73eZiNXD9yUGPTm+7yZr0C7AbxHi+1KTo/F9zzKTCznOWJjfswyWOwbRd6uC6GuV+7GwvkjUPfIy"
    "HgvW9/w5lurHAfVVEvJBfemv6/loUF81Oyjv3258FNjXKAjrIIbO7KQ7xQh0X/OwavMRZN81WMctUvkJmM1YMSG279/10yY7gc5WoH0HX0awfZXf"
    "jkD3XZLNCrB9R0P7Gs3EQfZdRfkQwPqSneeA+hYBpm/RQS9V6uL6XoLxRqB8C/Hee0qaB+hbjMTzjYqOOJzviisbcobSTV0oX/ygyLuK5MuAvYUC"
    "9sbQfIuTovkOfhPH8vX3+VSxfJft6VCTKiXN5VsA9DWc9kSAvtwKA/r6jP7YoL54N3nwBRoIU4H6oig4KapvIaC+vBe4/mXWLymFBki45QQ+RPD8"
    "yYB96RqCuvB9U8sx2vGWzuB3SfGtwfsuOd46UHr7XtfQrGNzOuC+RQzc14H25XlNBe3rJgQlgRsDlOMaYN8oW+Rfa6F9M3ap8DPHhfZ1PR3q63ES"
    "ik+G75t6rsSqs96r4XJiaF/KN1Kf8eyAfR0TXznlYsLxmWzwoEnGD7V8rcg9HMB2YsSr67aaKaKv8fQGKkWyJB2GeL69orSDLP1RTgPlyyEYO8FM"
    "rUlj8AZkdBLg3sCjkwp2L5gQ7KOE09rvqjOGDPmWdfzrCOuhe893aEV6OYZrmuhYacp0YuC9sqFW3YpC90bbTF3tewSCL48dDfWR6L3iIR6D3svB"
    "Es4dw7iPpxfHAXyzCoKv7m3pBWZODcN3xewaJkuniNHl2CMOdK+lNjljRX8GqL1LxjXisjCQZ2mVynkUCpXBsSNoK9vNZgPWGx8L8ZpuTleW5DJh"
    "yk46J+qAEUD1sJ0QpNd1KVWRenOD1ItNWme9fhfofacA1kuMLE3yNrosSw6jCFzvJFv15wTR266B6G17GwzC7k8N0Wv2cwxEr0s7LkUYCTpLpN4s"
    "3garp65sxvWMkAu0nJ8KRi/0497/Z+4m48K02XatWt00eo1C9Qoh20i1z9Qnh+sdCdWbgxXimaqzx+m1GL3FbioX26J+f41EwDPOIpxJSzkw2kn/"
    "BFi9HXYvR/vnBmDDJE9R9aUJ4Xqb6ani9S4ps0exIKGaJpUAvdbqv2LTitCyNRGXWYL0QqOd5vQgvRGt4juL0/uM+hBd3FcacKaAr0Cq/Y6B581b"
    "WymzIc6W5MPODpTUgeiV/AGYQllCr4M7eP8Fzc0uZSXRrdiX+ilfeBA6UFBeeReT23K02lIPk1cZCNs26+SRSIhPaYjlLweVt3Z7GsHuoJoFjwzu"
    "7CAmrOPh0UQOyj9Zh85sTiqmADIS70t9ZsMMxZvjjjEOr7gsUZMpaX/giEnILADipZkpAm/GWCRt66KWzC30Ep4QjFcPL2+/c4LptkJ7QijeUTrn"
    "aABeMUwIgLdESjwOBC/Bwl65uvLDpWRpbfnyuRNh8Fq0WQ+A12+ePKP/Y/nsCxyvPbeE7Syv0QOra0vnlk4Avru0dv7yc9jH0trg3WRl9tC7S1eW"
    "Ly+tOuC7y/jSyHlfxlnq5I+Bu3sFztIrSGc7oAgWbiqDfbUD4p/z9lGcHw95VyMJUeTdDco0x//bpzmFcGLg3WIslA6YQVuDz4+DusuRbd+Cy8LT"
    "RNLdyTLBMPq3BLJr5Tz8QtBmoXc3gqyLPcRxdYUNtpkPGmRd3cETIOvaXBtGhqvTkhfG6Iwzw9btTDCQyczA8aC64v3Gd1m1UjFWD6sb9zvjnZ18"
    "Zsi6mQLrcv7VdZBmgqxbGMKC87MppUNni6jbZojQPITU9S8CtPG7skfuQzV9sPwQRuT/hFi6bQdLlzaUNgb3uHCDVZa4EEpXfNwCpFvqq3BegTVc"
    "c5B00ZVYB6VLykoh10Lgh+8qlO6Kd2GLmVZNsMWPXrF+xqlp9uyqG1/cTaEzcD5ZJn0NdHRyKjjoK2XV9QTfslYOE3ThIh0Lk9XIdsZsAzTbWaHq"
    "bgWoupq9JpqpnpmG5mX3sliwbCaQuitJrdvGDZ8NfhNz1yD17hYbg/+Q7KWs/50D1G2PAtRtRwB12ykNjcIf3i2FhCxHkDiCqdsOMHXt7WB5HojO"
    "oOr2cd+Nc8CJYjaL08XT9dpqCAFawNMOX6uhC6Qw854v5zAhW6WcCdmMgdMVXas3RmKeGqBuewSgbtswlVzPXbPKZ2aEpDuNsjR2+KcFpZutT8sb"
    "ZwWk68mOp2GffSp18HNdwVErX6KsqhZAV5yRNW25qZp/+cC5x3Wcd2wWeem5cxeSog5E14hs3Mn4cSC9NVMQ3cEXnn9VIbNYrSozwc9t082NHXF5"
    "+KuTjVqbfnD2Um7lt8W3DJ+7VNLy4X8NiK06cAQ2N6f4M6aaoz4TpJN1CnuhNriisZhUmlRcXN7nUjdb7lOeImDuynRG/mLdtRXpkwToDt7Z4q7R"
    "7T4Vci5m8wturiwNLzG5h5HnEXRuKTmUY6BzS+ci0FTQuYSc2ymmhM3tK25uKWQCnEWzWycEzuU3FS7Jhc5NQ7fPhMi57ZHIud5t0Shsbi4x8OAi"
    "ZgU2V3YLtx8VohrUXMxVGdzB3GkDmtseC5pbIGbu7qSYub5Xie+YjsfMNZFHq3HUwuUWf1K43DTIMhPE3KLSNl9Mp2QF7IKMQb7NB9bJK5RJkSpY"
    "ro3ERNFyyfHoXsI8TbzcIoDLpSNk8XId7VDEVcNPBUHD8yRguQYpVw6H5MBFicNFyV1lKFpCyU1PjJLrtObftiv4tp0DU6u76Ku3x0bIPVHPM0LH"
    "TUN03LbzdopHwbtXOUN03Dbu83cMHLeIguPiT9p7ZvU8/NrehTM0veigvGlEnUQ5Yt8yIQD/cGhBvPGTYeJuIWprNc1jGkhctg9eqrLgUZC4AtVa"
    "MHjqObBFoI1mfwfkz0aLdda2B5rXF5TWLClimLgZwtZdLlxM3IYJ8NSD4g7edaJ+RYiL2w5wcftJUYuLS/eyf6fIuDi1frKeIjsvIpC4K7794MVT"
    "4oi4+ShIXE8CMCiuyyDctfZQcc/iDSj22/q4uGwekt+Vl506MamQBNc5+HwKdNy+AW9C21h6VWPZg8c9H8mcU9EiVniqsIwSqrNAubDeOFA3jYM5"
    "Izvcib4DvNxz2ElWi5Wbl4tqXREOQZGXZ8TM4wu3hKGrBWkDvFyGy23Xw+ViC+RGI8x8NBP77XAv45C54aGly7S1eLmVp9FBYLSV+QS0e+AxAUau"
    "Y/PYYF8Jm+neOt4d/Efb3Nxt7xB36lagc5XIgaGXgy93UbPBnOKuE7lTAN3CB0uEZXkRVdpR4LlLobmt3Zn7wamHn7viw+ea5aP4Sww/N0V9tVk9"
    "J3DG4Y1RELorNaC5els702u+cRRdB37GeBrsFVMDpdtlI8aD06USM7VwupKxPQJOF59AON1dD+rGh9NFpClMmFM83X5bIHSFylwIXd9joGC6Zqsk"
    "7SNl/2+FXm1LHBEafCWZRybJjPB1r0UlmgetWyVFppIcXeX+a4ne6hWIXdfpF/BrB2LXxwYyNmOOCLuFDxmYORTQcP3AGZsDFg1t8AXpuWSyi6PH"
    "Mfh7k2DskoPKpv0YkN0IToX64gm3ijltFVcXKN+D0qVgYBxJ12fXYgwSmg7Pb/A57IPF0VV+qCC6TeCl9gxmgV7Qp4iW+MtdKN3ECx90a5B1hf/3"
    "2xZVtx+D1a3F1KV3Q0zd6PyWhMlyZhUdMFhhdaEyjvEG3mDt5Ozh8yF1ie7ikLpbaU3OuWOUuUKRgxiCgmmHKBKJ2flOulEwKGSArCtb7XrsDUe0"
    "dyPmE7y/S0lsJd8PIn8a/o3eJYefmIxQ9CglTd39yeF0s12F0+XltbeBWLI5OV5N/+KJxNRRfUWvYSvf9L1bjtyjS3SYeSLnuYszkZi14Lng8Shq"
    "sHUlS6WCxrFY6zSmBHBMDqxA6hKTQHtaAXUtqmO/Bkq37aRpg5ExNZDukuvcsGC6nKnpwiJlfjSELo/qfQzOJCSQW07Zb9SGrxV2wU0c4IjPBDi6"
    "Tg+VmIiHoksnukkexSqwE/trYYe7csfK3OrC+KQQP/y83tX0huD671jcXPT7aBzfcUtzEgj+Kq42HIubpGb0+sJDzk39O5QUkSz0jnpHfU416Lmn"
    "y0FqQHRrw0oMpUuigH3LnKej+lNb0MpfwSUQR5Tnn+qAEYxCw+CSvtCu7o8c/moWDnnkOP2YhqcYXinq5u1il+LAFKJbJyhdSoEdC6a74ir2qH30"
    "c1xBDIfriWokm4Kmi+a9WXcTZxQs3azvXPrM3Ow34ketzLDFGhrueAaj0DDfCg7QdJccMF06LQkj6UrSowvymRCS7kYVSRcnaA72SgRCl7KaBaut"
    "9PaRSFFOacn894+v/zpAyPnj659Q5IaBJIl7lx4KT1pWEHT5UVYNffjctsLnjmCqDLS+OyaB68XB524SV0CRP3Qu0HhJGK6aLJmBrFBEVEIXD6pB"
    "pBBJ3PAjdfUIuX4qQjsdHdNUzlW64XpmjgYt1xRliJ8/vf3kJUDopYva02mWtElcl5FyR0T1+DDZPmqBc9HHaJBzOaMDwUQ4KZ2Ac+sDsaDJfd7N"
    "Uk+d0agwNXLXh83NYsToHac2a/UjIXNXgnVZZ+BXnIeednMa3OJcIAwGX5IVly4QOyGpCEwPmmbEXGIsgUhx3YypmLYxwFyinP9AunNeZtYl8jd6"
    "Bz8zyhjzMTTSLF6ux/NQNFpk5fCete6Rwcx1FJLSoOauxEFzqQ04Q1yFwQR6wUBPzsYi+D4kG8V2HHIWDcnVvix6rr09VuhB9dAexmDnLnkcD3kp"
    "Ad0wIyZDmDbaxTirsMXMwVxBwFwn993q0ASa2+s6oLlrg8Pu9uCLLAqZ+81++3raSvfSjouYe4Et3lbWHYeWezbttL65lWyne9/cwgyBZCPfSq+3"
    "qHhQFSV3Le18c2s72RwcdlqDw28+GxxGEXIv5H/4LJcvYAx5FSD3+bS1Das1+AKb28ZWexGU3EuDwy2YPHQF7JjRnyoYuc+BsdOG/viJfhwd97nB"
    "110Yc29w2Mr2wKKAHwdfwBFywHEHN7/5LOMFi+rk5sscFrz85pYPjEvrUgeKS7MEYzjFMhCwMrsBLK4+QHBrEWDcC+leJ93mr9IO9x0h0Uvp9nof"
    "tw72cy/dBqoIUXGRkrJeO6thcBcGh0C5hy1cpvbgENaUyYKpIVCuLzDFXEc4dtrhKCbu81mZ7iRwrDdzJATQgZP82h8+kwWsR8Y9l37zGTSP1NED"
    "6uKl8TW8qylxGiCRLpHhMeBw5fDAgnUaMFeuvgpk0KWx4mnY9maJw28W33zWxXIpbZnESEzcvWI7eSort/Ok+c0tmHeSbvewv/Z4LFykMzya5no+"
    "2l7ZHz5rwf/z7hgg3PWsleNdQ7yDNjUM7vbg6204LYPD65nMvJV16IzhmCYGwcWHk20t19HkwTg3MLJtPIydE8HfUh8lv7aNG6JPASGt40LvgTYC"
    "5yPVEdA0TgcCt3YssOP5FkquRnI9RbT0ZtrexAc6WEWuLDpdb4yVEU6Cf8vvy2oDv1xPgdpg/tDL9RnA3nLzzX633+5X9jR5itka+jm1CSD8aWFv"
    "15EgoL1swUO73S7a/V6/00/w2gMeIuAKfGLTblPW0LZT+/jUyLgGvzYtmzkc4Ha2u9GHByfr6/gYuagDddrZXmZ5DWrtwLoHh4sO+8H+TAM+XeHq"
    "zwgg9xlixG0ko0gnwAMW5GvD45lhA9vcgJWA/yVlivfHsLYSLhJ8NQIU99zKN59efeHi0qWl5JmlP3y6dPX86vl/OD4qrjJ45O57TaRXGMV6utdj"
    "KbnerwwWpPQWcWhQ5tZh7q10MnBcUiiw9e10B6+4gQ6Ic8ZYQNqG7WqSrIgD427DMW3ntDrtiRBxWfaicFjPu6CNfX29hSYUSvcyl32xWLjPFCA0"
    "+tv1YLjPcQPI5InsSmyehb4PhnsWdUP6A/oZB4ILP74oP2538u0k3cNV7WnLMRDcteiTFgX3GToa+R5pgoSB+zwOtWtQcJd3s14FBvdCwK6qOLir"
    "tNEg0dt6iH0s3HN5ywLhsja2oGi4a4WPhbuKu+Di4F7GaqcODO4qDjkAwb0g1EmDc0FwVzrpnqEeHwRXfpJBexi4y6wltEWfVfjbC0SaDvztuaLc"
    "S13trrTERd968Ldl+iJ/66Dfkn7H3wr+LbXpoN/CcoRen3+wfITOoe8EM6MUzNtnBod7g8PtH2yzdroNOl33mg+Cq7SqdLTkE5CLhEscoQYE9xzo"
    "fjkuG4lgV/d1YHDPkR4H7TeBQQClpNvYTUeIWpBxnwHp22KLwELjnkt30+RC3m7l0I2Pjnsu62Q94BhVbNwLIHJbfdpfHxb3+fQ69E6W30IcFfcC"
    "mVVicuQVNNzVYms963l6aTuNIeGyDl95LgKEi9yiixZ5K28nwFSyXh5i4P4QDJPkStoBA8HBv6X1gu345tbgCx8Edw35p8W/JdLxAHBl03qgnvPx"
    "URjc51MCq63C4C7RgjhwoQqB651Cg4P7jKNJeXC4tC4OHC4vqJiQCoebNfcqaLjKkC4DoxYjwuDgMnepBcK94IuKOAKu8HPSAVsp8w6DfousCmxN"
    "PBz8iwXBhZ9Qw2s1+xUI3AvA8Du9fC9L+qB/GJYTQOE+w3y0hw4FeIEXsgKI6252FBB3zZOZUURc+6UqRCzDZTWnxcVlPQGGbV5hnwR8czxA3E1Q"
    "B8CMzCsxM2KPWslKTc2TgeI2qUnnx0zZPwnpsWC4YuPCb+vCtibHwQWZcEIM3C08RQ1pKu3iLmyzSQ6LTzawUPC00LclESMhGjcRmOh4uLdq63Tw"
    "rNK4GvjL99AVgA92+m0eNGmYbG+qkc56yuxBb8ULJ9Ylqd9kB1Gb4YBQPew20XQAbZe3uoEfA38EKepFR14io8rg37KJ2hTFfRwSrrFQsHO8vC5O"
    "vCxYlyocrrfWaGGMBsKFtvGbXoqVptOt9ARwuGS676q3wzNwm/nJwHALVYNlZdV/GO9kEiTc59j7ut2j+X8PDSt9lvd3Zji4xBbJ9GN/6SIIdeBZ"
    "aNwAEYDc5ZVDYmMto4UeM/iEKpFawypmZoV/a3i1o0qoP3fRjqOHoQ28v7CtdEfGmdXpJsa85SZdno35w67laK3G6q6eBAB3mx2/PICMTjIBRWXo"
    "J2E0XP64izmEnZKOGbl3A6jbJR5f0t8DVbKdXoflQ7O+inPL4qkZ6lRRrFvaiEiTEYTbC9b6hgWiFxCuppMHOLeDd4CxkWNjuyAtpB7kVrTbbTBu"
    "+y01I1xcW7AbenJSQlxbGzSxOxfDtU27GCu4Ljrn8XFtWeNseCQDnabXhNOymEOGiUtIXyGAnbcPbJX0GJLjhEC3vHNm6g3SJ627ZptELg4lTuQq"
    "CU6OclsZSCFGrdBAK9suQVx0jIONnO5JiXYX+0/hjAM59VBtbfOHkyHeijKUa2BAXpQAgPMqJYuoLvc90eJOAeJ2ws3ZQatsO8mv5xQnWM9B+dzu"
    "/WkQboMWXOco7x85x+IISLtZOKxTRbg1AsE+1LROkTEIt6o1sDjc9ihhZsi2da0QJWBI0e78XlT8tkV/njWy7TN9EUzim8aLWcgQc3FKMutNKkod"
    "rVY7u74oNpYbTe5AM45B15kK1dZ/wtODeY9jsSH26vf6p4pzmzazXug9NwamxhXW+x32Sps2dzNgLyE0AMUcWjp8R92YBvPW7B3hd1spF0YQJsK5"
    "5YfgmKh5JD95Is5l7OJgPRbmrf2Dm0SCAlGRktbAEsEPxkCnjiA5AeatPIzOICImc9LspGwrk+DgBqEcFjmhrP1uoeEObl7H20bqCKPB4lrtZlye"
    "vkWoq8Ruye5PNrNO1uJASbZNjEPOLWlDVP0bDzouPjC6PWRrqHwkz/QbCXBpOELX4aBU2uKUAXJBtsjdKqkm26CADr5uUZZDhoG2LpnFm9aiWh98"
    "vcfyM2kOvsY7Yjac8pcBiVuzRw3WqvCsyh7hruHKrqPisY2BXPbSMJcC00Q1MXyHt410FV7TDoY9YCVludsNYjSDL4BR9JDoZQSgv7Wpga1sp8Rd"
    "JvHQpD3TmB2543FHJLYGcjDbRqW4e0IkXPdIu+cZJSa+jUxjezJA3BVXcVX6y9HwpCyjOB7ucziRVm6NmNFAuBeWLp9fS77ZBytp/3KytPrc0tVv"
    "9hOMkq5dXLqaXFi6+odPz19cunzu/LGhcCfvAtvRaO3lS+f/8GmytnKFArff7P/h04vLl77ZPwYirtejcWtcWPr7c+cv23fm5Zsl+PdcZeZTo+Ou"
    "Lp1bhi+eGfx6bfDryxcHv76AL026FJeWcPbHQMhdRa/aNrAmoDaEXdafyJkBvGwbVUlkRrYlk3AA3LILJ7SadxAHztWIALM0UVEjiLkmcsAhYzWr"
    "JwbLDRNeyKXoexpJHrOR5ehek2PmPoNXNNIwD2IL2AZyiODkBakqYkF/S+i5abkJ6yDcxfHQkRfQoWX5CpQ5mJirVwgXKoVOrB7L9hOnJ8BkN5mN"
    "nAxCt6qMCzocWENsai+M1kxnCZ872WAi7aEeMxWA7gWSa27WR5lu5TvoVeb4bfwyzapaX6F5MzV47hJTiewhGO2ce4jEDC/AAUdtHIUkeqvops+2"
    "5LC6zszZwucOfo0iu7OBeWR4qFCPB/0AmAO578q+7RtpWZMNsw6f/F4mRxvG3ex/8xkzrL0ceEivDZIbDmP324fV/WZ/G504NCPZ74Y1UyX0Rf43"
    "1Gtgf8HCgrXqo7LpOnjzdm63Pev12A+OERUvEknuGst+Mkyt2UB/Hg2ArHc+usDr4dvmdxZr90JwAgwjKyyrJ/0y6kuk/Ex2fzIn95wHnHDoxtRI"
    "93dbtVaA6ydbtwYuavzIjHCHt1PRI3H5EIAC+CxvOvYBL1EW2x4G2Hk0ePDwAPJA0LpkrqtZbCcB41014TZWbPGAc44LnTw6dQmHANDM3fK90SdH"
    "4HX3I2yjIeHTpjkS1wNHkx/M+y5h77KMqBkh/xgMkMahvzDi4jbq6x3KMII1Kbb7nbQjzFKuSHwN+k83L4E3yFc6YBMQpTjSXkWXwVZkBpJ7OlMI"
    "3mfsIF0HjfEn+rFEmB/+6nebkvcdbfgujpby4slARN9D3vNPt+OKHo3Qu+2LYuYfMlJ2R50ONm8NZ2K9lVZn25MayF+iXX8v3/Nd77NA60W9h27d"
    "9XQoEbcp5kzb9phSTxGs95kKd21MwF4p+zftJO4QZgXaK89SMPzp72U1EqjK00L1LUjfsGr6KNDeiou71HxSyWD6C4fqHR0JqKwO8bzA3axBgQVN"
    "QqE0FfYx2dhfkhLPJQnfBKWz5R2CTGWz8cfO+1YD+dbdWe+OwuAVG8c/VMr+xUQHxa2TiywgQeAGL74VgN4LdNZU2ugdK1LD8Y+Ge4fADZtqt98j"
    "5zyIL4meLiZNvPfT0Rs/TsuSF+5kSZ8WHO/x3AiLtg1HbeLeNFbgk91EWLyYbkM4WJRO7fK5AsPOqMTnPUp0HQnEu0IPyywofbjjXPqhLIt6LF57"
    "KHp6a3IkCK+bYtlDmYEO1UxHLFnRE2Dxqj/IpRy0Pzt0d8e2FUPhpUzWb2DHOG3FtVYjSLwbfA9V7jJEMHg39Z4nEGvb5I2HALz8N3t/xM1Vxd+V"
    "tJqsl2/D/0W3iIHvigMatG6+T2n7jePvtu19VT/orddBRgDwrnm5Iar2VREgw28C6F05E6cHvMttShJbtUXKRFrHbFDmH9yK3ChUuYxdSkaFmynr"
    "4+3y/c5d0qFPAWjXy0IWFxzKFQOAy5leC9YYteofTtzf4D3OdYRHQF3ZBj0YbEi5PjQlAK9Jb3OV0nWQRZ34AOMovPYrtlxPAMFrGxl18a+CdisX"
    "AI+FvTuySxLnBhq32uNxcXcr7+kLjhzao7s77JptxNIJNKcbLBnNnTsxJC9mmCBDg940GoqtvPjNre8APG/QKxybbLebt8W2SsJk4aglplfxvrm1"
    "iGmOsDV8xlDTcY+h5kVtFzALDhP45HN9MqRe+0jtfdoxML3hrFHExAF6AwW1wxcG/3/y3q05rutKE/wrJ9wPRc9A8FR1RT2QTxSlsWRdzBbpnnZE"
    "RziSAESkcC0g0zbL4QkBIgFIoluWbdpVlnpsiiABQiRBgKRIUFNQRNHt3wCQL9L8kln3vfblnEzcVJYrusuSkOfssy9rr/taHyurJOdpAwbjRnvy"
    "OKY6tN8EfYFS5lHlZKUVZCgyrUz5RcVuBo95ltR0Lr8e9F189ZHhuI1vGmeK2/pGbXtRTY4a+9KMOhS3n6T+HjOJo5Rd3+jYe0mCOP/rD2C9X6AJ"
    "TsKh8RBtvlLw34UOv1LS42rzgRYKnX3jpr7R5oBacaELu0ENfbmXxGQ3Lfevmo4raNr/FDf+ffLb4nlMAlmMd4WhXaBy1JkWrDScDqcoYFj8n8rd"
    "f891s0PWWaDZd6Hl1dXi5ye7oL7CiYeWwFQ8F+x41FPVcpcb6ZMNtRtwWzNq/aUWU0Hq5JJWwP/w96iVj3fIR4BNQOARjKzRdE5oCJK4HyiwZD0C"
    "eYJWjP8z4hxwtElxP2D0ccGVmAXNk6nHnWp1gS+BhCjqLgtllE/6dsAvuGrsbqc12WJmY0VjST/gkDw/XHpxsKJkZ7JlNN11mhIPQYhMjnSY9rGv"
    "Y6tDdoc4p9FPPGOHIkaYb/97lj4xFiqeUWzCOFOT3aEuDjONPoMZTM/QT6q16jv+/umuM04GK794Kc+yS2atfvEbT1ZwCTW7CjSntSqlzr+Sr08n"
    "Vt/nl5XpEVsgso4nv4WZA5nM2gzG6ALPlDv9ugTwmGe4Pr+vtKZbHSJzirZys98OWMldkkezsmfSzTfLXI+b/cY/Y6ffcyE9XcUMeYRV0Iwjifzd"
    "cde9t01VDeMj05UWspN3BVNHsuQVZpnY+XokRKHSxDg+QOzk6yjUCzrfyrdAADqA+X/aqSt7rHWuO05Rvwt8l1zn3hf9uo8H/3PqLzL/OdbnxF6j"
    "0fY/TYBahHoAUBt2cqUKAzA2oj4cg9Ki13tt0Fk0RpLV4gJUdj7U0l69Ls3ohPnuw0bNUg6Uy4aP+vWKCAS5P9ss/S6Q0ctzb88I20XztINXXGaE"
    "2Z0oqf90l81IIHTt1itcjlNnnZLA9wwVoAtdUQvYv15SJJCNCTudrGnc+yo5dITosJ6OE77Mn0dkTazb9+z9bt3KzuVqQJhBdboFhrnazOjxRjY1"
    "gGmc5MUZ09o+rI2ZQC8zqt6zcN19DYC28qWSlqyRb+AAruuDE2yT7TiGSKUY4wP5WXkRmbTvtQ4ImYy2uo4JYcMzrHycoTImiQx5x+fkVGfcTE9y"
    "AJEDzA7fghUtZYuTUSNfuKLMGgf0qlKMlDZWJtWyLlRwQkTUVV5jo80fMJuPHLxyEJIJEFc/sXcU2wVjHh154+W5SfzouLiShsSNKmkEM+WevgPl"
    "viLDeDvLvEPSkYV7uIwFnJLdeqLeJAg4ETppDURJKLTLzIUwbj0OhzjWFmtvpq/WvlojbA4UzVgqxsxCo9wL3Upr1ULdcB5jkYhcZTolRZZnkhyG"
    "2AvOSWVkvSbe67h0+aURGTdU/dn0pGH3CLsGtRDZl8z5mDEcWRQiUJP+QmuaCZv+yJekPQY7gbRqVc3oWpn6p9ZMoeMvTlGDB+yy06IqNG0t04By"
    "VC2rbkDcPwN6KJNMIuyhIgZEKqPPJhuZyTv7HhlLKacgvdAabeWpDRTSjbzkpRgMAmW1OJpYnwFDXjwkHRjANh/fpFEulNM8KDSDM+O2VrPczCjw"
    "gqS6MPx0/sln1NF3ZrDc6W0gVJ2SowB3eSLUQtkyggUrMalA9lE9gpWNyRbpxZSGciK0jRmeYOvBE2lMwgm16jBGqVmHkwF1dvOdCamZiR+EE4mQ"
    "qXOuUZScqbcOjsmVBYPS1Z3kjDGuq9ekenzjv3/rvOv3M9z+799SvVtvMLFUPBvnSAdlckT+eA55+4yIKXnV6eJpt5c+OG13QFK7sSH9aHtcxb4n"
    "qqn63LJAOsbW/6YdkhWD1oc7e841tJLJpxcw0h9R7U6zRP6GtyONGLoPIeP0tTlx89+QghGJl0njq7kcm1R1k9PHumjMITQPSj5s9OzTz0MaSohm"
    "IxYQ5zINxPsq4lHNMjIzUQkZbtzouDcQsl0mtPMcLBMfBlwCZPv62rgm/52oiekWMxtoq4nPoX3H46JBjAXRlD03JgKZU0b4QN3FKhDtBerQHRSd"
    "mn6YcT+gMDYvxpeT+2pzM4Fg5OOZxL4AhIbMf5QbJ+FD5OLQetNIhUKKbmjKOZA3F4iK1I0VjrXpA6QPgKrJ9ThokgUXo+W76VmrNnZCyxs5nHyu"
    "G38j00BwJ+wAtWbd78lgVdNCyW3nLOJBjUjAmQt+yn3oTJ8rXifnnGM9yFXZ4TyTHhhJPV1NJ2Bq6eOKWSbCJJCm4BdTPa0ZgelzgU+GU2cnDrb9"
    "bfm2vzsruxd3tnY2dlZ339u5WWz+i4/sXtpd2p3f/XBnyzcA3tmCv1+EF1d21ioaaW3nNjw236sfsDx7b+fW7nu7Fyv+ws4qjHN/Z6PaXaLfr8Gv"
    "izubNKu8STC8uARfd9++v7sIb64XewXTPOf42TVcL7w+V8ln7u/cgV8e5P2D6fd1XKFMEt5c2b1U6CG8s7Y7j4Pi7C/BcGs4uVIjYfcgDYhbcLHc"
    "ThjmhAPhCjfs63BSn7l+wvzn3QWc/85GXVdhms48jLRVwddXdm7AHG/ykHjsK/T+WiQ8eEfhfxdpR0sdh2X3NmDjdTORTHYewMfmkubD8JUH9MdC"
    "42GYzMbOLZibkMGDnfWdmubDTDe0hoc8/+s4Mv0bryDqRCx/vwevLBB1PazhweEojJxoIo9hZjdzA2DnHj4O/3ezit+sa1BMA74DGwXbBKfFb92G"
    "91Z2Vhs7FMuDuKUXww5v0jWM1VeilUuV7RDR2P4aFvubDOSs8zUiwpXuXNZrugZnt7lzI/yxYXMauxjvPJb7A2PcwptcHYMhgRr4z/P4L7uXerc0"
    "hpfWdh7i1tL0m4m+CtwNFnazR8NjmyJtxhz86167Hsc7qZS2ATNeRZJehc28C2f3Tt/9j5MBcbgK/i3QgjvH3cXjFdzYz4AMbYSD9EVGlgubuK77"
    "6tZlZ3kRLtEKPnAbfn63MMwh9kbeubb7AX4Q11/VT253bvc9GRUoFvZ8C2iNniGqkWPZ2aQte2/vXZKBMO6rwMiv0XXZkquH0DC58bSTz1XH8BpW"
    "KDeByNbDsLQdMTPfa1NlvGUwl/mdm8fhsuFkVmEq9/EkYCPcy7jfn8Lv7u29dkzGg6QF+ANepU14B474PbjXH9VMwr64/77JQBFLSCDu28YTUK1A"
    "rgCfj3Y6kJWSFDy8DPJgvRJmZFM/pH7K9P2wUQ+RVUczgHnDHFAwziOnPi7nT2wQuSL8eG3nDrx2l55EYkJhtSWXCX6+hQuub7FcuAP7b7AMI2ww"
    "f8zkkDB0+F/YRS+8bwNZL+08YuK4BNPBX28j+1tnfoTv3WLxsLhzd3exrwbMMNI7eNtwaZ/ZJQOSgyOGa6ffhm+s1zZizmQ6C9Dd9/rqyhxdeadC"
    "X0OymqOdorPdwAnBxtwMLZrhZ5SrN+t7NCsXQCrA8R+bokqc/DbvaNaxOZWvXnNv7N4s54mK+YNgCcwJhcpYD8jEuFnTzblxiKivc3ZRtb0z3hZr"
    "7gxnuUWqe9zeuY7T5m2eMx2BpuH6PNMEkSnfDO2ekZS01zOy7N13437PQljroo1K02fRr1ZJidTOz2IpMAW67s9039nY8L2f/YquARt6j96Lm0CH"
    "JRHXirpAy8xE3xI9T3tB+8vhOkIrQbFFFvWFzlRG5wCi3zaIEd2gdbgW0V6jljelVTR/KPSK5jkhF099iKwCBF7plADad+dclQ17DI/Lb9xGWqaB"
    "/3vTdY+m2wPsB26Pmil19Jt0ko45Xk1L6YL5goYjK4OkDj8Wa8C1mJaDRyFAKhBIM5Rprr+0Gpek6C9EXablEs1VyYJdt2lTbVfQuMt7TgsRLOw8"
    "QsaRdZ5m5nodfkfGfavcfDoxP5G5y0TiLtTOjmCbHl5bB9XgZqkTdfpwsNMKzahhmvNobsAMeMbqElGtE00htFvSFtXw1yUY+qbfQbk8kl5PZLi+"
    "cy1uVQ0XcAU/EbpV00ai4F6LWlb7i40qEBOA9q0Gc/EhDZ13rta4GnEp22DXwTqMDEJ255FvY81iP2pgneyh9rGOzkGvOrez5gXxPSeTPeprDfQ4"
    "D3O/mekWWhKQuBFO71kIl/td02FcDRabiFff9Vq8ZEtEDMAr4Uh236crFdpfi1yYpx2N21/TT7i2rbzptZMqKBBLHa+ZWrx1Eze8JpN3bXeRZEux"
    "33WsHKktYY/up+e1XsnwSmxw77Pztfh8bmfh49QlUQVZI5z6AD2wZRw4UppD8DKEaffsg8182saIWGy/HbFZCNK27r8ttup4cjWrY158fpuaHqMB"
    "FaxmkeO8qyaGgZ4u7aNvtrJFXkJQifbbQTt2+iw4FyGwJLjn6n8IopLeJ56NIxxFB23YpGv6SXGlRt9HiopcEbDXi7tL5pH4BJj0hhAMP4mWClp2"
    "TOQqpayFdj+Ns+s8Q2iwLuWuM3qSXIvFZtpFZlyhAQFfaeyrvbtEFHYN10gcae9dtZvcHsoCbpqbMhAy/8HclAfrvN04ieAPQ/dIRH3euNlDW+6E"
    "hfC3aBh7J/hzVN8/nD7duECiuHXn3pOo0M5HtBHkOaC7twHsguzQ27QL7xqnwzhFRQZ7KXhgMaZDa+QdRVH+7dNI7YKZfkaeg5VEKv3b57igYlBA"
    "DZ2bvGDUxeggUmWp78bfdQQUKDjZK4p7mT/DeWMO2Ac8KOv4zUJo7wHLUL1At+HR1ei8d9+vO1nTxpKW4cjo2EZRriMHIevLe4er40NUWiff6zqI"
    "l78RGVWFZuJIqVXwIyUtxGG9l3Y2lTtuoKOtsY84xjXhoYepmeJbiRtXWhGDKOomnp25uyxpS/FgEegMMW54ixjN/vuLmwvEuYU8WaItdxcdUQsV"
    "3yPmeu/tLmY+wwN2Fk/2wvN2lJ8114OfvUvMkdgS2C7oHLTpoTsU/nk4TceZTtF+vU/e9/o5k859B0WCsx3XcM4+RHSL4mJbXqf9gDSAD5GgZaN3"
    "Vg7Wl7zkWzUOWIzuGZdi9SV2BBr7fy+8X9bNxQI8gs7mosasAve6lHivg6MkIQiTB0oS/y4NzotfpHmnX6Rz0EBH/GGQY0fY2DwjEH00O9keTc4L"
    "jv0irag6cWi9zyN6yAYyBxpyviDo1pBnrBpN+WjDEbRAl2CSXiVvBEg0Kmicxo55z1jrDOYQkjjqQvdTJdGFzHJNJFJYVXL13zE90aNozL+t2Mvt"
    "+l+SY2uBH5AEANzbyJtx+M3TLUinQ1u+zzFd7LfzAB6pu6n5RJYzelPvIEeHzbQvY2Ct0Miy3z7qvaKJQb7nVqJXSfvqs676lcQCcD+WSC9cq/h9"
    "YJBLtFA0++zFfTZa168p88rdpyoGmWDvBc1ji6NwKgo/RWeFH3zfPdidY1xu0lV10q6HW7AAxKueC2J0auffQT9+P53ZazU65XUabPkGtWano1zD"
    "BJbAsDFM/mnQJyjXLlgRqBavEq8Xpl9WdyRA8Z6yBIwbsP9qjbwN7yGHXiI5vm58j+W3WZ/q6QJKQerGU1scRK1F7tcl+ONCRSIITp/v9HUOpaPh"
    "uo7mXiWx+oWK6HIT/VefenXC5xYFvlz69L99zt9aV1KXS4C8eEki+PD/OMzMMerMJk2ivvKgSod5nM3uxb+ervLIl4CA7lZp9OCwSGspODbjg4P7"
    "Poc0UYXwuHPAWKQH/8+eRYX3Ip0GS280ruVgmMRUCFr+AHEyPN7/AWr9RXztPtMKnqhwQvoscmX6MAmcT4nerjI5hODWwfrWxxHv/rghsjQMgOys"
    "99fPvi/O32Dt1Pa8F14cbG703JDvh0M2Df3vy4uT27SUKEKUlliQGMu7i/vujt//jovTaV0jAWJzgpqwwW+5PZVUFyT9T9F9tY+2+f1PrOBsD3oe"
    "udxl0H300Y/dJCgN5uGMNZbSvEe1NM3ntdfe+sJ0MGXAqHaFN7yUBxfGI1fbTfN+s1UXRq5rsC+c3plDPgxZ6LQPcvexvGAKf/JW313343CEKm4S"
    "gwDGyPq7096ZP0b6e/8N+OszGxeR2anjG9dU9JrUM4yvoyn/4d8UI/DEIU1pJeKODjKGxQonzR2sYT8rW6zgYoF5kLNI27lleLyn1XNo7fv3M7U+"
    "PSrN3fxDMC/KLNRPEyspV9PWhMuSjMU9d/cv5f+gU3ELOSSm3IaEINYq74MOCpuD3pWriRqTUuiht/2H68m5r7ARlEH0KX3uU/Ycl4Mu98k4Ig5e"
    "7yVIvN7w2l1U1Xc2vn4UAJiGcEPiVmANeULBBS/s/kJ9Oux1xGAxaoS2/kEO9Cywy/02Wg2Zee9G5cjxNeTu/AYlZOPAt0nZ3IzqMarE5rkYDQon"
    "P29hksjN8Q1FD4ji2imJMQcuX0226yS/LQ3fuiyWmBP4aEewL1koEE+ObMvrbCIwwcR+Z1Evb1N8N0ixinTRi2VHD973LaQn1EAWOJ1H9IyDYgnU"
    "xpWEf6QXWuMtsHbKlIxTGg4FXqCH//a9+NR9FIAZ4jyZ9WtqTHyDAAZEbvEUKbaSzFIeiGbJURqM1N1HzlgFUSbR+3k2HcjFTYdKk7ehaPJIYdeI"
    "22Bonbwwugqf62KPhVoJWVF9DsqhYhD053jGLcmzKLzULEeHbOvUsJLrHx7QqtJmQILEu2ujXuQTKKsXR4NRoOdcGiwSNiH/oyYP4TAwCfaj3/Ve"
    "yGGhE3gV/6K4+92w++TQh4VUcFDSz0soazXXEh+tBTGIq1cwU5YJyUa3CNV/AESDfQX2sqCe5jcSqy1Veh0vpJ3d0WziDfSfaHAlu1LxnWO/JrvV"
    "V0LuOtnfg3FAzN9bXVYaHuOxOTOLqDSJ2y+ZJYn/Gu+s2JbRdffj+Y3+GvAROECssvMml96tUA32nSqI22DSzHPKr8UI8Lahr34+zMQrWrK1ITIQ"
    "fFi3qQiMYgtaUBF/i0WYuGu2qIj6omaKHAWswoH9RBhcLVVMbpGOsl4R15jXrDusPOUj56mx08Tm0w/2AkZWKHqoe01zlZCVuFJu0Q2KGHUjEENc"
    "isy1hjxCuNOiPjdiMrCI1ZxFCkNlWnQ9QoN8lENF4mvUQVgfXt+52idKQzTW7gc7n5Eoo4Et/pC7F0uYDbkBds/I1xIFC+gNfugq9Auh76RADnYZ"
    "4zymAphD8Jc7rxpveBHXAeU6e1Huka+RpqKzLuE7UOjgoXdn4FQ+pMmUER5CRlhwHkdtRergHfSiBaeSKmR7hniIE9WPCOYh7YTwtnQyx6Cd9UlJ"
    "vxMloeEH1YdKrRPkU7J8zgrQahGhSI//kPWCcB8+fDgIHSIWx3QLjyNP5yrnNFVQPDZLcZg4BDQ/0/qsPQBAuJnIDuSpcVGOaQH+wfwi+Fdia/TQ"
    "AVAgevQz8N87ltS4+3N03wjTqutzsC/siK9noqxEHQRughkTknafn9UBJZ0ThNh7wKoucTIZyg2L5RwYcYJbBXHmgmVzRCT+F4w8kZ98CMmvMb8R"
    "VUSm5zY6IDZQwc97VegA0+RKDH0lWN3kQFhN6Qkbmhve10W7+qFmE7BKgo4ZSWNfsejiZ5Qo3geERW2jE5dy2gvEInZ/pL+X4SzMkADtqYqTjNlT"
    "sCoNl1bENFkha2lDNhobbagZ5RpVswWFQ9/muobI8SClOqwQvoeJQzKCB7bQLY5wLWIcC8rwAa02xq8gnhtBXKiHrVCQafEiCYoMoh684JpCfMpN"
    "RWQMbH61GZpEIGnsXC3AW/TRTMYYZwH1gjSzjZ1rVQx/MVisbTEZS5AJRtY1FmRynhHshVijG7UHdkyjHJiTxmfrk/YkA4cuUxn+IpkWW7PwmUF3"
    "RndYQ8tnQqp6gL1I8tDTey5uf1L1YwcRmUFzuCT4D4XDANWVey5czTIIfccG+Mt6Aothk/6Hv6+4lgUG0OqdmBvfI95PyTSY9wq7+QFqvjjpVZv2"
    "imQci07C7hy5aNy14RrlbtKfYhQNLtBqOEBre8bRPhJMGO8nT8QtDnXi3IXYPWV5YA2ma6pYZ57xmWaSyvkmyBrhGbt3adXboAZUQUyKF4a37x6Y"
    "/eFImVHhPe2/y473Bb2Dtg6xyDUOZnogDjLqUe+VpVnaJUydOV+YzQK51m75VEGtflmgI7zLSWMeoSOwA+skNah5NKEXjtvGCKsDt8ZPjLs53EC2"
    "jdpGCZ6DeqDhtFcLpIBnTG/WA3cMVvzREFmNPyxELVV8ZeSOXrfJAXigvMTolkB3UErGdXgBBeq8g+4oV4zF+B2FZxDEg4ryuIQRf6Trsmpeszgf"
    "itA8mlL30GDWTLGHpP0vljLXFQ5EbpXS2BpyIRhZMjDdXJIsOwL8KOgHHuwjDHudaHwlfdbyFbboKxtldzo3RWAHGTKCEKl2OCB4P1HhRJ6JNZ9z"
    "kqQVHM8h4muJGFyxFMJZ+B+h7xebm5JRt0Q5OHRu6yHE6HoyiiNrsNIiS4ELGWTBR0cR8AJQUtM831egEPL95aJUA29BPmQoIRpgNqLgzoWsf1Cc"
    "yweY3+1T6UCi4TSS8GkV3Gx1uK2BVX9G7mzm16SBKraIu+9FZWyNt1TFg38mck6bSzNDFTFhJ3XprtsAf4auHQfWraWXVbJ5pJFoQuV9atgCkw2h"
    "Do3c7+xCsm5RlSQTL4a2s5TW4eFGggaTYY5kxxnKlGrrDXJlw2iak5hXsuTyWBd0eCTWGGYFua9m4teIdrGZrJx30IuxUHAuukXcRikqAxFfajCY"
    "LoqP04vgCKyEC5oTIWjyMforH1lJDWZP1RJQ9+2oy2ip3LeypPQV38zuvaqxJQOW4UjdtbKu8lAh91poNgM3qcjYLDbyY+6ibfai/hkZB4hC4VIU"
    "GueeSSdm/i3q0BtxuKUkr0Jj7uIaW61NN+kLAyUkncTlttpFxlftqHNEsyMqZBcsj1wNImf0C8u7yHHcVHLWpgFxSRWlC+D4D8ihX07lKohjFxjL"
    "IVNYgGi0NszPhcVCMwHta2Md5TaY4Oc4ittnn1ymFzInQyk++62uhag9pvrhBbYoilTi84xkxgWAFR8glrpuylcUwpAAhjU/hF2kwNh71Hvpksuz"
    "LpYzRi5V+wRGppaovSM6CxZ9gaQ6m3Mwln8XXltOLaWMv0tcfdIUqbfGkdx/xzLRcPaSv8XhJaYIuX73NItK1ul8DGneouwcGrLvqKhFjn1TmOUH"
    "O4/goxuFfhql/E9x7bvRdHmRknsb2PUcr8UpDqt0fy5qdSY11bmLI+XoLxiGd6ZMaNJOKlzIkZXAvDKRqBgy9dvnMXtxVaFCaW1oQhxAUuUe0EqK"
    "Fwxt71saxbOGMq73fHLhgJrvqZVLC0kwYugObSBTSm6+tTbUFkprpYgyh69VJK9pEyF+45YEuMMb3LbGVddrhuR7Wriyzspx5XuQRk0f+T8fkym3"
    "KhHRSGioCivykxq+XGILXebJvV3Qnl6ggr5CL9Ws9wmRV2FwmPJ96cov1ArP/dvnGToNHZyQvcnDRll48Gzou+HK0CVOMzTC15sSMyqXhJFZPJVa"
    "j2oIWEdhafXgPpcur8dHo3SPGNfGp01HrbVWi4XuIUk3Zf/hVn5mHUzEhurBqliwugRAyWgvnFn5iEh5soLOB6Sr3IxZrltaAoQDu8bzYqkYmsFp"
    "Zew9uuzm5r+tRUkZ4WvmUe/Un1LOj2dCzs0UnCuk/sU3xN2mnpyklNQ/x1nQdWA6ze7rQotU28vMFEm8zscrSqT/1HGrLfUE3HYZOGnfJq1JlczR"
    "kg3vlRAwYjmLf6Xm8t+h8BKZiXNc8uPcXDUdx2qnVNOPTC4v9hCutOjZCVlWttJGAV64sbScJzq4mKXNy44WeEAQ82HOTfvhzae0kS3RT5Ylpb+A"
    "DkEM0ZkIdZ1/vXN+nu/ZUl1PP7++0FPDddZaK7eKSDr6peGOAhRKQWxZE9lkN5JuLJRAxY65TNDxe7dpJ+4m+jEdqu6O00gRU+jNlsMUos8AV3p2"
    "uQ5P6BIask9vwv5iWf1ihCmElTD08v/39mVJJ23GEvqMTeBNHqtC9W8dl/EUt3YxjFLAELrEGknlkG4K2EHb0td/5dnl3Ysy3jOyVefoXNdLyEGU"
    "eiJNWFAEXaLdSHGDYI6btFkkqIinL7HIugQfgmnx7mQwQu490jg3nl3eufN0gR4uQgmRA/yO9CCAdYSdVyghkk845HotjJAc3LPLxBV2F2CcOdzp"
    "GDmoB2rQJzhreHOJcyIe4CB+rR42iH0rsLbbFW4gPrYuYzcBCVEW5CpjVRVAhCQpiIjMml4nwEHmNOLe00XQoHvMMCh/lvzq60RutpIUNQgp9BZ8"
    "cmN3cfc38H24AEuy33WoQTgu0VpfYEHIjC/h4fLWbsK3tuIJeZMno719ogXZha2UQNQxtLhzX64L3cq69VvSeAM4kGECId0ymVbHNEiCBDm/sw4r"
    "FyIBa6U3TpDT6NaIIydUbcupbAMbsYHC7lPTN+RF+0AH0hvmd8vOUBRuvO33iW3hjPcCFSTrCUdmU2WS9+W7GyRzJVqyWCG7xvtyIMSgp+usIDhi"
    "IQamDzNKF3kxonkdEWBQcTrotw8tebfJuYGBN9i0pwucqrqplBIm3DDdfjCDoltEmUArvAsrJA3m2NjixhoHRQ1yH6inhOqYjUA7ggt9dplk6gI9"
    "DbQAj+0VKYjHYnGEXvyN4yKtqRzNvWz0R8m5Rn3oc71Hh3IgCKGda88u43AkDHfW4IIhM+LLG/DHRAx8lE5R+rWVZzh4GPhCjjCZBrixFKqU8Len"
    "C6otRJSYriQsk08W2QgJ75yXHhLuEHrctDlSpMz4iQZV+rj9WcUE3zSOUKzBLlArm09w40W7wz+Rbb9YuUXhj/VYRO64/YU6AB6Rk3NyMWjnVTG8"
    "u3MnY9xEK6vMRy8y6a3wKZEXDJ/069zdRhWJHN1O89F19sQpAu33Jgmji5XEISmUtkSD/Kby+qBXEGoAi9xgZJSRKtsHVBGTKneQo+8SHZN2GKhR"
    "1LGE/USoRStkli424RYR4s0K6gC4wYvRl2xso5UcwQjt2g2W+kXjoRnGSHZFG60sMBd/gAddB1uUvxKBFflbrzhFTFWGVIS2NW9KhFRUYOkFkKJc"
    "WUlAijbJO7AQIIrwahpEEX5jhabsQIoonLRmdzpCKlrHvRDwIcEFIeUF1c8Yp4jpwVNlDFcUWLf+noAV2RNuZQGvyGt94XgNsIjM8V02pBSuKDH9"
    "YrwiMwJiHx3eXxwqvOPBikSbDz8qVpF8KaAV1SAVmS7iuI5x2NjHv7tNOSz3A0gR/SOAExERrtP1ue/35IUiseb4RMQK65CJgo1ksgG9LnRAKSCR"
    "+AX1zAyGqAxBBPSzwH36KrHQ1aL1IESr1PoCrkMBgAjPINBqDD9Ejo+LQXayRXWP2umUgIicVXtffGDrOQxRsFfg9NaK4EPhkWbgIY5QA48hfk4+"
    "G71gHmaIuPyaMF8zNw1iiPMUtmKIocDvHchQ2CgPMaQnWRG1k1xOQYZWiiBDbsMCeIoBDJkAJWqIAIZiAe5ghnKIIdzjQM6GLsT+8gXP3QsAQ7Rl"
    "qNNRg8mLHmDIuRdqwIUoK/LpTS8uy6BCkZiCPXnMChAv2uEKKWZQuB0lRCF9MYEVIkih8GaCLKQ/r0gNAqMk5+hCQiplaCGnIfAUyvhCK5LJR+5B"
    "tG8PCC5kVy211cmVTOojelf3hzHEJafIavOMi+DZQDEbuPY+wYVy56Khi+wLY8hcKwy1gwZtb2ShRGSFSewTYEhv5DEejSGFvCLqdlA+XVE29Lpa"
    "VnKkT28G35qqb3vGGyKtDr+4QN+gAekHUXT2CzxkMcfAK9ij4Q4BX6CLDa+Ip2mRcoW8A2pdmouvDx4NGJFFK9y8GEsq8nlUqEPDb6xFB+8HJYWw"
    "wRIGUBMmCC3DInJ6fG9IokSnqxgEacXMyHyjiAjq8IgS3s0/NiARCdgVetXwjX2BEcE3/we87hxJicvT+1pomUrI+4ce8v48zGJdwqH96bAJkn15"
    "cQ+AQ1XCUJiO5Wm1LW+JJXJIQENxtMIK63i16AOxUCOu6BO0vqV3feUVsUQk5FS0bl4EodbDBR7yq1jjWCgdkVdX01mis8npzOu787CW+R5zjxe+"
    "F/Ahplq/a/D/zUNR8L+UifggsEOiolNQioQpCkK8hvD1uxzaoqukWQOUKr+i/ZvFNblBPs2NaCFBS0tAh8S2DhuqC87RhlQwO6NFxFEd2lA2uLOQ"
    "SjBDqLwtoL9vDp0OuNBY+RWLJkAPwefXq75Bh8g39bBSg73ilM+nKfbQM/QabuNuP114us6hSt+r3jmtCsHbDH9IjAVLy2Y3yL6Rh6JLjcIoOBNJ"
    "TJXo9BOSVCU1gtN2U1uUsyHmLbaZ+KIOiFiU7d/O5aZrZr4xdsXLIokqsuVxvrwurmHKe8cwymYt9+0WRaC4ZwB7v3nbpLM6qd+Yy4Csy7lAkRRv"
    "cULCfVZzDoBU5FywkdTbiUNnFITcSQPW5JheJBiU1LVzFBBEzKAxJYBjH0/RqVB2b+cnXTzfvxxAIlpb+kVjN44+vlZcIhOhDpMoP+seoESxlef1"
    "uqCAHBoQkb8+HMQR/pqPWkNO+C9UqEYyM9w7zsTCcJ1zhQc6Omy4IrEJJJDlWTfmJ5H+UzCZnv6z3AIOe3JwEYgk+ru39zc4cqyGg4tO7wGZKGha"
    "zzaip0MIUNyiWnKwcpRgRKFXBAvpQpSvGJ38xAXQNiQkFT6FrDprTef0OB+47BeSSMK4bP05nas2OGmKQE30sT9sIokk0X0UNKIkxml+2oNDE9WJ"
    "Nly6sO77yJdXuEY8k3eHgkV0myIS89KxmRpH0NF9Yj4M+RqaoFGiWj8QRA1qXbaz3ywgIuf7ZfJ7wLlmqB5scGaeS02iqPKS90hx5iRLsM1KY1XM"
    "moNd4tVmJQ0qBrntk4Ip3D0nNptEc3WjB+0W1XyCSq7pZjsm4DJr+RJtymuoOCR6YxJf5gt/McwPU6o1FwRZ3TpB39KcIuYLK1zgmcottHQCu8d/"
    "PUBD/ZMPKvL11IM8MXOrqpPTUcgmkZL0jWSfjdGDkYyphWTBUPRL9Cx2j5RJYZUJU8KacdTdKQkLFN7bNPeaOAAXkZcXJQwbULhRYps7TV+tcvgf"
    "ngjTxv7BiIp8sJBwtx8Mov5NmHq4oWBp6/R6gAyF9WSmeZnB7x9OqPApr0hZ6CacH/kWa3cllQp7hhFyZxkH40MQMXeh21jeAbkf/CABDEo9HrTo"
    "Hlu1gfcavY0FNXqv2EGUrHybs8+pNPHZ5eO+cnVDUL44WqZePhuhnHdWhg1yDFvjLS7sWIMcdB81G7rU5Xf2iBuURQ4eUNLBhmltTsJpJCJTwveE"
    "IOQpWNXSQMgYILAcO6N8445BvUWPRUOa5NcFKOQos6+bQeQcZVhzHGCLlRoUCixxVkk7WaiOyWe/nYoCcfEeAEOIowSqllITiHUuKWWtyW7Y8Waj"
    "5TDBg+I5Yar87nbTtPr0fPQNHMQXV5VvqepaQRVD1IMeGEJpiIvdRF5S7RFCyBUzbONdg5mtSk8EViNXYZL3TSF2PFyMdaGTwwULYhqlLDiHK+Ly"
    "OYM2rSpLtBJMfeIiD6edRLyGYJIuioJm4cfU+o/TTL9eMKFAJ6hyXaIMaC5YdMSauYLVsGCP4gL5Fjlsg67jMKaKEKGjaEN32MLherf5nS0SfdRa"
    "jEtaIzND1dAsxQPLTaUsg9O4qIW1+a9jRwRv8DcRYihitkxkNVd1letAP5MNjV1f5ZwAu4MrzdG5NAuGgwGx/m4GJQk5bsG6xgJeupBayvF9SUHO"
    "3dKMb8GN91yoBVnDQ5L28+QaUcfdOpUObGiqx315NHMg7axLaGGO6Eo1YLFMD4xflMelvPGVsBne8rL2gqvVxMqsNO3gqEYHdgZrZEwKr2/w9d+Q"
    "3I66fIpvEvxR5OMERlXoL1AAP2J2ts2J3iaN7yhfisQEEgbN3cZS9CP2b6pSpcPoUkh18ZVFvqLVD84LPFzIIzXrZXLPNtRpXVQSmUbUY7oX9SSJ"
    "NlR5gn0P1COpDZBPSiWV+6gqQUeEdCRnWhqMaCRM5DFHh3HbGljvIWEeRQk13vZMBqmf/mHhG0WDeLbs1KR5cUKWWPnO5d7i4NDQjlJDpwfZswQu"
    "C2djmF5htAvCjTPKMroR90gs0L6/qVr1fwAYpNqAYdOmkfM9ZAh657i5o4/XSe/1RH3GDPpw1dDnyRA1c1KLy0EeV6sU1CNStPMwJHNW7V2dIRt5"
    "wZXulli+yU3/etGMtKOAiMogT6JL7Pbd7wFdNZuCF66VhBfSUTEqLA7U++7a3SeNlG9DopEeLXjRPpxVlJWYB2utcy1/mrnQ3sCJVpktYLrXptYu"
    "WHMM9uSQT4pr10zPljJJ5kuNUEXhbS5zJi2fijgRv2hJM/rrMYqYEso7t6pNi5mX1UMV6SxcmEQWI5QWSlX6QSsqDIfSa9Myz6NQxUMs9kk9nEXo"
    "osTKW2XVAOM493zGYRm9yEZHhrNpikOKXeSuzELe3iPDL0LTnOI7XEu4DZflYg1ykWa9hVJ2N+cSdhE3V3GbqP8d5f/VohhtKCRGiCXUNzmpAzXy"
    "tdB1dtG+EI6iRPijQjgKHR1oeA4Xat+NHNoo7ZJB+Ebs8eWmD0g6n1LkL2hi8DeBcLnkW2UHp1yCeST5w46thykdHeiRZwtymY9X3rnFXQZD0hiT"
    "CfyqJRpidpcqo5nN7QMAifgdpwZKZTTnZ+rG9kFyHhPJ+XXw7xJDWONSuv2iIiVjpsGI6phoSm6U8OFK2bOpVa51w/7Ajw5hPuZ697PZL8pRw3f0"
    "VZPhmmd/mdXuTYp1rGrM5zDRjXguSL+3Kmo1hPeRON6WtpT7i4U3qvlqpdqIeA3R9zeHbsCk3wQX8PhmB/UeLXefo8IGTP67GRX0rxABcxwP1QqX"
    "XyrerebAXaS294dw5N4PT5e7svTCOeIrkSNA5dlwNaBHa6RXXoqrX8jEEN+ra1kVosJaF+T75ltYWc6H/R1suJD5wY3atXqIhpfqIvL1rsJu35fR"
    "ccMjCKTQKsWDIDU0SwnYSEQyMS7SooA+ivM7gkiiqZIo3OQkPHfYkiGFx31b2iJrVFN84k/xD5vMtB6AJsSjUX8bgrBYTymmAJmkhB/3xqmPFhdg"
    "k2K0JIuJiAoom+xiJEFSE3QS6/8Igpp8mZK8CH5XGGwOm0SOreiojyWRGr66FiW1HibRDVNiqEFP4i0KdBrHewbVjPfT8VaM9MzUlCSaksNTypPq"
    "zUfHyW94onwyou1beCFpd2TzbciEDMe5qlUiCbDSs8+e3SdXBudbk2eBHtwMdof9J2fDxmtDQ9I6nnAzQ+SO7AIx1ufoKSApRUfpE4WlDCaUo7lu"
    "StzsfJuhTdR3HdGYB1HyfQddJVhcspQAKdW8k9b12cXkVrJROl3E23w3tDJ3l8TKxt5CenXZ7cDk4ZoLFfwNEeqSrZgSSXwjvUu4ueHW4XIwmH7L"
    "orTOXYrGGjX0Jkm5nSRjexgmZ4vH/OCmNFNl0ozAlxj0iPUPZNMltCXyqK2kfEB54UYDzpI/9Wzv3afZS0z9LAR7K9vZIgBT/S0s5OAYGpOlbWle"
    "C8MyMR+hbors+1vUTRbopbSqLgZmin4lSKa0S2mSDPzUIhqqKHDsfIW5JmYv0kn+3XFBZHp22YV4HfwSep3uSI/5wLJW+V6vUpf0DQadE4KTs3MX"
    "LRrC60xCMojUlIftrfNYpOdE8E31VFjVCMZYAEQe9otce7fgL4DDbypteKjYPu6dxBFXeCpcN62K2XGBO0oAD+G6YGhrxxTeHdJA1yn5gtl77vEb"
    "ZPHIyE5VaPvr2icO+sbr8HeBd+Lz28zzcKlnty1IY4ypXAt0laksMRbUCnnURMdSnVMb6/WpSvExpjPAyYszScVPtnWrmpZMPEKEDmy0YUFZKoHx"
    "Jae3Gq3r/TUNcDNSb+9oeYytJk7B9yRWgosKmdcsDunyRz4IXm3oGZZJ8QQ0SjMMCskxwWNTN0sTiIk2LIwOtQxEA1jzwf5M61TgKFXmSrBRdZpU"
    "iRkHSbYRfHMP4f9usIFg56wqRhQljNhCgh8VJwrGRkihbJeveBUIeTDtbqdFHsU+V1F0h74RkKTwjFUxqlVBghCMyMpQpjS4pUoA3TP9Gx+rNtiw"
    "JJgNBYym5shxTtZg5cu6XdTKUWOeFIc0zGKH5SLxRCwhWPehhKRLhEXziUPiPi+xthgbCVXoHK1J/IXmsVoDUIClaur3aEVupaLBmopH7hFqPRQc"
    "m/c9n2GZxonpnqcZJHl+HZk+FvGyQIlkNdW1a+wDq8p5iaUBUbFkOQ6oR+WpqHsuRimtVggY7nFWCVROYRos5QhynlEw7pMK5zwEOljqmuQnKH1w"
    "sP+E9kMKRJxEaGo6M9d29hDB6ar719kn7idgXittsWT6ibTn4T3ZjLMSA0oVyf7g1Mbzfiq3TFqMW8mwF8owMZ/n7wvXXftnPAE88lvGKrFeXYOu"
    "rqtMYlTHzKKEWPXvyObLGc2clFVMjWDXn8s1pCsoOFUWH7Tud2lrlDRX1nU74g0maCo2Lj7lBroZt3XQagtsvMe3Jcs65nDNJ7shc0ES73kF3MeE"
    "NRc93M2oiinKNY57tmthnjOpmdxdcM2wqdjeJb9dOGQnZlzXoOBTFJeDsb5SKwqSQElLfmpNzIchd0596jnGAVsfeicCqRa6VlbNxSs+Z7si2NYV"
    "xmNLytsshackYtg2LIvPwbgwM+lXZlbbekRkcvsfE2NedaE4859bS8t0NWba5hNSixkZmxbcWQ5APKgltS84a0ka6EQpLLwd1nXM9xhljVUEZrOo"
    "7PNikPKKZuRDS6IgfV8lamPavTOb8hJ30u5oupntVkUWSOg9XaqAJ9iqTA9wn+urhj6HwigqL1mudq5v8N1k9hjFQWPbK0nFrGdgtArNddbyv6R+"
    "vl8m5xsA3OeK4jghKKhdzcUUvmkuyWfrBUgiW5RkPFHCfvIZqPgpziZfj6urTdA2ZHllyV2539FcV6x71V2pMkPKQmWbkVClzfKptGHDQzF1EXYk"
    "TXYM+6BvJ/Mo9TriJx6SKmfem6wRnx3UcW6X4+sIyBW9LlKN5AdKiNVgfLoWbM/E7Z3bGKFEIS9WQ31Da5bvJ/UNG0nbO55eqfdd5HVU3UaauHDG"
    "f/obV8tYeGib6yWYpmObJO5D51zNq6YCBK0tdCmL6+oLu58mGGZ7kxZcW02Hy5nL/OFrHJCmQ+Vg9O52JFaVNbKjWVHP6XLHfVjqyh9UPBUbkvju"
    "xzcDBFiJhZZQe3jTP6UpaNMn18lXEgkr7jnsaIgvhZgUWlW9oD95l4pTjURILhVVeDHrwK7rzjjYK7621H+vAHq1Lv4DlgFkec953CukN6zQ6gV3"
    "RfXlN8iWpRfQ3byEHASnusSK7UVp1F1AvEI1GfFz71EXL0kVyzGvArYVTPfZr1xrEUThpEbwKeLVFrHWS5Ili9BhBbwr+H2O+Q9pQxtERBu7WyWM"
    "q5D5xumM4dECwhUtbGnnhrCzyAfkQK7gjG/A+i/RCsqw0dRRALsQgrTbqsK5RZKd/cV0gkWQK3TjPbB+yM8IVHeDTuuGtGiMYK4kB4ndJKgYPZt7"
    "9qtakCusx7hbMUob8Li5mguzwUuAo4YjvLy7/XRBmhcC3TxOEa902DpcRQMe1DqiuYgAaT9TvCv3O7FT6h5eg3RFDy7Dxm+xbXqTGNBcD7wrEND3"
    "kKXZLiMa8xLRdGI3GflQKg73Sd8H1pVRw+7S08dYTzRHom3TLl++Ztp9MvVgWQs9ca4uuYwQHP3p4+oY3j7OuyaVC9mELqc3zJXjPLJL6KZHV4qS"
    "+D284JELBUj16bYnxCbgK+YUz+bQZaJTxjVTJJn+sWcYrE92t5nvENexKSLf4r7q/lb2CX7lGPCCeBxKk/UIWPdFSrlLs3/oqzCBZ+yV2N3CQ6C7"
    "uWXNl9e469cCqdp3whyfkW17RDBYfU2NVBAQsVuMFE1aED13yQ6LIbbd9Euz7gcNKwxBioG7PxSUZPXhEJCw4u8UyAL9BTcwMSbm36QNwCM2tL60"
    "VzgsCv88xFRAD30FCuhF/hQxGWDd2xHy1N4Br1bhHOkAV8hzx1tqDW58sgheeFDhwut+Ms9+c0BwK1KntgjS95KbANta9+C3j3iaN+L5KXtPllGm"
    "RT2LQ8K0CvP5hPxY6z0+SylES2Tvr1l+HbyyoQT1dPvph3TP8Mp8srMG/+A3aXdrIazsrOwCHADAKjBDtGHIccYYwqgekcbAJu89CRo4pVWWYQ7F"
    "hDWzChOvqSdcFb2P81llUx7UOPqQ5CjiRnF7K4wEYL8iEuA1aFW3sMqDjSRVBnpjVdkpszEPWirOY03bMq3Fkr3EI2ilDFnF2Cz1cFXhGyiNF2RP"
    "YZU00q+qAGeVAVU9ZT0Xt4j1OmyYPceOwp4wVWYTr7GxJWxAdVWxGopwVY1vZLBVcsMVuMrdSIGuQiMQpr0it9TjVzVK5xzJqqf20RPX6h5pOIRr"
    "xbbORTyLGNqKvdBEhAznYshWZNHOOVyrp+sc7E1QrTz5MDvLka1idldCtkoYotvYMsJVAm0VXawE4QoNOxnLwVulOn4KcfVYC48ShCun0JNN6wCu"
    "8EMO4Ir4fup8LrJYGsjFCNgpgmH1gG1FR3/PoVuhT1zm4ACtUgqOIK28clkEtVrVonBM3MADuchqyq8iLhGjWz1deAoq+9MPGV/DEWcPmCteEAoK"
    "5E54/WOEK9IgSBzywYJNjzTMCOUrBdQrDEQ8wg0tYF4h49Ji7Q2hwRLa1X22fsk7INgDkXEbw149ZasuNlyK4FfeDGRWw63wLhEnLKBgIfmDWrjE"
    "MnfJrH8BxxLb2OFh6Xaig4LPqBkLy4kbQcIi2b6W4mAJHYSraxhYjxFank6tjILltMocCctLZx05wsIyTcAhYbld9GhYBjHAupyDxCJtdknoMcLC"
    "Uma8rToXDemQsMxrcLpvYdyEhCUy0cCm2IBIsLBIY44gsKhtot2oBP7qEodh6WRT7Cv/WwZ5pTZZNhmHfOXpowR5Ff7IRc6UwkB8eF+AV7ktv8Xs"
    "x7Cu1Pm2T9AryhZlXSJJ3hDObS6P/aNdEQ6Ukzj+mUR49QF15QUUPkMScakfwCuaRyTEDoB2RZOJpF5FnBiG3maWHH+JxUWm7KKrp4qcxaKM7Bnw"
    "Cl3jFxn87KAYVwUuAMtDMCuxg9mW8SoOQV6xM6PgWDLz4EigrtQ5ywegzSS3U/ccnRjmkOCUsI8vWsBi9CTCSk5LStzjYQLilXeCoBlNFkEf4Fep"
    "lcuuRHWV9+Gdy3GwCifWAwVLvioYbZvSS39vOFhy+xgGy7EqHrrkDvUG1P7BsLhfLeV9RFZa4S55R2y/EFgFPuMe1ziK3IXDQ8F6rIlrCcv3oQ0K"
    "tnFIgzUfycVcL70XKxv9ENbhgWFls0kUsTxqw0vzM+b7RaodJrIgS7tIwUmBnuSL7PTfhCmRzOobGiv5OBO20XLs19GSswWppfQ0fRBsrBDsadyJ"
    "WyRFNs03s8D7gLqBBSbuYRWIdcTMQbGeLmgdNLCvBJywjItF2oBTfUk9umHYURkyVuR0YrFR/FQZJStWg9EHx+b4PbJ5tkkv9TBZmlknHkNS9Zug"
    "spxFYz4ASbWGvX2Y4GWZeMWUwRQsqxjrpaMpYWVFacRqWxwMK8vf8pXdD1AVWeIbTnI6HFkaXgBKWo1pW3QYHKKomZCMOyA4Fg+KgV4aNjJhvasR"
    "NOi5mpuH/Apnf49fJFPDbz4vw9dLCbNbKS5g71BZ/a6hrnm1qIPqZdL+/jdCCAK0qW3xMh4ANiuKT4oKKidq4UyR1DucShbHCkU3KRgDRwCcdbx4"
    "lpqQIC13NHARk+0c5TezPi1W618IYBbvOpY8wIFmn04+ipP3HOmIYbMiYZlAZzn/YA/crFz1M62EluKI5nCwsyxGkXi/it1SUxYQ3O4Z0SRnJavY"
    "JFdbrbP58PG02P2XyH+NmKksDWEq1UfLVpsFtR3vpzjjR8F1wMu2cZJgoYuG7wFqK9afoxd8qfoaHYj0VFsjnMojxNkqBvJsG+KoqOzRiu1bM8BW"
    "TDqmGfLWERfvG2urQADZoUdaRGN8UnX7vhC3+CFxbbNrg84PtiWPIut7LG1F39kX9pb9TMbBTbyZFxGm2Z7RDXCjc5za3UXa5H3ibqFTz3q+XuI7"
    "tEF2EelJEdgWCcI+wLYKln6NomhotN8gwC2pGSfVAfgMQxQtMcsRE4TaHila0ra5WehyVXEK2CplPMghU4IzMm7KcsReIzc0D80HmonckVAfcHnQ"
    "StB7KSd9WypuKrIZ1MplnZcPmFTdNAShegWYCAuc00tE8JGGxyPrn0FO73HVnVxNU+pAgM/F15BI9K8DMUvPP0QZAgXsXC4ePlNFsuH1HtOIWta4"
    "aT0mDJDOLyRCapKjCq5qv6f2HJVpXiKL7n5s6OmxFeK0BS8tAzXRv5rloRRAp0y9FQVwwWE7c1qFVhhL0D+EE1U0I4GJkNg/ZFYdC0ttPnSePaYF"
    "rvYJmJXxsfiKbFAEswYo6zOKpUjH8GBbN0Fl3X9GJfGql8iJJcsLA2sXTP4KLhIdIjefXQ4u530CafU1EdzOPE5v3c/oBWQPC1xM4rXVnS2JJO0V"
    "UauHtIq93jbEATC0lMU6JwgtPFIgaw7Kjj0cUkySGp3cK6IWVkTRPmI/VEwPDG/wvbO2Z3AiAUgrVdSSbLcypFaWJURVN0uSVlHA08pf0ByhPQNp"
    "uaC4caj4hKNUUq9ai1LUP4gWMjPM0mnKystuf9UrhefrQMxKye62YN31ezvoWQ+mxXGdLMuDP7CkyXMLWowRS4gDAmjpvfI22a+4u9slzjn8+oCz"
    "+pnLXt0ePWCzWCFA5VJ81MmdDcUYNZBZmfu4Jq9hT5BZlBi4/nRdfAmJ64SCiQkRcozjNualpOY33cvDxc4SfYnUpHvS7oEKmbdye55YEqkysLUk"
    "r+5KdlVa51HFxSok3cS5XGA4ouJ+vYBZxInvGdSt9L4QapX0AL2zmUNYN0LsCed93maHM3VG555IS2nIjBBmcMtCRwKJa/FR3MZUZ9os77DWV8KB"
    "BFsw46QUy2H7hbb2GwiVVQpOE/HUMNeCv58NvTzEqadsno+m8hZvO/IZOMvR6nbVCA0pziQ4wttiQdZGHYLHqOTJ4eltw5gXWTe8pzbjPTJI2Rev"
    "bHbnLqm4qEZSwe0D8c+JOCOKOBBCVjHFgS4L84NCbKPMYJjui8Gtg+Nj7cHha6VELlE4cK7M49tPVPybBJOVit06vKz0uRQ4i4GwmFaffvh028Wl"
    "VgQjcPeXu1vchZCvNsaLbCnxB6jRgnve2tpRbR61SwtcU9iFXHFZbuJ7PFQQLcsf4o+Y9hE6y8ZRAVMuakoja6fUEyUr13yM0k0h99lOauAeEWhW"
    "SiSFUXcul2pe6D1un8AxXOZyPpdCcokPC0cr01KFjSeD9LGiowHUCqlmhyQOSPFiCcSGjYsUHxheq56aMUgoQ0W5gI1st6gA9COmmyC2woUojN5P"
    "lchfP85WIY5UjiGWQ4fcqbtcmVEbVzxekzZJzvrLGuChwbZJFjBh+/uLzIGIo6yIiWBWhZ0M8bXaqCUbOLi/pNUkbexWpLedGNOp0CpG+hLALhm2"
    "KPeIgo8cv8t4hIlh3Qzrp4D31O8N6VB06wJwV0HYcwgU+xdd8mX3+h0iA+6WlZTIUYraml3io4TuOpB7DJZnY/p8UYszXLJWXjyj4nWgNfYB7bWC"
    "THKJA2YFXk+tt+5LKybcyXXzjTYCetl71IDPJRFbXXbK+hqwvYqXV2zhp9taY1QL6wXvP5ZOqtwiLV1cv3heoTzkV3myVCjUj8oowydKWF6WXCne"
    "ajKoHuW57GU4L2nAO8dxcW7TFipYSqheDsjLdEv8DDkMC8BeFKyyBAyeDQU5iHlL7WSO8uWWhewaVatVx5brgL68jN9wHUMoTacM8JU1c1mIa3Ub"
    "ML3KBpxkDcR6/T5wveIk/yNC9uIx2cz1OXTp0CJTeBRO3LlETif2rXF/C2RG+H3JkdcqnBCyShC8QjsT4R8rRwDcZXc3cQbAx2T040mWkKryO5eZ"
    "HGTtJKfvSSYuJ24DgSSp5nvA7mqinqJbyLksbe5l/K7wp+BCouLR/YJ3pUM1B0fqGk1kyFhRGsG+kbz2OjlLd+l7WvuF9MreMyAvpqFb0rSPbR2y"
    "QlyZj9R4eBF3YEAvoeXvn6m4zdXOrW8iftcn2K/wovTPqK09ambPiRd2lS8zmWlkP2CWKsyOvZ8SBlmifkiWoUVugBBcTKhO9fr+MLrCI+UmMT2A"
    "uczoyaC5VGKW8bgsjsggS/S5i+JN9qAFqvdUDnLLpQIahsEDaXkfWm+YlkU1zhxwqbSOXL7kobfo+Qh0K4tmB6ytCGYrdoPkIFsqbUSXiBu3UCJc"
    "qD+NA5/PsJ0zzplyuhK0radLnPlTYXZf2lZDsrUs0JFCbxUyYqMuKUlKAY3RjL2lxg5tLKNrbfgKQN+FSPPF+MTiBkUuVoM2D305SucMRy0NEql2"
    "YM7xVyICF3wv04BEgsxBUofABbSUzzPkohrMRWJ/lKZImskte9kjcQFZr0cBins+ShElC2jjAPW/m/vdULjqMiPhanCyFDAoOGugQDLv5pjZrNsu"
    "BESuf/h73p2bSN9U5U4t43BKtzmFM10U2rh3NLhx66njixT+u2iprysMxiXhPDrngMblbctw5K7TjX3uMnWuhu0jXQnPIiU+pSn6hGFQRc6NJJHB"
    "eaU5BYqbm8XIXEngMXPR5NXmcfKiY3saDcB6eqnqVkrzCT7eD+D7JGmo9ZIAKdS0S9JsPR4l8Qs6dK6anYiYAl+eFVoFg3M8C0mjmMaxZKmF89ID"
    "rlIGn4Jzecua2H2Uhhx32uJ+ATUMKsHu2rnBQCSBYXg+XcLzsiRE+H4Ddpf50iIqiUOiaP+hhU97YLPxuRRw79JjKEB51VbDNfLrCNRLgExEG/HZ"
    "ZQLvtc7pNzYNwe0iS3gN56692pfEnvfoXlmpICF8+dy2iHMqc2ctEOH0QtoabNvfHXf4XfGBOdnIqF8NKXCGi/iQ0ChXg9vcq1H+XgWCRkCvUsMw"
    "OjGhNEPx6kWbNCy+VJUrUfCJYmOiihq63VKJmuB5CTaM29fjUSit4IF2sS6tKyoXcBBCF7vUVgy/Km4Eb40l42aHsEoB79LOAHKqcUBViE+xu0S1"
    "QYOD9hcV4OdDHUicNMdyUq7b5SA5mnC6Ck1Bse/0nvQykc/3QlipZmfqJLhTGIRdw+4qcpeTYE75Tch/QzfUlN57+US1EHyb+p16XC/uAL1FyfwX"
    "41qaAoxX6IsWR6a0FwYTh+aNiwpEtz9RB+gDAcxL2vEbbJeGpz8BTVbDWEmrl/qpJ53zVggDEsaYE0gvT21RJC1IXCMgD/GFSmQO8VXPictqmS+E"
    "iyhm95fNNMNyUpPviyHOhUhoGPpXZgjlvbY0TcjdzkSrElOWSkVWdq4G7U0IjKX6Uuh0WNBjAj1rWw92pSfh/kCBivglVR6xSlG0VvQSCfAnR8MQ"
    "1eg2nbxrBf1MoQu0Qv1ylEct5L0qmJvmrwkJfZK3psir5n9jWZa1LaBcJfYESGlAcKWlL1MfB66VD0546UkQrk+O+tXQGlN6kDYWaxZDlJGISNIW"
    "eT3NkF+CdqIiVT2bRIdZJlNd68vLQR/qA/rL0Hri7gilqmvLBrGu02kSAFNoZETWdKqIE2hDalcWTvWvRIIsjpymA7qbEfeRiqdYak4d9V9X2iaW"
    "rE2itBdHfcqA0ZBateJ8SPyXUQM/KSh3w4lyE9r2RQI7aXfOsZAsbU42MU3YEyvG6bNLil7mGyw4J4iuyGOHOQq/7L+UFWAHyLBQqKYNRMXEzb0D"
    "jhZyHLG/VFlSzgCPU8nixJNbpEjVZNwkOY1URhKzWK50K6YXi35zEWWGgChIBHnntiaEi7UYXTtD/IGD2Hkkgic6EebqvCNJxlDaicu6ckstJZn8"
    "1NCGtWffdpaVanxEq+yczA2RVdnougb7Vr9nvYiUf0UFk+KpF0WSfRExEIJe48sFq8MzJcGDY2rBhHxlqhqhzNiC961kpdTEKkqsQc6hiSkU25M6"
    "czvqcShqihQO1fQWypNxVcERHxW5CEVnDbWwaV2qes2CJVHoR2fqcHCyhQkzaTFkkDaDCd80VDJaGN4OrGGU3Yp/yDSwdNykSUmi0XDHFt8ttlGo"
    "yw4KjhmrKnqnogQiK31Yo/7F8yUdwrXSqal28JYiJQKVUomsIEBainOOeLQJteyRDdfG9gI7lluZ7YXkJtV2KqDNdQhmwjdNqYqKfgpdvYqJY8IN"
    "BQM52L8k4LdjpTpJtw78sFB45vJ044RcpxHE7DOqcimdrmCZWcaN/4IWk2/HF8nVubjuyKzn2B0Lylt4k5iA/xxcD+5FyHXjTiwg2NTeM+UioUDv"
    "/zMI6gBWwtcy8avptXTVyKIPS8UM2aC/DHkv5imJxEMRuuxWgltE5USlZspuJ0w8WUU3BQ/NWRVxjoxGXE9+MflVefTVoJa1VtK5nPq9kNF9oZuh"
    "+rjNSd4TO6fYvdC1yin03qqtXgpVKTJrsgr9D2IQMluVSJJxWGlxkjYTZE1G20Nlqcd6FDF3sP50UaZhtr94xUNJfM0GcWUO9lYv+f97YDOEbgMh"
    "Wd7PWa6NeJ5IT38o3bR9L4Go+0sYoNwrtKnzSwGtKbRgrgLSmRSzh+vK+d2myqlfV3WAUpNA53vO+0gulaRtRMBix/4c89kc1tmXy1tfLn/x5fLq"
    "l9d/8eXyjS+vv11EPaPHHtEzy18ub3+5fIX+/eGXy3fx3+F/9ScPhfbl8u+/vL4ID/TCQvtyeZNGhWcfVDTmF/SJd3Xkq/SX+S+Xfwc//wb+Wunf"
    "HuiLj4o4afQAPPYHWiI+Bm9+rMOuwoeLsGk4oevvw+fof+crms0i/GON3rtLf/70y+X/V79eAFLDDcNf+VMP6LOrvDI30PIdeuhaAWONdvxt2ptb"
    "tPgbtjdrNAEe+Q8lzDWa1DI9u0UfeFT7bgGEDSlBnviMp/v7L5fXYfoOge3L5QX6COzsnToMNlzd9SVd9qd8APzhqoGkIs0lP8EarDZ6kCd9jd5Y"
    "rmiO/KcrRmAJZlv82mol9EyTokleXyoDuOnsmRjwY4/4lHS422UOQaPzyd6gBQl5LSlR/J7pm68V/p5ivH25/C7OD59d03/Bs66R1nq717+8Pk9n"
    "Ac/eKV+z3BtSfKxCupC1v0OL/i1f4TpcOHpg2zbViP8KnivuBO/5tUaYOKWEZZ0T7vmlL5dX6D9+p2Nu8TixWWt3qfYa7ANFroGEB4R0YKMCx9rL"
    "TjJNvM3cCoaeA7rohTlHdLGmU7pue7RKc3kbKe0YLXyO5rJNv+CXPtCpP0r2pTcqXaNkkO83MYFHzFfv0J/xdCJCkdvXhFoXLY9u3xfEq/D138m/"
    "7RW3jvjGmjH9u3Rx3Gw/pi28yvy/ByfrD9WuYYwSJVTJquUBWO+SayFBE31fJqqcZP/Ad81zTAWa4013dTh68UqltHDXhkuI9EjA8Q5j+vDK+3i1"
    "/6DS5I7RMtH4HWbKQV+4RQ/eKC95i8hoYe+wevlonommlPJALt7y5iEg7fX8dE9a5VUvISsqSGfjBfNhFn6AvQLzETedp4NAbhTj85GsZdUTWOAc"
    "nuynvLqDgPTpx/6gvH6R9YqMxOKNg2Vfphsrmh7yvhNu5HS2B0LwI8H5MU3o/2GG23uCXmqjXntCLgQeJomOZVEz8Nc14/7lzeh9g8KZHxIAYDxb"
    "UcqXiTr0ou9tXsd52fDkOutrm2zuyGuedf+zcuG3gxRZoO8umqYw/+X15VrgwNIGr0aXe/8ogs2c8RHNb5HIZZGFzAfG2cgAIM1BiKFiY8y0YVPL"
    "tukrV8KWXCE+ME/jvh3JVhVZxe3piUFoxopR4A36+jrr04E336ZTXDb+P8/zrAUkpBObJ5NIjLha5bM3TqEnxkt0jGxxXuFj5T/h4JWzKD5ukPu8"
    "O4xbSO/P89rq0QuzD+fqov75g3Duq8pO72aYhrlNzsc6T46At3vBGtIlm2ctcJl3QjgQLfKBji2GwtniEH28GFAOcy6oSIcJ+/mhmIpsS89lWIcq"
    "72ilpBJGmyh6aA566JgqE+lqef9jfTZGQkRCxlcf8i+Chsj3SfEQjeY3+ThjUERPbh4S0Tg975sCI9I8vhBLko7V4SPWWTk16/DAiWqaPDSbLIZN"
    "pGmmjwS4RGLEX6iEXHWIiREH4E0yP0/kxDEl+Q1nPJe8UcTx4jhBMP9xkM9iGMVg1tCZCIhi7kISLMVc1qaRsp6CKg5h0jgP1KHwcYBZVFl/x+x3"
    "xVukL3yhM1lTp8q63YAX3K1Lr9iZyAnUZB6VcBnloGXnHzj3onCosufCgTR+ufyRiZEao9AhNpIN/rYO9ZAdlgG5kS8Pc7MF5LRIAG/H6I0yX+E6"
    "YZQEtDFIxeU/Mo3GyI1EPr9QDnqXJ+ydPdu6mOUyoqM6HXUSpC/kwngrw3YkFr3EVq5q+EHZWC6hPCa2evmtAtZjEOh4Pr/mE65UZn2WIj367b/l"
    "nBNXHeYjneAcW+ox7mOQ7OThC/CPprpFCJAk2W6YCybQisJAmq5I3/sDc8wcELJs2+S4kJF6lXzS8CFpax6ZlhcQIv0JOIRIO0vHpxggktjD2yqn"
    "152/XhNszGdPG8f6+jyzWkOLTDyftaCRe1CYyliSjqj8xbpWJedtoJJ0rbZU33wQYUvqmV2JNjnGmFS1dsXuWAI0SUtY1fu0ThvwsT1cgzzJzCGa"
    "dL1EdJiUSqLbyoWXe6NTluyEK/uBqOzHsfcH9trR6XhF/05V5kP7g7LUPRAvdpaJmIjR4Hk9GLJlUTfwD+cKR0+Uy7J2RGtkJnC1X7zLRN04IOCl"
    "10+OEU+e/3bFAZdKpbH8R/xZi1GwcSJ03uzLVA10r0iYNJHfstzg/w6K734RMevYndm0pfPCEUyjviMMQ27cHbVkEVWzwb2dG7aHj59JbIVViS09"
    "TXNlrtXHJJgi+IhxvgNilgfbviDrw46Y7flFbZzJgW0WXKVXgvOft6YX9maD9+k36sTQ6E9fAYcciLOOUHqgccoEeEd/wyrvnrE4jaEN9Lhbslie"
    "6WqNM1b8rwdC6fSmetne64sT5PGtvUB5CuXoM3UziaL9wb18aPieqhL0FpfilzpR+dh52IhHaompKKW/9h627EWv5zxvu7D2YeGC9jPPGjU+3phL"
    "xNW/UIHLk/4dm0OBVzxQ/jOnFtNKYa2r9vA2j8ebLBHnWjuyb2TRuq3PAr+1ruHIARouQvDqHRB3NM9ROMj+PlLzwQ5327QkHlEWV8jW+YjGWlMv"
    "2RVWmBLs0nxPLjmLWVIcEgTTXPtTC85vYhHItJk9JZ8WG6sAalprw1WqSNzVZT/Sb9x1vpU/JIinliZkiTvsKr7aiHxaZ/nHjr8qyQ5IfDoeGtWr"
    "W2H5Hgir/6ywlNoL+KmqAGwZ5wv2+f5RVHPPBztUHkWhm0dez631OuG15mt6q/ZOC8tZtDH7YYvODryOT5k6eAAs1p6iN7pmD3hj+uNTYR++sGWu"
    "OTpf06+mJLBqit4qRzGZBf+2ds17h2/d27LzoP8XPpMrIpq7plEFHfcGD2sLWhKGQwcJjJIWtX+Q1zqNps+so3Ji0UCPhBzh1/Um9RHgww7U0t6n"
    "JkpoM9Yc85SUnCsm12Gy1w+bLv9y4GazlfZAnE0pVgTAiaPEnS0SbHihLtrSA4a2L5unTnlWqj0cgNoymWYjckZdgY9wxLkvuhYCXiaWtWmpenXh"
    "3yMArDVrv6zlpiEql7njg9up+VVjRudJQugZOVHVqTXpsJJ7UOsHiLJp+4e7LbPg+L08ded65GlZZg/s0cHf9pO1koq6moQj2fN31du6JSfqcgpJ"
    "U0lrz8p8WCPi7CEkadgvWG4P4itRWqo/7iWVJ5jEe4DTLUbrogA1529kORQsj94VV6bB7ebj7Rd3t6jB1Go7D9wWE4fGf8esEA/U6/dc89DoRPeJ"
    "zFuXlR4ScVyGJLmcamsv+gHtTQ6mOpDt8g2C81U1TzReCQwOsBPmXe/pjgTpiiV+mN0/z1Qkkm2Lxwvu7OeQjjzn1SQvT3PzluDEn/mfur9ccZE4"
    "xSNDir1HDyw96FYVYmM0iNjeZGJ7d24w2SwSvJg64q/Yu+ml+b06j4RFvH8ieMFrPIvwb7/kBUbs6YqMZCGMksijG/XXASTcJ+UN9EFzQprJkfWO"
    "TcW0Sm5aigAbUQY965HYSIGCMce2Um0vps0BpUznVhFaLHlcAjVEmXxRUpKR2pa9poaMo6tbmni1bWLlES/ulr75UDg5Wn3LlU/rkHmt24Jv86uf"
    "qer8hZl675u83j9ucV8MvpAZvmCxvlX1GUYuq/7Ajfdu3NdiHZMO8kDt6XWmqc+CiFCtsgH7mD56ixa+XKKQ8k6ln1VRJZRp7OztENVpnkkzLnLf"
    "HsTSbOnMarXv+i3fK0Ry3V6FUPxAbSSIik8OBTc5EUepo9R2Y7+7WXf26amXCiv2gbhMK/idKzxD3nTnuANXFgMrjFRQ+LV0wnhqVK7A7KSMwtyQ"
    "5xNlphbwmJtfnddqwW1OneobozmPYteFvAvlZjVR9aQGKjcaVaPuH9aZPihJyZGysQ/PZp8ZzF8H5vOebIO63Q7mudx7m0ecayAlfjVJvsG1YAUP"
    "80k9unhham+sGJYHwI1OxEesd2KLRdMRjvey1A8TQnpv08rHHch8mClXacaTdtrf2+WgxrbP5JRMmNreYuL09UUu9bmQe0KYrqNnS3QRRe4XpiiG"
    "yzegJTiiLNbHrQ8Xddq052VWJWk265XWxSKbrfV23E0NsCv807saJGbp91vPlSQUt6w1QpoVXHKeFGR7yQXH3PTrxawm84MjvXfLZLmqdU6x8aj5"
    "f57flMJkIX6ZDizvXaGdWDWRte4r3GJ/qD+lAWYYkYkvhZ7brNmZ9OBuFCv81WXaa1FuSqFBGbSQlhoJnVTiBDuej/EbiI/d4Ow2Mq+TPn1HY/uO"
    "M6cEl+YB7CFbMViRqVfmtlmjPilSy4jUUnk/HTPy0fQdsFtMvdQ9nMYWE8Td2jTPTzCiLxmjNsM5hBeakj2L807VQ1o40fJBkL3VrPrIllBHPcIN"
    "HCO9W86JYt7+yFxjEYd/5LMzS8kZB0cB7zuqFnVlKPve02K6THz0HXlrzhD9JmGHF0LHNdMtPJlMnWbor9InVtYsmQ8iPQp9l7i1iKYaBGjV9KsD"
    "pdeft0iTdkVS/Xw9NDEpmDFqlMkWNVe5Hyr8uE0pysIukG2jFpuZ2YmSGtJfg5uQTidaQE+E8r3o0sHMTPLLXcXs0SCXD/QtFoN7mF0QDwo+04jd"
    "5wMs1wOJHwa0eaP1FE4zGbJwQ78urPO9SteBoxWvh4WK3keIf6D+lh2OUKrVE/vSyJrQ1P1trf3KPovQ/9qB1g8nAaZ21y1FeK9pCqI+H++z1oYN"
    "RuPjtpJHUlSs4llI+AMVvle1sqs51qnWYNBxvarE1kIfaTnqJWC/EWmv8VFKGND5t3KtoSY3ZT3i5WH4OgWEtfQjx3e3130UstDjJUzuToF3xlqV"
    "uSOZJq77BO+SwhaSrOaTAvN0aN8K8/2CfzgEJj82fZk38ihQ4vty0Dc1DOjLH3/Cocg7h4a0BiVJxlPtpx9DbyB5VcL45v0hlZ/esxRRS8x6fsfl"
    "lY3Q8snLwboLy7yr0uxGvQSox5vvlzWtaWhf0hy3G1HoXQn1HDdQilYeKRhhgX1C0zeEkoJ0v2ytE9P2ekGaR18uIdbnZTlBXeWg9yMTKWVfbwHI"
    "PmmiW15LAc++2Co2te8WA12l8PbEJiJVzgzqdd+sLEe4z7eBFftbPFJkT5Sw7ms6Bd8t9FNlzFhMvmpVs9JntzvZ0GR3tdQnigpw1DSJje06u6TA"
    "0SM0ZEUvTv9idQNaflpTqAsPMsqxJVEPZMj1qAQhKD1Xl4r3FCFgYBf4u9j3kiSUlt/zmI2lBulXLE2HpXtBz+Vv+X6axHpxag1tUKPi/0jplRav"
    "wFVbbouiBqaVMVPqA/rGi6e//8bZF06ePfntAlQ9MhnhYMcpLjkbhQnAFh2gICzu5+iUtLzylsldmvrtJo/utsLWHy8nMQcbdCAQ4m+0mDaT9CEw"
    "yTpY0rU4WSD7w12pFLrJMe2r7wrOEolHzX+SVQZaN1j7QOzwp9wNjXaFPZt1pvQA9FlvyvKASSry2wXVpY9mlBmOfSF779t7nTvmrB584mmpzl6n"
    "nD3Xnp3tYhcT/idYvyPAFroUHbROBHaK7j19IZDmx+b4H8g6D0gFuWOO89aFTvr8Tc0y8/r+mao90To/0lf1jL4o1+b7ZypRy6hAs7+iF0msT5gy"
    "pupbK4KpN98cb0/y/Nh61bCUd16dkD9J5dp/fY2TuGPikGSOmq/C9D/UQzYJv1r17nmwp/iRxfQWT+Asi54My+fJ8l2kQLVK8lEaU0o+9q2LwpqT"
    "prfc2+/nkYRMwoZRf1t9nvSNXMwGwzzfZadv/BzFb2sYe+v8DMwXLDiNeknBathO9ZW6m1bn4NFOjd6vsmLznJ7HpnVFiozgdZV63F/BmcMW+A06"
    "89u6u1esyjrq94xzmWgNff/Md15tT3Z/qu/OjuoM4d+KeVog5qQuV6Br//Pg3/7t/660NTRzYbozBabr9OiFgTDnSPJ6Ta5s1r4rjjOVG1H+K/sN"
    "mFg/qiywKA4J/cS7PL58/6qWVaxqU8urjZ6s1E5F6HG93979U8iZCgnjhYUVk1p9gjcW7M90TYM+c/bkG2d/9NKLb7xI0N9e7ZYzJBz5OgWn1OTD"
    "pbobBfVqIS45+FK26ktxUmKU016+XhI/EQdopFEX5ffuzG8fD2UcmBaGHbqOq/e5fjXhFmmEOvf4xxZ0vpwkQzsMKRi8athucubX3sPBhRiD66BQ"
    "H5U8Zruwt7KV96u8a2aljddWzapd1G0/1xr+Ea/zH/7eklIMG2BbtelHbNXzgQf8jPr9O2Gu600TO7+QnEev4jJ33lQBxyJIAnSGpbKetk7CWTPs"
    "cO7GiWn397QRHFOcH9C9528685Fop/HShbvDU5j1Df0KPCHtu1HVdo04To29WVe3FM9qD+P21uNLdSe5MHMxXaNHbRjhfIE9u72/b2wlcmKa15k9"
    "jyE/rnfn7M0yF494LDLzcCh9bH+mnBh72g61SKZuUBKolJyqq4Q3+Jq1wLuSdBlY1hz1L1hbC0leldcekPu1JodGxsdDfKrZE1fnZF/tp9yCvzjV"
    "7Ux3O6GTabySTBuRFZO3iNXm52ZGZrvjnef+N5Fhd2KN5v/+jvUofM67yme/k8TU4mbjH9cmIKVZMIVZh0j5x7Vd1xBYvZu0Gd4bi327nAZZk5o/"
    "ja0qtd3JvB1pyMxJ6gOI7zNfvZXoaCM/bXfSLpHqt3pf3YQIZv4je/IDVWM4Q+8PTnX/P46XChkSVVuakOIJ/B1GpWe4YKaUpmCuTPburRjzCZUz"
    "/VQzBEFeO2B9DuHvTf28Igzob483cdKwPNxe6/i6j4v1fg3zKKqSzZXrq94HFlhEa/jHyCSMvS1rtuYXSrHLEWPmhQv0j5F0iI/8NrXpynHLgTTr"
    "4zf94iY80lTB7aD5MC/9TE3NR9q5fT3yEjZhs+DuPvfc6Mj4tGtZaFpgngKl9woTn86ceTVYFpH1ccKlGzWq+kEXLEU+US/otCaHW+NTk86W4lf5"
    "hdXAvQ5uQUW6btPe5shlLlvmd31kNUaa9rtG6+Jc+U6NYhWZxYkUMXYdmcEhcl1Yq8+dgv+IRl90+DSLSjmb6eQpOMkdR3/UnlTntwctKGV8uLaj"
    "No8Ai1AVvCI1WjHPAEzB2Y7PF2s6ObuVC7QlLkfkAf1yV50hUloaZsgbKMHLwikya9pU7rSaai7GP3h6K7bGuJytmO7idclwN95Et1newk1srR8B"
    "h2sPjexTIqemVu+0z/42f8nnT/dzRQb6zJtKDYqxkZFpb9Tk3qDeTfJ/689XmixG/sHIpFol0sjgXFIXV5RKW7CdrqQJw6laF64eaSfexikocY17"
    "d8W8Qo8K5BqETDO+o9F/oVzT1/nGNk/EI24paS5HPdKu6ESoJOM5X5zxyGfKp1VldgalnpDaXYwm8xtrVliulu79iVA2slQE4QlK4AfCr9gxqEgy"
    "P2p1ap3NkfHGgFbKaApaSFMr5kzvKEfYaDuc1CdOnCU5FwA4a/oJ1aS918IVvR3bFz9HLX16nOAif1bGSNVG581drpo6tslUAyWENN7QDK7/DEvV"
    "M+gsCp3gQmFB/2m4wSxI6xGya1hf3FQ0tNIcsSuu1cjVynUPiWVu2kF+q67r3d6wLcVnG84m0h2EXUiHUu6qGprJh7Pq3br3RKrs3TYpVwwFelgL"
    "5ZzO5lzzKUSb3LZUpGKNdyVDia0lnx7VKSXY29D/Yjud4h7baWazPxGVsBe71QV9trmwKly5htQF3X4b8u1yoLfWoZ1vPfbMxeQNLpr+D6kb1dXv"
    "fqBg1XWWa9Ibsq86sKgayox1FOPz1nvod1ED14GIjYUssp4ln54wlEWaWZtxyg80b9GBUIR6S4/gvV1fj/uobjsaSstC9Xwg8C11AXwQ7B9rxLxY"
    "SF34ICrSTdGay073yE84n6DIFAi7EMNejC9iqWmk3Op3y4nPa9JntVTjWqdpGt8e0GMLUj8gE7DpFZVIen7fa0tCxvltlZUF42DV+6L0y0J+yzFm"
    "Vk50jaBiaSZmAVkwNPPwMYTGdIXCEabGdFxKkXb9aFTbb5Qs08Zs9yZFO20/lfeU+nWUQd0X/KJDoF7rR6Go7UmidGQ3dakQ33ngekj9IY/1vO/f"
    "Dw5rv69StP7rnvMvHGNxztIa2qPf7UHBN/S33zaZZ3tsNpA1EK9NISf+lrgh3/c1DEL81i+2BpY2bOAj36G/l+e0Z1POAUuTKhSCvt+zzSefjcR1"
    "akseC7ZVfyXrPbB5hCA/MGyxyBUblPAAdfPbejHaT9/OaFXZ3gb1eQ8iuE8CK305eE4X1YGa37L6vhgRdmWt+p7ytKjfnhcsd0wBeeRydCJ463Dx"
    "7T4ulSTNidQ55dwyi/5WREfQq0NwmEAaOixPWG5mlFRvAYZIavTDD6VnW663OHAB029fw84x7dkEFDNq/hfpVn5HezKvKOS2bGGo2gqkeILHtTtw"
    "hNJEpLEmuRXL7/AUriWdCutsskjlWu3L8CqbS+5v3hXjvNve4xQMktqOMo0IR1d8NPmz/iCPCj1dskYYv7EYwlbiWIyfC77FX9jefqS5BaUkTS5o"
    "crtcrwIL/wlrK9e1zvvMnxouX4aSKXLbpvOL3Mkfletu6s/JWpRonVqP5IIDwMPL8UUMW6vrem7Y+0UPmZ9fsTt33Rc+cLlbhazBfvp1n+JyG64g"
    "n+7MFkFETS6YQPg4ijSUYT+j1N2kt2U5Th5POPTY3y7k7v2mf4dRDd2JC/fnA9/CqODPvoVAhLD851ujrdlW9fLk8BRoPe0WbNJPmEf/TOBxMNI7"
    "Molx305r8nxrUjFWZ+mHiZGZ9thsi/78KpZxMY9XZKdhglTnR2dGxloTrUlCRZztwgPDLWqbCP851uq45mihaf/3pAFSa2y2ja2ER6amx0e0FTeN"
    "Sv8Ko0yeP9+dxNmf7p4bbw9xN3pcX3es066m8Y9jVDnH1VIjgvr7agv+BaZxoYXzASF1fmQccX6tqix5bqb9k9YFmux/bY/8hOr6pKEhTqY93h6l"
    "NcHmTrdxoJextyume8M/Cd+74DM/i3tb8eYagEqkiJ6R9b8wgjBN5yLAtpMzs+1pnf9bI+Ot2TE6DH0W339tZNL9wsi3sLY34UgYbukN/vfZdjVL"
    "TZbLV+UsndQ0trXgKcPZT7ToW9TjmXeB/4PmW5L8p4CMOmHH4fyx6S4TQOKHfaM12Wm1qyF+w4E2w0ENjU/N8vYBccLRy8RaY91JxrntwOK7VOQR"
    "ofieHMP/gIXC5IflKZpr7LM5g4QAlEqnrhSPRJ0C34yE3tUz8exfG5ng1LCxFn7OHfJANdkeh4UxZiLegpl0pdR9j3EUqmNT48MEOY0TxAKbTnu4"
    "NVa1YLxjI2Oz8Fd0A8M3xuF6YQlMhCnJVVJGVlhRMjQ1BhfTk5ueRidc87bMQrsvVMeee05bGYRJ4JUZbreAsOLfPQwKbcgIVZRcANKj8jwcwJO9"
    "fF/2YWyEa/hOwhPRUK7O5DgWv5rtmY53bmS8OwEDhhM4Dj9NnGuN4lTtLR4bz3VoZKbDaXz8Fa0zbglyI1X7HPsZ13z+HDdglt8AyqULbxtX6c4M"
    "tYAAkcEVXi9/2D4aEFJbb3YExdLVj/c3D5sBUoqONzvSAU4wioWn1U9aY51uPCucgVT9J6UrMyOt2Smq3pwOTB+/SB9pYQvb861x92A0WFo99v1T"
    "Z05/59Qbrxbq3tyQupPT/L3qWKB8G2C4DS8DC8TZw6vD1MEb6xoRxqA7fX6mNUxNYUb4L1ZYNTEy2UWhcbx6qwUSCckiemO8Nd71bwx8S5OofC9R"
    "wzrRL9r4Z4G/AEuiQwG7tIWCQUY4EX/SPtCdHJvEHkb+A9iI5AR2ILFSLZ2G9SCBj701MonNS/x7snVjQBLjJ6qwceHgdSC6ex2MfutdwabLU3A0"
    "wyO4o1Tg7xue4L8jxtBIaMVvZWJ/A7+MT3H3yLOFj4ZBj8tfgH1MnAMZPtyaacPGTNCGdSemu+ODKGYxDerlUyeps/f/efLlV198AUbmv75y8szL"
    "1XdPfvfkqx4TcZaKXSvKlq7OXcAeBVTL1p6NZolNEzPhC1+mi4SvmU7QnkDJAjwJZMtQO0wP1tIelNq+cbhW1HOFOpqNE8A6ow7AN8ZHSDzBCoFD"
    "w16MdaedAESlgVJpS6DzLRVXsyPnWufbJBvgaKayxtMGbhBvPP84QpMG6WCCF46bhA3O/7stJKHvtWZaqCG9LigLeGM1KQLlJi7hOVIAZAT6BkpR"
    "WLqqJ6jsVeNtkjMvAOtqzUQK3vcViLczMjQ6CewJTp0q3MgN2obdxUs/MkbEPDuOY57t+SRB39LFsZUj2Xdao10mZP0z/McPSR36YYv+3nHgp8+L"
    "vBBOI7+7zkNnE3GH6q7k2pkWjZF4uBC09hmaPH77B5OdLn77he6MqUjwr6J0IK/E7QXtjBUNVHBI850ANm06Ec9BDo2RMy3FG/48xv/Jg/4gSgDX"
    "lUWPvMYaAvz8ygjpA6wYCr2eYgqVxIJZGmQG+ELo/xD0uNj1dnpk1itqs6xw6Uh+oLMX6FPfG+ETjBzip5RbxBGaMC1E+IU/vNSd6b4Jon62NfOd"
    "sZEhUrjh2Ebi6b2Q0o1nFgkH4N0TOM4anZUJH+5I9xwd0Ksjb8JNoWqDF9qj7XGi9klaU4fW/L3ucHdcZl29jOzr5ReqV1qz3VkCDm1NtNXKmjDq"
    "+/4MqmD/pATD/znLhwc2z3B3iJgbfxP+PE7CZHwEJ/SiNpxKjYRzaAtxKyDtYIMpO6xCTp2bmRqPtOz0CdGtX4L9ImjtkZ92ZlpD8gD86xhymQtw"
    "WqN2SAzDjGsj7VwXfUYaoLzWBTWYDpk5KBpazCuFJOAP/5cSgmHkvtCWnX9RctpfAQoYl6+elAZekomCqrzkpJCWoJi3fG2YtSN1kpYDf/wuKjFh"
    "DwL94p4hKXzftuk15ASk5w+T2XzKR+/h7Nu4H948PqMNU86ojXW6yPNPFni+xwqgzg4029OBqw+3J2QzT2NNBu/TWyOkP5/pTE1PCzOYAUWIiAAr"
    "hmdmutMd3QygMFCH2HgCBjJJMox/mu52wrlhLb0Wzb/AX/UqJt11oNVRevkMyMJZmpYVzFi3aWZ72muKrCR7KKB5W1sp66P2bw8t4Az/Gg6aTX17"
    "vmDS1Lw68C33R02bzv6Uplm9hLCn55SfwVgw1JkfvHaGSU7/g0HgyV3hPlkpaDP+yGPgr6e8aRZm52Hk4Sls8F39DOfxcxlB7Eb88S1kNvorv2oo"
    "SvAznFGHscvwl2lk1/7P/IKAMGGDADEfQcVrz+hAaK0yu6eH4X5UbFNMePOjDVOexH+Vr0yQ/4e+0EJjCL4KVwVbkBOWAovS6mf4bzw9fQpobxT/"
    "eY49VfIEqF2uJZ92RuTOj9prpsXdE8/9vHQhK7aDQWE7f75lO4jvkCKKbzGEr/ZZm239pApdbLyNdm7kwhT5ANqzwjRBv/QtAaUXwqC6cmAz0FPU"
    "CZ/FwyibafwAtqQYG4UzEIMfbhgYbjzst1GJM/MAvRGRA4AdGjycN4jJ8TA7MtuF+yskp+4v13zxP3HHnk62ff+J2/VgK2P8JBHaFAlU/NOwLAqT"
    "RScvtISwkHjJ55FgpFInn6CMRY/GjhPnLNEVBZVN3guDk5jCTZhSxdN8NMm3IucB7Pis7TzqoVW+e8m1dF06xaINTkx/Q5m25EkwXd/ih1DtkKtm"
    "DsUTFQJDGYAsn+kwg97MdrxzJ8h59UA6RSXmgDAonDwNPNymG4CKgxx/y7sSE1eQcOMg1P1ER36K91j3ojRTN8WRCZmk0wn4oy8kUx2K1K4RNKZr"
    "Jh0q/BmNmpF3PbZ4OHF+gJaK1JQadcWjngHhM/ITZOMd7mROqJogXRnLJjoT9q6GBQNXbE++1eqSdtTCt4kOyHdyARtTsNMIJDMwgGmZmblhMT9y"
    "oj2r8uKVETpVvrY6exVNQ6Yi0X/qSkRbMp23abxOrAyTrlSBbjeJzuRp0mzwP8ZmAqGYEvXiT9sdag6D46LROQamR2uGrRUBICNUaZXkyA5hR1qd"
    "52bpH6agom5yfqbduSCNUvDfW6YTaB/lV/TkotjEi74bveqPyDb5z8LUlVqAY3dN4Z9to3oRd72RK9buDJoajbyX7xb6C9Cmx1mQOUA89C3WhMOs"
    "WsgCSTuPfRspQHx7Nm+5U4M5PlheP94H9DKMZmQdOzN0LuTAHzwUrPrybIbb57p0bcX5MT0zBbQW5hVud3rrBg8ENh/xc+EjAyo5WLDI2yxTRiNl"
    "7ghA4U3EtsEUr95CMdDX4fzlQLbLAtJvdtG9gfdrZKwLoiX++JHis9ux6iN2fj0g2CPisNMfo8cODVy9YRQVzOda5K52wsxRR8pdDxsP/XvsMi5x"
    "tMnhLqkPqcrHysoJb7Dxn4xx9w9FrrI9fpJclpEtefg44+aY16Fp8sFFfaLScIMcytQ0LNTGhFl3CzBk/SKBlxzxJpyESdqh9AvgfboLhjlSET0s"
    "lBMcfsxR7Pl9onCfdjwbOTyGmzWMIfMe76LMmnmrVYgp+MH2DbON0WJSFdCglBfhK8Asu6Pt8Ho/ENpjubyKRVHkMP0GYWSLhwq2AhjMcJsmy0Lu"
    "/Ex3ujrXRit6QhImxlgPnZoIWRCzrYmWcHVQ8bszYH2jjT9YnbbnkF+ArgNKDd8k0DHH4OiBSXQi0U5k4gfBYA9ctjfhsyeUd3jmg6bBWNuiFrMj"
    "0xjcBO2rO/hXgyRdPp9wNgNiHJDTBPeDdw72AGYIAmOmzVyagmZ0ImxVwiZ3/BmiE0G8G3QmcELkhgF+Pt4dI7WIA1EaC+JXJzD8Cj/A2xNdOmMY"
    "dbql/mHjLiND2N8cxhk8EK6yaP52mTWqFK40u9T7w0k+3bd6WYuPzBaJS0+hzWoGRD794htnfnjyjZNnT77OWLsnX61+8PrZH7xSPf+DV86+XJ19"
    "8Y3TL77+g5de3jeacd9fwGFOv/H9My+eqeAP3/3Ba6d/8Cq888OTr38XHnr15EvVCy+fffHsydOvnHx9H4DF+nz43ksvv/7d756sTsHUcHLhvRdO"
    "vvHyQVCJXzr5+g9PVvrayTPkPqU9sDejHXj5hZOvRDu9V9zgVylyM4oMqzX5VrcDtO+SA8Lr463z5jEL79ehAZ/OIrBl6N9XUJl5i+VQ9GzfKL+Z"
    "r1BoWFyGKMlGCxpW//i8Lqxce8+8xA93iNWpNlrY7a8JdbdZVUjcvmMjz9kHIxcdfFGfcWThuei05Ay0Jg+GiutVP2yM4TXr4z3Vz0NDwe01jb4N"
    "w2awW3aDy5usisHhiHyrrYnNnfiplbQ3JFuN62JCCsjHyfMDuFDUzijuxnK1QEiHDk97uj0KN2tspNM+z7pZ0N3PtUZ/0opdocPtCdg+sJuBDPG/"
    "7U6zOWG5rOe6HZHPXy9qLLuCgHF0aTEX2K3BkSmmp8HqTBs0R9M4zo9gWynUJjwxYPIaHDUoKfjDm7A4yjkda7VJzeRxE2+36KOOC5Hxo//d4djJ"
    "4DcTglXpVbhXpyampc4EbtwuN7gUDo3uX3BNVqeCJOFTYGUffd+YHfUW/K85qCz2NwEXBfcan4S3KO3ELNkBDHmBfQgiAK1EygJvE2keBD00N5/x"
    "vvq7FKu0qYQ8FLzPhhHi40h8O5jcii6rNquX3yQIzpJjJJtp/FAyYZwmpVOTHBDaPNcaavEZ0rTTAWT2FKSUF5+3DehQgGUGiK/TUm2N778spd4O"
    "ODyMzLJTK1IoCq7e2RE0qnUvojuJEmDy/HP8j56ol8G3VBgqyNajAbMMakBpONoDnQhe/ZTpHBIMJasvklFR0l/6me2R4E0q/2Wm2SeDPCxUSC29"
    "aSDMiFd1yopWwrJqYRoDIXZqNbaQR/nXDrxY52kXZ1e+RcTMzD18PE8CUUHM1O5JHI2smW6Lonjmh0VvkCyTWaK7HybiY24b393J+sUPqEWSXKyY"
    "aw9+LQCEmMDWGneyhS+SFyz2iWlmk1H62Ql7NRIW+F2L2Yy2O2AnDB4RDuCpZhNeoqk092kwWMbtIy6YQB8RvWeCrV1xsvF9t8/1g+F3emTiXAsJ"
    "CkVRF9Uq/LGtzKkRle8MPqhFKPRtSQeox9mDt9EA4xUWtLV6LL0zOis+VE2G7Acpj1419VhrhFBMTbRiV0wJ/U6PDLd6ptsJmRsFUDuXha9FkAUI"
    "u2nc86FWVG2YwtQBlQ6z8x5/KOLRsduW/itMqgQ817Gyvmmu0ayFl0vD+EnVZB2a3En6D9jkMdB3xuD3ImbcfyHgGvt7ihnnUuWOCCUuCgvTB7Jh"
    "owQ0HF4sMRqLh7U9gXMmv6Ekj8bwbi9gZETKC48AyE2HoFunO0d34ngocmENjKXHgEXwJR9iikpQ9wK5Fn3TqeJ66DWJZQVAtTNsuOLf6NcDgKi5"
    "oRqKydwQPB3nBds3DNqBPs0S+iB4ZqeygVH3BKmNRBleBtlCr8+mSdwHRixDMqK34PVvAE7ZP8bsJ/YhzY6AStqyrw+zVOKaS9w1vkpK6Sfg34at"
    "fswiCDCNlBCCS7wPyDBXbO/mqWWXPaDCAsUlC61BB9OSDo3egq44WL2C0Uj06o0BU/MdykkHBEk3who05cyOjVAiLbCBweo0fthBdw2EuIpH7xqM"
    "sLpeC072CLZLNEwP28UT8E4+ZLYo+garELXQeASWWp3nV4bbQENd+nCClyUlM1kd8WCOePU8qpcx7NVg9ZqelrF5QuAx5V9+9Psb4VS9OkWUZ9t5"
    "jIwv9m9OUJ3NSEcVedTKgIzKUFNKazgSuj6rk7hwUudwa8fDd1B9CtBQZ4K/isk7tWDpSmBIpT0LerJiOp1rt2YkLlIqyA5ZFQlC02s6oX/4eyAv"
    "ID2M84yCVALSnIUPjp+owF6TtHW2mZAS6S6dQz+KuLoDehIlQ4cNvCCucvXxv8ll9UQG/ogGHf6RKnc+a158NwmwUeFJVsC8VjFYnYGLM8kZZ+1x"
    "8lzOkKsmYQyDFaetwvkCsYpjcwwYaxd3RRzYHhPIDIfIC84zla/KN7nMFitwx1tWweoAel4Aa6nTwnqyxGTE85vlcp5BD7HzEg+rLi0qWgLtqISj"
    "g+wOO2PAQdixyDVsgNQZrPgT4jNhT3QH62l1gUXkm9O9CNDh15wdQYpgdBpOfUF1vtOdHgzINHFKc4xF435D6BlvzLctfxlPk85gEOFmxjDpIBge"
    "E1gMkxjPikeTJkWIszPzqfAYMQkonx1EsBhHnCQ2Bh0wjDvrhIj4zGmM70mBBCq9096lUUzfdaAuXnaxjQU3qOD66GhR3gD7MAekSsVaHIDRg/6P"
    "acxZuYC89QKFgMDonpgGgUY28GD1KlXXMJLKYGhY+Fb3fBS7FdiUKKNRneLD7fHWGD2lLG4wBUA5SxecZdMA79eYYwFeDGXskq4hm2VhOTBxIOwx"
    "x50UgYR8RZRwFa5QKn81n8v93V4T7+9gGSLEeC+nE9FopMJIzRVNdpjquQcdxMd35YN+wTXrUr5n1hFsCyUOhv4hfO/GRia6w0gdgw5Sg6uGMySN"
    "F3THZ1NRlQif1LVqE1NZQLM2ch6MAStO42RHWVuh3ETjXczhLfcfo5rEA6elwmU4JJ+LP26YnSB6vLGfiaXBoMeSYM6HV2wi9PDBddBuhhlXUm2v"
    "XIWdgRT4gm2dwJc4SQHT3tHxFXI0oyoqmfIMBW7NFyKvslOJ0kgomYzcYAX8BClBYH+UefhPNDiD5cpbqgVffaKSqNeQ1qvZjSZSTQJPlB3Hdo64"
    "RlMnZxI3HOwH2SBqFKHFoRZZ1D46w7gMJTdMK39u8gJl4nXarWlR1wZq466nW7OdUhC81jc7mFWlnvFfip36oemQlaGGXhBIJWJ7NvQEOuEKXcjw"
    "ke8QUU2jD2KMcwzJTzmmvQXCSjpSTDyYd3uSmVulXByqJq8esDD0T/m290GTHkqC1nHpIB0DJVZOYW01567iatmZM5i1oj9K5rLX7BasqSeyGGHX"
    "L0W42dkZdKIJ6oOF86MVVq2ftDTdwnm7MZW2wlwzKfiiNjhvMfePU02iJINwgOoHb013Z1V5g23otLVmFQ2+rJ+W9k8LJN2Wrihx8andLA0JIx1R"
    "lJT3nreRCjTtFCeTFAdlk/BrRq/j6TyEYEGikbGLU9DfBuP2E8JhNWs24q2asKz3CZ28bKkMEX+VmXGabVwIRh7Bwep1kryc9Rv3V4nupqwUh9Jv"
    "q8JtL9DHT9AX6JSkFRR+Wp9FF/MIKqWjXUlhkycH014cZz337cV2aygpcBnKK0b5HnKWAlWelovcmGZAm0pKoFaFiiYoClboL6Tyo/+0hMG46V4U"
    "lg95TLVSLE6tITMrFT9tcqwGjdLfRL0GISMir0Ro2GSXMWVJYepLJM0KlYiw4/wZ99IkDSSX17V0EbbMlEkBkmnuNsKDc+c59Cy2Zrp046JwpI9F"
    "hi2kl57jVx0H4/Oqpc24c5EeuAZSBvvrNxjmnyhvBRuG6g/A4qJEYBXmFgOsMO2Vm1gmgsbb8bXtDj1FZcXnXOXoK9CHmeVckKS+yrLnhkPPmRPG"
    "Ez3JnMN6p1l2ysjZaEMqr6gEtpfO2cbXmg8NglanCm292GDTO8NXPv5sKLCiFEEakmlfwpzy3GC5CyXWIXHxAW0JWA9cxz1CJi33gOT+Kcr1hnN1"
    "Ass/MLwXVb4Hxo9tUn/cdm1Sz7a/evwF2lztrz5f7BSbpL5+/s93v/r8f4KW8ORffY/UV+CVdyawiLpXi9Tvgm3/5BN89KvPN4aA0cA3p6sfP/kj"
    "ZpzAv3eqc199/n6xUerro189vt3BT4NO8dXnNyldDkcpdk196avPf13N/vlqNfTkajU5+uSTyULj1K8eb2B7Qhlt6Ml9vMijElWNu6g+/+TqFI41"
    "Vf3pQ9yEa0OgbD5Zm6imwXg9X+qnGt4YhyUNjVazX31+u9xV9VVYRovm8Qu4KjNPbk2OVj+lbqraXPXUk6tD1cRXn18fqmuxegreXqfdOffV42tA"
    "LE/WdC2B4Z+SpeqGlLqtnoXjn67G/3y3S6e0HhY88eR+1YHB09ar4c+Fvquvn+/CUWDcCFjpGJzhtaky0ePcrk9XOPnR6hzsLajzeOSTaffVM7Bb"
    "1fBXjz+drH7a/erx9U4NW3ye9uE8UJytoDParc7jLue6+alRmOfv2rJ78FZdM9azTKdwqP8C4xHNdDAu9uSPcC9Gp/D1xvasZ2EOHVwYSBw8Bnjz"
    "6mSmTZ7CrHNYXLc6p3S0vx6t4W4SgRGJwDtP/ghS80/wA969ocLaG9uzjvG6h57cq47xS3wS1dD/ulmN/vnqZO8erUDmW3Tdvvr8I+AA8L/thHLh"
    "2J5cE1bT1KZVJmOHPISSawimM73nhq22Q2G0caLEMTpzniUQ0Ifwla8+X2nhjOnw+uvfGoYfGv3z3Vb4yJgdEuZ8IVs5lP6txtngn++67yKPpbsA"
    "f/81qDZPbsOV+9OHyP+PtpFrPqFkKuNPHg+FDkFoedEdQEYPYocqFvbczDVsrl/zKNErnl/7EDq68r4Wv3TMXRYboTMzRcQ/5RjtXtu7/unDlmzl"
    "/6x+CrIFNu9fj+N/P756AdnTIhxqNATuJ9ype/rMAVq/nuJRRJgglw6dX/MZHEL71/EpPKlE8leytT9F6Qj0+/n7k6MnKrffOfXo2MRb7P7RABPt"
    "ydFDagv7StMUcKL/AowFRcDx5BdlOvDSBRCqn39KT/8axkJiEqYzqWpYx0RJfR/Z//Zk7hRWE75UnX3pq8fLZysQi398ef/dZIOe4TnjEG4gtZSl"
    "jSWiZm4Jp3GvZdySZKbJv8knf7zQV3vZ0aknf5xEJQOuLF+daSQykF4iJVh3qu0x674JStS/dOj1lf46zbqzFPF+Pjq0f0QbbvbJ1Q4ux6mHqHiM"
    "I9GGBrSv2Ptw3z8ktbGmFy3pe6Awflil0i18jljYhUJTWrh18ABlTEc6dWNv2lOjbVbHQcX+6vMtPCbSt0na1XSprXknalf7Sn5FtWUt/2Q9a4Gn"
    "ZE1rT9XJybx97Su1akDcyPb18/Ac3CEg49DNFpTeT7Wb7Z9+CR+Ju9meDeftW9q+CrdgeMq1tD2DJzZOE6CFuc62f/olkKnRRNLfln6kLTKVN25x"
    "m+xD/GhodXvWK1Wu3e1pvS2u4S3p+VG/2+ed+ufcI2fbrImvJ21vz8Yar7S/1WGl++2rU7LcyOX2QsoUYz+kTTc+cOmJe3aG2B/zxGvTriMuWpdD"
    "o08eRy1xA5EmXXGNk9W1xCWeZkaEXESwYy4QIV9px51xn//q8w/wdrq2uGeBQ3bp4bm0OS4wx+uwQNisobhFbrCx/dKTZrmwyVdYFg5l3XL/9Es1"
    "dmATp/Du/6Fdbpl7lhgiGi/O2jsXGcVZK93/Jnp+l2QYKPGbaD1cQFlf6qsrjyfGUaG/LlDubeBYYkbwrvPA70wihUyl7XafV06aEoN23oUH1juk"
    "1a504wa8LwVpEprwxlc8tOKlqxkfujblfRWNpsaGvCz2OolF7Tr00uj4i+/Qe9bpplGj3uTGacPeU+XD0O69bNCDtghS7893wThDg1WeiTr6/umX"
    "THIR5VlLXzHka3v6nq2VseXOvv+l++SqOjuCUCNpfi4+Omv3+6dfknuUmMMwcGyiz9D6lzbT/h53/30e7YzzbTC1YdwpsdqSNsD0PggG/DirNZPA"
    "z9ulrsCeuLzRErcGTgit1B74FCsXyA1MCT1gj+DYq2UvqjW9zw7BdL1Iqc8Css+jH6EjfP8AXYL5nsCPr7BTYA/tgQObxk6nge322ya4YzLugL2C"
    "PacLW07qcVBZ3deYQ6D2uo++wfDLBdTBf/zV461J/oPpNvvtInyKFbWUE5QcNbjd+C6v4ajaCb9OTjIlZ9pS1nz9LLAPb+o6CD+jtPoQ/kHKkTlu"
    "gtcK7ZC99RquMR/Jmxbt1JD68Yo9hwv7TEp/Y+Nh/Ab9Cd3BqJZcHdpX82GmzvBldAcOBCeh9wwerPNw+qHwCWD/QL7hoNTY2Evf4fA2W4bARa6g"
    "h5T2UV5Mn5m0WMKh9SWOfPipe+/Jv55AWfIv7Yr6DvLJxTQ0O4UCEEmI6KaTe+H90zzzQ+tYHE2+rFkZMzshxr5TjIneQfFGNyLdBTX9p2Ktp+8G"
    "xudMovgt4MuF7gRnzyf74lWXg7Q0duTKWjqKvl8MyaUYAVVCTBgLAMABlpaNTFr0prTR8agEnGj7aGF5m2NV3jIltNjrODhnxvzg5TbHz0f8MVUg"
    "gyMn6Xv8Gk1lCpS1xrbHpEzOdelEFtnpBSzYxEdsY/huyGeJjDqkOpFgy5oiEwnwDUhbITstvjpHIaTzMFD7QC2Ri2YSiYwfUxAKSIGP+QL7wz5/"
    "hz13Y7CzBVcdMz4S2+gvmnxy7zAaJeuegBgsXJIJ+KNNRfy1wVFHCzikFsk2j/hesi3KzPcfneIvvmJyDM7S7hYudez0PVjX5KEkTArkPxDiXyQB"
    "kygU3Xhkamg90Om/X53zGu9RtFLme8K+4x9TkBDuvliTvHN7O92/nB7LbFixSOFVpp8fAv7JFuQ4GpBKI19j22VHGvqQHnaPvsux9hSirEH4fx3d"
    "lxP1I1EtEqrKKeWw+zBL7CaVi8hBNVaDN7zF16ygEwd17QTs6bULTuEOP+VSpf9WzYmrj9j334aIqL7a4UwGWg0x79jyP/xGzhhmsx7OsV3vnKey"
    "KZGG/eQxPCOv2DfQLH04dIDWzo1xLSdvi/FNOvF++z2TJ/3HTzZhFOACD6el8XPJA84uzgM3f+4pg5AJqQS7oGx4HK+4aIg1AutQ2kLDbK5OVzzs"
    "BXRvDJHrqUNaFcZ5Pn+nK26a/5+8d2uO4sryxb9KxnmRO0LSTE9MzAM8CSFAbXExEp52x3lJqVJStqoyRWWVDHoStjFgg8Htu8FtbIMNvgDddmNA"
    "2ER0zf88/L9F91Al8dRf4azb3nvtzKxS6YJ77BPhMKWq3Pe11339kvOe+sGHJmGdqKSusrCoDTP8jACi6T6XarV1DFrCyfyfO7QCYtMJ7EPNqvLz"
    "xuwhB1KT0rbQq3idLp+Ybx+QCDtDJ/wmuyWQwZLRyUYtK7DaHTQcHNBNiP9xIgTeJ/z6Zbf1//VmyoGkj+gemSSN5L9epjla2V/Bi1VF+muWDBlw"
    "joDtdRqZ5W7NND0u3C3EmcCeoLL7zclfDkZ13yQy2I0+KGsx78kTK9g7BI7mM22gZGE/FFORqJ6D0NvXvMWYFXZzkQhghvQf5003AW8VYRYWiFr/"
    "dJiiA+WtmgTKofVnRhLU2CrABYg0Rpb8VfkGYBx7e5DXNmjdH9PiOHWzPwBsHTfo6gcgzmXTQ8thsHMWKgcdpmlDemNhv9B67Vgw+rcHnx8LwDy/"
    "NB5MHRj/2+pLxwKMHL8E//8/t/+2+uloMNp6+9D+4NCBvz34+lAw0VpBz8od+GYU+MCNQ/u3jJT9X5dawCkutU4dCaijoOuEnv/ban5U7Pq5Y61T"
    "wdTR1nnKCjlGmSFfHwmkXzN7eZ7nvwUg7cI0C5v14MdDOLtPDwX7D4yrbqaOHobHQQW4tB10bVzA2eBZHO0gdDkSTLUu4IIPt1YOwc48uHeIYg0H"
    "6JT62k4+XzjJg8Wj3CwU9x6k1Ms2BRq4VaqSt0jDtF2w3r4xEPdUWVpKFyzuXCqK1Wxcq75RuUsSbcWxPkcMLOF45gbac/8g3UoL9SxEjxsUGUEu"
    "P0cn69GcgIN8evIngu4WbuXYYw1j+TnOiIaw2CAq1OGsEToxz8+NWN6+KeNy/nincM9c3tb28Lytv/0MA2l3tcV29WGC7Bi896ZmVdJtqVOiN9S3"
    "jeuqjDfWIrpWQhZj7Sr7Txvjm4T79k8fFvoe3fDPBl3+Cot8js77FLfjoN8HSXUhwxDv4E3QUTzLrS4Hgl9Zy0XpwBjBnXHivcBBREk1LgN6KAFF"
    "46cHBOeVGscrLtVmsLvj9CLTji6HueZmJght1k+G/nXpjq4vKnisCKqQwxL2cxy1tlOJ37JGTsuS1AKt77PJ4Sjw5woZ7tO84pobhbHhZjygdJj5"
    "1iexZhQ6zma4Rt6pPhyMsm7NNlxpwUCCam25b9Z+NtVEaAPWRSlAgw9ZNa8q50IZNCRwHMHnme5gyHkOBW8XcLyrRwfNhVrxPg8qu0MHcp3gf9oQ"
    "5N6R5pybeA+oRkPShHVO6M8JjlzotXX/pInSdp1v2aO5yU/jgf7Xm+RLyPmqPOZ7YYaPndZU3q8s0KY55PszKxa5n6sZkEX3jOHuGHJ5Xz7efzH9"
    "uotpbi+5+swCHFMfxFuhi6fEj+IpAb1RzZX/xY5mBlqgssyyPp8SyLnRf8p6Yx9HTck64jme4uM45A4BnucVOimC6KXW9bGWp4KAXsrZPa5e4OWl"
    "THynQNFHN0fzHictEZ69uGlXpHRF3GWhHc8m83r8pYOmT4gjLp/mUhIYK9k4YaiFMMyubnlvzm1I7krSnzPMI+96k4xLU2oKaEKkF/hBj9a3w8EB"
    "PyrnLispr9NKzfcFiBfzBurqvpnWcDQbytMyN/ynRGE/NIcnJPJzmsNdpPPRBS4r4rIDsu2SM1vsvpnUKiWebXXTOQ4vfBMWKoIoMvC04Nqdb+eE"
    "y/y3NNXLpbO7JETI4xXiZMIxaas2B94+ynVkTMGiRtCVAqJYnGdNXBhqTyD3I/xsvjAWJ+SnEXUHdp9p/Zl89R/LfuSvYU9s91FOEHYT5p3MJcL3"
    "A/UuK1El71hObOKxsefhKwN7dweOLkmVvVYC9q5q0TSeQwngu2iTPhJCAfF9HiyJhhVZc3xB0ENP7omkFANe607zrc8SNeMyJHhTWUJYA15CDdc9"
    "laPC8/Z5zsYuMBDdAOJHfbW4tB5yK5jxXg70U0KNd0kt5ZDxHoYA9t1QdfLcJ11NmGXNRFW9coIccLwKaVrwg6eIIK8Twk0+68cxl+miOsnyUoLl"
    "VlYO+uSAW1BrfcKi7Yst4soLPXIi4TQ6dl0FQW+C0djyU55XA3/ixtsFmh8t1LgXBtK17qovNX7XyvctAdDv5JRIZ9khOHrd++I8Msj51lXgMa4L"
    "SRjgnEKSFzsHS4+0yDAqlKNguChN4WcIU9+t1gJkMmtTzZNkz+CyRbfdqPJ8N9zVz8icgRnJDc6rVYqqUKib6FAfKPYKcsU9nQOc2ADLXhFtf2D2"
    "+0HyfhaD7XDTpJ7QkgnTHpGTrpML/cGihs4VlXqhdTMlXZ0Z9hJbZKjVT5Fa64Hay2Z1h7QfJa7oodlLJYwGs5ehaY7uRCuW6w4HNshHujA8jVmW"
    "JwloiHRRClpOS6LD6k3xR861vi4Bui9AGs2UlFPjDEqQ7zHmC5pLHvtenbGTUQR/L0eH8ZXPYk7HVvzJPxoPDp8LdzGzhMGN3JE84xKE6LDYvDIH"
    "9enJclR8NSzFwRBsITjAG5/oMKk/JKmfDiN/r+9QVWKQYsxi9EjOjEHIx1N82c8sI8XY4858CCoclIPLP8RzRLB8zJhH1CeJ7lapfobQk3ar5KkK"
    "2STihiQABGQJ/DdGY5B2r9d8BP1RtkTZA+N2fJ5zQqDvwdyBYv6PFPAgPfqHr4H1bWmvgFlJxZkhtRy4/p6yZ3RillXChgPl1cnCVHQrdf+7czKM"
    "xjhrTBmopLpIipmAcmjsfbmMtBqXTOamLA4AnM0MZS9x+ON4E1OQOOeJTFf2NxjUDwXJT5uFmhOQqE7wcVvB1KKAQDyE/mfVeH4clW5JGVL/DNLi"
    "vD5zvhqsDfTC6qf991ZoPHzOx0LhPgv/UYTuH80Tv3dbFG4/MW8D3M/3Cpkzo0EKNr9XkuPD9rufELVfc6J8mQ3eStRRKGxI+P3W/DIlPLI4lcol"
    "nh3fqWNA/fN0qPMdjOwpCX+r7r1ApZhOfDUJ7P94KaVoSavh/5/VnWlEGcf+gwKISNrNQYeMnW6eJzzU+wC0hECyRwTPXWWePBskHmRcPusWYbNK"
    "I2YxoWLod4ZSBVm5qbBVTZASBZ/LcPDbqFZ8TwB5KzgnxL0igD16bicdWJJ1JqgjEKZfeGfAIQp6KtZlXh9AWepVKd3tIvht9iUyDTHlWVmec+se"
    "puSx7xuaGZvXCCh9z+S94DUvqj0sLdT3XgKn7aDL+wREOFH2jXRYI/QAV4DNjKRi4Xj0ewUmdVJxWZxehVu778IeJQOQb9yolaLgMddgcJ5EsB8o"
    "TG5ZDu2Ffh0BaUyFtxFM0NlVyjSCHDIVOwuMdmCnbIWpEj0lRQK5txPs9wrsnG+ZbsNwMIGNyXFa1WWsZA4IIIznsfai2o6A8mLUe0mBli90/Q0W"
    "ppLD5WAfoncpVKYcW8353MnxQcEgXlMd+NScpKV2DZTaIrV58fcVm9KFl0TbLi81YJZWgBsr5Nru7lqoU5LCNOilZnhOMJy0BvpkjyPnyKA76QHo"
    "MpZhySXLBbu9ZAsXx5BYdXkqQ1/vQnCVtAYDA9McFlFFkSO2RYawDC8lo7RYUO4H6pNAbhdEqgx2Ty75rVINVB6QPC/gehu8KeEgeeQaUkIsrlQV"
    "4stP0oByqFwWS4zMzbogdO4WS2zhb6vf6jplE95Ttb88G/p+5v+7SQmMD37g+1mjPjJU9GWahhnksFoP5gLuXroOseRkjjhTXALHpl+tQGNrCARd"
    "E2qxOs3REcEuUYig3vpGfc97Ix7Q4nsWfkq2WZ5tyNlpvS6sxVpCueAn7CntFtZKWzbDvklCc1M7Ing46iKWxrvYuSA5b3LSuo4FpyAQHzNdc7tK"
    "+jS7RFGcE7i9RqUnzwH0+Mjmwxbf3+DwmhMO7zmt9VtrVhp9V8DxQH3+JCHBj6dpOYW+0+qMOEqocCB8ylLbRhW98LWRMpu4X9MKqFrql8z9gh27"
    "iKPaXB1DNKXQa8jvUMFuFERSaY1QCUChrZxeyCeb59ITu9QzmaCB2FGBA0VUZTdKz8xje5TyMRRy//t/dUVV/N//S6SbGsLRU5GbBBW6HJR4Jq4N"
    "IkE8AGxSeNvEnu0JvO53Qxd5fUZYFGf6zpr91nNo2SmUWneSyK3D76aUqWiq5HVWD/x0kBE93MC5tZYO3+N1FszlfBtKO/26Ki05ZJVihhHfXF6m"
    "i/IYW2WaqGs4mFSSS29MUkQwKq1j7XW2uXPMUR1xrFJea5aSm8G3uVdgiKbgaN5OkEOv1O3r5MRbnFeuKrEEGyxYN8ok6ZZDkj8kbwhf/Fiekr9o"
    "pWVxfL8Ul3IQEqUv0uhyo7w9KOJAdo1QkDzkp77YpdAArKX5oJDHYWp/xPTPgZFrT163ydZbDxoMcq+9UAXQpfxsciBM1nyqt/6Cu7l62zG3hsFP"
    "JsYo9YTw+eLuonDLL1LTu0XM8Vi22zKtVLvpMrvKrT4/k3xSNu9tpuFZwSbrCc3suV/4AikTwPnxC+AExTp8DZomaTR6nV3eAkJLzKMwedWbrEvn"
    "UB1p3lW+zyUFUU5yEfM1CrNm53kTll8WsjyvXhaydmvl8Q9vPb73TefdM6WvCln75sf2pQvrK6f1e0I6n610Pr7+5JP7G70mpH3rj5337rZ/eKd9"
    "9u7je2+s3/qxfe1M6VtB1r84tX77VOe96+1H75W+CGTt7Ruds9+v/+WVzrsfFF8B0j79dfvhCvbw/hslb/1o3361fedU57Xr7TdfK3vHR/uNV9sX"
    "/2x/L3m1B6x37crr7Q9uPFk513n9pnqlB2zD2uVb3V7n0bl3un3hHd5FT8g5ZMiyl3d0Ll5cf3Rn7cNX2t+83/kk/6aO9dvfyTqL7+nofHS98+BS"
    "++JL6ysvl9Nj58I7629833n7bufCrfw7OTpv3GjfftiFrba///Paw5vtMxdhXuu37sCxFk06/v7JWz92e+3G+nefwzl2XvvqyZU/93y/Rvvsq+17"
    "L7cfXnxy5syTy68W9Hw+rfaFO2tfXd3aKzWefHkeKIbP5r9XTrXfOtu+d7698rD9h/N6GT3foPH43gU4ovaVG/94eLbz3hdr587C/rXPPPjHw3Mb"
    "vjoDbgQPzkTSPn//yekLG7wko3Ply87FS49/vAzjuV94tA1fiwEDdl66AafXuXofVv74/uewwrXL99Yf/RG+tETa30swYCZ6A//x8MP12993vl9t"
    "v3Z1Z9560Tn75fqZb+Wnfzw8L6yI5g2Dr3/6VfvSa0/eXoGdMM3cPuzIay70iI8fvGFmqUY+3/ngQ/gFmNyT977rnP22MJd+XmzBnTFTbV/70/p3"
    "12Ezt/0qC6QU7pK6X3vtbmflFMyPOQqy/D9/0rlyznbB893MiyvaP55uX3tl7dKrePaPLq1/cl63wBN75W770hvqpy2+pYJvWOf222vn7rfvnWI2"
    "/4+Hl7nnHXozBezX2sfXue+1P622//g6jGCJ3A5uj3qHXjHRee/q2utfr331uqKhD+XzR9fXz3wJjBrYH0gevLfw/R8+/u+Vl7q+JoJny1S09ZdD"
    "MOG377z6+NFHsPkkh95bf+0lZCDfXGOGzDMCyfrkD9fXVt9s3/qQ57XhSyDgKEGIwvPr519uX/6u/erp9q3znbOXur714cnLN0AYgMxqX3y3r1c9"
    "IHcgBr7+xUvt2x93rsiW8dsbYGeffPh293c2YGtq1z6LErjzzh1YfOH1DKzLtM++t/7JjY3eydB+4+P2F693XlvpXLm9tvoqbGSXFzHkHnFvX2Di"
    "NC9caF/63L5tofP+7cLbFizVFt+uYOWH/zKF9dvfrN9Yce9RYC0CKNG8TAE4sf8qhc75U2ur3zCh6ncp4FovX1XvUli/9Qlsof8SBdAkrAKh35+A"
    "GsYnt9ZvXSu8OAE3wPzi3pPAIpMVUfOOBKYq9YIEUG0fr9713pBgB1emc+fu2c6p2/6rEVhZcS9FsF3JWxGYT+RdQ5pFKJfc+uevrl1+105P3oLQ"
    "vvZF+87F9qsfqPcfdL698eTMa97bD9Zvfw5k8fjRJzxH/f4DK7fLXn6A5335u87b97XOpt52sHbl1No719W7DjpXzzz59H3vNQedT87Cqtcevtu+"
    "+L3/kgMRMB/cKL7aYG31lTVKCvbfarD29p/KX2KAPPbCLavu+m8rWD/1WvvaTZ4/61dlLyng07K/l7ydYO2L1ccPrnXefH/981P5FxHIKq+83vno"
    "kXr9AJgVcHf9Fw9YfiXvHLC3wL1uACiZ9129Z+DJ2x+s375d+qKB9g9/gHU7oHTzXgHohlmwfq+A5e7ujQKWUM27BHjH1NsD2l/+ASy9/KsC+ADX"
    "Xrqv3xDAl7/rCwJy7Lj8rQC8bcxHNfQ/7suHL7VPXfEQ/+Fb+KrzzacFvH8yTb8pYvxjP+9+gzbfoz923rhehu3PU3B6m4/pj0PaYyxD9Ldfikj9"
    "/nr79PdbAfLn++kaMKVvEb4fNLbOO2cLEUJmTNaC2RZ+/+N7X3J36ndrm2yE4N/56BO+pvhr+9p3QCz9YvdDU+bB24Puh+kbRnC/ffoud8lcd/3R"
    "ZdAXHz941bLMzSL1I8m88x1+Yom5VXR+e+94Y0G6yq7hU8CqnxoKP/tZHj94oOwZdGycvYPb8vXXgZwET8cZOFe+Zr6KCtGVFdDqH99bUY+dlSHA"
    "iGBVayPgfbh+fK8e33sbtEo24y2VFRH27YbxF91A9eG/x6vX2xdfW3/0PlwVJsgtoerbCdpL9d8rYuq2/3CePQPbwNJ33ZNuyPuojfB+ofPZZQZs"
    "sn36T2jOFc5vZRU0MNuet2NnoPJRJ6PpwrxZoydd/j7YTewU4z/xeEGv460jOcfshW8jGFZwUXcSBN8OxhL9yUefgkTnKXZevwmTwwmpeaz9+UdQ"
    "LZn2tJbUN8q9O0vVq/YmWROOraVtQtp3rt4H+YFOPlKW2qBfg9366Exn9RqM1T57FYyHzsun26/+pYhVzxNAp5W5ajmcepm80l5KAep5g3U/JcD0"
    "VnkhO/H++u2P7N5qIPonKyvAWB6vfrZ29VRPKHoWnEDBrINrsHnmy52VL/Ig89Z/bbc+DzXfvvYuCCmrwm0dX17b6ix7ZJdWr4NGBVdx/fZ1TSFw"
    "fdoX31x7++PHq6uPf3iHN5y55zZR5OWu0YrbF76FWcFwyPMffbT2zgfIwn2CLB9086jxsEA9NJimYOuvrV4E4gTLDV2FZmj23MD3azdeB94FmwCa"
    "GPzKM9k6LLzwUd+lC8waPouT9eJrRV3pKSC/w3EDASBbPn+6femrHkfQOX9m7cH9fwqwO5xOvhc+GJj34x8erb19oxxaDW58+9LZ/LSAs9rh//Hw"
    "wx0Gc9cyTR6yiurGeO5WcLNI0oe/Myju9jiLvcA9B4njDp7OOyf8dhqqvfPNNZYO7KEgRk10SNqCVabQh3r7exZewl1NBK5/0HXRXP0H2WXrGV87"
    "D6vOg1hkdaQH43pxPuLb31tSlr46Z98twFLweVivWb9A6jmWbr3qWqiwI6gvtHR+iB1dZAVsEwsdpodUeelskQ+DPfv4hyudv5xSLWAHv2EGsHWA"
    "887qJ+t3vwUb4fEPb6x/fqrzp5ewDapWP9wSs7IPSHPrCLQqsRbhPyME87Uv0NhibwwKoSsPgEfAN6gVfnDrycqHaz9eW1t9BZT3xw++ApsKaLh9"
    "+gYbsGy04g6Q6w1kIwpY+vx49TQc6d9XrtiHO+/cwetLbOjvKx+1X/t4/eUf0AVy6TaQYefcBfhz/dOv1lY/BnOAIhtfW9MBNRFmD99cA4bBXbEo"
    "/mWAhMMpwBHo/cfPav/FaLx9XXb+zJfrD75CZk3eA2Yg7UsgF1faDy62z75nDwXl/OWrsG+dv7z+5MzFJ1dWgOj5HJkvPr73gPf28T0wSu/AeaH/"
    "TAyjt9E9+8YfnnxwjXVAphM0Qujo+Qi2Dt+NvZdex7WHD9rX/oRRxj6Auq15k9PeugJytx+dxqGMnt4DgVtkTmGOW4bU5q6k29yie6xjs5DYumu0"
    "lXjUM9+SA8U20f4RuODaBudg66ahsPHaG0uHvYFf6hWzc0bv4mbRrB/fex0dO99gBFrEpv05aL96ofP1JxLOtV11RbG2wbdy5Gr+mYJxH2wGpZrd"
    "T9YbJUGBorrRPw41KkvXXrHxcr6KPcyWnwhbeieIDMn+0htrq99IQguxJ47Wbg8zGnZbK4xUx2V1ICCeXsrWTqJEbzyPvu2X3tjQ7dPfg17HoXoJ"
    "en/4ikviKq/XcEq/jrNsCgl6/cfT7dduWtMHNfk//ZE8so46bExxZ1GfgdAe3zvXeRdzhdq3/ogJHZfvtU+LqxozMs6tgEhjLRfWhl60W3/kq8ii"
    "66fFbsb5Pjjfee018XLR5j9+8CqTRvsaytP1O6c6b3zRPnt3/dEH9snO+7dZZGOTW588fvA6Lxd0JLGNVk533rva+fadztV7cI68uJ8hxDKnVIGa"
    "Y+nRclA0UYnh53xD1sPLu8hpREgH5PiDnWhf/BINnh/e6rxxHZMK372PlGHsz8f3X2+fuwB6FjBTdIisvtu5d/XJqbcwA4AiiDgZNkrfu4s+skdw"
    "Ypd5SqC0Pn74ISmtLr1kO5jInFBjyRp1wLt/Wbv8bjGigQaS7xfcPvRxDxcBJ+ZxYoZ1EVjX6s8A4Ljz9u3O+VOu4qR9/y4YHp7V/WTl3JNPaM/5"
    "2dzsdQvfNLcNH6++wbNev70KlIOkS9Gs9r13Qfg9wUO0HTB0JDeloNQpsyRpc+dU+8IdvONn32VRb3VDs0KbTbxz2MUSejNSQdpbqkNPKBgWX3/9"
    "a7ildiSS5Oc7ty/Chycv/2ClEIY03r61ISgxOyQ6r18vii8bDNxpFGLrcTF9ti++BFYlGkv37wJ1w21Gkvc5DYq2S+ddThmcRDfE352AIy7THIzO"
    "YDqwisJTBB4uckvYJmGYFz9nufTk0zeBZ8J+cZxWj7tTEMOoVf464ITb/nTLPNPyQ9q9oIRtEppWi37pMMFdXbJmD4ATeTmgBaGETjGShEAF4owg"
    "J177PBlCipiBjslb5FyfahnAC80i6KO/CtbXCxfA56jGY3xd6dssnp86aC9fBWD57W8wYNS++Gb73suwarAzOd4k+brvga7xhhnLCox/PLxMVQzv"
    "rv/4JrambuAo1m990j59nZ1jvJCnAcJbbrqevdxexXQMk+h+mdUU25BEwudwDDRA5+qZ9plXJRfYOJc3BtjF6OK7d3C3flwBDmI5CypYtz/aCFaX"
    "n8K8d1aK/nDtydsrPVF0kasVCfjaK49XL2DawOpbnY8+7omky9lbsEg8JlIc81PtCZ9rnQ+4R7DwT7HCwfZQBpjbOX+OE9+YCnQmQAlkLlc22fy2"
    "PE4uFxQx2ZUg5HJOQuetC3B7S9Fw0dqgycBxgwbeBQRXdvWDG1zS0xX2Fg6DK6DYf9F+9XQPhFsrla3+U4Q1dN8QrG0ezNbkMj01JFvu04Z58z2y"
    "Nxe55OUHwC6lF1v0gpoFDvjkrR/bH52xGXU+ei2XF7ErHMSfQ61l190O4NaCttp+7Ya1NwLpElg/c3kxWyVCb87uD8D3VztXHmwSmtYlxVil67M7"
    "WOngBi5HoXVfsem3DeBZ62FT3aFmQQE0V5CSx23lDd8SrmyXEXPBui4jbhU/ttAON/7im+SclKaUDALsSHwnO4gZi3ElYitr364CI3vyzpX2yxf7"
    "jMb/U9FiQRblR0aP/drnq2sPHkl61f27Vv/J2Q4oNcmLC7KcT3z9gw87r4MAeMD3Brm/yTDqA/rVPZIvy9oA8NWjKPdDOdgrKGjszl//4rP2G6+j"
    "MkUOlfPtM6sK0Yyt1PadVzlXkHWu199F/nbr5cf3XgNpgs2u3NAQry6W64G8SoKNhXllj7CP8wo05KG88viPf3zUufQA6zH5MD5AHx9sNwjV9q1z"
    "65+dxmfuvb7+ww/sQOcYF4+Xw3Ft3/nQFVbBsRED4CdzqK2YnfD+aZCjOeBWeJibM1ar1ILehzt9Ye2bc3DVpPN3vkO64n31QFrVVqKk//52+8dX"
    "kBddvA37LPlZtMVMVsARuBjGobOCviBojnYh2B1v1vqPb4E+abWs/DgfWlhWNvSkAow8Y2zlWTOYfUHItOx4jx99hNU3JixuS2MMf5OpOgRW2EWe"
    "EIKwYoT5wqn2aaCOy+2zd9vfvAfaJerFp0+t37q3dvNB5+pDSpT5A8ecPZhVPA9Ko8T0eXL04kTtXiJfW0EfNajikmZ1De0afUrcpUEkFUvC2Dec"
    "L8jzV6iq6KyFHnW+qWpn6VBuPl0mDHvA1M5Bq6/hAa+i7srXwBd0LZ3GSGVHL0/E9o839doF2C6MkH/5XvviZ+KrAUX2j1ek8E3hoOL2XHy3c/es"
    "JVSMsVO9AT9sEU+5Bx4OY8Xqir9H3qgSzFO5kNQGr313kFPcGlCGzl2wc4VtYv8Tz6OIaFqkK4Vi6oiwffrbJ+99Y3yyhFGaS+T0AUz1j8G//gOZ"
    "hgQyBU2ALgL092/kgTHYo+wsQnOHwsk24MlbwGfFbA6DEbe/7/zpJeuLgM5+DZ3pkkiZrxTkcHM+Fn5Kjvr1R8gFDGda/+JVPBkTPhZW4hBCxa9N"
    "Y+LCLn6OKXSF0A/qcORww1QWENPGfutcudB+7ROyZW9jgZdRU0kUvARNBPUT/rb+1fVH7wvnFtRPuMDGwcmzRHfohXeAsXBmk9w6je/Z/vwloAcR"
    "WCwASC/5HgxnmQpjCXA35K0vFQIomU7ftcid7uK//SNSp4LmBJIW2uWMilsvw3Vsf/8npHP3mDHAC2Cdlo9x2SVfQS7E4GwM7JkojLswKJ3WEcL3"
    "nxfHD7YfvGW5Ca/myYcXn3zwiuUdj1dPw+F33r0PS1//y/d4givn2XvFgxioTV52AWuTOCY782hLicfzZtqbVmD2yEIxj2T1DecaBHFOrcy9tbCa"
    "LA404xD19kL74vt8PDo7H3k7uY3Wvn4b+JtwkbN3mG3aw0NX5DUZzMJnIvcjLsL4FI8fvJpLgNMsV6dr2wODD8gGHryKEW2+GciZUKsjT/15sd0+"
    "fwlToglNgJNV9GNyukXkSxhj7dqDYsU0Jv33uI/sfKeBXQgDxVYuRsGYGcgaxMv2hg4SuShVH7iUUtIlJECVoRippBxl3kp2ltvImU1ZdQ/fvmgz"
    "YPFWnVvBKyWu9AfFFG97CzxvYPtN0NeuMaPHw1QJ4bkSMzXck5d/yIFX2KOFHTY1Y2bGa5fvsYohie6GUjjjHfsCpnn74fqZ72xBgY6wWrwODoG4"
    "6DPjmLx3l3vAOKEgUVy2ySmPDfvH1C4R5qdsZj4SGuzslRtP3vqRmcnjHzBPkUf3wR+f0j0uzxtonz7bxuDn1Scrf1hb/YD1SOBBnpv9jgtss5+D"
    "IhrXEXDn7Cqe9+vXeTNBurVf+xjp6ewHcEPA6u8RB8aJXnpD8DXOXn3ywTWUs5cfdS58amasUViwD1LrcO3MX2hTgRotho1M86Mz7XufYxDq7T8x"
    "y5A4j8n9lyvBnipUSG/ft10z5Tx+dMsSzNrV79ofXWSKhefF++yqrf++ckUXXGNKpGE9XnU/S+Fbf+Hrr7Mo0QVmy7KAB138jPRI8a9brsQpgix/"
    "YM86V88gV733ACagkQRgArgm3lGy0PE0TIogZnLST5iR+PF1eFhqMnRd+casiU+3mKjBZMFZGlZzz0UIJEzLkTpyM6HlIhFDonkPOIatLzMlZla2"
    "Lz+kwF1KC3/evEqHiuTKEx8iOTPhty/eYZ8X2LosriQXweQGK5aOVC8FZyZ/2PYp20F3Qt8GnXOAmyVQVLJfQBjwwNoXF9o/fAqKj05v0egBxJuY"
    "FoDSkZp+eAv17nNn0dx4/0eQSxR86BqwERMA01Vudq58zA1FGipns9iGilhkLiWATTwsCoMCCgBqsyJabjz56FM+HFRelaTBZ85c6Lx7B93ht96z"
    "EDyP73+M0vvqPWgFgwsm1LmzQs0m7UZXNjpZYM5MYsHf4gHgnQTuTVAElo+QSXrX8JTbPFu876YrPGa2IWgLdUUFbBsfPxKE6tlI+tP8MENTwDOB"
    "jahbrRxBoJgQiCVYqctDWq4mFRS8leYnjvB4VY5X78G0hEkVIbm4ON8JRkoJ5ho+LDZlvBUyYPhLFneGe7zO5WWoLXx40S9HWMGIurjJXyL4t9m6"
    "gn/bVw+T1hdhnJViv3HlXwhmmAZ/e751U1mYGyHAjSX1aA4xvjilO0qCCvQ3A58aQbiIlTWIb1GGCPcbcZ1XMLOmdbMGnCQrRYY7Qh8zerDZiKtx"
    "FjaiZj0rosQdqUdNmOsifnu8GZUAxR0NF1m6oSXfulmGFWceqQxw0Ed6KsGMm2zdNFmnFQztBEsxxq2SCG1pByDXOgcj4e5k3UDkXAlmpWmr3yKP"
    "cU7xDnWBkzOAE5XWTfiNmmo8Of5Mab7loHJHWzdn4dgpjC4Bs3KoQ/kKj6Ietb5oZnmAub1IPfJXOdPyKQb6ad2sNONGVtQHR+fD1q0ERhuI/Dbd"
    "sOf2xkvN6lwoJ4JlBLNpvcaEjEeETnTenK6odCPuL+ybnmrdjAp60eRMFDbxuOpMLltDqPPuGk1Zt8W/50N4Foss4D4xkc302JWeUHbhNH/P30g2"
    "d7WJk5uJIyDbX22IaAeTh94XMeMzVJRKT9Jt6gVtl8B4s3jpY/+XPoDt3ANRwuuHMwkQ5T1tIIWGM9Cqb2Q7/RTCcNIZYIfwJPCnRrS8MwB3rgUe"
    "nT8qUP1SehxICzey2HgHQe66zcLNAGu9THeL9daNLKj+feWD+bSeYqx0LvIn1g/iHbAh+MlwxRyR88jyp2q2VSA83V3uQJ8JmzPNxDWuhAkvzjbf"
    "HCJexMBzSQNpJToByyRq8VotNrF6bOtgeCPqKdMSTuVmRsPutsPWg+rADkHjUTZWBbdFNY3Ra5w0YUTeREUPpg+70zuElXcE7lLFIz3k4SDUsNcQ"
    "hcWuAHFt5iNCvAOxv0SMK2HeyC2r6RzJURkBHh3uiqbXOjd6YGw02DsWTIwEz7fOuWe2jq034XHxoEpJ3TjrFCbToNpQdGjBgSIDQ4YO6gFJpyg3"
    "5w2R9uQBIWtQfPA8aq0byBMzq5wwZy6H3lN/UXp1jAGOvjD4RpAoZEgMBOO56SYJklPQugmqXWAFFdzJYYvT1zo3E5Lg7ILTNzofz87WKT8wke9h"
    "0wpAfROYskWyUuubPfH6QEmhj/IjKHiZQXRpnugC3VfSxkPwG+frYiD8DpH+wxB+h5txAcLvUJq/Pl4G5SErK30cP/oYORw/0eV2GRi/1oqP4gcf"
    "jfYi+H0HU5AGCr7vUFqbrkc+fN+YO68cgJ98pu99AD+c8Yz61YH4jVqlAQMqmYLyOwJ6CE/PYPnti4EvR/XMQ/MbK+g5GhHffPSA/UZJ08scsp90"
    "7KD96J+cA+aA4zu+swk2Cz6Ttm6B/eAfBel3NKqFdSGKvQWiySH6uc/loH55FTnmZ5j6FbjfYdStMwXuB//aKTK2H9wtoLIU+UslzTLeAoXwxx/J"
    "oCpi/PGfmdHmfaQ/+iumsqZyxD9rlKA1h4ZZVsD9G1OqKM4QlPkmZzSWwP/lHrbKfAkO4Bh+grlVmoxYA5ZOI48HOBVOV0mHR9lEZ2kgAeHUwDTw"
    "IQGnojrsE1G2gAIeiIQcLLbOwbRirrOBBIR/eWeLkIAGmQ0l14DZNYcM6N9Biw0ITBN4iIcNOGo2wmAD7rXbmCmAwINgZ8VhlkcIPELJ27SfCQz2"
    "HbF/CxU4aYzBcqjAkS7ioxwzkPeVF6yzLRV84Bj2w+azQw8cqddbXzZoH3zwQP4Llt8sAgjCYPInNSygB8LvcGNhd1EKlwEI6hMvww90thuccGAf"
    "2QqCIPstMteC7SkG0dsCiCB9FRUiPAeMLVnBDDrLaLeOJGh7wd99Nq/muhGkYJCzY/GhKBlqwJlH/WILlv2yeWhB4Sn4bAj2c9L4lZwEZjAHz1TR"
    "6/QrsJnNJtac7Nks0GDuqWirQIOobcrD+g4HzlJH9fP3zex4ExQyVDjhH3/DqUNo/LQgCSci49+DXV1qls4AerfXEKzQ5lAlwhdAVZA9gxKEzN1v"
    "QfqyEQ5goPJwvxruA5rQql3oU/E9Ghl6dUrxCRcLbDJI/non6IVViN3TtjUbdaGRzYIUivdHP41zFg+QXUi2PaxC14ZYc36nB7gDNV60CfzCsgue"
    "AcM0DYztYlrsFHihcs6i/SAcFazZaiQdNY3RCE+ygzYwBguDQrFsUO4C08tOohlqJ7JsRUNpJqK0ZTJ0hg6A3G7SaBkihaD7fcZnw6BNzOglbAb3"
    "UOSFp6EQ/ZHBqi1snxS3A36Y84g2qRfUwpUDNFyKYcPxOzgk44Clo7KztE7sHD4iWClDuR3CO82hgBxUopgMcKOtWleKlTjpOfaAtvDYw6QRlaMm"
    "Ttk/cIXaNM7hJo6SWY1rQcWqJ3Ki+gURpRoxahNgyyrFW6MpwufWTfzDLsoCM43K2WY6NpSHVCTVVyqIom1hKk44ugKKsHYOrpv8aGBR8YW1lAZn"
    "bK7h8PaRFCec+0WxWJiK9ct4ZC7TgYvZiGV7sHLaeHRKZ7R5mMXSSVnWBJSCGxTixEAfMUxM3IIuGGWmbTzIMr2tYy8qpxZyphwbGnSBichGLQZV"
    "jCBquGCGr4A+BXjGQWF8A1ENrkCMnlP/JN2ZERPJHeo/Ba2xdERaRn7ERQyNoPdNHXpufDV40Mfom8NqROd3/vTNw7v0yW6A2uhpNZo4REDvGHpj"
    "z14ST9zTtlqicWTyFEAcR6WXitIwEl48ETf73Us0TyBlM9xuI3qjZaVF0QUV3j+8KbDHieLNDn7NurnXLKQZatN55+EfTY+8EOyoMqCiEDYogr+o"
    "fRhCg1Xujem+WYJR1C8G5Eg+/CGCj/U1sEIaToHpEweSna54qA3m4dgoc/7TjJjSdtEhJ5QQsK742Vn4u0kiVtTN2SooCjiVergUxlUnL3RvW8aL"
    "NA+jykXOGNekH6DImYI+4nYp+nlBReLVch5OvJ8xMhaYNRIszTziSBHNmWISuIiYYl1hHWkPxkYGlbBXV2QEsK8afmut+yyqTVdF4qFDYzgYRcfc"
    "0EyM/GUxasLN/RKDRED0FCBgxSatZ/SvIhtyGyfsi0Krrbx/0phQu19iE0uBMRA/ay7VUcxmNPcGTsXGjYZ/MRiUGx/vYLfDlWO3i4FrgSyTdTza"
    "YPiT45zkgzLnn8kdDoNa68saxfx4qWjmhny6sCugI2BFfYPOciYggDxkdSR3MOQk1payRYAgYpoT7QJiDjTRHZToJfIe0AluHcLSPc+Ba5R10Maa"
    "5Gg+J/jWbwr+9gNnOdaHItwV2tIzpNC3TbZTD4TLsd+O78c/JxnacWQCPh05fOwoBpSPHB079vxYcHRs8sjY6FTr3NjklnEvy4YZOxQcHJkab509"
    "OoYRbB5tMpiE7yb3jYxDV+SW5a7GpHOYRTC2bx98cww+bgEa0zyP3Y0fmgp+c2zyuWMDrZVgYmDs0NGx/eOTU0fHDo7BL66DSdgP08MWUDGhQesc"
    "tmidC44dGn/uGPdPizu0dxy3qcf2H8JNHDt4ZGKc9n+ziJmtc40QOEPWBB7FeR8oleGO1XVb1DZcq26ImUeE6WXoVPMCICX4mRMhBtjNFUeG4Z7J"
    "NgOoubfcg8pNUSVgfc7X5vpH15REgJJb5uUAqKyceCb+iSA2Tc+Gs2zgB7fDaQcljleiFDerDVwRs2PLYUU+V+MwztJkexCce41+Jn4oLP1Smr9S"
    "8YNdG6i6OwbHuck59WnQ9kbmND9RyywU6WicduUFNsWopjPlNg3RuTedafKhA/1ILl08i00iTH4Dsdgg7YYjoJTDa5VelCE7Dtx5DNO3UNExSrM4"
    "ptBdbKaKfki4+GhL+AYbSEQEE8LEqhjT/0iA/7RAnsfIS9Q8Ebdu1PggkUnC9Sc2VBkAHa91E5NXyadrY4GO0IZB2iApN9CFKWIeesgw4ItJ0HAR"
    "8VDYNqP+UUMF3uVc/RVLEUyXuIMzkUpWRC9RMoDt8GyjxKhTFftQRFlaP0OY0DIjn1jjAGici2VXRwcTyUmCXD1s6LsvkVL2u5V5T8HEqiK3BjUc"
    "FVkMFtCuZ3HBp4pOXlggxmjCJXeSdm1oHSPYDkbWkLqAIrYJHeq5tCmzkEmoMtDExDtC6rKXzsUPGoZEPUGC9g0mVtdRLhCE3/bRRSc8L3ihFxXH"
    "NMLNOrFwk5dQgYezWZa0sujngTtqpyjuXFaxus81/1hu0k1rMdqQdLVpYg008WIHsgJKzsfw8AmXQitVKyhzUeprMSer8UKmO4cz2ttDN0j6C6zV"
    "9KtSTuXmyNTJaY/erXLZ2ht4lN2TZh8TSt8ijCKMW+S72lH4UdeZaBNlneHNFebPfML4NgqMaYcARzepG228hJ1CIM110vqiC1ddisMcV90p8NGN"
    "vcqDWucezEmccqlUxtaGe8GSjnTzp9tM2186RqmNOAyUxRuSuGxz4Fvl+97FsrrcoqQQLoWWua6ljPRROyZnVURrVo5nWL4NZcz414hj+3GF87zF"
    "zs5tDBiPPfalmb9xRR4//FPAm5KXkPqtSKGiKv6yDkBytWJeKodU0cXcMA58Tm0lH4KbC2xqatTaQsnNbt+7aPIZnC5Gxkvd5I+Qx/gpIaRu5ItA"
    "KuNVSE3Ubi/wQv27+AQFSWzv/cCk4vZT0jSSFJInb0CIxaARWSzspGYeaNptgJ5qfzQVVSaR6oRxEfSEUuXc8iDsluvWE0Z1hJLL1E9NtH8wsxUz"
    "1/vDUnXPYPUbbYQU3BQSdcuAVfPZ6ngqNv+mBFpVV4nYeuESjFWUzpJtAPPwinHzeKvyCZnLIl5gSuIroq6SAxuuEfbSaEhyjUy0DH/VfMznxYnK"
    "UAbFSt66XGheio2jHqCsuugrr5sUQQgJlNUF+PPwrMXkyqcE01oNde5gk+eHUY5C51FDl67iMNoVF0oFp4zTugnDzuGO8e3kdOasAOG610SmXBlu"
    "8IwDcv3VzsC4mi5Mnk0hD9XdN5SOsadkSseD+RQd3A8sV2t9x2lim0B61fMJqeK7GtYl1V6SHLtQkIZ9ncQPDfqOft0G7Kvqyiu/lOrLSFrD13BP"
    "5IjLCjG3hAC79cGthvGrbWDBjhZ7B2oAAUNFtbYxCAZoLWlbOwcGC1REjShAfjJrkDutv2yffyoWrB3LDW8PDr8GkY+Fk3MJMw75VldLerlcktNb"
    "sUxXVAN4GqaDQQjjxXPkwTGIPpBiueCmVK/SGVYb4caysXw8x7jLYWOpeukkaMENjDTD2kAFHg72pqAtRkMzBG2xTCqiQt5LSe4jVSxLC5f3Dbwz"
    "a2bDwSQaSwpCdlCVMGsM2WEPQdaDjiXVWWPH4sDVvNuU6rQwQwD3XYIj6NcbDo6CoSFeVcwBJr0LLYwGOWZBPtTnWjeHi4iyLk80GQjpKPNRpeEi"
    "uOxEjLvhA8s6I4OS/ozYIPxSl+LO2Qp6+z1w2dH5qBaToPb2+RmyRhdRn1s2p1HXHgEgul9RraZDmR1LKPUXKMg6ldH4oRM/DLc6jDPgInyoMzLs"
    "gDXScfhdFmt2zOU6iuODjH3KC6D8NpJYz7ghqyH2TVNU+TWJruTk+Tqo2Uk7of/4dzSOQfNq3ahTTfaJEIURMKTmCTE52MSz+Q3o8h8SA5rV7pmZ"
    "aBGOkXLUHAitS4lPYBxYrLfLHM3AFE/OKDEp8khGzcQ70WEFRMtVcrAjCRWV5K6yTn3Y5WPT9m7oaguGgwmqcl9Ed4Gz0rSN5ag146fLC9mxsIWz"
    "Q0wluMavHUfen8WUgKN00jozQTfX4WAU50KUg5lyzWojNN3DM7NRQjlAwzlk25EkaVZpNXl25988oCXB4Ghg6GZYY97i0uyQctZqhyWmXQJ8i93N"
    "gE7ELF4f+yBxOGzWHQyX91QNjBmCFEmyFOc8ocOl4LiTXa6BgsgdWVxsnhQGbK4SJeTO4j7Uhx1ebiGB30fM9X8O/hUupPW6oHUfuyx9XBQm3QDZ"
    "/Bs8xnqNZKoE2SJeOw6t510bBmbXBbJAb0V/GPusdU5pVAsRasEe82JTksSsUB0Ofg2Dd8f2GFbQu12pB7oNQZtoxPXh4BDH4OIKYg8t08+eS5Iy"
    "26Ick1fAvKNuu8jNxxyOc6p2lQey5PgHrd8a7poYHxVJLeSqkKaN+uikU7xUCZIXYcQgau+wQxRViVYhnpbB7uVsLH87TAwBjwVxhuJkhr0uHoTv"
    "JBI8C+BBDogh4Wlu3l32hk3GcmE/uFjCeo3DwZEqsOdlvBmWiRqQX3URo5yewRhc0k68/O6J4XJoXyc3gOokfc3SIN8DKYRkwkJwB9oPg/F7zIza"
    "THIrRi3bXyWsD3aAWBjxYxPzot3GGaeZ4V1YMA9fheQTGFZwv1L9U8D7PSyn4IfYKp7Vp4SpxFvIm+7tPosvCT15VD/sw//CJWGPndyQfITBlOcN"
    "B84Rs0zy1kGAWBGcpOJ6NMm+6ICJSN9G6SZEINJrWEMDj3pShHHGTICd9lhXiRlZ2LsqSVIQkIzh/9UqoaVQ4ox2eCqhyQWbNS7VI6QmVJaoIeYr"
    "UqYg/DZcDh6cC5EOlGLFiOZSXlJrZMdgaUZQJXIRQdluxkijQ0/rtcggviT4h+MbcA3g+1wkE3ZMkGOsd0KqE+oKrK0BJJjWKaNWYtfD/aATT2jH"
    "jSkclzxd6EoX7QwGc/XWpzN0WzIFSEahQwzBCDEOek56D9dGNtf379vMDL+ZE13Ktz9cKGUf9cbOVfHKFG3F+mw816yTW1kM/zxwGRw66vrmohmP"
    "POrZZgQkUDhGHBQBBxzp61rC4VIMO2xTEikx+RLadZ+FrPFjAu9fv1IJhn9ddaZJPt1gkJrpUhqMvlYpuCLpweJ4Gy6gHv803Kw8R+tYaSyOaiWx"
    "lhXkV1jnOKUQPts8kmU1G5+IypODSHZFZldJB0TF6ViSPy7Df2z2VHlODHfHU00GjC7PzAnVDoRcwmBKzLpVOGPi7OgebcYN2QKNHjjhLE8Kr+Cm"
    "UnKBvYz4a+b8GOYuqQpXjl3YWmY8dooa2W2AqQODN6y6lMR5DuKXMjOarqP/CpEgcUbDPhIOiVQDhoOsaBE+ggTiDVy0Ca4Gr8lZf1XJZ9UVr5kp"
    "vtNZQig6XIK7Q1kIGMAw85KO8DjcLHDnWWeE2+PBRuENYtZOR2YiHnnTBH9HI57YNSfIL8U0C9VsOI8bdCyRsLph9F35fD5dhVNsuxJg1yQ+vmIY"
    "7dJctThkN+YqyaKRSZMoU4E18hpccHg2N/tunXuh12EPxvSYSxgRccoh3TJ5ayre9XFzXgu1g49GcS693GQKNb3x2JaDK5DYfJCSTVc7TbQg9jJt"
    "rOLWTekZmOMcXXEFSiVc3+QaETAZcGCRQMCeMdBIF3CmQZoP+zBL4+XE5fKxche0r0rYkgN4iYk4RlrlczZyjpK9a5qQNkEGNAfDy9BbyzI5wlmU"
    "knhUFGDzOAwHcCw6gBHBqLazeQv2ATLSXfylEd0RB0jD6kyzykAd9LOTcsomDMrmZFBlLZklFIHywlXzCt+gJLKDgHaCfIGOdqurzkSkbZrE9hSF"
    "1W6en2XGmUSthIMb1qpyIgx2n0GYkGs0Y4uny9dFo9GmNgmEjqZKbp9wGg0k9GwEe1FP64qhSJuprgVqfQnHo/wzKS8zpfLK3Kw5uuXguWhxrRss"
    "+kpwhGllWD2UGaK0SEI1sDBQoCJWlSFhdjlklBnsAKeKbqWoYZmGOEKsEoLQ2IiqYKGx90bNRjYzXwqMfQxxpZYjmFJCeGkWG/tIvfVwtgl6abIR"
    "Ljb+ODTSnOVeoEmAAZT9Ub11TSM7q2rg30VN6Bes00a6ANKwHAqbcpzpKfyqiIDdend2Fg4TvsKEgUNASS9GlICeB8J+HllGNBchREewB/TMmflG"
    "GRo2PFcNm7PZtH2kBAh7pJm9GM4z3+KfM4V/PVYlKo02Qr+m5uaJzBMbtDddsK/3wHfzwPOmI9QuGGcth3/Nj0TxdKMc/vo54sFJmMyF012Qr58D"
    "ZtKgkw+i+myYZVGSh74ema5GMT7ThXXydxGqe3tBcCcZkMJyVDQZ+MewsbyAgqcb1vVhPOhqNIektQS34Vm4DakCvOb5dcW5fh7ngQAtwRgth6ft"
    "a6lCFtnQJFHK1iCuW1em0Yrje0MztXgpyWBwgNs26e7Ug8LSewJaJzg76LI+H2KeYPBM6xqSMzwzJs9shGcN6kOt1ghqWHUQMewaHVBi6TBoPYT5"
    "R1Iw3gPcmuaCqCdzSImbRrg2mzIIp4wh12AcCDY4Cj8O2fsxF9G2gCzKGn2DXdvWPMO5iM6ioSqG5uNkuTnbeshcbetw12akZW65EDZkTKy0rteb"
    "s3jgkw0CynqagNcl8whrZkg9lwTYI5377+DeZqj8RNXNY11Pgu3hCHw2mq/OIbtBkLhkB9CtqXuTFuEdYfDMAtClalsT7rdZVGv77L7WQ6Q69Tg6"
    "smHPE1xQHLU+jrAeZevY1vL0EDFkmHws7Etu8G4gePs4Dj1LE0q2BW59LJmOFsKEXmrIaVZwxWHYDJrvDmgLuf0yXf266WRIUcUO4Vs/G6Ey2UzC"
    "6fnWtWQuRmmiRtkV7IW7j1+wJCLsTPR2EttE3ndsnqUk82wQsz2gra/sGTt65Gjryr5jh/YH+8YOTOwfmxw9MDGyf2wb4NaOd1MzSt+LgCKzxYhU"
    "DmSde6iTEGcMzB4Ip/UQ5lrFJ9GB+Cz2ugC9Zn1hXD8Pj2cN2K5KPBdgNhrQSnWa8Z6b2Vz0YuvafJWGRTY9M591xbqeAnmH2pAv8jZGuh7Lgheb"
    "8AfTyp4onQa+gXI+A+UO7DGsL23OzkWiMDYcwvVE6yFc8e4I178DpQnzIehas1rRKOBbi85IAZGNgK0ZuBrvVmCeE1LqgmqtGhjUYg1qbe+OhbVm"
    "Sci41r8Ji7DWHocqwbX2xaQPbj25WIedVejWI/R+EQK2/l0zB2wdNkk1t7jW++sYt3G41iPJMuyuj2s9oo8ph2wNLAmorBHPNQrQ1rgL6keHbE26"
    "TYRZJzEicLAANeDW+0G3RiKZZrpUINeo5cRR4mFc+xqhciWgDk9qWJT4ENfPkq3pEK6pVw/fOu+m8hmacuodq82GdBkE2np/PW19PPQvz1Zxbaw5"
    "m8vCaNcH4oRukg92HfXCuu4CdX0sWUL6BlZS1IsV0vUIXvWqUbsV3DUvxcJd7wur1SH45GFck9UWbRbfegykLpgFqGAm5QDXeyLchNBYHD60Nf41"
    "xHpoGZg1qeuR+bkEwhpWvNycQx5HnJ9IzZonCsYaV0w6aib2mUGx5n89EGvNSx2QNZKFh2O9P5IDUUDW+0CviTYCsjbmV6ZwrPc72aBxrPd5epKH"
    "Z01bo+Cs+V8FZA3/UhMPx1r9ofCr2bLril9dLhLK0asV40eBR983NHb1CGwfyCa+lA69ek+EKkOjAF5NTobpegpbkxThq8E+QwHLjgPvwQKS9X4z"
    "maBZK0WyHpnmnU7N9SmDs3ZJNXRdFuuY4FerbQXOetKYUbbNEF8VsLMw83FroNZzrYfVBtGtHwokvjfEhuS20KyHhC+rn4fyHL4fOGvFxPCBZ9PF"
    "2X5hrBWz3x6S9RBdIsqlJUUyRr1e9S5CKbIm7xYhrBfoKRHcW8WwHlVP00aTdpkFy0DP1iNATVAPhjbaKN95vOq9mFmBDifobz4Yg2mBmKQO7f1S"
    "tiOw1mU8LvOcaLnM+bPNIVM/7+wQconk3BPshtGLL+JUu70MDtWHe+NTN+UruJroNtkSQvUBetQ6GbDLZyleonTAbUBTe75Bo9JWDE0gmpY/TL+I"
    "1PqOElGZh2vBb3YYiJpVXutaCsRZigCdKC3YnquKe58NjRJ/FAvWIARWPkfe3WQnQaiNAxeW//eVPxa6/fvKFepvwVfR2FdlJlucIa8m2QzkNHdC"
    "3JxoydZLDSlDUp35dqCmfc8kKln7qBvjrIcRwbisL+PfsDFwOeeqyDSJL5FiYVW/HMq0m2s4/SI2YcmRw5cmcQOLccpWT3hpr6sSXGmlaAFFHVFx"
    "BA0qjZ+HMPO0J570nggdQuzunm09xAiBk99FMGn6DCSRB5PWxj/MyQurZCW40mMCv+FcINsCl94bGoUUPabQ0pkawN1gjABjp2nNUZm9cUy6OwAw"
    "jcLEnGDmtgPngxSHo4/VFmfRHQR/hs3Z6QhuIvKJSXT9VF2bncGW7jIf5jtA5UfD+VrE1cjTcI/D5jQYvSjejH6cLaVoNc2BHBUDaXuo0lbAZ7mw"
    "wBDJkUHnicc7mVP2ngJytOVn++i7cLpSb84s0IbgiYARRG/mZH+cOjrlA4PFNf7nIEjjegoD4p1GZ6QBKhmSUYcmgAQ3N+wmoaM9+WEecx6RDRCj"
    "DekOETWwBM0cPTx1tGi+J+yww43FPazl/J8+4Syh2DACe6cRpPeislkXJgf9BbBZ8xgFI19lZHSZoVHdJemPJPfQP4uZu8BFNIMfkmabQ47WKlXJ"
    "06LHoF7/E0BGK1fXkImCRzrQUNwE3Eq5LGYEvOJbx41Gb7/Jyq17MaY44eFqLlzdF2w0PTR0tIlLQJvGOCWxrB/0ku3iRWP0wfJ5JxI8OfCfxZY8"
    "+lxEwZrG8Nahog9iRAHrH2apEt9G28Hwr1LzI33DRjtvbqm8+3kBR5upjvJU91B8DqaKuX5Yd7y/3lxcpPStGMMJ6AgkxhQsoBOArLvgUBO0iTpH"
    "voYD4htBtXUto1wMeD5psiMBCStL0Y6nK6HogWQGsgrgdmENuiQXQwBGQbxEKhNc8t3yFNvA5g3vVbBbmSNh15SZ8jsTOYEr+cuBgC45qMHCKVGu"
    "A9aiYPgP/tY+nwrFx2BbUbtiX6KcXGI8wUC96NCZpBUt76auMFyARzQNW4qSqRLiHrN8l7ASfGIv/yApLphiHmLeYTpPidWZ8hDK/K0s2R7Ac/FS"
    "u3iXvdgYNW/0B+/s3WynlRIPwkylrtDO8CzNgIRx8HxaxxqtqLFs4jY9QJ7hp71jk1Mjh+C3vWNHjx3aP3Yo2Ne6cjTYM/afY+OTB0emxo6Oj0wE"
    "Y0fh24mJqS3jPG96JOxuDwZ2x2C8/fAj/jIyOQktJ58/fHT/yKH9WwN5zk3DDbhnfDL4HfS1F6ZyaHJk6neqk+dhIdsAej507GhgGrVemZIW/W3I"
    "ofHRA1P6ADYL9HyodW1mPiN5gRey0TD5EKwfuPYoz5us/tn2eIWGu+I+F2LGrWvNWlQO+6yfrVL8ONkk2HOw3CSnpDyvM87Qj+q0MWS+W0F8PoAF"
    "MSokrhQEfSXxNio9q/ETYT6XMBzLakq8ynY47QZEb+UiRt3rnsMLO6JOE5avezhCsz2YZ9Cw4KkhcVSgBNC6uHSU7dpQLd0xjGeZELunes2nP2Oz"
    "P3BnNqZQItZUzkjX2iHt7KoHfuxvU9jOY/U5MOCXMUQX6HRd1INQtLKsQpoRumqSFAUlaL51l1OTdhbbeQzOcS+yH1iX0/AHUfPKaEbTUaOOb3Gh"
    "7BtNnDhJm1khmUWLzWShoQ2wnx7sGRe0zCEGnQ2UyemRL8XYqRgrg3EjUSG99KEFnkk1JvcdOtDoDk6BqkLBp+loufWQTG3ScJ6P6uhIa5LGY+y7"
    "eiC5AHKunhWIiS4/U0BnCj61roHObjicigOZkJrzVxgXV6l3XQUd5FiWm1SUbgNPwyQQM0wbQ7OhAtPA419IWg8XZ+FsXoySgntMzhMljmf6cqei"
    "q6JtjvL2WaovtBowUN524Z2LnmUaMuOrFibTcdRgz17MFJkP64XTFdjQnYFyRhk92r2XXNQP5dL4PG+Pu9y+k8mezM8M1Vm7Wwoz5B9zE6R0Tcz9"
    "xPmYJxizM8ItqSKZwf6aZIY9ZGgCD7BfSHanBFNJmBIjMVGlyLhEvSTVHYVvdtfV70upIEyJ+AVfWa4O6SImVdzAxdx6gzeT4sZR7q6i9ylhNvOp"
    "lfXFV9JwATcX+K6adeVYOwTfPN5TDzM+0Uz313UlTwO5eVACRptgoMB+Q3KiEVHsFJgzuQk3pmBP7nRnZJxtRGqK5mJdQZz9bFwl5mynw/8PADlv"
    "5PjXKTXE4vw0c0KLQgGnLCHUqED110Rvi9EIQo4dTyP1aexKEohI77OJz4ELqXtedWdOMC0kwOq5Rim3J83ee8KGj832SV+EEX5a+GakfTjb1l1b"
    "ZkfOp7AhAUG6eNNs4sPlYGZMCpnTxm06p809QNeewnLORIztBnYR0nZjgvwe12tEvbIKC/2gl4CyP8FQeIrAzVvxK9hBTHEFjaRLK5hlbArE2Twx"
    "FxNzC8UaZ+YHZEc+vQ1Bm/kx+VLVBfXEaobDKKZ8pbPcrAdKszc1DINhPyZDtx+M5v9sXUNXFJfJ6VRUqt6i4MtcQ43QDavZ8m1KYLPpsSUwzVTB"
    "qkYqQWg2xaHhNO5cCS7zEfx7aGTBFiQWMZnJAZ0vwCwDYz4aLdB3WFWbUJZCVxBmVybCGsWSK3ZNAoxwZz2gmJ2KoauFSnGY6Zsh+GaIEJnzOMzK"
    "y/TUIJhp4CFXPficdDkmXTa5S06mEOsQoeqAqOcR66UOXAd3hZfyn1g1V2XTzuXb+qjLpiqUmd7TxFvO+IaodD/uI2oYy9RF9AbpXGm5B1Kqotka"
    "pnJd27+OFMbqC9XWNZ8QNJyyUMLonqFJ/mrrcMquk9J6P4GPHRpVfejCvy2hKG9hzMQW7MbbAVAudMyxKK68wLJN234a68oxy31Zp7lvGUN5VBoi"
    "xeyJGlhAniGGclQbGu+zk382jHKO/eCoZjB7fjielOJ1yaWcbnJGBB6nnCqMTsfAEX3QJnFaL6KjZT6O8pXE/cEou7ke6VoquwGEsqZEx3O7QCgn"
    "DVDEF5wWaqPWVhdFROVFUEAWQIszDyIL0WCHuBmgucyrfpr1DNedcFKP9pSHdWg+zFmOGmY5mFVhJI2zbIJGDmt5T5S07lJGh+h4HvgyKs8+9jLO"
    "D0PyFvTRq90YDtBYwmOjE8sM5DJF66ntPMo2mC7WVlWipAR4WeVQ6twnc/hlqMvsuIW15pGXUXk+4vJtM8LoHTLyJBCK5QHKj8xDYT4yG7I65B9J"
    "os7kGZzGQusuQutSl/w1UvG8PdpfFRCZo/quguUiVs1wcJg2Hc8Gx0earFu72z1Oziiwlxw682SEIEAN69b03OGznjvvGZmDlzALV1ll/HAt3K98"
    "cOb9BD2Aa/6Pfw8OICBztAwcsUpdRKQm7w4mIulTchH4FpBpIk5d0uqmGz4oMyqgVemdLqJNpup+JwbZGgVzr17BFRDN6UPXAM2GdMXiVDl1OUBm"
    "TsuPTZ6zboUYmHTxKT0F/eq+sWTJtnelNftXUEIgxGQegBmvhE2vxrAEQuaZ/l0SKA88zPOoq1S7Mbhu0wkh3GVmrH2g4chQHhjzNDzKlV+566Mv"
    "Y6jruzwgZjNUZo1GdKSVAS8nRDq9b1MqIqI7ArPegOFgH3SDIitQ00CMlGlKS+FbUA7D7BO+MXRVDa4BY95b5xA5bS7dGlIPJi1cgYJjPoqP4mnP"
    "cPq7j8ZsE+ODf90VqJz2bNFi/tAUiOSHg3/bheafcUEbmGX0QXGEmAx2SaIn10ou6cX5nb029nw9slLC2JLVr3flnAi+ONVYzB7h+B1ryrFdozoU"
    "ckKS9eFYKSANq5knAxQo839yNVHgsJJ26bz2uvL4DYoHGtkQQgqCAIV78GLrYb0Sz7H6X6spGA+UGcp1gGWg8DGjeNR8VARknrbidLlJQVKKDgoq"
    "M6dOmXCA3R8M8VfnEAOH2HUBkvkw2qsilqcjrRx0lcOmL7rwLDCKq03ECEbYrznTJSXkGe5poJn5qubVFOjxRY4Jq5bs1t8YndkJDiJJrudLKPHM"
    "UWoi35OSauqSJ2KCiWWnrcFqft6bC7d1tW1U55BJXKNsI8h5CTyMWR7csDnEwp2lC/IsYw0L9B08rwO+0OVsSC45jeRMzKuA43wgrdq90rGGoZK8"
    "fxY3vCLtbi+bPHkAB93F9b31OWznPVIwvLF2qYtX0HsENC+MlhtLBZfIdHHSIvTfMjL9JrBCh5tBRebzYuMycWUe1vNeqWE0gmra4meJWiSn4Aq+"
    "h4Fl0kYWKofokunqX2SGhJfBDA3DxZgTapJpzBaLNigeVFzUi7JHyOj4LLTvywg40fa6YEBT3Q30YYBUrE2U7fay+LUD3cUOdbYFe58Nqxnia+JH"
    "MEHLYYAuhZYSurTYkFXSSIWm+wJvpvgL10U7bChMS8nI6Z35FTN/X3lLaFZ4gkBu4fe/jyp0PZejamJ04165Ad0c/F6eBkvEnujNv8FxebhcsDsu"
    "B+FS9IKDSXE2VQmaoNFuZl2tVxJJ+hK3MGbRAPeYpsvJY4okrYTLTZVXky/1NlUe0TwW9zCqF5BPCcYzLkdhl7HJNU3JUyofzi5sN9ZY2nTCv69c"
    "8QjeZfVAV1SmhgxZ19fyV0dSgUEUm50cfEWA538emytP3KJsoCYGCHJuewRogC2jcZlToK7wrCT9cOQEfZU6XyhMKBdruWlGd0EWJJthVtEKBwuK"
    "pZdRpa81e0hNf0c4YBOSs1w0uKQBkigxGlw9o5AIs6ki0PNeh64YkOOdgtzq+qJXmqYiNRwVW+urqvPM/U1MzTDlkGObsE75lw4BUVkmGEWak6nt"
    "5ruubkfNzmua/8H+eD45yGd2aADNutROif4h7ZLFyHlpHCqIGpJ7xlmuNt8dSx2FsKmMTmWmT4gSr675sM6LZ01EMvKARbg1siwY1NYNTNQYDGZC"
    "OE/VN9jArbsZ6QnOQMSm/PW8gNuYCRbgnomqDCAkbHOtda31sYJ5LkoC5EFRv1l8RWLW+XtFFuxl0/DYPsozngCzQgU9VnqrtcK9LDBp5Is18q4k"
    "RccbsQf085hNODGpKq4m3rvmrFgYDz/55FhXFDUaZVjKQqHbDXepbs5qjBKTRNPr/hdDtdwIiwUQB8OUbtWDfWm9ls+sVLhNJOMsDbNMiBmIo45F"
    "MxzxCp43QNAJIVPNAXG6cjwv/l6IvNuQ/6yxs6UzdGfQafn0LNcHuA9MaJnKn5nAFfcqwy0dqWa++mnn6m+dXKQlDdimkPV2IaQlaR/ik4yaGLyO"
    "KHWAaJRASqyoU0JxOCjHToX2oj/jyvyWpE7QaN2gI6ZJrUZJndC7twapnPrFaM4gTRnWCfMyjJdmHibzITM11JJxjEwlubjVO0GlURGGAwVmVbqD"
    "zq6BfSZ4O/QqO9BAr5bQQKeaRGpMUxRF0/hP3SS61j2aJVFBvLcCATLpAuQ8kqscYmwmmhQjRpXoQbJKMMlDLz/IAEhokDZWeIRPMIozemssivN4"
    "AyzYMElLYZz3xfVayMDDFsGZzVBGmesJ4HyUYaXDZbxQFC/DV61g6BvftYJYvIukgS3FpWjOe2MQzSn0FwcURK6l9IL5Ekhn+oh7hFx2kQGei8DO"
    "8NhSiC8MpzeGlwA6H2WI8RR3K8ZoWloG52yfmqmnSVpN5+KZtBzTeRI+89ormKQRZ5jHsbwM/RJSTA7cOe4G7kxnQF0YDIDUkwpTsjnd0J2ZKGgn"
    "8ccGNdfYzvyZZloO7nwURq3HOMkUS97CYDYVmighZ0YHs+vGV+cBPSw1G1Ee7Zn/MOOW8U2xEupxJW3QBuVfDYM3H/YmNuklXZCe98ZLzepc6CaF"
    "wOuCltYL4tlfjDwWN8KCkjpJFJPSKQlSfbo1sGe5XaHsHflzMW8RuBnjQfACwmCmuPbeUM8OVjYKnsG3PNQbsiOLeH6IyRptjPeMr4iI6RURWP7o"
    "SJJmylemJ8gzvW0vmmGPd7ppkGcahV7qQctvhEyQjSa+ALsS03vI+0N15p7ojcfGAR/CQ3NzMSq19cg9ux1EZ9cixaNygwqUMV6op4vlXDoDO3pc"
    "tV1VUmDOsJc1YB2hvBYLOfWm4ZyXNAmbsXjRcTObiXGftw3qrHp15weNqI7XNUxgCvIKgzjdLKozVVsDtWbprgAuzhwFKLw2wB6gu+3gOctr6/ki"
    "mqbmnu6WYfHVMHqIrUM5N+JFIoNQD4uwiSkcTLORQg+8gw6WwXRjtzndISznQ/mRcC+lx2hXgBwPKLAe08tdo2QOJglKGTHvtE6Slxkudd5Aqdod"
    "y9l8GxzCQuHxY5Oj41MjWwdxnhDOzL/NgfoUxNQKOqiigGO2BGSHGWSw38ebxCTrKHVgYWayG2I3ywMpETJKrRpYhik9h2fHh1EO1hxq4QWPLMMj"
    "UV9wzXIw/AuRC+qmdZHVgbwuBMZ2OM2Ti/hjsNRMmTzK0Zrha+hTWEE1whkUwJpBHUpmWO3zNcSesM17gQBCpBj4EX6LLS5e3AW2Od/AA22edBfC"
    "wjanFrR5svV1EbU5LVwQH7UZfp9N60lMPyrE5gn09YcOsHlvaPCaR3Jwzfgx1HjNB1PYmVQBNuPLXMH2ilMfs/moPa8cYDN+jozU9gGbD8mre+3P"
    "DrJ51GkACYEMG7jmEaJNhdK8j1+wcjSnz/lWPn+ci31o5hGrnQk2s/RloJmBjeV9SvYP3/c2mi7Sq9ZCB858MEQ5lFajf6nFCX9SyMyH0kYBlZlI"
    "JQfLTHp5F0xm0VMxPFiPmcoVFPNhgnvwUZiBn3kwzON7mbfBWftQzGMZfjRGRCkcM9gYRqv2AZmBdMQCAUZajsisrIUqm1lLUQGZeUxrj6KOMmJX"
    "AaW58KinepegNo8RqTaYtcPHzNoeedzmSYRjDIlTwDbFCrh5PEG25yM3y8fUoTYfZpqwaIIHzVu3UoXaTP9GG6A286pk5xRy8yQJg9RDbcbsMfrK"
    "wTU7YteAzQqvmWI//Fon/IZIsQ/o5n1ippUjN490kQ/l2M28pWatWh5oAOdxkBrwOfTgmxm0OWXD00dw9n7K4TebPzO6AQXM5pGlpZj1Z0RDKsFs"
    "lgPn/S8FbH7eMmzQ6+wTW8FrRt9CJCYQyXvbdGtIzfRVWoj6iTMuDuTVVVtHamYIQfhtRnPzUE1wQ5BmMVwZxtgpk33iNNeE7W8PpNk8HGDVkrVB"
    "g5hfqh3TzIBOq+gdiu2YW0RqRqaEj5HE3ipS87guynObn9LsEzIHVTOYNDZ7GhjN41XrVkMKQ/8U24O6a3e3BoO0iq98rA4QG7JgI0a3DQPPpbAp"
    "0GanOAVRkHMwsC8uLUVqVt8kGwA1Y184fX5o8yDN/Cgbz5HxvbjMve1BNHO3WdM+YVpEyrbdJDyzgRNt2sewrkhU93THoJmdjxOVer5/4W7zFseG"
    "FRgROzkJDQOsQrxN9DnQklP5kHYMl9lzwoKegvHMaMZpDTJmvNtW+WVw0cEsQG8x/JsUhHvfSMzCrb32SDxiFHqWq09L28Fk1t4X6qGOLC+1fkPs"
    "Ruw4uGY4Ol5z6yMha4/f2VlEZUaRXI8WQ5QURu3DxRSRmVlj0QpVKTIzdIjMOYlCpg7udFY06xKI5ilQCI2zWmztMIfPPJqiHxDXwc6mnjDN9Av2"
    "hm7UKuz+kqC6GcW3FKf5ah6medSdqdyBepyWwDODyolvNsXvtoXLPKFJqnUDjrIWEvsWgwP1e6wbBcESxB6dVVNk9nLRdgCdeUJ7OZiRwXyU78Mn"
    "c3mXLPrqKvya3gYaM7hdO4POXD4fdJKFAWZy1mloepm9vHQ1i2aamkOQj6YKTznPabg9gGZ2FSHH4T4GlfOeBYtzowtfUUre00BoNpw3ri0SM4aZ"
    "zMFVqW7mvP7n4DPPUOKEP+Ai5WoMqNMFUeiP/1RBms1J6yc2BmeeNyLD+BeZbIw4jX8KgOZEXD9aSjeTIEc+TBXpU0BkFlep9VQbNifzwnd2e9ga"
    "FaXX7LZyFHY4dt/nvBn9QzLHVs8Ng1/DdqqnM3x6KUzyJujOQzJPonUgbWOjw/NicIfsQLsN1lgVb/KMTmBKt4HCXIgIsARDaWP82ko96guGeQSN"
    "fnzNPEW+A25j/Y1YCbhtKGbLxjmEAh9QAZ6tNrOM6KoaLqX11IZQUt16y/jLVMWSoYeemmGpfqUSZ7PGduRGaT/4yzNlKoXbo/DnBcA8wbOEDaAp"
    "D2K4BLgVXFKYZHNxMRaQ35gRZ4ErIM0DA2+i4x6nGplEkjBAqAWKtsdmQcNB6yxCjmTxNCmeMawhrOPb6lN4ThQhLdu9TshLkFpfAugLaAIshbtt"
    "2MawEeZBi4g/FHKuCUZIfjnwy+XHNOhOSVYU08lZH47v10XIWLxki5gInVJoLOHAT4WiYvRzKEtaDm0UFWPPdHDGPMH32Vcw/TWQsJeLPCEHhSOU"
    "BWICABptGfmwaAVRBj9k0faQlwvXmdIX/CsNqhtcnUbcH/byWFdt0zCisCv8srZVaG/4daY9UJePjj13bHxyfGqcYYPHgyNjR4OJseDI0cPPjwWT"
    "h/fuHZ/cNzI1Nb5ltOW+R8Bujo6MQgdTI9LfCHwa27dvbGrq2AgFY7eAsTx+8LAa5XCwb/zQ4WBkothw7/h2YJUnD08cdrjKK7SYnivHMLO/v5sF"
    "Uz5SR3YGNLcYZl4CQtJMl0huakRlFPaudTcU5SP0Kc5HdMthlCfCmSb6dUhzUo/HmwFTnsi5C8VJiIaO6E857al/DGWOUpfdIGfxqdQQuFE/EXxy"
    "TyUg7+S1g6Gr1w0WOwfezAyCGy2ZSy+C0Y68LeTkhH1EVCbnKdJaYd7VW43cMdTkvifTnwnYGzXZZk1SU1G2OGoQdi29OdJMOIvK6NmpbwptDjh5"
    "bzrTxHtsgqMxJQxg6uAgCRqSbRnrrUJJhu+nOw6afCzBnK86iE/sL7KKJgla4Bgy19gq/TRn3wgKCeCI0niM0+SnBUrGRfB41gtE55OgNifqYkS1"
    "UqGjruFgdB5VGDYsSa+TtsBGmpgHTryBnIOyTJ5SzJsjOuKSDibi8UFr2CtMFCOScYbpzxQhedywJMPCugaysF4mDdiq8u6xic+R+6mLi3A4IHMX"
    "hd4Mpk6wCp+ROa/dTwElxAZpgz0jqLLWQpVqZUzSQXQg1/AFLqhHVnEaM1h5F20XEDl1vlxJ7UH6xwIh7yIJ5ZCc84XhjiAhj1eDHp34wbTqQIm/"
    "D2dr5v8zwz7WHo7CDGeK1VSDSAIMbBnb0YnsaBuGa5FtJVPk6KN7GNqZ2ZIQdt4DmamXA7ZzcMddnFCDKr436ERRzHSo4rty4US+uahNb4Rj4/jx"
    "ukH6LvTzlHCO+TTK+sLoTqJc/YhPGIp9WcpWdgjiuG8dZcMlPA2AY1NqkW6eG+4UtPF40CetegLDEyaaJaW9gIyFPheLWplr/EuHMX5uk97ypHXT"
    "rXNXIZ0DfV8ieVOtJGnyps+p8fJknPlrPaqyZHbBVwdwzSCeKe0QnXD+0qNeCy/cop8Spngiom4p/EKDJJQwgBnFoJGIekNOqpD8fkC0bkTQ11Md"
    "0Dbj7w6kMxsZj6WCgbPbZySBF75/WijE3Q3yOsbiI7qy3K1y+FO3XiVJuEnE4f2wb5SIUE/E6U+7iLBAmC2Prl5kR6FpEm2IPizPmVoW5v4DEpvo"
    "CUEcYkZwWqqQ9QAgpvwh+SXmnIklSffsA3140jakCiOkGBOEHsj5YspQhyWhGKOaLjujBHLYS9THiO0Sp4jncYdRKmIUUrI4TCljWIJAzE4f6myR"
    "Ll01LYUhZucrmFFwjRukYqqplsERqwKFWMvS0MrrMmRiUmMTDkCRFuDFeKVyM+yBTuxV3FglAR8sRSgmjEwXKc4jFKs/ng48scmHoanSAINoCuV7"
    "jgJXE4gjiJFWNXVx0v1snGV4V+jy0RBxAZ54L2mQdB709dMEKK6qPEK6TrsQoiTMWYfS12BQ1YeNV2d+O0jF5LFAj0poYg4SaetGFhqveJKYJn5F"
    "P24Drtj15FWzpbaaTbXmiRSq2rYEWbylcaX11uGKR/OdRjXSI7AS0TbFlg2vOnI7QMWmISKfQKNY7j35ruBiYYEIOXd+BoDFx31upDQbO2hENyhf"
    "gqYJejfnhBFbkOh4KrYTTEJ8V4oe2HXeB0SxLV52z+bKPjcAKBbCy62yG0IxygqsjZT4Laiaw8G+EJ2Vi4sYK8fqfzA6NM7f4iJKPSwrmYmTcAa1"
    "kEVQOqrU2uXdDgeTTQ+AWOowNfawjzvcOgu3Az315JvyQIfJweyBDvMs4BA8pyErYjGOTuVkpLoL4DAeA0hcUKr5SJImfFcCNjwx4FkAEgjR3slS"
    "vGEM4uaxhp/3M2kM7AGCz3oMwz8AH184qgNzz1KxGLwtDp5ZbKaxPYo6OlJjHIkYjA8oPJ6QZLAjilFLB35YNhN9HzF0hV0s2nFjZ+eimW+hhMet"
    "I0ylsRrzOTQ4ORJme0bGr+JUZT9UTkbi1crlAIXH7bz+49/R9ERdBMPnGZDzDCILx7tFE64hH4zZnsK8r2ZElm3sgwibfGb2sfo7yt74BDWERDw1"
    "M+iDxBWSu8o7RI0cDGc9Td5A56eW7No0Bx1c9qRL/U4RexMzJBCVjwu5ooKFU2cJMBzsL6/wNcc70wU9eLzmMj1okvYuTdPVHYXhQ6LZGOF5bTYs"
    "VSnM4ussYGIFnOCErhStIPSXZqOJM6aiKPQggsftQLFdpykDNnXTOazgcAZzBkhByx9i2hsfeDjQw1nkhljvsBgE5cDA+7oRrsIEPlKPanFAVE8m"
    "B1yPJoZNFBRwSZa1jwacfwBBgc3pxybrhrOp0adDIphAgYlsTapDZENeITsxB9JFBxZsTsfGV0PDWz3m58jFBtGbifIW2agaYQLbs5+lUr1Q4wBr"
    "0jPUUCfV27Ri3o2HgK/DYbbmeeByrFjB/o7a3REbER7fVebdcjHHQeWcjYymj5cOto8mSXoO2unioyFwB6yGdQAPeGESIqgi/K/NwYE5zkcO91ct"
    "2DrEcbuFbRYgfyfJNmSpOIgxG5BtcY7LdhWHJqpCqDN6dcME4cjcEPOKmorfGahfe9NK1AAMrsKoWTPdGN/X8XEgHUpnSpmnzlg6l8IwdkNQFbtG"
    "9D0mTjAmPn+lxP1i2gV/rbOzcSXkpWJiOzM2CQvDfpuwE93RFJ1KcJs0cC+WYRRwew/L9vsJ4FFOW1QCjqMJ7CcOcEYmQu14taHuHDrvQfRwJBHJ"
    "Z4QZqwvmiHWha41LWDlydRFyMSmzqA9HOmWzSrn9zbQeWywcOXWROaGHxSsuUiUNCPBoKTIygfc1V6kjksymXGkHKJ0uBr3J82ZAIJRbKxNhYJXz"
    "iAExFLzMcYSvi236WBe0XaylGOiCdoHeRC8Gaxj/oEsfqSjwLCrboQ01iEwKcbEYPrPAFtWA3XZVCpsziJe42fpC250wHgxT4MoZlLFGD4pcYMJW"
    "4pjiiHQOeQVcLgwEI+UMbhBAVpqrDuezE7knrO5hHGqWubsXOQXCoNx8U0rLFMC4HEUQJHbJZjHWlxlXL/k4Td9462r0PilchVeCW4KOS7OSA2Wr"
    "wATSC57musZc260SxCy7thWeg4ZnmqpG+XMxNUXhiQKaKuLiPm02Up6CcyzRNI/Wg7gPEqsMLfNe410mjzLH4cnzxZNNcg5AG+Tg3Ba7p4QZmK+Q"
    "5uwWSYvxMiK4LctrThS1nKAOFxCVe3Sawm1sgMVNuqEY30XU23FlcdUjQiA1pbDmGg2aeqa0EPfUfGyQpmqvnKvM9AskYDK0jxYkrpyG9bSAiqkP"
    "mVcO83YCrSje479+ZUE4/roqVwcjIZKNKD7rhnD7KucdWmcw+7E95BzQgU1GcaTSkAkPssGuarswOgVJSYqZC//1KzweO+xfV3fjuGINiLubmqk5"
    "MPteWoozUl71w1EB3hbJxtqSqGGnWMsTctQM1SKgme6st4LEgoTr0Vi3vKsCzVonTOloRonmk7GJfVHAqZRGl4Hr2ZyJQw+SaTCIypIsdG89wGuP"
    "5RIJaPN9CSaluP6dzJpI++jnNfpi+b2UMiVvDLFsuuxoYRPJPsQyhO4RPORVzE8InsQMlkOuJYZtyBI4w+IiRRipJ2SxS4Iyi8osXLJod7daJXeZ"
    "o1BpQDawyxXiHFhStqDRmhins0CvlvTzqJzd8GvHnfSxIJZylyzEjYQUnMrD9l1YrTGcF6ywinMnMcpSDH1ZVRDcXPhfDfkBC/EnjoKQTF4PCTIg"
    "UFK2d218BLQ7K6ZVYEG5R4QNkJGchc4+TEmE7LZTdDyS56koSdVMuwOzIF1GhSHdTuaiZp+yh8f6CNKqH/KFJ0vB0GLm1Zq0UdymVprV07IKOC6m"
    "kSJXhc1gDNcugLQTkRRPsNor+pBGn4HpIHIWGcUxp1UqKBmzPMs88XlztTGmF9WMSuXEPcLSNpcVLO3h/391eTpaABWoFJh2vLacQluNSzsVLWTz"
    "cb25VA3rG0HT/iZNYAEn0+XmUrCEgrseV2shNywi0dpv6ItyENp96ckKwuk3l2Ba8gP0FxdxaA/XauFSfBKlVFwtgaE92JyvowEa4ts5snQ6bZTB"
    "0E5B3yfUAyX4s8+mA3WeDkiBakogajnQWV5xqdZuv4xhq7PY4+UOKacMcHYqXMriWVlCWD8RL+UAZ80DJyn4WAI4C2NPh8AploA30NAlZPpcON2s"
    "BgtL+AKyLD6Jhxej3A6PQ5v5PNbss1E1nkYN6XhMP5ZxOfoOuVvYwA6D4zFa9LAGohPeqpxm/gJR0HKY/D6ux93QZw/gIQHLGqg2a2lD5plm8wtp"
    "ncbg2XYFoYWTPo5+EJxJKk/7yiJSTBIbYnB9bgF+Fu8VzHAwOBFl8/ABb8dJvcgEDUq6aDxGT8xZIPTfN0HQ1sIMIWcXgBMsZPzjRjizMU2Ett98"
    "OxeCUEYIxmpIhNMLZ7YRHgehj9kIcK+xk80CzQI3IxSCuIoOgGQuXobheQ9kWjjDvtFm8WG7cTylXcHxdAD+hkF2BGqWhsjsq75i89A8CtgYZr8A"
    "/CAMpiNDd4nszFOBne02m0qI0d3jYLqFtbkBuN2VkNJN6SUcdmaFefWDO+u3r8YLZsObS6AxNJfC2dnwOFxsuN3LO4BA23U4S3LE+0BhtJ2cTAeO"
    "bxaEdqHZqKXHK+Eu/SDcQrh+c1j3SCMmc1gYOpDAj9sBo7WIsWFWiY+jyAj4Cu9Wz003T9abcwNxcQ7bQqZNUuaQZnBU4+BaxbvtF0QVFo0WaCim"
    "Dd0hNNqDTWhyHJ3QSJ3TURWMWgxN4RC76EtkhyfjuQGSqXRLshRWWGG+nABT2gh/9tmRqcnxF0aCg8eeH9m3b2TkOfgDvvldcHhgau/41uFohWuz"
    "8KNtmg5P4nwTjL7MTzdx3n9fed/NfAHkHDGF6RR/IFncFyAtqhI8RCWNgRRBPIQLzURkbjkS7XEE/HHCa2MA2mebIINB5lTCJTiB4zA5x8kd5uwe"
    "ZJ/V+Hh3vFnqx1zHeng8rLEU9xFnj2ULZPymAydPMP5ST6jZkQy/P5HAhVcyvQvM7BQ/2Ahns7hqHnRAs4eE6A3K7AtMzy8I2l8BZnbK4zBFmNmp"
    "nNjzsWanSN8UoNkK/UpIs8fgPHNgs6B61eKTwNQ04OxkOB1OK7xZUmx8rFlQiEDPwutAIlqjzU6pa1zAm7U/mmk7vNmDWuYbrNm9SHwaajY8WdUa"
    "WmaUM9FwnW3+W1hEnb9VeLO0FP7WAM5CjwpwtlnPO3med1JMFH3l/XourIH97iBnD6AQViCzYxn8bSwOBzU75dGJRpsdZ22jDGz28ADoJnUmcqWq"
    "KsDZUdB7YYrTyEpBq+OzMeCzk7gdS/OhBz9rPnnQs9bCYssrhz0LRzi/gJMvwM5OpRh+QD7ZCE+eTOuWBkrwZ/eiVcRWQ1zAnZ1szk/j36xExmV4"
    "s6xsqydKIGan0kVRYANkTXEeWJYOC+Z6ouHDyu5JcfdYtXbAslPNOXS/ypIEWxaJwwOX5UNq4N2VtUtI+bccei/Cy47gHihATgcq6y6RhZU96Ks3"
    "HrysuaYGXJZ30VwMRpjlf3Oosva8g6R53OyFyUgmG60ruOxzPssvx5Q1bH46dVRpoWSn0oETFP/le2/RZPn7SlzAkvUb5MBkjynWUoCS5Q+V0ExE"
    "9tZByeIR850pg5HNf7mAUd14KzCy487osY3ITUCayNagZOeBKIAsCqEu5G/0l/CabUDJMu/1fmaeDfsX9wMla7gWrREPoV8U2RPCzLcLI0um8zPY"
    "0a+CdGCZ+wUrPlwMl9NETHY2SStbgY+dbi4bNQT+amCu69bgY6es7c13ktYOPwG3Qv4Kzw7RZs6FICd8c3nnIWT3N5fSeWfYYVc8OmzWQgpqZb0C"
    "6ntTVFDhyaR+pifi+pw44EgwWLxYsQV51v2Ax3rWwRKsuTlfz3sKitCxCZwrvk9aGBt/3RU9donW1kBdNwk3jR9rnySbeMm4EZy5WNkGfiw0CUEh"
    "ZR8NmDCwm3NMqiX99wse6+4juzzxbOX5iihvOwEeq9gdeyh3B4ITC+2Xa01755wnEcyiKrqE+HQr8U5CxarpqM7Ed7qbx3eURVNK4uNa5eobGpbX"
    "gj42ZCzoYzN2pVhmys3Gq9wOJGyN3KmsUwF7HTgZI3OwzhFOeWjUyeTGG+SsGvjpeLooOk8ODPZZnKjZjRoQYUzI2nkgWBQzKSk/lbgbDCzuPNhu"
    "NeAns3CXuaMS9Fer+vDXC/R1Dv2VXbzAf4wB0gX5da/I1aCJrzEljDTRiTTk655mo5mwGeQBvhKtpOrASsBeUSE+HpPrYFtgr6wIOgpx9wL17wrh"
    "tsFVTZ0ZsAO4rnQkvDR60fVxcrcfj6s8B/I0TANx0D3IU28lru8MmquehcfoG+kAkGUNPVDB78N6eJIMDODPdXGVbw+xldkpb3I9Zm+48YCrhksh"
    "KT/GWR4/JbTWTew/qC219HgQL8f/c+BZl8LCeLmRPD8i7DRdyacKz2olnHqI1dh4Y5RWI8cX5Ad1/DuDzmrPs9CJ9vCZkxaZmJGx1dDeoZ2GZj1G"
    "ihwLL/TNinrgRIlTShNiSAHmD8PRpjClk6gMGmvGxFITfa83hcxqTjD3qAk5VWzEgTzF9LqbnUdmLfbozDXjOW+yHLUdnUwX4kKxOx+hEfm0Ff3C"
    "s6pDAQ4Ivc4Ds0gq4Uny9ogAEoc2SazM+s37wmrlhxrKh6P4sHkugMsTor3s34PNQbYapu6N4HN493xYC6tIWUpH2iJoa43jvpgrGqIPEK4WDIh9"
    "urb9ILb60y5REH5GeK2T8+GJLD4JX4uviKYrAWEst4DJNutNChEDDYNpRCY0aZcomE6GcykllJHPPZtPUDTNw9lSEBIsu+AYqp3wM5Am6ljSHjlf"
    "XEMCPc4R78XwZAPIOh2ozpDshlNdiGENbFNa82S6SRSPAQMi7l8OJGvXkxjMn8OSHAJb2MaLQbxoGszNEzEWYzdq4RD8H1TaiomJBOTVgGWA0MWm"
    "rBDTjqdLwr7g62lkOWArY6aBYjI8L0qt0C5mdnYAIdLhKUGAOqsL6dhAEgkCUmliY/lvHbfV3OgK8I3fh+Y+10K+0Sdh4GweBFLaoDB8P7itU12U"
    "TzGNygFbp8yCKDiILZWV0QO2de/IxPhEcGz0wLFDFph0z8hvRo6OT+zdOlRrz15dUw5RTowc2j9yKHhhfP/A+OSBrWKzwvPGbzA1Erxw+HfHnt8L"
    "vdomQ/TV/pHRAyPeAjeNz7pv5LmRqeCFkd9OjE9NjD+LLXos9+DI3q0gsj6Lnqk5JN5KWNvlngfStY+xHEc3UUlwvByUVQc7RXqWoLE6XzkHPeXJ"
    "voFYD7PHTZxwudwmT1US16HVozYFyoqh5qhe1EOKl+dkE1X9WCdNVH4qhFbTs2nbkCQncqFa4lSOVE8jWBA6MBooR9EHyH2yENXDhe1hsuZVZGwz"
    "FGMCSE8VcieRWHtNodjLYMG8o1vQG3/1MMgEm4SAiB9z6EzuWvahPD9lQalN4a4etPpefSGexsQoTE49yRyac7JqeOjKsbfDWKuYhUF5mahUs4cN"
    "qD9UNMU+E9CVMpP6h3cT5orMp25uJzADkqfKipI8jp8Wd3V8YYEXRCdqrEIM5NiUTPJVoN63p8lPYYwgBpEujnhOWkRf09smhzOYbx5vHkdDKgsx"
    "D5SWG08PkgMMGE1DhaPJFQurN5bmzxRjdXQ+4vkJ2+HztVQBFAHzWaD5sFOM5Y3yksve26Q/FwcBlRu7YJ0bRFw971Nq6oQhsScxhFtB+xTO8jjc"
    "lJDU7YT1OJpfZrifSYDaFqaqiguRmlirh5hOIhP07g1dEWXixjuCp+pcaUXfS7wc2LxS3wWTDzj9nFBUmYS6ztH8nJskzYUoYUAsNWLgNOU4id0M"
    "uYNB+dnMskZJ7pRet6B0AOxHZksMDYzBHcVR5UmkVvYY15mVLr8PaxaHHVfnD2m9hhtCp6al4s34XZ4OXOpg3g9PoQFzcYnlUq5x2WBGYu8ERmpe"
    "ewBtMNecPMI/FSZqb2YGN+U4ajiWF8aS/rEjaKiKkmwfcZGRFHSaYqp7FwhUT83O9xI0iumAv3Q81IKLuvcOEftZ8jP5Sl3Xu7ycBfSVkGcSf0sT"
    "zqnN0721C5CihnG1xBf1UukidFupaPlmrY4RC/RpWIe9bRg2CkZXLa6Eyof8k+CkPkuXCH+meWT4J35QWdzigLcjDVixUaHs7vm6ramQftiPRZuP"
    "VQqizz0NONS+zOKKNod3u/Yk/zCJc4GK4mgwzktH8Rb3hYv6Aiw8tq5zw5pAiCcZWiZRg6PmvZFQ4WHWhGDnOR5sSxOoeXcoVE3U6KlDN15PGFTO"
    "gcTpkr2i5yuJZH2AoSqXR0pEy1YXiX/VVRkQKpeG2SQGZaOVoKH+nsr8Fni0EhRUxCU4QdddysLy2Kfydy2sOqmfgz3l5AoKr7jAShncKU2VYreY"
    "Zy39lWOc1lwJYD40ilyp0gve9AWrA5jvsZgti0vBTfPf5MBN5RY8NWxT7pMLDIsdUirK/AIGEGgruBMuyGL7CIeTqLzKc/TRTA9IVZyuv3sKkKbj"
    "uXPi1DaSC6Z3mB3WwO4yNhrrh4OFI4Z1n4BO0cgl8SFlkpuAOFWZTDo14GSKNeFlcyqHOHVfsTm5DYxT14nv8HNFUgU8UVMstSVs0+7jYZi/13Bb"
    "xTUttDMNAn4ZDfJmZHCDhbq86XA+tVnH2wY5Beo5PAV8EDFgfgaApo0wPzAMBjSf6Py3sgw5T7vajYORCCV9eiGtBNYTrc7/ZKVPIFP3SM8Swg3Q"
    "TPMLI+FQjmWKqjAn6KEvD3Nnq/FxEscY7lXQZUi+lIy8sEBobg3KWscrTeoi5oJiX+YxiehlDVZlY4zQcghZo5s2gKOSHNb4pgEX+sFUYoreogec"
    "lUqHeurhnC6FPswpTYjygGfma6HvriM/+XBwAJXzJMR3d1C+cMLlWnBO3Ppkc6EaTvtqYA7xlLPj/NLLEoxTH93U7g+Oepz2g3BNpYTar3KWALV/"
    "RPyrnZRLxxjxT4AOho6TWQ+7LoEyzXlImjxWGEtwOwd+OoZVDrvI4tAn6+Y3HLyAeyWqWOnY5GytY17pnMNAHammqEvQ7tKtIeetyit6RoZ2uQw6"
    "XUdHeMm3i3PJoZ/+x7/jBcc5oO2NCHgLrCrZ6eyGecPPmOSRnkQSIsIm8wx2qN48kWGGABy3iQo7KNQj4eKCxEK8w6N680GjsudvhBQwavRTV+dC"
    "MhIrUTNxW4P+nANAFdnKq2+UtRwORoy/QfF9WFN2Am2jHEOC243mJx7vArDwk4h4misp1eCne8w4zrFOG0jSbTg4BBfo9/Qb9JeeTKgqQEbmRWvQ"
    "0z3aThgO3D40pKapJjOwWKfcP67C7KtkXpahnJqMuoqcUndUUzBm4SwzYkG07bSYw+itAVpJ7KAulGA3p4hwqnJzG/myQoNw+kK6aBMNAyJzXHON"
    "0xuYoWqwUz+pOAd0qn5EkNOT4Qm4R175OeeDKfGBwLcDjQoDnjo8U5PIN1APqzZdwEtfoH10D+gc7rwaycyEfPRMG7/epa3ynDSjIxcHvlSmTanO"
    "8ddG7NPaHvGzJDkHbiWa5ruIUS3eR4Vy+hxfdw6x6R3apdywufIM4z0G9mB9NdAL3tIT8TIqsIzVkIEwmpnH1wKjkaDhB4YF21QWAAdIsTQsAlJw"
    "p0wOgnIaULoSyqndrmDdaQOhcE85Hdk7D/VUpKPZsywc7CIO+fRk7mRQ4rUNNX+mhClYo8E1lQsDLZVygHcR14WDnLQ6Af61zDv0f7l7t6+ozmxv"
    "+F9Zdzs9Bs3Yvb89+kKvTJu3O53E+EXzZXTuSqnWooBiA/XywsU7ipNyDCRyPigoCioCCmqpoBcd/w/HhlVVSDnyL3zz9JzWWlUUB9M7PcbeHaxa"
    "6znMZ57nfH4V5UiQ1yT8HgF8+g0N9n9iLRTvtxAU+H/F6hPKvNfYxsUGPP08vCNlaax7cs4KgM5NiaS6JMl6C3ynOlxqUk7HymmKpddgp/BYCOw0"
    "1KivepnEyLE91gliNh3mMJwcMR+Ei3Aq5v73DaYBv1mMorAz6FW6QiItWjo4lFSjbSLoUKXHUpI5ehQb0ZSTnKwWJddJtGpmA6fRdao9fctBdR4F"
    "ZFVcaM4+yVUUpz0q9ISkUjljQ419UqYWCYgAMcX+deO+E2jCaUvYI7qHq3S9RF1EgoVpMSXOC5SpXCAgCbHZXVEFQh0xkM9WAXCpukXJCQrd9s9k"
    "kquTCcUcV6kTsskTJ88KjOxKE9X66WT4DFUp3E0LK4gN1Ras+2fCiKV/sab1IkBzamJOG4Fc0Pw9tqw7RYbTtAE5XI6RryiWJmuSagYZJGlpj9n1"
    "dQ0dpFbCSSO7ww/WICujiUyjldR5qyRMYTozeTmtI4toarA8XpndBSP9KGIe3YpCXkkTDCsONxWjkbfiIlPhKkOgIQJFJyadrbA/SgTUxBTmCHHH"
    "V0Rubsm0BCxJtNJtIOH+AGxNggPBd1P/dtkCo+HoEK2QdUUgjDuqsmVYAFF38OA00siD/xvT9KIVZEd84VBUUIDR/62NyKGEiFLiwdIKMx7PyY04"
    "CWl3sbgxpa/Ok9tCWFeGC0OgC5zvFVeEe+rc/IGwpjQwqG46hNhlBBA5gr+q3mIM2zWp+WawwhJJqMmYyOj5aGmjvckhcHJf/wNpxPESevJcOEn8"
    "nbBkjODI/hzMiYNVYLPVNeGil0lbMLIeakNT1LC6iCxVbtStfXmBLtgKUE7Q3ZJCf2BVDfRjFwdeeHDBQvFm8f/RSlxUQ2lz0WDcMUzHKqtJx+h0"
    "7l6hcfUd0lIipuWJn1cFrBjEUw0Sqf1bU4KLIAEqBpBAlVJktrmaaqdyC2F2tnG84/LLQTVFoiXydlNCs6SMpg24VfUQ1LjSfKeiSEljRMHi2fAi"
    "vG9pZtZUasG+rP8yZiqG5VLdN0535yTPjNyt7grwg+QSyT0745oQAx6Ix2duPpuJnCvQTvOZTEZjIpJTTHtBLuefNktXGhCPnEYXCyEbVmo9eP0q"
    "ccmhBQSyfAC6Od7ZBDdkNacUgp+UPZkEJUCp/rdqKHFWYndMWRtRD6kiZ5ToRQAsEiSIiuHJTQe/EDHvqVOP7oHUqTIgaE34R5LOxLqmDZx/xdJo"
    "2LtnHAEG/UymLNDPD2Oz758+Ko5vRmJ+Frtn9x/0FG+O2Kif759kivfmvA9jj/Yf3D8I9rM4sFgcmH2/3u3t97z4MDXq7a8Pe++z6/B/kcCfxdnu"
    "D/3Z/YHeYv+iV5zP7HePRIJ/FjtXitP3YWXeh9Hu/YXZD2PdYdzP9xtP36/PerBa2EUE7uf+Zl9xLrs/Muvtb2y+35iH7UYBfxbnNvfn7zrPRGB/"
    "7j9fBzJ6xe75D11zFu6nplOkw7u/tAib/fDDJOwXNu4xxQ8B/VnsXoQXcA/Fse7ii01cbHYwAP/JD0UjfxafzRafTHrF9WxxYT2aL4uTHcXeSTz0"
    "4ssFeDgI9flhcLBIe45SZsVnY8Vrg7hAOPP9hbmwG7s/31vcHt2/AVt4AuvPlkL1fL/RXZwfA64Yg6Pw+HDL4njuP+sudq57uPalH0OOlz5PD+Ys"
    "3rx7NPhOPrAqEIdNYHTF3rBP2Yz3YWqM91QWt7M4ca04N+h98v7pyv4T2CbIS+cmrBD+F4Y7GLyTl0Gs7HJUcSoD+9sqvpj8MHYfvtgfWDwAyLM4"
    "Pwu03R8BosGrY/20rkNieWrxLM5Nevt3lnEhEyNecWL9/ZN1YlbF55WBefLjQktnaVaPfvHZ6Pv1zLEQPeUzIHlxMSOLJPa4N4eM8mF4BGYOkOaj"
    "gHkGp4aNeR+6MsWb3XisXSug9eDLzQ8z3chjPC5SWK1w+fBgnvyq0NgDxf1hcPkEQDtl2OLEyv4zM/pYr0eLtJUWrl8PxAJxWOhO/az13P7dLdrN"
    "eB8YOw8oZr1ifzdZHHgEIlycXDw0iuf+C7RaoMRob2RuvOLCZvHmig3jKTMdC7OzODaI+gzJs98/queanf8wOXbaY9NMWsBeUYhxiLYnhOK5P9yz"
    "f2+7ON8RMRMtESbrf8qap9pjZ6A4lxGtLCoCPwbtPjGCUga8XpzPFieXYT9dxZs98m5JpE9xSJhjjw7pKc4OLm0ednGXyLg+ilIGHgkyytymrBr1"
    "A6z6Q+ei0WpavVYE6sluAjLk/pNRcHpQ3cv2i1Pd+3fAYC6XRPcEQQLTZuzawfCebJLICG9miuvr5ILhOWy656ORPuHL90/ul8b5DGtiPNGH7Cq6"
    "YJ/s7XngBLH1Lwv1WZwZ2d/IkgLunQcFnEWlwRa/BN4nPwr8p5/uXAGfywH9tKRGMT592o2O5vSoxv8sTvaGAECVTFk6P4wCGmEzXSDQ4niWnWzB"
    "AmWv65TCA/2/LhgoOEywLBEWGw8UDgxk3QIEBRcINuYigqrDXg7AgaozWw5hge6vZbWbYmBA2W0wjr5CAmWOtaBA0f+b23KQQLWvZ0Xm+/dHUb8u"
    "ZVwgUHbrDAyoHk2AQFm5BfMyAU3jpqVgDmAkTy9UIEH3BzPoiq5kmU0VMii4vuAIGr4x4KDFrg5gKsN/Njyo9mCiAEL3NzLvn2y74qFJYsGEgtu8"
    "f/MpH4lCBwVeYnobbFBY2vvHmyF0UGZN3kwAGhR8+eJSRwgXFMYu3vzxVDQQKIz1/vF6MI5w8UCLj7s/DPY4zmkUJqi46oHHIoBBgefgWdZ+j4Ko"
    "oMWtDDI8RII4yo1ZCxgUGenmjy4sKCtOgwiqxcdggqpzWbbgQMHg79+djAQEtUkRgQuq7MSyjQuqzZCBA9UcrvBAmYoWGCgI4P7oKGsIBxAUgogP"
    "HSsfhleAUGCGbDhQViEl8UDZSJBeVHYiGhNULIKmqMYDRfmHkKa4+CO7lA4oKHy6P7DMn7qooPY3AUxQtpTefkf/+xeZKFxQXoT5AXILEdQ2iweA"
    "grJcMM8dGhHURFIfekYhNH3/PLt/c9kT4TgaIiiqsOnlUCWJNZ2EjsdCBMU0h4xmPcAKvAI4UHzdROHwxIeJxf2h0QoxQdEGYZin1PvxkEFlNJYZ"
    "clDARRyYd2dgzU7OFx3Xh/Fex4k5LFro/somMGax+zEelWyBTfZRYUMDgoueMHxBu9CEhhfevxgkE+FG6NUfBTwUbQXEk2CKTLwouQoYtTjX/Ql4"
    "ub+TEM2hKLq+5MvDcdg6nbaz1IvqYalPxjK4ohKf2g78QdCiypUXWZ8sTvQWZ7f2769Ljub9xlZENiMMNhqg/gFgo5i0UVIwNHpotFESGJLhKpUy"
    "wBGd/I+njdMRUUeJI9k51gyEBwg+DUYRToLEnawSCFLOtJI83ewlXjVibbJziz+qETjzdjKYpErh2r4S+5yn5b/kHkzfJ2WgtbOTObCSXK4LfmJQ"
    "pdbEAa9EUr6nwyuaH4Pz+HCz16wNSav9wIqxSx03xEo06mAUI1HPdu+Pg12KwQcm361JMfrlnBhK48IsWtgP1+ZhLd0futf3lzpoOR9+yMJy5LBM"
    "3jMAYopL3X/Wq21TAL1UrJjtqEUCmCpBs0aKgC+1InmQkymL+DaCafF2D4iLx2xeFsKUvQDKWCysg0sewC7VZiQIXqoLKXhSEcClxSkOXZXHenTo"
    "UhIS++hQbatUC2YRxWCiziD9jMepqE0JD3ookBQ4JrSp0k6di2o5YNB5OZiF32QVplZJeRXbahwf1dRdgEmTFV+t7M/3FXsmJTcHbscWuh2Siema"
    "g7MUM2ST4+gwp5Y2dQsHbC2qgul7FqyAn3gyiKdljwGVCpp1iJXnuj0wpB/GlvHb34cuj//agKeBEeTckIRRa0GHIbAS2tDY8vtXkx6XKT4q7Kk+"
    "cPOQTnAcAHpq+xLbkx96RorZecMEJ4N7WmYUYIniwiZJCTGC7Xu5RvakQU+DOkzy2yCVpD7IV/ECLh4VSIhNUV6xEHuzVy3S8mMlxcHuDjACqwI7"
    "+V99KExU/e3+k14xLrh642BzGSAUn3wsXFRx2kIZf6oTEF15PTrSMMPuTxJ5g21DxcmnoB+RViwtSKuJFRUlBAhXKYJq8ITV0bIZDKw+yiAdAkd1"
    "H3h2Gh018mvlWzqaOeDkTauoGNDyR0JU5YodSc3MIDLo6CBY2OL0uvWYMi/K+BA1SI9FrOKIEKvFp7PgyHnF6VHMHBaf3S8uPKZARbVLVIKvqkij"
    "rJVxYH5DwKr7L7pVIwil3cDGbl5nrTq3tb8+6WGG584LStGqDoNuNMcYHj/OFjdgz+C5d05SNPSk98NkFpUPPEtu8cZT1E5GniRUdoYSo0oKov8u"
    "HffWbHE+S0oKJGt/bHB/CQ4ru4Axw9g8FytuSuxbxZUnYOOljAgKLvnWChpkU8g5UPv9ywC0Rp5olXuc3IkhhxDOICER94en4BX2eWaBwUUs+Yjx"
    "bPfXZ/AE1jIgMVVyOtoIzaKyGlFL4NLSJp3+jUU60wfL+z+OWK4TFjMletLVOM5jke0CbTg96mSAjo7G6gr//lrWyP9+b/f+HLn6HFtXBsZqeczM"
    "ybqUHY3DirvptYKkMtCryiSLopKV03qPDLyqxiyhA0vv5rCYq85yJUQ+ZT2sWoFM5uQoWKs6rEQlocN8ygg5xMMqwsDKEXBWgeGwlWV/YBkkxsJZ"
    "RSHQz2FKQ/zmferqszonurOwhOqSgKtYYsguiK6KRltVdWlVd64YZlVadlCs5ymDpROSIm0qYZm1/LNor6xy0FXwgPCwSWEEIkqbo0gtByvlQK6D"
    "7fvJoq9GCUKVlcsTBpVZJCety8jEaJQrUBRkHUjNEdn9UUrMBfTX8QBZHTed7ryqtFDn5qmDPNaThGU9aCERI6HdCQ5UFpcVrRO4CJibwCYT5WRL"
    "ew/n0KLvxVgRWrhMeCiAVmGQ909XqAYyPYpJwIkRy6dg5qVjx1nXTSbtZJFawbD+PyonAQ7nwCxtj4Rb+BJ89v2BF5HCPDdIwb2EJpYp/XXBWdHu"
    "gxdRXMrqlBczEJfVyLWQfMskdR6As2Z7/WqLwhJgspEc8Pz+vRXmDPFgcPe6CYC8CNn6vN0kxnPR+/PLxGADbn7tNwjbGoz+iTWobihskXGz42gI"
    "rBS+pBC6Oj50zUZ0yFa7OcpwPmJuEx17NDYDcERgWZ5swwx4WB+uPaWg0mVSYko4B/YDtyEcRB0K1lzr0P0Ri12PA+iKony7x55ZPNBJ8VtRvDxu"
    "HqBEdiD1fHxAV0P44AjExs+J7ZGs1DRF/ncowWQR4zeE7PqJ6UWmrInQ/nfBxX4SnWQxj+PqJBwx8IOSiWGvpji3TUxu35d4/2QQFebKVpX7udpO"
    "cXRd2UzjsMiGJENEtxtODv1VlZw3QwqPkjHigKBPAg6IM53Jp33yfr0D/s/DZv3ZeS51MZ0OxIR1TSv2lS51e2ZNuh3wRNFhnToG8Tn2GQ4qVYHF"
    "DRA7MyU7DNHYrCcBDis+jLhzIOphN6aSpZwITOzBmhTCaUnNiiZlTYycaq/ghOFilQ/8h/9rMyAacONmRCou1wxFmZJyWLIROexQJ2kgXPhXR5M9"
    "IPcf6KrpnIxKFh9cBwg2raAqtdJBN38sTvTwDaNuspFO2cC6yKJnMEO7tGCJKkULHcAoepRItmsKWTG4eBhGmEuXMz46JC0LrbE/oFfmi0tWZGyF"
    "52oqlQQHOza+qZr94cgp3wkyPz9G7epqSDJ24FVgs+hgBhtz5X1JxFni9jFQa08oy2BB2aps4/rs+yzdTOFFcP3AC7c3HwxsCzy7P7TO9xUofhKN"
    "2p213IZ5sEUr0ldRDuJW3sJdkIMoy8Xyo2oGLY1xGxQvi26Ykr02BAK0uT+/yPnvwbLwt9ISSj0v9oYqBL5V3a2g3Pl+GFczZIQovFt2jfc3uk2I"
    "GwF0ay628gwRWLdOywkyOnekBhFvPwwuUzBCSicS8FauaH74cZaybspriYK8lXLz0Ki5qhkNeGvuvkoFHRn4WaYMzK3VGKAu1B4a3tbqffzIELeq"
    "vSI4IJcF5kW98BB8QdHEkDgh92MQ/1Pzrp3ZcuFuzT1Skb7u9ZMHuxUpMK1/sEwZ9pTOLnQuVunTxLaRySw3kZDzSzeU7F0cBt7WCp2t9pBuvHhj"
    "FnIQpC2H28eEtOVBKNLWFWjdixC6ThiCiDXXCo8Mclt+BWKLy899Yoi3bD2s9z4M95EXSfrW9NEfG+MW+enrC1TeWsvCdv8H49wGMWBNZwTlVycX"
    "sQSO7lLWNDOi0zSuW43txBHZLL7dF+Xt/X9fmeI9uY4knXzv0ZQIwpyiRjgsOC6utXPF3M49JB6u2I7SiLhcryZCjY0Vn42RwZ+fNTUeC9COcpOc"
    "6vQ+dGzu33uE8dHjdfTKpVUZhiS39HkWMxLkJ3UMIhX3r90AaqsxLWRcU1OxkXHde7q62hQNi4tOsgOLK242hgXd6/vZUXNBJKrySvE6Vty69ofB"
    "D+9e5I4n2RiWvqY3Mdl3YzbiPCPgcqM6MkOXCgNRXlkoXb6Lum3Rj8BYtR1idc+BwCbuwRwsJeDU3LyQLvKsMUUxZea3OnX0QUqS8xNmbDxLE3dY"
    "pzrXrbsX1I6i4XWRLjwsrqdanZI4eWZC2u7Nnv35u/rsDaIuuGm4Q3kS+Wt9hhrIOxclq6ggdXUHC7GtuvCotDm6xnTzIwCn+4c/kpmb9P74n/jq"
    "vZWI1VRjpLi//pjyl9sw1rwdwM2HyOFi6n4Y3sSaALCWe4pW5gh9zfnZgEypG8SWOCjEWom5lONJPdAof8DIAWjdqN57521TJ3AVArkCnSuwHvUK"
    "3p6cjOi4Mxe+UQ5ebX64sQxSaC5903GMru/f63ElSG9GJ7J5I1Zxw72g4hXXt6kC8GQdToKLLE9lWZpENhZv8fkyIZO4LVeqoEKRj7qGEi2lGqNX"
    "pkStb8SlOHkNlxMF0yusXhqdl3IM0rtudxYhMIg1GXGsE/uGsXlN55Z9y1eh8u4PPESrN7+4f3+TUXml4rR/d9NQTXB3g33yLiqv8y3C8ppLVWK1"
    "Plx7CisPIPC6We3p0eKTR8Rc1DpCp0DlaucUlJHRT/MEtpWYty58ExCvgxJgg+6q8+6W8y7DYMErETqJbnp7gKkonqfVYhysiWgh8nIkKqs+Jbnx"
    "iDpulSSrq8INnXCqL/DfLEjz+7fXLVVDepSCGoMgovB4iUgE9mMpMFXAkDSb4PGiZlXWcRI9I1VIUCTDvnHUv7Tx3kkivMWMEdC8Ku2OntZm9MKl"
    "NCWOU9hms2SrablHS+1DkmIKsld0K7xgwfCiXGIC58cRYSM9ssf1AiSp6+WYZJw+zQjcXkY4oAPhq4PSLCjSLq5hhP2wIHyjKUJcgdw306UwMpib"
    "gQiIGOQsUWf+cP79G1z6lKyyrbTxus7cJNg/69sg4IYC+mVLH4L61bpF0DD0lQHW9lJ4Vm7CprFnEZt0Tbg+Uhf711KvatSM3F6xRM5QwILZoFtJ"
    "ZKI5u7vfo+5lhgwbs41JfGnL46ZVNTgwl+GVVhYedJPYTHX7vt4iUa4n2JlOak/AMlTSe3xzf3wx0G5jNS1zP0AVNT7eW8H6mmnys17qlgSYVIL3"
    "1+/vP6ELtqrPIhzeRIILmxtFJDLaiAMPoIUhTVHllexNCdQmxUnB+FIXekVgAgVejUImEC1SJnLq13S+E+uYyh+Y/dCp93EI6GEDAxNG0lK3daxC"
    "P7Z53pi3XGGn/Ede8vDK+81up+PeqRCA/zX/As/YkWJssXe6QKIb7t0L5YHFZLzSsGDIip2TmIaFL9WFcd6dc5uS8/HMgVqQIXxG26BRLkiX0xtk"
    "1l4sAwWC7SUaMY1quaZLg9KU+yPz2ASt18vTmj7EfpNGZRU9leGgUrJ8hvXl1i2Iu3i8Nu0s2+SCGf86iiy6i8uUQEEXg3oAwYR/vH8yqJP1IRmy"
    "1Qxn1tHomB4jNjOc5nQEQU5J0LhMxxCfYRXT1Gq2sjtqNtWFblxp5yPSlToqHsxg2sDxlLkZS2kFu6HDgeFT9KWgR2k858Kr8L+Ug9VNKGQBJ1hi"
    "ICDd56JKdUquOeFN25jvACGz9J102TujObxt3g3ytg0682px/0k3sKHVpk+lAcE+VOpJqU5ZM9CWuoIohLTa+ZV0RiSd7Dokd3hZwAjUvA6f/Xdm"
    "Uk1v5Sf/OzMljipXE5SoqQOddVvk+WN4d3D/3lage93GKohETK5AjbtMjA2HBzX3oV2ZWCkuDiliaNcVhgu03yC5DTyZ+OeV+MphVayULzBIsJmH"
    "Jz7GpSkD9WkQGpR9m7S71gJKQPvBpLRUsp80uzTbaJNjXeShKZy7fKK0itPrVRH0p+etEyLvY3JMJU2Cx9M5CaHKfpflQ1oIUKj6Hf76MNkNr3sM"
    "eRnNmKVq8fZ1GImMeRjam6rOqTHN/h2ORokWdo70fqIATSOxnXT8p1ZvAarwzTZcGmIBmNSflXU4pQjvFHjYHFMi6OYKFk47UZjJyomTUur2mmdQ"
    "V91lBBEk9CwhLAliXkowaC9AwKpmNR5Dt/iONqdF7EM9ruU95EWpa1LE9SS2YFA4QtViY2dCzErs3e0PLBd7ZwlwgToFqMHSvFUOqZB8HmL1T6SY"
    "8TsWQ2td0kzpOnPyhI2KYjmDantzm6VduAjAXQ0HJe0NGgdDgz5IHkOAsySF66BPSJuIZm/DNpbqRjzo9qu//0sMPRENCp1/0bH3cHQ3+yg3fj0S"
    "Fzq/vp3fflLI9Ni40LkHt3O37u7N9+RnVg+ChfaHNnJTnXuD3YU724Xe64U7c/nt1UhA6MK9gcKjvtzE3cKDwUgkaD8zsPvyZe7BaG6hNwwB7fes"
    "7I3TCJM/RCBA+2vX/PUOf/6x/2N/FPRz7tFzf/hJfjMDS9VPRYA/w94L98b9qeW9jixQwIJ/1vSIDDpy2R5/fBXI6Y8MHQL0OdeXyQ0PF96s56e7"
    "/UeTsPkA4HPhwQPZcBjweff1tdzLEX+4q5Dpima/3A3Y9Xhu9FnuxnQQ6zn3w7K//kMJ1eg/f5LPruayM7CuwvIkEC3s/vPne8O9pWCe/exGrvdZ"
    "rv/h3uyTsvDOfu+13Ngdf2s4P/QE1hvyLPnA/KH1/MP5o4E7M0vz8exkOvZmZnMv+v3Mlj/cb2+jLLLzbnYIjsifXf5lq7fQ25/v6/UH1/zrL3/Z"
    "6jsQ1RlEgycXPpnJ5lfuHQDfnJt9kBse2X09c2jQZpgt17kMR5ebf5G79iMIDWwv98Nd+ERzaGVwzbgGi3S/bE0XHg7knr/y++fNY8fBac71Pihc"
    "35CvftkaFCrRomHywu2HuZ8W9/qfA83Va0zvEwNodmYc31KrtGYezE1Nwzeo58Zv5Ho3gGNCy6kEl5nHY3r6i49zYxNAz2PDMusj4uHzA5lczwCs"
    "D9UhaRRU/09+ys326VF4yYeBY/Zf9xSmxvIj12DF/q3nhYVB+w08t+5n/utB6yvdO3A4AGaWsNzaaL7vhf/iDuv7X7ZmeGRn4KNjLwPJ8rfu8th7"
    "Czf9m0CvGfhw7/4EfIhyo+a3z/yEYJbz3Qv5oeU8iJHDT9P8T1B/hesPChvXc+NToLf3Zq6BccYVwbcjkzuZzpLgybx45qujYyezNPjr1/3uJ3AW"
    "MPPu9pDf05V/2o1a5dFi7ocFWBQYSPhq7/qPez+u5591+KvTvLQD4ZLhcMGywvP5tW5/FkZe8lcHc70jJSGS97qWwTwAWfzXExUhJKPWIJW+++rV"
    "7vZYYSnjr93Kzd4C4vIaGRcZ/rlHgMElcJFxGHrV70XjnBvL+o8mQpDI7O+wUj8IEdn/4Za/NJDrzxQWbuQ31/NrmRJAyIFHDPox861CPfZH7mm8"
    "49zkWgjvWCuGMMqxNi0utnHhwc3CcsZgG7ODAbyp0I1BVbv4xoXMBHCmDWyMu5yxgY0Ly71APBfYGNwL7VXYwMbodtx+WXgwFAI2xq2rbwywsT/4"
    "Yq9niP00BWq813E/P7rM7GVBG2u/0kAb6yVYgW1huT/XsebiGrMfY3CN9VCCa8wqJJg9CagOK7+Ue/a0cGNAr1Awjf3FJX992F97aAEa+51TheVX"
    "DpJx4f4GcAYoCFhpAMhY2/YoIGPk59X+3Mym7dFZAMb52Y782F0LvTi3PLW3MOigF8Oud189yz9fLkzdcgGMRflMLYcBjEFz5F+MhgCM86OPo8GL"
    "US3fmNbOsItaXOjo9xfv+6uL7HpFIRbzaenvI6CK80uvdl8u5n6cLNzrCCIV4xZfD+Tm3lgQxRB3gOC6EMVaawlEMZ+2A1GMTE4UtyCK9wbXCg8W"
    "IyGKmasiwIlhHFbGNjix1vMGnFizqQIn1sSy8In9Bz9BRBgEJ5aI79VNG5aYpb8kLDErZo4wSkISswrVBNSIxLnph37HLHgmDhQx7rRjNvfodgiK"
    "mELY52EcYngDPs8/n47CIIYveeZIGGJzgmUxiIWzn9/1e54fBYWYhdK8wOx9RPhhcOJyY72hahGzjg5qjgVA7EEYLqxoPcCKtgIAYi//6BqrF1ov"
    "6ZAK0Yc9v+86q9/j4Q7jDkQJAD+tg4/xjIdljbuXeQKepNaVhwUYRrYZ28S/2FoeFVZYixxmTZhg+D0wOihofMbTQeLJAwhzLgazLSbgyc8OgKuz"
    "+/JafmXFk5PkfImJgGZXWK+iQzSbAYd/N5uxHuuVKSC+YFfrIJRglFCSr93sKNCBI3y97zAasCZaeRxg+L/dV3chtveH7/mL4/QtOwmHxwPWS9Ti"
    "tZPpEC95uJ/TBsdAAtbDs3fInGDH6ZUC/3JiDdjH73mMsZ4jixigZbfBE9Pvw1cnhvuLvhktF0MCcO6HxzlXBkEV/0Fe/gs8YPDvmHRk3lkUIdgC"
    "KT1JiF+eJr/9RByWWTTo4cVhQEOaLv/kNTiXrONs96hiXF9zirwvxSo4AwVxmFCkYOmYkL571+dQo3EkwVqfaOiv3cckzdp92CJMutexWhjd5og9"
    "DNzLK8F0ltLqAeheHtn2XyKRe/ko7XEigHu194IZzvWhwv3HrC0CyL17mQzold1Xd/K3t8oC97L9RAV0ew7ONoDby9o5l1kK4vbqRLc+hiByLygK"
    "cGm0H3d04F6I3/Wh046f2CclRHt1F9wrEEv9LcsIBmYzr5nsrEKPCdjL0/Gm/aGNfOdLWBvQDSiR68vsvpnLj00hMVWqgZ+MnvrwaL327BCiQvCv"
    "JQXZYXsKDoszO3sdP+SXB1B9vXqZfzgA3/Iajg7QK6rUTfmCvoa/OV4H9R12nE4GkdcZBU55b2Etv2goHyA78Elu8Hp+c+CfAsMLhxIchY8ERAEZ"
    "9OFAbuQRiHc0SBIom+DKQLPqFfyyNX3SOLy2UVNPaZ/1YCxeZgi0RSRw9tmfDBCvPtPwKBiD9143p0+HHjCCJw3Biyk75nLKUsAS/MEef+Qh+wva"
    "oUJz+HCARZNVrK7UVY6hK36s+6DlYgJHcX73owDn8tDKzSWesFIwOpMM29zdfpMfXTbD5XrHQ40ffCxMkEPg4QK5A1l3267obFBFqLf5Zzf0Pz3O"
    "fmFswO9iXQ+Up824h8O3BcuDfDrSG6GYn9/d3Z7NPe0AlWy9hMEJqwZ45uiAthizv3pTeLYBIcTu9g+Fex25x50UUC0/8lengXaVINrqVCE7ywHj"
    "/htCtc0vdUAgxrkatE33b4HugE/APEF0Vehdyb9ezD/tBrceeNYfoZAL/7nMMS5n48BYAufx335XT6FrG450JzOoH7MrCjuZIb//FjyD2ZGxW8ia"
    "7Jo8fQwhApVCVlQ4cS/fvQAjg/Lgb+1E+r8GBm0p+sPfNv05oAShAXoCkbFI8/IhBQuYWmCNwqfjvxz2eyeQLek4wEz5M/OohrMre9eH92YzwPH4"
    "WEZFe50vWSXvZvsLb9bhyDC1RtYJwmL0CH/4aW9qUcoZKqeH41M+g8/i6BCzOEGkOOa3XvqLj7FEWQGurK0+mNds764kvKz/pgcnVK58GXRZMUrW"
    "GrUeOTK6rB4hPLgTm+s9iW1XezosyGyk5kMfi/ggN5a1XgSuOA7SLCgBKTSriIjzhw/2Okb93nUTRVkrOQLe7G4WfPZM7tFdrAtfG8qtLEgJ2LwJ"
    "OgQcHVDs1oul4GXtYl00uiw/gaw5fOcw4LKcrtLZK6G445rsvhrS3knlALIg2BBn61obSylYbrBMUku2eAbsKWiHXwkr9kBuA1awGe7RNewa6Hls"
    "54h+2epDQXg9mH8p77H+4prv8bBhgdK2p0l3gdhVBT8D+Kmce3aS0LAHryNirGBMVAk+rN/z3O+c4uK/lM4xzB2UV8Asl7xaYGIGu1JzKGTYwtao"
    "339fh06Ytnm8Qkldwx26JnmyULD5lZXdbF9u/AV7bJhP7stIFRTMGDflzS7Dh2D/2FOGHWJKbu0eiyQbuV8X/BVX/XIw198v+TI6gt2X15hN9uYf"
    "gZmGdRUerOd+GMz9sIQONT2JFl9IuyIRVaYH/aiNsRy1nWBXBYy2urD7cgC2yJv7DWK3cvOWZklMLj26rbUrJp2nr2HAS85RIBHKPjtyNJGT25Y4"
    "9Q/02MsApWd4HDBlyBwqebKXGd7r+MHvgX+OAwn3Om4gP41vcYuIib9eDPh9QxglUE8h5tnsiWBesJAb4IgNEDsO5Wa7Crcf2r0sx8Fu3X19DTxE"
    "zffoVxK721UTnesPZB6Pj9taJgXBrYHc/KFTELri8htCaDUaWKyEP9wFNg0oHVisfs6N7/Xj/uubvMLCagYYBdmXqmOFJ1u58evW2wy9p9/jp/yb"
    "A3oL2HE3hNIPBgs8AO07qo3o5uWTg2XlKp62DrbpliYoqidiSe8P9CH1WjomfzC3Now1vOlrmKzoeeav94L20pF0eVxWTnHkbnTgu9aLmoqwupOG"
    "ZTWD6cOJGA6VcM8z5m9/fSh3vU83rIFHujd3M1yYOQmM1oOdiUoWf1Ioraw3wd8PqEUkDgQ3rEmH74E+2pt/BZqUH/4o+KzMgiH+U6YiwvEMqipt"
    "ZkzzdAk0Vt3eZntL/+p4q3jEd25g1/6DUc71UmWOcr2KDKCYgl2nIYOEJpOsIJyVJDQoHegPZVCqLeYGjkb/x8qn2pvxh/v1ZkBdBnfDTn1IGJSa"
    "BQMqrtP9J5YQsWX+6DCoLA1sAdhFgZiU86S8Ksxkg90wXT3KdvyyNQOqHzM/W2tILhoCDqKwDBx+F70WItpHAjetIMpVVxhm2EUxr3tkJ+75I70y"
    "UW55KvdyXHqPrdz1wfiluZnN3Pi637mxB+aVekpYyWBjDvHS3vQPudWnByGX2s/udTwSN4m63MuClqLWC7E1B/jYqvB0JDd3qyxSKXeNwRvonJGj"
    "Gb3ssnildi4DqXH7ps6s63GiUEt3X89x5x0nXO1+hAj0Ur5/xXNFIJfytSfmzgjE0r2527m5N7kbQ7CoSMBSiFp4McAM+ceLJbBKRXFMLetuwGio"
    "Uiwz8D0tyob4PUtlUEq1fdZuUzlUvP83CqRU9VV9ZIRSXWMOjig5Y9CjMy8xAcaj6Es56LDhhHvDvf7cdd3b54KS8t0nTj+CmTR4pHyJ4wQQSf2x"
    "W/7AmI5GFAgoGAe2AxLvSmOAnB2GddlXufu3Dok/alpz9PF2PIHjtSY+CH2UI7hjoI/qZJ01HHoggdsyQYxOJviR0EZLzKgdw7IznhjGKBJ+aovM"
    "gbxKDShju1uSdDlBmFEK+2dzdx/lN16BIstNzvtdwxV2A/xTwEatsnFwZioEzNzOP59WzYr3tIcUiCKweEYJYTD5fOKFqZncjRWsKqnKKSaBt4a5"
    "z+lQkKHBm2MHQIY6TGW+iIYMBS+OKwWFpTvsRqLXhWXFQQgK7+9mBywkLQ5x8ZIQNaKxfzYwnpvZAGvvr3btZvvBssDLWI+3IEFNAdnBBJVOHw0B"
    "yilmz0YCpT4TGwpUljC8lhudBWrq+wcwFpJ+tstf7SvcmYNnYOmFrT7Oy3NVjecLgHv669P6Bhi60ur2HD8cgPHEVonxx2BWPRfQEzNXNAJDQLLu"
    "hvXk6WqhDI5V+wGhroPQaVETrf7zNf/1j6iXhteA1KwrmMrId48WQTvw1RwDyAmHxdh/nt4IDsfEKmxl0QVVnlhwnmkNxclxIeepOcPGuTUdQHNU"
    "jQpMz7f7Zi432KEL8fq6jtJ1slSDxwkk5AV5f/xP6tge6vB7Hu1lnuB9s0cTfk8X3vrr6SgsP87ff5mbx6u6/rWfuNbt4G7iYXRkczeu54dfA8Oj"
    "l6UJiQouMwjRvtQkF19j3GEdDg+mIColZcMJadW4yCu3sDb3MlMQC3DXK+cw7fc0B4r8K3nCIgosrQ9eXEG5Io3LTjjW2+/fsq/42biZnDmWJko1"
    "BZJv8Xrhzjaqm3vj+QcTkukB7/bmrFzGsyAycTfD47lnvZpFsROIrkDwwxoCk0eQ6Tpf2iI+0YFmOgIHU6SR3kGZL42HiUqhp9fvG9JrBUpx/orX"
    "Eca9DDOVBXtpcfzE7N54n0rdJtRW5m7pplIX5dLuOPX+HeuXqlIq4XJmGqQAxvsPStsolEssUnCtRLWg6gK6ZP74uLiFzn6YRoXx/gDj2Zc1Zcly"
    "Q0hep5Php/i0/YE3qAUszYTHDuejitSiTQw2JUcuPC1uj3rhw4UkncoECmNLpBXs5WaH/AF8GFTQ7psF7bjKioa7QAkKGCV8pDOze51SJVTwkyDJ"
    "KkcqvfTzvbwcbjwRIbRBJgsDd8V+sRngTkSIuXkpCvoAx2DlFGkK0ET1PNMokkYJjL5GNrWwJIG3+fikk2O1C+TSf/4YGd48piL3EGKk1mbcWsqy"
    "yBdEuAsERyZW4yEUSqROnrAisDen1QpvZW96eW+qW2sQv6sH81vjL3Zfv+EReGCF88jmIoTziLpSsn44k6PdlZiF1DzWCuE0gfg2+/FbSmg1sCPu"
    "iGyBrTjEzx0qrPbzqXAnPptjVOwUFnOszloEzKXWnPrYMHm5OC6HoDAbse+JFQkBaWCB7tHi7qttae23VK7krlhouQW4dwJ1wMtrWCtnnANQS+Tb"
    "qVsCg3KT5F4ndt/cmfV7ergxJvCknGsIZBGCwDuFBVP9svMpmIUpI49yixmnN5CKaL+CFQ7C98CcLigICtawvdUqKpmq1iHgEwUXgcpWSFQiGBOV"
    "WOKeLsTpHlqmVqCXHJPva8O6Q9fugi+TPQTe2321yOpeF1aZxoG7b9bYEEUHgDbQ4aQzVvElXmbT6+VMMvaEDkjjhjDN1FZ+9BZ34SNZ+66jQ7n+"
    "Q+H6pn4XvboVp3RrwEaooCJJkVlJilA26RqMYxMApjaNMvidSnnyyxht9zzTl42wODO77A9l/AVsZGclA+5Sflu4z4VC/EiyHt2gwEYdU34dN/NP"
    "77GXiRV/i7NRwSIdr+sKOudFsGZy/wnmJntfIUuA6qduaBZrdUiD/tAGCBL20VPZmW5OlKw8I60wAXiPQUTyS6/2phYx/T3zJjc8o3Zig8xgax+5"
    "hJT0U4qp55kN0cMLx+HnrudHHwtHM5v3z7Og6HudnOrKLU9Rph15THBsaPAgj1kPY04P6ITOgUp4m8vjO5nBwr1r+v449nIqJebgFbCOWX0qOShS"
    "oYWfRuS6Afgl+qYZ9VKhR6qS+ugZgsQMv9btjdJYCta0dwJoDWuw4RFgDeir9z4AEutX6DKnam+kr8ChypMDVBJnsKRuAw7mLCAwA/h5WrSYbSLb"
    "RSLavLl0C9Tg0EbEwkLJ0UUHrW5Z0+mBokrI5iV36bxRAwQlFy4tAdDX/DQfa9snwReINyXZIKBmwZA7dKrxmccUOofkROsRLkrqJzXJUCcR1YBJ"
    "IKjJL6/627fBhbJ7bixsBFS16oouCAC8lB97hq58Xy96JD/2AssgI5QuF8HrYPBgeOTWra7cxH2kAb1uLK2V0WZeDrNPFGQV37FBTRBCOqBaJ3rz"
    "7OLzcaFLbNkufOb6UG58HXPuqxN08KOietXr2tHGC4PrC7BwsdFkxO0bnMbEqDNmTsKayuQPqJAIbkGrGop1n6k7YF2st6lD39wklPiEdad1aQTP"
    "gRgi9wgczJcQwCCvWFPoNhr4kOtQ+ew2NTF0eprRnLsSvdfFBeGuV/IBeHpLCc4YA6O+4sqTudk5n4X1iQoLo5MxFgF3N8tFUYg/yFpyZKS7dLA5"
    "R13WBLuyu/1UdTfcY1NGvg04N/XNFvrdpzHwEmLeV3iDIh0Jf3c+3oAxBwQeV2INNgTehXh9LEkflUW/+wYeqo810IXx5jR8XROjdtZYQ0siEgTv"
    "r9K+FUs2JyJB8M7Tn14KL7SHQfA+TSdbEl6sNVYfAYH3ZawRX0MMtviVeF0UCp56pDleG2uKXY2GwDufqEtcpX3UxxpjTRYEHv7399gMXgoF76Kh"
    "pkE/s5XgBdl4FBbemaZk4pLXFkMyJjBj3XCFj8DGw/sq3mB9EwGK9026Np3ELdKdgmjGu0gDNMaw7ticaAki4wFXpOviV2mGKE3zTTyZqlELxQZL"
    "3D4vKOAJfgOMEEvQPPBKKZy88wgnVRNDmgM/pRvKYuWdjzelaHEekuhK4mrIkVGHXB/HJxJHA8wjAfBazHnKvUtk8KbgrsrC5rUkamCkq7GaRJP3"
    "STzZTEuti19KXAWxqY/97kDsvHo48kY4G/5MM4hZWuIAID1eAYpFUwtK9aHx9Ky51PSJJHWVNsZqYlIWhEcqhtWzB1Srwy74ZHPsFBC9/lLs6snA"
    "6zUnakGbRE13CT6oI0GJI1FaIl4/QZC98DqsFRAR1VioiRrxonGsEQ4c1LezoEpg9ppZd6P+oilieHngSqzOeuioWHvWkIFj8z5pSeA29Ms18FQ9"
    "vAs67XeHBNsDhgdbciV9yqvFqXAvzhvJeH26JhFrOA7OHugccOpI56gXSURPu3OeANheC5AIzkJPpwiXBL67mk6c9phw+rzVGCJo8BKr1pPA3rvo"
    "TnUpfikGr9PfQND6S8CjNbGmBDFkLRwfLjtd35iuqy4Ju3f+s3N//uzCmb+cOef9+cyfz3x5dOg9x3jCxKRiLsUSLZoUiXq0WaJ1kumGywmzQiBO"
    "oroSBD78oDmWEAZtTqYa0ZI0otEvCcKHsxB5YuwaNAPhroLxUQdzACQfkx38hsYU3nysjzddhWdJCZAJgQOu1sB84CKx71MCmO9cqv5SqolpYgkh"
    "jqjcBRuh7wK4eGAFLa+sLEjfp+mWRBMZ12QDjAeEaI7VlcDpCz7rYPXxnkET1aXBvCnMvou4YI3a97dYCLTvoqtWwtB9FwPGzEXwY5fXIPidFW5W"
    "AH7fNrSkky6E30U6FhvC7wKc7iULwe/TRJ1ykC0Mv7MJZf5tBL+zRmBdAD+9bvW1QfE7DwtsYH9OePQCcKWF3YeoZw5y3zcysxWcwp/xWhe374w4"
    "UwLbJ6MIaN9f4w2J5mAm4k+iGdyUy5eJxnQLxwcM1fdFvNkC6YP/xhyIPuGLADrfRSfSiILos/xKZmxg//QlctMtoL6LYEauEPc2kaW0IPsuxmrp"
    "dA1i3+dnPV6shdV3HgVQmCuA1cf/bI5xcOLg9Z0FwW9OkL1G/zMau49d+EsYpYSg+z4T168ZbSgJeAi6Tz2ivOAI7L7zcRJz1HttcD5X9bFoBL/z"
    "5NjzrhWC31fpupiL3/dlnEIAA+D3lRy7BsE5izKI5KcpFIDfN6A1WyLx+3jvYfi+s6K3bfS+P6M/4oD3KV5V2H3g5l9KoyW2sPv4vwHoPjj7RNLT"
    "Z2qFRShHKgiKhvAzsYSj0KOh/M5rrQ1D1jNBNZ7fxThyTkuaztUA+n0K78RZ67p4fhfNFwFEP/gGpC2NSGf1l9IiLSFov7MJXAEyQhS03wU2caWw"
    "/ZTv4+lvjwLsx7G4fj4iLDkiyF8zSbxb5fgLxl5/ZwV2RGw/ZD5PUMdE41pLOgjXj3Q9foPeR12sUki/etTKx4PzI2WAT9bbyZqEVwsM0CITAPPH"
    "k7EjoPkBp13F/17iVNERsfxaSAYbjQyCPKHVxf9eJXXNoTK+pf1LfPVjYPtRigUogp5ai5oXhouMsvhrzBMkrwL9VXgOogRxF4/5u+oKgPyUXfdq"
    "rM3XxMWXVXmIMKBfmHJlgf1oePyoDnTVkeD8+FEnELUzGuhX1ZOHdkRMP3jFHjyJMCyazuhLKkVhHLxKEf74ORzH8JA8y758LT95UrB+Kg8IW2mM"
    "2bs67cFJ15Bu5mFraDUUNMqZx9gRQB/V9npODOEP7J2sTpv7KA18WjN4Y0yHUZFrPQzaHylj3iEyTzAQMzx0HKQ/GC/WCFLVIDllcHcamiV5y/mN"
    "FjTINeCx8lJ0wjOA9vdFnJzJRlH5tNow5B9ZB+NvRuL9BUYKHG0Y+u8i/iMJ/3AD2ADy3xcpvM9dl6ZMc2ncvwttEMa1eGkMYLSHaUP/qb8TQei/"
    "L9T5OOsNwv+h/+fhKujbo6P/sRuICtTx4SnlnrS4xLFmDW2x6uNj/fFGbfUDLh9MHWRQN52AHiB+CRxaH7mKw8P+hRfSEseF1CTAp20RbdUIH4EC"
    "bECln4RFoNVycj7Vx4L/s2cnJVBltDwbAXmZ5Ouq5V99BAhApWow81QLyruyw/inwAFGzijLD87JwmgfpDv/4eY+JA6gHKp+gA/vAPQ/zkPrE9d2"
    "7MTQ/8zBhkYxmXdKBVsWSLNFUE+eNBggJT3EXhgVVR+HBYMKStjXadmZOO2JX8f/1Iq3ckxANsDuc63p2nSN7ZB+FDxANSKt2SR9Jc2t8vYcOhgO"
    "lxFBdaQjQGcqhQEM5LTZrtg1ASR/pTiA59OI3oXv09OOkmSNoR8+Ihag0r81CZ39l7XWUYYzGW+qjQUmtgY4MhSgergmAaSKJcwLlSAAJsN23c4v"
    "/oYgAHWyhz67BAxK6xXvErUJTp/gkkVTMtVwBc6qGdQc7p7S4RRmNYGQwPgUMMOqkdVBqmEkZJGaRDqZBhPRGMM0vjFAoTexEgIC8/ckOvoi9lG6"
    "QtL5zfEa8MWTCbbX/xqQgBc4RemeRlXwKGqIdJh+YLol4DyasczXlKD6DdeT+HxMyJZuwlwyyxLsKVYFmr9GHIJkmg8SDqSOmxiwOiNipyoleFzY"
    "v5CuT4AgQDCQplPmKE2Sq+qdZPwy3h4XZ+roGIHqeVNvaUhfJXG9SrUB81Y5jMC/Kt0S6e6VxAgUz9/EzUSb8miB6qtvz1389gvv02+/uPi5d/bz"
    "85+d+/Yvnx8ZLjBqUHnpr2e+PHPO++LrLz/74gLP9M2ZL779/AgYgfbzasXehc/+8vm5P//5DLz7xdf2q2fPfPP5cWAC1QswxZm/nPnrGfsVe5sX"
    "Pz975gubgocFCvySWm5QXYD1TDcDx1rVbfN2M9jiugSld5RJPhg18GKosBiNHciVxcBzFSMIBlJlwo4qY2a5NI0gx3XGsakcSpCdhjrQFKVkxDHQ"
    "CQxGE78SmKDWABLIiQYI5jf1NKEUFUzGz+juBUvPNUq5O9ZwPEhBOw8mfp/7Vgm37sSwBEsvoOKoqjyGIGd35U32gOAExeyU7M6/GEqzBiONw2EJ"
    "cqWyOYWuCLaGXWJrpYtI5vjVOycNKXg+cRUsUTLekrgSI2sbFwnBJbQqfpRd1iUozEvYUkp+uXwP2ohq6dW/OsbgBXTi+BhBEaRlK0nui2rBcq4w"
    "U7V3IQG+G6+YvItWhHOgN9HxiNVQqufv4Lqhc4fZ0aQ6ZtV8Y7lxNTFMiFImsfq3iT0oLKj0TxJ7z0pVYZS4wMHFTCwbVbFzBMt0/3hfcZTIDjUm"
    "c7E3pxb+VydryDPmeio+A7IQr0tbwV4VlmRidWl03OvIz8NbWNXHxBl0o0uRuUZbNoRhtMvomrETgRssk/MInICb6EDCY0AjfTu/JfDBQLogtEj9"
    "fWCZyQTySgM3gCsOvBS7HDOnRwu23pclSxVN3jTNfrG03Vwnqw7VmE4OcTAqnxMy9hFJzeY49bTL+m05Y3FRBqw83iC7SM0HGMGPBDeoDyVquEvo"
    "svJamuMo2kElckIAg6U9jEqWeVLAgs4gpmUf9WCFmu+kcAUr4segGgqsPaCISuIKSlbPfIelPkyXSM3oXxtg8KDkcdj+knZSSdBTwWYDaaKPYOim"
    "dIxqTzrpiIkS8IDoTgJuTbO4U2NxFHJwc+L5h4REb/BXgBW8CHyZvIrfa1EIan89A/pmzTFLt5+m95RmRbAcqwEW7ArV7j4GqCAfmwp09fGFkvin"
    "YauS7+ZBqfyfrktgwKglUg9cCZDgF0gEMJoN1L+LChZzgM0JpUHKwgdeiFNGW18zwDV4UmcuDR7YgrlY9OvoZkfQWSqNGXhBLUudnLTIVQIVSO9q"
    "d7Sey8Vy/HauIgoukP1g7hdPt5gugAisQLvzWt1Yi8AMRIZ07ogFUQOB82r4hgV+EYkbqFIZ8C+zpCjowBZ9FQsbtJN0sS0aPJD1hGRHlBjIRbdS"
    "GIJn6B/NrhUOI2UReKCpVQZhBHUP1UdCEbRL1TR+eFSnSQmHl7AHKNYkw2qSgNXEw5GIkLsJXUzBs/AfoCRfE/vEQAr+7mQABdUQTLdG7haNNZwy"
    "txrYNWKdX6XOlKqyqeZDAgqqZ5NxiuIlmeTU1gNXxSLABS8woB9+Rt8eA1zQGqrEFSHrdV5K4KrQkRAGjzwt1s1/dwyUwT+Fhk1wNw/VCPXLNaDD"
    "6/AahlP0PTbMIPIMjFULb1fWYfBPxRb8L1fP2GldMkweWColCSrJEHXX57RnJbfMfS0Ms2AdwfM3ieIK0Abl4rO1SHV37gC0QWaywA5LgA1+lmxu"
    "aaIUBYRK6aY0hl7g1lV7X9SBB4lpMKoCWPBM5L2BLYuza0uNlNJbib1T1NBsIw1WmeKCjTRY7eAMfmUS0A7WoIoSLLhBN9AG214D/4uXoao9vugD"
    "Juz3mJ/D9sJmiinwhZpEPTY8gaVIU6ongDko1yUoXLK7ngJog5+ih+gCDWJGqqGN/GGlxwnUTvnk8l2QwA7c4Jcozg2Gnp9wGERsRCMgtZFFyOsC"
    "DvrdKQdskGDXTnESkUbBG2jeGdw3+C7pZJLcDD0H+kanNMbgn1QmiFk7GEJC5EQRWUw6Hz6RyS4lWLG4VX+XgrRMAzT4lVrLH//Twz6lJvSqmuB9"
    "8Erq8KxOS7xBUkcxDDquWAOhjjW8PybnYjAHqTfWkI6WTw6xyoX/na9BExfYJ1RtoQ1+I/ZRZ29UxuSUizcYei7UkQuxETBjg3GM4iJh5uozZnq9"
    "ryJvOiZBmaaxDiRXCG3wQZ7bThqrRcqceCEA72vYCciWeAs1ODXqS4kWEuFZ7ZGD2AavhcrlxGobkPALM4HKKGGl4QpYkwgoQlJ3mIKIWefDwkj2"
    "rjQ0IagfPRNQAyQ8XZcmc8b5+OpIdMLzZTjRwim8GEeuYKRCbpvDW74t6cZqA1fodMK6YIXmK+/fTzkxdkK1vYIFqUs3V3v/ASLpVMzr8SqECXgV"
    "kGGgli8KLlQh4rddBlC6tdr7wymbL8lUVFtghqHz1SzE50xj/JVJF0OHttHOL0ip0ehFC9xQ2SkOl9C5ZNG1mqOZV6pUthDZhrr/yGcm83g51sY3"
    "QyG6q6nHM9TZimrvS7o/weiG1QZ/rTZNBSdtOQTi8LRNB5WdrQGXJymlsYBGqw4CHl4kmWY7VMV0UpXRgMmJUI9a8jjWsnYH+8D7/ZZKUmCIVCLC"
    "3KslMEGLeyXdQNS0PtevSbq1OhoQUWtd6X+h4VCVyE0bs2K+n1ttgSL+WWbVezeVjZhpnrH3GNB+GujB5OdE6Kj4jGdUbWElYu97CCnxrDqBy66l"
    "ci1PMLNpFqUMgV67ZuxqFzDxUzFpZGm1xnKax7H4R3qvUS491BBhW2KSI1Puo5ywawOqbbBEo+FQwuoNmArugEholumpq9OiTjg3R+AEtXy2XLKX"
    "G6u6MUC8TiJdE1U0OaVhP81tQ9XRiIncte7cvz/thfPNSr45zDRSTpguRmCJ8wLlGR2I1qoo1tSEuZpWXQlUon1jX13gw4tXQOOE3V5uMuDYdQzC"
    "gxewwGFupEOvKll1vMDRganyRuU9q0OXBS+YsYOZ7+Y0nKe6GailhY7ZNH2qlUdeqEHTK200cjtW1dMbYr/H/+F5Y9ypBl7kpdgl2oRzeaQ6jJUj"
    "q5YbTm5ZVnUtJpDXKU102moaqldWy+TrYJXplvA9L6yx16BYkt6jzaqsSnUIP/HjaoDoRg3qB2gp2a2BN56TBgKCC72UdGRAHWoKQKluiTWq54Bs"
    "wuWsb2MoYS3pan0J1JZop3siXFxP0OrEb4DX61WYg5d/E2zo+GIhzlASmYh1DyiF1piuayr5ofCDCc30UlfodK8+n12ojK80GXxdmkvrrBUIi9aD"
    "Nb2aNPcUNftUR6IAMFNriZEuWGORBIdCrdBqxtQNnOqShxJzQbTgXlK5/o+LdSojjpwq/zeMf3GaYLtqCJXMmlK9AEYj0WweqQ5BMVakO6PZJdhs"
    "wxYh0HJD0ToXckoV01mJY5I0YOeN43Mp1lxFj1VUdq8OQ5DRKbJNLSltjgai8q4tR1dTzbY7B6FME1apLFUbC7fvlaLd713FJUTj84cAFD0XqoFo"
    "I0WDV7sIGKJA5UY0SFBa5fj+NzrDUlI4XbrUZmjCL1hBEPsbNutEsLwcjyotVFcCn9aIEHNJHR+o23KaYs1xik+oX1SMp5S7cD/pOuYWF1hKXBBw"
    "2h2gNuAQ1uduj1X4si5dDbJu7NaI1HOTmKfbsCisvpQGoiWdS7G8RnPk2FwPjwvd6xh5wnEJjM5x12wyqdx5JIU+708OghHHNsLWTm+4yv2oyzzR"
    "l14MKButrDoaNI9iOWonp13VJGJiUinqY7wtjSdhqR7yPgLCxLIiCt7oW0RwbKyzEBzPp+qak4lo6MZUTWOiOV37cw+1TBrkxsamWGtNe7yBoDLK"
    "ojeei11pamuFBcU9cFvebrW1pryEl25q/7lHDxCGcDzbnoiDi5D03s60gppO/mOjtQySY9xLw8AtyVQrvCKPupiOZ1Ot/9gADUmftje0RSA7fh9r"
    "TMQvt/881ZKC5baBz0JfRAA8fkPfeFzSSySiAR6/a7v0jw0IBJva41fqYK94DBbK42d1VFtpKwXyyJTXdy/TjnZ9O41EiSdLYDx+TVeapWDSSn2h"
    "Nrojfh0N6/j2RRNQ6W1nqgRzwl4uX21ta5HzbEy1tCZAfbXH33aH4B1Tl6+m6IDjJTTU99S1CpzejvSOe+14E7st7LK+7Yi97b6Md3mQ25tq+Hwj"
    "MR6/rY0BB+CcKBBt8Eoy1cC4QaWhHlPtbcD+vKOmVDtwTHM7ZguCftV55o6frwtnpI+G+fhdvKnt76DLLoMtaKRDhg1BqJIE0rfAnyAcbztlxzFn"
    "y2UBIC9hIvITLCQ2t7cpZXMw7GP7lVRNQ+rtDOyqXZYDhNPRCaOQloN9pHmF2J+kGnFXh8R95Flh8redoGaA9G2GAClQFu3exdZUoh6OsonYqb5i"
    "AEgZGQ+2PQWkedvpNbPigklOeTWpmlith2v+eepkgCDxDTrcFqFlGidPw/+3xt5uNSRwb6AEa0C5ve3+uFiQEUtx16GGakx5zW1MzXY4o/ZYc6oV"
    "XJvDA0JqkxC3ZkIF77GuaE2kULUAE/48dQIokc4ccfuQU+aU494nxKB6nFatFA+LF5m63B5PkiWMn8L7ZcCc9bArUPg0v/M2bDnW3PLzVKP65oj4"
    "kV9fil9uQNqxFbzM1JUxTutVnBCGJIzd3oCWDx535wR/lsjY3srKixT2FRDNhhgYU2zQRr5Jq1FPCEfyU5wSFwV2Gs4ZNYyaEPUkTXmK/tMGyyVz"
    "83MPqAswuOgh090eGDJWGlbyu8+++dv/+vyLM3/66xnv3OeffXv2zLkzR4eWZJPd5rUmfu55u4VLiYkhvhSrbWmDlSXr0kBPvN8DxHPWdyCgZJIf"
    "gMFavdY2OA3U0u2xJObh4iUhJdFgvZ25nACRBhLhW/TwwWCS51CcYk3xWji2JjxueAPnSvOLrWC+EgZN8ss04UKVwJL8EjyuS222hLZ5aHXIz4qH"
    "sCS/hP/EtINInkVZMMmvm9roSyBNczuQ98o/NnAGebSdZogClrxQ6mEDL3mOJSKugCXPEfUYVvIigc+4uJLwvVE9YVTJT42tdAEl//rzVHtb0gBK"
    "aj/slIKUPJty8ST/BFzvtTSh1xKzUSXPk59rwUoS8WMuqOT3zsEGsCXPK6cuRV+5+JKwwUbzfdwBmPxeXAkCvlEYk98Th1ook+frEsmEAzP5vfL7"
    "rCj7O9A8qXo1mIU2+YX4c4I2iaMZtEn4TzDVckFMW5uybG66SS9PMCe/S8TrkuwO1WGyywKg/LaV0bDORjFQAIWSNUEJAEpkqno0Winb6bWwJ8+n"
    "0DPGOMRGnWxrSb/tdGEnUbWyjcd2LWS8NheE8rMr7fg3fl8KhrIdHdEQDuXXMNhldssxgGkvBUTJphQ8qdaUOKnRcJRAfPKXS4JRKj89Aozyf8FZ"
    "0dVz8MxbUnA6nWlaVDLWLtzvIFNejGGIF2N6WOiUEJCARmmhoMmCqPwTOgx44AakEmXLAan8Xo4rZUFUforeak0kRqXK/Fvhl4Kp/J4tQsqGqSSZ"
    "ajWxkoGrRGZPWXCVsLAWC6mSRAk7YNGiwkd1JJAObuV58AaYuE2pOo56VUurHetFA1f+Kdp4RANXfgORU4qjZ2Mifp6y4Su/A43T3lbP+tTAV34f"
    "k49TIQBLDDiblJFwESxhPhUvpKKwK531ROJXguynIMqQASIxLM/FwApNobvutaqwra0WhOJYmJbnJcyKs9ygY6Bejh0RzRJ5PYGHSQouUKiiyBJc"
    "pDqVGzkitiXhG/Ig+PX3JnSsHOHSBLT4dUPsyttO+DuerBTqstUYhuMBXrLGUSEvBQ2tqdq4uFRt9kRHQLzEoCTWlG6maBb+XUsG/qjIlyTFbVqM"
    "wc9B5xLJjywkJE3TO+0fDfFS5ZxgWBAIjKV5XhozZYeT6OO1NEDEzg+g9JDDK0mJ9OFAL+2YAzOH7VdiNe0xiiIxZcFJmcvgckdCXza6CtBraPLK"
    "Ql8mPHCM0K7LY4fHvtQOYEpyOlXCZHZi5+jQl4EpZOiU9oExKkMjkz4C5iXLZbt+sJUyFZiGTZ8Y3iVZO0kzQfzHpv00uLJx0iRxToumVaSAEgpE"
    "bG3AmreTobKt60kBXkrOtt1rISeijSlt5q1PnAaBS8KyWPQa0aXkxKEmHwiktbSK4S6/d9icOUcPBKxDoaOJGY+Je2kna3AAigQSMS9BA1yRf7Vi"
    "mJbAALMhkbY35r19Kc5DKzBcGA0TXVxjHWjpsTAaJvovOjGnXOK2UriY7piS04qGxBQvK8afJpvaGtnHDQJitrbVon6PlYXE/A70eAP4WTWpljb0"
    "IC/HbXc3jI0JQqj8SRcgkw6w0S2oBPExKaxrj7c2gN/SxGWK44Bkymk1pnRmrMEOPvBKU4rFTQkWnDpoEPL5vfZL4AXFKON1JXUSyJmS/bBpUI/6"
    "tiXI3VVesgUEETyjGOaAkT9SNZcSqabLJ4WdGToMzYitbVewYYtrQGA4wSlDGLGm1GXMfrS0chY6ZiXIgJS1vHZJihwdT7NRUkhanVQZm2FKBNYQ"
    "QKx2+cL28D4GumYrTtUOB3E50ZxM4DnG6i5baTZ1WKicmYHkzCgK+B+CsSmbCM5ZUxdT2VROWbf+2iCbTTVt5pFGSZIcgLOpuCWhOYDMKHmsJwO0"
    "WW4USuqLbcYqjXX8AR75CBibQAhKU2uLRNnFGGamEBuqIUmlNO33gfQoVyZ2GsIOTCi32elsMCnqAVu9Hw6BE84w8CQ815CghGdN6mOicEqhAOMC"
    "NbjaRTBJf1rcx7cvPQp34BDrU5fhRSyEJcw8dcD8R4fmbIXTMT6aVA+0XYuoHVQM02mlH1ErAMn5PVY5x8Xo/P5SQlXtSdWjj22MgK3yxUw2wuG2"
    "YkIqBmrkxNA6KZvd2lYfu0Imubkx/raTbfahwDutXG2b2FjL5rHr9htC8MT8F+y+rRXCyzZaKuq+9tY28MjjsM40tqmiw+K1Njf+Y6OuAf6C9YFK"
    "oBJv6lK8tp52Dp9fjuE7qCBS1d5Xqbdb4C7im+gdNbW3gT5oaatLwuEDr8BcV4DPWlXCKcZOy99BzWC9GwhUH+NeFlUJb+fxqcrT0AIqB/WVVjBU"
    "FeTFxBGIM4EPcnnlXwfeEw+rTZ1WnE+rKnBY5L3YKR0gcay5IS7JmRQlBvHE+BgxU9YCvhZuoxZRDFthH7WJKjTflGEAVZaINYng6PIbhcSqeKVY"
    "AD8F6rc2t7c1t8AJANvCUtpISFJ0hpizBv15PExPPGotvSkt3Dg+r/JtN/0yCuhHYIbKED4dFWh5LXHx2A0flkT7VEGNqJh4BTifZ74895n33d++"
    "OvPnM+c+P+Od/fri3/70/c/d8NDZr7/7+uw/bnznXTj/2duOc59/fe6zI6N/6iH+5qlZ/4az/uPGn82UfzNT4s/sfH3xu88/++bs9/jS+W++/+zT"
    "zz/7s/c9/O83vNIz5/72p78cAyTUbAvmJXDQb85+a730/XGwQS/+7csvvvb4Ndjs12+nf76Gr537/DPvkMQ4AmDoF6CTa9E2NKWSdlcD1j+pYU/n"
    "v81Q7RWAhX7NSVRTK47GCv0yjTzoPlYxVKikGYGHJbEobXuclVSel5eCgLamvfooUKEsvDrX1pJuidV6b7cw+UPKJuwNgPxdSUcYhF8JPzSoaag0"
    "Z/LDevh2e3SwlG9fwlZrm9tVHqtNFANqXmzc+blHldqOARvaSmFNmqGFlDOu3dRTB3meJ4YeevA6IsZqPxyAqE6Wt4tJA2dYmj9K3kr5XsVPXmO4"
    "anco4NCzqWQarTn1GKbb08wVlMmJVaFJugRCjf/wVH8IOj64V/Bktf9J3uHJ4ol+3Zy6hFm59vhlyqCIHYNFvd3CtBovu02lfzBqo6ybJGLhORNQ"
    "taIrS9EmCAcuOv7rA4uebUpfUanZ5red2IQMGqeGdQGeZhsnUlWdKxkzHFftXUzhRlPqoMkZBDeRhqsSFzOWpJ9+UrlHSa2YoYVUqH/wXVWlxIgd"
    "tRe4VVtahyV+vv4bhSHlFhEiLIpG2pTC0HGuQRUVqyFthbd94V+WYKvMZrw+rfuvTOuVdwEj34a4UXPxsOOvco8gS23NSTQqtdwXUeNEuVUcTb+d"
    "AYFoSFxuaYWZEJIIo4BYA7yWPi4Q6eVAeti0vV3GVeJe6xMprJ7YoXaV5fa2qeoce8cngkxaZoRGiCxqqUhJwhrXueU/JdBWSqIordNEvyV00nZu"
    "He4pvUzricBSW7FoJ1cbYkiF9rYW1PztvFbnRVmvrnTGzYtq7WgxrZ7XQL8ob+NE8Um5bQlZ7g+c2ZLBqizXQucDKX2Oh67WXRVtFsuDklIKSe88"
    "coCPhEiqc8ZRw3FxS8l5Q+LtVkSp7iQgSW23pV3rt0S83nFd1FAWB/1aAKUpaeNpO5JqPEmk0qaaSNZspgXgNSAZsIr1E1CppIIK25ty0KXEo2ag"
    "qHf/1fFLLx46MY931SL6upWdkniO3CE4mjZpHYATCzjvVIvmThPc9BXqQ2uPNaW9ptQl7N6/kqr2VJk9XUv+EooUkqGKLpC1kousE+GO1kAdUJoo"
    "HLJECN+vCXx6lhJueMMNbxdhYM2yhalrq/GabQ0amVijelTP3MoV4ct2x1ttAudua5F+UBiJm7mx2oBdgfhZjZdujV35eepjwaN+fZRg/7SXbKUp"
    "kvy04jK5rcCzth8SLfUMyDReWgO6xLHB4O8JKe+gPsOsZDOlMQ4CTa1Fs9+agtOhxhZy2HpAg5aFTYWACdscSQ5MmxUZY27NLAmc+nlDA4G61srL"
    "+PlleqdC6FTy4mrksMkPdbI2UaCp4rW3xmtAv1/RPSOxaNxUPVxM3xONgE1l9m2z714GgVO5O43irnYGT01Hoqdiwjfe0gYmFMazFxeFoNooVx8v"
    "U1JH2udj2rxHQam2qiOlAzI3S51c0YGwqkgP25U4Eq5q08cEVpUWtBKYqlbTGw3MwTFocaAG10ekn4JHR53iNrMGQVWx7BeTPsKPCqqKKTMaA4wR"
    "X+mJi2unDU+VPkjYJw4ROyKuqg5S0WrZF6+izv7jY6o2WPdY2uQKXQjZ1L1Kd1w81QqnJB/4RJFUW9tIq5n3UiDjpINODkA14WH7fLvX3IY3atP/"
    "g0FUA8rEjirVZAk7V9IezqmcUi0IDKCqClQpaqeqjzW3t6Hz0JpoQjuKJhP/Se4d/rQfzxejrGclSKpWI6N5PPLC6QHQqsRxlSGr4t0CrNdRkbfN"
    "gKo2JGq9mtZ0sinVgiuw8NzQPyQTAnS7go810K1YlHbVuSvjfGcDrOqKTGl41e+4gtfGFHQQVttdcFW1BmxPxLMwqcJq71zisjkGbBuN1bG3h855"
    "Y4rLivFIcFXbzVddhs490QisVQISQDe0NoS4al+PV3qeQFetYkxMV9eBZL+PuYCrb6fBr3m7hWkVuymanvQ+oYRoc7t1GD/3YDspxgFU3ykBv6pa"
    "ZjBooHP6EqlJF8gxf44T/jylQlqay6Cwfk1JLpUpMGFyqjl1CVhRoa5Kl2ZroEWDCtMGaQFsQgB69Tt4uB1xV8G9TSa85vZ4M94+BuLHsVu5vTWF"
    "4IdkWTEGrEUJZi5tTCZcwNXv2vCk29mfjku+0GFQutuMTcOMP4A8xacUwl1VV53k2hZek7NDigD6qtMWHv1Gtcdyx4yZTDXKrW/emKgNiHCph1YS"
    "ownqGCA3g9FXY0HoVbzomq6JKT0hTQPIEvq2WbV3AWcDeW9tw+hBhkwlG2JB2NUzDWkSnJTLyJZwxLy0unYUcwBYv8OxE3y1gxxn2mZrJPoqxLPJ"
    "KPbG42gtC756PkXJGdLAPCGtizpfJF8XLwHBajfLNjj3QNssCNZzscsJ0C+g4oitgV8uYRtvfZIELYDD2i5XsAQGJozGqjq0EY8V3eE2QWLlJuvL"
    "CT2CpPDlFl09AbS2YpNDPEmdNW9n6tAARbS7KaRWFyVC6qisNVUlBZT2pTbkFGr8whZhKqp4eNlbcj64yDQhtrZa569W2YbnT2zWYF/6q7fRXIMM"
    "KeyCHUmOMNBzIPKtsVrmR51xgU2GFLAF6noWtBZpB5WFAV+mvVTtsUpSrkBGJHb67/iMhS3BdS34LI31ryuUyUnK9QGMEvEovk9dgrg7DPIqbTot"
    "sSS61hri1SacSnCTXUrVoONdx3LjwLp+CiqSTV9MrFV7CVOnlG67bAYJp2O/au/b+gTfQ6nFLwJYriR1AaOOaaNaflp6l+Av80wJ3FZW2dTTRKOg"
    "n8RXxDBmxXvwbTZU6znpV8VYCTzIGIG1WJuKWXUg6naK3tzZlGlgQ4UWUzVLOAn+hoBz6mLYA5+qabPRW/GuRgi91TVsAbOlzkGYpl6SUfH6KhY1"
    "l2kDcK0EP8Ct2LWuotNJcOAruudUCzNQYifOF1gQsbUF9Jok/dCsxuQk6e4BYfwIj6Yd2FZMXbKGT9HA4C6D/CGl4D96oZ65EMJJR5XdRB2KRwcP"
    "m0iGukbZW37bzVlE9oWSlymjYt0pqYmx2HAvGKrZy1dLYLeCl08gF8bpPm3UN4uwdV2wSgyKhaXFK3G8CnWhsJ0iZ5CtphqglxZWZNNAeUs2xgl0"
    "1dvYLmJvlynrK8J5FcQrDVGpGiSduw54mY4T9CRz0vdeBcz1dquGb0BUcYYLGftyIq24073M4l2wHTqO6iNsQ1kA2C/MlKyfiIBYw+NVAQ3UDVrV"
    "qdAahlgi7/E0MjsmAluJq+roCgUxOhkJpAJ3UGuIhQhoV1mPky/nCwJylUVndmu5JdICgUCEF+v3oZWbzWNV8Qv6qiFwTj22C11G90Rnd9JhbNcT"
    "1g/RbTOBK+4GGgC2DPKPvgjEmJKchWcInwgDHCpIdWI8wOEiwQMAyU1ZodXjY1OEq7bvPLc2wyxwMty70q47FGjZ6lqVg3miG61g/jQBPHB81Y5Y"
    "QT2N2N4dRnMVrLnGVHOCwWgVCJnISZWXlkZ1cuE0CwvRTQHO6X6Gw0ezneKTlcuX+HMeaOYVAfQtLFGHp/F70Jx1oDSShmPJ/7+ciBte5Uv7+Imq"
    "WQdQXr/D5l0Usf/O3Pw+hm7Olf/OzKFDIEALsEDOB7NGS0k7IbJeHfYMOswrGBV2t6Il7XiGcHLnuIHYbjaGFab43oR10ZUccL2QOG45hcskHCJr"
    "TbDe0+oc0UHF15w10YvcmaIuFaXMC+kQKOx5SxnHtTIuq4BdFkxdqiWW0iWBNqdbKsjKWgOahoaSd0ESFgwTNZQY/8L4gmnlDNITsVAzRHj0Mvix"
    "uoFOtTshX+ksacjEWULbENOOYhv+wF8TOErtruhali+FD4ldxFp6pFTbZMT+cyyBxbBb3ahUO2cbQIwlvRwznEe3V2vBZ5BQoJWRB2q9WFJlxGDJ"
    "zVh1C11JCpc0dW3VKDvs46QR4srMl2JCzxYyjG4wkQFCkyqHKsvtobjheEud5nTnYinJkMdBlBuLnPIS+iajslHSbJwiaM4YxhzKWFjpQMZsxbnb"
    "m+I16aTCjGTeoD5VBvuL1Rj763iOKqefUIf8c0+VdzllslaNCncHNB2uEigba2pJSTxAS1UNi6j42q/UgbZBnxL3iTMYJrSYvcX4KWmzCTMXEas2"
    "XkNZ0XYmQZzCOyVwum6ZkMJlwgRlWqtLLlItwVxyq7X7/zwKkGowzYTqWS1cITOUAKX9jq9F8LVXAQCxYWfQy004IW2MXB0NrJlW92JCWjJh+Shx"
    "1WljjD5i1dbGLKza3MTd3OxK4cHNSLja/PYTf2SokOmxsWpzi7OF5a29+Z78zOpBYLU7Xfd3Ohd3usb3Bp/kR1/tdCzvdF3f6RrBDztfRCLV7nTe"
    "2+m8s9PVtdPVu9M1BI/tdL3a6czudMGHWztd/TtdDyOha3e67uEDnc/osYmdrkc7XWM01Ja84kLY+j0re+MDsJXc5A8R8LX+eoc/tL7TAUMM7nTc"
    "2ula2emao7F6ozBs/cd3c482A09FwNjudN3Y6bpLC72907G615HN9d+0cGw1XSN9+p2umztdA7SvJaJML4zBp+Soe4OmE4VnW3iwAnv2114XHi/A"
    "+7gSXM9DPqoAui0/HI1v619/6fdk/eHOfM9SNKsjQTqfM0F2On/a6XxE5win0wF/BEFu/fUfYMgSujI3m/HXh/3BcedMOjdo8L6w/25/i9MBxfDv"
    "jVJgt0gGpAFw0QYTFtgjv/iyLNqt33stN3bHvzngD4/7rydC7qbNEETq55odj4B1yye9kwHaDaOE4Gh38Z8d/TudMP5GqT3D1Cy2B8He+o8m/dnl"
    "nY6JnY4HOx3dv2z1+sOL8MdO5/JO5xqxnOzml62+A9Fweb27ryZ3OoaiWHd5N5spXN+k6V7vdEwdgI2bG7zur07Tyibc7yqAxQWiq2N46JJGuEmL"
    "UWVguHIWHYP52y8LD4bUMPeQWLiZmZ3OG79sTWufD7i/8Gbb75+n3cJjwzsd8/hWR/exMHLls9xUZx6o2rEkOpvUWm4mu9Ox5i8+9vtfqGnt1fWq"
    "gfgwTwwsN7yGnc43pF3m8ejhbxSxCeTZzn7/NZBtVe0NTsda72v631uhlVYCoMvDqNPBUXNjE+6o08dGzVVrXSvLBb0BFQvLMYMCC+10dAIhrBf6"
    "Dgmmq5+1nkOO81dvFRYG1dEP7HT2gbYwb4YfcZjycOC6ZNnIaoMGwm2i1gGaABvAFi3FgpK+k+k0L5dZBTx3LAze3ewQ8CCqDDyBa6R4rtFRgOpc"
    "wjUKY078sjXDKjKXBRXxBpV1eEORXEz66IQwevMDK/mHA8yfJWZbC3ALkAiE3+99haI+/MPezDVw2FDhT3UWllHb+bde7nTcJY7UfDnFhI2G8WU6"
    "RMrM0dF8lb5c230zB8xgGXHyBrt6/d4J9BA6bsDaeR87Xd1sLdEWDz2FBeWfjoCVI4Pyo72PA+F+2c/iPeTXuv2ZJ/41INKSvzq4+/JaSbzfva5l"
    "sPD5aSDaA23hD0b7LdzbyGVXcrO39sZhN2uF5UnwfyN1Ay+fUX93OlfJOQKWmyiN/usqmgco1R13YFe5sXU/sxhC/7X9bbS295YOwv/1e7qQe/oz"
    "hYUbsPPC/Y385noJzF/9FKxEP2jwfln6FNqvFhQG/CVO7g5h/uZmH/AWw3i/8FVueGT39YyL9ltYznAAI2i/7JWCdldgvzsdWRftN9cHhOgAAYHz"
    "sdF+8yPX8qOPLbRf2yF0MX/5TFlXBBB/efn6Kxfx196ewfplP8jC+d3ruJ8fXWZOtdB+yX1aIHl56ID+BlxhK12y07VAruIr0npZF/434PMaIODA"
    "RAIIrJVlMNkWqarcHCWHG3pHAhDsLy7lxq/7jyAgeAXePf9toQTnNpaB0g5MsOYzGyFYO29RCMH+Yl9uZhM1Ojm1AVpZSMH52Y782F0LJVjtq1dc"
    "do0VvNP5mOj5Av7lQASD7szdesUhcwAgOP+0O/9iNIQNvLs9m+sdgTeYYyNwgdEoDcyHwzQXG5hDKrFYGGoEPfYovOBw0BP5XgSMsL8F9hm4HCLI"
    "CaXgQGvM5p8MBCGENbF2umY12RWOMARZ/tKACyKstbIgCLN9czCE+UzzlERQGMK49K77MEMkjHDIB1s1MKsKT5htkxZdjSnMhtABEw6LjoIVtg/C"
    "ghcmQbyOCYnO20FcYRWQdCHpge7sbdDrGmCY1VpJdOFIUxWNLczmSRNeAwqDFkJKd8zmHt3ezT5yUIX504Ar4KILwyu58UdhaOHcD3fzz6bRB+y9"
    "Dg8o02V5FEGwYV5aJMqwYY0ogGH9obgwyoE4CqywHbyqt1gSjwgqnJvtg1ghVPe0VS15nSa0Z4N+dHhhe2jrEW1tDkIX3n31jFZk9CU+ttM1Scyd"
    "gY8qxBlWAzmm6HiAwzJkUH8NBiZhg4Ouo/ifDgMfFocYuM/vWca/2Ok4KgJxKXlHnyjTAc8EyA4v07KXrIRJ0Jc/eYhi4PbdlxA7rFnBOat6GhW8"
    "deWMGqLCWtCFRwFfY18+bFDQUMxmOO7n8TDA53kh9rXSAkt6dwfBGrux25LESJkOnXFzs02GeJEwx6XOh78viXas83D0BXDokRCPA8k9K+kXkdDT"
    "tuoY+Mfs8Tu5Q4j91oi1OgeU4KyqsHCQdXBIlCoDRw6k8ikMW43UNcgUPAp8B8aF0yInA5usNvWA1i9peM69A7/JHxCHXuvxV19gks/OZAYdieV8"
    "z5I/0hswbMy3J4alzCsQBg85VHoPv2zNhNfHagsO1ZKAYPa8YmTlsB/lMKxORXdyNppSf/j8I/zfENseB3V5p3NbyBDaMZZF5FAekj4ZUMWgh7Se"
    "B5TNWder3Xv1k78wgWrn+j2IAvF1FaUFsJgpEbEKka22ogEYZteeD6rgI+T0RIEya1mzx49AZA7lUHrJ8d0gWqzR9ibYfbQxmvNPO1FurUMvDdMs"
    "MQec19wCKzIbmjk3tgm0zWWWgqjMumLIKZsISGZ/cRxcVe3RHx2OWVmXwNGvkdJ3eU/JL6v+3Vd3c3OoWd2jicjLHBOgmSclhsFV+cMTu28WiDaD"
    "cIC5wQ5jioA/o+VlybHvx0NpDqyHc7NKo+jZVWIUtB8lZUHzovs0egui1EgVd3R4ZtfkrEaXt2yrh1+FykhO/aukL/1xUJwhZj/cseKiWBGBsK6o"
    "UvUDcf86f+Ia1z8F4NkdgVhvVeXlgZprUSsCVRtYjt4DWCI9P5DphEGew+4COs78tJ8ZUHQ2KawDsJ+VgrCt1wbVCjYwigzx0kfHg1asZCknY8Si"
    "eKdjObc2WtjqsmSUNBmeo9ick0aNjlbBKknIXBPw94iSpYKfQX/kIS48Sh2rJJg7GjCbeKXRlaPKAaf1t/mxBxxrhXziQX5Yl1qtmpZerfKGTxyS"
    "WkZUYW9EvpXrrZG1NjU0fXCLZNkZf6eTPAaj+2Hzc3gMnX1ulBdB4kohrEvY64dUoUafoES9qyRTVApxTQ9pP3A3m93p7FBu3qB6Tr7HUso9t8Ri"
    "DvVICNhRljVkfbvWiChrKN/Yt7RljeFRmYrVcIT1PSIsNgTgu9s/FO51IEOBFL3MEGM4oTEHo7qTSiWSKgDKDriBoS4JQ9PfEFw2kYL72aYkkWGn"
    "3NE3mdV/72WmfeA0ZPh11XoyobxTJ2cFkdnuNqppv+cxvIV+0NgDf/g5fJjfeIW18Z7Hudm+cM7H5FlKjimF1Nz9W4WubTgFTkGS0D1gXme7QnVK"
    "CHjf5LIrYLr94TV6npzPjkHysOgB4AQMmkivg4LA3QH/ghw9UMXOcir8XwaL+wQ4IXRkhesPCi8fhrOkqB5HgJiTksnC0J/iPGrnYFZBsvc9wegV"
    "D/0eae1BdBewiaADlc1yL5ysHBwsaWoRVK4VPtqVI06JPBTugqGQB17QsD/h4XaCplh2S9q3VJZ10H/TAzrFDluOjvVdgYpCxqLU+sp8YWS7Mrhv"
    "J1NYOuwpifWttvhAR8ZloL5NGF2Bvj0yyvehZiF6VUyDw4J8Oxk7/Qz8kxJq6FZVSIlDI39zkiuXWWJNxkl6pov20VYr5KkjQH/nVrCXNtc3sDd/"
    "DcId/TzMoh/TsRHP6F8b8l/eK9OAFQ0GbneXROOA8xO4HJKLw6CAq8T8w6i0fUTfLSgUfhdTxqX94cpBwsnScNRyiCQFPmyHFVE5nV8JNLykBJSI"
    "KkDTLnJzVgXeGHnlu6/u7k0NRQ20prqpNqTULFlORy8fD3Y8Og7rWIVXbS/Rv9Zjdb+WijtOEoe81MIIljFqaRFDmwLOoeDJ8wMrYL7F10UZB0ov"
    "mh786IuWboB/q1wLwKHQylnF7U2NYHWNOYqDLOOYURcMyNad2cKzDeneIoN+4gjl+ZWV3WwfBQIcf2FNTt08WKa+zAHlSwzCH4WtPk0RFWc/xFMh"
    "AQkpmFukKpZLxRfsgfy6GOb/AUfPxSNJtEbkP0z9HLglmDOUGuqcZqfCA5Tg/OoCRaxWahFb/9a0c842nfOQihpLWK6i44ZZYITdbD8WF14OgNZU"
    "VdIBptJvEMa8dCJJFK3irKiagMqvq8SfEkP3uPL9z3I9A+GbCib8Qgc5mN2PTHWA1vb7qBO9965kwXCiIU5jUeQ3SWfLiZefuInH5gt/flMqWuTh"
    "5DdHpBOW/X2rF+A4oOj5mc3Cmx8N9bTXjzR8qu6W/Eh/XEMbw33lYIndys5HBUJXjD/KDaFKGczLH2XTpKXaAH5DYOm/bPVaF0uc3B3XqLGNItPh"
    "rpxecnF2y7yL65Y3GGe35LN0/oUHj4AlC6+3lI25Fb7Il+sfyy+/IT4KfsWjfaqykapnA49YPIdAcz6Tp1RX/4mCs6s2mIjqjvH1SCRBPS/Amv/w"
    "y/ZN1/EzbS7+SLfSSg/9mZeU2FlVygg8u8nd7A+BpD/3PZRHc4/0QPTCicsfcEzxkUDdgxlkO9IpoXxRIS6OW9tfLbEaazBsSGE1eEIw8GXcWeUn"
    "6i1azuFHBIEvUVShniiyH2hsypoQMEVgFcB+8M0Ae1UnBQtfKeMPipaW4wto6VLmO2BtTQwZDRNfpqCkJo4OB//VweMjWcnfvu1vDatwsQTlOrtL"
    "3T4qk9/VTX2BBAEyLKcwdZ0DNfa0NO+gdowUwochD8fJfzuE0sKpQ85MR7DIZVkTTbVyegum40GIoKEa2XL+KSzmDbpkncNIhI57gSDYNM2BF49J"
    "ijuRFbSPjmSvFMWG6Aps1EdTnJu4y8cjxnUKnNqHai7brqMuMU6mhFb558t4SUuHa2zdMeKxG3JLNtd8DFj7j5G9+mVrRk+hfV1aCoRYyCkl7r4c"
    "DH2fm9nMjVN2htU5pvy7LAZ76D/mwPfWQQD4oVcHpaRK66XT6889MzQoi4of6M3V5W68ukQdZGWR8bl3n1hpdffVeHhfFWLkcw6Tm4/UxWkdowUH"
    "jILL192BTF2d4IjAytcwFTxpBE6+wDvghVYtD/0RYPkUGKGM5W4M7W7PRgLlm7ZF7NmbIoGUm3FRUPkWv2akgyiEohCNmB+AsOBMKXg1ZUDyw+1K"
    "OTjM3hENkxEGeg5+EsDLd24PfDzUfB7TbiILDGq3iYHjbXkFt2RMCyFA8ge0CLftek2VUCWT6sLpO3APePMSjvkNeP0GWJ+d+ROA1mc5C3TQeTIw"
    "+K0Ba4pxAZhhTpZjgXJGuuc6fwpfqj0k6r7bmuwwkH9nnXpS9MqiYffNR1Ys94YhYo6Kvx8xGh2f3L+MvpUfgsEvdTv/SPj8FSzJ8R4OsZ6j4veH"
    "3stPvQQW0e9hmvj+2O7rBTYDJwjiDw4Uvkh7XeBad4Vtgv8UJH81K4c8wck9Ard5QP079xX6wZLpTQuFwBH32aN8XFgSXbjQJcJbjmNt1crcqzgS"
    "4FSA+G8e0U3v+uY/ImQcAPMfogObsmigfwyquTOl8yf/8RiosMimMoP3i1RFqzdOES43tnN9b0oS4KDT6PYKet6IHjBHzfP9BPLSRwa2iypgEdNY"
    "PwzAJHR+FiCAjWFyq+a3ApxfB0B2tn8fwI42xCbgweNOApcTw20TCm2CFDQ/AwEZEELc6keaA2h5Qc868JsCpRrlFXeW9NADvzLg/rQAcXxHP/tD"
    "Acoidn0A+UhNhnS22cD6fCgwvWkdNEeMsSVIygtUlcL8Dx2diQxjn7sedwr0JN+wDvwaAT1zQ7OQ1U+qE/1yjOxI2sug7qy7fv9MmMF4Lk6T8Yv5"
    "p4OF52vY6OXmZ/hGSZmcNWxWrdQ01sFKld2gFMxr+r+HeuF6u+aXDf74n7kFYLLVP/xxL/MkN7ZeZvUY3t1/mZ/axupaJ7McrKxzd/tNfnTZJiuf"
    "lfnNA9rHffKluMDVHeYGqu2johhG+ZW4i1J7lixbkB0RMbP6vQGpeqlShboY46D8uD+N4BZ87uncqDOSkkTWUpLVQDqMkle85nJJEIZFSRz3kI8q"
    "wDflUStgFimIWmS0f0khtKegiKhZ7gnfAN933iM+G8ndnCWDpBccTUT7pxZUULFB0dXDwJ1Otd816+5fhMbQv74ga4DnjegucxLIn9/M9WXQhkb8"
    "FIOtNcv88ALeRHWPGgmoKmyrenYrY2+IHP4tBqtddc0G6FA/wsDSBxLXv0XdcMt7432UarUrbomWyCtW7o8wBL73/h3YU1+mcjtYHuKH81sw/H9Q"
    "Glr9sEK4V9tNct7ivjRMfkobSZDT2W4iAsrjzuj+A2P6dAVZYGZgOX/ANUdABEm5Xf3wgs58KZZx+VddS7AYOZDx/skt+UhqJtf3mNJtvJGlMFNb"
    "P83AeQOG5IBFcw1ctVyXyHxisySVTdBliwQt4xroDU5d7r5Z2JtX9gsvaEgMacDPMFGJv9RADgVBJUaKoyrtcWJWfr0BNG7ANVAlMmNR0SztZUYt"
    "T0BY0vlJB/ZVKHpAyqlSMib/AlvgiirJLSW7yvsusCeaHgxJri/anWOnTP/sQ8hA/GT/CASWsKbv0H39VRpngKJVmU43yTqvgIoUs+TIecQPRTAC"
    "EpG4kzpP8BK/7rg2/pr2sctaSOsnJUJsYAvTbfLbenXyMExDa/3BSUBp5m4/Dt4DskzR7us3/uos+LyqFB54spPcA9OQq36CwnabQj9FEWzgL1dQ"
    "Ny0oIR/TGPoAgYwvVJpv3J+wMIbECZHX1CXOiVIqgf0Iucnd2Y1wO3cfUch5W1oMl+74160OEJs/qavBNTYRy9Q/ecFk0OanNGFsZ+Lh3vhtCWjc"
    "w+KyiFLnD9WA98lbjO7zi2qCvCVCpLJfu9mhwrMNp5MocjQDWIlry42/yG2Mhbq0gigU4V/XUPLkZhXFVZKdVtgLF9k6ELgDqLdpFKpItdsNocpU"
    "zw0qqOpPCxWi1AUls+7l8qWpSn6fQ5BhNC5e9OVWfSERdzYXvGzv9A2pNn336iP6gaW7n5Al4fCNi1iqvBYqkzkqSy+Oxz3oylgAAKfUyokmB2HI"
    "Pgx0DQrGjYtJsFwKN4X+nqY3B0LTP1S6ZRClAJwOTDkso8U0o1EQg22Mjh8fgCL2R7oDVSdu7uKCmxOQZDpM5ziKc4C355xr0ubas0lRM64heibb"
    "Q2hDgyAtskL3l0X+h6j7Eo2ybuOcv31j9+UAt5QS/NhBSkNWPMfiy7UsWn2w58Pv6d2bf6TppqoEVoAh5+52m+Ls6zKFVEjt5sNBnhpiSL+vf29q"
    "Uesj8nCGcsNgsntdLcKGTHW2Lr602lo1gzko03I7y46xH9r7VjgmFky0eZI0+pt1ZYKCRXgCglFS7p44JzH5XqWoMwtvZzA3vh1pJgILLSVl1lBr"
    "+e4Fc3HNlTULY1BpsxXigqwmgroPoQIkuau2HAkVoc4NgxO+P8HQauVNXwTdXCjtIC6VeJywvEF3eXasNWTuroAAisYTPaG4SbN/6NoYPQAGIn/r"
    "rh6nBBapwpiwQR0Pa0DXyrR2u+L3sGQjN2grZPegmjZLWdP9HeF2DIOde+/gsMy1YHamPrjNgy5LlxopSsMZiP4IR0b6lINqybWApRp2flI9YTPa"
    "MnK8G6amDVBqZZDslSxTGp21nVEj5jgjXlkN9+sLmK80HC0d9tRdIFMyokEezw+/piFXxYtB4klWpLCwbKnOgAI6XB+SxMkqvRScq7ObfDfGmH5o"
    "sgYdS+6thFuuRA6Wl8Wo30BQqpLvaC67Wwx2tmjUpxA2GtPAdpAG/WtDheXe/OqE1i8HAdwTJ2VX/fXhEgsQskWhiwUgo8JgY4NORACLIWRWPZHW"
    "yCDMQMXoQ3Ys31opB5oEly6XCLkehM5f43tNRIED4FyhC7Wh/rehSbKUoc6ozgFu5tfn4lUAAb4crTwCyGqqxJJ/9iT/uicsXtaGQ81SqnehxOaj"
    "lVvk738Y0FP0LYVOqg9DrjisqiziWtjHIF20TJHxQ0dgDIe6zhH+xk3LVes3bt696H6XnXiXvR35GzfvsrPvsi/eveh7l737Lnv9XXbqXfbJu+yC"
    "/ZM377Id9OGdd9kx+t+ld9ned9kH77KP3mWnD/oRHOvt6XfZxzQDLOcZfv6igz6cfvciQw88hWXiQmTJC+9eDNIzsLR1mi37LjtDA8LDN+DbyN/Q"
    "iZgoe5NGhmVMRf56zrsXnTTyHZr6Fq1h0NDmRde7bD/8Ef4ZnXfZh7S8xzTLCE9BtIE/JtXGb8D6I35kh757Qiu7rt6cQCq86KXVbL7LjtIipngb"
    "Ub+8EzUGbQQptkQLg0PbjP45HnM2eACwjedE5Q6LHB2K3Au0mBf/f3nf1hxXlaX5V04wD2X3SKKrpqcfpCeaSxcxgAlsKqIiiCCELUDRKkttSU0x"
    "DncgY5AZpgYJZUqkJUuWLCultDEuQYEc0WFHzJ/wq3/KnHXda9/OOZmS6aLmoSg58+Q++7L2uq/1GbAe82oeJgfcg2Pjk/CeL58+JEK7im9bxJds"
    "4yc/4ANbuIFt73xrYX28k4NRFvA1N+A1QN7f4jse4lR0k7/FQ/oBHzukO2LRf5IPJJCAcAVICDDoIvwMXnnIf8PvF9McInUpPpUb0cMTKIe4HkIF"
    "mSWUizrMyMvURdDfreJmLOChwE7EdjtSwZf4bThODkXIJyghYfh7A+kkPgoa+U9wv47+Ugk25I+dP11lKky4D5Bb8eH5lqMwtENzZ9ZwQjfiezUY"
    "aFE180xejKHi6dE13PZDXMz9cnMKxwcrT6US3givyLZQzV+KU2ZyPUe6zAI+wbl+ixv+v/F88GW8+TC707UQSLLoRXwT7KtriGdo0RM9vFI41W4N"
    "JJJZEB1euSNHfWMjZbiTzA4+/F/AGplhbOMJ7NhF4esf4k+Ep5UnCNJqpTGiUmYWO/iGRbdS+KOFu3NbXl5FYaMFjreJvBUO3r3zOLhLzKXcHG7L"
    "unUy/qHGC1EOpPOD367iOJ2SOlYSLz5BlKb+V1A1X/xwW6lEpm7UAztwxGz4sgEF+MttAvVUx2Is24zmzTdtG7+lyXbN6IMiQ1USbt+zLDlVwLr0"
    "1XiMnbzwX8Vhy3fdPt0nqhRRxKj/mGVO9vF+4aJoGTkalMrYMf8VgwNBOZKDzbmFhKdEE90At9drIgZvjBXBEViajSlaZ2H4aH+M64QgpfqatdEH"
    "SGvr0QPMRPV3uqQFfKSFt3sbvyJVY8Ff259x2YtGrNvRVA3+BKXGbSNrFqt1nSyGVb3WEV36wbGtMpJrQ9jlNd5Z0CJU5Mdq7zWYJUxrwZDHEeiG"
    "sM3XjWjFHcU7jf+9IX+QDfEXMtRqQbECFRv//gEn0MErQiv61FgqxKev4gSsduAMpyyUVuq6JZVhshlIG+uS1lmPuBUSeYXJDXYsDb3oU6HRBJlx"
    "I+XBWhecHYsmGQF2yVB0Jl2mbDR0MuBd7uR416763KFCTGwSR/DRvYyObhW0tJ+gEvXLjHRHuOS34o9o4SwPZU/W8JaisQp/tIVkvpDdvpGBCxv4"
    "JR6qWJI7C8hYQAiKNiYejOsR4NjxNcwYqSyplvuoZXLDDsh6ZewyZZ+CXYby+0ciKoNgJuPuyDYyFVs0M+FtbaSGDeKWgmyGL/oeN5gvmQE3q2BO"
    "AdYZzuAno6d3AuPFRz/rc6/DsT3MNFqSKJeb4Kbw+Gtgd3UMulrMzgzGmtWkPIy1pLlpAhSGn+FmiRvR4K3F1j7jrQUvZby1WGkJY3TmH14kNMWw"
    "a0iYEdkc08D5CRAbUtK2kXJMWB40W/X9DiDbkkIzg+BW5cfJcX72v9wRetgR4qQPF33oN+MOIhbdUkeAwYOzbNbDg8OV38Uf9vD4W7R9BhnOOJrT"
    "BxDAxTkzGsh6gZyLPnScXIEfkAlfxbfupDHk8vZBwn0bYctVuklQpB6tpeDlqn4XXYUEyJzVA8zVviYndEfGipVOfV/bPy4BpTP/cGB04oZnT4GP"
    "SlehLjmouoAZO8C6JvQoQHaGk2yIE3xT7ksriW4n6F9GmW7qDTb4d0kWpyh45qptiLLT8UDx4kMVUDxfvaLxO+y4ZYA8/MZcLpsDhPt9hBuRvjwK"
    "kxd5okM/8Zsnrp6mUfaaK5QB1QUSVOH5cFk7sg3ojeRJXBPG2/Uw+7wf+IP6yH2G+V2Vq3VdfDZ38RUPYlw/I8MjB6G5dRG6X7DcFMpfzVVLQf+l"
    "jUfySMHfCbIpdKBB8AGTnNP93ie8vySl3YBAgvRRmEapnvJAlxgcPrCwI9lnkspVHZhgETMXRADERwqRnt06KMEiqWYdD0uwCPiWUUoDxzwZw8aC"
    "TE3GGOqb+OGCaGGHA2AO5p/qF3WwmonGh2rZfHx4MLSuFF7wLCAIbdya1U52rkS0RASbcUJ/CQ85BWQHNbHrvnM6VjF7sl1rEs3cMWdbodqwE6Y4"
    "xUs53QDBsF+r03PEmiSBMN5UEeJLYh9WU0kNAqLOg25VGB4PIjH4zzZqONsDQSXWudTjIGKSDSdCi764PAa4YsY3eCNJxElnynEcyE1RGdP8WfVq"
    "/aFwwB5eM6KShMp4MiCNGe2/LxeCx7/HiEF0kEEQ177rOaBjgm2y96zZa/rODXFgyT/1Kg6SoVEVGj4xdMlsHgxMTiPgLescaDLFsaIyAyMWOLUb"
    "5aJZ/WBW9ssnBrCiDAcOvPaaQ2V/Hjnu/YM9DixmTXiRj1DzjnTOemGq6fGGufSL6RPLuIQDJE1jTsaEYKWs28wYbdN/rw1Q19jaSfzNNLPOzzON"
    "zpmi+bT160dRhDiMr9XCd/o+JuecyoN44qiLxiCitVzFAb7HwZSZpd1AFvTTV3FJAtzADXcxBg8MNHsTokzLECTUD8xIKAp+IA65gWFD++HBrMal"
    "Ujf68zV6MdCHC2IeN+QMgTEiJOpsW2N7G9o5JnppdHq5rJBrRlokTzsOUiozsc9oHkjiHhwf/LTxctQVQv4HzWK8iiZEMji6YMI8XflEnUnB2vOs"
    "tUqPCVMUjoW7mtdJPa41hFa5C5Za3Rik5FBOww8VLKtgp50UzwCatUBL47bZ7TuGj5A3qWsukUqck6Tbnx/FNfnGYCuil6cEQkB6bLMEM+xvdv1B"
    "vBYpipSnA/qpQXfNyPWYKBPE+3OAvaZsmUCXaWBd1BB4japx0uCwiYyrAUSvF0in1VQ7sfQah7QDxp8k9Wd/HStuab2oOa5swlPl/0h0CeeWMqmf"
    "zwRKVt6YKtyweZjy5pjLjxWZ/WsJ1e24OQhbASosYgCopvixYQKkezbWEOtyIl2SVHME2YaJfFE+hPOhyIADIsn2qVW0gKMzQ/vBU0rqtZY1lAZR"
    "SU4/Coqd+8AotWZdCyKgOri0q6JPd0SZ/r5yeuW1/0rKWP4sTse2Cx7E88iC2zY0awYjl18WJG7errWeO855K8SZtFb4joc7sJ18r9dcWBO2bV0r"
    "zwyx2v27blIBvsc/1Jy12SqYagd/tERudo2zIVZ+1kzKqhcaCmIJPTlrms2qVJy13KHDW79ABexQhOG2McmblfTkJ+TVGdnYBmkJLn7D1yXtkovF"
    "LYmIXK5ky7h/7shLun8zAL8D03UdOVvKr44cxodMHju9DikKd3kw/nXIUH5hDrJjGKouvmuyAX6UbJovoqnkk4MTpKZ5staqUtq+y3WWmgwtaU35"
    "DF//hGBWLa+4T0u5JH9gcEhiv3bnR5PTsfL0aBldkAnBRGGgq3RxmoEUp8yvCuk/oAchDXCc9xrqqV4X3WJd0/YqQJDzA6akeGPf5GBYycd5aSp0"
    "0XY3N6Wp0Nmf/NH1i8tsT4sla93UMzslhJ8P7BTWuAkiiIMgO2eDNpXe6JwA1LhxmMnW5Co3p85+8aPD13FxWtv4dddHiwq13r1Bkm4XJCFKuavn"
    "BXJvzyFND1ArkQakzlVKGFMkO1xj6OrKUGOcoxFsTTLXI7TMA+1NbfTm8NZ5MVYdtDsZxmE2hDS+6z8TKHafPMb4Wd39pUln2U+C6ZiZpohj1ajq"
    "67FQ85Sd8LSktgs+/zMl5R4DVDv2VyAeXIU3K8l2Rhs7XU4MdfsEZ17vtw78S30gdMtXUVZmYMon1PtsX8I6T2SNv7U/VO9MelpHLjj9fURKvbFQ"
    "nWP5U2HCdo13ubUKM0c9tNgATdzTE0cLf3p0U+77jse7XQV94FtTUVKRsOCZqIaBWIsnYvRH1zlH2ep4yRJYU+Flj/fnRR2PCFkrRO0uxvW0t+Ue"
    "HkTW7V0ZIX+TZbmF8YHZIo2u6GlHuMPBFM3+e1xXjpL1N0oAN8fBuoFG2rt+wSzx5/jtcewueWtjT0js40lmY7IY/mVCqddl/OQqlQOZXM0Qr2fy"
    "U3uS1tVhv0hWcmQyzoxYGCz7qkjlc31i6kgOTTIILUMdDJqm8YkMchhN6M8iI5t4BOPYcqzhJd39CY+c0O2CM73THkeXV+eyl331y2rwa6a1E827"
    "c0zUeZ+3ihsrrOWJ4jyOWKokR+GzpdvGgrwj7CEmNt1FNg2eNaZ96mo0i+hKqx0U8ne5swEVA/9yMO1jZS+olecko/wqmg8QLBSdjJvac80rOrCt"
    "0jxbBL0auBP9vJc3q7Lvlnu7aSLi1PlszxTe3uPki9eCg6smU2pw41WI9A3i3lFyudvroOojVJ+rDINQAvjcloz1qnmHBrqy41j7HMSWaIJLDxs+"
    "jnogCepSLbwYqwWY7PORGjZVllLqHbkcW8vUU90p1I4YRNDWm571u5O0Ogc1OgfePzxKo9dhS0PsFtOH6oVHaAapubqe+7wmPb6JGPekd+3VlwIz"
    "T50NxNtAtz4We80MaxV7fpMNgGB1E0x35aALW1NTfK4qI8qW3pX30WvN5Gs3YMyR3p4jfQHZhQgnZE3Mzoyfnxgpfif5VaVRCPTNV8JeYoikOnkY"
    "CDbyNQUXylP6m2doJQirr+30BVhVC6rRonEpnurgttNSV/rVqnvjz+Lg/UnmUs8b/BrOn8RPoKTnZ8hk46u1GWc+C8ur8Va+XZNABIWWFwOa0BBz"
    "BWUE7sFmXFCYFrU1AOBz1AsF5h77uoqKqHXQJe1a7D68KGPFxIVJcPzA72fRsKU8yvmLc5J83g2FbKCjeaW4dFBKDglNzdRlrwS9zBLHMharhE3q"
    "wLDOgy/GVXM9OkZTYynYLKoxVvzr/PgUlY1OvPrSC2dtM0fc58sQa5k8/58aABkz6qzNH6QZDxqpEB++LnDoubdnhNYgC3xapelsSbtRG4dvccR1"
    "uZttcfPvmBDTl7hsaezqy8OzNKj21hTrdupjMVeDX1d2x3SZGYlqlunSjinYYxqYxd50U2k+VakWiSOF+Jzds1l476xtf5Ldk9BREXStkKIvt3Wz"
    "0OG13LkL82j0mxZumXdZj7mpEmb5cNeLHFbGDMUDV16kWW0Mkqy2dSWLVT1DpkADCOZf0d7DNWDukd/gQ21aPn5hNiRTx6vSbctnxoHVjisOs/lx"
    "PsfTc6FsSD9ezyVKqhKXD06NvzcxldKR1h03qNslzrgC7zS2+a5rfl/d9zFVV8ylPuPFLDeS52SZuB4nyJ2paSr/otpVvm+ikkFlmzB6wOsZoHRX"
    "vyNV96mGBuVTBKuu9Q1D+HO4TqUGOTX+b1Tw8OaL/4NL5NnhDNBe5f7QS6HLMwpZ6SVS3Y2eJhi/yKSu9eTnXBKEE4i8wWFLaJ5OlEXzowSqul7h"
    "gwm/ur7lpQAYz/irw3blxam3Xn7zzFvnXnrh3AunqRHK8H//9W9U2wamx5x2FIPWs154prSwhzCCDxv84TT2W5QhKi1N619N8MfRwkSPr7HSyOkm"
    "6SGLmKKDlgX3LV5AuE4KLZhySIg4QMJkekGoXT4k0XXHv+eB1/1qHzfhxX/C987PSqMn5/HHLwMiAetLfxK1XYa1QOZBeUqJxstN+y3Hk4iaLJsX"
    "RVRcWWJwut8FQM75f+rsT+tZ2cnNzs5D6yb6/ytDpek6PjWPMVtt6MJO7dyLvHb6tjULj1n4Vug2CTK/BAYKrKZnidWdOVtM/mH8g4lGxXDyQx9D"
    "5QcJ12xLXFHzypNlAnz5mhW4cc1MwO6hWkcbwEy///7U5EVaDjkGJExo3Xtj/BGXtv7udSoV8YlJsoqSrVqCORRGL6FD2UICwGorxZmhfjL50h+7"
    "l8rG1HGT5GdZ9jBWNCV3YHLX8NuWSzMstyQl4l1mk9uAoHU8taStbx1vtjDXJ16GQmUqFvvhnQyfuAJ6wPgFaGF2uTQKoZBdenm1xaPhJ9YksqUL"
    "P9P7BlLtHYlvAQVbvGzPFSP5fDx4qv0M201dUbxvhHzPJlfGCZLFH8bPnzn7/GuTF+f/WLgIlQd4tKDJ5MXshzLX2Q9BSSrJkHsCROlYBYGaF/9t"
    "5Ne//q9Rjev5Sx/PzE2XNv/Mhx8H8ZMktk+uxdINickQiNJhwRHgqkS+H8TfY09Kt7wlTh26dleFnFrS5+66pEa2CP7jXWEdg+AK9OPSIxV77tK8"
    "MTacgVKcPffCW+fe/e3Lb708MvfHuaIueTFSyH577vXXml75PLW7xi/SIIyQpkTwZCkZ4F4kfdWj323ZicNkjqRO9PSoqwqD9EZoojhaVE3f+eAt"
    "AawLlXay03dmN2Oze2p7OhwcBGTybpeHUhfBmVyHsr3ICU7puq6JY8imZ+Sq3bomAB80ywgjZ7iP741feFfWZTfkW/HEXhXRbEHFfhBf8kLxj/9Q"
    "mBocVyeiZSm5nOMF0544NjtNXQ1sYRffSQbmNZvlA/MnaPowzptnpWHE0Nb8xhE2WNKWpKK0TB8mS0vJSwYV8dmWrtI1uGlzOZ31KCJwkD1R1+am"
    "OiMyYJ3Jnmwhl81pweoACWApQvEZ9MuzHuAEWJlx2F0TM5Ocel3pWifHkSYjx1GBgdeeRsQUg9hB3PKYDlFniaEOXoa91QYPYvzi+YmpKSdFFoRw"
    "fxBHkW5PzUHGIiju15roDjQ9PzfD3bZ19g9S+WUuHZA16+FLE7PzU3PDf8eCRxOtqth9lDTRKf79ee35OmzDErPPWw5ipeSGaFLWV27TqczGm/TP"
    "krO9O1/X+z6RUpBtkTQDbYBFYW0VyKMV2UoJj91bmIw1OVfRNGpq8g+Tc7PvVj1V/P1oLSHU1eB45TWGwH7DgDLVZWYms9YLgGXzay5RQVuRatlV"
    "V6jls9VmjMzpm5I8XZU2WlGRL5f+1/VbnkaumZDW4X3nrVqFvOYKG+ZEoovPdlV2TaRsX2FkLz2hqVACJfDCvwFHu1CP9pPvOjpaHCeLv/BytYxi"
    "kQNWuy3cOgetJzvpdDbrFbxt3RE1IGoEVlreiQ8npmZSZpnJu4sMK0isO3v2tcILAPsZTZVms4d99X21vgm6ytz4xQvjU9MXJ6SvturoxnRma88k"
    "Oao+eyyDrnp6+WTUpmdYONMio9GxY+l5270/tSTnIzfyL2fZq0XtPVA5fpiSz6536Tv97uRFF0GwKnuyFD1QUlW6ONgbo70kcHRLK3R2ziD3fDFA"
    "h/cTObyMjukq8bal7pxk3CZyiQUJB173U8f/LHiwbeP/MEcbSvRAwj5AuunSvXkfnIdBT0M2F98tuePkeW0b2SSbOAc2ljP4apPDm+9xIrvQqt93"
    "TJOCv4h+NTEj5ldQxRK7zJJeLZV7VoetauJY1AV7LHy0+kgrbKQgh0gvd9zNKGcI2kT3hQC2xgSvQdXLIyYpdYZQzyaUF9yB/rvjGk9IsmVgUhFM"
    "5mVZpVCt+mxdJveDOKHe6uQM+EY6ctgchfwM3Cldld4pd4VbgmsVeB25OAUp7t3xucL01aQ9v2eEf3Q3Kzd/7FhKzlBRDScf6T2hImlbJC6K5iut"
    "l4wWYjLSosR+rUPfMRucvFqhIpRIuLkC1tHMFMJTX+4Dr10gOLJFJJbzOJRnGy9xHDPfcpoJp5N/Dyz4KIwONKqCiiufTnlBp9OB2yE2UIOBj5+v"
    "GAOZpJaXyhIOt9DBk1TVZiYqlvtC5B4r+uj76zHIT7mD+kNrjV4XDf57o9gGvMk2xlZurWkSJEbuGIT3AMReFducRFJPW6Mu+lHB2mruQo4VtimF"
    "Lf+rabtYi9MAw3wvSl0nKl/elpI7OmrOUuEW5JAbQ/0J/jZVo0Gq1Us2oA+fLhJpo442baGdTQ68xoijSc+YEf/Xpe2b7QKhxcYRJZyy5dKnC6Mm"
    "2W5EtDAvDtnccRVesuIUljqcLnx4Y1U2khcoWQZrS8zz8O/cc9/abgvS0EoJ5VOv8bQBrnG5UQIkE8UEDNcgh3u2+MyJOKta5tpgW9S91P1orB4G"
    "XfVy4jWF3VGlaVsxkNuQSOkVAuuPz5OW+bkCpMRvTDL6iirAekbv4X0630zxjn7zznMBDef6+djTDnJZtWpZNzoTV4sr7GtMgqp+AkmXQrJjXo12"
    "bag0I/i8Uu7ItLCxiHees3jOsLmeS6x6esFtbxD6eOe5CxNTE1g1Ub63tOZn33kuBIANfI0N9emmfK1J5j5mEzNruWZ8nVXtNRJVGB7vTkkos7JG"
    "sQBphOPoNva+VmP6pASz5/fWcGGPaCeG4fKXEJk1jRYS9u4RzEILKes10DC22SlOUztd+JdxIF0gl/6ZldmeuL4hqtj9VFVNZUZCpUKs5kDNXgzW"
    "j7f5XalowBCU0KiEeIgTVZe005HCy5HkrMk1VgF312FVR5ZCkqGtm4v0lWjYNFn1S2lFxzr+oToazy7dg/ZEqvDUe5GbUS50a7EArgtSC7lpfwo7"
    "ZzALbyg0b8h81N1L4f413HKIi78ObZ4mZ5tDXqdIcmBsmn59YyELvCbVHavCzTqUPJR1cCSlXtBrRWXHqsmVV8B6aXXBppFy3WRdg0X2jphdpd5o"
    "ZTb1quuIknFdMoiUp1bVVKS2o0IvSTqsrRxTNcUkDCamHUKZ1wPg9XM0/bXBVz6dfEUbN2w7wRYTiV3xXqaZb8PDbUee80Av7Bi34qZc4sXwIvhF"
    "wEV1lbPXV8SoEOaYLVtv3rUmkTCZRWsQdFr1l6TR3OLSUUuW7vAQYh0rv6gbwkyI/B32YraI32bhVtoksh3CKq9q9KyE3RGcbkyPlp1YjScoju4b"
    "1fG5K1eGnvtwArzOAO9bbs6TnSfLT/afdJ70ys37iFj/ZUZRg69bT9aetJ/0ntwUQHTY0fInK+VPuvBN+flrUJxIgkOQAi9MQPBvlkboPtl48s2T"
    "VlEO1YH/az/ZfLL+5KD8B7z4pmmc6MBbyi/gsa2i/P0Ovg2ee3NiemZqQrAScPjdcpB2+d9O+ZLyoaIcd6N4svTkFr4AfzT/3tTkeQItoQm1y9ev"
    "wUz2ykeWy3/KBpzlqj50Z8CzK+WXazDxXvkHDPZbLaQMHmmVQ2yXy6TBIAHqd5MTH2GdK3djpY1bw2X34Ad7OHF49FVoyC2r6ZSj0MyTkQGcTKfc"
    "Gxxjs1xop/xZ+WpPMzeb9tIEAAO+5yGb4hBLMFkYZKl86zru+JZ5ftZ7TiHuy6W/P3GJAf7KH+/iDMrN3Cgn0+VHE9ewHGqn/Ba2q5x5t9yKDVz7"
    "SxPYsZ836NaTr5+swgZltJLyqwOkDBxlE/9YLQfeZ1oMfM/lw/v4P9ws81tokMjAExcmZ89PTc/q7h7ghvYK/HNZNqU893JT5rHy6Py/zk/OTsqU"
    "l/Dk209uw3yWcT77kU+MrxGfGtKM3Ci4MyGG2oTDKLgUrEjuXq9QSihHHip45gd0C9pVK8cunwTdU5yanoKKWeoEAAVg5bEswfl0cKBT+P9AqeWH"
    "MPpWgYTSe7IPBVsejDTV+Uksg468/B1MZ8MSaoFcRW4UTEZ6pBSnhoelOYmbyzbek67/pYXcwr2ZwCqmj0saxXpTe1NadFO6vCs9mM8B3tQD5BdP"
    "bnjDmfqmUaggV1teGKKOitO7hUfSfdIaLZC3bJeUoL+gceGIz09cmqN0T3qDlPWPMzAyAoWfukzl0FdO2xvTKxKvBUr7Bu4QzGAdyLT8YjgeJz0D"
    "fbuDRR9/f44xpU2Ph2YTMnNZHpbxypNfA3ZW+LS/imzdmyBMhrtzBHVSlybGZ6exPtnSfav8Rwd57QYtHs6wZR73hgxrH8+8ePbN519867VE6aY/"
    "sj3d8iLAPd9yvy4/N3wTljEzgX2nqd86gObMz3xwafwCdl+aoE+0MLD8NZBkrxyf6Ga33FoUXD36Vxc3uuWPA/OibS1Qhm7ZQYeek6w328FYIbpk"
    "Um4KS3ihUQbQquGdsEa5/WNmYq1h71XzF//lIvQss6+CDkVj0JpICw1lQtqcCF4L1/nrwr59g5gLcMWdsYI32lIN0Uz5nyXkYj34DOW8N29oej9d"
    "nuqFCTgJbNFhmyLB3wCVN+EgXTT0/Kvym6lpamUbvr9tZrBTssJNfKD8dFTI+Rbx3FvlQroo4G/CXFvlFHfoXuJcWzj7kjuMgHIAOXGvvvgCAkO8"
    "8sKrr738EtHfknB0pWyLFTyLdeIFZvMX730MvUiwdHNy1lsL9Gz1mRULXWKA+I8luUk9mjBMd5PVF+bYpRQE1QZnvw76VcETZHEHq2+NcH3s1MQc"
    "9WTE1oswFcCtAiQcmgnc0ZsFvq/95Ab8uIX3Gce5hZrRPqaZl0xqfCoUsnTRDkiL3EAC7dF5T0fIAYq8M6Ii5BZKQORVPdwGFPC98jRBc+zBGv55"
    "fIY0sB2cxxsM/2Md7vD9Zrn4XdmkAxkdxmmjMgN6bzE1SfJvH8Wxqmq+0nvm0uQHk9itdOL8hxdLtjxVUC2naoLf0Fu+KX94i+Wx6Fj0T3DGN/8x"
    "NLCha6v7wpcOd5I/LP/+Pel+63yl5gyQuccU+VvT4cwT2GAacOYmqWKk7L5S3j7aySU8w3PTdOmA0F+av6Sq4Gb5ixuoSAFTJ84B6noLI0/zGFTG"
    "w4AtbanuR/MAQYx2B+FTaxEE3sEDPOG3veoImrlyGNS+Ubeh0XrlF6I+nXVEjQTMCST4JOi1e7zZbyW1Vt8PihNdQT5hdNJZ0URBsN7i7+Ad9Ip2"
    "+fkd2LmPaR7IUcPATIJ/+SE7vFHw0w4q7FjcgeRFu1merMzQqdcvJWjM8idP66I9ZlzsnArPVwj4AwhDuESvTbxf3jms08HtgYv7DX5zbnJuiqeO"
    "KijOCaZevPoSzX4V+EqBB9ZBCnz5j+N/mGRjFnZzDbfhzKUPSjX1f447HX6/NDxI1X/z0vSF+fPIX2UGoH2SGIQLgxBO0kLP2FRGHSjKP1lKULcy"
    "6bVFpq1q1Hu/Kh/7xhgjyaesIfLb0i6AM4R2UJfGz7OavYlEx2xmW28Ebs0/TY9fYgpnS5UOmY+OWy/hlq3hJXyRuTld2g1iM5Qg6OiIjpUeARqF"
    "173MNSDlR1+j3QgfvsD9Czk5int+QJqUE4vW/DzLlWpowW/iTX0F1UH6TEQib5i9KDwvuj20s2JIT1yYHCcCWWHr/EWbm1KO2xXFdpk9G0RcZ6V7"
    "kzFu3+xLRFk0Gmz5IgxKpQ8p02QNvwlVVixogPJb+OnZuemZGdkB0EH2ubnApUvzM3PyBRhXXbJVS852ESUwjYQsBL87SzNwrTP43DuoTQ1rx4tX"
    "Stu7NEMvuDvIdCDVawoFQNfRKAd0sfVBZg/lO7UFnvaf/L8/FZLwUf7pKMTdHvG9iME/rIOkf1sSoftQigXMRyj+SVf0k/588xkp0/Lycvxy+LNv"
    "v36WCFj+MfTc5YsMHW2mQa1KAUu6/NKNgxMQWQJ23LCbNjwpHVDLxyDZqLgMs7siw1i2CQMpD5TnaBBFMSyfKY9zjiBNcQQja+y39DvGQoRGIWzJ"
    "lxry5CUZD5p/kMjCoTzhRIdUzoyZJNhPwGk7pOW5l5Khhht6GRyQiIxTXkHAl0A0H9IWisvwF01bnmL9kf4qFQl5plQ+TSNUaRFLzW6lwdU4tZF9"
    "74q96m3Rf8msRM2wLVK+KD/dJy1Vtr2F4yBlwEjQnXVC+zjPjn9UuHZa1qp+b+LjafTkTM4ycy/1c9uclTudjIioXSHZ0WIN3bwe9j1lXts54h1c"
    "Q3l9iyxzI0dK4Vga3vS+06DzqqEGzibPl8NeK9aGCiQ19uUsCccSv7BpdvtfqJlYhp+CfrX9K+4rBh3n4bVIs9OoOsBHoI7CT/kp+BauQ0ngQ0UA"
    "so79xpxqyo+qP6YNRiv90PdWRL6xDm9fhykTx3EvQ3ELuzItGrv65HLvbgWvJBMa/02rU4fUPqoT9vabjsfsoXBu8YgRoDUM9pT8BPe7zVL6bS6W"
    "d07osQLAHxWgns78AmHCzc5ZP55RbMRrLa4nYcmtMbo06+SnZ+d1wQIDeAD9wupF1vXHcsFpKXaeE38EriCbkppoYobo2kMtR3UcN13yaAS7t4K+"
    "g66wpxZS9RIxs41ANZFWzEBURII2dd1aSUR4KQ2Hwh9sWcM3YMFsGaol59XkxEcgVeYIrgIhwicuUAtG/7DIJ+9thfGTgSp4S17bQi17jQ5yk3xc"
    "wdk4JQcSlf8wOSuCDOTxsMou3Dlcg8jR804fbImFUhjVUC2EykGt6YB6YFHquBchHDGjiu4GTZydFajhT85hmyoxjlYKZHmigL6o2KLF++VJifJB"
    "491CRQP9HVZjB93qg0uTcx+LDqy2nwXitgfp2OHLFoVEdWaKfu3hhnRYegg9laJhXg2l2UnQjPxuXHwlJ+dGxElkTo2UO3Sj4e084DPvkDm7SmSt"
    "hAZ7fBM5EgwwwlMRHzFjP0XNwAKoH0FhGIl2wXjc22RRx7R+gB6fzXIOW3SQ+6lpfDQ+W5y/NIHN3rjvpgdS7+McVswENmOPvJzgldsAub6Ph9Er"
    "fHfWLeQUt8QhtineAvIQMdcPYzUkiIZcEQfc1vdD5dK44QwHGiqsLDIq6FDhR0za7ktfMfVbbyfwm+zX6UNEEAD7WHkw6DlaRnHVo7PbK/+5Yzha"
    "9ixxUg0B/PBGjgtwyAvU9QmOc8w1KmvUaC/5RlxH+EbUQNGpTeEK/939vbcU3CygrjgMvctoDbBRADJbH/FPXp7zjjNQcVhMZwipjQdhTRaWxtVI"
    "QdTq/A8z45cE8Wvcwar4OBfeb8PDR3WNvTeewDeUY+iG7XnkyXNVyAZScGEUeynkScIXeEEFwxhXSYlGbkjxkg4FjIwB4GmnqjqNYayTFIBNdZab"
    "lAQrK9K4FSmAWE/38B9HX2JbIi98vsYel36IGtGgfAaw1jTCQ7EzRZavgfz0XiXDa3IEW3V+BGascKr1En63RWEwcD+RhafvhAcSucPl8XooXbQW"
    "1HMdRSSCMC4EY8QonVl45uVbLlxCjQmq02cL9fLiWVyamBr/GAGP2Z0MqkqnoF+UxyMcv20dfu5nerFQ7EA/zIu+VAL4jPenpj8qLstfV0RmU2iY"
    "HYo7FL7qoUDqkKm5g9NZkXg1T8WOlAPLLW0PToopLvMfPnA82rNk56Dy1sH9g8O/STaEpQawZExejRlSu89NkBxMqEKsCBVuAehThRwPVBPnShb5"
    "HsQSYcMxZWj80sfFB+VhzZR29IfQJnoaepOSO2L4I5D7FzEYU7KikeLVOcCeLM3qct3jkLTBaIQffQiL/+jD6amJYf6t1RBK4gKjAqlMC7rGkd3M"
    "zp//kCNHI77nsFAnN0lkCnNzfkUX/7knIv1rzEDSa0P+P9yFHaRPMn4hTASaCNjoaKusE0dVF+ZIQYSN0Xw2T1aArNkZ0AW/zxKSRYXqchCMSs6i"
    "DSDqXTSwN8YMtzOccsvFx1rwo1XSEBPHNxSdnSSs8O7/ikCt1B01N/4vcpCzLgKLkDOzE/86Dwy9tPCpDy0fLfSIRlBnACPFUKKG9iBtolSUp+Yp"
    "5WxKMGyI9U3PgycdvsUqxHLSTU92qKg42LbvzPI2mCLDbTI8lyUZzYsWbjLTbMOwe09uczx/XUyvFWQ2rQIPHURFr3AxUhIdqJbSWUqyAP3rpqr/"
    "dpFkz65RcGMkyT1AGWAOUlpms5i/cBl8BLMBA8HBd2CaJAUMO2kFDAX4x1q58n031NBzL6T1dkkiA33MV8dNtB+DadhZC3UiNucCC+4WTkqy/l5/"
    "9Y1XX3/79eKVM28Vsori9ZfP0fuy098Qt/OG9UEHDLJieFj7C+fOvXz23MsvFS+eee21l1/EEP9bb79ByYJ5LmzfWOoG5C/St+KmmuQA7/I7/7zM"
    "C6by9pvFuTPFWy+/eOatlwyC+plXxFnk70Ur3olg6b1C/JPqk3QKTOCIAiP6jXMv//Nbr577fXHmjdd+DwtI7tobZ87JwailXeAVKskMl90H6QV2"
    "/BulslGUVDdDSTmuGhx9KKQmXZ6eQXK64vIUlskzvGQzc+CFy3Tn3DBoYbgB/GgPyRQmU2KqbS/tIHj+g/GZWU1BIJpe9h5uhtlDy8i7hA9wd/bI"
    "x9zCo+3Bn+aUl1XvLOVjxuAOW4AHyXAkp7Zgw26nzW3/fqf1GkIwFk95ChQOwwaQuCZqOMiLUlxAngwV2RseVkfs9sa1mNg3lNxuVpA70qnnSZYF"
    "rslZdsRPI+wdP+1KGlQ9MmGlNr/svG6tYeg6REpAymYZrdXSaybS0LgfYFoNjXiTMp5A0MTc5xZ7MVQv3aTgU7Y/QTZm4VuuZ+dn4P6B1qEWP+bT"
    "ApgHI14wBUv+NHv8yQl9Y4isDLZKb2HsdIN8Ux4ja4lAO3GU+/ImrlA8jf1Jm6JRrvvhJOWwK3iG+/JBwlLFP3YksLFHCXkjPzsMvU1auwWLwYMz"
    "mlJPoj5MgSOo/LqVrpX/7ICWveyGWhVGiVKojRyuRwS16YiELLZNYXJ4uh3SztSRMPLLBGcPSYL5orkw+TjqBpLDsrnycDLshF5OuIdH4O8tctNo"
    "siIaPktyLdjb2EX7fcP4IjaoGiH2Aw1pQJdyme5w+HTkmKjhCadEgQv2Lxgl/21rUDcvnk8E49v4Z6MhbE5+zsO7jX7nLundvyAAbxYVmSnyt8EU"
    "USlDF/uO+AQPkPb2MXoxjDPVn/JM/dw688MNnTxKVpPkzDPHwSV58uTArqs8i1GE2Ak038kFCxnKiE30KVcDV4sDAblDapD2s0Of5gNKDUYKh5EL"
    "xiMc8p4TQofuV+upX8UzAXtGodUjd8UAvPOkIJsD6VJHvZ50WaI8+bQc8hlZFpXZLzLKpwL+raMxn0wMBdlenHo8Wp2m1OV6rJbnlmxZH8yBk/Q4"
    "k/3y98uF85mPFF6wJryAfpgC37/L+kWHIxce12gP5zeSrabg2upW/gzwxJgysY/6ZUdSb7ad5bnsriqLMtwzlzxZPrEqe6xOpbEiHOeAy4PbBbsk"
    "1h053FTjRd6pufgjzwhf+NhujWF5a7K4CPSATXLVAzPs8IzKfesPA5hLltdtKsHXZAcG0WdaQK8O7Bczd1zI2hXbbWLiUxuLAfIYvijmMClquUrv"
    "zMPy6tuZ566JWr4sWeNkGjdA3fWHOsDcDIyKeNkZLc/tlQLT9Q0SOi6TvZTAy7X51mucBB7C4nLO2JIzdP2S7hAJF9fSltXQ9KmyNwa2Ff98D+Pk"
    "7FuV+aaQazE00LG6JSdowYX7JgtG6yqsyOnWMvl6FUizth7P6kN9A8n6GavPCEDWK4IfZrxY/ssO7eV6wjtIO5XiXxodt7WN8ZsVSRC/pTU8FvXV"
    "Rdm0ivsZgrzSmct29grLBka1mo/lnVFmWX4OFT7faLOLYh8JdBCQViHCPWTEPS8PqOVRWQJ0Fa8SXKZt/BzHOi7UajhmsmLXjOBemijfHQgu9Xgz"
    "YCXlhKBP7dgtJFNUaEupp2Pg5zukzZvskmPjm6q+d4toUWPeHsn+1cKXZt5aaISCxRM6srhQsIt8fItSAQ6ShbN6PbCQmlNTD9gbxGpLi8XBPlLR"
    "kotEKPc2vmIiK4qsNIMXNenA7mmvZr4GP5RJuBlsKKoCe+T4QIfrhk0QB0V8BDZojZ7ZxZge17WCH8IAhZDG+nW5C/s03AZ5nZO6vcmlHwG6toCf"
    "upNtD9lzxIP2FFe7D+iJer2H4kmzSlQ7oVsSVrIyAtbysqlqx8orohP9ZL98LkbWDBN78XGmwJEYGdMp9rApPjTmiBcrlhY1w4h/ac05azFRKgoe"
    "kodwiUKvA5Rfse/I63ZJHm3gubVVNJmE8A2i3TSOpaFVHH6Vjbo2VZrrLeDZALfD51AhdSiVmfRD3wmkjg/SqG+h5bOi0JOoppOraD+seNFMC9WY"
    "AjhJM9t//Aen8N2kndguF7mnQUepSeCCKUotUheEK/qmyEX5jxEP+ZHK5ikcQ1uMO+KOBbmTZLmw/tnhj1q8uUQeQBsjBrfRL1bx2hKg8zAAY7SP"
    "m4c3XMUIBlVHKM+tzWoW2piUL7Un/lI2LSmODCuubrOgTRY2KR2nkKYEFvZQ5LJmVnHoRs9WZ88TpF1qm+/VttxELifekZEA2FDMs5Fg10ye7Aad"
    "ooIRmuHtBouJRSdbkkwSihB3biV5Jel0xRzIIw+OFOEMWFgFJw7/GElCC/qXg7nWAfdzINhAZfsEHFj+cxuNYnYXMA5gqn7DRwqMngCUQNuQzGnw"
    "7JxnB8YyKq4wi5IIfzNaSOoQWaHE/qNkVsHzk+PraWMk2tyDgLBa0goLDmyn8L2RkqBUvv/Xo0Wy18eIQdKLaLbFISVXg6cDjGj63gYTcwcysKLq"
    "q1VKzNi0YsXA2Pn7qLY5tjppEB4fYvOqbRsFaaOlTdydTfHWbBTcDcNLNW6bJkEjBQs4wpAbEWffvmvF7E7u63JbGDVuzHIgjcdsclrfjuH3IyH2"
    "G/MrUgOGpE2Z0Wfygt+KEWxM1iUGI8umwOYtPBgZ0PHinkKwUahE7nWkElGjBGB7QNPD9nu2zniWnJA4ksZPsxKVkxT5Baqm7hKza2kXE7yogooW"
    "TMTpEtmlM9d3GQL7lAWknvcNpLg11pnWiUsKxJgIuAheLDgjL6bpt7AxTMo4SHWSQ6rat8KyOObzBvMrCKBVaUZRXRYLNR1BO/GsufvQdm03gszw"
    "TfL4wbCeKHdylPyvArplRdcqHTc5j10PIHMyq3o5vU0YMeyy5WdGml4zS5Qqa5KaRGJr2UAbR9yjBALqltYBMlii6WxI5ey203YS2FRSXKay31pa"
    "+diECXwOFVFKg03s3rB+Rcdt4IKEUeVNm6ew5CWXwABxgsBIE/wn38ElDQyCNAJHdbZYDNOKg3CHFI+1cdQ25ZeuG8odiiIkycwMay+Y6xUFV1z/"
    "Mi+sMhK3XVj3rk9QZD6srULIRQfu2x3iNqlugmNe8aMJwq6jxteilJzdUlbsiO96Sfha2Dhy3fresIhwTQIGy8RexD3bwzro1rDJCqXL2o2zPYaM"
    "MaH1iQfin1tyTmFuq6fOy5EIO+hn5HsDJMxt4g1uqXpqkmHoRzcLSX2nU9pRuuJ2JMFNWrbJ8+UBjnidNDalZ8JBTa6SMEFVx7eFB7cLTpbfoHCE"
    "32hvJO7oiQ7gd56Dbb6F6u6SK37RC0sZ+N+QEVp1w8y+7zi3yS3imdw+wKRQaXUt8vIxvswe9evsOiLdrRU7EjSDarl2UMrVjfVj0pcPpN+ZkmzL"
    "piwf4NQxJ8bPLrF8ROsiirA/iFqAet8lvKir36QqGpE66+8857Vhe+e5MZKSqshuuimRGue9Ux5FUvdbaKmHYJOD43WiIEeF4vLbrkqhVAJ3+q8p"
    "t+uZl+dq7trDGClxd1uG3fWaFw7JyYULCMf1wt4jUYPhgpe4XyV0vf49BwEhL0vpsyjk3q3eIcfgiskVr97k1K7uSWLBKimqq6at9EjQjI2rsYg4"
    "WpYGkRt/jdHxHukot7hSsoOB84qchW3cj+WEIsfJFDTskuvRuGILfFOU6l1CXZKmmNY3TpaI19eelyboHMCub8nv3UCioUwOrDuWdj5bopSi9wX+"
    "XIEv2wkpZztd9EaKym7OSl2eahU3VXFziXJMXLPEHvXd2EPauKXx2sI1mBtzPHcrILh2QLUt3I2liKGbC1xOKVzegW1mB9uwzUWWrtplpEHXUbEN"
    "VsQBto469M1Y+eRpumJmlAmklmiNpq5NuwTxz0Yybby5ZwdlfvS0er2Q3mqk4x+4tJAWtoNruSac6uUkjYqLI9Y0bdC3PLBn/XsXTc/6p3v3nu49"
    "erp39eneYflHsnH9072jp90/yZNt/Punp3sP4G/45MHT7ie2pf3TvRtPu4v47dHTvftPu+XgD+t629P7n+6Vv/u2wDFphAf4uu2ne4/LSZZffIXz"
    "gL/os2/lV0fB2+I++E/3vsAnt57u7ePwR+UoG7KEP8Gn8Pdhsjk+vBae+U52YLd8ffn7Hv6j/P2XT/fuylwO41b5+KZ9nGP5TJffuncbJ/LADFQu"
    "Ab67nWihj78u13xY8NbsPcKtgs96OANax1aquT5ObBeffYhvOLIvpS/u4Wz2yomme+7jd/SOH8spFLiix/IR0ccN+rW04X+69zlvOgx9PzikNF4v"
    "PEBb/UjecJcOjJZX5CjSB9TivZavkUhTDfxxHFrCbXzZboGzpo/aSpZBP3/82WP+8d5tOZPuYrq9P1Bf9//QthN13xXSW0SCLN91lEHdgBfQ0e8V"
    "lnjClv/yjh4+weeYBCSC4a6arXsstLCLH35KmxDfQu/0QnDa6PlCWMEiTSUJE/B07zNz3LTdX8iObFkipe9+rIQQkFPZ5etlVkNLXpPRHsZgm0BW"
    "n9D9St+qAUAGcrQ6VMBFdAv/0WNulTtZyG9uEG167OAhPln+Zp1IsRKgAHe6J1O8o9S/j2/4j+IUbsECDl4eyJc0R1rEUbA99RgGeUHCr62598or"
    "6WLfKf9NPwKW61abQ0AwlLRHrwg3DtZMb+4bIAE5Rk9kyAM6woXspN1h+hSa4WrNABVyA9TRi1u2KWeEj+F015SxLdAlHhyEgT/DfXogR033PL96"
    "3TkmMyYL+G8bNxFYBP1oV6VjcJbPBMHhWBPeEqly31C30j7dg57RDZAh8OSGy0tYsWb4Edz9/nEhgjGFSm4n6EeVIVrknRMAjOjj7dlLm5TbsBf6"
    "XtH9FvtFmfDkEP/xWN6OKh2Ijv1RO04hkybddh94/q5IbzjU42BOiKTbwrXq0e/7ah0fE29SkWT4Y2bgcMrHwqcA0c4a9j6dV9XMuiRmxvCAgfWw"
    "xPFO37LL7Pob3S5HCicEdmEYwq7yNVpv/3MaLVjZ4g1aQ/57SDsSajLWEqO3fYPa2n+QjXKHlQmUPJ/j6xef3tnNQmcktlxuYnjvBwfUyCsDiaU+"
    "8FXVXWV/i3z+uLSviDsEu/OIN0iYaVs3qXywg0+t0e+/wxe3VSCxPk9bVYvLkTGGeLo9YRhHotw9QN0F+AbuaHdRTpx5/1U1SrJQHniaV9EYe0z2"
    "2Gd4jR77xHG7EbqHu3V7K4GMvicERCdwO6BNIr7DtNqa4dW0qQQUUogtBLufxwupnVNOLCBl3CfWQMSxqlcvAhqJHQvKtA9ZiOOvKiFHxEo6tCzP"
    "Iy8+JMPH7qlNdy45Yv/jOISSgBELRon+6/ds0VqDZCECLGksiGMwk350bx/rRE7iJ5opI55Ypia4J8hRF3zkE3hd97qQzTe0PAuE4lgnbpmAoeCe"
    "3tb9MXAoDYlctLAAM0WYxI/4U2YPEYAKHlf6QYekgiRNmhK/6KxyIuU2XdrPV9SL5XxUSWN+NrnC0GtjsKeZ0T0QanzkI69UG/fBuIzKEjjSGJlF"
    "9YMwstRUmSbvigvT4XS+NT6YDYfdIvLiyIC3kD5Cs/bgW+KLd9bzZmWtuhSiCx69Ht89s7OPG/lkDOCLvBN8Rnv4qxXVVw0AjIiPB8L9Yc88LBjd"
    "jUK8edtEVgYQRpjzJ2aN7RgdxknnvVt0lj5EjOETR6JALfjSGKmdfptAjokdqUkl4jZ+t0anH8HKiAuFCGirYH1dSFzZVIQ0U+vLSo+TAKLxefG+"
    "nPWKkmzgitkSP7R5u3qtLHSNPcx7xn+zbQBskO0skNHvg9hUqCgMa2NVAw/cpoKsDd6NqszsPaF9jnBvkoaeQS4R5JucAmmRcJJarcPEqT5Tg5MT"
    "UE3ENAk3R9j2tjUfQxAdE0LpWdtG36lYOupWzoLp9KEkpvF1avUuj1gUdQffo3bmI1nGJ6qocNjBw+TB72iZ3QiXR374jURr+CQDkB55TNyg8DcN"
    "uZ9C7VGv1FfhUgxwj1D1I72/OQAf92HKjHLhsr6BfGq9p1vsCPVOFph5Iro0IOQPHv91Ohs/+czTLMS88fzbx0L+IVZQ2LeYJ1UVagD+oyNFahyu"
    "7yF+ut0QB0gHC7Wg42EC6bC7HMiRDY1eExiWVV5UT34OgBqE91lH3KWPnG4+KIhQNauzTBR+MIxS70Hq+GDUnGvZixGcPNhQHGr0XbXxXC9eUaVs"
    "VQ9liFmGc2Uk1AVa/Y/4o59S+iDRimITOfcxmdx1OEUV/jYXnuI4GW7slyg+HjQIzsTgRtWHT09l4Y3chOyVQb1gb2UgvKOAYw1VXSe3Gc0Dc6Fl"
    "OCA8Es7UORgyFCCu3kqm0Pd0GyIr8XHwI+7WJtItaOyTgVfKy8h7nPmATvps4sJYEeYrGM77GMcije2etU+KWtGcjkok7wub9PzDxCmcGNJT7awz"
    "hkLd7jVb6UPUtO7RH4mV19i5jfGj0pZCVey9rXSpRpTzHPd7Z46DP2VTRqr2VdRp2NA90p1pj3u+RXiIp3hDgzF3ect5iY/k7K8GvN65UDirhCyW"
    "ANZKtuQe8eHPrFIW4Fp5aly1uyNzASL8qwoe580kAYVVEWTYMmr0vpjaNvzXU4vMQmdFXow7xucJZ7BdiaUVq+t61D9a7Q9Xe0jmhEXZwiWv4s/o"
    "5rBfzgPcapLVxzSfAOKS3+ktYtPSs/0Hx+VKhbhYvlfFvmrVX/GcsFj0AmO1fjefEEmbOibeVx+HQHfhsODwXSrS9TD9s++C0CvasHhaXc4rEG67"
    "WrO6/mHEKg8EZDGeamYApzZ863K6cLq77NRHisjxX2JuuJDB4caS7v7mGV1ONxwqmuQ1OrbrccjQkH4GSGWjCRKxkjvNILOykmSLhFc15cFxTufL"
    "+itBOMNVPozeGbxNpYGn09JivnumiGcxJbqng5BJDfJZI6umRuENKfJkMNJywft40AqabEp6ab10l7MPREnKBylPGnhNrf60whqkwTIn9DJlEtZV"
    "UWNia8LJWJEMnaSHTKrAkiDYHMQtwVz9HwkZ7gm13VdFivl78Qxh3XhEVT2apvAktjGZdYUHbrJdZDZ0M6NWqah7P9YzrDwGEntNEeKqKC9BZmnV"
    "r/+kq0bQcviQ8AKNu2yLXiNPCo2IhxRvbCKEXmevDQRJp1/bEKvZyrv4B56x+x36Bs3rgsQ72urEDAdErVMhhSb0PmpTHBm4yuld6FdKF7Q0wa3L"
    "7Xc/dsYvCNwuWRGkuTheKHCILs1WaFd7lUCFE3twhXtBItxXcexx2EyBAlOf6IOLRP73Ze8f2OS9e1ID9MDLcqMfM7OjSFgX/3ufE3Mll3EXzct9"
    "eosaTRwe827Ydxr5o3+saoIqhdkyK0vYNuZ+oAJyR+hpccz5y9PuRS8BzONk6Sw25lDEQ/828PoGINahBjTqEXRlpo/oWsQiNpQrpINajobV2XI/"
    "tNdD6qZTg7N0adYp+tSpOL3dIxB6dy5IaIn7iPk7EFSv4OI4YWtK/LsJCRqml7hEHdY6Q0n/VZwWe4+W95lLNeZJfhuksbqbQhQ9OHBhAxkS5l5K"
    "4HBfmJqnAzUDNcTl7poto/Efp8u6GgvSNAyil2gJP/hSKOUTZWRZL1wFUmIUI+SMk5AQ63Z4YMBEST3+E+dY0JVATpnWWXOaQZi73/wcBgBV7Ivk"
    "tPQlFXI1RkUqSCzRLDLrB4FcrJaZCZdssK2hr7cBWThCrLyFA6A3Ct80nlDULkgW9Ebdw8PMkd2Q7ElBc+KeckOfGJATpREeB8k9T8M/1o7kpZ03"
    "hoT0w+9RhD6ozg7DWBwY5aQjt5YGxm5fIJJIyKty9yIR1OdtVqp8oJNqngz+cwBS/myM4pTPKcIqjtNyq1O3J6YGkeqS2BEqJe0gxWjRJINyqC4t"
    "r46HgdnYF1SOBYasVzj6Gcr3lA/jJPEwB5liPPpQ5PAl7lUNi+n0WFtV5BhfovNAuvFXhRuzLgO0L/DM3O34jFJDTcl3UCzz0Chc7fqw/MmiawY3"
    "YJcykawm1tN9q3b3SH3XIvniDtkhA8+sWp533+x1pkDrqrzikD3kLrc7d7nFa1bJ3Ekk/rwYn8Zr9jjYWSbotP+XsyTVFrOBRHhmVR0KLlhp4n3W"
    "hnvsZIUpmPQaahSBXchjPDRdNDas1GpHUfvdMKARp9plc3WLVGmDiwzsaqqFc8rjRuFx/gIRSmsDBukUyxrqr0uqCQ3emtQkjxDSNGqbRtS2jlDv"
    "lzdpz89Fyizn15AucU/d8Ht+NyATY3cetUofO83uc61F/czqAVnfwb5bgLCrR45j4foKcXm4vQ0dAsdBba1MRTWpFTU+CnvTK5h8kAhdmX1yfOzX"
    "fqKR2v2Dc1RE+cPfeMrx8cKTXkLtLwhQ1oXLzXJyM848HCwA5xk4BXtS9x5Ji0TvL2pfI8kXutjU24dSI/yTBuZc3yCj+wYTyKRV865VtEY4UXTb"
    "WDfN+mUjlTatp1IK+FaY6xsGckPmUIuBG7vq/Qx79dPr3lav43N1/D0b4NyhBlJuHb93FJrn8vAD2cr0BNVOOQmY3abGFNyyYFzNm/m5sHaPI0kH"
    "Ep5GpEvp14mg9dalPwzF+fOePTIUyp3vbHOpXEHNVrWMMhW2rltNTc+tDBpw0FGiRq2sFJqhR+lvHUC4JhdIcy166eBS1T6zbBqgH02Vpud0XA7c"
    "JRMhjkxjq6Ns68uqQK6nhZPWXmX2L4irkvhW4TdAwEkPB1xVAprGoeUZJ0OVHq5CP3b8MfFKPuqmOT3JbBVS3p85PnI10/R0KP1011QTrOYXpZxF"
    "XOA61Sq1LpHlO5asU9DWO3aKvoXnunzUtap5FiDMJxZIcC3hKl1MY+7t4Q5zsz8WlDT1hkyiEZCzSKptbYHnyWViBj9qqGLNK/ioAnS2v7Ve8gdi"
    "63pkFKrYj6JMmFxiWB4TuqYas0B32JfaYDmPDW3Lz9Wx5LbJ+LP8LWuIF10dDbPm5n2TsuP1gJS0B/fiFKC0rVvS0P93QQ+AhD2QQJoWteCR/PG4"
    "pjVVAok60/lYOEoCi1ooxWN5hXEK2kyaB9QuJUaptttADPOejuSSIFNw1anbrjRqE76YpT7IIlhnW0bruqLyigpg69realU2bN/o1+m66WeEgk1j"
    "5ks7wlfYxKceuW3MFtNLtItJxmkKUwzKh117BR8tO9mQuFB2Cu88efBsnx89yJca87tGs75YsGaHvOCx272HvnhuJ/Q8v7d2H2jbtX7kjIPPtXQi"
    "ZyRFZ/nNaUxu9xEyvXu29O8YsNzpAU+kJ2oEk+31Rh0IwvskZuv1EamZ5KBI34lRwy7jTCJuJC25jxLR9lPpHJJOfkw0cHdTzoBCpjXpG3/9EOCs"
    "oYZA4Egfdw3ew36/hk+YRl3X7TPpTg5YzBgsST0oXKVrs5Yex5NwQUkvzaZ2IYWWUDdAHXePNOrCXANB7rkK4pMRtSQNSe7lbZM1vSrGlIvmQm6X"
    "wdocVk12Tyr+PVXmUKM3nsXu+dGl1wVlcni9cR6Qq6EnTXa7jqDWJUj9H/J+nZ5BNUfTycKZp1PVHMC5h2sOni0P1jyYOWXa74f2VV24OZmAeofd"
    "Go9xaQuF9I9X0XnovDvbLv+ay/63KyhRqoU8CPW03EhGM+ps5wBt3cdXN8q4lC4hgHYVPEl2Aodq6Pl0Gj6dWr+th/Ip7iutGgfuEQgp4/ry2IBH"
    "i59z0k2QK1B+msZvZ/9fevJemVdIccasTk7epb3gCA7rHSd5KL6TRxUOcfjUufcK2/ihv+JfxYhvUiTkR5NTLj/NPVmQfXVA8k+7JfX0gtwR7Z74"
    "SHTZI1MpcBi0vHoQ7t2Yl0FakJe7Lbb+fnXFTVAeQyTo0OgrnDmGNgu5FOseBx7CidE8fPMRiaTB7dq3s5rVZooB1/JSpfYpq78qVBgK8gD33iZL"
    "NO3j02BGdEkCSeW3Q7WOikM2tLiNnvMVNpXrkvhk3Chf6S/URfkY2fOWYQXVfdsTU35oDwm4tzuoqsO4nSNB4dhuwl94Cae4C96kVI27qy6GnnFc"
    "mlLU84CLPuUablZjV9Akwg1Ptx5Ni5zp+bkZ7oIbTrKCt//oEtmHL03Mzk/NDf8dyKhh644TXvvvz2uvx2HrV599nt2xtffgzq6LVCrn9OYqLC0+"
    "bwDung+6RjeqtEzzzn3Nm5mBBp5BK04/2w2ZtrL9nj3miT9OziXbZapscA1wCFb7Xf2JbWf7mNwboof//WimgiKXm3ekO5gird9A/PoSlf/wWen1"
    "p8rXru1717DKoghkcHqw9HwTFUupi/nr0aIPcIZszGhCm+02vmINGUZSZWwn7CK7JV2TOOncpPu+cnbh34CDaGPZXWkh+9imkSU2d7QYMMd6KJ10"
    "stJH7PSIl2Okr14911DD8xPWQAfBZg8PfzgxNWP7R4oqGCdbmXICSLE6e/a1YYF3SNkYYyanKSQNTzuUzp/3pJmbVRfmxi9eGJ+avmisJY2xSe6h"
    "SOLsljjfuSdxBjKoqqaeKFsL9esjcbIiCyO3y/MZFcszfGPZEiipofK+m89jcgPXVHI7ZizdXN+dvChu7hjKItxg19FVJxIUkXOsVIxKTyWmF5fG"
    "3uycUWITx6s373PSg8JpVKfOmbNtsBV0hAsym64+teHH04AQEhgwPYEZ8jJ8q2AsfG77PjjVgq53bHa9W7K1yfMTDYW3l0rW2MaKy4iyJ5IIeYVh"
    "eIGxqkxPCeu0rdYyMaMWjm/IJEzq+pZsjzz+Vw3B4zX2THR83DCGAwM9BAUczqnoknkjFhDkKLtQdIUmbi8takU2BcjTCf0+t5nkt69saXhg0jg+"
    "qpCnNv1BdO9ETk666jmBjlOV3s3ux2w9W782V9opnC04j6oS4FZ58iCMeO+qhLunN5o9gYJN9O74nO3O1xyba+yEdZNEtwLZE00VZw4epIgHELOp"
    "9CtDOZWp9+m89Uw8D/bzCpgNM1MIl3o5DQksLegrOpfVYYcawXJPW5xGTeqbJoPuWplgOVdbyLy/cpfPNdboX8QwOa2yhUu+3KouRY7IOuzoX7fa"
    "4gQAXRuwD4EDyB1VJjM1whH0A4sZ0bIfupLvq5OC+GvHGjNOsEVYyOnNS9zQBBa45zuq2WLmg2Ne/X3cKdCEwPpoaK5X5kEirFvhhxdGCS2CIe+C"
    "irX/P9FxcpW+mZT0nkVMUmFz5OUCau1Usv6tNrFaeMJ9vFcPjWnP0q2yyrPwZWiqZ5Sbi7suYp16DaAsPbn9SFcUqqn4qL68sKcckNa4Lv5JhkR5"
    "5CyX4GJaeu5V4tLJ6fqQ4Ym8HGXpCbLx49GJnnVfNeo370mxLS/7Pym73cXIaH2e8emAA8zZejLYoaR7SthYUbEhQfuJDPN1g3v8ds/VMFLacxWQ"
    "W3WOYFztbXp/1SUWuH12kZ+AFnM9o+LMgcaKM120bFJ8Vt1Nd9fyTHo7ecsEa3bPtQt4KNdoUXXohutK6vFj+Tsc7HP2KXd/NvCFm9YLnZ5xX5iO"
    "3BzbghD2p17nWWN//QUMNk5QrNyg2YA1CfIRZlsG4TGddjJUxyjYgU0VyGNK5g0deM4HWqnkDtmUqHCXK9cR12lUt0N0LUBMK4oN7YwRGl/p21ml"
    "dDUy9ZJtIJ0z6lO86+0oj7LW45AS3rn+namC0TRsiXp1YS43kz0gk/ctbm+XfmUUUn2A9N+zdFbXYsODL02r6QmmuWtZi37jXkF7LS0BRZ8PPIb0"
    "ux9j5f2Z1UvZOM69uCFRYtahEOwj+95ZfYMx5qwvJA2+8Dq0t5mcDfBT05qFzRmw7Hc/LbNjekyExQLqa+6rGk1Au4XIARJW5f1nqq+pV8pkSB4b"
    "/ElTGq76Z9Nr2v6jAVpV2rhvgGGVaj4TuHeR1g9ZBzHHvq7WCt9y0xsIacSxyzHPkurHaZSNqVZJjHvisiWjeNcqVntNUama9r++s1tUgQXXH29V"
    "48Makr3jtYjeDfoA9RFsDTsre8K5rzMwNQiKIfpIU6MMPXzViE0ESL1hCUe/Td1fpDohqqWfmZvNYcp6R+q5xhPgr4nsAaE216GuH3gv0isUyzej"
    "Y6809m+ho/jKlf8HCKmBrg=="
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
