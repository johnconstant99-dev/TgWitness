# TgWitness verifier sources SHA-256: fb5ae93c742e37b64020560891345d0ffad9f188a02e365314041c1653845b1c
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
    if not isinstance(manifest, dict) or not isinstance(manifest.get("public_key"), str):
        raise ValueError("manifest.json is not a signed bundle manifest")
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


PUBLIC_BITCOIN_SOURCES = ("https://blockstream.info/api", "https://mempool.space/api")
BITCOIN_SOURCES = PUBLIC_BITCOIN_SOURCES


def use_bitcoin_sources(urls):
    from urllib.parse import urlsplit
    global BITCOIN_SOURCES
    clean = []
    for url in urls:
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password \
                or parts.query or parts.fragment:
            raise ValueError("--bitcoin-source needs an http(s) Esplora API address without credentials: " + url)
        clean.append(url.strip().rstrip("/"))
    BITCOIN_SOURCES = tuple(dict.fromkeys(clean)) or PUBLIC_BITCOIN_SOURCES


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
            raise ValueError("Bitcoin header sources disagree")
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
        agreed = ("two HTTPS explorers" if BITCOIN_SOURCES == PUBLIC_BITCOIN_SOURCES
                  else "the supplied source" if len(BITCOIN_SOURCES) == 1 else str(len(BITCOIN_SOURCES)) + " supplied sources")
        summary.update(status="confirmed", time=min(c["time"] for c in confirmed), blocks=confirmed,
                       verification="proof evaluated; headers with 6 confirmations agreed by " + agreed,
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
        elif (kind == "session.concurrent_at_start"
              or kind == "coverage.gap" and payload.get("reason") == "concurrent_sessions_at_start"):
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
ESTIMATE_MEANING = ("Estimate from the share of service messages among observed numbers. It describes the range "
                    "as a whole; the missing count stays as observed.")


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
                          "meaning": "Offline checks confirm the recorded beacon's self-consistency. --check-drand "
                                     "compares selected rounds with HTTPS relays; authenticated rounds give a lower "
                                     "time bound for subsequent records."},
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
            lines.append("drand beacons checked offline: each randomness is the SHA-256 of its signature. Run with "
                         "--check-drand to compare rounds with HTTPS relays and get a lower time bound.")
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
        chronology["meaning"] = ("Observation times come from the collector's clock; the hash chain fixes the order of "
                                 "the records, and timestamps, drand rounds and witness records fix them in time. "
                                 "These entries do not affect the signatures.")
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
    return {"cards": len(cards), "meaning": "Minimised copy of the team notes, signed by the collector"}


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
            "annotations_checked": bool(evidence), "meaning": "Team opinions; the signature authenticates the document as the team signed it"}


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


JOURNAL_KINDS = ("message.new", "message.snapshot", "message.recovered", "message.edited", "message.deleted",
                 "message.missing_on_recheck")


def check_journal_changes(archive, manifest, public):
    summary = manifest.get("journal") if isinstance(manifest.get("journal"), dict) else {}
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
    chat_id = (manifest.get("chat") or {}).get("id")
    count, first, previous, messages = 0, None, 0, set()
    with archive.open("journal-changes.jsonl") as stream:
        for line in bounded_lines(stream):
            event = strict_json(line)
            if not isinstance(event, dict) or set(event) != set(FIELDS) | {"hash", "signature"}:
                raise ValueError("Unexpected record in journal-changes.jsonl")
            if type(event["seq"]) is not int or event["seq"] <= previous:
                raise ValueError("journal-changes.jsonl is not in journal order")
            if event["chat_id"] != chat_id or event["kind"] not in JOURNAL_KINDS or type(event["message_id"]) is not int:
                raise ValueError("journal-changes.jsonl holds a record outside this chat's messages")
            calculated = hashlib.sha256(canonical({k: event[k] for k in FIELDS})).hexdigest()
            if event["hash"] != calculated:
                raise ValueError("Changed journal record " + str(event["seq"]) + " in journal-changes.jsonl")
            if not isinstance(event["signature"], str):
                raise ValueError("Unsigned journal record " + str(event["seq"]) + " in journal-changes.jsonl")
            key.verify(base64.b64decode(event["signature"], validate=True), bytes.fromhex(calculated))
            first = event["seq"] if first is None else first
            previous, count = event["seq"], count + 1
            messages.add(event["message_id"])
    if summary.get("records") != count or summary.get("messages") != len(messages):
        raise ValueError("The signed journal summary disagrees with journal-changes.jsonl")
    return {"records": count, "messages": len(messages), "first_seq": first, "last_seq": previous or None}


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
        journal = check_journal_changes(archive, manifest, public) if "journal-changes.jsonl" in manifest["files"] else None
        return {"format": manifest["format"], "fingerprint": fp,
                "message_count": manifest.get("message_count"), "producer": manifest.get("producer"),
                "chat": manifest.get("chat"), "key_pinned": bool(expected_fingerprint), "parts": parts,
                "files_checked": len(manifest["files"]), "chat_json_sha256": manifest["files"].get("chat.json"),
                "attachments": attachments, "sha256sums": sums, "report_seal": seal,
                "report_parts": companions["parts"], "report_pdf": companions["pdf"], "message_ids": ids,
                "journal_changes": journal,
                "case": manifest.get("case") or {}}


COMPARE_MEANING = {
    "number": "Both archives record the same chat and account, so messages are matched by their number. "
              "Unchanged means equality of the complete saved message record. A difference shows that the saved "
              "records differ, in content or in observation metadata.",
    "content": "The archives come from different chats or accounts (for example both sides of a private chat), "
               "or their scope identity is missing. Possible matches use time, sender, full text and file hash. "
               "Unchanged counts identical saved records among these pairs; differences describe the paired records.",
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
                           "tasks and their observed outcomes."}




LOSS_PREFIXES = ("connection.", "network.", "account.", "session.", "coverage.gap", "process.", "telegram.", "clock.",
                 "collector.")
LOSS_FIELDS = ("seq", "observed_at", "source_at", "kind", "chat_id", "message_id", "actor_id", "payload",
               "previous_hash")


def verify_account_loss(data, expected_fingerprint=None):
    statement = data["statement"]
    public = statement["public_key"]
    fp = fingerprint(public)
    if expected_fingerprint and fp != expected_fingerprint:
        raise ValueError("Public key differs from the independently trusted fingerprint")
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
    if not isinstance(data.get("signature"), str):
        raise ValueError("Unsigned account loss report")
    key.verify(base64.b64decode(data["signature"], validate=True), canonical(statement))
    records = statement.get("records")
    if not isinstance(records, list) or not isinstance(statement.get("loss"), dict):
        raise ValueError("Malformed account loss report")
    previous = 0
    for event in records:
        if not isinstance(event, dict) or set(event) != set(LOSS_FIELDS) | {"hash", "signature"}:
            raise ValueError("Unexpected record in the account loss report")
        if type(event["seq"]) is not int or event["seq"] <= previous:
            raise ValueError("Account loss report records are not in journal order")
        if not isinstance(event["kind"], str) or not event["kind"].startswith(LOSS_PREFIXES):
            raise ValueError("Account loss report holds a record of another kind")
        calculated = hashlib.sha256(canonical({k: event[k] for k in LOSS_FIELDS})).hexdigest()
        if event["hash"] != calculated:
            raise ValueError("Changed journal record " + str(event["seq"]) + " in the account loss report")
        if not isinstance(event["signature"], str):
            raise ValueError("Unsigned journal record " + str(event["seq"]) + " in the account loss report")
        key.verify(base64.b64decode(event["signature"], validate=True), bytes.fromhex(calculated))
        previous = event["seq"]
    loss = statement["loss"]
    return {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "records": len(records), "truncated": bool(statement.get("truncated")), "window": statement.get("window"),
            "generated_at": statement.get("generated_at"), "account": statement.get("account"),
            "producer": statement.get("producer"), "loss": {key: loss.get(key) for key in ("cause", "at", "telegram_error", "dc_id")},
            "route": (loss.get("route") or {}).get("kind") if isinstance(loss.get("route"), dict) else None,
            "journal_head": statement.get("journal_head"), "meaning": statement.get("meaning")}


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
                           "Source linkage names the original archive and collector key; review filtering and redaction "
                           "against that archive."}





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
                   "head_binding": "A second key retained the journal head. Who holds that key is shown by the custodian's key-control record, kept with its fingerprint.",
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
    return {"tier": tier, "ladder": ladder, "scope": "complete exported head; coverage reports observation continuity"}


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
        lines.append("No external time was checked in this run: use --tsa-ca or --check-bitcoin for the archive's "
                     "timestamps, or add a witness.")
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
# Catalogue SHA-256: b3e6b168d055028731b3ce717dd4fbebb8b962a48233923ac2dd0651a4fd655d
VERIFIER_LANGUAGE_DATA = (
    "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"
    "P/1PabcwV1qyGfZNEjacWpFC9lt5vIudC08zN5ad1lUxOAQBDJnpmttV0qZZJYrinMLlNSo9eQ6gxQc2u7Z4G4RDf044vOe01m+tWWn0XYHaA/X5"
    "44QEP+6m5RT6TKs94iihQpXwKUstG9UHw9dGymzhfE0r2GuphjLnC1bsEvZqc3UM0ZQCuSG/QwW7URBJpRVHJXCHtg57IZ+6XqNfrNrTpTrKBA3E"
    "jgocxKIq4lF6Zh4ppJSPoZD7P/+rK0bj//lfIt1UF46eitwkqNDhoMQzcW0QCeIG4CuFuyv27UzgdT8bumTMpaP2l4P7refQskMote4kLVyH301h"
    "VNFUyeusHpTqIOODuI5zcy3tvsflGMzlfBvKS4HtprTkcFqKGUZ8cnmaLspjbJVpoq7hYFJJLr0wSREPqbQqttfe5vYxR3XEsUp5rZlKbgTf5i7U"
    "EE3B0bwdIIdeqdmXyYm3OK9cVWIJNliwbpZJ0i2HJL9JXhe++LE8JX/QSovs+HwpLuUAKUqv5ehyorw1KKJKdo1QkDzkpz7fo7AFrKV5r5DHYSqJ"
    "xPTPQZtrT163wdZb9xoMma+9UAUIp/xocpBO1nyqt/6Cq7l2yzG3hkFjJsYo1Ynw+dLeonDLT1LTu8Xf8Vi2WzKtVLvhMrvKzT4/knxSNq9tpsFe"
    "wSbrCfTsuV/4ACkTwPnxC1AHxap+DcEmaTR6nl3uFKEp5jGdvFpQ1qVzGJE07iqf55LyKie5iPkahVmz87wJy1ePrMyrq0fWb64+/PGNh3e/7rx9"
    "tvTikfWvf2q/enFj9Yy+daTz6Wrnw2uPPv5hs0tH2jf/1HnnTvvHt9rn7jy8+8rGzZ/aV8+W3jGy8fnpjVunO+9caz94p/RakfU3r3fOfb/xlxc6"
    "b79XvFCkfear9v1VbOHdV0ruEGnferF9+3TnpWvt114quzGk/cqL7Ut/tr+XXBQC812/8nL7veuPVs93Xr6hLgiBZVi/fLPb5SCdu2faF9/iVfSE"
    "nMOZLLsKpHPp0saD2+vvv9D++t3Ox/l7PzZufSfzLN760fngWufeq+1Lz22sPl9Oj52Lb2288n3nzTudizfzN3x0XrnevnW/C1ttf//n9fs32mcv"
    "wbg2bt6GbS2adPz9ozd+6naJx8Z3n8E+dl768tGVP/e8raN97sX23efb9y89Onv20eUXC3o+71b74u31Lz/a3gUdj764ABTDe/M/q6fbb5xr373Q"
    "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"
    "adcPIBjpFYr+m9Gxlxv7t9BRfOXK/wNveSEr"
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
    for url in args.bitcoin_source or ():
        command += ["--bitcoin-source", url]
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
    parser.add_argument("--bitcoin-source", action="append", metavar="URL",
                        help="Esplora API of your own Bitcoin node or explorer, used instead of the two public explorers; "
                             "repeat to require agreement. Implies --check-bitcoin")
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
    parser.add_argument("--explain", action="store_true", help="Explain what each readable check establishes")
    parser.add_argument("--interactive", action="store_true", help="Ask for the original ZIP and trusted key; save a readable transcript")
    return parser


def verification_arguments(parser, argv):
    args = parser.parse_args(argv)
    if bool(args.sealed_attestation) != bool(args.sealed_policy):
        parser.error("--sealed-attestation and --sealed-policy must be supplied together")
    args.implied_checks = set()
    if args.bitcoin_source:
        try:
            use_bitcoin_sources(args.bitcoin_source)
        except ValueError as exc:
            parser.error(str(exc))
        args.check_bitcoin = True
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
                    "evidence", "check_drand", "check_bitcoin", "bitcoin_source", "require_tier", "sealed_attestation", "board")
                   if getattr(args, name)]
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
                 "tgwitness-case-board-handover-v1", "tgwitness-account-loss-v1"}
        if kind not in known and not any(is_format(kind, name) for name in (
                "public-proof-v1", "history-report-v1", "dossier-v1")):
            raise VerifierTooOld("Unsupported signed JSON format")
    if kind == "tgwitness-account-loss-v1":
        shown, result = "account_loss", verify_account_loss(data, args.fingerprint)
        pinned = bool(args.fingerprint)
        notes.append("Account loss report: " + str(result["records"]) + " signed journal record(s) from "
                     + str((result["window"] or {}).get("from")) + "; Telegram ended the session at "
                     + str(result["loss"]["at"]) + " (" + str(result["loss"]["cause"]) + ")."
                     + (" The report reached its record limit." if result["truncated"] else ""))
    elif kind == "tgwitness-board-selection-v1":
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
    changes = result.get("journal_changes")
    if changes:
        verification_print("Journal records of deletions and earlier versions: " + str(changes["records"]) + " for "
                           + str(changes["messages"]) + " message(s); each hash and signature checked.")
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
