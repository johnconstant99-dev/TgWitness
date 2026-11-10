# TgWitness verifier sources SHA-256: ae1e8191d5833196d927813fb9dd5dd0946bbe85a5590b7aca29955e1da8b336
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
            elif proof_name.endswith(".ots"):
                proof = read_member(archive, proof_name)
                entry.update(kind="opentimestamps", **(confirm_ots(proof, digest) if check_bitcoin else ots_summary(proof, digest)))
            else:
                continue
            results.append(entry)
    return results


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
                 "concurrent_sessions_at_start": "other sessions were signed in when observation started"}
SESSION_WINDOWS = ("updates_diverted", "session_revoked_externally")
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
            self.open(at)
            self.active, self.run_id = True, payload.get("run_id")
        elif kind == "observation.stopped":
            self.close(at, "observation paused by the operator" if payload.get("reason") == "operator"
                       else "observation stopped: " + str(payload.get("reason") or "unknown"))
            self.release("updates_diverted", at)
            self.active = False
        elif kind == "process.stopped":
            self.close(at, "collector process stopped")
            self.release("updates_diverted", at)
            self.active = False
        elif kind == "process.started":
            self.close(self.alive, "collector process ended without an orderly stop")
            self.release("updates_diverted", at)
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
        elif kind == "session.exclusive_from":
            s.setdefault("only_session", []).append({"from": at, "ended": payload.get("other_sessions_ended"),
                                                    "two_step": payload.get("two_step")})
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
        hash_files, account_exports = set(), []

        def measured(lines):
            for line in lines:
                event = strict_json(line)
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
         "detail": runtime.get("limitation") or "no independently checked runtime attestation bound to this export and a created key"},
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
# Catalogue SHA-256: e539e934a40d9161427851a5962e3cbf2c878c76d0f6845a124c7b6709aa5229
VERIFIER_LANGUAGE_DATA = (
    "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"
    "DenSEeIWzruX7nMmWd1LLmS+ojBbdh6bsATu/f91GXDvp7fO/PXPv/vr/fknn05kob2fzq9tffThszNjFtf7ydUzT7649v2VlVaw3lu3/vXJZ3e3"
    "/nxpa/LuX+//5tmtta2piSyK97PpkWfNkSefXdv65rMscPfTT2aeTN57dufsk0//kEJ2b43NbX19Bkb4/W8yKN1bzfGthZEn565tfXwuh8m99Zvx"
    "rYtL+nsGitut9+nn57f+MPP9mQ+enL9hILjdNjy9fKsMfvvJ/bGtDy/RLgZCzqN25cC2n1y8+Oybhad/PLs1//snV2Jk7WfN27zOFFf7yZ+uPVn9"
    "aOvi6LMz7+fp8cmHl5795t6TT+4++fBWjKH95DczW82vS9jq1r2lp1/f2Jq46Ob17NaCO9bUpKO/f/+7tTKY7Ge3r7tzfHLu5vefL1XiYW9Njm/d"
    "f3/r64vfT0x8f3k80fPptLY+XHh688udQWB/P3vBUQydzf89M7L1u8mt+xe2zny99dsLdhmViNd/vf+hO6Ktz2f+/evJJ59NP/1g0u3f1sTqv3/9"
    "QUuoa3cj6ONEJFsXVr4f+7AFqPWTz2efXPzor2uX3ff8L/S1ljDW7oNPRmfc6T35csWt/K8r190Kn16+/+ybf3V/VCKtB1rtZmI38N+//uOz5r0n"
    "9x5snftypyjVW2tjW1Nnn340DoN989GzKxfsG//+9YWnZ+9uffQb89MOIanpyJ40P3n6wcrW/RHiG//+9WUaeY9gqN0GPf3iGo39dPHB1r+ed1/Q"
    "XdOPOwb5/We3n0wu7xGe9JPPvnx6fu7pzfM6sNtN/vefrj2bmHU3390nx8qAENzff/vF/z0zWooJTbPdmlp8dvvazpGgiUa2Fsb/+s2f3OYjY/vs"
    "2blRoMj5KbrhNCPHqr//7bWnDz7euvVHmldLxGd3lI4ru+efXXh/6/LtrfGxrVsXnkx+VArx/P37M467OCa4dfHTWrjO7tSIIzybHt1qfvHkc94y"
    "gmp2O/v9Hz8pB2iGt/G9rUlg6U8uLbjFJ1jMJBy3Jj97dmWmFQDz1m++2Jo+/+TcmSefN58+GHcbWYK6HD3ioZaJOAVdeeuj6wqt/OT3zQRaWak2"
    "hVJWhhQiJz9rzj+bOeNBk0ksOUoU5ORnE8shbvKTCyNPH8wToVrgZFjr5S8NcPKzW1fcFoaIyU40qUSyYMkgsq7cenZrKkFJhg2QXzwoMvFg0mwE"
    "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"
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
         "distributed": "Distributed acquisition", "board": "Case Board"}


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
    notes += coverage_lines(result["coverage"]) + outside_lines(result["outside"])
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
    if getattr(args, "evidence", None) and kind in ("evidence", "chat", "handover", "witness", "account", "distributed"):
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
