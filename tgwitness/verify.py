# TgWitness verifier sources SHA-256: 717558eed8abc87dde00206f8b21c6580b98694696fa2b9035e5597504add80d
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
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

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
    if s.get("probes"):
        lines.append("Witness probes: " + ", ".join(name + " " + str(count) for name, count in s["probes"].items())
                     + ("; slowest live answer " + str(round(s["probe_delay_max"], 1)) + " s"
                        if s.get("probe_delay_max") is not None else ""))
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
# Catalogue SHA-256: db8b439425baa94c1fc02a4974c711c7b0ae2bf5bf661589db9c507ca768494f
VERIFIER_LANGUAGE_DATA = (
    "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"
    "8Y0b/w/Plq/B"
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
