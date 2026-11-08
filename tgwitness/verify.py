# TgWitness verifier sources SHA-256: eb8c5cd3b580e5beb241701ec02c780067755b0e2c986b3d12a7dcf889fe0704
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
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)


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

    def open(self, at):
        if self.closed_at is not None:
            self.gaps.append({"from": self.closed_at, "to": at, "reason": self.close_reason})
            self.closed_at = None
        self.start, self.alive, self.observing = at, at, True

    def close(self, at, reason):
        if self.observing:
            self.periods.append({"from": self.start, "to": at})
            self.observing, self.closed_at, self.close_reason = False, at, reason

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
            self.open(at)
            self.active, self.run_id = True, payload.get("run_id")
        elif kind == "observation.stopped":
            self.close(at, "observation paused by the operator" if payload.get("reason") == "operator"
                       else "observation stopped: " + str(payload.get("reason") or "unknown"))
            self.active = False
        elif kind == "process.stopped":
            self.close(at, "collector process stopped")
            self.active = False
        elif kind == "process.started":
            self.close(self.alive, "collector process ended without an orderly stop")
            self.active = False
        elif kind == "collector.error":
            self.close(self.alive, "collector error: capture may be incomplete")
            self.notes.append({"at": at, "chat_id": chat_id, "reason": "collector_error",
                               "operation": payload.get("operation"), "error_type": payload.get("error_type")})
            if payload.get("observation_stopped") is True:
                self.active = False
        elif kind == "connection.closed" and payload.get("role") in (None, "current"):
            self.close(at, "connection to Telegram closed")
        elif kind == "coverage.gap":
            reason = payload.get("reason")
            if chat_id is None and reason in INTERRUPTIONS:
                cause = ACCOUNT_LOSS.get(payload.get("cause")) if reason == "authorization_required" else None
                self.close(at, INTERRUPTIONS[reason] + (": " + cause if cause else ""))
                if reason != "transport_disconnected":
                    self.active = False
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
        self.sequences.add(event, MESSAGE_KINDS)

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
        unobserved = []
        for chat_id, ids in sorted(self.ids.items()):
            ordered = sorted(ids)
            holes = missing_ranges(ordered)
            unobserved.append({"chat_id": chat_id, "title": self.titles.get(chat_id),
                               "observed_from": ordered[0], "observed_to": ordered[-1], "observed": len(ordered),
                               "not_observed": sum(high - low + 1 for low, high in holes),
                               "ranges": [{"low": low, "high": high} for low, high in holes[:ranges_per_chat]],
                               "ranges_total": len(holes)})
        return {"continuous": periods, "gaps": gaps, "notes": self.notes[:200], "notes_total": len(self.notes),
                "unobserved_ids": unobserved, "gap_summary": self.sequences.result(self.titles), "first_record": self.first, "last_record": self.last,
                "meaning": "Observation intervals follow connected capture heartbeats from the same run, within three "
                           "heartbeat intervals (at least three minutes). Each interval ends at its last capture "
                           "confirmation or recorded stop. Message-number gaps describe the observed numbering range."}


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
        self.paused = False

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
        if wide(scope):
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


def coverage_lines(coverage):
    def span(seconds):
        hours, rest = divmod(int(seconds), 3600)
        return (str(hours) + " h " if hours else "") + str(rest // 60) + " min"
    lines = ["Continuously observed from " + p["from"] + " to " + p["to"] + " (" + span(p["seconds"]) + ")"
             + (", observing at the last capture confirmation" if p.get("still_observing") else "")
             for p in coverage["continuous"]]
    lines += ["Gap from " + g["from"] + " to " + g["to"] + ": " + str(g["reason"]) for g in coverage["gaps"]]
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


def verify_checkpoint(checkpoint, public_key, event_count, hash_at):
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


def read_sealed(stream):
    digest, window = hashlib.sha256(), b""
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        window += chunk
        if len(window) > 2 * SEAL_WINDOW:
            digest.update(window[:-SEAL_WINDOW])
            window = window[-SEAL_WINDOW:]
    at = window.rfind(SEAL_OPEN)
    if at < 0:
        return None
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
    parent = lookup.get(item.get("parent_id") or item.get("card_id"))
    return board_scope(parent, lookup, trail) if parent else None


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
            verify_checkpoint(checkpoint, public, result["events"], hash_at)
            result["checkpoint_event_count"] = checkpoint["statement"]["event_count"]
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
CONDITION_LABELS = {"integrity": "Integrity", "signer": "Signer key", "head_binding": "Independent binding of the last record",
                    "external_time": "External time", "environment": "Attested collection run"}
CONDITION_ROLE = {"integrity": "required", "signer": "required", "head_binding": "one_of", "external_time": "one_of",
                  "environment": "optional"}
ROLE_LABELS = {"required": "Required conditions", "one_of": "At least one of these", "optional": "Optional condition"}
CONDITION_SCOPE = {"integrity": "The archive is unchanged since the collector signed it.",
                   "signer": "The signing key is the collector key the recipient retained.",
                   "head_binding": "Records up to the bound record were not removed or replaced after the binding.",
                   "external_time": "The covered records existed by the stated time.",
                   "environment": "The signing key was created inside the attested collection run."}
MINIMUM_NAMES = {"signer": "confirmed signer key", "head_binding or external_time": "independent binding of the last record or external time"}


def assurance(result):
    witness = result.get("witness") or {}
    anchors = result.get("anchors") or []
    stamps = [a for a in anchors if a.get("event_count") == result.get("events") and (
        a.get("kind") == "rfc3161" and a.get("signature", "").startswith("checked against") or
        a.get("kind") == "opentimestamps" and a.get("status") == "confirmed")]
    times = [a["time"] for a in stamps]
    if witness.get("head_bitcoin_block_time"):
        times.append(witness["head_bitcoin_block_time"])
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
                    + "; witness clock " + str(witness.get("head_witnessed_at"))) if independent else "no pinned independent witness at the export head"},
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
                      "collector {fingerprint}… matches the trusted fingerprint" if result.get("key_pinned")
                      else "collector {fingerprint}… not compared with a retained fingerprint", fingerprint=fp[:16])]
    independent = bool(witness.get("witness_key_pinned") and witness.get("witness_fingerprint") not in (None, fp)
                       and not witness.get("conflicts"))
    retained = result.get("checkpoint_event_count")
    through = max(retained or 0, (witness.get("verified_through_event") or 0) if independent else 0)
    at_head = journal and (retained == events or independent and bool(witness.get("export_head_witnessed")))
    if journal and through:
        text, values = "records 1–{through} of {total} held by an independent party", {"through": through, "total": events}
    elif journal:
        text, values = "no retained checkpoint or confirmed witness", {}
    else:
        text, values = "this archive type carries no journal checkpoints; verify the evidence journal", {}
    rows.append(condition("head_binding", "met" if at_head else "partial" if journal and through else "missing",
                          "--checkpoint kept outside the collector, or --witness with --witness-fingerprint" if journal
                          else "in the evidence journal ZIP: --checkpoint, or --witness with --witness-fingerprint", text, **values))
    checked = [a for a in anchors if a.get("kind") == "rfc3161" and str(a.get("signature", "")).startswith("checked against")
               or a.get("kind") == "opentimestamps" and a.get("status") == "confirmed"]
    times = [a["time"] for a in checked if a.get("event_count") == events and a.get("time")]
    if independent and witness.get("export_head_witnessed") and witness.get("head_bitcoin_block_time"):
        times.append(witness["head_bitcoin_block_time"])
    runtime = result.get("runtime_attestation") or {}
    attested = runtime.get("verified") is True and runtime.get("key_origin") == "created"
    if attested and runtime.get("attested_at"):
        times.append(runtime["attested_at"])
    unchecked = [a for a in anchors if a not in checked]
    stamped = max((a.get("event_count") or 0 for a in checked), default=0)
    if times:
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
                          "RFC 3161 with --tsa-ca, OpenTimestamps with --check-bitcoin, witness Bitcoin seals or a checked GitHub attestation"
                          if journal else "in the evidence journal ZIP: --tsa-ca or --check-bitcoin", text, **values))
    drand = ((result.get("outside") or {}).get("drand") or {}).get("checked") or {}
    if drand.get("confirmed"):
        rows[-1]["drand"] = ", ".join(drand.get("relays") or [])
        rows[-1]["detail"] += " · drand rounds confirmed by " + rows[-1]["drand"]
    rows.append(condition("environment", "met" if attested else "missing",
                          "--sealed-attestation with --sealed-policy for a GitHub Actions run; Intel TDX: python -m tgwitness.cloud verify"
                          if journal else "in the evidence journal ZIP: --sealed-attestation with --sealed-policy",
                          "collection ran in the attested workflow {workflow}" if attested
                          else "no attested collection run checked here",
                          **({"workflow": runtime.get("workflow")} if attested else {})))
    met = {row["id"] for row in rows if row["status"] == "met"}
    missing = ([] if "signer" in met else ["signer"]) + \
              ([] if {"head_binding", "external_time"} & met else ["head_binding or external_time"])
    minimum = not missing
    bound = events if minimum else max(through if journal else 0, stamped)
    options = [] if "signer" in met else ["--fingerprint FINGERPRINT"]
    if journal and "head_binding or external_time" in missing:
        options += sorted({"--tsa-ca TSA-ROOT.pem" if a.get("kind") == "rfc3161" else "--check-bitcoin" for a in unchecked
                           if a.get("event_count") == events and (a.get("kind") == "rfc3161" or a.get("status") == "bitcoin-unverified")}) \
            or ["--checkpoint CHECKPOINT.json"]
    return {"profile": "attested" if minimum and "environment" in met else "evidence" if minimum else "integrity",
            "minimum_met": minimum, "missing": missing, "records": events,
            "bound_through": bound if "signer" in met else 0, "conditions": rows,
            "next_options": options, "journal_needed": not journal and "head_binding or external_time" in missing,
            "minimum": "integrity, confirmed signer key, and an independent checkpoint, confirmed witness or verified "
                       "external timestamp covering the last exported record"}


def next_lines(evidence, t=None):
    t = t or english
    lines = [t("Next step: run verify.py again with {options}", options=" ".join(evidence["next_options"]))] \
        if evidence.get("next_options") else []
    if evidence.get("journal_needed"):
        lines.append(t("This archive type carries no checkpoints or timestamps: the last record is bound in the evidence "
                       "journal of the same workspace. Verify that ZIP with --fingerprint and --checkpoint."))
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
            page = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "TgWitness-verify"}),
                                          timeout=30).read(MAX_SMALL_MEMBER_BYTES).decode("utf-8", "replace")
            ids = [int(n) for n in re.findall(r'data-post="[^"/]+/(\d+)"', page)]
            posts += [(None, None, block) for block in re.split(r'data-post="', page)[1:]]
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
            found.append((message.get("id"), message.get("date"), body))
        return found
    return [(None, None, text)]


def check_channel(witness, source):
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(witness["public_key"], validate=True))
    matching, invalid, differing, foreign, dates = set(), [], [], 0, {}
    for message_id, date, text in channel_texts(source):
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
                if date:
                    dates[statement["seq"]] = date
    posted = set(witness["posted"])
    return {"matching": len(matching), "matching_records": sorted(matching),
            "invalid_signatures": invalid, "differ_from_journal": differing,
            "other_witnesses": foreign,
            "posted_but_not_found": sorted(posted - matching),
            "never_posted": sorted(set(witness["statements"]) - posted),
            "telegram_post_dates": dates,
            "post_date_verification": "not-performed"}


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
# Catalogue SHA-256: aac482d4272881c88f2fb2d0699127a2e887389c7c2d24e7efcfe4f730433a16
VERIFIER_LANGUAGE_DATA = (
    "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"
    "cvNG0GPZrrBXRWTY2JcKx7coUPw///P/AOTLkXk="
)
# END GENERATED VERIFIER LANGUAGES
import zlib
VERIFIER_LANGUAGES = json.loads(zlib.decompress(base64.b64decode(VERIFIER_LANGUAGE_DATA)))
SAY = {code: entry["words"] for code, entry in VERIFIER_LANGUAGES.items()}


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
        width = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)
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
                   "connection to Telegram lost": "Disconnected", "observation could not resume after a restart": "Interrupted"}
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
        met = {row["id"] for row in evidence["conditions"] if row["status"] == "met"}
        needed = {"required": True, "one_of": not {"head_binding", "external_time"} & met, "optional": False}
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
            self.explain({"signer": "Key pinning", "head_binding": "Retained checkpoint"}.get(row["id"], ""))
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
    parser.add_argument("--channel", help="Witness channel posts: Telegram Desktop result.json, saved page or t.me/s URL")
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
        conflict = (result["witness"]["conflicts"] or [None])[0]
        if conflict and conflict["event_count"] > result["events"]:
            raise ValueError("The witness saw record " + str(conflict["event_count"]) + " at " + conflict["at"]
                             + ", before this export was created at " + str(result["witness"]["export_created_at"])
                             + ", but the export ends at record " + str(result["events"]))
        if conflict:
            raise ValueError("The journal differs from what the witness saw at " + conflict["at"] + " (record "
                             + str(conflict["event_count"]) + ")")
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
    if check and check["telegram_post_dates"]:
        notes.append("Channel dates are supplied metadata; witness signatures cover the post content.")
    if args.require_witness:
        witnessed = result.get("witness")
        if not witnessed:
            raise ValueError("--require-witness requires a full evidence ZIP and its witness journal")
        if not witnessed["witness_key_pinned"] or not witnessed["export_head_witnessed"]:
            raise ValueError("No pinned witness checkpoint matches the exported journal head; "
                             "retain a witness checkpoint at the export boundary")
        if witnessed["witness_fingerprint"] == result["fingerprint"]:
            raise ValueError("Collector and independent witness must use different trusted signing keys")
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
