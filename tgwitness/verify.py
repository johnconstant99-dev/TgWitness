# TgWitness verifier sources SHA-256: 500a572b12e7d043ee23f11b74352e0be3b4ea9371190110655626fbd9b02502
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
    return ("The scope does not confirm that private chats, bots, ordinary groups and the account's own messages "
            "were all included without excluded chats; those messages take numbers from the same sequence.")


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
# Catalogue SHA-256: 50f04203669b9b22b3f84973b01b0b86089cd6268e1a01a693b0325c2688f278
VERIFIER_LANGUAGE_DATA = (
    "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"
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
        notes.append("Channel dates are supplied metadata; witness signatures do not authenticate publication times.")
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
