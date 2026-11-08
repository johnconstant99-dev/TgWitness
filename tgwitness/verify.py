# TgWitness verifier sources SHA-256: 884f112536bafa6c37c4182c75a3f49ac7b6587fece77ef24ef12938cb189d50
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
           "these numbers; a gap does not say who removed a message or why, and it may be a message Telegram never "
           "showed to this account.")
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
                         + " ID(s) not observed in " + str(chat["ranges_total"]) + " range(s) (not evidence of deletion)")
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
                         + " s; this comparison does not authenticate either timestamp.")
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
                                 "signatures, but chronological claims require independent time evidence. "
                                 "An ordered journal does not prove its timestamps are accurate.")
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
        print("Matched: " + str(result["matched"]) + " (possible correspondence, not proof of message identity)")
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
# Catalogue SHA-256: 7a7d91e67e41c140fdf62f64ce1bfc0a4f7838d8ed1356caf3a929e08764ab67
VERIFIER_LANGUAGE_DATA = (
    "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"
    "7mLz6r2759eSOpyiX0eQ5QMXsWFHYubYERAPwJjwx+uHZ9BrWzx9P4eHtJjh4BiV0lJYAO9YsJpBT+LWRY8R5JSAR+4D05D/awQJnGEL7yn16IoN"
    "VWiNK+9xpkcfkKxcrsqQ0zJGKtzT9KBv2Jv9JbfHSDyvMlnon/nN1uIgCXjuEt/YFOnmoqaGrxnHgZZx6wgwmZJ3kuLzevNo272bpm19O/DZncWH"
    "40CGKkdIkU+BNTDiyYhOmTPsLSURyYlUuUTDnTmhXlVWz/e19Q0WylrBd/8Yu2KGVzU6/xi7Kobqm08nWeozh8uBTqosGW4jfQ3vnlm8+1xeNMFD"
    "fakkFwxpFWLcJ+LL5wOvuNQP5zI9oV65fH/pzlmzGdZ0vTEWpCrzcLtd+lzs89XYyllRbIQvEEi6zo8HXkfBiEPxcFdpjH67oq8mpISAtYNJaF2Z"
    "UZJdKkCtylFFDDSEV8ElQmvp2nRLzv5Te13Wi9bHlYsmbJI+nqNXwFVZPKZsSHVVF0W/R19vrozD6wGjWeQTZqO0iM7Fi2/M3dDaDKKM6dOt36No"
    "5Ggh51zrJw+rJPcSrvX/zOwn/TwPuJYwNby04YJ/Ku6wxeaodW0+q2MKBd28j1nzo1TYjVpOjJRGlTuBA1Txp5G+6mNHyVz6IeKlEIO1AuRW8aS9"
    "ODMutqOmtJx1mOaW3zNWlKnRIKontgWFwh6qZRsdC3Ez8ZJpp6eWJibpZgxIWGCNr84E6q3lICXI5iFSf0fyB+8yG6p5SfW0b8xJC319TRmDZnk3"
    "Hjc24XKwdOy9Xal5sBeW7O0ciWPIDWcJ4nrXhCQfYsnbkY0S3Qj1NDq4+b0QLRGL9zT/05FX31x4OfNg7tLJXMin+ekX8y8eLowd15BPc1//be7z"
    "L1/dOj5//duVEJ/qZx/NXT366sz4whcvFiZOLnxxY/7Ft7lYTwt3Ty88ODV3+cuFr8/kgjzVx06/fPp07usLc7cnsuhO9eP3X12iHq58kgPuVP/u"
    "RH36SP3W9/VPP85DdZp78GP93MP5x2MwVdsqB9cJ1r5w91L96tSrIzOwAwrZye5HrtMxN3O8fulb2M76+bNrwHOaOzU2d+7cwi/T89fG6w+uwOJT"
    "WE4LX38tC85iOb38+cTc0/P1c8cWxo7lk9/cZ7DqS3MXnsx9di0N4zT3yVR9+pMGorH+48P5mW/nZq7DvBamrsCmZc1//v7VuYlGCE71mUdzE0/m"
    "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"
    "aoaNfalwfIsCxf/93/8P4uJONA=="
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
            self.check("none", "Derivation", "filtering and redaction correctness are not established")
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
    compared['assurance']['scope'] = 'two authenticated chat exports; comparison does not prove event history'
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
