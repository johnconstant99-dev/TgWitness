# TgWitness verifier sources SHA-256: f6201001c80b40310aaacbc35ebf106002881ef39d8f6c6aaf54aafa5ac5b907
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
# Catalogue SHA-256: dd107b09430e23f078506338438aeaa1a90a88a8095ed6a8d9e348de52e40023
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
