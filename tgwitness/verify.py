# TgWitness verifier sources SHA-256: 8a1f9e8b12c619ba6b3affa43c5d6ffb44b79bb5f52c4d513320a61bde2eac6f
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
        super().__init__("пакет подписан корректно, но этот верификатор старше формата пакета" +
                         (": " + detail if detail else ""))


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
                return None
        if len(set(found)) != 1:
            raise ValueError("Independent Bitcoin header sources disagree")
        cache[height] = found[0]
        return found[0]
    return fetch


def confirm_ots(proof, digest, fetch=None):
    summary = ots_summary(proof, digest, commitments=True)
    fetch = fetch or bitcoin_fetcher()
    confirmed = []
    for item in summary.pop("commitments"):
        header = fetch(item["height"])
        if header is None:
            continue
        if len(header) != 80 or header[36:68].hex() != item["merkle_root"]:
            raise ValueError("OpenTimestamps commitment differs from the Bitcoin block Merkle root")
        confirmed.append({"height": item["height"],
                          "time": datetime.fromtimestamp(int.from_bytes(header[68:72], "little"), timezone.utc).isoformat()})
    if confirmed:
        summary.update(status="confirmed", time=min(c["time"] for c in confirmed), blocks=confirmed,
                       verification="proof evaluated; headers with 6 confirmations agreed by two HTTPS explorers; not full chain validation",
                       sources=list(BITCOIN_SOURCES))
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
    return {"asked": len(chosen), "confirmed": len(chosen) if used else 0, "relays": used}


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
            "meaning": "Verified committed acquisition prefix, with collection intervals and completed ranges. "
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
                           "Source linkage does not establish correct filtering, redaction, legal compliance or completeness."}





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
                 "relays": confirmation["relays"]}
    return {"format": manifest["format"], "fingerprint": fp, "public_key": public, "events": result["events"],
            "head_hash": result["head_hash"], "interval_minutes": interval, "channel": manifest.get("channel"),
            "producer": manifest.get("producer"), "anchors": anchors, "no_response": silent, "posted": posted,
            "post_failures": failures, "statements": statements, "key_pinned": bool(expected_fingerprint),
            "freshness": freshness, "days": days, "missing_days": missing_days, "collector_keys": collector_keys,
            **({"chronology": result["chronology"]} if "chronology" in result else {})}


def key_history_summary(keys):
    return {**keys, "meaning": "Recorded Telegram authorizations; collector-signed claim, not proof that no key copies exist",
            "note": "ключ импортирован: подтверждение зависит от доверия к источнику" if keys["origin"] == "imported" else None}


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
        return "ASSURANCE: self_attested — only the collector's own key vouches for this record"
    witness = result.get("witness") or {}
    detail = (" since #" + str(witness["head_witness_record"]) + " (" + str(witness["head_witnessed_at"]) + ")"
              if witness.get("head_witness_record") else "")
    absent = {row["tier"] for row in value["ladder"] if row["status"] != "pass"}
    limits = [text for tier, text in (("fresh", "not fresh"), ("witness_anchored", "witness not anchored"),
                                    ("sealed", "not sealed")) if tier in absent]
    return "ASSURANCE: " + value["tier"] + detail + (" · " + " · ".join(limits) if limits else "")


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
# Catalogue SHA-256: a21b43bf83711ac10a5f13dbe63ac08bf7222930880e6eb7954dd0800b0b0761
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

    def verdict(self, ok, reason="", pinned=True):
        unconfirmed = ok and not pinned
        text = " " + (self.glyph["warn"] if unconfirmed else self.glyph["ok"] if ok else self.glyph["bad"]) + "  " \
               + self.t("INTEGRITY VERIFIED · SIGNER NOT CONFIRMED" if unconfirmed
                        else "INTEGRITY VERIFIED" if ok else "VERIFICATION FAILED") + " "
        self.say()
        if self.color:
            self.say("  " + self.paint(text.ljust(self.WIDTH - 2), "warnbar" if unconfirmed else "okbar" if ok else "badbar"))
        else:
            self.say("  " + self.glyph["tl"] + self.glyph["h"] * (self.WIDTH - 4) + self.glyph["tr"])
            self.say("  " + self.glyph["v"] + text.ljust(self.WIDTH - 4) + self.glyph["v"])
            self.say("  " + self.glyph["bl"] + self.glyph["h"] * (self.WIDTH - 4) + self.glyph["br"])
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

    def pinning(self, pinned):
        if pinned:
            self.check("ok", "Key pinning", self.t("matches your trusted fingerprint"))
        else:
            self.check("warn", "Key pinning", self.t("not pinned: compare the fingerprint with a copy kept elsewhere"))

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
        self.check("none", "Continuous", self.number(len(periods)))
        for period in periods:
            self.say("    " + str(period["from"]) + " → " + str(period["to"]) + " · "
                     + self.t("Duration") + ": " + str(int(period["seconds"])) + " s")
        if not periods:
            self.say("    " + self.t("No observation period recorded."))
        self.check("warn" if gaps else "none", "Gap", self.number(len(gaps)))
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
                self.check("none", "Account", self.t("Not checked") + " · " + str(account.get("reason") or ""))

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

    def show(self, shown, path, result, notes, pinned):
        self.say(assurance_line(result))
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
            if result.get("checkpoint_checked"):
                self.check("ok", "Retained checkpoint", self.t("matches the journal"))
            else:
                self.check("warn", "Retained checkpoint", self.t("Not supplied" if self.explain_enabled else
                                                                  "not supplied: removed trailing records would go unnoticed"))
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
        self.pinning(pinned)
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
        self.verdict(True, pinned=pinned)
        producer = result.get("producer")
        if producer:
            self.say("  " + self.paint(self.t("Produced by") + ": " + str(producer.get("software")) + " "
                                       + str(producer.get("version")) + " · " + str(producer.get("project")) + " · "
                                       + str(producer.get("homepage")), "dim"))
        self.say("  " + self.paint(self.t("Signatures bind saved bytes to this collector's key."), "dim"))
        self.explain("Limits")
        self.say()

    def localized_note(self, note):
        if note == "ключ не закреплён: результат зависит от ключа внутри самого пакета":
            return reader_message("key_unconfirmed", self.lang)
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
    if args.require_tier and ASSURANCE_TIERS.index(args.require_tier) >= ASSURANCE_TIERS.index("fresh"):
        args.check_drand = True
    if args.require_tier and ASSURANCE_TIERS.index(args.require_tier) >= ASSURANCE_TIERS.index("timestamped"):
        args.check_bitcoin = True
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
    if not args.checkpoint:
        notes.append("No retained checkpoint supplied: records removed from the end of this journal are not "
                     "detected. Pass --checkpoint with a checkpoint kept away from the collector.")
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


def verification_requirements(args, checked):
    result, notes, shown = checked.details, checked.notes, checked.kind
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
        result["runtime_attestation"] = {k: checked_runtime[k] for k in ("verified", "sha256", "workflow", "limitation")}
        result["runtime_attestation"]["key_origin"] = "created"
    result["assurance"] = assurance(result)
    if any(row["status"] == "fail" for row in result["assurance"]["ladder"]):
        raise ValueError("Assurance checks found contradictory witness evidence")
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
    unmet = bool(args.require_tier and ASSURANCE_TIERS.index(result["assurance"]["tier"]) < ASSURANCE_TIERS.index(args.require_tier))
    unpinned = args.strict and not pinned
    if not pinned:
        notes.append("ключ не закреплён: результат зависит от ключа внутри самого пакета")
    if unmet:
        notes.append("Required assurance tier was not reached: " + args.require_tier)
    if console:
        console.show(shown, args.bundle, result, notes, pinned)
        if unmet or unpinned:
            raise SystemExit(2)
        return
    if mode == "json":
        verification_print(json.dumps({"verified": True, "kind": shown, "signer_pinned": pinned, "notes": notes, "result": result,
                          "requirements_met": not (unmet or unpinned)},
                         indent=2, ensure_ascii=True))
        if unmet or unpinned:
            raise SystemExit(2)
        return
    verification_print(assurance_line(result))
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
    verification_print("Integrity verified. Source authenticity and clock accuracy are not established.")
    if not pinned:
        verification_print("Signer identity is unpinned: retain and compare the fingerprint independently.")
    if unmet or unpinned:
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
