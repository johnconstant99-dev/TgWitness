# TgWitness verifier sources SHA-256: bdf2968fb9bf0f38f0410977daf65ec95212c5b7daf9a7c4b56a2fb722799f9f
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
        super().__init__("The archive format is newer than this verifier; use the current verify.py" +
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
    """Validate claimed range coverage, not Telegram origin or absent payloads."""
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
                            pass  # Unsupported hash never produces a verified commitment.
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
    """TLS explorer consensus, explicitly not independent Bitcoin chain validation."""
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


# Channels have separate ID sequences; private chats, bots and basic groups share the account sequence.
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
    """times maps each observed message number to the time it was first observed; notices are numbers known
    only from a deletion or recheck record, without saved content."""
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
    """Whether a collection scope records every message that takes a number from the account sequence."""
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
    """Collects observed numbers from journal records in order and measures their gaps."""

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
            # Account-level deletions name numbers without an attribution to an observed chat.
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
                    # Only messages that arrived during whole-account collection bound the measured range.
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
                          "meaning": "Records after a drand round were written after the round's time: nobody "
                                     "knows a round's value earlier. Rounds are compared with drand relays only "
                                     "with --check-drand."},
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
            lines.append("Rounds not compared with drand relays: run with --check-drand")
        elif checked["relays"]:
            lines.append("Confirmed by drand relays: " + str(checked["confirmed"]) + " of " + str(checked["asked"])
                         + " round(s) asked (" + ", ".join(checked["relays"]) + ")"
                         + ("" if len(checked["relays"]) > 1 else "; only one operator answered"))
        else:
            lines.append("Rounds could not be compared: no drand relay answered")
        if drand["clock_behind_seconds"] > 1:
            lines.append("The collector's clock was up to " + str(drand["clock_behind_seconds"])
                         + " s behind drand time")
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
    for count, event in enumerate(events, 1):
        if set(event) != set(FIELDS) | {"hash", "signature"}:
            raise ValueError("Unexpected or missing fields at event " + str(count))
        if event["seq"] != count or event["previous_hash"] != previous:
            raise ValueError("Broken sequence or hash chain at event " + str(count))
        calculated = hashlib.sha256(canonical({k: event[k] for k in FIELDS})).hexdigest()
        if event["hash"] != calculated:
            raise ValueError("Changed content at event " + str(count))
        key.verify(base64.b64decode(event["signature"], validate=True), bytes.fromhex(calculated))
        if event["kind"] == "media.hashed":
            payload = event["payload"]
            validate_server_hashes(payload.get("server_hashes"))
            if (payload["server_hashes"]["status"] != "complete" or payload.get("downloaded_bytes") != 0
                    or payload.get("media_sha256") is not None):
                raise ValueError("A hash-only record incorrectly claims downloaded file content")
        previous = calculated
    return {"events": count, "head_hash": previous, "fingerprint": fingerprint(public_key)}


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
        seal = check_seal(read_json_seal(json.loads(read_member(archive, "report.json", MAX_JSON_BYTES))), public)
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
            event = json.loads(line)
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
                    event = json.loads(line)
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
        records = [json.loads(line) for line in bounded_lines(incoming)]
    replay = board_replay(records, public)
    signed = json.loads(read_member(archive, "case-board.json", MAX_JSON_BYTES))
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
            retained_heads.append(json.loads(read_member(archive, name)).get("statement", {}).get("annotations_head"))
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
                    event = json.loads(line)
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
                if name not in files or json.loads(read_member(archive, name, MAX_JSON_BYTES)) != expected:
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
    signed = json.loads(read_member(archive, "case-board.json", MAX_JSON_BYTES))
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
            record = json.loads(line)
            if record["hash"] in wanted:
                for card in cards:
                    if card.get("target", {}).get("event_hash") == record["hash"] and card.get("observation") != record:
                        raise ValueError("Board exposes content outside the handover record")
                matched.add(record["hash"])
    if matched != set(wanted):
        raise ValueError("Board refers to a record not disclosed in the handover")
    if "report.json" in manifest["files"]:
        report = json.loads(read_member(archive, "report.json", MAX_JSON_BYTES))
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
                row = json.loads(line)
                if row["seq"] > count:
                    break
                prefix.append(row)
        if board_replay(prefix, public) != statement["state"]:
            raise ValueError("Case Board state differs from its signed annotations prefix")
        boundary = statement["journal_head"]
        source_head = {"seq": 0, "hash": "0" * 64}
        with open_archive(evidence) as archive, archive.open("events.jsonl") as incoming:
            for line in bounded_lines(incoming):
                row = json.loads(line)
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
            saved_coverage = json.loads(read_member(archive, "coverage.json", MAX_JSON_BYTES))
            saved_gaps = saved_coverage.get("gap_summary") if isinstance(saved_coverage, dict) else None
            if isinstance(saved_gaps, dict):
                gap_settings = saved_gaps.get("parameters")
        observed, outside = Coverage(gap_settings), OutsideRecords()
        hash_files, account_exports = set(), []

        def measured(lines):
            for line in lines:
                event = json.loads(line)
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
                    event = json.loads(line)
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
    """Check a local acquisition prefix; unsigned trailing bytes are not observations.

    Pages group decoded messages, not raw RPC responses. The final filtered ZIP
    keeps its existing per-account signatures and does not disclose excluded pages.
    """
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
            record = json.loads(line)
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
    """Read-only inspection of a stopped distributed job; never opens its vault."""
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
    # Preview shortening must never define equality. Include future fields too;
    # canonical JSON preserves value types and array order, unlike dict equality.
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
    claimed = json.loads(read_member(archive, "message-ids.json", MAX_JSON_BYTES))
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
                record = json.loads(line)
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
                    # The export wire format places one complete message on each line.
                    # Reject other layouts instead of authenticating bytes but silently skipping records.
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
            message = json.loads(line.removesuffix(","))
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
        envelope = json.loads(read_member(self.archive, name))
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
        record = json.loads(line)
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
        # Version 2 keeps records the selection left out as content-free markers, and replies say what they answer.
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
                    row = json.loads(line)
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
            # A reply to a disclosed or withheld message must point at that record; only not_in_source points nowhere.
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
            event = json.loads(line)
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
            event = json.loads(line)
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
    """One prefix boundary per UTC date; no full journal retained in memory."""
    def __init__(self):
        self.tree, self.dates = MerkleFrontier(), {}
        self.previous, self.last_date = None, None

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
        date = moment.astimezone(timezone.utc).date().isoformat()
        if self.last_date is not None and date <= self.last_date:
            raise ValueError("Witness appended records into an already sealed day")
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
                    if payload.get("status") == "ok":
                        prior = retained.get(collector_key)
                        if prior and prior.get("keys") is not None and prior["keys"] != anchors[-1].get("keys"):
                            raise ValueError("Witness accepted a changed or removed collector key history")
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
        # Every credited anchor is checked; sampling must not certify unchecked rounds.
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
            "freshness": freshness, "days": days, "missing_days": missing_days, "collector_keys": collector_keys}


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


def cross_check_witness(witness, bundle_path, bundle_result):
    count, key = bundle_result["events"], bundle_result["fingerprint"]
    mine = [a for a in witness["anchors"] if a["collector_fingerprint"] == key]
    hashes = bundle_hashes(bundle_path, {a["event_count"] for a in mine
                                         if a["status"] == "ok" and 0 < (a["event_count"] or 0) <= count})
    prefixes = bundle_capture_prefixes(bundle_path, {a["event_count"] for a in mine
                                                    if a.get("capture") and a["status"] == "ok" and a["event_count"] <= count})
    consistent, conflicts, later, anomalies, matched = 0, [], 0, [], []
    for anchor in mine:
        if anchor["status"] != "ok":
            anomalies.append(anchor)
        elif anchor["event_count"] > count:
            later += 1
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
    return {"witness_fingerprint": witness["fingerprint"], "anchors_for_this_key": len(mine),
            "other_keys": len(witness["anchors"]) - len(mine) - invalid, "invalid_answers": invalid,
            "consistent": consistent, "conflicts": conflicts,
            "after_export": later, "anomalies": anomalies, "no_response": len(witness["no_response"]),
            "witnessed": periods, "witness_gaps": gaps,
            "verified_through_event": verified_through, "unwitnessed_events": count - verified_through,
            "continuity_verified_through_event": continuity_through,
            "export_head_witnessed": any(a["event_count"] == count for a in matched),
            "export_head_witness_records": [a["seq"] for a in matched if a["event_count"] == count],
            "witness_key_pinned": bool(witness.get("key_pinned")),
            "collector_keys": witness.get("collector_keys", {}).get(key),
            "days": witness.get("days", []), "missing_days": witness.get("missing_days", []),
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
UNPINNED_NOTE = "Signer key is not pinned: pass --fingerprint with the fingerprint you retained."


def assurance(result):
    """Credit only checks performed by this verifier, with coverage of the export head."""
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
                          "Other progress fields are signed statements only. No proof of Telegram origin "
                          "or historical completeness."}


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
# Source: verifier_languages.json; update with tools/sync_verifier_languages.py
# Catalogue SHA-256: ab869f9b974e0b75597cfd052fecc67c21e49a6311d547d8d040a688b6b64c83
VERIFIER_LANGUAGE_DATA = (
    "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"
    "UnMWNcfGvlo6vkWB4v/7f/8/eFX88A=="
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
    # Windows locale.getlocale() may use English language names instead of tags.
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
        # Only formatting produced here may become terminal control sequences.
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
        # Separate lines avoid broken columns for CJK and right-to-left scripts.
        self.say("  " + self.paint(self.glyph[mark[0]], mark[1]) + " " + self.t(label))
        if detail:
            self.say("    " + (self.paint(detail, "dim") if state == "none" else detail))
        if state != "none":
            self.explain(label)

    def explain(self, label):
        meanings = VERIFIER_LANGUAGES[self.lang]["explain"]
        if self.explain_enabled and label in meanings:
            import textwrap
            # Preserve shaping clusters and bidirectional paragraphs; let the terminal wrap these scripts.
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
        import unicodedata
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
        # Preserve the exact diagnostic for experts; do not translate source data or error identifiers.
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
        # Keep arbitrary source/operator reasons verbatim; known software reasons use translated labels.
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
        if note == UNPINNED_NOTE:
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
        # Protocol diagnostics, user-entered data and unknown future notes stay verbatim.
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
    """Find by manifest, never by a guessed filename, key, or self-declared trust."""
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
    """Keep terminal colours on screen and plain UTF-8 in the saved copy."""
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
    """No shell commands, installations, key auto-pinning, or archive mutation."""
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
        if result["witness"]["conflicts"]:
            raise ValueError("The journal differs from what the witness saw at "
                             + result["witness"]["conflicts"][0]["at"] + " (record "
                             + str(result["witness"]["conflicts"][0]["event_count"]) + ")")
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
