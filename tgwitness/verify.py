# TgWitness verifier sources SHA-256: ee492675198adac4072b14954b55418c9c366b579645bba65537825b37d31b25
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
        self.session_event(at, kind, payload)
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
                           "confirmation or recorded stop. Message-number gaps describe the observed numbering range.",
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
    for reason, label in SESSION_NOTES.items():
        found = [n["at"] for n in coverage.get("notes") or [] if n.get("reason") == reason and n.get("chat_id") is None]
        if found:
            lines.append("Session: " + label + " (" + str(len(found)) + "x, first " + found[0] + ")")
    if s.get("security_events"):
        lines.append("Telegram security notices (777000): " + ", ".join(
            name + " " + str(count) for name, count in sorted(s["security_events"].items())))
    for item in s.get("other_sessions_ended") or []:
        lines.append("All other sessions ended from this workspace at " + item["at"]
                     + (" (" + str(item["ended"]) + " signed in before)" if isinstance(item.get("ended"), int) else ""))
    for item in s.get("password_changes") or []:
        lines.append("Two-step password " + str(item.get("operation") or "set or changed") + " from this workspace at " + item["at"])
    if s.get("phone_calls"):
        lines.append("Phone call updates delivered to this session: " + str(s["phone_calls"]))
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
# Catalogue SHA-256: 12d79c5c59feb262b5c22b5d349cb060f459aa515ea06148872faeda98543512
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
