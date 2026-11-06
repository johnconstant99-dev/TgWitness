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
    return algorithm, reply[identifiers[0][2]:identifiers[0][3]]


def timestamp_signature(reply, roots):
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
    algorithm, named = signing_certificate_hash(reply, attributes)
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
            "signer_sha256": signer.fingerprint(hashes.SHA256()).hex()}


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


# Missing message numbers. Telegram numbers messages once per channel or supergroup, and once per account
# across private chats, bots and ordinary groups. A number between two observed messages that this
# collector never saw is a gap: a message that existed and was not observed. A gap names no actor and no
# reason, and every result lists the parameters that produced it.
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
    # Account control events (account.initialized, account.connection_checked) use the same signed
    # envelope as older events. They do not extend message or coverage claims.
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
    if event["kind"] not in ("media.saved", "actor.avatar_saved"):
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
            "meaning": "Verified local acquisition prefix, not Telegram-signed evidence or an atomic snapshot. "
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
                if record["kind"] in ("media.saved", "actor.avatar_saved"):
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


def verify_account_export(path, expected_fingerprint=None, max_gib=None):
    def integer(value, name, minimum=0):
        if type(value) is not int or value < minimum:
            raise ValueError("Invalid account export " + name)
        return value

    def digest(value, name):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Invalid account export " + name)
        return value

    def timestamp(value, name):
        if not isinstance(value, str):
            raise ValueError("Invalid account export " + name)
        parsed = parse_time(value)
        if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("Account export times must have an explicit UTC offset: " + name)
        return parsed

    with open_archive(path, max_gib=max_gib) as archive, tempfile.TemporaryDirectory() as temporary:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if manifest.get("format") != "tgwitness-account-export-v1":
            raise VerifierTooOld("Unsupported account export format")
        public = manifest["public_key"]
        fp = fingerprint(public)
        if manifest.get("fingerprint") != fp:
            raise ValueError("Account export fingerprint does not match the signing key")
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
        key.verify(base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        files = manifest["files"]
        if not isinstance(files, dict) or set(names) != set(files) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing account export members")
        for name, checksum in files.items():
            if (not name or "\\" in name or ":" in name or name.startswith("/")
                    or any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError("Unsafe account export member name")
            if member_digest(archive, name) != digest(checksum, "file hash"):
                raise ValueError("File hash mismatch: " + name)
        for required in ("job.json", "inventory.json", "SHA256SUMS", "verify.py", "README.txt"):
            if required not in files:
                raise ValueError("Missing account export member: " + required)
        sums = check_sums(archive, manifest)
        account_id = integer(manifest["account_id"], "account ID", 1)
        job_id = manifest["job_id"]
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("Invalid account export job ID")
        options = manifest["options"]
        if not isinstance(options, dict):
            raise ValueError("Invalid account export options")
        options_hash = hashlib.sha256(canonical(options)).hexdigest()
        if digest(manifest["options_sha256"], "options hash") != options_hash:
            raise ValueError("Account export options hash mismatch")

        def signed(name, kind):
            envelope = json.loads(read_member(archive, name))
            statement = envelope["statement"]
            if (statement.get("format") != "tgwitness-account-export-" + kind + "-v1"
                    or statement.get("public_key") != public or statement.get("job_id") != job_id
                    or type(statement.get("account_id")) is not int or statement["account_id"] != account_id
                    or statement.get("options_sha256") != options_hash):
                raise ValueError("Account export signed identity/options mismatch: " + name)
            key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(statement))
            return statement, hashlib.sha256(canonical(envelope)).hexdigest()

        job, _ = signed("job.json", "job")
        if job.get("options") != options or job.get("created_at") != manifest.get("created_at"):
            raise ValueError("Account export job does not match the manifest")
        timestamp(job["created_at"], "created_at")
        timestamp(manifest["completed_at"], "completed_at")
        inventory, inventory_hash = signed("inventory.json", "inventory")
        if inventory_hash != digest(manifest["inventory_sha256"], "inventory hash"):
            raise ValueError("Account export inventory hash mismatch")
        timestamp(inventory["observed_at"], "inventory observed_at")
        if (type(inventory.get("discovery_complete")) is not bool or not isinstance(inventory.get("gaps"), list)
                or any(not isinstance(gap, str) for gap in inventory["gaps"])):
            raise ValueError("Invalid account export discovery coverage")
        if not isinstance(inventory.get("chats"), list) or not isinstance(inventory.get("tasks"), list):
            raise ValueError("Invalid account export task inventory")
        tasks = {}
        chats = {}
        for chat in inventory["chats"]:
            cid = chat.get("id")
            if type(cid) is not int or not cid or cid in chats or type(chat.get("selected")) is not bool:
                raise ValueError("Invalid or duplicate account export inventory chat")
            if chat["selected"]:
                if options.get("chat_ids") and cid not in options["chat_ids"]:
                    raise ValueError("Account export selected a chat outside its frozen options")
                if options.get("chat_kinds") is not None and chat.get("kind") not in options["chat_kinds"]:
                    raise ValueError("Account export selected a chat kind outside its frozen options")
                if options.get("include_archived") is False and chat.get("archived"):
                    raise ValueError("Account export selected an excluded archived chat")
            chats[cid] = chat
        metadata_categories = {"profile", "contacts", "sessions", "profile_photos", "stories", "other_data"}
        for task in inventory["tasks"]:
            task_id, category = task["id"], task["category"]
            if not isinstance(task_id, str) or not task_id or task_id in tasks:
                raise ValueError("Duplicate or invalid account export task ID")
            integer(task["cursor_start"], "initial cursor")
            if category == "messages":
                if type(task.get("chat_id")) is not int or task["chat_id"] == 0:
                    raise ValueError("Invalid message task chat ID")
                if task["chat_id"] not in chats or not chats[task["chat_id"]]["selected"]:
                    raise ValueError("Account export message task is outside the selected inventory")
                newest = integer(task["newest_message_id"], "newest message ID")
                if task["cursor_start"] != newest + 1 or type(task.get("own_only")) is not bool:
                    raise ValueError("Invalid message task boundary")
            elif category not in metadata_categories or task.get("chat_id") is not None:
                raise ValueError("Invalid account export task category")
            tasks[task_id] = {"statement": task, "cursor": task["cursor_start"], "terminal": False, "ok": True}

        inventory_omissions = ["Selected chat has no history task: " + str(cid) for cid, chat in chats.items()
                               if chat["selected"] and not any(t["statement"].get("chat_id") == cid for t in tasks.values())]
        category_options = {"profile": "include_profile", "contacts": "include_contacts",
                            "sessions": "include_session_metadata", "profile_photos": "include_profile_photos",
                            "stories": "include_stories", "other_data": "include_other_data"}
        for category, option in category_options.items():
            present = any(t["statement"]["category"] == category for t in tasks.values())
            if options.get(option) is True and not present:
                inventory_omissions.append("Selected category has no acquisition task: " + category)
            if options.get(option) is False and present:
                raise ValueError("Account export task is excluded by its frozen options")

        receipts = []
        for name in files:
            if name.startswith("receipts/"):
                found = re.fullmatch(r"receipts/(\d+)\.json", name)
                if not found:
                    raise ValueError("Unexpected account export receipt name")
                receipts.append((int(found[1]), name))
        receipts.sort()
        counts = dict.fromkeys(("records", "messages", "media_saved", "media_skipped", "bytes_saved"), 0)
        media_hashed = 0
        hash_manifests, hash_index = set(), hashlib.sha256()
        seen = sqlite3.connect(Path(temporary) / "seen.sqlite3")
        seen.execute("CREATE TABLE messages (chat INTEGER, id INTEGER, PRIMARY KEY (chat, id)) WITHOUT ROWID")
        data_files, media_files, failed_attachments, failed_pages, messages_seen = set(), set(), 0, 0, 0
        previous = "0" * 64
        since = timestamp(options["from_utc"], "from_utc") if options.get("from_utc") else None
        until = timestamp(options["to_utc"], "to_utc") if options.get("to_utc") else None
        try:
            for seq, (number, name) in enumerate(receipts, 1):
                receipt, receipt_hash = signed(name, "page")
                if (number != seq or type(receipt.get("seq")) is not int or receipt["seq"] != seq
                        or receipt.get("previous_receipt_sha256") != previous
                        or receipt.get("inventory_sha256") != inventory_hash):
                    raise ValueError("Broken account export receipt chain at " + str(seq))
                previous = receipt_hash
                state = tasks.get(receipt.get("task_id"))
                if state is None or state["terminal"]:
                    raise ValueError("Unknown or already terminal account export task")
                task = state["statement"]
                if (receipt.get("category") != task["category"] or receipt.get("chat_id") != task.get("chat_id")
                        or type(receipt.get("chat_id")) is not type(task.get("chat_id"))):
                    raise ValueError("Account export receipt task scope mismatch")
                before = integer(receipt["cursor_before"], "page cursor before")
                after = integer(receipt["cursor_after"], "page cursor after")
                if before != state["cursor"] or type(receipt.get("terminal")) is not bool:
                    raise ValueError("Broken account export task cursor continuity")
                if receipt.get("outcome") not in ("ok", "failed"):
                    raise ValueError("Invalid account export receipt outcome")
                timestamp(receipt["captured_from"], "captured_from")
                timestamp(receipt["captured_until"], "captured_until")
                count = integer(receipt["count"], "page record count")
                page_seen = integer(receipt["seen_count"], "page seen count")
                if page_seen < count:
                    raise ValueError("Account export seen count is shorter than the saved page")
                if task["category"] == "messages":
                    messages_seen += page_seen
                if task["category"] == "messages" and (after > before or (after == before and not receipt["terminal"])):
                    raise ValueError("Invalid account export message pagination boundary")
                data_name = receipt["data_file"]
                matched = re.fullmatch(r"data/(\d+)\.jsonl", data_name) if isinstance(data_name, str) else None
                if not matched or int(matched[1]) != seq or data_name in data_files or data_name not in files:
                    raise ValueError("Missing, reused or mismatched account export page data")
                data_files.add(data_name)
                if files[data_name] != digest(receipt["data_sha256"], "page data hash"):
                    raise ValueError("Account export receipt data hash mismatch")
                actual, last_id = 0, before
                with archive.open(data_name) as stream:
                    for line in bounded_lines(stream):
                        record = json.loads(line)
                        if not isinstance(record, dict) or line != canonical(record) + b"\n":
                            raise ValueError("Account export records must be canonical JSONL")
                        if record.get("category") != task["category"]:
                            raise ValueError("Account export record category mismatch")
                        if task["category"] == "messages":
                            message_id = integer(record["id"], "message ID", 1)
                            if (type(record.get("chat_id")) is not int or record["chat_id"] != task["chat_id"]
                                    or message_id > task["newest_message_id"]
                                    or not after <= message_id < last_id):
                                raise ValueError("Account export message outside the signed pagination boundary")
                            last_id = message_id
                            if (task["own_only"] or options.get("own_messages_only")) and record.get("outgoing") is not True:
                                raise ValueError("Account export own-message scope mismatch")
                            at = timestamp(record["date"], "message date")
                            if (since and at < since) or (until and at >= until):
                                raise ValueError("Account export message outside the selected date range")
                            if options.get("sender_ids") and record.get("from_id") not in options["sender_ids"]:
                                raise ValueError("Account export sender selection mismatch")
                            if options.get("text_contains") and not any(term.casefold() in (record.get("text") or "").casefold()
                                                                         for term in options["text_contains"]):
                                raise ValueError("Account export text selection mismatch")
                            try:
                                seen.execute("INSERT INTO messages VALUES (?, ?)", (task["chat_id"], message_id))
                            except sqlite3.IntegrityError:
                                raise ValueError("Duplicate account export message") from None
                            counts["messages"] += 1
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
                                if files.get(hash_file) != manifest_digest:
                                    raise ValueError("File-hash manifest differs from its signed message record")
                                hash_manifests.add(hash_file)
                                hash_index.update(canonical({"category": record["category"], "chat_id": record.get("chat_id"),
                                    "message_id": record.get("id"), "attachment_index": attachment_index, "manifest": hash_file}) + b"\n")
                            if outcome == "saved":
                                checksum = digest(attachment["sha256"], "attachment hash")
                                media_name = "media/" + checksum
                                size = integer(attachment["bytes"], "attachment byte count")
                                if (attachment.get("file") != media_name or files.get(media_name) != checksum
                                        or archive.getinfo(media_name).file_size != size):
                                    raise ValueError("Account export attachment bytes/hash mismatch")
                                expected = attachment.get("expected_bytes")
                                if expected is not None and integer(expected, "expected attachment bytes") != size:
                                    raise ValueError("Account export attachment size differs from observation")
                                representation = attachment.get("representation")
                                if representation is not None and (not isinstance(representation, dict)
                                        or integer(representation.get("bytes"), "attachment representation bytes") != size):
                                    raise ValueError("Account export attachment size differs from its representation")
                                media_files.add(media_name)
                                counts["media_saved"] += 1
                                counts["bytes_saved"] += size
                            elif outcome == "hashed":
                                if (attachment.get("file") or attachment.get("sha256") or not server_hashes
                                        or server_hashes["status"] != "complete"):
                                    raise ValueError("Hash-only attachment claims saved bytes or incomplete coverage")
                                media_hashed += 1
                            elif outcome in ("excluded", "failed"):
                                if attachment.get("file") or attachment.get("sha256"):
                                    raise ValueError("Unsaved account export attachment claims saved bytes")
                                counts["media_skipped"] += 1
                                failed_attachments += outcome == "failed"
                            else:
                                raise ValueError("Invalid account export attachment outcome")
                        actual += 1
                if actual != count:
                    raise ValueError("Account export page record count mismatch")
                counts["records"] += actual
                state.update(cursor=after, terminal=receipt["terminal"], ok=state["ok"] and receipt["outcome"] == "ok")
                failed_pages += receipt["outcome"] == "failed"
        finally:
            seen.close()
        if {name for name in files if name.startswith("data/")} != data_files:
            raise ValueError("Unreceipted account export page data")
        if {name for name in files if name.startswith("media/")} != media_files:
            raise ValueError("Unreferenced account export media")
        if hash_manifests:
            if files.get("hashes/index.jsonl") != hash_index.hexdigest():
                raise ValueError("File-hash index differs from signed message references")
            hash_manifests.add("hashes/index.jsonl")
        if {name for name in files if name.startswith("hashes/")} != hash_manifests:
            raise ValueError("Unreferenced account export file-hash manifest")
        if (integer(manifest["receipt_count"], "receipt count") != len(receipts)
                or digest(manifest["receipt_head_sha256"], "receipt head") != previous):
            raise ValueError("Account export manifest receipt boundary mismatch")
        declared_counts = manifest["counts"]
        if "unique_media_bytes" in declared_counts:
            counts["unique_media_bytes"] = sum(archive.getinfo(name).file_size for name in media_files)
        if declared_counts.get("media_hashed", 0) != media_hashed:
            raise ValueError("Account export hash-only attachment count mismatch")
        if any(type(declared_counts.get(name)) is not int or declared_counts[name] != count for name, count in counts.items()):
            raise ValueError("Account export manifest counts mismatch")
        if "messages_exported" in declared_counts and declared_counts["messages_exported"] != counts["messages"]:
            raise ValueError("Account export message summary mismatch")
        if "messages_seen" in declared_counts and declared_counts["messages_seen"] != messages_seen:
            raise ValueError("Account export seen-message summary mismatch")
        if "media_hashed" in declared_counts:
            counts["media_hashed"] = media_hashed
        done = sum(state["terminal"] and state["ok"] for state in tasks.values())
        failed_tasks = [name for name, state in tasks.items() if not state["ok"]]
        coverage = manifest["coverage"]
        if (type(coverage.get("inventory_complete")) is not bool
                or coverage["inventory_complete"] != inventory["discovery_complete"]
                or type(coverage.get("tasks_total")) is not int or coverage["tasks_total"] != len(tasks)
                or type(coverage.get("tasks_done")) is not int or coverage["tasks_done"] != done
                or type(coverage.get("failures")) is not int
                or coverage["failures"] != len(failed_tasks) + failed_attachments + len(inventory["gaps"])):
            raise ValueError("Account export coverage summary mismatch")
        complete = (inventory["discovery_complete"] and done == len(tasks)
                    and not inventory["gaps"] and not inventory_omissions and not failed_attachments and not failed_pages)
        if type(manifest.get("complete_within_scope")) is not bool or manifest["complete_within_scope"] != complete:
            raise ValueError("Account export completeness claim disagrees with acquisition receipts")
        if not isinstance(manifest.get("status"), str) or (manifest["status"] in ("done", "complete") and not complete):
            raise ValueError("Account export status contradicts its partial acquisition coverage")
        return {"format": manifest["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
                "job_id": job_id, "account_id": account_id, "status": manifest["status"], "counts": counts,
                "options": options, "options_sha256": manifest["options_sha256"],
                "receipt_count": len(receipts), "receipt_head_sha256": previous, "files_checked": len(files),
                "sha256sums": sums, "producer": manifest.get("producer"), "coverage": {
                    "inventory_complete": inventory["discovery_complete"], "tasks_total": len(tasks), "tasks_done": done,
                    "unfinished_tasks": [name for name, state in tasks.items() if not state["terminal"]],
                    "failed_tasks": failed_tasks,
                    "failed_pages": failed_pages, "failed_attachments": failed_attachments,
                    "gaps": inventory["gaps"] + inventory_omissions},
                "complete_within_scope": complete, "source_completeness_established": False,
                "html_index_signed_by_manifest": "index.html" in files,
                "meaning": "Integrity is checked relative to the signing key. Completion covers the frozen selected "
                           "tasks and observed outcomes, not all Telegram data, a simultaneous snapshot or trusted time."}


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


def verify_account_disclosure(path, expected_fingerprint=None, source=None, max_gib=None):
    with open_archive(path, max_gib=max_gib) as archive, tempfile.TemporaryDirectory() as temporary:
        manifest = read_manifest(archive)
        if manifest.get("format") not in DISCLOSURE_FORMATS:
            raise VerifierTooOld("Unsupported account disclosure format")
        # Version 2 keeps records the selection left out as content-free markers, and replies say what they answer.
        marked = manifest["format"] == "tgwitness-account-disclosure-v2"
        public = manifest["public_key"]
        fp = fingerprint(public)
        if manifest.get("fingerprint") != fp:
            raise ValueError("Disclosure fingerprint does not match its signing key")
        if expected_fingerprint and fp != expected_fingerprint:
            raise ValueError("Public key differs from the independently trusted fingerprint")
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public, validate=True))
        key.verify(base64.b64decode(read_member(archive, "manifest.sig"), validate=True), canonical(manifest))
        files = manifest["files"]
        if not isinstance(files, dict) or set(archive.namelist()) != set(files) | {"manifest.json", "manifest.sig"}:
            raise ValueError("Unexpected or missing disclosure archive members")
        allowed = {"messages.jsonl", "index.html", "analytics.json", "README.txt", "verify.py", "SHA256SUMS",
                   "VERIFY.cmd", "VERIFY.sh", "START_HERE.txt"}
        for name, checksum in files.items():
            if name not in allowed and not re.fullmatch(r"media/[0-9a-f]{64}", name):
                raise ValueError("Unexpected disclosure content: " + name)
            if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError("Invalid disclosure file hash")
            if member_digest(archive, name) != checksum:
                raise ValueError("File hash mismatch: " + name)
        if "messages.jsonl" not in files or "index.html" not in files:
            raise ValueError("Missing authoritative disclosure messages or readable index")
        sums = check_sums(archive, manifest)
        for field in ("source_archive_sha256", "source_collector_fingerprint"):
            if not isinstance(manifest.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest[field]):
                raise ValueError("Invalid disclosure source reference")
        if not isinstance(manifest.get("policy"), dict):
            raise ValueError("Disclosure must record its applied policy")
        seen = sqlite3.connect(Path(temporary) / "disclosure.sqlite3")
        seen.execute("CREATE TABLE messages (chat TEXT, id TEXT, state TEXT, PRIMARY KEY(chat,id)) WITHOUT ROWID")
        seen.execute("CREATE TABLE replies (chat TEXT, id TEXT, state TEXT)")
        media, messages, withheld = set(), 0, 0
        try:
            with archive.open("messages.jsonl") as stream:
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
                    state = message.get("state", "disclosed") if marked else "disclosed"
                    if marked and state not in ("disclosed", "withheld"):
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
                        withheld += count
                        continue
                    reply = message.get("reply_to") if marked else None
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
                                or files.get(name) != checksum or archive.getinfo(name).file_size != size):
                            raise ValueError("Disclosure attachment bytes/hash mismatch")
                        media.add(name)
                    messages += 1
            chats = seen.execute("SELECT COUNT(DISTINCT chat) FROM messages WHERE state='disclosed'").fetchone()[0]
            # A reply to a disclosed or withheld message must point at that record; only not_in_source points nowhere.
            dangling = seen.execute("SELECT count(*) FROM replies r LEFT JOIN messages m ON m.chat=r.chat AND m.id=r.id "
                                    "WHERE (r.state!='not_in_source' AND (m.id IS NULL OR m.state!=r.state)) "
                                    "OR (r.state='not_in_source' AND m.id IS NOT NULL)").fetchone()[0]
            if dangling:
                raise ValueError("A disclosed reply points at a record that is not in this disclosure")
        finally:
            seen.close()
        if {name for name in files if name.startswith("media/")} != media:
            raise ValueError("Unreferenced disclosure media")
        counts = {"messages": messages, "chats": chats, "media": len(media)}
        if marked:
            counts["withheld"] = withheld
        if (not isinstance(manifest.get("counts"), dict) or set(manifest["counts"]) != set(counts)
                or any(type(manifest["counts"][name]) is not int or manifest["counts"][name] != count
                       for name, count in counts.items())):
            raise ValueError("Disclosure manifest counts mismatch")
        source_checked = False
        if source is not None:
            with open(source, "rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            if checksum != manifest["source_archive_sha256"]:
                raise ValueError("Disclosure source archive hash mismatch")
            verify_account_export(source, manifest["source_collector_fingerprint"], max_gib=max_gib)
            source_checked = True
        return {"format": manifest["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
                "disclosure_id": manifest.get("disclosure_id"), "created_at": manifest.get("created_at"),
                "counts": counts, "policy": manifest["policy"], "files_checked": len(files), "sha256sums": sums,
                "source_archive_sha256": manifest["source_archive_sha256"],
                "source_collector_fingerprint": manifest["source_collector_fingerprint"],
                "source_reference_checked": source_checked, "derivation_correctness_established": False,
                "html_index_signed_by_manifest": True, "producer": manifest.get("producer"),
                "meaning": "The signature protects this disclosure's bytes and policy statement. "
                           "Source linkage does not establish correct filtering, redaction, legal compliance or completeness."}



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
                 "relays": confirmation["relays"]}
    return {"format": manifest["format"], "fingerprint": fp, "public_key": public, "events": result["events"],
            "head_hash": result["head_hash"], "interval_minutes": interval, "channel": manifest.get("channel"),
            "producer": manifest.get("producer"), "anchors": anchors, "no_response": silent, "posted": posted,
            "post_failures": failures, "statements": statements, "key_pinned": bool(expected_fingerprint),
            "freshness": freshness, "days": days, "missing_days": missing_days, "collector_keys": collector_keys}


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
# Catalogue SHA-256: 9160bce279cd7a93f6d16b76a5eab7d7e169afa1ee3fcd422c60b4f24ee90202
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
        self.say("  " + self.paint(self.t("Source authenticity and clock accuracy are not established by this check."), "dim"))
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


def main(argv=None):
    import builtins

    def print(*values, **kwargs):
        builtins.print(*(safe_text(v) if isinstance(v, str) else v for v in values), **kwargs)

    parser = argparse.ArgumentParser(description=__doc__)
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
    if args.interactive:
        if args.compare or args.compare_fingerprint or args.json or args.plain:
            parser.error("--interactive produces a readable single-archive check; comparison/JSON/plain options do not apply")
        if args.require_witness and (not args.witness or not args.witness_fingerprint):
            parser.error("--require-witness requires --witness and --witness-fingerprint")
        try:
            code = interactive_verify(args)
        except (EOFError, KeyboardInterrupt):
            print(reader_message("cancelled", console_language(args.lang)))
            code = 2
        if args.pause and not os.environ.get("TGWITNESS_VERIFY_NO_PAUSE"):
            try:
                input(reader_message("pause", console_language(args.lang)) + " ")
            except (EOFError, KeyboardInterrupt):
                pass
        raise SystemExit(code)
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
                print(json.dumps({"verified": False, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
                raise SystemExit(code)
            print("ASSURANCE: fail")
            parser.exit(code, "VERIFICATION FAILED: " + type(exc).__name__ + ": " + safe_text(exc) + "\n")
        pinned = bool(compared['first']['key_pinned'] and compared['second']['key_pinned'])
        compared['assurance'] = assurance(compared)
        compared['assurance']['scope'] = 'two authenticated chat exports; comparison does not prove event history'
        if mode == "json":
            print(json.dumps({"verified": True, "kind": "comparison", "result": compared,
                              "signer_pinned": pinned, "requirements_met": not args.strict or pinned},
                             indent=2, ensure_ascii=True))
        else:
            print(assurance_line(compared))
            print_comparison(compared)
        if args.strict and not pinned:
            raise SystemExit(2)
        return
    console = Console(sys.stdout, console_language(args.lang),
                      mode == "pretty" and not args.no_color and not os.environ.get("NO_COLOR"), args.explain) \
        if mode == "pretty" or args.explain and mode == "plain" else None
    notes = []

    pinned = bool(args.fingerprint or args.witness_fingerprint)
    shown = "evidence"
    spinner = console.spinner() if console else None
    if spinner:
        spinner.__enter__()
    try:
        if args.bundle.is_dir():
            if args.checkpoint or args.witness or args.tsa_ca or args.channel or args.evidence:
                raise ValueError("Journal/report options do not apply to a distributed acquisition directory")
            shown = "distributed"
            result = verify_distributed_work(args.bundle, args.fingerprint, args.max_gib)
            pinned = bool(args.fingerprint)
            notes.append(result["meaning"])
        elif args.bundle.suffix.lower() in (".html", ".htm", ".pdf"):
            shown, result = "report", verify_report(args.bundle, args.fingerprint, args.evidence)
            pinned = bool(args.fingerprint)
        elif args.bundle.suffix.lower() == ".json":
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
        elif (archive_format := bundle_format(args.bundle)) in DISCLOSURE_FORMATS:
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
    except Exception as exc:
        code = 3 if args.strict and isinstance(exc, VerifierTooOld) else 1
        if spinner:
            spinner.__exit__(None, None, None)
        if console:
            console.say("ASSURANCE: fail")
            console.failure(args.bundle, exc)
            raise SystemExit(code)
        if mode == "json":
            print(json.dumps({"verified": False, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
            raise SystemExit(code)
        print("ASSURANCE: fail")
        parser.exit(code, "VERIFICATION FAILED: " + type(exc).__name__ + ": " + safe_text(exc) + "\n")
    if spinner:
        spinner.__exit__(None, None, None)
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
        print(json.dumps({"verified": True, "kind": shown, "signer_pinned": pinned, "notes": notes, "result": result,
                          "requirements_met": not (unmet or unpinned)},
                         indent=2, ensure_ascii=True))
        if unmet or unpinned:
            raise SystemExit(2)
        return
    print(assurance_line(result))
    print(json.dumps(result, indent=2))
    print(producer_line(result.get("producer")))
    seal = result.get("report_seal")
    if seal:
        print("Report seal verified: " + ("chat.html" if shown == "chat" else "report.html" if shown == "evidence"
                                          else args.bundle.name) + ", language " + str(seal["language"]) + ".")
    if result.get("report_json"):
        print("JSON report seal verified: report.json.")
    pdf = result.get("report_pdf") or (result if result.get("pdf_signature") else None)
    if pdf:
        print("PDF signature and Ed25519 seal verified: " + str(pdf.get("file") or args.bundle.name)
              + " (certificate " + pdf["pdf_signature"]["certificate"] + ").")
    if result.get("report_parts"):
        print("Report parts verified: " + str(result["report_parts"]) + ", each sealed over this export.")
    ids = result.get("message_ids")
    if ids and ids["numbered_per_chat"]:
        print("Message IDs " + str(ids["first_id"]) + "-" + str(ids["last_id"]) + ": " + str(ids["present"])
              + " present, " + str(ids["missing"]) + " absent in " + str(ids["missing_ranges"])
              + " range(s); message-ids.json matches chat.json.")
    if result.get("sha256sums"):
        print("SHA256SUMS matches the signed manifest.")
    for line in notes:
        print(line)
    print("Integrity verified. Source authenticity and clock accuracy are not established.")
    if not pinned:
        print("Signer identity is unpinned: retain and compare the fingerprint independently.")
    if unmet or unpinned:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
