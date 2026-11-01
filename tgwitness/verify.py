"""Standalone verifier: python verify.py bundle.zip [--fingerprint SHA256] [--tsa-ca ROOT.pem].

Accepts a signed observation bundle (tgwitness-evidence-v1), a signed chat export
(tgwitness-chat-export-v1), a signed account export (tgwitness-account-export-v1),
a minimized disclosure (tgwitness-account-disclosure-v1), an independent witness
journal (tgwitness-witness-v1) or a
people-profile file (tgwitness-dossier-v1 JSON); the format is detected from the file.
For an observation bundle it also reports continuous observation periods, gaps and
message IDs that were never observed. With --witness WITNESS.zip it checks that every
journal head the witness saw is part of this journal, and with --channel it checks the
witness's channel posts against the witness journal.
Archives and checkpoints made before the rename carry tgwatch-* names and are accepted.
"""
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
import zipfile
from datetime import datetime, timezone
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
# A readable report ends with a seal: a signed statement over the SHA-256 of every byte before it.
SEAL_OPEN = b'<script type="application/tgwitness-seal+json" id="tgwitness-seal">'
SEAL_CLOSE = b"</script></body></html>\n"
SEAL_WINDOW = 1024 * 1024  # the seal is always within the last mebibyte of a report


def open_archive(path, max_gib=None):
    """Open a ZIP and enforce member count, duplicates and total expanded size before any read."""
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
        if sum(info.file_size for info in infos) > limit * 1024**3:
            raise ValueError("Bundle exceeds the verifier's size limit; raise it with --max-gib")
    except BaseException:
        archive.close()
        raise
    return archive


def read_member(archive, name, limit=MAX_SMALL_MEMBER_BYTES):
    """A whole member, bounded by both its declared size and the bytes actually produced."""
    if archive.getinfo(name).file_size > limit:
        raise ValueError(name + " exceeds the verifier's size limit for this member")
    with archive.open(name) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(name + " exceeds the verifier's size limit for this member")
    return data


def read_manifest(archive):
    return json.loads(read_member(archive, "manifest.json", MAX_MANIFEST_BYTES))


def member_digest(archive, name):
    digest = hashlib.sha256()
    with archive.open(name) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_lines(stream):
    """Lines of a journal or chat file, refusing one longer than any record could be."""
    for line in iter(lambda: stream.readline(MAX_RECORD_BYTES + 1), stream.read(0)):
        if len(line) > MAX_RECORD_BYTES:
            raise ValueError("A record exceeds the verifier's size limit")
        yield line


def read_json_file(path):
    path = Path(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(path.name + " exceeds the verifier's size limit")
    return json.loads(path.read_text(encoding="utf-8"))


def der(data, offset):
    """Tag, value start and value end of the DER element at offset."""
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
    """(tag, offset, value start, value end) of each DER element between start and end."""
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
    """The parts of an RFC 3161 reply, read strictly: status, the TSTInfo bytes, the certificates and
    the one SignerInfo of the signed data around them."""
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
    """Imprint algorithm and hash, time and nonce of a TSTInfo, by position as RFC 3161 defines it."""
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
    """Status and time of an RFC 3161 reply whose TSTInfo stamps exactly this SHA-256 (and the request's nonce).
    The signature is checked by timestamp_signature, or by OpenSSL with --tsa-ca."""
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
    """The hash algorithm and the hash of the signer's certificate named in the ESS attribute."""
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
    """Who signed an RFC 3161 reply, checked: the hash of the TSTInfo in the signed attributes, the
    signature over them, the certificate the ESS attribute names, its critical time-stamping key usage
    as its only use, and a chain valid at the stamped time up to one of the given root certificates."""
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
            "root_sha256": root.fingerprint(hashes.SHA256()).hex()}


def ots_summary(proof, digest):
    """Validate the OTS structure, not its commitment against a Bitcoin block.

    Attestation tags count only at tree leaves, never inside operation arguments
    or opaque attestation payloads. Keep this standalone and network-free: the
    recipient must still run `ots verify` to authenticate a Bitcoin timestamp.
    """
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

    def node(message_size, depth=0):
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
                    payload.integer()
                    payload.finish()
                    if message_size != 32:
                        raise ValueError("OpenTimestamps Bitcoin commitment must be 32 bytes")
                    kinds.add("bitcoin-unverified")
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
                node(size, depth + 1)
            if not more:
                return

    node(32)
    reader.finish()
    status = next(kind for kind in ("bitcoin-unverified", "pending", "unknown") if kind in kinds)
    return {"status": status, "verification": "structure only; run ots verify"}


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
    """Check the TSA signature and certificate chain against only the given root certificate."""
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


def verify_anchors(archive, names, public_key, event_count, hash_at, tsa_ca=None):
    """Checkpoints anchored in evidence mode: each checkpoint, then every answer stored for it."""
    results = []
    for name in sorted(n for n in names if n.startswith("anchors/") and n.endswith(".json")):
        data = read_member(archive, name)
        verify_checkpoint(json.loads(data), public_key, event_count, hash_at)
        digest, stem = hashlib.sha256(data).digest(), name[:-len(".json")] + "."
        for proof_name in sorted(n for n in names if n.startswith(stem) and n != name):
            service = proof_name[len(stem):].rsplit(".", 1)[0]
            entry = {"checkpoint": name[len("anchors/"):], "service": service}
            if proof_name.endswith(".tsr"):
                reply = read_member(archive, proof_name)
                query_name = proof_name[:-4] + ".tsq"
                query = read_member(archive, query_name) if query_name in names else None
                entry.update(kind="rfc3161", **timestamp_reply_summary(reply, digest, query))
                if tsa_ca:
                    openssl_verify_timestamp(data, reply, query, tsa_ca)
                entry["signature"] = "checked against the given root" if tsa_ca else "not checked (use --tsa-ca)"
            elif proof_name.endswith(".ots"):
                entry.update(kind="opentimestamps", **ots_summary(read_member(archive, proof_name), digest),
                             attestation="as the calendar states it; ots verify checks it against Bitcoin")
            else:
                continue
            results.append(entry)
    return results


def is_format(value, name):
    """True for tgwitness-<name>, or tgwatch-<name> written before the project was renamed."""
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
    """Streaming tree root using O(log n) memory, recomputed from exported events."""
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
    """RFC 9162 section 2.1.3.2; all unused/extra nodes are rejected."""
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
    """RFC 9162 section 2.1.4.2, plus explicit empty/equal tree cases."""
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
    """Authenticate the tree, its journal head and its extension of a retained boundary."""
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


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Coverage:
    """Continuous observation periods, gaps, and message IDs never observed, read from the journal.

    A period runs from "observation started" until a pause, a stop, a lost connection, a process
    restart, or a silence longer than three heartbeat intervals and at least three minutes (heartbeats
    come every minute unless the operator changed the interval; each heartbeat records it). Message
    IDs missing between observed ones are reported as "not observed", never as deleted: they may
    be deleted, never delivered, or simply outside the saved history.
    """
    def __init__(self):
        self.periods, self.gaps, self.notes = [], [], []
        self.start = self.alive = self.closed_at = self.close_reason = None
        self.observing = self.disconnected = False
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
                self.close(self.alive, "no records for " + str(round(silent / 60)) + " min while observing: "
                           "the process stopped, froze or the computer slept")
                self.open(at)
        interval = payload.get("interval_seconds") if kind == "collector.heartbeat" else \
            (payload.get("parameters") or {}).get("heartbeat_seconds") if kind == "observation.started" else None
        if type(interval) is int and interval > 0:
            self.allowed = max(LIVENESS_GAP_SECONDS, 3 * interval)
        changed = (payload.get("after") or {}).get("heartbeat_seconds") if kind == "parameters.changed" else None
        if type(changed) is int and changed > 0:

            self.allowed = max(self.allowed, 3 * changed)
        if kind == "observation.started":
            self.close(self.alive, "observation restarted")
            self.open(at)
            self.disconnected = False
        elif kind == "observation.stopped":
            self.close(at, "observation paused by the operator" if payload.get("reason") == "operator"
                       else "observation stopped: " + str(payload.get("reason") or "unknown"))
        elif kind == "process.stopped":
            self.close(at, "collector process stopped")
        elif kind == "process.started":
            self.close(self.alive, "collector process ended without an orderly stop")
        elif kind == "coverage.gap":
            reason = payload.get("reason")
            if chat_id is None and reason in INTERRUPTIONS:
                self.close(at, INTERRUPTIONS[reason])
                self.disconnected = reason == "transport_disconnected"
            else:
                self.notes.append({"at": at, "chat_id": chat_id, "reason": reason})
        elif kind == "connection.restored" and self.disconnected:
            self.disconnected = False
            self.open(at)
        if self.observing:
            self.alive = at
        if chat_id is not None and isinstance(payload.get("title"), str) and kind in (
                "target.changed", "source.discovered", "target.removed"):
            self.titles[chat_id] = payload["title"]
        if kind == "scope.applied":
            for added in payload.get("added") or []:
                self.titles[added.get("chat_id")] = added.get("title")
        if kind in MESSAGE_KINDS and chat_id is not None and chat_id < CHANNEL_IDS_BELOW \
                and isinstance(event["message_id"], int):
            self.ids.setdefault(chat_id, set()).add(event["message_id"])

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
            holes = [(a + 1, b - 1) for a, b in zip(ordered, ordered[1:]) if b - a > 1]
            unobserved.append({"chat_id": chat_id, "title": self.titles.get(chat_id),
                               "observed_from": ordered[0], "observed_to": ordered[-1], "observed": len(ordered),
                               "not_observed": sum(high - low + 1 for low, high in holes),
                               "ranges": [{"low": low, "high": high} for low, high in holes[:ranges_per_chat]],
                               "ranges_total": len(holes)})
        return {"continuous": periods, "gaps": gaps, "notes": self.notes[:200], "notes_total": len(self.notes),
                "unobserved_ids": unobserved, "first_record": self.first, "last_record": self.last,
                "meaning": "Continuous = observation on, connected and writing records at least every three "
                           "minutes (or every three heartbeat intervals when they are longer). IDs not observed were never seen by this collector; that is not evidence "
                           "that they were deleted. Only channels and supergroups number messages per chat."}


def coverage_lines(coverage):
    """Plain-language summary of Coverage.result() for people reading verifier output."""
    def span(seconds):
        hours, rest = divmod(int(seconds), 3600)
        return (str(hours) + " h " if hours else "") + str(rest // 60) + " min"
    lines = ["Continuously observed from " + p["from"] + " to " + p["to"] + " (" + span(p["seconds"]) + ")"
             + (", still observing at the last record" if p.get("still_observing") else "")
             for p in coverage["continuous"]]
    lines += ["Gap from " + g["from"] + " to " + g["to"] + ": " + str(g["reason"]) for g in coverage["gaps"]]
    for chat in coverage["unobserved_ids"]:
        if chat["not_observed"]:
            lines.append("Chat " + (chat["title"] or str(chat["chat_id"])) + ": IDs " + str(chat["observed_from"])
                         + "-" + str(chat["observed_to"]) + ", " + str(chat["not_observed"])
                         + " ID(s) not observed in " + str(chat["ranges_total"]) + " range(s) (not evidence of deletion)")
    return lines or ["No observation period recorded."]


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


# Readable reports --------------------------------------------------------------------------

def read_sealed(stream):
    """(SHA-256 of the bytes before the seal, seal) of a report; None when it has none (older exports)."""
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
    return digest.hexdigest(), json.loads(block[:-len(SEAL_CLOSE)])


def check_seal(sealed, public_key=None, expected_fingerprint=None):
    """What a sealed report says it describes, once its signature and its bytes are checked."""
    content, seal = sealed
    statement = seal["statement"]
    if not is_format(statement.get("format"), "report-seal-v1"):
        raise ValueError("Unsupported report seal")
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


def check_sums(archive, manifest):
    """SHA256SUMS (for sha256sum -c) must repeat the signed manifest's hash of every other file."""
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
    """A report handed over on its own: its seal and, with --evidence, the archive it describes."""
    with open(path, "rb") as stream:
        sealed = read_sealed(stream)
    if not sealed:
        raise ValueError("This report has no seal: it was made before seals or not by TgWitness")
    seal = check_seal(sealed, None, expected_fingerprint)
    subject = seal["subject"]
    result = {"format": "tgwitness-report-seal-v1", "fingerprint": seal["fingerprint"], "report_seal": seal,
              "producer": seal["producer"], "key_pinned": bool(expected_fingerprint), "evidence_checked": False}
    if evidence:
        if is_format(bundle_format(evidence), "chat-export-v1"):
            checked = verify_chat_export(evidence, expected_fingerprint)
            matches = checked["chat_json_sha256"] == subject.get("chat_json_sha256")
        else:
            checked = verify_bundle(evidence, expected_fingerprint)
            count = subject.get("event_count")
            # A report of an earlier export describes a prefix of a later journal.
            matches = type(count) is int and 0 <= count <= checked["events"] \
                and ("0" * 64 if count == 0 else bundle_hashes(evidence, [count]).get(count)) == subject.get("head_hash")
        if checked["fingerprint"] != seal["fingerprint"] or not matches:
            raise ValueError("The report describes a different archive")
        result["evidence_checked"] = True
    return result


def verify_bundle(path, expected_fingerprint=None, checkpoint=None, tsa_ca=None):
    with open_archive(path) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "evidence-v1"):
            raise ValueError("Unsupported evidence format")
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
        seal = archive_seal(archive, "report.html", public) if "report.html" in manifest["files"] else None
        if seal and (seal["subject"].get("event_count") != manifest["event_count"]
                     or seal["subject"].get("head_hash") != manifest["head_hash"]
                     or seal["subject"].get("events_sha256") != manifest["files"].get("events.jsonl")):
            raise ValueError("The report seal describes a different journal")
        observed = Coverage()

        def measured(lines):
            for line in lines:
                event = json.loads(line)
                media = media_reference(event)
                if media:
                    digest, size = media
                    name = "media/" + digest
                    if manifest["files"].get(name) != digest:
                        raise ValueError("Preserved media is missing or differs from the signed journal: " + digest)
                    if size is not None and archive.getinfo(name).file_size != size:
                        raise ValueError("Preserved media size differs from the signed journal: " + digest)
                observed.add(event)
                yield event
        with archive.open("events.jsonl") as stream:
            result = verify_events(measured(bounded_lines(stream)), public)
        if result["events"] != manifest["event_count"] or result["head_hash"] != manifest["head_hash"]:
            raise ValueError("Manifest does not match journal")
        result["coverage"] = observed.result()
        result["producer"] = manifest.get("producer")
        result.update(format=manifest["format"], files_checked=len(manifest["files"]), sha256sums=sums,
                      report_seal=seal, case=manifest.get("case") or {})

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
        result["anchors"] = verify_anchors(archive, names, public, result["events"], hash_at, tsa_ca)
        result["key_pinned"] = bool(expected_fingerprint)
        result["checkpoint_checked"] = checkpoint is not None
        return result


def verify_chat_export(path, expected_fingerprint=None):
    with open_archive(path) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "chat-export-v1"):
            raise ValueError("Unsupported chat export format")
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
        sums = check_sums(archive, manifest)
        seal = archive_seal(archive, "chat.html", public) if "chat.html" in manifest["files"] else None
        if seal and (seal["subject"].get("chat_id") != (manifest.get("chat") or {}).get("id")
                     or seal["subject"].get("message_count") != manifest.get("message_count")
                     or seal["subject"].get("chat_json_sha256") != manifest["files"].get("chat.json")):
            raise ValueError("The report seal describes a different chat export")
        return {"format": manifest["format"], "fingerprint": fp,
                "message_count": manifest.get("message_count"), "producer": manifest.get("producer"),
                "chat": manifest.get("chat"), "key_pinned": bool(expected_fingerprint), "parts": parts,
                "files_checked": len(manifest["files"]), "chat_json_sha256": manifest["files"].get("chat.json"),
                "sha256sums": sums, "report_seal": seal, "case": manifest.get("case") or {}}


def chat_messages(archive):
    """Stream messages from chat.json, written one message per line by TgWitness."""
    with archive.open("chat.json") as stream:
        inside = False
        for raw in bounded_lines(io.TextIOWrapper(stream, encoding="utf-8")):
            line = raw.strip()
            if not inside:
                inside = line.endswith('"messages": [')
                continue
            if line.startswith("]"):
                return
            if line.startswith("{"):
                yield json.loads(line.rstrip(","))


def verify_parts(archive, manifest):
    """Multi-account export: every account signed the ranges it fetched; recompute them."""
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
    """Authenticate a frozen account-export acquisition, without asserting Telegram completeness.

    The signed inventory fixes the selected tasks. Page receipts bind their original
    JSONL bytes and downloaded attachments before packaging; their global chain and
    per-task cursors must agree. A partial acquisition can be cryptographically valid.
    """
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
            raise ValueError("Unsupported account export format")
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
                        for attachment in attachments:
                            outcome = attachment.get("outcome")
                            if outcome == "saved":
                                checksum = digest(attachment["sha256"], "attachment hash")
                                media_name = "media/" + checksum
                                size = integer(attachment["bytes"], "attachment byte count")
                                if (attachment.get("file") != media_name or files.get(media_name) != checksum
                                        or archive.getinfo(media_name).file_size != size):
                                    raise ValueError("Account export attachment bytes/hash mismatch")
                                media_files.add(media_name)
                                counts["media_saved"] += 1
                                counts["bytes_saved"] += size
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
        if (integer(manifest["receipt_count"], "receipt count") != len(receipts)
                or digest(manifest["receipt_head_sha256"], "receipt head") != previous):
            raise ValueError("Account export manifest receipt boundary mismatch")
        declared_counts = manifest["counts"]
        if any(type(declared_counts.get(name)) is not int or declared_counts[name] != count for name, count in counts.items()):
            raise ValueError("Account export manifest counts mismatch")
        if "messages_exported" in declared_counts and declared_counts["messages_exported"] != counts["messages"]:
            raise ValueError("Account export message summary mismatch")
        if "messages_seen" in declared_counts and declared_counts["messages_seen"] != messages_seen:
            raise ValueError("Account export seen-message summary mismatch")
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


def verify_account_disclosure(path, expected_fingerprint=None, source=None, max_gib=None):
    """A separately signed minimized derivative; source linkage is not proof of derivation."""
    with open_archive(path, max_gib=max_gib) as archive, tempfile.TemporaryDirectory() as temporary:
        manifest = read_manifest(archive)
        if manifest.get("format") != "tgwitness-account-disclosure-v1":
            raise ValueError("Unsupported account disclosure format")
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
        allowed = {"messages.jsonl", "index.html", "README.txt", "verify.py", "SHA256SUMS"}
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
        seen.execute("CREATE TABLE messages (chat TEXT, id TEXT, PRIMARY KEY(chat,id)) WITHOUT ROWID")
        media, messages = set(), 0
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
                    try:
                        seen.execute("INSERT INTO messages VALUES (?,?)",
                                     (canonical(chat["id"]).decode(), canonical(message["id"]).decode()))
                    except sqlite3.IntegrityError:
                        raise ValueError("Duplicate disclosure message") from None
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
            chats = seen.execute("SELECT COUNT(DISTINCT chat) FROM messages").fetchone()[0]
        finally:
            seen.close()
        if {name for name in files if name.startswith("media/")} != media:
            raise ValueError("Unreferenced disclosure media")
        counts = {"messages": messages, "chats": chats, "media": len(media)}
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
    """{seq: hash} for the wanted records of an evidence bundle's events.jsonl, in one pass."""
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
    """Authenticate counters and bind them to the exact signed checkpoint."""
    statement = value["statement"]
    fields = {"format", "created_at", "public_key", "event_count", "head_hash", "challenge", "counts", "last_message_at", "health"}
    if set(value) != {"statement", "signature"} or set(statement) != fields:
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
    return statement


def bundle_capture_prefixes(bundle_path, boundaries):
    wanted, result = set(boundaries), {}
    tree = MerkleFrontier()
    counts, last = dict.fromkeys(CAPTURE_KINDS, 0), None
    if 0 in wanted:
        result[0] = {"head_hash": "0" * 64, "counts": dict(counts), "last_message_at": None,
                     "root": tree.root().hex()}
    if not wanted:
        return result
    limit = max(wanted)
    with open_archive(bundle_path) as archive, archive.open("events.jsonl") as stream:
        for line in bounded_lines(stream):
            event = json.loads(line)
            if event["seq"] > limit:
                break
            tree.append(event["hash"])
            if event["kind"] in counts:
                counts[event["kind"]] += 1
                if event["kind"].startswith("message."):
                    last = max(last or event["observed_at"], event["observed_at"])
            if event["seq"] in wanted:
                result[event["seq"]] = {"head_hash": event["hash"], "counts": dict(counts), "last_message_at": last,
                                        "root": tree.root().hex()}
    return result


def check_capture_prefix(value, bundle_path):
    """Recount a previously verified evidence prefix, including its last message time."""
    statement = value["statement"]
    prefix = bundle_capture_prefixes(bundle_path, [statement["event_count"]]).get(statement["event_count"])
    if prefix is None or prefix["head_hash"] != statement["head_hash"]:
        raise ValueError("Capture proof head is absent from the evidence")
    if prefix["counts"] != statement["counts"] or prefix["last_message_at"] != statement.get("last_message_at"):
        raise ValueError("Capture counters differ from the evidence records")
    return prefix["counts"]


WITNESS_TOKEN = re.compile(r"TGW1\.([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{40,})")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def post_statement(event, witness_fingerprint):
    """What a witness posts to its channel for one of its journal records (signed separately)."""
    payload = event["payload"]
    statement = {"format": "tgwitness-witness-post-v1", "witness": witness_fingerprint, "seq": event["seq"],
            "at": event["observed_at"], "record_hash": event["hash"],
            "status": payload.get("status") or ("no_response" if event["kind"] == "witness.no_response" else None),
            "collector": payload.get("collector_fingerprint"), "events": payload.get("event_count"),
            "head": payload.get("head_hash")}
    if payload.get("capture"):
        statement.update(capture_sha256=hashlib.sha256(canonical(payload["capture"])).hexdigest(),
                         counts=payload["capture"]["statement"]["counts"], delta=payload.get("capture_delta"))
    return statement


def post_token(statement, signature_b64):
    return "TGW1." + b64url(canonical(statement)) + "." + b64url(base64.b64decode(signature_b64))


def verify_witness(path, expected_fingerprint=None):
    """A witness journal export (tgwitness-witness-v1): signatures, chain, and what the witness saw."""
    with open_archive(path) as archive:
        names = archive.namelist()
        manifest = read_manifest(archive)
        if not is_format(manifest["format"], "witness-v1"):
            raise ValueError("Unsupported witness format")
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
        retained = {}

        def observed(stream):
            """One pass: each event is read when the chain check asks for it, then summarised."""
            nonlocal interval
            for line in bounded_lines(stream):
                if not line.strip():
                    continue
                event = json.loads(line)
                yield event
                payload, kind = event["payload"], event["kind"]
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
                    collector_key = payload.get("collector_fingerprint")
                    if payload.get("status") == "ok":
                        prior = retained.get(collector_key)
                        if payload.get("continuity") is not None:
                            if not payload.get("capture"):
                                raise ValueError("Continuity proof has no matching capture proof")
                            committed = verify_continuity(payload["continuity"], payload["checkpoint"]["statement"],
                                                          prior, captured["challenge"])
                            anchors[-1]["continuity"] = payload["continuity"]
                            anchors[-1]["root"] = committed["root"]
                        elif prior and prior.get("root"):
                            raise ValueError("Witness accepted a continuity downgrade")
                        retained[collector_key] = {k: anchors[-1][k] for k in ("event_count", "head_hash", "root")
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
    if result["events"] != manifest["event_count"] or result["head_hash"] != manifest["head_hash"]:
        raise ValueError("Witness manifest does not match its journal")
    return {"format": manifest["format"], "fingerprint": fp, "public_key": public, "events": result["events"],
            "head_hash": result["head_hash"], "interval_minutes": interval, "channel": manifest.get("channel"),
            "producer": manifest.get("producer"), "anchors": anchors, "no_response": silent, "posted": posted,
            "post_failures": failures, "statements": statements, "key_pinned": bool(expected_fingerprint)}


def witnessed_periods(witness, key=None):
    """Times the witness got consistent answers without a miss, and the gaps between them.
    With key, only answers signed by that collector key count as consistent."""
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
    """Every head the witness saw must be a prefix of the exported journal (same key, same hash)."""
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
            if (capture and (not prefix or any(prefix[k] != capture[k] for k in ("counts", "last_message_at")))
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
    return {"witness_fingerprint": witness["fingerprint"], "anchors_for_this_key": len(mine),
            "other_keys": len(witness["anchors"]) - len(mine) - invalid, "invalid_answers": invalid,
            "consistent": consistent, "conflicts": conflicts,
            "after_export": later, "anomalies": anomalies, "no_response": len(witness["no_response"]),
            "witnessed": periods, "witness_gaps": gaps,
            "verified_through_event": verified_through, "unwitnessed_events": count - verified_through,
            "continuity_verified_through_event": continuity_through,
            "export_head_witnessed": any(a["event_count"] == count for a in matched),
            "export_head_witness_records": [a["seq"] for a in matched if a["event_count"] == count],
            "witness_key_pinned": bool(witness.get("key_pinned"))}


def channel_texts(source):
    """(message id, date, text) of channel posts: a Telegram Desktop JSON export, a saved page or a t.me/s URL."""
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
    """Signed witness posts in the channel must match the witness journal record by record."""
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
    """A people-profile file: signature, and optionally every referenced record against an evidence export."""
    value = read_json_file(path)
    statement = value["statement"]
    if not is_format(statement.get("format"), "dossier-v1"):
        raise ValueError("Unsupported profile format")
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
    statement = value["statement"]
    if not is_format(statement.get("format"), "public-proof-v1"):
        raise ValueError("Unsupported public proof")
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
    statement = value["statement"]
    if not is_format(statement.get("format"), "history-report-v1"):
        raise ValueError("Unsupported history progress report")
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
                    if payload["account_id"] != statement["account_id"]:
                        raise ValueError("History report account differs from the journal")
                elif event["kind"] in ("message.snapshot", "history.message.unavailable"):
                    if event["chat_id"] not in counts:
                        raise ValueError("History report omits an acquired source")
                    key = "captured" if event["kind"] == "message.snapshot" else "unavailable"
                    counts[event["chat_id"]][key] += 1
        if observed_sources is None or set(observed_sources) != set(ids):
            raise ValueError("History report source plan differs from the journal")
        if any(counts[s["chat_id"]] != {key: s[key] for key in ("captured", "unavailable")} for s in sources):
            raise ValueError("History report counts differ from the journal")
        checked = True
    return {"format": statement["format"], "fingerprint": fp, "key_pinned": bool(expected_fingerprint),
            "history_run_id": statement["id"], "phase": statement["phase"], "captured": statement["captured"],
            "unavailable": statement["unavailable"], "sources_total": statement["sources_total"],
            "evidence_counts_checked": checked, "checkpoint_event_count": boundary,
            "limitation": "Journal comparison checks the source plan, account and message counters. "
                          "Other progress fields are signed statements only. No proof of Telegram origin "
                          "or historical completeness."}


def producer_line(producer):
    if not producer:
        return "Producer: not named in this (older) archive."
    return ("Producer (signed): " + str(producer.get("software")) + " " + str(producer.get("version")) + " - "
            + str(producer.get("project")) + " - " + str(producer.get("homepage")))


def fingerprint_colors(value):
    """Sixteen (hue, saturation, lightness) blocks drawn from a fingerprint, the same in report and console:
    two copies whose colours differ were signed by different keys. Compare the full hex to be sure."""
    data = bytes.fromhex(value)
    return [(data[i] * 360 // 256, 68, 40 + data[i + 1] % 24) for i in range(0, 32, 2)]


# Console -----------------------------------------------------------------------------------

SAY = {
    "ru": {
        "TgWitness verifier": "Проверка TgWitness",
        "Signed Telegram evidence · Ed25519 · SHA-256": "Подписанные доказательства из Telegram · Ed25519 · SHA-256",
        "File": "Файл", "Type": "Тип", "Signer": "Подписант", "Checks": "Проверки", "Timestamps": "Метки времени",
        "Coverage": "Покрытие наблюдения", "Case": "Дело", "Notes": "Примечания", "Details": "Подробности",
        "Evidence archive": "Архив доказательств", "Chat export": "Экспорт чата", "Witness journal": "Журнал свидетеля",
        "People profiles": "Профили людей", "Public proof": "Публичное доказательство",
        "Sealed report": "Опечатанный отчёт", "History report": "Отчёт об истории",
        "Manifest signature": "Подпись манифеста", "Ed25519 · valid": "Ed25519 · верна",
        "Signature": "Подпись", "File hashes": "Хеши файлов",
        "{n} files · SHA-256 match": "файлов: {n} · SHA-256 совпадают",
        "Record chain": "Цепочка записей", "{n} records · head {hash}": "записей: {n} · вершина {hash}",
        "Messages": "Сообщения", "{n} messages · {title}": "сообщений: {n} · {title}",
        "Accounts": "Аккаунты", "{n} account(s) signed their message ranges": "аккаунтов: {n}, каждый подписал свои диапазоны",
        "Report seal": "Печать отчёта", "{name} · intact · language {lang}": "{name} · не изменён · язык {lang}",
        "not present (older export)": "нет (экспорт старой версии)",
        "matches the signed manifest": "совпадает с подписанным манифестом",
        "Retained checkpoint": "Сохранённая контрольная точка", "matches the journal": "совпадает с журналом",
        "not supplied: removed trailing records would go unnoticed":
            "не передана: удаление последних записей останется незамеченным",
        "Key pinning": "Привязка ключа", "matches your trusted fingerprint": "совпадает с вашим доверенным отпечатком",
        "not pinned: compare the fingerprint with a copy kept elsewhere":
            "не привязан: сверьте отпечаток с копией, хранящейся отдельно",
        "Witness": "Свидетель", "checkpoints match through record {a} of {b}": "контрольные точки совпадают до записи {a} из {b}",
        "Described archive": "Описываемый архив", "verified and matches the seal": "проверен и совпадает с печатью",
        "not supplied (--evidence)": "не передан (--evidence)",
        "Describes": "Описывает", "checkpoint #{n}": "точка #{n}",
        "signature chained to your root": "подпись проверена до вашего корня",
        "signature not checked: add --tsa-ca": "подпись не проверена: добавьте --tsa-ca",
        "pending: run ots upgrade, then ots verify": "ожидает: выполните ots upgrade, затем ots verify",
        "in Bitcoin: confirm with ots verify": "в Bitcoin: подтвердите через ots verify",
        "No independent timestamps: times come from the collector's clock.":
            "Независимых меток нет: время — по часам коллектора.",
        "INTEGRITY VERIFIED": "ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА", "VERIFICATION FAILED": "ПРОВЕРКА НЕ ПРОЙДЕНА",
        "Source authenticity and clock accuracy are not established by this check.":
            "Эта проверка не устанавливает подлинность источника и точность часов.",
        "… and {n} more": "… и ещё {n}", "Checking signatures, hashes and the record chain":
            "Проверяю подписи, хеши и цепочку записей",
        "Title": "Название", "Case ID": "Номер дела", "Examiner": "Эксперт", "Organization": "Организация",
        "Produced by": "Создано",
    },
    "uk": {
        "TgWitness verifier": "Перевірка TgWitness",
        "Signed Telegram evidence · Ed25519 · SHA-256": "Підписані докази з Telegram · Ed25519 · SHA-256",
        "File": "Файл", "Type": "Тип", "Signer": "Підписант", "Checks": "Перевірки", "Timestamps": "Мітки часу",
        "Coverage": "Покриття спостереження", "Case": "Справа", "Notes": "Примітки", "Details": "Подробиці",
        "Evidence archive": "Архів доказів", "Chat export": "Експорт чату", "Witness journal": "Журнал свідка",
        "People profiles": "Профілі людей", "Public proof": "Публічний доказ", "Sealed report": "Опечатаний звіт", "History report": "Звіт про історію",
        "Manifest signature": "Підпис маніфесту", "Ed25519 · valid": "Ed25519 · дійсний",
        "Signature": "Підпис", "File hashes": "Хеші файлів",
        "{n} files · SHA-256 match": "файлів: {n} · SHA-256 збігаються",
        "Record chain": "Ланцюжок записів", "{n} records · head {hash}": "записів: {n} · вершина {hash}",
        "Messages": "Повідомлення", "{n} messages · {title}": "повідомлень: {n} · {title}",
        "Accounts": "Акаунти", "{n} account(s) signed their message ranges": "акаунтів: {n}, кожен підписав свої діапазони",
        "Report seal": "Печатка звіту", "{name} · intact · language {lang}": "{name} · не змінено · мова {lang}",
        "not present (older export)": "немає (експорт старої версії)",
        "matches the signed manifest": "збігається з підписаним маніфестом",
        "Retained checkpoint": "Збережена контрольна точка", "matches the journal": "збігається з журналом",
        "not supplied: removed trailing records would go unnoticed":
            "не передано: видалення останніх записів залишиться непоміченим",
        "Key pinning": "Прив'язка ключа", "matches your trusted fingerprint": "збігається з вашим довіреним відбитком",
        "not pinned: compare the fingerprint with a copy kept elsewhere":
            "не прив'язаний: звірте відбиток із копією, що зберігається окремо",
        "Witness": "Свідок", "checkpoints match through record {a} of {b}": "контрольні точки збігаються до запису {a} з {b}",
        "Described archive": "Описуваний архів", "verified and matches the seal": "перевірено, збігається з печаткою",
        "not supplied (--evidence)": "не передано (--evidence)",
        "Describes": "Описує", "checkpoint #{n}": "точка #{n}",
        "signature chained to your root": "підпис перевірено до вашого кореня",
        "signature not checked: add --tsa-ca": "підпис не перевірено: додайте --tsa-ca",
        "pending: run ots upgrade, then ots verify": "очікує: виконайте ots upgrade, потім ots verify",
        "in Bitcoin: confirm with ots verify": "у Bitcoin: підтвердіть через ots verify",
        "No independent timestamps: times come from the collector's clock.":
            "Незалежних міток немає: час — за годинником колектора.",
        "INTEGRITY VERIFIED": "ЦІЛІСНІСТЬ ПІДТВЕРДЖЕНО", "VERIFICATION FAILED": "ПЕРЕВІРКУ НЕ ПРОЙДЕНО",
        "Source authenticity and clock accuracy are not established by this check.":
            "Ця перевірка не встановлює автентичність джерела і точність годинника.",
        "… and {n} more": "… і ще {n}", "Checking signatures, hashes and the record chain":
            "Перевіряю підписи, хеші та ланцюжок записів",
        "Title": "Назва", "Case ID": "Номер справи", "Examiner": "Експерт", "Organization": "Організація",
        "Produced by": "Створено",
    },
}
KINDS = {"evidence": "Evidence archive", "chat": "Chat export", "account": "Account export",
         "account_disclosure": "Account disclosure", "witness": "Witness journal",
         "dossier": "People profiles", "proof": "Public proof", "report": "Sealed report",
         "history": "History report"}


def console_language(choice=None):
    """--lang, else the terminal's locale when it is Russian or Ukrainian, else English."""
    if choice:
        return choice
    value = next((os.environ[name] for name in ("LC_ALL", "LC_MESSAGES", "LANG") if os.environ.get(name)), "")
    if not value:
        import locale
        value = locale.getlocale()[0] or ""
    value = value.lower()
    return "ru" if value.startswith(("ru", "russian")) else "uk" if value.startswith(("uk", "ukrainian")) else "en"


def enable_ansi(stream):
    """Windows consoles show colours once virtual terminal processing is switched on."""
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


class Console:
    """The verifier's answer for a person at a terminal; scripts and pipes get the plain form."""
    WIDTH = 66
    STYLES = {"ok": "1;32", "bad": "1;31", "warn": "1;33", "dim": "2", "bold": "1", "accent": "1;38;5;75",
              "okbar": "1;97;42", "badbar": "1;97;41"}

    def __init__(self, stream, lang="en", color=True):
        try:
            "".join(SAY.get(lang, {}).values()).encode(stream.encoding or "ascii")
        except (LookupError, UnicodeEncodeError):
            lang = "en"  # a console that cannot show the language gets English rather than escapes
        self.stream, self.words, self.lang = stream, SAY.get(lang, {}), lang
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
        return "\033[" + self.STYLES[style] + "m" + text + "\033[0m" if self.color and style else text

    def say(self, text=""):
        self.stream.write(text + "\n")

    def number(self, value):
        return format(value, ",").replace(",", " " if self.lang in SAY else ",") if type(value) is int else str(value)

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
        self.say("  " + self.paint(self.glyph[mark[0]], mark[1]) + " " + self.t(label).ljust(24) + " "
                 + (self.paint(detail, "dim") if state == "none" else detail))

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

    def verdict(self, ok, reason=""):
        text = " " + (self.glyph["ok"] if ok else self.glyph["bad"]) + "  " \
               + self.t("INTEGRITY VERIFIED" if ok else "VERIFICATION FAILED") + " "
        self.say()
        if self.color:
            self.say("  " + self.paint(text.ljust(self.WIDTH - 2), "okbar" if ok else "badbar"))
        else:
            self.say("  " + self.glyph["tl"] + self.glyph["h"] * (self.WIDTH - 4) + self.glyph["tr"])
            self.say("  " + self.glyph["v"] + text.ljust(self.WIDTH - 4) + self.glyph["v"])
            self.say("  " + self.glyph["bl"] + self.glyph["h"] * (self.WIDTH - 4) + self.glyph["br"])
        if reason:
            self.say("  " + self.paint(reason, "bad"))

    def spinner(self):
        return Spinner(sys.stderr, self.t("Checking signatures, hashes and the record chain"), self.glyph["spin"])

    def failure(self, path, exc):
        self.field("File", str(path))
        self.verdict(False, type(exc).__name__ + ": " + str(exc))
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
                pending = anchor.get("status") == "pending"
                self.check("wait" if pending else "ok", "OpenTimestamps · " + anchor["service"][:10],
                           point + " · " + self.t("pending: run ots upgrade, then ots verify" if pending
                                                  else "in Bitcoin: confirm with ots verify"))

    def lines(self, label, lines, limit=8):
        if not lines:
            return
        self.heading(label)
        for line in lines[:limit]:
            self.say("  " + self.paint(self.glyph["dot"], "dim") + " " + line)
        if len(lines) > limit:
            self.say("  " + self.paint(self.t("… and {n} more", n=len(lines) - limit), "dim"))

    def show(self, shown, path, result, notes, pinned):
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
                self.check("warn", "Retained checkpoint", self.t("not supplied: removed trailing records would go unnoticed"))
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
        elif shown == "report":
            seal = result["report_seal"]
            subject = seal["subject"]
            self.check("ok", "Report seal", self.t("{name} · intact · language {lang}", name=path.name, lang=seal["language"]))
            described = (self.t("{n} records · head {hash}", n=self.number(subject.get("event_count")),
                                hash=str(subject.get("head_hash"))[:8] + "…") if "event_count" in subject else
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
            self.lines("Coverage", coverage_lines(result["coverage"]))
            notes = [n for n in notes if n not in coverage_lines(result["coverage"])
                     and not n.startswith("No retained checkpoint")]
        elif shown == "account":
            self.lines("Coverage", account_export_lines(result), limit=12)
            notes = [note for note in notes if note not in account_export_lines(result)]
        elif shown == "account_disclosure":
            self.lines("Details", ["messages: " + str(result["counts"]["messages"]),
                                   "chats: " + str(result["counts"]["chats"]), "media: " + str(result["counts"]["media"]),
                                   result["meaning"]])
        elif shown not in ("chat", "report"):
            facts = [key + ": " + json.dumps(value, ensure_ascii=False) for key, value in result.items()
                     if isinstance(value, (str, int, bool)) and key != "fingerprint"]
            self.lines("Details", facts, limit=12)
        self.lines("Notes", notes)
        self.case(result.get("case") or (result.get("report_seal") or {}).get("case") or {})
        self.verdict(True)
        producer = result.get("producer")
        if producer:
            self.say("  " + self.paint(self.t("Produced by") + ": " + str(producer.get("software")) + " "
                                       + str(producer.get("version")) + " · " + str(producer.get("project")) + " · "
                                       + str(producer.get("homepage")), "dim"))
        self.say("  " + self.paint(self.t("Source authenticity and clock accuracy are not established by this check."), "dim"))
        self.say()


class Spinner:
    """A small animation on stderr while large archives are hashed; gone before the answer is printed."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path,
                        help="Evidence/chat/account/disclosure/witness ZIP, profile/proof/history report JSON, or a sealed report HTML")
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
    parser.add_argument("--max-gib", type=int, default=MAX_UNCOMPRESSED_GIB,
                        help="Largest uncompressed archive to read, in GiB (default 4)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--pretty", action="store_true", help="Readable, coloured answer (default at a terminal)")
    output.add_argument("--plain", action="store_true", help="Plain text answer (default when piped)")
    output.add_argument("--json", action="store_true", help="Only a JSON answer, for scripts")
    parser.add_argument("--no-color", action="store_true", help="No colours (also with the NO_COLOR variable)")
    parser.add_argument("--lang", choices=("en", "ru", "uk"), help="Language of the readable answer")
    args = parser.parse_args()
    if args.require_witness and (not args.witness or not args.witness_fingerprint):
        parser.error("--require-witness requires --witness and --witness-fingerprint")
    globals()["MAX_UNCOMPRESSED_GIB"] = max(1, args.max_gib)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    mode = "json" if args.json else "pretty" if args.pretty or (not args.plain and sys.stdout.isatty()) else "plain"
    console = Console(sys.stdout, console_language(args.lang), not args.no_color and not os.environ.get("NO_COLOR")) \
        if mode == "pretty" else None
    if console:
        console.banner()
    elif mode == "plain":
        print("TgWitness verifier - PhishDestroy - https://github.com/phishdestroy/TgWitness")
    notes = []

    pinned = bool(args.fingerprint or args.witness_fingerprint)
    shown = "evidence"
    spinner = console.spinner() if console else None
    if spinner:
        spinner.__enter__()
    try:
        if args.bundle.suffix.lower() in (".html", ".htm"):
            shown, result = "report", verify_report(args.bundle, args.fingerprint, args.evidence)
            pinned = bool(args.fingerprint)
        elif args.bundle.suffix.lower() == ".json":
            kind = read_json_file(args.bundle).get("statement", {}).get("format")
            if is_format(kind, "public-proof-v1"):
                shown = "proof"
                result = verify_public_proof(args.bundle, args.fingerprint, args.witness_fingerprint, args.evidence)
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
        elif (archive_format := bundle_format(args.bundle)) == "tgwitness-account-disclosure-v1":
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
        elif is_format(archive_format, "witness-v1"):
            shown = "witness"
            result = verify_witness(args.bundle, args.witness_fingerprint or args.fingerprint)
            if args.channel:
                result["channel_check"] = check_channel(result, args.channel)
            result.pop("statements")
        else:
            result = verify_bundle(args.bundle, args.fingerprint,
                                   read_json_file(args.checkpoint) if args.checkpoint else None, args.tsa_ca)
            notes += coverage_lines(result["coverage"])
            pinned = bool(args.fingerprint)
            if not args.checkpoint:
                notes.append("No retained checkpoint supplied: records removed from the end of this journal are not "
                             "detected. Pass --checkpoint with a checkpoint kept away from the collector.")
            if any(a.get("kind") == "opentimestamps" for a in result.get("anchors", [])):
                notes.append("OpenTimestamps structure only: run ots verify to authenticate the Bitcoin timestamp.")
            if args.witness and not args.witness_fingerprint:
                notes.append("The witness key is not pinned: the witness journal is checked only against itself.")
            if args.witness:
                witness = verify_witness(args.witness, args.witness_fingerprint)
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
    except Exception as exc:
        if spinner:
            spinner.__exit__(None, None, None)
        if console:
            console.failure(args.bundle, exc)
            raise SystemExit(1)
        if mode == "json":
            print(json.dumps({"verified": False, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
            raise SystemExit(1)
        parser.exit(1, "VERIFICATION FAILED: " + type(exc).__name__ + ": " + str(exc) + "\n")
    if spinner:
        spinner.__exit__(None, None, None)
    if console:
        console.show(shown, args.bundle, result, notes, pinned)
        return
    if mode == "json":
        print(json.dumps({"verified": True, "kind": shown, "signer_pinned": pinned, "notes": notes, "result": result},
                         indent=2, ensure_ascii=False))
        return
    print(json.dumps(result, indent=2))
    print(producer_line(result.get("producer")))
    seal = result.get("report_seal")
    if seal:
        print("Report seal verified: " + ("chat.html" if shown == "chat" else "report.html" if shown == "evidence"
                                          else args.bundle.name) + ", language " + str(seal["language"]) + ".")
    if result.get("sha256sums"):
        print("SHA256SUMS matches the signed manifest.")
    for line in notes:
        print(line)
    print("Integrity verified. Source authenticity and clock accuracy are not established.")
    if not pinned:
        print("Signer identity is unpinned: retain and compare the fingerprint independently.")


if __name__ == "__main__":
    main()
