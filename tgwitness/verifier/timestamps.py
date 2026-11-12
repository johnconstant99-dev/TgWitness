from .common import (
    CheckUnavailable,
    InvalidSignature,
    OTS_BITCOIN,
    OTS_MAGIC,
    OTS_PENDING,
    Path,
    UnsupportedAlgorithm,
    VerifierTooOld,
    authenticate_statement,
    base64,
    datetime,
    ec,
    encode_dss_signature,
    hashes,
    hashlib,
    json,
    ocsp,
    padding,
    re,
    read_member,
    rsa,
    strict_json,
    struct,
    timezone,
    x509,
)
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


def timestamp_signature(reply, roots, *, include_reference=False, intermediates=()):
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
        candidates = list(trusted.values()) + [c for c in [*raw.values(), *intermediates] if c not in chain]
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


PUBLIC_BITCOIN_SOURCES = ("https://blockstream.info/api", "https://mempool.space/api")
BITCOIN_SOURCES = PUBLIC_BITCOIN_SOURCES


def use_bitcoin_sources(urls):
    from urllib.parse import urlsplit
    global BITCOIN_SOURCES
    clean = []
    for url in urls:
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password \
                or parts.query or parts.fragment:
            raise ValueError("--bitcoin-source needs an http(s) Esplora API address without credentials: " + url)
        clean.append(url.strip().rstrip("/"))
    BITCOIN_SOURCES = tuple(dict.fromkeys(clean)) or PUBLIC_BITCOIN_SOURCES


def bitcoin_fetcher():
    from .chain import hash_bytes
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
            raise ValueError("Bitcoin header sources disagree")
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
        agreed = ("two HTTPS explorers" if BITCOIN_SOURCES == PUBLIC_BITCOIN_SOURCES
                  else "the supplied source" if len(BITCOIN_SOURCES) == 1 else str(len(BITCOIN_SOURCES)) + " supplied sources")
        summary.update(status="confirmed", time=min(c["time"] for c in confirmed), blocks=confirmed,
                       verification="proof evaluated; headers with 6 confirmations agreed by " + agreed,
                       sources=list(BITCOIN_SOURCES))
    elif unreachable:
        summary["check"] = "unavailable"
    return summary


def tsa_roots(path):
    data = Path(path).read_bytes()
    try:
        roots = x509.load_pem_x509_certificates(data)
    except ValueError:
        roots = [x509.load_der_x509_certificate(data)]
    if not roots:
        raise ValueError("The --tsa-ca file holds no certificate")
    return roots


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


def stamp_time(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def revocation_subject(reply, extra=()):
    token = timestamp_token(reply)
    _, _, start, end = token["signer"]
    items = children(reply, start, end)
    if len(items) < 6 or items[3][0] != 0xA0:
        raise ValueError("The timestamp signer has no signed attributes")
    algorithm, named, _ = signing_certificate_hash(reply, signed_attributes(reply, items[3][2], items[3][3]))
    loaded, signer = {}, None
    for data in token["certificates"]:
        loaded[data] = x509.load_der_x509_certificate(data)
    for data in loaded:
        hasher = hashes.Hash(algorithm())
        hasher.update(data)
        if hasher.finalize() == named:
            signer = loaded[data]
    certificates = list(loaded.values())
    if signer is None:
        raise ValueError("The reply does not carry the certificate the signature names")
    for candidate in certificates + list(extra):
        if candidate.subject != signer.issuer:
            continue
        try:
            signer.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        return {"signer": signer, "issuer": candidate, "time": tst_info(token["tst"])["time"]}
    raise ValueError("The issuer of the signing certificate is neither in the reply nor in the given root file")


def ocsp_responder(response, issuer):
    for candidate in [issuer] + list(response.certificates):
        if response.responder_name is not None:
            named = candidate.subject == response.responder_name
        else:
            named = x509.SubjectKeyIdentifier.from_public_key(candidate.public_key()).digest == response.responder_key_hash
        if not named:
            continue
        if candidate.fingerprint(hashes.SHA256()) != issuer.fingerprint(hashes.SHA256()):
            try:
                candidate.verify_directly_issued_by(issuer)
                usage = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
                continue
            if (x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING not in usage
                    or not candidate.not_valid_before_utc <= response.produced_at_utc <= candidate.not_valid_after_utc):
                continue
        key = candidate.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(),
                           response.signature_hash_algorithm)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(response.signature_hash_algorithm))
            else:
                continue
        except InvalidSignature:
            continue
        return candidate
    raise ValueError("The OCSP response is not signed by the issuer or by a responder it authorised for OCSP signing")


def revocation_status(kind, data, subject):
    signer, issuer, when, source = subject["signer"], subject["issuer"], subject["time"], kind.upper()
    if kind == "ocsp":
        response = ocsp.load_der_ocsp_response(data)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("The OCSP responder answered " + response.response_status.name)
        found = None
        for single in response.responses:
            query = ocsp.OCSPRequestBuilder().add_certificate(signer, issuer, single.hash_algorithm).build()
            if (single.serial_number, single.issuer_name_hash, single.issuer_key_hash) == (
                    query.serial_number, query.issuer_name_hash, query.issuer_key_hash):
                found = single
        if found is None:
            raise ValueError("The OCSP response does not name this signing certificate")
        ocsp_responder(response, issuer)
        if found.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
            raise ValueError("The OCSP responder does not know this signing certificate")
        revoked = found.revocation_time_utc if found.certificate_status == ocsp.OCSPCertStatus.REVOKED else None
        reason, issued, until = found.revocation_reason, found.this_update_utc, found.next_update_utc
    elif kind == "crl":
        try:
            crl = x509.load_der_x509_crl(data)
        except ValueError:
            crl = x509.load_pem_x509_crl(data)
        if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
            raise ValueError("The CRL is not signed by the issuer of the signing certificate")
        entry = crl.get_revoked_certificate_by_serial_number(signer.serial_number)
        revoked = entry.revocation_date_utc if entry else None
        reason = next((e.value.reason for e in entry.extensions if isinstance(e.value, x509.CRLReason)), None) if entry else None
        issued, until = crl.last_update_utc, crl.next_update_utc
    else:
        raise ValueError("Unknown revocation evidence: " + kind)
    if revoked is not None:
        compromised = reason in (x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise)
        state = "revoked" if revoked <= when or compromised else "revoked_after"
        return {"status": state, "source": source, "revoked_at": stamp_time(revoked),
                "reason": reason.value if reason else None,
                "detail": "signing certificate revoked at " + stamp_time(revoked)
                          + (", before" if revoked <= when else ", after") + " the time stamp"
                          + (", for key compromise" if compromised else "") + " (" + source + ")"}
    if issued < when and (until is None or until < when):
        raise ValueError("The " + source + " answer of " + stamp_time(issued) + " expired before the stamped time")
    if issued > signer.not_valid_after_utc:
        raise ValueError("The " + source + " answer was issued after the signing certificate expired")
    return {"status": "good", "source": source, "as_of": stamp_time(issued),
            "detail": "signing certificate not revoked as of " + stamp_time(issued) + " (" + source + ")"}


def timestamp_revocation(archive, names, base, reply, tsa_ca=None):
    found = [kind for kind in ("ocsp", "crl") if base + "." + kind in names]
    if not found:
        return {"status": "not checked", "detail": "revocation not checked (no OCSP/CRL in the archive)"}
    try:
        extra = x509.load_pem_x509_certificates(Path(tsa_ca).read_bytes()) if tsa_ca else []
    except (OSError, ValueError):
        extra = []
    problems = []
    for kind in found:
        try:
            return revocation_status(kind, read_member(archive, base + "." + kind), revocation_subject(reply, extra))
        except (ValueError, TypeError, IndexError, InvalidSignature, UnsupportedAlgorithm) as exc:
            problems.append(kind.upper() + ": " + str(exc))
    return {"status": "failed", "error": "; ".join(problems), "detail": "revocation check failed: " + "; ".join(problems)}


def verify_anchors(archive, names, public_key, event_count, hash_at, tsa_ca=None, check_bitcoin=False):
    from .journal import verify_checkpoint
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
                    timestamp_signature(reply, tsa_roots(tsa_ca))
                entry["signature"] = "checked against the given root" if tsa_ca else "not checked (use --tsa-ca)"
                if tsa_ca:
                    entry.update(qualified_timestamp(reply))
                try:
                    entry.update(timestamp_certificate_reference(reply))
                except (ValueError, IndexError, TypeError):
                    entry["certificate_reference"] = "unavailable"
                entry["revocation"] = timestamp_revocation(archive, names, proof_name[:-4], reply, tsa_ca)
                if entry["revocation"]["status"] == "revoked":
                    raise ValueError("The " + service + " timestamp is invalid: its " + entry["revocation"]["detail"]
                                     + ("; reason " + entry["revocation"]["reason"] if entry["revocation"]["reason"] else ""))
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
    from .chain import canonical
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
    from .chain import fingerprint
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


