import base64
import hashlib
import json
import struct
from datetime import datetime, timezone
from urllib.parse import unquote

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding

from .verify import canonical, children, der, oid

INTEL_ROOT_DER = base64.b64decode(
    "MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIwaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3Qg"
    "Q0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT"
    "AlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoM"
    "EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZI"
    "zj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxF"
    "P2sJBK5zlKOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2Nl"
    "cnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInz"
    "g7SVUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYIKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9C"
    "iSDcNoowLuPRLsWGf/Yi7GSX94BgwTwgAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=")
INTEL_ROOT_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
PCS = "https://api.trustedservices.intel.com"
ROOT_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
INTEL_QE_VENDOR = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
TDX, ECDSA_P256 = 0x81, 2
BODIES = {2: 584, 3: 648, 4: 885}
SGX_EXTENSION, TCB, PCEID, FMSPC = ("1.2.840.113741.1.13.1", "1.2.840.113741.1.13.1.2", "1.2.840.113741.1.13.1.3",
                                    "1.2.840.113741.1.13.1.4")
DSTACK_EVENT = 0x08000001
STATUSES = ("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded",
            "OutOfDate", "OutOfDateConfigurationNeeded", "Revoked")
QE_STATUSES = ("UpToDate", "OutOfDate", "ConfigurationNeeded", "OutOfDateConfigurationNeeded", "Revoked")
MODULE_STATUSES = ("UpToDate", "OutOfDate", "Revoked")
RESERVED_ATTRIBUTES = sum(1 << bit for bit in (*range(1, 4), *range(7, 16), *range(23, 27), *range(32, 62)))
MEASUREMENTS = ("mrtd", "rtmr0", "rtmr1", "rtmr2")
IDENTITY_EVENTS = ("app-id", "compose-hash", "instance-id", "key-provider", "os-image-hash", "storage-encrypted",
                   "storage-fs")


class QuoteError(ValueError):
    pass


def intel_root():
    certificate = x509.load_der_x509_certificate(INTEL_ROOT_DER)
    if certificate.fingerprint(hashes.SHA256()).hex() != INTEL_ROOT_SHA256:
        raise QuoteError("The pinned Intel root certificate is damaged")
    return certificate


def report_data(value):
    return hashlib.sha512(canonical(value)).digest()


def td_report(body, kind):
    names = ("tee_tcb_svn", 16), ("mr_seam", 48), ("mr_signer_seam", 48), ("seam_attributes", 8), \
        ("td_attributes", 8), ("xfam", 8), ("mrtd", 48), ("mr_config_id", 48), ("mr_owner", 48), \
        ("mr_owner_config", 48), ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48), ("report_data", 64)
    if kind in (3, 4):
        names += ("tee_tcb_svn2", 16), ("mr_service_td", 48)
    report, offset = {}, 0
    for name, size in names:
        report[name], offset = body[offset:offset + size], offset + size
    return report


def parse_quote(raw):
    raw = bytes(raw)
    if len(raw) < 48:
        raise QuoteError("The quote is truncated")
    version, key_type, tee = struct.unpack_from("<HHI", raw, 0)
    if tee != TDX:
        raise QuoteError("Not an Intel TDX quote")
    if key_type != ECDSA_P256:
        raise QuoteError("Unsupported attestation key type " + str(key_type))
    if raw[12:28] != INTEL_QE_VENDOR:
        raise QuoteError("The quote was not produced by Intel's quoting enclave")
    if version == 4:
        kind, size, offset = 2, BODIES[2], 48
    elif version == 5:
        if len(raw) < 54:
            raise QuoteError("The quote is truncated")
        kind, size = struct.unpack_from("<HI", raw, 48)
        if BODIES.get(kind) != size:
            raise QuoteError("Unsupported TD report body " + str(kind) + " of " + str(size) + " bytes")
        offset = 54
    else:
        raise QuoteError("Unsupported quote version " + str(version))
    signed = offset + size
    if len(raw) < signed + 4:
        raise QuoteError("The quote is truncated")
    length = struct.unpack_from("<I", raw, signed)[0]
    auth = raw[signed + 4:signed + 4 + length]
    if len(auth) != length or len(auth) < 134 or raw[signed + 4 + length:].strip(b"\0"):
        raise QuoteError("The quote's signature data has the wrong length")
    cert_type, cert_size = struct.unpack_from("<HI", auth, 128)
    cert = auth[134:134 + cert_size]
    if cert_type != 6 or len(cert) != cert_size or len(cert) < 456:
        raise QuoteError("The quote carries no quoting enclave report")
    qe_auth_size = struct.unpack_from("<H", cert, 448)[0]
    inner = 450 + qe_auth_size
    if len(cert) < inner + 6:
        raise QuoteError("The quote's certification data is truncated")
    chain_type, chain_size = struct.unpack_from("<HI", cert, inner)
    chain = cert[inner + 6:inner + 6 + chain_size]
    if chain_type != 5 or len(chain) != chain_size:
        raise QuoteError("The quote carries no PCK certificate chain")
    return {"version": version, "body": kind, "signed": raw[:signed], "report": td_report(raw[offset:signed], kind),
            "signature": auth[0:64], "attestation_key": auth[64:128], "qe_report": cert[0:384],
            "qe_signature": cert[384:448], "qe_auth": cert[450:inner], "pck_chain": chain.rstrip(b"\0")}


def ecdsa(raw):
    if len(raw) != 64:
        raise QuoteError("Expected a 64-byte ECDSA P-256 signature")
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def check_signature(key, signature, data, what):
    try:
        key.verify(ecdsa(signature), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        raise QuoteError(what + ": the signature is invalid") from None


def pem_chain(text):
    data = text.encode() if isinstance(text, str) else bytes(text)
    try:
        return x509.load_pem_x509_certificates(data.rstrip(b"\0"))
    except ValueError:
        raise QuoteError("Unreadable certificate chain") from None


def chain_summary(raw):
    """The quote's PCK certificate chain as it is, for a report; verify_quote decides whether it is trusted."""
    return [{"subject": certificate.subject.rfc4514_string(), "issuer": certificate.issuer.rfc4514_string(),
             "serial": format(certificate.serial_number, "x"),
             "not_before": certificate.not_valid_before_utc.isoformat(),
             "not_after": certificate.not_valid_after_utc.isoformat(),
             "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
             "pinned_root": certificate.fingerprint(hashes.SHA256()).hex() == INTEL_ROOT_SHA256}
            for certificate in pem_chain(parse_quote(raw)["pck_chain"])]


def in_window(start, end, now):
    return (start is None or start <= now) and (end is None or now <= end)


def crl_list(data, issuer, now, what):
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        raise QuoteError(what + " is unreadable") from None
    if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
        raise QuoteError(what + " is not signed by " + issuer.subject.rfc4514_string())
    if not in_window(crl.last_update_utc, crl.next_update_utc, now):
        raise QuoteError(what + " is not current")
    return crl


def check_chain(chain, root, crls, now, what):
    chain = list(chain)
    if chain and chain[-1].public_bytes(Encoding.DER) == root.public_bytes(Encoding.DER):
        chain = chain[:-1]
    if not chain:
        raise QuoteError(what + ": no certificates")
    for index, certificate in enumerate(chain):
        issuer = chain[index + 1] if index + 1 < len(chain) else root
        try:
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature):
            raise QuoteError(what + ": " + certificate.subject.rfc4514_string() + " is not issued by "
                             + issuer.subject.rfc4514_string()) from None
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            constraints = None
        if not constraints or not constraints.ca:
            raise QuoteError(what + ": " + issuer.subject.rfc4514_string() + " is not a certificate authority")
        for checked in (certificate, issuer):
            if not checked.not_valid_before_utc <= now <= checked.not_valid_after_utc:
                raise QuoteError(what + ": " + checked.subject.rfc4514_string() + " is not valid at "
                                 + now.isoformat())
    for index, certificate in enumerate(chain):
        issuer = chain[index + 1] if index + 1 < len(chain) else root
        crl = crls.get(issuer.subject.public_bytes())
        if crl is None:
            raise QuoteError(what + ": no revocation list from " + issuer.subject.rfc4514_string())
        if crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None:
            raise QuoteError(what + ": " + certificate.subject.rfc4514_string() + " is revoked")
    return chain


def pck_extension(certificate):
    try:
        data = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(SGX_EXTENSION)).value.value
    except x509.ExtensionNotFound:
        raise QuoteError("The PCK certificate has no Intel SGX extension") from None
    found = {}
    _, start, end = der(data, 0)
    for _, _, item_start, item_end in children(data, start, end):
        parts = children(data, item_start, item_end)
        if len(parts) != 2 or parts[0][0] != 0x06:
            continue
        name, (_, _, value_start, value_end) = oid(data, *parts[0][2:]), parts[1]
        if name == TCB:
            for _, _, c_start, c_end in children(data, value_start, value_end):
                sub = children(data, c_start, c_end)
                component, (s_tag, _, s_start, s_end) = oid(data, *sub[0][2:]), sub[1]
                number = int(component.rsplit(".", 1)[1])
                value = data[s_start:s_end]
                found["tcb." + str(number)] = value if s_tag == 0x04 else int.from_bytes(value, "big")
        else:
            found[name] = data[value_start:value_end]
    try:
        cpu_svn = bytes(found["tcb." + str(i)] for i in range(1, 17))
        return {"cpu_svn": cpu_svn, "pce_svn": found["tcb.17"], "pce_id": found[PCEID], "fmspc": found[FMSPC]}
    except (KeyError, TypeError, ValueError):
        raise QuoteError("The PCK certificate's Intel SGX extension is incomplete") from None


def collateral_time(document, now, what):
    issued, next_update = parse_time(document["issueDate"]), parse_time(document["nextUpdate"])
    if not issued <= now <= next_update:
        raise QuoteError(what + " is not current at " + now.isoformat() + " (issued " + document["issueDate"]
                         + ", next update " + document["nextUpdate"] + ")")


def parse_time(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def signed_document(collateral, name, root, crls, now, what):
    chain = check_chain(pem_chain(collateral[name + "_issuer_chain"]), root, crls, now, what)
    if len(chain) != 1:
        raise QuoteError(what + " must be signed by a certificate the root issued directly")
    text = collateral[name]
    check_signature(chain[0].public_key(), bytes.fromhex(collateral[name + "_signature"]), text.encode(), what)
    return json.loads(text)


def converge(platform, component):
    if component == "Revoked":
        return "Revoked"
    if component == "OutOfDate" and platform in ("UpToDate", "SWHardeningNeeded"):
        return "OutOfDate"
    if component == "OutOfDate" and platform in ("ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
        return "OutOfDateConfigurationNeeded"
    return platform


def relaunch(launch, current):
    configuration = ("ConfigurationNeeded", "OutOfDateConfigurationNeeded", "ConfigurationAndSWHardeningNeeded",
                     "TDRelaunchAdvisedConfigurationNeeded")
    if launch in ("OutOfDate", "OutOfDateConfigurationNeeded") and current in (
            "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
        return "TDRelaunchAdvisedConfigurationNeeded" if launch in configuration or current in configuration \
            else "TDRelaunchAdvised"
    return launch


def components(level, key):
    return [c["svn"] for c in level["tcb"].get(key) or []]


def ordered_levels(tcb_info):
    return sorted(tcb_info["tcbLevels"], reverse=True, key=lambda level: (
        components(level, "sgxtcbcomponents"), level["tcb"]["pcesvn"], components(level, "tdxtcbcomponents")))


def module_identity(tcb_info, svn):
    if svn[1] == 0:
        return None
    wanted = "TDX_%02X" % svn[1]
    for identity in tcb_info.get("tdxModuleIdentities") or []:
        if identity["id"].upper() == wanted:
            return identity
    raise QuoteError("TCB Info has no TDX module identity " + wanted)


def platform_level(tcb_info, cpu_svn, pce_svn, svn):
    skip = 2 if svn[1] > 0 else 0
    for level in ordered_levels(tcb_info):
        sgx, tdx = components(level, "sgxtcbcomponents"), components(level, "tdxtcbcomponents")
        if len(sgx) != 16 or len(tdx) != 16:
            raise QuoteError("TCB Info has a level without 16 SGX and 16 TDX components")
        if all(have >= need for have, need in zip(cpu_svn, sgx)) and pce_svn >= level["tcb"]["pcesvn"] and \
                all(have >= need for have, need in list(zip(svn, tdx))[skip:]):
            if level["tcbStatus"] not in STATUSES:
                raise QuoteError("Unrecognized TCB status " + str(level["tcbStatus"]))
            status, advisories, date = level["tcbStatus"], list(level.get("advisoryIDs") or []), level["tcbDate"]
            identity = module_identity(tcb_info, svn)
            if identity:
                module = next((m for m in identity["tcbLevels"] if svn[0] >= m["tcb"]["isvsvn"]), None)
                if module is None:
                    raise QuoteError("The TDX module ISVSVN " + str(svn[0]) + " is below every module TCB level")
                if module["tcbStatus"] not in MODULE_STATUSES:
                    raise QuoteError("Unrecognized TDX module TCB status " + str(module["tcbStatus"]))
                status = converge(status, module["tcbStatus"])
                advisories += [a for a in module.get("advisoryIDs") or [] if a not in advisories]
                date = min(date, module["tcbDate"], key=parse_time)
            return status, advisories, date
    raise QuoteError("No TCB level of this platform is listed in Intel's TCB Info")


def check_module(tcb_info, report):
    base = tcb_info.get("tdxModule")
    if not base:
        raise QuoteError("TDX TCB Info has no tdxModule")
    expected = module_identity(tcb_info, report["tee_tcb_svn"]) or base
    if bytes.fromhex(expected["mrsigner"]) != report["mr_signer_seam"]:
        raise QuoteError("The TDX module is not signed by the signer Intel lists")
    attributes, mask = bytes.fromhex(expected["attributes"]), bytes.fromhex(expected["attributesMask"])
    for want, bits, have in zip(attributes, mask, report["seam_attributes"]):
        if want & bits != have & bits or have & ~bits & 0xFF:
            raise QuoteError("The TDX module attributes differ from Intel's")


def td_problems(quote):
    report, problems = quote["report"], []
    attributes = int.from_bytes(report["td_attributes"], "little")
    if attributes & 0x01:
        problems.append("the TD runs in debug mode: the host can read its memory and registers")
    if attributes & 0x70:
        problems.append("TD profiling is enabled")
    if attributes & RESERVED_ATTRIBUTES:
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


def check_qe(qe_report, identity):
    if qe_report[128:160] != bytes.fromhex(identity["mrsigner"]):
        raise QuoteError("The quoting enclave is not signed by Intel")
    if qe_report[48] & 0x02:
        raise QuoteError("The quoting enclave runs in debug mode")
    if struct.unpack_from("<H", qe_report, 256)[0] != identity["isvprodid"]:
        raise QuoteError("The quoting enclave has the wrong product ID")
    mask = int.from_bytes(bytes.fromhex(identity["miscselectMask"]), "little")
    if struct.unpack_from("<I", qe_report, 16)[0] & mask != int.from_bytes(bytes.fromhex(identity["miscselect"]),
                                                                           "little") & mask:
        raise QuoteError("The quoting enclave's MISCSELECT differs from Intel's")
    for want, bits, have in zip(bytes.fromhex(identity["attributes"]), bytes.fromhex(identity["attributesMask"]),
                                qe_report[48:64]):
        if want & bits != have & bits:
            raise QuoteError("The quoting enclave's attributes differ from Intel's")
    svn = struct.unpack_from("<H", qe_report, 258)[0]
    for level in identity["tcbLevels"]:
        if svn >= level["tcb"]["isvsvn"]:
            if level["tcbStatus"] not in QE_STATUSES:
                raise QuoteError("Unrecognized QE TCB status " + str(level["tcbStatus"]))
            return level["tcbStatus"], list(level.get("advisoryIDs") or [])
    raise QuoteError("The quoting enclave's SVN is below every level Intel lists")


def verify_quote(raw, collateral, now=None, root=None):
    now = now or datetime.now(timezone.utc)
    root = root or intel_root()
    quote = parse_quote(raw)
    try:
        root_crl = crl_list(bytes.fromhex(collateral["root_ca_crl"]), root, now, "Intel's root revocation list")
        crls = {root.subject.public_bytes(): root_crl}
        pck_ca = check_chain(pem_chain(collateral["pck_crl_issuer_chain"]), root, crls, now,
                             "The PCK revocation list issuer")[0]
        crls[pck_ca.subject.public_bytes()] = crl_list(bytes.fromhex(collateral["pck_crl"]), pck_ca, now,
                                                       "The PCK revocation list")
        tcb_info = signed_document(collateral, "tcb_info", root, crls, now, "Intel's TCB Info")
        identity = signed_document(collateral, "qe_identity", root, crls, now, "Intel's QE Identity")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, QuoteError):
            raise
        raise QuoteError("The collateral is incomplete or unreadable: " + type(exc).__name__) from None
    collateral_time(tcb_info, now, "Intel's TCB Info")
    collateral_time(identity, now, "Intel's QE Identity")
    if tcb_info.get("id") != "TDX" or tcb_info.get("version", 0) < 3:
        raise QuoteError("The collateral's TCB Info is not for TDX")
    if identity.get("id") != "TD_QE" or identity.get("version") not in (2, 3):
        raise QuoteError("The collateral's QE Identity is not for the TDX quoting enclave")
    chain = check_chain(pem_chain(quote["pck_chain"]), root, crls, now, "The PCK certificate chain")
    if chain[-1].subject != pck_ca.subject:
        raise QuoteError("The PCK certificate and the revocation list come from different Intel CAs")
    pck = chain[0]
    check_signature(pck.public_key(), quote["qe_signature"], quote["qe_report"], "The quoting enclave report")
    if hashlib.sha256(quote["attestation_key"] + quote["qe_auth"]).digest() != quote["qe_report"][320:352] \
            or len(quote["qe_auth"]) != 32:
        raise QuoteError("The quoting enclave report does not name the key that signed the quote")
    qe_status, qe_advisories = check_qe(quote["qe_report"], identity)
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + quote["attestation_key"])
    except ValueError:
        raise QuoteError("The quote's attestation key is not a P-256 point") from None
    check_signature(key, quote["signature"], quote["signed"], "The TD report")
    platform = pck_extension(pck)
    if bytes.fromhex(tcb_info["fmspc"]) != platform["fmspc"]:
        raise QuoteError("Intel's TCB Info is for another platform (FMSPC)")
    report = quote["report"]
    status, advisories, date = platform_level(tcb_info, platform["cpu_svn"], platform["pce_svn"], report["tee_tcb_svn"])
    check_module(tcb_info, report)
    current = None
    if "tee_tcb_svn2" in report:
        current = converge(platform_level(tcb_info, platform["cpu_svn"], platform["pce_svn"],
                                          report["tee_tcb_svn2"])[0], qe_status)
    status = converge(status, qe_status)
    advisories += [a for a in qe_advisories if a not in advisories]
    if status == "Revoked" or current == "Revoked":
        raise QuoteError("Intel has revoked this platform's TCB")
    if current:
        status = relaunch(status, current)
    problems = td_problems(quote)
    if problems:
        raise QuoteError("; ".join(problems))
    return {"status": status, "advisory_ids": advisories, "tcb_date": date, "qe_status": qe_status,
            "fmspc": platform["fmspc"].hex(), "pck_ca": pck_ca.subject.rfc4514_string(),
            "collateral_issued": tcb_info["issueDate"], "quote_version": quote["version"],
            "report": {k: v.hex() for k, v in report.items()}}


def signed_member(body, name):
    marker = '"' + name + '":'
    start = body.index(marker) + len(marker)
    while body[start] in " \t\r\n":
        start += 1
    _, end = json.JSONDecoder().raw_decode(body, start)
    return body[start:end], json.loads(body)["signature"]


def fetch_collateral(raw, session):
    pck = pem_chain(parse_quote(raw)["pck_chain"])[0]
    fmspc = pck_extension(pck)["fmspc"].hex().upper()
    issuer = pck.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    ca = "processor" if "Processor" in issuer else "platform"

    def get(url, params=None):
        response = session.get(url, params=params, timeout=60)
        if response.status_code != 200:
            raise QuoteError(url + " answered HTTP " + str(response.status_code))
        return response

    def header(response, *names):
        for name in names:
            if response.headers.get(name):
                return unquote(response.headers[name])
        raise QuoteError("Intel's answer has no " + names[0] + " header")
    crl = get(PCS + "/sgx/certification/v4/pckcrl", {"ca": ca, "encoding": "der"})
    tcb = get(PCS + "/tdx/certification/v4/tcb", {"fmspc": fmspc})
    qe = get(PCS + "/tdx/certification/v4/qe/identity")
    tcb_text, tcb_signature = signed_member(tcb.text, "tcbInfo")
    qe_text, qe_signature = signed_member(qe.text, "enclaveIdentity")
    return {"pck_crl_issuer_chain": header(crl, "SGX-PCK-CRL-Issuer-Chain"), "pck_crl": crl.content.hex(),
            "root_ca_crl": get(ROOT_CRL_URL).content.hex(),
            "tcb_info_issuer_chain": header(tcb, "TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"),
            "tcb_info": tcb_text, "tcb_info_signature": tcb_signature,
            "qe_identity_issuer_chain": header(qe, "SGX-Enclave-Identity-Issuer-Chain"),
            "qe_identity": qe_text, "qe_identity_signature": qe_signature}


def event_digest(event):
    payload = bytes.fromhex(event["event_payload"])
    version = event.get("version") or 1
    if version == 1:
        data = struct.pack("<I", DSTACK_EVENT) + b":" + event["event"].encode() + b":" + payload
    elif version == 2:
        data = json.dumps({"name": event["event"], "payload": payload.hex(), "type": DSTACK_EVENT},
                          ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    else:
        raise QuoteError("Unknown dstack event log version " + str(version))
    return hashlib.sha384(data).digest()


def replay(event_log):
    register, events = bytes(48), []
    for event in event_log:
        if event.get("imr") != 3:
            continue
        runtime = event.get("event_type") == DSTACK_EVENT
        try:
            given = bytes.fromhex(event.get("digest") or "")
            digest = event_digest(event) if runtime else given
            payload = bytes.fromhex(event.get("event_payload") or "")
        except (TypeError, ValueError):
            raise QuoteError("Unreadable RTMR3 event " + str(event.get("event"))) from None
        if len(digest) != 48 or (given and given != digest):
            raise QuoteError("RTMR3 event " + str(event.get("event")) + " does not match its digest")
        register = hashlib.sha384(register + digest).digest()
        events.append({"name": str(event.get("event")), "payload": payload, "runtime": runtime})
    return register, events


def launch_identity(events):
    before, after, ready = [], [], False
    for event in events:
        (after if ready else before).append(event)
        if event["runtime"] and event["name"] == "system-ready":
            ready = True
    if not ready:
        raise QuoteError("The event log has no system-ready event: the CVM had not finished booting")
    found = {}
    for name in IDENTITY_EVENTS:
        values = [e["payload"] for e in before if e["runtime"] and e["name"] == name]
        if len(values) > 1:
            raise QuoteError("Two " + name + " events before system-ready")
        found[name] = values[0] if values else None
    if found["compose-hash"] is None or len(found["compose-hash"]) != 32:
        raise QuoteError("The event log has no compose-hash event")
    try:
        provider = json.loads(found["key-provider"]) if found["key-provider"] is not None else None
    except ValueError:
        provider = found["key-provider"].decode(errors="replace")
    return {"app_id": (found["app-id"] or b"").hex(), "compose_hash": found["compose-hash"].hex(),
            "instance_id": found["instance-id"].hex() if found["instance-id"] is not None else None,
            "key_provider": provider, "os_image_hash": found["os-image-hash"].hex()
            if found["os-image-hash"] is not None else None,
            "storage_encrypted": found["storage-encrypted"].decode(errors="replace")
            if found["storage-encrypted"] is not None else None,
            "init_scripts": [e["payload"].hex() for e in before if e["runtime"] and e["name"] == "init-script-hash"],
            "measured": [e["name"] for e in before], "after_ready": [e["name"] for e in after]}


def evidence(answer):
    raw = bytes.fromhex(answer["quote"])
    log = answer["event_log"]
    return raw, json.loads(log) if isinstance(log, str) else log


def measured(raw, event_log):
    quote = parse_quote(raw)
    register, events = replay(event_log)
    if register != quote["report"]["rtmr3"]:
        raise QuoteError("The event log does not replay to the quote's RTMR3")
    return quote, launch_identity(events)


def compare_measurements(report, expected):
    if not expected:
        return "unavailable", ("the published dstack OS image was not compared (--tdx-image none); without it the "
                               "firmware, kernel and command line are not checked")
    differ = [name for name in MEASUREMENTS if str(expected.get(name, "")).lower().removeprefix("0x") != report[name]]
    if differ:
        return "fail", "differ from the expected image: " + ", ".join(differ)
    return "pass", "MRTD and RTMR0-2 equal the values computed from the image"
