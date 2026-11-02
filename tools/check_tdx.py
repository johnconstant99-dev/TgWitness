"""Intel TDX quotes and dstack event logs, checked by tgwitness.tdx without dcap-qvl or any Phala service.

Real quotes (tools/tdx) must verify against the pinned Intel root. A forged PKI shaped like Intel's
exercises every refusal: a broken signature, a revoked certificate, stale collateral, a debuggable or
migratable TD, and an event log that does not replay to the quote's RTMR3.
"""
import hashlib
import json
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS

import minicheck as pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import tdx  # noqa: E402

FIXTURES = Path(__file__).parent / "tdx"
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
SEPT_VE_DISABLE = 1 << 28


def window(collateral):
    """A moment inside every validity period of the collateral, as dcap-qvl's tests choose it."""
    documents = [json.loads(collateral[k]) for k in ("tcb_info", "qe_identity")]
    start = max(tdx.parse_time(d["issueDate"]) for d in documents)
    end = min(tdx.parse_time(d["nextUpdate"]) for d in documents)
    for name in ("root_ca_crl", "pck_crl"):
        crl = x509.load_der_x509_crl(bytes.fromhex(collateral[name]))
        start, end = max(start, crl.last_update_utc), min(end, crl.next_update_utc)
    assert start < end
    return end - timedelta(seconds=1)


def fixture(name):
    # Quotes are kept as hex text: the published source holds no binary files of this kind.
    return bytes.fromhex((FIXTURES / (name + ".hex")).read_text()), json.loads((FIXTURES / name.replace(".quote", ".collateral.json")).read_text())


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes(
        (size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def der_oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        while arc > 0x7F:
            arc >>= 7
            chunk.insert(0, 0x80 | (arc & 0x7F))
        body += bytes(chunk)
    return tlv(0x06, body)


def der_int(value):
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def raw_signature(key, data):
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def pem(*certificates):
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certificates)


class Forge:
    """A PKI shaped like Intel's (root, PCK platform CA, PCK certificate, TCB signer) issuing TDX quotes."""
    FMSPC, CPU_SVN, PCE_SVN = bytes.fromhex("00906ed50000"), bytes([2] * 16), 11
    MODULE_SIGNER, QE_SIGNER = bytes(range(48)), bytes(range(100, 132))

    def __init__(self, now=NOW):
        self.now, self.revoked = now, {"ca": set(), "root": set()}
        self.root_key, self.ca_key, self.pck_key, self.signer_key, self.key = (
            ec.generate_private_key(ec.SECP256R1()) for _ in range(5))
        self.root = self.certificate("Forged SGX Root CA", self.root_key, None, ca=True)
        self.ca = self.certificate("Forged SGX PCK Platform CA", self.ca_key, (self.root, self.root_key), ca=True)
        sgx = tlv(0x30, b"".join([
            tlv(0x30, der_oid(tdx.SGX_EXTENSION + ".1") + tlv(0x04, bytes(16))),
            tlv(0x30, der_oid(tdx.TCB) + tlv(0x30, b"".join(
                [tlv(0x30, der_oid(tdx.TCB + "." + str(i + 1)) + der_int(v)) for i, v in enumerate(self.CPU_SVN)]
                + [tlv(0x30, der_oid(tdx.TCB + ".17") + der_int(self.PCE_SVN)),
                   tlv(0x30, der_oid(tdx.TCB + ".18") + tlv(0x04, self.CPU_SVN))]))),
            tlv(0x30, der_oid(tdx.PCEID) + tlv(0x04, b"\0\0")),
            tlv(0x30, der_oid(tdx.FMSPC) + tlv(0x04, self.FMSPC)),
            tlv(0x30, der_oid(tdx.SGX_EXTENSION + ".5") + tlv(0x0A, b"\0"))]))
        self.pck = self.certificate("Forged SGX PCK Certificate", self.pck_key, (self.ca, self.ca_key),
                                    extension=x509.UnrecognizedExtension(x509.ObjectIdentifier(tdx.SGX_EXTENSION), sgx))
        self.signer = self.certificate("Forged SGX TCB Signing", self.signer_key, (self.root, self.root_key))

    def certificate(self, name, key, issuer, ca=False, extension=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = x509.CertificateBuilder().subject_name(subject).public_key(key.public_key()) \
            .issuer_name(issuer[0].subject if issuer else subject).serial_number(x509.random_serial_number()) \
            .not_valid_before(self.now - timedelta(days=30)).not_valid_after(self.now + timedelta(days=3650)) \
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        if extension is not None:
            builder = builder.add_extension(extension, critical=False)
        return builder.sign(issuer[1] if issuer else key, hashes.SHA256())

    def crl(self, issuer, key, serials):
        builder = x509.CertificateRevocationListBuilder().issuer_name(issuer.subject) \
            .last_update(self.now - timedelta(days=1)).next_update(self.now + timedelta(days=30))
        for serial in serials:
            builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                                      .revocation_date(self.now - timedelta(hours=1)).build())
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER).hex()

    def collateral(self, status="UpToDate", issued=None, days=30):
        issued = issued or self.now - timedelta(days=1)
        dates = {"issueDate": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "nextUpdate": (issued + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        level = {"tcb": {"sgxtcbcomponents": [{"svn": 2}] * 16, "pcesvn": self.PCE_SVN,
                         "tdxtcbcomponents": [{"svn": 3}] + [{"svn": 0}] * 15},
                 "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": status,
                 "advisoryIDs": [] if status == "UpToDate" else ["INTEL-SA-00837"]}
        tcb_info = json.dumps({"id": "TDX", "version": 3, **dates, "fmspc": self.FMSPC.hex().upper(), "pceId": "0000",
                               "tcbType": 0, "tcbEvaluationDataNumber": 17,
                               "tdxModule": {"mrsigner": self.MODULE_SIGNER.hex().upper(), "attributes": "0" * 16,
                                             "attributesMask": "F" * 16},
                               "tdxModuleIdentities": [], "tcbLevels": [level]}, separators=(",", ":"))
        identity = json.dumps({"id": "TD_QE", "version": 2, **dates, "tcbEvaluationDataNumber": 17,
                               "miscselect": "00000000", "miscselectMask": "FFFFFFFF",
                               "attributes": "11" + "0" * 30, "attributesMask": "FBFFFFFFFFFFFFFF" + "0" * 16,
                               "mrsigner": self.QE_SIGNER.hex().upper(), "isvprodid": 2,
                               "tcbLevels": [{"tcb": {"isvsvn": 4}, "tcbDate": "2026-01-01T00:00:00Z",
                                              "tcbStatus": "UpToDate"}]}, separators=(",", ":"))
        return {"pck_crl_issuer_chain": pem(self.ca, self.root), "root_ca_crl": self.crl(self.root, self.root_key,
                                                                                         self.revoked["root"]),
                "pck_crl": self.crl(self.ca, self.ca_key, self.revoked["ca"]),
                "tcb_info_issuer_chain": pem(self.signer, self.root), "tcb_info": tcb_info,
                "tcb_info_signature": raw_signature(self.signer_key, tcb_info.encode()).hex(),
                "qe_identity_issuer_chain": pem(self.signer, self.root), "qe_identity": identity,
                "qe_identity_signature": raw_signature(self.signer_key, identity.encode()).hex()}

    def quote(self, report_data=b"", rtmr3=bytes(48), measurements=None, attributes=SEPT_VE_DISABLE, qe_debug=False):
        measurements = measurements or self.measurements()
        header = struct.pack("<HHIHH", 4, 2, tdx.TDX, 4, self.PCE_SVN) + tdx.INTEL_QE_VENDOR + bytes(20)
        body = bytes([3] + [0] * 15) + bytes(48) + self.MODULE_SIGNER + bytes(8) + attributes.to_bytes(8, "little") \
            + bytes(8) + measurements["mrtd"] + bytes(48 * 3) + measurements["rtmr0"] + measurements["rtmr1"] \
            + measurements["rtmr2"] + rtmr3 + report_data.ljust(64, b"\0")
        point = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        qe_auth = bytes(range(32))
        qe_report = self.CPU_SVN + bytes(4) + bytes(28) + bytes([0x13 if qe_debug else 0x11]) + bytes(15) + bytes(64) \
            + self.QE_SIGNER + bytes(96) + struct.pack("<HH", 2, 4) + bytes(60) \
            + hashlib.sha256(point[1:] + qe_auth).digest() + bytes(32)
        chain = pem(self.pck, self.ca, self.root).encode() + b"\0"
        certification = qe_report + raw_signature(self.pck_key, qe_report) + struct.pack("<H", 32) + qe_auth \
            + struct.pack("<HI", 5, len(chain)) + chain
        auth = raw_signature(self.key, header + body) + point[1:] + struct.pack("<HI", 6, len(certification)) + certification
        return header + body + struct.pack("<I", len(auth)) + auth

    @staticmethod
    def measurements():
        return {name: hashlib.sha384(name.encode()).digest() for name in tdx.MEASUREMENTS}


def runtime_event(name, payload, version=None):
    event = {"imr": 3, "event_type": tdx.DSTACK_EVENT, "digest": "", "event": name, "event_payload": payload.hex()}
    if version:
        event["version"] = version
    event["digest"] = tdx.event_digest(event).hex()
    return event


def launch_log(compose_hash, app_id=None, instance_id=b"\x07" * 20, provider=b'{"name":"kms","id":"00"}', extra=()):
    events = [runtime_event("system-preparing", b""), runtime_event("app-id", app_id or compose_hash[:20]),
              runtime_event("compose-hash", compose_hash), runtime_event("instance-id", instance_id),
              runtime_event("boot-mr-done", b""), runtime_event("key-provider", provider),
              runtime_event("storage-encrypted", b"1"), runtime_event("system-ready", b""), *extra]
    return [{"imr": 0, "event_type": 1, "digest": "ab" * 48, "event": "", "event_payload": ""}] + events


def rtmr3(log):
    return tdx.replay(log)[0]


@pytest.fixture
def forge():
    return Forge()


def test_the_pinned_intel_root_is_intels():
    root = tdx.intel_root()
    assert root.subject.rfc4514_string() == "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX Root CA"
    assert root.fingerprint(hashes.SHA256()).hex() == tdx.INTEL_ROOT_SHA256


@pytest.mark.parametrize("name, version", [("intel-v4.quote", 4), ("intel-v5-td15ex.quote", 5)])
def test_real_intel_quotes_verify_to_the_intel_root(name, version):
    raw, collateral = fixture(name)
    found = tdx.verify_quote(raw, collateral, window(collateral))
    assert found["status"] == "UpToDate" and found["advisory_ids"] == [] and found["quote_version"] == version
    assert found["fmspc"] == "b0c06f000000" and "PCK Platform CA" in found["pck_ca"]
    with pytest.raises(tdx.QuoteError, match="not current"):
        tdx.verify_quote(raw, collateral, window(collateral) + timedelta(days=400))


def test_a_real_dstack_quote_replays_its_compose_and_verifies_with_collateral_from_intel():
    answer = json.loads((FIXTURES / "dstack-v4.json").read_text())
    collateral = json.loads((FIXTURES / "dstack-v4.collateral.json").read_text())
    raw, log = tdx.evidence(answer)
    quote, identity = tdx.measured(raw, log)
    assert identity["compose_hash"] == "3763bc34552cf3a27ff71ad5f7a90471562a1a2df552dfc1998cba2d60da27e7"
    assert identity["app_id"] == identity["compose_hash"][:40] and identity["instance_id"] == \
        "c3714eb66990eace777b4e664c16e09375dec4c9"
    assert identity["key_provider"]["name"] == "local-sgx" and identity["after_ready"] == ["LIUM_MINER_HOTKEY"]
    assert quote["report"]["report_data"].startswith(bytes.fromhex("1234"))
    found = tdx.verify_quote(raw, collateral, window(collateral))
    assert found["status"] == "UpToDate" and found["fmspc"] == "90c06f000000"
    damaged = list(log)
    index = next(i for i, e in enumerate(damaged) if e["event"] == "compose-hash")
    damaged[index] = {**damaged[index], "event_payload": "00" * 32}
    with pytest.raises(tdx.QuoteError, match="does not match its digest"):
        tdx.measured(raw, damaged)
    with pytest.raises(tdx.QuoteError, match="does not replay"):
        tdx.measured(raw, [e for e in log if e["event"] != "instance-id"])


def test_tcb_levels_converge_with_the_tdx_module_as_intel_qvl_does():
    info = json.loads(json.loads((FIXTURES / "intel-outdated.collateral.json").read_text())["tcb_info"])
    cpu = bytes([3, 3, 2, 2, 4, 1, 0, 5] + [0] * 8)

    def svn(module, version):
        return bytes([module, version, 3] + [0] * 13)
    assert tdx.platform_level(info, cpu, 13, svn(6, 1)) == ("UpToDate", [], "2024-11-13T00:00:00Z")
    for module, date in ((4, "2024-03-13T00:00:00Z"), (2, "2023-08-09T00:00:00Z")):
        assert tdx.platform_level(info, cpu, 13, svn(module, 1)) == (
            "OutOfDate", ["INTEL-SA-01036", "INTEL-SA-01099"], date)
    for value in (svn(6, 2), svn(2, 3), svn(1, 1), svn(4, 0)):
        with pytest.raises(tdx.QuoteError):
            tdx.platform_level(info, cpu, 13, value)
    assert tdx.converge("ConfigurationNeeded", "OutOfDate") == "OutOfDateConfigurationNeeded"
    assert tdx.relaunch("OutOfDate", "UpToDate") == "TDRelaunchAdvised"


def test_a_forged_quote_verifies_only_against_its_own_root(forge):
    raw = forge.quote(b"statement")
    found = tdx.verify_quote(raw, forge.collateral(), NOW, root=forge.root)
    assert found["status"] == "UpToDate" and found["report"]["report_data"].startswith(b"statement".hex())
    with pytest.raises(tdx.QuoteError, match="not signed by .*Intel SGX Root CA"):
        tdx.verify_quote(raw, forge.collateral(), NOW)  # the real Intel root
    genuine = json.loads((FIXTURES / "dstack-v4.collateral.json").read_text())
    with pytest.raises(tdx.QuoteError, match="PCK certificate chain: .* is not issued by"):
        tdx.verify_quote(raw, genuine, window(genuine))  # Intel's own collateral, a forged PCK chain


def test_every_break_in_the_chain_is_refused(forge):
    raw, collateral = forge.quote(b"x"), forge.collateral()
    body = bytearray(raw)
    body[48 + 520] ^= 1  # report data
    with pytest.raises(tdx.QuoteError, match="TD report: the signature is invalid"):
        tdx.verify_quote(bytes(body), collateral, NOW, root=forge.root)
    qe = bytearray(raw)
    qe[48 + 584 + 4 + 134 + 300] ^= 1  # inside the quoting enclave report
    with pytest.raises(tdx.QuoteError, match="quoting enclave report: the signature"):
        tdx.verify_quote(bytes(qe), collateral, NOW, root=forge.root)
    tampered = dict(collateral, tcb_info=collateral["tcb_info"].replace('"UpToDate"', '"UpToDate" ', 1))
    with pytest.raises(tdx.QuoteError, match="TCB Info: the signature"):
        tdx.verify_quote(raw, tampered, NOW, root=forge.root)
    with pytest.raises(tdx.QuoteError, match="not current"):
        tdx.verify_quote(raw, forge.collateral(issued=NOW - timedelta(days=60)), NOW, root=forge.root)
    forge.revoked["ca"].add(forge.pck.serial_number)
    with pytest.raises(tdx.QuoteError, match="revoked"):
        tdx.verify_quote(raw, forge.collateral(), NOW, root=forge.root)
    forge.revoked = {"ca": set(), "root": {forge.ca.serial_number}}
    with pytest.raises(tdx.QuoteError, match="revoked"):
        tdx.verify_quote(raw, forge.collateral(), NOW, root=forge.root)


@pytest.mark.parametrize("attributes, message", [
    (SEPT_VE_DISABLE | 1, "debug mode"),
    (SEPT_VE_DISABLE | (1 << 29), "migrated"),
    (0, "SEPT_VE_DISABLE"),
    (SEPT_VE_DISABLE | (1 << 40), "reserved"),
    (SEPT_VE_DISABLE | (1 << 17), "service TD"),
])
def test_a_td_the_host_could_read_or_move_is_refused(forge, attributes, message):
    with pytest.raises(tdx.QuoteError, match=message):
        tdx.verify_quote(forge.quote(attributes=attributes), forge.collateral(), NOW, root=forge.root)


def test_statuses_and_the_quoting_enclave(forge):
    found = tdx.verify_quote(forge.quote(), forge.collateral("OutOfDate"), NOW, root=forge.root)
    assert found["status"] == "OutOfDate" and found["advisory_ids"] == ["INTEL-SA-00837"]
    with pytest.raises(tdx.QuoteError, match="revoked this platform"):
        tdx.verify_quote(forge.quote(), forge.collateral("Revoked"), NOW, root=forge.root)
    with pytest.raises(tdx.QuoteError, match="quoting enclave runs in debug mode"):
        tdx.verify_quote(forge.quote(qe_debug=True), forge.collateral(), NOW, root=forge.root)


def test_the_launch_identity_is_what_was_measured_before_system_ready():
    compose = hashlib.sha256(b"app-compose").digest()
    log = launch_log(compose, extra=[runtime_event("late", b"x", version=2)])
    register, events = tdx.replay(log)
    identity = tdx.launch_identity(events)
    assert identity["compose_hash"] == compose.hex() and identity["app_id"] == compose[:20].hex()
    assert identity["key_provider"] == {"name": "kms", "id": "00"} and identity["storage_encrypted"] == "1"
    assert identity["after_ready"] == ["late"] and register == rtmr3(log)
    with pytest.raises(tdx.QuoteError, match="system-ready"):
        tdx.launch_identity(tdx.replay([e for e in log if e["event"] != "system-ready"])[1])
    twice = log[:4] + [runtime_event("compose-hash", b"\1" * 32)] + log[4:]
    with pytest.raises(tdx.QuoteError, match="Two compose-hash"):
        tdx.launch_identity(tdx.replay(twice)[1])
    # A version 2 event is hashed as canonical JSON, not as the binary layout.
    v2 = runtime_event("x", b"\1", version=2)
    assert v2["digest"] == hashlib.sha384(b'{"name":"x","payload":"01","type":134217729}').hexdigest()


def test_measurements_are_compared_only_with_values_from_the_image(forge):
    quote = tdx.parse_quote(forge.quote())
    report = {k: v.hex() for k, v in quote["report"].items()}
    expected = {k: v.hex() for k, v in Forge.measurements().items()}
    assert tdx.compare_measurements(report, None)[0] == "unavailable"
    assert tdx.compare_measurements(report, expected)[0] == "pass"
    assert tdx.compare_measurements(report, {**expected, "rtmr1": "00" * 48}) == (
        "fail", "differ from the expected image: rtmr1")


def test_collateral_comes_from_intel_with_the_exact_signed_bytes(forge):
    raw, collateral = forge.quote(), forge.collateral()
    tcb = '{"tcbInfo":' + collateral["tcb_info"] + ',"signature":"' + collateral["tcb_info_signature"] + '"}'
    qe = '{"enclaveIdentity":' + collateral["qe_identity"] + ',"signature":"' + collateral["qe_identity_signature"] + '"}'
    asked = []

    class Session:
        def get(self, url, params=None, timeout=None):
            asked.append((url, params))
            if url.endswith("/pckcrl"):
                return NS(status_code=200, content=bytes.fromhex(collateral["pck_crl"]),
                          headers={"SGX-PCK-CRL-Issuer-Chain": collateral["pck_crl_issuer_chain"].replace("\n", "%0A")})
            if url.endswith("/tcb"):
                return NS(status_code=200, text=tcb, headers={"TCB-Info-Issuer-Chain": collateral["tcb_info_issuer_chain"]})
            if url.endswith("/qe/identity"):
                return NS(status_code=200, text=qe,
                          headers={"SGX-Enclave-Identity-Issuer-Chain": collateral["qe_identity_issuer_chain"]})
            return NS(status_code=200, content=bytes.fromhex(collateral["root_ca_crl"]), headers={})
    fetched = tdx.fetch_collateral(raw, Session())
    assert fetched == collateral
    assert asked[0] == (tdx.PCS + "/sgx/certification/v4/pckcrl", {"ca": "platform", "encoding": "der"})
    assert asked[1] == (tdx.PCS + "/tdx/certification/v4/tcb", {"fmspc": "00906ED50000"})
    assert tdx.verify_quote(raw, fetched, NOW, root=forge.root)["status"] == "UpToDate"


if __name__ == "__main__":
    raise SystemExit(pytest.run(globals()))
