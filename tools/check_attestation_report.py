import json
import sys
from pathlib import Path

import minicheck as pytest
import requests
from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import attestation_report, tdx, tsa_roots  # noqa: E402
from tgwitness.security import Vault  # noqa: E402
from tgwitness.verify import timestamp_token  # noqa: E402

# Real replies of the Belgian government's qualified TSA and of FreeTSA over the report below.
VECTOR = json.loads((Path(__file__).parent / "tsa" / "time-stamps.json").read_text())
PHALA = json.loads((Path(__file__).parent / "tdx" / "phala-dstack-0.5.12.json").read_text())
BELGIUM, FREETSA = tsa_roots.QUALIFIED_TSA, "https://freetsa.org/tsr"


def recorded(data, url, session=None):
    if url not in VECTOR["time_stamps"]:
        raise requests.ConnectionError("no route to " + url)
    item = VECTOR["time_stamps"][url]
    return bytes.fromhex(item["query"]), bytes.fromhex(item["reply"])


def sealed(tmp_path, vault=True, tsas=(BELGIUM, FREETSA)):
    base = tmp_path / "verification"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_bytes(VECTOR["report"].encode())
    signer = Vault(tmp_path / "verifier") if vault else None
    return base, signer, attestation_report.seal(base, signer, tsas, stamp=recorded)


def signer_of(url):
    reply = bytes.fromhex(VECTOR["time_stamps"][url]["reply"])
    certificates = [x509.load_der_x509_certificate(c) for c in timestamp_token(reply)["certificates"]]
    return next(c for c in certificates if "Timestamp Unit" in c.subject.rfc4514_string() or "TSA" in
                c.subject.rfc4514_string() and "Root" not in c.subject.rfc4514_string())


def test_the_belgian_time_stamp_is_qualified_and_freetsa_is_not(tmp_path, monkeypatch):
    base, vault, seal = sealed(tmp_path)
    belgium, freetsa = seal["statement"]["time_stamps"]
    assert belgium["root_sha256"] == tsa_roots.BELGIUM_ROOT_CA6_SHA256 and freetsa["qualified"] is None
    assert belgium["qualified"]["service"] == "TSU 202301" and belgium["qualified"]["status"] == "granted"
    assert belgium["qualified"]["trusted_list"]["territory"] == "BE"
    assert tsa_roots.qualified(signer_of(FREETSA)) is None
    monkeypatch.setattr(tsa_roots, "QUALIFIED", {})
    assert tsa_roots.qualified(signer_of(BELGIUM)) is None


def test_a_sealed_report_checks_with_its_signature_and_time_stamps(tmp_path):
    base, vault, seal = sealed(tmp_path)
    assert seal["fingerprint"] == attestation_report.fingerprint(vault.public_key) and not seal["failed_time_stamps"]
    found = dict(attestation_report.check(base, seal["fingerprint"]))
    assert "as expected" in found["verifier"] and "SHA-256" in found["report"]
    stamps = [text for label, text in attestation_report.check(base) if label == "time stamp"]
    assert len(stamps) == 2 and "qualified eIDAS time stamp, TSU 202301 granted on the BE trusted list" in stamps[0]
    assert "Belgium Root CA6" in stamps[0] and "qualified" not in stamps[1]


def test_every_change_to_a_sealed_report_is_refused(tmp_path):
    base, vault, seal = sealed(tmp_path)
    original = base.with_suffix(".json").read_bytes()
    base.with_suffix(".json").write_bytes(original.replace(b"pass", b"fail"))
    with pytest.raises(attestation_report.SealError, match="SHA-256 differs"):
        attestation_report.check(base)
    base.with_suffix(".json").write_bytes(original)
    with pytest.raises(attestation_report.SealError, match="not the expected one"):
        attestation_report.check(base, "0" * 64)
    seal_path = base.with_suffix(".seal.json")
    document = json.loads(seal_path.read_text())
    document["statement"]["time_stamps"] = document["statement"]["time_stamps"][:1]
    seal_path.write_text(json.dumps(document))
    with pytest.raises(attestation_report.SealError, match="signature over the seal is invalid"):
        attestation_report.check(base)
    seal_path.write_text(json.dumps(seal))
    first, second = seal["statement"]["time_stamps"]
    belgian = base.with_name(first["reply"]).read_bytes()
    base.with_name(first["reply"]).write_bytes(base.with_name(second["reply"]).read_bytes())
    with pytest.raises(attestation_report.SealError, match="not the time stamp the seal names"):
        attestation_report.check(base)
    base.with_name(first["reply"]).write_bytes(belgian)
    assert attestation_report.check(base)


def test_an_unreachable_authority_is_recorded_and_the_rest_still_seals(tmp_path):
    base, vault, seal = sealed(tmp_path, tsas=(BELGIUM, "https://tsa.invalid/"))
    assert [s["tsa"] for s in seal["statement"]["time_stamps"]] == [BELGIUM]
    assert seal["failed_time_stamps"][0]["tsa"] == "https://tsa.invalid/" and "ConnectionError" in \
        seal["failed_time_stamps"][0]["error"]
    unsigned = sealed(tmp_path / "unsigned", vault=False, tsas=())[2]
    assert "signature" not in unsigned and unsigned["statement"]["time_stamps"] == []
    assert dict(attestation_report.check(tmp_path / "unsigned" / "verification"))["verifier"] == \
        "not signed by a verifier key"


def report():
    raw, log = tdx.evidence(PHALA)
    quote = tdx.parse_quote(raw)["report"]
    checks = [{"check": c, "status": "pass", "title": t, "detail": "<script>alert(1)</script> " + c, "source": "test"}
              for c, t, _ in attestation_report.TRUST_CHAIN]
    checks.append({"check": "provider_actions", "status": "review", "title": "Provider log", "detail": "restart",
                   "source": "Phala Cloud API"})
    return {"format": "tgwitness-assurance-report-v1", "generated_at": "2026-11-04T08:38:44.783+00:00",
            "verifier": {"software": "TgWitness", "version": "test"}, "result": "review",
            "verification_scope": "hardware-attestation", "provider_title": "Phala Cloud (Intel TDX)",
            "deployment": {"name": "case-1", "commit": "df7d860cf57fc470a22f100c0badf852d6685143",
                           "deployment_id": "e9310b69181fc8c4"},
            "server": {"id": "cvm_meYvZ8K7", "location": "US-WEST-1"}, "fingerprint": "3e" * 32, "checks": checks,
            "provider_actions": [{"command": "restart", "id": "op1", "started": "2026-11-04T08:33:04",
                                  "actor": "operator", "assessment": "review", "meaning": "collection was interrupted"}],
            "collector_statement": {"statement": {"fingerprint": "3e" * 32}},
            "attestation": {"quote": {k: v.hex() for k, v in quote.items() if k.startswith(("mrtd", "rtmr"))},
                            "intel": {"status": "UpToDate", "fmspc": "20a06f000000"},
                            "identity": {"app_id": "0c7bda6e", "instance_id": "d6173eb1", "compose_hash": "10dbf19f"},
                            "os_image": {"image": "dstack-0.5.12", "machine": "QEMU 8.2.2, 1 vCPU, 2 GiB",
                                         "mrtd": quote["mrtd"].hex(), "rtmr0": quote["rtmr0"].hex(),
                                         "rtmr1": quote["rtmr1"].hex(), "rtmr2": "00" * 48},
                            "certificates": tdx.chain_summary(raw)},
            "establishes": ["what the quote shows"], "does_not_establish": ["what it cannot exclude"]}


def test_write_puts_every_part_beside_the_report(tmp_path):
    base = tmp_path / "verification"
    seal = attestation_report.write(report(), "# markdown\n", base, Vault(tmp_path / "verifier"), ())
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == [
        "verification.html", "verification.json", "verification.md", "verification.pdf", "verification.seal.json"]
    assert base.with_suffix(".md").read_text() == "# markdown\n" and json.loads(base.with_suffix(".json").read_text())
    assert "PDF" in dict(attestation_report.check(base, seal["fingerprint"]))["pdf"].upper()


def test_the_certificate_renders_signs_and_refuses_a_changed_pdf(tmp_path):
    base, vault, seal = sealed(tmp_path)
    page = attestation_report.html_report(report(), seal)
    base.with_suffix(".pdf").write_bytes(attestation_report.pdf_report(report(), seal, vault))
    assert "<script>alert" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "eIDAS QUALIFIED" in page and "Intel SGX Root CA" in page and "PINNED ROOT" in page
    assert "DIFFERENT" in page and page.count(">EQUAL<") == 3 and "2026-11-04 08:38 UTC" in page
    assert "Timestamp Unit 202301 (QTSP: FPS Policy and Support - BOSA)" in page
    findings = dict(attestation_report.check(base, seal["fingerprint"]))
    assert "signed by the same verifier key" in findings["pdf"]
    pdf = bytearray(base.with_suffix(".pdf").read_bytes())
    pdf[200] ^= 0x01
    base.with_suffix(".pdf").write_bytes(bytes(pdf))
    with pytest.raises(ValueError, match="changed after it was signed"):
        attestation_report.check(base)


if __name__ == "__main__":
    raise SystemExit(pytest.run(globals()))
