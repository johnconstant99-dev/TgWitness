import asyncio
import hashlib
import subprocess
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tgwitness import anchoring
from tgwitness.anchor import find_openssl
from tgwitness.anchoring import EvidenceMode, anchor_latest, evidence_settings
from tgwitness.app import create_app
from tgwitness.evidence import export_file, retain_checkpoint
from tgwitness.network import NetworkConfig
from tgwitness.tsa_roots import trusted_roots
from tgwitness.verify import (OTS_PENDING, children, der, fingerprint, ots_summary, timestamp_reply_summary,
                              timestamp_signature, timestamp_token, verify_anchors, verify_bundle)
from test_collector import FakeClient

REAL = Path(__file__).resolve().parent / "tsa"
OTS_ANSWER = b"\xf0\x10" + bytes(range(16)) + b"\x08\x00" + OTS_PENDING + b"\x1b\x1ahttps://cal.example/digest"


def synthetic_tsa(tmp_path):
    """A local RFC 3161 authority (OpenSSL) whose root is not trusted anywhere else."""
    try:
        binary = find_openssl()
    except ValueError:
        pytest.skip("OpenSSL is required for RFC 3161 tests")
    now = datetime.now(timezone.utc)
    ca_key, tsa_key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA only")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test TSA only")])

    def builder(subject, key):
        return x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(
            key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
                now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
    ca = builder(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True
        ).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        ).sign(ca_key, hashes.SHA256())
    tsa = builder(tsa_name, tsa_key).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        ).add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True
        ).sign(ca_key, hashes.SHA256())
    ca_path, tsa_path, key_path, serial, config = (tmp_path / n for n in
                                                    ("ca.pem", "tsa.pem", "tsa-key.pem", "serial", "tsa.cnf"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    tsa_path.write_bytes(tsa.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(tsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    serial.write_text("01")
    config.write_text("[tsa]\ndefault_tsa=demo\n[demo]\nserial=" + serial.as_posix() + "\ncrypto_device=builtin\n"
                      "signer_cert=" + tsa_path.as_posix() + "\ncerts=" + ca_path.as_posix() + "\n"
                      "signer_key=" + key_path.as_posix() + "\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\n"
                      "digests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=yes\n"
                      "ess_cert_id_alg=sha256\n")

    def reply(query):
        source, out = tmp_path / "q.tsq", tmp_path / "r.tsr"
        source.write_bytes(query)
        subprocess.run([binary, "ts", "-reply", "-config", str(config), "-queryfile", str(source), "-out", str(out)],
                       capture_output=True, check=True)
        return out.read_bytes()
    return reply, ca_path


async def local_services(tsa_reply):
    """TSA at /tsr, calendars at /cal-a and /cal-chunked (chunked encoding); anything else fails with 500."""
    seen = []

    async def handle(reader, writer):
        head = (await reader.readuntil(b"\r\n\r\n")).decode()
        path = head.split()[1]
        length = int(next(l.split(":")[1] for l in head.split("\r\n") if l.lower().startswith("content-length")))
        body = await reader.readexactly(length)
        seen.append((path, body))
        if path == "/tsr":
            data = await asyncio.to_thread(tsa_reply, body)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
        elif path == "/cal-a/digest":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(OTS_ANSWER)).encode() + b"\r\n\r\n" + OTS_ANSWER)
        elif path == "/cal-chunked/digest":
            half = len(OTS_ANSWER) // 2
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         + b"%x\r\n" % half + OTS_ANSWER[:half] + b"\r\n"
                         + b"%x\r\n" % (len(OTS_ANSWER) - half) + OTS_ANSWER[half:] + b"\r\n0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], seen


def test_checkpoint_is_timestamped_exported_and_verified(journal, tmp_path, monkeypatch):
    tsa_reply, ca_path = synthetic_tsa(tmp_path)
    store, vault = journal
    (tmp_path / "other").mkdir()
    _, wrong_ca = synthetic_tsa(tmp_path / "other")
    roots = [(x509.load_pem_x509_certificate(wrong_ca.read_bytes()),)]
    monkeypatch.setattr(anchoring, "trusted_roots", lambda: roots[0])

    async def run():
        server, port, seen = await local_services(tsa_reply)
        base = "http://127.0.0.1:" + str(port)
        settings = {"tsa_urls": [base + "/tsr"],
                    "ots_calendars": [base + "/cal-a", base + "/cal-chunked", base + "/broken"]}
        store.append("test", {"n": 1})
        retain_checkpoint(store, vault)
        untrusted = await anchor_latest(store, NetworkConfig(kind="direct"), {**settings, "ots_calendars": []})
        roots[0] = (x509.load_pem_x509_certificate(ca_path.read_bytes()),)
        first = await anchor_latest(store, NetworkConfig(kind="direct"), settings)
        second = await anchor_latest(store, NetworkConfig(kind="direct"), settings)
        server.close()
        return untrusted, first, second, seen
    untrusted, first, second, seen = asyncio.run(run())
    assert not untrusted["results"][0]["ok"] and "trusted root" in untrusted["results"][0]["error"]
    ok = {r["service"].rsplit("/", 1)[1]: r for r in first["results"]}
    assert ok["tsr"]["ok"] and ok["tsr"]["time"] and ok["cal-a"]["status"] == "pending"
    assert ok["tsr"]["signer"] == "CN=Synthetic test TSA only" and ok["tsr"]["root"] == "CN=Synthetic test CA only"
    assert ok["cal-chunked"]["ok"] and not ok["broken"]["ok"] and ok["broken"]["error"] == "HTTP 500"
    assert [r["service"].rsplit("/", 1)[1] for r in second["results"]] == ["broken"]
    checkpoint_bytes = (store.root / "checkpoints" / first["checkpoint"]["file"]).read_bytes()
    digest = hashlib.sha256(checkpoint_bytes).digest()
    assert all(body == digest for path, body in seen if path.endswith("/digest"))
    assert store.events(kind="anchor.completed")[0]["payload"]["checkpoint"]["sha256"] == digest.hex()

    path = export_file(store, vault, "zip")
    result = verify_bundle(path, fingerprint(vault.public_key), tsa_ca=ca_path)
    kinds = sorted((a["kind"], a.get("status")) for a in result["anchors"])
    assert kinds == [("opentimestamps", "pending"), ("opentimestamps", "pending"), ("rfc3161", 0)]
    tsa = next(a for a in result["anchors"] if a["kind"] == "rfc3161")
    assert tsa["signature"] == "checked against the given root" and tsa["time"]


    hashes = {0: "0" * 64, **{e["seq"]: e["hash"] for e in store.all_events()}}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert verify_anchors(archive, names, vault.public_key, result["events"], hashes.get, ca_path)
        with pytest.raises(ValueError, match="signature check failed"):
            verify_anchors(archive, names, vault.public_key, result["events"], hashes.get, wrong_ca)
        reply = archive.read(next(n for n in names if n.endswith(".tsr")))
        query = archive.read(next(n for n in names if n.endswith(".tsq")))
    with pytest.raises(ValueError, match="does not cover"):
        timestamp_reply_summary(reply, hashlib.sha256(b"other").digest())
    _, start, _ = der(query, 0)
    _, nonce_start, nonce_end = der(query, der(query, der(query, start)[2])[2])
    with pytest.raises(ValueError, match="nonce"):
        timestamp_reply_summary(reply, digest, query[:nonce_start] + bytes(nonce_end - nonce_start) + query[nonce_end:])
    with pytest.raises(ValueError, match="not for this checkpoint"):
        ots_summary((store.root / "checkpoints" / "anchors").glob("*.ots").__next__().read_bytes(), bytes(32))


def test_real_authorities_chain_to_the_shipped_roots_and_tampering_fails():
    digest = hashlib.sha256((REAL / "data.bin").read_bytes()).digest()
    for name, root in (("freetsa", "CN=www.freetsa.org"), ("digicert-http", "CN=DigiCert Trusted Root G4"),
                       ("sectigo", "CN=USERTrust RSA Certification Authority")):
        reply, query = (REAL / (name + ".tsr")).read_bytes(), (REAL / (name + ".tsq")).read_bytes()
        assert timestamp_reply_summary(reply, digest, query)["time"].startswith("2026-10-31T")
        assert root in timestamp_signature(reply, trusted_roots())["root"]
    with pytest.raises(ValueError, match="trusted root"):
        timestamp_signature((REAL / "dfn.tsr").read_bytes(), trusted_roots())
    reply = (REAL / "sectigo.tsr").read_bytes()
    _, _, start, end = timestamp_token(reply)["signer"]
    signature = children(reply, start, end)[5]
    for at, message in ((signature[2] + 7, "signature is invalid"), (reply.find(digest) + 3, "does not cover this TSTInfo")):
        tampered = bytearray(reply)
        tampered[at] ^= 1
        with pytest.raises(ValueError, match=message):
            timestamp_signature(bytes(tampered), trusted_roots())


def test_mtproxy_route_never_sends_timestamp_requests(journal):
    store, vault = journal
    retain_checkpoint(store, vault)
    route = NetworkConfig(kind="mtproxy", host="proxy.example", port=443, secret="dd" + "a" * 32)
    settings = EvidenceMode(enabled=True, tsa_urls=["https://127.0.0.1:9/tsr"], ots_calendars=[]).model_dump()
    result = asyncio.run(anchor_latest(store, route, settings))
    assert not result["results"][0]["ok"] and "MTProxy" in result["results"][0]["error"]
    assert not list((store.root / "checkpoints" / "anchors").iterdir())


def test_evidence_settings_validation_and_api(tmp_path, monkeypatch):
    for bad in ({"tsa_urls": ["ftp://tsa.example"]}, {"tsa_urls": ["http://timestamp.digicert.com"]},
                {"ots_calendars": ["http://cal.example"]}, {"ots_calendars": ["https://user:secret@cal.example"]}):
        with pytest.raises(ValidationError):
            EvidenceMode(**bad)
    assert EvidenceMode().model_dump()["enabled"] is False
    assert all(url.startswith("https://") for url in EvidenceMode().model_dump()["tsa_urls"])
    monkeypatch.delenv("TGWITNESS_TOKEN", raising=False)
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer " + app.state.vault.token

        app.state.store.set_setting("evidence", {"tsa_urls": ["http://timestamp.digicert.com", "http://tsa.example/x"],
                                                 "ots_calendars": ["http://cal.example"]})
        assert evidence_settings(app.state.store)["tsa_urls"] == ["https://timestamp.sectigo.com", "https://tsa.example/x"]
        assert evidence_settings(app.state.store)["ots_calendars"] == ["https://cal.example"]
        assert c.post("/api/evidence/anchor", json={}).status_code == 409
        body = {"enabled": True, "interval_minutes": 10, "tsa_urls": ["https://127.0.0.1:9/tsr"], "ots_calendars": []}
        state = c.post("/api/evidence", json=body).json()
        assert state["settings"]["enabled"] and state["defaults"]["tsa_urls"][0] == "https://freetsa.org/tsr"
        assert c.post("/api/evidence", json={**body, "tsa_urls": ["javascript:alert(1)"]}).status_code == 422
        assert c.post("/api/evidence", json={**body, "tsa_urls": ["http://127.0.0.1:9/tsr"]}).status_code == 422
        deadline = time.time() + 30
        while not c.get("/api/evidence").json()["last"] and time.time() < deadline:
            time.sleep(0.2)
        last = c.get("/api/evidence").json()["last"]
        assert last and not last["results"][0]["ok"]
        events = c.get("/api/events?kind=evidence.changed").json()["events"]
        assert events[0]["payload"]["fingerprint"] == fingerprint(app.state.vault.public_key)
