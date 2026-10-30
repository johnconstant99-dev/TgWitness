import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tgwitness.anchor import find_openssl, request_archive, timestamp_request, verify_timestamp
from tgwitness.evidence import checkpoint


def openssl_binary():
    try:
        return find_openssl()
    except ValueError:
        pytest.skip("OpenSSL is required for the local RFC 3161 interoperability test")


def test_timestamp_query_binds_exact_checkpoint_and_nonce(journal, tmp_path):
    binary = openssl_binary()
    store, vault = journal
    store.append("test", {})
    cp = checkpoint(store, vault)
    content = request_archive(cp)
    with zipfile.ZipFile(BytesIO(content)) as z:
        query = z.read("timestamp.tsq")
        data = z.read("checkpoint.json")
        assert hashlib.sha256(data).digest() in query
        assert query != timestamp_request(data)
        assert json.loads(data) == cp
    source = tmp_path / "request.tsq"
    source.write_bytes(query)
    result = subprocess.run([binary, "ts", "-query", "-in", str(source), "-text"],
                            capture_output=True, check=True)
    assert b"sha256" in result.stdout and b"Certificate required: yes" in result.stdout


def test_timestamp_ca_nonce_and_data_are_all_checked(tmp_path, monkeypatch):
    binary = openssl_binary()
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test CA only")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test TSA only")])
    def builder(subject, issuer, key):
        return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
                now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
    ca = builder(ca_name, ca_name, ca_key).add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True).add_extension(
        x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
    ).sign(ca_key, hashes.SHA256())
    tsa = builder(tsa_name, ca_name, tsa_key).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True).add_extension(
        x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True
    ).sign(ca_key, hashes.SHA256())
    ca_path, tsa_path, key_path = [tmp_path / n for n in ("ca.pem", "tsa.pem", "tsa-key.pem")]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    tsa_path.write_bytes(tsa.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(tsa_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    data_path, query_path, response_path = [tmp_path / n for n in ("checkpoint.json", "request.tsq", "response.tsr")]
    data_path.write_bytes(b'{"synthetic":"fixture; not an independent trusted timestamp"}')
    query_path.write_bytes(timestamp_request(data_path.read_bytes()))
    serial = tmp_path / "serial"
    serial.write_text("01")
    config = tmp_path / "tsa.cnf"
    config.write_text("[tsa]\ndefault_tsa=demo\n[demo]\n"
                      "serial=" + serial.as_posix() + "\ncrypto_device=builtin\n"
                      "signer_cert=" + tsa_path.as_posix() + "\n"
                      "certs=" + ca_path.as_posix() + "\n"
                      "signer_key=" + key_path.as_posix() + "\n"
                      "signer_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\n"
                      "accuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=yes\n"
                      "ess_cert_id_alg=sha256\n")
    subprocess.run([binary, "ts", "-reply", "-config", str(config), "-queryfile", str(query_path),
                    "-out", str(response_path)], capture_output=True, check=True)
    assert verify_timestamp(data_path, response_path, ca_path, query_path, openssl=binary)["verified"]
    original = data_path.read_bytes()
    data_path.write_bytes(original + b"changed")
    with pytest.raises(ValueError, match="verification failed"):
        verify_timestamp(data_path, response_path, ca_path, query_path, openssl=binary)
    data_path.write_bytes(original)
    query_path.write_bytes(timestamp_request(original))  # same data, different nonce
    with pytest.raises(ValueError, match="verification failed"):
        verify_timestamp(data_path, response_path, ca_path, query_path, openssl=binary)
    unrelated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_ca = builder(ca_name, ca_name, unrelated_key).add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True).sign(unrelated_key, hashes.SHA256())
    wrong_path = tmp_path / "untrusted-ca.pem"
    wrong_path.write_bytes(wrong_ca.public_bytes(serialization.Encoding.PEM))
    # Even a valid root in OpenSSL's ambient CA environment must not be trusted.
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="verification failed"):
        verify_timestamp(data_path, response_path, wrong_path, openssl=binary)
