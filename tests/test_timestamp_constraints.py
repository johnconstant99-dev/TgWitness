import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from tgwitness.anchor import find_openssl, timestamp_request, verify_timestamp
from tgwitness.verify import timestamp_signature


def timestamp_chain(folder, fault):
    try:
        openssl = find_openssl()
    except ValueError:
        pytest.skip("OpenSSL is required for synthetic RFC 3161 chains")
    now = datetime.now(timezone.utc)

    def certificate(name, parent=None, *, ca=True, length=0, sign=True, unknown=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        issuer, signing_key = (parent[0].subject, parent[1]) if parent else (subject, key)
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=2))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=length if ca else None), critical=True)
                   .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca and sign, ca and sign,
                                                False, False), critical=True))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        if unknown:
            builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5.99"),
                                                                        b"\x05\x00"), critical=True)
        return builder.sign(signing_key, hashes.SHA256()), key

    root = certificate("Synthetic root", length=2)
    middle = certificate("Synthetic intermediate", root, length=0, sign=fault != "key_usage",
                         unknown=fault == "critical_extension")
    chain = [middle, root]
    if fault == "path_length":
        chain.insert(0, certificate("Forbidden subordinate CA", middle))
    leaf = certificate("Synthetic timestamp signer", chain[0], ca=False)
    paths = {name: folder / name for name in ("root.pem", "chain.pem", "signer.pem", "key.pem", "serial",
                                             "tsa.cnf", "data", "query.tsq", "reply.tsr")}
    paths["root.pem"].write_bytes(root[0].public_bytes(serialization.Encoding.PEM))
    paths["chain.pem"].write_bytes(b"".join(c[0].public_bytes(serialization.Encoding.PEM) for c in chain))
    paths["signer.pem"].write_bytes(leaf[0].public_bytes(serialization.Encoding.PEM))
    paths["key.pem"].write_bytes(leaf[1].private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths["serial"].write_text("01")
    paths["data"].write_bytes(b"synthetic checkpoint")
    paths["query.tsq"].write_bytes(timestamp_request(paths["data"].read_bytes()))
    paths["tsa.cnf"].write_text(
        "[tsa]\ndefault_tsa=demo\n[demo]\ncrypto_device=builtin\n"
        + "\n".join(name + "=" + paths[file].as_posix() for name, file in (
            ("serial", "serial"), ("signer_cert", "signer.pem"), ("certs", "chain.pem"), ("signer_key", "key.pem")))
        + "\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\ndigests=sha256\n"
        "accuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=yes\ness_cert_id_alg=sha256\n")
    subprocess.run([openssl, "ts", "-reply", "-config", str(paths["tsa.cnf"]), "-queryfile",
                    str(paths["query.tsq"]), "-out", str(paths["reply.tsr"])], capture_output=True, check=True)
    return root[0], paths, openssl


@pytest.mark.parametrize("fault", (None, "key_usage", "path_length", "critical_extension"))
def test_timestamp_chain_enforces_certificate_constraints(tmp_path, fault):
    root, paths, openssl = timestamp_chain(tmp_path, fault)
    reply = paths["reply.tsr"].read_bytes()
    if fault:
        with pytest.raises(ValueError, match="verification failed"):
            verify_timestamp(paths["data"], paths["reply.tsr"], paths["root.pem"], paths["query.tsq"], openssl=openssl)
        with pytest.raises(ValueError, match="certificate|chain"):
            timestamp_signature(reply, [root])
    else:
        assert verify_timestamp(paths["data"], paths["reply.tsr"], paths["root.pem"],
                                paths["query.tsq"], openssl=openssl)["verified"]
        assert timestamp_signature(reply, [root])["root"] == "CN=Synthetic root"
