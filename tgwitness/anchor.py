"""Prepare an offline RFC 3161 request and verify a TSA response with a trusted CA."""
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from .store import canonical


def der(tag, value):
    length = len(value)
    encoded_length = bytes([length]) if length < 128 else (
        bytes([128 + (length.bit_length() + 7) // 8]) +
        length.to_bytes((length.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + encoded_length + value


def timestamp_request(data):
    # SHA-256 AlgorithmIdentifier: 2.16.840.1.101.3.4.2.1, NULL parameters.
    algorithm = der(0x30, bytes.fromhex("06096086480165030402010500"))
    imprint = der(0x30, algorithm + der(0x04, hashlib.sha256(data).digest()))
    nonce = b"\0" + os.urandom(16)
    nonce = nonce.lstrip(b"\0") or b"\0"
    if nonce[0] & 0x80:
        nonce = b"\0" + nonce
    return der(0x30, der(0x02, b"\x01") + imprint + der(0x02, nonce) + der(0x01, b"\xff"))


INSTRUCTIONS = """TgWitness external timestamp preparation

No external service has been contacted. This archive is NOT a trusted timestamp.
checkpoint.json is signed by the collector; timestamp.tsq is an RFC 3161 request
for SHA-256 of the exact checkpoint.json bytes, with a random nonce.

Send timestamp.tsq to a TSA you independently trust using its documented method.
Retain the original request, checkpoint, and returned timestamp.tsr.
Obtain the TSA CA certificate chain independently, not solely from the response.

Verify from a trusted TgWitness installation:
python -m tgwitness.anchor verify --checkpoint checkpoint.json --request timestamp.tsq \
--response timestamp.tsr --ca trusted-tsa-root.pem

If needed add --intermediates tsa-intermediates.pem and --openssl /path/to/openssl.
The verifier checks both checkpoint bytes and the original request (including nonce).
Then verify the evidence ZIP against checkpoint.json and a separately trusted
collector fingerprint using tgwitness/verify.py.

A TSA response establishes a statement about existence of these bytes at the TSA's
time. It does not authenticate Telegram origin or make every claim in the bytes true.
"""


def request_archive(checkpoint):
    data = canonical(checkpoint)
    query = timestamp_request(data)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("checkpoint.json", data)
        archive.writestr("timestamp.tsq", query)
        archive.writestr("SHA256SUMS", hashlib.sha256(data).hexdigest() + "  checkpoint.json\n" +
                         hashlib.sha256(query).hexdigest() + "  timestamp.tsq\n")
        archive.writestr("README.txt", INSTRUCTIONS)
    return output.getvalue()


def find_openssl(explicit=None):
    path = explicit or shutil.which("openssl")
    if not path and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/usr/bin/openssl.exe"
        if candidate.is_file():
            path = str(candidate)
    if not path:
        raise ValueError("OpenSSL is required to verify RFC 3161 responses.")
    return str(path)


def verify_timestamp(checkpoint_path, response_path, ca_path, request_path=None,
                     intermediates=None, openssl=None):
    paths = [checkpoint_path, response_path, ca_path] + ([request_path] if request_path else [])
    if intermediates:
        paths.append(intermediates)
    if any(not Path(p).is_file() for p in paths):
        raise ValueError("Every timestamp/CA input must be an existing file.")
    binary = find_openssl(openssl)
    # Unlike `openssl verify`, `ts` has no -no-CApath/-no-CAstore options.
    # Its create_cert_store loads only explicitly supplied CAfile/path/store.
    # Do not provide a CApath or CAstore: trust is limited to this CA file.
    common = [binary, "ts", "-verify", "-in", str(response_path), "-CAfile", str(ca_path)]
    if intermediates:
        common += ["-untrusted", str(intermediates)]
    for selector in ([["-data", str(checkpoint_path)], ["-queryfile", str(request_path)]]
                     if request_path else [["-data", str(checkpoint_path)]]):
        result = subprocess.run(common + selector, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise ValueError("TSA verification failed: " + result.stderr.decode(errors="replace")[-3000:])
    detail = subprocess.run([binary, "ts", "-reply", "-in", str(response_path), "-text"],
                            capture_output=True, timeout=30, check=True)
    return {"verified": True, "checkpoint_sha256": hashlib.sha256(Path(checkpoint_path).read_bytes()).hexdigest(),
            "request_checked": request_path is not None, "trust_store": "explicit CA file",
            "tsa_statement": detail.stdout.decode(errors="replace"),
            "limitation": "Timestamping does not establish Telegram origin or truthfulness. "
                          "No online revocation or long-term archival validation was performed."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("checkpoint", type=Path)
    prepare.add_argument("--out", type=Path, required=True)
    verify = commands.add_parser("verify")
    for name in ("checkpoint", "response", "ca"):
        verify.add_argument("--" + name, type=Path, required=True)
    for name in ("request", "intermediates"):
        verify.add_argument("--" + name, type=Path)
    verify.add_argument("--openssl")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            checkpoint = json.loads(args.checkpoint.read_bytes())
            with args.out.open("xb") as output:
                output.write(request_archive(checkpoint))
            print("Prepared timestamp request. No TSA was contacted:", args.out)
        else:
            print(json.dumps(verify_timestamp(args.checkpoint, args.response, args.ca, args.request,
                                             args.intermediates, args.openssl), indent=2))
    except Exception as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
