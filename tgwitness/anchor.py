"""Prepare an offline RFC 3161 request and verify a TSA response against a trusted CA, without OpenSSL."""
import argparse
import hashlib
import io
import json
import os
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

If needed add --intermediates tsa-intermediates.pem. OpenSSL is not needed.
The verifier checks both checkpoint bytes and the original request (including nonce).
Then verify the evidence ZIP against checkpoint.json and a separately trusted
collector fingerprint using tgwitness/verify.py.

A TSA response binds these bytes to the authority's stated time. Retain the
response with the matching checkpoint and verification result.
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


def verify_timestamp(checkpoint_path, response_path, ca_path, request_path=None, intermediates=None):
    from cryptography import x509
    from .verifier.timestamps import timestamp_reply_summary, timestamp_signature, tsa_roots
    paths = [checkpoint_path, response_path, ca_path] + ([request_path] if request_path else [])
    if intermediates:
        paths.append(intermediates)
    if any(not Path(p).is_file() for p in paths):
        raise ValueError("Every timestamp/CA input must be an existing file.")
    data, reply = Path(checkpoint_path).read_bytes(), Path(response_path).read_bytes()
    query = Path(request_path).read_bytes() if request_path else None
    extra = x509.load_pem_x509_certificates(Path(intermediates).read_bytes()) if intermediates else []
    try:
        summary = timestamp_reply_summary(reply, hashlib.sha256(data).digest(), query)
        signed = timestamp_signature(reply, tsa_roots(ca_path), intermediates=extra)
    except (ValueError, TypeError, IndexError) as exc:
        raise ValueError("TSA verification failed: " + str(exc)) from None
    return {"verified": True, "checkpoint_sha256": hashlib.sha256(data).hexdigest(),
            "request_checked": request_path is not None, "trust_store": "explicit CA file",
            "time": summary["time"], "signer": signed["signer"], "root": signed["root"],
            "root_sha256": signed["root_sha256"],
            "limitation": "The timestamp shows that the checkpoint existed by its time; the response was checked "
                          "against the explicit CA file."}


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
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            checkpoint = json.loads(args.checkpoint.read_bytes())
            with args.out.open("xb") as output:
                output.write(request_archive(checkpoint))
            print("Prepared timestamp request. No TSA was contacted:", args.out)
        else:
            print(json.dumps(verify_timestamp(args.checkpoint, args.response, args.ca, args.request,
                                             args.intermediates), indent=2))
    except Exception as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
