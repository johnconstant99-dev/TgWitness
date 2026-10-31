"""Runner-only packaging. This module is never exposed as an HTTP signing API."""
import argparse
import json
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .sealed_crypto import encrypt_file
from .store import canonical
from .verify import verify_bundle


def connection(config, url, destination):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".trycloudflare.com")
            or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("Unexpected tunnel URL")
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "connection.json"
        source.write_bytes(canonical({"format": "tgwitness-sealed-connection-v1",
            "url": url.rstrip("/") + "/#access=" + config["token"], "context": config["context"]}))
        encrypt_file(source, destination, config["recipient"])


def package(config, output, attestation):
    output, attestation = Path(output), Path(attestation)
    evidence = output / "evidence.zip"
    if evidence.is_symlink() or attestation.is_symlink() or not 0 < attestation.stat().st_size < 16 * 1024**2:
        raise ValueError("Invalid handoff files")
    if json.loads((output / "result.json").read_bytes()) != {"phase": "sealed"}:
        raise ValueError("The capture did not finish")
    verify_bundle(evidence)
    with tempfile.TemporaryDirectory(dir=output) as temp:
        source = Path(temp) / "delivery.zip"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.write(evidence, "evidence.zip")
            archive.write(attestation, "attestation.jsonl")
            archive.writestr("README.txt", "This ZIP contains a Telegram observation archive and its GitHub attestation.\n"
                "Verify with tools from an independently trusted TgWitness checkout:\n"
                "python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/FORK\n"
                "Do not execute scripts supplied by an untrusted archive.\n"
                "Attestation binds the file to the approved workflow, not to a Telegram signature.\n"
                "Inspect collection limits and partial results in the signed journal.\n"
                "If session revocation was not confirmed, end this session in Telegram Settings > Devices.\n")
        encrypt_file(source, output / "delivery.tgwsealed", config["recipient"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("connection", "package"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--url")
    parser.add_argument("--attestation", type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_bytes())
        if args.command == "connection":
            connection(config, args.url, args.out)
        else:
            package(config, args.out, args.attestation)
    except Exception as exc:
        parser.exit(1, "Packaging failed: " + type(exc).__name__ + "\n")


if __name__ == "__main__":
    main()
