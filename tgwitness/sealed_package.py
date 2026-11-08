import argparse
import json
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .sealed_crypto import encrypt_file, encrypt_stream
from .store import canonical
from .verify import verify_bundle
from .sealed_parts import MANIFEST, SEALED_RESULT, load_manifest
from .sealed_crypto import recipient_id


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
    result = json.loads((output / "result.json").read_bytes())
    if result == SEALED_RESULT:
        statement = load_manifest(output / MANIFEST, encrypted=True)
        if statement["recipient_sha256"] != recipient_id(config["recipient"]) or statement["context"] != config["context"]:
            raise ValueError("Multipart delivery belongs to another recipient or capture")
        with encrypt_stream(output / "delivery.tgwsealed", config["recipient"]) as outgoing:
            with zipfile.ZipFile(outgoing, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.write(output / MANIFEST, MANIFEST)
                archive.write(attestation, "attestation.jsonl")
                archive.writestr("README.txt", "This delivery has encrypted parts of one complete ZIP. Keep all delivery-*.tgwsealed files.\n"
                    "Using a trusted TgWitness installation, put this manifest beside the parts and assemble:\n"
                    "python -m tgwitness.sealed_parts evidence.parts.json --key sealed-key.json --out evidence.zip\n"
                    "Then verify the manifest attestation and assembled archive:\n"
                    "python -m tgwitness.sealed_verify evidence.parts.json --bundle attestation.jsonl --repo OWNER/FORK --max-gib 64\n"
                    "The parts are encrypted separately to bound memory and avoid another plaintext copy on the runner.\n"
                    "Missing or modified parts are rejected. Collection may still be partial; inspect signed coverage.\n")
        return
    if result != {"phase": "sealed"}:
        raise ValueError("The capture did not finish")
    if config.get("client") == "official_web":
        from tgwitness_capture.verify import verify_zip
        verify_zip(evidence)
    else:
        verify_bundle(evidence)
    with encrypt_stream(output / "delivery.tgwsealed", config["recipient"]) as outgoing:
        with zipfile.ZipFile(outgoing, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.write(evidence, "evidence.zip")
            archive.write(attestation, "attestation.jsonl")
            archive.writestr("README.txt", "This ZIP contains a Telegram observation archive and its GitHub attestation.\n"
                "Verify with tools from an independently trusted TgWitness checkout:\n"
                "python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/FORK\n"
                "Do not execute scripts supplied by an untrusted archive.\n"
                "Attestation binds the file to the approved workflow and recorded source revision.\n"
                "Inspect collection limits and partial results in the signed journal.\n"
                "If session revocation was not confirmed, end this session in Telegram Settings > Devices.\n")


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
