"""Verify downloaded showcase statements and their journal consistency proofs offline."""
import argparse
import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .store import canonical
from .verify import fingerprint, verify_continuity


def authenticate(value, trusted_fingerprint):
    statement = value["statement"]
    public_key = statement["public_key"]
    actual = fingerprint(public_key)
    if actual != trusted_fingerprint.lower():
        raise ValueError("Signing key does not match the trusted fingerprint")
    if "fingerprint" in value and value["fingerprint"] != actual:
        raise ValueError("Displayed fingerprint differs from the signing key")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
        base64.b64decode(value["signature"], validate=True), canonical(statement))
    return statement


def verify(value, trusted_fingerprint, previous=None):
    if value.get("format") == "tgwitness-showcase-pair-v1":
        if previous is None:
            previous = value.get("previous")
        value = value["current"]
    if previous and previous.get("format") == "tgwitness-showcase-pair-v1":
        previous = previous["current"]
    statement = authenticate(value, trusted_fingerprint)
    if statement["format"] == "tgwitness-showcase-messages-v1":
        return {"projection_signature": "valid", "kind": "redacted_messages"}
    if statement["format"] != "tgwitness-showcase-v1":
        raise ValueError("Unknown showcase format")
    checkpoint = authenticate(statement["checkpoint"], trusted_fingerprint)
    if checkpoint["format"] != "tgwitness-checkpoint-v1":
        raise ValueError("Unknown checkpoint format")
    earlier = None
    if previous:
        old = authenticate(previous, trusted_fingerprint)
        if old["format"] != statement["format"] or old["workspace_id"] != statement["workspace_id"]:
            raise ValueError("Previous snapshot belongs to a different projection")
        old_checkpoint = authenticate(old["checkpoint"], trusted_fingerprint)
        earlier = authenticate(old["continuity"], trusted_fingerprint)
        if any(earlier[k] != old_checkpoint[k] for k in ("public_key", "event_count", "head_hash")):
            raise ValueError("Previous checkpoint differs from its signed tree")
    current = verify_continuity(statement["continuity"], checkpoint, earlier, statement["challenge"])
    return {"projection_signature": "valid", "checkpoint_signature": "valid", "event_count": current["event_count"],
            "continuity": "consistent with previous snapshot" if previous else "first observed boundary",
            "counts": "signed collector statement; not independently recounted from original records"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--fingerprint", required=True, help="Collector key SHA-256 from an independently trusted source")
    parser.add_argument("--previous", type=Path, help="Previously retained snapshot; overrides the pair's embedded previous snapshot")
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.snapshot.read_text(encoding="utf-8")), args.fingerprint,
                        json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else None)
    except (ValueError, KeyError, TypeError, InvalidSignature, OSError) as exc:
        parser.exit(1, "Verification failed: " + (str(exc) or type(exc).__name__) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
