"""Check a fixed TgWitness documentation export; with keys, open and check its sealed records."""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .documentation import FORMAT, KEYS_FORMAT, reason_key
from .store import canonical


def decoded(value):
    return base64.b64decode(value, validate=True)


def verify(exported, keys=None, expected_fingerprint=None):
    signed = exported.get("signed") if isinstance(exported, dict) else None
    if not isinstance(signed, dict):
        raise ValueError("This copy is a draft; only a fixed document is signed.")
    statement = signed["statement"]
    if statement.get("format") != FORMAT:
        raise ValueError("Unsupported documentation format")
    public = decoded(statement["public_key"])
    fingerprint = hashlib.sha256(public).hexdigest()
    if expected_fingerprint and fingerprint != expected_fingerprint.lower():
        raise ValueError("Public key differs from the independently trusted fingerprint")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(decoded(signed["signature"]), canonical(statement))
    except InvalidSignature:
        raise ValueError("The signature does not match this statement") from None
    if hashlib.sha256(canonical(exported.get("document"))).hexdigest() != statement["document_sha256"]:
        raise ValueError("The document differs from the signed statement")
    digest = hashlib.sha256(canonical(statement)).hexdigest()
    if keys is not None:
        if keys.get("format") != KEYS_FORMAT or keys.get("statement_sha256") != digest:
            raise ValueError("These keys belong to another document")
    master = decoded(keys["master"]) if keys and keys.get("master") else None
    given = {label: decoded(value) for label, value in ((keys or {}).get("labels") or {}).items()}
    listed = {(item["seq"], item["hash"]) for item in statement["items"] if item["type"] == "step"}
    revealed, sealed = [], []
    for entry in statement.get("sealed") or []:
        if (entry["seq"], entry["hash"]) not in listed:
            raise ValueError("A sealed record is not listed in the document")
        usable = [(label, reason_key(master, label) if master else given.get(label)) for label in entry["labels"]]
        usable = [(label, key) for label, key in usable if key]
        if not usable:
            sealed.append({"seq": entry["seq"], "hash": entry["hash"], "labels": entry["labels"]})
            continue
        label, key = usable[0]
        aad = bytes.fromhex(entry["hash"])
        try:
            content = AESGCM(key).decrypt(decoded(entry["keys"][label]["nonce"]),
                                          decoded(entry["keys"][label]["wrapped"]), aad)
            plain = AESGCM(content).decrypt(decoded(entry["nonce"]), decoded(entry["ciphertext"]), aad)
        except (InvalidTag, KeyError):
            raise ValueError("A key does not open sealed record #" + str(entry["seq"])) from None
        if hashlib.sha256(plain).hexdigest() != entry["hash"]:
            raise ValueError("Sealed record #" + str(entry["seq"]) + " does not match its journal hash")
        revealed.append({"seq": entry["seq"], "hash": entry["hash"], "labels": entry["labels"],
                         "record": json.loads(plain)})
    return {"valid": True, "fingerprint": fingerprint, "key_pinned": bool(expected_fingerprint),
            "statement_sha256": digest, "title": statement["title"], "revision": statement["revision"],
            "steps": len(listed), "notes": sum(item["type"] == "note" for item in statement["items"]),
            "conclusions": sum(item["type"] == "conclusion" for item in statement["items"]),
            "journal_head": statement.get("journal_head"), "revealed": revealed, "still_sealed": sealed}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tgwitness.documentation_verify", description=__doc__)
    parser.add_argument("document", type=Path, help="JSON copy downloaded from the documentation drawer")
    parser.add_argument("--keys", type=Path, help="Keys file for sealed content (all labels or chosen labels)")
    parser.add_argument("--fingerprint", help="Workspace key SHA-256 obtained independently")
    parser.add_argument("--reveal", type=Path, help="Write opened records to this new JSON file")
    args = parser.parse_args(argv)
    try:
        keys = json.loads(args.keys.read_text(encoding="utf-8")) if args.keys else None
        result = verify(json.loads(args.document.read_text(encoding="utf-8")), keys, args.fingerprint)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("NOT VERIFIED: " + str(exc))
        return 1
    print("VERIFIED: " + result["title"] + " · revision " + str(result["revision"]))
    print("Signer fingerprint: " + result["fingerprint"] + ("" if result["key_pinned"] else " (not pinned)"))
    print("Statement SHA-256: " + result["statement_sha256"])
    print("Steps %d · notes %d · conclusions %d" % (result["steps"], result["notes"], result["conclusions"]))
    print("Sealed records opened and matched: %d · still sealed: %d" % (len(result["revealed"]), len(result["still_sealed"])))
    if args.reveal:
        with args.reveal.open("x", encoding="utf-8") as target:
            json.dump(result["revealed"], target, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
