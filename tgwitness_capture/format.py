import hashlib
import json
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "tgwitness-capture-v1"
DOMAIN = b"tgwitness-capture-v1\x00"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ZERO = "0" * 64


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def fingerprint(public_key):
    raw = bytes.fromhex(public_key)
    if len(raw) != 32:
        raise ValueError("Invalid public key")
    return digest(raw)


def seal(key, purpose, body):
    return key.sign(DOMAIN + purpose.encode("ascii") + b"\x00" + canonical(body)).hex()


def check_seal(public_key, purpose, body, signature):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
        bytes.fromhex(signature), DOMAIN + purpose.encode("ascii") + b"\x00" + canonical(body))


def check_events(events, public_key, observer_id):
    previous = ZERO
    clocks = {}
    fields = {"format", "observer_id", "session_id", "seq", "kind", "observed_at",
              "recorded_at", "monotonic_ns", "previous_hash", "payload", "artifacts"}
    for seq, event in enumerate(events, 1):
        if set(event) != fields | {"hash", "signature"}:
            raise ValueError("Unexpected event fields")
        body = {key: value for key, value in event.items() if key in fields}
        if (body["format"] != FORMAT or body["observer_id"] != observer_id
                or type(body["seq"]) is not int or body["seq"] != seq
                or body["previous_hash"] != previous):
            raise ValueError("Broken event sequence")
        if not isinstance(body["payload"], dict) or not isinstance(body["artifacts"], list):
            raise ValueError("Invalid event contents")
        if type(body["monotonic_ns"]) is not int or body["monotonic_ns"] < 0:
            raise ValueError("Invalid monotonic clock")
        if any(not isinstance(body[name], str) or not body[name]
               for name in ("session_id", "kind", "observed_at", "recorded_at")):
            raise ValueError("Invalid event metadata")
        if body["monotonic_ns"] < clocks.get(body["session_id"], -1):
            raise ValueError("Monotonic clock moved backwards within a process session")
        clocks[body["session_id"]] = body["monotonic_ns"]
        expected = digest(DOMAIN + b"event\x00" + canonical(body))
        if event["hash"] != expected:
            raise ValueError("Event hash mismatch")
        check_seal(public_key, "event-hash", expected, event["signature"])
        for artifact in body["artifacts"]:
            if (set(artifact) != {"sha256", "size", "role", "media_type"}
                    or not isinstance(artifact["sha256"], str) or not HEX.fullmatch(artifact["sha256"])
                    or type(artifact["size"]) is not int or artifact["size"] < 0
                    or not isinstance(artifact["role"], str) or not isinstance(artifact["media_type"], str)):
                raise ValueError("Invalid artifact descriptor")
        previous = expected
    return previous


def check_checkpoint(checkpoint, public_key, observer_id):
    body = checkpoint["body"]
    if (set(body) != {"format", "observer_id", "public_key", "seq", "head_hash", "created_at", "challenge"}
            or body["format"] != FORMAT or body["observer_id"] != observer_id
            or body["public_key"] != public_key or type(body["seq"]) is not int or body["seq"] < 0
            or not isinstance(body["head_hash"], str) or not HEX.fullmatch(body["head_hash"])):
        raise ValueError("Invalid checkpoint")
    check_seal(public_key, "checkpoint", body, checkpoint["signature"])
    return body
