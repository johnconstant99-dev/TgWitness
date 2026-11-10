from .common import (
    Ed25519PublicKey,
    FIELDS,
    base64,
    hashlib,
    re,
    validate_server_hashes,
)
def verify_events(events, public_key):
    from .chain import canonical, fingerprint
    from .coverage import parse_time
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
    previous, count = "0" * 64, 0
    previous_time, previous_at = None, None
    chronology = {"regressions": 0, "unparseable": 0, "samples": []}
    for count, event in enumerate(events, 1):
        if set(event) != set(FIELDS) | {"hash", "signature"}:
            raise ValueError("Unexpected or missing fields at event " + str(count))
        if event["seq"] != count or event["previous_hash"] != previous:
            raise ValueError("Broken sequence or hash chain at event " + str(count))
        calculated = hashlib.sha256(canonical({k: event[k] for k in FIELDS})).hexdigest()
        if event["hash"] != calculated:
            raise ValueError("Changed content at event " + str(count))
        key.verify(base64.b64decode(event["signature"], validate=True), bytes.fromhex(calculated))
        anomaly = None
        try:
            observed = parse_time(event["observed_at"])
            if observed.utcoffset() is None:
                raise ValueError("Observation time has no UTC offset")
        except (AttributeError, TypeError, ValueError, OverflowError):
            observed = None
            chronology["unparseable"] += 1
            anomaly = {"seq": count, "observed_at": event["observed_at"], "reason": "unparseable"}
        if observed is not None and previous_time is not None and observed < previous_time:
            chronology["regressions"] += 1
            anomaly = {"seq": count, "observed_at": event["observed_at"], "previous_at": previous_at,
                       "backwards_seconds": (previous_time - observed).total_seconds(), "reason": "regression"}
        if anomaly is not None and len(chronology["samples"]) < 100:
            chronology["samples"].append(anomaly)
        if observed is not None:
            previous_time, previous_at = observed, event["observed_at"]
        if event["kind"] == "media.hashed":
            payload = event["payload"]
            validate_server_hashes(payload.get("server_hashes"))
            if (payload["server_hashes"]["status"] != "complete" or payload.get("downloaded_bytes") != 0
                    or payload.get("media_sha256") is not None):
                raise ValueError("A hash-only record incorrectly claims downloaded file content")
        previous = calculated
    result = {"events": count, "head_hash": previous, "fingerprint": fingerprint(public_key)}
    if chronology["regressions"] or chronology["unparseable"]:
        chronology["meaning"] = ("Observation times come from the collector's clock; the hash chain fixes the order of "
                                 "the records, and timestamps, drand rounds and witness records fix them in time. "
                                 "These entries do not affect the signatures.")
        result["chronology"] = chronology
    return result


def media_reference(event):
    if event["kind"] not in ("media.saved", "actor.avatar_saved", "secret_chat.file"):
        return None
    payload = event["payload"]
    digest, size = payload.get("media_sha256"), payload.get("size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid media reference in the signed journal")
    if size is not None and (type(size) is not int or size < 0):
        raise ValueError("Invalid media size in the signed journal")
    return digest, size


def verify_checkpoint(checkpoint, public_key, event_count, hash_at, check_drand=False):
    from .chain import canonical, is_format
    from .outside import confirm_drand
    statement = checkpoint["statement"]
    if not is_format(statement["format"], "checkpoint-v1") or statement["public_key"] != public_key:
        raise ValueError("Checkpoint format or signing key mismatch")
    if type(statement["event_count"]) is not int or statement["event_count"] < 0:
        raise ValueError("Invalid checkpoint event count")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
        base64.b64decode(checkpoint["signature"], validate=True), canonical(statement))
    if statement["event_count"] > event_count:
        raise ValueError("Journal is shorter than the retained checkpoint")
    if hash_at(statement["event_count"]) != statement["head_hash"]:
        raise ValueError("Journal disagrees with the retained checkpoint")
    anchor = statement.get("drand_anchor")
    if check_drand and anchor and isinstance(anchor.get("round"), int) and isinstance(anchor.get("randomness"), str):
        try:
            confirmed = confirm_drand([{"round": anchor["round"], "randomness": anchor["randomness"],
                                        "seq": statement["event_count"]}])
        except ValueError as exc:
            raise ValueError("Checkpoint drand anchor: " + str(exc)) from exc
        if confirmed["confirmed"] == 0:
            raise ValueError("Checkpoint drand anchor round " + str(anchor["round"])
                             + " could not be confirmed against any drand relay")
    return anchor if anchor else None


