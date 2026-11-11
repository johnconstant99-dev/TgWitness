import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone

CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
GENESIS, PERIOD = 1692803367, 3
RELAY = "https://api.drand.sh/" + CHAIN + "/public/"


def validate(value):
    if (not isinstance(value, dict) or type(value.get("round")) is not int
            or not 1 <= value["round"] <= 2**40 or not isinstance(value.get("signature"), str)
            or not re.fullmatch(r"[0-9a-f]{96}", value["signature"])
            or hashlib.sha256(bytes.fromhex(value["signature"])).hexdigest() != value.get("randomness")):
        raise ValueError("Invalid drand beacon representation")
    return {key: value[key] for key in ("round", "signature", "randomness")}


def round_time(number):
    return datetime.fromtimestamp(GENESIS + (number - 1) * PERIOD, timezone.utc).isoformat()


def records(events):
    found = []
    for event in events:
        if event["kind"] != "official.drand":
            continue
        value = validate(event["payload"])
        if event["payload"].get("chain") != CHAIN or event["payload"].get("round_time") != round_time(value["round"]):
            raise ValueError("Unexpected drand chain or time")
        if found and value["round"] <= found[-1]["round"]:
            raise ValueError("Drand rounds must increase")
        found.append({"seq": event["seq"], **value})
    return found


def fetch(number):
    request = urllib.request.Request(RELAY + str(number), headers={"User-Agent": "TgWitness verifier"})
    with urllib.request.urlopen(request, timeout=15) as response:
        data = response.read(4097)
    if len(data) > 4096:
        raise ValueError("Oversized drand reply")
    return json.loads(data)


def confirm(values, request=fetch, limit=100):
    if not values:
        return {"status": "INCOMPLETE", "checked": 0, "recorded": 0, "reason": "no_beacons"}
    import secrets
    chosen = values if len(values) <= limit else [values[0], values[-1], *secrets.SystemRandom().sample(values[1:-1], limit - 2)]
    checked = 0
    for value in chosen:
        try:
            answer = validate(request(value["round"]))
        except (OSError, ValueError):
            continue
        if answer != {key: value[key] for key in ("round", "signature", "randomness")}:
            raise ValueError("Recorded drand value differs from the independently queried relay")
        checked += 1
    return {"status": "PASS" if checked == len(values) else "INCOMPLETE", "checked": checked,
            "recorded": len(values), "method": "independent TLS query to pinned-chain public relay",
            "scope": "not-before bounds"}
