"""Public drand observations through the selected connector, never direct fallback."""
import hashlib
import http.client
import ipaddress
import re
import ssl
import time
import urllib.request

from .format import decode

CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
GENESIS, PERIOD = 1692803367, 3
RELAYS = ("api.drand.sh", "drand.cloudflare.com")


def beacon(value):
    if not isinstance(value, dict) or type(value.get("round")) is not int or value["round"] < 1:
        raise ValueError("Invalid drand round")
    signature = value.get("signature")
    if (not isinstance(signature, str) or not re.fullmatch("[a-f0-9]{96}", signature)
            or hashlib.sha256(bytes.fromhex(signature)).hexdigest() != value.get("randomness")):
        raise ValueError("Invalid drand signature encoding/randomness digest")
    return {key: value[key] for key in ("round", "signature", "randomness")}


def bytes_via_connector(host, path, connector):
    from python_socks import ProxyType
    from python_socks.sync import Proxy
    if connector["protocol"] not in {"socks5", "http"}:
        raise ValueError("Public anchoring is unavailable through an MTProxy-only connector")
    proxy = Proxy.create(proxy_type=ProxyType.SOCKS5 if connector["protocol"] == "socks5" else ProxyType.HTTP,
                         host=connector["host"], port=connector["port"], rdns=True)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(host, timeout=5, context=context)
    sock = proxy.connect(dest_host=host, dest_port=443, timeout=5)
    try:
        connection.sock = context.wrap_socket(sock, server_hostname=host)
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Public beacon did not return HTTP 200")
        raw = response.read(8193)
        if len(raw) > 8192:
            raise ValueError("Public beacon exceeds response limit")
        return raw
    finally:
        connection.close()
        sock.close()


def via_connector(host, path, connector):
    return decode(bytes_via_connector(host, path, connector))


def egress_probe(connector, expected_ip=None, fetch=bytes_via_connector):
    if connector["protocol"] == "mtproxy":
        return {"status": "unavailable", "reason": "MTProxy cannot carry an independent HTTPS egress probe"}
    raw = fetch("www.cloudflare.com", "/cdn-cgi/trace", connector)
    fields = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ValueError("Malformed egress observation")
        fields[key] = value
    address = str(ipaddress.ip_address(fields.get("ip", "")))
    if expected_ip and expected_ip != address:
        raise ValueError("Connector egress IP changed; stop and review before another session")
    if connector["mode"].startswith("warp") and fields.get("warp") not in {"on", "plus"}:
        raise ValueError("Chosen WARP route is not confirmed by the HTTPS probe")
    return {"status": "observed", "ip": address, "warp": fields.get("warp", "unknown"),
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "scope": "sample to Cloudflare through the selected gateway; does not establish Telegram destination routing"}


def observe(connector, fetch=via_connector):
    value = beacon(fetch(RELAYS[0], "/" + CHAIN + "/public/latest", connector))
    other = beacon(fetch(RELAYS[1], "/" + CHAIN + "/public/" + str(value["round"]), connector))
    if other != value:
        raise ValueError("Public drand relays disagree")
    round_time = GENESIS + (value["round"] - 1) * PERIOD
    if abs(time.time() - round_time) > 120:
        raise ValueError("Public round is stale or local clock is inaccurate")
    return {"chain": CHAIN, **value, "round_unix": round_time, "confirmation": "two HTTPS relays agree; BLS not checked locally",
            "meaning": "if independently confirmed, subsequent records postdate this randomness; no upper time bound"}


def confirm(events, online=False, fetch=None):
    """Verifier-side public reads; no collector route or secret is used."""
    from .witness import NoRedirect
    rounds = {}
    for event in events:
        if event["kind"] != "trusted.beacon.drand":
            continue
        payload = event["payload"]
        value = beacon(payload)
        if payload.get("chain") != CHAIN or payload.get("round_unix") != GENESIS + (value["round"] - 1) * PERIOD:
            raise ValueError("Invalid recorded drand chain/time")
        if value["round"] in rounds and rounds[value["round"]] != value:
            raise ValueError("Conflicting drand round")
        rounds[value["round"]] = value
    if online:
        if len(rounds) > 500:
            raise ValueError("More than 500 drand rounds; verify smaller session bundles")
        for number, value in rounds.items():
            for relay in RELAYS:
                url = "https://" + relay + "/" + CHAIN + "/public/" + str(number)
                if fetch:
                    result = fetch(url)
                else:
                    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(url, timeout=10) as response:
                        raw = response.read(8193)
                    if len(raw) > 8192:
                        raise ValueError("Public beacon exceeds response limit")
                    result = decode(raw)
                if beacon(result) != value:
                    raise ValueError("Recorded drand value disagrees with a public relay")
    return {"rounds": len(rounds), "relay_checked": bool(online and rounds), "bls_verified": False,
            "upper_time_bound": False}
