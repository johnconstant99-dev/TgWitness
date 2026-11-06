"""Read-only provider observations on an independent witness host.

Cloudflare is a network observer, not a Telegram content oracle. No connector token
endpoint, mutation endpoint, or collector signing key is used here.
"""
import ipaddress
import re
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from .format import canonical, decode, utcnow
from .witness import NoRedirect


def fetch(path, token, body=None):
    request = urllib.request.Request("https://api.cloudflare.com/client/v4" + path,
                                    data=canonical(body) if body is not None else None,
                                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=10) as response:
        raw = response.read(2 * 1024**2 + 1)
    if len(raw) > 2 * 1024**2:
        raise ValueError("Provider response too large")
    value = decode(raw)
    if value.get("errors") or value.get("success") is False:
        raise ValueError("Provider rejected the read-only query")
    return value


def observe(journal, config, token, request=fetch):
    if not isinstance(config, dict) or set(config) - {"account", "connector_id", "gateway_location", "source_ip"}:
        raise ValueError("Unknown provider witness configuration")
    account = config.get("account", "")
    if not re.fullmatch(r"[a-f0-9]{32}", account):
        raise ValueError("Invalid Cloudflare account ID")
    connector = str(uuid.UUID(config["connector_id"]))
    if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("Invalid provider token")
    base = "/accounts/" + account + "/warp_connector/" + connector
    observed = utcnow()
    artifacts, outcomes = [], {}
    for label, path in (("connector", base), ("connections", base + "/connections")):
        try:
            raw = request(path, token)
            artifacts.append(journal.artifact(canonical(raw), "cloudflare_" + label, "application/json"))
            outcomes[label] = {"status": "observed", "provider_status": raw.get("result", {}).get("status")
                               if isinstance(raw.get("result"), dict) else None}
        except Exception as exc:
            outcomes[label] = {"status": "unavailable", "error": type(exc).__name__}
    if config.get("gateway_location"):
        location = str(uuid.UUID(config["gateway_location"]))
        source = str(ipaddress.ip_address(config["source_ip"]))
        until = datetime.now(timezone.utc)
        variables = {"account": account, "location": location, "source": source,
                     "since": (until - timedelta(minutes=5)).isoformat(), "until": until.isoformat()}
        query = ("query($account: String!, $location: String!, $source: String!, $since: Time!, $until: Time!) { "
                 "viewer { accounts(filter: {accountTag: $account}) { cf1GatewayDnsRawGroups(limit: 1000, "
                 "filter: {location: $location, sourceIP: $source, datetime_geq: $since, datetime_lt: $until}, "
                 "orderBy: [datetime_DESC]) { dimensions { datetime destination } } } } }")
        try:
            raw = request("/graphql", token, {"query": query, "variables": variables})
            rows = raw["data"]["viewer"]["accounts"][0]["cf1GatewayDnsRawGroups"]
            artifacts.append(journal.artifact(canonical(raw), "cloudflare_dns", "application/json"))
            outcomes["dns"] = {"status": "observed", "rows": len(rows), "possibly_truncated": len(rows) >= 1000,
                               "window": variables, "complete": False}
        except Exception as exc:
            outcomes["dns"] = {"status": "unavailable", "error": type(exc).__name__, "window": variables}
    return journal.append("network_witness.observed", {"account": account, "connector_id": connector, "outcomes": outcomes,
                          "polled_at": observed, "scope": "provider samples; no proof of continuous presence, egress binding, or Telegram content",
                          "binding": "resource IDs supplied by operator; verifier must establish relation to case"}, artifacts)
