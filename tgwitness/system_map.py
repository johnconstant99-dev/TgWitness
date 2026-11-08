import ipaddress
import platform
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import ai, alerts
from .anchoring import DRAND_RELAYS, GATEWAY_GRAPHQL, evidence_settings
from .replica import replica_settings
from .security import owner_only_state
from .storage import settings as storage_settings
from .store import utcnow
from .topology import TELEGRAM_NETWORKS, telegram_network
from .witness_api import state as witness_state


def endpoint(value):
    if not isinstance(value, (tuple, list)) or len(value) < 2:
        return None
    host, port = value[:2]
    if not isinstance(host, str) or type(port) is not int or not 0 < port < 65536:
        return None
    return {"host": host, "port": port}


def socket_state(client):
    connection = getattr(getattr(client, "_sender", None), "_connection", None)
    writer = getattr(connection, "_writer", None)
    try:
        if writer is None or writer.is_closing():
            return {"local": None, "peer": None}
        return {"local": endpoint(writer.get_extra_info("sockname")),
                "peer": endpoint(writer.get_extra_info("peername"))}
    except (AttributeError, OSError, ValueError):
        return {"local": None, "peer": None}


def service_endpoint(url):
    try:
        parsed = urlsplit(url or "")
        return endpoint((parsed.hostname, parsed.port or {"https": 443, "http": 80}.get(parsed.scheme)))
    except ValueError:
        return None


OWNER_ONLY_TTL = 300
_owner_only = {}


def owner_only(root):
    key, now = str(root), time.monotonic()
    cached = _owner_only.get(key)
    if cached and now - cached[0] < OWNER_ONLY_TTL:
        return cached[1]
    try:
        restricted, detail = owner_only_state(Path(root))
    except OSError:
        restricted, detail = False, "owner-only access could not be checked"
    value = {"restricted": bool(restricted), "detail": detail}
    _owner_only[key] = (now, value)
    return value


def pool_binding(socket, target, route):
    peer = (socket or {}).get("peer") or {}
    peer_host, target_host = peer.get("host"), (target or {}).get("host")
    peer_network = telegram_network(peer_host) if peer_host else None
    target_network = telegram_network(target_host) if target_host else None
    proxied = bool(route.get("gateway")) or route["kind"] in ("mtproxy", "mtproxy_auto", "socks5", "http", "warp", "vpn")
    return {"peer_network": peer_network, "target_network": target_network,
            "peer_in_pool": peer_network is not None, "target_in_pool": target_network is not None,
            "proxied": proxied, "carries_telegram_only": target_network is not None}


def account_snapshot(identifier, label, app):
    if app is None:
        return {"id": identifier, "label": label, "state": "unavailable"}
    state = app.state
    c = state.collector
    client = c.client
    connected = bool(client and client.is_connected())
    route = c.route_status()
    policy = c.policy_state()
    current = state.connection.public()["current"]
    session = getattr(client, "session", None)
    target = endpoint((getattr(session, "server_address", None), getattr(session, "port", None)))
    target_prefix = None
    if target:
        try:
            address = ipaddress.ip_address(target["host"])
            target_prefix = str(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
        except ValueError:
            pass
    rpc = client.rpc_activity() if client and hasattr(client, "rpc_activity") else None
    methods = (rpc or {}).get("methods", {})
    counters = {key: sum(row.get(key, 0) for row in methods.values()) for key in ("calls", "ok", "errors")}
    proxy = route.get("current") if route["kind"] == "mtproxy_auto" else route
    gateway = endpoint(((proxy or {}).get("host"), (proxy or {}).get("port")))
    if route.get("fallback_to_direct"):
        gateway = None
    evidence = evidence_settings(c.store)
    replica = replica_settings(c.store)
    captures = state.capture.public()["connections"]
    witnesses = witness_state(state.vault, c.store)["tokens"]
    outside = state.api_context.outside_state()
    timestamp_health = state.api_context.timestamps_health(outside)
    replica_health = state.api_context.replica_health(outside)
    storage = storage_settings(c.store)
    storage_last = c.store.get_setting("storage_last", {}) or {}
    hooks = state.vault.read("webhooks").get("entries", [])
    analysis = ai.settings(state)
    source_check = c.store.get_setting("source_check", None)
    independent = c.store.get_setting("evidence_witnesses", {}) or {}
    features = [
        {"id": "timestamps", "enabled": evidence["enabled"], "busy": state.anchor_status.get("busy", False),
         "health": timestamp_health["state"], "last_success": timestamp_health.get("last_verified_at"),
         "endpoints": [service_endpoint(url) for url in evidence["tsa_urls"] + evidence["ots_calendars"]]},
        {"id": "replica", "enabled": replica["enabled"], "busy": state.replica_status.get("busy", False),
         "health": replica_health["state"], "last_success": replica_health.get("last_success_at"),
         "lag_records": replica_health.get("lag_records"), "endpoints": [service_endpoint(replica["endpoint"])],
         "recipient_encryption": bool(replica["recipient_public_key"]),
         "retention_days": replica["retention_days"], "retention_mode": replica["retention_mode"]},
        {"id": "storage", "enabled": storage["enabled"], "busy": state.storage.busy,
         "health": "failed" if storage_last.get("error") else None, "last_check": storage_last.get("at"),
         "backend": storage["backend"], "endpoints": [service_endpoint(replica["endpoint"])] if storage["backend"] == "s3" else []},
        {"id": "proxy_lists", "enabled": route["kind"] == "mtproxy_auto", "endpoints": []},
        {"id": "source_check", "enabled": bool(source_check), "last_check": (source_check or {}).get("checked_at"),
         "health": "failed" if source_check and not source_check.get("matches") else None,
         "endpoints": [service_endpoint("https://api.github.com")]},
        {"id": "alerts", "enabled": alerts.alert_settings(c.store)["enabled"], "endpoints": []},
        {"id": "operator_bot", "enabled": state.operator_bot.public()["settings"]["enabled"],
         "endpoints": [service_endpoint("https://api.telegram.org")]},
        {"id": "webhooks", "enabled": bool(hooks), "endpoints": [service_endpoint(item.get("url")) for item in hooks]},
        {"id": "analysis", "enabled": ai.enabled(state), "endpoints": [service_endpoint(analysis.get("endpoint"))]},
        {"id": "witness", "enabled": bool(witnesses), "endpoints": [],
         "last_poll": max((item["last_poll"]["at"] for item in witnesses if item["last_poll"]), default=None),
         "overdue": any(item["overdue"] for item in witnesses)},
        *({"id": kind, "enabled": item["enabled"], "configured": item["configured"],
           "endpoints": [service_endpoint(item["url"])]} for kind, item in captures.items()),
    ]
    for kind, urls in (("drand", DRAND_RELAYS), ("gateway", [GATEWAY_GRAPHQL]), ("devices", [])):
        last = independent.get(kind) or {}
        features.append({"id": kind, "enabled": evidence["enabled"] and evidence[kind],
                         "health": "failed" if last.get("ok") is False else None,
                         "last_success": last.get("at") if last.get("ok") else last.get("last_ok_at"),
                         "last_check": last.get("at"), "endpoints": [service_endpoint(url) for url in urls]})
    return {
        "id": identifier, "label": label,
        "state": "connected" if connected else "disconnected", "observing": c.running,
        "phase": c.phase, "run_id": c.run_id,
        "route": {"kind": route["kind"], "managed": route.get("managed"), "gateway": gateway,
                  "fallback": bool(route.get("fallback_to_direct")), "process_running": current["process_running"],
                  "pool": route.get("pool"), "proxy_checked_at": (route.get("current") or {}).get("checked_at")},
        "policy": {key: policy.get(key) for key in ("exposure", "outside_enabled", "outside_route")},
        "outside_gateway": None if not policy.get("outside_proxy") else
            endpoint((policy["outside_proxy"].get("host"), policy["outside_proxy"].get("port"))),
        "socket": socket_state(client) if connected else {"local": None, "peer": None},
        "telegram": {"dc": getattr(session, "dc_id", None), "endpoint": target, "endpoint_prefix": target_prefix},
        "telegram_binding": pool_binding(socket_state(client) if connected else None, target,
                                         {"kind": route["kind"], "gateway": gateway}),
        "activity": {"since": (rpc or {}).get("since"), **counters, "available": rpc is not None,
                     "last_update_at": c.last_update_at},
        "check": {key: (current.get("check") or {}).get(key)
                  for key in ("current", "checked_at", "telegram_connected", "latency_ms")},
        "storage": {"directory": str(c.store.root), "vault_directory": str(state.vault.root),
                    "key_mode": state.vault.key_mode, "owner_only": owner_only(state.vault.root), "secrets_encrypted": True,
                    "journal_encrypted_by_app": False, "media_encrypted_by_app": False},
        "features": features,
    }


def network_policy(accounts):
    connected = [a for a in accounts if a.get("state") == "connected"]
    bindings = [a.get("telegram_binding") or {} for a in connected]
    targets_in = sum(1 for b in bindings if b.get("target_in_pool"))
    direct = [b for b in bindings if not b.get("proxied")]
    direct_in = sum(1 for b in direct if b.get("peer_in_pool"))
    return {"state": "advisory", "pool": list(TELEGRAM_NETWORKS), "pool_source": "telegram-published-ranges",
            "connected": len(connected), "targets_in_pool": targets_in,
            "direct": len(direct), "direct_peers_in_pool": direct_in,
            "outside_pool": [a["id"] for a, b in zip(connected, bindings)
                             if not b.get("target_in_pool") and a.get("telegram", {}).get("endpoint")],
            "packet_counters": None}


def snapshot(ctx, request):
    state = ctx.app.state
    registry = getattr(state, "profiles", None)
    entries = registry.entries if registry else {
        ctx.profile_id: {"label": state.store.get_setting("profile_label", "Main account"), "app": ctx.app}}
    accounts = []
    for identifier, entry in list(entries.items()):
        try:
            accounts.append(account_snapshot(identifier, entry["label"], entry.get("app")))
        except (OSError, ValueError, RuntimeError):
            accounts.append({"id": identifier, "label": entry["label"], "state": "unavailable"})
    assurance = state.assurance or {}
    receipt = state.run_receipt
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    deployment = (receipt.get("host") or {}).get("deployment") or {}
    tunnel_configured = bool(deployment.get("tunnel_id") or deployment.get("beacon"))
    return {
        "schema": 1, "generated_at": utcnow(), "demo": state.store.get_setting("demo", False),
        "runtime": {"os": platform.system(), "container": container, "provider": assurance.get("mode"),
                    "place": (state.store.get_setting("setup", {}) or {}).get("place"),
                    "tdx_recorded": bool(receipt.get("tdx_start")), "inventory_complete": False},
        "ingress": {"scheme": request.url.scheme, "listener": endpoint(request.scope.get("server")),
                    "cloudflare": "configured" if tunnel_configured else "unobserved", "authentication": "panel_session"},
        "accounts": accounts,
        "network_policy": network_policy(accounts),
        "traffic": state.network_observer.snapshot(),
    }
