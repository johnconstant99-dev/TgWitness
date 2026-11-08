import ipaddress
import json
import os
import platform
from pathlib import Path
from urllib.parse import urlsplit

from . import ai, alerts, proxy_sources
from .account_import import DC_ADDRESSES
from .anchoring import evidence_settings
from .proxy_catalog import SOURCES as PROXY_LISTS
from .replica import replica_settings
from .storage import settings as storage_settings
from .store import utcnow
from .witness_api import state as witness_state


TELEGRAM_NETWORKS = ("91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
                     "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
                     "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48", "2a0a:f280::/32")
NETWORKS = tuple(ipaddress.ip_network(value) for value in TELEGRAM_NETWORKS)
CITIES = {1: "Miami", 2: "Amsterdam", 3: "Miami", 4: "Amsterdam", 5: "Singapore"}
EVENT_FIELDS = ("id", "at", "kind", "workspace", "component", "purpose", "destination", "method", "outcome",
                "route", "gateway", "status", "duration_ms", "error", "parent")


def endpoint(value):
    if not isinstance(value, (tuple, list)) or len(value) < 2:
        return None
    host, port = value[:2]
    if not isinstance(host, str) or not host or type(port) is not int or not 0 < port < 65536:
        return None
    return {"host": host, "port": port}


def url_endpoint(url):
    try:
        parts = urlsplit(url or "")
        return endpoint((parts.hostname, parts.port or {"https": 443, "http": 80}.get(parts.scheme)))
    except (TypeError, ValueError):
        return None


def address(host):
    try:
        value = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return None
    return value.ipv4_mapped or value if value.version == 6 else value


def telegram_network(host):
    value = address(host)
    if value is None:
        return None
    return next((str(net) for net in NETWORKS if net.version == value.version and value in net), None)


def is_loopback(host):
    value = address(host)
    return host == "localhost" if value is None else value.is_loopback


def networks(text):
    found = []
    for item in (text or "").split(","):
        try:
            if item.strip():
                found.append(ipaddress.ip_network(item.strip(), strict=False))
        except ValueError:
            continue
    return found


def socket_pair(connection):
    writer = getattr(connection, "_writer", None)
    try:
        if writer is None or writer.is_closing():
            return None
        local, peer = endpoint(writer.get_extra_info("sockname")), endpoint(writer.get_extra_info("peername"))
    except (AttributeError, OSError, ValueError):
        return None
    if peer:
        peer["telegram_network"] = telegram_network(peer["host"])
    return {"local": local, "peer": peer}


def borrowed(client):
    rows = []
    for dc, pair in list((getattr(client, "_borrowed_senders", None) or {}).items()):
        sender = pair[1] if isinstance(pair, tuple) and len(pair) > 1 else None
        if sender is None or type(dc) is not int:
            continue
        pair_socket = socket_pair(getattr(sender, "_connection", None))
        rows.append({"dc": dc, "connected": pair_socket is not None, "socket": pair_socket})
    return rows


def activity(client, collector):
    rpc = client.rpc_activity() if client is not None and hasattr(client, "rpc_activity") else None
    methods = (rpc or {}).get("methods", {})
    totals = {key: sum(row.get(key, 0) for row in methods.values())
              for key in ("calls", "ok", "errors", "flood_waits")}
    top = sorted(methods.items(), key=lambda item: item[1].get("calls", 0), reverse=True)[:6]
    return {"available": rpc is not None, "since": (rpc or {}).get("since"), **totals,
            "methods": [{"method": name, "calls": row.get("calls", 0), "errors": row.get("errors", 0)} for name, row in top],
            "last_update_at": getattr(collector, "last_update_at", None),
            "last_heartbeat": getattr(collector, "last_heartbeat", None)}


def helper(state):
    portable = getattr(getattr(state, "connection", None), "portable", None)
    selected = portable.selected() if portable else None
    if not selected:
        return None
    process = portable.processes.get(selected.get("id"))
    return {"mode": selected.get("mode"), "port": (selected.get("network") or {}).get("port"),
            "running": process is not None and process.returncode is None, "paused": bool(selected.get("paused"))}


def route_state(collector, state):
    route = collector.route_status()
    current = route.get("current") if route["kind"] == "mtproxy_auto" else None
    gateway = None
    if current:
        gateway = endpoint((current.get("host"), current.get("port")))
    elif route["kind"] in ("mtproxy", "socks5", "http"):
        gateway = endpoint((route.get("host"), route.get("port")))
    fallback = bool(route.get("fallback_to_direct"))
    return {"kind": route["kind"], "managed": route.get("managed"), "gateway": None if fallback else gateway,
            "source": (current or {}).get("source"), "latency_ms": (current or {}).get("latency_ms"),
            "checked_at": (current or {}).get("checked_at"), "fallback": fallback, "exposure": route.get("exposure"),
            "tls": bool(route.get("tls")), "helper": helper(state), "check": route.get("check"),
            "pool": route.get("pool")}


def services(state, collector, route):
    store, vault = collector.store, state.vault
    evidence, replica, storage = evidence_settings(store), replica_settings(store), storage_settings(store)
    alert, hooks = alerts.alert_settings(store), vault.read("webhooks").get("entries", [])
    analysis = ai.settings(state)
    found = {
        "timestamps": {"enabled": evidence["enabled"], "endpoints": [url_endpoint(u) for u in evidence["tsa_urls"]],
                       "interval_minutes": evidence["interval_minutes"]},
        "calendars": {"enabled": evidence["enabled"], "endpoints": [url_endpoint(u) for u in evidence["ots_calendars"]]},
        "drand": {"enabled": evidence["enabled"] and evidence["drand"]},
        "gateway_log": {"enabled": evidence["enabled"] and evidence["gateway"]},
        "devices": {"enabled": evidence["enabled"] and evidence["devices"]},
        "replica": {"enabled": replica["enabled"], "endpoints": [url_endpoint(replica["endpoint"])],
                    "recipient_encryption": bool(replica["recipient_public_key"])},
        "storage": {"enabled": storage["enabled"], "backend": storage["backend"],
                    "endpoints": [url_endpoint(replica["endpoint"])] if storage["backend"] == "s3" else []},
        "alerts": {"enabled": alert["enabled"], "kinds": sorted({str(u).split("://", 1)[0].lower()
                                                               for u in vault.read("alerts").get("urls", [])})},
        "webhooks": {"enabled": bool(hooks), "endpoints": [url_endpoint(item.get("url")) for item in hooks]},
        "analysis": {"enabled": ai.enabled(state), "endpoints": [url_endpoint(analysis.get("endpoint"))]},
        "proxy_lists": {"enabled": route["kind"] == "mtproxy_auto"},
        "proxy_checks": {"enabled": route["kind"] == "mtproxy_auto"},
    }
    bot = getattr(state, "operator_bot", None)
    found["operator_bot"] = {"enabled": bool(bot and bot.public()["settings"].get("enabled"))}
    source = store.get_setting("source_check", None)
    found["source_check"] = {"enabled": bool(source), "checked_at": (source or {}).get("checked_at"),
                             "matches": (source or {}).get("matches")}
    tokens = witness_state(vault, store)["tokens"]
    polls = sorted(item["last_poll"]["at"] for item in tokens if item.get("last_poll") and item["last_poll"].get("at"))
    found["witness"] = {"enabled": bool(tokens), "tokens": len(tokens), "last_poll": polls[-1] if polls else None,
                        "overdue": any(item.get("overdue") for item in tokens)}
    capture = getattr(state, "capture", None)
    if capture:
        for kind, item in capture.public()["connections"].items():
            found["recorder_" + kind] = {"enabled": bool(item.get("enabled")), "configured": bool(item.get("configured")),
                                         "endpoints": [url_endpoint(item.get("url"))]}
    for item in found.values():
        if "endpoints" in item:
            item["endpoints"] = [value for value in item["endpoints"] if value]
    context = getattr(state, "api_context", None)
    try:
        outside = context.outside_state()
        found["timestamps"]["health"] = context.timestamps_health(outside).get("state")
        found["replica"]["health"] = context.replica_health(outside).get("state")
    except Exception:
        pass
    return found


def account(identifier, entry, registry, groups):
    group = registry.group_of(identifier) if registry else None
    base = {"id": identifier, "label": entry.get("label") or identifier,
            "group": {"id": group, "label": groups.get(group, "")} if group else None}
    app = entry.get("app")
    if app is None:
        return {**base, "state": "unavailable", "problem": entry.get("error_type")}
    state = app.state
    collector = state.collector
    client = collector.client
    connected = bool(client and client.is_connected())
    route = route_state(collector, state)
    policy = collector.policy_state()
    session = getattr(client, "session", None)
    target = endpoint((getattr(session, "server_address", None), getattr(session, "port", None)))
    if target:
        target["telegram_network"] = telegram_network(target["host"])
    sender = getattr(client, "_sender", None)
    outside = policy.get("outside_proxy")
    return {
        **base,
        "state": "connected" if connected else "disconnected", "observing": bool(collector.running),
        "phase": collector.phase, "run_id": getattr(collector, "run_id", None),
        "authorized": bool(state.vault.read("credentials").get("session")),
        "route": route,
        "outside": {"enabled": bool(policy.get("outside_enabled")), "route": policy.get("outside_route"),
                    "gateway": endpoint(((outside or {}).get("host"), (outside or {}).get("port"))),
                    "problem": policy.get("outside_problem")},
        "telegram": {"dc": getattr(session, "dc_id", None), "endpoint": target},
        "socket": socket_pair(getattr(sender, "_connection", None)) if connected else None,
        "media": borrowed(client) if client is not None else [],
        "activity": activity(client, collector),
        "storage": {"directory": str(collector.store.root), "vault": str(state.vault.root),
                    "key_mode": state.vault.key_mode},
        "services": services(state, collector, route),
    }


def ingress(ctx, state, request):
    headers = request.headers
    peer = request.client.host if request.client else None
    trusted = networks(os.environ.get("TGWITNESS_TRUSTED_PROXIES", ""))
    peer_address = address(peer)
    peer_trusted = bool(peer_address and any(peer_address in net for net in trusted if net.version == peer_address.version))
    cloudflare = "cf-connecting-ip" in headers or "cf-ray" in headers
    forwarded = "x-forwarded-for" in headers
    via = "cloudflare" if cloudflare else "reverse_proxy" if forwarded else "loopback" if is_loopback(peer) else "network"
    published = None
    try:
        saved = json.loads((Path(ctx.root) / "panel-address.json").read_text(encoding="utf-8"))
        url = saved.get("url") if isinstance(saved, dict) else None
        host = urlsplit(url).hostname if isinstance(url, str) else None
        if host:
            published = {"kind": "quick" if host.endswith(".trycloudflare.com") else
                         "local" if is_loopback(host) else "domain", "host": host,
                         "tunnel_enabled": saved.get("tunnel_enabled")}
    except (OSError, ValueError, TypeError):
        pass
    receipt = getattr(state, "run_receipt", None) or {}
    deployment = (receipt.get("host") or {}).get("deployment") or None
    if deployment:
        ssh = deployment.get("ssh")
        deployment = {"provider": deployment.get("provider"), "mode": deployment.get("mode"),
                      "tunnel": "quick" if deployment.get("beacon") else "named" if deployment.get("tunnel_id") else None,
                      "panel_host": deployment.get("panel_host"), "witness_host": deployment.get("witness_host"),
                      "ssh": "disabled" if ssh == "disabled" else "debug" if isinstance(ssh, dict) else None}
    sessions, grants = [], 0
    access = getattr(state, "access", None)
    if access:
        current = getattr(request.state.principal, "session_id", None)
        summary = access.state(current)
        grants = len(summary["grants"])
        sessions = [{"admin": item["admin"], "label": item["label"], "address": item["address"],
                     "current": item["current"], "last_seen_at": item["last_seen_at"], "requests": item["requests"]}
                    for item in summary["sessions"]]
    return {"listener": endpoint(request.scope.get("server")), "peer": peer, "peer_trusted": peer_trusted,
            "via": via, "scheme": request.url.scheme, "forwarded_proto": headers.get("x-forwarded-proto"),
            "trusted_proxies": len(trusted), "proxy_header": os.environ.get("TGWITNESS_PROXY_HEADER") or None,
            "allowed_networks": len(networks(os.environ.get("TGWITNESS_PANEL_ALLOWED_IPS", ""))),
            "token_source": "environment" if os.environ.get("TGWITNESS_TOKEN") else "file",
            "published": published, "deployment": deployment, "sessions": sessions, "grants": grants}


def host(state):
    assurance = getattr(state, "assurance", None) or {}
    receipt = getattr(state, "run_receipt", None) or {}
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    provider = assurance.get("mode")
    tdx = bool(receipt.get("tdx_start")) or provider == "phala"
    place = (state.store.get_setting("setup", None) or {}).get("place") or ("server" if provider else "computer")
    kind = "tdx" if tdx else "server" if provider else "docker" if container else place
    return {"kind": kind, "place": place, "container": container, "provider": provider, "tdx": tdx,
            "hostname": platform.node(), "os": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(),
            "version": receipt.get("version"), "run_id": receipt.get("run_id"), "started_at": receipt.get("started_at")}


def pool(ctx, state):
    catalog = getattr(ctx, "public_proxies", None)
    settings = catalog.settings() if catalog else proxy_sources.load(ctx.root)
    token = False
    try:
        token = bool(catalog and catalog.github_token())
    except Exception:
        pass
    disabled = set(settings.disabled)
    lists = [{"id": item["id"], "label": item["label"], "host": urlsplit(item["url"]).hostname,
              "enabled": item["id"] not in disabled} for item in PROXY_LISTS]
    lists += [{"id": item.id, "label": item.label, "host": urlsplit(item.url).hostname if item.url else None,
               "enabled": item.enabled and item.id not in disabled} for item in settings.custom]
    described = None
    try:
        collector = state.collector
        described = collector.pool().describe(collector.route_owner)["pool"]
    except Exception:
        pass
    return {"operator_catalog": bool(os.environ.get("TGWITNESS_PROXY_CATALOG")),
            "feed_proxy": bool(os.environ.get("TGWITNESS_PROXY_FEED_PROXY")),
            "github_search": settings.github.enabled and token, "countries": settings.countries,
            "github_status": dict(getattr(catalog, "github_status", None) or {}),
            "lists": lists, "state": described}


def traffic(state, after):
    observer = getattr(state, "network_observer", None)
    if observer is None:
        return {"available": False}
    try:
        snap = observer.snapshot()
    except Exception:
        return {"available": False}
    events = []
    for row in snap.get("events", []):
        if not isinstance(row, dict) or not isinstance(row.get("id"), int) or row["id"] <= after:
            continue
        item = {key: row.get(key) for key in EVENT_FIELDS if key in row}
        target = item.get("destination")
        if isinstance(target, dict) and isinstance(target.get("host"), str):
            item["destination"] = {**target, "telegram_network": telegram_network(target["host"]),
                                   "loopback": is_loopback(target["host"])}
        events.append(item)
    return {"available": True, "started_at": snap.get("started_at"), "total": snap.get("total"),
            "retained": snap.get("retained"), "capacity": snap.get("capacity"),
            "coverage": snap.get("coverage"), "events": events[-200:]}


def snapshot(ctx, request, after=0):
    state = ctx.app.state
    registry = getattr(state, "profiles", None)
    entries = registry.entries if registry else {
        ctx.profile_id: {"label": state.store.get_setting("profile_label", "Main account"), "app": ctx.app}}
    groups = {item["id"]: item["label"] for item in (registry.groups() if registry else [])}
    accounts = []
    for identifier, entry in list(entries.items()):
        try:
            accounts.append(account(identifier, entry, registry, groups))
        except Exception as exc:
            accounts.append({"id": identifier, "label": entry.get("label") or identifier, "state": "unavailable",
                             "problem": type(exc).__name__})
    return {
        "schema": "tgwitness-topology-v1", "generated_at": utcnow(), "demo": bool(state.store.get_setting("demo", False)),
        "host": host(state), "ingress": ingress(ctx, state, request), "accounts": accounts, "pool": pool(ctx, state),
        "policy": {"private_destinations": os.environ.get("TGWITNESS_ALLOW_PRIVATE_DESTINATIONS", "").strip() == "1"},
        "telegram": {"datacenters": [{"id": dc, "address": ip, "port": 443, "city": CITIES.get(dc),
                                      "network": telegram_network(ip)} for dc, ip in sorted(DC_ADDRESSES.items())],
                     "networks": list(TELEGRAM_NETWORKS)},
        "traffic": traffic(state, after),
    }
