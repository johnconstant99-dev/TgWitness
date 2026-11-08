import contextvars
import sys
import threading
import time
import weakref
from collections import deque
from urllib.parse import urlsplit

from .store import utcnow


_scope = contextvars.ContextVar("network_observation", default=None)
_observers = weakref.WeakKeyDictionary()
_bindings = {}
_guard = threading.RLock()
_installed = False
PURPOSES = {
    "proxy_catalog": "Download or check MTProxy lists",
    "proxy_sources": "Read configured proxy sources",
    "guided_connection": "Check the selected connection",
    "portable_routes": "Prepare or check a local VPN helper",
    "anchoring": "Request an external timestamp or randomness beacon",
    "replica": "Maintain the encrypted off-site copy",
    "storage": "Transfer archive files or prepare the storage helper",
    "capture_connections": "Contact the configured independent recorder",
    "assurance": "Read host metadata or publish the panel address",
    "tdx": "Retrieve hardware-attestation collateral",
    "cloud_attestation": "Verify cloud attestation",
    "cloud": "Manage the selected cloud deployment",
    "cloud_wizard": "Manage the selected cloud deployment",
    "alerts": "Deliver a configured notification",
    "operator_bot": "Receive or send operator-bot messages",
    "webhooks": "Deliver a configured webhook",
    "ai": "Send a configured archive-analysis request",
    "source_check": "Compare running code with a GitHub revision",
    "witness": "Read or publish an independent checkpoint",
    "verify": "Retrieve external verification material",
    "mcp_server": "Read the configured archive service",
}


def destination(host, port):
    if not isinstance(host, str) or type(port) is not int:
        return None
    if not 0 < port < 65536 or len(host) > 253 or any(c in host for c in "\r\n/@?#"):
        return None
    return {"host": host, "port": port}


def origin(url):
    try:
        parts = urlsplit(url)
        return destination(parts.hostname, parts.port or {"http": 80, "https": 443}.get(parts.scheme))
    except (TypeError, ValueError):
        return None


class NetworkObserver:
    def __init__(self):
        self.rows = deque(maxlen=2000)
        self.serial = 0
        self.started_at = utcnow()
        self.lock = threading.RLock()

    def add(self, **fields):
        with self.lock:
            self.serial += 1
            row = {"id": self.serial, "at": utcnow(), **fields}
            self.rows.append(row)
            return self.serial

    def snapshot(self):
        with self.lock:
            return {"started_at": self.started_at, "total": self.serial, "retained": len(self.rows),
                    "capacity": self.rows.maxlen, "events": list(self.rows)[-200:],
                    "coverage": "python_process", "persisted": False}


def attach(access, collector, workspace):
    global _installed
    with _guard:
        observer = _observers.get(access)
        if observer is None:
            observer = _observers[access] = NetworkObserver()
        for obj in (collector, collector.store):
            identifier = id(obj)
            _bindings[identifier] = (weakref.ref(obj, lambda ref, key=identifier: unbind(key, ref)),
                                     weakref.ref(observer), workspace)
        if not _installed:
            sys.addaudithook(audit)
            _installed = True
        return observer


def unbind(identifier, reference):
    with _guard:
        if _bindings.get(identifier, (None,))[0] is reference:
            _bindings.pop(identifier, None)


def detach(collector):
    if collector is not None:
        with _guard:
            for obj in (collector, collector.store):
                _bindings.pop(id(obj), None)


def context():
    inherited = _scope.get()
    observer, workspace = (inherited[0], inherited[1]) if inherited else (None, None)
    component, purpose = "unattributed", "Unattributed application request"
    frame = sys._getframe(1)
    try:
        for _ in range(48):
            if frame is None:
                break
            module = frame.f_globals.get("__name__", "")
            if module.startswith(("tgwitness.", "telethon.")) and module != __name__:
                short = module.split(".")[-1]
                if short in PURPOSES and component in ("unattributed", "telegram", "netclient"):
                    component, purpose = short, PURPOSES[short]
                    operation = frame.f_code.co_name
                    if short == "proxy_catalog" and operation == "download":
                        purpose = "Download configured MTProxy list"
                    elif short == "proxy_catalog" and operation in ("probe", "check", "pinned"):
                        purpose = "Check Telegram connectivity through an MTProxy"
                    elif short == "proxy_sources" and operation == "lookup":
                        purpose = "Look up a proxy endpoint country"
                    elif short == "proxy_sources" and operation in ("github_search", "fetch"):
                        purpose = "Discover MTProxy lists through GitHub code search"
                    elif short == "anchoring" and operation == "record_drand":
                        purpose = "Read a public drand randomness round for the journal"
                    elif short == "anchoring" and operation == "gateway_rows":
                        purpose = "Read configured Cloudflare Gateway DNS records"
                elif module.startswith("telethon.") and component == "unattributed":
                    component, purpose = "telegram", "Telegram transport"
                for name in ("self", "c", "collector", "store"):
                    obj = frame.f_locals.get(name)
                    binding = _bindings.get(id(obj))
                    if observer is None and binding and binding[0]() is obj:
                        observer, workspace = binding[1](), binding[2]
            frame = frame.f_back
    finally:
        del frame
    if observer is None:
        with _guard:
            available = {binding[1]() for binding in list(_bindings.values()) if binding[0]() is not None}
            available.discard(None)
        if len(available) == 1:
            observer = next(iter(available))
    return observer, workspace, component, purpose


def audit(event, args):
    if not _bindings or event not in ("socket.connect", "socket.getaddrinfo", "socket.sendto", "http.client.send"):
        return
    try:
        method = None
        if event == "http.client.send":
            client, data = args
            if not isinstance(data, (bytes, bytearray, memoryview)):
                return
            line = bytes(data[:8192]).split(b"\r\n", 1)[0]
            if not line.endswith((b" HTTP/1.1", b" HTTP/1.0")):
                return
            first = line.split(b" ", 1)[0]
            if first not in (b"GET", b"HEAD", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS", b"CONNECT"):
                return
            target = destination(client.host, client.port)
            kind, method = "http_send", first.decode("ascii")
        elif event == "socket.getaddrinfo":
            target = destination(args[0], args[1])
            kind = "dns_lookup"
        else:
            address = args[1] if event == "socket.connect" else args[-1]
            target = destination(*address[:2]) if isinstance(address, tuple) and len(address) >= 2 else None
            kind = "connect_attempt" if event == "socket.connect" else "udp_send_attempt"
        if target is None:
            return
        observer, workspace, component, purpose = context()
        if observer:
            scope = _scope.get()
            observer.add(kind=kind, workspace=workspace, component=component, purpose=purpose,
                         destination=target, method=method, outcome="attempt", parent=scope[2] if scope else None)
    except Exception:
        return


async def observe_request(work, method, url, network, *args, **kwargs):
    if not _bindings:
        return await work(method, url, network, *args, **kwargs)
    try:
        observer, workspace, component, purpose = context()
    except Exception:
        observer = None
    if observer is None:
        return await work(method, url, network, *args, **kwargs)
    target = origin(url)
    if target and target["host"] == "1.1.1.1" and urlsplit(url).path == "/dns-query":
        component, purpose = "dns", "Resolve a destination through DNS over HTTPS"
    route = getattr(network, "kind", "unknown")
    gateway = destination(getattr(network, "host", None), getattr(network, "port", None))
    identifier = record(observer, kind="http_request", workspace=workspace, component=component,
                              purpose=purpose, destination=target, method=method,
                              route=route, gateway=gateway, outcome="started",
                              parent=_scope.get()[2] if _scope.get() else None)
    token = _scope.set((observer, workspace, identifier))
    started = time.monotonic()
    try:
        result = await work(method, url, network, *args, **kwargs)
        record(observer, kind="http_result", workspace=workspace, component=component, purpose=purpose,
                     destination=target, method=method, route=route, gateway=gateway, parent=identifier,
                     outcome="response", status=result[0], duration_ms=round((time.monotonic() - started) * 1000))
        return result
    except BaseException as exc:
        record(observer, kind="http_result", workspace=workspace, component=component, purpose=purpose,
                     destination=target, method=method, route=route, gateway=gateway, parent=identifier,
                     outcome="failed", error=type(exc).__name__, status=getattr(exc, "status", None),
                     duration_ms=round((time.monotonic() - started) * 1000))
        raise
    finally:
        _scope.reset(token)


def record(observer, **fields):
    try:
        return observer.add(**fields)
    except Exception:
        return None
