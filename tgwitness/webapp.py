import re
from urllib.parse import urljoin, urlsplit

from telethon.tl import functions

from . import interactions, netclient
from .keyboard import of_payload
from .store import utcnow

MAX_BYTES = 4 * 1024**2
MAX_ENDPOINTS = 500
PLATFORM = "web"
LAUNCH_MEANING = ("Telegram returned the address this mini application is opened at. Asking for it is an account "
                  "action recorded in the journal; the address alone does not show what the application does.")
INSPECT_MEANING = ("One response fetched at this time, parsed for the addresses it references. A mini application can "
                   "load different addresses later, for another visitor or after its operator changes it. Referenced "
                   "addresses are not confirmed to exist or to have been contacted.")
ROUTE_MEANING = ("Fetched through this workspace's route for requests outside Telegram. A direct route would show the "
                 "operator's address to the application's host.")
ATTRIBUTES = re.compile(r"""(?i)\b(?:src|href|action|data-src|data-url|poster|formaction)\s*=\s*["']([^"'\s>]{1,2048})""")
CSS_URL = re.compile(r"""(?i)url\(\s*["']?([^"')\s]{1,2048})""")
IMPORTS = re.compile(r"""(?i)\bimport\s*\(?\s*["']([^"'\s]{1,2048})["']""")
CALLS = re.compile(r"""(?i)\b(?:fetch|open|axios(?:\.\w+)?|navigator\.sendBeacon|EventSource|WebSocket)\s*\(\s*["']([^"'\s]{1,2048})["']""")
LITERALS = re.compile(r"""["'`](https?://[^"'`\s]{3,2048}|/[A-Za-z0-9_\-./]{1,512})["'`]""")
SOCKET = re.compile(r"(?i)\bwss?://[^\s\"'`<>]{3,2048}")


def buttons(payload):
    markup = of_payload(payload)
    found = []
    for row in (markup or {}).get("rows") or []:
        for button in row:
            if button.get("type") == "web_app":
                found.append({"text": button.get("text") or "", "url": button.get("url")})
    return found


def in_messages(store, chat_id, limit=200):
    found = {}
    for event in store.events(chat_id=chat_id, limit=limit):
        for button in buttons(event.get("payload")):
            if button["url"] and button["url"] not in found:
                found[button["url"]] = {**button, "seq": event["seq"], "message_id": event.get("message_id")}
    return list(found.values())


async def launch_url(collector, peer, bot, url=None, start_param=None):
    interactions.permitted(collector)
    request = functions.messages.RequestWebViewRequest(peer=peer, bot=bot, platform=PLATFORM, url=url,
                                                       start_param=start_param)
    answer = await collector.client(request)
    address = getattr(answer, "url", None)
    collector.store.append("webapp.launch_requested", {
        "requested_url": url, "start_param": start_param, "address": address,
        "expires_at": getattr(answer, "expires", None), "meaning": LAUNCH_MEANING})
    return address


def same_origin(base, value):
    origin, target = urlsplit(base), urlsplit(value)
    return (target.scheme, target.netloc) == (origin.scheme, origin.netloc)


def endpoints(body, base):
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    found, order = {}, 0
    for source, pattern in (("attribute", ATTRIBUTES), ("style", CSS_URL), ("import", IMPORTS),
                            ("call", CALLS), ("literal", LITERALS), ("socket", SOCKET)):
        for match in pattern.finditer(text):
            value = (match.group(1) if pattern is not SOCKET else match.group(0)).strip()
            if not value or value.startswith(("data:", "blob:", "javascript:", "#", "mailto:", "tel:")):
                continue
            try:
                absolute = urljoin(base, value)
            except ValueError:
                continue
            parts = urlsplit(absolute)
            if parts.scheme not in ("http", "https", "ws", "wss") or not parts.netloc:
                continue
            key = parts._replace(fragment="").geturl()
            if key in found:
                if source not in found[key]["seen_as"]:
                    found[key]["seen_as"].append(source)
                continue
            if len(found) >= MAX_ENDPOINTS:
                break
            order += 1
            found[key] = {"url": key, "host": (parts.hostname or "").lower(), "path": parts.path or "/",
                          "query": bool(parts.query), "scheme": parts.scheme, "written_as": value,
                          "same_origin": same_origin(base, absolute), "seen_as": [source], "order": order}
    items = sorted(found.values(), key=lambda item: item["order"])
    for item in items:
        item.pop("order")
    hosts = sorted({item["host"] for item in items if item["host"]})
    origin = urlsplit(base)
    return {"format": "tgwitness-webapp-endpoints-v1", "base": base, "origin": origin.netloc,
            "endpoints": items, "hosts": hosts,
            "third_party_hosts": [host for host in hosts if host != (origin.hostname or "").lower()],
            "sockets": sorted({item["url"] for item in items if item["scheme"] in ("ws", "wss")}),
            "truncated": len(found) >= MAX_ENDPOINTS, "meaning": INSPECT_MEANING}


async def inspect(collector, url, timeout=20):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Provide the http or https address of the mini application.")
    route = collector.outside_route()
    if route.kind == "none":
        raise route.error
    status, headers, body = await netclient.request("GET", url, route, timeout=timeout, limit=MAX_BYTES)
    found = endpoints(body, url)
    content = next((value for name, value in (headers or {}).items() if name.lower() == "content-type"), None)
    record = {**found, "status": status, "content_type": content, "bytes": len(body or b""),
              "fetched_at": utcnow(), "route": route.kind, "route_meaning": ROUTE_MEANING}
    collector.store.append("webapp.inspected", {
        "address": url, "status": status, "content_type": content, "bytes": record["bytes"],
        "endpoints": len(found["endpoints"]), "addresses": found["endpoints"], "hosts": found["hosts"],
        "route": route.kind, "meaning": INSPECT_MEANING + " " + ROUTE_MEANING})
    return record


def register(app, authenticate, require_live, visible_chats):
    from fastapi import Depends, HTTPException, Request
    from pydantic import BaseModel, Field

    class Address(BaseModel):
        url: str = Field(..., max_length=2048)

    @app.get("/api/webapp", dependencies=[Depends(authenticate)])
    async def listing(request: Request, chat_id: int, limit: int = 200):
        chats = visible_chats(request)
        if chats is not None and chat_id not in chats:
            raise HTTPException(403, "This chat is not open to this access.")
        if not 1 <= limit <= 1000:
            raise HTTPException(422, "Read between 1 and 1000 records at a time.")
        return {"chat_id": chat_id, "buttons": in_messages(app.state.store, chat_id, limit)}

    @app.post("/api/webapp/inspect", dependencies=[Depends(authenticate)])
    async def inspect_address(body: Address, request: Request):
        if not request.state.principal.admin:
            raise HTTPException(403, "Only the main administrator can fetch a mini application.")
        require_live()
        try:
            return await inspect(app.state.collector, body.url)
        except netclient.RouteError as exc:
            raise HTTPException(409, str(exc)) from None
        except (netclient.HTTPError, OSError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from None


def note_indicators(found, addresses, source, ref, at):
    for item in addresses:
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        if item.get("scheme") in ("http", "https"):
            found.link(item["url"], source, ref, at)
        elif isinstance(item.get("host"), str) and item["host"]:
            found.domain(item["host"], source, ref, at)
    return found
