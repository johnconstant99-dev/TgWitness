"""Notifications through Apprise: problems, changes in observed chats and a daily summary.

By default only chat names, counts and problem descriptions leave the machine. Message text
is added only when the operator turns on text excerpts. The panel's notification list uses
the same wording.
"""
import asyncio
import hashlib
import re
import socket
import threading
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, Field

from . import i18n
from . import netclient
from . import tuning
from .store import canonical, utcnow


BATCH = 2000
MAX_LINES = 25
EXCERPT_CHARS = 120
CHANGES = {"message.deleted": "deleted", "message.edited": "edited", "message.missing_on_recheck": "missing"}
PROBLEM_KINDS = ("storage.low", "storage.ok", "coverage.gap", "collector.error", "connection.retry_failed",
                 "source.access_unconfirmed", "export.failed", "chat_export.interrupted", "replica.completed",
                 "anchor.completed", "profile.unavailable", "host.state")

CHANGE_SCAN = 5000
PROBLEM_PAGES = 20
SUMMARY_KINDS = ("message.new", "message.recovered", "message.edited", "message.deleted", "message.missing_on_recheck")

DIRECT_SOCKET = {"amqp", "amqps", "aprs", "deltachat", "deltachats", "growl", "irc", "ircs", "mailto", "mailtos",
                 "mqtt", "mqtts", "rsyslog", "smpp", "smpps", "xmpp", "xmpps"}

OWN_SOCKET = DIRECT_SOCKET - {"mailto", "mailtos"}


def own_socket(url):
    return url.split("://", 1)[0].lower() in OWN_SOCKET
_send_lock = threading.Lock()


class AlertSettings(BaseModel):
    enabled: bool = False
    problems: bool = True
    changes: bool = False
    daily: bool = True
    daily_hour: int = Field(default=9, ge=0, le=23)
    language: Literal[i18n.LANGUAGES] = "en"
    include_text: bool = False


def alert_settings(store):
    return AlertSettings(**store.get_setting("alerts", {})).model_dump()


def tr(words, text, **values):
    out = words.get(text)
    out = out if isinstance(out, str) else text
    return re.sub(r"\{(\w+)\}", lambda m: str(values[m.group(1)]) if m.group(1) in values else m.group(0), out)


def describe(url):
    """Apprise's own masked form of a destination, or None when Apprise cannot use it."""
    import apprise
    plugin = apprise.Apprise.instantiate(url)
    return plugin.url(privacy=True) if plugin else None


def route_problem(urls, network):
    if network.kind == "none":
        return str(network.error)
    if network.telegram_only:
        return "Notifications are not sent over MTProxy. Choose Direct, SOCKS5 or HTTP in Account → Connection settings."
    if network.kind != "direct" and any(url.split("://", 1)[0].lower() in DIRECT_SOCKET for url in urls):
        return ("A destination connects without HTTP (email, IRC, MQTT, XMPP and similar) and cannot use this "
                "workspace's proxy. Choose an HTTP-based service or a direct connection.")
    return None


def proxy_url(network, address=None):
    """address: the proxy's resolved and checked address, connected instead of its name."""
    if network.kind == "direct":
        return None
    login = (quote(network.username, safe="") + ":" + quote(network.password, safe="") + "@") if network.username else ""
    host = address or network.host
    host = "[" + host + "]" if ":" in host else host

    return ("socks5h" if network.kind == "socks5" else "http") + "://" + login + host + ":" + str(network.port)


_guard = {"on": False, "allowed": set(), "refused": None}


class Refused(OSError):
    """An internal destination; an OSError, so the services report it as a failed connection."""


def _checked(host, port):
    """The addresses to connect to, checked once and then used (no second lookup); None: unchecked."""
    if not _guard["on"] or host in _guard["allowed"]:
        return None
    addresses = list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    try:
        netclient.refuse_internal(host, addresses)
    except netclient.RouteError as error:
        _guard["refused"] = str(error)
        raise Refused(str(error)) from None
    return addresses


def _install_guard():
    import smtplib
    import urllib3.util.connection as connection
    if getattr(connection.create_connection, "guarded", False):
        return
    plain = connection.create_connection

    def create_connection(address, *args, **kwargs):
        addresses = _checked(address[0], address[1])
        if addresses is None:
            return plain(address, *args, **kwargs)
        failure = OSError("No address for " + str(address[0]))
        for checked in addresses:
            try:
                return plain((checked, address[1]), *args, **kwargs)
            except OSError as exc:
                failure = exc
        raise failure
    create_connection.guarded = True
    connection.create_connection = create_connection

    def smtp(original):
        def get_socket(self, host, port, timeout):
            addresses = _checked(host, port)
            return original(self, addresses[0] if addresses else host, port, timeout)
        return get_socket
    smtplib.SMTP._get_socket = smtp(smtplib.SMTP._get_socket)
    smtplib.SMTP_SSL._get_socket = smtp(smtplib.SMTP_SSL._get_socket)


@contextmanager
def _routed(proxy):
    """Apprise sends through requests; for this send its proxy settings are the workspace route only."""
    import requests
    original = requests.Session.merge_environment_settings

    def merge(self, url, proxies, stream, verify, cert):
        host = urlsplit(url).hostname or ""
        if proxy and _guard["on"] and netclient.literal(host):
            try:
                netclient.refuse_internal(host, [netclient.literal(host)])
            except netclient.RouteError as error:
                _guard["refused"] = str(error)
                raise requests.exceptions.ConnectionError(str(error)) from None
        settings = original(self, url, {}, stream, verify, cert)
        settings["proxies"] = {"http": proxy, "https": proxy} if proxy else {}
        return settings
    requests.Session.merge_environment_settings = merge
    try:
        yield
    finally:
        requests.Session.merge_environment_settings = original


def deliver(urls, title, body, network):
    """Send one notification to every destination. Returns how many accepted it and the first error."""
    import apprise
    problem = route_problem(urls, network)
    if problem:
        return {"sent": 0, "failed": len(urls), "error": problem}
    address = None
    if network.kind != "direct":

        try:
            address = netclient.checked_proxy(network, list(dict.fromkeys(
                info[4][0] for info in socket.getaddrinfo(network.host, network.port, type=socket.SOCK_STREAM))))
        except (netclient.RouteError, OSError) as exc:
            return {"sent": 0, "failed": len(urls), "error": str(exc)[:300]}
    _install_guard()
    with _send_lock, _routed(proxy_url(network, address)):
        _guard.update(on=not netclient.private_allowed(), refused=None,
                      allowed={address} if address else set())
        try:
            bundle = apprise.Apprise()
            for url in urls:
                bundle.add(url)
            result = bundle.notify(body=body, title=title)
        finally:
            _guard["on"] = False
        refused = _guard["refused"]
    if isinstance(result, bool):
        return {"sent": len(urls) if result else 0, "failed": 0 if result else len(urls),
                "error": None if result else refused or "The service did not accept the notification."}
    errors = [entry.message for entry in result.logs() if str(entry.level).upper() in ("ERROR", "WARNING")]
    error = None
    if result.failed_count or not result.success_count:
        error = (refused or (errors[0] if errors else "The service did not accept the notification."))[:300]
    return {"sent": result.success_count, "failed": result.failed_count, "error": error}


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return (str(int(n)) if unit == "B" else "%.1f" % n) + " " + unit
        n /= 1024


def problem_line(event, titles, words):
    p, kind = event["payload"], event["kind"]
    where = titles.get(event["chat_id"], str(event["chat_id"])) if event["chat_id"] is not None else ""
    if kind == "storage.low":
        return tr(words, "Disk almost full: {size} free. Photo and file downloads are paused.",
                  size=human_size(p.get("free_bytes") or 0))
    if kind == "storage.ok":
        return tr(words, "Disk space available again; photo and file downloads resumed.")
    if kind == "coverage.gap" and p.get("reason") == "authorization_required":
        return tr(words, "Telegram signed this account out. Sign in again to resume observation.")
    if kind == "coverage.gap":
        return tr(words, "Coverage gap{where}: {reason}", where=" (" + where + ")" if where else "",
                  reason=p.get("reason") or "")
    if kind == "collector.error":
        return tr(words, "Collection error during {operation}: {error}", operation=p.get("operation") or "?",
                  error=p.get("error_type") or "?")
    if kind == "connection.retry_failed" and (p.get("attempt") == 3 or (p.get("attempt") or 0) % 20 == 0):
        return tr(words, "Cannot reach Telegram: {n} reconnect attempts failed ({error}).", n=p.get("attempt"),
                  error=p.get("error_type") or "?")
    if kind == "source.access_unconfirmed":
        return tr(words, "Source not found among the account's chats: {chat}", chat=where)
    if kind == "export.failed":
        return tr(words, "Export failed: {format}", format=(p.get("format") or "?").upper())
    if kind == "chat_export.interrupted" and p.get("error_type"):
        return tr(words, "Chat export stopped ({chat}): {error}", chat=where, error=p["error_type"])
    if kind == "replica.completed" and p.get("error"):
        return tr(words, "Off-site copy stopped: {error}", error=p["error"])
    # A checkpoint another service stamped on an earlier pass is partly covered, as when some answer at once.
    if kind == "anchor.completed" and not any(r.get("ok") for r in p.get("results", [])) and not p.get("covered"):
        return tr(words, "No timestamp service answered for the latest checkpoint.")
    if kind == "profile.unavailable":
        return tr(words, "Workspace {name} could not start: {error}", name=p.get("profile_id") or "?",
                  error=p.get("error_type") or "?")
    if kind == "host.state":
        return host_line(p, words)
    return None


def host_line(state, words):
    """A server deployed with python -m tgwitness.cloud measured SSH or a login; closing them is no problem."""
    before, found, login = state.get("before") or {}, [], False
    if state.get("ssh_listening") and not before.get("ssh_listening"):
        found.append(tr(words, "port 22 accepts connections"))
    if (state.get("ssh_processes") or 0) > (before.get("ssh_processes") or 0):
        found.append(tr(words, "SSH server processes started"))
    if (state.get("sessions") or 0) > (before.get("sessions") or 0):
        found.append(tr(words, "logged-in sessions: {n}", n=state["sessions"]))
        login = True
    if (state.get("logins") or 0) > (before.get("logins") or 0):
        found.append(tr(words, "new logins recorded: {n}", n=state["logins"] - (before.get("logins") or 0)))
        login = True
    if not found:
        return None
    if login:
        return tr(words, "Server access detected: {details}", details="; ".join(found))
    # An open port or a started SSH process alone is not a recorded login.
    return tr(words, "SSH change on the server, no new login recorded: {details}", details="; ".join(found))


def change_line(title, counts, words):
    return tr(words, "{chat}: {deleted} deleted, {edited} edited, {missing} not found", chat=title,
              deleted=counts.get("deleted", 0), edited=counts.get("edited", 0), missing=counts.get("missing", 0))


def discovered_line(title, words):
    return tr(words, "New chat under observation: {chat}", chat=title)


def excerpt_line(store, event, title, words, chars=EXCERPT_CHARS):
    """One changed message with a short excerpt of its text (only when text excerpts are on)."""
    if event["kind"] == "message.edited":
        text = event["payload"].get("text") or ""
    else:
        content = store.message_state(event["chat_id"], event["message_id"])["content"]
        text = (content or {}).get("text") or ""
    text = " ".join(text.split())
    text = (text[:chars - 1] + "…") if len(text) > chars else text or tr(words, "(no saved text)")
    values = {"chat": title, "id": event["message_id"], "excerpt": text}
    if event["kind"] == "message.deleted":
        return tr(words, "{chat} · deleted #{id}: {excerpt}", **values)
    if event["kind"] == "message.edited":
        return tr(words, "{chat} · edited #{id}: {excerpt}", **values)
    return tr(words, "{chat} · not found #{id}: {excerpt}", **values)


def change_item(event, title, words):
    values = {"chat": title, "id": event["message_id"]}
    if event["kind"] == "message.deleted":
        return tr(words, "Message #{id} deleted in {chat}", **values)
    if event["kind"] == "message.edited":
        return tr(words, "Message #{id} edited in {chat}", **values)
    return tr(words, "Message #{id} not found at recheck in {chat}", **values)


NOTICE_RECOVERIES = ("connection.restored", "replica.changed", "evidence.changed")


def notice_payload(event):
    value = event.get("payload")
    return value if isinstance(value, dict) else {}


def notice_hour(event):
    try:
        at = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
        return at.replace(tzinfo=at.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat(timespec="hours")
    except (AttributeError, TypeError, ValueError, OverflowError):
        return "event:" + str(event["seq"])


def notice_key(*parts):
    return "v1:" + hashlib.sha256(canonical(parts)).hexdigest()


def timestamp_answered(payload):
    results = payload.get("results")
    return bool(payload.get("covered")) or isinstance(results, list) and any(
        isinstance(result, dict) and result.get("ok") for result in results)


def problem_group(event):
    """Typed identity and recovery family. Distinct user operations remain individual records."""
    p, kind, chat = notice_payload(event), event["kind"], event["chat_id"]
    fields, family = None, kind
    if kind == "collector.error":
        fields = [p.get("operation"), p.get("error_type")]
    elif kind == "connection.retry_failed":
        fields, family = [p.get("error_type")], "connection"
    elif kind == "coverage.gap":
        fields = [p.get("reason"), p.get("error_type")]
        if p.get("reason") in ("transport_disconnected", "authorization_required", "resume_failed"):
            family = "connection"
    elif kind == "replica.completed":
        fields, family = [p.get("destination"), p.get("error")], "replica"
    elif kind == "anchor.completed":
        results = p.get("results")
        outcomes = [{k: r.get(k) for k in ("kind", "url", "received", "error", "error_type")}
                    for r in results if isinstance(r, dict)] if isinstance(results, list) else None
        fields = [sorted(outcomes, key=canonical)] if outcomes is not None else [results]
        family = "timestamps"
    elif kind == "source.access_unconfirmed":
        fields = [p.get("reason")]
    elif kind == "storage.low":
        fields, family = [], "storage"
    identity = [kind, chat, *fields] if fields is not None else [kind, chat, event["seq"]]
    return identity, (family, chat), fields is not None


def recovered_family(event):
    p, kind = notice_payload(event), event["kind"]
    family = {"connection.restored": "connection", "storage.ok": "storage",
              "replica.changed": "replica", "evidence.changed": "timestamps"}.get(kind)
    if kind == "replica.completed" and not p.get("error"):
        family = "replica"
    if kind == "anchor.completed" and timestamp_answered(p):
        family = "timestamps"
    return (family, event["chat_id"]) if family else None


def notice_destination(event, level):
    kind, p = event["kind"], notice_payload(event)
    if level == "change":
        action = {"type": "chat", "chat_id": event["chat_id"]} if event["chat_id"] is not None else {"type": "record"}
        return "changes", "info", action
    category, part = {
        "storage.low": ("media", "media"), "storage.ok": ("media", "media"),
        "coverage.gap": ("collection", "intake"), "collector.error": ("collection", "intake"),
        "connection.retry_failed": ("connection", "connection"),
        "source.access_unconfirmed": ("sources", "sources"),
        "export.failed": ("exports", "exports"), "chat_export.interrupted": ("exports", "exports"),
        "replica.completed": ("replica", "replica"), "anchor.completed": ("timestamps", "timestamps"),
        "profile.unavailable": ("accounts", "accounts"), "host.state": ("server", "server"),
    }.get(kind, ("collection", None))
    if kind == "coverage.gap" and p.get("reason") == "authorization_required":
        category, part = "connection", "connection"
    if kind == "collector.error" and p.get("operation") == "off-site copy":
        category, part = "replica", "replica"
    severity = "warning"
    if level == "ok":
        severity = "success"
    elif kind in ("collector.error", "export.failed", "chat_export.interrupted", "profile.unavailable", "replica.completed") \
            or category == "connection" and p.get("reason") == "authorization_required":
        severity = "error"
    action = {"type": "diagnostics", "part": part} if part else {"type": "record"}
    return category, severity, action


def notice_entry(event, level, text, read_key, *, group_id=None, count_exact=True):
    category, severity, action = notice_destination(event, level)
    return {"seq": event["seq"], "at": event["observed_at"], "kind": event["kind"], "level": level,
            "text": text, "chat_id": event["chat_id"], "message_id": event["message_id"],
            "group_id": group_id or read_key, "read_key": read_key, "count": 1, "occurrences": 1,
            "count_exact": count_exact, "first_seq": event["seq"], "first_at": event["observed_at"],
            "last_at": event["observed_at"], "category": category, "severity": severity, "action": action}


def panel_items(store, words, limit=60, *, allowed_chats=None, workspace_id="default"):
    """Bounded, scoped notification projection; the signed journal is never changed.

    Recurring problems and chat changes are grouped per UTC hour. Known recovery events
    separate problem episodes. A truncated scan reports lower-bound counts explicitly.
    """
    if limit <= 0 or allowed_chats is not None and not allowed_chats:
        return []
    titles = {t["chat_id"]: t["title"] for t in store.targets()
              if allowed_chats is None or t["chat_id"] in allowed_chats}

    def scan(kinds, bound):
        records = store.events_of(kinds, limit=bound + 1, chat_ids=allowed_chats)
        return records[:bound], len(records) > bound

    problem_bound = limit * 5 * PROBLEM_PAGES
    records, truncated = scan((*PROBLEM_KINDS, *NOTICE_RECOVERIES), problem_bound)
    ignored = set(store.get_setting("ignored_source_warnings", []))
    resolved = store.get_setting("resolved_source_warnings", {})
    groups, recovered = {}, {}
    for event in reversed(records):
        if event["kind"] == "source.access_unconfirmed" and (event["chat_id"] in ignored
                or event["seq"] <= resolved.get(str(event["chat_id"]), 0)):
            continue
        family = recovered_family(event)
        if family:
            recovered[family] = event["seq"]
        try:
            text = problem_line({**event, "payload": notice_payload(event)}, titles, words)
        except (AttributeError, TypeError, ValueError, OverflowError):
            text = tr(words, "Problem recorded: {kind}", kind=event["kind"])
        if not text:
            continue
        identity, family, grouped = problem_group(event)
        read_key = notice_key(workspace_id, identity, notice_hour(event))
        key = notice_key(read_key, recovered.get(family, 0))
        item = notice_entry(event, "ok" if event["kind"] == "storage.ok" else "problem", text, read_key,
                            group_id=key, count_exact=not (grouped and truncated))
        if not item["count_exact"]:
            item["scan_limit"] = problem_bound
        previous = groups.get(key)
        if previous:
            item.update(count=previous["count"] + 1, occurrences=previous["count"] + 1,
                        first_seq=previous["first_seq"], first_at=previous["first_at"])
        groups[key] = item
    problems = sorted(groups.values(), key=lambda item: item["seq"], reverse=True)[:limit]

    records, truncated = scan(tuple(CHANGES), CHANGE_SCAN)
    groups = {}
    for event in records:
        if event["chat_id"] is None:
            continue
        key = notice_key(workspace_id, "changes", event["chat_id"], notice_hour(event))
        group = groups.setdefault(key, {"event": event, "first": event, "counts": {}, "count": 0})
        change = CHANGES[event["kind"]]
        group["counts"][change] = group["counts"].get(change, 0) + 1
        group["count"] += 1
        group["first"] = event
    changes = []
    for key, group in groups.items():
        event, count = group["event"], group["count"]
        title = titles.get(event["chat_id"], str(event["chat_id"]))
        text = change_item(event, title, words) if count == 1 else change_line(title, group["counts"], words)
        if truncated:
            text = tr(words, "Recent changes in {chat}", chat=title)
        item = notice_entry(event, "change", text, key, count_exact=not truncated)
        if truncated:
            item["scan_limit"] = CHANGE_SCAN
        item.update(count=count, occurrences=count, first_seq=group["first"]["seq"], first_at=group["first"]["observed_at"])
        if count > 1:
            item["records"] = count
        changes.append(item)
    for event in store.events_of(("source.discovered",), limit=limit, chat_ids=allowed_chats):
        title = notice_payload(event).get("title") or titles.get(event["chat_id"], str(event["chat_id"]))
        key = notice_key(workspace_id, "source.discovered", event["seq"])
        changes.append(notice_entry(event, "change", discovered_line(title, words), key))
    changes.sort(key=lambda item: item["seq"], reverse=True)
    return sorted(problems + changes[:max(0, limit - len(problems))], key=lambda item: item["seq"], reverse=True)


def capped(lines, words, limit=MAX_LINES):
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(lines[:limit] + [tr(words, "…and {n} more.", n=len(lines) - limit)])


def summary(store, words, now=None, limit=MAX_LINES):
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(days=1)).isoformat(timespec="milliseconds")
    counts = store.counts_since(since, SUMMARY_KINDS)
    lines = []
    targets = store.targets(True)
    for target in targets:
        c = {kind: counts.get((target["chat_id"], kind), 0) for kind in SUMMARY_KINDS}
        if any(c.values()):
            lines.append(tr(words, "{chat}: {new} new, {edited} edited, {deleted} deleted, {missing} not found",
                            chat=target["title"], new=c["message.new"] + c["message.recovered"],
                            edited=c["message.edited"], deleted=c["message.deleted"],
                            missing=c["message.missing_on_recheck"]))
    if not lines:
        lines.append(tr(words, "No activity in {n} observed chats in the last 24 hours.", n=len(targets)))
    return capped(lines, words, limit)


def workspace_name(store):
    account = store.get_setting("account", None) or {}
    if account.get("username"):
        return "@" + account["username"]
    return "ID " + str(account["id"]) if account.get("id") else "TgWitness"


def collect(store, cursor, titles, words, include_text=False, max_lines=MAX_LINES, chars=EXCERPT_CHARS):
    """Problem lines, per-chat change counts, newly added chats and (optionally) excerpts after cursor."""
    problems, changes, discovered, excerpts = [], {}, [], []
    while True:
        events = store.events_after(cursor, BATCH)
        for event in events:
            line = problem_line(event, titles, words)
            if line:
                problems.append(line)
            change = CHANGES.get(event["kind"])
            if change and event["chat_id"] is not None:
                per_chat = changes.setdefault(event["chat_id"], {})
                per_chat[change] = per_chat.get(change, 0) + 1
                if include_text and len(excerpts) <= max_lines:
                    excerpts.append(excerpt_line(store, event, titles.get(event["chat_id"], str(event["chat_id"])),
                                                 words, chars))
            if event["kind"] == "source.discovered":
                discovered.append(discovered_line(event["payload"].get("title") or str(event["chat_id"]), words))
            cursor = event["seq"]
        if len(events) < BATCH:
            return cursor, problems, changes, discovered, excerpts


async def alert_pass(store, vault, network, now=None):
    settings, urls = alert_settings(store), vault.read("alerts").get("urls", [])
    head = (store.stats()["head"] or {}).get("seq", 0)
    if not settings["enabled"] or not urls:
        store.set_setting("alerts_cursor", head)
        return None
    words, name = i18n.words(settings["language"]), workspace_name(store)
    titles = {t["chat_id"]: t["title"] for t in store.targets()}
    start = store.get_setting("alerts_cursor", head)
    limit = tuning.value(store, "alerts_max_lines")
    cursor, problems, changes, discovered, excerpts = collect(store, start, titles, words, settings["include_text"],
                                                              limit, tuning.value(store, "alerts_excerpt_chars"))
    messages = []
    if settings["problems"] and problems:
        messages.append((tr(words, "TgWitness · {name}: problems", name=name), capped(problems, words, limit)))
    if settings["changes"] and (changes or discovered):
        lines = [change_line(titles.get(chat, str(chat)), counts, words) for chat, counts in changes.items()]
        messages.append((tr(words, "TgWitness · {name}: changes in observed chats", name=name),
                         capped(discovered + lines + excerpts, words, limit)))
    local = (now or datetime.now(timezone.utc)).astimezone()
    daily_due = settings["daily"] and local.hour >= settings["daily_hour"] \
        and store.get_setting("alerts_daily", None) != local.date().isoformat()
    if daily_due:
        messages.append((tr(words, "TgWitness · {name}: last 24 hours", name=name),
                         summary(store, words, now, limit)))
    sent, error = 0, None
    for title, body in messages:
        result = await asyncio.to_thread(deliver, urls, title, body, network)
        sent += 1 if result["sent"] else 0
        if result["error"]:
            error = result["error"]
            break
    if error is None:
        store.set_setting("alerts_cursor", cursor)
        if daily_due:
            store.set_setting("alerts_daily", local.date().isoformat())
    if messages:
        store.set_setting("alerts_last", {"at": utcnow(), "notifications": sent, "error": error})
    return {"notifications": sent, "error": error}


async def alert_loop(store, vault, network_config, wakeup, workspace_id="default"):
    while True:
        with suppress(TimeoutError):
            await asyncio.wait_for(wakeup.wait(), tuning.value(store, "alerts_check_seconds"))
        wakeup.clear()
        try:
            await alert_pass(store, vault, network_config())
        except Exception as exc:
            store.set_setting("alerts_last", {"at": utcnow(), "notifications": 0, "error": type(exc).__name__})
        from . import webhooks
        try:
            await webhooks.pump(store, vault, network_config(), workspace_id)
        except Exception as exc:
            async with webhooks.lock(store):
                data = webhooks.state(store)
                data["last_error"] = type(exc).__name__
                store.set_setting("webhook_delivery", data)
