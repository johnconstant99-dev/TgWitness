"""Notifications through Apprise: problems, changes in observed chats and a daily summary.

By default only chat names, counts and problem descriptions leave the machine. Message text
is added only when the operator turns on text excerpts. The panel's notification list uses
the same wording.
"""
import asyncio
import re
import threading
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, Field

from . import i18n
from . import tuning
from .store import utcnow

# Pace, lines per notification and excerpt length are panel parameters (tuning.PARAMETERS);
# these are their defaults.
BATCH = 2000
MAX_LINES = 25
EXCERPT_CHARS = 120
CHANGES = {"message.deleted": "deleted", "message.edited": "edited", "message.missing_on_recheck": "missing"}
PROBLEM_KINDS = ("storage.low", "storage.ok", "coverage.gap", "collector.error", "connection.retry_failed",
                 "source.access_unconfirmed", "export.failed", "chat_export.interrupted", "replica.completed",
                 "anchor.completed", "profile.unavailable", "host.state")
# Panel list: newest change records grouped per chat and hour, and pages searched for problems.
CHANGE_SCAN = 5000
PROBLEM_PAGES = 20
SUMMARY_KINDS = ("message.new", "message.recovered", "message.edited", "message.deleted", "message.missing_on_recheck")
# These services open their own sockets (SMTP, IRC, MQTT, XMPP...), so they cannot use the workspace proxy.
DIRECT_SOCKET = {"amqp", "amqps", "aprs", "deltachat", "deltachats", "growl", "irc", "ircs", "mailto", "mailtos",
                 "mqtt", "mqtts", "rsyslog", "smpp", "smpps", "xmpp", "xmpps"}
_send_lock = threading.Lock()


class AlertSettings(BaseModel):
    enabled: bool = False
    problems: bool = True
    changes: bool = False
    daily: bool = True
    daily_hour: int = Field(default=9, ge=0, le=23)
    language: Literal[i18n.LANGUAGES] = "en"
    include_text: bool = False  # excerpts of deleted and edited messages in change notifications


def alert_settings(store):
    return AlertSettings(**store.get_setting("alerts", {})).model_dump()


def tr(words, text, **values):
    out = words.get(text)
    out = out if isinstance(out, str) else text
    return re.sub(r"\{(\w+)\}", lambda m: str(values[m.group(1)]) if m.group(1) in values else m.group(0), out)


def describe(url):
    """Apprise's own masked form of a destination, or None when Apprise cannot use it."""
    import apprise  # Apprise, requests and their native modules take seconds to load; only notifications need them
    plugin = apprise.Apprise.instantiate(url)
    return plugin.url(privacy=True) if plugin else None


def route_problem(urls, network):
    if network.kind == "mtproxy":
        return "Notifications are not sent over MTProxy. Choose Direct, SOCKS5 or HTTP in Account → Connection settings."
    if network.kind != "direct" and any(url.split("://", 1)[0].lower() in DIRECT_SOCKET for url in urls):
        return ("A destination connects without HTTP (email, IRC, MQTT, XMPP and similar) and cannot use this "
                "workspace's proxy. Choose an HTTP-based service or a direct connection.")
    return None


def proxy_url(network):
    if network.kind == "direct":
        return None
    login = (quote(network.username, safe="") + ":" + quote(network.password, safe="") + "@") if network.username else ""
    host = "[" + network.host + "]" if ":" in network.host else network.host
    # socks5h: names are resolved by the proxy, so lookups do not leave through the local network.
    return ("socks5h" if network.kind == "socks5" else "http") + "://" + login + host + ":" + str(network.port)


@contextmanager
def _routed(proxy):
    """Apprise sends through requests; for this send its proxy settings are the workspace route only."""
    import requests
    original = requests.Session.merge_environment_settings

    def merge(self, url, proxies, stream, verify, cert):
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
    with _send_lock, _routed(proxy_url(network)):
        bundle = apprise.Apprise()
        for url in urls:
            bundle.add(url)
        result = bundle.notify(body=body, title=title)
    if isinstance(result, bool):  # Apprise 1.x reports only whether every destination accepted it
        return {"sent": len(urls) if result else 0, "failed": 0 if result else len(urls),
                "error": None if result else "The service did not accept the notification."}
    errors = [entry.message for entry in result.logs() if str(entry.level).upper() in ("ERROR", "WARNING")]
    error = None
    if result.failed_count or not result.success_count:
        error = (errors[0] if errors else "The service did not accept the notification.")[:300]
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
    if kind == "anchor.completed" and not any(r.get("ok") for r in p.get("results", [])):
        return tr(words, "No timestamp service answered for the latest checkpoint.")
    if kind == "profile.unavailable":
        return tr(words, "Workspace {name} could not start: {error}", name=p.get("profile_id") or "?",
                  error=p.get("error_type") or "?")
    if kind == "host.state":
        return host_line(p, words)
    return None


def host_line(state, words):
    """A server deployed with python -m tgwitness.cloud measured SSH or a login; closing them is no problem."""
    before, found = state.get("before") or {}, []
    if state.get("ssh_listening") and not before.get("ssh_listening"):
        found.append(tr(words, "port 22 accepts connections"))
    if (state.get("ssh_processes") or 0) > (before.get("ssh_processes") or 0):
        found.append(tr(words, "SSH server processes started"))
    if (state.get("sessions") or 0) > (before.get("sessions") or 0):
        found.append(tr(words, "logged-in sessions: {n}", n=state["sessions"]))
    if (state.get("logins") or 0) > (before.get("logins") or 0):
        found.append(tr(words, "new logins recorded: {n}", n=state["logins"] - (before.get("logins") or 0)))
    if not found:
        return None
    return tr(words, "Server access detected: {details}", details="; ".join(found))


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


def panel_items(store, words, limit=60):
    """Recent problems and chat changes for the panel's notification list, newest first.

    Problems keep their place however busy the chats are, and changes in one chat are grouped
    per hour: a chat deleting a message every minute cannot push a sign-out or a full disk out.
    """
    titles = {t["chat_id"]: t["title"] for t in store.targets()}

    def entry(event, level, text, **extra):
        return {"seq": event["seq"], "at": event["observed_at"], "kind": event["kind"], "level": level,
                "text": text, "chat_id": event["chat_id"], "message_id": event["message_id"], **extra}

    problems, before = [], None
    for _ in range(PROBLEM_PAGES):  # completed copies and timestamps are not problems: look further back
        batch = store.events_of(PROBLEM_KINDS, limit=limit * 5, before=before)
        for event in batch:
            text = problem_line(event, titles, words)
            if text and len(problems) < limit:
                problems.append(entry(event, "ok" if event["kind"] == "storage.ok" else "problem", text))
        if len(problems) >= limit or len(batch) < limit * 5:
            break
        before = batch[-1]["seq"]
    records, groups = store.events_of(tuple(CHANGES), limit=CHANGE_SCAN), {}
    # The oldest hour of a full scan may be cut off; it is left out rather than shown with low counts.
    partial = records[-1]["observed_at"][:13] if len(records) == CHANGE_SCAN else None
    for event in records:
        hour = event["observed_at"][:13]
        if event["chat_id"] is None or hour == partial:
            continue
        group = groups.setdefault((event["chat_id"], hour), {"event": event, "counts": {}, "records": 0})
        group["counts"][CHANGES[event["kind"]]] = group["counts"].get(CHANGES[event["kind"]], 0) + 1
        group["records"] += 1
    changes = []
    for (chat_id, _), group in groups.items():
        title = titles.get(chat_id, str(chat_id))
        if group["records"] == 1:
            changes.append(entry(group["event"], "change", change_item(group["event"], title, words)))
        else:
            changes.append(entry(group["event"], "change", change_line(title, group["counts"], words),
                                 records=group["records"]))
    for event in store.events_of(("source.discovered",), limit=limit):
        title = event["payload"].get("title") or titles.get(event["chat_id"], str(event["chat_id"]))
        changes.append(entry(event, "change", discovered_line(title, words)))
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
        store.set_setting("alerts_cursor", head)  # turning alerts on never replays old records
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


async def alert_loop(store, vault, network_config, wakeup):
    while True:
        with suppress(TimeoutError):
            await asyncio.wait_for(wakeup.wait(), tuning.value(store, "alerts_check_seconds"))
        wakeup.clear()
        try:
            await alert_pass(store, vault, network_config())
        except Exception as exc:
            store.set_setting("alerts_last", {"at": utcnow(), "notifications": 0, "error": type(exc).__name__})
