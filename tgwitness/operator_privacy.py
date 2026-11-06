import ipaddress
import re


IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F:.]{0,45}(?:%[A-Za-z0-9_.-]{1,64})?(?![\w:])")


URL_LOGIN = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s@]+@", re.I)
BEARER = re.compile(r"(\bBearer\s+)[^\s,;\"']+", re.I)
CREDENTIAL = re.compile(
    r'''(?i)(\b(?:api[_-]?(?:key|hash)|access[_-]?token|auth[_-]?key|token|secret|password|phone_code|login_code)["']?\s*[:=]\s*)(["']?)([^\s&<>"',;}]+)(\2)''')


def private_log(text):
    text = URL_LOGIN.sub(r"\1[credentials hidden]@", text)
    text = BEARER.sub(r"\1[secret hidden]", text)
    text = CREDENTIAL.sub(lambda match: match[1] + match[2] + '[secret hidden]' + match[4], text)
    return hide_addresses(text)


def hide_addresses(text):
    def replace(match):
        try:
            ipaddress.ip_address(match.group())
        except ValueError:
            return match.group()
        return "[IP hidden]"
    return IPV4.sub(replace, IPV6.sub(replace, text))


COLLECTOR_FIELDS = frozenset((
    "phase", "running", "connected", "has_session", "authorization_required", "account",
    "last_heartbeat", "media_pending", "media_jobs", "oldest_pending_media_at", "source_status",
    "last_update_at", "chat_export", "recheck", "storage_low", "scope", "rpc_backoff_until",
    "reconnect_attempts", "next_reconnect_at", "recheck_enabled", "recheck_interval_minutes",
))
HEALTH_FIELDS = frozenset((
    "state", "reason", "phase", "attempts", "next_reconnect_at", "telegram_pause_until", "telegram_pause_method",
    "diverted_since",
    "last_heartbeat", "last_event_at", "heartbeat_seconds", "last_pass_at", "last_success_at",
    "next_attempt_at", "interval_seconds", "queued", "running", "retry", "failed", "saved",
    "pending", "oldest_pending_at", "enabled_sources", "enabled", "counts",
))


def connection_details(principal, allowed=None):
    return principal.admin or (principal.may("account") and allowed is None)


def without_diagnostics(value):
    if isinstance(value, dict):
        return {key: without_diagnostics(item) for key, item in value.items()
                if key not in ('error', 'last_error', 'traceback', 'path')}
    if isinstance(value, list):
        return [without_diagnostics(item) for item in value]
    return value


def status_parts(principal, current, parts, allowed=None):
    if current is None:
        return current, parts
    if connection_details(principal, allowed):
        return current, parts
    current = {key: value for key, value in (current or {}).items() if key in COLLECTOR_FIELDS}
    filtered = {name: {key: value for key, value in part.items() if key in HEALTH_FIELDS}
                for name, part in (parts or {}).items() if isinstance(part, dict)}
    if parts and "state" in parts:
        filtered["state"] = parts["state"]
    return without_diagnostics(current), filtered
