"""Who opens the panel, what they see and do there, and the main administrator's console.

The panel token (panel-token.txt) stays the main administrator's key. The administrator issues
further access: a token is shown once and the vault keeps only its SHA-256. Each access opens the
workspaces and chats it names, with the permissions ticked for it, and can be bound to addresses,
a number of sign-ins, an end date and a number of parallel sessions. Signing in with any token
starts a session; the panel then works with the session, which can be listed and ended.
"""
import hashlib
import ipaddress
import logging
import re
import secrets
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .store import utcnow

LOG = logging.getLogger("tgwitness.access")
JOURNAL_LOG = logging.getLogger("tgwitness.journal")

PERMISSIONS = ("view", "export", "sources", "collect", "interact", "settings", "account")
ADMIN_DEFAULTS = {"max_sessions": 0, "on_limit": "replace", "session_minutes": 720}
WORKSPACE_ID = re.compile(r"default|[a-f0-9]{32}")

# Every route an issued access may use: (permission, how a chat-limited access is checked).
#   path   - the {chat_id} in the address must be one of its chats
#   body   - the route itself checks the chat named in the request
#   filter - the route answers with the allowed chats only
#   root   - a route of the main panel that checks each workspace itself
#   None   - the whole workspace: refused to an access limited to chosen chats
# A route missing here is open to the main administrator only.
POLICY = {
    "GET /api/status": ("view", "filter"),
    "GET /api/profiles": ("view", "root"),
    "GET /api/events": ("view", "filter"),
    "GET /api/chats": ("view", "filter"),
    "GET /api/notifications": ("view", "filter"),
    "GET /api/chats/{chat_id}/messages": ("view", "path"),
    "GET /api/chats/{chat_id}/authors": ("view", "path"),
    "GET /api/chats/{chat_id}/profile": ("view", "path"),
    "GET /api/chats/{chat_id}/dossier": ("view", "path"),
    "GET /api/chats/{chat_id}/scale": ("view", "path"),
    "GET /api/avatar/{peer_id}": ("view", "body"),
    "GET /api/media/{digest}": ("view", "body"),
    "GET /api/scope": ("view", None),
    "GET /api/evidence": ("view", None),
    "GET /api/source-check": ("view", None),
    "GET /api/replica": ("view", None),
    "GET /api/alerts": ("view", None),
    "GET /api/parameters": ("view", None),
    "GET /api/checkpoint": ("view", None),
    "GET /api/run-receipt": ("view", None),
    "POST /api/verify": ("view", None),
    "GET /api/export/{fmt}": ("export", None),
    "POST /api/export/{fmt}": ("export", None),
    "GET /api/anchor-request": ("export", None),
    "GET /api/chats/{chat_id}/dossier/export": ("export", "path"),
    "POST /api/chats/{chat_id}/dossier/export": ("export", "path"),
    "POST /api/chat-export/start": ("export", "body"),
    "GET /api/chat-export/{export_id}": ("export", "body"),
    "POST /api/chat-export/{export_id}/cancel": ("export", "body"),
    "GET /api/chat-export/{export_id}/download": ("export", "body"),
    "POST /api/multi-export/start": ("export", "root"),
    "GET /api/multi-export/current": ("export", "root"),
    "GET /api/multi-export/{export_id}": ("export", "root"),
    "POST /api/multi-export/{export_id}/cancel": ("export", "root"),
    "GET /api/multi-export/{export_id}/download": ("export", "root"),
    "GET /api/dialogs": ("sources", None),
    "POST /api/targets": ("sources", "body"),
    "POST /api/targets/priority": ("sources", "body"),
    "DELETE /api/targets/{chat_id}": ("sources", "path"),
    "POST /api/scope": ("sources", None),
    "POST /api/recheck": ("sources", None),
    "POST /api/snapshot": ("sources", "body"),
    "POST /api/chats/{chat_id}/profile": ("sources", "path"),
    "POST /api/chats/{chat_id}/dossier": ("sources", "path"),
    "POST /api/collector/{action}": ("collect", None),
    "POST /api/interactions/preview": ("interact", None),
    "POST /api/interactions": ("interact", "body"),
    "POST /api/capture": ("settings", None),
    "POST /api/monitoring": ("settings", None),
    "POST /api/evidence": ("settings", None),
    "POST /api/evidence/anchor": ("settings", None),
    "POST /api/source-check": ("settings", None),
    "POST /api/replica": ("settings", None),
    "POST /api/replica/sync": ("settings", None),
    "POST /api/replica/test": ("settings", None),
    "GET /api/replica/key": ("settings", None),
    "POST /api/alerts": ("settings", None),
    "POST /api/alerts/test": ("settings", None),
    "POST /api/parameters": ("settings", None),
    "GET /api/witness": ("settings", None),
    "POST /api/witness/tokens": ("settings", None),
    "DELETE /api/witness/tokens/{token_id}": ("settings", None),
    "POST /api/auth/configure": ("account", None),
    "POST /api/auth/phone/start": ("account", None),
    "POST /api/auth/import": ("account", None),
    "POST /api/auth/qr/start": ("account", None),
    "GET /api/auth/qr/{login_id}": ("account", None),
    "POST /api/auth/qr/{login_id}/cancel": ("account", None),
    "POST /api/auth/phone": ("account", None),
    "POST /api/auth/code": ("account", None),
    "POST /api/auth/password": ("account", None),
    "POST /api/auth/logout": ("account", None),
    "POST /api/network": ("account", None),
    "GET /api/network/policy": ("account", None),
    "POST /api/network/policy": ("account", None),
    "GET /api/network/catalog": ("account", None),
    "POST /api/network/catalog/refresh": ("account", None),
    "POST /api/network/catalog/{proxy_id}": ("account", None),
    "POST /api/network/parse-link": ("account", None),
    "POST /api/network/test": ("account", None),
}
# Journal records too frequent for the console; they stay in the journal and the panel.
QUIET_KINDS = ("message.", "reaction.", "membership.", "media.saved", "collector.heartbeat")


class Refused(Exception):
    """The access exists but may not do this; the text is shown in the panel."""


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def unix_iso(value):
    return None if value is None else datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


class GrantSettings(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    permissions: list[Literal[PERMISSIONS]] = Field(default_factory=lambda: ["view"], max_length=len(PERMISSIONS))
    all_workspaces: bool = False
    # Workspace ID -> null for every chat of it, or the only chat IDs it opens.
    workspaces: dict[str, list[int] | None] = Field(default_factory=dict, max_length=1000)
    ips: list[str] = Field(default_factory=list, max_length=100)
    bind_first_ip: bool = False
    max_uses: int | None = Field(default=None, ge=1, le=1000000)
    expires_at: float | None = None
    max_sessions: int = Field(default=1, ge=1, le=100)
    on_limit: Literal["refuse", "replace"] = "refuse"
    session_minutes: int = Field(default=720, ge=5, le=43200)

    @field_validator("label")
    @classmethod
    def plain_label(cls, value):
        if not value.strip():
            raise ValueError("Enter a name for this access.")
        return value.strip()

    @field_validator("ips")
    @classmethod
    def networks(cls, values):
        result = []
        for value in values:
            try:
                result.append(str(ipaddress.ip_network(value.strip(), strict=False)))
            except ValueError:
                raise ValueError("Enter addresses as IP addresses or subnets such as 203.0.113.7 or 203.0.113.0/24.") from None
        return list(dict.fromkeys(result))

    @model_validator(mode="after")
    def complete(self):
        for key, chats in self.workspaces.items():
            if not WORKSPACE_ID.fullmatch(key):
                raise ValueError("Unknown workspace.")
            if chats is not None:
                if not chats or len(chats) > 10000:
                    raise ValueError("Choose at least one chat, or open the whole workspace.")
                self.workspaces[key] = sorted(set(chats))
        if not self.all_workspaces and not self.workspaces:
            raise ValueError("Choose at least one workspace for this access.")
        self.permissions = [p for p in PERMISSIONS if p in {"view", *self.permissions}]
        return self


class AdminSettings(BaseModel):
    max_sessions: int = Field(default=0, ge=0, le=100)  # 0: no limit
    on_limit: Literal["refuse", "replace"] = "replace"
    session_minutes: int = Field(default=720, ge=5, le=43200)


@dataclass
class Principal:
    admin: bool
    label: str
    grant: dict | None = None
    session_id: str | None = None

    @property
    def owner(self):
        return "admin" if self.admin else self.grant["id"]

    def opens(self, profile_id):
        return self.admin or self.grant["all_workspaces"] or profile_id in self.grant["workspaces"]

    def chats(self, profile_id):
        """None: every chat of the workspace; otherwise the only chat IDs this access sees."""
        if self.admin or self.grant["all_workspaces"]:
            return None
        listed = self.grant["workspaces"].get(profile_id)
        return None if listed is None else set(listed)

    def may(self, permission):
        return self.admin or permission in self.grant["permissions"]

    def public(self):
        if self.admin:
            return {"admin": True, "label": self.label, "permissions": list(PERMISSIONS), "all_workspaces": True,
                    "workspaces": {}, "expires_at": None}
        return {"admin": False, "label": self.label, "permissions": self.grant["permissions"],
                "all_workspaces": self.grant["all_workspaces"], "workspaces": self.grant["workspaces"],
                "expires_at": unix_iso(self.grant["expires_at"])}


def check(principal, profile_id, rule, path_params):
    """Raises Refused if an issued access may not make this request."""
    if principal.admin:
        return
    if rule is None:
        raise Refused("Only the main administrator can do this.")
    permission, chat = rule
    if chat != "root" and not principal.opens(profile_id):
        raise Refused("This access does not open this workspace.")
    if not principal.may(permission):
        raise Refused("This access does not allow this action.")
    allowed = None if chat == "root" else principal.chats(profile_id)
    if allowed is not None:
        if chat is None:
            raise Refused("This access opens only chosen chats; this part of the workspace is closed to it.")
        if chat == "path" and int(path_params["chat_id"]) not in allowed:
            raise Refused("This chat is not open to this access.")


class Console(logging.Handler):
    """Everything the process logs since it started, kept in memory for the administrator's console."""

    def __init__(self, size=5000):
        super().__init__(logging.INFO)
        self.lines, self.counter, self.guard = deque(maxlen=size), 0, threading.Lock()

    def emit(self, record):
        try:
            text = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                text += " · " + type(record.exc_info[1]).__name__
        except Exception:
            text = str(record.msg)
        with self.guard:
            self.counter += 1
            self.lines.append({"n": self.counter, "at": utcnow(), "level": record.levelname,
                               "source": record.name, "text": text[:2000]})

    def after(self, n, limit=500):
        with self.guard:
            lines = [line for line in self.lines if line["n"] > n]
        return lines[:limit]

    def attach(self):
        root = logging.getLogger()
        self.stderr = None
        if not root.handlers and sys.stderr is not None:
            # Python prints warnings to stderr only while the root logger has no handler; keep that.
            self.stderr = logging.StreamHandler()
            self.stderr.setLevel(logging.WARNING)
            root.addHandler(self.stderr)
        if root.getEffectiveLevel() > logging.INFO:
            root.setLevel(logging.INFO)
        for name in ("httpx", "httpcore"):  # their INFO lines carry full request addresses
            if logging.getLogger(name).level == logging.NOTSET:
                logging.getLogger(name).setLevel(logging.WARNING)
        for name in ("", "uvicorn", "uvicorn.error"):
            logging.getLogger(name).addHandler(self)

    def detach(self):
        for name in ("", "uvicorn", "uvicorn.error"):
            logging.getLogger(name).removeHandler(self)
        if getattr(self, "stderr", None):
            logging.getLogger().removeHandler(self.stderr)


class AccessControl:
    """Issued accesses (in the vault) and the open sessions of the whole installation."""

    def __init__(self, vault, store, console=None):
        self.vault, self.store = vault, store
        saved = vault.read("access")
        self.grants = saved.get("grants", [])
        now = time.time()
        self.sessions = {s["sha256"]: {**s, "requests": 0} for s in saved.get("sessions", []) if s["expires"] > now}
        self.lock = threading.RLock()
        self.console = console or Console()
        self.labels = lambda profile_id: profile_id  # replaced by the panel with workspace names

    # ---- storage ----
    def save(self):
        sessions = [{k: v for k, v in s.items() if k != "requests"} for s in self.sessions.values()]
        self.vault.save("access", {"grants": self.grants, "sessions": sessions})

    def admin_settings(self):
        return {**ADMIN_DEFAULTS, **self.store.get_setting("access_admin", {})}

    def grant(self, grant_id):
        return next((g for g in self.grants if g["id"] == grant_id), None)

    def match(self, token):
        found, wanted = None, digest(token)
        for entry in self.grants:
            if secrets.compare_digest(entry["sha256"], wanted):
                found = entry
        return found

    # ---- rules ----
    @staticmethod
    def address_allowed(grant, address):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:  # not an IP address (a local socket or a test client)
            return not grant["ips"] and grant.get("bound_ip") in (None, address)
        if grant["ips"] and not any(ip in ipaddress.ip_network(n) for n in grant["ips"]):
            return False
        return not grant.get("bound_ip") or grant["bound_ip"] == str(ip)

    def refuse(self, grant, address, now, signing_in):
        """Raises Refused (and logs it) if this access may not be used now from this address."""
        try:
            if grant["expires_at"] is not None and now >= grant["expires_at"]:
                raise Refused("This access has expired.")
            if signing_in and grant["max_uses"] is not None and grant["uses"] >= grant["max_uses"]:
                raise Refused("This access has been used as many times as it allows.")
            if not self.address_allowed(grant, address):
                raise Refused("This access does not open the panel from this address.")
        except Refused as exc:
            LOG.warning("%s refused for %s from %s: %s", "Sign-in" if signing_in else "Request",
                        grant["label"], address, exc)
            raise

    def live(self, owner, now):
        return sorted((s for s in self.sessions.values() if s["owner"] == owner and s["expires"] > now),
                      key=lambda s: s["created"])

    # ---- sessions ----
    def login(self, token, address, agent):
        """A new session for a valid token, or None for an unknown token. Raises Refused."""
        now = time.time()
        with self.lock:
            for sha in [k for k, s in self.sessions.items() if s["expires"] <= now]:
                del self.sessions[sha]
            if secrets.compare_digest(digest(token), digest(self.vault.token)):
                grant, settings, label = None, self.admin_settings(), "Main administrator"
            else:
                grant = self.match(token)
                if grant is None:
                    return None
                self.refuse(grant, address, now, signing_in=True)
                settings, label = grant, grant["label"]
            owner = grant["id"] if grant else "admin"
            live = self.live(owner, now)
            if settings["max_sessions"] and len(live) >= settings["max_sessions"]:
                if settings["on_limit"] == "refuse":
                    LOG.warning("Sign-in refused for %s from %s: session limit %d reached",
                                label, address, settings["max_sessions"])
                    raise Refused("This access already has as many open sessions as it allows. "
                                  "End one of them or wait until it expires.")
                for old in live[:len(live) - settings["max_sessions"] + 1]:
                    self.end(old["id"], "replaced by a newer session")
            if grant:
                grant["uses"] += 1
                grant["last_login_at"], grant["last_address"] = utcnow(), address
                if grant["bind_first_ip"] and not grant.get("bound_ip"):
                    grant["bound_ip"] = address
            session_token = "tgws_" + secrets.token_urlsafe(32)
            session = {"sha256": digest(session_token), "id": secrets.token_hex(8), "owner": owner,
                       "address": address, "agent": (agent or "")[:200], "created": now, "last_seen": now,
                       "expires": now + settings["session_minutes"] * 60, "requests": 0}
            self.sessions[session["sha256"]] = session
            self.save()
        self.store.append("access.session_started", {"access_id": owner, "label": label,
                                                    "session_id": session["id"], "address": address})
        LOG.info("Session %s started for %s from %s", session["id"], label, address)
        return session_token, self.principal(session)

    def principal(self, session):
        if session["owner"] == "admin":
            return Principal(True, "Main administrator", None, session["id"])
        grant = self.grant(session["owner"])
        return Principal(False, grant["label"], grant, session["id"])

    def resolve(self, credential, address):
        """The principal behind a bearer credential, or None. Raises Refused."""
        if secrets.compare_digest(digest(credential), digest(self.vault.token)):
            return Principal(True, "Main administrator (panel token)")
        now = time.time()
        with self.lock:
            session = self.sessions.get(digest(credential))
            if session is None:
                return None
            if session["expires"] <= now:
                self.end(session["id"], None)
                return None
            minutes = self.admin_settings()["session_minutes"]
            if session["owner"] != "admin":
                grant = self.grant(session["owner"])
                if grant is None:
                    self.end(session["id"], None)
                    return None
                try:
                    self.refuse(grant, address, now, signing_in=False)
                except Refused:
                    if grant["expires_at"] is not None and now >= grant["expires_at"]:
                        self.end(session["id"], "access expired")
                    raise
                minutes = grant["session_minutes"]
            session["last_seen"], session["expires"] = now, now + minutes * 60
            session["requests"] += 1
            return self.principal(session)

    def end(self, session_id, reason):
        """Close a session; with a reason the journal records it."""
        with self.lock:
            found = next((s for s in self.sessions.values() if s["id"] == session_id), None)
            if found is None:
                return False
            del self.sessions[found["sha256"]]
            self.save()
        label = "Main administrator" if found["owner"] == "admin" else (self.grant(found["owner"]) or {}).get("label")
        if reason:
            self.store.append("access.session_ended", {"access_id": found["owner"], "label": label,
                                                      "session_id": session_id, "reason": reason})
        LOG.info("Session %s of %s ended: %s", session_id, label, reason or "expired")
        return True

    # ---- issued accesses ----
    def journal_view(self, grant):
        return {"access_id": grant["id"], **{k: grant[k] for k in (
            "label", "permissions", "all_workspaces", "workspaces", "ips", "bind_first_ip", "max_uses",
            "max_sessions", "on_limit", "session_minutes")}, "expires_at": unix_iso(grant["expires_at"])}

    def issue(self, settings: GrantSettings):
        if settings.expires_at is not None and settings.expires_at <= time.time():
            raise Refused("Choose an end date in the future.")
        token = "tgwa_" + secrets.token_urlsafe(32)
        grant = {"id": secrets.token_hex(8), "sha256": digest(token), "created_at": utcnow(), "uses": 0,
                 "bound_ip": None, "last_login_at": None, "last_address": None, **settings.model_dump()}
        with self.lock:
            self.grants.append(grant)
            self.save()
        self.store.append("access.granted", self.journal_view(grant))
        LOG.info("Access %s issued (%s)", grant["label"], ", ".join(grant["permissions"]))
        return token, grant

    def change(self, grant_id, settings: GrantSettings):
        with self.lock:
            grant = self.grant(grant_id)
            if grant is None:
                raise Refused("Unknown access.")
            if settings.expires_at is not None and settings.expires_at <= time.time():
                raise Refused("Choose an end date in the future.")
            if not settings.bind_first_ip:
                grant["bound_ip"] = None
            grant.update(settings.model_dump())
            self.save()
            extra = self.live(grant_id, time.time())[:-grant["max_sessions"]] if grant["max_sessions"] else []
        for old in extra:
            self.end(old["id"], "access changed")
        self.store.append("access.changed", self.journal_view(grant))
        LOG.info("Access %s changed", grant["label"])
        return grant

    def revoke(self, grant_id):
        with self.lock:
            grant = self.grant(grant_id)
            if grant is None:
                raise Refused("Unknown access.")
            sessions = [s["id"] for s in self.sessions.values() if s["owner"] == grant_id]
        for session_id in sessions:
            self.end(session_id, "access revoked")
        with self.lock:
            self.grants = [g for g in self.grants if g["id"] != grant_id]
            self.save()
        self.store.append("access.revoked", {"access_id": grant_id, "label": grant["label"]})
        LOG.info("Access %s revoked", grant["label"])

    def set_admin(self, settings: AdminSettings):
        with self.store.transaction():
            self.store.set_setting("access_admin", settings.model_dump())
            self.store.append("access.admin_changed", settings.model_dump())
        LOG.info("Main administrator session settings changed")
        return self.admin_settings()

    # ---- views ----
    def state(self, current_session=None):
        now = time.time()
        with self.lock:
            sessions = [s for s in self.sessions.values() if s["expires"] > now]
            listed = []
            for s in sorted(sessions, key=lambda s: s["created"], reverse=True):
                grant = None if s["owner"] == "admin" else self.grant(s["owner"])
                listed.append({"id": s["id"], "access_id": s["owner"], "admin": s["owner"] == "admin",
                               "label": "Main administrator" if grant is None else grant["label"],
                               "address": s["address"], "agent": s["agent"], "requests": s["requests"],
                               "started_at": unix_iso(s["created"]), "last_seen_at": unix_iso(s["last_seen"]),
                               "expires_at": unix_iso(s["expires"]), "current": s["id"] == current_session})
            grants = []
            for g in self.grants:
                view = {k: v for k, v in g.items() if k != "sha256"}
                view["expires_at"] = unix_iso(g["expires_at"])
                view["expires_unix"] = g["expires_at"]
                view["expired"] = g["expires_at"] is not None and now >= g["expires_at"]
                view["used_up"] = g["max_uses"] is not None and g["uses"] >= g["max_uses"]
                view["sessions"] = sum(1 for s in sessions if s["owner"] == g["id"])
                grants.append(view)
        return {"grants": grants, "sessions": listed, "admin": self.admin_settings(),
                "permissions": list(PERMISSIONS)}

    def journal_listener(self, profile_id):
        """Mirror journal records of one workspace into the console (without message content)."""
        def listen(event):
            if event["kind"].startswith(QUIET_KINDS):
                return
            details = []
            if event["chat_id"] is not None:
                details.append("chat " + str(event["chat_id"]))
            payload = event["payload"] if isinstance(event["payload"], dict) else {}
            for key in ("reason", "error_type", "label", "phase"):
                if isinstance(payload.get(key), (str, int)):
                    details.append(key + " " + str(payload[key])[:120])
            JOURNAL_LOG.info("%s · #%d %s%s", self.labels(profile_id), event["seq"], event["kind"],
                             (" · " + ", ".join(details)) if details else "")
        return listen
