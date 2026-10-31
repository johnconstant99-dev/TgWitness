"""Scoped, bounded archive reads shared by integrations and analysis."""
import hashlib
import json
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from typing import Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .access import GrantSettings, Principal, Refused, check

TOOLS = ("list_workspaces", "list_chats", "search_messages", "get_message_versions",
         "get_message_context", "get_journal_event", "get_capture_status")
MAX_RESPONSE = 65536


class RateLimited(Refused):
    pass


class ConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    workspaces: dict[str, list[int] | None] = Field(min_length=1, max_length=100)
    expires_at: float

    @field_validator("name")
    @classmethod
    def name_text(cls, value):
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError("Enter a connection name.")
        return value.strip()


class ArchiveQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal[TOOLS]
    workspace: str = "default"
    chat_id: int | None = None
    message_id: int | None = Field(default=None, ge=1)
    event_seq: int | None = Field(default=None, ge=1)
    query: str = Field(default="", max_length=200)
    since: datetime | None = None
    until: datetime | None = None
    before: int | None = Field(default=None, ge=1)
    offset: int = Field(default=0, ge=0, le=100000)
    limit: int = Field(default=20, ge=1, le=50)

    @field_validator("since", "until")
    @classmethod
    def aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Include a timezone in archive dates.")
        return value

    @model_validator(mode="after")
    def period(self):
        if self.since and self.until and self.since > self.until:
            raise ValueError("The start must precede the end of the selected period.")
        return self


class Connections:
    def __init__(self, vault):
        self.vault = vault
        self.entries = vault.read("archive-access").get("connections", [])
        self.lock = threading.RLock()
        self.requests = {}

    def save(self):
        self.vault.save("archive-access", {"connections": self.entries})

    @staticmethod
    def public(entry):
        return {k: v for k, v in entry.items() if k != "sha256"} | {"tools": list(TOOLS)}

    def issue(self, settings):
        now = time.time()
        if not now + 60 <= settings.expires_at <= now + 90 * 86400:
            raise ValueError("Access must expire between one minute and 90 days from now.")
        scope = GrantSettings(label=settings.name, workspaces=settings.workspaces).workspaces
        with self.lock:
            if len(self.entries) >= 100:
                raise ValueError("At most 100 archive connections are supported.")
            token = "tgw_mcp_" + secrets.token_urlsafe(32)
            entry = {"id": secrets.token_hex(16), "name": settings.name, "workspaces": scope,
                     "expires_at": settings.expires_at, "created_at": now, "last_used_at": None,
                     "revoked_at": None, "sha256": hashlib.sha256(token.encode()).hexdigest()}
            self.entries.append(entry)
            self.save()
            return token, self.public(entry)

    def revoke(self, connection_id):
        with self.lock:
            entry = next((e for e in self.entries if e["id"] == connection_id), None)
            if entry is None:
                raise KeyError(connection_id)
            entry["revoked_at"] = time.time()
            self.requests.pop(connection_id, None)
            self.save()

    def resolve(self, token, *, count=True):
        if not token.startswith("tgw_mcp_") or len(token) > 128:
            raise Refused("Invalid archive credential.")
        digest, now = hashlib.sha256(token.encode()).hexdigest(), time.time()
        with self.lock:
            entry = next((e for e in self.entries if secrets.compare_digest(e["sha256"], digest)), None)
            if not entry or entry["revoked_at"] or entry["expires_at"] <= now:
                raise Refused("Archive access has expired or been revoked.")
            if count:
                recent = self.requests.setdefault(entry["id"], deque())
                while recent and recent[0] < now - 60:
                    recent.popleft()
                if len(recent) >= 60:
                    raise RateLimited("Archive request limit reached. Retry in one minute.")
                recent.append(now)
                if not entry["last_used_at"] or now - entry["last_used_at"] >= 60:
                    entry["last_used_at"] = now
                    self.save()
            grant = {"id": entry["id"], "workspaces": entry["workspaces"], "all_workspaces": False,
                     "permissions": ["view"], "expires_at": entry["expires_at"]}
            return Principal(False, entry["name"], grant)


def source_ref(workspace, event):
    return {"workspace": workspace, "chat_id": event["chat_id"], "message_id": event["message_id"],
            "event_seq": event["seq"], "hash": event["hash"],
            "href": "/?" + urlencode({"workspace": workspace, "event": event["seq"]}) + "#journal"}


def event_view(workspace, event):
    payload = event["payload"]
    observed = payload.get("sender_observation")
    observed = observed if isinstance(observed, dict) else {}
    def plain(value, limit):
        return value[:limit] if isinstance(value, str) else None
    digest = payload.get("media_sha256")
    text = payload.get("text") if isinstance(payload.get("text"), str) else ""
    return {"source": source_ref(workspace, event), "kind": event["kind"],
            "observed_at": event["observed_at"], "source_at": event.get("source_at"),
            "text": text[:4000], "text_truncated": len(text) > 4000,
            "sender": {"id": payload.get("sender_id") if type(payload.get("sender_id")) is int else None,
                       "name": plain(observed.get("display_name"), 256), "username": plain(observed.get("username"), 64)},
            "deletion_notice": event["kind"] == "message.deleted",
            "missing_on_recheck": event["kind"] == "message.missing_on_recheck",
            "media_sha256": digest if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest) else None,
            "untrusted_content": True}


class ArchiveReader:
    def __init__(self, registry, principal):
        self.registry, self.principal = registry, principal

    def workspace(self, query, *, chat=False):
        check(self.principal, query.workspace, ("view", "path" if chat else "filter"),
              {"chat_id": query.chat_id} if chat else {})
        entry = self.registry.entries.get(query.workspace)
        if entry is None:
            raise Refused("Workspace is unavailable.")
        return entry["app"].state

    def read(self, query):
        if query.tool == "list_workspaces":
            entries = [{"workspace": key, "name": entry["label"]} for key, entry in self.registry.entries.items()
                       if self.principal.opens(key)]
            return self.page(entries, query)
        if query.tool in ("get_message_versions", "get_message_context") and (
                query.chat_id is None or query.message_id is None):
            raise ValueError("Choose a chat and message.")
        state = self.workspace(query, chat=query.chat_id is not None)
        store, allowed = state.store, self.principal.chats(query.workspace)
        if query.tool == "list_chats":
            targets = store.archive_chats(query.offset, query.limit + 1, allowed)
            entries = [{"chat_id": t["chat_id"], "title": t["title"], "kind": t["kind"],
                        "enabled": bool(t["enabled"])} for t in targets
                       if allowed is None or t["chat_id"] in allowed]
            return {"workspace": query.workspace, "items": entries[:query.limit],
                    "next_offset": query.offset + query.limit if len(entries) > query.limit else None}
        if query.tool == "get_capture_status":
            c = state.collector
            return {"workspace": query.workspace, "running": c.running,
                    "scope": sorted(allowed) if allowed is not None else "workspace",
                    "completeness": "Unknown. Absence from the archive does not establish absence in Telegram.",
                    "gaps": self.events(store, query, allowed, kind="coverage"),
                    "workspace_gaps_visible": allowed is None}
        if query.tool == "get_journal_event":
            if query.event_seq is None:
                raise ValueError("Choose an event sequence.")
            events = store.events(before=query.event_seq + 1, limit=1, chat_ids=allowed, timeout_s=3)
            if not events or events[0]["seq"] != query.event_seq:
                raise Refused("Record is unavailable to this access.")
            if query.chat_id is not None and events[0]["chat_id"] != query.chat_id:
                raise Refused("Record is outside the selected chat.")
            return event_view(query.workspace, events[0])
        return self.events(store, query, allowed)

    @staticmethod
    def page(entries, query):
        end = query.offset + query.limit
        return {"items": entries[query.offset:end], "next_offset": end if end < len(entries) else None}

    def events(self, store, query, allowed, kind=None):
        versions = query.tool == "get_message_versions"
        context = query.tool == "get_message_context"
        records = store.events(chat_id=query.chat_id, message_id=query.message_id if versions else None,
                               before=query.before, limit=query.limit + 1, search=query.query or None,
                               chat_ids=allowed, kind=kind, since=query.since, until=query.until, timeout_s=3,
                               text_only=True, message_only=kind is None,
                               message_min=max(1, query.message_id - 10) if context else None,
                               message_max=query.message_id + 10 if context else None)
        items = [event_view(query.workspace, e) for e in records[:query.limit]]
        while len(json.dumps(items, ensure_ascii=False).encode()) > MAX_RESPONSE - 2048:
            items.pop()
        next_before = items[-1]["source"]["event_seq"] if items and len(records) > len(items) else None
        return {"items": items, "next_before": next_before, "untrusted_content": True,
                "coverage": "Only saved observations are included; edits and deletion notices are separate records."}
