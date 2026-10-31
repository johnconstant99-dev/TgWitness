import asyncio
import base64
import hashlib
import json
import shutil
import time
import secrets
from contextlib import suppress
from datetime import datetime, timezone
from functools import wraps

from collections import deque

from telethon import events, utils
from telethon.errors import SessionPasswordNeededError, FloodWaitError, InvalidBufferError, RPCError
from telethon.extensions import BinaryReader
from telethon.sessions import StringSession
from telethon.tl import functions, types

from . import api_pool
from . import chat_export
from . import keyboard
from . import message_content
from . import replica
from . import tuning
from .history import History
from .account_import import validate_string
from .telegram_client import WitnessClient
from .workers import complete_in_thread
from .store import canonical, utcnow
from .evidence import retain_checkpoint
from .netclient import RouteError, proxy_address
from .network import NetworkConfig, NoRoute, RoutePolicy, saved_route
from .proxy_catalog import NoProxyAvailable, ProxyPool, PublicCatalog
from .monitoring import capture_settings, media_kind, monitoring_settings
from .scope import allowed, folder_rule, in_folder, kind_of, recheck_settings, scope_settings
from .verify import fingerprint


STORAGE_RECHECK_SECONDS = 30


ROUTE_ERRORS = (OSError, TimeoutError, asyncio.IncompleteReadError, InvalidBufferError)
EXPOSURE_MEANING = {
    "hide": "Telegram is contacted only through a proxy; requests outside Telegram only through a proxy set for them.",
    "fallback": "Automatic MTProxy; after the set minutes without a working proxy Telegram is contacted directly "
                "and sees this server's address until a listed proxy answers again.",
    "tunnel": "Direct connections are allowed: Telegram and other services may see this server's address "
              "(or that of the tunnel or VPN it uses).",
}
MEMBERSHIP_ACTIONS = (types.MessageActionChatAddUser, types.MessageActionChatDeleteUser,
                      types.MessageActionChatJoinedByLink, types.MessageActionChatJoinedByRequest)


def recovered_source(update):
    """Telethon hands over messages fetched through getDifference (after a gap or restart) with pts=0."""
    return "update_recovery" if getattr(update, "pts", None) == 0 else None


def plain(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"bytes_base64": base64.b64encode(value).decode()}
    if hasattr(value, "to_dict"):
        return plain(value.to_dict())
    if isinstance(value, dict):


        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


def date_string(value):
    return value.isoformat() if value else None


def buttons_of(message):
    """The message's buttons in the same form as saved records (keyboard.keyboard of raw.reply_markup)."""
    return keyboard.keyboard(plain(getattr(message, "reply_markup", None)))


SENDER_FLAGS = ("bot", "scam", "fake", "premium", "verified", "restricted", "deleted")


def sender_observation(sender):
    if not sender:
        return None
    observed = {
        "id": getattr(sender, "id", None), "username": getattr(sender, "username", None),
        "display_name": utils.get_display_name(sender),
        "meaning": "cached Telegram profile at observation; names are mutable",
    }
    flags = {name: getattr(sender, name) for name in SENDER_FLAGS if isinstance(getattr(sender, name, None), bool)}
    if flags:
        observed["flags"] = flags
    photo_id = getattr(getattr(sender, "photo", None), "photo_id", None)
    if isinstance(photo_id, int):
        observed["photo_id"] = photo_id
    return observed


def describe_message(message):
    action = getattr(message, "action", None)
    sender = getattr(message, "sender", None)
    return {
        "text": message.message or "",
        "sender_id": message.sender_id,
        "sender_observation": sender_observation(sender),
        "outgoing": bool(getattr(message, "out", False)),
        "reply_to_message_id": getattr(message, "reply_to_msg_id", None),
        "grouped_id": getattr(message, "grouped_id", None),
        "sent_at": date_string(message.date),
        "edited_at": date_string(getattr(message, "edit_date", None)),
        "has_media": bool(getattr(message, "media", None)),
        "reaction_visibility": "partial snapshot; identities may be omitted",
        "service_action": type(action).__name__ if action else None,
        "raw": plain(message),
    }


def message_record(message):
    """A Telegram-export-style record for one message: no access hashes or sessions."""
    sender = getattr(message, "sender", None)
    action = getattr(message, "action", None)
    media = getattr(message, "media", None)
    record = {
        "id": message.id,
        "type": "service" if action else "message",
        "date": date_string(message.date),
        "date_unixtime": int(message.date.timestamp()) if message.date else None,
        "edited": date_string(getattr(message, "edit_date", None)),
        "from": utils.get_display_name(sender) if sender else None,
        "from_id": message.sender_id,
        "from_username": getattr(sender, "username", None),
        "reply_to_message_id": getattr(message, "reply_to_msg_id", None),
        "text": message.message or "",
    }
    if action:
        record["action"] = type(action).__name__
    if media:
        record["media_type"] = type(media).__name__
    return record


class Collector:
    def __init__(self, store, vault, client_factory=WitnessClient):
        self.store, self.vault = store, vault
        self.client_factory = client_factory
        self.client = None
        self.login_client = None
        self.pending_credentials = None
        self.pending_account_id = None
        self.pending_key_origin = None
        self.pinned_proxy = None
        self.qr_task = None
        self.qr_state = None
        self.export_task = None
        self.export_state = None
        self.export_path = None
        self.export_claim = None
        self.people = {}
        self.avatar_lock = asyncio.Lock()
        self.avatar_failures = {}
        self.running = False
        self.phase = "offline"
        self.last_error = None
        self.pending_phone = None
        self.phone_hash = None
        self.dialog_cache = {}
        self.watchdog = None
        self.media_wakeup = asyncio.Event()
        self.media_worker = None
        self.last_heartbeat = None
        self.source_status = {}
        self.last_update_at = None
        self.max_handler_ms = 0
        self.run_id = None
        self.account_guard = None
        self.reconnect_attempts = 0
        self.next_reconnect_at = 0
        self.proxy_pool = None
        self.auto_route = None
        self.route_drops = deque()
        self.direct_fallback = False
        self.unavailable_since = None
        self.pool_retry_at = 0
        self.target_ids = set()
        self.known_ids = set()
        self.target_revision = -1
        self.folders = {}
        self.scope_rejected = set()
        self.scope_refreshed_at = 0
        self.reconciler = None
        self.intake = asyncio.Queue()
        self.intake_worker = None
        self.recheck_wakeup = asyncio.Event()
        self.recheck_state = None
        self.resumed_state_at = None
        self.buffering = False
        self.buffered = []
        self.buffer_overflow = False
        self.buffer_limit = tuning.BY_KEY["startup_buffer"].default
        self.storage_low = False
        self.history = History(self)

    def status(self):
        credentials = self.vault.read("credentials")
        return {
            "network": self.route_status(),
            "phase": self.phase, "running": self.running,
            "connected": bool(self.client and self.client.is_connected()),
            "has_session": bool(credentials.get("session")),
            "has_api_credentials": bool(credentials.get("api_id") and credentials.get("api_hash")),
            "builtin_api": credentials.get("api_id") is None or credentials.get("api_id") in api_pool.POOL_IDS,
            "api_pool_size": len(api_pool.POOL) - len(api_pool.rejected),
            "account": self.store.get_setting("account", None),
            "last_error": self.last_error, "last_heartbeat": self.last_heartbeat,
            "media_pending": sum(n for s, n in self.store.media_stats().items()
                                 if s in ("queued", "running", "retry")),
            "media_jobs": self.store.media_stats(),
            "oldest_pending_media_at": self.store.media_oldest(),
            "source_status": self.source_status,
            "last_update_at": self.last_update_at,
            "max_handler_ms": round(self.max_handler_ms, 2),
            "rpc_backoff_until": self.store.get_setting("rpc_backoff_until", 0),
            "disk_free_bytes": shutil.disk_usage(self.store.root).free,
            "run_id": self.run_id,
            "reconnect_attempts": self.reconnect_attempts,
            "next_reconnect_at": self.next_reconnect_at,
            "chat_export": dict(self.export_state) if self.export_state else None,
            "recheck": self.recheck_state,
            "storage_low": self.storage_low,
            "media_min_free_bytes": self.param("media_min_free_mb") * 1024**2,
            **recheck_settings(self.store),
            "scope": scope_settings(self.store),
            "update_state_resumed_from": self.resumed_state_at,
        }

    def param(self, key):
        return tuning.value(self.store, key)

    def refresh_targets(self):
        if self.target_revision != self.store.targets_revision:
            targets = self.store.targets()
            self.target_ids = {t["chat_id"] for t in targets if t["enabled"]}
            self.known_ids = {t["chat_id"] for t in targets}
            self.target_revision = self.store.targets_revision

    def selected(self, chat_id):
        self.refresh_targets()
        return chat_id in self.target_ids

    async def covers(self, chat_id, entity=None):
        """Whether updates from this chat are recorded; folder and account modes add new chats here."""
        if chat_id is None:
            return False
        if self.selected(chat_id):
            return True
        scope = scope_settings(self.store)
        if scope["mode"] == "selected" or chat_id in scope["exclude"]:
            return False
        if chat_id in self.known_ids or chat_id in self.scope_rejected:
            return False
        entry = self.dialog_cache.get(chat_id) or {}
        entity = entry.get("entity") or entity
        if entity is None:
            entity = await self.lookup_entity(chat_id)
        kind = entry.get("kind") or kind_of(entity)
        if kind is None:
            return False
        rule = self.folder_for(scope)
        if not allowed(scope, kind) or (scope["mode"] == "folder" and (
                rule is None or not in_folder(rule, chat_id, kind, entity, entry.get("archived", False)))):
            self.scope_rejected.add(chat_id)
            return False
        self.discover(chat_id, kind, entity, scope)
        return True

    async def lookup_entity(self, chat_id):
        get_entity = getattr(self.client, "get_entity", None)
        if not get_entity:
            return None
        try:

            return await asyncio.wait_for(get_entity(chat_id), 10)
        except Exception:
            return None

    def folder_for(self, scope):
        if scope["mode"] != "folder":
            return None
        return self.folders.get(scope["folder_id"])

    def discover(self, chat_id, kind, entity, scope):
        title = (utils.get_display_name(entity) if entity is not None else "") or str(chat_id)
        with self.store.transaction():
            self.store.set_target(chat_id, title, kind, True, origin="scope", priority=0)
            self.store.append("source.discovered", {
                "title": title, "kind": kind, "mode": scope["mode"],
                "folder": (self.folder_for(scope) or {}).get("title"),
                "coverage": "recorded from this record on; earlier history of this chat is not fetched"}, chat_id)
        self.source_status[str(chat_id)] = {"state": "discovered", "checked_at": utcnow(),
                                            "meaning": "Added automatically by the observation scope.",
                                            "visibility": "unknown", "role": "unknown"}
        if scope["new_chats"]["profile"] or scope["new_chats"]["history"]:
            self.intake.put_nowait((chat_id, entity))

    async def intake_loop(self):
        """New chats and bots: save their profile and the messages visible when they appeared."""
        while self.running:
            chat_id, entity = await self.intake.get()
            options = scope_settings(self.store)["new_chats"]
            while self.running and time.time() < self.store.get_setting("rpc_backoff_until", 0):
                await asyncio.sleep(1)
            try:
                entity = entity or await self.lookup_entity(chat_id)
                if entity is None:
                    raise ValueError("chat_entity_unavailable")
                if options["profile"]:
                    await self.capture_profile(chat_id, entity)
                if options["history"] and self.selected(chat_id):
                    await self.snapshot(chat_id, options["history"], entity=entity, origin="new_chat")
            except asyncio.CancelledError:
                raise
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                self.store.append("telegram.backoff", {"operation": "new chat intake", "retry_after_seconds": exc.seconds})
                self.intake.put_nowait((chat_id, entity))
            except Exception as exc:
                self.store.append("collector.error", {
                    "operation": "new chat intake", "error_type": type(exc).__name__,
                    "coverage": "messages of this chat are still recorded live; its profile or earlier "
                                "messages may be missing"}, chat_id)

    async def capture_profile(self, chat_id, entity):
        """What Telegram shows about a chat or bot now: description, bot commands, members, invite link."""
        info = {}
        if isinstance(entity, types.User):
            full = (await asyncio.wait_for(self.client(functions.users.GetFullUserRequest(entity)), 30)).full_user
            info["about"] = getattr(full, "about", None)
            info["common_chats"] = getattr(full, "common_chats_count", None)
            bot = getattr(full, "bot_info", None)
            if bot:
                info["bot"] = {"description": getattr(bot, "description", None),
                               "commands": [{"command": c.command, "description": c.description}
                                            for c in getattr(bot, "commands", None) or []],
                               "menu_button": plain(getattr(bot, "menu_button", None))}
        elif isinstance(entity, types.Channel):
            full = (await asyncio.wait_for(self.client(functions.channels.GetFullChannelRequest(entity)), 30)).full_chat
            info.update(about=getattr(full, "about", None), participants=getattr(full, "participants_count", None),
                        linked_chat_id=getattr(full, "linked_chat_id", None))
        elif isinstance(entity, types.Chat):
            full = (await asyncio.wait_for(self.client(functions.messages.GetFullChatRequest(entity.id)), 30)).full_chat
            info.update(about=getattr(full, "about", None),
                        participants=len(getattr(getattr(full, "participants", None), "participants", None) or []))
        else:
            raise ValueError("unsupported_chat_type")
        invite = getattr(getattr(full, "exported_invite", None), "link", None)
        if invite:
            info["invite_link"] = invite
        if getattr(full, "bot_info", None) and not isinstance(entity, types.User):
            info["bots"] = [getattr(b, "user_id", None) for b in full.bot_info]
        return self.store.append("source.profile", {
            "title": utils.get_display_name(entity), "kind": kind_of(entity), "username": getattr(entity, "username", None),
            **info, "raw": plain(full),
            "meaning": "what Telegram returned to this account about the chat at this time; descriptions are mutable"},
            chat_id)

    async def save_profile(self, chat_id):
        """Panel action: save the current profile of a source now."""
        await self.restore()
        entity = self.dialog_cache.get(chat_id, {}).get("entity") or await self.lookup_entity(chat_id)
        if entity is None:
            raise ValueError("Telegram did not return this chat. Load chats and try again.")
        return await self.capture_profile(chat_id, entity)

    async def apply_scope(self, refresh=True):
        """Bring sources in line with the scope: add matching chats, pause chats that no longer match.

        Chosen-chats mode pauses every automatically added source. Excluded chats are paused in every
        mode. Returns what changed; the change is recorded in the signed journal.
        """
        scope = scope_settings(self.store)
        self.scope_rejected = set()
        if refresh or (scope["mode"] != "selected" and not self.dialog_cache):
            await self.dialogs()
        self.scope_refreshed_at = time.time()
        excluded, rule = set(scope["exclude"]), self.folder_for(scope)
        if scope["mode"] == "folder" and rule is None:
            raise ValueError("The chosen Telegram folder was not found. Choose a folder again.")
        added, paused, resumed = [], [], []
        known = {t["chat_id"]: t for t in self.store.targets()}
        with self.store.transaction():
            for chat_id, target in known.items():
                if chat_id in excluded and target["enabled"]:
                    self.store.set_target(chat_id, target["title"], target["kind"], False)
                    paused.append(chat_id)
                elif target["origin"] == "scope":
                    entry = self.dialog_cache.get(chat_id)
                    if (scope["mode"] == "selected" or chat_id in excluded
                            or not allowed(scope, entry["kind"] if entry else target["kind"])):
                        wanted = False
                    elif scope["mode"] == "account":
                        wanted = True
                    elif entry:
                        wanted = in_folder(rule, chat_id, entry["kind"], entry["entity"], entry["archived"])
                    elif rule.get("all") or chat_id in rule["include"] or chat_id in rule["exclude"]:
                        wanted = in_folder(rule, chat_id, target["kind"])
                    else:

                        wanted = bool(target["enabled"])
                    if bool(target["enabled"]) != wanted:
                        self.store.set_target(chat_id, target["title"], target["kind"], wanted)
                        (resumed if wanted else paused).append(chat_id)
            if scope["mode"] != "selected":
                for chat_id, entry in self.dialog_cache.items():
                    if chat_id in known or chat_id in excluded or not allowed(scope, entry["kind"]):
                        continue
                    if scope["mode"] == "folder" and not in_folder(rule, chat_id, entry["kind"], entry["entity"],
                                                                   entry["archived"]):
                        continue
                    self.store.set_target(chat_id, entry["title"], entry["kind"], True, origin="scope", priority=0)
                    added.append(chat_id)
            if added or paused or resumed:
                self.store.append("scope.applied", {
                    "mode": scope["mode"], "folder": (rule or {}).get("title"), "types": scope["types"],
                    "added": [{"chat_id": c, "title": self.dialog_cache[c]["title"], "kind": self.dialog_cache[c]["kind"]}
                              for c in added],
                    "paused": paused, "resumed": resumed, "excluded": sorted(excluded),
                    "dialogs_inspected": len(self.dialog_cache),
                    "coverage": "chats beyond the first " + str(self.param("dialog_limit")) + " dialogs are added when they "
                                "become active; earlier history of added chats is not fetched"})
        return {"added": len(added), "paused": len(paused), "resumed": len(resumed)}

    def make_client(self, api_id, api_hash, session=""):
        device = api_pool.DESKTOP_DEVICE if api_id == api_pool.DESKTOP_ID else {}
        string_session = StringSession(session)
        self.resumed_state_at = self.load_update_state(string_session)


        client = self.client_factory(string_session, api_id, api_hash,
                                     sequential_updates=True, flood_sleep_threshold=0,
                                     request_retries=self.param("telegram_request_retries"),
                                     connection_retries=self.param("telegram_connection_retries"),
                                     timeout=self.param("telegram_timeout_seconds"), catch_up=True,
                                     **device, **self.route_options())
        for handler, builder in ((self.on_new, events.NewMessage()),
                                 (self.on_edit, events.MessageEdited()),
                                 (self.on_delete, events.MessageDeleted()),
                                 (self.on_raw, events.Raw())):
            @wraps(handler)
            async def active_client_only(update, handler=handler):

                if client is not self.client:
                    return
                if self.running:
                    await handler(update)
                elif self.buffering:

                    if len(self.buffered) < self.buffer_limit:
                        self.buffered.append((handler, update))
                    else:
                        self.buffer_overflow = True
            client.add_event_handler(active_client_only, builder)
        client.route_id = self.current_route_id() if self.automatic() else None
        return client

    def save_update_state(self):
        """Persist Telegram's update position (pts) so a restart can catch up on what it missed.

        StringSession keeps this state only in memory; Telethon refreshes it in the session
        about once a minute and on disconnect. Channel access hashes are kept with it because
        Telethon cannot request a channel's missed updates without them.
        """
        session = getattr(self.client, "session", None)
        account = (self.store.get_setting("account", {}) or {}).get("id")
        if account is None or not hasattr(session, "get_update_states"):
            return
        record = {"account_id": account, "saved_at": utcnow(), "account": None, "channels": []}
        for entity_id, state in list(session.get_update_states()):
            if entity_id == 0:
                record["account"] = {"pts": state.pts, "qts": state.qts, "seq": state.seq,
                                     "date": int(state.date.timestamp())}
                continue
            try:
                peer = session.get_input_entity(utils.get_peer_id(types.PeerChannel(entity_id)))
            except (ValueError, TypeError):
                continue
            if isinstance(peer, types.InputPeerChannel):
                record["channels"].append({"id": entity_id, "pts": state.pts, "access_hash": peer.access_hash})
        if record["account"] or record["channels"]:
            self.vault.save("update_state", record)

    def persist_update_state(self):
        try:
            self.save_update_state()
        except Exception as exc:
            self.store.append("collector.error", {"operation": "save update state", "error_type": type(exc).__name__,
                                                 "coverage": "a restart may not catch up on missed updates"})

    def load_update_state(self, session):
        """Load the saved update position into a new session; returns when it was saved, or None."""
        saved = self.vault.read("update_state")
        account = (self.store.get_setting("account", {}) or {}).get("id")
        if not saved or account is None or saved.get("account_id") != account:
            return None
        try:
            if saved.get("account"):
                a = saved["account"]
                session.set_update_state(0, types.updates.State(
                    pts=a["pts"], qts=a["qts"], date=datetime.fromtimestamp(a["date"], timezone.utc),
                    seq=a["seq"], unread_count=0))
            now = datetime.now(timezone.utc)
            for channel in saved.get("channels", []):
                session.set_update_state(channel["id"], types.updates.State(
                    pts=channel["pts"], qts=0, date=now, seq=0, unread_count=0))
            session.process_entities([types.InputPeerChannel(c["id"], c["access_hash"])
                                      for c in saved.get("channels", [])])
        except (KeyError, TypeError, ValueError):
            return None
        return saved.get("saved_at")

    async def cancel_login(self):
        task, self.qr_task = self.qr_task, None
        self.qr_state = None
        if task and task is not asyncio.current_task():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        candidate, self.login_client = self.login_client, None
        self.pending_phone = self.phone_hash = self.pending_credentials = None
        self.pending_account_id = None
        if candidate and candidate is not self.client:
            await candidate.disconnect()

    async def sign_out(self):
        """End this workspace's Telegram session and forget it here. The journal, sources, settings and
        signing key stay; the workspace still belongs to its account, so only that account can connect again."""
        if self.running:
            raise ValueError("Pause observation before signing out.")
        await self.cancel_login()
        credentials = self.vault.read("credentials")
        if not credentials.get("session"):
            raise ValueError("No Telegram account is connected.")
        client, self.client = self.client, None
        ended, error = False, None
        try:
            if client is None:
                await self.ensure_route()
                client = self.make_client(credentials["api_id"], credentials["api_hash"], credentials["session"])
            if not client.is_connected():
                await self.connect_client(client)

            ended = bool(await asyncio.wait_for(client.log_out(), 25))
        except Exception as exc:
            error = type(exc).__name__
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass
        self.vault.save("credentials", {k: v for k, v in credentials.items() if k != "session"})
        self.dialog_cache = {}
        self.phase, self.last_error = "offline", None
        account = self.store.get_setting("account", None) or {}
        self.store.append("account.signed_out", {
            "account_id": account.get("id"), "telegram_session_ended": ended,
            **({"error_type": error} if error else {}),
            "kept": "journal, sources, settings and signing key; only the same account can connect again"})
        return {"telegram_session_ended": ended, **({"error_type": error} if error else {})}

    def network_config(self):
        return saved_route(self.vault.read("network"))

    def automatic(self):
        return self.network_config().kind == "mtproxy_auto"

    def pool(self):
        if self.proxy_pool is None:
            self.proxy_pool = ProxyPool(PublicCatalog(self.store.root))
        return self.proxy_pool

    @property
    def route_owner(self):
        return str(self.store.root)


    def route_policy(self):
        """This workspace's IP mode; a workspace that chose a direct route before the modes existed keeps it."""
        saved = self.store.get_setting("route_policy", None)
        if saved is None:
            return RoutePolicy(exposure="tunnel" if self.network_config().kind == "direct" else "hide").model_dump()
        return RoutePolicy.model_validate(saved).model_dump()

    def outside_proxy(self):
        saved = self.vault.read("outside_proxy")
        return saved_route(saved) if saved else None

    def outside_route(self):
        """The route for requests outside Telegram (timestamps, notifications, off-site copy, source check,
        proxy lists): the proxy set for them, this workspace's SOCKS5/HTTP route, or direct where the IP mode allows."""
        policy = self.route_policy()
        if not policy["outside_enabled"]:
            return NoRoute(RouteError("Requests outside Telegram are turned off for this workspace. "
                                      "Turn them on under Account → Connection settings."))
        proxy = self.outside_proxy()
        if proxy:
            return proxy
        network = self.network_config()
        if network.kind in ("socks5", "http"):
            return network
        if policy["exposure"] == "hide":
            return NoRoute(RouteError("Hide IP mode sends requests outside Telegram only through a proxy. Set a "
                                      "SOCKS5 or HTTP proxy for them under Account → Connection settings."))
        return NetworkConfig(kind="direct")

    def policy_state(self):
        proxy, route = self.outside_proxy(), self.outside_route()
        return {**self.route_policy(), "outside_proxy": proxy.public() if proxy else None,
                "outside_route": route.kind, "outside_problem": str(route.error) if route.kind == "none" else None,
                "direct_fallback": self.direct_fallback}

    async def set_route_policy(self, policy, outside=None, remove_outside=False):
        if policy.exposure != "tunnel" and self.network_config().kind == "direct":
            raise ValueError("This workspace connects to Telegram directly. Choose a proxy route first, "
                             "then change the IP mode.")
        if outside is not None and outside.kind not in ("socks5", "http"):
            raise ValueError("Requests outside Telegram use a SOCKS5 or HTTP proxy.")
        if outside is not None:
            self.vault.save("outside_proxy", outside.model_dump())
        elif remove_outside:
            self.vault.save("outside_proxy", {})
        proxy = self.outside_proxy()
        with self.store.transaction():
            self.store.set_setting("route_policy", policy.model_dump())
            self.store.append("network.policy_changed", {
                **policy.model_dump(), "outside_proxy": proxy.receipt() if proxy else None,
                "outside_route": self.outside_route().kind, "meaning": EXPOSURE_MEANING[policy.exposure]})
        if policy.exposure == "hide" and self.direct_fallback:

            self.direct_fallback = False
            if self.client:
                await self.client.disconnect()
        return self.policy_state()


    def share(self):
        return self.param("proxy_max_accounts")

    def current_route_id(self):
        return "direct" if self.direct_fallback else self.auto_route[0] if self.auto_route else None

    def route_options(self):
        """Telethon connection options of this workspace's route; automatic mode uses its chosen proxy."""
        if not self.automatic():
            config = self.network_config()
            if self.pinned_proxy and self.pinned_proxy[0] == config.host:
                config = config.model_copy(update={"host": self.pinned_proxy[1]})
            return config.client_options()
        if self.direct_fallback:
            return {}
        if not self.auto_route:
            raise NoProxyAvailable("No automatic MTProxy has been chosen yet.")
        return self.auto_route[1].client_options()

    def route_receipt(self):
        receipt = self.network_config().receipt(self.direct_fallback)
        if receipt["kind"] == "mtproxy_auto":
            receipt["proxy_id"] = self.auto_route[0] if self.auto_route else None
        receipt["exposure"] = self.route_policy()["exposure"]
        return receipt

    def route_status(self):
        public = self.network_config().public(self.direct_fallback)
        if public["kind"] == "mtproxy_auto":
            public.update(self.pool().describe(self.route_owner))
        public["exposure"] = self.route_policy()["exposure"]
        return public

    def fallback_due(self):
        """Whether the IP mode now lets this workspace reach Telegram directly, as no listed proxy answers."""
        exposure = self.route_policy()["exposure"]
        if exposure == "hide":
            return False
        if self.unavailable_since is None:
            self.unavailable_since = time.time()
        wait = 0 if exposure == "tunnel" else self.param("proxy_fallback_minutes") * 60
        return time.time() - self.unavailable_since >= wait

    def use_direct(self, reason):
        self.pool_retry_at = time.time() + 120
        self.pool().waiting.add(self.route_owner)
        if self.direct_fallback:
            return
        self.direct_fallback, self.auto_route = True, None
        self.store.append("network.route_fallback", {
            "kind": "mtproxy_auto", "to": "direct", "reason": reason, "exposure": self.route_policy()["exposure"],
            "without_proxy_seconds": round(time.time() - (self.unavailable_since or time.time())),
            "fallback_to_direct": True,
            "meaning": "No listed MTProxy answered; Telegram sees this server's address until one answers again."})

    async def ensure_route(self):
        """Automatic mode: choose this workspace's proxy (the same one as before while it works); where the
        IP mode allows, connect directly while no listed proxy answers."""
        if not self.automatic():
            await self.pin_proxy()
            return
        if self.auto_route:
            return
        if self.direct_fallback and time.time() < self.pool_retry_at:
            return
        try:
            alias, route = await self.pool().acquire(
                self.route_owner, preferred=self.store.get_setting("auto_route", None), share=self.share())
        except NoProxyAvailable:
            if self.direct_fallback or self.fallback_due():
                self.use_direct("no_working_proxy")
                return
            raise
        returned = self.direct_fallback
        self.direct_fallback, self.unavailable_since = False, None
        self.pool().waiting.discard(self.route_owner)
        self.auto_route = (alias, route)
        with self.store.transaction():
            self.store.set_setting("auto_route", alias)
            self.store.set_setting("auto_route_since", time.time())
            self.store.append("network.route_assigned", {
                "kind": "mtproxy_auto", "proxy_id": alias, "source": self.proxy_source(alias),
                **({"returned_from_direct": True} if returned else {}), "fallback_to_direct": False,
                "meaning": "Telegram traffic of this account goes through this listed MTProxy until it fails."})

    async def pin_proxy(self):
        """A listed proxy is resolved and checked once here, and Telethon connects to that address: a name
        cannot later resolve inside this machine or its network unless the main administrator set it."""
        config = self.network_config()
        self.pinned_proxy = None
        if config.kind in ("socks5", "http", "mtproxy"):
            try:
                self.pinned_proxy = (config.host, await proxy_address(config))
            except RouteError as exc:
                raise ValueError(str(exc)) from None

    async def align(self, client):
        """Point a client at the workspace's current automatic route before it connects."""
        wanted = self.current_route_id()
        if wanted and getattr(client, "route_id", None) != wanted:
            await client.switch_route(self.route_options())
            client.route_id = wanted

    def proxy_source(self, alias):
        try:
            return self.pool().entries()[1][alias]["label"]
        except (KeyError, ValueError):
            return None

    def record_route(self, alias, route, old, reason, exc=None, cooldown=0):
        self.auto_route, self.unavailable_since = (alias, route), None
        with self.store.transaction():
            self.store.set_setting("auto_route", alias)
            self.store.set_setting("auto_route_since", time.time())
            self.store.append("network.route_rotated", {
                "kind": "mtproxy_auto", "from_proxy_id": old, "to_proxy_id": alias,
                "source": self.proxy_source(alias), "reason": reason,
                **({"error_type": type(exc).__name__} if exc else {}),
                "previous_cooldown_seconds": cooldown, "fallback_to_direct": False})

    async def rotate_route(self, client, reason, exc=None):
        """Automatic mode: rest the client's failing proxy and move this account to the next working one;
        where the IP mode allows, connect directly when none answers."""
        old = getattr(client, "route_id", None)
        if old == "direct" or (self.auto_route and self.auto_route[0] != old):
            return
        cooldown = self.pool().degrade(old, type(exc).__name__ if exc else reason,
                                       self.param("proxy_cooldown_minutes") * 60,
                                       self.param("proxy_cooldown_max_hours") * 3600) if old else 0
        self.auto_route = None
        self.route_drops.clear()
        try:
            alias, route = await self.pool().acquire(self.route_owner, avoid={old} if old else (), share=self.share())
        except NoProxyAvailable:
            fallback = self.fallback_due()
            self.store.append("network.route_unavailable", {
                "kind": "mtproxy_auto", "previous_proxy_id": old, "reason": reason,
                **({"error_type": type(exc).__name__} if exc else {}), "fallback_to_direct": fallback,
                "meaning": "No listed MTProxy answered; Telegram is contacted directly, as the IP mode allows."
                           if fallback else "No listed MTProxy answered; Telegram is not contacted until one does."})
            if fallback:
                self.use_direct("no_working_proxy")
                return
            with suppress(Exception):
                await client.disconnect()
            raise
        self.record_route(alias, route, old, reason, exc, cooldown)

    async def planned_rotation(self):
        """Move to another working proxy after the set hours although the current one works."""
        hours, since = self.param("proxy_rotate_hours"), self.store.get_setting("auto_route_since", None)
        if not hours or not self.auto_route or self.direct_fallback or since is None or time.time() - since < hours * 3600:
            return
        old = self.auto_route[0]
        try:
            alias, route = await self.pool().acquire(self.route_owner, avoid={old}, share=self.share())
        except NoProxyAvailable:
            self.pool().keep(self.route_owner, old)
            self.store.set_setting("auto_route_since", time.time())
            return
        self.record_route(alias, route, old, "planned")
        await self.client.disconnect()

    async def review_route(self):
        """Automatic mode while connected: leave a direct fallback once a listed proxy answers again,
        and switch proxies on the planned schedule."""
        if self.direct_fallback:
            if time.time() >= self.pool_retry_at and (self.route_policy()["exposure"] == "hide"
                                                      or self.pool().available(self.route_owner, self.share())):
                self.pool_retry_at = 0
                await self.client.disconnect()
            return
        await self.planned_rotation()

    async def connect_client(self, client):
        """Connect; in automatic mode a proxy that fails is set aside and the next one is tried."""
        attempts = self.param("proxy_connect_attempts")
        for attempt in range(1, attempts + 1):
            automatic = self.automatic()
            if automatic:
                await self.ensure_route()
                await self.align(client)
            try:
                await asyncio.wait_for(client.connect(), 25)
            except RPCError:
                raise
            except Exception as exc:


                proxied = automatic and getattr(client, "route_id", None) not in (None, "direct")
                if proxied:
                    await self.rotate_route(client, "connect_failed", exc)
                if not proxied or attempt == attempts:
                    if isinstance(exc, ROUTE_ERRORS):
                        raise
                    raise ConnectionError("Telegram transport failed: " + type(exc).__name__) from exc
            else:
                if automatic and not self.direct_fallback:
                    self.pool().succeeded(client.route_id)
                return

    async def set_network(self, config):
        if self.running:
            raise ValueError("Pause observation before changing the Telegram route.")
        if config.kind == "direct" and self.route_policy()["exposure"] != "tunnel":
            raise ValueError("A direct route is allowed only in the mode for a server behind a tunnel or VPN. "
                             "Change the IP mode first.")

        await self.cancel_login()
        if self.client:
            await self.client.disconnect()
        self.client = None
        self.dialog_cache = {}
        self.pool().release(self.route_owner)
        self.pool().waiting.discard(self.route_owner)
        self.auto_route, self.direct_fallback, self.unavailable_since = None, False, None
        self.pinned_proxy = None
        self.vault.save("network", config.model_dump())
        with self.store.transaction():
            self.store.set_setting("resume", False)
            self.store.set_setting("auto_route", None)
            self.store.append("network.changed", config.receipt())
        self.phase = "offline"
        self.last_error = None
        return config.public()

    async def test_network(self):

        credentials = self.vault.read("credentials")
        api_id, api_hash = ((credentials["api_id"], credentials["api_hash"]) if credentials.get("api_id")
                            else api_pool.login_order()[0])
        client = None
        try:
            await self.ensure_route()
            client = self.make_client(api_id, api_hash)
            await self.connect_client(client)
            self.store.append("network.probe", {**self.route_receipt(), "connected": True,
                              "meaning": "Telegram transport connected; capture completeness is not tested"})
            return {"connected": True, "route": self.route_status()}
        except Exception as exc:
            self.store.append("network.probe", {**self.route_receipt(), "connected": False,
                                               "error_type": type(exc).__name__})
            raise
        finally:
            if client:
                await client.disconnect()

    def login_pairs(self, api_id, api_hash):
        """An entered, imported or own saved pair is used as is; otherwise rotate through the built-in pool."""
        if api_id is None and api_hash is None:
            saved = self.vault.read("credentials")
            api_id, api_hash = saved.get("api_id"), saved.get("api_hash")
        if api_id and api_hash and api_id not in api_pool.POOL_IDS:
            return [(api_id, api_hash)]
        return api_pool.login_order((api_id, api_hash) if api_id and api_hash else None)

    async def with_api_pair(self, api_id, api_hash, attempt):
        pairs = self.login_pairs(api_id, api_hash)
        for number, (pair_id, pair_hash) in enumerate(pairs, 1):
            try:
                return await attempt(pair_id, pair_hash)
            except api_pool.PAIR_ERRORS:
                api_pool.reject(pair_id)
                await self.cancel_login()
                self.phase = "ready" if self.vault.read("credentials").get("session") else "offline"
                if number == len(pairs):
                    raise

    async def configure(self, api_id=None, api_hash=None, session="", expected_user_id=None):
        return await self.with_api_pair(api_id, api_hash, lambda pair_id, pair_hash:
                                        self.connect_login(pair_id, pair_hash, session, expected_user_id))

    async def connect_login(self, api_id, api_hash, session="", expected_user_id=None):
        if self.running:
            raise ValueError("Pause observation before changing accounts.")
        await self.cancel_login()

        session = validate_string(session) if session else ""
        await self.ensure_route()
        candidate = self.make_client(api_id, api_hash, session)
        self.login_client = candidate
        self.pending_credentials = {"api_id": api_id, "api_hash": api_hash}
        self.pending_account_id = expected_user_id

        self.pending_key_origin = "imported" if session else "created"
        try:
            await self.connect_client(candidate)
            is_authorized = await candidate.is_user_authorized()
            if session and not is_authorized:
                raise ValueError("This session is not authorized.")
            if is_authorized:
                await self.authorized()
                return {"step": "authorized"}
        except BaseException:
            await self.cancel_login()
            self.phase = "ready" if self.vault.read("credentials").get("session") else "offline"
            raise
        self.phase = "login_required"
        return {"step": "phone"}

    async def start_phone(self, phone, api_id=None, api_hash=None):
        async def attempt(pair_id, pair_hash):
            await self.connect_login(pair_id, pair_hash)
            return await self.send_code(phone)
        return await self.with_api_pair(api_id, api_hash, attempt)

    async def start_qr(self, api_id=None, api_hash=None):
        async def attempt(pair_id, pair_hash):
            await self.connect_login(pair_id, pair_hash)
            return await self.login_client.qr_login()
        try:
            qr = await self.with_api_pair(api_id, api_hash, attempt)
        except BaseException:
            await self.cancel_login()
            raise
        candidate = self.login_client
        try:
            record = {"id": secrets.token_urlsafe(18), "step": "qr", "expires": qr.expires.isoformat()}
            self.qr_state = record
            self.phase = "qr_required"

            async def wait_for_scan():
                try:
                    await asyncio.wait_for(qr.wait(), 120)
                    if self.login_client is not candidate or self.qr_state is not record:
                        return
                    await self.authorized()
                    record["step"] = "authorized"
                except SessionPasswordNeededError:
                    if self.login_client is candidate and self.qr_state is record:
                        self.phase = "password_required"
                        record["step"] = "password"
                except asyncio.CancelledError:
                    raise
                except Exception as exc:

                    if self.qr_state is record or self.qr_state is None:
                        record["step"] = "expired" if isinstance(exc, TimeoutError) else "failed"
                        record["error"] = "QR code expired. Generate a new code." if isinstance(exc, TimeoutError) else (
                            str(exc) if isinstance(exc, ValueError) else "QR authorization failed: " + type(exc).__name__)
                        self.qr_state = record
                    if self.login_client is candidate:
                        self.login_client = None
                        self.pending_credentials = self.pending_account_id = None
                        self.phase = "ready" if self.vault.read("credentials").get("session") else "offline"
                        await candidate.disconnect()

            self.qr_task = asyncio.create_task(wait_for_scan())

            await asyncio.sleep(0)
            return {**record, "url": qr.url}
        except BaseException:
            await self.cancel_login()
            raise

    def poll_qr(self, login_id):
        if not self.qr_state or self.qr_state["id"] != login_id:
            return {"step": "cancelled"}
        return dict(self.qr_state)

    async def cancel_qr(self, login_id):
        if self.qr_state and self.qr_state["id"] == login_id:
            was_pending = self.login_client is not None
            await self.cancel_login()
            if was_pending:
                self.phase = "ready" if self.vault.read("credentials").get("session") else "offline"
        return {"step": "cancelled"}

    async def send_code(self, phone):
        if not self.login_client or self.phase != "login_required":
            raise ValueError("Configure API credentials first.")
        result = await self.login_client.send_code_request(phone)
        self.pending_phone, self.phone_hash = phone, result.phone_code_hash
        return {"step": "code"}

    async def confirm_code(self, code):
        if not self.pending_phone or not self.phone_hash:
            raise ValueError("Request a login code first.")
        try:
            await self.login_client.sign_in(self.pending_phone, code, phone_code_hash=self.phone_hash)
        except SessionPasswordNeededError:
            self.phase = "password_required"
            return {"step": "password"}
        await self.authorized()
        return {"step": "authorized"}

    async def confirm_password(self, password):
        if not self.login_client or self.phase != "password_required":
            raise ValueError("Two-step verification was not requested.")
        await self.login_client.sign_in(password=password)
        await self.authorized()
        return {"step": "authorized"}

    async def authorized(self):
        if self.running:
            raise ValueError("Pause observation before completing an account change.")
        candidate = self.login_client
        if not candidate:
            raise ValueError("Configure API credentials first.")
        try:
            me = await candidate.get_me()
            self.remember(me)
            if getattr(me, "bot", False):
                raise ValueError("A user account is required; bot sessions are not supported.")
            if self.pending_account_id is not None and self.pending_account_id != me.id:
                raise ValueError("The authorized Telegram account does not match the imported account ID.")
            existing = self.store.get_setting("account", {}) or {}
            if existing.get("id") is not None and existing["id"] != me.id:
                raise ValueError("This journal belongs to a different Telegram account. Create another account workspace.")
            if self.account_guard:
                self.account_guard(me.id, self)
            credentials = dict(self.pending_credentials)
            credentials["session"] = candidate.session.save()
            if self.client:
                await self.client.disconnect()
            self.vault.save("credentials", credentials)
            with self.store.transaction():
                self.store.set_setting("account", {"id": me.id, "username": me.username,
                                                   "key_origin": self.pending_key_origin})
                self.store.append("account.authorized", {"account_id": me.id, "key_origin": self.pending_key_origin})
        except BaseException:
            await self.cancel_login()
            self.phase = "ready" if self.vault.read("credentials").get("session") else "offline"
            raise
        self.client = candidate
        self.login_client = None
        self.pending_credentials = None
        self.pending_account_id = None
        if self.qr_state:
            self.qr_state["step"] = "authorized"
        self.dialog_cache = {}
        self.pending_phone = self.phone_hash = None
        self.phase, self.last_error = "ready", None

    async def restore(self):
        credentials = self.vault.read("credentials")
        if not credentials.get("session"):
            raise ValueError("Connect a Telegram account first.")
        if not self.client:
            await self.ensure_route()
            self.client = self.make_client(credentials["api_id"], credentials["api_hash"], credentials["session"])
        if not self.client.is_connected():
            await self.connect_client(self.client)
        if not await self.client.is_user_authorized():
            self.phase = "login_required"
            raise ValueError("Telegram authorization expired. Sign in again.")

    async def dialogs(self):
        await self.restore()
        self.dialog_cache = {}
        count, limit = 0, self.param("dialog_limit")

        async for dialog in self.client.iter_dialogs(limit=limit):
            count += 1
            entity = getattr(dialog, "entity", None)
            kind = kind_of(entity) or (
                "supergroup" if getattr(entity, "megagroup", False) else "channel" if dialog.is_channel
                else "group" if dialog.is_group else "bot" if getattr(entity, "bot", False) else "private")
            self.dialog_cache[dialog.id] = {
                "chat_id": dialog.id, "title": dialog.name, "kind": kind, "entity": entity,
                "archived": getattr(dialog, "folder_id", None) == 1,
                "visibility": "public_username" if getattr(entity, "username", None) else "private_or_unlisted",
                "role": "creator" if getattr(entity, "creator", False)
                        else "administrator" if getattr(entity, "admin_rights", None) else "member_or_unknown",
            }
        await self.load_folders()
        return {"dialogs": [{k: v for k, v in d.items() if k != "entity"}
                            for d in self.dialog_cache.values()],
                "folders": [{"id": f["id"], "title": f["title"],
                             "chats": sum(1 for c, d in self.dialog_cache.items()
                                          if in_folder(f, c, d["kind"], d["entity"], d["archived"]))}
                            for f in self.folders.values()],
                "limit": limit, "may_be_truncated": count >= limit}

    async def load_folders(self):
        """The account's Telegram folders (dialog filters); empty when Telegram does not answer."""
        own = (self.store.get_setting("account", {}) or {}).get("id")
        try:
            result = await asyncio.wait_for(self.client(functions.messages.GetDialogFiltersRequest()), 15)
        except FloodWaitError:
            raise
        except Exception:
            if not self.folders:
                self.folders = {f["id"]: f for f in self.store.get_setting("folders_seen", [])}
            return
        filters = getattr(result, "filters", result) or []
        self.folders = {f.id: folder_rule(f, own) for f in filters if isinstance(
            f, (types.DialogFilter, getattr(types, "DialogFilterChatlist", types.DialogFilter)))}
        self.store.set_setting("folders_seen", list(self.folders.values()))

    async def resolve_target(self, chat_id):
        if chat_id not in self.dialog_cache:
            await self.dialogs()
        if chat_id not in self.dialog_cache:
            raise ValueError("Target is not among the dialogs this account read. Refresh the group list or raise "
                             "the chat list limit in Parameters.")
        return self.dialog_cache[chat_id]["entity"]

    async def start(self):
        if self.running:
            return
        if self.watchdog or self.media_worker or self.reconciler or self.intake_worker:
            await self.stop()
        if scope_settings(self.store)["mode"] == "selected" and not self.store.targets(True):
            raise ValueError("Select at least one group or channel first.")
        await self.cancel_login()
        self.buffered, self.buffering, self.buffer_overflow = [], True, False
        self.buffer_limit = self.param("startup_buffer")
        try:
            await self.prepare_start()
        except BaseException:
            self.buffered, self.buffering = [], False
            raise
        self.store.recover_media()
        self.running, self.phase, self.last_error = True, "observing", None
        self.store.set_setting("resume", True)
        self.store.append("observation.started", {
            "run_id": self.run_id, "monotonic_ns": time.monotonic_ns(),
            "account": self.store.get_setting("account", None),
            "capture": capture_settings(self.store),
            "monitoring": monitoring_settings(self.store),
            "scope": scope_settings(self.store),
            "parameters": tuning.values(self.store),
            "targets": [t["chat_id"] for t in self.store.targets(True)],
            "coverage": "live updates visible to the account; no completeness guarantee",
            "catch_up_from": self.resumed_state_at,
            "restart_note": "The saved Telegram update position is resumed when available (catch_up_from) and "
                            "missed updates are requested; a periodic recheck recovers missed messages and marks "
                            "saved ones Telegram no longer returns. Telegram may still omit updates after long outages.",
        })
        self.mark_recheck_start()
        pending, self.buffered, self.buffering = self.buffered, [], False
        if self.buffer_overflow:
            self.store.append("coverage.gap", {"reason": "startup buffer full",
                                               "completeness": "updates received while starting were dropped"})
        for handler, update in pending:
            await handler(update)
        self.watchdog = asyncio.create_task(self.supervise(self.monitor, "connection monitor"))
        self.media_worker = asyncio.create_task(self.supervise(self.download_worker, "media worker"))
        self.reconciler = asyncio.create_task(self.supervise(self.recheck_loop, "recheck"))
        self.intake_worker = asyncio.create_task(self.supervise(self.intake_loop, "new chat intake"))
        catch_up = getattr(self.client, "catch_up", None)
        if catch_up:
            await catch_up()

    async def prepare_start(self):
        await self.restore()

        await self.dialogs()
        await self.apply_scope(refresh=False)
        self.source_status = {}
        for target in self.store.targets(True):
            visible = target["chat_id"] in self.dialog_cache
            self.source_status[str(target["chat_id"])] = {
                "state": "visible_in_dialogs" if visible else "access_unconfirmed",
                "checked_at": utcnow(), "meaning": "Dialog visibility is not a guarantee of every update.",
                "visibility": self.dialog_cache.get(target["chat_id"], {}).get("visibility", "unknown"),
                "role": self.dialog_cache.get(target["chat_id"], {}).get("role", "unknown")}
            if not visible:
                self.store.append("source.access_unconfirmed", {
                    "reason": "not present in the enumerated account dialogs",
                    "other_sources_continue": True}, target["chat_id"])
        if scope_settings(self.store)["mode"] == "selected" and not any(
                s["state"] == "visible_in_dialogs" for s in self.source_status.values()):
            raise ValueError("None of the selected sources was visible in the account dialogs. Check membership and refresh.")

    async def supervise(self, work, name):
        try:
            await work()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.failure(exc, name)
            self.running, self.phase = False, "collector_error"
            if self.client:
                asyncio.create_task(self.client.disconnect())

    async def stop(self, shutdown=False):
        await self.history.pause("process_shutdown" if shutdown else "observation_stopped")
        if shutdown and self.export_task:
            self.export_task.cancel()
            await asyncio.gather(self.export_task, return_exceptions=True)
        active = self.running
        if active:
            self.persist_update_state()
        self.running = False
        self.buffered, self.buffering = [], False
        tasks = (self.watchdog, self.media_worker, self.reconciler, self.intake_worker)
        for task in tasks:
            if task:
                task.cancel()
        await asyncio.gather(*(t for t in tasks if t), return_exceptions=True)
        self.watchdog = self.media_worker = self.reconciler = self.intake_worker = None
        if not shutdown:
            self.store.set_setting("resume", False)
        if active:
            self.store.append("observation.stopped", {"reason": "shutdown" if shutdown else "operator",
                                                    "media_jobs_preserved": self.store.media_stats()})
            retain_checkpoint(self.store, self.vault)

        if self.client and (shutdown or not (self.export_busy() or self.export_claim)):
            await self.client.disconnect()
        if shutdown and self.proxy_pool:
            self.proxy_pool.release(self.route_owner)
            self.proxy_pool.waiting.discard(self.route_owner)
        await self.cancel_login()
        self.phase = "paused"

    async def monitor(self):
        previous = True
        wall, monotonic = time.time(), time.monotonic()
        heartbeat_at = checkpoint_at = None
        while self.running:
            new_wall, new_monotonic = time.time(), time.monotonic()
            drift = (new_wall - wall) - (new_monotonic - monotonic)
            if abs(drift) > 5:
                self.store.append("clock.discontinuity", {
                    "run_id": self.run_id, "wall_minus_monotonic_seconds": round(drift, 3),
                    "meaning": "Local wall-clock change detected; observation times need independent validation."})
            wall, monotonic = new_wall, new_monotonic
            connected = self.client.is_connected()
            if connected != previous:
                self.store.append("connection.restored" if connected else "coverage.gap", {
                    "reason": "transport_connected" if connected else "transport_disconnected",
                    "completeness": "unknown; intermediate events may be missing"})
                if connected:
                    self.recheck_wakeup.set()
                else:
                    await self.note_drop()
            previous = connected
            self.phase = "observing" if connected else "reconnecting"
            if connected and self.automatic():
                await self.review_route()
            if not connected:
                await self.reconnect()
                if not self.running:
                    return
            now, interval = time.monotonic(), self.param("heartbeat_seconds")
            if heartbeat_at is None or now - heartbeat_at >= interval - 1:
                heartbeat_at = now
                self.persist_update_state()
                self.last_heartbeat = utcnow()
                self.store.append("collector.heartbeat", {
                    "connected": connected, "run_id": self.run_id, "monotonic_ns": time.monotonic_ns(),
                    "media_jobs": self.store.media_stats(), "interval_seconds": interval,
                    "meaning": "collector liveness, not proof of complete capture"})
            if checkpoint_at is None or now - checkpoint_at >= self.param("checkpoint_minutes") * 60 - 1:
                checkpoint_at = now
                retain_checkpoint(self.store, self.vault)
            await asyncio.sleep(min(10, interval))

    async def note_drop(self):
        """Automatic mode: a proxy that keeps losing the connection is replaced before reconnecting."""
        if not self.automatic() or self.direct_fallback:
            return
        now = time.monotonic()
        self.route_drops.append(now)
        while self.route_drops and now - self.route_drops[0] > self.param("proxy_drop_window_minutes") * 60:
            self.route_drops.popleft()
        if len(self.route_drops) >= self.param("proxy_drop_limit"):
            with suppress(NoProxyAvailable):
                await self.rotate_route(self.client, "repeated_disconnect")

    async def reconnect(self):
        now = time.time()
        if now < max(self.next_reconnect_at, self.store.get_setting("rpc_backoff_until", 0)):
            return
        self.reconnect_attempts += 1
        self.store.append("connection.retry", {"attempt": self.reconnect_attempts})
        try:
            await self.restore()
        except ValueError:
            self.phase, self.running = "authorization_required", False
            self.store.append("coverage.gap", {"reason": "authorization_required"})
            asyncio.create_task(self.client.disconnect())
        except FloodWaitError as exc:
            self.next_reconnect_at = now + exc.seconds
            self.store.set_setting("rpc_backoff_until", self.next_reconnect_at)
            self.store.append("telegram.backoff", {"operation": "reconnect", "retry_after_seconds": exc.seconds})
        except Exception as exc:
            self.next_reconnect_at = now + min(self.param("reconnect_max_seconds"),
                                               5 * 2 ** min(self.reconnect_attempts, 10))
            self.last_error = type(exc).__name__
            self.store.append("connection.retry_failed", {
                "attempt": self.reconnect_attempts, "error_type": type(exc).__name__,
                "retry_at_unix": self.next_reconnect_at})
        else:
            self.phase, self.last_error = "observing", None
            self.reconnect_attempts, self.next_reconnect_at = 0, 0
            catch_up = getattr(self.client, "catch_up", None)
            if catch_up:
                await catch_up()
            self.recheck_wakeup.set()

    async def failure(self, exc, context):
        self.last_error = type(exc).__name__
        try:
            self.store.append("collector.error", {"operation": context, "error_type": type(exc).__name__,
                                                 "coverage": "this update may not have been recorded"})
        except Exception:
            self.running, self.phase = False, "storage_error"
            if self.client:
                asyncio.create_task(self.client.disconnect())

    async def capture_message(self, message, kind, chat_id, update=None, source=None, history_run_id=None):
        started = time.perf_counter()
        self.remember(getattr(message, "sender", None))
        payload = describe_message(message)
        payload["source"] = source or ("history_snapshot" if kind == "message.snapshot" else "live_update")
        payload["collector_account_id"] = (self.store.get_setting("account", {}) or {}).get("id")
        payload["run_id"] = self.run_id
        if history_run_id is not None:
            payload["history_run_id"] = history_run_id
        if update is not None:
            payload["transport_update"] = plain(update)

        if kind == "message.edited":
            payload["editor_id"] = None
            payload["editor_visibility"] = "not supplied by this update"
            if payload["outgoing"]:
                payload["editor_visibility"] = ("outgoing message: in private chats and groups only its author, "
                                                "this account, can edit it; in channels other admins may edit posts")
        if payload["outgoing"] and payload["text"] and kind == "message.new":


            keyboard = self.store.latest_reply_keyboard(chat_id, self.param("keyboard_window"), message.id)
            if keyboard and payload["text"] in keyboard[1]:
                payload["button_press"] = {
                    "type": "reply_keyboard", "text": payload["text"], "keyboard_event": keyboard[0],
                    "meaning": "this account sent the text of a button from the newest saved reply keyboard; "
                               "inline (callback) button presses are not visible to another session"}
        job = None
        media_skip = None
        if message.media:
            settings = capture_settings(self.store)
            account = self.store.get_setting("account", {}) or {}
            media_type = media_kind(message) if message.file else None
            rule = settings["types"].get(media_type) if media_type else None
            if not settings["download_media"]:
                media_skip = "media download disabled"
            elif not message.file:
                media_skip = "metadata-only media type; no downloadable file"
            elif not rule["enabled"]:
                media_skip = "attachment type not collected by policy: " + media_type
            elif not account.get("id"):
                media_skip = "authorized account identity unavailable"
            else:
                descriptor = bytes(message)
                job = {"account_id": account["id"], "descriptor": descriptor,
                       "max_bytes": rule["max_mb"] * 1024**2}
                payload["media_capture"] = {
                    "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
                    "account_id": account["id"], "max_bytes": job["max_bytes"], "media_type": media_type,
                    "policy": "original observed descriptor; never substitute a newer message"}
        event = self.store.append(kind, payload, chat_id, message.id,
                                  message.sender_id if kind in ("message.new", "message.recovered") else None,
                                  date_string(getattr(message, "edit_date", None) or message.date),
                                  media_job=job)
        if getattr(message, "action", None):
            self.store.append("membership.service" if isinstance(message.action, (
                types.MessageActionChatAddUser, types.MessageActionChatDeleteUser,
                types.MessageActionChatJoinedByLink, types.MessageActionChatJoinedByRequest
            )) else "chat.service", {
                "message_event": event["seq"], "action": plain(message.action),
                "attribution": "service-message sender; meaning depends on the action type"
            }, chat_id, message.id, message.sender_id, date_string(message.date))
        if media_skip:
            self.store.append("media.skipped", {"message_event": event["seq"], "reason": media_skip},
                              chat_id, message.id)
        if job:
            self.media_wakeup.set()
        self.last_update_at = utcnow()
        self.max_handler_ms = max(self.max_handler_ms, (time.perf_counter() - started) * 1000)
        return event

    def own_skipped(self, message):
        """Messages sent by this account are skipped when the scope leaves out own actions."""
        return bool(getattr(message, "out", False)) and not scope_settings(self.store)["own_actions"]

    async def on_new(self, event):
        if not (self.running and monitoring_settings(self.store)["messages"]) or self.own_skipped(event.message):
            return
        try:
            if not await self.covers(event.chat_id, getattr(event, "chat", None)):
                return
            update = getattr(event, "original_update", None)
            source = recovered_source(update)
            if source and self.store.message_state(event.chat_id, event.message.id)["content"]:
                return
            await self.capture_message(event.message, "message.new", event.chat_id, update, source)
        except Exception as exc:
            await self.failure(exc, "message.new")

    async def on_edit(self, event):
        if not (self.running and monitoring_settings(self.store)["edits"]) or self.own_skipped(event.message):
            return
        try:
            if not await self.covers(event.chat_id, getattr(event, "chat", None)):
                return
            content = self.store.message_state(event.chat_id, event.message.id)["content"]
            if content and content["observable"] == message_content.of_payload(describe_message(event.message)):
                return
            await self.capture_message(event.message, "message.edited", event.chat_id,
                                       getattr(event, "original_update", None))
        except Exception as exc:
            await self.failure(exc, "message.edited")

    def record_deletion(self, chat_id, message_id, raw, resolution=None):
        state = self.store.message_state(chat_id, message_id)
        if state["deleted"]:
            return
        payload = {"deleted_by": None, "deletion_time": None,
                   "meaning": "Telegram deletion notification; observation time is not deletion time", "raw": raw}
        if resolution:
            payload["chat_resolution"] = resolution
        if state["content"] and state["content"].get("outgoing"):
            payload["deleted_message_was_outgoing"] = True
            payload["deleter_visibility"] = "the message was sent by this account; who deleted it is not supplied"
        self.store.append("message.deleted", payload, chat_id, message_id)

    async def on_delete(self, event):
        if not self.running or not monitoring_settings(self.store)["deletions"]:
            return
        try:
            raw = plain(event.original_update)
            if event.chat_id is None:


                unresolved = []
                for message_id in event.deleted_ids:
                    chat_id = self.store.account_message_chat(message_id)
                    if chat_id is not None and await self.covers(chat_id):
                        self.record_deletion(chat_id, message_id, raw, {
                            "method": "chat of the previously saved message with this ID",
                            "basis": "private chats and ordinary groups share one account-wide message ID sequence"})
                    else:
                        unresolved.append(message_id)
                if unresolved:
                    self.store.append("deletion.unscoped", {
                        "message_ids": unresolved, "scope": "account-level update; no saved message has these IDs",
                        "deleted_by": None, "raw": raw})
            elif await self.covers(event.chat_id):
                for message_id in event.deleted_ids:
                    self.record_deletion(event.chat_id, message_id, raw)
        except Exception as exc:
            await self.failure(exc, "message.deleted")

    async def on_raw(self, update):
        if not self.running:
            return
        try:
            settings = monitoring_settings(self.store)
            if isinstance(update, (types.UpdateNewMessage, types.UpdateNewChannelMessage)) and isinstance(
                    update.message, types.MessageService):

                chat_id = utils.get_peer_id(update.message.peer_id)
                membership = isinstance(update.message.action, (
                    types.MessageActionChatAddUser, types.MessageActionChatDeleteUser,
                    types.MessageActionChatJoinedByLink, types.MessageActionChatJoinedByRequest))
                if membership and not settings["membership"]:
                    return
                if await self.covers(chat_id):
                    source = recovered_source(update)
                    if source and self.store.message_state(chat_id, update.message.id)["content"]:
                        return
                    await self.capture_message(update.message, "message.new", chat_id, update, source)
            elif isinstance(update, types.UpdateChannelTooLong):
                chat_id = utils.get_peer_id(types.PeerChannel(update.channel_id))
                if self.selected(chat_id):
                    self.store.append("coverage.gap", {
                        "reason": "Telegram reported channel updates requiring difference recovery",
                        "completeness": "unknown", "raw": plain(update)}, chat_id)
            elif isinstance(update, types.UpdateMessageReactions):
                if not settings["reactions"]:
                    return
                chat_id = utils.get_peer_id(update.peer)
                if await self.covers(chat_id):
                    self.store.append("reaction.snapshot", {
                        "raw": plain(update), "visibility": "aggregate and recent reactions if supplied",
                        "complete_actor_list": False, "change_actor": None,
                    }, chat_id, update.msg_id)
            elif isinstance(update, (types.UpdateChannelParticipant, types.UpdateChatParticipant)):
                if not settings["membership"]:
                    return
                chat_id = utils.get_peer_id(types.PeerChannel(update.channel_id)) if hasattr(
                    update, "channel_id") else -update.chat_id
                if await self.covers(chat_id):
                    self.store.append("membership.update", {
                        "user_id": update.user_id, "raw": plain(update),
                        "visibility": "only participant updates delivered to this account",
                    }, chat_id, actor_id=update.actor_id, source_at=date_string(update.date))
        except Exception as exc:
            await self.failure(exc, "raw.update")

    async def recheck_loop(self):
        """Periodically ask Telegram again: recover missed messages, missed edits and silent removals.

        Live updates and catch-up can still lose events (Telethon drops ChannelDifferenceTooLong and
        DifferenceTooLong; long outages; leaving or losing a chat). This is the second layer.
        """

        delay, forced = self.param("recheck_first_delay_seconds"), True
        while self.running:
            try:
                await asyncio.wait_for(self.recheck_wakeup.wait(), delay)
                forced = True
            except TimeoutError:
                pass
            self.recheck_wakeup.clear()
            if not self.running:
                return
            delay = self.param("recheck_tick_seconds")
            if not self.client.is_connected() or time.time() < self.store.get_setting("rpc_backoff_until", 0):
                continue
            if (scope_settings(self.store)["mode"] != "selected"
                    and time.time() - self.scope_refreshed_at > self.param("scope_refresh_minutes") * 60):
                try:
                    await self.apply_scope()
                except FloodWaitError as exc:
                    self.store.set_setting("rpc_backoff_until", time.time() + exc.seconds)
                    self.store.append("telegram.backoff", {"operation": "scope refresh",
                                                           "retry_after_seconds": exc.seconds})
                    continue
                except Exception as exc:
                    self.scope_refreshed_at = time.time()
                    self.store.append("collector.error", {"operation": "scope refresh", "error_type": type(exc).__name__,
                                                         "coverage": "new chats are still added when they become active"})
            due = self.due_targets(forced)
            forced = False
            if due:
                await self.recheck_pass(due)

    def mark_recheck_start(self):
        """Before live updates are saved, note where saved history ends so the recheck walks any gap from there."""
        walked = self.store.get_setting("recheck_walked", {})
        for target in self.store.targets(True):
            key = str(target["chat_id"])
            if key not in walked and (last := self.store.last_message_id(target["chat_id"])) is not None:
                walked[key] = last
        self.store.set_setting("recheck_walked", walked)

    def due_targets(self, forced=False):
        """Sources whose recheck is due: priority sources at the short interval, others at the long one."""
        settings, last, now = recheck_settings(self.store), self.store.get_setting("recheck_last", {}), time.time()
        due = []
        for target in self.store.targets(True):
            minutes = settings["recheck_minutes"] if target["priority"] else settings["recheck_other_minutes"]
            if not minutes:
                continue
            seen = last.get(str(target["chat_id"]), 0)
            if (forced and target["priority"]) or now - seen >= minutes * 60:
                due.append((0 if target["priority"] else 1, seen, target))
        due.sort(key=lambda item: item[:2])
        return [target for _, _, target in due[:self.param("recheck_max_chats")]]

    async def recheck_pass(self, targets=None):
        started, settings, results = time.monotonic(), monitoring_settings(self.store), []
        pause = self.param("recheck_pause_seconds")
        for target in self.store.targets(True) if targets is None else targets:
            if not self.running:
                break
            try:
                result = await self.recheck_chat(target["chat_id"], settings)
                results.append(result)
                if "continues_after" not in result:

                    last = self.store.get_setting("recheck_last", {})
                    last[str(target["chat_id"])] = time.time()
                    self.store.set_setting("recheck_last", last)
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                self.store.append("telegram.backoff", {"operation": "recheck", "retry_after_seconds": exc.seconds})
                results.append({"chat_id": target["chat_id"], "error": "FloodWaitError"})
                break
            except Exception as exc:
                results.append({"chat_id": target["chat_id"], "error": type(exc).__name__})
            await asyncio.sleep(pause / 2 if target.get("priority", 1) else pause)
        if not results:
            return self.recheck_state
        totals = {k: sum(r.get(k, 0) for r in results) for k in ("recovered", "edited", "missing", "checked")}
        self.recheck_state = {"at": utcnow(), "chats": len(results),
                              "errors": sum(1 for r in results if "error" in r), **totals}
        self.store.append("recheck.completed", {
            "chats": results, "duration_seconds": round(time.monotonic() - started, 1), **totals,
            "meaning": "Messages in the checked ID ranges were returned by Telegram at this time unless reported "
                       "missing; messages newer than the last saved one were recovered."})
        return self.recheck_state

    async def recheck_chat(self, chat_id, settings):
        entity = await self.resolve_target(chat_id)
        result = {"chat_id": chat_id, "recovered": 0, "edited": 0, "missing": 0, "checked": 0}
        if settings["messages"]:
            floors = self.store.get_setting("recheck_floor", {})
            last = self.store.last_message_id(chat_id)
            if last is None and str(chat_id) not in floors:

                newest = await self.client.get_messages(entity, limit=1)
                floors[str(chat_id)] = newest[0].id if newest else 0
                self.store.set_setting("recheck_floor", floors)
            elif limit := self.param("recheck_new_limit"):


                walked = self.store.get_setting("recheck_walked", {})
                floor = max(walked.get(str(chat_id), last) or 0, floors.get(str(chat_id), 0))
                seen, reached, stopped = 0, floor, False
                async for message in self.client.iter_messages(entity, min_id=floor, reverse=True, limit=limit):
                    if not self.running:
                        stopped = True
                        break
                    seen, reached = seen + 1, message.id
                    if self.own_skipped(message):
                        floors[str(chat_id)] = message.id
                        self.store.set_setting("recheck_floor", floors)
                        continue
                    if isinstance(getattr(message, "action", None), MEMBERSHIP_ACTIONS) and not settings["membership"]:
                        floors[str(chat_id)] = message.id
                        self.store.set_setting("recheck_floor", floors)
                        continue
                    if self.store.message_state(chat_id, message.id)["content"]:
                        continue
                    await self.capture_message(message, "message.recovered", chat_id, source="recheck")
                    result["recovered"] += 1
                walked = self.store.get_setting("recheck_walked", {})
                if stopped or seen >= limit:

                    walked[str(chat_id)] = reached
                    result["continues_after"] = reached
                else:
                    walked[str(chat_id)] = max(reached, self.store.last_message_id(chat_id) or 0)
                self.store.set_setting("recheck_walked", walked)
        if not (settings["edits"] or settings["deletions"]):
            return result

        batch = self.param("recheck_batch")
        newest = self.store.alive_message_ids(chat_id, limit=batch)
        older = []
        if len(newest) == batch:
            cursors = self.store.get_setting("recheck_cursor", {})
            below = min(cursors.get(str(chat_id)) or newest[-1], newest[-1])
            older = self.store.alive_message_ids(chat_id, below=below, limit=batch)
            cursors[str(chat_id)] = older[-1] if len(older) == batch else None
            self.store.set_setting("recheck_cursor", cursors)
        ids = newest + older
        if not ids:
            return result
        messages = await self.client.get_messages(entity, ids=ids)
        missing = []
        for message_id, message in zip(ids, messages):
            if message is None:
                missing.append(message_id)
            elif settings["edits"] and not self.own_skipped(message):

                content = self.store.message_state(chat_id, message_id)["content"]
                if content and content["observable"] != message_content.of_payload(describe_message(message)):
                    await self.capture_message(message, "message.edited", chat_id, source="recheck")
                    result["edited"] += 1
        result.update(checked=len(ids), checked_from=min(ids), checked_to=max(ids))
        if missing and settings["deletions"]:
            if len(missing) == len(ids) and len(ids) >= 10:

                await self.client.get_messages(entity, limit=1)
            for message_id in missing:
                state = self.store.message_state(chat_id, message_id)
                if state["deleted"] or state["missing"]:
                    continue
                content = state["content"]
                self.store.append("message.missing_on_recheck", {
                    "method": "message requested again by ID",
                    "last_saved_event": {"seq": content["seq"], "hash": content["hash"]} if content else None,
                    "meaning": "Telegram returned no message with this ID at recheck and no deletion notice was "
                               "received: deleted while notices were missed, removed by an auto-delete timer, "
                               "or no longer visible to this account."}, chat_id, message_id)
                result["missing"] += 1
        return result

    async def snapshot(self, chat_id, limit, entity=None, origin=None):
        """Save the latest visible messages. origin "new_chat": taken when the chat appeared; messages
        already saved live are skipped there."""
        if not self.selected(chat_id):
            raise ValueError("Enable this target before taking a history snapshot.")
        await self.restore()
        entity = entity or await self.resolve_target(chat_id)
        count = 0
        self.store.append("snapshot.started", {"limit": limit, "meaning": "current visible history",
                                               **({"origin": origin} if origin else {})}, chat_id)
        try:
            async for message in self.client.iter_messages(entity, limit=limit):
                if origin and self.own_skipped(message):
                    continue
                if origin and self.store.message_state(chat_id, message.id)["content"]:
                    continue
                await self.capture_message(message, "message.snapshot", chat_id,
                                           source="new_chat_snapshot" if origin else None)
                count += 1
        except BaseException as exc:
            self.store.append("snapshot.interrupted", {"captured": count, "requested": limit,
                                                      "error_type": type(exc).__name__}, chat_id)
            raise
        self.store.append("snapshot.completed", {"captured": count, "requested": limit,
                                                 "reconstructed_missed_events": False}, chat_id)
        return {"captured": count, "requested": limit}

    def export_busy(self):
        return bool(self.export_task and not self.export_task.done())

    def reserve_export(self, owner):
        """One export per account, individual or multi-account. Checked and taken with no await in
        between, before the owner's first await; only the owner releases it."""
        if self.export_busy() or self.export_claim:
            return False
        self.export_claim = owner
        return True

    def release_export(self, owner):
        if self.export_claim == owner:
            self.export_claim = None

    def note(self, kind, payload, chat_id=None):
        """A diagnostic journal record that must never mask the failure being recorded."""
        try:
            self.store.append(kind, payload, chat_id)
        except Exception:
            pass

    async def chat_scale(self, chat_id):
        """Exact current message count from Telegram (one request) and a full-download estimate."""
        await self.restore()
        entity = await self.resolve_target(chat_id)
        started = time.monotonic()
        latest = await self.client.get_messages(entity, limit=1)
        request_seconds = time.monotonic() - started
        total = getattr(latest, "total", None) or 0
        last_id = latest[0].id if latest else None

        per_chat_ids = self.dialog_cache.get(chat_id, {}).get("kind") in ("supergroup", "channel")
        pages = -(-total // 100)

        per_page = max(1.0 if total > 3000 else 0.0, request_seconds)
        return {"chat_id": chat_id, "total": total, "last_message_id": last_id,
                "ids_are_per_chat": per_chat_ids,
                "missing_ids": max(0, last_id - total) if per_chat_ids and last_id else None,
                "pages": pages, "estimate_seconds": round(pages * per_page),
                "request_seconds": round(request_seconds, 3)}

    async def start_export(self, chat_id, report_options=None):

        export_id = secrets.token_urlsafe(18)
        if not self.reserve_export(export_id):
            raise ValueError("A chat export is already running on this account. Wait for it or cancel it first.")
        try:
            await self.restore()
            entity = await self.resolve_target(chat_id)
            info = self.dialog_cache.get(chat_id, {})
            try:
                total = (await self.client.get_messages(entity, limit=0)).total
            except Exception:
                total = None
            record = {"id": export_id, "chat_id": chat_id, "title": info.get("title"),
                      "phase": "running", "captured": 0, "total": total, "eta_seconds": None,
                      "ready": False, "error": None, "started_at": utcnow()}
            self.export_state = record
            self.export_path = None
            self.export_task = asyncio.create_task(self.run_export(entity, info, record, report_options))

            self.export_task.add_done_callback(lambda _: self.release_export(export_id))
        except BaseException:
            self.release_export(export_id)
            raise
        await asyncio.sleep(0)
        return dict(record)

    async def run_export(self, entity, info, record, report_options=None):
        directory = self.store.root / "temporary-exports"
        scratch = directory / ("tgwitness-export-chat-" + record["id"] + ".jsonl")
        out_path = directory / ("tgwitness-export-chat-" + record["id"] + ".zip")
        chat_id = record["chat_id"]
        try:

            directory.mkdir(mode=0o700, exist_ok=True)
            self.store.append("chat_export.started", {"chat_id": chat_id, "title": info.get("title"),
                                                      "meaning": "full visible history snapshot"}, chat_id)
            count = await self.stream_history(entity, scratch, record)
            meta = {"chat": {"id": chat_id, "title": info.get("title"), "kind": info.get("kind"),
                             "visibility": info.get("visibility")},
                    "account": self.store.get_setting("account", None), "message_count": count}
            await complete_in_thread(chat_export.build_bundle, scratch, meta, self.vault, out_path,
                                    self.param("export_max_gib") * 1024**3, report_options)
            replica.outbox(self.store, out_path)
            self.export_path = out_path
            record.update(phase="done", captured=count, ready=True)
            self.store.append("chat_export.completed", {"chat_id": chat_id, "message_count": count,
                "fingerprint": fingerprint(self.vault.public_key),
                "reconstructed_missed_events": False}, chat_id)
        except asyncio.CancelledError:
            record.update(phase="cancelled")
            self.note("chat_export.interrupted", {"chat_id": chat_id, "captured": record["captured"],
                                                  "reason": "cancelled"}, chat_id)
            with suppress(OSError):
                out_path.unlink(missing_ok=True)
            raise
        except BaseException as exc:
            record.update(phase="failed", error=type(exc).__name__)
            self.note("chat_export.interrupted", {"chat_id": chat_id, "captured": record["captured"],
                                                  "error_type": type(exc).__name__}, chat_id)
            with suppress(OSError):
                out_path.unlink(missing_ok=True)
        finally:
            with suppress(OSError):
                scratch.unlink(missing_ok=True)

    async def iterate_history(self, entity, on_message, min_id=0, offset_id=0, on_wait=None):
        """Newest to oldest; after FloodWait or a brief connection loss, resume below the last message seen."""
        failures = 0
        while True:
            try:
                async for message in self.client.iter_messages(entity, offset_id=offset_id, min_id=min_id):
                    offset_id, failures = message.id, 0
                    await on_message(message)
                return
            except FloodWaitError as exc:
                wait = min(exc.seconds + 1, 3600)
                self.store.append("telegram.backoff", {"seconds": wait, "context": "chat_export"})
                if on_wait:
                    on_wait(wait)
                await asyncio.sleep(wait)
            except (OSError, ConnectionError, TimeoutError):
                failures += 1
                if failures > 8:
                    raise
                await asyncio.sleep(min(60, 5 * failures))
                if not self.client.is_connected():
                    await self.restore()

    async def stream_history(self, entity, scratch, record):
        count, started = 0, time.monotonic()
        with scratch.open("w", encoding="utf-8") as handle:
            async def write(message):
                nonlocal count
                self.remember(getattr(message, "sender", None))
                handle.write(json.dumps(message_record(message), ensure_ascii=False) + "\n")
                count += 1
                record["captured"] = count
                if count % 200 == 0:
                    handle.flush()
                    elapsed = time.monotonic() - started
                    if record.get("total") and elapsed > 0:
                        record["eta_seconds"] = round(max(0, record["total"] - count) / (count / elapsed))
                    await asyncio.sleep(0)
            await self.iterate_history(entity, write)
        return count

    async def resolve_for_export(self, chat_id, username=None):
        """This account's own handle on the chat: from its dialogs, or by public username."""
        await self.restore()
        try:
            return await self.resolve_target(chat_id)
        except ValueError:
            if not username:
                raise
            entity = await self.client.get_entity(username)
            if utils.get_peer_id(entity) != chat_id:
                raise ValueError("The public username now points to a different chat.")
            return entity

    async def fetch_range(self, entity, low, high, path, progress=None, on_wait=None):
        """Messages low..high inclusive, newest first. The SHA-256 is computed as messages arrive,
        before anything is re-read from disk, so the merged file can be checked against it."""
        digest, count = hashlib.sha256(), 0
        with path.open("w", encoding="utf-8") as handle:
            async def write(message):
                nonlocal count
                self.remember(getattr(message, "sender", None))
                record = message_record(message)
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                digest.update(canonical(record) + b"\n")
                count += 1
                if progress:
                    progress()
                if count % 200 == 0:
                    await asyncio.sleep(0)
            await self.iterate_history(entity, write, min_id=low - 1, offset_id=high + 1, on_wait=on_wait)
        return count, digest.hexdigest()

    def poll_export(self, export_id):
        if not self.export_state or self.export_state["id"] != export_id:
            return {"phase": "unknown"}
        return dict(self.export_state)

    async def cancel_export(self, export_id):
        if self.export_state and self.export_state["id"] == export_id and self.export_task:
            self.export_task.cancel()
            await asyncio.gather(self.export_task, return_exceptions=True)
        return {"phase": "cancelled"}

    def export_result_path(self, export_id):
        if (self.export_state and self.export_state["id"] == export_id and self.export_state.get("ready")
                and self.export_path and self.export_path.is_file()):
            return self.export_path
        return None

    def remember(self, entity):
        """Keep full user/chat objects seen in updates; profile photos need the full object."""
        peer = getattr(entity, "id", None)
        if peer is None or not hasattr(entity, "photo"):
            return
        if len(self.people) >= 5000:
            self.people.pop(next(iter(self.people)))
        self.people[utils.get_peer_id(entity)] = entity

    async def avatar(self, peer_id):
        """Small profile photo from a local cache; downloaded once, never written to the journal."""
        directory = self.store.root / "avatars"
        path, missing = directory / (str(peer_id) + ".jpg"), directory / (str(peer_id) + ".none")
        if path.is_file():
            return path
        if missing.is_file() and time.time() - missing.stat().st_mtime < 86400:
            return None
        if time.time() - self.avatar_failures.get(peer_id, 0) < 600:
            return None
        if time.time() < self.store.get_setting("rpc_backoff_until", 0):
            return None
        account_id = (self.store.get_setting("account", {}) or {}).get("id")
        if not (self.client and self.client.is_connected()):

            if peer_id != account_id or not self.vault.read("credentials").get("session"):
                return None
            try:
                await self.restore()
            except Exception:
                self.avatar_failures[peer_id] = time.time()
                return None
        entity = self.people.get(peer_id) or self.dialog_cache.get(peer_id, {}).get("entity")
        if entity is None and peer_id == account_id:
            try:
                entity = await asyncio.wait_for(self.client.get_me(), 15)
                self.remember(entity)
            except Exception:
                entity = None
        if entity is None:
            return None
        async with self.avatar_lock:
            if path.is_file():
                return path
            try:
                data = await asyncio.wait_for(
                    self.client.download_profile_photo(entity, file=bytes, download_big=False), 20)
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                return None
            except Exception:
                self.avatar_failures[peer_id] = time.time()
                return None
            directory.mkdir(mode=0o700, exist_ok=True)
            if not data:
                missing.write_bytes(b"")
                return None
            temporary = directory / (str(peer_id) + ".tmp")
            temporary.write_bytes(data)
            temporary.replace(path)
            return path

    async def download_worker(self):
        media_root = self.store.root / "media"
        media_root.mkdir(exist_ok=True)
        while self.running:
            if time.time() < self.store.get_setting("rpc_backoff_until", 0):
                await asyncio.sleep(1)
                continue
            free, threshold = shutil.disk_usage(media_root).free, self.param("media_min_free_mb") * 1024**2
            if free < threshold:

                if not self.storage_low:
                    self.storage_low = True
                    self.store.append("storage.low", {"free_bytes": free, "threshold_bytes": threshold,
                                                      "media_jobs": self.store.media_stats()})
                await asyncio.sleep(STORAGE_RECHECK_SECONDS)
                continue
            if self.storage_low:
                self.storage_low = False
                self.store.append("storage.ok", {"free_bytes": free, "media_jobs": self.store.media_stats()})
            account = self.store.get_setting("account", {}) or {}
            job = self.store.claim_media(account.get("id", 0))
            if not job:
                self.media_wakeup.clear()
                try:
                    await asyncio.wait_for(self.media_wakeup.wait(), 1)
                except TimeoutError:
                    pass
                continue
            temp = media_root / ("pending-" + str(job["message_event"]))
            try:
                original = self.store.events(before=job["message_event"] + 1, limit=1)[0]
                policy = original["payload"].get("media_capture", {})
                if (hashlib.sha256(job["descriptor"]).hexdigest() != policy.get("descriptor_sha256")
                        or job["max_bytes"] != policy.get("max_bytes")
                        or job["account_id"] != policy.get("account_id")
                        or job["chat_id"] != original["chat_id"] or job["message_id"] != original["message_id"]):
                    raise ValueError("queue_descriptor_differs_from_signed_observation")
                with BinaryReader(job["descriptor"]) as reader:
                    message = reader.tgread_object()
                size = getattr(message.file, "size", None) if message.file else None
                if size is None or size > job["max_bytes"]:
                    raise ValueError("unknown_size_or_above_limit")
                if shutil.disk_usage(media_root).free < size + 64 * 1024**2:
                    raise OSError("insufficient_free_space")

                async def progress(current, total):
                    if max(current, total) > job["max_bytes"]:
                        raise ValueError("above_limit")


                timeout = self.param("media_timeout_seconds") + size // (self.param("media_min_speed_kbps") * 1024)
                media = message.media
                if isinstance(media, types.MessageMediaWebPage):


                    media = message.photo or message.document
                with temp.open("wb") as stream:
                    result = await asyncio.wait_for(
                        self.client.download_media(media, file=stream, progress_callback=progress), timeout)
                if result is None:
                    raise ValueError("download_unavailable")
                h = hashlib.sha256()
                with temp.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        h.update(chunk)
                digest, actual_size = h.hexdigest(), temp.stat().st_size
                if actual_size > job["max_bytes"]:
                    raise ValueError("above_limit")
                if actual_size != size:
                    raise ValueError("download_size_differs_from_observed_attachment")
                destination = media_root / digest
                if destination.exists():
                    existing = hashlib.sha256()
                    with destination.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            existing.update(chunk)
                    if existing.hexdigest() != digest:
                        raise ValueError("existing_content_addressed_file_is_corrupt")
                    temp.unlink()
                else:
                    temp.replace(destination)
                self.store.finish_media(job, "done", {
                    "media_sha256": digest, "size": actual_size,
                    "original_name": getattr(message.file, "name", None),
                    "mime_type": getattr(message.file, "mime_type", None),
                })
            except asyncio.CancelledError:
                self.store.finish_media(job, "retry", {"reason": "collector stopped; durable job retained"})
                raise
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                self.store.finish_media(job, "retry", {"error_type": type(exc).__name__,
                                                      "retry_after_seconds": exc.seconds}, delay=exc.seconds)
            except Exception as exc:
                retry = (isinstance(exc, (OSError, TimeoutError, ConnectionError))
                         and job["attempts"] < self.param("media_attempts"))
                delay = min(self.param("media_retry_max_seconds"), 2 ** min(job["attempts"], 20) * 5) if retry else 0
                self.store.finish_media(job, "retry" if retry else "failed", {
                    "error_type": type(exc).__name__,
                    "reason": str(exc) if isinstance(exc, ValueError) else "download failed",
                    "retry_after_seconds": delay}, delay=delay)
            finally:
                temp.unlink(missing_ok=True)
