import asyncio
import base64
import hashlib
import json
import shutil
import time
import secrets
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from functools import wraps
from itertools import islice
from pathlib import Path

from collections import deque

from telethon import __version__ as telethon_version, events, utils
from telethon.errors import SessionPasswordNeededError, FloodWaitError, InvalidBufferError, RPCError
from telethon.errors import ChannelInvalidError, ChannelPrivateError, FileReferenceExpiredError, TakeoutInvalidError
from telethon.errors import TakeoutInitDelayError, TypeNotFoundError
from telethon.errors import FreshResetAuthorisationForbiddenError, PasswordHashInvalidError
from telethon.errors import (AuthKeyDuplicatedError, AuthKeyInvalidError, AuthKeyUnregisteredError,
                             FrozenMethodInvalidError, SessionExpiredError, SessionRevokedError,
                             UserDeactivatedBanError, UserDeactivatedError)
from telethon.extensions import BinaryReader
from telethon.sessions import StringSession
from telethon.tl import functions, types
from telethon.tl.alltlobjects import LAYER

from . import api_pool
from . import chat_export
from . import keyboard
from . import message_content
from . import message_details
from .message_numbers import MissingNumbers
from . import replica
from . import tuning
from .history import History
from .account_import import session_key, validate_string
from .avatar_history import AvatarHistory
from .telegram_client import WitnessClient
from .security import KeyLock
from .workers import complete_in_thread
from .store import canonical, utcnow
from .evidence import retain_checkpoint
from .netclient import RouteError, proxy_address
from .network import NetworkConfig, NoRoute, RoutePolicy, saved_route
from .proxy_catalog import NoProxyAvailable, ProxyPool, PublicCatalog
from .monitoring import (capture_settings, media_kind, monitoring_settings, duration_allowed, media_action,
                         effective_media_rule)
from . import file_hashes
from . import ephemeral
from .scope import allowed, folder_rule, in_folder, kind_of, recheck_settings, scope_settings
from .verify import fingerprint


STORAGE_RECHECK_SECONDS = 30
SMALL_MEDIA_BYTES = 2 * 1024**2


class AuthorizationRequired(ValueError):
    pass


class ProtectedSession(ValueError):
    pass


class UnreadableHistory(ValueError):
    pass


SESSIONS_EVERY = 15 * 60
SESSIONS_MEANING = ("Signed-in sessions of this account as Telegram lists them. 'current' is this workspace's session; "
                    "its address is stored as a SHA-256 digest with Telegram's country and region.")


def sessions_snapshot(authorizations):
    def entry(a):
        return {"hash": str(a.hash), "device_model": a.device_model, "app_name": a.app_name,
                "app_version": a.app_version, "api_id": a.api_id, "official_app": bool(a.official_app),
                "country": a.country, "region": a.region, "created_at": date_string(a.date_created)}
    current = next((a for a in authorizations if a.current), None)
    return {"current": {**entry(current), "ip_sha256": hashlib.sha256((current.ip or "").encode()).hexdigest()}
            if current else None,
            "others": sorted((entry(a) for a in authorizations if not a.current), key=lambda e: e["hash"])}


BULK_DELETION = 10
BULK_MEANING = ("Many messages disappeared in one Telegram update: the history was cleared or bulk-deleted. "
                "If it includes messages this account sent, the other side cleared the chat for both.")
ACCESS_LOST_MEANING = ("The account was removed from this chat or can no longer read it. Observation of this chat "
                       "stopped at that moment; records saved before it remain in the journal.")


SALVAGE_WINDOW = 100
SALVAGE_LIMIT = 20
UNPARSED_MEANING = ("Telegram has a message under this number, but it contains a data type that Telethon "
                    "layer {layer} cannot decode. Its content is not in this export; read it again after a "
                    "Telegram schema update.")


def unparsed_record(number, error):
    return {"id": number, "type": "unparsed", "date": None, "date_unixtime": None, "edited": None,
            "from": None, "from_id": None, "from_username": None, "reply_to_message_id": None,
            "text": "", "reply_to": None,
            "unparsed": {"constructor": format(error.invalid_constructor_id, "08x"), "telethon_layer": LAYER,
                         "remainder_sha256": hashlib.sha256(error.remaining or b"").hexdigest(),
                         "meaning": UNPARSED_MEANING.format(layer=LAYER)}}


def unreadable_history(error):
    return UnreadableHistory(
        "Telegram sends this chat a data type that Telethon layer " + str(LAYER) + " cannot decode (constructor "
        + format(error.invalid_constructor_id, "08x") + ") in almost every answer, so its history cannot be read "
        "message by message. Update TgWitness to a release with a newer Telegram schema.")


AUTHORIZATION_ERRORS = (AuthorizationRequired, AuthKeyDuplicatedError, AuthKeyInvalidError,
                        AuthKeyUnregisteredError, SessionExpiredError, SessionRevokedError,
                        UserDeactivatedBanError, UserDeactivatedError, FrozenMethodInvalidError)


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
# The client description in the connection request Telegram receives.
CLIENT_FIELDS = ("device_model", "system_version", "app_version", "lang_code", "system_lang_code")
CLOCK_TIMEOUT = 10
PROFILE_TIMEOUT = 30
PROFILE_FLAGS = ("scam", "fake", "verified", "restricted", "noforwards", "broadcast", "megagroup", "gigagroup",
                 "signatures", "join_to_send", "join_request", "slowmode_enabled")
ROLES = {"ChannelParticipantCreator": "creator", "ChannelParticipantAdmin": "admin", "ChannelParticipantSelf": "member",
         "ChannelParticipant": "member", "ChannelParticipantBanned": "restricted", "ChannelParticipantLeft": "left",
         "ChatParticipantCreator": "creator", "ChatParticipantAdmin": "admin", "ChatParticipant": "member"}
RECHECK_LIMIT = 10000
ADMIN_LOG_LIMIT = 10000
ADMIN_LOG_MEANING = ("The chat's admin log as Telegram returned it to this admin account: Telegram keeps about the last "
                     "48 hours. Deleted and edited messages appear with their content and the account that acted.")
CLOCK_METHOD = ("updates.getState: Telegram's time in whole seconds against the collector's clock halfway through the "
                "request; offset is Telegram minus collector")
ACCOUNT_LOSS = ((UserDeactivatedBanError, "USER_DEACTIVATED_BAN", "account_banned"),
                (UserDeactivatedError, "USER_DEACTIVATED", "account_deleted"),
                (AuthKeyDuplicatedError, "AUTH_KEY_DUPLICATED", "session_duplicated"),
                (SessionRevokedError, "SESSION_REVOKED", "session_revoked"),
                (SessionExpiredError, "SESSION_EXPIRED", "session_expired"),
                (AuthKeyUnregisteredError, "AUTH_KEY_UNREGISTERED", "session_ended"),
                (AuthKeyInvalidError, "AUTH_KEY_INVALID", "session_ended"),
                (FrozenMethodInvalidError, "FROZEN_METHOD_INVALID", "account_frozen"))
LOSS_MEANING = {
    "account_banned": "Telegram banned this account; nothing more can be observed with it.",
    "account_deleted": "The Telegram account was deleted.",
    "session_duplicated": "The same session was used in two places at once (AUTH_KEY_DUPLICATED); Telegram ended it.",
    "session_revoked": "The session was ended from another device or by Telegram.",
    "session_expired": "Telegram let the session expire.",
    "session_ended": "Telegram no longer recognises this session: it was ended or the account was removed.",
    "account_frozen": "Telegram froze this account and refuses most requests; the account can appeal through @SpamBot.",
    "not_authorized": "Telegram reports the session as signed out and gave no reason.",
}


def account_loss_cause(exc):
    return next((cause for kind, _, cause in ACCOUNT_LOSS if isinstance(exc, kind)), None)


def telegram_error(exc):
    return next((error for kind, error, _ in ACCOUNT_LOSS if isinstance(exc, kind)), type(exc).__name__)


class AccountLost(AuthorizationRequired):
    def __init__(self, cause, error=None):
        super().__init__("Telegram authorization expired. Sign in again.")
        self.cause, self.error = cause, error


def connection_change(call):
    @wraps(call)
    async def guarded(self, *args, **kwargs):
        if self.export_busy() or self.export_claim:
            raise ValueError("An export is using this account. Wait for it or cancel it before changing its connection.")
        previous, current = self.connection_change_task, asyncio.current_task()
        if previous is not None and previous is not current:
            raise ValueError("This account's connection is already being changed. Wait for it to finish.")
        self.connection_change_task = current
        try:
            return await call(self, *args, **kwargs)
        finally:
            self.connection_change_task = previous
    return guarded


def recovered_source(update):
    return "update_recovery" if getattr(update, "pts", None) == 0 else None


def media_priority(message, size):
    ttl = (getattr(message, "ttl_period", None), getattr(message.media, "ttl_seconds", None))
    if any(isinstance(value, int) and value > 0 for value in ttl):
        return 0
    return 1 if isinstance(size, int) and 0 <= size <= SMALL_MEDIA_BYTES else 10


def attachment_identity(message):
    attachment = getattr(message, "photo", None) or getattr(message, "document", None)
    if isinstance(attachment, (types.Photo, types.Document)):
        return type(attachment).__name__, attachment.id
    return None


def downloadable_media(message):
    if isinstance(message.media, types.MessageMediaWebPage):
        return message.photo or message.document
    return message.media


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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


def absent_numbers(scratch):
    numbers = set()
    with Path(scratch).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                number = json.loads(line).get("id")
                if type(number) is int:
                    numbers.add(number)
    return MissingNumbers(sorted(numbers))


def merge_history(scratch, entries):
    entries = sorted(entries, key=lambda e: e["id"], reverse=True)
    merged = Path(scratch).with_suffix(".merged")
    with Path(scratch).open(encoding="utf-8") as incoming, merged.open("w", encoding="utf-8") as outgoing:
        for line in incoming:
            if not line.strip():
                continue
            number = json.loads(line).get("id")
            while entries and type(number) is int and entries[0]["id"] > number:
                outgoing.write(json.dumps(entries.pop(0), ensure_ascii=False) + "\n")
            outgoing.write(line if line.endswith("\n") else line + "\n")
        for entry in entries:
            outgoing.write(json.dumps(entry, ensure_ascii=False) + "\n")
    merged.replace(scratch)


def date_string(value):
    return value.isoformat() if value else None


def buttons_of(message):
    return keyboard.keyboard(plain(getattr(message, "reply_markup", None)))


SENDER_FLAGS = ("bot", "scam", "fake", "premium", "verified", "restricted", "deleted")


def sender_observation(sender):
    if not sender:
        return None
    observed = {
        "id": getattr(sender, "id", None), "username": getattr(sender, "username", None),
        "display_name": utils.get_display_name(sender),
        "partial": bool(getattr(sender, "min", False)),
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


def admin_event(event):
    action = event.action
    found = {"id": event.id, "date": date_string(event.date), "user_id": event.user_id,
             "action": type(action).__name__.replace("ChannelAdminLogEventAction", "")}
    for field, key in (("message", "message"), ("prev_message", "previous"), ("new_message", "new")):
        value = getattr(action, field, None)
        if value is not None and hasattr(value, "id"):
            found[key] = message_record(value)
    for field in ("prev_value", "new_value"):
        value = getattr(action, field, None)
        if isinstance(value, (str, int, bool)):
            found[field] = value
    return found


def message_record(message):
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
        "reply_to": plain(getattr(message, "reply_to", None)),
    }
    if action:
        record["action"] = type(action).__name__
        if isinstance(getattr(action, "title", None), str):
            record["action_title"] = action.title
    if media:
        record["media_type"] = type(media).__name__
    record.update(message_details.details(plain(message)))
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
        self.observation_starting = False
        self.connection_change_task = None
        self.foreground = 0
        self.key_lock = None
        self.sessions_checked_at = -SESSIONS_EVERY
        self.people = {}
        self.avatar_lock = asyncio.Lock()
        self.avatar_failures = {}
        self.avatar_history = AvatarHistory(store, lambda: self.client)
        self.running = False
        self.phase = "offline"
        self.last_error = None
        self.authorization_required = False
        self.authorization_generation = 0
        self.authorization_cleanup = None
        self.pending_phone = None
        self.phone_hash = None
        self.dialog_cache = {}
        self.watchdog = None
        self.media_wakeup = asyncio.Event()
        self.media_worker = None
        self.urgent_media_worker = None
        self.ephemeral_media_worker = None
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
            "account_task": ("monitoring" if self.running or self.observation_starting else
                             "history" if self.history.busy else
                             "profile_image" if (self.export_claim or "").startswith("avatar:") else
                             "export" if self.export_claim else None),
            "available_for_export": not (self.running or self.observation_starting or self.export_claim
                                         or self.export_busy() or self.history.busy or self.connection_change_task),
            "connected": bool(self.client and self.client.is_connected()),
            "has_session": bool(credentials.get("session")),
            "authorization_required": self.authorization_required,
            "has_api_credentials": bool(credentials.get("api_id") and credentials.get("api_hash")),
            "builtin_api": credentials.get("api_id") is None or credentials.get("api_id") in api_pool.POOL_IDS,
            "api_pool_size": len(api_pool.POOL) - len(api_pool.rejected),
            "account": self.store.get_setting("account", None),
            "account_loss": self.store.get_setting("account_loss", None),
            "account_restriction": self.store.get_setting("account_restriction", None),
            "client": self.client_identity(credentials=credentials),
            "last_error": self.last_error, "last_heartbeat": self.last_heartbeat,
            "media_pending": sum(n for s, n in self.store.media_stats().items()
                                 if s in ("queued", "running", "retry")),
            "media_jobs": self.store.media_stats(),
            "oldest_pending_media_at": self.store.media_oldest(),
            "source_status": self.source_status_view(),
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

    def handle_authorization_error(self, exc, operation, *, client=None):
        if not isinstance(exc, AUTHORIZATION_ERRORS):
            return False
        if client is not None and client is not self.client:
            return True
        self.authorization_generation += 1
        first = not self.authorization_required
        self.authorization_required, self.running, self.buffering = True, False, False
        self.buffered = []
        self.phase, self.last_error = "authorization_required", type(exc).__name__
        cause = exc.cause if isinstance(exc, AccountLost) else account_loss_cause(exc) or "not_authorized"
        error = exc.error if isinstance(exc, AccountLost) else telegram_error(exc)
        self.store.set_setting("account_loss", {"cause": cause, "at": utcnow(), "telegram_error": error})
        if first:
            self.note("coverage.gap", {"reason": "authorization_required", "operation": operation,
                                      "error_type": type(exc).__name__, "saved_records_retained": True,
                                      "cause": cause, "telegram_error": error, "meaning": LOSS_MEANING[cause]})
        if self.authorization_cleanup is None or self.authorization_cleanup.done():
            self.authorization_cleanup = asyncio.create_task(self.cleanup_rejected_authorization(self.client))
        return True

    async def wait_authorization_cleanup(self):
        task = self.authorization_cleanup
        if task is not None and task is not asyncio.current_task():
            await asyncio.shield(task)

    async def cleanup_rejected_authorization(self, client):
        try:
            await self.cancel_workers()
            await self.history.pause("authorization_required")
            await self.avatar_history.close()
            if client is not None:
                await client.disconnect()
        except Exception as exc:
            self.note("collector.error", {"operation": "authorization cleanup", "error_type": type(exc).__name__})

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
        client = self.client
        get_entity = getattr(client, "get_entity", None)
        if not get_entity:
            return None
        try:

            return await asyncio.wait_for(get_entity(chat_id), 10)
        except AUTHORIZATION_ERRORS as exc:
            self.handle_authorization_error(exc, "chat lookup", client=client)
            raise
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
        while self.running:
            chat_id, entity = await self.intake.get()
            client = self.client
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
                if self.handle_authorization_error(exc, "new chat intake", client=client):
                    self.intake.put_nowait((chat_id, entity))
                    return
                self.store.append("collector.error", {
                    "operation": "new chat intake", "error_type": type(exc).__name__,
                    "coverage": "messages of this chat are still recorded live; its profile or earlier "
                                "messages may be missing"}, chat_id)

    async def capture_profile(self, chat_id, entity):
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
        event = self.store.append("source.profile", {
            "title": utils.get_display_name(entity), "kind": kind_of(entity), "username": getattr(entity, "username", None),
            **info, "raw": plain(full),
            "meaning": "what Telegram returned to this account about the chat at this time; descriptions are mutable"},
            chat_id)
        self.remember(entity, chat_id=chat_id)
        return event

    async def save_profile(self, chat_id):
        await self.restore()
        entity = self.dialog_cache.get(chat_id, {}).get("entity") or await self.lookup_entity(chat_id)
        if entity is None:
            raise ValueError("Telegram did not return this chat. Load chats and try again.")
        return await self.capture_profile(chat_id, entity)

    async def apply_scope(self, refresh=True):
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
                    "own_actions": scope["own_actions"],
                    "added": [{"chat_id": c, "title": self.dialog_cache[c]["title"], "kind": self.dialog_cache[c]["kind"]}
                              for c in added],
                    "paused": paused, "resumed": resumed, "excluded": sorted(excluded),
                    "dialogs_inspected": len(self.dialog_cache),
                    "coverage": "chats beyond the first " + str(self.param("dialog_limit")) + " dialogs are added when they "
                                "become active; earlier history of added chats is not fetched"})
        return {"added": len(added), "paused": len(paused), "resumed": len(resumed)}

    def make_client(self, api_id, api_hash, session="", client_profile=None, languages=None):
        from . import client_identity
        saved = self.vault.read("credentials")
        if client_profile is None and (saved.get("api_id"), saved.get("api_hash")) == (api_id, api_hash):
            if not session or session_key(session) == session_key(saved.get("session")):
                client_profile = saved.get("client_profile")
        supplied = {**client_identity.validate(languages), **client_identity.validate(client_profile)}
        device = client_identity.resolve(api_id, supplied, self.vault.public_key)
        options = {key: value for key, value in device.items() if key != "lang_pack"}
        string_session = StringSession(session)
        self.resumed_state_at = self.load_update_state(string_session)


        client = self.client_factory(string_session, api_id, api_hash,
                                     sequential_updates=True, flood_sleep_threshold=0,
                                     request_retries=self.param("telegram_request_retries"),
                                     connection_retries=self.param("telegram_connection_retries"),
                                     timeout=self.param("telegram_timeout_seconds"), catch_up=True,
                                     **options, **self.route_options())
        client.tgwitness_client_profile = device
        client.rpc_backoff_getter = lambda: self.store.get_setting("rpc_backoff_until", 0)
        client.rpc_backoff_setter = lambda until: self.store.set_setting("rpc_backoff_until", max(
            until, self.store.get_setting("rpc_backoff_until", 0)))
        from .rpc_pacing import AccountPacer
        client.bulk_pacer = AccountPacer(self.store)
        request = getattr(client, "_init_request", None)
        if isinstance(request, functions.InitConnectionRequest):
            request.lang_pack = device["lang_pack"]
        def rpc_error(exc):
            self.handle_authorization_error(exc, "Telegram RPC", client=client)
        client.rpc_error_handler = rpc_error
        client.connection_listener = lambda state: self.connection_changed(client, state)
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

    def imported_session(self):
        return (self.store.get_setting("account", None) or {}).get("key_origin") != "created"

    @connection_change
    async def sign_out(self):
        if self.running:
            raise ValueError("Pause observation before signing out.")
        if self.imported_session():
            raise ProtectedSession("This session was imported. Signing out would end it in Telegram for good: "
                                   "it cannot be signed in again without the phone and a login code. "
                                   "Use Forget on this computer to remove it here and leave it active in Telegram.")
        await self.cancel_login()
        credentials = self.vault.read("credentials")
        if not credentials.get("session"):
            raise ValueError("No Telegram account is connected.")
        await self.avatar_history.close()
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
        self.authorization_required = False
        account = self.store.get_setting("account", None) or {}
        self.store.append("account.signed_out", {
            "account_id": account.get("id"), "telegram_session_ended": ended,
            **({"error_type": error} if error else {}),
            "kept": "journal, sources, settings and signing key; only the same account can connect again"})
        return {"telegram_session_ended": ended, **({"error_type": error} if error else {})}

    @connection_change
    async def forget_session(self):
        if self.running:
            raise ValueError("Pause observation before forgetting the session.")
        await self.cancel_login()
        credentials = self.vault.read("credentials")
        if not credentials.get("session"):
            raise ValueError("No Telegram account is connected.")
        await self.avatar_history.close()
        client, self.client = self.client, None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass
        self.vault.save("credentials", {k: v for k, v in credentials.items() if k != "session"})
        self.dialog_cache = {}
        self.phase, self.last_error = "offline", None
        self.authorization_required = False
        account = self.store.get_setting("account", None) or {}
        self.store.append("account.forgotten", {
            "account_id": account.get("id"), "telegram_session_ended": False,
            "kept": "journal, sources, settings and signing key; the session stays active in Telegram"})
        return {"telegram_session_ended": False, "forgotten": True}

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
        saved = self.store.get_setting("route_policy", None)
        if saved is None:
            kind = self.network_config().kind
            return RoutePolicy(exposure="tunnel" if kind == "direct" else "hide",
                               outside_enabled=kind in ("direct", "socks5", "http") or self.outside_proxy() is not None).model_dump()
        return RoutePolicy.model_validate(saved).model_dump()

    def outside_proxy(self):
        saved = self.vault.read("outside_proxy")
        return saved_route(saved) if saved else None

    def outside_route(self):
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
        proposed = outside if outside is not None else None if remove_outside else self.outside_proxy()
        if (policy.exposure == "hide" and policy.outside_enabled and proposed is None
                and self.network_config().kind not in ("socks5", "http")):
            raise ValueError("Set a SOCKS5 or HTTP proxy for requests outside Telegram, or turn those requests off.")
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

    def client_identity(self, client=None, credentials=None):
        init = getattr(client or self.client, "_init_request", None)
        api_id = getattr(init, "api_id", None) or (credentials if credentials is not None
                                                   else self.vault.read("credentials")).get("api_id")
        sent = {name: getattr(init, name) for name in CLIENT_FIELDS if isinstance(getattr(init, name, None), str)}
        session = getattr(client or self.client, "session", None)
        identity = {"library": "Telethon " + telethon_version, "layer": LAYER, "api_id": api_id,
                    **({"dc_id": session.dc_id} if isinstance(getattr(session, "dc_id", None), int) else {}),
                    "api_pair": "built-in public pair" if api_id in api_pool.POOL_IDS else
                                "own application" if api_id else None,
                    **(sent or api_pool.device_for(api_id))}
        if api_id == api_pool.DESKTOP_ID:
            identity["meaning"] = "Telegram Desktop's public pair, sent with a Telegram Desktop client description"
        return identity

    async def telegram_clock(self):
        try:
            before = time.time()
            state = await asyncio.wait_for(self.client(functions.updates.GetStateRequest()), CLOCK_TIMEOUT)
            after = time.time()
            server = state.date.timestamp() + 0.5
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return {"measured_at": utcnow(), "error_type": type(exc).__name__}
        return {"measured_at": utcnow(), "telegram_time": date_string(state.date),
                "offset_seconds": round(server - (before + after) / 2, 3),
                "uncertainty_seconds": round((after - before) / 2 + 0.5, 3), "method": CLOCK_METHOD}

    async def chat_profile(self, entity, media_dir=None, *, include_photo=True):
        profile, observer, errors = {}, {}, {}
        for name in PROFILE_FLAGS:
            if isinstance(getattr(entity, name, None), bool):
                profile[name] = getattr(entity, name)
        reasons = [{"platform": getattr(r, "platform", None), "reason": getattr(r, "reason", None),
                    "text": getattr(r, "text", None)} for r in getattr(entity, "restriction_reason", None) or []]
        if reasons:
            profile["restriction_reasons"] = reasons
        names = [getattr(entity, "username", None)] + [getattr(u, "username", None)
                                                       for u in getattr(entity, "usernames", None) or []]
        if any(names):
            profile["usernames"] = list(dict.fromkeys(n for n in names if n))

        async def ask(key, request):
            try:
                return await asyncio.wait_for(request(), PROFILE_TIMEOUT)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                errors[key] = type(exc).__name__
                return None
        if isinstance(entity, types.Channel):
            answer = await ask("full_info", lambda: self.client(functions.channels.GetFullChannelRequest(entity)))
            full = getattr(answer, "full_chat", None)
            if full is not None:
                profile.update(about=full.about or None, participants_count=full.participants_count,
                               admins_count=full.admins_count, hidden_prehistory=bool(full.hidden_prehistory),
                               available_min_id=full.available_min_id, slowmode_seconds=full.slowmode_seconds,
                               linked_chat_id=-1000000000000 - full.linked_chat_id if full.linked_chat_id else None)
            answer = await ask("own_membership", lambda: self.client(functions.channels.GetParticipantRequest(
                entity, types.InputPeerSelf())))
            part = getattr(answer, "participant", None)
            if part is not None:
                observer = {"role": ROLES.get(type(part).__name__, type(part).__name__),
                            "joined_at": date_string(getattr(part, "date", None)),
                            "invited_by": getattr(part, "inviter_id", None),
                            "via_request": bool(getattr(part, "via_request", False)) or None}
                rights = getattr(part, "admin_rights", None)
                if rights is not None:
                    observer["admin_rights"] = sorted(k for k, v in rights.to_dict().items() if v is True)
        elif isinstance(entity, types.Chat):
            answer = await ask("full_info", lambda: self.client(functions.messages.GetFullChatRequest(entity.id)))
            full = getattr(answer, "full_chat", None)
            if full is not None:
                profile.update(about=full.about or None, participants_count=getattr(entity, "participants_count", None))
                me = (self.store.get_setting("account", None) or {}).get("id")
                for part in getattr(getattr(full, "participants", None), "participants", None) or []:
                    if getattr(part, "user_id", None) == me:
                        observer = {"role": ROLES.get(type(part).__name__, type(part).__name__),
                                    "joined_at": date_string(getattr(part, "date", None)),
                                    "invited_by": getattr(part, "inviter_id", None)}
        first = await ask("first_message", lambda: self.client.get_messages(entity, ids=1))
        action = getattr(first, "action", None)
        if action is not None and type(action).__name__ in ("MessageActionChannelCreate", "MessageActionChatCreate"):
            profile.update(created_at=date_string(first.date), created_title=getattr(action, "title", None))
        if getattr(getattr(entity, "photo", None), "photo_id", None):
            profile["photo_id"] = entity.photo.photo_id
            data = await ask("photo", lambda: self.client.download_profile_photo(entity, file=bytes, download_big=True)) if include_photo else None
            if isinstance(data, bytes) and data:
                digest = hashlib.sha256(data).hexdigest()
                profile["photo_sha256"] = digest
                if media_dir is not None:
                    (Path(media_dir) / digest).write_bytes(data)
        return ({k: v for k, v in profile.items() if v not in (None, "", [])},
                {k: v for k, v in observer.items() if v not in (None, "", [])}, errors)

    async def recheck_absent(self, entity, absent):
        asked, returned, started = list(islice(absent, RECHECK_LIMIT)), [], utcnow()
        for low in range(0, len(asked), 100):
            batch = asked[low:low + 100]
            for attempt in range(3):
                try:
                    answer = await self.client.get_messages(entity, ids=batch)
                    break
                except FloodWaitError as exc:
                    if attempt == 2 or exc.seconds > 600:
                        raise
                    await asyncio.sleep(exc.seconds + 1)
            returned += [m for m in answer or [] if m is not None and getattr(m, "id", None) is not None
                         and type(m).__name__ != "MessageEmpty"]
        return {"asked_at": started, "asked": len(asked), "absent_total": len(absent),
                "empty": len(asked) - len(returned), "returned": sorted(m.id for m in returned),
                "limit_reached": len(absent) > len(asked), "method": "channels.getMessages by number",
                "meaning": "An empty answer means Telegram has no message under that number for this account: deleted, "
                           "or never visible to it. Telegram does not say which."}, returned

    async def admin_log(self, entity):
        if not isinstance(entity, types.Channel):
            return None
        events, max_id = [], 0
        try:
            while len(events) < ADMIN_LOG_LIMIT:
                answer = await asyncio.wait_for(self.client(functions.channels.GetAdminLogRequest(
                    entity, q="", max_id=max_id, min_id=0, limit=100)), PROFILE_TIMEOUT)
                batch = list(getattr(answer, "events", None) or [])
                if not batch:
                    break
                for event in batch:
                    events.append(admin_event(event))
                max_id = min(e.id for e in batch)
                if len(batch) < 100:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return {"read_at": utcnow(), "events": events, "error_type": type(exc).__name__,
                    "meaning": ADMIN_LOG_MEANING} if events else None
        return {"read_at": utcnow(), "events": events, "complete": len(events) < ADMIN_LOG_LIMIT,
                "meaning": ADMIN_LOG_MEANING}

    def managed_route(self):
        managed = getattr(self, "portable_routes", None)
        selected = managed.selected() if managed else None
        return selected["mode"] if selected else None

    def route_receipt(self):
        receipt = self.network_config().receipt(self.direct_fallback)
        if receipt["kind"] == "mtproxy_auto":
            receipt["proxy_id"] = self.auto_route[0] if self.auto_route else None
        if mode := self.managed_route():
            receipt["managed"] = mode
        receipt["exposure"] = self.route_policy()["exposure"]
        return receipt

    def route_status(self):
        public = self.network_config().public(self.direct_fallback)
        if public["kind"] == "mtproxy_auto":
            public.update(self.pool().describe(self.route_owner))
        public["exposure"] = self.route_policy()["exposure"]
        public["managed"] = self.managed_route()
        check = self.store.get_setting("connection_check", None)
        public["check"] = {key: check.get(key) for key in ("telegram_connected", "exit_ip", "country", "warp", "checked_at")} \
            if check else None
        return public

    def fallback_due(self):
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
        managed = getattr(self, "portable_routes", None)
        if managed and managed.selected():
            if managed.selected().get("paused"):
                raise ValueError("The local tunnel is stopped. Start it in Connection before continuing.")
            await managed.restore()
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
        config = self.network_config()
        self.pinned_proxy = None
        if config.kind in ("socks5", "http", "mtproxy"):
            try:
                self.pinned_proxy = (config.host, await proxy_address(config))
            except RouteError as exc:
                raise ValueError(str(exc)) from None

    async def align(self, client):
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
        if self.direct_fallback:
            if time.time() >= self.pool_retry_at and (self.route_policy()["exposure"] == "hide"
                                                      or self.pool().available(self.route_owner, self.share())):
                self.pool_retry_at = 0
                await self.client.disconnect()
            return
        await self.planned_rotation()

    def lock_key(self, client):
        key = getattr(getattr(getattr(client, "session", None), "auth_key", None), "key", None)
        if not key or self.key_lock is not None and self.key_lock[0] == key:
            return
        lock = KeyLock(key)
        if self.key_lock is not None:
            self.key_lock[1].close()
        self.key_lock = (key, lock)

    def unlock_key(self):
        if self.key_lock is not None:
            self.key_lock[1].close()
            self.key_lock = None

    async def connect_client(self, client):
        self.lock_key(client)
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

    @connection_change
    async def set_network(self, config):
        if self.running:
            raise ValueError("Pause observation before changing the Telegram route.")
        policy = self.route_policy()
        if (policy['exposure'] == 'hide' and policy['outside_enabled']
                and config.kind not in ('socks5', 'http') and self.outside_proxy() is None):
            raise ValueError("Set a SOCKS5 or HTTP proxy for requests outside Telegram, or turn those requests off.")
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
            self.store.set_setting("connection_check", None)
            self.store.set_setting("resume", False)
            self.store.set_setting("auto_route", None)
            self.store.append("network.changed", config.receipt())
        self.phase = "authorization_required" if self.authorization_required else "offline"
        if not self.authorization_required:
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
        if api_id is not None or api_hash is not None:
            if not api_id or not api_hash:
                raise ValueError("Supply both API credentials or leave both empty")
            return [(api_id, api_hash)]
        saved = self.vault.read("credentials")
        api_id, api_hash = saved.get("api_id"), saved.get("api_hash")
        if api_id and api_hash and (api_id, api_hash) not in api_pool.POOL:
            return [(api_id, api_hash)]
        return api_pool.login_order((api_id, api_hash) if api_id and api_hash else None)

    async def with_api_pair(self, api_id, api_hash, attempt):
        pairs = self.login_pairs(api_id, api_hash)
        for number, (pair_id, pair_hash) in enumerate(pairs, 1):
            try:
                return await attempt(pair_id, pair_hash)
            except api_pool.PAIR_ERRORS:
                if (pair_id, pair_hash) in api_pool.POOL:
                    api_pool.reject(pair_id)
                await self.cancel_login()
                self.phase = self.resting_phase()
                if number == len(pairs):
                    raise

    async def configure(self, api_id=None, api_hash=None, session="", expected_user_id=None, client_profile=None, languages=None):
        return await self.with_api_pair(api_id, api_hash, lambda pair_id, pair_hash:
                                        self.connect_login(pair_id, pair_hash, session, expected_user_id, client_profile, languages))

    @connection_change
    async def connect_login(self, api_id, api_hash, session="", expected_user_id=None, client_profile=None, languages=None):
        from .client_identity import validate
        if client_profile is not None:
            client_profile = validate(client_profile)
        await self.wait_authorization_cleanup()
        if self.running:
            raise ValueError("Pause observation before changing accounts.")
        await self.cancel_login()

        session = validate_string(session) if session else ""
        release = self.account_guard(None, self, key=session_key(session)) if session and self.account_guard else None
        try:
            await self.ensure_route()
            candidate = self.make_client(api_id, api_hash, session, client_profile, languages)
            self.login_client = candidate
            self.pending_credentials = {"api_id": api_id, "api_hash": api_hash,
                                        "client_profile": candidate.tgwitness_client_profile}
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
                self.phase = self.resting_phase()
                raise
            self.phase = "login_required"
            return {"step": "phone"}
        finally:
            if release:
                release()

    async def start_phone(self, phone, api_id=None, api_hash=None, client_profile=None, languages=None):
        async def attempt(pair_id, pair_hash):
            await self.connect_login(pair_id, pair_hash, client_profile=client_profile, languages=languages)
            return await self.send_code(phone)
        try:
            return await self.with_api_pair(api_id, api_hash, attempt)
        except BaseException:
            await self.cancel_login()
            self.phase = self.resting_phase()
            raise

    async def start_qr(self, api_id=None, api_hash=None, client_profile=None, languages=None):
        async def attempt(pair_id, pair_hash):
            await self.connect_login(pair_id, pair_hash, client_profile=client_profile, languages=languages)
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
                        self.phase = self.resting_phase()
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
                self.phase = self.resting_phase()
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

    @connection_change
    async def authorized(self):
        await self.wait_authorization_cleanup()
        if self.running:
            raise ValueError("Pause observation before completing an account change.")
        candidate = self.login_client
        if not candidate:
            raise ValueError("Configure API credentials first.")
        release = None
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
                release = self.account_guard(me.id, self)
            credentials = dict(self.pending_credentials)
            credentials["session"] = candidate.session.save()
            await self.avatar_history.close()
            if self.client:
                await self.client.disconnect()
            # An old RPC may have failed while the candidate was being validated.
            await self.wait_authorization_cleanup()
            self.vault.save("credentials", credentials)
            with self.store.transaction():
                self.store.set_setting("account", {"id": me.id, "username": me.username,
                                                   "key_origin": self.pending_key_origin})
                self.store.set_setting("account_loss", None)
                self.store.append("account.authorized", {"account_id": me.id, "key_origin": self.pending_key_origin,
                                                         "client": self.client_identity(candidate)})
        except BaseException:
            await self.cancel_login()
            self.phase = self.resting_phase()
            raise
        finally:
            if release:
                release()
        self.client = candidate
        self.login_client = None
        self.pending_credentials = None
        self.pending_account_id = None
        if self.qr_state:
            self.qr_state["step"] = "authorized"
        self.dialog_cache = {}
        self.pending_phone = self.phone_hash = None
        self.authorization_required = False
        self.phase, self.last_error = "ready", None

    def resting_phase(self):
        if self.authorization_required:
            return "authorization_required"
        return "ready" if self.vault.read("credentials").get("session") else "offline"

    async def restore(self):
        await self.wait_authorization_cleanup()
        credentials = self.vault.read("credentials")
        if not credentials.get("session"):
            raise ValueError("Connect a Telegram account first.")
        client = self.client
        authorization_generation = self.authorization_generation
        try:
            if not client:
                await self.ensure_route()
                client = self.client = self.make_client(credentials["api_id"], credentials["api_hash"], credentials["session"])
            if not client.is_connected():
                await self.connect_client(client)
            if not await client.is_user_authorized():
                cause, error = await self.refusal(client)
                raise AccountLost(cause, error)
            if self.authorization_required:
                me = await client.get_me()
                if me is None:
                    raise AuthorizationRequired("Telegram authorization expired. Sign in again.")
                existing = self.store.get_setting("account", {}) or {}
                if existing.get("id") is not None and existing["id"] != me.id:
                    raise ValueError("This journal belongs to a different Telegram account. Create another account workspace.")
        except AUTHORIZATION_ERRORS as exc:
            self.handle_authorization_error(exc, "restore", client=client)
            raise
        if client is self.client and self.authorization_required:
            if authorization_generation != self.authorization_generation:
                raise AuthorizationRequired("Telegram authorization expired. Sign in again.")
            self.authorization_required = False
            self.phase, self.last_error = "observing" if self.running else "ready", None
        if client is self.client and authorization_generation == self.authorization_generation:
            self.store.set_setting("account_loss", None)
        if (client is self.client and authorization_generation == self.authorization_generation
                and not credentials.get("client_profile") and self.vault.read("credentials") == credentials):
            credentials["client_profile"] = client.tgwitness_client_profile
            self.vault.save("credentials", credentials)

    async def refusal(self, client):
        try:
            await client(functions.users.GetUsersRequest([types.InputUserSelf()]))
        except RPCError as exc:
            cause = account_loss_cause(exc)
            if cause:
                return cause, telegram_error(exc)
        except Exception:
            pass
        return "not_authorized", None

    def source_status_view(self):
        ignored = set(self.store.get_setting("ignored_source_warnings", []))
        enabled = {str(t["chat_id"]) for t in self.store.targets(True)}
        return {chat: {**status, **({"ignored": True} if int(chat) in ignored
                                  and status.get("state") == "access_unconfirmed" else {})}
                for chat, status in self.source_status.items() if chat in enabled}

    RECEIVING_DAYS = 7

    def source_visibility(self, chat_id, overview):
        cached = self.dialog_cache.get(chat_id)
        status = {"checked_at": utcnow(), "meaning": "Dialog visibility is not a guarantee of every update.",
                  "visibility": (cached or {}).get("visibility", "unknown"), "role": (cached or {}).get("role", "unknown")}
        lost = self.store.get_setting("lost_sources", {})
        if cached is not None:
            if str(chat_id) in lost:
                lost.pop(str(chat_id))
                self.store.set_setting("lost_sources", lost)
                self.store.append("source.access_restored", {"meaning": "The chat is visible to the account again."}, chat_id)
            return {**status, "state": "visible_in_dialogs"}
        if str(chat_id) in lost:
            return {**status, "state": "access_lost", **lost[str(chat_id)], "meaning": ACCESS_LOST_MEANING}
        last = (overview.get(chat_id) or {}).get("last_observed_at")
        if last and last >= (datetime.now(timezone.utc) - timedelta(days=self.RECEIVING_DAYS)).isoformat(timespec="milliseconds"):
            return {**status, "state": "receiving_updates", "last_observed_at": last}
        reason = "beyond_dialog_limit" if getattr(self, "dialogs_truncated", False) else "not_in_dialogs"
        return {**status, "state": "access_unconfirmed", "reason": reason}

    def refresh_source_visibility(self):
        targets = self.store.targets(True)
        statuses, overview = {}, self.store.chat_overview()
        with self.store.transaction():
            ignored = set(self.store.get_setting("ignored_source_warnings", []))
            resolved = self.store.get_setting("resolved_source_warnings", {})
            returned = ignored.intersection(self.dialog_cache, (t["chat_id"] for t in targets))
            for target in targets:
                chat_id = target["chat_id"]
                statuses[str(chat_id)] = self.source_visibility(chat_id, overview)
                if chat_id in returned:
                    receipt = self.store.append("target.changed", {"title": target["title"], "enabled": True,
                                                                   "ignore_unconfirmed": False,
                                                                   "reason": "source visible in account dialogs"}, chat_id)
                    resolved[str(chat_id)] = receipt["seq"]
            if returned:
                self.store.set_setting("ignored_source_warnings", sorted(ignored - returned))
                self.store.set_setting("resolved_source_warnings", resolved)
        self.source_status = statuses

    async def dialogs(self):
        await self.restore()
        dialogs = {}
        count, limit = 0, self.param("dialog_limit")

        async for dialog in self.client.iter_dialogs(limit=limit):
            count += 1
            entity = getattr(dialog, "entity", None)
            kind = kind_of(entity) or (
                "supergroup" if getattr(entity, "megagroup", False) else "channel" if dialog.is_channel
                else "group" if dialog.is_group else "bot" if getattr(entity, "bot", False) else "private")
            dialogs[dialog.id] = {
                "chat_id": dialog.id, "title": dialog.name, "kind": kind, "entity": entity,
                "archived": getattr(dialog, "folder_id", None) == 1,
                "visibility": "public_username" if getattr(entity, "username", None) else "private_or_unlisted",
                "role": "creator" if getattr(entity, "creator", False)
                        else "administrator" if getattr(entity, "admin_rights", None) else "member_or_unknown",
            }
        await self.load_folders()
        self.dialog_cache = dialogs
        self.dialogs_truncated = count >= limit
        self.refresh_source_visibility()
        return {"dialogs": [{k: v for k, v in d.items() if k != "entity"}
                            for d in self.dialog_cache.values()],
                "folders": [{"id": f["id"], "title": f["title"],
                             "chats": sum(1 for c, d in self.dialog_cache.items()
                                          if in_folder(f, c, d["kind"], d["entity"], d["archived"]))}
                            for f in self.folders.values()],
                "limit": limit, "may_be_truncated": count >= limit}

    def connection_changed(self, client, state):
        role = "current" if client is self.client else "candidate" if client is self.login_client else "other"
        key = getattr(getattr(getattr(client, "session", None), "auth_key", None), "key", None)
        if state == "opened":
            self.lock_key(client)  # A new login receives its auth key during connect.
        if state == "closed" and self.key_lock is not None and self.key_lock[0] == key:
            self.unlock_key()
        self.note("connection." + state, {"role": role, "route": self.route_receipt(),
                                          "dc_id": getattr(client.session, "dc_id", None)})
        if state == "opened" and role == "current" and time.monotonic() - self.sessions_checked_at > SESSIONS_EVERY:
            self.sessions_checked_at = time.monotonic()
            with suppress(RuntimeError):
                asyncio.get_running_loop().create_task(self.check_sessions(client))

    async def check_sessions(self, client=None):
        client = client or self.client
        await asyncio.sleep(0)
        try:
            result = await asyncio.wait_for(client(functions.account.GetAuthorizationsRequest()), 30)
        except Exception:
            return None
        snapshot = sessions_snapshot(result.authorizations)
        previous = self.store.get_setting("sessions_seen", None)
        if previous != snapshot:
            known = {s["hash"] for s in (previous or {}).get("others", [])}
            now = {s["hash"] for s in snapshot["others"]}
            self.store.set_setting("sessions_seen", snapshot)
            self.store.append("account.sessions", {
                **snapshot, "added": sorted(now - known) if previous else None,
                "removed": sorted(known - now) if previous else None, "meaning": SESSIONS_MEANING})
        return snapshot

    async def account_sessions(self):
        await self.restore()
        result = await asyncio.wait_for(self.client(functions.account.GetAuthorizationsRequest()), 30)
        await self.check_sessions()
        return {"sessions": [{
            "hash": str(a.hash), "current": bool(a.current), "device_model": a.device_model, "platform": a.platform,
            "app_name": a.app_name, "app_version": a.app_version, "official_app": bool(a.official_app),
            "country": a.country, "region": a.region, "created_at": date_string(a.date_created),
            "active_at": date_string(a.date_active), "password_pending": bool(a.password_pending)}
            for a in result.authorizations], "inactive_ttl_days": getattr(result, "authorization_ttl_days", None)}

    async def end_session(self, session_hash):
        await self.restore()
        result = await asyncio.wait_for(self.client(functions.account.GetAuthorizationsRequest()), 30)
        target = next((a for a in result.authorizations if str(a.hash) == str(session_hash)), None)
        if target is None:
            raise ValueError("This session is no longer signed in.")
        if target.current:
            raise ProtectedSession("This is the session TgWitness works on. It cannot be ended from here.")
        try:
            await self.client(functions.account.ResetAuthorizationRequest(hash=target.hash))
        except FreshResetAuthorisationForbiddenError:
            raise ValueError("Telegram lets a session end other sessions only after it has been signed in for "
                             "24 hours.") from None
        self.store.append("account.session_ended", {
            "device_model": target.device_model, "app_name": target.app_name, "app_version": target.app_version,
            "country": target.country, "created_at": date_string(target.date_created),
            "ended_by": "the operator, from this workspace"})
        await self.check_sessions()
        return {"ended": True}

    async def change_password(self, current_password, new_password, hint=""):
        await self.restore()
        try:
            await self.client.edit_2fa(current_password=current_password or None, new_password=new_password,
                                       hint=hint or "")
        except PasswordHashInvalidError:
            raise ValueError("The current two-step password is wrong.") from None
        self.store.append("account.password_changed", {
            "had_password": bool(current_password), "hint_set": bool(hint),
            "meaning": "The two-step password was set or changed from this workspace; it is not stored here."})
        return {"changed": True}

    async def signed_in_devices(self):
        if not (self.running and self.client and self.client.is_connected()):
            raise ValueError("Telegram is not connected: observation is paused or reconnecting.")
        result = await asyncio.wait_for(self.client(functions.account.GetAuthorizationsRequest()), 30)
        return [{"hash": str(a.hash), "current": bool(a.current), "official_app": bool(a.official_app),
                 "password_pending": bool(a.password_pending), "unconfirmed": bool(a.unconfirmed),
                 "device_model": a.device_model, "platform": a.platform, "system_version": a.system_version,
                 "app_name": a.app_name, "app_version": a.app_version, "api_id": a.api_id,
                 "created_at": date_string(a.date_created), "active_at": date_string(a.date_active),
                 "country": a.country, "region": a.region} for a in result.authorizations]

    async def load_folders(self):
        own = (self.store.get_setting("account", {}) or {}).get("id")
        client = self.client
        try:
            result = await asyncio.wait_for(client(functions.messages.GetDialogFiltersRequest()), 15)
        except FloodWaitError:
            raise
        except AUTHORIZATION_ERRORS as exc:
            self.handle_authorization_error(exc, "dialog folders", client=client)
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
        from .settings_hub import validate_collection_scope
        validate_collection_scope(self.store)
        if self.running:
            return
        if self.export_claim or self.export_busy() or self.history.busy or self.observation_starting:
            raise ValueError("This account is busy. Pause its current task before starting observation.")
        self.observation_starting = True
        client = self.client
        try:
            await self.start_observation()
        except BaseException as exc:
            self.buffered, self.buffering = [], False
            if self.running:
                with suppress(Exception):
                    await self.stop()
                self.running = False
                await self.cancel_workers()
                await self.avatar_history.close()
                if self.client and not (self.export_busy() or self.export_claim):
                    with suppress(Exception):
                        await self.client.disconnect()
            if isinstance(exc, AUTHORIZATION_ERRORS):
                self.handle_authorization_error(exc, "start observation", client=client)
            raise
        finally:
            self.observation_starting = False

    async def start_observation(self):
        if (self.watchdog or self.media_worker or self.urgent_media_worker or self.ephemeral_media_worker
                or self.reconciler or self.intake_worker):
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
        clock = await self.telegram_clock()
        self.running, self.phase, self.last_error = True, "observing", None
        self.store.set_setting("resume", True)
        self.store.append("observation.started", {
            "run_id": self.run_id, "monotonic_ns": time.monotonic_ns(),
            "account": self.store.get_setting("account", None),
            "client": self.client_identity(), "route": self.route_receipt(), "clock": clock,
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
        self.media_worker = asyncio.create_task(self.supervise(lambda: self.download_worker("bulk"), "media worker"))
        self.urgent_media_worker = asyncio.create_task(
            self.supervise(lambda: self.download_worker("urgent"), "urgent media worker"))
        self.ephemeral_media_worker = asyncio.create_task(
            self.supervise(lambda: self.download_worker("ephemeral"), "self-destructing media worker"))
        self.reconciler = asyncio.create_task(self.supervise(self.recheck_loop, "recheck"))
        self.intake_worker = asyncio.create_task(self.supervise(self.intake_loop, "new chat intake"))
        catch_up = getattr(self.client, "catch_up", None)
        if catch_up:
            await catch_up()

    async def prepare_start(self):
        await self.restore()

        await self.dialogs()
        await self.apply_scope(refresh=False)
        self.source_status, overview = {}, self.store.chat_overview()
        for target in self.store.targets(True):
            status = self.source_visibility(target["chat_id"], overview)
            self.source_status[str(target["chat_id"])] = status
            if status["state"] == "access_unconfirmed":
                self.store.append("source.access_unconfirmed", {
                    "reason": "beyond the chats listed for this account (dialog_limit)"
                              if status["reason"] == "beyond_dialog_limit"
                              else "not present in the enumerated account dialogs",
                    "other_sources_continue": True}, target["chat_id"])
        if scope_settings(self.store)["mode"] == "selected" and not any(
                s["state"] in ("visible_in_dialogs", "receiving_updates") for s in self.source_status.values()):
            raise ValueError("None of the selected sources was visible in the account dialogs. Check membership and refresh.")

    async def supervise(self, work, name):
        client = self.client
        try:
            await work()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if self.handle_authorization_error(exc, name, client=client):
                return
            await self.failure(exc, name, client=client, fatal=True)

    async def cancel_workers(self):
        tasks = (self.watchdog, self.media_worker, self.urgent_media_worker, self.ephemeral_media_worker,
                 self.reconciler, self.intake_worker)
        tasks = tuple(task for task in tasks if task and task is not asyncio.current_task())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self, shutdown=False):
        await self.wait_authorization_cleanup()
        await self.history.pause("process_shutdown" if shutdown else "observation_stopped")
        if shutdown and self.export_task:
            self.export_task.cancel()
            await asyncio.gather(self.export_task, return_exceptions=True)
        active = self.running
        if active:
            self.persist_update_state()
        self.running = False
        self.buffered, self.buffering = [], False
        await self.cancel_workers()
        self.watchdog = self.media_worker = self.urgent_media_worker = self.reconciler = self.intake_worker = None
        self.ephemeral_media_worker = None
        await self.avatar_history.close()
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
                from .people import refresh_one
                await refresh_one(self)
                if time.monotonic() - self.sessions_checked_at > SESSIONS_EVERY:
                    self.sessions_checked_at = time.monotonic()
                    await self.check_sessions()
            if checkpoint_at is None or now - checkpoint_at >= self.param("checkpoint_minutes") * 60 - 1:
                checkpoint_at = now
                retain_checkpoint(self.store, self.vault)
            await asyncio.sleep(min(10, interval))

    async def note_drop(self):
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
        client = self.client
        try:
            await self.restore()
        except AUTHORIZATION_ERRORS as exc:
            self.handle_authorization_error(exc, "reconnect", client=client)
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

    async def failure(self, exc, context, *, client=None, fatal=False):
        if self.handle_authorization_error(exc, context, client=client):
            return
        self.last_error = type(exc).__name__
        if fatal:
            self.running, self.phase = False, "collector_error"
        try:
            self.store.append("collector.error", {"operation": context, "error_type": type(exc).__name__,
                                                 "observation_stopped": fatal, "run_id": self.run_id,
                                                 "coverage": "this update may not have been recorded"})
            if fatal:
                self.store.append("observation.stopped", {"reason": "collector_error", "operation": context,
                                                          "run_id": self.run_id})
        except Exception:
            self.running, self.phase = False, "storage_error"
            fatal = True
        if fatal:
            self.buffered, self.buffering = [], False
            await self.cancel_workers()
            await self.avatar_history.close()
            if self.client and not (self.export_busy() or self.export_claim):
                await self.client.disconnect()

    async def capture_message(self, message, kind, chat_id, update=None, source=None, history_run_id=None,
                              acquisition=None):
        started = time.perf_counter()
        payload = describe_message(message)
        payload["source"] = source or ("history_snapshot" if kind == "message.snapshot" else "live_update")
        payload["collector_account_id"] = (self.store.get_setting("account", {}) or {}).get("id")
        payload["run_id"] = self.run_id
        if history_run_id is not None:
            payload["history_run_id"] = history_run_id
        if acquisition is not None:
            payload["acquisition"] = acquisition
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
        ephemeral_media = ephemeral.describe(getattr(message, "media", None))
        if ephemeral_media:
            payload["ephemeral_media"] = ephemeral_media
        if message.media:
            settings = capture_settings(self.store)
            account = self.store.get_setting("account", {}) or {}
            media_type = media_kind(message) if message.file else None
            rule = effective_media_rule(settings, media_type, ephemeral_media) if media_type else None
            if ephemeral_media and ephemeral_media["availability"] == "unavailable_at_observation":
                media_skip = "ephemeral_attachment_unavailable_at_observation"
            elif not settings["download_media"]:
                if settings["record_disabled_media"] or ephemeral_media:
                    media_skip = "media download disabled"
            elif not message.file:
                media_skip = "metadata-only media type; no downloadable file"
            elif not duration_allowed(message, rule):
                media_skip = "video duration unknown or above the selected limit"
            elif not rule["enabled"]:
                media_skip = "attachment type not collected by policy: " + media_type
            elif not account.get("id"):
                media_skip = "authorized account identity unavailable"
            else:
                descriptor = bytes(message)
                size = getattr(message.file, "size", None)
                job = {"account_id": account["id"], "descriptor": descriptor,
                       "max_bytes": rule["max_mb"] * 1024**2,
                       "priority": media_priority(message, size), "estimated_bytes": size}
                payload["media_capture"] = {
                    "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
                    "account_id": account["id"], "max_bytes": job["max_bytes"], "media_type": media_type,
                    "priority": job["priority"], "estimated_bytes": size,
                    "action": media_action(settings, rule, size),
                    "policy": "original observed descriptor; never substitute a newer message"}
                if ephemeral_media:
                    payload["media_capture"]["ephemeral_media"] = ephemeral_media
                    base = settings["types"][media_type]
                    # Self-destructing media is fetched even where the type or duration rule would skip it;
                    # the record says which rule was set aside and what still applies.
                    overridden = ([] if base["enabled"] else ["type_not_collected"]) + (
                        [] if duration_allowed(message, base) else ["duration_limit"])
                    if overridden and settings["preserve_ephemeral_media"]:
                        payload["media_capture"]["rule_override"] = {
                            "setting": "preserve_ephemeral_media", "overridden": overridden,
                            "still_applied": "per-type size ceiling, free-disk reserve and FloodWait limits"}
        event = self.store.append(kind, payload, chat_id, message.id,
                                  message.sender_id if kind in ("message.new", "message.recovered") else None,
                                  date_string(getattr(message, "edit_date", None) or message.date),
                                  media_job=job)
        self.remember(getattr(message, "sender", None), chat_id=chat_id)
        if getattr(message, "action", None):
            self.store.append("membership.service" if isinstance(message.action, (
                types.MessageActionChatAddUser, types.MessageActionChatDeleteUser,
                types.MessageActionChatJoinedByLink, types.MessageActionChatJoinedByRequest
            )) else "chat.service", {
                "message_event": event["seq"], "action": plain(message.action),
                "attribution": "service-message sender; meaning depends on the action type"
            }, chat_id, message.id, message.sender_id, date_string(message.date))
        if media_skip:
            status = "unavailable" if media_skip == "ephemeral_attachment_unavailable_at_observation" else "not_saved"
            self.store.append("media.skipped", {"message_event": event["seq"], "reason": media_skip,
                **(ephemeral.outcome(ephemeral_media, status) if ephemeral_media else {})},
                              chat_id, message.id)
        if job:
            self.media_wakeup.set()
        self.last_update_at = utcnow()
        self.max_handler_ms = max(self.max_handler_ms, (time.perf_counter() - started) * 1000)
        return event

    def own_skipped(self, message):
        return bool(getattr(message, "out", False)) and not scope_settings(self.store)["own_actions"]

    async def on_new(self, event):
        client = self.client
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
            await self.failure(exc, "message.new", client=client)

    async def on_edit(self, event):
        client = self.client
        if not (self.running and monitoring_settings(self.store)["edits"]) or self.own_skipped(event.message):
            return
        try:
            if not await self.covers(event.chat_id, getattr(event, "chat", None)):
                return
            content = self.store.message_state(event.chat_id, event.message.id)["content"]
            payload = describe_message(event.message)
            if content and content["observable"] == message_content.of_payload(payload) \
                    and content["edited_at"] == payload.get("edited_at"):
                return
            await self.capture_message(event.message, "message.edited", event.chat_id,
                                       getattr(event, "original_update", None))
        except Exception as exc:
            await self.failure(exc, "message.edited", client=client)

    def record_deletion(self, chat_id, message_id, raw, resolution=None, batch=None):
        state = self.store.message_state(chat_id, message_id)
        if state["deleted"]:
            return
        payload = {"deleted_by": None, "deletion_time": None,
                   "meaning": "Telegram deletion notification; observation time is not deletion time",
                   **({"batch": batch} if batch else {"raw": raw})}
        if resolution:
            payload["chat_resolution"] = resolution
        if state["content"] and state["content"].get("outgoing"):
            payload["deleted_message_was_outgoing"] = True
            payload["deleter_visibility"] = "the message was sent by this account; who deleted it is not supplied"
        self.store.append("message.deleted", payload, chat_id, message_id)

    def deletion_batch(self, chat_id, ids, raw):
        if len(ids) < 2:
            return None
        outgoing = sum(1 for message_id in ids
                       if ((self.store.message_state(chat_id, message_id)["content"] or {}).get("outgoing")))
        event = self.store.append("history.cleared" if len(ids) >= BULK_DELETION else "deletion.batch", {
            "count": len(ids), "first_id": min(ids), "last_id": max(ids), "message_ids": sorted(ids),
            "outgoing_saved": outgoing, "raw": raw,
            "meaning": BULK_MEANING if len(ids) >= BULK_DELETION else "Several messages deleted in one Telegram update."},
            chat_id)
        return {"seq": event["seq"], "hash": event["hash"], "count": len(ids)}

    async def on_delete(self, event):
        client = self.client
        if not self.running or not monitoring_settings(self.store)["deletions"]:
            return
        try:
            raw = plain(event.original_update)
            if event.chat_id is None:


                unresolved, by_chat = [], {}
                for message_id in event.deleted_ids:
                    chat_id = self.store.account_message_chat(message_id)
                    if chat_id is not None and await self.covers(chat_id):
                        by_chat.setdefault(chat_id, []).append(message_id)
                    else:
                        unresolved.append(message_id)
                for chat_id, ids in by_chat.items():
                    batch = self.deletion_batch(chat_id, ids, raw)
                    for message_id in ids:
                        self.record_deletion(chat_id, message_id, raw, {
                            "method": "chat of the previously saved message with this ID",
                            "basis": "private chats and ordinary groups share one account-wide message ID sequence"},
                            batch=batch)
                if unresolved:
                    self.store.append("deletion.unscoped", {
                        "message_ids": unresolved, "scope": "account-level update; no saved message has these IDs",
                        "deleted_by": None, "raw": raw})
            elif await self.covers(event.chat_id):
                batch = self.deletion_batch(event.chat_id, list(event.deleted_ids), raw)
                for message_id in event.deleted_ids:
                    self.record_deletion(event.chat_id, message_id, raw, batch=batch)
        except Exception as exc:
            await self.failure(exc, "message.deleted", client=client)

    async def check_access(self, chat_id, update):
        try:
            if chat_id < -1000000000000:
                peer = await self.client.get_input_entity(types.PeerChannel(-1000000000000 - chat_id))
                answer = await self.client(functions.channels.GetChannelsRequest([peer]))
            else:
                answer = await self.client(functions.messages.GetChatsRequest([-chat_id]))
            chat = answer.chats[0] if answer.chats else None
        except (ChannelPrivateError, ChannelInvalidError):
            chat = None
        if chat is None or isinstance(chat, (types.ChannelForbidden, types.ChatForbidden)):
            self.access_lost(chat_id, "no_access", update)
        elif getattr(chat, "left", False) or getattr(chat, "deactivated", False):
            self.access_lost(chat_id, "not_a_member", update)

    def access_lost(self, chat_id, reason, update=None):
        lost = self.store.get_setting("lost_sources", {})
        if str(chat_id) in lost:
            return
        lost[str(chat_id)] = {"lost_at": utcnow(), "reason": reason}
        self.store.set_setting("lost_sources", lost)
        self.store.append("source.access_lost", {"reason": reason, "meaning": ACCESS_LOST_MEANING,
                                                 **({"raw": plain(update)} if update is not None else {})}, chat_id)
        self.store.append("coverage.gap", {"reason": "source_access_lost", "cause": reason,
                                           "completeness": "nothing is received from this chat after this point",
                                           "meaning": ACCESS_LOST_MEANING}, chat_id)
        self.source_status[str(chat_id)] = {"state": "access_lost", "checked_at": utcnow(), **lost[str(chat_id)],
                                            "meaning": ACCESS_LOST_MEANING}

    async def on_raw(self, update):
        client = self.client
        if not self.running:
            return
        try:
            settings = monitoring_settings(self.store)
            if isinstance(update, (types.UpdateUserStatus, types.UpdateUserName, types.UpdateUser)):
                from .people import observe_update
                observe_update(self.store, update, profiles=settings["profiles"], presence=settings["presence"], raw=plain(update))
                return
            if isinstance(update, types.UpdateChannel):
                chat_id = utils.get_peer_id(types.PeerChannel(update.channel_id))
                if self.selected(chat_id):
                    await self.check_access(chat_id, update)
                return
            if isinstance(update, (types.UpdateNewMessage, types.UpdateNewChannelMessage)) and isinstance(
                    update.message, types.MessageService):

                chat_id = utils.get_peer_id(update.message.peer_id)
                action = update.message.action
                me = (self.store.get_setting("account", None) or {}).get("id")
                if (isinstance(action, types.MessageActionChatDeleteUser) and action.user_id == me
                        and self.selected(chat_id)):
                    await self.check_access(chat_id, update)
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
            elif isinstance(update, (types.UpdatePinnedChannelMessages, types.UpdatePinnedMessages)) and not update.pinned:
                chat_id = (utils.get_peer_id(types.PeerChannel(update.channel_id))
                           if isinstance(update, types.UpdatePinnedChannelMessages) else utils.get_peer_id(update.peer))
                if await self.covers(chat_id):
                    for message_id in update.messages:
                        self.store.append("message.unpinned", {
                            "unpinned_by": None, "raw": plain(update),
                            "meaning": "Telegram reported that this message is no longer pinned; it does not say who unpinned it."},
                            chat_id, message_id)
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
            await self.failure(exc, "raw.update", client=client)

    async def recheck_loop(self):
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
                client = self.client
                try:
                    await self.apply_scope()
                except FloodWaitError as exc:
                    self.store.set_setting("rpc_backoff_until", time.time() + exc.seconds)
                    self.store.append("telegram.backoff", {"operation": "scope refresh",
                                                           "retry_after_seconds": exc.seconds})
                    continue
                except Exception as exc:
                    if self.handle_authorization_error(exc, "scope refresh", client=client):
                        return
                    self.scope_refreshed_at = time.time()
                    self.store.append("collector.error", {"operation": "scope refresh", "error_type": type(exc).__name__,
                                                         "coverage": "new chats are still added when they become active"})
            due = self.due_targets(forced)
            forced = False
            if due:
                await self.recheck_pass(due)

    def mark_recheck_start(self):
        walked = self.store.get_setting("recheck_walked", {})
        for target in self.store.targets(True):
            key = str(target["chat_id"])
            if key not in walked and (last := self.store.last_message_id(target["chat_id"])) is not None:
                walked[key] = last
        self.store.set_setting("recheck_walked", walked)

    def due_targets(self, forced=False):
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
            client = self.client
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
                if self.handle_authorization_error(exc, "recheck", client=client):
                    break
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

                floors[str(chat_id)] = await self.number_before(entity)
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
        newest = self.store.alive_message_ids(chat_id, limit=batch, include_missing=True)
        older = []
        if len(newest) == batch:
            cursors = self.store.get_setting("recheck_cursor", {})
            below = min(cursors.get(str(chat_id)) or newest[-1], newest[-1])
            older = self.store.alive_message_ids(chat_id, below=below, limit=batch, include_missing=True)
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
            elif not self.own_skipped(message):
                state = self.store.message_state(chat_id, message_id)
                content = state["content"]
                payload = describe_message(message)
                changed = content and (content["observable"] != message_content.of_payload(payload)
                                       or content["edited_at"] != payload.get("edited_at"))
                if settings["edits"] and changed:
                    await self.capture_message(message, "message.edited", chat_id, source="recheck")
                    result["edited"] += 1
                elif state["missing"]:
                    await self.capture_message(message, "message.recovered", chat_id, source="recheck")
                    result["recovered"] += 1
        result.update(checked=len(ids), checked_from=min(ids), checked_to=max(ids))
        if missing and settings["deletions"]:
            if len(missing) == len(ids):
                try:
                    probe = await self.client.get_messages(entity, limit=1)
                except TypeNotFoundError:
                    probe = [True]
                if not probe or not any(message is not None for message in probe):
                    self.store.append("coverage.gap", {
                        "reason": "recheck_visibility_uncertain", "checked_from": min(ids), "checked_to": max(ids),
                        "meaning": "No requested messages or visible history were returned. Individual messages "
                                   "were not marked missing because chat access could not be confirmed."}, chat_id)
                    result["visibility_uncertain"] = True
                    return result
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
        owner = None
        if origin is None:
            owner = "snapshot:" + secrets.token_hex(16)
            if not self.reserve_export(owner):
                raise ValueError("This account is busy. Pause its current task before loading history.")
        try:
            return await self._snapshot(chat_id, limit, entity, origin)
        finally:
            if owner:
                try:
                    await self.avatar_history.close()
                finally:
                    self.release_export(owner)

    async def _snapshot(self, chat_id, limit, entity=None, origin=None):
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
        if (self.running or self.observation_starting or self.history.busy or self.export_busy()
                or self.export_claim or self.connection_change_task is not None):
            return False
        self.export_claim = owner
        return True

    def release_export(self, owner):
        if self.export_claim == owner:
            self.export_claim = None
            self.close_when_idle()

    def idle(self):
        return not (self.running or self.observation_starting or self.history.busy or self.export_busy()
                    or self.export_claim or self.connection_change_task is not None or self.foreground
                    or self.login_client is not None or self.qr_task is not None)

    def close_when_idle(self):
        try:
            asyncio.get_running_loop().create_task(self.release_idle_connection())
        except RuntimeError:
            pass

    async def release_idle_connection(self):
        await asyncio.sleep(0)
        client = self.client
        try:
            if not self.idle() or client is None or not client.is_connected():
                return False
            await self.avatar_history.close()
            if not self.idle() or self.client is not client:
                return False
            await client.disconnect()
        except Exception:
            return False
        return True

    def note(self, kind, payload, chat_id=None):
        try:
            self.store.append(kind, payload, chat_id)
        except Exception:
            pass

    async def chat_scale(self, chat_id):
        owner = "scale:" + secrets.token_hex(16)
        if not self.reserve_export(owner):
            raise ValueError("This account is busy. Pause its current task before preparing an export.")
        try:
            return await self._chat_scale(chat_id)
        finally:
            self.release_export(owner)

    async def _chat_scale(self, chat_id):
        await self.restore()
        entity = await self.resolve_target(chat_id)
        started = time.monotonic()
        try:
            latest = await self.client.get_messages(entity, limit=1)
            last_id = latest[0].id if latest else None
        except TypeNotFoundError:
            latest = []
            for skip in (1, 2, 4, 8, 16, 32, 64):
                with suppress(TypeNotFoundError):
                    latest = await self.client.get_messages(entity, limit=1, add_offset=skip)
                    break
            last_id = await self.number_before(entity) or None
        request_seconds = time.monotonic() - started
        total = getattr(latest, "total", None) or 0

        per_chat_ids = self.dialog_cache.get(chat_id, {}).get("kind") in ("supergroup", "channel")
        pages = -(-total // 100)

        per_page = max(1.0 if total > 3000 else 0.0, request_seconds)
        return {"chat_id": chat_id, "total": total, "last_message_id": last_id,
                "ids_are_per_chat": per_chat_ids,
                "missing_ids": max(0, last_id - total) if per_chat_ids and last_id else None,
                "pages": pages, "estimate_seconds": round(pages * per_page),
                "request_seconds": round(request_seconds, 3)}

    async def start_export(self, chat_id, report_options=None, files=None):

        export_id = secrets.token_urlsafe(18)
        if not self.reserve_export(export_id):
            raise ValueError("This account is busy. Pause observation or its current task before exporting.")
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
                      "ready": False, "error": None, "started_at": utcnow(), "files": files}
            self.export_state = record
            if self.export_path:
                self.export_path.unlink(missing_ok=True)
            self.export_path = None
            self.export_task = asyncio.create_task(self.run_export(entity, info, record, report_options))

            self.export_task.add_done_callback(lambda _: self.release_export(export_id))
        except BaseException:
            self.release_export(export_id)
            raise
        await asyncio.sleep(0)
        return dict(record)

    async def run_export(self, entity, info, record, report_options=None):
        client = self.client
        directory = self.store.root / "temporary-exports"
        scratch = directory / ("tgwitness-export-chat-" + record["id"] + ".jsonl")
        out_path = directory / ("tgwitness-export-chat-" + record["id"] + ".zip")
        media_dir = directory / ("tgwitness-export-chat-" + record["id"] + "-media")
        chat_id = record["chat_id"]
        try:

            directory.mkdir(mode=0o700, exist_ok=True)
            media_dir.mkdir(mode=0o700, exist_ok=True)
            files = record.get("files")
            settings = capture_settings(self.store)
            self.store.append("chat_export.started", {"chat_id": chat_id, "title": info.get("title"),
                                                      "meaning": "full visible history snapshot",
                                                      "attachments": files or ("within the workspace's attachment settings"
                                                      if settings["download_media"] else "off")},
                              chat_id)
            clock = await self.telegram_clock()
            profile, observer, problems = await self.chat_profile(entity, media_dir,
                include_photo=files not in ("skip", "hashes") and settings["download_media"] and settings["include_avatars"])
            count = await self.stream_history(entity, scratch, record, media_dir, files)
            recheck = None
            if chat_id < -1000000000000:
                absent = absent_numbers(scratch)
                if absent:
                    try:
                        recheck, missed = await self.recheck_absent(entity, absent)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        recheck, missed = {"asked_at": utcnow(), "asked": 0, "absent_total": len(absent),
                                           "error_type": type(exc).__name__}, []
                    if missed:
                        merge_history(scratch, [{**message_record(m), "found_on_recheck": True,
                                                 **(await self.export_attachment(m, media_dir, files))} for m in missed])
                    count += len(missed)
            log = await self.admin_log(entity) if observer.get("role") in ("creator", "admin") else None
            meta = {"chat": {"id": chat_id, "title": info.get("title"), "kind": info.get("kind"),
                             "visibility": info.get("visibility"), "profile": profile,
                             **({"profile_errors": problems} if problems else {})},
                    "observer": observer, "recheck": recheck, "admin_log": log,
                    "journal": chat_export.journal_changes(self.store, chat_id),
                    "account": self.store.get_setting("account", None), "message_count": count,
                    "client": self.client_identity(), "route": self.route_receipt(),
                    "acquisition": {"started_at": record.get("started_at"), "finished_at": utcnow(),
                                    "files": files or "workspace_settings",
                                    "clock_at_start": clock, "clock_at_end": await self.telegram_clock()}}
            await complete_in_thread(chat_export.build_bundle, scratch, meta, self.vault, out_path,
                                    self.param("export_max_gib") * 1024**3, report_options, media_dir)
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
            self.handle_authorization_error(exc, "chat export", client=client)
            self.note("chat_export.interrupted", {"chat_id": chat_id, "captured": record["captured"],
                                                  "error_type": type(exc).__name__}, chat_id)
            with suppress(OSError):
                out_path.unlink(missing_ok=True)
        finally:
            with suppress(OSError):
                scratch.unlink(missing_ok=True)
            shutil.rmtree(media_dir, ignore_errors=True)

    async def read_numbers(self, entity, numbers):
        found = {}
        for start in range(0, len(numbers), 100):
            batch = numbers[start:start + 100]
            for attempt in range(3):
                try:
                    answer = await self.client.get_messages(entity, ids=batch)
                    break
                except FloodWaitError as exc:
                    if attempt == 2 or exc.seconds > 600:
                        raise
                    await asyncio.sleep(exc.seconds + 1)
                except TypeNotFoundError as error:
                    if len(batch) == 1:
                        found[batch[0]] = error
                    else:
                        middle = len(batch) // 2
                        found.update(await self.read_numbers(entity, batch[:middle]))
                        found.update(await self.read_numbers(entity, batch[middle:]))
                    answer = None
                    break
            for message in answer or []:
                if message is not None and not isinstance(message, types.MessageEmpty):
                    if utils.get_peer_id(message.peer_id) != utils.get_peer_id(entity):
                        raise ValueError("History returned a message from a different source.")
                    found[message.id] = message
        return found

    async def number_before(self, entity, offset_date=None):
        error = None
        for skip in (0, 1, 2, 4, 8, 16, 32, 64):
            try:
                latest = await self.client.get_messages(entity, limit=1, offset_date=offset_date,
                                                        **({"add_offset": skip} if skip else {}))
            except TypeNotFoundError as exc:
                error = exc
                continue
            readable = latest[0].id if latest else 0
            if not skip:
                return readable
            above = await self.read_numbers(entity, list(range(readable + 1, readable + SALVAGE_WINDOW + 1)))
            return max((number for number, value in above.items() if offset_date is None
                        or isinstance(value, TypeNotFoundError) or value.date < offset_date), default=readable)
        raise unreadable_history(error)

    async def salvage_page(self, entity, offset_id, min_id, on_message, on_unparsed):
        top = offset_id - 1 if offset_id else await self.number_before(entity)
        low = max(min_id + 1, top - SALVAGE_WINDOW + 1, 1)
        found = await self.read_numbers(entity, list(range(low, top + 1)))
        unreadable = [n for n, value in found.items() if isinstance(value, TypeNotFoundError)]
        if len(unreadable) > SALVAGE_LIMIT:
            raise unreadable_history(found[unreadable[0]])
        for number in sorted(found, reverse=True):
            value = found[number]
            if isinstance(value, TypeNotFoundError):
                await on_unparsed(number, value)
            else:
                await on_message(value)
        if unreadable:
            self.store.append("history.unparsed", {
                "chat_id": utils.get_peer_id(entity), "numbers": sorted(unreadable),
                "constructors": sorted({format(found[n].invalid_constructor_id, "08x") for n in unreadable}),
                "telethon_layer": LAYER, "meaning": UNPARSED_MEANING.format(layer=LAYER)})
        return low

    @asynccontextmanager
    async def history_reader(self, entity):
        if not isinstance(entity, types.Channel):
            yield self.client, None
            return
        try:
            session = await self.client(functions.account.InitTakeoutSessionRequest(
                message_megagroups=True, message_channels=True))
            if not isinstance(session, types.account.Takeout):
                raise ValueError("Telegram did not open a Takeout session.")
        except (TakeoutInitDelayError, RPCError, OSError, ConnectionError, TimeoutError, ValueError) as exc:
            self.note("telegram.takeout_unavailable", {
                "error_type": type(exc).__name__, "retry_after": getattr(exc, "seconds", None),
                "meaning": "History is read without a Takeout session, about three times slower."})
            yield self.client, None
            return
        from .account_export_transport import WrappedClient
        reader = WrappedClient(self.client, session.id)
        try:
            yield reader, 0
        finally:
            with suppress(Exception):
                await reader(functions.account.FinishTakeoutSessionRequest(success=True))

    async def iterate_history(self, entity, on_message, min_id=0, offset_id=0, on_wait=None, on_unparsed=None,
                              page_timeout=None, attempts=8, client=None, wait_time=None):
        failures = 0
        while True:
            writing = False
            pages = (client or self.client).iter_messages(entity, offset_id=offset_id, min_id=min_id,
                                                          **({"wait_time": wait_time} if wait_time is not None else {}))
            try:
                while True:
                    try:
                        message = await asyncio.wait_for(anext(pages), page_timeout)
                    except StopAsyncIteration:
                        return
                    writing = True
                    await on_message(message)
                    writing = False
                    offset_id, failures = message.id, 0
            except TypeNotFoundError:
                if writing or on_unparsed is None:
                    raise
                offset_id = await self.salvage_page(entity, offset_id, min_id, on_message, on_unparsed)
                if offset_id <= min_id + 1:
                    return
            except FloodWaitError as exc:
                if writing:
                    raise
                wait = exc.seconds + 1
                self.store.set_setting("rpc_backoff_until", max(time.time() + wait,
                    self.store.get_setting("rpc_backoff_until", 0)))
                self.store.append("telegram.backoff", {"seconds": wait, "context": "chat_export"})
                if on_wait:
                    on_wait(wait)
                await asyncio.sleep(wait)
            except (OSError, ConnectionError, TimeoutError):
                if writing:
                    raise
                failures += 1
                if failures > attempts:
                    raise
                await asyncio.sleep(min(60, 5 * failures))
                if not self.client.is_connected():
                    await self.restore()
            finally:
                with suppress(Exception):
                    await pages.aclose()

    async def export_attachment(self, message, directory, files=None):
        if not getattr(message, "media", None) or not getattr(message, "file", None):
            return {}
        settings = capture_settings(self.store)
        kind = media_kind(message)
        if files == "skip":
            return {"file_status": "skipped_by_export_option", "file_kind": kind}
        if not settings["download_media"] and files is None:
            return {}
        rule, size = settings["types"].get(kind) or {"enabled": False, "max_mb": 0}, getattr(message.file, "size", None)
        if not rule["enabled"] and files != "hashes":
            return {"file_status": "type_not_collected", "file_kind": kind}
        if not duration_allowed(message, rule) and files != "hashes":
            return {"file_status": "duration_limit", "file_kind": kind}
        action = "hashes_only" if files == "hashes" else media_action(settings, rule, size)
        if action == "exclude":
            return {"file_status": "excluded_by_policy", "file_kind": kind}
        if action == "hashes_only":
            try:
                hashes = await self.attachment_hashes(message)
                digest = hashlib.sha256(canonical(hashes)).hexdigest()
                return {"file_status": "hashes_only" if hashes["status"] == "complete" else "incomplete_hashes",
                        "file_kind": kind, "server_hashes": hashes, "file_hash_sha256": digest}
            except (RPCError, OSError, TimeoutError, ValueError) as exc:
                return {"file_status": "hashes_unavailable", "file_kind": kind, "file_error": type(exc).__name__}
        limit = rule["max_mb"] * 1024**2
        if size is None or size > limit:
            return {"file_status": "above_limit" if size else "unknown_size", "file_kind": kind,
                    **({"file_size": size} if size else {})}
        if shutil.disk_usage(directory).free < size + self.param("media_min_free_mb") * 1024**2:
            raise ValueError("Not enough free disk space for the attachments of this export. Free space or turn "
                             "attachment downloads off under Sources → Recording.")

        async def progress(current, total):
            if max(current, total) > limit:
                raise ValueError("above_limit")
        timeout = self.param("media_timeout_seconds") + size // (self.param("media_min_speed_kbps") * 1024)
        temp = directory / ("part-" + str(message.id))
        try:
            for attempt in range(3):
                try:
                    with temp.open("wb") as stream:
                        media = downloadable_media(message)
                        result = await asyncio.wait_for(self.client.download_media(
                            media, file=stream, progress_callback=progress, **file_hashes.download_options(media)), timeout)
                    if result is None:
                        return {"file_status": "unavailable", "file_kind": kind}
                    written = temp.stat().st_size
                    if written > limit:
                        raise ValueError("above_limit")
                    if written != size:
                        return {"file_status": "unavailable", "file_kind": kind,
                                "file_error": "download_size_differs_from_observed_attachment"}
                    digest = await complete_in_thread(file_digest, temp)
                    destination = directory / digest
                    if destination.exists():
                        if destination.is_symlink() or await complete_in_thread(file_digest, destination) != digest:
                            raise ValueError("existing_content_addressed_file_is_corrupt")
                    else:
                        temp.replace(destination)
                    return {"file": "media/" + digest, "file_sha256": digest, "file_size": written, "file_kind": kind}
                except FloodWaitError as exc:
                    if attempt == 2:
                        return {"file_status": "rate_limited", "file_kind": kind}
                    await asyncio.sleep(min(exc.seconds + 1, 600))
                except (OSError, TimeoutError, ConnectionError) as exc:
                    if attempt == 2:
                        return {"file_status": "unavailable", "file_kind": kind, "file_error": type(exc).__name__}
                    await asyncio.sleep(5 * (attempt + 1))
                except ValueError as exc:
                    if str(exc) != "above_limit":
                        raise
                    return {"file_status": "above_limit", "file_kind": kind, "file_size": size}
        finally:
            temp.unlink(missing_ok=True)

    async def stream_history(self, entity, scratch, record, media_dir=None, files=None):
        count, started, attached = 0, time.monotonic(), []
        with scratch.open("w", encoding="utf-8") as handle:
            async def write(message, entry=None):
                nonlocal count
                if entry is None:
                    self.remember(getattr(message, "sender", None))
                    entry = message_record(message)
                    if media_dir is not None and getattr(message, "media", None) and getattr(message, "file", None):
                        attached.append(message.id)
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                count += 1
                record["captured"] = count
                if count % 200 == 0:
                    handle.flush()
                    elapsed = time.monotonic() - started
                    if record.get("total") and elapsed > 0:
                        record["eta_seconds"] = round(max(0, record["total"] - count) / (count / elapsed))
                    await asyncio.sleep(0)

            async def unparsed(number, error):
                await write(None, unparsed_record(number, error))
            async with self.history_reader(entity) as (reader, wait):
                await self.iterate_history(entity, write, on_unparsed=unparsed, client=reader, wait_time=wait)
        if attached:
            await self.export_files(entity, scratch, record, media_dir, attached, files)
        return count

    async def export_files(self, entity, scratch, record, media_dir, ids, files=None):
        record.update(stage="files", files_total=len(ids), files_done=0, eta_seconds=None)
        found, started = {}, time.monotonic()
        expected = {}
        if files == "skip":
            found = {number: {"file_status": "skipped_by_export_option"} for number in ids}
            ids = []
        else:
            wanted = set(ids)
            with scratch.open(encoding="utf-8") as source:
                for line in source:
                    entry = json.loads(line)
                    if entry.get("id") in wanted:
                        expected[entry["id"]] = hashlib.sha256(canonical(entry)).digest()
        for low in range(0, len(ids), 100):
            batch = ids[low:low + 100]
            for message in await self.client.get_messages(entity, ids=batch):
                if message is None or isinstance(message, types.MessageEmpty):
                    continue
                if message.id not in batch or message.id in found:
                    continue
                if (utils.get_peer_id(message.peer_id) != utils.get_peer_id(entity)
                        or hashlib.sha256(canonical(message_record(message))).digest() != expected.get(message.id)):
                    found[message.id] = {"file_status": "message_changed_or_unavailable_at_media_read"}
                else:
                    found[message.id] = await self.export_attachment(message, media_dir, files)
                record["files_done"] += 1
                elapsed = time.monotonic() - started
                record["eta_seconds"] = round((len(ids) - record["files_done"]) * elapsed / record["files_done"])
        for missing in set(ids) - set(found):
            found[missing] = {"file_status": "message_unavailable_at_file_read"}
        merged = scratch.with_suffix(".files")
        with scratch.open(encoding="utf-8") as source, merged.open("w", encoding="utf-8") as target:
            for line in source:
                entry = json.loads(line)
                if entry.get("id") in found and entry.get("type") != "unparsed":
                    entry.update(found[entry["id"]])
                target.write(json.dumps(entry, ensure_ascii=False) + "\n")
        merged.replace(scratch)
        record["stage"] = None

    async def resolve_for_export(self, chat_id, username=None):
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

    async def fetch_range(self, entity, low, high, path, progress=None, on_wait=None, page_timeout=None, attempts=8,
                          client=None, wait_time=None):
        digest, count = hashlib.sha256(), 0
        with path.open("w", encoding="utf-8") as handle:
            async def emit(record):
                nonlocal count
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                digest.update(canonical(record) + b"\n")
                count += 1
                if progress:
                    progress()
                if count % 200 == 0:
                    await asyncio.sleep(0)

            async def write(message):
                if utils.get_peer_id(message.peer_id) != utils.get_peer_id(entity):
                    raise ValueError("History returned a message from a different source.")
                self.remember(getattr(message, "sender", None))
                await emit(message_record(message))

            async def unparsed(number, error):
                await emit(unparsed_record(number, error))
            await self.iterate_history(entity, write, min_id=low - 1, offset_id=high + 1, on_wait=on_wait,
                                       on_unparsed=unparsed, page_timeout=page_timeout, attempts=attempts,
                                       client=client, wait_time=wait_time)
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

    def remember(self, entity, *, chat_id=None):
        peer = getattr(entity, "id", None)
        if peer is None or not hasattr(entity, "photo"):
            return
        if len(self.people) >= 5000:
            self.people.pop(next(iter(self.people)))
        self.people[utils.get_peer_id(entity)] = entity
        if chat_id is not None:
            if self.running and self.selected(chat_id) and monitoring_settings(self.store)["profiles"]:
                from .people import observe_entity
                observe_entity(self.store, entity, chat_id)
            if capture_settings(self.store)["include_avatars"]:
                self.avatar_history.observe(entity, chat_id=chat_id)

    async def avatar(self, peer_id):
        cached = self.store.root / "avatars" / (str(peer_id) + ".jpg")
        if cached.is_file():
            return cached
        owner = "avatar:" + secrets.token_hex(8)
        if not self.reserve_export(owner):
            return None
        try:
            return await self._avatar(peer_id)
        finally:
            self.release_export(owner)

    async def _avatar(self, peer_id):
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
        client = self.client
        entity = self.people.get(peer_id) or self.dialog_cache.get(peer_id, {}).get("entity")
        if entity is None and peer_id == account_id:
            try:
                entity = await asyncio.wait_for(client.get_me(), 15)
                self.remember(entity)
            except Exception as exc:
                self.handle_authorization_error(exc, "account avatar", client=client)
                entity = None
        if entity is None:
            return None
        async with self.avatar_lock:
            if path.is_file():
                return path
            try:
                data = await asyncio.wait_for(
                    client.download_profile_photo(entity, file=bytes, download_big=False), 20)
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                return None
            except Exception as exc:
                self.handle_authorization_error(exc, "account avatar", client=client)
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

    async def refresh_media_reference(self, message, job, client=None):
        identity = attachment_identity(message)
        if identity is None:
            raise ValueError("original_attachment_has_no_stable_id")
        fresh = await asyncio.wait_for((client or self.client).get_messages(job["chat_id"], ids=job["message_id"]), 30)
        if fresh is None or not getattr(fresh, "media", None) or attachment_identity(fresh) is None:
            raise ValueError("original_attachment_no_longer_available")
        if (attachment_identity(fresh) != identity or fresh.id != job["message_id"]
                or fresh.chat_id != job["chat_id"]):
            raise ValueError("refreshed_attachment_differs_from_signed_observation")
        return downloadable_media(fresh)

    async def download_worker(self, lane="all", *, owner=None, history_run=None, producer_done=None,
                              client_for_job=None):
        media_root = self.store.root / "media"
        media_root.mkdir(exist_ok=True)
        while self.running or owner and self.export_claim == owner:
            if lane != "ephemeral" and not owner and capture_settings(self.store)["messages_first"] and self.history.status()["phase"] in ("none", "running", "paused"):
                await asyncio.sleep(.2)
                continue
            if not capture_settings(self.store)["download_media"]:
                if owner:
                    return
                self.media_wakeup.clear()
                try:
                    await asyncio.wait_for(self.media_wakeup.wait(), 1)
                except TimeoutError:
                    pass
                continue
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
            limits = ({"max_priority": 0} if lane == "ephemeral" else
                      {"min_priority": 1, "max_priority": 1} if lane == "urgent" else
                      {"min_priority": 2} if lane == "bulk" else {})
            capture = capture_settings(self.store)
            job = self.store.claim_media(account.get("id", 0), history_run=history_run,
                                         allow_takeout=client_for_job is not None,
                                         **limits) if capture["download_media"] else None
            if not job:
                if owner:
                    retry_at = self.store.next_history_media_attempt(account.get("id", 0), history_run, **limits)
                    if retry_at is not None:
                        await asyncio.sleep(max(.05, min(1, retry_at - time.time())))
                        continue
                    if producer_done is not None and not producer_done.is_set():
                        self.media_wakeup.clear()
                        try:
                            await asyncio.wait_for(self.media_wakeup.wait(), 1)
                        except TimeoutError:
                            pass
                        continue
                    return
                self.media_wakeup.clear()
                try:
                    await asyncio.wait_for(self.media_wakeup.wait(), 1)
                except TimeoutError:
                    pass
                continue
            temp = media_root / ("pending-" + str(job["message_event"]))
            client = self.client
            try:
                original = self.store.events(before=job["message_event"] + 1, limit=1)[0]
                if client_for_job is not None:
                    client = client_for_job(original)
                policy = original["payload"].get("media_capture", {})
                if (hashlib.sha256(job["descriptor"]).hexdigest() != policy.get("descriptor_sha256")
                        or job["max_bytes"] != policy.get("max_bytes")
                        or job["account_id"] != policy.get("account_id")
                        or ("priority" in policy and job["priority"] != policy["priority"])
                        or ("estimated_bytes" in policy and job["estimated_bytes"] != policy["estimated_bytes"])
                        or job["chat_id"] != original["chat_id"] or job["message_id"] != original["message_id"]):
                    raise ValueError("queue_descriptor_differs_from_signed_observation")
                with BinaryReader(job["descriptor"]) as reader:
                    message = reader.tgread_object()
                ephemeral_media = ephemeral.describe(message.media)
                size = getattr(message.file, "size", None) if message.file else None
                kind = policy.get("media_type") or media_kind(message)
                rule = effective_media_rule(capture, kind, ephemeral_media)
                limit = rule["max_mb"] * 1024**2
                action = policy.get("action", "download")
                if action == "exclude":
                    self.store.finish_media(job, "skipped", {
                        "reason": "above the size limit of the attachment settings"
                        if size is not None and size > job["max_bytes"] else "excluded by the observed media policy"})
                    continue
                current_action = media_action(capture, rule, size)
                if (not rule["enabled"] or not duration_allowed(message, rule) or current_action == "exclude"
                        or (action == "download" and size is not None and limit < size <= job["max_bytes"])):
                    self.store.finish_media(job, "skipped", {
                        "reason": "above the size limit of the attachment settings" if rule["enabled"]
                        else "attachment type not collected by policy: " + kind,
                        "meaning": "the attachment settings changed after this file was queued"})
                    continue
                if action == "download" and current_action != "download":
                    self.store.finish_media(job, "skipped", {"reason": "media action changed after this attachment was queued"})
                    continue
                if action == "hashes_only":
                    hashes = await self.attachment_hashes(message, job=job, client=client)
                    self.store.finish_media(job, "hashed" if hashes["status"] == "complete" else "failed", {
                        "server_hashes": hashes, "original_name": getattr(message.file, "name", None),
                        "reason": "hashes_only" if hashes["status"] == "complete" else "incomplete_server_hashes",
                        "downloaded_bytes": 0})
                    continue
                if size is None or size > job["max_bytes"]:
                    raise ValueError("unknown_size_or_above_limit")
                if shutil.disk_usage(media_root).free < size + 64 * 1024**2:
                    raise OSError("insufficient_free_space")

                async def progress(current, total):
                    if max(current, total) > job["max_bytes"]:
                        raise ValueError("above_limit")


                timeout = self.param("media_timeout_seconds") + size // (self.param("media_min_speed_kbps") * 1024)
                media = downloadable_media(message)
                refreshed = False

                async def download(media):
                    with temp.open("wb") as stream:
                        return await asyncio.wait_for(
                            client.download_media(media, file=stream, progress_callback=progress,
                                                  **file_hashes.download_options(media)), timeout)

                try:
                    result = await download(media)
                except FileReferenceExpiredError:
                    media = await self.refresh_media_reference(message, job, client=client)
                    refreshed = True
                    result = await download(media)
                if result is None:
                    raise ValueError("download_unavailable")
                digest = await complete_in_thread(file_digest, temp)
                actual_size = temp.stat().st_size
                if actual_size > job["max_bytes"]:
                    raise ValueError("above_limit")
                if actual_size != size:
                    raise ValueError("download_size_differs_from_observed_attachment")
                destination = media_root / digest
                if destination.exists():
                    if await complete_in_thread(file_digest, destination) != digest:
                        raise ValueError("existing_content_addressed_file_is_corrupt")
                    temp.unlink()
                else:
                    temp.replace(destination)
                self.store.finish_media(job, "done", {
                    "media_sha256": digest, "size": actual_size,
                    "original_name": getattr(message.file, "name", None),
                    "mime_type": getattr(message.file, "mime_type", None),
                    "file_reference_refreshed": refreshed,
                })
            except asyncio.CancelledError:
                self.store.finish_media(job, "retry", {"reason": "collector stopped; durable job retained"})
                raise
            except AUTHORIZATION_ERRORS as exc:
                self.handle_authorization_error(exc, "media download", client=getattr(client, "_export_client", client))
                self.store.finish_media(job, "retry", {"error_type": type(exc).__name__,
                    "reason": "Telegram authorization expired; durable job retained"})
                return
            except FloodWaitError as exc:
                until = max(time.time() + exc.seconds, self.store.get_setting("rpc_backoff_until", 0))
                self.store.set_setting("rpc_backoff_until", until)
                self.store.finish_media(job, "retry", {"error_type": type(exc).__name__,
                                                      "retry_after_seconds": exc.seconds}, delay=exc.seconds)
            except TakeoutInvalidError:
                self.store.finish_media(job, "retry", {"reason": "Takeout expired; durable job retained"})
                raise
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

    async def attachment_hashes(self, message, *, job=None, client=None):
        client = client or self.client
        # Bound this cache independently of the number of messages in a chat.
        if not hasattr(self, "_file_hash_cache"):
            self._file_hash_cache, self._file_hash_cache_bytes = {}, 0
            self._file_hash_lock = asyncio.Lock()
        media = downloadable_media(message)
        identity = file_hashes.representation(media)
        key = canonical({"account_id": (self.store.get_setting("account", {}) or {}).get("id"), "representation": identity})
        async with self._file_hash_lock:
            if key in self._file_hash_cache:
                return self._file_hash_cache[key][0]
            try:
                result = await asyncio.wait_for(file_hashes.collect(client, media), self.param("media_timeout_seconds"))
            except FileReferenceExpiredError:
                job = job or {"chat_id": message.chat_id, "message_id": message.id}
                media = await self.refresh_media_reference(message, job, client=client)
                if file_hashes.representation(media) != identity:
                    raise ValueError("refreshed_hash_representation_changed") from None
                result = await asyncio.wait_for(file_hashes.collect(client, media), self.param("media_timeout_seconds"))
            size = len(canonical(result))
            if result["status"] == "complete" and size <= 8 * 1024**2:
                while self._file_hash_cache and (len(self._file_hash_cache) >= 512 or self._file_hash_cache_bytes + size > 8 * 1024**2):
                    _, used = self._file_hash_cache.pop(next(iter(self._file_hash_cache)))
                    self._file_hash_cache_bytes -= used
                self._file_hash_cache[key] = (result, size)
                self._file_hash_cache_bytes += size
            return result
