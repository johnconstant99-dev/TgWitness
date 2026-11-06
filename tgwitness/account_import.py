import asyncio
import base64
import binascii
import hashlib
import json
import re
import secrets
import sqlite3
import struct
from contextlib import suppress
from pathlib import PurePath

from telethon.crypto import AuthKey
from telethon.errors import AuthKeyNotFound, RPCError, SessionPasswordNeededError
from telethon.sessions import StringSession
from telethon.tl import functions, types

from .tdata import read_tdata_zip
from . import api_pool
from . import client_identity

MAX_UPLOAD = 8 * 1024**2
IMPORT_REQUEST_LIMIT = 12 * 1024**2
DC_ADDRESSES = {1: "149.154.175.53", 2: "149.154.167.51", 3: "149.154.175.100",
                4: "149.154.167.91", 5: "149.154.171.5"}


def string_session(dc, key):
    if type(dc) is not int or dc not in DC_ADDRESSES or not isinstance(key, bytes) or len(key) != 256:
        raise ValueError("Expected a production Telegram DC (1–5) and a complete 256-byte authorization key.")
    session = StringSession()
    session.set_dc(dc, DC_ADDRESSES[dc], 443)
    session.auth_key = AuthKey(key)
    return session.save()


def session_key(value):
    try:
        session = StringSession((value or "").strip())
    except (ValueError, TypeError, binascii.Error, struct.error):
        return None
    return session.auth_key.key if session.auth_key else None


def validate_string(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("Expected a Telethon StringSession of at most 4 KiB.")
    try:
        session = StringSession(value.strip())
        if not session.auth_key:
            raise ValueError()
        return string_session(session.dc_id, session.auth_key.key)
    except (ValueError, TypeError, binascii.Error, OSError, struct.error):
        raise ValueError("Invalid Telethon StringSession.") from None


def sqlite_session(payload):
    db = sqlite3.connect(":memory:")
    try:
        db.deserialize(payload)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4096)
        db.set_progress_handler(lambda: 1, 100000)
        objects = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('version','sessions')"))
        if set(objects) != {"version", "sessions"}:
            raise ValueError("This SQLite file is not a Telegram session: it has no sessions and version tables.")
        if objects != {"version": "table", "sessions": "table"}:
            raise ValueError("This session file defines its session tables as SQLite views, which are not read for "
                             "safety. Save the session again from its original client.")
        columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
        if {"server_address", "port", "dc_id", "auth_key"} <= columns:
            if db.execute("SELECT version FROM version LIMIT 2").fetchall() not in ([(7,)], [(8,)]):
                raise ValueError("Supported Telethon SQLite schemas: 7 and 8.")
            rows = db.execute("SELECT dc_id,auth_key FROM sessions LIMIT 2").fetchall()
            if len(rows) != 1:
                raise ValueError("Expected exactly one authorized Telethon session.")
            return {"session": string_session(*rows[0]), "format": "Telethon SQLite"}
        if {"dc_id", "auth_key", "test_mode", "user_id", "is_bot"} <= columns:
            if db.execute("SELECT number FROM version LIMIT 2").fetchall() not in ([(2,)], [(3,)]):
                raise ValueError("Supported Pyrogram SQLite schemas: 2 and 3.")
            rows = db.execute("SELECT dc_id,auth_key,test_mode,user_id,is_bot FROM sessions LIMIT 2").fetchall()
            if len(rows) != 1:
                raise ValueError("Expected exactly one authorized Pyrogram session.")
            dc, key, test, user_id, bot = rows[0]
            if test != 0 or bot != 0 or type(user_id) is not int or user_id <= 0:
                raise ValueError("Only authorized production user sessions are supported; no bots or test DCs.")
            return {"session": string_session(dc, key), "expected_user_id": user_id, "format": "Pyrogram SQLite"}
        raise ValueError("Unsupported SQLite session schema.")
    except (sqlite3.Error, TypeError, OSError):
        raise ValueError("Cannot read this session. Close its original client and upload a complete, checkpointed SQLite file.") from None
    finally:
        db.close()


def json_account(payload, include_password=False):
    if len(payload) > 64 * 1024:
        raise ValueError("Account JSON must be at most 64 KiB.")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON field.")
                result[key] = value
            return result
        raw = json.loads(payload.decode("utf-8-sig"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid account JSON.") from None
    if not isinstance(raw, dict):
        raise ValueError("Import one JSON account object, not a bulk account list.")
    result = {"format": "Account JSON"}
    if include_password and raw.get("twoFA") not in (None, ""):
        if not isinstance(raw["twoFA"], str) or len(raw["twoFA"]) > 512:
            raise ValueError("The twoFA password must be text of at most 512 characters.")
        result["two_factor_password"] = raw["twoFA"]
    client_profile = client_identity.from_account(raw)
    if client_profile:
        result["client_profile"] = client_profile
    aliases = {"api_id": ("api_id", "app_id"), "api_hash": ("api_hash", "app_hash"),
               "session": ("string_session", "session_string", "session_str"),
               "expected_user_id": ("user_id", "id"), "auth_key": ("auth_key", "auth_key_hex")}
    for destination, names in aliases.items():
        values = [raw[name] for name in names if raw.get(name) not in (None, "")]
        if len(values) > 1 and any(value != values[0] for value in values[1:]):
            raise ValueError("Conflicting account JSON fields.")
        if values:
            result[destination] = values[0]
    # Explicit Telethon fields take precedence over a generic foreign-format
    # `session` blob. Two recognizable authorizations must still agree.
    generic = raw.get("session")
    if generic not in (None, ""):
        if "session" not in result:
            result["session"] = generic
        elif isinstance(generic, str) and session_key(generic):
            if validate_string(generic) != validate_string(result["session"]):
                raise ValueError("Conflicting account JSON fields.")
    for key in ("api_id", "expected_user_id"):
        if key in result:
            value = result[key]
            if isinstance(value, bool) or not str(value).isdigit() or not 0 < int(value) <= (2147483647 if key == "api_id" else 2**63 - 1):
                raise ValueError("Invalid numeric account JSON field.")
            result[key] = int(value)
    if "api_hash" in result and (not isinstance(result["api_hash"], str) or not re.fullmatch(r"[a-fA-F0-9]{32}", result["api_hash"])):
        raise ValueError("API hash must contain 32 hexadecimal characters.")
    if "session" in result:
        result["session"] = validate_string(result["session"])
    if "auth_key" in result:
        key = result.pop("auth_key")
        if not isinstance(key, str) or not re.fullmatch(r"[a-fA-F0-9]{512}", key):
            raise ValueError("Auth Key HEX must contain all 512 hexadecimal characters, without ellipses.")
        converted = string_session(raw.get("dc_id"), bytes.fromhex(key))
        if "session" in result and identity(result["session"]) != identity(converted):
            raise ValueError("JSON session and authorization key disagree.")
        result.setdefault("session", converted)
    if len(result) == 1:
        raise ValueError("JSON contains no supported API credentials or authorization.")
    return result


def identity(value):
    session = StringSession(value)
    return session.dc_id, session.auth_key.key


def import_accounts(files, passcode="", include_password=False):
    if not 1 <= len(files) <= 4:
        raise ValueError("Select 1–4 account files totaling at most 8 MiB.")
    total, converted = 0, []
    for item in files:
        try:
            content = base64.b64decode(item["content"], validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid upload encoding.") from None
        total += len(content)
        if not content or total > MAX_UPLOAD:
            raise ValueError("Select nonempty account files totaling at most 8 MiB.")
        suffix = PurePath(item["name"]).suffix.lower()
        if content.startswith(b"SQLite format 3\0"):
            result = sqlite_session(content)
        elif content.startswith(b"PK\x03\x04") or suffix == ".zip":
            dc, key, user_id = read_tdata_zip(content, passcode)
            result = {"session": string_session(dc, key), "expected_user_id": user_id, "format": "TData ZIP"}
        elif suffix == ".json":
            result = json_account(content, include_password)
        elif suffix == ".session":
            raise ValueError("This .session file is not a Telegram session: it is not an SQLite database.")
        else:
            if len(content) > 4096:
                raise ValueError("Unsupported account file. Expected SQLite, TData ZIP, account JSON, or StringSession text.")
            try:
                result = {"session": validate_string(content.decode("utf-8-sig")), "format": "Telethon StringSession"}
            except UnicodeError:
                raise ValueError("Unsupported binary account file.") from None
        converted.append(result)
    merged = {"formats": [item["format"] for item in converted]}
    for result in converted:
        for key in ("session", "api_id", "api_hash", "expected_user_id", "client_profile", "two_factor_password"):
            if key not in result:
                continue
            if key in merged:
                same = identity(merged[key]) == identity(result[key]) if key == "session" else merged[key] == result[key]
                if not same:
                    if key == "api_id":
                        raise ValueError("The selected files contain different API IDs. Choose the JSON belonging to this session; do not combine files from different apps.")
                    if key == "api_hash":
                        raise ValueError("The selected files contain different API hashes. Use one matching API ID and hash pair.")
                    if key == "client_profile":
                        raise ValueError("The selected JSON files describe different devices. Keep the JSON belonging to this session.")
                    raise ValueError("The selected files contain different account sessions. Import one account at a time into separate workspaces.")
            else:
                merged[key] = result[key]
    merged["has_authorization"] = bool(merged.get("session"))
    return merged


def preview(files, passcode=""):
    try:
        result = import_accounts(files, passcode)
    except (ValueError, OSError) as exc:
        return {"state": "invalid", "can_connect": False, "message": str(exc)}
    ready = result["has_authorization"]
    if ready and bool(result.get("api_id")) != bool(result.get("api_hash")):
        return {"state": "incomplete", "can_connect": False, "formats": result["formats"],
                "message": "Session found, but its application settings are incomplete. Supply both API ID and API hash in the JSON, or select the session file without this JSON to use the built-in app settings."}
    return {"state": "ready" if ready else "missing_session", "can_connect": ready,
            "formats": result["formats"], "client_profile": result.get("client_profile"), "api_id": result.get("api_id"),
            "key_id": hashlib.sha256(session_key(result["session"])).hexdigest()[:16] if ready else None,
            "expected_user_id": result.get("expected_user_id"),
            "message": "Session found. Telegram will validate it when you connect." if ready else
            "No session — only application settings. Add a .session or TData file, or sign in by phone or QR."}


CHECK_SECONDS = 20
CHECK_STATES = {"session_revoked": "revoked", "session_expired": "revoked", "session_ended": "revoked",
                "not_authorized": "revoked", "account_banned": "banned", "account_deleted": "banned",
                "session_duplicated": "duplicate", "account_frozen": "frozen"}
PASSWORD_PENDING = ("The sign-in of this session stopped at the two-step password. It cannot be used until "
                    "someone enters that password on the original device.")


async def check_session(collector, account, api_id=None, api_hash=None, languages=None):
    from .collector import LOSS_MEANING, ROUTE_ERRORS, account_loss_cause, telegram_error
    from .proxy_catalog import NoProxyAvailable
    if api_id is None:
        api_id, api_hash = ((account["api_id"], account["api_hash"]) if account.get("api_id")
                            else api_pool.login_order()[0])
    supplied = {**client_identity.validate(languages), **client_identity.validate(account.get("client_profile"))}
    device = client_identity.resolve(api_id, supplied, hashlib.sha256(session_key(account["session"])).hexdigest())
    owner, client = "session-check-" + secrets.token_hex(16), None

    def lost(cause, error=None):
        return {"state": CHECK_STATES[cause], "message": LOSS_MEANING[cause], "telegram_error": error}
    try:
        _, route = await collector.pool().acquire(owner, share=collector.share())
        client = collector.client_factory(StringSession(account["session"]), api_id, api_hash, receive_updates=False,
                                          flood_sleep_threshold=0, connection_retries=0, request_retries=1,
                                          timeout=CHECK_SECONDS,
                                          **{k: v for k, v in device.items() if k != "lang_pack"},
                                          **route.client_options())
        request = getattr(client, "_init_request", None)
        if isinstance(request, functions.InitConnectionRequest):
            request.lang_pack = device["lang_pack"]
        await asyncio.wait_for(client.connect(), CHECK_SECONDS)
        try:
            users = await asyncio.wait_for(client(functions.users.GetUsersRequest([types.InputUserSelf()])),
                                           CHECK_SECONDS)
            me = users[0] if users else None
            if not isinstance(me, types.User):
                return lost("not_authorized")
            if me.bot:
                return {"state": "invalid", "message": "A user account is required; bot sessions are not supported."}
            if account.get("expected_user_id") not in (None, me.id):
                return {"state": "invalid",
                        "message": "The authorized Telegram account does not match the imported account ID."}
            answer = await asyncio.wait_for(client(functions.help.GetAppConfigRequest(hash=0)), CHECK_SECONDS)
        except SessionPasswordNeededError:
            return {"state": "password", "message": PASSWORD_PENDING}
        except RPCError as exc:
            if not account_loss_cause(exc):
                raise
            return lost(account_loss_cause(exc), telegram_error(exc))
        values = getattr(getattr(answer, "config", None), "value", None) or []
        if any(isinstance(item, types.JsonObjectValue) and item.key == "freeze_since_date" for item in values):
            return lost("account_frozen")
        return {"state": "alive",
                "message": "The session is active. The check only read this account's profile and settings.",
                "account": {"id": me.id, "username": me.username,
                            "name": " ".join(filter(None, (me.first_name, me.last_name))) or None}}
    except AuthKeyNotFound:
        return lost("session_ended")
    except NoProxyAvailable as exc:
        return {"state": "unchecked", "message": str(exc)}
    except RPCError as exc:
        return {"state": "unchecked", "message": "Telegram refused the check. Try again later.",
                "telegram_error": exc.message}
    except ROUTE_ERRORS:
        return {"state": "unchecked", "message": "Telegram did not answer in time. Try again later."}
    finally:
        try:
            if client is not None:
                with suppress(Exception):
                    await asyncio.wait_for(client.disconnect(), 5)
        finally:
            collector.pool().release(owner)
            collector.pool().waiting.discard(owner)
