"""Convert bounded account uploads in memory; never contact Telegram or save uploads."""
import base64
import binascii
import json
import re
import sqlite3
import struct
from pathlib import PurePath

from telethon.crypto import AuthKey
from telethon.sessions import StringSession

from .tdata import read_tdata_zip

MAX_UPLOAD = 8 * 1024**2
IMPORT_REQUEST_LIMIT = 12 * 1024**2
DC_ADDRESSES = {1: "149.154.175.53", 2: "149.154.167.51", 3: "149.154.175.100",
                4: "149.154.167.91", 5: "149.154.171.5"}


def string_session(dc, key):
    """Always the reference address of the DC: an address from an untrusted file could be a server
    that answers with the key it handed over and stands in for Telegram."""
    if type(dc) is not int or dc not in DC_ADDRESSES or not isinstance(key, bytes) or len(key) != 256:
        raise ValueError("Expected a production Telegram DC (1–5) and a complete 256-byte authorization key.")
    session = StringSession()
    session.set_dc(dc, DC_ADDRESSES[dc], 443)
    session.auth_key = AuthKey(key)
    return session.save()


def validate_string(value):
    """The StringSession rebuilt from its DC and key alone; its address and port are ignored."""
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
        if objects != {"version": "table", "sessions": "table"}:
            raise ValueError("Expected real session/version tables, not views.")
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


def json_account(payload):
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
    aliases = {"api_id": ("api_id", "app_id"), "api_hash": ("api_hash", "app_hash"),
               "session": ("string_session", "session_string", "session"),
               "expected_user_id": ("user_id", "id"), "auth_key": ("auth_key", "auth_key_hex")}
    for destination, names in aliases.items():
        values = [raw[name] for name in names if raw.get(name) not in (None, "")]
        if len(values) > 1 and any(value != values[0] for value in values[1:]):
            raise ValueError("Conflicting account JSON fields.")
        if values:
            result[destination] = values[0]
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


def import_accounts(files, passcode=""):
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
        elif content.startswith(b"PK\x03\x04"):
            dc, key, user_id = read_tdata_zip(content, passcode)
            result = {"session": string_session(dc, key), "expected_user_id": user_id, "format": "TData ZIP"}
        elif suffix == ".json":
            result = json_account(content)
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
        for key in ("session", "api_id", "api_hash", "expected_user_id"):
            if key not in result:
                continue
            if key in merged:
                same = identity(merged[key]) == identity(result[key]) if key == "session" else merged[key] == result[key]
                if not same:
                    raise ValueError("Selected files describe different accounts or API credentials. Import one account at a time.")
            else:
                merged[key] = result[key]
    merged["has_authorization"] = bool(merged.get("session"))
    return merged
