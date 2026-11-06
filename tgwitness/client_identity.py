"""Bounded Telegram client descriptions, retained with account authorization."""
import platform
import re
import unicodedata
from datetime import datetime, timezone

from telethon import TelegramClient
from telethon.tl import functions, types

from . import api_pool

FIELDS = {
    "device_model": ("device_model", "device"),
    "system_version": ("system_version", "sdk"),
    "app_version": ("app_version",),
    "lang_code": ("lang_code",),
    "system_lang_code": ("system_lang_code", "system_lang_pack"),
    "lang_pack": ("lang_pack",),
    "tz_offset": ("tz_offset",),
}


def language_defaults(language, accept_language=None):
    """Use the panel choice and browser locale only where no account value exists."""
    valid = lambda value: len(value) <= 32 and re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", value)
    language = language if isinstance(language, str) and valid(language) else "en"
    choices = []
    for order, part in enumerate((accept_language or "").split(",")[:20]):
        tag, *params = part.strip().split(";")
        if not valid(tag):
            continue
        weight = 1.0
        for param in params:
            name, _, value = param.strip().partition("=")
            if name == "q":
                try:
                    weight = float(value)
                except ValueError:
                    weight = 0.0
        if 0 < weight <= 1:
            choices.append((-weight, order, tag))
    system = min(choices)[2] if choices else language
    return {"lang_code": language, "system_lang_code": system}


def validate(profile):
    if profile is None:
        return {}
    if not isinstance(profile, dict) or set(profile) - FIELDS.keys():
        raise ValueError("Unsupported Telegram client profile fields.")
    result = {}
    for field, value in profile.items():
        if field == "tz_offset":
            if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,5}", value):
                value = int(value)
            if type(value) is not int or not -43200 <= value <= 50400:
                raise ValueError("Invalid Telegram client profile: tz_offset")
            result[field] = value
            continue
        limit = 32 if field in ("lang_code", "system_lang_code", "lang_pack") else 512 if field == "device_model" else 128
        if (not isinstance(value, str) or len(value) > limit
                or any(unicodedata.category(c).startswith("C") for c in value)):
            raise ValueError("Invalid Telegram client profile: " + field)
        value = value.strip()
        if not value and field != "lang_pack":
            raise ValueError("Empty Telegram client profile: " + field)
        if field in ("lang_code", "system_lang_code", "lang_pack") and value and not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("Invalid Telegram language identifier: " + field)
        result[field] = value
    return result


def from_account(raw):
    profile = {}
    for field, aliases in FIELDS.items():
        values = [raw[name] for name in aliases if raw.get(name) is not None]
        if values:
            if any(value != values[0] for value in values[1:]):
                raise ValueError("Conflicting Telegram client profile: " + field)
            profile[field] = values[0]
    return validate(profile)


def resolve(api_id, supplied=None, seed=""):
    machine = platform.machine()
    model = "PC 64bit" if machine in ("x86_64", "AMD64") else "PC 32bit" if machine in ("i386", "i686", "x86") else machine
    profile = {"device_model": model or "Desktop", "system_version": re.sub(r"-.+", "", platform.release()) or "1.0",
               "app_version": TelegramClient.__version__, "lang_code": "en", "system_lang_code": "en", "lang_pack": ""}
    supplied = validate(supplied)
    profile.update(api_pool.device_for(api_id, seed, supplied))
    profile.update(supplied)
    return validate(profile)


def desktop_timezone(now=None):
    """Desktop's quarter-hour offset; see opentele2-core/src/fingerprint.rs (MIT)."""
    offset = (now or datetime.now(timezone.utc).astimezone()).utcoffset()
    seconds = int(offset.total_seconds()) if offset is not None else 0
    while seconds < -43200:
        seconds += 86400
    while seconds > 50400:
        seconds -= 86400
    rounded = (abs(seconds) + 450) // 900 * 900
    return -rounded if seconds < 0 else rounded


def apply_init_params(client):
    request = getattr(client, "_init_request", None)
    if not isinstance(request, functions.InitConnectionRequest):
        return
    supplied = getattr(client, "tgwitness_client_profile", {})
    if "tz_offset" in supplied:
        offset = supplied["tz_offset"]
    elif request.lang_pack == "tdesktop":
        offset = desktop_timezone()
    else:
        return
    values = request.params.value if isinstance(request.params, types.JsonObject) else []
    request.params = types.JsonObject([value for value in values if value.key != "tz_offset"] +
                                     [types.JsonObjectValue("tz_offset", types.JsonNumber(offset))])


def consistency_warnings(api_id, profile, layer):
    """Advisory format checks, not Telegram's undocumented abuse decisions."""
    from .client_profiles import catalog
    expected = api_pool.device_for(api_id, supplied=profile)
    if not expected:
        return []
    issues = []
    if profile.get("lang_pack") != expected["lang_pack"]:
        issues.append("The imported lang_pack does not match this API's platform.")
    model, system, version = (profile.get(key, "") for key in ("device_model", "system_version", "app_version"))
    if api_id in (4, 6, 21724):
        if not re.fullmatch(r"SDK [0-9]{1,3}", system):
            issues.append("Android system_version should use the SDK version format.")
        if re.match(r"(?:iPhone|iPad|iPod|Mac|iMac|PC |Desktop)", model, re.I):
            issues.append("The device_model describes another platform for an Android API.")
    if api_id in (10840, 2834):
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", system):
            issues.append("This Apple API expects a numeric system_version.")
        prefix = r"(?:iPhone|iPad|iPod)" if api_id == 10840 else r"(?:Mac|iMac)"
        if not re.match(prefix, model):
            issues.append("The device_model does not match this Apple API's platform.")
    if api_id == 2496 and not model.startswith("Mozilla/"):
        issues.append("The Web API expects a browser user agent as device_model.")
    if api_id == 2040 and re.match(r"(?:SDK |iOS )", system):
        issues.append("The system_version describes a mobile platform for the Desktop API.")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?: \([0-9]+\))?(?: (?:x64|arm64|A|K))?", version):
        issues.append("The app_version does not match the reviewed official version formats.")
    if api_id in (4, 6, 21724, 10840) and not re.search(r"[-_]", profile.get("system_lang_code", "")):
        issues.append("The mobile system_lang_code has no region component.")
    if layer != catalog()["platforms"]["layer"]:
        issues.append("Telethon's schema layer differs from the reviewed profile baseline (230); review library compatibility.")
    return issues
