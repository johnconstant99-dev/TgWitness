"""Bounded Telegram client descriptions, retained with account authorization."""
import platform
import re
import unicodedata

from telethon import TelegramClient

from . import api_pool

FIELDS = {
    "device_model": ("device_model", "device"),
    "system_version": ("system_version", "sdk"),
    "app_version": ("app_version",),
    "lang_code": ("lang_code",),
    "system_lang_code": ("system_lang_code",),
    "lang_pack": ("lang_pack",),
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
        limit = 32 if field in ("lang_code", "system_lang_code", "lang_pack") else 128
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
    profile.update(api_pool.device_for(api_id, seed))
    profile.update(validate(supplied))
    return validate(profile)
