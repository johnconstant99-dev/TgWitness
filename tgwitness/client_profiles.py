from functools import lru_cache
import hashlib
import json
from pathlib import Path


@lru_cache(maxsize=1)
def catalog():
    return json.loads(Path(__file__).with_suffix(".json").read_bytes())


def _pick(items, seed, field):
    slot = int.from_bytes(hashlib.sha256((field + ":" + seed).encode()).digest(), "big")
    slot %= sum(item["weight"] for item in items)
    for item in items:
        slot -= item["weight"]
        if slot < 0:
            return item[field]
    raise ValueError("Empty Telegram client profile catalog.")


def desktop(seed):
    data = catalog()
    return {"device_model": _pick(data["models"], seed, "model"),
            "system_version": _pick(data["systems"], seed, "version"),
            **{key: data[key] for key in ("app_version", "lang_code", "system_lang_code", "lang_pack")}}


def platform_profile(api_id, seed, supplied=None):
    name = {4: "android", 6: "android", 21724: "android_x", 10840: "ios", 2834: "macos"}.get(api_id)
    if api_id == 2496:
        supplied = supplied or {}
        version = supplied.get("app_version", "")
        name = "webogram" if version == "0.7.0" else "web_k" if (
            version.endswith(" K") or supplied.get("lang_pack") == "macos") else "web_a"
    if not name:
        return {}
    data = catalog()["platforms"]
    profile = data["profiles"][name]
    devices = data["devices"][profile["catalog"]]
    slot = int.from_bytes(hashlib.sha256((name + ":" + str(seed)).encode()).digest(), "big")
    slot %= sum(device["weight"] for device in devices)
    for device in devices:
        slot -= device["weight"]
        if slot < 0:
            return {"device_model": device["model"], "system_version": device["system_version"],
                    **{key: profile[key] for key in ("app_version", "lang_code", "system_lang_code", "lang_pack")}}
    raise ValueError("Empty Telegram client profile catalog.")
