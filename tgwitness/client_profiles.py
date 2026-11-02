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
