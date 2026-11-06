"""Snapshot non-Desktop profiles from opentele2 2.0.0 (MIT), without network access."""
import hashlib
import json
import os
from pathlib import Path

os.environ["OPENTELE_NO_FETCH"] = "1"
from opentele2 import _native  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://github.com/DedInc/opentele2/tree/7e973bc71cd7a714ad13ac703c0895a90d36a735"


def main():
    if _native.__version__ != "2.0.0":
        raise ValueError("Use opentele2 2.0.0 for this reviewed snapshot.")
    path = ROOT / "tgwitness/client_profiles.json"
    data = json.loads(path.read_bytes())
    devices = {name: _native.catalog_entries(name) for name in ("android", "ios", "macos", "web_a", "web_k")}
    profiles = {}
    for name, client, platform in (("android", "TelegramAndroid", "android"),
            ("android_x", "TelegramAndroidX", "android"), ("ios", "TelegramIOS", "ios"),
            ("macos", "TelegramMacOS", "macos"), ("web_a", "TelegramWeb_A", "web_a"),
            ("web_k", "TelegramWeb_K", "web_k"), ("webogram", "Webogram", "web_k")):
        profile = _native.profile(client)
        profiles[name] = {key: profile[key].strip() if isinstance(profile[key], str) else profile[key]
                          for key in ("api_id", "app_version", "lang_code", "system_lang_code", "lang_pack")}
        profiles[name]["catalog"] = platform
    data["platforms"] = {"source": SOURCE, "version": "2.0.0", "layer": 230,
        "reviewed_on": "2026-11-05", "license": "MIT; see client_profiles.LICENSE",
        "note": "Offline upstream versions; supplied and saved account values take precedence. API ID 4 is the Android source-build ID from DrKLO/Telegram BuildVars.java.",
        "android_source": "https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java",
        "profiles": profiles, "devices": devices}
    # Keep the pre-existing Desktop snapshot and its deterministic choices intact.
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Platform snapshot:", {key: len(value) for key, value in devices.items()})
    print("SHA-256:", hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
