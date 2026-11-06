"""Check that saving one media setting keeps the default media types (T24)."""
import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.monitoring import MEDIA_DEFAULT_MB, MEDIA_DEFAULT_OFF, MEDIA_TYPES, Capture, capture_settings, normalize_capture
from tools.check_session_reservations import workspace

DEFAULT_TYPES = {kind: {"enabled": kind not in MEDIA_DEFAULT_OFF, "max_mb": MEDIA_DEFAULT_MB[kind]} for kind in MEDIA_TYPES}


def enabled(settings):
    return {kind: rule["enabled"] for kind, rule in settings["types"].items()}


def check_normalize():
    assert normalize_capture(None)["types"] == DEFAULT_TYPES
    for saved in (Capture().model_dump(), Capture(download_media=False).model_dump(),
                  Capture(types={"photo": {"enabled": True, "max_mb": 5}}).model_dump(), {"types": {}}, {}):
        types = normalize_capture(saved)["types"]
        assert {k: v for k, v in types.items() if k != "photo"} == {k: v for k, v in DEFAULT_TYPES.items() if k != "photo"}, saved
    legacy = normalize_capture({"download_media": True, "max_media_mb": 30})["types"]
    assert all(rule == {"enabled": True, "max_mb": 30} for rule in legacy.values()), \
        "settings saved before per-type rules keep every type at the old size"
    chosen = normalize_capture({"types": {"animation": {"enabled": True, "max_mb": 7}}})["types"]
    assert chosen["animation"] == {"enabled": True, "max_mb": 7} and not chosen["sticker"]["enabled"]
    return "ok  defaults: missing types fall back to the same defaults; legacy settings unchanged"


async def check_api():
    async with workspace() as (app, http):
        store = app.state.store
        before = capture_settings(store)
        assert before["types"] == DEFAULT_TYPES

        response = await http.post("/api/capture", json={"types": {"photo": {"enabled": True, "max_mb": 5}}})
        assert response.status_code == 200, response.text
        after = response.json()
        assert after["types"]["photo"] == {"enabled": True, "max_mb": 5}
        assert not after["types"]["animation"]["enabled"] and not after["types"]["sticker"]["enabled"], after["types"]
        assert store.get_setting("capture")["types"] == after["types"] and len(after["types"]) == 8, \
            "every type is saved explicitly"

        response = await http.post("/api/capture", json={"download_media": False})
        assert response.status_code == 200, response.text
        assert enabled(response.json()) == enabled(before) and store.get_setting("capture")["types"] == DEFAULT_TYPES

        response = await http.post("/api/recording", json={"capture": {"types": {"video": {"enabled": False, "max_mb": 9}}}})
        assert response.status_code == 200, response.text
        saved = store.get_setting("capture")["types"]
        assert saved["video"] == {"enabled": False, "max_mb": 9}
        assert not saved["animation"]["enabled"] and not saved["sticker"]["enabled"] and len(saved) == 8

        current = capture_settings(store)
        response = await http.post("/api/recording", json={"capture": current})
        assert response.status_code == 200, response.text
        assert capture_settings(store) == current, "saving the shown values changes nothing"

        full = {**current, "types": {**current["types"], "sticker": {"enabled": True, "max_mb": 5}}}
        response = await http.post("/api/capture", json=full)
        assert response.status_code == 200 and response.json()["types"]["sticker"]["enabled"], \
            "an explicit choice to collect stickers is kept"
    return "ok  api: saving photo, download or recording settings keeps animations and stickers off"


def main():
    print(check_normalize())
    print(asyncio.run(asyncio.wait_for(check_api(), 60)))
    print("capture default checks passed")


if __name__ == "__main__":
    main()
