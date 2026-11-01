"""Explicit live-event selection, separate from history and attachment policies."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool


class Monitoring(BaseModel):
    model_config = ConfigDict(extra="forbid")
    messages: StrictBool = True
    edits: StrictBool = True
    deletions: StrictBool = True
    reactions: StrictBool = True
    membership: StrictBool = True


CAPTURE_DEFAULTS = {"download_media": True, "max_media_mb": 20}
MEDIA_TYPES = ("photo", "video", "animation", "video_note", "voice", "audio", "sticker", "document")
MEDIA_DEFAULT_MB = {"photo": 20, "video": 100, "animation": 20, "video_note": 50, "voice": 20, "audio": 50,
                    "sticker": 5, "document": 50}
# New workspaces leave optional GIF and sticker downloads off until explicitly enabled.
MEDIA_DEFAULT_OFF = ("animation", "sticker")


class MediaRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = True
    max_mb: int = Field(default=20, ge=1, le=2000)


class Capture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    download_media: StrictBool = True
    record_disabled_media: StrictBool = True
    max_media_mb: int = Field(default=20, ge=1, le=2000)
    types: dict[Literal[MEDIA_TYPES], MediaRule] = Field(default_factory=dict)


def capture_settings(store):
    """Saved attachment policy with a rule for every media type.

    Policies saved before per-type rules apply their single size limit to every type.
    """
    previous = store.get_setting("capture", None)
    saved = previous or {}
    rules = saved.get("types") or {}
    legacy = saved.get("max_media_mb") if saved and "types" not in saved else None
    types = {}
    for kind in MEDIA_TYPES:
        rule = rules.get(kind) or {"enabled": previous is not None or kind not in MEDIA_DEFAULT_OFF,
                                   "max_mb": legacy or MEDIA_DEFAULT_MB[kind]}
        types[kind] = {"enabled": bool(rule.get("enabled", True)), "max_mb": int(rule.get("max_mb") or 20)}
    return {"download_media": bool(saved.get("download_media", True)),
            "record_disabled_media": bool(saved.get("record_disabled_media", True)),
            "max_media_mb": int(saved.get("max_media_mb") or CAPTURE_DEFAULTS["max_media_mb"]), "types": types}


def media_kind(message):
    """Attachment type used by the per-type rules (Telethon message properties)."""
    for kind, attribute in (("photo", "photo"), ("video_note", "video_note"), ("voice", "voice"),
                            ("sticker", "sticker"), ("animation", "gif"), ("video", "video"), ("audio", "audio")):
        if getattr(message, attribute, None):
            return kind
    return "document"


def monitoring_settings(store):

    return Monitoring.model_validate(store.get_setting("monitoring", {})).model_dump()
