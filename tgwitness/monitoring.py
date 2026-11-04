from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_serializer


class Monitoring(BaseModel):
    model_config = ConfigDict(extra="forbid")
    messages: StrictBool = True
    edits: StrictBool = True
    deletions: StrictBool = True
    reactions: StrictBool = True
    membership: StrictBool = True
    profiles: StrictBool = True
    presence: StrictBool = False


CAPTURE_DEFAULTS = {"download_media": True, "max_media_mb": 20}
MEDIA_TYPES = ("photo", "video", "animation", "video_note", "voice", "audio", "sticker", "document")
MEDIA_DEFAULT_MB = {"photo": 20, "video": 100, "animation": 20, "video_note": 50, "voice": 20, "audio": 50,
                    "sticker": 5, "document": 50}
MEDIA_DEFAULT_OFF = ("animation", "sticker")


class MediaRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = True
    max_mb: int = Field(default=20, ge=1, le=2000)
    max_seconds: int = Field(default=0, ge=0, le=86400)

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if not self.max_seconds:
            value.pop("max_seconds", None)
        return value


class Capture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    download_media: StrictBool = True
    record_disabled_media: StrictBool = True
    max_media_mb: int = Field(default=20, ge=1, le=2000)
    types: dict[Literal[MEDIA_TYPES], MediaRule] = Field(default_factory=dict)


def capture_settings(store):
    previous = store.get_setting("capture", None)
    saved = previous or {}
    rules = saved.get("types") or {}
    legacy = saved.get("max_media_mb") if saved and "types" not in saved else None
    types = {}
    for kind in MEDIA_TYPES:
        rule = rules.get(kind) or {"enabled": previous is not None or kind not in MEDIA_DEFAULT_OFF,
                                   "max_mb": legacy or MEDIA_DEFAULT_MB[kind]}
        types[kind] = {"enabled": bool(rule.get("enabled", True)), "max_mb": int(rule.get("max_mb") or 20)}
        if rule.get("max_seconds"):
            types[kind]["max_seconds"] = int(rule["max_seconds"])
    return {"download_media": bool(saved.get("download_media", True)),
            "record_disabled_media": bool(saved.get("record_disabled_media", True)),
            "max_media_mb": int(saved.get("max_media_mb") or CAPTURE_DEFAULTS["max_media_mb"]), "types": types}


def media_kind(message):
    for kind, attribute in (("photo", "photo"), ("video_note", "video_note"), ("voice", "voice"),
                            ("sticker", "sticker"), ("animation", "gif"), ("video", "video"), ("audio", "audio")):
        if getattr(message, attribute, None):
            return kind
    return "document"


def duration_allowed(message, rule):
    limit = rule.get("max_seconds", 0)
    if not limit:
        return True
    duration = getattr(getattr(message, "file", None), "duration", None)
    return duration is not None and 0 <= duration <= limit


def monitoring_settings(store):

    return Monitoring.model_validate(store.get_setting("monitoring", {})).model_dump()
