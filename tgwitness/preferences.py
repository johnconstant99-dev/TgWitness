"""Server-backed presentation preferences, independent of Telegram authorization."""
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, field_validator

from . import i18n


class Preferences(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language: str = "en"
    timezone: str = "UTC"
    theme: Literal["system", "light", "dark"] = "system"
    level: Literal["simple", "standard", "expert"] = "simple"

    @field_validator("language")
    @classmethod
    def language_known(cls, value):
        if value not in i18n.LANGUAGES:
            raise ValueError("Unsupported panel language")
        return value

    @field_validator("timezone")
    @classmethod
    def timezone_known(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Choose a valid IANA time zone.") from None
        return value


def preference_key(principal):
    # An issued token cannot change another operator's presentation preferences.
    return "ui_preferences:" + ("admin" if principal.admin else str(principal.owner))


def saved(store, principal):
    return store.get_setting(preference_key(principal), None)
