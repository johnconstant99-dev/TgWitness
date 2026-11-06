"""Reusable report presentation, deliberately excluding case material and scope."""
import secrets

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .report import HIDDEN_CODEPOINTS, ReportOptions

FORMAT = "tgwitness-report-profile-v1"
CASE_FIELDS = frozenset({"case_title", "case_id", "examiner", "organization", "notes", "selection",
                         "review_question", "review_method", "review_findings", "review_conclusion", "jurisdiction_guidance"})
LAYOUT_FIELDS = frozenset(ReportOptions.model_fields) - CASE_FIELDS
MAX_PROFILES = 50


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=80)
    options: dict

    @field_validator("name")
    @classmethod
    def printable(cls, value):
        if any(ord(char) in HIDDEN_CODEPOINTS or char in "\n\r\t" for char in value):
            raise ValueError("Remove control and text-direction characters")
        return value

    @field_validator("options")
    @classmethod
    def layout_only(cls, value):
        if set(value) - LAYOUT_FIELDS:
            raise ValueError("Report profiles contain layout settings only, without case details or data filters.")
        options = ReportOptions.model_validate(value).model_dump()
        return {key: options[key] for key in options if key in LAYOUT_FIELDS}


def catalog(store):
    return store.get_setting("report_profiles", [])


def save(store, profile):
    with store.lock:
        rows = list(catalog(store))
        existing = next((row for row in rows if row["name"].casefold() == profile.name.casefold()), None)
        if existing is None and len(rows) >= MAX_PROFILES:
            raise ValueError("Keep up to 50 report configurations. Remove an unused configuration first.")
        row = {"id": existing["id"] if existing else secrets.token_hex(16), **profile.model_dump()}
        rows = [item for item in rows if item["id"] != row["id"]] + [row]
        store.set_setting("report_profiles", rows)
        return row


def remove(store, profile_id):
    with store.lock:
        rows = catalog(store)
        if not any(row["id"] == profile_id for row in rows):
            raise ValueError("This report configuration no longer exists. Refresh the list.")
        store.set_setting("report_profiles", [row for row in rows if row["id"] != profile_id])
