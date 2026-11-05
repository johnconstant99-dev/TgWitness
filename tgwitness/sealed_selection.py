"""The normalized, signed scope of a restricted runner capture."""
import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .account_export import AccountExportOptions
from .monitoring import Capture, normalize_capture
from .store import canonical


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["chat", "account"] = "chat"
    chat_id: int | None = Field(default=None, strict=True)
    capture: Capture = Field(default_factory=lambda: Capture.model_validate({
        **normalize_capture(None), "include_avatars": False, "messages_first": True}))
    account_scope: Literal["all", "selected"] | None = None
    account_options: AccountExportOptions | None = None

    @model_validator(mode="after")
    def scope(self):
        if self.mode == "chat":
            if self.chat_id is None or self.account_options is not None or self.account_scope is not None:
                raise ValueError("Select a chat and its capture settings.")
        else:
            if self.chat_id is not None or self.account_options is None or "capture" in self.model_fields_set:
                raise ValueError("Account export requires account_options, without chat capture settings.")
            if not self.account_options.messages_first:
                raise ValueError("Restricted account exports preserve messages before attachments.")
            inferred = "selected" if self.account_options.chat_ids else "all"
            if self.account_scope is not None and self.account_scope != inferred:
                raise ValueError("Selected scope requires chat IDs; all-chat scope must not restrict chat IDs.")
            self.account_scope = inferred
        return self

    def settings(self):
        if self.mode == "account":
            return {"mode": "account", "account_scope": self.account_scope,
                    "account_options": self.account_options.model_dump()}
        return {"mode": "chat", "chat_id": self.chat_id, "capture": normalize_capture(self.capture.model_dump())}


def selection_hash(settings):
    return hashlib.sha256(canonical(settings)).hexdigest()


def checked_selection(events, internal, expected=None, require_complete=False):
    """Only call after journal signatures, nested export and attestation are verified.

    Old approved captures did not include the normalized selection/hash fields;
    their signed selection event still contains the full effective settings.
    """
    if len(events) != 1:
        raise ValueError("Expected exactly one signed capture selection")
    event = events[0]
    if event.get("mode") == "account":
        raw = {"mode": "account", "account_options": event.get("options")}
    else:
        raw = {"mode": "chat", "chat_id": event.get("chat_id"), "capture": event.get("capture")}
    settings = Selection.model_validate(raw).settings()
    digest = selection_hash(settings)
    transport = settings["account_options"]["transport"] if settings["mode"] == "account" else "regular"
    if event.get("transport") != transport:
        raise ValueError("Signed selection transport mismatch")
    if "selection" in event or "selection_sha256" in event:
        if event.get("selection") != settings or event.get("selection_sha256") != digest:
            raise ValueError("Signed selection digest mismatch")
    account = internal.get("account_export")
    if settings["mode"] == "account":
        if account is None or account.get("options") != settings["account_options"]:
            raise ValueError("Account export differs from the signed capture selection")
    elif account is not None:
        raise ValueError("Unexpected account export in a chat capture")
    if expected is not None and Selection.model_validate(expected).settings() != settings:
        raise ValueError("Capture settings differ from the independently expected selection")
    complete = account["complete_within_scope"] if account else None
    if require_complete and complete is not True:
        raise ValueError("A complete account export within the selected scope is required")
    return {"selection": settings, "selection_sha256": digest,
            "mode": transport if account else "journal", "complete_within_scope": complete,
            "expected_selection_matched": True if expected is not None else None}
