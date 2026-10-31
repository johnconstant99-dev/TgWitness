"""Save recording settings together, using the existing journal receipts."""

from pydantic import BaseModel, ConfigDict, model_validator

from .monitoring import Capture, Monitoring, capture_settings, monitoring_settings
from .scope import Recheck, ScopeUpdate, WIDE_WARNING, recheck_settings, scope_settings


class RecordingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    monitoring: Monitoring | None = None
    capture: Capture | None = None
    scope: ScopeUpdate | None = None
    recheck: Recheck | None = None

    @model_validator(mode="after")
    def not_empty(self):
        if all(getattr(self, name) is None for name in type(self).model_fields):
            raise ValueError("Choose recording settings to save.")
        return self

    def permissions(self):
        return ({"settings"} if self.monitoring is not None or self.capture is not None else set()) | (
            {"sources"} if self.scope is not None or self.recheck is not None else set())


class Invalid(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def settings(store):
    return {"monitoring": monitoring_settings(store), "capture": capture_settings(store),
            "scope": scope_settings(store), "recheck": recheck_settings(store)}


def scope_change(previous, body):
    current = body.model_dump(exclude={"acknowledged"})
    current["exclude"] = sorted(set(current["exclude"]))
    widening = current["mode"] != "selected" and (previous["mode"] != current["mode"]
                                                 or previous["folder_id"] != current["folder_id"])
    if widening and not body.acknowledged:
        raise Invalid(409, WIDE_WARNING)
    if current["mode"] == "folder" and current["folder_id"] is None:
        raise Invalid(422, "Choose a Telegram folder. Load chats first if the list is empty.")
    return current, widening


def save(store, body):
    """Call under the workspace operation lock. No network or filesystem side effects."""
    before, changed = settings(store), []
    scope, widening = scope_change(before["scope"], body.scope) if body.scope is not None else (None, False)
    with store.transaction():
        if body.monitoring is not None:
            current = body.monitoring.model_dump()
            if current != before["monitoring"]:
                store.set_setting("monitoring", current)
                store.append("monitoring.changed", {
                    "before": before["monitoring"], "after": current,
                    "applies_to": "subsequent live updates for selected sources in this account profile",
                    "coverage": "disabled categories are intentionally not recorded; no backfill",
                    "history_snapshots": "explicit snapshots remain separate; embedded metadata is not redacted",
                })
                changed.append("monitoring")
        if body.capture is not None:
            value = body.capture.model_dump()
            if "record_disabled_media" not in body.capture.model_fields_set:
                value["record_disabled_media"] = before["capture"]["record_disabled_media"]
            store.set_setting("capture", value)
            current = capture_settings(store)
            if current != before["capture"]:
                store.append("capture.changed", current)
                changed.append("capture")
        if scope is not None and scope != before["scope"]:
            store.set_setting("scope", scope)
            store.append("scope.changed", {
                "before": before["scope"], "after": scope,
                "acknowledged": body.scope.acknowledged if widening else None,
                "warning": WIDE_WARNING if scope["mode"] != "selected" else None,
                "coverage": "applies to updates from now on; earlier history is not fetched",
            })
            changed.append("scope")
        if body.recheck is not None:
            current = body.recheck.model_dump()
            if current != before["recheck"]:
                for key, value in current.items():
                    store.set_setting(key, value)
                store.append("recheck.changed", {
                    **current, "meaning": "minutes between rechecks of priority sources and of every other source; "
                    "0 turns a tier off"})
                changed.append("recheck")
    return changed, settings(store)
