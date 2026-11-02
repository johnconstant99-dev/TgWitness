import hashlib
import json
from types import SimpleNamespace
from typing import Any

from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from . import alerts, report, settings_hub, tuning
from .monitoring import Monitoring, monitoring_settings
from .recording import RecordingUpdate, save as save_recording
from .scope import Recheck, recheck_settings

HUB = ("files", "timestamps", "drand", "notifications", "replica", "outside", "ip")
PARAMETERS = tuple("parameter:" + key for key in tuning.BY_KEY)
KEYS = ("goal", *HUB, "monitoring", "recheck", "alert_rules", "reports", "route", *PARAMETERS)
ROUTE_MODES = ("auto", "direct", "vpn", "proxy", "mtproxy", "warp")
CATEGORIES = {"goal": "goal", "files": "collection", "monitoring": "collection",
              "recheck": "collection", "timestamps": "protection", "drand": "protection",
              "notifications": "notifications", "replica": "notifications", "alert_rules": "notifications",
              "outside": "connection", "ip": "connection", "route": "connection", "reports": "reports",
              **{key: "parameters" for key in PARAMETERS}}
LABELS = {"goal": "Goal", "monitoring": "What to record", "recheck": "Recheck schedule",
          "alert_rules": "Notification rules", "reports": "Report settings", "route": "Connection route",
          **{f["key"]: f["label"] for f in settings_hub.FIELDS},
          **{"parameter:" + key: p.label for key, p in tuning.BY_KEY.items()}}
SECTION_KEYS = {"parameters": PARAMETERS, "reports": ("reports",), "capture": ("files", "monitoring"),
                "recheck": ("recheck",), "route": ("outside", "ip")}


class GroupChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, Any] = Field(min_length=1, max_length=len(KEYS))
    allow_outside: bool = False
    disable_dependents: bool = False
    overwrite: list[str] = Field(default_factory=list, max_length=1000)
    revision: str | None = Field(default=None, max_length=64)


class Adopt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profiles: list[str] = Field(min_length=1, max_length=1000)
    keys: list[str] | None = Field(default=None, max_length=len(KEYS))


def read(app, keys):
    s = app.state.store
    hub = settings_hub.values(app) if any(key in HUB for key in keys) else {}
    result = {}
    for key in keys:
        if key == "goal":
            result[key] = (s.get_setting("goal_preset", None) or {}).get("goal")
        elif key in HUB:
            result[key] = hub[key]
        elif key == "monitoring":
            result[key] = monitoring_settings(s)
        elif key == "recheck":
            result[key] = recheck_settings(s)
        elif key == "alert_rules":
            result[key] = {k: v for k, v in alerts.alert_settings(s).items() if k != "enabled"}
        elif key == "reports":
            result[key] = report.saved(s).model_dump()
        elif key == "route":
            strategy = s.get_setting("connection_strategy", {}) or {}
            result[key] = ({"mode": strategy["mode"], "allow_direct": bool(strategy.get("allow_direct"))}
                           if strategy.get("mode") else None)
        else:
            result[key] = tuning.value(s, key.removeprefix("parameter:"))
    return result


def valid(key, value):
    if key not in KEYS:
        raise ValueError("Unknown shared setting.")
    if key == "goal" and value in settings_hub.PRESETS or key == "files" and value in ("photos", "short_media", "all") \
            or key == "ip" and value in ("auto", "hide") or key in HUB and key not in ("files", "ip") and type(value) is bool:
        return value
    if key in ("goal", *HUB):
        raise ValueError("Invalid value for " + LABELS[key] + ".")
    if key.startswith("parameter:"):
        try:
            return tuning.validate(tuning.BY_KEY[key.removeprefix("parameter:")], value)
        except tuning.Invalid as exc:
            raise ValueError(LABELS[key] + ": " + str(exc)) from None
    try:
        if not isinstance(value, dict):
            raise TypeError
        if key == "monitoring":
            return Monitoring.model_validate(value).model_dump()
        if key == "recheck":
            return Recheck.model_validate(value).model_dump()
        if key == "alert_rules":
            rules = alerts.AlertSettings.model_validate({**value, "enabled": False}).model_dump()
            return {k: v for k, v in rules.items() if k != "enabled"}
        if key == "reports":
            return report.ReportOptions.model_validate(value).model_dump()
        if value.get("mode") not in ROUTE_MODES or type(value.get("allow_direct", False)) is not bool:
            raise TypeError
        return {"mode": value["mode"], "allow_direct": value.get("allow_direct", False)}
    except (TypeError, ValueError):
        raise ValueError("Invalid value for " + LABELS[key] + ".") from None


def follows(member, group):
    return {key for key, value in group.items() if member.get(key) == value}


def effective(registry, profile_id):
    group = group_record(registry, registry.group_of(profile_id))
    entry = registry.entries.get(profile_id) or {}
    if group is None or entry.get("app") is None:
        return {}
    shared = group.get("values", {})
    current = read(entry["app"], list(shared))
    return {key: {"value": current[key], "group_value": value,
                  "source": "group" if current[key] == value else "own"} for key, value in shared.items()}


def member_view(registry, profile_id):
    group = group_record(registry, registry.group_of(profile_id))
    if group is None:
        return None
    return {"group": {"id": group["id"], "label": group["label"]}, "keys": effective(registry, profile_id)}


def group_record(registry, group_id):
    return next((g for g in registry.groups() if g["id"] == group_id), None) if group_id else None


def label_of(entry, app):
    account = (app.state.store.get_setting("account", {}) or {}) if app else {}
    return {"id": entry["id"], "label": entry["label"], "username": account.get("username")}


def group_view(registry, group_id):
    group = registry._group(group_id)
    shared, members = group.get("values", {}), []
    for profile_id in registry.members(group_id):
        entry = registry.entries[profile_id]
        app = entry.get("app")
        if app is None:
            members.append({**label_of(entry, None), "available": False})
            continue
        current = read(app, KEYS)
        members.append({**label_of(entry, app), "available": True, "values": current,
                        "own": sorted(set(shared) - follows(current, shared))})
    return {"group": {"id": group["id"], "label": group["label"]}, "values": shared, "members": members,
            "keys": [{"key": key, "category": CATEGORIES[key], "label": LABELS[key]} for key in KEYS],
            "revision": revision(shared, members)}


def revision(shared, members):
    raw = [shared, [[m["id"], m.get("values")] for m in members]]
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()


def proposed(shared, body):
    changes = {key: None if value is None else valid(key, value) for key, value in body.values.items()}
    result = {k: v for k, v in shared.items() if k not in changes or changes[k] is not None}
    result.update({k: v for k, v in changes.items() if v is not None})
    hub_changes = [key for key in changes if key in HUB]
    if "goal" in changes and changes["goal"] is not None:
        result.update({k: v for k, v in settings_hub.PRESETS[changes["goal"]].items() if k in HUB and k not in changes})
    elif len(hub_changes) == 1 and changes[hub_changes[0]] is not None and all(k in shared for k in HUB):
        result.update(settings_hub.edited({k: shared[k] for k in HUB}, SimpleNamespace(
            key=hub_changes[0], value=changes[hub_changes[0]], allow_outside=body.allow_outside,
            disable_dependents=body.disable_dependents)))
    defined = [key for key in HUB if key in result]
    if defined and len(defined) != len(HUB):
        raise HTTPException(409, "Choose a goal for the group first; its settings come together.")
    if defined and not settings_hub.coherent(result):
        raise HTTPException(409, "These group settings conflict. Review external requests and timestamps.")
    return result


def plan(registry, group_id, body):
    view = group_view(registry, group_id)
    shared = view["values"]
    after = proposed(shared, body)
    changed = sorted(key for key in set(shared) | set(after) if shared.get(key) != after.get(key))
    rows = []
    for member in view["members"]:
        row = {k: member[k] for k in ("id", "label", "username", "available")}
        if not member["available"]:
            rows.append({**row, "status": "unavailable"})
            continue
        current = member["values"]
        given = [k for k in changed if k in after]
        own = {k: current[k] for k in given if current[k] != after[k] and (k not in shared or current[k] != shared[k])}
        takes = [k for k in given if current[k] != after[k] and k not in own]
        rows.append({**row, "status": "own" if own else "follows", "own": own, "takes": takes,
                     "new": [k for k in own if k not in shared]})
    return {"group": view["group"], "before": {k: shared.get(k) for k in changed},
            "after": {k: after.get(k) for k in changed}, "values": after, "members": rows,
            "follow": sum(1 for r in rows if r["status"] == "follows"), "total": len(rows),
            "revision": view["revision"]}


def adoptable(values):
    return {k: v for k, v in values.items() if k != "route"}


async def apply_member(app, values, group, reason):
    values = adoptable(values)
    if not values:
        return None
    s = app.state.store
    try:
        async with app.state.operation_lock:
            hub = {k: v for k, v in values.items() if k in HUB}
            if settings_hub.values(app)["continuous"]:
                settings_hub.validate_collection_scope(s)
            if hub:
                await app.state.settings_apply({**settings_hub.values(app), **hub})
            with s.transaction():
                if "goal" in values:
                    settings_hub.save_goal(s, values["goal"])
                if "monitoring" in values or "recheck" in values:
                    save_recording(s, RecordingUpdate(
                        monitoring=Monitoring(**values["monitoring"]) if "monitoring" in values else None,
                        recheck=Recheck(**values["recheck"]) if "recheck" in values else None))
                if "alert_rules" in values:
                    current = alerts.alert_settings(s)
                    rules = {**current, **values["alert_rules"]}
                    if rules != current:
                        s.set_setting("alerts", rules)
                        s.append("alerts.changed", alerts.change_record(rules, app.state.vault.read("alerts").get("urls", [])))
                if "reports" in values:
                    report.save(s, report.ReportOptions.model_validate(values["reports"]))
                wanted = {k.removeprefix("parameter:"): v for k, v in values.items() if k.startswith("parameter:")}
                if wanted:
                    saved, before, after = tuning.changes(s, wanted)
                    if after:
                        app.state.save_parameters(s, saved, before, after)
                s.append("group.settings_inherited", {"group_id": group["id"], "group": group["label"],
                                                      "reason": reason, "settings": values})
            app.state.alert_wakeup.set()
    except HTTPException as exc:
        return str(exc.detail)
    except ValueError as exc:
        return str(exc)
    except Exception as exc:
        return "Not applied: " + type(exc).__name__
    return None


async def adopt_all(registry, profile_id, group):
    shared = adoptable(group.get("values", {}))
    entry = registry.entries.get(profile_id) or {}
    if not shared or entry.get("app") is None:
        return
    error = await apply_member(entry["app"], shared, group, "joined the group")
    if error:
        registry.app.state.store.append("profile_group.settings_failed", {
            "group_id": group["id"], "profile_id": profile_id, "error": error})


def save_values(registry, group_id, values):
    store = registry.app.state.store
    groups = registry.groups()
    for group in groups:
        if group["id"] == group_id:
            group["values"] = values
    store.set_setting("profile_groups", groups)


async def change(registry, group_id, body):
    async with registry.lock:
        result = plan(registry, group_id, body)
        if body.revision and body.revision != result["revision"]:
            raise HTTPException(409, "Settings changed. Review the differences again.")
        group = registry._group(group_id)
        with registry.app.state.store.transaction():
            save_values(registry, group_id, result["values"])
        applied, kept, failed, unavailable = [], [], [], []
        overwrite = set(body.overwrite)
        for row in result["members"]:
            if row["status"] == "unavailable":
                unavailable.append(row["id"])
                continue
            keys = [*row["takes"], *(row["own"] if row["id"] in overwrite else [])]
            if row["own"] and row["id"] not in overwrite:
                kept.append(row["id"])
            if not keys:
                continue
            app = registry.entries[row["id"]]["app"]
            error = await apply_member(app, {k: result["after"][k] for k in keys}, group, "group value changed")
            if error:
                failed.append({"id": row["id"], "label": row["label"], "error": error})
            else:
                applied.append(row["id"])
        registry.app.state.store.append("profile_group.settings_changed", {
            "group_id": group_id, "group": group["label"], "before": result["before"], "after": result["after"],
            "applied": applied, "kept_own": kept, "failed": failed, "unavailable": unavailable})
        return {"applied": applied, "kept": kept, "failed": failed, "unavailable": unavailable,
                **group_view(registry, group_id)}


async def adopt(registry, group_id, body):
    async with registry.lock:
        group = registry._group(group_id)
        shared = group.get("values", {})
        keys = [k for k in (body.keys if body.keys is not None else shared) if k in shared]
        if body.keys is not None and len(keys) != len(body.keys):
            raise HTTPException(409, "The group does not share this setting.")
        members = set(registry.members(group_id))
        applied, failed, kept_own = [], [], []
        for profile_id in body.profiles:
            entry = registry.entries.get(profile_id)
            if profile_id not in members or entry is None:
                raise HTTPException(409, "This workspace is not in the group.")
            if entry.get("app") is None:
                failed.append({"id": profile_id, "label": entry["label"], "error": "Workspace unavailable"})
                continue
            current = read(entry["app"], keys)
            values = {k: shared[k] for k in keys if current[k] != shared[k]}
            if "route" in values:
                kept_own.append({"id": profile_id, "label": entry["label"], "keys": ["route"]})
            values = adoptable(values)
            if not values:
                continue
            error = await apply_member(entry["app"], values, group, "returned to the group value")
            if error:
                failed.append({"id": profile_id, "label": entry["label"], "error": error})
            else:
                applied.append(profile_id)
        registry.app.state.store.append("profile_group.settings_adopted", {
            "group_id": group_id, "group": group["label"], "keys": keys, "applied": applied,
            "failed": failed, "kept_own": kept_own})
        return {"applied": applied, "failed": failed, "kept_own": kept_own, **group_view(registry, group_id)}


def migrate(registry):
    store = registry.app.state.store
    groups, changed = registry.groups(), []
    for group in groups:
        if "values" in group or not group.get("template") or not group.get("sections"):
            continue
        template = registry.entries.get(group["template"]) or {}
        if template.get("app") is None:
            continue
        keys = [k for section in group["sections"] for k in SECTION_KEYS.get(section, ())]
        current = read(template["app"], keys)
        group["values"] = {k: v for k, v in current.items() if v is not None and not (k == "files" and v == "custom")}
        changed.append({"group_id": group["id"], "keys": sorted(group["values"])})
    if changed:
        with store.transaction():
            store.set_setting("profile_groups", groups)
            for item in changed:
                store.append("profile_group.migrated", {**item, "from": "template copy",
                                                        "members": "unchanged; differing values stay their own"})


def record_route(registry, group_id, strategy, applied):
    group = group_record(registry, group_id)
    if group is None or not applied:
        return
    value = {"mode": strategy["mode"], "allow_direct": bool(strategy.get("allow_direct"))}
    shared = group.get("values", {})
    if shared.get("route") == value:
        return
    with registry.app.state.store.transaction():
        save_values(registry, group_id, {**shared, "route": value})
        registry.app.state.store.append("profile_group.settings_changed", {
            "group_id": group_id, "group": group["label"], "before": {"route": shared.get("route")},
            "after": {"route": value}, "applied": applied, "kept_own": [], "failed": [], "unavailable": [],
            "source": "checked connection"})


def register(app, authenticate, require_live):
    deps = [Depends(authenticate)]

    def registry():
        return app.state.profiles

    def refused(exc):
        raise HTTPException(400 if str(exc) == "Unknown account group." else 422, str(exc)) from None

    @app.get("/api/profile-groups/{group_id}/settings", dependencies=deps)
    async def group_settings(group_id: str):
        try:
            return group_view(registry(), group_id)
        except ValueError as exc:
            refused(exc)

    @app.post("/api/profile-groups/{group_id}/settings/preview", dependencies=deps)
    async def group_settings_preview(group_id: str, body: GroupChange):
        try:
            return plan(registry(), group_id, body)
        except ValueError as exc:
            refused(exc)

    @app.post("/api/profile-groups/{group_id}/settings", dependencies=deps)
    async def group_settings_change(group_id: str, body: GroupChange):
        require_live()
        try:
            return await change(registry(), group_id, body)
        except ValueError as exc:
            refused(exc)

    @app.post("/api/profile-groups/{group_id}/settings/adopt", dependencies=deps)
    async def group_settings_adopt(group_id: str, body: Adopt):
        require_live()
        try:
            return await adopt(registry(), group_id, body)
        except ValueError as exc:
            refused(exc)
