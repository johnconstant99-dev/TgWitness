"""One settings model for first run and subsequent edits; adapters use existing stores.

Presets are previewed against current values. A revision protects the reviewed diff from
another tab. Presentation levels never grant permissions or erase hidden configuration.
"""
import hashlib
import asyncio
import json
import time
from typing import Literal

from fastapi import Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from . import alerts, i18n, preferences, replica, tuning
from .anchoring import evidence_settings, EvidenceMode
from .monitoring import capture_settings, Capture, MEDIA_TYPES
from .scope import ScopeUpdate, in_folder
from .store import utcnow

Goal = Literal["copy", "watch", "evidence"]
PRESETS = {
    "copy": {"continuous": False, "files": "photos", "timestamps": False, "drand": False,
             "notifications": False, "replica": False, "outside": False, "ip": "auto"},
    "watch": {"continuous": True, "files": "short_media", "timestamps": True, "drand": False,
              "notifications": True, "replica": False, "outside": True, "ip": "auto"},
    "evidence": {"continuous": True, "files": "all", "timestamps": True, "drand": True,
                 "notifications": True, "replica": False, "outside": True, "ip": "hide"},
}
FIELDS = [
    {"key": key, "label": label, "section": section, "level": level, "type": kind}
    for key, label, section, level, kind in (
        ("continuous", "Continuous collection", "collection", "standard", "bool"),
        ("files", "Saved files", "collection", "standard", "files"),
        ("timestamps", "Independent timestamps", "protection", "standard", "bool"),
        ("drand", "Proof of live recording", "protection", "expert", "bool"),
        ("notifications", "Problem notifications", "notifications", "standard", "bool"),
        ("replica", "Off-site copy", "notifications", "expert", "bool"),
        ("outside", "Requests outside Telegram", "connection", "standard", "bool"),
        ("ip", "Can Telegram see this server's address?", "connection", "simple", "ip"),
    )
]


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step: int = Field(default=1, ge=1, le=7)
    goal: Goal = "copy"
    route: Literal["auto", "warp", "proxy", "direct"] = "auto"
    allow_direct: bool = False
    unchecked: bool = False
    scope: Literal["account", "selected", "folder"] = "account"
    chat_ids: list[int] = Field(default_factory=list, max_length=10000)
    folder_id: int | None = Field(default=None, ge=0, le=4096)
    account_kind: Literal["dedicated", "main"] | None = None


class GoalChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    goal: Goal
    revision: str | None = None
    keep_manual: bool = False


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: Literal["continuous", "files", "timestamps", "drand", "notifications", "replica", "outside", "ip"]
    value: bool | str
    allow_outside: bool = False
    disable_dependents: bool = False
    revision: str


def file_policy(choice):
    result = Capture(download_media=True, max_media_mb=1000 if choice == "all" else 20,
        types={k: {"enabled": choice == "all" or k == "photo" or choice == "short_media" and k in ("video", "video_note"),
                   "max_mb": 1000 if choice == "all" else 20,
                   "max_seconds": 60 if choice == "short_media" and k in ("video", "video_note") else 0}
               for k in MEDIA_TYPES}).model_dump()
    for rule in result["types"].values():
        if not rule.get("max_seconds"):
            rule.pop("max_seconds", None)
    return result


def wizard_state(app):
    s, c = app.state.store, app.state.collector
    saved = s.get_setting("first_run", None)
    if saved is None:
        existing = bool(s.get_setting("setup", None) or c.status()["has_session"] or s.targets())
        saved = {"completed": existing, "skipped": False}
    return {**Draft().model_dump(), **saved}


def values(app):
    s, c = app.state.store, app.state.collector
    evidence, capture = evidence_settings(s), capture_settings(s)
    files = next((choice for choice in ("photos", "short_media", "all") if capture == file_policy(choice)), "custom")
    wizard = wizard_state(app)
    continuous = s.get_setting("resume", False) if wizard.get("completed") or wizard.get("skipped") else s.get_setting("collection_intent", False)
    return {"continuous": continuous, "files": files, "timestamps": evidence["enabled"],
            "drand": evidence["drand"], "notifications": alerts.alert_settings(s)["enabled"],
            "replica": replica.replica_settings(s)["enabled"],
            "outside": c.route_policy()["outside_enabled"],
            "ip": s.get_setting("ip_choice", "hide" if c.route_policy()["exposure"] == "hide" else "auto")}


def revision(app):
    # Include raw fields so two distinct custom policies cannot share a preview revision.
    s = app.state.store
    raw = [values(app), capture_settings(s), evidence_settings(s), alerts.alert_settings(s), replica.replica_settings(s),
           app.state.collector.route_policy(), app.state.collector.network_config().public(),
           s.get_setting("goal_preset", None)]
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


def state(app):
    s, c = app.state.store, app.state.collector
    preset = s.get_setting("goal_preset", None)
    current = values(app)
    baseline = (preset or {}).get("values", {})
    wizard = wizard_state(app)
    metadata = [dict(f, value=current[f["key"]], modified=f["key"] in baseline and current[f["key"]] != baseline[f["key"]]) for f in FIELDS]
    parameters = [{"key": "parameter:" + key, "label": p.label, "section": "parameters", "level": "expert"}
                  for key, p in tuning.BY_KEY.items()]
    return {"wizard": wizard, "goal": (preset or {}).get("goal"), "values": current,
            "fields": metadata, "parameters": parameters, "revision": revision(app),
            "connection": app.state.connection.public()["current"],
            "recommendations": ["replica", "witness", "code"] if (preset or {}).get("goal") == "evidence" else [],
            "needs_notification_destination": current["notifications"] and not app.state.vault.read("alerts").get("urls"),
            "outside_problem": c.policy_state()["outside_problem"] if current["outside"] else None,
            "collection_problem": s.get_setting("collection_problem", None)}


def preview(app, body):
    current = values(app)
    desired = dict(PRESETS[body.goal])
    baseline = (app.state.store.get_setting("goal_preset", None) or {}).get("values", {})
    if body.keep_manual:
        desired.update({k: v for k, v in current.items() if k in baseline and v != baseline[k]})
    return {"goal": body.goal, "revision": revision(app), "values": desired,
            "diff": [{"key": k, "before": current[k], "after": v} for k, v in desired.items() if current[k] != v]}


def main_account_scope(app, body):
    """A main account records only chosen chats: the whole account or a folder would bring in its owner's
    private conversations. The answer comes from the first setup; a copy of one's own account is exempt."""
    saved = wizard_state(app)
    kind = body.account_kind or saved.get("account_kind")
    goal = body.goal if "goal" in body.model_fields_set else saved.get("goal", body.goal)
    if kind == "main" and goal != "copy" and body.scope != "selected":
        raise HTTPException(409, "On your main account only chosen chats can be recorded. Choose chats, or use a separate account.")


def checked(app, draft=None):
    result = app.state.store.get_setting("connection_check", {}) or {}
    from .guided_connection import revision as connection_revision
    if draft is not None:
        strategy = app.state.store.get_setting("connection_strategy", {})
        if strategy.get("mode") != draft.route or strategy.get("allow_direct", False) != draft.allow_direct:
            return False
    return bool(result.get("telegram_connected") and time.time() - result.get("checked_at", 0) < 300
                and result.get("revision") == connection_revision(app.state.collector))


def register(app, authenticate, require_live, operation, save_evidence, save_capture):
    deps = [Depends(authenticate)]

    @app.get("/api/preferences", dependencies=deps)
    async def get_preferences(request: Request):
        return {"saved": preferences.saved(app.state.store, request.state.principal)}

    @app.post("/api/preferences", dependencies=deps)
    async def put_preferences(request: Request, body: preferences.Preferences, response: Response):
        app.state.store.set_setting(preferences.preference_key(request.state.principal), body.model_dump())
        response.set_cookie(i18n.COOKIE, body.language, max_age=31536000, samesite="strict", path="/")
        return {"saved": body.model_dump()}

    @app.get("/api/settings", dependencies=deps)
    async def get_settings():
        return state(app)

    @app.post("/api/settings/goal/preview", dependencies=deps)
    async def goal_preview(body: GoalChange):
        return preview(app, body)

    async def apply_values(desired):
        s, c = app.state.store, app.state.collector
        before = values(app)
        if desired["drand"] and not desired["timestamps"] or any(desired[k] for k in ("timestamps", "notifications", "replica")) and not desired["outside"]:
            raise HTTPException(409, "The preserved manual settings conflict with this goal. Review external requests and timestamps.")
        if desired["replica"]:
            destination = replica.replica_settings(s)
            if not destination["endpoint"] or not destination["bucket"]:
                raise HTTPException(409, "Configure the off-site copy destination in Settings first.")
        if desired["continuous"] != before["continuous"] or desired["ip"] != before["ip"]:
            from .guided_connection import busy_account
            try:
                busy_account(app)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
        # IP tightening never permits an existing direct session to carry on unnoticed.
        if desired["ip"] == "hide" and (c.network_config().kind == "direct" or c.direct_fallback):
            await c.stop()
            from .network import NetworkConfig
            await c.set_network(NetworkConfig())
        if not desired["continuous"] and c.running:
            await c.stop()
        policy = c.route_policy()
        exposure = "hide" if desired["ip"] == "hide" else policy["exposure"]
        wanted = {"exposure": exposure, "outside_enabled": desired["outside"]}
        # "Auto" preserves the user's answer about direct fallback.
        with s.transaction():
            s.set_setting("route_policy", wanted)
            if wanted != policy:
                # The same record the IP protection form writes: who may see this server's address is evidence.
                from .collector import EXPOSURE_MEANING
                s.append("network.policy_changed", {**wanted, "before": policy, "source": "settings",
                                                    "meaning": EXPOSURE_MEANING[exposure]})
            s.set_setting("ip_choice", desired["ip"])
            strategy = s.get_setting("connection_strategy", {})
            if strategy and desired["ip"] == "hide":
                s.set_setting("connection_strategy", {**strategy, "allow_direct": False})
            s.set_setting("collection_intent", desired["continuous"])
            if not desired["continuous"]:
                s.set_setting("resume", False)
            if desired["files"] != "custom":
                save_capture(s, file_policy(desired["files"]))
            evidence = {**evidence_settings(s), "enabled": desired["timestamps"], "drand": desired["drand"]}
            save_evidence(s, EvidenceMode(**evidence))
            notification = {**alerts.alert_settings(s), "enabled": desired["notifications"], "problems": True}
            s.set_setting("alerts", notification)
            s.set_setting("replica", {**replica.replica_settings(s), "enabled": desired["replica"]})
            s.append("settings.changed", {"before": before, "after": desired})
        c.media_wakeup.set()
        app.state.anchor_wakeup.set()
        app.state.alert_wakeup.set()
        app.state.replica_wakeup.set()
        wizard = wizard_state(app)
        if desired["continuous"] and (wizard.get("completed") or wizard.get("skipped")) and not c.running:
            try:
                await asyncio.wait_for(c.start(), 45)
                s.set_setting("collection_problem", None)
            except (OSError, ValueError, TimeoutError) as exc:
                # Preferences are saved even if the transport is temporarily unavailable.
                s.set_setting("collection_problem", type(exc).__name__)
                s.append("settings.collection_pending", {"error_type": type(exc).__name__})
        elif not desired["continuous"]:
            s.set_setting("collection_problem", None)

    @app.post("/api/settings/goal", dependencies=deps)
    async def goal_apply(body: GoalChange):
        require_live()
        async with app.state.operation_lock:
            if body.revision != revision(app):
                raise HTTPException(409, "Settings changed. Review the differences again.")
            proposed = preview(app, body)
            await apply_values(proposed["values"])
            app.state.store.set_setting("goal_preset", {"goal": body.goal, "version": 1,
                "values": PRESETS[body.goal], "at": utcnow()})
        return state(app)

    @app.post("/api/settings/edit", dependencies=deps)
    async def edit(body: Edit):
        require_live()
        async with app.state.operation_lock:
            if body.revision != revision(app):
                raise HTTPException(409, "Settings changed. Review the differences again.")
            desired = values(app)
            if body.key == "files":
                valid = body.value in ("photos", "short_media", "all")
            elif body.key == "ip":
                valid = body.value in ("auto", "hide")
            else:
                valid = type(body.value) is bool
            if not valid:
                raise HTTPException(422, "Invalid setting value")
            desired[body.key] = body.value
            if body.key in ("timestamps", "drand", "notifications", "replica") and body.value and not desired["outside"]:
                if not body.allow_outside:
                    raise HTTPException(409, "This feature needs external requests. Allow them?")
                desired["outside"] = True
            if body.key == "outside" and not body.value and any(desired[k] for k in ("timestamps", "drand", "notifications", "replica")):
                if not body.disable_dependents:
                    raise HTTPException(409, "Turn off the dependent features too?")
                desired.update(timestamps=False, drand=False, notifications=False, replica=False)
            if desired["drand"]:
                if body.key == "timestamps" and not body.value:
                    desired["drand"] = False
                else:
                    desired["timestamps"] = True
            await apply_values(desired)
        return state(app)

    @app.post("/api/first-run", dependencies=deps)
    async def save_draft(body: Draft):
        require_live()
        existing = wizard_state(app).get("completed")
        if not existing and body.step >= 5 and not body.unchecked and not checked(app, body):
            raise HTTPException(409, "Check the connection or explicitly continue without checking.")
        if body.step >= 6 and not app.state.collector.status()["has_session"]:
            raise HTTPException(409, "Connect Telegram first.")
        old = wizard_state(app)
        app.state.store.set_setting("first_run", {**old, **body.model_dump(), "at": utcnow()})
        return state(app)

    async def selected_chats(body):
        c = app.state.collector
        if not c.dialog_cache:
            await c.dialogs()
        selected = set(body.chat_ids) if body.scope == "selected" else set(c.dialog_cache)
        if body.scope == "folder":
            folder = c.folders.get(body.folder_id)
            if folder is None:
                raise ValueError("Choose an available Telegram folder.")
            selected = {cid for cid, d in c.dialog_cache.items() if in_folder(folder, cid, d["kind"], d["entity"], d["archived"])}
        if not selected or not selected <= set(c.dialog_cache):
            raise ValueError("Select available chats first.")
        return selected

    async def save_scope(body):
        from . import recording
        c, s = app.state.collector, app.state.store
        selected = await selected_chats(body)
        with s.transaction():
            recording.save(s, recording.RecordingUpdate(scope=ScopeUpdate(mode=body.scope,
                folder_id=body.folder_id, acknowledged=True)))
            if body.scope == "selected":
                for chat in s.targets():
                    s.set_target(chat["chat_id"], chat["title"], chat["kind"], chat["chat_id"] in selected)
                for cid in selected:
                    d = c.dialog_cache[cid]
                    s.set_target(cid, d["title"], d["kind"], True)
                s.append("sources.selected", {"chat_ids": sorted(selected)})
        return selected

    @app.post("/api/settings/scope", dependencies=deps)
    async def edit_scope(body: Draft):
        require_live()
        main_account_scope(app, body)
        async def apply():
            await save_scope(body)
            if app.state.collector.running:
                await app.state.collector.apply_scope()
            old = app.state.store.get_setting("first_run", {})
            app.state.store.set_setting("first_run", {**old, "scope": body.scope, "folder_id": body.folder_id, "chat_ids": body.chat_ids})
            return state(app)
        return await operation(apply)

    @app.post("/api/first-run/estimate", dependencies=deps)
    async def estimate(body: Draft):
        require_live()
        async def sample():
            c = app.state.collector
            ids = sorted(await selected_chats(body))
            await c.restore()
            counts, sizes = [], []
            from .monitoring import media_kind, duration_allowed
            capture = capture_settings(app.state.store)
            # Bounded sampling. Counts come from Telegram, never from sequential message IDs.
            for cid in ids[:3]:
                entity = await c.resolve_target(cid)
                batch = await asyncio.wait_for(c.client.get_messages(entity, limit=20), 15)
                total = getattr(batch, "total", None)
                if total is None:
                    continue
                counts.append(total)
                for msg in batch:
                    size = len((getattr(msg, "message", "") or "").encode()) + 512
                    file = getattr(msg, "file", None)
                    rule = capture["types"][media_kind(msg)]
                    file_size = getattr(file, "size", None)
                    if capture["download_media"] and rule["enabled"] and duration_allowed(msg, rule) and file_size and file_size <= rule["max_mb"] * 1024**2:
                        size += file_size
                    sizes.append(size)
            if not counts or not sizes:
                return {"available": False}
            messages = sum(counts) / len(counts) * len(ids)
            size = messages * sum(sizes) / len(sizes) / 1024**2
            return {"available": True, "size": round(size), "min": max(1, round(messages / 200 / 60 + size / 10 / 60)),
                    "max": max(2, round(messages / 20 / 60 + size / 60)), "sample_chats": len(counts),
                    "assumptions": "20–200 messages/s and 1–10 MiB/s; excludes Telegram-imposed waits", "approximate": True}
        return await operation(sample)

    @app.post("/api/first-run/skip", dependencies=deps)
    async def skip():
        require_live()
        s = app.state.store
        s.set_setting("first_run", {**wizard_state(app), "skipped": True})
        return state(app)

    @app.post("/api/first-run/finish", dependencies=deps)
    async def finish(body: Draft):
        require_live()
        if not body.unchecked and not checked(app, body):
            raise HTTPException(409, "The connection check expired. Check again or continue without checking.")
        c, s = app.state.collector, app.state.store
        if not c.status()["has_session"]:
            raise HTTPException(409, "Connect Telegram first.")
        if wizard_state(app).get("completed"):
            return {"action": "existing", **state(app)}
        main_account_scope(app, body)
        from .account_export import AccountExportOptions
        async def start():
            if wizard_state(app).get("completed"):
                return {"action": "existing", **state(app)}
            if body.goal != (s.get_setting("goal_preset", {}) or {}).get("goal"):
                raise ValueError("Apply the selected goal before starting.")
            dialogs = await c.dialogs()
            selected = await save_scope(body)
            if body.goal == "copy":
                capture = capture_settings(s)
                rules = {"video_message" if k == "video_note" else k: v for k, v in capture["types"].items()}
                await app.state.account_export.start(AccountExportOptions(chat_ids=sorted(selected) if body.scope != "account" else [],
                    media_types=[k for k, v in rules.items() if v["enabled"] and capture["download_media"]],
                    max_media_file_mib=max(v["max_mb"] for v in rules.values()), media_rules=rules,
                    report_language=s.get_setting("ui_preferences:admin", {}).get("language", "en"),
                    include_contacts=False, include_profile=False))
            else:
                await c.start()
            s.set_setting("first_run", {**body.model_dump(), "completed": True, "skipped": False, "at": utcnow()})
            return {"action": "export" if body.goal == "copy" else "collect", "listed_chats": len(dialogs["dialogs"]), **state(app)}
        return await operation(start)
