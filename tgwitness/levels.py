"""Setup by goal and the two scales the panel shows: credibility (what an outsider can check about
the record) and reliability (how likely collection keeps running and the record survives).

Nothing here switches anything on by itself. For a goal the panel proposes settings, the person
reviews them and applies them; the scales are computed from what is set and working now, never from
the goal that was picked. Settings that need the person's own accounts or keys (notifications, an
off-site copy, a server) are proposed as next steps and open their own forms.
"""
from pydantic import BaseModel, ConfigDict
from typing import Literal

from .monitoring import MEDIA_DEFAULT_MB, MEDIA_TYPES

GOALS = ("personal", "investigation", "evidence")
SIZES = ("small", "medium", "large")
FILES = ("text", "media", "all")
PLACES = ("computer", "server")

# Applied by the panel in one step; everything else is a step with its own form.
APPLIED = ("timestamps", "drand", "devices")
STEPS = ("alerts", "replica", "server", "gateway", "code", "witness")
EXTRA = {"timestamps": "evidence", "drand": "evidence", "devices": "evidence", "alerts": "alerts",
         "replica": "evidence", "replica_lock": "evidence", "server": "cloud", "always_on": "cloud",
         "code": "github", "witness": "bot", "gateway": "cloud", "gateway_log": "evidence"}

RECOMMENDED = {
    "personal": {"apply": (), "steps": ("alerts",), "interval_minutes": 60},
    "investigation": {"apply": ("timestamps", "devices"), "steps": ("alerts", "replica", "server"),
                      "interval_minutes": 30},
    "evidence": {"apply": ("timestamps", "drand", "devices"), "steps": STEPS, "interval_minutes": 10},
}
DIALOG_LIMIT = {"small": 1000, "medium": 3000, "large": 20000}
LARGE_MEDIA_MB = {"photo": 20, "video": 1000, "animation": 50, "video_note": 100, "voice": 50, "audio": 200,
                  "sticker": 5, "document": 1000}
# Free disk kept when everything is downloaded; downloads pause below it.
LARGE_MEDIA_RESERVE_MB = 4096
# Smallest server disk, in GB, offered for a large observation that keeps every file.
LARGE_DISK_GB = 160

CREDIBILITY = (("journal", 1), ("timestamps", 3), ("drand", 1), ("devices", 1), ("code", 1), ("witness", 1),
               ("server", 2), ("gateway_log", 1))
RELIABILITY = (("always_on", 3), ("replica", 3), ("replica_lock", 1), ("alerts", 1))
LEVELS = ((80, "maximum"), (50, "high"), (25, "moderate"), (0, "basic"))


class Setup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    goal: Literal[GOALS]
    size: Literal[SIZES]
    files: Literal[FILES]
    place: Literal[PLACES]
    timestamps: bool = False
    drand: bool = False
    devices: bool = False


def files_choice(capture):
    """The answer that matches the current attachment policy."""
    if not capture["download_media"]:
        return "text"
    rules = capture["types"]
    if all(rules[kind]["enabled"] and rules[kind]["max_mb"] >= LARGE_MEDIA_MB[kind] for kind in MEDIA_TYPES):
        return "all"
    return "media"


def size_choice(dialog_limit):
    return "small" if dialog_limit <= DIALOG_LIMIT["small"] else "medium" if dialog_limit <= DIALOG_LIMIT["medium"] \
        else "large"


def capture_for(files, capture):
    """The attachment policy for an answer; None when the current one already gives it."""
    if files_choice(capture) == files:
        return None
    if files == "text":
        return {**capture, "download_media": False}
    sizes = LARGE_MEDIA_MB if files == "all" else MEDIA_DEFAULT_MB
    return {"download_media": True, "record_disabled_media": capture["record_disabled_media"],
            "max_media_mb": capture["max_media_mb"],
            "types": {kind: {"enabled": True, "max_mb": sizes[kind]} for kind in MEDIA_TYPES}}


def plan(setup, evidence, capture, parameters):
    """What applying the setup changes: new evidence settings, attachment policy and parameter values,
    each None or empty when nothing changes."""
    if (setup.drand or setup.devices) and not setup.timestamps:
        raise ValueError("Live-recording records and the device list work only with independent timestamps on.")
    wanted = {**evidence, "enabled": setup.timestamps, "drand": setup.drand, "devices": setup.devices}
    if setup.timestamps and not evidence["enabled"]:
        wanted["interval_minutes"] = RECOMMENDED[setup.goal]["interval_minutes"]
    values = {}
    if size_choice(parameters["dialog_limit"]) != setup.size:
        values["dialog_limit"] = DIALOG_LIMIT[setup.size]
    if setup.files == "all" and setup.size == "large":
        values["media_min_free_mb"] = max(parameters["media_min_free_mb"], LARGE_MEDIA_RESERVE_MB)
    return {"evidence": wanted if wanted != evidence else None,
            "capture": capture_for(setup.files, capture),
            "parameters": {key: value for key, value in values.items() if parameters.get(key) != value}}


def scale(weights, on):
    total = sum(weight for _, weight in weights)
    score = sum(weight for name, weight in weights if on.get(name))
    percent = round(100 * score / total) if total else 0
    return {"score": score, "total": total, "percent": percent,
            "level": next(name for floor, name in LEVELS if percent >= floor),
            "items": [{"id": name, "weight": weight, "on": bool(on.get(name)), "extra": EXTRA.get(name)}
                      for name, weight in weights]}


def assess(evidence, replica, alerts, destinations, assurance, source, witnesses, place, gateway_log=False):
    """Both scales from the current settings. A part counts when it is switched on and set up; whether
    it is working right now is shown next to it from health.py."""
    timestamps = bool(evidence["enabled"])
    polled = [w for w in witnesses if w.get("last_poll") and not w.get("overdue")]
    credibility = {"journal": True, "timestamps": timestamps, "drand": timestamps and evidence.get("drand"),
                   "devices": timestamps and evidence.get("devices"),
                   "code": bool(source.get("current") and (source.get("last") or {}).get("matches")),
                   "witness": bool(polled), "server": bool(assurance),
                   "gateway_log": timestamps and bool(evidence.get("gateway")) and bool(gateway_log)}
    copy = bool(replica["enabled"])
    reliability = {"always_on": bool(assurance) or place == "server", "replica": copy,
                   "replica_lock": copy and replica["retention_days"] > 0,
                   "alerts": bool(alerts["enabled"] and alerts["problems"] and destinations)}
    return {"credibility": scale(CREDIBILITY, credibility), "reliability": scale(RELIABILITY, reliability)}
