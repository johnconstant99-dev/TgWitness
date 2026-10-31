"""What each part of a workspace is actually doing, kept apart from whether it is switched on.

Every part answers with one of STATES and a reason code; the panel words them. "working" needs
recent evidence that the part did its job: a switched-on setting, a started process or missing
data is never reported as success. Data older than the part's own schedule is "unknown".
"""
from datetime import datetime, timedelta, timezone

STATES = ("off", "configured", "running", "working", "degraded", "failed", "unknown")
# Summaries show the first of these that any part has.
ORDER = ("failed", "degraded", "unknown", "running", "configured", "working", "off")
# Slack on top of a part's own schedule before its data counts as stale.
SLACK_SECONDS = 180
# Attachments still waiting after this long while observation runs.
MEDIA_WAIT_SECONDS = 3600


def parse(value):
    """ISO text (journal times) or Unix seconds; None when absent or unreadable."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc) if value > 0 else None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(value):
    return value.isoformat(timespec="milliseconds") if value else None


def age(value, now):
    moment = parse(value)
    return None if moment is None else (now - moment).total_seconds()


def part(state, reason, **detail):
    return {"state": state, "reason": reason, **detail}


def worst(states):
    states = [s for s in states if s]
    return next((s for s in ORDER if s in states), "unknown")


def now_utc():
    return datetime.now(timezone.utc)


# Timestamps ---------------------------------------------------------------------------------

def stamp_counts(last):
    """The latest attempt, by what came back: verified tokens, OpenTimestamps proofs awaiting
    Bitcoin, answers that failed the checks, and services that gave no usable answer. Services
    that answered for the same checkpoint on an earlier pass count as covered."""
    counts = {"verified": 0, "ots_pending": 0, "ots_bitcoin_unverified": 0, "rejected": 0, "unreachable": 0,
              "covered": 0, "covered_verified": 0}
    for result in (last or {}).get("results", []):
        if result.get("ok") and result.get("kind") == "rfc3161":
            counts["verified"] += 1
        elif result.get("ok") and result.get("status") == "bitcoin-unverified":
            counts["ots_bitcoin_unverified"] += 1
        elif result.get("ok"):
            counts["ots_pending"] += 1
        elif result.get("received"):
            counts["rejected"] += 1
        else:
            counts["unreachable"] += 1
    for covered in (last or {}).get("covered", []):
        counts["covered"] += 1
        counts["covered_verified"] += covered.get("kind") == "rfc3161"
    return counts


def timestamps(settings, last, success, failure, runtime, route_problem, now):
    """settings: evidence_settings; last/success/failure: the saved latest attempt, latest attempt
    with an answer and latest attempt with a failure; runtime: the anchor loop's own status."""
    runtime = runtime or {}
    interval = settings["interval_minutes"] * 60
    counts = stamp_counts(last)
    detail = {"last_attempt_at": (last or {}).get("at"), "last_pass_at": runtime.get("last_pass_at"),
              "last_pass": runtime.get("outcome"),
              "next_attempt_at": runtime.get("next_at") if settings["enabled"] else None,
              "last_success_at": (success or {}).get("at"), "last_verified_at": (success or {}).get("verified_at"),
              "last_failure": failure, "counts": counts, "interval_seconds": interval,
              "checkpoint": (last or {}).get("checkpoint")}
    if not settings["enabled"]:
        return part("off", "disabled", **detail)
    if route_problem:
        return part("failed", "route", route_problem=route_problem, **detail)
    if runtime.get("busy"):
        return part("running", "sending", **detail)
    if runtime.get("error"):
        return part("failed", "loop_error", error=runtime["error"], **detail)
    seen = [t for t in (parse(detail["last_attempt_at"]), parse(detail["last_pass_at"])) if t]
    if not seen:
        return part("configured", "first_pending", **detail)
    if (now - max(seen)).total_seconds() > 2 * interval + SLACK_SECONDS:
        return part("unknown", "stale", **detail)
    newest_pass = parse(detail["last_pass_at"])
    if runtime.get("outcome") == "up_to_date" and (not last or newest_pass >= parse(last.get("at"))):
        return part("working", "up_to_date", **detail)
    if runtime.get("outcome") == "no_checkpoint" and not last:
        return part("configured", "no_checkpoint", **detail)
    answered = counts["verified"] + counts["ots_pending"] + counts["ots_bitcoin_unverified"] + counts["covered"]
    if not answered:
        return part("failed", "no_answer", **detail)
    if counts["rejected"] or counts["unreachable"]:
        return part("degraded", "partial", **detail)
    if settings["tsa_urls"] and not (counts["verified"] or counts["covered_verified"]):
        return part("degraded", "unverified", **detail)
    return part("working", "stamped", **detail)


# Off-site copy ------------------------------------------------------------------------------

def replica(settings, last, success, runtime, route_problem, head_seq, now):
    """last: the latest pass (replica_last); success: the latest pass without an error."""
    runtime = runtime or {}
    interval = settings["interval_minutes"] * 60
    copied = (last or {}).get("journal_seq")
    if copied is None:
        copied = (success or {}).get("journal_seq")
    detail = {"last_pass_at": (last or {}).get("at"), "last_success_at": (success or {}).get("at"),
              "journal_seq": copied, "head_seq": head_seq,
              "lag_records": max(0, (head_seq or 0) - (copied or 0)) if copied is not None else None,
              "lag_seconds": age((success or {}).get("at"), now),
              "error": (last or {}).get("error"), "next_attempt_at": runtime.get("next_at") if settings["enabled"] else None,
              "interval_seconds": interval}
    if not settings["enabled"]:
        return part("off", "disabled", **detail)
    if route_problem:
        return part("failed", "route", route_problem=route_problem, **detail)
    if runtime.get("busy"):
        return part("running", "copying", **detail)
    if runtime.get("error"):
        return part("failed", "loop_error", **{**detail, "error": runtime["error"]})
    passed = [t for t in (parse(detail["last_pass_at"]), parse(runtime.get("last_pass_at"))) if t]
    if not passed:
        return part("configured", "first_pending", **detail)
    if (now - max(passed)).total_seconds() > 2 * interval + SLACK_SECONDS:
        return part("unknown", "stale", **detail)
    if detail["error"]:
        return part("failed", "error", **detail)
    return part("working", "copied", **detail)


# Sealed server ------------------------------------------------------------------------------

def server_checks(measured, baseline):
    """Protection conditions of a sealed server, each passed, needing attention or unknown.
    Self-reported by the collector on its own host (assurance.ATTESTATION)."""
    measured, baseline = measured or {}, baseline or {}
    checks = []

    def add(name, value, result):
        checks.append({"name": name, "value": value, "result": result})
    listening = measured.get("ssh_listening")
    add("ssh_port", listening, "unknown" if listening is None else "attention" if listening else "pass")
    processes = measured.get("ssh_processes")
    add("ssh_processes", processes, "unknown" if processes is None else "attention" if processes else "pass")
    sessions = measured.get("sessions")
    add("sessions", sessions, "unknown" if sessions is None else "attention" if sessions else "pass")
    logins, before = measured.get("logins"), baseline.get("logins")
    if logins is None or before is None:
        add("new_logins", None, "unknown")
    else:
        add("new_logins", max(0, logins - before), "attention" if logins > before else "pass")
    return checks


def server(assurance, baseline, measured, now, interval=60):
    """assurance: app.state.assurance (None on an ordinary installation); baseline: the host
    measured into the signed start record; measured: the assurance loop's latest measurement."""
    if not assurance:
        return {"deployment": part("off", "not_deployed"), "checks": part("off", "not_deployed", items=[])}
    provider = assurance.get("provider") or {}
    info = {"mode": assurance.get("mode"), "instance_id": provider.get("instance_id")}
    if provider.get("error"):
        deployment = part("degraded", "provider_unavailable", error=provider["error"], **info)
    elif not (baseline or {}).get("deployment"):
        deployment = part("degraded", "no_deployment_record", **info)
    else:
        deployment = part("working", "deployed", **info)
    measured_at = (measured or {}).get("measured_at")
    stale = age(measured_at, now)
    if stale is None or stale > 3 * interval + SLACK_SECONDS:
        items = [{**c, "result": "unknown"} for c in server_checks({}, baseline)]
        return {"deployment": deployment,
                "checks": part("unknown", "not_measured" if stale is None else "stale", items=items,
                               measured_at=measured_at)}
    items = server_checks(measured.get("state"), baseline)
    results = {c["result"] for c in items}
    state, reason = ("degraded", "attention") if "attention" in results else \
        ("unknown", "partly_unknown") if "unknown" in results else ("working", "passed")
    return {"deployment": deployment, "checks": part(state, reason, items=items, measured_at=measured_at)}


# Collector ----------------------------------------------------------------------------------

FAILED_PHASES = {"authorization_required": "signed_out", "collector_error": "collector_error",
                 "storage_error": "storage_error", "resume_failed": "resume_failed"}
SIGN_IN_PHASES = ("code_required", "password_required", "qr_pending")


def connection(c, now):
    detail = {"phase": c.get("phase"), "attempts": c.get("reconnect_attempts") or 0,
              "next_reconnect_at": iso(parse(c.get("next_reconnect_at"))), "error": c.get("last_error"),
              "telegram_pause_until": iso(parse(c.get("rpc_backoff_until")))}
    if c.get("phase") in FAILED_PHASES:
        return part("failed", FAILED_PHASES[c["phase"]], **detail)
    if not c.get("has_session"):
        return part("configured" if c.get("phase") in SIGN_IN_PHASES else "off", "no_account", **detail)
    if not c.get("running"):
        return part("off", "paused", **detail)
    if not c.get("connected"):
        return part("degraded", "reconnecting", **detail)
    pause = parse(c.get("rpc_backoff_until"))
    if pause and pause > now:
        return part("degraded", "telegram_pause", **detail)
    return part("working", "connected", **detail)


def intake(c, heartbeat_seconds, now):
    """Liveness comes from the collector's heartbeat; a quiet chat with no new messages is not a fault."""
    detail = {"last_heartbeat": c.get("last_heartbeat"), "last_event_at": c.get("last_update_at"),
              "heartbeat_seconds": heartbeat_seconds}
    if not c.get("running"):
        return part("off", "paused", **detail)
    beat = age(c.get("last_heartbeat"), now)
    if beat is None:
        return part("unknown", "no_heartbeat", **detail)
    if beat > 3 * heartbeat_seconds + 30:
        return part("unknown", "stale", **detail)
    if not c.get("connected"):
        return part("degraded", "disconnected", **detail)
    return part("working", "live", **detail)


def sources(c, enabled_sources):
    statuses = list((c.get("source_status") or {}).values())
    counts = {"enabled": enabled_sources, "checked": len(statuses),
              "visible": sum(s.get("state") == "visible_in_dialogs" for s in statuses),
              "added": sum(s.get("state") == "discovered" for s in statuses),
              "unconfirmed": sum(s.get("state") == "access_unconfirmed" for s in statuses)}
    scope = (c.get("scope") or {}).get("mode", "selected")
    if not enabled_sources and scope == "selected":
        return part("off", "no_sources", counts=counts)
    if not statuses:
        return part("unknown", "not_checked", counts=counts)
    if counts["unconfirmed"] and not (counts["visible"] or counts["added"]):
        return part("failed", "none_visible", counts=counts)
    if counts["unconfirmed"]:
        return part("degraded", "some_unconfirmed", counts=counts)
    return part("working", "visible", counts=counts)


def media(c, capture, now):
    jobs = c.get("media_jobs") or {}
    counts = {"pending": sum(jobs.get(s, 0) for s in ("queued", "running", "retry")),
              "retry": jobs.get("retry", 0), "failed": jobs.get("failed", 0)}
    waiting = age(c.get("oldest_pending_media_at"), now)
    detail = {"counts": counts, "oldest_pending_at": c.get("oldest_pending_media_at"),
              "disk_free_bytes": c.get("disk_free_bytes"), "min_free_bytes": c.get("media_min_free_bytes")}
    if not capture.get("download_media"):
        return part("off", "disabled", **detail)
    if c.get("storage_low"):
        return part("failed", "disk_low", **detail)
    if not c.get("running"):
        return part("off", "paused", **detail)
    if counts["failed"]:
        return part("degraded", "failed_items", **detail)
    if counts["pending"] and waiting is not None and waiting > MEDIA_WAIT_SECONDS:
        return part("degraded", "queue_waiting", **detail)
    return part("working", "ok", **detail)


def collector(c, capture, heartbeat_seconds, enabled_sources, now):
    parts = {"connection": connection(c, now), "intake": intake(c, heartbeat_seconds, now),
             "sources": sources(c, enabled_sources), "media": media(c, capture, now)}
    return {**parts, "state": worst(p["state"] for p in parts.values())}


def collector_of(app_state, status=None, now=None):
    """The collector parts of one workspace app; status: its collector.status() when already read."""
    from .monitoring import capture_settings
    from . import tuning
    store = app_state.store
    return collector(status or app_state.collector.status(), capture_settings(store),
                     tuning.value(store, "heartbeat_seconds"), len(store.targets(True)), now or now_utc())


def next_at(seconds, now=None):
    return iso((now or now_utc()) + timedelta(seconds=seconds))
