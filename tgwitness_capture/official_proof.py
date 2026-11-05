"""Interpret verified official-client events without trusting their HTML report."""
from .format import canonical, digest


def official_report(events, expected=None):
    from .beacon import records
    starts = [e for e in events if e["kind"] == "official.started"]
    opened = [e for e in events if e["kind"] == "official.opened"]
    if not starts and not opened:
        if expected is not None:
            raise ValueError("No official-client procedure to compare with expected settings")
        return None
    expected_options = None
    if expected is not None:
        if (not isinstance(expected, dict) or set(expected) != {"format", "options", "source"}
                or expected["format"] != "tgwitness-official-selection-v1" or not isinstance(expected["options"], dict)
                or not isinstance(expected["source"], str) or not expected["source"]):
            raise ValueError("Unsupported expected official-client settings")
        expected_options = expected["options"]
    reasons = []
    if not starts:
        if expected_options is not None:
            raise ValueError("No recorded interval confirms the expected settings")
        reasons.append("observation_not_started")
    for event in starts:
        payload = event["payload"]
        settings = payload.get("settings")
        if (not isinstance(settings, dict) or payload.get("settings_sha256") != digest(canonical(settings))
                or settings.get("mode") not in {"passive", "paced"} or settings.get("direct_fallback") is not False
                or payload.get("recording_starts_after_login") is not True):
            raise ValueError("Invalid official-client settings binding")
        if expected_options is not None and settings != expected_options:
            raise ValueError("Official-client settings differ from the independently expected settings")
        if expected is not None and payload.get("source") != expected["source"]:
            raise ValueError("Official-client source differs from the independently expected source")
    finished = [e for e in events if e["kind"] == "official.finished"]
    if len(finished) != 1:
        reasons.append("procedure_not_finished")
    elif finished[0]["payload"].get("logout_confirmed") is not True:
        reasons.append("logout_unconfirmed")
    interruptions = [e for e in events if e["kind"] in {"official.stopped", "capture.failed", "capture.partial", "video.interrupted"}]
    if interruptions:
        reasons.append("observation_interrupted")
    sessions = {}
    for event in events:
        if event["kind"] == "video.started":
            capture_id = event["payload"].get("capture_id")
            if not isinstance(capture_id, str) or capture_id in sessions:
                raise ValueError("Invalid video session")
            sessions[capture_id] = {"indices": [], "stopped": False}
        elif event["kind"] == "video.segment":
            session = sessions.get(event["payload"].get("capture_id"))
            index = event["payload"].get("segment_index")
            if (session is None or session["stopped"] or type(index) is not int
                    or index != len(session["indices"]) or not event["artifacts"]
                    or not any(a["role"] == "screen_video_segment" for a in event["artifacts"])):
                raise ValueError("Video segment order or artifact binding is invalid")
            session["indices"].append(index)
        elif event["kind"] in {"video.stopped", "video.interrupted"}:
            session = sessions.get(event["payload"].get("capture_id"))
            if session is None or session["stopped"]:
                raise ValueError("Video end without an open start")
            if (event["kind"] != "video.stopped" or event["payload"].get("clean_exit") is not True
                    or event["payload"].get("requested_stop") is not True
                    or event["payload"].get("unsealed_segments") != []):
                if "video_coverage_incomplete" not in reasons:
                    reasons.append("video_coverage_incomplete")
            session["stopped"] = True
    required_video = any(e["payload"]["settings"].get("require_video") for e in starts)
    if required_video and (len(sessions) < len(starts) or any(not s["indices"] or not s["stopped"] for s in sessions.values())):
        if "video_coverage_incomplete" not in reasons:
            reasons.append("video_coverage_incomplete")
    if not any(e["kind"] == "capture.saved" for e in events):
        reasons.append("no_saved_observation")
    beacons = records(events)
    if any(e["payload"]["settings"].get("drand") for e in starts) and not beacons:
        reasons.append("no_public_beacon")
    return {"mode": starts[0]["payload"]["settings"]["mode"] if starts else None,
            "settings_checked": expected_options is not None, "intervals": len(starts),
            "video_segments": sum(len(s["indices"]) for s in sessions.values()),
            "procedure_status": "INCOMPLETE" if reasons else "PASS", "reasons": reasons,
            "interruptions": [{"seq": e["seq"], "kind": e["kind"], "at": e["recorded_at"]} for e in interruptions],
            "environment_status": "INCOMPLETE", "cloudflare_status": "INCOMPLETE",
            "drand_status": "INCOMPLETE", "drand_rounds": beacons,
            "scope": "rendered observations only; no complete account history or Telegram-signed content",
            "trust": "local integrity only; verify independent environment and network evidence separately"}
