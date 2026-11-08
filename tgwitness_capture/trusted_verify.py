from .continuity import analyze, parse_export, render, report_version
from .format import canonical, decode
from .trusted_model import Choice, VisualNote


def verify_analysis(events, read):
    cases = {}
    checked = 0
    for event in events:
        if not event["kind"].startswith("trusted."):
            continue
        payload = event["payload"]
        case = payload.get("case_id")
        if not case:
            if event["kind"] in {"trusted.configured", "trusted.frame", "trusted.export_received",
                                 "trusted.visual_annotation", "trusted.continuity_analyzed"}:
                raise ValueError("Trusted Live observation has no case binding")
            continue
        if event["kind"] == "trusted.configured":
            Choice.model_validate(payload["choice"])
            if case in cases:
                raise ValueError("Duplicate Trusted Live case configuration")
            cases[case] = {"chat": None, "visual": [], "frames": set()}
        if case not in cases:
            raise ValueError("Trusted Live case was never configured")
        state = cases[case]
        artifacts = event["artifacts"]

        def one(role):
            matches = [item for item in artifacts if item["role"] == role]
            if len(matches) != 1:
                raise ValueError("Expected exactly one Trusted Live " + role)
            return read("objects/" + matches[0]["sha256"])

        if event["kind"] == "trusted.frame":
            state["frames"].update(item["sha256"] for item in artifacts if item["role"] == "trusted_viewport")
        elif event["kind"] == "trusted.export_received":
            chat = parse_export(one("desktop_export_original"))
            if (chat["id"], chat["type"]) != (payload.get("chat_id"), payload.get("chat_type")):
                raise ValueError("Export metadata does not match the original")
            if state["chat"] and (chat["id"], chat["type"]) != (state["chat"]["id"], state["chat"]["type"]):
                raise ValueError("Chat changed within a Trusted Live case")
            state["chat"] = chat
        elif event["kind"] == "trusted.visual_annotation":
            value = VisualNote.model_validate({key: payload[key] for key in VisualNote.model_fields})
            if value.frame_sha256 not in state["frames"]:
                raise ValueError("Visual annotation does not reference a retained case frame")
            state["visual"].append({**value.model_dump(), "observed_at": payload["observed_at"], "basis": "operator_transcription"})
        elif event["kind"] == "trusted.continuity_analyzed":
            if state["chat"] is None:
                raise ValueError("Continuity report has no source export")
            stored = one("continuity_report")
            report = analyze(state["chat"], state["visual"], version=report_version(decode(stored)))
            if stored != canonical(report) or one("annotated_chat") != render(state["chat"], report):
                raise ValueError("Continuity report differs from preserved observations")
            checked += 1
    return checked
