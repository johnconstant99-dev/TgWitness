from dataclasses import asdict, dataclass, field
from datetime import timezone
import hashlib
import re

from ..handover import EMAIL, PHONE
from ..store import canonical
from ..verify import hash_bytes, parse_time, safe_text


@dataclass(frozen=True)
class Evidence:
    seq: int
    hash: str
    journal: str = "collector"
    observed_at: str | None = None


@dataclass
class Fact:
    template_key: str
    params: dict
    evidence: list[Evidence]
    anchor: dict | None = None


@dataclass
class Limit:
    template_key: str
    params: dict = field(default_factory=dict)


@dataclass
class Scene:
    kind: str
    from_seq: int
    to_seq: int
    at_from: str
    at_to: str
    facts: list[Fact] = field(default_factory=list)
    limits: list[Limit] = field(default_factory=list)
    journal: str = "collector"


CATALOG = {
    "setup": ("process.started", "key.created", "key.imported", "workspace.mode_changed"),
    "authorization": ("account.authorized", "account.signed_out", "device.", "account.devices"),
    "scope": ("scope.", "observation.", "monitoring.", "capture.changed", "target.", "source.added"),
    "collection": ("message.", "membership.", "media.", "deletion."),
    "gaps": ("coverage.gap", "process.stopped", "connection.", "clock.discontinuity"),
    "anchoring": ("checkpoint.", "anchor.", "beacon.drand"),
    "witnessing": ("witness.",),
    "external_input": ("document.received", "email.received", "export.received", "export.denied"),
    "analysis": ("analysis.", "verification.", "document.analyzed"),
    "export": ("export.completed", "chat_export.completed", "custody."),
    "publication": ("publish.", "dossier.committed"),
    "takedown": ("takedown.",),
}

FIELDS = ("key_origin", "session_kind", "session_origin", "source", "reason", "status", "name", "file",
          "sha256", "producer", "pages", "created_at", "modified_at", "signature_objects", "sig_objects",
          "signature_claimed", "dkim_status", "round", "record", "from_seq", "to_seq", "root", "account_masked")


def masked(value):
    text = safe_text(value)
    text = EMAIL.sub(lambda m: m[0][0] + "***@***", text)
    text = PHONE.sub(lambda m: "***" + re.sub(r"\D", "", m[0])[-2:], text)
    return ''.join(c for c in text if ord(c) not in range(0x202a, 0x202f) and ord(c) not in range(0x2066, 0x206a))


def scene_kind(kind):
    return next((name for name, patterns in CATALOG.items()
                 if any(kind.startswith(p) if p.endswith('.') else kind == p for p in patterns)), "other")


def build(events, verification, journal="collector", max_scene_records=2000):
    scenes, groups, restarts = [], [], []
    if type(max_scene_records) is not int or not 1 <= max_scene_records <= 10000:
        raise ValueError('Scene record limit must be an integer from 1 to 10000')
    pending_stop = None
    previous_seq = 0
    for event in events:
        if type(event.get("seq")) is not int or event["seq"] <= previous_seq:
            raise ValueError("Narrative source records must be ordered and unique")
        hash_bytes(event["hash"])
        previous_seq = event["seq"]
        when = parse_time(event["observed_at"]).astimezone(timezone.utc)
        if event['kind'] == 'process.stopped':
            pending_stop = event
        elif event['kind'] == 'process.started' and pending_stop:
            if parse_time(pending_stop['observed_at']) <= when:
                restarts.append((pending_stop, event))
            pending_stop = None
        kind = scene_kind(event["kind"])
        group_key = (kind, when.date())
        if not groups or groups[-1][0] != group_key or len(groups[-1][1]) >= max_scene_records:
            groups.append((group_key, []))
        groups[-1][1].append(event)
    for (kind, _), group in groups:
        refs = [Evidence(e["seq"], e["hash"], journal, e['observed_at']) for e in group]
        times = [e['observed_at'] for e in group]
        scene = Scene(kind, group[0]["seq"], group[-1]["seq"], min(times, key=parse_time),
                      max(times, key=parse_time), journal=journal)
        scene.facts.append(Fact("scene.records", {"n": len(group), "from": scene.at_from, "to": scene.at_to}, refs))
        scene.limits.extend([Limit("limit.clock"), Limit("limit.recorded")])
        if kind == "collection":
            counts = {name: sum(e["kind"] == value for e in group) for name, value in (
                ("messages", "message.new"), ("edits", "message.edited"),
                ("deletions", "message.deleted"), ("missing", "message.missing_on_recheck"))}
            scene.facts.append(Fact("collection.counts", counts, refs))
            scene.limits.append(Limit("limit.coverage"))
        else:
            for event, ref in zip(group, refs):
                payload = event["payload"]
                scene.facts.append(Fact("record.field", {"field": "event_kind", "value": masked(event["kind"])}, [ref]))
                for key in FIELDS:
                    value = payload.get(key)
                    if value is None or not isinstance(value, (str, int, float, bool)):
                        continue
                    if isinstance(value, str) and len(value) > 2000:
                        scene.limits.append(Limit("limit.omitted"))
                        continue
                    intact = not isinstance(value, str) or key in ('sha256', 'root') and re.fullmatch(r'[0-9a-f]{64}', value)
                    shown = value if intact else masked(value)
                    scene.facts.append(Fact("record.field", {"field": key, "value": shown}, [ref]))
                for key in ('phone', 'email'):
                    if isinstance(payload.get(key), str) and len(payload[key]) <= 200:
                        scene.facts.append(Fact("record.field", {"field": "account_masked", "value": masked(payload[key])}, [ref]))
                account = payload.get('account_id')
                if type(account) in (str, int) and re.fullmatch(r'-?\d{3,20}', str(account)):
                    scene.facts.append(Fact('record.field', {'field': 'account_masked', 'value': '***' + str(account)[-2:]}, [ref]))
                if kind in ("external_input", "analysis"):
                    scene.limits.append(Limit("limit.document"))
        if kind == "gaps":
            scene.limits.append(Limit("limit.gap"))
        if kind == "other":
            scene.limits.append(Limit("limit.unknown"))
        scene.limits = list({(v.template_key, canonical(v.params)): v for v in scene.limits}.values())
        scenes.append(scene)
    gaps_by_seq = {r.seq: s for s in scenes if s.kind == 'gaps' for r in s.facts[0].evidence}
    for stopped, started in restarts:
        scene = gaps_by_seq[stopped['seq']]
        ref = Evidence(started['seq'], started['hash'], journal, started['observed_at'])
        scene.to_seq = started['seq']
        scene.at_to = max(scene.at_to, started['observed_at'], key=parse_time)
        scene.facts[0].params['n'] += 1
        scene.facts[0].params['to'] = scene.at_to
        scene.facts[0].evidence.append(ref)
        scene.facts.append(Fact('record.field', {'field': 'event_kind', 'value': 'process.started'}, [ref]))
    limits = [Limit("limit.truth"), Limit("limit.review")]
    for step in verification.get("assurance", {}).get("ladder", []):
        if step["status"] != "pass":
            limits.append(Limit("assurance.state", {"tier": step["tier"], "status": step["status"]}))
    anchors = []
    for value in verification.get('anchors', []):
        checked = (value.get('kind') == 'opentimestamps' and value.get('status') == 'confirmed' or
                   value.get('kind') == 'rfc3161' and value.get('signature') == 'checked against the given root')
        if checked:
            suffix = '.ots' if value['kind'] == 'opentimestamps' else '.tsr'
            name = 'anchors/' + value['checkpoint'].removesuffix('.json') + '.' + value['service'] + suffix
            anchors.append({'kind': value['kind'], 'ref': name, 'to_seq': value['event_count'],
                            'time': value['time'], 'time_basis': 'bitcoin-block-header' if suffix == '.ots' else 'tsa-clock'})
    for scene in scenes:
        for fact in scene.facts:
            covers = [a for a in anchors if max(r.seq for r in fact.evidence) <= a['to_seq']]
            if covers:
                fact.anchor = covers[0]
    return {"format": "tgwitness-narrative-v1", "scenes": [asdict(s) for s in scenes],
            "limits": [asdict(v) for v in limits], "assurance": verification.get("assurance"),
            "source": {"fingerprint": verification.get("fingerprint"), "head_hash": verification.get("head_hash"),
                       "events": verification.get("events"), "journal": journal},
            "model_sha256": hashlib.sha256(canonical([asdict(s) for s in scenes])).hexdigest(),
            "translation_review": "machine-assisted, not reviewed", "verified_anchors": anchors}
