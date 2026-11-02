from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import report_design


class Presentation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    design: report_design.Design = "classic"
    activity_chart: bool = True
    hourly_chart: bool = True
    participant_chart: bool = True
    chat_chart: bool = True
    composition_chart: bool = True
    participant_labels: Literal["aliases", "ids"] = "aliases"
    chart_limit: int = Field(default=10, ge=5, le=30)

    @field_validator("design", mode="before")
    @classmethod
    def migrate_design(cls, value):
        return report_design.canonical(value)


FORMAT = "tgwitness-observation-analytics-v1"
KINDS = {
    "message.new": "new",
    "message.snapshot": "snapshot",
    "message.recovered": "recovered",
    "message.edited": "edited",
    "message.deleted": "deleted",
    "message.missing_on_recheck": "missing",
}
MESSAGE_KINDS = frozenset(("new", "snapshot", "recovered"))
MAX_GROUPS = 100_000
MAX_DAY_BUCKETS = 366
MAX_MONTH_BUCKETS = 1200


def _counts():
    return dict.fromkeys(KINDS.values(), 0)


def _identifier(value):
    return value if type(value) is int and 0 < abs(value) < 2**63 else None


def _sequence(value):
    return value if type(value) is int and 0 < value < 2**63 else None


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment.utcoffset() is None:
            return None
        return moment.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _row():
    return {"counts": _counts(), "total": 0, "first_seq": None, "last_seq": None}


def _add(row, kind, seq):
    row["counts"][kind] += 1
    row["total"] += 1
    if seq is not None:
        row["first_seq"] = seq if row["first_seq"] is None else min(row["first_seq"], seq)
        row["last_seq"] = seq if row["last_seq"] is None else max(row["last_seq"], seq)


def _merge(target, source):
    for kind in KINDS.values():
        target["counts"][kind] += source["counts"][kind]
    target["total"] += source["total"]
    if source["first_seq"] is not None:
        target["first_seq"] = source["first_seq"] if target["first_seq"] is None else min(target["first_seq"], source["first_seq"])
    if source["last_seq"] is not None:
        target["last_seq"] = source["last_seq"] if target["last_seq"] is None else max(target["last_seq"], source["last_seq"])


def _copy(row):
    return {**row, "counts": dict(row["counts"])}


class _Groups:
    def __init__(self):
        self.rows = {}
        self.unknown = _row()
        self.total = 0
        self.overflow = False

    def add(self, identity, kind, seq):
        self.total += 1
        if identity is None:
            _add(self.unknown, kind, seq)
            return
        if self.overflow:
            return
        if identity not in self.rows:
            if len(self.rows) >= MAX_GROUPS:
                self.overflow = True
                self.rows.clear()
                return
            self.rows[identity] = _row()
        _add(self.rows[identity], kind, seq)

    def result(self):
        return {"status": "too_many_groups" if self.overflow else "available",
                "total": self.total, "counted_events": self.total,
                "unknown_count": self.unknown["total"], "unknown": _copy(self.unknown),
                "rows": [{"id": identity, **_copy(row)} for identity, row in sorted(self.rows.items())]}


class Analytics:
    def __init__(self):
        self.totals = _row()
        self.message_observations = 0
        self.first = self.last = None
        self.invalid_time_events = 0
        self.hourly = [[0] * 24 for _ in range(7)]
        self.periods = {}
        self.granularity = "day"
        self.period_overflow = False
        self.participants = _Groups()
        self.chats = _Groups()

    def _period(self, moment, kind, seq):
        if self.period_overflow:
            return
        day = moment.date().isoformat()
        period = day if self.granularity == "day" else day[:7]
        if period not in self.periods and self.granularity == "day" and len(self.periods) >= MAX_DAY_BUCKETS:
            monthly = {}
            for previous, row in self.periods.items():
                _merge(monthly.setdefault(previous[:7], _row()), row)
            self.periods = monthly
            self.granularity = "month"
            period = day[:7]
        if period not in self.periods and self.granularity == "month" and len(self.periods) >= MAX_MONTH_BUCKETS:
            self.period_overflow = True
            self.periods.clear()
            return
        _add(self.periods.setdefault(period, _row()), kind, seq)

    def add(self, event):
        if not isinstance(event, dict):
            return
        event_kind = event.get("kind")
        kind = KINDS.get(event_kind) if isinstance(event_kind, str) else None
        if kind is None:
            return
        seq = _sequence(event.get("seq"))
        _add(self.totals, kind, seq)
        self.chats.add(_identifier(event.get("chat_id")), kind, seq)
        if kind in MESSAGE_KINDS:
            self.message_observations += 1
            payload = event.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            sender = payload.get("sender_observation")
            sender = sender if isinstance(sender, dict) else {}
            identity = payload.get("sender_id", sender.get("id", event.get("sender_id")))
            self.participants.add(_identifier(identity), kind, seq)
        moment = _time(event.get("observed_at"))
        if moment is None:
            self.invalid_time_events += 1
            return
        self.first = moment if self.first is None else min(self.first, moment)
        self.last = moment if self.last is None else max(self.last, moment)
        self.hourly[moment.weekday()][moment.hour] += 1
        self._period(moment, kind, seq)

    def result(self):
        valid_times = self.totals["total"] - self.invalid_time_events
        return {"format": FORMAT, "basis": "observation_events", "timezone": "UTC",
                "totals": dict(self.totals["counts"]), "activity_events": self.totals["total"],
                "message_observations": self.message_observations,
                "first_observed_at": self.first.isoformat() if self.first else None,
                "last_observed_at": self.last.isoformat() if self.last else None,
                "invalid_time_events": self.invalid_time_events,
                "sequence": {"from": self.totals["first_seq"], "to": self.totals["last_seq"]},
                "activity": {"status": "too_many_periods" if self.period_overflow else "available",
                             "granularity": self.granularity, "sparse": True,
                             "counted_events": valid_times,
                             "rows": [{"period": period, **_copy(row)} for period, row in sorted(self.periods.items())]},
                "hourly": {"status": "available", "weekday_order": "monday_first",
                           "counted_events": valid_times, "rows": [list(row) for row in self.hourly]},
                "participants": self.participants.result(), "chats": self.chats.result()}


def _ranking(data, limit, *, participants=False, labels="aliases"):
    rows = data["rows"]
    aliases = {row["id"]: index for index, row in enumerate(sorted(rows, key=lambda row: row["id"]), 1)}
    ranked = sorted(rows, key=lambda row: (-row["total"], row["id"]))
    visible, remaining = ranked[:limit], ranked[limit:]
    output = []
    for row in visible:
        item = {key: row[key] for key in ("total", "first_seq", "last_seq")}
        if participants:
            item["count"] = row["total"]
            if labels == "ids":
                item.update(id=row["id"], label="Sender {id}", label_values={"id": str(row["id"])})
            else:
                item.update(label="Participant {n}", label_values={"n": f'{aliases[row["id"]]:02d}'})
        else:
            item.update(id=row["id"], label="Chat {id}", label_values={"id": str(row["id"])}, counts=dict(row["counts"]))
        output.append(item)
    if remaining:
        other = _row()
        for row in remaining:
            _merge(other, row)
        other.update(label="Other", label_values={}, groups=len(remaining))
        if participants:
            other.pop("counts")
            other["count"] = other["total"]
        output.append(other)
    if data["unknown_count"]:
        unknown = _copy(data["unknown"])
        unknown.update(label="Unknown", label_values={})
        if participants:
            unknown.pop("counts")
            unknown["count"] = unknown["total"]
        output.append(unknown)
    return {"status": data["status"], "total": data["total"], "counted_events": data["counted_events"],
            "unknown_count": data["unknown_count"], "other_groups": len(remaining),
            "rows": output if data["status"] == "available" else []}


def selected(data, options):
    options = options or {}
    value = options.get("chart_limit", 10)
    limit = max(5, min(30, value)) if type(value) is int else 10
    labels = "ids" if options.get("participant_labels") == "ids" else "aliases"
    output = {key: data[key] for key in ("format", "basis", "timezone", "activity_events", "message_observations",
                                       "first_observed_at", "last_observed_at", "invalid_time_events")}
    output.update(totals=dict(data["totals"]), sequence=dict(data["sequence"]))
    if options.get("activity_chart", True):
        chart = data["activity"]
        output["activity"] = {**chart, "rows": [_copy(row) for row in chart["rows"]]}
    if options.get("hourly_chart", True):
        chart = data["hourly"]
        output["hourly"] = {**chart, "rows": [list(row) for row in chart["rows"]]}
    if options.get("participant_chart", True):
        output["participants"] = _ranking(data["participants"], limit, participants=True, labels=labels)
    if options.get("composition_chart", True):
        output["composition"] = dict(data["totals"])
    if options.get("chat_chart", True):
        output["chats"] = _ranking(data["chats"], limit)
    return output
