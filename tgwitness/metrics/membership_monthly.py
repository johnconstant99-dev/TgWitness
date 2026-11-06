from ..people import membership
from . import Processor, moment, register

JOINED = {"joined"}
LEFT = {"left"}
REMOVED = {"removed", "banned"}


@register("join_leave_per_month", version=1, title="Joins and departures per month",
          parameter="metric_join_leave",
          methodology="Membership changes Telegram reported, once per person, chat, change and day.")
class JoinLeave(Processor):
    columns = ("Month (UTC)", "Joined", "Left", "Removed or banned", "Net")

    def __init__(self):
        self.changes = set()

    def add(self, event):
        if not str(event.get("kind", "")).startswith("membership."):
            return
        when = moment(event)
        if when is None or not isinstance(event.get("payload"), dict):
            return
        for uid, change in membership(event):
            state = change.get("state")
            group = "joined" if state in JOINED else "left" if state in LEFT else "removed" if state in REMOVED else None
            if group:
                self.changes.add((event.get("chat_id"), uid, group, when.date().isoformat()))

    def result(self, rows_listed):
        months = {}
        for _chat, _uid, group, day in self.changes:
            row = months.setdefault(day[:7], {"joined": 0, "left": 0, "removed": 0})
            row[group] += 1
        rows = [[month, r["joined"], r["left"], r["removed"], r["joined"] - r["left"] - r["removed"]]
                for month, r in sorted(months.items())]
        return {"rows": rows[-rows_listed:], "rows_total": len(rows), "flags": [], "flags_total": 0,
                "summary": {key: sum(r[key] for r in months.values()) for key in ("joined", "left", "removed")}}
