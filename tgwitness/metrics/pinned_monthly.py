from . import Processor, moment, register


@register("pinned_per_month", version=1, title="Pins and unpins per month",
          parameter="metric_pinned",
          methodology="Pin service messages, unpin notices and pinned messages added or removed between "
                      "chat-state snapshots.")
class PinnedMonthly(Processor):
    columns = ("Month (UTC)", "Pinned (service messages)", "Unpinned (notices)", "Added in snapshots",
               "Removed in snapshots")

    def __init__(self):
        self.months, self.pins = {}, set()

    def row(self, event):
        when = moment(event)
        return self.months.setdefault(when.strftime("%Y-%m"), [0, 0, 0, 0]) if when else None

    def add(self, event):
        kind = event.get("kind")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if kind in ("message.new", "message.recovered", "message.snapshot") and \
                payload.get("service_action") == "MessageActionPinMessage":
            key = (event.get("chat_id"), event.get("message_id"))
            if key not in self.pins and (row := self.row(event)) is not None:
                self.pins.add(key)
                row[0] += 1
        elif kind == "message.unpinned" and (row := self.row(event)) is not None:
            raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
            row[1] += len(raw.get("messages") or []) or 1
        elif kind == "chat.state":
            change = (payload.get("changes") or {}).get("pinned")
            if isinstance(change, dict) and (row := self.row(event)) is not None:
                row[2] += len(change.get("added") or [])
                row[3] += len(change.get("removed") or [])

    def result(self, rows_listed):
        rows = [[month, *values] for month, values in sorted(self.months.items())]
        return {"rows": rows[-rows_listed:], "rows_total": len(rows), "flags": [], "flags_total": 0,
                "summary": {"pinned": sum(r[1] for r in rows), "unpinned": sum(r[2] for r in rows),
                            "added_in_snapshots": sum(r[3] for r in rows), "removed_in_snapshots": sum(r[4] for r in rows)}}
