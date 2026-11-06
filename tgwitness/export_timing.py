"""Monotonic timings for one start or resume, excluding previously saved messages."""
import time

from .store import utcnow


class ExportTiming:
    def __init__(self):
        self.started_at = utcnow()
        self.changed = time.monotonic()
        self.phase = "preparing"
        self.seconds = dict.fromkeys(("preparing", "running", "selecting", "packaging"), 0.0)
        self.baseline = None

    def move(self, phase):
        now = time.monotonic()
        if self.phase in self.seconds:
            self.seconds[self.phase] += now - self.changed
        self.phase, self.changed = phase, now

    def snapshot(self, captured):
        seconds = dict(self.seconds)
        if self.phase in seconds:
            seconds[self.phase] += time.monotonic() - self.changed
        messages = max(0, captured - self.baseline) if self.baseline is not None else 0
        rate = messages / seconds["running"] if seconds["running"] > 0 else None
        return {"scope": "current_run", "started_at": self.started_at,
                "elapsed_seconds": round(sum(seconds.values()), 3),
                "phase_seconds": {key: round(value, 3) for key, value in seconds.items()},
                "reused_messages": self.baseline, "new_messages": messages,
                "messages_per_second": round(rate, 3) if rate is not None else None}
