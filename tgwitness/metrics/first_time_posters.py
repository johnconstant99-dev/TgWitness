from collections import Counter
from datetime import date, timedelta
from statistics import median

from . import FIRST_KINDS, Processor, moment, register

WARM_UP_DAYS = 7
BASELINE_DAYS = 14


@register("first_time_posters_over_time", version=1, title="First-time posters per day",
          parameter="metric_first_time_posters",
          methodology="Flagged: at least 5 first-time posters and 3x their 14-day median, with messages under 1.5x "
                      "their median. A chat's first 7 days are not flagged.")
class FirstTimePosters(Processor):
    columns = ("Day (UTC)", "First-time posters", "Messages")

    def __init__(self):
        self.first, self.messages, self.seen = {}, Counter(), set()

    def add(self, event):
        if event.get("kind") not in FIRST_KINDS:
            return
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        sender, chat, number = payload.get("sender_id"), event.get("chat_id"), event.get("message_id")
        when = moment(event)
        if type(sender) is not int or type(number) is not int or chat is None or when is None or payload.get("service_action"):
            return
        day = when.date().isoformat()
        key = (chat, sender)
        if key not in self.first or day < self.first[key]:
            self.first[key] = day
        if (chat, number) not in self.seen:
            self.seen.add((chat, number))
            self.messages[(chat, day)] += 1

    def result(self, rows_listed):
        newcomers = Counter((chat, day) for (chat, _sender), day in self.first.items())
        total_new, total_messages = Counter(), Counter()
        for (chat, day), count in newcomers.items():
            total_new[day] += count
        for (chat, day), count in self.messages.items():
            total_messages[day] += count
        days = sorted(set(total_new) | set(total_messages))
        rows = [[day, total_new[day], total_messages[day]] for day in days]
        flags = []
        for chat in sorted({chat for chat, _ in self.messages}, key=str):
            active = sorted(day for c, day in self.messages if c == chat)
            start = date.fromisoformat(active[0])
            for index, day in enumerate(active):
                current = date.fromisoformat(day)
                if (current - start).days < WARM_UP_DAYS:
                    continue
                cutoff = (current - timedelta(days=BASELINE_DAYS)).isoformat()
                window = [value for value in active[max(0, index - BASELINE_DAYS):index] if value >= cutoff]
                if len(window) < WARM_UP_DAYS:
                    continue
                base_new = median(newcomers[(chat, d)] for d in window)
                base_messages = median(self.messages[(chat, d)] for d in window)
                found, volume = newcomers[(chat, day)], self.messages[(chat, day)]
                if found >= max(5, 3 * base_new) and volume <= 1.5 * max(base_messages, 1):
                    flags.append({"chat_id": chat, "day": day, "first_time_posters": found, "baseline": base_new,
                                  "messages": volume, "baseline_messages": base_messages})
        return {"rows": rows[-rows_listed:], "rows_total": len(rows), "flags": flags[:50], "flags_total": len(flags),
                "summary": {"senders": len(self.first), "chats": len({chat for chat, _ in self.first})}}
