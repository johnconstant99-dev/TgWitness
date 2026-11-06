from . import FIRST_KINDS, Processor, register

CHANNEL_IDS_BELOW = -1000000000000
SERVICE_KINDS = ("chat.service", "membership.service")


@register("service_vs_message_ratio", version=1, title="Service messages among message numbers",
          parameter="metric_service_ratio",
          methodology="Distinct saved message numbers per chat and the share taken by service messages.")
class ServiceRatio(Processor):
    columns = ("Chat", "Numbering", "Ordinary messages", "Service messages", "Service share")

    def __init__(self):
        self.numbers, self.service = {}, {}

    def add(self, event):
        chat, number, kind = event.get("chat_id"), event.get("message_id"), event.get("kind")
        if type(number) is not int or chat is None:
            return
        if kind in FIRST_KINDS:
            self.numbers.setdefault(chat, set()).add(number)
            payload = event.get("payload")
            if isinstance(payload, dict) and payload.get("service_action"):
                self.service.setdefault(chat, set()).add(number)
        elif kind in SERVICE_KINDS:
            self.service.setdefault(chat, set()).add(number)

    def result(self, rows_listed):
        rows, ordinary_total, service_total = [], 0, 0
        for chat in sorted(set(self.numbers) | set(self.service), key=str):
            service = len(self.service.get(chat, ()))
            ordinary = len(self.numbers.get(chat, set()) - self.service.get(chat, set()))
            ordinary_total, service_total = ordinary_total + ordinary, service_total + service
            numbering = "per chat" if isinstance(chat, int) and chat < CHANNEL_IDS_BELOW else "account-wide"
            rows.append([chat, numbering, ordinary, service, round(service / (ordinary + service), 4)
                         if ordinary + service else None])
        rows.sort(key=lambda row: -(row[2] + row[3]))
        total = ordinary_total + service_total
        return {"rows": rows[:rows_listed], "rows_total": len(rows), "flags": [], "flags_total": 0,
                "summary": {"ordinary": ordinary_total, "service": service_total,
                            "service_share": round(service_total / total, 4) if total else None}}
