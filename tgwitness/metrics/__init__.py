from datetime import datetime, timezone
from importlib import import_module

FORMAT = "tgwitness-metric-processors-v1"
MODULES = ("first_time_posters", "service_ratio", "membership_monthly", "pinned_monthly")
FIRST_KINDS = ("message.new", "message.snapshot", "message.recovered")
REGISTRY = {}


def register(name, *, version, title, methodology, parameter):
    def wrap(cls):
        if name in REGISTRY:
            raise ValueError("Duplicate metric processor: " + name)
        cls.name, cls.version, cls.title, cls.methodology, cls.parameter = name, version, title, methodology, parameter
        REGISTRY[name] = cls
        return cls
    return wrap


class Processor:
    columns = ()

    def add(self, event):
        raise NotImplementedError

    def result(self, rows_listed):
        raise NotImplementedError

    @classmethod
    def run(cls, events, rows_listed=60):
        processor = cls()
        for event in events:
            processor.add(event)
        return processor.result(rows_listed)


def load():
    for module in MODULES:
        import_module("." + module, __name__)
    return REGISTRY


def moment(event):
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    for value in (payload.get("sent_at"), event.get("source_at"), event.get("observed_at")):
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    return None


def enabled(values):
    return [name for name, cls in sorted(load().items()) if values.get(cls.parameter, True)]


def from_store(store):
    from ..tuning import values
    chosen = values(store)
    return enabled(chosen), chosen["metric_rows_listed"]


class Pipeline:
    def __init__(self, names=None, rows_listed=60):
        load()
        wanted = sorted(REGISTRY) if names is None else [name for name in sorted(REGISTRY) if name in names]
        self.processors, self.rows_listed = [REGISTRY[name]() for name in wanted], rows_listed

    def add(self, event):
        if isinstance(event, dict):
            for processor in self.processors:
                processor.add(event)

    def result(self):
        return {"format": FORMAT, "rows_listed": self.rows_listed,
                "processors": [{"name": p.name, "version": p.version, "title": p.title, "methodology": p.methodology,
                                "columns": list(p.columns), **p.result(self.rows_listed)} for p in self.processors]}


def run(events, names=None, rows_listed=60):
    pipeline = Pipeline(names, rows_listed)
    for event in events:
        pipeline.add(event)
    return pipeline.result()
