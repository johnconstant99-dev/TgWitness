def detached(value):
    if isinstance(value, dict):
        result = value.copy()
        for key, item in value.items():
            result[key] = detached(item)
        return result
    if isinstance(value, list):
        return [detached(item) for item in value]
    if isinstance(value, tuple):
        return tuple(detached(item) for item in value)
    if isinstance(value, set):
        return {detached(item) for item in value}
    return value


class Records:
    def __init__(self, values):
        self.values = values

    def __iter__(self):
        for value in self.values:
            yield detached(value)


def records(values):
    return Records(values) if values is not None else None


def factory(source):
    if source is None:
        return None

    def read():
        return records(source())

    return read


def context(values):
    result = detached(values or {})
    for name in ('events_again', 'source_events'):
        if callable(result.get(name)):
            result[name] = factory(result[name])
    return result
