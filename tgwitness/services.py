import json
from functools import lru_cache


@lru_cache(maxsize=1)
def notifications():
    import apprise
    services = []
    for item in apprise.Apprise().details()["schemas"]:
        details = item.get("details") or {}
        services.append({
            "name": str(item["service_name"]),
            "protocols": sorted(set(item.get("protocols") or ()) | set(item.get("secure_protocols") or ())),
            "secure_protocols": sorted(item.get("secure_protocols") or ()),
            "documentation": item.get("setup_url"),
            "templates": list(details.get("templates") or ()),
            "tokens": details.get("tokens") or {},
        })
    return json.loads(json.dumps({"count": len(services), "services": sorted(services, key=lambda s: s["name"].lower())},
                                default=lambda value: sorted(value) if isinstance(value, (set, frozenset)) else str(value)))
