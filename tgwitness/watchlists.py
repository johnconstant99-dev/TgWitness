import csv
import io
import re
import secrets
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from .indicators import Indicators
from .store import utcnow

LISTS = "watchlists.lists"
CURSOR = "watchlists.cursor"
MAX_LISTS = 20
MAX_ENTRIES = 500
MAX_VALUE = 500
MAX_TEXT = 20000
MAX_PATTERN = 200
BATCH = 2000
EXCERPT = 200
KINDS = ("term", "regex", "wallet", "username", "telegram_id", "domain", "phone", "url")
TEXT_KINDS = ("message.new", "message.edited")
DERIVED_KINDS = ("media.qr_decoded", "media.analysed")
RISKY = re.compile(r"(\([^)]*[+*]\)[+*{])|(\[[^\]]*\][+*]\s*[+*])")
MEANING = ("A term the investigator put on a watchlist was found in a saved record. The match is in the text as it was "
           "saved.")


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal[KINDS] = "term"
    value: str = Field(min_length=1, max_length=MAX_VALUE)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def usable(self):
        self.value = self.value.strip()
        if not self.value:
            raise ValueError("Enter what to look for.")
        if self.kind == "regex":
            if len(self.value) > MAX_PATTERN:
                raise ValueError("Keep the pattern under %d characters." % MAX_PATTERN)
            if RISKY.search(self.value):
                raise ValueError("This pattern can hang on long messages. Simplify the nested repetitions.")
            try:
                re.compile(self.value, re.IGNORECASE)
            except re.error as exc:
                raise ValueError("This is not a valid pattern: " + str(exc)) from None
        if self.kind == "telegram_id" and not re.fullmatch(r"-?\d{1,20}", self.value):
            raise ValueError("A Telegram ID is a number.")
        if self.kind == "username":
            self.value = self.value.lstrip("@").lower()
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", self.value):
                raise ValueError("Enter a Telegram username, for example @name.")
        if self.kind in ("domain", "phone", "wallet", "url"):
            self.value = self.value.strip().rstrip("/")
        if self.kind == "domain":
            self.value = self.value.lower().removeprefix("www.")
        if self.kind == "phone":
            self.value = "+" + re.sub(r"\D", "", self.value)
            if not 8 <= len(self.value) <= 16:
                raise ValueError("Enter a phone number with 7 to 15 digits.")
        return self


class Listing(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=1000)
    enabled: StrictBool = True
    alert: StrictBool = True
    excerpts: StrictBool = False
    chat_ids: list[int] = Field(default_factory=list, max_length=500)

    @field_validator("chat_ids")
    @classmethod
    def unique(cls, value):
        return sorted(set(value))


class Import(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal[KINDS] = "term"
    text: str = Field(min_length=1, max_length=100000)


def available(store):
    goal = (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")
    if goal == "evidence":
        raise ValueError("Watchlists are off for the Evidence for a case goal.")


def lists(store):
    return store.get_setting(LISTS, None) or []


class OutOfScope(Exception):
    pass


def scoped(found, chats, change=True):
    if chats is not None:
        if not set(found["chat_ids"]) <= set(chats):
            raise KeyError(found["id"])
        if change and not found["chat_ids"]:
            raise OutOfScope()
    return found


def chosen(body, chats):
    if chats is not None and (not body.chat_ids or not set(body.chat_ids) <= set(chats)):
        raise OutOfScope()


def find(store, list_id, chats=None):
    found = next((item for item in lists(store) if item["id"] == list_id), None)
    if found is None:
        raise KeyError(list_id)
    return scoped(found, chats, change=False)


def visible(store, chats):
    return [item for item in lists(store)
            if chats is None or not item["chat_ids"] or set(item["chat_ids"]) <= set(chats)]


def add_list(store, body, actor, chats=None):
    available(store)
    chosen(body, chats)
    with store.transaction():
        current = lists(store)
        if len(current) >= MAX_LISTS:
            raise ValueError("Remove a list before adding another.")
        entry = {"id": secrets.token_hex(8), **body.model_dump(), "entries": [], "created_at": utcnow(),
                 "created_by": actor}
        store.set_setting(LISTS, current + [entry])
        store.append("watchlist.list_changed", {"list": entry, "actor": actor, "action": "added"})
    return entry


def update_list(store, list_id, body, actor, chats=None):
    available(store)
    with store.transaction():
        current = lists(store)
        found = next((item for item in current if item["id"] == list_id), None)
        if found is None:
            raise KeyError(list_id)
        scoped(found, chats)
        chosen(body, chats)
        before = {key: found[key] for key in body.model_dump()}
        found.update(body.model_dump())
        store.set_setting(LISTS, current)
        store.append("watchlist.list_changed", {"before": before, "list": found, "actor": actor, "action": "updated"})
    return found


def remove_list(store, list_id, actor, chats=None):
    with store.transaction():
        found = scoped(find(store, list_id), chats)
        store.set_setting(LISTS, [item for item in lists(store) if item["id"] != list_id])
        store.append("watchlist.list_changed", {"list": found, "actor": actor, "action": "removed"})
    return {"removed": list_id}


def add_entries(store, list_id, bodies, actor, chats=None):
    available(store)
    with store.transaction():
        current = lists(store)
        found = next((item for item in current if item["id"] == list_id), None)
        if found is None:
            raise KeyError(list_id)
        scoped(found, chats)
        known = {(entry["kind"], entry["value"]) for entry in found["entries"]}
        added = []
        for body in bodies:
            key = (body.kind, body.value)
            if key in known:
                continue
            if len(found["entries"]) + len(added) >= MAX_ENTRIES:
                raise ValueError("This list already has the maximum number of entries.")
            known.add(key)
            added.append({"id": secrets.token_hex(8), **body.model_dump(), "added_at": utcnow()})
        found["entries"].extend(added)
        store.set_setting(LISTS, current)
        if added:
            store.append("watchlist.entries_added", {"list_id": list_id, "name": found["name"],
                                                     "entries": added, "actor": actor})
    return {"added": added, "skipped": len(bodies) - len(added)}


def remove_entry(store, list_id, entry_id, actor, chats=None):
    with store.transaction():
        current = lists(store)
        found = next((item for item in current if item["id"] == list_id), None)
        if found is None:
            raise KeyError(list_id)
        scoped(found, chats)
        entry = next((item for item in found["entries"] if item["id"] == entry_id), None)
        if entry is None:
            raise KeyError(entry_id)
        found["entries"] = [item for item in found["entries"] if item["id"] != entry_id]
        store.set_setting(LISTS, current)
        store.append("watchlist.entries_removed", {"list_id": list_id, "name": found["name"],
                                                   "entries": [entry], "actor": actor})
    return {"removed": entry_id}


def parse_import(body):
    found, errors = [], []
    for number, line in enumerate(body.text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, rest = line.partition(":")
        if kind.strip().lower() in KINDS and rest.strip():
            kind, value = kind.strip().lower(), rest.strip()
        else:
            kind, value = body.kind, line
        try:
            found.append(Entry(kind=kind, value=value))
        except ValueError as exc:
            lines = [line.partition("Value error, ")[2] or line for line in str(exc).splitlines()
                     if "Value error," in line]
            errors.append({"line": number, "value": value[:120],
                           "error": (lines[0] if lines else str(exc).splitlines()[0])[:200]})
    return found, errors


def export_text(found):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["kind", "value", "note", "added_at"])
    for entry in found["entries"]:
        writer.writerow([entry["kind"], entry["value"], entry.get("note") or "", entry.get("added_at") or ""])
    return out.getvalue().encode("utf-8")


def texts_of(event):
    payload = event.get("payload") or {}
    found = []
    if isinstance(payload.get("text"), str):
        found.append(payload["text"])
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    from .message_details import details
    parsed = details(raw) if raw else {}
    for item in parsed.get("text_entities") or []:
        for key in ("href", "text"):
            if isinstance(item.get(key), str):
                found.append(item[key])
    for row in (parsed.get("buttons") or {}).get("rows") or []:
        for button in row:
            if isinstance(button, dict):
                for key in ("text", "url"):
                    if isinstance(button.get(key), str):
                        found.append(button[key])
    for item in payload.get("codes") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            found.append(item["text"])
    if isinstance(payload.get("text_recognized"), str):
        found.append(payload["text_recognized"])
    return [value[:MAX_TEXT] for value in found if value]


def word_match(value, text):
    pattern = r"(?<![\w@])" + re.escape(value) + r"(?![\w])"
    return re.search(pattern, text, re.IGNORECASE | re.UNICODE) is not None


def extracted(texts, at):
    reader = Indicators()
    for text in texts:
        reader.text(text, "text", {"seq": 0}, at)
    found = {}
    for item in reader.result()["items"]:
        found.setdefault(item["kind"], set()).add(item["value"])
        if item.get("normalized"):
            found[item["kind"]].add(item["normalized"])
    return found


def matches(entry, texts, found, event):
    kind, value = entry["kind"], entry["value"]
    joined = "\n".join(texts)
    if kind == "term":
        return value.lower() in joined.lower() and (word_match(value, joined) or " " in value)
    if kind == "regex":
        return bool(re.search(value, joined[:MAX_TEXT], re.IGNORECASE))
    if kind == "telegram_id":
        payload = event.get("payload") or {}
        sender = (payload.get("sender_observation") or {}).get("id") or payload.get("sender_id")
        return str(sender) == value or str(event.get("chat_id")) == value
    if kind == "username":
        return any(item.lower().lstrip("@") == value for item in found.get("telegram", set()))
    if kind == "wallet":
        return any(item == value or item.lower() == value.lower() for item in found.get("wallet", set()))
    if kind == "domain":
        return any(item.lower() == value or item.lower().endswith("." + value) for item in found.get("domain", set()))
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return any(re.sub(r"\D", "", item) == digits for item in found.get("phone", set()))
    return any(item.rstrip("/").lower() == value.lower() for item in found.get("url", set()))


def excerpt(texts, entry):
    joined = " ".join(texts)[:MAX_TEXT]
    if entry["kind"] in ("term", "regex"):
        found = re.search(entry["value"] if entry["kind"] == "regex" else re.escape(entry["value"]), joined, re.IGNORECASE)
        if found:
            start = max(0, found.start() - EXCERPT // 2)
            return ("…" if start else "") + joined[start:start + EXCERPT].strip() + ("…" if start + EXCERPT < len(joined) else "")
    return joined[:EXCERPT].strip() + ("…" if len(joined) > EXCERPT else "")


def scan(store, since=None, limit=BATCH, chats=None):
    available(store)
    active = [item for item in lists(store) if item["enabled"] and item["entries"]]
    head = (store.stats()["head"] or {}).get("seq", 0)
    start = store.get_setting(CURSOR, 0) if since is None else since
    if not active:
        if since is None and chats is None:
            store.set_setting(CURSOR, head)
        return {"scanned": 0, "hits": 0, "cursor": head}
    kinds = ",".join(TEXT_KINDS + DERIVED_KINDS)
    events = sorted(store.events(kind=kinds, after=start, limit=limit), key=lambda event: event["seq"])
    seen = store.watchlist_hits(events[0]["seq"], events[-1]["seq"]) if events else set()
    hits, cursor = 0, start
    for event in events:
        cursor = event["seq"]
        chat = event.get("chat_id")
        if chats is not None and chat not in chats:
            continue
        texts = texts_of(event)
        if not texts:
            continue
        found = extracted(texts, event.get("observed_at"))
        for item in active:
            if item["chat_ids"] and chat not in item["chat_ids"]:
                continue
            for entry in item["entries"]:
                if (entry["id"], event["seq"]) in seen or not matches(entry, texts, found, event):
                    continue
                seen.add((entry["id"], event["seq"]))
                payload = {"list_id": item["id"], "list": item["name"], "entry_id": entry["id"],
                           "kind": entry["kind"], "value": entry["value"], "record": event["seq"],
                           "record_kind": event["kind"], "meaning": MEANING}
                if item["excerpts"]:
                    payload["excerpt"] = excerpt(texts, entry)
                store.append("watchlist.hit", payload, chat, event.get("message_id"))
                hits += 1
    if since is None and chats is None:
        store.set_setting(CURSOR, max(cursor, start) if events else head)
    return {"scanned": len(events), "hits": hits, "cursor": max(cursor, start) if events else head}


def rescan(store, list_id=None, chats=None):
    since = None if chats is None else 0
    if chats is None:
        with store.transaction():
            store.set_setting(CURSOR, 0)
    total = {"scanned": 0, "hits": 0, "cursor": 0}
    while True:
        result = scan(store, since=since, limit=BATCH, chats=chats)
        total["scanned"] += result["scanned"]
        total["hits"] += result["hits"]
        total["cursor"] = result["cursor"]
        if since is not None:
            since = result["cursor"]
        if result["scanned"] < BATCH:
            return total


def hits(store, list_id=None, entry_id=None, chats=None, limit=500):
    found = []
    for event in store.events(kind="watchlist.hit", limit=limit * 2):
        payload = event.get("payload") or {}
        if list_id and payload.get("list_id") != list_id:
            continue
        if entry_id and payload.get("entry_id") != entry_id:
            continue
        if chats is not None and event.get("chat_id") not in chats:
            continue
        found.append({"hit_record": event["seq"], "at": event.get("observed_at"), "chat_id": event.get("chat_id"),
                      "message_id": event.get("message_id"), **{key: payload.get(key) for key in (
                          "list_id", "list", "entry_id", "kind", "value", "excerpt", "record", "record_kind")}})
        if len(found) >= limit:
            break
    return found


def statistics(store, chats=None):
    counts = {}
    for item in hits(store, chats=chats, limit=5000):
        entry = counts.setdefault(item["entry_id"], {"entry_id": item["entry_id"], "list_id": item["list_id"],
                                                     "value": item["value"], "kind": item["kind"], "count": 0,
                                                     "first_at": item["at"], "last_at": item["at"], "chats": []})
        entry["count"] += 1
        entry["first_at"] = min(entry["first_at"], item["at"] or entry["first_at"])
        entry["last_at"] = max(entry["last_at"], item["at"] or entry["last_at"])
        if item["chat_id"] is not None and item["chat_id"] not in entry["chats"]:
            entry["chats"].append(item["chat_id"])
    return sorted(counts.values(), key=lambda item: -item["count"])


def alert_lines(store, start, cursor, words, say, limit=20):
    from .alerts import alert_settings
    text = alert_settings(store)["include_text"]
    alerting = {item["id"] for item in lists(store) if item.get("alert", True)}
    found, before = [], cursor + 1
    while len(found) <= limit:
        events = store.events_of(["watchlist.hit"], limit=BATCH, after=start, before=before)
        for event in events:
            payload = event.get("payload") or {}
            if payload.get("list_id") not in alerting:
                continue
            line = say(words, "Watchlist {list}: {kind} {value}", list=payload.get("list", ""),
                       kind=payload.get("kind", ""), value=payload.get("value", ""))
            if text and payload.get("excerpt"):
                line += " — " + payload["excerpt"]
            found.append(line)
            if len(found) > limit:
                break
        if len(events) < BATCH:
            break
        before = events[-1]["seq"]
    return list(reversed(found))[:limit]


def owner_of(request):
    principal = request.state.principal
    return {"label": getattr(principal, "label", None) or ("Main administrator" if principal.admin else None),
            "owner": principal.owner}


def register(app, authenticate, require_live, visible_chats):
    import asyncio

    from fastapi import Depends, HTTPException, Request, Response

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except KeyError:
            raise HTTPException(404, "List or entry not found.") from None
        except OutOfScope:
            raise HTTPException(403, "This chat is not open to this access.") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/watchlists", dependencies=[Depends(authenticate)])
    async def overview(request: Request):
        chats = visible_chats(request)
        return {"lists": visible(app.state.store, chats), "kinds": list(KINDS),
                "statistics": await call(statistics, app.state.store, chats)}

    @app.post("/api/watchlists", dependencies=[Depends(authenticate)])
    async def list_add(request: Request, body: Listing):
        require_live()
        return await call(add_list, app.state.store, body, owner_of(request), visible_chats(request))

    @app.put("/api/watchlists/{list_id}", dependencies=[Depends(authenticate)])
    async def list_edit(request: Request, list_id: str, body: Listing):
        require_live()
        return await call(update_list, app.state.store, list_id, body, owner_of(request), visible_chats(request))

    @app.delete("/api/watchlists/{list_id}", dependencies=[Depends(authenticate)])
    async def list_remove(request: Request, list_id: str):
        require_live()
        return await call(remove_list, app.state.store, list_id, owner_of(request), visible_chats(request))

    @app.post("/api/watchlists/{list_id}/entries", dependencies=[Depends(authenticate)])
    async def entries_add(request: Request, list_id: str, body: Entry):
        require_live()
        return await call(add_entries, app.state.store, list_id, [body], owner_of(request), visible_chats(request))

    @app.post("/api/watchlists/{list_id}/import", dependencies=[Depends(authenticate)])
    async def entries_import(request: Request, list_id: str, body: Import):
        require_live()
        parsed, errors = parse_import(body)
        if not parsed:
            raise HTTPException(422, "No usable entries in the text." if not errors else errors[0]["error"])
        result = await call(add_entries, app.state.store, list_id, parsed, owner_of(request), visible_chats(request))
        return {**result, "errors": errors}

    @app.get("/api/watchlists/{list_id}/export", dependencies=[Depends(authenticate)])
    async def entries_export(request: Request, list_id: str):
        found = await call(find, app.state.store, list_id, visible_chats(request))
        return Response(export_text(found), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="watchlist-' + list_id + '.csv"'})

    @app.delete("/api/watchlists/{list_id}/entries/{entry_id}", dependencies=[Depends(authenticate)])
    async def entry_remove(request: Request, list_id: str, entry_id: str):
        require_live()
        return await call(remove_entry, app.state.store, list_id, entry_id, owner_of(request),
                          visible_chats(request))

    @app.get("/api/watchlists/hits", dependencies=[Depends(authenticate)])
    async def hit_list(request: Request, list_id: str | None = None, entry_id: str | None = None, limit: int = 500):
        if not 1 <= limit <= 2000:
            raise HTTPException(422, "Ask for between 1 and 2000 hits.")
        return {"hits": await call(hits, app.state.store, list_id, entry_id, visible_chats(request), limit)}

    @app.post("/api/watchlists/scan", dependencies=[Depends(authenticate)])
    async def scan_now(request: Request, full: bool = False):
        require_live()
        chats = visible_chats(request)
        if full:
            return await call(rescan, app.state.store, None, chats)
        return await call(scan, app.state.store, None, BATCH, chats)
