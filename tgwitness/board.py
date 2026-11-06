import copy
import json
import uuid
from collections import Counter

from .access import Refused
from .board_models import MODELS
from .store import ZERO, canonical, utcnow
from .verify import (ANNOTATION_FIELDS, annotation_hash, board_prepare, board_replay, board_scope,
                     board_slice_summary, board_where, fingerprint)


def initialize(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS annotations(seq INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, record TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS annotations_immutable_update BEFORE UPDATE ON annotations
          BEGIN SELECT RAISE(ABORT, 'Annotations are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS annotations_immutable_delete BEFORE DELETE ON annotations
          BEGIN SELECT RAISE(ABORT, 'Annotations are append-only'); END;
        CREATE INDEX IF NOT EXISTS event_hash_lookup ON events(hash);
    """)


def records(connection):
    return (json.loads(row[0]) for row in connection.execute("SELECT record FROM annotations ORDER BY seq"))


def head(connection):
    row = connection.execute("SELECT seq,hash FROM annotations ORDER BY seq DESC LIMIT 1").fetchone()
    return {"seq": row[0], "hash": row[1]} if row else {"seq": 0, "hash": ZERO}


def journal_head(connection):
    row = connection.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return {"seq": row[0], "hash": row[1]} if row else {"seq": 0, "hash": ZERO}


def event_by_hash(connection, value):
    row = connection.execute("SELECT * FROM events WHERE hash=?", (value,)).fetchone()
    if row:
        value = dict(row)
        value["payload"] = json.loads(value["payload"])
        return value
    return None


def admin_record(target):
    return target is not None and target["kind"].startswith(("access.", "profile."))


def visible_target(target, principal):
    if principal.admin or not admin_record(target):
        return target
    return {**target, "payload": {}}


def require_scope(principal, workspace, scope):
    if not principal.opens(workspace) or not principal.may("view") or not principal.may("board.read"):
        raise Refused("This access does not open the Case Board.")
    allowed = principal.chats(workspace)
    if allowed is not None and (scope is None or not scope <= allowed):
        raise Refused("This card is not open to this access.")


def visible(state, principal, workspace):
    lookup = {item["id"]: item for item in state["items"]}
    shown = []
    for item in state["items"]:
        try:
            require_scope(principal, workspace, board_scope(item, lookup))
        except Refused:
            continue
        shown.append(copy.deepcopy(item))
    ids = {item["id"] for item in shown}
    for item in shown:
        if item.get("collection_id") not in ids:
            item["collection_id"] = None
        if item["kind"] == "board.collection":
            item["card_ids"] = [key for key in item.get("card_ids", []) if key in ids]
    return {"items": shown, "status_history": [entry for entry in state["status_history"] if entry["card_id"] in ids]}


def reaction_delta(previous, current):
    def values(event):
        raw = event["payload"].get("raw") or {}
        data = raw.get("reactions") or {}
        counts = {canonical(item.get("reaction")).decode(): item.get("count", 0)
                  for item in data.get("results", []) if isinstance(item, dict) and type(item.get("count")) is int}
        return counts, data.get("recent_reactions") or []
    counts, actors = values(current)
    old = values(previous)[0] if previous else {}
    changes = [{"reaction": json.loads(key), "delta": counts.get(key, 0) - old.get(key, 0)}
               for key in sorted(counts.keys() | old.keys()) if counts.get(key, 0) != old.get(key, 0)] if previous else []
    return {"basis": "snapshot comparison", "from": previous["observed_at"] if previous else None,
            "to": current["observed_at"], "previous_seq": previous["seq"] if previous else None,
            "count_changes": changes, "recent_actor_observations": actors,
            "complete_actor_list": False, "exact_change_time": None,
            "note": "Changes occurred between observations; recent actor lists may be incomplete."}


class Board:
    def __init__(self, store, workspace="default"):
        self.store, self.workspace = store, workspace

    def state(self, connection):
        board_prepare(connection)
        return board_replay(records(connection), self.store.signer.public_key)

    def read(self, connection, principal):
        require_scope(principal, self.workspace, set())
        return visible(self.state(connection), principal, self.workspace)

    def append(self, action, body, principal, authorize=None):
        if not principal.may("board.write"):
            raise Refused("This access cannot write to the Case Board.")
        model = MODELS[action].model_validate(body)
        payload = model.model_dump(by_alias=True, exclude_none=True)
        payload["id"] = payload.get("id") or uuid.uuid4().hex
        with self.store.transaction():
            if authorize:
                principal = authorize()
                if not principal.may("board.write"):
                    raise Refused("This access cannot write to the Case Board.")
            db = self.store.db
            state = self.state(db)
            lookup = {item["id"]: item for item in state["items"]}
            old = lookup.get(payload["id"])
            if old:
                require_scope(principal, self.workspace, board_scope(old, lookup))
                if old["created_access_id"] != principal.owner and not principal.may("board.manage"):
                    raise Refused("Only the author or a board manager can revise this card.")
                if old["kind"] != "board." + action or payload.get("supersedes") != old["annotation_hash"]:
                    raise ValueError("The card changed. Reload before saving a revision.")
            elif payload.get("supersedes"):
                raise ValueError("The previous annotation is missing.")
            if action in {"bookmark", "highlight"}:
                target = event_by_hash(db, model.target.event_hash)
                if target is None:
                    raise ValueError("The referenced observation was not found.")
                if admin_record(target) and not principal.admin:
                    raise Refused("Panel access and workspace records are open only to the main administrator.")
                require_scope(principal, self.workspace, {target["chat_id"]} if target["chat_id"] is not None else None)
                for key in ("seq", "chat_id", "message_id", "kind"):
                    hint = getattr(model.target, key)
                    if hint is not None and hint != target[key]:
                        raise ValueError("Target metadata does not match the referenced observation.")
                payload["target"] = {"event_hash": target["hash"], **{key: target[key] for key in ("seq", "chat_id", "message_id", "kind")}}
                if action == "highlight":
                    text, selection = target["payload"].get(model.range.field), model.range
                    if (not isinstance(text, str) or text[selection.start:selection.start+selection.length] != selection.quote
                            or len(selection.quote) != selection.length or selection.version not in (None, target["hash"])):
                        raise ValueError("The quote must match the exact saved version and Unicode code-point range.")
                    payload["range"]["version"] = target["hash"]
            if action == "slice":
                require_scope(principal, self.workspace, None if model.query.include_unscoped else set(model.query.chats()))
                payload["snapshot"] = {"computed_at": utcnow(), "journal_head": journal_head(db),
                                       **board_slice_summary(db, payload["query"])}
            if action == "collection":
                if not principal.may("board.manage"):
                    raise Refused("Managing collections requires board.manage.")
                scope = set(model.chat_ids) or None
                require_scope(principal, self.workspace, scope)
                for key in model.card_ids:
                    card = lookup.get(key)
                    if not card or card.get("removed"):
                        raise ValueError("A collection card is missing.")
                    card_scope = board_scope(card, lookup)
                    require_scope(principal, self.workspace, card_scope)
                    if scope is not None and (card_scope is None or not card_scope <= scope):
                        raise ValueError("Collection scope must include every card's chats.")
            if action in {"comment", "status", "move", "remove"}:
                parent = lookup.get(payload.get("parent_id") or payload.get("card_id"))
                if not parent or parent.get("removed"):
                    raise ValueError("The referenced card is missing.")
                require_scope(principal, self.workspace, board_scope(parent, lookup))
                if action in {"status", "move"} and parent["kind"] not in {"board.bookmark", "board.highlight", "board.slice"}:
                    raise ValueError("Choose a bookmark, highlight or slice.")
                if ((action == "status" and model.state in {"confirmed", "dismissed"}) or
                    (action == "remove" and (parent["created_access_id"] != principal.owner or parent["kind"] == "board.collection"))):
                    if not principal.may("board.manage"):
                        raise Refused("This action requires board.manage.")
                if action == "comment":
                    if old and old["parent_id"] != model.parent_id:
                        raise ValueError("A comment revision cannot change its parent.")
                if action == "move" and model.collection_id:
                    collection = lookup.get(model.collection_id)
                    if not collection or collection["kind"] != "board.collection" or collection.get("removed"):
                        raise ValueError("The collection is missing.")
                    scope = board_scope(collection, lookup)
                    require_scope(principal, self.workspace, scope)
                    child_scope = board_scope(parent, lookup)
                    if scope is not None and (child_scope is None or not child_scope <= scope):
                        raise ValueError("Collection scope must include every card's chats.")
                if action == "move":
                    payload["collection_id"] = model.collection_id
            item = {**payload, "kind": "board." + action}
            require_scope(principal, self.workspace, board_scope(item, lookup))
            if old and board_scope(item, lookup) != board_scope(old, lookup):
                raise ValueError("A revision cannot change a card's chat scope.")
            tail = state["annotations_head"]
            record = dict(seq=tail["seq"]+1, at=utcnow(), access_id=principal.owner,
                access_label="Main administrator" if principal.admin else principal.label,
                kind="board." + action, payload=payload, previous_hash=tail["hash"])
            assert tuple(record) == ANNOTATION_FIELDS
            record["hash"] = annotation_hash(record)
            record["signature"] = self.store.signer.sign(bytes.fromhex(record["hash"]))
            board_replay([*records(db), record])
            db.execute("INSERT INTO annotations VALUES(?,?,?)", (record["seq"], record["hash"], canonical(record).decode()))
            return record

    def detail(self, connection, principal, identifier):
        state = self.read(connection, principal)
        lookup = {item["id"]: item for item in state["items"]}
        card = lookup.get(identifier)
        if card is None:
            raise KeyError(identifier)
        target = event_by_hash(connection, card["target"]["event_hash"]) if card.get("target") else None
        target = visible_target(target, principal)
        thread_ids, thread = {identifier}, []
        for item in state["items"]:
            if item["kind"] == "board.comment" and item["parent_id"] in thread_ids:
                thread.append(item)
                thread_ids.add(item["id"])
        related = []
        if target:
            peer = target.get("actor_id") or target["payload"].get("sender_id")
            media = target["payload"].get("media_sha256")
            for item in state["items"]:
                if item["id"] == identifier or item.get("removed") or not item.get("target"):
                    continue
                other = event_by_hash(connection, item["target"]["event_hash"])
                if other and (other["hash"] == target["hash"] or
                    peer is not None and peer in (other.get("actor_id"), other["payload"].get("sender_id")) or
                    media and media == other["payload"].get("media_sha256")):
                    related.append(item["id"])
                    if len(related) == 30:
                        break
        return {"card": card, "target": target, "dangling": bool(card.get("target") and target is None),
                "thread": thread, "status_history": [item for item in state["status_history"] if item["card_id"] == identifier],
                "related": related, "fingerprint": fingerprint(self.store.signer.public_key)}

    def slice(self, connection, principal, identifier, offset=0, limit=5000):
        card = self.detail(connection, principal, identifier)["card"]
        if card["kind"] != "board.slice" or card["removed"]:
            raise KeyError(identifier)
        query, snapshot = card["query"], card["snapshot"]
        current = board_slice_summary(connection, query)
        where, args = board_where(query)
        result = []
        for row in connection.execute("SELECT * FROM events WHERE " + where + " ORDER BY seq LIMIT ? OFFSET ?", (*args, limit, offset)):
            event = dict(row)
            event["payload"] = json.loads(event["payload"])
            item = {"event": event, "added_since_bookmark": event["seq"] > snapshot["journal_head"]["seq"],
                    "unscoped": event["chat_id"] is None}
            if event["kind"] == "reaction.snapshot":
                row = connection.execute("SELECT * FROM events WHERE kind='reaction.snapshot' AND chat_id=? AND message_id=? AND seq<? ORDER BY seq DESC LIMIT 1",
                    (event["chat_id"], event["message_id"], event["seq"])).fetchone()
                previous = dict(row) if row else None
                if previous:
                    previous["payload"] = json.loads(previous["payload"])
                item["reaction_delta"] = reaction_delta(previous, event)
            result.append(item)
        return {"card": card, "current": current, "records": result, "offset": offset,
                "next_offset": offset+len(result) if offset+len(result) < current["record_count"] else None,
                "diff": {"added": current["record_count"] - snapshot["record_count"], "removed": 0}}

    def journal_window(self, connection, principal, identifier, before=None, after=None, limit=200, added=False):
        card = self.detail(connection, principal, identifier)["card"]
        if card["kind"] != "board.slice" or card["removed"]:
            raise KeyError(identifier)
        where, args = board_where(card["query"])
        if added:
            where += " AND seq>?"
            args.append(card["snapshot"]["journal_head"]["seq"])
        total = connection.execute("SELECT count(*) FROM events WHERE " + where, args).fetchone()[0]
        condition = where + (" AND seq<?" if before is not None else " AND seq>?" if after is not None else "")
        params = [*args, *([before] if before is not None else [after] if after is not None else [])]
        rows = list(connection.execute("SELECT * FROM events WHERE " + condition + " ORDER BY seq " +
                    ("ASC" if after is not None else "DESC") + " LIMIT ?", (*params, limit)))
        if after is not None:
            rows.reverse()
        events = []
        for row in rows:
            event = dict(row)
            event["payload"] = json.loads(event["payload"])
            events.append(event)
        older = newer = None
        if events:
            if connection.execute("SELECT 1 FROM events WHERE " + where + " AND seq<? LIMIT 1", (*args, events[-1]["seq"])).fetchone():
                older = events[-1]["seq"]
            if connection.execute("SELECT 1 FROM events WHERE " + where + " AND seq>? LIMIT 1", (*args, events[0]["seq"])).fetchone():
                newer = events[0]["seq"]
        return {"events": events, "next_before": older, "next_after": newer, "matched": total,
                "count_exact": True, "slice": {"id": identifier, "title": card["title"], "query": card["query"]}}


def export_state(connection, vault):
    state = board_replay(records(connection), vault.public_key)
    statement = {"format": "tgwitness-case-board-v1", "public_key": vault.public_key,
                 "created_at": utcnow(), "journal_head": journal_head(connection), "state": state,
                 "meaning": "Team notes and bookmarks — opinions of the investigation team, not observations"}
    return {"statement": statement, "signature": vault.sign(canonical(statement))}


def export_slices(connection, state):
    for item in state["items"]:
        if item["kind"] != "board.slice" or item["removed"]:
            continue
        query, snapshot = item["query"], item["snapshot"]
        where, args = board_where(query)
        yield item["id"], {"id": item["id"], "query": query, "snapshot": snapshot,
            "current": board_slice_summary(connection, query),
            "event_hashes": [row[0] for row in connection.execute("SELECT hash FROM events WHERE " + where + " ORDER BY hash", args)],
            "added_seq": [row[0] for row in connection.execute("SELECT seq FROM events WHERE " + where + " AND seq>? ORDER BY seq", (*args, snapshot["journal_head"]["seq"]))],
            "removed_seq": []}


def soft_limits(store, state):
    from . import tuning
    counts = Counter("comments" if item["kind"] == "board.comment" else "cards" for item in state["items"] if not item["removed"])
    return {key: {"count": counts[key], "limit": tuning.value(store, "board_max_" + key),
                  "exceeded": counts[key] > tuning.value(store, "board_max_" + key)} for key in ("cards", "comments")}


def notifications(store, after, principal, workspace):
    if not principal or not principal.may("board.read"):
        return [], after
    with store.snapshot() as snapshot:
        db = snapshot.connection
        if head(db)["seq"] <= after:
            return [], after
        state = Board(store, workspace).state(db)
        lookup = {item["id"]: item for item in state["items"]}
        result, cursor = [], after
        for row in db.execute("SELECT record FROM annotations WHERE seq>? ORDER BY seq LIMIT 100", (after,)):
            record = json.loads(row[0])
            cursor = record["seq"]
            item = {**record["payload"], "kind": record["kind"]}
            try:
                require_scope(principal, workspace, board_scope(item, lookup))
            except Refused:
                continue
            result.append({"seq": record["seq"], "kind": record["kind"], "id": item["id"],
                           "parent_id": item.get("parent_id") or item.get("card_id")})
        return result, cursor
