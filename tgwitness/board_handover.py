import copy
import json
import re
import sqlite3
import tempfile
from pathlib import Path

from . import board, board_report
from .store import canonical, utcnow
from .verify import board_scope, board_slice_summary


def prepare(snapshot, records_path, vault, options, minimiser):
    if options.case_board == "off" or not board.head(snapshot.connection)["seq"]:
        return None
    state = board.board_replay(board.records(snapshot.connection), vault.public_key)
    lookup = {item["id"]: item for item in state["items"]}
    chosen = set(options.chats)
    allowed = [item for item in state["items"] if (scope := board_scope(item, lookup)) is not None and scope <= chosen]
    selected_ids = {item["id"] for item in allowed}
    state = {**state, "items": copy.deepcopy(allowed), "status_history": []}
    for item in state["items"]:
        if item.get("collection_id") not in selected_ids:
            item["collection_id"] = None
    identities = {}
    for item in state["items"]:
        identities[item["created_access_id"]] = item["created_access_label"]
        identities[item["access_id"]] = item["access_label"]
    authors = {identifier: "R%02d" % (i+1) for i, identifier in enumerate(identities)}
    names = {label: authors[identifier] for identifier, label in identities.items()}

    def clean(text):
        text = minimiser.clean(text)
        if options.board_pseudonyms:
            for name, alias in sorted(names.items(), key=lambda item: -len(item[0])):
                if name:
                    text = re.sub(re.escape(name), lambda match: alias, text, flags=re.IGNORECASE)
        return text

    def author(item):
        if options.board_pseudonyms:
            item["created_access_label"] = authors[item["created_access_id"]]
            item["created_access_id"] = item["created_access_label"]
            item["access_label"] = authors[item["access_id"]]
            item["access_id"] = item["access_label"]
        for key in ("title", "note", "text", "reason"):
            if key in item:
                item[key] = clean(item[key]) if options.text != "none" else "[withheld]"
        if "labels" in item:
            item["labels"] = [clean(label) for label in item["labels"]] if options.text != "none" else []
        item.pop("mentions", None)
        item.pop("supersedes", None)
        return item

    with tempfile.TemporaryDirectory(prefix="board-disclosure-", dir=records_path.parent) as temporary:
        db = sqlite3.connect(str(Path(temporary) / "selected.sqlite3"))
        try:
            db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY, hash TEXT UNIQUE, observed_at TEXT, chat_id INTEGER, message_id INTEGER, kind TEXT, actor_id INTEGER, record TEXT, payload TEXT)")
            with records_path.open("rb") as incoming:
                for line in incoming:
                    event = json.loads(line)
                    original = snapshot.connection.execute("SELECT actor_id,payload,hash FROM events WHERE seq=?", (event["seq"],)).fetchone()
                    if original is None or original["hash"] != event["hash"]:
                        raise ValueError("Disclosure source differs from the board snapshot")
                    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", tuple(event.get(key) for key in
                        ("seq", "hash", "observed_at", "chat_id", "message_id", "kind")) + (original["actor_id"], line.decode(), original["payload"]))
            cards = []
            for item in state["items"]:
                if item["removed"] or item["kind"] not in {"board.bookmark", "board.highlight", "board.slice"}:
                    continue
                item = author(item)
                if item.get("target"):
                    row = db.execute("SELECT record FROM events WHERE hash=?", (item["target"]["event_hash"],)).fetchone()
                    if not row:
                        continue
                    item["observation"] = json.loads(row[0])
                    item["dangling"] = False
                    if item["kind"] == "board.highlight":
                        if item["observation"].get("minimised") or options.text == "none":
                            item["range"] = {"quote": "[highlight withheld in minimised disclosure]", "field": item["range"]["field"], "offsets_withheld": True}
                        else:
                            item["range"]["quote"] = clean(item["range"]["quote"])
                else:
                    item["current"] = board_slice_summary(db, item["query"])
                    if not item["current"]["record_count"]:
                        continue
                    baseline = board_slice_summary(db, item["query"], item["snapshot"]["journal_head"]["seq"])
                    item["diff"] = {"added": item["current"]["record_count"]-baseline["record_count"], "removed": 0}
                    item["snapshot"] = {"disclosed_records_at_bookmark": baseline["record_count"],
                                        "original_snapshot_withheld": True}
                    item["query"] = {key: value for key, value in item["query"].items() if key not in {"actors", "search"}}
                    item["disclosure"] = "Slice counts describe disclosed records only; original query actors, search and snapshot withheld."
                item["comments"] = []
                cards.append(item)
            by_id = {card["id"]: card for card in cards}
            if options.case_board == "comments":
                for item in state["items"]:
                    if item["kind"] != "board.comment" or item["removed"]:
                        continue
                    parent = lookup.get(item["parent_id"])
                    while parent and parent["kind"] == "board.comment":
                        parent = lookup.get(parent["parent_id"])
                    if parent and parent["id"] in by_id:
                        by_id[parent["id"]]["comments"].append(author(item))
            collection_ids = {item.get("collection_id") for item in cards}
            collections = [{"id": item["id"], "title": clean(item["title"]) if options.text != "none" else "[withheld]",
                            "description": clean(item.get("description", "")) if options.text != "none" else "", "order": item.get("order", 0)}
                           for item in state["items"] if item["kind"] == "board.collection" and item["id"] in collection_ids and not item["removed"]]
            material = {"meaning": board_report.MEANING, "annotations_head": state["annotations_head"],
                        "mode": options.case_board, "cards": cards, "collections": collections,
                        "disclosure": "Minimised copy of the team notes; review free-text names before sharing."}
        finally:
            db.close()
    statement = {"format": "tgwitness-case-board-handover-v1", "public_key": vault.public_key,
                 "created_at": utcnow(), "material": material}
    return {"statement": statement, "signature": vault.sign(canonical(statement))}
