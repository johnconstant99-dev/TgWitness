"""A separately labelled, readable layer of team opinions, never observation facts."""
import copy
import html as escaping

from . import board

MEANING = "Team notes and bookmarks — opinions of the investigation team, not observations"


def material(connection, statement, options):
    mode = options.get("case_board", "bookmarks")
    if mode == "off" or not statement:
        return None
    state = statement["state"]
    items = {item["id"]: copy.deepcopy(item) for item in state["items"] if not item["removed"]}
    cards = [item for item in items.values() if item["kind"] in {"board.bookmark", "board.highlight", "board.slice"}]
    for item in cards:
        if item.get("target"):
            target = board.event_by_hash(connection, item["target"]["event_hash"])
            item["observation"] = target
            item["dangling"] = target is None
        else:
            item["current"] = board.board_slice_summary(connection, item["query"])
            item["diff"] = {"added": item["current"]["record_count"]-item["snapshot"]["record_count"], "removed": 0}
        item["comments"] = []
    lookup = {item["id"]: item for item in cards}
    if mode == "comments":
        for comment in items.values():
            if comment["kind"] != "board.comment":
                continue
            parent = items.get(comment["parent_id"])
            while parent and parent["kind"] == "board.comment":
                parent = items.get(parent["parent_id"])
            if parent and parent["id"] in lookup:
                lookup[parent["id"]]["comments"].append(comment)
    # Report data selection also limits the notes shown in the readable derivative.
    selection = options.get("selection") or {}
    if selection.get("enabled"):
        from .report_selection import Selection, compile_selection
        selected = compile_selection(Selection.model_validate(selection))
        cards = [item for item in cards if item.get("observation") and selected(item["observation"])]
    collection_ids = {item.get("collection_id") for item in cards}
    collections = [{"id": item["id"], "title": item["title"], "description": item.get("description", ""), "order": item.get("order", 0)}
                   for item in items.values() if item["kind"] == "board.collection" and item["id"] in collection_ids]
    return {"meaning": MEANING, "annotations_head": state["annotations_head"], "mode": mode,
            "collections": sorted(collections, key=lambda item: (item["order"], item["title"])), "cards": cards}


def groups(data):
    known = {item["id"] for item in data["collections"]}
    for collection in [{"id": None, "title": "Inbox", "description": ""}, *data["collections"]]:
        cards = [item for item in data["cards"] if (item.get("collection_id") if item.get("collection_id") in known else None) == collection["id"]]
        if cards:
            yield collection, cards


def html(data, say):
    if not data or not data["cards"]:
        return ""
    e = lambda value: escaping.escape(str(value if value is not None else ""))
    out = '<section id="case-board" class="section board-report"><div class="section-heading"><span class="eyebrow">CASE BOARD</span><h2>' + e(say("Case Board")) + '</h2></div><p class="lead">' + e(say(MEANING)) + '</p>'
    for collection, cards in groups(data):
        out += '<h3>' + e(collection["title"]) + '</h3><p>' + e(collection["description"]) + '</p>'
        for card in cards:
            out += '<article class="board-report-card"><div class="board-report-meta">' + e(card["access_label"]) + ' · ' + e(card["at"]) + ' · ' + e(card["state"]) + '</div><h4>' + e(card.get("title") or card["kind"]) + '</h4>'
            if target := card.get("target"):
                out += '<p><code>#' + e(target["seq"]) + '</code> · ' + e(target.get("chat_id")) + ' · ' + e(target["kind"]) + '</p><code class="board-report-hash">' + e(target["event_hash"]) + '</code>'
                quote = card.get("range", {}).get("quote") if card["kind"] == "board.highlight" else (card.get("observation") or {}).get("payload", {}).get("text")
                if quote:
                    out += '<blockquote class="board-report-quote">' + e(quote) + '</blockquote>'
                if card["kind"] == "board.highlight":
                    out += '<p class="lead">' + e(say("Highlight is tied to this saved version.")) + '</p>'
                if card.get("dangling"):
                    out += '<p class="callout">' + e(say("Dangling reference: the source observation is missing.")) + '</p>'
            else:
                out += '<p>' + e(say("Slice recomputed: +{added} / −{removed} records since bookmark.", **card["diff"])) + '</p><table><thead><tr><th>' + e(say("Kind")) + '</th><th>' + e(say("Records")) + '</th></tr></thead><tbody>'
                for kind, count in card["current"]["counts"].items():
                    out += '<tr><td>' + e(kind) + '</td><td>' + e(count) + '</td></tr>'
                out += '</tbody></table>'
                if card.get("disclosure"):
                    out += '<p>' + e(card["disclosure"]) + '</p>'
                else:
                    out += '<p><code>board/slices/' + e(card["id"]) + '.json</code></p>'
            if card.get("note"):
                out += '<p class="board-report-note">' + e(card["note"]) + '</p>'
            for comment in card["comments"]:
                out += '<div class="board-report-comment"><small>' + e(comment["access_label"]) + ' · ' + e(comment["at"]) + '</small><p>' + e(comment["text"]) + '</p></div>'
            out += '</article>'
    return out + '</section>'


def pdf(lay, data):
    if not data or not data["cards"]:
        return
    say = lay.say
    lay.section(say("Case Board"), say(MEANING))
    for collection, cards in groups(data):
        lay.heading(collection["title"])
        if collection["description"]:
            lay.text(collection["description"], size=9)
        for card in cards:
            lay.gap(5)
            lay.need(32)
            lay.text(card.get("title") or card["kind"], size=12, style="B")
            lay.gap(2)
            lay.text(card["access_label"] + " · " + card["at"] + " · " + card["state"], size=8)
            if target := card.get("target"):
                lay.text("#" + str(target["seq"]) + " · " + target["kind"] + " · " + str(target.get("chat_id")), size=9)
                quote = card.get("range", {}).get("quote") if card["kind"] == "board.highlight" else (card.get("observation") or {}).get("payload", {}).get("text")
                if quote:
                    lay.gap(2)
                    if len(quote) <= 800:
                        lay.need(45)
                        lay.callout(quote, color=(175,146,90))
                    else:
                        lay.text(quote, size=10)
                if card["kind"] == "board.highlight":
                    lay.text(say("Highlight is tied to this saved version."), size=8)
                if card.get("dangling"):
                    lay.callout(say("Dangling reference: the source observation is missing."))
            else:
                lay.text(say("Slice recomputed: +{added} / −{removed} records since bookmark.", **card["diff"]), size=9)
                lay.grid([say("Kind"), say("Records")], [[kind, str(count)] for kind, count in card["current"]["counts"].items()], (75, 25))
            if card.get("note"):
                lay.gap(2)
                lay.text(card["note"], size=9)
            for comment in card["comments"]:
                lay.gap(2)
                lay.text(comment["access_label"] + " · " + comment["at"], size=8)
                lay.text(comment["text"], size=9)
