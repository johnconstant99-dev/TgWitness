import csv
import html
import io

from . import action_protocol
from .evidence import safe_cell

PREFIX = "EX-"
STYLE = ("body{font:11pt/1.5 'Segoe UI',system-ui,Arial,sans-serif;color:#141a22;max-width:900px;margin:28px auto;padding:0 20px}"
         "h1{font-size:19pt;margin:0 0 4px}h2{font-size:12.5pt;margin:22px 0 6px;padding-bottom:3px;border-bottom:1px solid #d5dbe3}"
         ".lead{color:#4a5565}.note{border-left:4px solid #c27c0e;background:#fdf6ea;padding:8px 12px;margin:10px 0}"
         "table{width:100%;border-collapse:collapse;font-size:9.5pt}th,td{border:1px solid #d5dbe3;padding:4px 6px;text-align:left;"
         "vertical-align:top}th{background:#f2f5f8}.mono{font-family:Consolas,'Cascadia Mono',monospace;font-size:9pt;"
         "overflow-wrap:anywhere}dl{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;margin:0}dt{color:#4a5565}dd{margin:0}"
         ".blank{display:inline-block;min-width:320px;border-bottom:1px solid #141a22;height:1.3em}.sign p{margin:12px 0}"
         "ol li,ul li{margin:3px 0}@page{size:A4;margin:16mm}@media print{body{margin:0;max-width:none}}")
CSP = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; "
       "base-uri 'none'; form-action 'none'\">")


def e(value):
    return html.escape(str(value), quote=True)


def page(title, body, language="en"):
    return ('<!doctype html><html lang="' + e(language) + '"><meta charset="utf-8">' + CSP + "<title>" + e(title)
            + "</title><style>" + STYLE + "</style><body>" + body + "</body></html>")


def steps(model):
    return [block for block in model["blocks"] if block["type"] == "step"]


def exhibits(model, payload, prefix=PREFIX):
    names = {path.split("/", 1)[1].split(".", 1)[0]: path for path in payload if path.startswith("files/")}
    found, order = {}, []
    for number, block in enumerate(steps(model), 1):
        step = block["step"]
        if step.get("hidden"):
            continue
        for item in step.get("files") or []:
            sha256 = item.get("sha256")
            if sha256 not in names:
                continue
            if sha256 not in found:
                order.append(sha256)
                found[sha256] = {"sha256": sha256, "file": names[sha256], "size": len(payload[names[sha256]]),
                                 "media_type": item.get("mime_type") or "", "role": item.get("role") or "", "steps": [],
                                 "records": [], "chat_id": block.get("chat_id")}
            found[sha256]["steps"].append(number)
            if (step.get("ref") or {}).get("seq"):
                found[sha256]["records"].append(step["ref"]["seq"])
    width = max(3, len(str(len(order))))
    return [{"exhibit": prefix + str(index).zfill(width), **found[sha256]} for index, sha256 in enumerate(order, 1)]


def exhibits_csv(items):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["exhibit", "file", "sha256", "size", "media_type", "role", "steps", "journal_records", "chat_id"])
    for item in items:
        writer.writerow([safe_cell(c) for c in (item["exhibit"], "data/" + item["file"], item["sha256"], item["size"],
                         item["media_type"], item["role"], " ".join(map(str, item["steps"])),
                         " ".join(map(str, item["records"])), item["chat_id"])])
    return out.getvalue().encode("utf-8")


def exhibits_html(items, title, say):
    rows = "".join("<tr><td><b>" + e(item["exhibit"]) + '</b></td><td class="mono">data/' + e(item["file"]) + '</td><td class="mono">'
                   + e(item["sha256"]) + "</td><td>" + e(item["size"]) + "</td><td>" + e(item["media_type"] or "—") + "</td><td>"
                   + e(", ".join(map(str, item["steps"]))) + "</td><td>" + e(", ".join("#" + str(r) for r in item["records"]))
                   + "</td></tr>" for item in items)
    return page(say("Exhibit index"), "<h1>" + e(say("Exhibit index")) + '</h1><p class="lead">' + e(title) + "</p><p>"
                + e(say("Every file in this package that a documented step cites, with its exhibit number. Step numbers follow "
                        "the full report; journal records identify the signed observation behind each file.")) + "</p>"
                + ("<table><tr><th>" + "</th><th>".join(e(say(h)) for h in ("Exhibit", "File", "SHA-256", "Bytes", "Type",
                                                                              "Steps", "Journal records"))
                   + "</th></tr>" + rows + "</table>" if items else "<p>" + e(say("This record cites no files.")) + "</p>"),
                getattr(say, "language", "en"))


def message_link(chat_id, message_id, usernames, kind):
    if not message_id or chat_id is None:
        return None
    if usernames and kind in ("channel", "group"):
        return "https://t.me/" + usernames[0] + "/" + str(message_id)
    text = str(abs(chat_id))
    if chat_id < 0 and text.startswith("100"):
        return "https://t.me/c/" + text[3:] + "/" + str(message_id)
    return None


def subjects(model):
    cards, chats, people, hidden_subjects = {}, {}, {}, set()
    for block in steps(model):
        step, chat = block["step"], block.get("chat_id")
        if step["type"] == "subject" and chat is not None:
            if step.get("hidden"):
                hidden_subjects.add(chat)
            else:
                cards[chat] = step
    for episode in model["episodes"]:
        chat = episode["chat_id"]
        if chat is None:
            continue
        card = cards.get(chat, {})
        label = {} if chat in hidden_subjects else episode
        chats[chat] = {"chat_id": chat, "title": card.get("title") or label.get("title"),
                       "kind": card.get("kind") or label.get("kind"), "usernames": card.get("usernames") or [],
                       "labels": card.get("flags") or [], "user_id": card.get("user_id"), "messages": []}
    for block in steps(model):
        step, chat = block["step"], block.get("chat_id")
        if chat not in chats or step.get("hidden") or step["type"] not in ("sent", "sent_elsewhere", "reply", "edited"):
            continue
        entry = chats[chat]
        link = message_link(chat, step.get("message_id"), entry["usernames"], entry["kind"])
        entry["messages"].append({"message_id": step.get("message_id"), "at": step.get("at"),
                                  "telegram_time": step.get("telegram_time"), "direction": "outgoing" if step["type"].startswith("sent")
                                  else "incoming", "journal_record": (step.get("ref") or {}).get("seq"), "link": link})
        sender = step.get("sender") or {}
        if sender.get("id") and step["type"] in ("reply", "edited"):
            person = people.setdefault(sender["id"], {"user_id": sender["id"], "usernames": [], "names": [], "chats": [],
                                                       "first_seen": step.get("at"), "last_seen": step.get("at"), "messages": 0})
            for key, value in (("usernames", sender.get("username")), ("names", sender.get("display_name")), ("chats", chat)):
                if value and value not in person[key]:
                    person[key].append(value)
            person["last_seen"] = step.get("at") or person["last_seen"]
            person["messages"] += 1
    for chat, card in cards.items():
        if card.get("user_id") and card["user_id"] not in people:
            people[card["user_id"]] = {"user_id": card["user_id"], "usernames": card.get("usernames") or [],
                                       "names": [card.get("title")] if card.get("title") else [], "chats": [chat],
                                       "first_seen": card.get("at"), "last_seen": card.get("at"), "messages": 0}
        if card.get("user_id") in people:
            people[card["user_id"]]["labels"] = card.get("flags") or []
    return {"chats": list(chats.values()), "people": list(people.values())}


REQUEST_NOTES = (
    "Check the procedure that applies to the case.",
    "Telegram states that, on a valid order from a judicial authority, it may disclose the IP address and phone number "
    "of an account suspected in a criminal case, and does not disclose message content. Requests key on the numeric ID.",
    "Usernames can be changed and reused; the numeric ID stays with the account. Cite IDs with the times the usernames "
    "were observed.",
    "Data categories commonly asked of a provider: subscriber data, access logs (IP address and port with time), traffic "
    "data, content. Preservation can be requested before production.",
    "In channels and supergroups where this account is an administrator, Telegram keeps deleted messages and earlier "
    "versions of edits in the admin log for about 48 hours.",
)


def annex(model):
    found = subjects(model)
    return {"format": "tgwitness-request-annex-v1", "chats": found["chats"], "people": found["people"],
            "notes": list(REQUEST_NOTES)}


def annex_csv(data):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["subject", "telegram_id", "kind", "usernames", "names", "labels", "first_seen", "last_seen", "messages",
                     "message_references"])
    for chat in data["chats"]:
        writer.writerow([safe_cell(c) for c in ("chat", chat["chat_id"], chat["kind"] or "",
                         " ".join("@" + u for u in chat["usernames"]), chat["title"] or "", " ".join(chat["labels"]), "", "",
                         len(chat["messages"]),
                         " ".join(m["link"] or "%s:%s" % (chat["chat_id"], m["message_id"]) for m in chat["messages"]))])
    for person in data["people"]:
        writer.writerow([safe_cell(c) for c in ("person", person["user_id"], "user",
                         " ".join("@" + u for u in person["usernames"]), "; ".join(person["names"]),
                         " ".join(person.get("labels") or []), person["first_seen"] or "",
                         person["last_seen"] or "", person["messages"], "")])
    return out.getvalue().encode("utf-8")


def annex_html(data, title, say):
    chats = "".join(
        "<tr><td>" + e(chat["title"] or "—") + '</td><td class="mono">' + e(chat["chat_id"]) + "</td><td>" + e(say(chat["kind"] or "chat"))
        + "</td><td>" + e(" ".join("@" + u for u in chat["usernames"]) or "—") + "</td><td>" + e(" ".join(chat["labels"]).upper() or "—")
        + "</td><td>" + e(len(chat["messages"])) + "</td></tr>" for chat in data["chats"])
    people = "".join(
        '<tr><td class="mono">' + e(person["user_id"]) + "</td><td>" + e("; ".join(person["names"]) or "—") + "</td><td>"
        + e(" ".join("@" + u for u in person["usernames"]) or "—") + "</td><td>" + e(person["first_seen"] or "—") + "</td><td>"
        + e(person["last_seen"] or "—") + "</td><td>" + e(" ".join(person.get("labels") or []).upper() or "—") + "</td></tr>"
        for person in data["people"])
    refs = "".join(
        "<h3>" + e(chat["title"] or chat["chat_id"]) + '</h3><table><tr><th>' + e(say("Message")) + "</th><th>" + e(say("Direction"))
        + "</th><th>" + e(say("Telegram time")) + "</th><th>" + e(say("Journal record")) + "</th><th>" + e(say("Reference"))
        + "</th></tr>" + "".join("<tr><td>#" + e(m["message_id"]) + "</td><td>" + e(say(m["direction"])) + "</td><td>"
                                 + e(m["telegram_time"] or m["at"] or "—") + "</td><td>#" + e(m["journal_record"]) + '</td><td class="mono">'
                                 + e(m["link"] or "%s:%s" % (chat["chat_id"], m["message_id"])) + "</td></tr>" for m in chat["messages"])
        + "</table>" for chat in data["chats"] if chat["messages"])
    return page(say("Annex for official requests"), "<h1>" + e(say("Annex for official requests")) + '</h1><p class="lead">'
                + e(title) + "</p>" + "".join('<div class="note">' + e(say(note)) + "</div>" for note in data["notes"][:2])
                + "<h2>" + e(say("Chats and accounts")) + "</h2><table><tr><th>" + "</th><th>".join(
                    e(say(h)) for h in ("Name", "Telegram ID", "Kind", "Usernames", "Telegram labels", "Messages cited"))
                + "</th></tr>" + chats + "</table><h2>" + e(say("People who wrote in the documented chats")) + "</h2>"
                + ("<table><tr><th>" + "</th><th>".join(e(say(h)) for h in ("Telegram ID", "Names", "Usernames", "First seen",
                                                                              "Last seen", "Telegram labels"))
                   + "</th></tr>" + people + "</table>" if people else "<p>" + e(say("None recorded.")) + "</p>")
                + "<h2>" + e(say("Message references")) + "</h2>" + (refs or "<p>" + e(say("None recorded.")) + "</p>")
                + "<h2>" + e(say("Notes")) + "</h2><ul>" + "".join("<li>" + e(say(note)) + "</li>" for note in data["notes"][2:])
                + "</ul>", getattr(say, "language", "en"))


PROCESS = (
    "TgWitness recorded what this Telegram account received and did through the Telegram API, in the order it happened, "
    "in an append-only journal. Each record contains the SHA-256 of the previous record and is signed with the workspace "
    "Ed25519 key, so a removed, inserted or changed record breaks the chain.",
    "The investigator documented the session in TgWitness. When the document was fixed, its statement was hashed, signed "
    "with the same key and recorded in the journal; the document cites the journal record behind every step.",
    "Files such as screenshots and photos are stored under their SHA-256 and cited by the steps; the hash of each file in "
    "this package is listed below and in manifest-sha256.txt.",
    "Content hidden for a stated reason is not in this package; it is sealed with AES-256-GCM and opened only with keys "
    "handed over separately.",
)
NOTICE = ("Under the US Federal Rules of Evidence, a record certified under Rule 902(11), 902(13) or 902(14) may be "
          "offered only after reasonable written notice to the adverse party and after the record and certification are "
          "made available for inspection. A certification establishes authenticity only; it does not overcome hearsay or "
          "other objections. Adapt this template to the rules that apply before signing.")


def certification_html(session, model, fixed, fingerprint, hashes, say, stamped=()):
    known = action_protocol
    chats = [episode for episode in model["episodes"] if episode["chat_id"] is not None]
    times = [block["step"].get("at") for block in steps(model) if block["step"].get("at")]
    limits = list(model.get("limits") or []) + [limit for limit in known.LIMITS if limit not in (model.get("limits") or [])]
    hidden = sum(bool(block["step"].get("hidden")) for block in steps(model))
    ident = [(say("Document"), session["title"]), (say("Document ID"), session["id"]),
             (say("Revision"), session.get("revision") or 1), (say("Statement SHA-256"), fixed["statement_sha256"]),
             (say("Recorded in journal record"), "#" + str(fixed["event_seq"])), (say("Workspace signing key"), fingerprint),
             (say("Fixed at (UTC)"), fixed["at"]), (say("Observed period (UTC)"), (min(times) + " – " + max(times)) if times else "—"),
             (say("Timestamp receipts (for independent verification)"), ", ".join(stamped) if stamped else say("none in this package"))]
    rows = "".join('<tr><td class="mono">' + e(path) + '</td><td class="mono">' + e(digest) + "</td></tr>"
                   for path, digest in sorted(hashes.items()))
    body = ("<h1>" + e(say("Certification of authenticity of electronic records")) + '</h1><p class="lead">'
            + e(say("Template prepared by TgWitness for the declarant to review, complete and sign.")) + "</p>"
            '<div class="note">' + e(say(NOTICE)) + "</div><h2>1. " + e(say("Record identification")) + "</h2><dl>"
            + "".join("<dt>" + e(name) + '</dt><dd class="mono">' + e(value) + "</dd>" for name, value in ident) + "</dl>"
            "<h2>2. " + e(say("Accounts and chats")) + "</h2><p>" + e(say("Telegram account used for the observation:"))
            + ' <span class="blank"></span></p><ul>' + "".join(
                "<li>" + e(known.episode_title(episode, say)) + ' — <span class="mono">' + e(say("Telegram ID {id}", id=episode["chat_id"]))
                + "</span></li>" for episode in chats) + "</ul>"
            "<h2>3. " + e(say("Process that produced the records")) + "</h2><ol>"
            + "".join("<li>" + e(say(text)) + "</li>" for text in PROCESS) + "</ol>"
            "<h2>4. " + e(say("Time sources")) + "</h2><ul><li>" + e(say("Record times are the collector computer's clock in UTC "
                                                                       "when each record was saved."))
            + "</li><li>" + e(say("Telegram times are server dates sent by Telegram with each message, to the second."))
            + "</li><li>" + e(say("Included timestamp receipts are listed in section 1 and stored under data/timestamps/. "
                                  "Their signatures, timestamp chains and binding to this document have not been verified."))
            + "</li></ul><h2>5. " + e(say("Files and their SHA-256")) + "</h2><table><tr><th>" + e(say("File")) + "</th><th>SHA-256</th></tr>"
            + rows + "</table><h2>6. " + e(say("Scope of the records")) + "</h2><ul>"
            + "".join("<li>" + e(say(limit)) + "</li>" for limit in limits)
            + ("<li>" + e(say("{n} documented steps are hidden for a stated reason and sealed.", n=hidden)) + "</li>" if hidden else "")
            + '</ul><h2>7. ' + e(say("Declaration")) + '</h2><div class="sign"><p>' + e(say("I, the undersigned, declare that I am "
                                                                                          "familiar with the process described above, that the records "
                                                                                          "identified here were produced by that process in the course "
                                                                                          "of the investigation, and that the SHA-256 values listed match "
                                                                                          "the files produced."))
            + "</p>" + "".join("<p>" + e(say(label)) + ': <span class="blank"></span></p>' for label in (
                "Full name", "Title and organisation", "Qualifications", "Signature", "Date", "Place")) + "</div>")
    return page(say("Certification of authenticity of electronic records"), body, getattr(say, "language", "en"))
