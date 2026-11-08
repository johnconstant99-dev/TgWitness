import re
import secrets
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import action_protocol
from .store import utcnow

PERSONAS = "undercover.personas"
AUTHORISATIONS = "undercover.authorisations"
MAX_ITEMS = 100
GAP_HOURS = 24
KINDS = ("undercover_operation", "chis", "directed_surveillance", "court_order", "prosecutor_approval", "other")
KIND_NAMES = {"undercover_operation": "Undercover operation approval", "chis": "CHIS authorisation",
              "directed_surveillance": "Directed surveillance authorisation", "court_order": "Court order",
              "prosecutor_approval": "Prosecutor approval", "other": "Other authority"}
DEFINITIONS = (
    "A conversation is outgoing activity in one chat; a pause of more than {hours} hours starts a new conversation. Under "
    "the US DOJ Online Investigative Principles each separate online conversation counts as one undercover contact.",
    "The first contact is the first message this account sent in the chat within the documented period.",
    "Operator is the panel access that requested the message. Messages sent from another Telegram app or session have no "
    "recorded operator.",
    "TgWitness records and flags; it does not decide whether an authorisation was required or sufficient.",
)


class Persona(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=120)
    telegram_id: int | None = None
    legend: str = Field(default="", max_length=4000)
    controlled_by: str = Field(default="", max_length=200)
    status: Literal["active", "retired"] = "active"


class Authorisation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1, max_length=200)
    kind: Literal[KINDS] = "undercover_operation"
    authority: str = Field(default="", max_length=200)
    chat_ids: list[int] = Field(default_factory=list, max_length=500)
    valid_from: datetime
    valid_to: datetime | None = None
    document_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    notes: str = Field(default="", max_length=2000)

    @field_validator("valid_from", "valid_to")
    @classmethod
    def aware(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Include a timezone in dates.")
        return value.astimezone(timezone.utc) if value else None

    @model_validator(mode="after")
    def ordered(self):
        if self.valid_to and self.valid_to <= self.valid_from:
            raise ValueError("The authorisation must end after it starts.")
        self.chat_ids = sorted(set(self.chat_ids))
        return self


def items(store, key):
    return store.get_setting(key, None) or []


def stored(body):
    data = body.model_dump()
    for name in ("valid_from", "valid_to"):
        if data.get(name):
            data[name] = data[name].isoformat()
    return data


def add(store, key, body, actor, kind):
    with store.transaction():
        current = items(store, key)
        if len(current) >= MAX_ITEMS:
            raise ValueError("Remove an old entry first.")
        entry = {"id": secrets.token_hex(8), **stored(body), "created_at": utcnow(), "created_by": actor}
        store.set_setting(key, current + [entry])
        store.append(kind, {"entry": entry, "actor": actor})
    return entry


def update(store, key, ident, body, actor, kind):
    with store.transaction():
        current = items(store, key)
        found = next((item for item in current if item["id"] == ident), None)
        if found is None:
            raise KeyError(ident)
        before = dict(found)
        found.update(stored(body), updated_at=utcnow(), updated_by=actor)
        store.set_setting(key, current)
        store.append(kind, {"before": before, "entry": found, "actor": actor})
    return found


def withdraw(store, ident, actor):
    with store.transaction():
        current = items(store, AUTHORISATIONS)
        found = next((item for item in current if item["id"] == ident), None)
        if found is None:
            raise KeyError(ident)
        found.update(withdrawn_at=utcnow(), withdrawn_by=actor)
        store.set_setting(AUTHORISATIONS, current)
        store.append("undercover.authorisation_withdrawn", {"entry": found, "actor": actor})
    return found


def snapshot(store):
    personas, authorisations = items(store, PERSONAS), items(store, AUTHORISATIONS)
    return {"personas": personas, "authorisations": authorisations} if personas or authorisations else None


def moment(value):
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def covering(authorisations, chat_id, at):
    when = moment(at)
    found = []
    for item in authorisations:
        start, end, withdrawn = moment(item.get("valid_from")), moment(item.get("valid_to")), moment(item.get("withdrawn_at"))
        if when is None or start is None or when < start or (end and when > end) or (withdrawn and when > withdrawn):
            continue
        if item.get("chat_ids") and chat_id not in item["chat_ids"]:
            continue
        found.append(item["reference"])
    return found


def record(model, gap_hours=GAP_HOURS):
    context = model.get("undercover") or {}
    authorisations = context.get("authorisations") or []
    titles = {episode["chat_id"]: action_protocol.episode_title(episode, action_protocol.plain_say)
              for episode in model["episodes"]}
    chats, account = {}, []
    for number, block in enumerate([b for b in model["blocks"] if b["type"] == "step"], 1):
        step, chat = block["step"], block.get("chat_id")
        if step["type"] == "account_change":
            account.append({"step": number, "at": step.get("at"), "change": step.get("change"),
                            "record": (step.get("ref") or {}).get("seq")})
            continue
        if step["type"] not in ("sent", "sent_elsewhere") or chat is None:
            continue
        entry = chats.setdefault(chat, {"chat_id": chat, "title": titles.get(chat), "messages": [], "conversations": 0,
                                        "flags": []})
        cover = covering(authorisations, chat, step.get("at"))
        operator = step.get("operator") or (None if step["type"] == "sent_elsewhere" else None)
        entry["messages"].append({"step": number, "at": step.get("at"), "message_id": step.get("message_id"),
                                  "record": (step.get("ref") or {}).get("seq"), "operator": operator,
                                  "from_panel": step["type"] == "sent", "ai_draft": step.get("ai_draft"),
                                  "authorisations": cover, "hidden": bool(step.get("hidden"))})
    for entry in chats.values():
        last = None
        for message in entry["messages"]:
            when = moment(message["at"])
            if last is None or (when and last and (when - last).total_seconds() > gap_hours * 3600):
                entry["conversations"] += 1
                message["new_conversation"] = True
            last = when or last
        first = entry["messages"][0]
        first["first_contact"] = True
        entry["first_contact"] = {"at": first["at"], "step": first["step"], "record": first["record"]}
        entry["ai_assisted"] = sum(bool(m["ai_draft"]) for m in entry["messages"])
        if authorisations and any(not m["authorisations"] for m in entry["messages"]):
            entry["flags"].append("outside_authorisation")
        if any(not m["operator"] for m in entry["messages"]):
            entry["flags"].append("operator_unknown")
    flags = sorted({flag for entry in chats.values() for flag in entry["flags"]})
    if not authorisations and chats:
        flags.append("no_authorisation_recorded")
    return {"format": "tgwitness-undercover-record-v1", "gap_hours": gap_hours,
            "personas": context.get("personas") or [], "authorisations": authorisations,
            "chats": list(chats.values()), "account_changes": account, "flags": flags,
            "conversations": sum(entry["conversations"] for entry in chats.values()),
            "definitions": [text.replace("{hours}", str(gap_hours)) for text in DEFINITIONS]}


FLAG_NAMES = {"outside_authorisation": "Messages outside the validity or scope of every recorded authorisation",
              "operator_unknown": "Messages without a recorded operator (for example sent from another app)",
              "no_authorisation_recorded": "No authorisation is recorded in the workspace"}


def render_html(data, title, say):
    from .court import e, page
    personas = "".join("<tr><td>" + e(p["label"]) + '</td><td class="mono">' + e(p.get("telegram_id") or "—") + "</td><td>"
                       + e(p.get("controlled_by") or "—") + "</td><td>" + e(say(p.get("status") or "active")) + "</td><td>"
                       + e(p.get("legend") or "—") + "</td></tr>" for p in data["personas"])
    authorisations = "".join(
        "<tr><td>" + e(a["reference"]) + "</td><td>" + e(say(KIND_NAMES.get(a.get("kind"), a.get("kind", "")))) + "</td><td>"
        + e(a.get("authority") or "—") + "</td><td>" + e(a.get("valid_from") or "—") + " – " + e(a.get("valid_to") or say("open"))
        + (" (" + e(say("withdrawn {at}", at=a["withdrawn_at"])) + ")" if a.get("withdrawn_at") else "") + "</td><td>"
        + e(", ".join(map(str, a.get("chat_ids") or [])) or say("all chats")) + '</td><td class="mono">'
        + e(a.get("document_sha256") or "—") + "</td></tr>" for a in data["authorisations"])
    chats = "".join(
        "<tr><td>" + e(c["title"] or c["chat_id"]) + '</td><td class="mono">' + e(c["chat_id"]) + "</td><td>"
        + e(c["first_contact"]["at"]) + " (" + e(say("step {n}", n=c["first_contact"]["step"])) + ")</td><td>"
        + e(c["conversations"]) + "</td><td>" + e(len(c["messages"])) + "</td><td>" + e(c["ai_assisted"]) + "</td><td>"
        + e(", ".join(say(FLAG_NAMES.get(f, f)) for f in c["flags"]) or "—") + "</td></tr>" for c in data["chats"])
    messages = "".join(
        "<h3>" + e(c["title"] or c["chat_id"]) + "</h3><table><tr><th>" + "</th><th>".join(
            e(say(h)) for h in ("Step", "Time", "Message", "Operator", "AI draft", "Authorisation", "Journal record"))
        + "</th></tr>" + "".join(
            "<tr><td>" + e(m["step"]) + ("<br><b>" + e(say("first contact")) + "</b>" if m.get("first_contact") else "")
            + ("<br>" + e(say("new conversation")) if m.get("new_conversation") and not m.get("first_contact") else "")
            + "</td><td>" + e(m["at"]) + "</td><td>#" + e(m["message_id"]) + "</td><td>"
            + e((m["operator"] or {}).get("label") if isinstance(m["operator"], dict) else m["operator"] or say("not recorded"))
            + "</td><td>" + e(say("record #{n}, {p}% similar", n=m["ai_draft"]["seq"], p=round(m["ai_draft"]["similarity"] * 100))
                              if m["ai_draft"] else "—") + "</td><td>" + e(", ".join(m["authorisations"]) or "—")
            + "</td><td>#" + e(m["record"]) + "</td></tr>" for m in c["messages"]) + "</table>" for c in data["chats"])
    flags = "".join("<li>" + e(say(FLAG_NAMES.get(f, f))) + "</li>" for f in data["flags"])
    body = ("<h1>" + e(say("Undercover activity record")) + '</h1><p class="lead">' + e(title) + "</p>"
            + ('<div class="note"><b>' + e(say("Flags")) + "</b><ul>" + flags + "</ul></div>" if flags else "")
            + "<h2>" + e(say("Personas")) + "</h2>" + ("<table><tr><th>" + "</th><th>".join(
                e(say(h)) for h in ("Label", "Telegram ID", "Controlled by", "Status", "Legend")) + "</th></tr>" + personas
                + "</table>" if personas else "<p>" + e(say("None recorded.")) + "</p>")
            + "<h2>" + e(say("Authorisations")) + "</h2>" + ("<table><tr><th>" + "</th><th>".join(
                e(say(h)) for h in ("Reference", "Type", "Authority", "Valid", "Chats", "Document SHA-256")) + "</th></tr>"
                + authorisations + "</table>" if authorisations else "<p>" + e(say("None recorded.")) + "</p>")
            + "<h2>" + e(say("Contacts by chat")) + "</h2>" + ("<table><tr><th>" + "</th><th>".join(
                e(say(h)) for h in ("Chat", "Telegram ID", "First contact", "Conversations", "Messages sent", "AI-assisted",
                                    "Flags")) + "</th></tr>" + chats + "</table>" if chats else "<p>" + e(say("No outgoing messages.")) + "</p>")
            + "<h2>" + e(say("Every outgoing message")) + "</h2>" + (messages or "<p>—</p>")
            + "<h2>" + e(say("Persona changes during the period")) + "</h2>" + ("<ul>" + "".join(
                "<li>" + e(a["at"]) + " — " + e(say(a["change"] or "")) + " (" + e(say("step {n}", n=a["step"])) + ")</li>"
                for a in data["account_changes"]) + "</ul>" if data["account_changes"] else "<p>" + e(say("None.")) + "</p>")
            + "<h2>" + e(say("Definitions")) + "</h2><ul>" + "".join("<li>" + e(say(d)) + "</li>" for d in data["definitions"])
            + "</ul>")
    return page(say("Undercover activity record"), body, getattr(say, "language", "en"))


def owner_of(request):
    principal = request.state.principal
    return {"label": getattr(principal, "label", None) or ("Main administrator" if principal.admin else None),
            "owner": principal.owner}


def register(app, authenticate, require_live):
    import asyncio

    from fastapi import Depends, HTTPException, Request

    async def call(function, *args):
        try:
            return await asyncio.to_thread(function, *args)
        except KeyError:
            raise HTTPException(404, "Entry not found.") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/undercover", dependencies=[Depends(authenticate)])
    async def overview():
        return {"personas": items(app.state.store, PERSONAS), "authorisations": items(app.state.store, AUTHORISATIONS),
                "kinds": KIND_NAMES}

    @app.post("/api/undercover/personas", dependencies=[Depends(authenticate)])
    async def persona_add(request: Request, body: Persona):
        require_live()
        return await call(add, app.state.store, PERSONAS, body, owner_of(request), "undercover.persona_updated")

    @app.put("/api/undercover/personas/{ident}", dependencies=[Depends(authenticate)])
    async def persona_edit(request: Request, ident: str, body: Persona):
        require_live()
        return await call(update, app.state.store, PERSONAS, ident, body, owner_of(request), "undercover.persona_updated")

    @app.post("/api/undercover/authorisations", dependencies=[Depends(authenticate)])
    async def authorisation_add(request: Request, body: Authorisation):
        require_live()
        return await call(add, app.state.store, AUTHORISATIONS, body, owner_of(request), "undercover.authorisation_added")

    @app.put("/api/undercover/authorisations/{ident}", dependencies=[Depends(authenticate)])
    async def authorisation_edit(request: Request, ident: str, body: Authorisation):
        require_live()
        return await call(update, app.state.store, AUTHORISATIONS, ident, body, owner_of(request),
                          "undercover.authorisation_updated")

    @app.post("/api/undercover/authorisations/{ident}/withdraw", dependencies=[Depends(authenticate)])
    async def authorisation_withdraw(request: Request, ident: str):
        require_live()
        if not re.fullmatch(r"[a-f0-9]{16}", ident):
            raise HTTPException(404, "Entry not found.")
        return await call(withdraw, app.state.store, ident, owner_of(request))
