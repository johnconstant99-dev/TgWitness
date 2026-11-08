import hashlib
import json
import re
import secrets
import statistics
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from . import ai
from .store import utcnow

INDEX = "conversation.plans"
PREFIX = "conversation.plan."
MAX_PLANS = 200
MAX_GOALS = 40
MAX_STEPS = 200
SCAN = 3000
EXCHANGES = 60
TEMPLATES = {
    "payment": ("Payment route", (
        "Get the wallet address or payment details",
        "Learn the payment method, exchange or card they use",
        "Learn the amount asked and what it is for",
        "Get a payment confirmation, transaction ID or receipt")),
    "infrastructure": ("Infrastructure", (
        "Get the website, app or bot link",
        "Learn other channels, groups and bots they run",
        "Get support, manager or operator contacts",
        "Get the referral or invitation link")),
    "people": ("People behind it", (
        "Learn who else takes part: manager, support, recruiter",
        "Note language, region and time zone signals",
        "Learn when the other side usually replies",
        "Ask about other clients, reviews or earlier payouts")),
    "custom": ("Custom plan", ()),
}
KINDS = ("question", "answer", "emoji", "follow_up", "other")
STATUS = ("open", "obtained", "dropped")
EMOJI = re.compile("[\U0001F1E6-\U0001F1FF\U0001F300-\U0001FAFF☀-➿⭐⭕‼⁉〰〽]"
                   "[️\U0001F3FB-\U0001F3FF]?")
WORD = re.compile(r"[^\W\d_]{4,}", re.UNICODE)
SYSTEM = (
    "You help a fraud investigator keep a conversation going with a suspected scammer in order to document evidence "
    "such as wallets, links, contacts and the scheme itself. Write the next message for the investigator. "
    "Match the other side's language, register, slang, abbreviations, punctuation habits, emoji use and typical "
    "message length, and stay consistent with what the investigator has already written in this chat. "
    "Keep the investigator's cover: never mention an investigation, the police or evidence. Do not invent personal "
    "facts about the investigator beyond the chat, do not threaten, and do not promise or make real payments. "
    "Return only JSON: {\"style\": {\"language\": string, \"register\": string, \"slang\": [string], "
    "\"emoji\": [string], \"typical_length\": string, \"notes\": string}, \"drafts\": [{\"text\": string, "
    "\"why\": string}], \"caution\": string}. Each draft must be ready to send as is.")
REMINDER = ("Your previous answer could not be used. Reply with one JSON object exactly in the requested shape, "
            "with at least one draft, and nothing else.")
RETRY = {"The provider returned an unsupported response.",
         "The model did not return drafts. Try again or change the request."}


class Create(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chat_id: int
    title: str = Field(default="", max_length=160)
    template: Literal["payment", "infrastructure", "people", "custom"] = "custom"


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    offset_minutes: int = Field(default=0, ge=-720, le=840)


class Goal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=300)
    status: Literal["open", "obtained", "dropped"] = "open"
    note: str = Field(default="", max_length=1000)
    evidence: list[int] = Field(default_factory=list, max_length=50)

    @field_validator("text", "note")
    @classmethod
    def trimmed(cls, value):
        return value.strip()

    @field_validator("evidence")
    @classmethod
    def positive(cls, value):
        if any(seq < 1 for seq in value):
            raise ValueError("Evidence refers to journal record numbers.")
        return sorted(set(value))


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=4096)
    kind: Literal["question", "answer", "emoji", "follow_up", "other"] = "question"
    goal: str | None = Field(default=None, pattern=r"^[a-f0-9]{8}$")
    state: Literal["planned", "skipped"] = "planned"
    draft: int | None = Field(default=None, ge=1)
    message_id: int | None = Field(default=None, ge=1)
    request_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{16,80}$")

    @field_validator("text")
    @classmethod
    def filled(cls, value):
        if not value.strip():
            raise ValueError("Enter the message text.")
        return value.strip()


class Assist(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent: str = Field(min_length=1, max_length=1000)
    goal: str | None = Field(default=None, pattern=r"^[a-f0-9]{8}$")
    context: int = Field(default=60, ge=10, le=200)
    variants: int = Field(default=3, ge=1, le=5)


class Generate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    consent: StrictBool = False


def available(store):
    goal = (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")
    if goal == "evidence":
        raise ValueError("Conversation plans are off for the Evidence for a case goal.")


def chat_title(store, chat_id):
    return next((t["title"] for t in store.targets() if t["chat_id"] == chat_id), None) or str(chat_id)


def load(store, plan_id):
    plan = store.get_setting(PREFIX + plan_id, None) if re.fullmatch(r"[a-f0-9]{32}", plan_id or "") else None
    if not plan:
        raise KeyError(plan_id)
    return plan


def visible(plan, chats):
    if chats is not None and plan["chat_id"] not in chats:
        raise KeyError(plan["id"])
    return plan


def save(store, plan):
    plan["updated_at"] = utcnow()
    store.set_setting(PREFIX + plan["id"], plan)
    return plan


def summary(store, plan):
    goals = Counter(goal["status"] for goal in plan["goals"])
    return {"id": plan["id"], "title": plan["title"], "chat_id": plan["chat_id"],
            "chat_title": chat_title(store, plan["chat_id"]), "created_at": plan["created_at"],
            "updated_at": plan["updated_at"], "goals": len(plan["goals"]), "obtained": goals["obtained"],
            "steps": len(plan["steps"])}


def listing(store, chats=None):
    plans = [store.get_setting(PREFIX + plan_id, None) for plan_id in store.get_setting(INDEX, None) or []]
    return sorted((summary(store, plan) for plan in plans if plan and (chats is None or plan["chat_id"] in chats)),
                  key=lambda item: item["updated_at"], reverse=True)


def new_id(items):
    taken = {item["id"] for item in items}
    while True:
        ident = secrets.token_hex(4)
        if ident not in taken:
            return ident


def goal_entry(goals, body):
    return {"id": new_id(goals), "text": body.text, "status": body.status, "note": body.note,
            "evidence": body.evidence, "created_at": utcnow()}


def create(store, body, owner, chats=None):
    available(store)
    if chats is not None and body.chat_id not in chats:
        raise KeyError(body.chat_id)
    with store.transaction():
        index = store.get_setting(INDEX, None) or []
        if len(index) >= MAX_PLANS:
            raise ValueError("Delete an older plan before starting a new one.")
        name, texts = TEMPLATES[body.template]
        plan = {"id": secrets.token_hex(16), "chat_id": body.chat_id, "owner": owner, "template": body.template,
                "title": body.title.strip() or name + " · " + chat_title(store, body.chat_id),
                "offset_minutes": 0, "created_at": utcnow(), "revision": 1, "goals": [], "steps": []}
        for text in texts:
            plan["goals"].append(goal_entry(plan["goals"], Goal(text=text)))
        store.set_setting(INDEX, index + [plan["id"]])
        save(store, plan)
    return view(store, plan)


def change(store, plan_id, chats, revision, mutate):
    available(store)
    with store.transaction():
        plan = visible(load(store, plan_id), chats)
        if revision is not None and revision != plan.get("revision", 1):
            raise ValueError("Someone changed this plan in the meantime. Reload it to see the latest version.")
        mutate(plan)
        plan["revision"] = plan.get("revision", 1) + 1
        save(store, plan)
    return view(store, plan)


def edit(store, plan_id, body, chats=None, revision=None):
    return change(store, plan_id, chats, revision,
                  lambda plan: plan.update(title=body.title.strip(), offset_minutes=body.offset_minutes))


def delete(store, plan_id, chats=None, revision=None):
    with store.transaction():
        plan = visible(load(store, plan_id), chats)
        if revision is not None and revision != plan.get("revision", 1):
            raise ValueError("Someone changed this plan in the meantime. Reload it to see the latest version.")
        store.set_setting(INDEX, [ident for ident in store.get_setting(INDEX, None) or [] if ident != plan["id"]])
        store.set_setting(PREFIX + plan["id"], None)
    return {"deleted": plan["id"]}


def find(items, ident):
    item = next((item for item in items if item["id"] == ident), None)
    if item is None:
        raise KeyError(ident)
    return item


def add_goal(store, plan_id, body, chats=None, revision=None):
    def mutate(plan):
        if len(plan["goals"]) >= MAX_GOALS:
            raise ValueError("This plan already has the maximum number of goals.")
        plan["goals"].append(goal_entry(plan["goals"], body))
    return change(store, plan_id, chats, revision, mutate)


def update_goal(store, plan_id, goal_id, body, chats=None, revision=None):
    return change(store, plan_id, chats, revision, lambda plan: find(plan["goals"], goal_id).update(
        text=body.text, status=body.status, note=body.note, evidence=body.evidence))


def remove_goal(store, plan_id, goal_id, chats=None, revision=None):
    def mutate(plan):
        find(plan["goals"], goal_id)
        plan["goals"] = [goal for goal in plan["goals"] if goal["id"] != goal_id]
        for step in plan["steps"]:
            if step.get("goal") == goal_id:
                step["goal"] = None
    return change(store, plan_id, chats, revision, mutate)


def checked_step(plan, body):
    if body.goal is not None:
        find(plan["goals"], body.goal)
    return {"text": body.text, "kind": body.kind, "goal": body.goal, "state": body.state, "draft": body.draft,
            "message_id": body.message_id, "request_id": body.request_id}


def add_step(store, plan_id, body, chats=None, revision=None):
    def mutate(plan):
        if len(plan["steps"]) >= MAX_STEPS:
            raise ValueError("This plan already has the maximum number of steps.")
        plan["steps"].append({"id": new_id(plan["steps"]), **checked_step(plan, body), "created_at": utcnow()})
    return change(store, plan_id, chats, revision, mutate)


def update_step(store, plan_id, step_id, body, chats=None, revision=None):
    return change(store, plan_id, chats, revision,
                  lambda plan: find(plan["steps"], step_id).update(checked_step(plan, body)))


def remove_step(store, plan_id, step_id, chats=None, revision=None):
    def mutate(plan):
        find(plan["steps"], step_id)
        plan["steps"] = [step for step in plan["steps"] if step["id"] != step_id]
    return change(store, plan_id, chats, revision, mutate)


def move_step(store, plan_id, step_id, offset, chats=None, revision=None):
    def mutate(plan):
        index = plan["steps"].index(find(plan["steps"], step_id))
        target = max(0, min(len(plan["steps"]) - 1, index + offset))
        plan["steps"].insert(target, plan["steps"].pop(index))
    return change(store, plan_id, chats, revision, mutate)


def moment(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def same(text):
    return re.sub(r"\s+", " ", text or "").strip().casefold()


def messages(store, chat_id, limit=SCAN):
    found = []
    for event in store.events(chat_id=chat_id, kind="message.new", limit=limit):
        payload = event.get("payload") or {}
        at = moment(payload.get("sent_at") or event.get("observed_at"))
        if at is None:
            continue
        found.append({"seq": event["seq"], "message_id": event.get("message_id"), "outgoing": bool(payload.get("outgoing")),
                      "text": payload.get("text") or "", "at": at, "observed_at": event.get("observed_at")})
    return sorted(found, key=lambda item: (item["at"], item["seq"]))


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def reply_after(chat, index):
    for later in chat[index + 1:]:
        if not later["outgoing"]:
            return later
    return None


def short(text, size=160):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= size else text[:size - 1] + "…"


def receipt(store, request_id):
    from .interactions import requested
    pending = requested(store, request_id) if request_id else None
    return ((pending or {}).get("result") or {}).get("message_id")


def matched(store, plan, chat):
    claimed, result = set(), {}
    outgoing = [(index, message) for index, message in enumerate(chat) if message["outgoing"]]

    def take(step, index, message, basis):
        claimed.add(message["seq"])
        reply = reply_after(chat, index)
        result[step["id"]] = {
            "seq": message["seq"], "message_id": message["message_id"], "sent_at": iso(message["at"]), "basis": basis,
            "text": short(message["text"]) if basis == "similar" or basis == "linked" else None,
            "reply": reply and {"seq": reply["seq"], "message_id": reply["message_id"], "sent_at": iso(reply["at"]),
                                "text": short(reply["text"]),
                                "after_seconds": round((reply["at"] - message["at"]).total_seconds())}}

    def after(step, message):
        created = moment(step["created_at"])
        return created is None or message["at"] >= created - timedelta(seconds=5)

    waiting = [step for step in plan["steps"] if step["state"] != "skipped"]
    passes = (
        ("linked", lambda step: step.get("message_id"), lambda step, message, key: message["message_id"] == key),
        ("panel", lambda step: receipt(store, step.get("request_id")), lambda step, message, key: message["message_id"] == key),
        ("text", lambda step: same(step["text"]),
         lambda step, message, key: same(message["text"]) == key and after(step, message)),
        ("similar", lambda step: same(step["text"]),
         lambda step, message, key: len(key) >= 4 and after(step, message)
         and SequenceMatcher(None, same(message["text"]), key).ratio() >= 0.8))
    for basis, keyed, fits in passes:
        for step in waiting:
            key = step["id"] not in result and keyed(step)
            if not key:
                continue
            found = next(((index, message) for index, message in outgoing
                          if message["seq"] not in claimed and fits(step, message, key)), None)
            if found:
                take(step, *found, basis)
    unlinked = [{"seq": m["seq"], "message_id": m["message_id"], "sent_at": iso(m["at"]), "text": short(m["text"], 120)}
                for _, m in outgoing if m["seq"] not in claimed and m["message_id"]][-20:][::-1]
    return result, unlinked


def exchanges(chat):
    found = []
    for index, message in enumerate(chat):
        if message["outgoing"] and index + 1 < len(chat) and not chat[index + 1]["outgoing"]:
            reply = chat[index + 1]
            found.append({"ours": short(message["text"], 120), "ours_seq": message["seq"], "sent_at": iso(message["at"]),
                          "reply": short(reply["text"], 120), "reply_seq": reply["seq"], "replied_at": iso(reply["at"]),
                          "after_seconds": max(0, round((reply["at"] - message["at"]).total_seconds()))})
    return found


def activity(chat, offset_minutes=0):
    zone = timezone(timedelta(minutes=offset_minutes))
    theirs = [m for m in chat if not m["outgoing"]]
    pairs = exchanges(chat)
    delays = [pair["after_seconds"] for pair in pairs]
    hours, days = [0] * 24, [0] * 7
    for message in theirs:
        local = message["at"].astimezone(zone)
        hours[local.hour] += 1
        days[local.weekday()] += 1
    gaps = sorted(({"from": iso(a["at"]), "to": iso(b["at"]), "seconds": round((b["at"] - a["at"]).total_seconds())}
                   for a, b in zip(theirs, theirs[1:])), key=lambda gap: gap["seconds"], reverse=True)[:3]
    return {"messages": len(chat), "theirs": len(theirs), "ours": len(chat) - len(theirs),
            "first_at": iso(chat[0]["at"]) if chat else None, "last_theirs_at": iso(theirs[-1]["at"]) if theirs else None,
            "replies": len(delays), "median_seconds": round(statistics.median(delays)) if delays else None,
            "fastest_seconds": min(delays, default=None), "slowest_seconds": max(delays, default=None),
            "hours": hours, "weekdays": days, "silences": gaps, "exchanges": pairs[-EXCHANGES:][::-1],
            "offset_minutes": offset_minutes, "basis": "Telegram message times; read receipts are never sent or used."}


def script_of(text):
    letters = [c for c in text if c.isalpha()]
    counts = Counter("cyrillic" if "Ѐ" <= c <= "ӿ" else "latin" if c.isascii() else "other" for c in letters)
    return counts


def style(chat):
    theirs = [m["text"] for m in chat if not m["outgoing"] and m["text"].strip()]
    if not theirs:
        return {"messages": 0}
    scripts = Counter()
    for text in theirs:
        scripts.update(script_of(text))
    letters = sum(scripts.values()) or 1
    emoji = Counter(match for text in theirs for match in EMOJI.findall(text))
    words = Counter(word.casefold() for text in theirs for word in WORD.findall(text))
    bursts, run = [], 0
    for message in chat:
        if message["outgoing"]:
            if run:
                bursts.append(run)
            run = 0
        else:
            run += 1
    if run:
        bursts.append(run)
    share = lambda count: round(count / len(theirs), 2)  # noqa: E731
    return {"messages": len(theirs), "average_length": round(sum(map(len, theirs)) / len(theirs)),
            "scripts": {name: round(count / letters, 2) for name, count in scripts.most_common()},
            "emoji": [[symbol, count] for symbol, count in emoji.most_common(8)],
            "words": [[word, count] for word, count in words.most_common(12) if count > 1],
            "starts_lowercase": share(sum(text.lstrip()[:1].islower() for text in theirs)),
            "no_final_punctuation": share(sum(text.rstrip()[-1:] not in ".!?…" for text in theirs)),
            "with_emoji": share(sum(bool(EMOJI.search(text)) for text in theirs)),
            "messages_in_a_row": round(sum(bursts) / len(bursts), 1) if bursts else 0}


def view(store, plan):
    chat = messages(store, plan["chat_id"])
    sent, unlinked = matched(store, plan, chat)
    steps = [{**step, "sent": sent.get(step["id"])} for step in plan["steps"]]
    drafts = {event["seq"] for event in store.events(chat_id=plan["chat_id"], kind="conversation.draft_generated",
                                                      limit=500)}
    for step in steps:
        step["draft_recorded"] = step.get("draft") in drafts if step.get("draft") else None
    return {**plan, "revision": plan.get("revision", 1), "chat_title": chat_title(store, plan["chat_id"]), "steps": steps,
            "unlinked": unlinked, "activity": activity(chat, plan.get("offset_minutes", 0)), "style": style(chat)}


def transmission(store, plan, body, limit):
    chat = [m for m in messages(store, plan["chat_id"]) if m["text"].strip()][-body.context:]
    goal = find(plan["goals"], body.goal)["text"] if body.goal else None
    lines = [{"from": "us" if m["outgoing"] else "them", "at": iso(m["at"]), "text": m["text"][:1000]} for m in chat]
    payload = {"task": body.intent.strip(), "goal": goal, "variants": body.variants, "chat": lines,
               "observed_style": style(chat)}
    while lines and len(json.dumps(payload, ensure_ascii=False)) > limit:
        lines.pop(0)
    if not lines:
        raise ValueError("This chat has no saved text messages to learn the style from.")
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}], len(lines)


def clean(answer, variants):
    listed_drafts = answer if isinstance(answer, list) else next(
        (answer[key] for key in ("drafts", "variants", "messages", "options", "replies")
         if isinstance(answer, dict) and isinstance(answer.get(key), list)), None)
    if listed_drafts is None and isinstance(answer, dict) and isinstance(answer.get("text"), str):
        listed_drafts = [answer]
    if listed_drafts is None:
        raise ValueError("The model did not return drafts. Try again or change the request.")
    answer = answer if isinstance(answer, dict) else {}
    drafts = []
    for item in listed_drafts:
        text = next((item[key] for key in ("text", "message", "draft") if isinstance(item.get(key), str)), None) \
            if isinstance(item, dict) else item
        if isinstance(text, str) and text.strip() and len(drafts) < variants:
            why = item.get("why") or item.get("reason") if isinstance(item, dict) else ""
            drafts.append({"text": text.strip()[:4096], "why": str(why or "")[:300]})
    if not drafts:
        raise ValueError("The model did not return drafts. Try again or change the request.")
    raw = answer.get("style") if isinstance(answer.get("style"), dict) else {}
    listed = lambda value: [str(item)[:40] for item in value[:12]] if isinstance(value, list) else []  # noqa: E731
    found = {"language": str(raw.get("language") or "")[:80], "register": str(raw.get("register") or "")[:120],
             "slang": listed(raw.get("slang")), "emoji": listed(raw.get("emoji")),
             "typical_length": str(raw.get("typical_length") or "")[:80], "notes": str(raw.get("notes") or "")[:600]}
    return drafts, found, str(answer.get("caution") or "")[:400]


class Assistant:
    def __init__(self):
        self.provider = ai.Provider()
        self.previews = {}

    def preview(self, state, plan, body, owner):
        available(state.store)
        config = ai.settings(state)
        route = state.collector.outside_route()
        messages_out, count = transmission(state.store, plan, body, config["context_chars"])
        now = time.time()
        self.previews = {key: p for key, p in self.previews.items() if p["expires"] > now}
        if sum(p["owner"] == owner for p in self.previews.values()) >= 10 or len(self.previews) >= 100:
            raise ValueError("Too many pending previews. Retry after they expire.")
        ident = secrets.token_hex(16)
        text = json.dumps(messages_out, ensure_ascii=False)
        self.previews[ident] = {"owner": owner, "plan_id": plan["id"], "chat_id": plan["chat_id"], "body": body.model_dump(),
                                "messages": messages_out, "count": count, "expires": now + 600,
                                "provider_fingerprint": ai.fingerprint(config), "route_fingerprint": ai.route_fingerprint(route)}
        return {"preview_id": ident, "expires_at": now + 600, "messages": count, "characters": len(text),
                "enabled": ai.enabled(state, config),
                "provider": {**{key: config[key] for key in ("provider", "endpoint", "model")}, **ai.transport(config, route)},
                "transmission": messages_out}

    async def generate(self, state, plan, body, owner):
        available(state.store)
        if not body.consent:
            raise ValueError("Confirm that this data may be sent to the AI provider.")
        found = self.previews.get(body.preview_id)
        if not found or found["owner"] != owner or found["plan_id"] != plan["id"] or found["expires"] <= time.time():
            raise ValueError("This preview is unavailable or expired. Preview again.")
        attempts, request = 0, found["messages"]
        while True:
            attempts += 1
            try:
                answer, generation = await self.provider.complete(state, request, expected=found["provider_fingerprint"],
                                                                  expected_route=found["route_fingerprint"])
                drafts, observed, caution = clean(answer, found["body"]["variants"])
                break
            except ValueError as exc:
                if attempts > 1 or str(exc) not in RETRY:
                    raise
                request = found["messages"] + [{"role": "system", "content": REMINDER}]
        self.previews.pop(body.preview_id, None)
        digest = hashlib.sha256(json.dumps(found["messages"], ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        event = state.store.append("conversation.draft_generated", {
            "plan_id": plan["id"], "intent": found["body"]["intent"], "goal": found["body"]["goal"],
            "messages_sent": found["count"], "transmission_sha256": digest, "attempts": attempts,
            "provider": generation.get("provider"), "model": generation.get("model"),
            "endpoint": generation.get("endpoint"), "drafts": [draft["text"] for draft in drafts],
            "meaning": "AI drafts suggested to the investigator. A draft becomes a message only if the investigator sends it."},
            chat_id=plan["chat_id"])
        return {"drafts": drafts, "style": observed, "caution": caution, "event": event["seq"], "attempts": attempts,
                "generation": {key: generation.get(key) for key in ("provider", "model", "tokens", "cost", "processing")}}
