import hashlib
import json
import re
import secrets
import time
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from . import ai
from .message_selection import detect_language

MAX_ITEMS = 100
MAX_TEXT = 4000
KINDS = ("message.new", "message.edited")
SYSTEM = (
    "You translate messages from a Telegram investigation for the investigator. Translate every item into "
    "{target} faithfully: keep the meaning of slang, abbreviations, threats, promises and payment instructions; do not "
    "soften, censor, summarise or add anything. Copy wallet addresses, links, amounts, numbers, usernames and code "
    "exactly as written. Return only JSON: {{\"translations\": [{{\"id\": string, \"text\": string, \"language\": "
    "string, \"note\": string}}]}} with one entry per input id. \"language\" is the source language you recognised; "
    "\"note\" briefly explains slang or ambiguity, or is empty.")
REMINDER = ("Your previous answer could not be used. Reply with one JSON object in the requested shape containing a "
            "translation for every input id, and nothing else.")
RETRY = {"The provider returned an unsupported response.", "The model did not return translations."}
MEANING = "Machine translation suggested to the investigator. The original record is unchanged."


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid")
    chat_id: int
    seqs: list[int] = Field(min_length=1, max_length=MAX_ITEMS)
    target: str = Field(default="en", min_length=2, max_length=2)
    include_target_language: StrictBool = False

    @field_validator("seqs")
    @classmethod
    def records(cls, value):
        if any(seq < 1 for seq in value):
            raise ValueError("Choose journal records to translate.")
        return list(dict.fromkeys(value))

    @field_validator("target")
    @classmethod
    def language(cls, value):
        value = value.lower()
        if language_name(value) is None:
            raise ValueError("Choose a supported two-letter target language.")
        return value


class Generate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    consent: StrictBool = False


def language_name(code):
    if not re.fullmatch(r"[a-z]{2}", code or ""):
        return None
    from lingua import Language
    found = next((lang for lang in Language.all() if lang.iso_code_639_1.name.lower() == code), None)
    return found.name.title() if found else None


def likely(text):
    found = detect_language(text)
    return found.get("language") or (found.get("candidate") if (found.get("score") or 0) >= 0.4 else None)


def available(store):
    goal = (store.get_setting("goal_preset", None) or store.get_setting("setup", None) or {}).get("goal")
    if goal == "evidence":
        raise ValueError("Translation is off for the Evidence for a case goal.")


def record(store, seq):
    found = store.events_after(seq - 1, 1)
    return found[0] if found and found[0]["seq"] == seq else None


def source_items(store, chat_id, seqs):
    found, missing = [], []
    for seq in seqs:
        event = record(store, seq)
        payload = (event or {}).get("payload") or {}
        text = payload.get("text") if isinstance(payload.get("text"), str) else ""
        if not event or event["kind"] not in KINDS or event.get("chat_id") != chat_id or not text.strip():
            missing.append(seq)
            continue
        found.append({"seq": seq, "message_id": event.get("message_id"), "text": text[:MAX_TEXT],
                      "language": likely(text)})
    return found, missing


def languages(store, chat_id, limit=500, target="en"):
    counts, foreign = Counter(), []
    for event in store.events(chat_id=chat_id, kind="message.new", limit=limit):
        text = ((event.get("payload") or {}).get("text") or "")
        if not text.strip():
            continue
        language = likely(text) or "unknown"
        counts[language] += 1
        if language not in (target, "unknown"):
            foreign.append(event["seq"])
    return {"languages": dict(counts.most_common()), "foreign": sorted(foreign)[-MAX_ITEMS:], "target": target,
            "detector": "lingua"}


def prompt(items, target):
    return [{"role": "system", "content": SYSTEM.format(target=language_name(target))},
            {"role": "user", "content": json.dumps({"target": target, "items": [
                {"id": str(item["seq"]), "text": item["text"]} for item in items]}, ensure_ascii=False)}]


def clean(answer, items):
    rows = answer.get("translations") if isinstance(answer, dict) else answer if isinstance(answer, list) else None
    if not isinstance(rows, list):
        raise ValueError("The model did not return translations.")
    wanted, result = {str(item["seq"]): item for item in items}, {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ident, text = str(row.get("id", "")), row.get("text")
        if ident in wanted and isinstance(text, str) and text.strip() and ident not in result:
            result[ident] = {"text": text.strip()[:MAX_TEXT * 2], "language": str(row.get("language") or "")[:40],
                             "note": str(row.get("note") or "")[:400]}
    if not result:
        raise ValueError("The model did not return translations.")
    return result


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class Translator:
    def __init__(self):
        self.provider = ai.Provider()
        self.previews = {}

    def preview(self, state, body, owner):
        available(state.store)
        items, missing = source_items(state.store, body.chat_id, body.seqs)
        skipped = [item["seq"] for item in items if item["language"] == body.target and not body.include_target_language]
        items = [item for item in items if item["seq"] not in skipped]
        if not items:
            raise ValueError("Nothing to translate: the chosen messages are empty, missing or already in that language.")
        config = ai.settings(state)
        route = state.collector.outside_route()
        messages = prompt(items, body.target)
        while len(json.dumps(messages, ensure_ascii=False)) > config["context_chars"] and len(items) > 1:
            items = items[:-1]
            messages = prompt(items, body.target)
        now = time.time()
        self.previews = {key: p for key, p in self.previews.items() if p["expires"] > now}
        if sum(p["owner"] == owner for p in self.previews.values()) >= 10 or len(self.previews) >= 100:
            raise ValueError("Too many pending previews. Retry after they expire.")
        ident = secrets.token_hex(16)
        self.previews[ident] = {"owner": owner, "chat_id": body.chat_id, "target": body.target, "items": items,
                                "messages": messages, "expires": now + 600,
                                "provider_fingerprint": ai.fingerprint(config),
                                "route_fingerprint": ai.route_fingerprint(route)}
        return {"preview_id": ident, "expires_at": now + 600, "messages": len(items), "missing": missing,
                "skipped": skipped, "left_out": [seq for seq in body.seqs if seq not in {i["seq"] for i in items}
                                                 and seq not in missing and seq not in skipped],
                "characters": len(json.dumps(messages, ensure_ascii=False)), "enabled": ai.enabled(state, config),
                "target": body.target, "target_name": language_name(body.target),
                "provider": {**{key: config[key] for key in ("provider", "endpoint", "model")}, **ai.transport(config, route)},
                "transmission": messages}

    async def generate(self, state, body, owner, chats=None):
        available(state.store)
        if not body.consent:
            raise ValueError("Confirm that these messages may be sent to the AI provider.")
        found = self.previews.get(body.preview_id)
        if not found or found["owner"] != owner or found["expires"] <= time.time():
            raise ValueError("This preview is unavailable or expired. Preview again.")
        if chats is not None and found["chat_id"] not in chats:
            raise ValueError("This preview is unavailable or expired. Preview again.")
        attempts, request = 0, found["messages"]
        while True:
            attempts += 1
            try:
                answer, generation = await self.provider.complete(state, request, expected=found["provider_fingerprint"],
                                                                  expected_route=found["route_fingerprint"])
                translated = clean(answer, found["items"])
                break
            except ValueError as exc:
                if attempts > 1 or str(exc) not in RETRY:
                    raise
                request = found["messages"] + [{"role": "system", "content": REMINDER}]
        self.previews.pop(body.preview_id, None)
        items = [{"seq": item["seq"], "message_id": item["message_id"], "source_sha256": digest(item["text"]),
                  "source_language": item["language"], **translated[str(item["seq"])]}
                 for item in found["items"] if str(item["seq"]) in translated]
        event = state.store.append("translation.created", {
            "target": found["target"], "items": items, "untranslated": [item["seq"] for item in found["items"]
                                                                       if str(item["seq"]) not in translated],
            "provider": generation.get("provider"), "model": generation.get("model"),
            "endpoint": generation.get("endpoint"), "attempts": attempts,
            "transmission_sha256": digest(json.dumps(found["messages"], ensure_ascii=False, sort_keys=True)),
            "meaning": MEANING}, chat_id=found["chat_id"])
        return {"event": event["seq"], "items": items, "target": found["target"], "attempts": attempts,
                "generation": {key: generation.get(key) for key in ("provider", "model", "tokens", "cost", "processing")}}


def latest(store, chat_id, target=None, limit=500):
    found = {}
    for event in sorted(store.events(chat_id=chat_id, kind="translation.created", limit=limit), key=lambda e: e["seq"]):
        payload = event.get("payload") or {}
        if target and payload.get("target") != target:
            continue
        for item in payload.get("items") or []:
            if isinstance(item, dict) and isinstance(item.get("seq"), int):
                found[item["seq"]] = {**item, "target": payload.get("target"), "record": event["seq"],
                                      "model": payload.get("model"), "provider": payload.get("provider")}
    return found
