import html
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher

from . import message_details
from .indicators import Indicators

FORMAT = "tgwitness-action-protocol-v1"
WINDOW_SECONDS = 300
MAX_FOLLOWING = 20
MAX_DELETIONS = 200
MAX_TEXT = 2000
MAX_EVENTS = 20000
CHAT_KINDS = ("message.new,message.edited,message.deleted,media.saved,source.added,conversation.draft_generated,"
              "media.qr_decoded")
ACCOUNT_KINDS = ("account.profile_updated", "account.privacy_updated", "account.global_privacy_updated",
                 "account.avatar_updated", "account.avatar_removed")
DRAFT_SIMILARITY = 0.8
LIMITS = (
    "Times are the collector's clock when each record was saved. Telegram times are server dates with "
    "one-second resolution.",
    "Messages are listed for a limited time after each action. A reply missing from this protocol is not proof "
    "that no reply was sent.",
    "Actions in another Telegram app appear only through the messages this account sent or received; inline "
    "button presses there are not visible.",
    "Indicators are strings found in messages. Who controls a wallet, link or account is a separate question.",
    "Each step cites its journal record. Verify the signed journal before relying on this protocol.",
)
RISKS = {"telegram_proxy": "Telegram proxy link: opening it in a Telegram app contacts that server and reveals "
                            "the IP address.",
         "telegram_story": "Story link: opening it from an account can record a view by that account.",
         "mixed_script": "The address mixes alphabets and may imitate another domain."}
STATUS = {"succeeded": "Telegram accepted the action.",
          "approval_pending": "The join request was sent and waits for an administrator.",
          "rejected": "The action was not performed.",
          "unknown": "The outcome is unknown; check the chat before repeating the action."}
CHAT_STYLE = ("body{font:15px system-ui;background:#0f1720;color:#e8eef4;max-width:920px;margin:28px auto;padding:0 16px}"
              "section{background:#16212c;border:1px solid #2c3e50;border-radius:12px;padding:16px;margin:16px 0}"
              "li{margin:10px 0;line-height:1.45}time{color:#9fb7cc;font-variant-numeric:tabular-nums}"
              ".lag{color:#f0ba58}.ref{color:#7f95a8;font-size:12px}.warn{color:#ff9d7a}"
              "blockquote{margin:6px 0;padding:6px 10px;border-left:3px solid #4b6a85;white-space:pre-wrap;overflow-wrap:anywhere}"
              "code{overflow-wrap:anywhere}figure{margin:8px 0}img{max-width:100%;border:1px solid #2c3e50;border-radius:8px}"
              "figcaption{color:#7f95a8;font-size:12px}")


def plain_say(text, /, **params):
    for name, value in params.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def moment(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def seconds(later, earlier):
    a, b = moment(later), moment(earlier)
    return round((a - b).total_seconds(), 3) if a and b else None


def clip(value):
    if not isinstance(value, str) or not value:
        return None
    return value if len(value) <= MAX_TEXT else value[:MAX_TEXT] + "…"


def compact(value):
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def reference(event):
    return {"seq": event["seq"], "hash": event.get("hash")}


def mapping(value):
    return value if isinstance(value, dict) else {}


def message_step(kind, event):
    payload = mapping(event.get("payload"))
    details = message_details.details(payload.get("raw"))
    sender = mapping(payload.get("sender_observation"))
    text = payload.get("text") if isinstance(payload.get("text"), str) else ""
    found = Indicators()
    found.message(text, details, None, event.get("observed_at"))
    media = mapping(details.get("media_info"))
    return compact({
        "type": kind, "at": event.get("observed_at"), "ref": reference(event), "message_id": event.get("message_id"),
        "telegram_time": payload.get("edited_at") if kind == "edited" else payload.get("sent_at"),
        "sender": compact({key: sender.get(key) for key in ("id", "username", "display_name")}),
        "text": clip(text), "reply_to_message_id": payload.get("reply_to_message_id"),
        "media": compact({key: media.get(key) for key in ("kind", "mime_type", "file_name", "size")}),
        "buttons": [labels for labels in ([button.get("text") for button in row if isinstance(button, dict)]
                                          for row in mapping(details.get("buttons")).get("rows") or []) if labels],
        "deceptive_links": [{"text": item.get("text"), "href": item.get("href")}
                            for item in details.get("text_entities") or [] if item.get("deceptive")],
        "risky_links": [{"text": item.get("text"), "href": item.get("href"), "risk": item["risk"]}
                        for item in details.get("text_entities") or [] if item.get("risk")]
                       + [{"text": button.get("text"), "href": button["url"], "risk": message_details.link_risk(button["url"])}
                          for row in mapping(details.get("buttons")).get("rows") or [] for button in row
                          if isinstance(button, dict) and message_details.link_risk(button.get("url"))],
        "indicators": [{key: item[key] for key in ("kind", "value", "chain", "punycode") if key in item}
                       for item in found.result()["items"]]})


class Protocol:
    def __init__(self, window_seconds, max_following):
        self.window, self.most = window_seconds, max_following
        self.episodes, self.anchors = {}, {}

    def episode(self, chat_id):
        if chat_id not in self.episodes:
            self.episodes[chat_id] = {"chat_id": chat_id, "title": None, "kind": None, "steps": [], "not_listed": 0}
        return self.episodes[chat_id]

    def add(self, chat_id, step):
        self.episode(chat_id)["steps"].append(step)

    def name(self, chat_id, title, kind):
        episode = self.episode(chat_id)
        episode["title"] = episode["title"] or title
        episode["kind"] = episode["kind"] or kind

    def act(self, chat_id, at, basis, telegram_time=None):
        self.close(chat_id)
        self.anchors[chat_id] = {"at": at, "telegram_time": telegram_time, "basis": basis, "listed": 0, "hidden": 0}

    def close(self, chat_id):
        anchor = self.anchors.get(chat_id)
        if anchor and anchor["hidden"]:
            self.add(chat_id, {"type": "not_listed", "count": anchor["hidden"], "after": anchor["basis"]})
            anchor["hidden"] = 0

    def timed(self, chat_id, step):
        anchor = self.anchors[chat_id]
        step.update(compact({"after_seconds": seconds(step.get("at"), anchor["at"]), "after": anchor["basis"],
                             "telegram_after_seconds": seconds(step.get("telegram_time"), anchor["telegram_time"])}))
        return step

    def follow(self, chat_id, step):
        anchor = self.anchors[chat_id]
        after = seconds(step.get("at"), anchor["at"])
        if after is None or after > self.window or anchor["listed"] >= self.most:
            anchor["hidden"] += 1
            self.episode(chat_id)["not_listed"] += 1
            return
        anchor["listed"] += 1
        self.add(chat_id, self.timed(chat_id, step))

    def attach(self, chat_id, message_id, payload):
        digest = payload.get("media_sha256")
        if not isinstance(digest, str):
            return
        for step in reversed(self.episode(chat_id)["steps"][-50:]):
            if step.get("message_id") == message_id and step["type"] in ("reply", "edited", "sent", "sent_elsewhere"):
                step.setdefault("files", []).append(compact({"sha256": digest, "mime_type": payload.get("mime_type")}))
                return


def self_step(event, payload):
    found = [item for item in payload.get("findings") or [] if isinstance(item, dict)]
    return compact({
        "type": "self_check", "at": event.get("observed_at"), "ref": reference(event),
        "risks": [{key: item.get(key) for key in ("label", "visible_to", "recommended")}
                  for item in found if item.get("level") == "risk"],
        "notices": sum(item.get("level") == "notice" for item in found),
        "bot_view": mapping(payload.get("bot_view"))})


def account_step(event, payload):
    from .persona import GLOBAL, SETTINGS
    labels = {name: label for name, _, label, *_ in SETTINGS}
    options = {name: label for name, label, _ in GLOBAL}
    step = {"type": "account_change", "at": event.get("observed_at"), "ref": reference(event)}
    kind = event["kind"]
    if kind == "account.profile_updated":
        before, after = mapping(payload.get("before")), mapping(payload.get("after"))
        step.update(change="profile", fields=[{"field": name, "before": clip(before.get(name)) or "",
                                               "after": clip(after.get(name)) or ""}
                                              for name in payload.get("changed") or [] if isinstance(name, str)])
    elif kind == "account.privacy_updated":
        before = mapping(payload.get("before"))
        rows = []
        for name, value in mapping(payload.get("applied")).items():
            value = value if isinstance(value, dict) else {"visible_to": value}
            old = mapping(before.get(name))
            people = "allow_users" in old and any(sorted(value.get(field) or []) != sorted(old.get(field) or [])
                                                  for field in ("allow_users", "deny_users"))
            rows.append(compact({"setting": name, "label": labels.get(name, name), "before": old.get("visible_to"),
                                 "after": value.get("visible_to"), "allow": len(value.get("allow_users") or []),
                                 "deny": len(value.get("deny_users") or []), "exceptions_changed": people or None}))
        step.update(change="privacy", settings=rows,
                    failed=[labels.get(name, name) for name in mapping(payload.get("failed"))])
    elif kind == "account.global_privacy_updated":
        before, after = mapping(payload.get("before")), mapping(payload.get("after"))
        step.update(change="options", options=[{"option": name, "label": options.get(name, name),
                                                "before": bool(before.get(name)), "after": bool(after.get(name))}
                                               for name in payload.get("changed") or [] if isinstance(name, str)])
    elif kind == "account.avatar_updated":
        step.update(change="photo_set", sha256=payload.get("sha256"), size=payload.get("size"))
    else:
        step.update(change="photo_removed", photo_id=payload.get("photo_id"))
    return compact(step)


def subject_step(event, payload):
    files = ([{"sha256": payload["photo_sha256"], "mime_type": "image/jpeg", "role": "avatar"}]
             if isinstance(payload.get("photo_sha256"), str) else [])
    return compact({
        "type": "subject", "at": event.get("observed_at"), "ref": reference(event), "title": clip(payload.get("title")),
        "kind": payload.get("kind"), "usernames": [u for u in payload.get("usernames") or [] if isinstance(u, str)],
        "user_id": payload.get("user_id"), "chat_id": event.get("chat_id"),
        "flags": [f for f in payload.get("flags") or [] if isinstance(f, str)], "about": clip(payload.get("about")),
        "bot_description": clip(payload.get("bot_description")),
        "commands": [{"command": c.get("command"), "description": clip(c.get("description"))}
                     for c in (payload.get("commands") or [])[:40] if isinstance(c, dict)],
        "participants": payload.get("participants"), "created_at": payload.get("created_at"),
        "common_chats": payload.get("common_chats"), "restricted": payload.get("restriction_reasons"),
        "changes": [c for c in payload.get("changes") or [] if isinstance(c, dict)], "files": files,
        "unavailable": payload.get("unavailable")})


PEER_FLAGS = {
    "need_contacts_exception": "Telegram reported need_contacts_exception=true",
    "add_contact": "Telegram offers to add the other side to contacts",
    "block_contact": "Telegram offers to block the other side",
    "share_contact": "Telegram offers to share this account's contact",
    "report_spam": "Telegram offers to report the other side as spam",
    "report_geo": "Telegram offers to report the location",
    "autoarchived": "Telegram archived the chat automatically",
    "invite_members": "Telegram offers to invite members",
    "request_chat_broadcast": "the other side requested to add a channel",
}
PEER_FACTS = {"registration_month": "the account was registered in {value}",
              "phone_country": "the phone number is registered in {value}",
              "name_change_date": "the name was last changed on {value}",
              "photo_change_date": "the profile photo was last changed on {value}",
              "geo_distance": "the other side is about {value} metres away"}


PRESENCE_STATES = {"online": "online", "offline": "offline", "recently": "last seen recently",
                   "last_week": "last seen within a week", "last_month": "last seen within a month",
                   "unknown": "status not available"}


def qr_step(event, payload):
    return compact({"type": "qr_code", "at": event.get("observed_at"), "ref": reference(event),
                    "media_sha256": payload.get("media_sha256"),
                    "codes": [clip(item.get("text")) for item in payload.get("codes") or [] if isinstance(item, dict)],
                    "indicators": [{key: item[key] for key in ("kind", "value", "chain") if key in item}
                                   for item in payload.get("indicators") or [] if isinstance(item, dict)]})


def presence_step(event, payload):
    status = mapping(payload.get("status"))
    previous = mapping(payload.get("previous"))
    return compact({"type": "presence", "at": payload.get("checked_at") or event.get("observed_at"),
                    "ref": reference(event), "user_id": payload.get("user_id"), "username": payload.get("username"),
                    "label": clip(payload.get("label")), "state": status.get("state"),
                    "was_online": status.get("was_online"), "before": previous.get("state")})


def peer_step(event, payload):
    return compact({"type": "peer_settings", "at": event.get("observed_at"), "ref": reference(event),
                    "flags": [f for f in payload.get("flags") or [] if isinstance(f, str)],
                    "stated": {k: v for k, v in mapping(payload.get("stated")).items() if k in PEER_FACTS}})


def search_step(event, payload):
    return compact({"type": "search_recorded", "at": event.get("observed_at"), "ref": reference(event),
                    "query": clip(payload.get("query")), "source": payload.get("source"), "chats": payload.get("chats"),
                    "since": payload.get("since"), "until": payload.get("until"), "matched": payload.get("matched", 0),
                    "note": clip(payload.get("note")), "operator": mapping(payload.get("operator")).get("label")})


def draft_step(event, payload):
    drafts = [text for text in payload.get("drafts") or [] if isinstance(text, str)]
    return compact({"type": "ai_draft", "at": event.get("observed_at"), "ref": reference(event),
                    "intent": clip(payload.get("intent")), "model": payload.get("model"),
                    "provider": payload.get("provider"), "messages_sent": payload.get("messages_sent"),
                    "drafts": len(drafts), "attempts": payload.get("attempts")}), drafts


def normal(text):
    return re.sub(r"\s+", " ", text or "").strip().casefold()


def drafted(text, drafts):
    best = None
    for seq, texts in reversed(drafts):
        for candidate in texts:
            ratio = 1.0 if normal(candidate) == normal(text) else SequenceMatcher(None, normal(candidate), normal(text)).ratio()
            if ratio >= DRAFT_SIMILARITY and (best is None or ratio > best["similarity"]):
                best = {"seq": seq, "similarity": round(ratio, 2)}
        if best:
            return best
    return None


def visual_step(event, payload):
    files = [{"sha256": item["sha256"], "mime_type": item.get("media_type"), "role": item.get("role")}
             for item in payload.get("artifacts") or [] if isinstance(item, dict) and isinstance(item.get("sha256"), str)]
    server, tls = mapping(payload.get("server")), mapping(payload.get("tls"))
    return compact({
        "type": "visual", "at": event.get("observed_at"), "ref": reference(event),
        "url": payload.get("requested_url"), "final_url": payload.get("final_url"), "title": clip(payload.get("title")),
        "http_status": payload.get("http_status"), "server_ip": server.get("ip"), "issuer": tls.get("issuer"),
        "subject": mapping(payload.get("subject")), "recorder": payload.get("fingerprint"),
        "recorder_seq": payload.get("recorder_seq"), "files": files,
        "errors": [item.get("component") for item in payload.get("errors") or [] if isinstance(item, dict)]})


def resolved_chats(events):
    found = {}
    for event in events:
        payload = mapping(event.get("payload"))
        if event["kind"] == "interaction.result" and type(payload.get("request_event")) is int \
                and payload.get("chat_id") is not None:
            found[payload["request_event"]] = payload["chat_id"]
    return found


def summary(episode):
    steps = episode["steps"]
    found = {}
    for step in steps:
        for item in step.get("indicators") or []:
            found.setdefault((item["kind"], item["value"]), item)
    replies = [s for s in steps if s["type"] in ("reply", "edited")]
    timed = [s["after_seconds"] for s in replies if isinstance(s.get("after_seconds"), (int, float))]
    return compact({"from": steps[0].get("at") if steps else None, "to": steps[-1].get("at") if steps else None,
                    "actions": sum(s["type"] in ("requested", "sent_elsewhere") for s in steps),
                    "replies": len(replies), "first_reply_seconds": min(timed) if timed else None,
                    "deletions": sum(s["type"] == "deleted" for s in steps),
                    "account_changes": sum(s["type"] == "account_change" for s in steps),
                    "ai_assisted": sum(bool(s.get("ai_draft")) for s in steps),
                    "files": sum(len(s.get("files") or []) for s in steps),
                    "deceptive_links": sum(len(s.get("deceptive_links") or []) for s in steps),
                    "risky_links": sum(len(s.get("risky_links") or []) for s in steps),
                    "indicators": list(found.values())})


def build(events, window_seconds=WINDOW_SECONDS, max_following=MAX_FOLLOWING, chats=None, account=None):
    events = sorted((e for e in events if type(e.get("seq")) is int and isinstance(e.get("kind"), str)),
                    key=lambda e: e["seq"])
    resolved, previews, requests, drafts, asked = resolved_chats(events), {}, {}, {}, {}
    protocol = Protocol(window_seconds, max_following)
    allowed = (lambda chat: chat in chats) if chats is not None else (lambda chat: True)
    account = chats is None if account is None else account
    for event in events:
        kind, chat_id, payload = event["kind"], event.get("chat_id"), mapping(event.get("payload"))
        if kind == "interaction.preview":
            previews[event["seq"]] = compact({
                "type": "checked_link", "at": event.get("observed_at"), "ref": reference(event),
                "link": payload.get("link"), "title": payload.get("title"), "target_kind": payload.get("kind"),
                "about": clip(payload.get("about")), "participants": payload.get("participants_count"),
                "already_member": payload.get("already_member") or None,
                "approval_needed": payload.get("request_needed") or None})
        elif kind == "interaction.requested":
            request, button = mapping(payload.get("request")), mapping(payload.get("button"))
            chat = request.get("chat_id") if request.get("chat_id") is not None else resolved.get(event["seq"])
            requests[event["seq"]] = chat
            if not allowed(chat):
                continue
            protocol.close(chat)
            preview = previews.get(payload.get("preview_event"))
            if preview:
                protocol.add(chat, preview)
                protocol.name(chat, preview.get("title"), preview.get("target_kind"))
            operator = mapping(payload.get("operator")).get("label")
            if request.get("action") == "send":
                asked.setdefault(chat, []).append((normal(request.get("text")), operator))
            protocol.add(chat, compact({
                "type": "requested", "at": event.get("observed_at"), "ref": reference(event),
                "action": request.get("action"), "text": clip(request.get("text")), "button": button.get("text"),
                "button_type": button.get("type"), "message_id": request.get("message_id"),
                "queued_until": payload.get("queued_until"), "operator": operator}))
            queued = payload.get("queued_until")
            at = (datetime.fromtimestamp(queued, timezone.utc).isoformat(timespec="milliseconds")
                  if isinstance(queued, (int, float)) else event.get("observed_at"))
            protocol.act(chat, at, "button press" if request.get("action") == "press" else "request")
        elif kind == "interaction.result":
            chat = payload.get("chat_id") if payload.get("chat_id") is not None else requests.get(payload.get("request_event"))
            if not allowed(chat) or payload.get("request_event") not in requests:
                continue
            answer = mapping(payload.get("answer"))
            protocol.add(chat, compact({
                "type": "outcome", "at": event.get("observed_at"), "ref": reference(event),
                "status": payload.get("status"), "error": clip(payload.get("error")),
                "error_type": payload.get("error_type"), "retry_after": payload.get("retry_after"),
                "answer": clip(answer.get("message")), "answer_alert": answer.get("alert") or None,
                "answer_url": answer.get("url")}))
        elif kind == "capture.opened":
            if (chat_id is None and chats is not None) or (chat_id is not None and not allowed(chat_id)):
                continue
            protocol.add(chat_id, visual_step(event, payload))
        elif kind == "account.opsec_checked":
            if account:
                protocol.add(None, self_step(event, payload))
        elif kind in ACCOUNT_KINDS:
            if account:
                protocol.add(None, account_step(event, payload))
        elif kind == "search.recorded":
            scope = payload.get("chats")
            if account or (chats is not None and scope and set(scope) <= set(chats)):
                protocol.add(None, search_step(event, payload))
        elif kind == "media.qr_decoded":
            if chat_id is not None and allowed(chat_id):
                protocol.add(chat_id, qr_step(event, payload))
        elif kind == "presence.changed":
            if account:
                protocol.add(None, presence_step(event, payload))
        elif kind == "peer.settings_changed":
            if chat_id is not None and allowed(chat_id):
                protocol.add(chat_id, peer_step(event, payload))
        elif kind == "subject.snapshot":
            if chat_id is not None and allowed(chat_id):
                protocol.name(chat_id, payload.get("title"), payload.get("kind"))
                protocol.add(chat_id, subject_step(event, payload))
        elif chat_id is None or not allowed(chat_id):
            continue
        elif kind == "conversation.draft_generated":
            step, texts = draft_step(event, payload)
            drafts.setdefault(chat_id, []).append((event["seq"], texts))
            protocol.add(chat_id, step)
        elif kind == "message.new" and payload.get("outgoing"):
            step = message_step("sent" if payload.get("source") == "panel_action" else "sent_elsewhere", event)
            source = drafted(step.get("text"), drafts.get(chat_id, [])) if step.get("text") else None
            if source:
                step["ai_draft"] = source
            pending = asked.get(chat_id) or []
            match = next((index for index, (text, _) in enumerate(pending) if text == normal(step.get("text"))), None)
            if step["type"] == "sent" and match is not None:
                operator = pending.pop(match)[1]
                if operator:
                    step["operator"] = operator
            if chat_id in protocol.anchors:
                protocol.close(chat_id)
                protocol.timed(chat_id, step)
            protocol.add(chat_id, step)
            protocol.act(chat_id, step.get("at"), "message", step.get("telegram_time"))
        elif chat_id not in protocol.anchors:
            continue
        elif kind == "message.new":
            protocol.follow(chat_id, message_step("reply", event))
        elif kind == "message.edited":
            protocol.follow(chat_id, message_step("edited", event))
        elif kind == "message.deleted":
            if sum(s["type"] == "deleted" for s in protocol.episode(chat_id)["steps"]) >= MAX_DELETIONS:
                protocol.episode(chat_id)["not_listed"] += 1
                continue
            protocol.add(chat_id, protocol.timed(chat_id, compact({
                "type": "deleted", "at": event.get("observed_at"), "ref": reference(event),
                "message_id": event.get("message_id")})))
        elif kind == "media.saved":
            protocol.attach(chat_id, event.get("message_id"), payload)
        elif kind == "source.added" and payload.get("source") == "panel_interaction":
            protocol.name(chat_id, payload.get("title"), payload.get("kind"))
            protocol.add(chat_id, protocol.timed(chat_id, compact({
                "type": "observing", "at": event.get("observed_at"), "ref": reference(event),
                "title": payload.get("title")})))
    for chat_id in list(protocol.anchors):
        protocol.close(chat_id)
    episodes = [e for e in protocol.episodes.values() if e["steps"]]
    episodes.sort(key=lambda e: e["steps"][0]["ref"]["seq"] if e["steps"][0].get("ref") else 0)
    for episode in episodes:
        episode["summary"] = summary(episode)
    return {"format": FORMAT, "window_seconds": window_seconds, "max_following": max_following,
            "episodes": episodes, "limits": list(LIMITS)}


def collect(store, chat_id=None, chats=None, window_seconds=WINDOW_SECONDS, max_following=MAX_FOLLOWING,
            limit=MAX_EVENTS, include=None, since_seq=None, account=None):
    start = max(since_seq - 1, 0) if since_seq else 0
    actions = store.events(kind="interaction.", after=start, limit=limit)
    resolved = resolved_chats(actions)
    first = {}
    for event in actions:
        payload = mapping(event.get("payload"))
        request = mapping(payload.get("request"))
        chat = event.get("chat_id")
        if chat is None:
            chat = request.get("chat_id") if request.get("chat_id") is not None else resolved.get(event["seq"])
        if chat is None and event["kind"] == "interaction.result":
            chat = payload.get("chat_id")
        if chat is not None:
            first[chat] = min(first.get(chat, event["seq"]), event["seq"])
    if chat_id is not None:
        first = {chat_id: first.get(chat_id, 0)}
    for chat in include or ():
        first.setdefault(chat, start + 1 if since_seq else 0)
    if chats is not None:
        first = {chat: seq for chat, seq in first.items() if chat in chats}
    selected = set(first) if chat_id is not None or chats is not None or include else None
    opened = store.events(kind="capture.opened,account.opsec_checked,search.recorded,subject.snapshot,"
                          "peer.settings_changed,presence.changed," + ",".join(ACCOUNT_KINDS),
                          after=start, limit=limit)
    events, truncated = list(actions) + opened, len(actions) >= limit or len(opened) >= limit
    for chat, seq in first.items():
        found = (store.events(chat_id=chat, kind=CHAT_KINDS, after=seq - 1, limit=limit) if seq
                 else store.events(chat_id=chat, kind=CHAT_KINDS, limit=limit))
        truncated = truncated or len(found) >= limit
        events.extend(found)
    unique = {event["seq"]: event for event in events}
    result = build(unique.values(), window_seconds, max_following, selected,
                   account if account is not None else chats is None)
    titles = {t["chat_id"]: (t.get("title"), t.get("kind")) for t in store.targets()}
    for episode in result["episodes"]:
        title, kind = titles.get(episode["chat_id"], (None, None))
        episode["title"] = episode["title"] or title
        episode["kind"] = episode["kind"] or kind
    result["truncated"] = truncated
    return result


def who(step, say):
    sender = step.get("sender") or {}
    name = sender.get("display_name") or (("@" + sender["username"]) if sender.get("username") else None)
    return name or (say("Telegram ID {id}", id=sender["id"]) if sender.get("id") else say("The other side"))


def quoted(text):
    return "“" + text + "”" if text else ""


def pretty(value):
    return ("%.1f" % value).rstrip("0").rstrip(".") if value < 10 else str(round(value))


def same(value):
    return value


def minor(step):
    return step["type"] in ("requested", "observing") or (
        step["type"] == "outcome" and step.get("status") == "succeeded" and not step.get("answer")
        and not step.get("answer_url"))


def sentence(step, say, clock=same):
    kind = step["type"]
    if kind == "checked_link":
        line = say("Checked the link {link}: {kind} {title}.", link=step.get("link", ""),
                   kind=step.get("target_kind", ""), title=quoted(step.get("title", "")))
        if step.get("participants"):
            line += " " + say("{n} participants.", n=step["participants"])
        if step.get("already_member"):
            line += " " + say("This account was already a member.")
        if step.get("approval_needed"):
            line += " " + say("Joining needs administrator approval.")
        return line
    if kind == "requested":
        action = step.get("action")
        if action == "send":
            line = say("Requested to send {text}.", text=quoted(step.get("text", "")))
        elif action == "press":
            line = say("Requested to press the button {button} on message #{id}.",
                       button=quoted(step.get("button", "")), id=step.get("message_id", "?"))
        else:
            line = say("Requested to open the link.")
        queued = step.get("queued_until")
        if isinstance(queued, (int, float)):
            queued = datetime.fromtimestamp(queued, timezone.utc).isoformat()
        return line + (" " + say("Queued by the action pace limit until {at}.", at=clock(queued)) if queued else "")
    if kind == "observing":
        return say("Added {title} to observation.", title=quoted(step.get("title", "")))
    if kind in ("sent", "sent_elsewhere"):
        line = (say("This account sent message #{id}: {text}", id=step.get("message_id", "?"), text=quoted(step.get("text", "")))
                if kind == "sent" else
                say("This account sent message #{id} from another app or session: {text}",
                    id=step.get("message_id", "?"), text=quoted(step.get("text", ""))))
        line += " " + say("Telegram time {at}.", at=clock(step["telegram_time"])) if step.get("telegram_time") else ""
        line += " " + say("Requested by {operator}.", operator=step["operator"]) if step.get("operator") else ""
        return line + (" " + drafted_note(step["ai_draft"], say) if step.get("ai_draft") else "")
    if kind == "account_change":
        return account_sentence(step, say)
    if kind == "subject":
        return subject_sentence(step, say, clock)
    if kind == "qr_code":
        line = say("Read {n} codes from a saved image (SHA-256 {hash}): {texts}", n=len(step.get("codes") or []),
                   hash=step.get("media_sha256", "?"), texts="; ".join(quoted(text) for text in step.get("codes") or []))
        found = step.get("indicators") or []
        if found:
            line += " " + say("Found in them: {list}.", list=", ".join(
                say(item.get("kind", "")) + " " + str(item.get("value", "")) for item in found))
        return line + " " + say("The code text is what it encodes; who controls the address behind it is a separate question.")
    if kind == "presence":
        name = step.get("label") or ("@" + step["username"] if step.get("username") else say("Telegram ID {id}",
                                                                                             id=step.get("user_id", "?")))
        line = say("{who} is {state}.", who=name, state=say(PRESENCE_STATES.get(step.get("state"), step.get("state") or "?")))
        if step.get("before"):
            line = say("{who}: {before} → {state}.", who=name,
                       before=say(PRESENCE_STATES.get(step["before"], step["before"])),
                       state=say(PRESENCE_STATES.get(step.get("state"), step.get("state") or "?")))
        if step.get("was_online"):
            line += " " + say("Telegram gives the last time online as {at}.", at=clock(step["was_online"]))
        return line
    if kind == "peer_settings":
        parts = [say(PEER_FACTS[name], value=value) for name, value in (step.get("stated") or {}).items()]
        parts += [say(PEER_FLAGS[name]) for name in step.get("flags") or [] if name in PEER_FLAGS]
        line = say("Telegram changed what it offers for this chat: {parts}.", parts="; ".join(parts) or "—")
        return line + " " + say("These are Telegram's own hints about the other side; Telegram does not say why a hint "
                                "appeared.")
    if kind == "search_recorded":
        scope = say("{n} chats", n=len(step["chats"])) if step.get("chats") else say("all chats open to the investigator")
        line = say("Searched the saved archive for {query} in {scope}: {n} results.", query=quoted(step.get("query", "")),
                   scope=scope, n=step.get("matched", 0))
        if step.get("since") or step.get("until"):
            line += " " + say("Period {start} – {end}.", start=clock(step["since"]) if step.get("since") else "…",
                              end=clock(step["until"]) if step.get("until") else "…")
        if not step.get("matched"):
            line += " " + say("Recorded as a search with no results.")
        return line + (" " + say("Note: {text}", text=step["note"]) if step.get("note") else "")
    if kind == "ai_draft":
        line = say("AI drafts requested from {model} for the task {task}: {n} messages of this chat were sent to the "
                   "provider and {k} drafts suggested to the investigator.", model=step.get("model") or "?",
                   task=quoted(step.get("intent", "")), n=step.get("messages_sent", 0), k=step.get("drafts", 0))
        return line + " " + say("A draft becomes a message only if the investigator sends it.")
    if kind == "outcome":
        line = say(STATUS.get(step.get("status"), "Outcome: {status}."), status=step.get("status", ""))
        if step.get("error") or step.get("error_type"):
            line += " " + say("Reason: {reason}.", reason=step.get("error") or step.get("error_type"))
        if step.get("retry_after"):
            line += " " + say("Telegram asked to wait {n} s.", n=step["retry_after"])
        if step.get("answer"):
            line += " " + say("The bot answered the button press: {text}", text=quoted(step["answer"]))
        if step.get("answer_url"):
            line += " " + say("The answer pointed to {url}.", url=step["answer_url"])
        return line
    if kind in ("reply", "edited"):
        name = who(step, say)
        if kind == "edited":
            line = say("{name} edited message #{id}: {text}", name=name, id=step.get("message_id", "?"),
                       text=quoted(step.get("text", "")))
        elif step.get("reply_to_message_id"):
            line = say("{name} replied with message #{id} to #{to}: {text}", name=name, id=step.get("message_id", "?"),
                       to=step["reply_to_message_id"], text=quoted(step.get("text", "")))
        else:
            line = say("{name} wrote message #{id}: {text}", name=name, id=step.get("message_id", "?"),
                       text=quoted(step.get("text", "")))
        return line
    if kind == "self_check":
        line = say("Checked how the investigating account appears to others: {risks} risks, {notices} notices.",
                   risks=len(step.get("risks") or []), notices=step.get("notices", 0))
        for item in step.get("risks") or []:
            line += " " + say("{label}: {now}; recommended: {better}.", label=say(item.get("label") or ""),
                              now=say("visible to " + str(item.get("visible_to"))),
                              better=say("visible to " + str(item.get("recommended"))))
        return line
    if kind == "visual":
        line = say("Opened {url} in the isolated browser.", url=step.get("url", ""))
        if step.get("final_url") and step["final_url"] != step.get("url"):
            line += " " + say("It ended at {url}.", url=step["final_url"])
        if step.get("title"):
            line += " " + say("Page title: {title}.", title=quoted(step["title"]))
        if step.get("http_status"):
            line += " " + say("HTTP status {status}.", status=step["http_status"])
        if step.get("server_ip"):
            line += " " + say("Server address {ip}.", ip=step["server_ip"])
        if step.get("issuer"):
            line += " " + say("Certificate issuer: {issuer}.", issuer=step["issuer"])
        subject = step.get("subject") or {}
        if subject:
            shown = " · ".join(str(value) for value in (subject.get("title"), subject.get("telegram"),
                                                         "ID " + str(subject["chat_id"]) if subject.get("chat_id") is not None else None) if value)
            line += " " + say("Requested as the view of {who}; this caption comes from the workspace records, "
                              "not from the screenshot.", who=shown)
        if step.get("errors"):
            line += " " + say("Not captured: {parts}.", parts=", ".join(step["errors"]))
        return line
    if kind == "deleted":
        return say("A deletion notice was received for message #{id}.", id=step.get("message_id", "?"))
    if kind == "not_listed":
        return say("{n} more messages in this chat are not listed after this action.", n=step.get("count", 0))
    return kind


FIELD_NAMES = {"first_name": "first name", "last_name": "last name", "username": "username", "about": "bio"}


def drafted_note(source, say):
    if source.get("similarity", 0) >= 1:
        return say("The text is identical to an AI draft in record #{seq}.", seq=source.get("seq", "?"))
    return say("The text is based on an AI draft in record #{seq} ({p}% similar).", seq=source.get("seq", "?"),
               p=round(source.get("similarity", 0) * 100))


SUBJECT_KINDS = {"bot": "bot", "user": "person", "channel": "channel", "group": "group"}
SUBJECT_FIELDS = {"title": "name", "usernames": "usernames", "about": "bio or description", "bot_description":
                  "bot description", "commands": "bot commands", "photo_sha256": "profile photo", "flags": "Telegram labels",
                  "participants": "members"}


def shown_value(value, say):
    if isinstance(value, list):
        return ", ".join(str(item.get("command") if isinstance(item, dict) else item) for item in value) or say("(none)")
    return quoted(str(value)) if value not in (None, "") else say("(none)")


def subject_sentence(step, say, clock=same):
    names = ", ".join("@" + name for name in step.get("usernames") or [])
    ident = step.get("user_id") or step.get("chat_id")
    line = say("Profile snapshot of the {kind} {title}", kind=say(SUBJECT_KINDS.get(step.get("kind"), "chat")),
               title=quoted(step.get("title", ""))) + (" (" + names + ")" if names else "")         + (" · " + say("ID {id}", id=ident) if ident is not None else "") + "."
    if step.get("flags"):
        line += " " + say("Telegram labels: {labels}.", labels=", ".join(f.upper() for f in step["flags"]))
    if step.get("about"):
        line += " " + say("Bio: {text}", text=quoted(step["about"]))
    if step.get("bot_description"):
        line += " " + say("Bot description: {text}", text=quoted(step["bot_description"]))
    if step.get("commands"):
        line += " " + say("Commands: {list}.", list=", ".join("/" + str(c.get("command")) for c in step["commands"]))
    if step.get("participants"):
        line += " " + say("{n} members.", n=step["participants"])
    for change in step.get("changes") or []:
        line += " " + say("Changed {field}: {before} → {after}.", field=say(SUBJECT_FIELDS.get(change.get("field"),
                                                                                               change.get("field", ""))),
                          before=shown_value(change.get("before"), say), after=shown_value(change.get("after"), say))
    return line


def account_sentence(step, say):
    change = step.get("change")
    shown = lambda value: quoted(value) if value else say("(empty)")  # noqa: E731
    if change == "profile":
        parts = [say(FIELD_NAMES.get(item["field"], item["field"])) + ": " + shown(item.get("before")) + " → "
                 + shown(item.get("after")) for item in step.get("fields") or []]
        return say("The investigating account changed its profile: {changes}.",
                   changes="; ".join(parts) or say("no visible change"))
    if change == "privacy":
        parts = []
        for item in step.get("settings") or []:
            part = say(item.get("label") or "") + ": " + say("visible to " + str(item.get("before") or "?")) + " → " \
                + say("visible to " + str(item.get("after") or "?"))
            if item.get("exceptions_changed"):
                part += " (" + say("always allowed {a}, never allowed {d}", a=item.get("allow", 0), d=item.get("deny", 0)) + ")"
            parts.append(part)
        line = say("The investigating account changed privacy settings: {changes}.", changes="; ".join(parts) or "—")
        if step.get("failed"):
            line += " " + say("Not applied: {names}.", names=", ".join(say(name) for name in step["failed"]))
        return line
    if change == "options":
        parts = [say(item.get("label") or "") + ": " + say("on" if item.get("before") else "off") + " → "
                 + say("on" if item.get("after") else "off") for item in step.get("options") or []]
        return say("The investigating account changed account options: {changes}.", changes="; ".join(parts) or "—")
    if change == "photo_set":
        return say("The investigating account set a new profile photo (SHA-256 {hash}).", hash=step.get("sha256", "?"))
    return say("The investigating account removed its current profile photo.")


AFTER = {"request": "+{s} s after the request", "button press": "+{s} s after the button press",
         "message": "+{s} s after the message"}


def delay(step, say):
    parts = []
    if isinstance(step.get("after_seconds"), (int, float)):
        parts.append(say(AFTER.get(step.get("after"), "+{s} s after the action"), s=pretty(step["after_seconds"])))
    if isinstance(step.get("telegram_after_seconds"), (int, float)):
        parts.append(say("Telegram: +{s} s", s=pretty(step["telegram_after_seconds"])))
    return " · ".join(parts)


def overview(episode, say, clock=same):
    facts = episode.get("summary") or {}
    if not facts.get("actions") and not facts.get("replies"):
        line = say("From {start} to {end}.", start=clock(facts.get("from", "?")), end=clock(facts.get("to", "?")))
    else:
        line = say("From {start} to {end}: {actions} actions, {replies} replies or edits.",
                   start=clock(facts.get("from", "?")), end=clock(facts.get("to", "?")),
                   actions=facts.get("actions", 0), replies=facts.get("replies", 0))
    if "first_reply_seconds" in facts:
        line += " " + say("The fastest reply came {s} s after an action.", s=pretty(facts["first_reply_seconds"]))
    if facts.get("deletions"):
        line += " " + say("{n} deletion notices.", n=facts["deletions"])
    if facts.get("account_changes"):
        line += " " + say("{n} changes to the investigating account's profile or settings.", n=facts["account_changes"])
    if facts.get("ai_assisted"):
        line += " " + say("{n} sent messages are based on AI drafts.", n=facts["ai_assisted"])
    if facts.get("files"):
        line += " " + say("{n} files saved.", n=facts["files"])
    if facts.get("deceptive_links"):
        line += " " + say("{n} links show a different address than they open.", n=facts["deceptive_links"])
    if facts.get("risky_links"):
        line += " " + say("{n} links can expose the person who opens them or imitate another site.",
                          n=facts["risky_links"])
    return line


def warnings(step, say):
    e = lambda value: html.escape(str(value), quote=True)
    found = ""
    for item in step.get("deceptive_links") or []:
        found += ('<div class="warn">' + e(say("The link text {text} opens {href}", text=quoted(item.get("text") or ""),
                                              href=item.get("href") or "")) + "</div>")
    for item in step.get("risky_links") or []:
        found += ('<div class="warn">' + e(say(RISKS.get(item.get("risk"), "Risky link."))) + " <code>"
                  + e(item.get("href") or item.get("text") or "") + "</code></div>")
    return found


def render_text(model, say=plain_say):
    lines = []
    for episode in model["episodes"]:
        lines += ["", "== " + episode_title(episode, say) + " ==", overview(episode, say)]
        for step in episode["steps"]:
            lag = delay(step, say)
            lines.append((step.get("at") or "") + (" (" + lag + ")" if lag else "") + " — " + sentence(step, say))
            for item in step.get("indicators") or []:
                lines.append("    " + say("Found {kind}: {value}", kind=item["kind"], value=item["value"]))
    return "\n".join(lines[1:] + ["", *("* " + say(limit) for limit in model["limits"])])


def episode_title(episode, say):
    if episode.get("title"):
        return episode["title"]
    if episode.get("chat_id") is None:
        return say("Account check and isolated browser")
    return say("Chat {id}", id=episode["chat_id"])


def pictures(step, images, say):
    e = lambda value: html.escape(str(value), quote=True)
    found = ""
    for item in step.get("files") or []:
        source = (images or {}).get(item["sha256"])
        if source:
            found += ('<figure><img alt="' + e(say("Screenshot {sha}", sha=item["sha256"][:16])) + '" src="' + source
                      + '"><figcaption>SHA-256 <code>' + e(item["sha256"]) + "</code></figcaption></figure>")
    return found


def render_html(model, say=plain_say, images=None):
    e = lambda value: html.escape(str(value), quote=True)
    parts = []
    for episode in model["episodes"]:
        title = episode_title(episode, say)
        items = []
        for step in episode["steps"]:
            body = e(sentence(step, say))
            lag = delay(step, say)
            extra = ""
            if step.get("buttons"):
                extra += "<div>" + e(say("Buttons")) + ": " + e(" | ".join(" · ".join(map(str, row)) for row in step["buttons"])) + "</div>"
            if step.get("media"):
                extra += "<div>" + e(say("Attachment")) + ": " + e(", ".join(str(v) for v in step["media"].values())) + "</div>"
            for item in step.get("files") or []:
                extra += "<div>" + e(say("Saved file")) + " <code>" + e(item["sha256"]) + "</code></div>"
            extra += warnings(step, say)
            for item in step.get("indicators") or []:
                extra += "<div>" + e(say("Found {kind}: {value}", kind=item["kind"], value=item["value"])) \
                         + (" (" + e(item["chain"]) + ")" if item.get("chain") else "") + "</div>"
            extra += pictures(step, images, say)
            ref = step.get("ref") or {}
            items.append("<li><time>" + e(step.get("at") or "") + "</time>"
                         + (' <span class="lag">' + e(lag) + "</span>" if lag else "") + "<div>" + body + "</div>" + extra
                         + ('<div class="ref">' + e(say("Journal record #{seq}", seq=ref["seq"])) + " · <code>"
                            + e(ref.get("hash") or "") + "</code></div>" if ref.get("seq") else "") + "</li>")
        parts.append("<section><h2>" + e(title) + "</h2><p>" + e(overview(episode, say)) + "</p><ol>"
                     + "".join(items) + "</ol></section>")
    if not parts:
        parts.append("<p>" + e(say("No actions from this workspace were recorded.")) + "</p>")
    return ('<!doctype html><html lang="' + e(getattr(say, "language", "en")) + '"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'img-src data:; base-uri \'none\'; form-action \'none\'">'
            "<title>" + e(say("Action protocol")) + "</title><style>" + CHAT_STYLE + "</style>"
            "<h1>" + e(say("Action protocol")) + "</h1>" + "".join(parts)
            + "<h2>" + e(say("How to read this protocol")) + "</h2><ul>"
            + "".join("<li>" + e(say(limit)) + "</li>" for limit in model["limits"]) + "</ul></html>")
