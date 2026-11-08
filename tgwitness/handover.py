import hashlib
import json
import re
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import message_details, pdf_report, report, tuning, verification_kit
from .dossier import PHONE
from . import viewer
from .evidence import producer, report_entry, write_indicators, write_pdf, write_viewer
from .store import canonical, utcnow
from .verify import Coverage, fingerprint, verify_events

FORMAT = "tgwitness-handover-v1"
EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+(?![\w-])")
MENTION = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{3,31})(?!\w)")
MESSAGE_KINDS = ("message.new", "message.snapshot", "message.recovered", "message.edited")
GONE_KINDS = ("message.deleted", "message.missing_on_recheck")
MEDIA_KINDS = ("media.saved", "media.skipped", "media.failed", "media.retry")
GLOBAL_KEEP = frozenset((
    "process.started", "process.stopped", "observation.stopped", "coverage.gap", "connection.restored",
    "connection.retry", "connection.retry_failed", "collector.heartbeat", "clock.discontinuity", "telegram.backoff",
    "network.changed", "network.route_assigned", "network.route_rotated", "network.route_unavailable",
    "network.route_fallback", "network.policy_changed", "account.authorized", "account.signed_out",
    "monitoring.changed", "capture.changed", "parameters.changed", "recheck.changed", "evidence.changed",
    "anchor.completed", "storage.low", "storage.ok"))
CHAT_KEEP = frozenset((
    "target.changed", "target.priority", "target.removed", "source.added", "source.discovered", "coverage.gap",
    "snapshot.started", "snapshot.completed", "snapshot.interrupted", "chat_export.started", "chat_export.completed",
    "chat_export.interrupted", "source.access_unconfirmed", "dossier.changed"))
CHAT_PEOPLE = ("reaction.", "membership.", "chat.service", "source.profile")
LIMITS = [
    "This extract is part of a journal: chosen chats, period and people. Records left out are counted, not shown.",
    "Records marked as minimised have content withheld; their signature authenticates the original record, "
    "whose content can be confirmed against the complete journal by its hash.",
    "Pseudonyms (P01, P02…) are stable within this extract only; the mapping to real people is not included.",
    "Names written inside message texts are not detected; mentions of known participants are replaced.",
    "Coverage is computed from the complete journal for the chosen chats.",
    "Each record is an observation by this workspace's Telegram client, signed with the collector key in the manifest.",
]


class EmptySelection(ValueError):
    pass


class RemoteAttachment(ValueError):
    pass


class MissingAttachment(FileNotFoundError):
    pass


class Options(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    purpose: str = Field(min_length=3, max_length=1000)
    chats: list[int] = Field(min_length=1, max_length=200)
    since: datetime | None = None
    until: datetime | None = None
    subjects: list[int] = Field(default_factory=list, max_length=500)
    others: Literal["show", "pseudonymize", "omit"] = "pseudonymize"
    text: Literal["all", "subjects", "none"] = "all"
    attachments: Literal["subjects", "all", "none"] = "subjects"
    avatars: bool = False
    mask_contacts: bool = False
    case_board: Literal["off", "bookmarks", "comments"] = "off"
    board_pseudonyms: bool = True

    @field_validator("purpose")
    @classmethod
    def printable(cls, value):
        if any(ord(char) in report.HIDDEN_CODEPOINTS for char in value.replace("\n", " ").replace("\r", " ")):
            raise ValueError("Remove control and text-direction characters")
        return value

    @field_validator("since", "until")
    @classmethod
    def utc(cls, value):
        return value if value is None or value.tzinfo else value.replace(tzinfo=timezone.utc)

    @model_validator(mode="after")
    def coherent(self):
        if self.since and self.until and self.until <= self.since:
            raise ValueError("The end of the period must be after its start.")
        if self.others == "omit" and not self.subjects:
            raise ValueError("Choose the people to include, or show or pseudonymize everyone else.")
        self.chats, self.subjects = list(dict.fromkeys(self.chats)), list(dict.fromkeys(self.subjects))
        return self


def replace_ranges(text, ranges):
    data, end = text.encode("utf-16-le"), None
    for offset, length, value in sorted(ranges, reverse=True):
        if end is not None and offset + length > end:
            continue
        data = data[:2 * offset] + value.encode("utf-16-le") + data[2 * (offset + length):]
        end = offset
    return data.decode("utf-16-le", errors="replace")


def moment(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class Survey:
    def __init__(self, chats, gap_settings=None):
        # A handover holds chosen chats, so the account-wide numbering is not measurable from it.
        self.chats, self.people = set(chats), {}
        self.coverage = Coverage(gap_settings, chats_selected=True)
        self.requests, self.result_chats, self.head = {}, {}, None

    def add(self, event):
        chat, kind, payload = event["chat_id"], event["kind"], event["payload"]
        self.head = event
        if chat is None or chat in self.chats:
            self.coverage.add(event)
        if kind in MESSAGE_KINDS and chat in self.chats:
            sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
            person = payload.get("sender_id", sender.get("id"))
            if isinstance(person, int):
                known = self.people.setdefault(person, {"id": person, "username": None, "display_name": None, "messages": 0})
                known["username"] = sender.get("username") or known["username"]
                known["display_name"] = sender.get("display_name") or known["display_name"]
                known["messages"] += kind != "message.edited"
        elif kind == "interaction.requested":
            self.requests[event["seq"]] = (chat, payload.get("preview_event"))
        elif kind == "interaction.result":
            self.result_chats[payload.get("request_event")] = payload.get("chat_id", chat)

    def interactions(self):
        wanted = {seq for seq, (chat, _) in self.requests.items()
                  if chat in self.chats or self.result_chats.get(seq) in self.chats}
        return wanted, {self.requests[seq][1] for seq in wanted if self.requests[seq][1] is not None}


class Minimiser:
    def __init__(self, options, observer, people, requests=(), previews=()):
        self.o, self.observer = options, observer
        self.chats, self.subjects = set(options.chats), set(options.subjects)
        self.requests, self.previews = set(requests), set(previews)
        self.action_text = {}
        self.mentioned = {p["username"].casefold(): p["id"] for p in people.values() if p.get("username")}
        self.labels, self.messages, self.roles, self.files = {}, set(), {}, set()
        self.counts = {"unchanged": 0, "minimised": 0, "left_out": 0}

    def label(self, person):
        if person not in self.labels:
            self.labels[person] = "P%02d" % (len(self.labels) + 1)
        return self.labels[person]

    def shown(self, person):
        return self.o.others == "show" or person in self.subjects or person == self.observer \
            or not isinstance(person, int) or person < 0

    def role(self, person, outgoing):
        if outgoing or (person is not None and person == self.observer):
            return "observer"
        return "subject" if person in self.subjects else "other"

    def clean(self, text):
        if self.o.others != "show":
            text = MENTION.sub(lambda m: self.label(self.mentioned[m[1].casefold()])
                               if m[1].casefold() in self.mentioned and not self.shown(self.mentioned[m[1].casefold()])
                               else m[0], text)
        if self.o.mask_contacts:
            text = EMAIL.sub("[e-mail]", PHONE.sub("[phone]", text))
        return text

    def keep(self, event):
        self.counts["unchanged"] += 1
        return dict(event)

    def leave(self):
        self.counts["left_out"] += 1
        return None

    def minimise(self, event, payload, withheld, hide_actor=False):
        self.counts["minimised"] += 1
        record = {k: v for k, v in event.items() if k != "payload"}
        if hide_actor and record.get("actor_id") is not None:
            record["actor_id"] = None
            withheld = [*withheld, "actor_id"]
        record["payload"], record["minimised"] = payload, sorted(set(withheld))
        return record

    def present(self, event):
        kind, chat = event["kind"], event["chat_id"]
        if chat is None:
            if kind in GLOBAL_KEEP:
                return self.keep(event)
            if kind in ("observation.started", "scope.applied", "scope.changed", "recheck.completed"):
                return self.other_chats_removed(event)
            if kind == "interaction.preview" and event["seq"] in self.previews:
                return self.interaction(event)
            if kind == "interaction.requested" and event["seq"] in self.requests:
                return self.interaction(event)
            if kind == "interaction.result" and event["payload"].get("request_event") in self.requests:
                return self.interaction(event)
            return self.leave()
        if chat not in self.chats:
            return self.leave()
        if kind in MESSAGE_KINDS:
            return self.message(event)
        if kind in GONE_KINDS:
            return self.keep(event) if (chat, event["message_id"]) in self.messages else self.leave()
        if kind in MEDIA_KINDS:
            return self.attachment(event)
        if kind == "actor.avatar_saved":
            person = event["payload"].get("peer_id", event.get("actor_id"))
            if self.o.avatars and person in self.subjects | {self.observer}:
                self.files.add(event["payload"].get("media_sha256"))
                return self.keep(event)
            return self.leave()
        if kind in ("interaction.requested", "interaction.result"):
            return self.interaction(event) if (event["seq"] in self.requests
                                               or event["payload"].get("request_event") in self.requests) else self.leave()
        if kind in CHAT_KEEP:
            return self.keep(event)
        if kind.startswith(CHAT_PEOPLE) and self.o.others == "show":
            return self.keep(event)
        return self.leave()

    def interaction(self, event):
        payload, kind = event["payload"], event["kind"]

        def fields(value, names):
            return {key: self.clean(item) if isinstance(item, str) else item
                    for key, item in value.items() if key in names and
                    (item is None or isinstance(item, (str, int, float, bool)))}

        at = moment(event["observed_at"])
        in_period = at is not None and (not self.o.since or at >= self.o.since) \
            and (not self.o.until or at < self.o.until)

        def visible_text(role):
            return in_period and not (role == "other" and self.o.others == "omit") and (
                self.o.text == "all" or self.o.text == "subjects" and role != "other")

        if kind == "interaction.preview":
            shown = fields(payload, {"link", "title", "kind", "already_member", "request_needed"})
        elif kind == "interaction.requested":
            request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
            role = self.roles.get(request.get("keyboard_event"), "other") if request.get("action") == "press" else "observer"
            allowed = visible_text(role)
            self.action_text[event["seq"]] = allowed
            shown = fields(payload, {"account_id", "observation_running", "own_actions", "preview_event",
                                     "queued_until"})
            shown["request"] = fields(request, {"request_id", "action", "preview_id", "observe", "chat_id", "reply_to",
                                                 "message_id", "keyboard_event", "row", "column"})
            if request.get("action") == "send" and allowed and isinstance(request.get("text"), str):
                shown["request"]["text"] = self.clean(request["text"])
            button = payload.get("button")
            if isinstance(button, dict):
                shown["button"] = fields(button, {"type", "text"} if allowed else {"type"})
            elif button is None:
                shown["button"] = None
        else:
            shown = fields(payload, {"request_id", "request_event", "status", "chat_id", "message_id",
                                     "message_event", "error_type", "retry_after"})
            answer = payload.get("answer")
            if isinstance(answer, dict):
                names = {"cache_time", "alert", "has_url", "native_ui"}
                if in_period and self.action_text.get(payload.get("request_event"), False):
                    names |= {"message", "url"}
                shown["answer"] = fields(answer, names)
        hide_actor = event.get("actor_id") is not None and not self.shown(event["actor_id"])
        if shown == payload and not hide_actor:
            return self.keep(event)
        return self.minimise(event, shown, ["interaction details"], hide_actor)

    def other_chats_removed(self, event):
        payload, chats = event["payload"], self.chats
        shown = dict(payload)
        if isinstance(payload.get("targets"), list):
            shown["targets"] = [t for t in payload["targets"] if t in chats]
        if isinstance(payload.get("scope"), dict) and isinstance(payload["scope"].get("exclude"), list):
            shown["scope"] = {**payload["scope"], "exclude": [t for t in payload["scope"]["exclude"] if t in chats]}
        for field in ("exclude", "excluded", "paused", "resumed"):
            if isinstance(payload.get(field), list):
                shown[field] = [t for t in payload[field] if t in chats]
        for field in ("added", "chats"):
            if isinstance(payload.get(field), list):
                shown[field] = [t for t in payload[field] if isinstance(t, dict) and t.get("chat_id") in chats]
        if shown == payload:
            return self.keep(event)
        return self.minimise(event, shown, ["other chats"])

    def message(self, event):
        payload, key = event["payload"], (event["chat_id"], event["message_id"])
        person = payload.get("sender_id", event.get("actor_id"))
        role = self.role(person, payload.get("outgoing"))
        sent = moment(payload.get("sent_at") or event["observed_at"])
        in_period = sent is not None and (not self.o.since or sent >= self.o.since) \
            and (not self.o.until or sent < self.o.until)
        if not (in_period or key in self.messages) or (role == "other" and self.o.others == "omit"):
            return self.leave()
        self.messages.add(key)
        self.roles[event["seq"]] = role
        text = payload.get("text") if isinstance(payload.get("text"), str) else ""
        show_text = self.o.text == "all" or (self.o.text == "subjects" and role != "other")
        cleaned = self.clean(replace_ranges(text, self.hidden_names(payload.get("raw")))) if show_text else None
        if self.o.others == "show" and show_text and not self.o.mask_contacts and cleaned == text:
            return self.keep(event)
        hidden = role == "other" and self.o.others != "show"
        observed = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
        withheld = ["raw"] + (["text"] if text and not show_text else []) + (["sender"] if hidden else []) \
            + (["mentions or contact details"] if show_text and cleaned != text else [])
        shown = {"text": cleaned, "text_withheld": bool(text) and not show_text,
                 "sender_id": None if hidden else person,
                 "sender_observation": {"display_name": self.label(person)} if hidden
                 else {k: self.clean(observed[k]) if isinstance(observed[k], str) else observed[k]
                       for k in ("id", "username", "display_name", "flags") if k in observed},
                 "details": self.details(message_details.details(payload.get("raw")), role, show_text),
                 **{k: payload.get(k) for k in ("outgoing", "reply_to_message_id", "grouped_id", "sent_at", "edited_at",
                                                "has_media", "source")}}
        return self.minimise(event, shown, withheld, hide_actor=hidden)

    def hidden_names(self, raw):
        ranges = []
        for entity in (raw or {}).get("entities") or []:
            if isinstance(entity, dict) and entity.get("_") in ("MessageEntityMentionName", "InputMessageEntityMentionName") \
                    and isinstance(entity.get("offset"), int) and isinstance(entity.get("length"), int):
                person = entity.get("user_id")
                if isinstance(person, dict):
                    person = person.get("user_id")
                if person is not None and not self.shown(person):
                    ranges.append((entity["offset"], entity["length"], self.label(person)))
        return ranges

    def details(self, found, role, show_text):
        found = {k: v for k, v in found.items() if k in (
            "text_entities", "forwarded_from", "via_bot_id", "author", "views", "forwards", "buttons",
            "replies", "reactions", "auto_delete_seconds", "protected", "album_id", "media_info")}
        entities = []
        for item in (found.get("text_entities") or []) if show_text else []:
            item = {k: self.clean(v) if isinstance(v, str) else v for k, v in item.items()
                    if k in ("type", "text", "href", "user_id", "language", "document_id", "deceptive", "risk")}
            if isinstance(item.get("user_id"), dict):
                item["user_id"] = item["user_id"].get("user_id")
            hidden = item.get("user_id") is not None and not self.shown(item["user_id"])
            if hidden:
                item["user_id"] = item["text"] = self.label(item["user_id"])
                item.pop("href", None)
            elif item["type"] in ("phone", "email") and self.o.mask_contacts:
                item["text"] = "[phone]" if item["type"] == "phone" else "[e-mail]"
            else:
                item["text"] = self.clean(item["text"])
            entities.append(item)
        found.pop("text_entities", None)
        if entities:
            found["text_entities"] = entities
        forward = dict(found.get("forwarded_from") or {})
        for field in ("from_id", "saved_from_id"):
            if forward.get(field) is not None and not self.shown(forward[field]):
                forward[field] = self.label(forward[field])
        if self.o.others != "show" or not show_text:
            for field in ("from_name", "post_author"):
                forward.pop(field, None)
        else:
            forward = {k: self.clean(v) if isinstance(v, str) else v for k, v in forward.items()}
        found.pop("forwarded_from", None)
        if forward:
            found["forwarded_from"] = forward
        if found.get("via_bot_id") is not None and not self.shown(found["via_bot_id"]):
            found["via_bot_id"] = self.label(found["via_bot_id"])
        if not show_text or (role == "other" and self.o.others != "show"):
            found.pop("author", None)
        elif isinstance(found.get("author"), str):
            found["author"] = self.clean(found["author"])
        if not show_text:
            found.pop("buttons", None)
        elif found.get("buttons"):
            rows = []
            for row in found["buttons"].get("rows", []):
                buttons = []
                for button in row:
                    item = {k: self.clean(v) if isinstance(v, str) else v for k, v in button.items()
                            if k in ("type", "text", "url", "query", "copy_text", "user_id", "fwd_text")}
                    if item.get("user_id") is not None and not self.shown(item["user_id"]):
                        item["user_id"] = item["text"] = self.label(item["user_id"])
                    buttons.append(item)
                rows.append(buttons)
            found["buttons"] = {"inline": bool(found["buttons"].get("inline")), "rows": rows}
        if found.get("media_info"):
            technical = {"kind", "mime_type", "size", "document_id", "photo_id", "dc_id", "width", "height",
                         "duration_seconds", "self_destruct_seconds", "ephemeral_media"}
            textual = {"url", "site_name", "title", "file_name"} if show_text else set()
            if role == "other" and self.o.others != "show":
                textual.discard("file_name")
            found["media_info"] = {k: self.clean(v) if isinstance(v, str) else v
                                   for k, v in found["media_info"].items() if k in technical | textual}
        return found

    def attachment(self, event):
        payload = event["payload"]
        role = self.roles.get(payload.get("message_event"))
        if role is None:
            return self.leave()
        allowed = self.o.attachments == "all" or (self.o.attachments == "subjects" and role != "other")
        if event["kind"] != "media.saved":
            return self.keep(event)
        if not allowed:
            return self.leave()
        self.files.add(payload.get("media_sha256"))
        if role == "other" and self.o.others != "show" and payload.get("original_name"):
            return self.minimise(event, {k: v for k, v in payload.items() if k != "original_name"}, ["file name"])
        return self.keep(event)


def selection_text(options, titles, people, minimiser):
    subject = lambda person: " · ".join(x for x in ((people.get(person) or {}).get("display_name"),
                                                    "@" + people[person]["username"] if (people.get(person) or {}).get("username") else "",
                                                    "id " + str(person)) if x)
    return {"chats": [titles.get(chat) or str(chat) for chat in options.chats],
            "since": options.since.isoformat() if options.since else None,
            "until": options.until.isoformat() if options.until else None,
            "subjects": [subject(person) for person in options.subjects],
            "others": options.others, "text": options.text, "attachments": options.attachments,
            "avatars": options.avatars, "mask_contacts": options.mask_contacts,
            "pseudonyms": len(minimiser.labels)}


def export(store, vault, options, report_options=None):
    report_options = report_options or report.resolved()
    directory = store.root / "temporary-exports"
    directory.mkdir(mode=0o700, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(prefix="tgwitness-handover-", suffix=".zip", dir=directory, delete=False)
    path = Path(temp.name)
    temp.close()
    records_path = path.with_suffix(".jsonl")
    try:
        account = store.get_setting("account", None) or {}
        with store.snapshot() as snapshot:
            from .gap_analysis import settings as gap_settings
            survey = Survey(options.chats, gap_settings(store))

            def surveyed(events):
                for event in events:
                    survey.add(event)
                    yield event
            checked = verify_events(surveyed(snapshot.events()), vault.public_key)
            requests, previews = survey.interactions()
            minimiser = Minimiser(options, account.get("id"), survey.people, requests, previews)
            with records_path.open("wb") as out:
                for event in snapshot.events():
                    shown = minimiser.present(event)
                    if shown is not None:
                        out.write(canonical(shown) + b"\n")
            titles = {t["chat_id"]: t["title"] for t in store.targets()
                      if t["chat_id"] in minimiser.chats and t.get("title")}
            from .board_handover import prepare as prepare_board
            board_export = prepare_board(snapshot, records_path, vault, options, minimiser)
        if not minimiser.messages:
            raise EmptySelection("No message in the journal matches these chats, period and people.")
        head = survey.head or {}
        journal = {"event_count": checked["events"], "head_hash": checked["head_hash"],
                   "head_signature": head.get("signature")}
        coverage = survey.coverage.result()

        def records():
            with records_path.open("rb") as handle:
                for line in handle:
                    yield json.loads(line)

        digest = report.Digest()
        for record in records():
            digest.add(record)
        digest.hash_images(store.root / "media")
        summary = digest.result()
        summary["titles"] = {**titles, **summary["titles"]}
        selection = selection_text(options, summary["titles"], survey.people, minimiser)
        hashes, total, limit = {}, 0, tuning.value(store, "export_max_gib") * 1024**3
        created = utcnow()
        context = {"kind": "handover", "options": report_options, "report_id": str(uuid.uuid4()), "created_at": created,
                   "producer": producer(), "limits": LIMITS, "public_key": vault.public_key,
                   "fingerprint": checked["fingerprint"], "event_count": checked["events"],
                   "head_hash": checked["head_hash"], "digest": summary, "anchors": [], "files": {},
                   "account": account or None, "archive": True, "sign": vault.sign, "events_again": records,
                   "journal_verified": True,
                   "handover": {"purpose": options.purpose, "selection": selection, "counts": dict(minimiser.counts)}}
        if board_export:
            context["case_board"] = board_export["statement"]["material"]
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            def write_member(name, values):
                nonlocal total
                sha = hashlib.sha256()
                with archive.open(name, "w", force_zip64=True) as outgoing:
                    for chunk in values:
                        total += len(chunk)
                        if total > limit - 4 * 1024**2:
                            raise ValueError("Bundle exceeds the uncompressed size limit set in Parameters")
                        outgoing.write(chunk)
                        sha.update(chunk)
                hashes[name] = sha.hexdigest()
                return hashes[name]

            with records_path.open("rb") as handle:
                write_member("records.jsonl", iter(lambda: handle.read(1024 * 1024), b""))
            write_member("coverage.json", [json.dumps(coverage, ensure_ascii=False, indent=1).encode("utf-8")])
            if board_export:
                write_member("case-board.json", [canonical(board_export)])
            write_member("verify.py", [Path(__file__).with_name("verify.py").read_bytes()])
            verification_kit.write(write_member, report_options.get("language", "en"))
            write_indicators(write_member, summary.get("indicators"), context)
            for name in sorted(x for x in minimiser.files if isinstance(x, str) and re.fullmatch("[0-9a-f]{64}", x)):
                source = store.root / "media" / name
                if not source.is_file():
                    if (store.root / "storage.sqlite3").exists():
                        from .storage import Receipts
                        receipts = Receipts(store.root)
                        try:
                            receipt = receipts.get(name)
                        finally:
                            receipts.close()
                        if receipt and receipt["evicted"]:
                            raise RemoteAttachment("A selected attachment is in remote storage. Open Storage → Restore all files, "
                                                   "then create the handover again, or explicitly omit attachments.")
                    raise MissingAttachment("A selected attachment is missing. Restore the file, then create the "
                                            "handover again, or explicitly omit attachments.")
                with source.open("rb") as incoming:
                    if write_member("media/" + name, iter(lambda: incoming.read(1024 * 1024), b"")) != name:
                        raise ValueError("Attachment changed: " + name)
            context["records_sha256"] = hashes["records.jsonl"]
            write_member("custody.json", [json.dumps(report.custody(context), ensure_ascii=False,
                                                     indent=1).encode("utf-8")])
            if report_options.get("timeline"):
                context["viewer"] = write_viewer(write_member, "journal",
                    (viewer.journal_item(event, report_options.get("raw_records", True)) for event in records()),
                    None, summary.get("indicators"), report_options)
            context["files"] = dict(hashes)
            data = report.report_data(records, coverage, context)
            write_member("report.json", [report.sealed_json(data, context)])
            write_pdf(write_member, "report.pdf", lambda: pdf_report.report_pdf(data, context, vault, records()))
            context["files"] = dict(hashes)
            write_member("report.html", report.evidence_chunks(records(), coverage, context))
            listed = {**hashes, **dict.fromkeys(("README.txt", "SHA256SUMS", "manifest.json", "manifest.sig"), "")}
            write_member("README.txt", [verification_kit.quickstart(report_options.get("language", "en")), b"\n",
                                       report.readme(context, listed, "\n".join(LIMITS) + "\n")])
            write_member("SHA256SUMS", [report.sha256sums(hashes)])
            manifest = {"format": FORMAT, "created_at": created, "public_key": vault.public_key,
                        "fingerprint": fingerprint(vault.public_key), "producer": producer(),
                        "case": report.case_of(report_options), "purpose": options.purpose,
                        "journal": journal, "selection": options.model_dump(mode="json"),
                        "counts": dict(minimiser.counts), "pseudonyms": len(minimiser.labels), "limitations": LIMITS,
                        "report": report_entry(context, report_options), "files": hashes,
                        "case_assessment": data["case_assessment"]}
            manifest_bytes = canonical(manifest)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sig", vault.sign(manifest_bytes))
        summary_record = {"purpose": options.purpose, "selection": options.model_dump(mode="json"),
                          "counts": dict(minimiser.counts), "pseudonyms": len(minimiser.labels),
                          "journal_event_count": checked["events"], "journal_head_hash": checked["head_hash"]}
        return path, summary_record
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        records_path.unlink(missing_ok=True)
