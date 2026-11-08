from . import render_data
import base64
import difflib
import hashlib
import html
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from . import __version__, case_assessment, i18n, message_details, metrics, report_analytics, report_charts, snapshot_analytics
from . import report_design, report_history, report_layouts, report_selection, report_selection_view
from . import indicators as ioc
from . import viewer
from .store import canonical, utcnow
from .verify import (SEAL_CLOSE, SEAL_OPEN, coverage_lines, fingerprint, fingerprint_colors, ots_summary,
                     timestamp_reply_summary, timestamp_signature, verify_checkpoint)

SEAL_FORMAT = "tgwitness-report-seal-v1"
CUSTODY_FORMAT = "tgwitness-custody-v1"
RTL = ("ar", "fa", "ur", "he")
HIDDEN_CODEPOINTS = frozenset((*range(0x00, 0x09), *range(0x0B, 0x20), *range(0x7F, 0xA0),
                             0x200E, 0x200F, 0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A)))


class ReportOptions(report_analytics.Presentation):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    language: str = Field(default="auto", max_length=16)
    case_title: str = Field(default="", max_length=200)
    case_id: str = Field(default="", max_length=80)
    examiner: str = Field(default="", max_length=120)
    organization: str = Field(default="", max_length=160)
    notes: str = Field(default="", max_length=4000)
    theme: Literal["auto", "light", "dark"] = "auto"
    timeline: bool = True
    raw_records: bool = True
    media_previews: bool = True
    show_changes: bool = True
    show_indicators: bool = True
    case_board: Literal["off", "bookmarks", "comments"] = "bookmarks"
    part_size: int = Field(default=5000, ge=500, le=100000)
    group_heartbeats: bool = True
    template: Literal["dossier", "brief", "activity", "custom"] = "dossier"
    review_question: str = Field(default="", max_length=2000)
    review_method: str = Field(default="", max_length=4000)
    review_findings: str = Field(default="", max_length=8000)
    review_conclusion: str = Field(default="", max_length=4000)
    selection: report_selection.Selection = Field(default_factory=report_selection.Selection)

    @field_validator("language")
    @classmethod
    def supported(cls, value):
        if value != "auto" and value not in i18n.LANGUAGES:
            raise ValueError("Unsupported report language")
        return value

    @field_validator("case_title", "case_id", "examiner", "organization", "notes",
                     "review_question", "review_method", "review_findings", "review_conclusion")
    @classmethod
    def printable(cls, value, info):
        value = value.replace("\r\n", "\n")
        multiline = info.field_name == "notes" or info.field_name.startswith("review_")
        if any(ord(char) in HIDDEN_CODEPOINTS for char in value) or (not multiline and ("\n" in value or "\t" in value)):
            raise ValueError("Remove control and text-direction characters")
        return value


def saved(store):
    try:
        return ReportOptions.model_validate(store.get_setting("report_options", {}) or {})
    except ValueError:
        return ReportOptions()


def save(store, options):
    store.set_setting("report_options", options.model_dump())
    return options


def resolved(store=None, language_hint="en"):
    options = (saved(store) if store is not None else ReportOptions()).model_dump()
    if options["language"] == "auto":
        options["language"] = language_hint if language_hint in i18n.LANGUAGES else "en"
    return options


def case_of(options):
    options = options or {}
    return {key: options[name] for key, name in (("title", "case_title"), ("id", "case_id"), ("examiner", "examiner"),
                                                 ("organization", "organization"), ("notes", "notes"))
            if options.get(name)}


class Words:
    def __init__(self, language):
        self.language = language if language in i18n.LANGUAGES else "en"
        self.table = i18n.words(self.language)
        self.direction = "rtl" if self.language in RTL else "ltr"

    def __call__(self, text, /, **values):
        text = self.table.get(text, text)
        if isinstance(text, dict):
            text = text.get("other") or next(iter(text.values()))
        for name, value in values.items():
            text = text.replace("{" + name + "}", str(value))
        return text


def text_keys():
    import ast
    from pathlib import Path
    from .chat_export import EXPORT_LIMITS, JOURNAL_LIMIT
    from .evidence import LIMITS
    from . import report_composition_pdf
    sources = (Path(__file__), Path(__file__).with_name("pdf_report.py"))
    keys = [node.args[0].value for source in sources for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "say"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    return list(dict.fromkeys(keys + case_assessment.text_keys() + report_charts.text_keys() + snapshot_analytics.text_keys() + report_selection_view.text_keys() + report_layouts.text_keys() + report_composition_pdf.text_keys() + list(SCRIPT_WORDS) + LIMITS + EXPORT_LIMITS + [JOURNAL_LIMIT] + list(MEDIA_NAMES.values()) + ["Media"]
                              + list(ROUTE_KINDS.values()) + list(EXPOSURES.values()) + list(FILE_STATUS.values())
                              + list(ACTION_NAMES.values()) + [label for _, label in OUTCOMES.values()]
                              + ["Action", "no result recorded"] + list(OTHERS.values()) + list(TEXTS.values())
                              + list(FILES.values()) + list(WITHHELD.values())))


def e(value):
    return html.escape("" if value is None else str(value))


def script_json(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def utc_text(value, seconds=True):
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        moment = moment.astimezone(timezone.utc) if moment.tzinfo else moment
        return moment.strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M") + " UTC"
    except ValueError:
        return str(value)


def when(value):
    if not value:
        return "—"
    return '<time datetime="' + e(value) + '">' + e(utc_text(value)) + "</time>"


def num(value):
    return '<span data-n="' + e(value) + '">' + e(value) + "</span>" if type(value) is int else e(value)


def short(value, head=12, tail=6):
    value = str(value or "")
    return value if len(value) <= head + tail + 1 else value[:head] + "…" + value[-tail:]


def grouped(value):
    return " ".join(value[i:i + 4] for i in range(0, len(value), 4))


def span_text(say, first, last):
    try:
        seconds = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()
    except (TypeError, ValueError):
        return "—"
    days, rest = divmod(int(seconds), 86400)
    if days:
        return say("{n} d", n=days) + " " + say("{n} h", n=rest // 3600)
    if rest >= 3600:
        return say("{n} h", n=rest // 3600) + " " + say("{n} min", n=rest % 3600 // 60)
    return say("{n} min", n=rest // 60)


def size_text(value):
    if type(value) is not int:
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return (str(value) if unit == "B" else "%.1f" % value) + " " + unit
        value /= 1024


CATEGORY_ORDER = ("message", "edited", "deleted", "missing", "media", "reaction", "member", "system")
CATEGORIES = {"message.new": "message", "message.snapshot": "message", "message.recovered": "message",
              "message.edited": "edited", "message.deleted": "deleted", "message.missing_on_recheck": "missing",
              "media.saved": "media", "media.hashed": "media"}
TITLE_KINDS = ("target.changed", "source.discovered", "target.removed")
VERSION_KINDS = ("message.new", "message.snapshot", "message.recovered", "message.edited")
CHANGE_KINDS = ("message.edited", "message.deleted", "message.missing_on_recheck")
HISTORY_LIMIT = 1000
ACTION_LIMIT = 500
CLOCK_LIMIT = 500
IMAGES = ("image/jpeg", "image/png", "image/webp", "image/gif")


def category(kind):
    return CATEGORIES.get(kind) or ("reaction" if kind.startswith("reaction.") else
                                    "member" if kind.startswith("membership.") else "system")


def category_label(say, name):
    return {"message": say("Messages"), "edited": say("Edits"), "deleted": say("Deletions"), "media": say("Files"),
            "missing": say("Missing on recheck"),
            "reaction": say("Reactions"), "member": say("Membership"), "system": say("System")}[name]


def kind_label(say, kind):
    return {"message.new": say("New message"), "message.snapshot": say("History snapshot"),
            "message.recovered": say("Recovered message"), "message.edited": say("Edited message"),
            "message.deleted": say("Deletion notice"), "message.missing_on_recheck": say("Missing on recheck"),
            "media.saved": say("Saved file"), "media.hashed": say("File hashes; content not downloaded")}.get(kind, kind)


class Digest:
    def __init__(self, processors=None, rows_listed=60):
        self.categories = dict.fromkeys(CATEGORY_ORDER, 0)
        self.chats, self.titles, self.media, self.senders = {}, {}, {}, set()
        self.first = self.last = self.first_hash = None
        self.clients, self.routes, self.direct = {}, {}, {"count": 0, "first": None, "last": None}
        self.clocks = []
        self.indicators = ioc.Indicators()
        self.changed = set()
        self.actions, self.previews, self.action_count = {}, {}, 0
        self.own_messages, self.own_total, self.own_scope = [], 0, set()
        self.trust_signals = {"drand": 0, "starts": 0, "tdx": 0}
        self.analytics = report_analytics.Analytics()
        self.metrics = metrics.Pipeline(processors, rows_listed)

    @staticmethod
    def seen(table, value, at):
        key = canonical({k: v for k, v in value.items() if k != "proxy_id"}).decode()
        entry = table.setdefault(key, {"value": value, "first": at, "last": at, "count": 0})
        entry["last"], entry["count"] = at, entry["count"] + 1

    def add(self, event):
        self.analytics.add(event)
        self.metrics.add(event)
        kind, payload, chat = event["kind"], event["payload"], event["chat_id"]
        if kind == "beacon.drand":
            self.trust_signals["drand"] += 1
        if kind == "process.started":
            self.trust_signals["starts"] += 1
            if isinstance(payload.get("run"), dict) and payload["run"].get("tdx_start"):
                self.trust_signals["tdx"] += 1
        self.categories[category(kind)] += 1
        self.first, self.last = self.first or event["observed_at"], event["observed_at"]
        self.first_hash = self.first_hash or event["hash"]
        if kind in ("observation.started", "account.authorized") and isinstance(payload.get("client"), dict):
            self.seen(self.clients, payload["client"], event["observed_at"])
        if kind == "observation.started" and isinstance(payload.get("route"), dict):
            self.seen(self.routes, payload["route"], event["observed_at"])
        if kind == "observation.started" and isinstance(payload.get("clock"), dict) and len(self.clocks) < CLOCK_LIMIT:
            self.clocks.append({**payload["clock"], "seq": event["seq"]})
        if kind == "network.route_fallback":
            self.direct.update(count=self.direct["count"] + 1, last=event["observed_at"],
                               first=self.direct["first"] or event["observed_at"])
        if kind in CHANGE_KINDS and chat is not None and event["message_id"] is not None:
            self.changed.add((chat, event["message_id"]))
        if chat is not None:
            self.chats[chat] = self.chats.get(chat, 0) + 1
            if kind in TITLE_KINDS and isinstance(payload.get("title"), str):
                self.titles[chat] = payload["title"]
        if kind == "scope.applied":
            for added in payload.get("added") or []:
                if isinstance(added, dict) and isinstance(added.get("title"), str):
                    self.titles[added.get("chat_id")] = added["title"]
        if CATEGORIES.get(kind) == "message" and payload.get("sender_id") is not None:
            self.senders.add(payload["sender_id"])
        if CATEGORIES.get(kind) in ("message", "edited"):
            self.indicators.message(payload.get("text"), shown_details(payload),
                                    {"chat": chat, "message": event["message_id"], "seq": event["seq"]},
                                    event["observed_at"])
        if kind == "webapp.inspected" and isinstance(payload.get("addresses"), list):
            from .webapp import note_indicators
            note_indicators(self.indicators, payload["addresses"], "mini app",
                            {"chat": chat, "message": event["message_id"], "seq": event["seq"]},
                            event["observed_at"])
        digest = payload.get("media_sha256") if kind == "media.saved" else None
        if isinstance(digest, str):
            self.media[digest] = {"mime_type": payload.get("mime_type"), "size": payload.get("size"),
                                  "ref": {"chat": chat, "message": event["message_id"], "seq": event["seq"]},
                                  "at": event["observed_at"]}
        self.add_action(event)

    def hash_images(self, folder):
        for digest, info in self.media.items():
            if str(info.get("mime_type") or "").startswith("image/") and (folder / digest).is_file():
                self.indicators.image(digest, folder / digest, info.get("ref"), info.get("at"))

    def add_action(self, event):
        kind, payload, at = event["kind"], event["payload"], event["observed_at"]
        if kind == "observation.started" and isinstance(payload.get("scope"), dict) \
                and isinstance(payload["scope"].get("own_actions"), bool):
            self.own_scope.add(payload["scope"]["own_actions"])
        elif kind == "interaction.preview" and len(self.previews) < ACTION_LIMIT:
            self.previews[event["seq"]] = {"link": payload.get("link"), "title": payload.get("title")}
        elif kind == "interaction.requested":
            self.action_count += 1
            if len(self.actions) < ACTION_LIMIT:
                request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
                self.actions[event["seq"]] = {"seq": event["seq"], "at": at, "chat": event["chat_id"],
                                              "request": request, "button": payload.get("button"),
                                              "preview": self.previews.get(payload.get("preview_event")),
                                              "result": None}
        elif kind == "interaction.result" and payload.get("request_event") in self.actions:
            answer = payload.get("answer") if isinstance(payload.get("answer"), dict) else {}
            self.actions[payload["request_event"]]["result"] = {
                "seq": event["seq"], "status": payload.get("status"), "chat": payload.get("chat_id"),
                "message_event": payload.get("message_event"), "error_type": payload.get("error_type"),
                "answer": answer.get("message"), "answer_url": answer.get("url")}
        elif kind in ("message.new", "message.recovered") and payload.get("outgoing") \
                and payload.get("source") != "panel_action":
            self.own_total += 1
            if len(self.own_messages) < ACTION_LIMIT:
                self.own_messages.append({"seq": event["seq"], "at": at, "chat": event["chat_id"],
                                          "text": (payload.get("text") or "")[:300]})

    def result(self):
        return {"categories": self.categories, "chats": self.chats, "titles": self.titles, "media": self.media,
                "senders": len(self.senders), "first": self.first, "last": self.last, "first_hash": self.first_hash,
                "clients": list(self.clients.values()), "routes": list(self.routes.values()), "clocks": self.clocks,
                "indicators": self.indicators.result(), "trust_signals": dict(self.trust_signals),
                "direct_fallbacks": self.direct, "changed": self.changed,
                "actions": list(self.actions.values()), "action_count": self.action_count,
                "own_messages": self.own_messages, "own_total": self.own_total, "own_scope": sorted(self.own_scope),
                "analytics": self.analytics.result(), "processors": self.metrics.result()}


def describe_anchor(checkpoint_name, checkpoint, proof_name, proof, query=None, *, public_key=None,
                    event_count=None, hash_at=None):
    digest = hashlib.sha256(checkpoint).digest()
    stem = checkpoint_name[:-len(".json")]
    entry = {"checkpoint": checkpoint_name, "file": "anchors/" + proof_name, "checkpoint_bound": False,
             "service": proof_name[len(stem) + 1:].rsplit(".", 1)[0]}
    try:
        entry["event_count"] = json.loads(checkpoint)["statement"]["event_count"]
        if public_key is not None and event_count is not None and hash_at is not None:
            verify_checkpoint(json.loads(checkpoint), public_key, event_count, hash_at)
            entry["checkpoint_bound"] = True
        if proof_name.endswith(".tsr"):
            entry.update(kind="rfc3161", time=timestamp_reply_summary(proof, digest, query)["time"])
            try:
                from .tsa_roots import trusted_roots
                entry["signed"] = timestamp_signature(proof, trusted_roots(), include_reference=True)
            except Exception as exc:
                entry["signed"] = None
                entry["signature_error"] = type(exc).__name__
        else:
            entry.update(kind="opentimestamps", status=ots_summary(proof, digest)["status"])
    except Exception as exc:
        entry.update(kind="unreadable", error=type(exc).__name__)
    return entry


def rfc3161_count(anchors, *, validated=False):
    return sum(1 for a in anchors if a.get("kind") == "rfc3161"
               and (not validated or case_assessment.verified_stamp(a, 2**63 - 1)))


def stamps_text(say, anchors):
    rfc, latest = rfc3161_count(anchors), latest_stamp(anchors)
    ots = sum(1 for a in anchors if a.get("kind") == "opentimestamps")
    if not rfc and not ots:
        return say("None in this export: times rely on the collector's clock.")
    text = say("{a} RFC 3161 · {b} OpenTimestamps", a=rfc, b=ots)
    if latest:
        text += " · " + say("latest: record #{n}, {time}, {service}", n=latest.get("event_count"),
                            time=utc_text(latest.get("time")), service=latest.get("service"))
    return text


def latest_stamp(anchors):
    stamped = [a for a in anchors if case_assessment.verified_stamp(a, 2**63 - 1)]
    return max(stamped, key=lambda a: (a.get("event_count") or 0, a.get("time") or "")) if stamped else None


def standards(say, kind="evidence", stamps=0):
    rows = [
        ("ISO/IEC 27037:2012", say("Identification, collection, acquisition and preservation of digital evidence"),
         say("Capture time, tool, method and account are recorded; every record is hashed and signed when it is captured.")),
        ("ISO/IEC 27042:2015", say("Analysis and interpretation of digital evidence"),
         say("Authoritative files and readable derivatives are kept apart; limitations are stated with the results.")),
        ("NIST SP 800-86", say("Integrating forensic techniques into incident response"),
         say("Collection, examination, analysis and reporting are separate, documented steps.")),
        ("Berkeley Protocol (OHCHR, 2022)", say("Digital open source investigations"),
         say("Source identifiers, capture times, collector and hash values are preserved with each item.")),
    ]
    if stamps:
        rows += [("RFC 3161", say("Time-Stamp Protocol"),
                  say("Journal checkpoints in this export are stamped by independent timestamp authorities; see Timestamps.")),
                 ("eIDAS, Art. 41", say("Qualified electronic time stamps (EU)"),
                  say("Checked here: the token's signature and the recorded bytes it covers."))]
    else:
        rows.append(("RFC 3161", say("Time-Stamp Protocol"),
                     say("Not used: a chat export is not timestamped.") if kind == "chat" else
                     say("Not used in this extract: timestamps cover the complete journal and are checked with the "
                         "full archive.") if kind == "handover" else
                     say("No independently validated checkpoint timestamp in this copy.")))
    return rows + [
        ("RFC 8032 · FIPS 180-4", say("Ed25519 signatures · SHA-256 hashes"),
         say("Records and the manifest are signed with Ed25519; files and records are identified by SHA-256.")),
        ("ISO 8601 · RFC 3339", say("Date and time format"),
         say("All times are written in UTC with an explicit offset.")),
        ("ISO 15836 (Dublin Core) · schema.org", say("Document metadata"),
         say("Reports carry machine-readable metadata for case-management and archiving systems.")),
    ]


def file_purpose(say, name):
    if name.startswith("viewer/"):
        return say("Viewer data: checked against the report seal before display")
    if name.startswith("media/"):
        return say("Saved file, named by its SHA-256")
    if name.startswith("anchors/"):
        return say("Timestamp answer") if not name.endswith(".json") else say("Signed checkpoint that was timestamped")
    if name.startswith(("records/", "messages/")):
        return say("Part of a long list, a sealed page of its own")
    return {
        "report.json": say("The report as signed JSON, for case systems and scripts"),
        "report.pdf": say("The report as a signed PDF, for printing and filing"),
        "indicators.csv": say("Indicators for spreadsheets: links, domains, wallets, accounts (formula-safe)"),
        "indicators.stix.json": say("The same indicators as a STIX 2.1 bundle"),
        "indicators.misp.json": say("The same indicators as a MISP event"),
        "chat.pdf": say("The report as a signed PDF, for printing and filing"),
        "message-ids.json": say("Message numbers: present, absent and every absent run"),
        "events.jsonl": say("Authoritative journal: one signed record per line"),
        "records.jsonl": say("The records of this extract, signed; minimised ones name what was withheld"),
        "events.csv": say("The same records for spreadsheets (formula-safe)"),
        "report.html": say("This readable report, sealed"),
        "coverage.json": say("Observation periods, gaps and message IDs never observed"),
        "custody.json": say("Chain of custody and acquisition details"),
        "SHA256SUMS": say("SHA-256 checksums of the listed payload files, for sha256sum -c"),
        "verify.py": say("Standalone verifier (Python 3.11+, cryptography)"),
        "VERIFY.cmd": "Windows verification launcher",
        "VERIFY.sh": "macOS/Linux verification launcher (sh VERIFY.sh)",
        "START_HERE.txt": "Verification quick start",
        "README.txt": say("Instructions in the report language and in English"),
        "manifest.json": say("Signed list of every file with its SHA-256"),
        "manifest.sig": say("Ed25519 signature of manifest.json"),
        "chat.json": say("Authoritative messages, Telegram-export style"),
        "chat.html": say("Readable chat, sealed"),
        "admin-log.json": say("The chat's admin log as Telegram returned it: deletions and edits with the acting account"),
        "authors.json": say("Everyone who posted, with message counts"),
        "authors.csv": say("The same list for spreadsheets"),
    }.get(name, "")


def sha256sums(hashes):
    return "".join(hashes[name] + "  " + name + "\n" for name in sorted(hashes)).encode("utf-8")


def custody(context):
    say = Words("en")
    options, kind = context["options"], context["kind"]
    record = {
        "format": CUSTODY_FORMAT, "report_id": context["report_id"], "created_at": context["created_at"],
        "case": case_of(options),
        "acquisition": {
            "tool": context["producer"],
            "method": ("Telegram client (MTProto) observing the account below; each record is chained by SHA-256 "
                       "and signed with Ed25519 when it is written" if kind == "evidence" else
                       "Full visible history read through the Telegram API by the account below; a current snapshot"),
            "account": context.get("account"),
        },
        "export": {"created_at": context["created_at"], "by": options.get("examiner") or None,
                   "organization": options.get("organization") or None,
                   "host": {"os": platform.system() + " " + platform.release(), "python": platform.python_version()},
                   "time_standard": "UTC, ISO 8601", "report_language": options.get("language"),
                   "report_options": {k: options.get(k) for k in ("theme", "timeline", "raw_records", "media_previews",
                                                                   "part_size", "group_heartbeats", "show_changes", "show_indicators", "template",
                                                                   *report_analytics.Presentation.model_fields)}},
        "integrity": {"hash": "SHA-256 (FIPS 180-4)", "signature": "Ed25519 (RFC 8032)",
                      "public_key": context["public_key"], "fingerprint": fingerprint(context["public_key"]),
                      "manifest": "manifest.json lists the SHA-256 of every file; manifest.sig signs it",
                      "report_seal": "the readable report ends with a signed seal over its own bytes"},
        "standards": [{"reference": ref, "title": title, "how": how}
                      for ref, title, how in standards(say, kind, rfc3161_count(context.get("anchors", []), validated=True))],
        "custody_log": [{"at": context["created_at"], "action": "exported and sealed",
                         "by": options.get("examiner") or None, "tool": "TgWitness " + __version__}],
        "statement": "Alignment with the listed practices. Integrity is verifiable with verify.py; "
                     "retained checkpoints, witness records and timestamps bind the records to outside parties and time.",
    }
    if kind == "handover":
        handover = context["handover"]
        record["minimisation"] = {
            "purpose": handover["purpose"], "selection": handover["selection"], "counts": handover["counts"],
            "verification": "Records shown unchanged are verified in full; minimised records by the collector's "
                            "signature over the hash of the original record; records left out are only counted."}
    if kind == "evidence" and context.get("selection"):
        record["export"]["report_options"]["selection"] = context["selection"]["selection"]
    if kind in ("evidence", "handover"):
        digest = context["digest"]
        record["acquisition"].update(first_record_at=digest["first"], last_record_at=digest["last"],
                                     record_count=context["event_count"], head_hash=context["head_hash"],
                                     chats=len(digest["chats"]))
        record["acquisition"]["clients"] = [{"client": c["value"], "first_seen": c["first"], "last_seen": c["last"]}
                                            for c in digest.get("clients") or []] or None
        record["acquisition"]["clock_checks"] = digest.get("clocks") or None
        record["acquisition"]["routes"] = [{"route": {k: v for k, v in r["value"].items() if k != "proxy_id"},
                                            "first_seen": r["first"], "last_seen": r["last"]}
                                           for r in digest.get("routes") or []] or None
        scope = digest.get("own_scope") or []
        record["acquisition"]["actions_by_observing_account"] = {
            "panel_actions": digest.get("action_count", 0), "messages_sent": digest.get("own_total", 0),
            "own_messages_recorded": (False not in scope) if scope else None}
        direct = digest.get("direct_fallbacks") or {}
        if direct.get("count"):
            record["acquisition"]["direct_fallbacks"] = {
                **direct, "meaning": "No listed proxy answered; Telegram saw this server's address until one did"}
        record["timestamps"] = [{k: a.get(k) for k in ("checkpoint", "event_count", "service", "kind", "time", "status")
                                 if a.get(k) is not None} for a in context.get("anchors", [])]
        latest = latest_stamp(context.get("anchors", []))
        record["latest_timestamped_record"] = latest and {"event_count": latest.get("event_count"),
                                                          "time": latest.get("time"), "service": latest["service"]}
    else:
        meta, stats = context["meta"], context["stats"]
        record["acquisition"].update(chat=meta.get("chat"), message_count=meta.get("message_count"),
                                     first_message_at=stats["first_at"], last_message_at=stats["last_at"],
                                     chat_json_sha256=context.get("chat_json_sha256"),
                                     collection=meta.get("collection"),
                                     accounts=[p["statement"].get("account_id") for p in meta.get("parts") or []] or None,
                                     client=meta.get("client"), route=meta.get("route"), observer=meta.get("observer"),
                                     recheck=meta.get("recheck"), admin_log=meta.get("admin_log"),
                                     attachments=meta.get("attachments"), **reading(meta))
    return record


def reading(meta):
    found = meta.get("acquisition") if isinstance(meta.get("acquisition"), dict) else {}
    return {"read_started_at": found.get("started_at"), "read_finished_at": found.get("finished_at"),
            "clock_checks": [c for c in (found.get("clock_at_start"), found.get("clock_at_end")) if isinstance(c, dict)]
            or None}


def readme(context, files, english):
    say = Words(context["options"].get("language", "en"))
    options, fp = context["options"], fingerprint(context["public_key"])
    evidence, handover = context["kind"] == "evidence", context["kind"] == "handover"
    archive = "tgwitness-evidence.zip" if evidence else "tgwitness-handover.zip" if handover else "tgwitness-chat-export.zip"
    title = say("Evidence archive") if evidence else say("Handover extract") if handover else say("Chat export")
    lines = ["TgWitness · " + title, options.get("case_title") or "", "=" * 64]
    if handover:
        lines += [say("Purpose") + ": " + context["handover"]["purpose"].replace("\n", " "), ""]
    for label, key in ((say("Case ID"), "case_id"), (say("Examiner"), "examiner"), (say("Organization"), "organization")):
        if options.get(key):
            lines.append(label + ": " + options[key])
    lines += [say("Created") + ": " + utc_text(context["created_at"]), say("Report ID") + ": " + context["report_id"],
              say("Signing key fingerprint") + ": " + fp]
    report_name = "chat.html" if not (evidence or handover) else "report.html"
    lines += ["", say("Start here"), "-" * 64,
              say("Extract the complete archive before opening the HTML report. Keep viewer/ and media/ beside it."),
              "  " + report_name + " — " + say("Report, search, filters and archive verification"),
              say("Keep the original ZIP unchanged. Save selections and working notes outside the extracted folder."),
              "", say("What is in this archive"), "-" * 64]
    folders = ("media/", "anchors/", "records/", "messages/", "viewer/")
    shown = [n for n in sorted(files) if not n.startswith(folders)]
    width = max([len(n) for n in shown] + [len(n) for n in folders]) + 3
    for name in shown:
        lines.append("  " + name.ljust(width) + file_purpose(say, name))
    for prefix in folders:
        count = sum(1 for n in files if n.startswith(prefix))
        if count:
            lines.append("  " + prefix.ljust(width) + file_purpose(say, prefix + ("x.json" if prefix == "anchors/" else ""))
                         + " (" + str(count) + ")")
    lines += ["", say("How to verify"), "-" * 64,
              say("Run these commands in the extracted folder, with the original ZIP in its parent folder."),
              say("Use a verifier from a trusted checkout. The bundled copy is provided for convenience."),
              "1. " + say("Get the signer's key fingerprint from a trusted channel, not from this archive."),
              "   python verify.py ../" + archive + " --fingerprint TRUSTED_SHA256",
              "2. " + say("Without Python, check the file hashes (not the signature):"),
              "   sha256sum -c SHA256SUMS            (macOS: shasum -a 256 -c SHA256SUMS)",
              "   Get-FileHash -Algorithm SHA256 <file>   (Windows PowerShell)"]
    if evidence:
        lines += ["3. " + say("Timestamps: check an RFC 3161 answer with OpenSSL and the authority's root certificate:"),
                  "   openssl ts -verify -data anchors/<checkpoint>.json -in anchors/<checkpoint>.<service>.tsr"
                  " -CAfile tsa-root.pem",
                  "   " + say("OpenTimestamps proofs: ots upgrade, then ots verify -f CHECKPOINT.json PROOF.ots"),
                  "4. " + say("The report alone:") + " python verify.py report.html --fingerprint TRUSTED_SHA256"
                  + " --evidence ../" + archive]
    elif handover:
        lines += ["3. " + say("The report alone:") + " python verify.py report.html --fingerprint TRUSTED_SHA256"
                  + " --evidence ../" + archive]
    else:
        lines += ["3. " + say("The report alone:") + " python verify.py chat.html --fingerprint TRUSTED_SHA256"
                  + " --evidence ../" + archive]
    lines += ["", say("Checksum scope"), "-" * 64,
              say("SHA256SUMS covers the payload files listed inside it. It excludes itself, manifest.json and manifest.sig."),
              say("The signed manifest also covers SHA256SUMS. manifest.sig authenticates the exact bytes of manifest.json."),
              say("Matching hashes show that the files are unchanged; --fingerprint confirms the signer."),
              "", say("Working with the data"), "-" * 64,
              say("JSON and JSONL are UTF-8. Times are ISO 8601 in UTC; numeric Telegram IDs identify accounts and chats, not people."),
              say("Import CSV as UTF-8 and keep ID, wallet and hash columns as text. Formula-like values are escaped for spreadsheets."),
              say("Indicators are observations, not verdicts. Review their source references before importing STIX or MISP."),
              say("The PDF is a signed reading copy. Use the HTML viewer for search and the JSON or JSONL for structured analysis.")]
    lines += ["", say("Reading this record"), "-" * 64] + ["- " + say(item) for item in context["limits"]]
    text = "\n".join(lines) + "\n"
    prefix = "\n".join(context["limits"])
    supplement = english[len(prefix):].lstrip() if english.startswith(prefix) else english.strip()
    if say.language != "en":
        english_context = {**context, "options": {**options, "language": "en"}}
        text += "\n" + "=" * 64 + "\nEnglish\n" + "=" * 64 + "\n"
        text += readme(english_context, files, english).decode("utf-8")
    elif supplement:
        text += "\n" + supplement + "\n"
    return text.encode("utf-8")


MARK = ('<svg viewBox="0 0 48 48" aria-hidden="true"><defs><linearGradient id="tgw-g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#1d4ed8"/></linearGradient></defs>'
        '<rect width="48" height="48" rx="13" fill="url(#tgw-g)"/><path d="M15 12h18a6 6 0 0 1 6 6v10a6 6 0 0 1-6 6H22'
        'l-5.6 4.6c-.5.4-1.4.1-1.4-.6V34a6 6 0 0 1-6-6V18a6 6 0 0 1 6-6Z" fill="#fff"/><circle cx="24" cy="23" r="5.2" '
        'fill="none" stroke="#1d4ed8" stroke-width="2.6"/><circle cx="24" cy="23" r="1.8" fill="#1d4ed8"/></svg>')
STAMP = ('<svg viewBox="0 0 36 36" aria-hidden="true"><circle cx="18" cy="18" r="17" class="core"/>'
         '<path class="tick" d="M10.5 18.5l5 5 10-11"/><path class="cross" d="M12.5 12.5l11 11M23.5 12.5l-11 11"/>'
         '<path class="warn" d="M18 9.5v10M18 25.5v.4"/></svg>')
ICON_PRINT = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16'
              'a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z"/></svg>')
LIGHT = ("--bg:#f4f5f7;--bg2:#f8f9fb;--th:#eef0f4;--card:#fff;--ink:#0f1728;--soft:#2f3a4d;--muted:#596377;"
         "--line:#e3e6eb;--line2:#cfd4dc;--rule:#0f1728;--accent:#2563eb;--accent-text:#1d4ed8;--tint:#eef3ff;"
         "--tint-line:#c9d8fd;--ok:#08734a;--oktint:#ebf8f1;--ok-line:#bfe5d1;--warn:#a64b06;--warntint:#fff7e8;"
         "--warn-line:#f5d9a8;--bad:#b42318;--badtint:#fef2f1;--bad-line:#f6cfcb;--violet:#6d3fc0;--violettint:#f4f0fd;"
         "--teal:#0f6e63;--tealtint:#eaf7f5;--pink:#a3336b;--code:#f8f9fb;--bubble:#fff;--dot:rgb(15 23 40 / .07);"
         "--glow-1:rgb(37 99 235 / .14);--glow-2:rgb(124 77 255 / .12);--glow-3:rgb(20 184 166 / .10);"
         "--shadow-sm:0 1px 3px rgb(16 24 40 / .06),0 1px 2px rgb(16 24 40 / .04);"
         "--shadow-md:0 12px 28px -12px rgb(16 24 40 / .18),0 2px 6px -2px rgb(16 24 40 / .06);"
         "--chatbg:linear-gradient(160deg,#dfeaf7,#e6f1e4);color-scheme:light")
DARK = ("--bg:#0e131d;--bg2:#191f2c;--th:#202838;--card:#151b27;--ink:#e7ebf2;--soft:#c2c9d6;--muted:#97a1b3;"
        "--line:#283142;--line2:#354055;--rule:#c2c9d6;--accent:#4f8dff;--accent-text:#8cb4ff;--tint:#172544;"
        "--tint-line:#2c4475;--ok:#5dd39e;--oktint:#11291f;--ok-line:#1f4a37;--warn:#f2b35b;--warntint:#2c2112;"
        "--warn-line:#57401f;--bad:#ff8f86;--badtint:#321a1c;--bad-line:#5e2b2e;--violet:#bba3ff;--violettint:#231d3c;"
        "--teal:#5ccfc3;--tealtint:#10292a;--pink:#f08ec1;--code:#191f2c;--bubble:#1d2a3f;--dot:rgb(255 255 255 / .05);"
        "--glow-1:rgb(79 141 255 / .16);--glow-2:rgb(162 123 255 / .12);--glow-3:rgb(47 199 180 / .10);"
        "--shadow-sm:0 1px 3px rgb(0 0 0 / .35),0 1px 2px rgb(0 0 0 / .25);"
        "--shadow-md:0 14px 30px -12px rgb(0 0 0 / .6),0 2px 6px -2px rgb(0 0 0 / .35);"
        "--chatbg:linear-gradient(160deg,#16243a,#142b2a);color-scheme:dark")
SANS = "Inter,'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,'Helvetica Neue',Arial,sans-serif"
MONO = "'JetBrains Mono','Cascadia Code','SF Mono',Consolas,'Liberation Mono',monospace"
ICONS = Path(__file__).with_name("report_icons.svg").read_text(encoding="utf-8")


def icon(name, cls="i"):
    return '<svg class="' + cls + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>'


SECTION_ICONS = {"case": ("files", "blue"), "minimisation": ("eye", "violet"), "changes": ("edit", "orange"),
                 "actions": ("route", "violet"), "integrity": ("fingerprint", "blue"), "timestamps": ("seal", "teal"),
                 "coverage": ("layers", "teal"), "custody": ("route", "green"), "verify": ("check", "green"),
                 "files": ("zip", "slate"), "standards": ("journal", "slate"), "limits": ("alert", "orange"),
                 "records": ("journal", "blue"), "messages": ("message", "blue"), "people": ("users", "violet"),
                 "ids": ("tag", "red"), "indicators": ("tag", "red"), "source": ("telegram", "blue"),
                 "admin-log": ("trash", "red"), "seal": ("lock", "green")}
CSS = (
    ":root{" + LIGHT + "}:root[data-theme=dark]{" + DARK + "}"
    "@media (prefers-color-scheme:dark){:root[data-theme=auto]{" + DARK + "}}"
    "*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth;scroll-padding-top:62px}"
    "body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.55 " + SANS + "}"
    "a{color:var(--accent)}code,.mono,pre{font-family:" + MONO + "}code{font-size:.9em;overflow-wrap:anywhere}"
    ".bar{position:sticky;top:0;z-index:9;display:flex;align-items:center;gap:12px;min-height:46px;padding:6px 20px;"
    "background:var(--card);border-bottom:1px solid var(--line)}"
    ".brand{display:flex;align-items:center;gap:9px;font-size:14px;font-weight:650;white-space:nowrap}"
    ".brand svg{width:22px;height:22px}.brand small{font-weight:500;color:var(--muted)}"
    ".bar nav{display:flex;margin-inline-start:auto;flex-wrap:wrap;justify-content:flex-end}"
    ".bar nav a{color:var(--soft);text-decoration:none;font-size:13px;padding:5px 9px;border-radius:3px}"
    ".bar nav a:hover{background:var(--bg2);color:var(--ink)}"
    ".icon-btn{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:3px;border:1px solid var(--line);"
    "background:var(--card);color:var(--soft);cursor:pointer}.icon-btn:hover{color:var(--ink);border-color:var(--soft)}"
    ".icon-btn svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linejoin:round}"
    ".icon-btn svg .fill{fill:currentColor;stroke:none}"
    "main{max-width:940px;margin:28px auto 36px;padding:44px 56px 40px;background:var(--card);border:1px solid var(--line);"
    "box-shadow:0 1px 3px rgba(0,0,0,.06)}"
    ".hero{display:grid;grid-template-columns:1fr 258px;gap:28px;align-items:start;padding-bottom:22px;"
    "border-bottom:2px solid var(--rule)}"
    ".eyebrow{font-size:11.5px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:var(--muted)}"
    ".hero h1{font:600 clamp(23px,3.1vw,31px)/1.2 Georgia,'Times New Roman','Noto Serif',serif;margin:8px 0 18px;"
    "overflow-wrap:anywhere}"
    ".facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 22px;font-size:14px}"
    ".facts div{min-width:0}.facts>div>span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;"
    "letter-spacing:.07em}.facts b{font-weight:600;overflow-wrap:anywhere}"
    ".stamp{display:grid;grid-template-columns:auto minmax(0,1fr);gap:3px 12px;align-items:center;padding:12px 14px;"
    "border:1px solid var(--line);border-inline-start:4px solid var(--muted);background:var(--bg2);"
    "-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".stamp svg{grid-row:1/span 4;width:32px;height:32px}.stamp .core{fill:var(--muted)}"
    ".stamp .tick,.stamp .cross,.stamp .warn{fill:none;stroke:#fff;stroke-width:3;stroke-linecap:round;"
    "stroke-linejoin:round;opacity:0}"
    ".stamp.ok{border-inline-start-color:var(--ok)}.stamp.ok .core{fill:var(--ok)}.stamp.ok .tick{opacity:1}"
    ".stamp.bad{border-inline-start-color:var(--bad)}.stamp.bad .core{fill:var(--bad)}.stamp.bad .cross{opacity:1}"
    ".stamp.unknown .tick{opacity:.6}.stamp.partial{border-inline-start-color:var(--warn)}.stamp.partial .core{fill:var(--warn)}"
    ".stamp.partial .warn{opacity:1}.stamp.partial .stamp-state{color:var(--warn)}"
    ".stamp-hint{grid-column:2;font-size:12px;line-height:1.35;color:var(--accent)}"
    ".stamp-label{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}"
    ".stamp-state{font-size:13.5px;font-weight:650;line-height:1.3}.stamp.ok .stamp-state{color:var(--ok)}"
    ".stamp.bad .stamp-state{color:var(--bad)}.stamp-key{font:11.5px " + MONO + ";color:var(--muted);overflow-wrap:anywhere}"
    ".tiles{display:flex;flex-wrap:wrap;margin:22px 0 0;border-top:1px solid var(--line);"
    "border-inline-start:1px solid var(--line)}"
    ".tile{display:flex;flex-direction:column-reverse;justify-content:flex-end;flex:1 1 96px;min-width:0;"
    "padding:8px 12px 9px;border-inline-end:1px solid var(--line);border-bottom:1px solid var(--line)}.tile i{display:none}"
    ".tile b{font-size:19px;line-height:1.25;font-weight:650;font-variant-numeric:tabular-nums}"
    ".tile>span{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}"
    "section.card{margin:30px 0 0;padding:24px 0 0;border-top:1px solid var(--line)}"
    ".brief-cols{display:grid;grid-template-columns:1fr 1fr;gap:6px 28px}.brief-cols ul{margin:4px 0 0;padding-inline-start:18px}"
    ".brief-cols li{margin:3px 0}@media (max-width:760px){.brief-cols{grid-template-columns:1fr}}"
    "section.card>h2{display:flex;align-items:baseline;gap:9px;font-size:18px;line-height:1.3;margin:0 0 6px}"
    "h2 .num{font-weight:700}h2 .num:after{content:'.'}"
    "h3{font-size:14.5px;margin:20px 0 8px}.lead{color:var(--muted);margin:0 0 14px;max-width:80ch}"
    "table{width:100%;border-collapse:collapse}"
    ".kv th,.kv td,.grid th,.grid td{border:1px solid var(--line);vertical-align:top}"
    ".kv th{width:30%;text-align:start;font-weight:600;color:var(--soft);padding:7px 12px;background:var(--th)}"
    ".kv td{padding:7px 12px;overflow-wrap:anywhere}"
    ".grid{font-size:13.5px}.grid th{text-align:start;font-size:12px;font-weight:650;color:var(--soft);padding:7px 10px;"
    "background:var(--th)}.grid td{padding:7px 10px;overflow-wrap:break-word}.grid td small{overflow-wrap:anywhere}"
    ".scroll{overflow-x:auto}"
    ".pill{display:inline-flex;align-items:center;gap:6px;padding:1px 7px;border-radius:3px;font-size:11.5px;"
    "font-weight:650;border:1px solid color-mix(in srgb,currentColor 30%,transparent);background:var(--tint);"
    "color:var(--accent);white-space:nowrap}"
    ".pill.ok{background:var(--oktint);color:var(--ok)}.pill.warn{background:var(--warntint);color:var(--warn)}"
    ".pill.bad{background:var(--badtint);color:var(--bad)}.pill.violet{background:var(--violettint);color:var(--violet)}"
    ".pill.grey{background:var(--bg2);color:var(--muted)}.kv .pill{white-space:normal}"
    ".callout{padding:11px 14px;margin:12px 0;background:var(--warntint);"
    "border:1px solid color-mix(in srgb,var(--warn) 30%,transparent);border-inline-start:4px solid var(--warn)}"
    ".callout.ok{background:var(--oktint);border-color:color-mix(in srgb,var(--ok) 30%,transparent);"
    "border-inline-start-color:var(--ok)}"
    ".callout.bad{background:var(--badtint);border-color:color-mix(in srgb,var(--bad) 30%,transparent);"
    "border-inline-start-color:var(--bad)}"
    ".callout.info{background:var(--tint);border-color:color-mix(in srgb,var(--accent) 25%,transparent);"
    "border-inline-start-color:var(--accent)}"
    ".keycard{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;border:1px solid var(--line);"
    "padding:14px 18px;background:var(--bg2);margin:6px 0 16px}"
    ".keycard small{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}"
    ".fp{display:grid;grid-template-columns:repeat(8,auto);gap:4px 12px;justify-content:start;font:600 15px " + MONO + ";"
    "letter-spacing:.03em}"
    ".swatch{display:grid;grid-template-columns:repeat(4,18px);gap:3px;-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".swatch i{width:18px;height:18px;border-radius:2px}"
    ".chain{display:flex;align-items:stretch;overflow-x:auto;padding:4px 0 8px;margin:4px 0 14px}"
    ".link{flex:0 0 auto;border:1px solid var(--line);background:var(--bg2);border-radius:2px;padding:9px 13px;min-width:150px}"
    ".link b{display:block;font-size:13px}.link code{font-size:12px;color:var(--muted)}"
    ".link.head{border-color:var(--rule);background:var(--card)}.link.more{border-style:dashed;background:transparent}"
    ".arrow{flex:0 0 28px;align-self:center;height:1px;background:var(--muted);position:relative}"
    ".arrow:after{content:'';position:absolute;inset-inline-end:-1px;top:-4px;border:4.5px solid transparent;"
    "border-inline-start-color:var(--muted)}"
    ".steps{counter-reset:s;list-style:none;padding:0;margin:8px 0 0}"
    ".steps>li{position:relative;padding:0 0 16px 40px}.steps>li:before{counter-increment:s;content:counter(s);position:absolute;"
    "inset-inline-start:0;top:-1px;width:26px;height:26px;border-radius:50%;display:grid;place-items:center;"
    "background:var(--ink);color:var(--card);font-weight:700;font-size:13px}"
    "[dir=rtl] .steps>li{padding:0 40px 16px 0}"
    "pre.cmd{position:relative;background:var(--code);color:var(--ink);border:1px solid var(--line);border-radius:2px;"
    "padding:10px 12px;white-space:pre-wrap;overflow-wrap:anywhere;margin:8px 0;font-size:12.5px;direction:ltr;text-align:left}"
    "pre.cmd code{display:block;padding-inline-end:72px}pre.cmd .copy{position:absolute;top:6px;right:6px;"
    "border:1px solid var(--line);background:var(--card);color:var(--soft);border-radius:3px;font-size:12px;"
    "padding:3px 8px;cursor:pointer}pre.cmd .copy:hover{color:var(--ink);border-color:var(--soft)}"
    ".tools{position:sticky;top:46px;z-index:4;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 0;"
    "margin-bottom:6px;background:var(--card);border-bottom:1px solid var(--line)}"
    ".tools input[type=search],.tools select{font:inherit;font-size:13.5px;padding:6px 10px;border-radius:3px;"
    "border:1px solid var(--line);background:var(--card);color:var(--ink)}.tools input[type=search]{flex:1 1 220px}"
    ".chip{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--soft);border-radius:3px;"
    "padding:4px 10px;font-size:12.5px;cursor:pointer}.chip b{font-weight:650;margin-inline-start:4px;opacity:.7}"
    ".chip[aria-pressed=true]{background:var(--ink);border-color:var(--ink);color:var(--card)}"
    ".shown{margin-inline-start:auto;color:var(--muted);font-size:13px}"
    ".part-nav{display:flex;flex-wrap:wrap;gap:6px 18px;margin:0 0 14px;font-size:13.5px}"
    ".ranges{font:12.5px " + MONO + ";color:var(--soft)}"
    ".rec{border:1px solid var(--line);border-inline-start:3px solid var(--c);border-radius:2px;padding:9px 14px 8px;"
    "margin:8px 0;background:var(--card);break-inside:avoid}"
    ".rec header{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;font-size:13px;color:var(--muted)}"
    ".rec .seq{font-weight:700;color:var(--muted);text-decoration:none;font-family:ui-monospace,Menlo,Consolas,monospace}"
    ".rec .k{font-weight:700;color:var(--c)}.rec .at{margin-inline-start:auto}"
    ".who{font-weight:650;margin-top:4px}.who .sub,.uname{font-weight:500;color:var(--muted)}"
    ".rec .text{white-space:pre-wrap;overflow-wrap:anywhere;margin:5px 0 3px}"
    ".rec .gone{color:var(--bad);font-size:14px;margin-top:4px}.rec .file{font-size:14px;margin-top:4px}"
    ".fwd{font-size:13px;color:var(--accent);margin:4px 0}.facts-line{font-size:12.5px;color:var(--muted);margin:4px 0}"
    ".behind{font-size:13.5px;margin:6px 0;padding:7px 10px;border-radius:2px;background:var(--warntint);"
    "border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}.behind ul{margin:4px 0 0;padding-inline-start:18px}"
    ".behind code,.kbd code{overflow-wrap:anywhere}.kbd{font-size:13px;margin:6px 0}"
    ".seen+.seen{margin-top:6px}.seen small{display:block;color:var(--muted);font-size:12px;margin-top:2px}"
    ".withheld{font-size:13px;color:var(--muted);margin:4px 0;font-style:italic}.withheld .pill{font-style:normal}"
    ".bubble img.att{display:block;max-width:min(100%,380px);max-height:320px;border-radius:10px;margin:6px 0}"
    ".hist{border:1px solid var(--line);border-radius:2px;padding:12px 16px;margin:10px 0;break-inside:avoid}"
    ".hist header{font-size:14px;margin-bottom:6px}.hist header span{color:var(--muted);margin-inline-start:6px}"
    ".versions{list-style:none;margin:0;padding:0;border-inline-start:2px solid var(--line)}"
    ".versions>li{padding:4px 0 8px 14px}.vhead{font-size:12.5px;color:var(--muted)}"
    ".versions .text{white-space:pre-wrap;overflow-wrap:anywhere;margin:4px 0}.gone-step .gone{color:var(--bad);margin:4px 0;font-size:13.5px}"
    "del{background:var(--badtint);color:var(--bad)}ins{background:var(--oktint);color:var(--ok)}"
    "del,ins{-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".kbd-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}.key{display:inline-flex;flex-direction:column;gap:2px;"
    "border:1px solid var(--line);border-radius:3px;padding:4px 10px;background:var(--bg2)}.key code{font-size:11.5px;color:var(--muted)}"
    ".rec img{display:block;max-width:min(100%,420px);max-height:340px;border-radius:2px;margin:8px 0;border:1px solid var(--line)}"
    ".rec footer{display:flex;flex-wrap:wrap;gap:10px;font-size:11.5px;color:var(--muted);margin-top:4px}"
    ".cat-message{--c:var(--accent)}.cat-edited,.cat-missing{--c:var(--warn)}.cat-deleted{--c:var(--bad)}.cat-media{--c:var(--violet)}"
    ".cat-reaction{--c:var(--pink)}.cat-member{--c:var(--ok)}.cat-system{--c:var(--muted)}"
    "details.raw summary{cursor:pointer;color:var(--muted);font-size:12px;margin-top:4px}"
    "details.raw pre{background:var(--code);border:1px solid var(--line);border-radius:2px;padding:10px 12px;font-size:12px;"
    "white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto}"
    ".note{white-space:pre-wrap;background:var(--bg2);border:1px solid var(--line);padding:12px 14px;margin:0}"
    ".timeline{list-style:none;margin:6px 0 0;padding:0;position:relative}"
    ".timeline:before{content:'';position:absolute;inset-inline-start:9px;top:6px;bottom:6px;width:2px;background:var(--line)}"
    ".timeline li{position:relative;padding:0 0 16px 34px}[dir=rtl] .timeline li{padding:0 34px 16px 0}"
    ".timeline li:before{content:'';position:absolute;inset-inline-start:3px;top:4px;width:14px;height:14px;border-radius:50%;"
    "background:var(--card);border:3px solid var(--ink)}.timeline li b{display:block}"
    ".timeline li span{color:var(--muted);font-size:14px}"
    ".sign td{height:40px}.drop{border:2px dashed var(--line);border-radius:3px;padding:18px;text-align:center;"
    "color:var(--muted);margin-top:14px;transition:background .2s,border-color .2s}"
    ".drop.over{border-color:var(--accent);background:var(--tint)}.drop label{color:var(--accent);cursor:pointer;font-weight:600}"
    ".drop input{position:absolute;width:1px;height:1px;opacity:0}"
    ".bars td.bar-cell{width:38%}.meter{height:8px;border-radius:2px;background:var(--bg2);overflow:hidden}"
    ".meter i{display:block;height:100%;background:var(--soft)}"
    "footer.end{color:var(--muted);font-size:12px;text-align:center;margin:0 16px 28px;line-height:1.7}"
    "footer.end b{color:var(--soft)}"
    ".chatwall{background:var(--chatbg);border-radius:6px;padding:14px clamp(8px,2vw,22px) 18px;"
    "-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".day{text-align:center;margin:14px 0 8px}.day time{display:inline-block;background:rgba(0,0,0,.28);color:#fff;"
    "font-size:12.5px;font-weight:600;padding:3px 12px;border-radius:999px}"
    ".msg-row{display:flex;gap:8px;align-items:flex-end;margin:3px 0;break-inside:avoid}"
    ".msg-row.cont{margin-top:1px}.ava{flex:0 0 38px;height:38px;border-radius:50%;display:grid;place-items:center;"
    "color:#fff;font-weight:700;font-size:14px;background:linear-gradient(160deg,var(--h1),var(--h2))}"
    ".ava.blank{visibility:hidden}"
    ".bubble{position:relative;max-width:min(78%,640px);background:var(--bubble);border-radius:16px 16px 16px 6px;"
    "padding:7px 12px 6px;box-shadow:0 1px 1.5px rgba(0,0,0,.13)}[dir=rtl] .bubble{border-radius:16px 16px 6px 16px}"
    ".bubble .name{font-weight:680;font-size:14px;color:var(--h2)}"
    ".bubble .text{white-space:normal;overflow-wrap:anywhere}"
    ".quote{display:block;border-inline-start:3px solid var(--accent);background:var(--tint);border-radius:6px;"
    "padding:3px 9px;margin:4px 0;font-size:13.5px;color:var(--soft);text-decoration:none;overflow:hidden;"
    "text-overflow:ellipsis;white-space:nowrap}.quote b{color:var(--accent);margin-inline-end:6px}"
    ".media-chip{display:inline-flex;gap:6px;align-items:center;font-size:13px;color:var(--soft);background:var(--bg2);"
    "border-radius:10px;padding:5px 10px;margin:4px 0}"
    ".bubble .meta{float:inline-end;margin:6px 0 0 12px;font-size:11.5px;color:var(--muted)}"
    ".bubble .meta a{color:inherit;text-decoration:none}"
    ".svc-row{text-align:center;margin:8px 0}.svc-row span{display:inline-block;background:rgba(0,0,0,.22);color:#fff;"
    "font-size:13px;padding:4px 12px;border-radius:999px;max-width:90%}"
    ".gap-row.found span{background:var(--warntint);color:var(--warn);border-color:var(--warn)}"
    ".gap-row{text-align:center;margin:8px 0}.gap-row span{display:inline-block;background:var(--badtint);color:var(--bad);"
    "border:1px dashed var(--bad);font-size:12.5px;font-weight:600;padding:3px 12px;border-radius:999px}"
    ".c0{--h1:#ff885e;--h2:#e65a5a}.c1{--h1:#ffcd6a;--h2:#e8912f}.c2{--h1:#e0a2f3;--h2:#9a5bd3}.c3{--h1:#a0de7e;--h2:#3fa64a}"
    ".c4{--h1:#53edd6;--h2:#1aa6a6}.c5{--h1:#72d5fd;--h2:#2a8fd6}.c6{--h1:#ffa8a8;--h2:#e05c96}"
    ".chathead{display:flex;gap:16px;align-items:center}.chathead .ava{flex:0 0 64px;height:64px;font-size:24px}"
    ":target{outline:2px solid var(--accent);outline-offset:3px;border-radius:2px}"
    "@media (max-width:760px){main{margin:0;padding:22px 16px 28px;border:0;box-shadow:none}"
    ".hero{grid-template-columns:1fr;gap:18px}.bar nav{display:none}.kv th{width:42%}.keycard{grid-template-columns:1fr}"
    ".fp{grid-template-columns:repeat(4,auto)}.bubble{max-width:88%}}"
    "@page{size:A4;margin:16mm 14mm 18mm;@bottom-left{font:8pt " + SANS + ";color:#555}"
    "@bottom-right{content:counter(page) ' / ' counter(pages);font:8pt " + SANS + ";color:#555}}"
    "@media print{body{background:#fff;font-size:12.5px}.bar,.no-print,.tools,.copy,.drop{display:none!important}"
    "main{margin:0;padding:0;max-width:none;border:0;box-shadow:none}section.card{break-inside:avoid-page}"
    "section.card.long{break-inside:auto}.rec,.msg-row,.hist,tr{break-inside:avoid}h2,h3{break-after:avoid}"
    ":root,:root[data-theme]{" + LIGHT + "}}"
)
SCRIPT = r"""
// The page as the browser parsed it, before this script changes anything: compared with a file dropped in below.
const page=document.documentElement.outerHTML;
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const words=JSON.parse(($("#report-words")||{}).textContent||"{}"),say=k=>words[k]||k,lang=document.documentElement.lang;
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const canon=v=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":
  "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
try{
  const date=new Intl.DateTimeFormat(lang,{dateStyle:"medium",timeStyle:"medium",timeZone:"UTC"});
  const day=new Intl.DateTimeFormat(lang,{dateStyle:"full",timeZone:"UTC"});
  const clock=new Intl.DateTimeFormat(lang,{timeStyle:"short",timeZone:"UTC"});
  const number=new Intl.NumberFormat(lang),names=Intl.DisplayNames?new Intl.DisplayNames([lang],{type:"language"}):null;
  for(const t of $$("time[datetime]")){const d=new Date(t.getAttribute("datetime"));if(isNaN(d))continue;
    t.title=t.getAttribute("datetime");
    t.textContent=t.hasAttribute("data-day")?day.format(d):t.hasAttribute("data-clock")?clock.format(d):date.format(d)+" UTC";}
  for(const n of $$("[data-n]"))n.textContent=number.format(Number(n.dataset.n));
  if(names)for(const n of $$("[data-lang]"))n.textContent=names.of(n.dataset.lang)+" ("+n.dataset.lang+")";
}catch(e){}
for(const pre of $$("pre.cmd")){const b=document.createElement("button");b.type="button";b.className="copy";
  b.textContent=say("Copy");b.addEventListener("click",()=>navigator.clipboard&&navigator.clipboard.writeText(
  pre.querySelector("code").textContent).then(()=>{b.textContent=say("Copied");setTimeout(()=>b.textContent=say("Copy"),1600)}));
  pre.append(b);}
const picks=$$("[data-theme-pick]"),pressed=()=>{for(const b of picks)b.setAttribute("aria-pressed",String(b.dataset.themePick===document.documentElement.dataset.theme));};
for(const b of picks)b.addEventListener("click",()=>{document.documentElement.dataset.theme=b.dataset.themePick;pressed();});pressed();
const printer=$("#print");if(printer)printer.addEventListener("click",()=>print());
const q=$("#q");if(q){
  const chips=$$(".chip[data-cat]"),chat=$("#chat"),shown=$("#shown-n"),items=$$("[data-cat].rec,[data-cat].msg-row,[data-cat].svc-row");
  let timer;const apply=()=>{const text=q.value.trim().toLowerCase(),on=new Set(chips.filter(c=>c.getAttribute("aria-pressed")==="true")
    .map(c=>c.dataset.cat)),where=chat?chat.value:"";let n=0;
    for(const item of items){const show=(!on.size||on.has(item.dataset.cat))&&(!where||item.dataset.chat===where)
      &&(!text||item.textContent.toLowerCase().includes(text));item.hidden=!show;if(show)n+=+(item.dataset.count||1);}
    for(const d of $$(".day,.gap-row"))d.hidden=!!(text||on.size||where);
    if(shown)shown.textContent=new Intl.NumberFormat(lang).format(n);};
  for(const c of chips)c.addEventListener("click",()=>{c.setAttribute("aria-pressed",String(c.getAttribute("aria-pressed")!=="true"));apply();});
  q.addEventListener("input",()=>{clearTimeout(timer);timer=setTimeout(apply,180);});if(chat)chat.addEventListener("change",apply);}
async function opened(text){const seal=JSON.parse(text),s=seal.statement;
  const key=await crypto.subtle.importKey("raw",bytes(s.public_key),{name:"Ed25519"},false,["verify"]);
  return{s,signature:seal.signature,fp:hex(await crypto.subtle.digest("SHA-256",bytes(s.public_key))),
    ok:await crypto.subtle.verify({name:"Ed25519"},key,bytes(seal.signature),new TextEncoder().encode(canon(s)))};}
const stamp=$("#stamp"),state=$("#seal-state"),node=$("#tgwitness-seal"),hint=$("#seal-hint");
const badge=$("#sig-badge");
const mark=(kind,text)=>{stamp.classList.remove("ok","bad","partial","unknown");stamp.classList.add(kind);state.textContent=text;
  if(hint)hint.hidden=kind!=="partial";
  if(badge){badge.className="sig-badge "+kind;badge.title=text;badge.querySelector("span").textContent=
    say(kind==="ok"?"Signed":kind==="bad"?"Changed":kind==="partial"?"Not yet checked":"Signed · check with verify.py");}};
if(stamp&&node)opened(node.textContent).then(r=>{const good=r.ok&&r.fp===stamp.dataset.fp;
  mark(good?"partial":"bad",say(good?"Signature valid · this file not yet checked":"Signature does not match"));})
  .catch(e=>e instanceof SyntaxError?mark("bad",say("This file was changed after it was sealed."))
    :mark("unknown",say("Signed · check with verify.py")));
const zone=$("#drop");if(zone){const input=$("#drop-file"),out=$("#drop-result"),marker=new TextEncoder().encode(zone.dataset.open);
  const show=(kind,text)=>{out.className="callout "+kind;out.textContent=text;out.hidden=false;};
  const check=async file=>{show("info",say("Checking…"));const data=new Uint8Array(await file.arrayBuffer());let at=-1;
    outer:for(let i=data.length-marker.length;i>=0;i--){for(let j=0;j<marker.length;j++)if(data[i+j]!==marker[j])continue outer;at=i;break;}
    if(at<0)return show("bad",say("No seal found in this file."));
    const tail=new TextDecoder().decode(data.subarray(at+marker.length)),close=zone.dataset.close;
    if(!tail.endsWith(close))return show("bad",say("The seal is not at the end of the file."));
    // The seal is written with "<" escaped; a raw one closes the seal element and adds unsigned page content.
    if(tail.slice(0,-close.length).includes("<"))return show("bad",say("This file was changed after it was sealed."));
    try{const r=await opened(tail.slice(0,-close.length)),content=hex(await crypto.subtle.digest("SHA-256",data.subarray(0,at)));
      if(!r.ok)return show("bad",say("The seal signature is not valid."));
      // The stamp speaks only for a file that carries this page's own seal.
      const same=stamp&&node&&JSON.parse(node.textContent).signature===r.signature;
      if(content!==r.s.content_sha256){if(same)mark("bad",say("This file was changed after it was sealed."));
        return show("bad",say("This file was changed after it was sealed."));}
      if(same&&r.fp===stamp.dataset.fp){
        const parsed=new DOMParser().parseFromString(new TextDecoder().decode(data),"text/html").documentElement.outerHTML;
        if(parsed===page)mark("ok",say("Verified: this file is exactly as signed"));
        else{mark("bad",say("This page differs from the sealed file you chose."));
          return show("bad",say("The file you chose is intact, but the page shown here differs from it."));}}
      show(r.fp===(stamp&&stamp.dataset.fp)?"ok":"info",say("Seal intact: every byte of this file is as signed.")+" "
        +say("Key fingerprint")+": "+r.fp.match(/.{4}/g).join(" ")+(r.fp===(stamp&&stamp.dataset.fp)?"":" · "+say("a different key than this report")));
    }catch(e){show("bad",say("This browser cannot check Ed25519 signatures. Use verify.py."));}};
  zone.addEventListener("dragover",e=>{e.preventDefault();zone.classList.add("over");});
  zone.addEventListener("dragleave",()=>zone.classList.remove("over"));
  zone.addEventListener("drop",e=>{e.preventDefault();zone.classList.remove("over");if(e.dataTransfer.files[0])check(e.dataTransfer.files[0]);});
  input.addEventListener("change",()=>{if(input.files[0])check(input.files[0]);});}
"""
CONSOLE_JS = Path(__file__).with_name("report_console.js").read_text(encoding="utf-8")
CSS += Path(__file__).with_name("report_console.css").read_text(encoding="utf-8")
CSS += Path(__file__).with_name("report_skin.css").read_text(encoding="utf-8")
CSS += case_assessment.CSS
DOSSIER_CSS = Path(__file__).with_name("report_dossier.css").read_text(encoding="utf-8")
CSS += DOSSIER_CSS
CSS += report_charts.CSS
CSS += report_design.CSS
CSS += report_layouts.CSS
SCRIPT += "\n" + CONSOLE_JS
SCRIPT_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode() + "'"
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: file:; script-src " + SCRIPT_HASH
       + "; frame-src 'self' file:; base-uri 'none'; form-action 'none'")
SCRIPT_WORDS = ("Context message", "Matches export filters", "Copy", "Copied", "Signature valid · this file not yet checked",
                "Verified: this file is exactly as signed", "Signed", "Not yet checked", "Changed",
                "This page differs from the sealed file you chose.",
                "The file you chose is intact, but the page shown here differs from it.", "Signature does not match",
                "Signed · check with verify.py", "Checking…", "No seal found in this file.",
                "The seal is not at the end of the file.", "The seal signature is not valid.",
                "This file was changed after it was sealed.", "Seal intact: every byte of this file is as signed.",
                "Key fingerprint", "a different key than this report",
                "This browser cannot check Ed25519 signatures. Use verify.py.") + tuple(dict.fromkeys(
    json.loads('"' + text + '"') for text in re.findall(r'\bsayf?\("((?:[^"\\]|\\.)*)"', CONSOLE_JS)))


def head(say, *, title, description, meta, linked, theme, template="dossier", design="classic"):
    tags = [("generator", "TgWitness " + __version__), ("description", description),
            ("robots", "noindex, nofollow, noarchive"), ("referrer", "no-referrer"), ("color-scheme", "light dark")]
    design = report_design.normalized(design)
    tags += [*meta, ("tgwitness:report-design", design)]
    return ('<!doctype html><html lang="' + e(say.language) + '" dir="' + say.direction + '" data-report-design="' + design + '" data-report-template="' + e(template) + '" data-theme="' + e(theme)
            + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + e(CSP) + '"><title>' + e(title) + "</title>"
            '<link rel="schema.DC" href="http://purl.org/dc/elements/1.1/">'
            + "".join('<meta name="' + e(n) + '" content="' + e(v) + '">' for n, v in tags if v not in (None, ""))
            + '<script type="application/ld+json">' + script_json(linked) + "</script>"
            "<style>" + CSS + page_footer(say, meta) + '</style></head><body class="dossier">' + ICONS)


def css_text(value):
    return '"' + "".join(c if " " <= c <= "~" and c not in '"\\<>' else "\\%x " % ord(c) for c in str(value)) + '"'


def page_footer(say, meta):
    found = dict(meta)
    parts = [say("Case ID") + " " + str(found["tgwitness:case-id"])] if found.get("tgwitness:case-id") else []
    if found.get("tgwitness:report-id"):
        parts.append(say("Report ID") + " " + str(found["tgwitness:report-id"])[:8])
    return "@page{@bottom-left{content:" + css_text(" · ".join(parts)) + "}}" if parts else ""


def bar(say, label, links, viewer_kind=None):
    sections = "".join('<a href="#' + a + '">' + icon(SECTION_ICONS.get(a, ("info", ""))[0]) + e(t) + "</a>"
                       for a, t in links)
    if not viewer_kind:
        nav, opening = '<nav class="sections">' + sections + "</nav>", "<main>"
    else:
        tabs = [("report", say("Report"), "journal"),
                ("data", say("Messages") if viewer_kind == "chat" else say("Records"), "message" if viewer_kind == "chat" else "layers"),
                ("people", say("Participants") if viewer_kind == "chat" else say("Senders"), "users"),
                ("iocs", say("Indicators"), "tag"), ("check", say("Check"), "shield")]
        nav = ('<nav class="tabs no-print">' + "".join(
            '<a href="#' + key + '" data-view="' + key + '" aria-label="' + e(text) + '" aria-current="' + str(key == "report").lower() + '">' + icon(glyph)
            + "<span>" + e(text) + "</span>" + ("" if key in ("report", "check") else "<b></b>") + "</a>"
            for key, text, glyph in tabs) + "</nav>")
        opening = '<div class="view" id="view-report"><main>'
    return ('<header class="bar"><a class="brand" href="#summary">' + MARK + '<span>TgWitness</span><span class="version">'
            + e(__version__) + '</span></a><span class="doc-kind">' + e(label) + "</span>" + nav
            + '<div class="prefs no-print"><a class="sig-badge" id="sig-badge" href="#check" data-view="check">' + icon("shield")
            + "<span>" + e(say("Checking…")) + '</span></a><span class="lang-pill" title="' + e(say("Report language")) + '">'
            + icon("globe") + '<span data-lang="' + e(say.language) + '">' + e(say.language) + "</span></span>"
            '<div class="theme-pick" role="group" aria-label="' + e(say("Theme")) + '">'
            + "".join('<button type="button" data-theme-pick="' + mode + '" title="' + e(say(label_)) + '">' + icon(glyph) + "</button>"
                      for mode, label_, glyph in (("light", "Light", "sun"), ("dark", "Dark", "moon"), ("auto", "Automatic", "monitor")))
            + '</div><button class="icon-btn" id="print" type="button" title="' + e(say("Print or save as PDF")) + '">'
            + ICON_PRINT + "</button></div></header>" + opening)


def hero(say, eyebrow, title, facts, fp, sealed):
    stamp = ('<aside class="stamp" id="stamp" data-fp="' + e(fp) + '"><div class="stamp-top">' + STAMP + "<div>"
             '<div class="stamp-label">' + e(say("Digital signature")) + '</div><div class="stamp-state" id="seal-state">'
             + e(say("Checking…")) + '</div></div></div><div class="stamp-key"><span>Ed25519</span>'
             + e(" ".join(grouped(fp).split()[:4])) + " …</div>"
             '<a class="stamp-hint no-print" id="seal-hint" href="#seal" hidden>'
             + e(say("Check the file itself")) + " →</a></aside>") if sealed else ""
    return ('<section class="hero" id="summary"><div class="cover-register"><span>TG / WITNESS</span><span>'
            + e(say("Evidence dossier")) + '</span></div><div class="hero-main"><div class="eyebrow">' + e(eyebrow) + "</div><h1>"
            + e(title) + "</h1>"
            '<div class="facts">' + "".join("<div><span>" + e(k) + "</span><b>" + v + "</b></div>" for k, v in facts if v)
            + "</div></div>" + stamp + "</section>")


TILE_TONES = {"accent": "blue", "violet": "violet", "warn": "orange", "bad": "red", "ok": "green", "pink": "teal"}


def tiles(items):
    out = []
    for item in items:
        label, value, colour = item[:3]
        glyph = item[3] if len(item) > 3 else "info"
        out.append('<div class="tile tone-' + TILE_TONES.get(colour, "slate") + '" style="--c:var(--' + colour + ')"><i>'
                   + icon(glyph) + "</i><b>" + value + "</b><span>" + e(label) + "</span></div>")
    return '<div class="tiles">' + "".join(out) + "</div>"


def toc(links):
    return ('<nav class="toc no-print">' + "".join('<a href="#' + a + '">' + icon(SECTION_ICONS.get(a, ("info", ""))[0])
                                                    + e(text) + "</a>" for a, text in links) + "</nav>")


def section(number, anchor, title, lead="", long=False):
    glyph, tone = SECTION_ICONS.get(anchor, ("info", "slate"))
    return ('<section class="card' + (" long" if long else "") + '" id="' + anchor + '"><h2><span class="sec-icon tone-'
            + tone + '">' + icon(glyph) + '</span><span class="num">' + str(number) + '</span><span class="section-title">' + e(title) + '</span></h2>'
            + ('<p class="lead">' + e(lead) + "</p>" if lead else ""))


def kv(rows):
    return '<table class="kv">' + "".join("<tr><th>" + e(k) + "</th><td>" + v + "</td></tr>" for k, v in rows if v) + "</table>"


def table(columns, rows):
    return ('<div class="scroll"><table class="grid"><thead><tr>' + "".join("<th>" + e(c) + "</th>" for c in columns)
            + "</tr></thead><tbody>" + "".join("<tr>" + "".join("<td>" + c + "</td>" for c in row) + "</tr>" for row in rows)
            + "</tbody></table></div>")


def command(text):
    return '<pre class="cmd"><code>' + e(text) + "</code></pre>"


def keycard(say, fp):
    swatch = "".join('<i style="background:hsl(%d %d%% %d%%)"></i>' % color for color in fingerprint_colors(fp))
    return ('<div class="keycard"><div><small>' + e(say("Signing key fingerprint (SHA-256)")) + '</small><div class="fp">'
            + "".join("<span>" + g + "</span>" for g in grouped(fp).split()) + '</div></div><div class="swatch" title="'
            + e(say("Visual fingerprint: copies signed by another key show other colours")) + '">' + swatch + "</div></div>")


def evidence_brief(say, digest, count, anchors, coverage, account_text, handover=None, selected=False):
    cats, latest = digest["categories"], latest_stamp(anchors)
    summary = say("{account} observed {chats} chats from {first} to {last}. The journal holds {n} records: {m} messages, "
                  "{e} edits, {d} deletions and {f} saved files.", account=account_text or say("The observing account"),
                  chats=len(digest["chats"]), first=utc_text(digest["first"]), last=utc_text(digest["last"]),
                  n=count, m=cats["message"], e=cats["edited"], d=cats["deleted"], f=len(digest["media"]))
    if selected:
        summary = say("This report selects {n} records from {chats} chats: {m} message observations, {e} edits and {d} deletion observations.",
                      n=count, chats=len(digest["chats"]), m=cats["message"], e=cats["edited"], d=cats["deleted"])
    if cats.get("missing"):
        summary += " " + say("Missing on recheck") + ": " + str(cats["missing"]) + "."
    if handover:
        summary = say("An extract for a stated purpose: {a} records shown unchanged and {b} minimised; {c} records of the "
                      "journal were left out.", a=handover["counts"]["unchanged"], b=handover["counts"]["minimised"],
                      c=handover["counts"]["left_out"]) + " " + summary
    shows = [say("Each record is unchanged since the collector signed it, provided the key fingerprint matches one kept "
                 "apart from the collector (verify.py checks this)."),
             say("What the observing account received from Telegram, and when the collector recorded it.")]
    if latest:
        shows.append(say("That the journal up to record #{n} existed by {time}: an independent timestamp by {service}.",
                         n=latest.get("event_count"), time=utc_text(latest.get("time")), service=latest.get("service")))
    gaps = len((coverage or {}).get("gaps") or [])
    hidden = [say("Who is behind an account or a chat: Telegram shows names and IDs, not identities."),
              say("That Telegram delivered everything: gaps in observation ({n}) are listed under Coverage.", n=gaps)
              if gaps else say("Activity outside the observed periods: the Coverage section lists those periods."),
              say("Messages deleted before observation began, and the deleting person where no admin log names one."),
              say("Exact times after record #{n}: they come from the collector's clock.", n=latest.get("event_count"))
              if latest else say("Independently fixed times: observed times come from the collector clock until a timestamp or witness covers them.")]
    return summary, shows, hidden


def chat_brief(say, meta, stats, ids, account_text):
    chat, profile = meta.get("chat") or {}, (meta.get("chat") or {}).get("profile") or {}
    summary = say("The {n} messages Telegram returned to {account} for {chat}, sent from {first} to {last}, exported on "
                  "{date}.", n=meta.get("message_count"), account=account_text or say("the exporting account"),
                  chat=chat.get("title") or chat.get("id"), first=utc_text(stats["first_at"]), last=utc_text(stats["last_at"]),
                  date=utc_text(meta.get("exported_at")))
    shows = [say("The messages are as exported, provided the key fingerprint matches one kept apart from the collector "
                 "(verify.py checks this).")]
    if ids.get("selection_applied"):
        shows.append(say("Absent numbers in this selection were not observed; deletions are recorded as separate notices."))
    elif ids.get("numbered_per_chat") and ids.get("missing"):
        shows.append(say("{n} message numbers in this range are absent: deleted before the export, or never visible to "
                         "this account.", n=ids["missing"]))
    labels = [say(text) for flag, text, _ in LABELS if profile.get(flag)]
    if labels:
        shows.append(say("Telegram's own label at export time: {labels}.", labels="; ".join(labels)))
    hidden = [say("Who is behind an account or a chat: Telegram shows names and IDs, not identities."),
              say("Earlier versions of edited messages, or who deleted a message (only an admin log says that).")
              if not meta.get("admin_log") else say("Earlier versions of edited messages older than the admin log."),
              say("Messages hidden from this account: the export holds what Telegram returned to it.")]
    return summary, shows, hidden


def brief_section(say, summary, shows, hidden):
    items = lambda values: "<ul>" + "".join("<li>" + e(v) + "</li>" for v in values) + "</ul>"
    return ('<section class="card brief" id="brief"><h2><span class="sec-icon tone-blue">' + icon("info") + "</span>"
            + e(say("In brief")) + '</h2><p class="lead">' + e(summary)
            + '</p><div class="brief-cols"><div><h3>' + e(say("What this shows")) + "</h3>" + items(shows)
            + "</div><div><h3>" + e(say("What this does not show")) + "</h3>" + items(hidden) + "</div></div></section>")


def case_section(say, number, options, extra_rows):
    rows = [(say("Case title"), e(options.get("case_title"))), (say("Case ID"), e(options.get("case_id"))),
            (say("Examiner"), e(options.get("examiner"))), (say("Organization"), e(options.get("organization")))]
    rows += extra_rows
    notes = ('<h3>' + e(say("Notes")) + '</h3><p class="note">' + e(options["notes"]) + "</p>") if options.get("notes") else ""
    return section(number, "case", say("Case")) + kv(rows) + notes + "</section>"


def custody_section(say, number, steps, record):
    lines = "".join("<li><b>" + e(t) + "</b><span>" + d + "</span></li>" for t, d in steps)
    blank = "".join("<tr>" + "<td></td>" * 5 + "</tr>" for _ in range(4))
    return (section(number, "custody", say("Chain of custody"),
                    say("How this material was acquired, preserved and handed over. custody.json carries the same "
                        "record for case-management systems."))
            + '<ol class="timeline">' + lines + "</ol>" + kv(record)
            + "<h3>" + e(say("Custody transfers")) + '</h3><p class="lead">'
            + e(say("Fill in by hand when the printed report or the archive changes hands.")) + "</p>"
            + '<div class="scroll"><table class="grid sign"><thead><tr>'
            + "".join("<th>" + e(c) + "</th>" for c in (say("Date and time"), say("Released by"), say("Received by"),
                                                       say("Purpose"), say("Signature")))
            + "</tr></thead><tbody>" + blank + "</tbody></table></div></section>")


ROUTE_KINDS = {"mtproxy_auto": "Automatic MTProxy · public lists", "direct": "Direct connection",
               "socks5": "SOCKS5 proxy", "http": "HTTP CONNECT proxy", "mtproxy": "MTProxy"}
EXPOSURES = {"hide": "Hide this server's address", "fallback": "Direct connection as a last resort",
             "tunnel": "Server behind a tunnel or VPN"}


def client_text(say, value):
    pair = {"built-in public pair": say("built-in public pair"),
            "own application": say("own application")}.get(value.get("api_pair"))
    device = " / ".join(str(value[k]) for k in ("device_model", "system_version", "app_version") if value.get(k))
    text = " · ".join(part for part in (
        value.get("library"), ("layer " + str(value["layer"])) if value.get("layer") else "",
        ("DC " + str(value["dc_id"])) if value.get("dc_id") else "",
        ("api_id " + str(value["api_id"]) + (" (" + pair + ")" if pair else "")) if value.get("api_id") else "",
        device) if part)
    if value.get("meaning") and value.get("api_pair") == "built-in public pair":
        text += " — " + say("Telegram Desktop's public pair, sent with a Telegram Desktop client description")
    return text


def build_text(say, producer):
    parts = [label + " " + producer[key] for label, key in ((say("Commit"), "commit"),
                                                            (say("Source files SHA-256"), "source_tree_sha256"))
             if producer.get(key)]
    return " · ".join(parts) or say("Not recorded in this export")


def clock_text(say, clock):
    if not isinstance(clock, dict):
        return say("Not recorded in this export")
    if not isinstance(clock.get("offset_seconds"), (int, float)):
        return say("not measured ({error})", error=clock.get("error_type") or "?")
    return say("Telegram {offset} s ± {uncertainty} s against the collector",
               offset="%+.2f" % clock["offset_seconds"], uncertainty="%.2f" % (clock.get("uncertainty_seconds") or 0))


def clocks_html(say, clocks, empty="Not recorded in this journal"):
    if not clocks:
        return e(say(empty))
    measured = [c["offset_seconds"] for c in clocks if isinstance(c.get("offset_seconds"), (int, float))]
    head = ('<div class="seen">' + e(say("Largest difference: {s} s", s="%.2f" % max(abs(x) for x in measured)))
            + "</div>") if len(measured) > 1 else ""
    return head + "".join('<div class="seen">' + e(clock_text(say, c)) + "<small>" + when(c.get("measured_at"))
                          + "</small></div>" for c in clocks[-10:])


def route_text(say, value):
    kind = value.get("kind")
    text = say(ROUTE_KINDS[kind]) if kind in ROUTE_KINDS else str(kind)
    if value.get("exposure") in EXPOSURES:
        text += " · " + say("IP protection") + ": " + say(EXPOSURES[value["exposure"]])
    if value.get("fallback_to_direct"):
        text += " · " + say("connected directly at the start")
    return text


def seen_list(say, entries, describe):
    if not entries:
        return e(say("Not recorded in this journal"))
    return "".join('<div class="seen">' + e(describe(say, entry["value"])) + "<small>" + when(entry["first"])
                   + (" — " + when(entry["last"]) if entry["last"] != entry["first"] else "") + "</small></div>"
                   for entry in entries[:10])


def direct_text(say, direct):
    if not direct or not direct.get("count"):
        return ""
    return ('<div class="seen"><span class="pill warn">' + e(say("Direct connections while no proxy answered: {n}",
                                                                   n=direct["count"]))
            + "</span><small>" + when(direct["first"])
            + (" — " + when(direct["last"]) if direct["last"] != direct["first"] else "") + " · "
            + e(say("Telegram saw this server's address at those times.")) + "</small></div>")


def standards_section(say, number, kind="evidence", stamps=0):
    rows = [["<b>" + e(ref) + "</b><br><small>" + e(title) + "</small>", e(how)]
            for ref, title, how in standards(say, kind, stamps)]
    return (section(number, "standards", say("Standards and methodology"),
                    say("This export follows these practices."))
            + table([say("Reference"), say("How it is applied")], rows) + "</section>")


def limits_section(say, number, limits):
    return (section(number, "limits", say("Reading this record"), say("What the records state and what binds them."))
            + "<ul>" + "".join("<li>" + e(say(item)) + "</li>" for item in limits) + "</ul></section>")


def files_section(say, number, files, own):
    shown = sorted(files)
    rows = [["<code>" + e(n) + "</code>", e(file_purpose(say, n)), '<code title="' + e(files[n]) + '">' + e(short(files[n], 16, 8))
             + "</code>"] for n in shown[:300]]
    rows += [["<code>" + e(n) + "</code>", e(file_purpose(say, n)), e(say("listed in manifest.json"))] for n in own]
    more = ('<p class="lead">' + e(say("… and {n} more, listed in manifest.json and SHA256SUMS.", n=len(shown) - 300)) + "</p>"
            if len(shown) > 300 else "")
    return (section(number, "files", say("Files in this archive"),
                    say("manifest.json lists the SHA-256 of every file and is signed in manifest.sig."))
            + table([say("File"), say("Purpose"), "SHA-256"], rows) + more + "</section>")


def seal_section(say, number, report_id, created_at):
    return (section(number, "seal", say("Digital signature"),
                    say("This file ends with a signed seal: the SHA-256 of every byte before it, what it describes and the "
                        "case details, signed with the key above."))
            + kv([(say("Report ID"), "<code>" + e(report_id) + "</code>"), (say("Sealed at"), when(created_at))])
            + '<div class="drop" id="drop" data-open="' + e(SEAL_OPEN.decode()) + '" data-close="' + e(SEAL_CLOSE.decode())
            + '"><p>' + e(say("Drop this report file here to check every byte in this browser. Nothing is uploaded."))
            + '</p><label>' + e(say("Choose the file")) + '<input id="drop-file" type="file" accept=".html,.htm,text/html">'
            + '</label></div><div class="callout" hidden id="drop-result" role="status"></div></section>')


def ending(say, producer, viewer_meta=None, data=""):
    views = ""
    if viewer_meta:
        views = ("</div>" + "".join('<div class="view" id="view-' + key + '" hidden></div>' for key in ("data", "people", "iocs", "check"))
                 + '<div id="print-sheet"></div><script type="application/json" id="viewer-meta">' + script_json(viewer_meta)
                 + "</script>" + data)
    return ('</main><footer class="end"><b>TgWitness ' + e(producer.get("version")) + "</b> · " + e(producer.get("project"))
            + " · " + e(producer.get("homepage")) + " · " + e(producer.get("source")) + "<br>"
            + e(say("Free and open source, made to help victims of fraud and the people who investigate it.")) + "</footer>"
            + views + '<script type="application/json" id="report-words">' + script_json({k: say(k) for k in SCRIPT_WORDS})
            + '</script><script type="module">' + SCRIPT + "</script>")


def viewer_meta(say, kind, context, **extra):
    options = {**ReportOptions().model_dump(), **(context.get("options") or {})}
    if kind == "chat":
        cats = {"text": say("Text"), "media": say("With media"), "edited": say("Edited"), "service": say("Service")}
        hidden = []
    else:
        cats = {c: category_label(say, c) for c in CATEGORY_ORDER}
        hidden = ["system"]
    kinds = {k: kind_label(say, k) for k in ("message.new", "message.snapshot", "message.recovered", "message.edited",
                                              "message.deleted", "message.missing_on_recheck", "media.saved", "media.hashed")}
    return {"kind": kind, "cats": cats, "hidden": hidden, "kinds": kinds, "report_id": context.get("report_id"),
            "fingerprint": context.get("fingerprint"), "iocKinds": {k: say(v) for k, v in IOC_KINDS.items()},
            "iocLead": ioc_lead(say),
            "media_previews": options["media_previews"], "raw_records": options["raw_records"],
            "group_heartbeats": options["group_heartbeats"], **extra}


def records_pointer(say, number, anchor, title, count, label, lead=""):
    return (section(number, anchor, title, lead) + '<div class="records-pointer"><b>' + e(label) + "</b><span>"
            + e(say("Search, filters, people, indicators and every item in full are in the viewer tab. Select items to "
                    "print them or to save an extract that verify.py checks against this archive."))
            + '</span><a class="v-btn" href="#data" data-view="data">' + e(say("Open")) + " →</a></div></section>")


def sealed(chunks, statement, sign):
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
        yield chunk
    if sign is None:
        yield b"</body></html>\n"
        return
    statement = {**statement, "content_sha256": digest.hexdigest()}
    seal = {"statement": statement, "signature": sign(canonical(statement)),
            "fingerprint": fingerprint(statement["public_key"])}
    yield SEAL_OPEN + script_json(seal).encode("ascii") + SEAL_CLOSE


def metadata(say, *, title, description, created_at, report_id, fp, case, extra):
    creator = case.get("examiner") or case.get("organization") or "TgWitness"
    return [("DC.title", title), ("DC.creator", creator), ("DC.publisher", case.get("organization")),
            ("DC.date", created_at), ("DC.language", say.language), ("DC.identifier", "urn:uuid:" + report_id),
            ("DC.format", "text/html"), ("DC.type", "Text.Report"), ("DC.description", description),
            ("DC.rights", "Evidence material; handle according to your case procedures"),
            ("tgwitness:report-id", report_id), ("tgwitness:key-fingerprint", fp),
            ("tgwitness:case-id", case.get("id"))] + extra


def linked_data(*, kind, title, description, created_at, report_id, language, producer, case, about, based_on, fp):
    data = {"@context": "https://schema.org", "@type": "Report", "name": title, "description": description,
            "identifier": "urn:uuid:" + report_id, "dateCreated": created_at, "inLanguage": language,
            "encodingFormat": "text/html", "genre": kind,
            "keywords": ["Telegram", "digital evidence", "chain of custody", "Ed25519", "SHA-256"],
            "creator": {"@type": "SoftwareApplication", "name": "TgWitness", "softwareVersion": producer.get("version"),
                        "url": producer.get("source")},
            "publisher": {"@type": "Organization", "name": producer.get("project"), "url": producer.get("homepage")},
            "about": about, "isBasedOn": based_on,
            "additionalProperty": [{"@type": "PropertyValue", "propertyID": "ed25519-key-fingerprint-sha256", "value": fp}]}
    if case.get("examiner"):
        data["author"] = {"@type": "Person", "name": case["examiner"]}
    if case.get("organization"):
        data["sourceOrganization"] = {"@type": "Organization", "name": case["organization"]}
    if case.get("id"):
        data["additionalProperty"].append({"@type": "PropertyValue", "propertyID": "case-id", "value": case["id"]})
    return data


REPLY_DETAILS_KEYS = ("reply_to_message_id", "reply_to_top_id", "reply_to_peer_id", "forum_topic",
                      "quote_text", "quote_offset", "quote_entities")


def message_times(payload):
    sent = payload.get("sent_at") if "sent_at" in payload else payload.get("date")
    edited = payload.get("edited_at")
    return {"sent_at": sent if isinstance(sent, str) and sent else None,
            "edited_at": edited if isinstance(edited, str) and edited else None}


def shown_details(payload):
    if "details" in payload:
        found = payload["details"]
        return found if isinstance(found, dict) else {}
    raw = payload.get("raw")
    found = message_details.details(raw)
    reply = raw.get("reply_to") if isinstance(raw, dict) else None
    reply = reply if isinstance(reply, dict) else {}
    for key, source in (("reply_to_message_id", "reply_to_msg_id"), ("reply_to_top_id", "reply_to_top_id"),
                        ("quote_offset", "quote_offset")):
        value = payload[key] if key in payload else reply.get(source)
        if type(value) is int:
            found[key] = value
    raw_peer = reply.get("reply_to_peer_id")
    peer_field = {"PeerUser": "user_id", "PeerChat": "chat_id", "PeerChannel": "channel_id"}.get(raw_peer.get("_")) \
        if isinstance(raw_peer, dict) else None
    peer = payload.get("reply_to_peer_id") if "reply_to_peer_id" in payload else \
        message_details.peer_id(raw_peer) if peer_field and type(raw_peer.get(peer_field)) is int else None
    if type(peer) is int:
        found["reply_to_peer_id"] = peer
    topic = payload.get("forum_topic") if "forum_topic" in payload else reply.get("forum_topic")
    if type(topic) is bool:
        found["forum_topic"] = topic
    quote = payload.get("quote_text") if "quote_text" in payload else reply.get("quote_text")
    if isinstance(quote, str) and quote:
        found["quote_text"] = quote
        if "quote_entities" in payload:
            if isinstance(payload["quote_entities"], list):
                found["quote_entities"] = payload["quote_entities"]
        elif "quote_text" not in payload and isinstance(reply.get("quote_entities"), list):
            found["quote_entities"] = message_details.entities(quote, reply["quote_entities"])
    return found


def seconds_text(say, value):
    days, rest = divmod(int(value), 86400)
    hours, minutes = rest // 3600, rest % 3600 // 60
    return " ".join([say("{n} d", n=days)] * bool(days) + [say("{n} h", n=hours)] * bool(hours)
                    + [say("{n} min", n=minutes)] * bool(minutes or not (days or hours)))


def details_html(say, d):
    parts = []
    reply = []
    if type(d.get("reply_to_message_id")) is int:
        reply.append(e(say("Reply to")) + " #" + e(d["reply_to_message_id"]))
    if type(d.get("reply_to_peer_id")) is int:
        reply.append(e(say("Chat of the original message")) + " " + e(d["reply_to_peer_id"]))
    if type(d.get("reply_to_top_id")) is int:
        reply.append(e(say("Reply thread")) + " #" + e(d["reply_to_top_id"]))
    if type(d.get("forum_topic")) is bool:
        reply.append(e(say("Forum topic")) + ": " + e(say("Yes") if d["forum_topic"] else say("No")))
    if reply:
        parts.append('<div class="facts-line">' + " · ".join(reply) + '</div>')
    if isinstance(d.get("quote_text"), str) and d["quote_text"]:
        parts.append('<div class="quoted"><b>' + e(say("Quoted text")) + '</b><blockquote class="text">'
                     + e(d["quote_text"]) + '</blockquote>')
        if type(d.get("quote_offset")) is int:
            parts.append('<div class="facts-line">' + e(say("Quote offset (UTF-16)")) + ": " + e(d["quote_offset"]) + '</div>')
        parts.append(details_html(say, {"text_entities": d.get("quote_entities") or []}) + '</div>')
    forward = d.get("forwarded_from")
    if forward:
        who = forward.get("from_name") or (say("ID {id}", id=forward["from_id"]) if forward.get("from_id") is not None
                                           else say("a hidden sender"))
        parts.append('<div class="fwd">' + e(say("Forwarded from {name}", name=who))
                     + (" · " + e(forward["post_author"]) if forward.get("post_author") else "")
                     + (" · " + say("originally sent") + " " + when(forward["date"]) if forward.get("date") else "")
                     + "</div>")
    behind = [x for x in d.get("text_entities") or [] if x.get("type") in ("text_link", "mention_name")]
    if behind:
        parts.append('<div class="behind"><b>' + e(say("Links behind the text")) + "</b><ul>" + "".join(
            "<li><q>" + e(x.get("text")) + "</q> → " + ("<code>" + e(x["href"]) + "</code>" if x.get("href")
                                                        else e(say("user ID {id}", id=x.get("user_id"))))
            + (' <span class="pill bad">⚠ ' + e(say("the text shows a different address")) + "</span>"
               if x.get("deceptive") else "") + "</li>"
            for x in behind) + "</ul></div>")
    buttons = d.get("buttons")
    if buttons and buttons.get("rows"):
        target = lambda b: b.get("url") or b.get("copy_text") or b.get("query")
        parts.append('<div class="kbd"><b>' + e(say("Buttons")) + "</b>" + "".join(
            '<div class="kbd-row">' + "".join('<span class="key">' + e(b.get("text")) + ("<code>" + e(target(b)) + "</code>"
                                                                                       if target(b) else "") + "</span>"
                                             for b in row) + "</div>" for row in buttons["rows"]) + "</div>")
    facts = []
    if d.get("via_bot_id") is not None:
        facts.append(say("via bot ID {id}", id=d["via_bot_id"]))
    if d.get("author"):
        facts.append(say("signed: {name}", name=d["author"]))
    if type(d.get("views")) is int:
        facts.append(say("views: {n}", n=d["views"]))
    if type(d.get("forwards")) is int:
        facts.append(say("forwards: {n}", n=d["forwards"]))
    if type(d.get("replies")) is int:
        facts.append(say("replies: {n}", n=d["replies"]))
    if d.get("reactions"):
        facts.append(say("reactions: {list}", list=reactions_text(d["reactions"])))
    if type(d.get("auto_delete_seconds")) is int:
        facts.append(say("auto-delete timer: {time}", time=seconds_text(say, d["auto_delete_seconds"])))
    if d.get("protected"):
        facts.append(say("saving and forwarding restricted"))
    if facts:
        parts.append('<div class="facts-line">' + e(" · ".join(facts)) + "</div>")
    return "".join(parts)


def timer_expected(payload):
    return isinstance(payload.get("auto_delete"), dict) and payload["auto_delete"].get("expected") is True


def timer_text(say, kind):
    if kind == "message.deleted":
        return say("The deletion was seen when the message's auto-delete timer expired: an expected removal by the timer.")
    return say("Telegram no longer returned this message at a later check; its auto-delete timer had expired by then.")


def reactions_text(found):
    return " ".join(str(x["reaction"]) + " " + str(x["count"]) for x in found[:20])


IOC_KINDS = {"url": "Link", "domain": "Domain", "wallet": "Wallet", "telegram": "Telegram username",
             "telegram-invite": "Telegram invite link", "email": "E-mail address", "phone": "Phone number",
             "image": "Image (SHA-256)"}
IOC_SOURCES = {"text": "text", "hidden link": "hidden link", "button": "button", "link preview": "link preview",
               "chat description": "chat description", "attachment": "attachment"}
IOC_CHECKSUMS = {"valid": "checksum valid", "none": "no checksum", "not checked": "checksum not checked"}
IOC_SHOWN = 1000


def ioc_rows(say, found):
    for item in found["items"][:IOC_SHOWN]:
        kind = say(IOC_KINDS[item["kind"]])
        if item["kind"] == "wallet":
            kind += " · " + str(item.get("chain")) + " · " + say(IOC_CHECKSUMS.get(item.get("checksum"), "checksum not checked"))
        value = ioc.defang(item["kind"], item["value"]) + (" (" + item["punycode"] + ")" if item.get("punycode") else "") \
            + (" · dHash " + item["dhash"] if item.get("dhash") else "")
        yield kind, value, item["count"], ", ".join(say(IOC_SOURCES.get(s, s)) for s in item["sources"]), \
            item["first_seen"], item


def ioc_lead(say):
    return say("Links, domains, wallets, Telegram accounts, phone numbers and e-mail addresses found in the recorded "
               "messages, written so that they do not open by accident. Each entry cites the record it was found in. "
               "indicators.csv, indicators.stix.json (STIX 2.1) and indicators.misp.json (MISP) carry them for abuse "
               "desks and threat-intelligence platforms.")


def indicators_section(say, number, found, link):
    rows = []
    for kind, value, count, where, first, item in ioc_rows(say, found):
        refs = " ".join('<a href="#data" data-goto="' + e(ref_key(ref)) + '">' + e(ref_label(ref)) + "</a>"
                        for ref in item["refs"][:6])
        rows.append([e(kind), "<code>" + e(value) + "</code>", num(count), e(where),
                     refs + (" …" if count > 6 else ""), when(first)])
    more = found["total"] - len(rows) + found.get("not_listed", 0)
    return (section(number, "indicators", say("Indicators"), ioc_lead(say))
            + table([say("Type"), say("Value"), say("Seen"), say("Where in the message"), say("Messages"),
                     say("First seen")], rows)
            + ('<p class="lead">' + e(say("… and {n} more in indicators.csv.", n=more)) + "</p>" if more > 0 else "")
            + "</section>")


def ref_key(ref):
    return ("r" + str(ref["seq"])) if ref.get("seq") is not None else ("m" + str(ref.get("message")))


def ref_label(ref):
    return "#" + str(ref["seq"]) if ref.get("seq") is not None else "#" + str(ref.get("message"))


def ref_link(parts, folder, key, anchor, prefix=""):
    def link(ref):
        value = ref.get(key)
        for part in parts or []:
            if isinstance(value, int) and part["from"] <= value <= part["to"]:
                return part["file"] + "#" + anchor + str(value)
        return prefix + "#" + anchor + str(value)
    return link


def media_text(say, info):
    from . import ephemeral
    if not info:
        return ""
    size = " × ".join(str(info[k]) for k in ("width", "height") if info.get(k))
    return " · ".join(x for x in (info.get("file_name"), info.get("mime_type"),
                                  size_text(info["size"]) if type(info.get("size")) is int else "", size,
                                  say("{n} s", n=info["duration_seconds"]) if info.get("duration_seconds") else "",
                                  info.get("url"), ephemeral.label(say, info.get("ephemeral_media"))) if x)


def record_html(event, say, titles, options, archive, base=""):
    kind, payload, chat, seq = event["kind"], event["payload"], event["chat_id"], event["seq"]
    cat = category(kind)
    parts = ['<article class="rec cat-' + cat + '" id="r' + str(seq) + '" data-cat="' + cat + '" data-chat="'
             + e("" if chat is None else chat) + '"><header><a class="seq" href="#r' + str(seq) + '">#' + str(seq) + "</a>"
             '<span class="k">' + e(kind_label(say, kind)) + "</span>"]
    if chat is not None:
        parts.append("<span>" + e(titles.get(chat) or say("Chat {id}", id=chat))
                     + (" · " + e(say("message {id}", id=event["message_id"])) if event["message_id"] is not None else "")
                     + "</span>")
    parts.append('<span class="at">' + e(say("Observed")) + " " + when(event["observed_at"]) + "</span></header>")
    sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
    sender_id = payload.get("sender_id", sender.get("id"))
    if sender.get("display_name") or sender_id is not None:
        parts.append('<div class="who">' + e(sender.get("display_name") or say("User {id}", id=sender_id))
                     + (' <span class="uname">@' + e(sender["username"]) + "</span>" if sender.get("username") else "")
                     + (' <span class="sub">· id ' + e(sender_id) + "</span>" if sender_id is not None else "") + "</div>")
    if isinstance(payload.get("text"), str) and payload["text"]:
        parts.append('<div class="text">' + e(payload["text"]) + "</div>")
    if payload.get("text_withheld"):
        parts.append('<div class="withheld">' + e(say("Text withheld in this extract")) + "</div>")
    if event.get("minimised"):
        parts.append('<div class="withheld"><span class="pill warn">' + e(say("Minimised")) + "</span> "
                     + e(say("Withheld: {list}", list=", ".join(say(WITHHELD.get(item, item))
                                                                for item in event["minimised"]))) + "</div>")
    if CATEGORIES.get(kind) in ("message", "edited"):
        found = shown_details(payload)
        parts.append(details_html(say, found))
        if found.get("media_info"):
            parts.append('<div class="file">' + e(say(MEDIA_NAMES.get(found["media_info"]["kind"], "Media"))) + " · "
                         + e(media_text(say, found["media_info"])) + "</div>")
    if kind in ("message.deleted", "message.missing_on_recheck") and timer_expected(payload):
        parts.append('<div class="gone">' + e(timer_text(say, kind)) + "</div>")
    elif kind == "message.deleted":
        parts.append('<div class="gone">' + e(say("Telegram reported this message as deleted.")) + "</div>")
    elif kind == "message.missing_on_recheck":
        parts.append('<div class="gone">' + e(say("Telegram no longer returned this message at a later check.")) + "</div>")
    if kind.startswith("media.") and payload.get("ephemeral_media"):
        from . import ephemeral
        parts.append('<div class="file ephemeral-media">' + e(ephemeral.label(say, payload["ephemeral_media"])) + "</div>")
    if kind == "media.saved" and isinstance(payload.get("media_sha256"), str):
        digest, mime = payload["media_sha256"], payload.get("mime_type")
        parts.append('<div class="file">' + e(payload.get("original_name") or say("Saved file")) + " · " + e(mime or "—")
                     + " · " + e(size_text(payload.get("size"))) + "<br><code>" + e(digest) + "</code></div>")
        if archive and options.get("media_previews") and mime in IMAGES and re.fullmatch("[0-9a-f]{64}", digest):
            parts.append('<img loading="lazy" alt="" src="' + base + "media/" + digest + '">')
    if kind == "media.hashed" and isinstance(payload.get("server_hashes"), dict):
        hashes = payload["server_hashes"]
        digest = hashlib.sha256(canonical(hashes)).hexdigest()
        parts.append('<div class="file">' + e(payload.get("original_name") or "Attachment")
                     + " · " + e(size_text(hashes.get("covered_bytes"))) + " · "
                     + e(str(len(hashes.get("ranges", [])))) + " SHA-256 ranges. File content not downloaded.")
        if archive:
            parts.append('<br><a download href="' + base + 'hashes/' + digest + '.json">Download hash manifest</a>')
        parts.append('</div>')
    footer = ['<span title="' + e(event["hash"]) + '">SHA-256 ' + e(short(event["hash"], 16, 6)) + "</span>"]
    times = message_times(payload)
    if times["sent_at"]:
        footer.append("<span>" + e(say("Sent")) + " " + when(times["sent_at"]) + "</span>")
    if times["edited_at"]:
        footer.append("<span>" + e(say("Edited")) + " " + when(times["edited_at"]) + "</span>")
    if (event.get("source_at") and not any(times.values())
            and not any(key in payload for key in ("sent_at", "edited_at"))):
        footer.append("<span>" + e(say("Telegram time")) + " " + when(event["source_at"]) + "</span>")
    parts.append("<footer>" + "".join(footer) + "</footer>")
    if options.get("design") in report_layouts.DESIGNS:
        parts.append(report_layouts.record_metadata_html(event, say))
    if options.get("raw_records"):
        parts.append('<details class="raw"><summary>' + e(say("Record data")) + "</summary><pre>"
                     + e(json.dumps(payload, ensure_ascii=False, indent=2)) + "</pre></details>")
    return "".join(parts) + "</article>"


def record_items(events, say, titles, options, archive, base=""):
    group, run = options.get("group_heartbeats", True), None
    for event in events:
        if group and event["kind"] == "collector.heartbeat":
            at = (event["seq"], event["observed_at"])
            run = [run[0], at, run[2] + 1] if run else [at, at, 1]
            continue
        if run:
            yield heartbeats_html(say, *run)
            run = None
        yield record_html(event, say, titles, options, archive, base)
    if run:
        yield heartbeats_html(say, *run)


def heartbeats_html(say, first, last, count):
    seqs = "#" + str(first[0]) + ("–#" + str(last[0]) if count > 1 else "")
    return ('<article class="rec cat-system" id="r' + str(first[0]) + '" data-cat="system" data-chat="" data-count="'
            + str(count) + '"><header><a class="seq" href="#r' + str(first[0]) + '">' + e(seqs) + '</a><span class="k">'
            + e(say("Collector heartbeats: {n}", n=count) if count > 1 else say("Collector heartbeat"))
            + '</span><span class="at">' + when(first[1])
            + (" — " + when(last[1]) if count > 1 else "") + '</span></header><div class="facts-line">'
            + e(say("Liveness records the collector writes at a fixed interval while observing, shown here as one "
                    "line. Each one is in the journal file with its own hash and signature."))
            + "</div></article>")


def report_subject(context):
    handover = context.get("handover")
    if handover:
        return {"kind": "handover", "record_count": handover["counts"]["unchanged"] + handover["counts"]["minimised"],
                "head_hash": context.get("head_hash"), "records_sha256": context.get("records_sha256")}
    return {"kind": "evidence", "event_count": context.get("event_count"), "head_hash": context.get("head_hash"),
            **({"events_sha256": context["events_sha256"]} if context.get("events_sha256") else {})}


JSON_FORMAT = "tgwitness-report-json-v1"
JSON_HISTORY_LIMIT = 20000


def seal_statement(context, subject=None):
    options = {**ReportOptions().model_dump(), "language": "en", **(context.get("options") or {})}
    return {"format": SEAL_FORMAT, "report_id": context.get("report_id") or "unsealed",
            "created_at": context.get("created_at"), "language": Words(options["language"]).language,
            "public_key": context.get("public_key"), "producer": context.get("producer"), "case": case_of(options),
            "subject": subject or report_subject(context)}


def report_json(events_again, coverage, context):
    return sealed_json(report_data(events_again, coverage, context), context)


def sealed_json(data, context):
    statement = {**seal_statement(context), "content_sha256": hashlib.sha256(canonical(data)).hexdigest()}
    sign = context.get("sign")
    seal = {"statement": statement, "signature": sign(canonical(statement)) if sign else None,
            "fingerprint": fingerprint(statement["public_key"]) if statement["public_key"] else None}
    return (json.dumps({"format": JSON_FORMAT, "report": data, "seal": seal}, ensure_ascii=False, indent=1)
            + "\n").encode("utf-8")


def report_data(events_again, coverage, context):
    events_again, coverage, context = render_data.factory(events_again), render_data.detached(coverage), render_data.context(context)
    options = {**ReportOptions().model_dump(), "language": "en", **(context.get("options") or {})}
    say = Words(options["language"])
    digest, handover = context.get("report_digest") or context.get("digest") or Digest().result(), context.get("handover")
    anchors, changed = context.get("anchors", []), digest.get("changed") or set()
    histories = history_context(context, events_again, changed, JSON_HISTORY_LIMIT)
    subject = report_subject(context)
    data = {
        "kind": subject["kind"], "report_id": context.get("report_id"), "created_at": context.get("created_at"),
        "language": say.language, "producer": context.get("producer"), "case": case_of(options),
        "subject": {**subject, "public_key": context.get("public_key"), "fingerprint": context.get("fingerprint")},
        "summary": {"categories": digest["categories"], "chats": len(digest["chats"]), "files": len(digest["media"]),
                    "senders": digest["senders"], "first_record_at": digest["first"], "last_record_at": digest["last"],
                    "timestamps": len([a for a in anchors if a.get("kind") != "unreadable"])},
        "chats": [{"chat_id": chat, "title": digest["titles"].get(chat), "records": count}
                  for chat, count in sorted(digest["chats"].items(), key=lambda item: -item[1])],
        "changes": {"messages_changed": len(changed), "listed": len(histories),
                    "messages": [{"chat_id": chat, "message_id": message, **item}
                                 for (chat, message), item in histories.items()]},
        "actions": {"panel_actions": digest.get("action_count", 0), "listed": digest.get("actions") or [],
                    "messages_sent": digest.get("own_total", 0), "sent_listed": digest.get("own_messages") or []},
        "timestamps": anchors, "coverage": coverage, "custody": custody(context),
        "case_assessment": case_assessment.journal(context, coverage),
        "case_board": context.get("case_board"),
        "indicators": digest.get("indicators") or {"items": [], "total": 0, "not_listed": 0},
        "files": context.get("files") or {},
        "parts": [{k: p[k] for k in ("index", "file", "from", "to", "count", "first_at", "last_at", "sha256") if k in p}
                  for p in context.get("parts") or []],
        "limitations": context.get("limits") or [],
        **report_material(context),
    }
    if handover:
        data["minimisation"] = handover
    return json.loads(json.dumps(data, ensure_ascii=False, default=str))


def report_material(context):
    if context.get("handover") or context.get("kind") not in (None, "evidence"):
        return {}
    options = {**ReportOptions().model_dump(), **(context.get("options") or {})}
    examination = {key: options["review_"+key] for key in report_charts.REVIEW_FIELDS if options.get("review_"+key)}
    digest = context.get("report_digest") or context.get("digest") or {}
    raw = digest.get("analytics")
    processors = digest.get("processors") if (digest.get("processors") or {}).get("processors") else None
    analytics = report_analytics.selected(raw, options) if raw and any(options[k] for k in
                 ("activity_chart", "hourly_chart", "participant_chart", "chat_chart", "composition_chart")) else None
    if analytics:
        analytics["participant_labels"] = options["participant_labels"]
        analytics["source"] = {"file": "events.jsonl", "sha256": context.get("events_sha256"),
                               "journal_head": context.get("head_hash"), "records": context.get("event_count")}
    return {**({"selection": context["selection"]} if context.get("selection") else {}),
            "presentation": {k: options[k] for k in ("template", *report_analytics.Presentation.model_fields)},
            **({"analytics": analytics} if analytics else {}),
            **({"processors": processors} if processors else {}),
            **({"examination": {"author": "operator", **examination}} if examination else {})}


def pointing(version):
    details = version["details"]
    media = details.get("media_info") or {}
    return ([(x["type"], x["text"], x.get("href"), x.get("user_id")) for x in details.get("text_entities") or []
             if x["type"] in message_details.POINTING], details.get("buttons"),
            (media.get("kind"), media.get("document_id"), media.get("photo_id")),
            tuple(details.get(key) for key in REPLY_DETAILS_KEYS))


def message_histories(events, changed, limit=HISTORY_LIMIT):
    found = {}
    for event in events:
        key = (event["chat_id"], event["message_id"])
        if key not in changed:
            continue
        if key not in found:
            if len(found) >= limit:
                continue
            found[key] = {"versions": [], "gone": []}
        item, kind, payload = found[key], event["kind"], event["payload"]
        if kind in VERSION_KINDS:
            times = message_times(payload)
            version = {"seq": event["seq"], "kind": kind, "observed_at": event["observed_at"],
                       "text": payload.get("text") if isinstance(payload.get("text"), str) else "",
                       **times, "telegram_at": times["edited_at"] or times["sent_at"],
                       "sender": payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict)
                       else {}, "sender_id": payload.get("sender_id"), "details": shown_details(payload),
                       "withheld": bool(payload.get("text_withheld"))}
            last = item["versions"][-1] if item["versions"] else None
            if kind != "message.edited" and last and last["text"] == version["text"] and pointing(last) == pointing(version) \
                    and message_times(last) == times:
                continue
            item["versions"].append(version)
        elif kind in ("message.deleted", "message.missing_on_recheck"):
            item["gone"].append({"seq": event["seq"], "kind": kind, "observed_at": event["observed_at"],
                                 **({"auto_delete": True} if timer_expected(payload) else {})})
    return found


def history_context(context, events_again, changed, limit=HISTORY_LIMIT):
    if not changed or not events_again:
        return {}
    if context.get("selection") and context.get("source_events"):
        predicate = report_selection.compile_selection(context["selection"]["selection"])
        return report_history.collect(context["source_events"](), changed, limit=limit, predicate=predicate)
    return message_histories(events_again(), changed, limit)


def diff_html(old, new):
    a, b = re.findall(r"\s+|\S+", old), re.findall(r"\s+|\S+", new)
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "equal":
            out.append(e("".join(a[i1:i2])))
        if op in ("delete", "replace"):
            out.append("<del>" + e("".join(a[i1:i2])) + "</del>")
        if op in ("insert", "replace"):
            out.append("<ins>" + e("".join(b[j1:j2])) + "</ins>")
    return "".join(out)


def record_link(seq, linked):
    return ('<a href="#r' + str(seq) + '">#' + str(seq) + "</a>") if linked else "#" + str(seq)


def changes_section(say, number, histories, total, titles, linked, selected=False):
    out = section(number, "changes", say("Selected message histories") if selected else say("Changed and deleted messages"),
                  say("Selected changes with saved message history. Versions outside the filters are marked as context.") if selected else
                  say("Every saved version of each message that was edited, deleted or not found at a later check. "
                      "Removed words are struck through and added words are marked; each step names its signed record."))
    out += "".join(history_card(say, key, item, titles, linked) for key, item in histories.items())
    if total > len(histories):
        out += ('<p class="lead">' + e(say("… and {n} more changed messages, listed under Records.",
                                           n=total - len(histories))) + "</p>")
    return out + "</section>"


def history_card(say, key, item, titles, linked=True):
    chat, message_id = key
    first = item["versions"][0] if item["versions"] else {}
    sender, sender_id = first.get("sender") or {}, first.get("sender_id")
    who = " · ".join(e(part) for part in (sender.get("display_name"),
                                          "@" + sender["username"] if sender.get("username") else "",
                                          "id " + str(sender_id) if sender_id is not None else "") if part)
    steps, previous = [], None
    for number, version in enumerate(item["versions"]):
        if number == 0:
            label = '<span class="pill">' + e(say("Original") if version["kind"] != "message.edited"
                                            else say("First saved version")) + "</span>"
        else:
            label = '<span class="pill warn">' + e(say("Edit {n}", n=number) if version["kind"] == "message.edited"
                                                    else say("Saved version {n}", n=number + 1)) + "</span>"
        times = message_times(version)
        head = label + " " + e(say("observed")) + " " + when(version["observed_at"])
        if times["sent_at"]:
            head += " · " + e(say("Sent")) + " " + when(times["sent_at"])
        if times["edited_at"]:
            head += " · " + e(say("Edited")) + " " + when(times["edited_at"])
        if "sent_at" not in version and "edited_at" not in version and version.get("telegram_at"):
            head += " · " + e(say("Telegram time")) + " " + when(version["telegram_at"])
        head += " · " + record_link(version["seq"], linked and not version.get("context_only"))
        if version.get("context_only"):
            head += ' · <span class="pill">' + e(say("Context outside the report filters")) + '</span>'
        if version.get("withheld"):
            text = "<i>" + e(say("Text withheld in this extract")) + "</i>"
        elif previous is None:
            text = e(version["text"]) if version["text"] else "<i>" + e(say("(no text)")) + "</i>"
            if version["kind"] == "message.edited":
                text = '<p class="lead">' + e(say("The earlier version was not captured.")) + '</p>' + text
        elif version["text"] == previous["text"]:
            text = "<i>" + e(say("Text unchanged")) + "</i>"
        else:
            text = ('<div class="version-compare"><div><b>' + e(say("Before")) + '</b><p>'
                    + e(previous["text"] or say("(no text)")) + '</p></div><div><b>' + e(say("After"))
                    + '</b><p>' + e(version["text"] or say("(no text)")) + '</p></div></div><b>'
                    + e(say("Changes")) + '</b><div>' + diff_html(previous["text"], version["text"]) + '</div>')
        shown = details_html(say, version["details"]) if previous is None or pointing(previous) != pointing(version) else ""
        media = version["details"].get("media_info")
        if media and (previous is None or pointing(previous)[2] != pointing(version)[2]):
            shown += '<div class="file">' + e(say(MEDIA_NAMES.get(media["kind"], "Media"))) + " · " \
                + e(media_text(say, media)) + "</div>"
        steps.append('<li><div class="vhead">' + head + '</div><div class="text">' + text + "</div>" + shown + "</li>")
        previous = version
    for gone in item["gone"]:
        deleted = gone["kind"] == "message.deleted"
        retained = last_saved_before(item["versions"], gone["seq"])
        kept = ('<div class="retained-message"><b>' + e(say("Saved text before deletion") if deleted
                 else say("Saved text before recheck")) + '</b><div class="text">'
                + (e(retained["text"]) if retained and retained["text"] else
                   e(say("(no text)")) if retained else e(say("No message content was saved before this observation.")))
                + '</div></div>')
        steps.append('<li class="gone-step"><div class="vhead"><span class="pill bad">'
                     + e(kind_label(say, gone["kind"])) + "</span> " + e(say("observed")) + " " + when(gone["observed_at"])
                     + " · " + record_link(gone["seq"], linked and not gone.get("context_only"))
                     + (' · <span class="pill">' + e(say("Context outside the report filters")) + '</span>'
                        if gone.get("context_only") else '') + '</div><p class="gone">'
                     + e(timer_text(say, gone["kind"]) if gone.get("auto_delete") else
                         say("This is when the deletion notice was observed; the chat's admin log names the acting "
                             "administrator where the account can read it.") if deleted
                         else say("Telegram no longer returned this message at a later check."))
                     + "</p>" + kept + "</li>")
    return ('<article class="hist" id="m' + e(chat) + "-" + e(message_id) + '"><header><b>'
            + e(titles.get(chat) or say("Chat {id}", id=chat)) + " · " + e(say("message {id}", id=message_id)) + "</b>"
            + (" <span>" + who + "</span>" if who else "") + '</header><ol class="versions">' + "".join(steps)
            + "</ol></article>")


def last_saved_before(versions, seq):
    return next((version for version in reversed(versions) if version["seq"] < seq), None)


WITHHELD = {"raw": "the saved Telegram object", "text": "message text", "sender": "sender identity",
            "actor_id": "sender ID", "other chats": "other chats", "mentions or contact details":
            "mentions or contact details", "file name": "file name", "preview details": "preview details"}
OTHERS = {"show": "shown as recorded", "pseudonymize": "replaced by pseudonyms (P01, P02…)", "omit": "left out"}
TEXTS = {"all": "all message text", "subjects": "text of the chosen people and the observing account only",
         "none": "no message text"}
FILES = {"subjects": "files of the chosen people and the observing account", "all": "files of every message shown",
         "none": "no files"}


def minimisation_section(say, number, handover, journal_count):
    chosen, counts = handover["selection"], handover["counts"]
    period = (when(chosen["since"]) if chosen.get("since") else e(say("from the first record"))) + " — " \
        + (when(chosen["until"]) if chosen.get("until") else e(say("to the last record")))
    others = e(say(OTHERS[chosen["others"]])) + (" · " + e(say("{n} pseudonyms", n=chosen.get("pseudonyms", 0)))
                                               if chosen["others"] == "pseudonymize" else "")
    rows = [(say("Purpose"), '<p class="note">' + e(handover["purpose"]) + "</p>"),
            (say("Chats"), "<br>".join(e(chat) for chat in chosen["chats"])), (say("Period"), period),
            (say("Chosen people"), "<br>".join(e(person) for person in chosen["subjects"])
             or e(say("Everyone in these chats is treated as another person"))),
            (say("Everyone else"), others), (say("Message text"), e(say(TEXTS[chosen["text"]]))),
            (say("Attachments"), e(say(FILES[chosen["attachments"]]))),
            (say("Profile photos"), e(say("included for the chosen people") if chosen["avatars"] else say("not included"))),
            (say("Phone numbers and e-mail addresses in texts"), e(say("masked") if chosen["mask_contacts"] else say("shown")))]
    return (section(number, "minimisation", say("Minimisation"),
                    say("This extract was prepared for a recipient who needs only part of the journal. Other people's "
                        "data is limited to what the purpose requires."))
            + tiles([(say("Shown unchanged"), num(counts["unchanged"]), "ok", "check"),
                     (say("Minimised"), num(counts["minimised"]), "warn", "eye"),
                     (say("Left out"), num(counts["left_out"]), "bad", "x"),
                     (say("Complete journal"), num(journal_count), "accent", "journal")])
            + kv(rows)
            + '<div class="callout info">' + e(say(
                "Records shown unchanged are verified in full: their hash is recomputed and their signature checked. "
                "Minimised records keep the signature over the hash of the original record and name what was "
                "withheld; their content is confirmed against the complete journal by that hash. Records left out "
                "are only counted. Independent timestamps and the witness cover the complete journal; check them with "
                "the complete export.")) + "</div></section>")


ACTION_NAMES = {"open": "Opened a link: joined the chat or started the bot", "send": "Sent a message",
                "press": "Pressed a button"}
OUTCOMES = {"succeeded": ("ok", "done"), "rejected": ("bad", "refused"), "unknown": ("warn", "outcome unknown"),
            "approval_pending": ("warn", "join request awaiting approval")}


def actions_section(say, number, digest, titles, linked):
    actions, own = digest.get("actions") or [], digest.get("own_messages") or []
    out = section(number, "actions", say("Actions by the observing account"),
                  say("Actions taken with the observing account change what others in the chat see. They are listed "
                      "here so that the records around them can be read with that in mind."))
    chat_name = lambda chat: titles.get(chat) or (say("Chat {id}", id=chat) if chat is not None else "—")
    if actions:
        rows = []
        for action in actions:
            request, result = action["request"], action["result"] or {}
            kind = request.get("action")
            if kind == "open":
                preview = action.get("preview") or {}
                detail = e(preview.get("title") or "") + (" <code>" + e(preview.get("link")) + "</code>"
                                                          if preview.get("link") else "")
            elif kind == "send":
                detail = e(request.get("text") or "")
            else:
                button = action.get("button") or {}
                detail = e(button.get("text") or "") + (" · " + e(say("bot answered: {answer}", answer=result["answer"]))
                                                        if result.get("answer") else "")
            tone, label = OUTCOMES.get(result.get("status"), ("warn", "no result recorded"))
            records = [record_link(action["seq"], linked)] + [record_link(result[k], linked)
                                                               for k in ("seq", "message_event") if result.get(k)]
            rows.append([when(action["at"]), e(say(ACTION_NAMES.get(kind, "Action"))),
                         e(chat_name(result.get("chat") or action["chat"])), detail,
                         '<span class="pill ' + tone + '">' + e(say(label)) + "</span>"
                         + (" <small>" + e(result["error_type"]) + "</small>" if result.get("error_type") else ""),
                         " ".join(records)])
        out += "<h3>" + e(say("Through the panel")) + "</h3>" + table(
            [say("Time"), say("Action"), say("Chat"), say("Details"), say("Outcome"), say("Records")], rows)
        if digest.get("action_count", 0) > len(actions):
            out += '<p class="lead">' + e(say("… and {n} more, listed under Records.",
                                              n=digest["action_count"] - len(actions))) + "</p>"
    else:
        out += '<div class="callout ok">' + e(say("No action through the panel is recorded in this journal.")) + "</div>"
    scope = digest.get("own_scope") or []
    if own:
        out += "<h3>" + e(say("Messages the account sent itself")) + "</h3>" + table(
            [say("Time"), say("Chat"), say("Text"), say("Records")],
            [[when(m["at"]), e(chat_name(m["chat"])), e(m["text"]), record_link(m["seq"], linked)] for m in own])
        if digest.get("own_total", 0) > len(own):
            out += '<p class="lead">' + e(say("… and {n} more, listed under Records.",
                                              n=digest["own_total"] - len(own))) + "</p>"
    elif scope and False not in scope:
        out += '<div class="callout ok">' + e(say("Own actions were recorded; this account sent no other messages "
                                                  "in this journal.")) + "</div>"
    if False in scope:
        out += '<div class="callout">' + e(say("Messages this account sent outside TgWitness were not recorded while "
                                               "Own actions was off in the observation scope.")) + "</div>"
    return out + "</section>"


def ranges_text(ranges, total, limit=8):
    pairs = [(r["low"], r["high"]) if isinstance(r, dict) else tuple(r) for r in ranges[:limit]]
    shown = [str(low) if low == high else str(low) + "–" + str(high) for low, high in pairs]
    more = max(total, len(ranges)) - len(shown)
    return ('<span class="ranges">' + e(", ".join(shown) + (" … +" + str(more) if more > 0 else "")) + "</span>"
            if shown else "—")


def coverage_plot(coverage):
    rows = []
    for key in ("continuous", "gaps"):
        spans = []
        for item in coverage.get(key) or []:
            try:
                start, end = (datetime.fromisoformat(item[k].replace("Z", "+00:00")) for k in ("from", "to"))
                if start.tzinfo is None or end.tzinfo is None or end < start:
                    return None
                spans.append((start.timestamp(), end.timestamp()))
            except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
                return None
        rows.append(spans)
    all_spans = rows[0] + rows[1]
    if not all_spans or len(all_spans) > 2000:
        return None
    first, last = min(a for a, _ in all_spans), max(b for _, b in all_spans)
    if last <= first:
        return None
    return {"from": datetime.fromtimestamp(first, timezone.utc).isoformat(),
            "to": datetime.fromtimestamp(last, timezone.utc).isoformat(),
            "rows": [[((a-first)/(last-first), (b-a)/(last-first)) for a, b in spans] for spans in rows]}


def coverage_figure(say, coverage):
    plot = coverage_plot(coverage)
    if not plot:
        return ""
    out = '<figure class="coverage-figure"><figcaption>' + e(say("Observation timeline")) + '</figcaption>'
    for index, label in enumerate(("Continuous observation", "Gaps")):
        out += '<div class="coverage-track"><span>' + e(say(label)) + '</span><svg viewBox="0 0 1000 24" preserveAspectRatio="none" aria-hidden="true">'
        out += '<rect width="1000" height="24" class="coverage-track-bg"/>'
        for x, width in plot["rows"][index]:
            out += f'<rect x="{x*1000:.3f}" y="3" width="{width*1000:.3f}" height="18" class="coverage-span coverage-span-{index}"/>'
        out += '</svg></div>'
    return (out + '<div class="coverage-axis"><span>' + when(plot["from"]) + '</span><span>' + when(plot["to"])
            + '</span></div><p>' + e(say("Recorded intervals only. Blank space is time outside the recorded intervals.")) + '</p></figure>')


def gap_overview(say, summary):
    if not summary or summary.get("status") != "on":
        return None
    sequences = [(c.get("title") or str(c["chat_id"]), c) for c in summary.get("chats") or []]
    if summary.get("account"):
        sequences.append((say("Account-wide message numbering"), summary["account"]))
    settings = summary["parameters"]
    measured, skipped, listed = [], [], []
    for name, item in sequences:
        if item.get("status") != "applicable":
            skipped.append([name, item.get("reason") or "—"])
            continue
        row = [name, str(item["observed_from"]) + " – " + str(item["observed_to"]), item["observed"], item["missing"],
               format(item["density"] * 100, ".2f") + "%", item["largest_gap"]]
        if settings["gap_service_estimate"]:
            row.append((item.get("service_estimate") or {}).get("expected_service_in_missing", "—"))
        measured.append(row)
        for gap in item.get("clusters") or []:
            listed.append([name, str(gap["low"]) + " – " + str(gap["high"]), gap["missing"],
                           gap["after"]["message_id"], gap["after"]["observed_at"],
                           gap["before"]["message_id"], gap["before"]["observed_at"]])
    note = " ".join((
        say("Parameters: gaps of {smallest} or more message numbers are listed, at most {listed} for each numbering.",
            smallest=settings["gap_cluster_min"], listed=settings["gap_clusters_listed"]),
        say("The account-wide numbering is measured where it applies.") if settings["gap_account_sequence"]
        else say("The account-wide numbering is not measured."),
        say("A service-message estimate is shown.") if settings["gap_service_estimate"]
        else say("No service-message estimate is shown.")))
    headers = [say("Message numbering"), say("Observed range"), say("Observed"), say("Numbers missing"), say("Density"),
               say("Largest gap")]
    if settings["gap_service_estimate"]:
        headers.append(say("Estimated service messages"))
    return {"headers": headers, "measured": measured, "skipped": skipped, "listed": listed, "note": note,
            "lead": say("Telegram numbers messages once per channel or supergroup, and once per account across private "
                        "chats, bots and ordinary groups. A missing number is a message that existed and was never "
                        "observed by this collector. A gap names no actor and no reason."),
            "listed_headers": [say("Message numbering"), say("Missing range"), say("Count"),
                               say("Last observed number before"), say("Observed at"),
                               say("First observed number after"), say("Observed at")],
            "skipped_headers": [say("Message numbering"), say("Not measured because")]}


def gap_html(say, summary):
    view = gap_overview(say, summary)
    if view is None:
        return ""
    out = "<h3>" + e(say("Missing message numbers")) + '</h3><p class="lead">' + e(view["lead"]) + "</p>"
    if view["measured"]:
        out += table(view["headers"], [[e(row[0])] + [num(value) for value in row[1:]] for row in view["measured"]])
    if view["listed"]:
        out += "<h4>" + e(say("Listed gaps")) + "</h4>" + table(view["listed_headers"], [
            [e(name), e(numbers), num(count), num(after), when(after_at), num(before), when(before_at)]
            for name, numbers, count, after, after_at, before, before_at in view["listed"]])
    if view["skipped"]:
        out += table(view["skipped_headers"], [[e(name), e(reason)] for name, reason in view["skipped"]])
    return out + '<p class="hint">' + e(view["note"]) + "</p>"


def coverage_section(say, number, coverage):
    if not coverage:
        return ""
    periods = [[when(p["from"]), when(p["to"]), e(span_text(say, p["from"], p["to"]))]
               for p in coverage["continuous"]]
    gaps = [[when(g["from"]), when(g["to"]), e(g.get("reason"))] for g in coverage["gaps"]]
    ids = [[e(c.get("title") or c["chat_id"]), num(c["observed_from"]) + " – " + num(c["observed_to"]), num(c["observed"]),
            num(c["not_observed"]), ranges_text(c.get("ranges") or [], c.get("ranges_total", 0))]
           for c in coverage["unobserved_ids"]]
    out = section(number, "coverage", say("Coverage"),
                  coverage.get("meaning") or say("Recorded observation intervals."))
    out += coverage_figure(say, coverage)
    out += "<h3>" + e(say("Continuous observation")) + "</h3>" + (table([say("Interval start"), say("Interval end"), say("Duration")], periods)
                                                                    if periods else "<p>—</p>")
    if gaps:
        out += "<h3>" + e(say("Gaps")) + "</h3>" + table([say("Interval start"), say("Interval end"), say("Reason")], gaps)
    if ids:
        out += ("<h3>" + e(say("Message IDs per chat")) + '</h3><p class="lead">' + e(say(
            "Channels and supergroups number their messages 1, 2, 3… A number between the first and the last "
            "observed one that was never seen is listed here; coverage.json lists every one."))
            + "</p>" + table([say("Chat"), say("Observed range"), say("Observed"), say("Not observed"),
                              say("Numbers not observed")], ids))
    out += gap_html(say, coverage.get("gap_summary"))
    out += ("<h3>" + e(say("Verifier summary")) + '</h3><p class="lead">' + e(say("As verify.py prints it, in English."))
            + '</p><ul class="mono" style="font-size:13px">' + "".join("<li>" + e(line) + "</li>" for line in coverage_lines(coverage))
            + "</ul>")
    if coverage["notes_total"]:
        out += "<p>" + e(coverage["notes_total"]) + " chat-level coverage note(s), listed as coverage events below.</p>"
    return out + "</section>"


def timestamps_section(say, number, anchors, archive_name, fp):
    out = section(number, "timestamps", say("Timestamps"),
                  say("A timestamp shows that a checkpoint, and every record before it, existed no later than the stamped "
                      "time. Records after the latest stamped checkpoint rely on the collector's clock."))
    latest = latest_stamp(anchors)
    if latest:
        out += ('<div class="callout ok">' + e(say("Latest independently timestamped record: #{n}", n=latest.get("event_count")))
                + " · " + when(latest.get("time")) + " · " + e(latest["service"]) + "</div>")
    else:
        out += ('<div class="callout">' + e(say("No independent timestamps in this export: times come from the collector's "
                                                "clock. Turn on Evidence mode to stamp checkpoints automatically.")) + "</div>")
    rows = []
    for anchor in anchors:
        if anchor.get("kind") == "rfc3161":
            signer = (anchor.get("signed") or {}).get("signer")
            status = ('<span class="pill ok">' + e(say("Token valid")) + "</span> <small>" + e(signer) + "</small>"
                      if case_assessment.verified_stamp(anchor, 2**63 - 1)
                      else '<span class="pill warn">' + e(say("Checkpoint or timestamp awaiting verification")) + "</span>")
            rows.append([num(anchor.get("event_count")), e(anchor["service"]), "RFC 3161", when(anchor.get("time")), status])
        elif anchor.get("kind") == "opentimestamps":
            pending = anchor.get("status") == "pending"
            rows.append([num(anchor.get("event_count")), e(anchor["service"]), "OpenTimestamps · Bitcoin", "—",
                         '<span class="pill ' + ("warn" if pending else "violet") + '">'
                         + e(say("Waiting for Bitcoin confirmation") if pending else say("In Bitcoin; confirm with ots verify"))
                         + "</span>"])
        else:
            rows.append([num(anchor.get("event_count")), e(anchor["service"]), "—", "—",
                         '<span class="pill bad">' + e(say("Unreadable")) + "</span>"])
    if rows:
        out += table([say("Records covered"), say("Service"), say("Type"), say("Stamped at"), say("Status")], rows)
        tsr = next((a for a in anchors if a.get("kind") == "rfc3161"), None)
        ots = next((a for a in anchors if a.get("kind") == "opentimestamps"), None)
        out += "<h3>" + e(say("How to check the timestamps")) + "</h3>"
        out += command("python verify.py " + archive_name + " --fingerprint " + fp + " --tsa-ca tsa-root.pem")
        if tsr:
            out += command("openssl ts -verify -data anchors/" + tsr["checkpoint"] + " -in " + tsr["file"]
                           + " -CAfile tsa-root.pem")
        if ots:
            out += command("ots upgrade " + ots["file"] + "\nots verify -f anchors/" + ots["checkpoint"] + " " + ots["file"])
        out += '<p class="lead">' + e(say("Obtain the authority's root certificate from the authority itself, not from "
                                          "this archive.")) + "</p>"
    return out + "</section>"


def verify_section(say, number, archive_name, fp, report_name, archive, data_name=None):
    data_name = data_name or ("events.jsonl" if report_name == "report.html" else "chat.json")
    steps = ["<li>" + e(say("Get the signer's key fingerprint from a trusted channel, not from this archive.")) + "</li>"]
    if archive:
        steps.append("<li>" + e(say("Check the whole archive: signature, file hashes, message numbers and this report's seal.")
                                if report_name == "chat.html" else
                                say("Check the whole archive: signatures, hashes, record chain and this report's seal."))
                     + command("python verify.py " + archive_name + " --fingerprint " + fp) + "</li>")
        steps.append("<li>" + e(say("Without Python, check the file hashes (not the signature):"))
                     + command("sha256sum -c SHA256SUMS") + command("shasum -a 256 -c SHA256SUMS")
                     + command("Get-FileHash -Algorithm SHA256 " + data_name) + "</li>")
    steps.append("<li>" + e(say("This report on its own:"))
                 + command("python verify.py " + report_name + " --fingerprint " + fp
                           + (" --evidence " + archive_name if archive else "")) + "</li>")
    return (section(number, "verify", say("How to verify"),
                    say("Anyone can repeat these checks. They show whether the material changed after it was signed."))
            + '<ol class="steps">' + "".join(steps) + "</ol></section>")


class EvidenceHTML:
    def __init__(self, events, coverage, context):
        self.events = events
        self.coverage = coverage
        self.context = context
        self.context = self.context or {}
        self.options = {**ReportOptions().model_dump(), "language": "en", **(self.context.get("options") or {})}
        self.say = Words(self.options["language"])
        say = self.say
        self.producer = self.context.get("producer") or {"software": "TgWitness", "version": __version__, "project": "PhishDestroy",
                                               "homepage": "https://phishdestroy.io",
                                               "source": "https://github.com/phishdestroy/TgWitness"}
        self.source_digest = self.context.get("digest") or Digest().result()
        self.digest = self.context.get("report_digest") or self.source_digest
        self.anchors, self.files, self.archive = self.context.get("anchors", []), self.context.get("files", {}), self.context.get("archive", False)
        self.fp, self.report_id = self.context.get("fingerprint") or "", self.context.get("report_id") or "unsealed"
        self.created, self.count, self.head_hash = self.context.get("created_at") or utcnow(), self.context.get("event_count"), self.context.get("head_hash")
        self.case, self.archive_name = case_of(self.options), "tgwitness-evidence.zip"
        self.title = self.options.get("case_title") or say("Telegram observation journal")
        self.description = say("Signed record of Telegram observations made by TgWitness, with integrity and custody details.")
        self.sign = self.context.get("sign")
        self.handover = self.context.get("handover")
        self.material = report_material(self.context)
        self.filtered = self.context.get("report_digest") is not None
        self.label, self.shown_count = say("Evidence report"), self.count
        if self.context.get("selection"):
            self.shown_count = self.context["selection"]["counts"]["selected_records"]
        if self.handover:
            self.archive_name, self.label = "tgwitness-handover.zip", say("Handover extract")
            self.title = self.options.get("case_title") or say("Handover extract")
            self.description = say("Part of a signed TgWitness journal prepared for handover, with other people's data minimised.")
            self.shown_count = self.handover["counts"]["unchanged"] + self.handover["counts"]["minimised"]

    def render(self):
        say = self.say
        self.data_kind = "journal" if self.options.get("timeline") and (self.context.get("viewer") or self.context.get("events_again")) else None
        self.inline = viewer.Inline("journal", self.options["part_size"]) if self.data_kind and not self.context.get("viewer") else None
        self.statement = {"format": SEAL_FORMAT, "report_id": self.report_id, "created_at": self.created, "language": say.language,
                     "public_key": self.context.get("public_key"), "producer": self.producer, "case": self.case,
                     "subject": {**report_subject(self.context), **({"viewer": self.context.get("viewer") or {}} if self.data_kind else {})}}
        rendered = self.chunks()
        if self.options.get("design") in report_layouts.DESIGNS:
            event_factory = self.context.get("events_again") or (lambda: iter(self.events))
            replacements = report_layouts.journal_replacements(event_factory, self.context, say, self.options,
                                                               self.shown_count, bool(self.data_kind))
            rendered = report_layouts.compose(rendered, self.options["design"], say, "journal", replacements)
        yield from sealed(rendered, self.statement, self.sign)

    def chunks(self):
        yield from self.render_header()
        yield from self.render_summary()
        yield from self.render_integrity()
        yield from self.render_custody()
        yield from self.render_records()

    def render_header(self):
        say = self.say
        meta = metadata(say, title=self.title, description=self.description, created_at=self.created, report_id=self.report_id, fp=self.fp,
                        case=self.case, extra=[("tgwitness:format", "tgwitness-handover-v1" if self.handover
                                           else "tgwitness-evidence-v1"),
                                          ("tgwitness:event-count", self.count), ("tgwitness:head-hash", self.head_hash),
                                          ("tgwitness:events-sha256", self.context.get("events_sha256"))])
        linked = linked_data(kind="Handover extract" if self.handover else "Evidence report", title=self.title,
                             description=self.description, created_at=self.created,
                             report_id=self.report_id, language=say.language, producer=self.producer, case=self.case, fp=self.fp,
                             about={"@type": "Dataset", "name": "TgWitness observation journal",
                                    "identifier": self.head_hash, "size": self.count},
                             based_on={"@type": "MediaObject", "name": "events.jsonl",
                                       "encodingFormat": "application/x-ndjson",
                                       "identifier": {"@type": "PropertyValue", "propertyID": "sha256",
                                                      "value": self.context.get("events_sha256")}})
        self.changed, self.events_again = self.digest.get("changed") or set(), self.context.get("events_again")
        links = [("summary", say("Summary"))] + ([("minimisation", say("Minimisation"))] if self.handover else []) \
            + ([("changes", say("Changes"))] if self.changed and self.events_again and self.options.get("show_changes", True) else []) \
            + [("case-assessment", say(case_assessment.TITLE)), ("actions", say("Actions")), ("integrity", say("Integrity"))] \
            + ([] if self.handover else [("timestamps", say("Timestamps"))]) + [("custody", say("Custody")),
                                                                         ("verify", say("Verify"))]
        if self.material.get("analytics"):
            links.insert(1, ("report-analytics", say(report_charts.TITLE)))
        if self.material.get("processors"):
            links.insert(2, ("report-metrics", say(report_charts.METRICS_TITLE)))
        if (self.context.get("case_board") or {}).get("cards"):
            links.insert(2, ("case-board", say("Case Board")))
        if self.material.get("examination"):
            links.insert(1, ("examination", say(report_charts.REVIEW_TITLE)))
        if self.material.get("selection"):
            links.insert(1, ("report-selection", say("Selected data")))
        if self.filtered:
            links = [link for link in links if link[0] != "actions"]
        if self.options.get("timeline"):
            links.append(("records", say("Records")))
        yield (head(say, title=self.title + " · TgWitness", description=self.description, meta=meta, linked=linked,
                    theme=self.options.get("theme", "auto"), template=self.options.get("template", "dossier"), design=self.options.get("design"))
               + bar(say, self.label, links, "journal" if self.data_kind else None)).encode("utf-8")
        facts = [(say("Case ID"), e(self.options.get("case_id"))), (say("Examiner"), e(self.options.get("examiner"))),
                 (say("Organization"), e(self.options.get("organization"))), (say("Created"), when(self.created)),
                 (say("Report ID"), '<span class="mono">' + e(self.report_id[:8]) + "</span>")]
        categories = self.digest["categories"]
        yield (hero(say, self.label + " · " + say("Signed"), self.title, facts, self.fp, self.sign is not None)
               + tiles([(say("Records"), num(self.shown_count), "accent", "layers"),
                        (say("Chats"), num(len(self.digest["chats"])), "accent", "telegram"),
                        (say("Messages"), num(categories["message"]), "accent", "message"),
                        (say("Edits"), num(categories["edited"]), "warn", "edit"),
                        (say("Deletions"), num(categories["deleted"]), "bad", "trash"),
                        *([(say("Missing on recheck"), num(categories["missing"]), "warn", "eye")]
                          if categories.get("missing") else []),
                        (say("Files"), num(len(self.digest["media"])), "violet", "file"),
                        (say("Timestamps"), num(len([a for a in self.anchors if a.get("kind") != "unreadable"])), "ok", "seal"),
                        (say("Observation period"), e(span_text(say, self.digest["first"], self.digest["last"])), "pink", "eye")])
               + (toc(links) if self.data_kind else "")).encode("utf-8")

    def render_summary(self):
        say = self.say
        account = self.context.get("account") or {}
        self.account_text = " · ".join(x for x in (("@" + account["username"]) if account.get("username") else "",
                                              ("id " + str(account["id"])) if account.get("id") else "") if x)
        self.numbers = iter(range(1, 100))
        yield report_selection_view.html(self.material.get("selection"), say).encode("utf-8")
        yield brief_section(say, *evidence_brief(say, self.digest, self.shown_count, self.anchors, self.coverage, self.account_text,
                                                 self.handover, self.filtered)).encode("utf-8")
        analysis_sections = [report_charts.examination_html(self.material.get("examination"), say),
                             report_charts.html(self.material.get("analytics"), say)
                             + report_charts.metrics_html(self.material.get("processors"), say)]
        if self.options.get("template") == "activity":
            analysis_sections.reverse()
        yield ''.join(analysis_sections).encode("utf-8")
        yield case_assessment.html(case_assessment.journal(self.context, self.coverage), say).encode("utf-8")
        yield case_section(say, next(self.numbers), self.options, [
            (say("Observing account"), e(self.account_text)),
            (say("Report language"), '<span data-lang="' + e(say.language) + '">' + e(say.language) + "</span>"),
            (say("Report ID"), "<code>" + e(self.report_id) + "</code>"), (say("Created"), when(self.created)),
            (say("Produced by"), e(self.producer.get("software")) + " " + e(self.producer.get("version")) + " · "
             + e(self.producer.get("project")))]).encode("utf-8")
        if self.handover:
            yield minimisation_section(say, next(self.numbers), self.handover, self.count).encode("utf-8")
        if self.context.get("case_board"):
            from . import board_report
            yield board_report.html(self.context["case_board"], say).encode("utf-8")
        if self.changed and self.events_again and self.options.get("show_changes", True):
            yield changes_section(say, next(self.numbers), history_context(self.context, self.events_again, self.changed), len(self.changed),
                                  self.digest["titles"], bool(self.options.get("timeline")), self.filtered).encode("utf-8")
        if self.options.get("show_indicators", True) and (self.digest.get("indicators") or {}).get("items"):
            yield indicators_section(say, next(self.numbers), self.digest["indicators"],
                                     ref_link(self.context.get("parts"), "records", "seq", "r")).encode("utf-8")
        if not self.filtered:
            yield actions_section(say, next(self.numbers), self.digest, self.digest["titles"], bool(self.options.get("timeline"))).encode("utf-8")

    def render_integrity(self):
        say = self.say
        chain = ('<div class="chain"><div class="link"><b>' + e(say("Chain start")) + "</b><code>0000…0000</code></div>"
                 '<span class="arrow"></span>')
        if self.count and self.count > 1:
            chain += ('<div class="link"><b>#1</b><code>' + e(short(self.source_digest["first_hash"], 8, 4)) + "</code></div>"
                      '<span class="arrow"></span>')
        if self.count and self.count > 2:
            chain += ('<div class="link more"><b>' + e(say("Records in between: {n}", n=self.count - 2)) + "</b><code>SHA-256 · Ed25519"
                      '</code></div><span class="arrow"></span>')
        chain += ('<div class="link head"><b>#' + e(self.count) + " · " + e(say("Head")) + "</b><code>" + e(short(self.head_hash, 8, 4))
                  + "</code></div></div>")
        if self.handover:
            counts = self.handover["counts"]
            yield (section(next(self.numbers), "integrity", say("Integrity"),
                           say("This extract comes from the journal below. Its records keep their signatures; the "
                               "manifest lists the SHA-256 of every file and is signed with the same key."))
                   + (keycard(say, self.fp) if self.fp else "")
                   + kv([(say("Records in the complete journal"), num(self.count)),
                         (say("Head hash of the complete journal"), "<code>" + e(self.head_hash) + "</code>"),
                         (say("Shown unchanged, verified in full"), num(counts["unchanged"])),
                         (say("Minimised, signature verified"), num(counts["minimised"])),
                         (say("Left out"), num(counts["left_out"])),
                         (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"), (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                         (say("Public key"), "<code>" + e(self.context.get("public_key")) + "</code>"),
                         ("records.jsonl SHA-256", "<code>" + e(self.context.get("records_sha256")) + "</code>"
                          if self.context.get("records_sha256") else "")])
                   + "</section>").encode("utf-8")
        else:
            yield (section(next(self.numbers), "integrity", say("Integrity"),
                       say("Every record is linked to the previous one by SHA-256 and signed with Ed25519 when it is "
                           "captured. The manifest lists the SHA-256 of every file and is signed with the same key."))
               + (keycard(say, self.fp) if self.fp else "")
               + '<p class="lead">' + e(say("Compare this fingerprint with a copy kept apart from the collector, for "
                                            "example one published or given to the recipient beforehand.")) + "</p>"
               + chain
               + kv([(say("Records"), num(self.count)), (say("Head hash"), "<code>" + e(self.head_hash) + "</code>"),
                     (say("Independent timestamps"), e(stamps_text(say, self.anchors))),
                     (say("Independent witness"), e(say("Not part of this archive. A witness that kept the journal head "
                                                        "is checked with verify.py --witness."))),
                     (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"), (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                     (say("Public key"), "<code>" + e(self.context.get("public_key")) + "</code>"),
                     ("events.jsonl SHA-256", "<code>" + e(self.context.get("events_sha256")) + "</code>"
                      if self.context.get("events_sha256") else "")])
               + "</section>").encode("utf-8")
        if not self.handover:
            yield timestamps_section(say, next(self.numbers), self.anchors, self.archive_name, self.fp).encode("utf-8")

    def render_custody(self):
        say = self.say
        if self.coverage:
            if self.material.get("selection"):
                yield ('<h2>' + e(say("Source journal coverage")) + '</h2>').encode("utf-8")
            yield coverage_section(say, next(self.numbers), self.coverage).encode("utf-8")
        latest = latest_stamp(self.anchors)
        steps = [(say("Observed and recorded"), when(self.source_digest["first"]) + " — " + when(self.source_digest["last"])),
                 (say("Each record hashed and signed at capture"), e(say("Records: {n}", n=self.count)))]
        if self.handover:
            steps.append((say("Extract prepared and minimised"), when(self.created) + " · " + e(say(
                "{a} shown unchanged, {b} minimised, {c} left out", a=self.handover["counts"]["unchanged"],
                b=self.handover["counts"]["minimised"], c=self.handover["counts"]["left_out"]))))
        else:
            steps.append((say("Checkpoints timestamped"), (when(latest.get("time")) + " · " + e(latest["service"]))
                          if latest else e(say("none in this export"))))
        steps += [(say("Journal verified and exported"), when(self.created)),
                  (say("Report sealed"), when(self.created) + " · " + e(self.options.get("examiner") or ""))]
        yield custody_section(say, next(self.numbers), steps, [
            (say("Acquisition tool"), e(self.producer.get("software")) + " " + e(self.producer.get("version"))),
            (say("Program build"), build_html(say, self.producer)),
            (say("Acquisition method"), e(say("Telegram client observing the account; records chained by SHA-256 and "
                                              "signed with Ed25519 as they are written."))),
            (say("Observing account"), e(self.account_text)),
            (say("Telegram client"), seen_list(say, self.source_digest.get("clients"), client_text)),
            (say("Connection route"), seen_list(say, self.source_digest.get("routes"), route_text)
             + direct_text(say, self.source_digest.get("direct_fallbacks"))),
            (say("Collector clock against Telegram"), clocks_html(say, self.source_digest.get("clocks"))),
            (say("Export host"), e(platform.system() + " " + platform.release() + " · Python " + platform.python_version())),
            (say("Time standard"), "UTC · ISO 8601")]).encode("utf-8")
        yield verify_section(say, next(self.numbers), self.archive_name, self.fp, "report.html", self.archive,
                             "records.jsonl" if self.handover else "events.jsonl").encode("utf-8")
        if self.archive and self.files:
            yield files_section(say, next(self.numbers), self.files, ("report.html", "README.txt", "SHA256SUMS", "manifest.json",
                                                            "manifest.sig")).encode("utf-8")
        yield standards_section(say, next(self.numbers), "handover" if self.handover else "evidence",
                                rfc3161_count(self.anchors, validated=True)).encode("utf-8")
        yield limits_section(say, next(self.numbers), self.context.get("limits") or []).encode("utf-8")

    def render_records(self):
        say = self.say
        data = ""
        if self.data_kind:
            if self.inline is not None:
                for event in self.events_again():
                    self.inline.add(viewer.journal_item(event, self.options.get("raw_records", True)))
                data = self.inline.html(None, self.digest.get("indicators"))
                self.statement["subject"]["viewer"] = self.inline.descriptor()
            if self.statement["subject"]["viewer"].get("files"):
                yield records_pointer(say, next(self.numbers), "records", say("Records"), self.shown_count, say(
                    "{n} records", n=self.shown_count)).encode("utf-8")
            elif not self.shown_count:
                yield (section(next(self.numbers), "records", say("Records")) + '<p>'
                       + e(say("No records match this selection.")) + '</p></section>').encode("utf-8")
            else:
                yield (section(next(self.numbers), "records", say("Records")) + '<div class="callout info">' + e(say(
                    "This journal has {n} records, more than a report saved on its own carries. Open report.html "
                    "inside the signed archive for all of them; the journal files carry every record.", n=self.shown_count))
                    + "</div></section>").encode("utf-8")
        if self.sign is not None:
            yield seal_section(say, next(self.numbers), self.report_id, self.created).encode("utf-8")
        yield ending(say, self.producer, viewer_meta(
            say, "journal", self.context, titles={str(k): v for k, v in self.digest["titles"].items()}, title=self.title,
            archive="tgwitness-handover.zip" if self.handover else "tgwitness-evidence.zip", head_hash=self.head_hash,
            event_count=self.count) if self.data_kind else None, data).encode("utf-8")


def evidence_chunks(events, coverage=None, context=None):
    yield from EvidenceHTML(render_data.records(events), render_data.detached(coverage),
                             render_data.context(context)).render()


MEDIA_NAMES = {"MessageMediaPhoto": "Photo", "MessageMediaDocument": "File", "MessageMediaWebPage": "Link preview",
               "MessageMediaGeo": "Location", "MessageMediaGeoLive": "Location", "MessageMediaVenue": "Location",
               "MessageMediaContact": "Contact", "MessageMediaPoll": "Poll", "MessageMediaDice": "Dice",
               "MessageMediaGame": "Game", "MessageMediaInvoice": "Invoice", "MessageMediaStory": "Story"}


def initials(name):
    words = [w for w in re.split(r"\s+", str(name or "").strip()) if w]
    return ("".join(w[0] for w in words[:2]) or "?").upper()


def colour(peer):
    try:
        return "c" + str(abs(int(peer)) % 7)
    except (TypeError, ValueError):
        return "c5"


def action_text(action):
    words = re.sub(r"(?<!^)(?=[A-Z])", " ", str(action or "").replace("MessageAction", "")).strip()
    return words[:1].upper() + words[1:].lower() if words else ""


FILE_STATUS = {"type_not_collected": "type not collected by the attachment settings",
               "hashes_only": "server hashes saved; file content not downloaded",
               "incomplete_hashes": "incomplete server hashes; file content not downloaded",
               "hashes_unavailable": "server hashes unavailable; file content not downloaded",
               "excluded_by_policy": "excluded by the attachment settings",
               "above_limit": "larger than the attachment limit", "unknown_size": "size unknown; not downloaded",
               "unavailable": "Telegram did not provide the file", "rate_limited": "not downloaded: Telegram rate limit"}


def absent_text(say, low, high):
    return say("Message number {n} absent", n=low) if low == high else \
        say("Message numbers {a}–{b} absent ({n})", a=low, b=high, n=high - low + 1)


def unparsed_text(say, record):
    return say("Message number {n} exists in Telegram but uses a data type this TgWitness version cannot decode "
               "(constructor {c}); its content is not in this export.",
               n=record.get("id"), c=(record.get("unparsed") or {}).get("constructor") or "?")


def absent_before(record, previous):
    number = record.get("id")
    if type(number) is int and type(previous) is int and number > previous + 1:
        return previous + 1, number - 1
    return None


def edited_text(say, edited):
    return say("edited {time}", time=utc_text(edited, False)) if isinstance(edited, str) and edited[:2].isdigit() \
        else say("edited")


def edited_html(say, edited):
    return ('<span title="' + e(edited) + '">' + e(edited_text(say, edited)) + "</span>") if isinstance(edited, str) \
        else e(edited_text(say, edited))


def edited_note(say, stats):
    if not stats.get("edited"):
        return ""
    return ('<div class="callout info">' + e(say(
        "An edited message shows when it was last edited. A history snapshot holds only the current text; earlier "
        "versions exist only where the observation journal recorded them.")) + "</div>")


def poster_notes(say, person, chat):
    notes = []
    if person.get("user_id") is not None and person.get("user_id") == chat.get("id"):
        notes.append(say("The channel itself: its posts appear in the channel's name"))
    if person.get("signatures"):
        notes.append(say("Signed by: {names}", names=", ".join(map(str, person["signatures"][:20]))))
    return notes


def build_html(say, producer):
    rows = [(say("Commit"), producer.get("commit")), (say("Source files SHA-256"), producer.get("source_tree_sha256"))]
    shown = "<br>".join(e(label) + " <code>" + e(value) + "</code>" for label, value in rows if value)
    if not shown:
        return e(say("Not recorded in this export"))
    if producer.get("commit") and producer.get("source_tree_sha256"):
        shown += "<br><small>" + e(say("A checkout of this commit gives the same source files SHA-256 unless files "
                                       "were changed.")) + "</small>"
    return shown


def name_note(say, record):
    notes = [say("name at export")] if record.get("from_basis") == "export_time" else []
    if record.get("from_source") == "contact":
        notes.append(say("from the account's contacts"))
    elif notes and record.get("from_source") == "profile":
        notes.append(say("from the Telegram profile"))
    return " · ".join(notes)


def chat_rows(records, say, preview=False, base="", numbered=False, after=None, metadata=False):
    quotes, previous_day, previous_sender, previous_id = {}, None, object(), after
    for record in records:
        date, sender = record.get("date") or "", record.get("from_id")
        gap = absent_before(record, previous_id) if numbered else None
        if gap:
            yield '<div class="gap-row"><span>' + e(absent_text(say, *gap)) + "</span></div>"
        if record.get("found_on_recheck"):
            yield '<div class="gap-row found"><span>' + e(say("Found on recheck: missing from the history Telegram first "
                                                             "returned")) + "</span></div>"
            previous_sender = object()
        if type(record.get("id")) is int:
            previous_id = record["id"] if type(previous_id) is not int else max(previous_id, record["id"])
        day = date[:10]
        if day and day != previous_day:
            yield '<div class="day"><time datetime="' + e(day) + '" data-day>' + e(day) + "</time></div>"
            previous_day, previous_sender = day, object()
        name = record.get("from") or (str(sender) if sender is not None else say("Unknown"))
        if record.get("type") == "unparsed":
            yield ('<div class="gap-row" id="m' + e(record.get("id")) + '" data-cat="service"><span>'
                   + e(unparsed_text(say, record)) + "</span></div>")
            previous_sender = object()
            continue
        if record.get("type") == "service":
            yield ('<div class="svc-row" id="m' + e(record.get("id")) + '" data-cat="service"><span>' + e(name) + " · "
                   + e(action_text(record.get("action")) or say("Service message")) + "</span>"
                   + (report_layouts.chat_metadata_html(record, say) if metadata else "") + "</div>")
            previous_sender = object()
            continue
        start = (sender, name) != previous_sender
        previous_sender = (sender, name)
        cat = "media" if record.get("media_type") else "edited" if record.get("edited") else "text"
        body = []
        if record.get("selection"):
            selected = record["selection"]
            language = selected.get("language") or {}
            label = say("Context message") if selected.get("role") == "context" else say("Matches export filters")
            body.append('<div class="media-chip">' + e(label) + (" · " + e(language.get("language") or
                        language.get("status")) if language else "") + "</div>")
        if start:
            note = name_note(say, record)
            body.append('<div class="name">' + e(name) + (' <span class="uname">@' + e(record["from_username"]) + "</span>"
                                                          if record.get("from_username") else "")
                        + (' <span class="uname">' + e(note) + "</span>" if note else "") + "</div>")
        reply = record.get("reply_to_message_id")
        if reply:
            quoted = quotes.get(reply)
            body.append('<a class="quote" href="#m' + e(reply) + '"><b>' + e(quoted[0] if quoted else "#" + str(reply))
                        + "</b>" + e(quoted[1] if quoted else say("Earlier message")) + "</a>")
        if record.get("media_type"):
            described = media_text(say, record.get("media_info"))
            saved = record.get("file") if isinstance(record.get("file"), str) else None
            reason = FILE_STATUS.get(record.get("file_status"))
            body.append('<div class="media-chip">◆ ' + e(say(MEDIA_NAMES.get(record["media_type"], "Media")))
                        + (" · " + e(described) if described else "")
                        + (" · " + e(say("saved in the archive")) + ' <code title="' + e(record.get("file_sha256")) + '">'
                           + e(short(record.get("file_sha256"), 8, 4)) + "</code>" if saved
                           else " · " + e(say(reason) if reason else say("not included in this export"))) + "</div>")
            mime = (record.get("media_info") or {}).get("mime_type")
            if saved and preview and (record["media_type"] == "MessageMediaPhoto" or mime in IMAGES) \
                    and re.fullmatch("media/[0-9a-f]{64}", saved):
                body.append('<img class="att" loading="lazy" alt="" src="' + e(base + saved) + '">')
        text = record.get("text") or ""
        if text:
            body.append('<div class="text">' + e(text).replace("\n", "<br>") + "</div>")
        body.append(details_html(say, record))
        if metadata:
            body.append(report_layouts.chat_metadata_html(record, say))
        meta = ('<span class="meta"><a href="#m' + e(record.get("id")) + '">#' + e(record.get("id")) + "</a> · "
                + ('<time datetime="' + e(date) + '" data-clock>' + e(date[11:16]) + "</time>" if date else "")
                + (" · " + edited_html(say, record["edited"]) if record.get("edited") else "") + "</span>")
        yield ('<article class="msg-row' + ("" if start else " cont") + " " + colour(sender) + '" id="m' + e(record.get("id"))
               + '" data-cat="' + cat + '"><div class="ava' + ("" if start else " blank") + '">' + e(initials(name))
               + '</div><div class="bubble">' + "".join(body) + meta + "</div></article>")
        quotes[record.get("id")] = (name, text[:90] or say(MEDIA_NAMES.get(record.get("media_type"), "Media")))
        if len(quotes) > 20000:
            quotes.pop(next(iter(quotes)))


class ChatHTML:
    def __init__(self, meta, records, context):
        self.meta = meta
        self.records = records
        self.context = context
        self.options = {**ReportOptions().model_dump(), "language": "en", **(self.context.get("options") or {})}
        self.say = Words(self.options["language"])
        say = self.say
        self.producer, self.chat, self.stats = self.context["producer"], self.meta.get("chat") or {}, self.context["stats"]
        self.people, self.files, self.fp = self.context["people"], self.context.get("files", {}), self.context["fingerprint"]
        self.report_id, self.created, self.case = self.context["report_id"], self.context["created_at"], case_of(self.options)
        self.chat_title = self.chat.get("title") or say("Chat {id}", id=self.chat.get("id"))
        self.title = self.options.get("case_title") or self.chat_title
        self.description = say("Signed export of a Telegram chat's visible history, made by TgWitness.")
        self.sign = self.context.get("sign")

    def render(self):
        say = self.say
        self.inline = None if self.context.get("viewer") else viewer.Inline("chat", self.options["part_size"])
        self.statement = {"format": SEAL_FORMAT, "report_id": self.report_id, "created_at": self.created, "language": say.language,
                     "public_key": self.context["public_key"], "producer": self.producer, "case": self.case,
                     "subject": {**chat_subject(self.meta, self.context), "viewer": self.context.get("viewer") or {}}}
        rendered = self.chunks()
        if self.options.get("design") in report_layouts.DESIGNS:
            rendered = report_layouts.compose(rendered, self.options["design"], say, "chat",
                                              report_layouts.chat_replacements(self.records, self.context, self.meta, say, self.options))
        yield from sealed(rendered, self.statement, self.sign)

    def chunks(self):
        yield from self.render_header()
        yield from self.render_summary()
        yield from self.render_messages()
        yield from self.render_custody()

    def render_header(self):
        say = self.say
        tags = metadata(say, title=self.title, description=self.description, created_at=self.created, report_id=self.report_id, fp=self.fp,
                        case=self.case, extra=[("tgwitness:format", "tgwitness-chat-export-v1"),
                                          ("tgwitness:chat-id", self.chat.get("id")),
                                          ("tgwitness:message-count", self.meta.get("message_count")),
                                          ("tgwitness:chat-json-sha256", self.context.get("chat_json_sha256"))])
        linked = linked_data(kind="Chat export", title=self.title, description=self.description, created_at=self.created,
                             report_id=self.report_id, language=say.language, producer=self.producer, case=self.case, fp=self.fp,
                             about={"@type": "Conversation", "name": self.chat_title, "identifier": str(self.chat.get("id"))},
                             based_on={"@type": "MediaObject", "name": "chat.json", "encodingFormat": "application/json",
                                       "identifier": {"@type": "PropertyValue", "propertyID": "sha256",
                                                      "value": self.context.get("chat_json_sha256")}})
        yield (head(say, title=self.title + " · TgWitness", description=self.description, meta=tags, linked=linked,
                    theme=self.options.get("theme", "auto"), design=self.options.get("design"))
               + bar(say, say("Chat export"), [("summary", say("Summary")), ("people", say("Participants")),
                                               ("messages", say("Messages")), ("integrity", say("Integrity")),
                                               ("verify", say("Verify"))], "chat")).encode("utf-8")
        facts = [(say("Chat"), e(self.chat_title)), (say("Case ID"), e(self.options.get("case_id"))),
                 (say("Examiner"), e(self.options.get("examiner"))), (say("Organization"), e(self.options.get("organization"))),
                 (say("Created"), when(self.created)), (say("Report ID"), '<span class="mono">' + e(self.report_id[:8]) + "</span>")]
        self.ids = self.context.get("message_ids") or {}
        absent = [(say("Numbers absent"), num(self.ids["missing"]), "bad")] if self.ids.get("numbered_per_chat") else []
        yield (hero(say, say("Chat export") + " · " + say("Signed"), self.title, facts, self.fp, self.sign is not None)
               + tiles([(say("Messages"), num(self.meta.get("message_count")), "accent", "message"),
                        (say("Participants"), num(len(self.people)), "violet", "users"),
                        (say("With media"), num(self.stats["media"]), "violet", "file"),
                        (say("Edited"), num(self.stats["edited"]), "warn", "edit"),
                        (say("Service"), num(self.stats["service"]), "ok", "settings")]
                       + [item + ("tag",) for item in absent]
                       + [(say("Period"), e(span_text(say, self.stats["first_at"], self.stats["last_at"])), "pink", "eye")])
               + toc([("summary", say("Summary")), ("people", say("Participants")), ("messages", say("Messages")),
                      ("integrity", say("Integrity")), ("verify", say("Verify"))])).encode("utf-8")

    def render_summary(self):
        say = self.say
        account = self.meta.get("account") or {}
        self.account_text = " · ".join(x for x in (("@" + account["username"]) if account.get("username") else "",
                                              ("id " + str(account["id"])) if account.get("id") else "") if x)
        self.numbers = iter(range(1, 100))
        yield brief_section(say, *chat_brief(say, self.meta, self.stats, self.ids, self.account_text)).encode("utf-8")
        yield snapshot_analytics.html_section(self.context.get("analytics"), self.options, say).encode("utf-8")
        yield case_assessment.html(case_assessment.snapshot(self.context, "chat", self.meta), say).encode("utf-8")
        yield case_section(say, next(self.numbers), self.options, [
            (say("Chat"), '<span class="chathead"><span class="ava ' + colour(self.chat.get("id")) + '">' + e(initials(self.chat_title))
             + "</span><span><b>" + e(self.chat_title) + "</b><br><small>" + e(self.chat.get("kind")) + " · " + e(self.chat.get("visibility"))
             + " · id " + e(self.chat.get("id")) + "</small></span></span>"),
            (say("First message"), when(self.stats["first_at"])), (say("Last message"), when(self.stats["last_at"])),
            (say("Exporting account"), e(self.account_text)),
            (say("Report language"), '<span data-lang="' + e(say.language) + '">' + e(say.language) + "</span>"),
            (say("Report ID"), "<code>" + e(self.report_id) + "</code>")]).encode("utf-8")
        if source_rows(say, self.meta, self.stats):
            yield source_section(say, next(self.numbers), self.meta, self.stats).encode("utf-8")
        top = max([p["messages"] for p in self.people] or [1])
        rows = [['<span class="ava ' + colour(p["user_id"]) + '" style="width:30px;height:30px;font-size:12px;display:inline-grid">'
                 + e(initials(p["name"] or p["user_id"])) + "</span> <b>" + e(p["name"] or say("Unknown")) + "</b>"
                 + (' <span class="uname">@' + e(p["username"]) + "</span>" if p.get("username") else "")
                 + "".join("<br><small>" + e(line) + "</small>" for line in poster_notes(say, p, self.chat)),
                 "<code>" + e(p["user_id"]) + "</code>", num(p["messages"]),
                 '<div class="meter"><i style="width:' + str(max(2, round(100 * p["messages"] / top))) + '%"></i></div>',
                 when(p["first_message_at"]), when(p["last_message_at"])] for p in self.people[:100]]
        more = ('<p class="lead">' + e(say("… and {n} more, listed in authors.csv and authors.json.", n=len(self.people) - 100))
                + "</p>" if len(self.people) > 100 else "")
        yield (section(next(self.numbers), "people", say("Participants"), say("Everyone who posted in the exported history, "
                                                                          "most active first. Names are the profile at export time."))
               + '<div class="bars">' + table([say("Participant"), "ID", say("Messages"), "", say("First message"),
                                                say("Last message")], rows) + "</div>" + more + "</section>").encode("utf-8")
        if self.ids:
            yield message_ids_section(say, next(self.numbers), self.ids).encode("utf-8")
        if self.context.get("admin_events") is not None:
            yield admin_log_section(say, next(self.numbers), self.meta, self.context["admin_events"]).encode("utf-8")
        if self.options.get("show_indicators", True) and (self.context.get("indicators") or {}).get("items"):
            yield indicators_section(say, next(self.numbers), self.context["indicators"],
                                     ref_link(self.context.get("parts"), "messages", "message", "m")).encode("utf-8")

    def render_messages(self):
        say = self.say
        if self.inline is not None:
            for record in self.records():
                self.inline.add(record)
            self.data = self.inline.html(self.people, self.context.get("indicators"))
            self.statement["subject"]["viewer"] = self.inline.descriptor()
        else:
            self.data = ""
        if self.statement["subject"]["viewer"].get("files"):
            yield (records_pointer(say, next(self.numbers), "messages", say("Messages"), self.meta.get("message_count"), say(
                "{n} messages", n=self.meta.get("message_count")), say("The visible history at export time, oldest first."))
                   .replace('<div class="records-pointer">', edited_note(say, self.stats) + '<div class="records-pointer">', 1)
                   ).encode("utf-8")
        parts = self.meta.get("parts") or []
        accounts = [["<code>" + e(p["statement"].get("account_id")) + "</code>", "<code>"
                     + e(short(fingerprint(p["statement"]["fetched_by_public_key"]), 16, 8)) + "</code>",
                     num(len(p["statement"].get("ranges") or [])), num(sum(r.get("count", 0) for r in p["statement"].get("ranges") or []))]
                    for p in parts]
        yield (section(next(self.numbers), "integrity", say("Integrity"),
                       say("chat.json is authoritative. The manifest lists the SHA-256 of every file and is signed with "
                           "Ed25519; this page carries its own signed seal."))
               + keycard(say, self.fp)
               + kv([("chat.json SHA-256", "<code>" + e(self.context.get("chat_json_sha256")) + "</code>"),
                     (say("Messages"), num(self.meta.get("message_count"))),
                     (say("Independent timestamps"), e(say("None: a chat export is not timestamped."))),
                     (say("Independent witness"), e(say("None: a chat export is not witnessed."))),
                     (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"),
                     (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                     (say("Public key"), "<code>" + e(self.context.get("public_key")) + "</code>")])
               + (("<h3>" + e(say("Accounts that fetched the history")) + "</h3>"
                   + table([say("Account"), say("Key fingerprint"), say("Ranges"), say("Messages")], accounts)) if accounts else "")
               + "</section>").encode("utf-8")

    def render_custody(self):
        say = self.say
        read = reading(self.meta)
        steps = [(say("History read through the Telegram API"),
                  when(read["read_started_at"]) + " — " + when(read["read_finished_at"]) if read["read_started_at"]
                  else e(say("Time of reading not recorded in this export"))),
                 (say("Period of the messages"), when(self.stats["first_at"]) + " — " + when(self.stats["last_at"])),
                 (say("Messages written to chat.json and hashed"), e(say("Messages: {n}", n=self.meta.get("message_count")))),
                 (say("Archive signed and report sealed"), when(self.created) + " · " + e(self.options.get("examiner") or ""))]
        yield custody_section(say, next(self.numbers), steps, [
            (say("Acquisition tool"), e(self.producer.get("software")) + " " + e(self.producer.get("version"))),
            (say("Program build"), build_html(say, self.producer)),
            (say("Acquisition method"), e(say("Full visible history read through the Telegram API; a current snapshot, "
                                              "not a reconstruction of deleted or earlier edited messages."))),
            (say("Exporting account"), e(self.account_text)),
            (say("Telegram client"), e(client_text(say, self.meta["client"])) if isinstance(self.meta.get("client"), dict)
             else e(say("Not recorded in this export"))),
            (say("Connection route"), e(route_text(say, self.meta["route"])) if isinstance(self.meta.get("route"), dict)
             else e(say("Not recorded in this export"))),
            (say("Collector clock against Telegram"), clocks_html(say, read["clock_checks"], "Not recorded in this export")),
            (say("Export host"), e(platform.system() + " " + platform.release() + " · Python " + platform.python_version())),
            (say("Time standard"), "UTC · ISO 8601")]).encode("utf-8")
        yield verify_section(say, next(self.numbers), "tgwitness-chat-export.zip", self.fp, "chat.html", True).encode("utf-8")
        yield files_section(say, next(self.numbers), self.files, ("chat.html", "README.txt", "SHA256SUMS", "manifest.json",
                                                        "manifest.sig")).encode("utf-8")
        yield standards_section(say, next(self.numbers), "chat").encode("utf-8")
        yield limits_section(say, next(self.numbers), self.context.get("limits") or []).encode("utf-8")
        if self.sign is not None:
            yield seal_section(say, next(self.numbers), self.report_id, self.created).encode("utf-8")
        yield ending(say, self.producer, viewer_meta(
            say, "chat", self.context, title=self.title, archive="tgwitness-chat-export.zip", chat_id=self.chat.get("id"),
            chat_title=self.chat_title, numbered=bool(self.ids.get("numbered_per_chat") and not self.ids.get("selection_applied")),
            data_sha256=self.context.get("chat_json_sha256")), self.data).encode("utf-8")


def chat_chunks(meta, records, context):
    yield from ChatHTML(render_data.detached(meta), render_data.factory(records),
                         render_data.context(context)).render()


LABELS = (("scam", "Telegram marks this chat as a scam", "bad"),
          ("fake", "Telegram marks this chat as fake: it impersonates someone", "bad"),
          ("restricted", "Telegram restricts this chat", "warn"), ("verified", "Verified by Telegram", "ok"))
ROLE_NAMES = {"creator": "creator", "admin": "administrator", "member": "member", "restricted": "restricted member",
              "left": "not a member"}
ADMIN_ACTIONS = {"DeleteMessage": "Deleted a message", "EditMessage": "Edited a message", "ParticipantJoin": "Joined",
                 "ParticipantLeave": "Left", "ParticipantInvite": "Invited a member",
                 "ParticipantToggleBan": "Banned or restricted a member", "ParticipantToggleAdmin": "Changed admin rights",
                 "ChangeTitle": "Changed the title", "ChangeAbout": "Changed the description",
                 "ChangeUsername": "Changed the username", "ChangePhoto": "Changed the photo",
                 "UpdatePinned": "Changed the pinned message", "ToggleNoForwards": "Changed content protection"}


def source_rows(say, meta, stats):
    chat = meta.get("chat") or {}
    profile, observer, errors = chat.get("profile") or {}, meta.get("observer") or {}, chat.get("profile_errors") or {}
    if not (profile or observer or errors):
        return []
    labels = [(say(text), tone) for flag, text, tone in LABELS if profile.get(flag)]
    rows = [(say("Telegram labels"), " · ".join(text for text, _ in labels) or say("None: no scam, fake, restricted or "
                                                                                   "verified label"),
             "bad" if any(t == "bad" for _, t in labels) else labels[0][1] if labels else None)]
    for reason in profile.get("restriction_reasons") or []:
        rows.append((say("Restriction"), " · ".join(str(x) for x in (reason.get("platform"), reason.get("reason"),
                                                                     reason.get("text")) if x), "warn"))
    if profile.get("usernames"):
        rows.append((say("Usernames"), ", ".join("@" + n for n in profile["usernames"]), None))
    if profile.get("about"):
        rows.append((say("Description"), profile["about"], None))
    for key, label in (("participants_count", "Members"), ("admins_count", "Administrators")):
        if type(profile.get(key)) is int:
            rows.append((say(label), "{:,}".format(profile[key]).replace(",", " "), None))
    if profile.get("created_at"):
        rows.append((say("Created"), utc_text(profile["created_at"]) + (" · " + say("as “{title}”", title=profile["created_title"])
                                                                        if profile.get("created_title") else ""), None))
    elif profile:
        rows.append((say("Created"), say("Not visible to this account: Telegram did not return message 1"), None))
    for item in stats.get("renames") or []:
        rows.append((say("Title in the history"), utc_text(item.get("date")) + " · “" + str(item["title"]) + "” · #"
                     + str(item.get("id")), None))
    if profile.get("linked_chat_id"):
        rows.append((say("Linked discussion"), "id " + str(profile["linked_chat_id"]), None))
    if profile.get("noforwards"):
        rows.append((say("Content protection"), say("Saving and forwarding restricted for members"), None))
    if profile.get("signatures"):
        rows.append((say("Post signatures"), say("Posts carry the name of the admin who sent them"), None))
    if "hidden_prehistory" in profile:
        rows.append((say("History for new members"), say("Hidden: new members do not see earlier messages")
                     if profile["hidden_prehistory"] else say("Visible"), "warn" if profile["hidden_prehistory"] else None))
    if type(profile.get("available_min_id")) is int and profile["available_min_id"] > 0:
        rows.append((say("Visible to this account"), say("Messages after #{n} only", n=profile["available_min_id"]), "warn"))
    if profile.get("photo_sha256"):
        rows.append((say("Chat photo"), say("SHA-256 {hash}, saved as media/{hash}", hash=profile["photo_sha256"]), None))
    if observer:
        role = say(ROLE_NAMES.get(observer.get("role"), str(observer.get("role"))))
        rows.append((say("This account in the chat"), " · ".join(x for x in (
            role, say("joined {time}", time=utc_text(observer["joined_at"])) if observer.get("joined_at") else "",
            say("invited by ID {id}", id=observer["invited_by"]) if observer.get("invited_by") else "",
            say("admin rights: {list}", list=", ".join(observer["admin_rights"])) if observer.get("admin_rights") else "")
            if x), None))
    if errors:
        rows.append((say("Not answered by Telegram"), ", ".join(k + " (" + v + ")" for k, v in errors.items()), "warn"))
    return rows


def source_section(say, number, meta, stats):
    rows = source_rows(say, meta, stats)
    if not rows:
        return ""
    tone = lambda text, kind: ('<span class="pill ' + kind + '">' + e(text) + "</span>") if kind else e(text)
    return (section(number, "source", say("The chat at export time"), say(
        "What Telegram said about the chat when the export began, and the exporting account's place in it. Labels "
        "such as scam and fake are Telegram's own."))
        + kv([(label, tone(text, kind)) for label, text, kind in rows]) + "</section>")


def recheck_text(say, recheck):
    if not isinstance(recheck, dict):
        return ""
    if recheck.get("error_type"):
        return say("The absent numbers could not be requested again: Telegram answered {error}.",
                   error=recheck["error_type"])
    text = say("{n} absent numbers were requested again by number at {time}; Telegram returned no message for {e} of "
               "them: deleted, or never visible to this account.", n=recheck.get("asked"),
               time=utc_text(recheck.get("asked_at")), e=recheck.get("empty"))
    if recheck.get("returned"):
        text += " " + say("Returned then and included in this export, marked found on recheck: {n}.",
                          n=len(recheck["returned"]))
    if recheck.get("edge"):
        low, high = recheck["edge"]
        text += " " + say("Numbers {a}–{b}, just below the oldest message the history listing returned, were also "
                          "requested; messages found there: {n}.", a=low, b=high, n=recheck.get("edge_found", 0))
    if recheck.get("unchecked"):
        text += " " + say("{n} absent numbers were not requested; they cannot be told apart from deleted ones.",
                          n=recheck["unchecked"])
    elif recheck.get("limit_reached"):
        text += " " + say("Only the first {n} absent numbers were requested.", n=recheck.get("asked"))
    return text


def admin_rows(say, events, limit=500):
    for event in (events or [])[:limit]:
        content, message = "", ""
        if event.get("message"):
            message, content = "#" + str(event["message"].get("id")), event["message"].get("text") or ""
        if event.get("previous") or event.get("new"):
            before, after = event.get("previous") or {}, event.get("new") or {}
            message = "#" + str(after.get("id") or before.get("id"))
            content = (before.get("text") or "") + "  →  " + (after.get("text") or "")
        if not content and ("prev_value" in event or "new_value" in event):
            content = str(event.get("prev_value", "")) + "  →  " + str(event.get("new_value", ""))
        yield (utc_text(event.get("date")), "ID " + str(event.get("user_id")),
               say(ADMIN_ACTIONS.get(event.get("action"), str(event.get("action")))), message, content)


def admin_log_section(say, number, meta, events):
    summary = meta.get("admin_log") or {}
    rows = [[e(t), e(who), e(what), e(ref), e(text)]
            for t, who, what, ref, text in admin_rows(say, events)]
    return (section(number, "admin-log", say("Admin log"), say(
        "Telegram keeps a chat's admin log for about 48 hours and shows it to its admins. It names the account that "
        "deleted or edited a message, with the content: the one record of a deletion that says who did it."))
        + kv([(say("Read at"), when(summary.get("read_at"))), (say("Events"), num(summary.get("events"))),
              (say("Complete"), e(say("yes") if summary.get("complete") else say("no: the export read the first {n}",
                                                                              n=summary.get("events")))),
              (say("Not answered by Telegram"), e(summary["error_type"]) if summary.get("error_type") else "")])
        + table([say("Time"), say("Account"), say("Action"), say("Message"), say("Content")], rows)
        + "</section>")


def chat_subject(meta, context):
    chat = meta.get("chat") or {}
    return {"kind": "chat-export", "chat_id": chat.get("id"), "chat_title": chat.get("title"),
            "message_count": meta.get("message_count"), "chat_json_sha256": context.get("chat_json_sha256")}


def message_ids_section(say, number, ids):
    out = section(number, "ids", say("Message numbers"), say(
        "This export contains a selection. Absent message numbers may have been excluded by the filters."
        if ids.get("selection_applied") else
        "Telegram numbers the messages of a channel or supergroup 1, 2, 3… in order, service messages included. A "
        "number between the first and the last exported message that is absent belongs to a message Telegram did "
        "not return: deleted before the export, or not visible to this account. If only part of the chat was "
        "exported, numbers outside that part are absent too."))
    if not ids.get("numbered_per_chat"):
        return (out + '<p class="lead">' + e(say("In private chats and basic groups the numbers are shared by all of "
                                                  "the account's chats, so gaps say nothing about this chat.")) + "</p></section>")
    first, last, missing = ids["first_id"], ids["last_id"], ids["missing"]
    span = last - first + 1 if isinstance(first, int) and isinstance(last, int) else 0
    share = 100 * missing / span if span and missing else 0
    share = (" (" + ("<0.1" if share < 0.1 else ("%.1f" % share).rstrip("0").rstrip(".")) + " %)") if share else ""
    if ids.get("recheck"):
        out += '<div class="callout info">' + e(recheck_text(say, ids["recheck"])) + "</div>"
    out += kv([(say("First message number"), num(first)), (say("Last message number"), num(last)),
               (say("Numbers in this range"), num(span)), (say("Messages present"), num(ids["present"])),
               (say("Numbers absent"), "<b>" + num(missing) + "</b>" + e(share)),
               (say("Runs of absent numbers"), num(len(ids["missing_ranges"])))])
    shown = ids["missing_ranges"][:200]
    if shown:
        rows = [[num(low) + ("" if low == high else " – " + num(high)), num(high - low + 1)] for low, high in shown]
        out += "<h3>" + e(say("Absent numbers")) + "</h3>" + table([say("Message numbers"), say("Count")], rows)
        out += '<p class="lead">' + e(say("… and {n} more runs.", n=len(ids["missing_ranges"]) - len(shown))
                                      if len(ids["missing_ranges"]) > len(shown) else "") + " " + e(say(
            "message-ids.json lists every absent number; verify.py recounts them from chat.json.")) + "</p>"
    return out + "</section>"

