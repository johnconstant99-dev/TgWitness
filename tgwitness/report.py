"""Readable reports for signed exports: localized, self-contained, printable and sealed.

A report is for people; events.jsonl or chat.json and the signed manifest stay authoritative.
Every report ends with a seal: an Ed25519-signed statement carrying the SHA-256 of every byte
before it, what the report describes (journal head and record count, or the hash of chat.json)
and the case details entered by the operator. verify.py checks the seal inside an archive and
for a report handed over on its own (python verify.py report.html --fingerprint ...). In a
browser the report checks its statement's signature itself, and the hash of its own bytes when
the file is dropped onto it. Nothing in a report loads from the network.

The same export also carries custody.json (who acquired what, how and when, with the standards
followed) and SHA256SUMS, which `sha256sum -c` checks without Python.
"""
import base64
import hashlib
import html
import json
import platform
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__, i18n
from .store import canonical, utcnow
from .verify import (SEAL_CLOSE, SEAL_OPEN, coverage_lines, fingerprint, fingerprint_colors, ots_summary,
                     timestamp_reply_summary, timestamp_signature)

SEAL_FORMAT = "tgwitness-report-seal-v1"
CUSTODY_FORMAT = "tgwitness-custody-v1"
RTL = ("ar", "fa", "ur", "he")
# Bidirectional overrides can make a case title read differently from its bytes.
HIDDEN = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


class ReportOptions(BaseModel):
    """How reports look and what they say about the case. Saved per workspace and recorded,
    signed, in every export manifest and report seal."""
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

    @field_validator("language")
    @classmethod
    def supported(cls, value):
        if value != "auto" and value not in i18n.LANGUAGES:
            raise ValueError("Unsupported report language")
        return value

    @field_validator("case_title", "case_id", "examiner", "organization", "notes")
    @classmethod
    def printable(cls, value, info):
        value = value.replace("\r\n", "\n")
        if HIDDEN.search(value) or (info.field_name != "notes" and ("\n" in value or "\t" in value)):
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
    """Saved options, with "auto" replaced by the language the panel is shown in."""
    options = (saved(store) if store is not None else ReportOptions()).model_dump()
    if options["language"] == "auto":
        options["language"] = language_hint if language_hint in i18n.LANGUAGES else "en"
    return options


def case_of(options):
    """The case details that were filled in, as they appear in manifests, seals and custody records."""
    options = options or {}
    return {key: options[name] for key, name in (("title", "case_title"), ("id", "case_id"), ("examiner", "examiner"),
                                                 ("organization", "organization"), ("notes", "notes"))
            if options.get(name)}


class Words:
    """Report text in one panel language; English keys, as in tgwitness/locales."""
    def __init__(self, language):
        self.language = language if language in i18n.LANGUAGES else "en"
        self.table = i18n.words(self.language)
        self.direction = "rtl" if self.language in RTL else "ltr"

    def __call__(self, text, **values):
        text = self.table.get(text, text)
        if isinstance(text, dict):
            text = text.get("other") or next(iter(text.values()))
        for name, value in values.items():
            text = text.replace("{" + name + "}", str(value))
        return text


def text_keys():
    """Every English text a report can show; each panel language translates all of them."""
    import ast
    from pathlib import Path
    from .chat_export import EXPORT_LIMITS
    from .evidence import LIMITS
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    keys = [node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "say"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    return list(dict.fromkeys(keys + list(SCRIPT_WORDS) + LIMITS + EXPORT_LIMITS + list(MEDIA_NAMES.values()) + ["Media"]))


def e(value):
    return html.escape("" if value is None else str(value))


def script_json(value):
    """JSON safe inside a <script> element: no markup characters, ASCII only."""
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
    """A time readers see in their language (the script formats it); UTC text without scripts."""
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


# Journal records ----------------------------------------------------------------------------

CATEGORY_ORDER = ("message", "edited", "deleted", "media", "reaction", "member", "system")
CATEGORIES = {"message.new": "message", "message.snapshot": "message", "message.recovered": "message",
              "message.edited": "edited", "message.deleted": "deleted", "message.missing_on_recheck": "deleted",
              "media.saved": "media"}
TITLE_KINDS = ("target.changed", "source.discovered", "target.removed")
IMAGES = ("image/jpeg", "image/png", "image/webp", "image/gif")


def category(kind):
    return CATEGORIES.get(kind) or ("reaction" if kind.startswith("reaction.") else
                                    "member" if kind.startswith("membership.") else "system")


def category_label(say, name):
    return {"message": say("Messages"), "edited": say("Edits"), "deleted": say("Deletions"), "media": say("Files"),
            "reaction": say("Reactions"), "member": say("Membership"), "system": say("System")}[name]


def kind_label(say, kind):
    return {"message.new": say("New message"), "message.snapshot": say("History snapshot"),
            "message.recovered": say("Recovered message"), "message.edited": say("Edited message"),
            "message.deleted": say("Deletion notice"), "message.missing_on_recheck": say("Missing on recheck"),
            "media.saved": say("Saved file")}.get(kind, kind)


class Digest:
    """What a report's summary needs, gathered in the pass that verifies the journal."""
    def __init__(self):
        self.categories = dict.fromkeys(CATEGORY_ORDER, 0)
        self.chats, self.titles, self.media, self.senders = {}, {}, {}, set()
        self.first = self.last = self.first_hash = None

    def add(self, event):
        kind, payload, chat = event["kind"], event["payload"], event["chat_id"]
        self.categories[category(kind)] += 1
        self.first, self.last = self.first or event["observed_at"], event["observed_at"]
        self.first_hash = self.first_hash or event["hash"]
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
        digest = payload.get("media_sha256") if kind == "media.saved" else None
        if isinstance(digest, str):
            self.media[digest] = {"mime_type": payload.get("mime_type"), "size": payload.get("size")}

    def result(self):
        return {"categories": self.categories, "chats": self.chats, "titles": self.titles, "media": self.media,
                "senders": len(self.senders), "first": self.first, "last": self.last, "first_hash": self.first_hash}


def describe_anchor(checkpoint_name, checkpoint, proof_name, proof, query=None):
    """A stored timestamp answer as the report shows it, read with the verifier's own checks."""
    digest = hashlib.sha256(checkpoint).digest()
    stem = checkpoint_name[:-len(".json")]
    entry = {"checkpoint": checkpoint_name, "file": "anchors/" + proof_name,
             "service": proof_name[len(stem) + 1:].rsplit(".", 1)[0]}
    try:
        entry["event_count"] = json.loads(checkpoint)["statement"]["event_count"]
        if proof_name.endswith(".tsr"):
            entry.update(kind="rfc3161", time=timestamp_reply_summary(proof, digest, query)["time"])
            try:
                from .tsa_roots import trusted_roots
                entry["signed"] = timestamp_signature(proof, trusted_roots())
            except Exception:
                entry["signed"] = None
        else:
            entry.update(kind="opentimestamps", status=ots_summary(proof, digest)["status"])
    except Exception as exc:
        entry.update(kind="unreadable", error=type(exc).__name__)
    return entry


def latest_stamp(anchors):
    stamped = [a for a in anchors if a.get("kind") == "rfc3161"]
    return max(stamped, key=lambda a: (a.get("event_count") or 0, a.get("time") or "")) if stamped else None


# Standards, files and custody -----------------------------------------------------------------

def standards(say):
    """Practices this export follows. Alignment, not certification."""
    return [
        ("ISO/IEC 27037:2012", say("Identification, collection, acquisition and preservation of digital evidence"),
         say("Capture time, tool, method and account are recorded; every record is hashed and signed when it is captured.")),
        ("ISO/IEC 27042:2015", say("Analysis and interpretation of digital evidence"),
         say("Authoritative files and readable derivatives are kept apart; limitations are stated with the results.")),
        ("NIST SP 800-86", say("Integrating forensic techniques into incident response"),
         say("Collection, examination, analysis and reporting are separate, documented steps.")),
        ("Berkeley Protocol (OHCHR, 2022)", say("Digital open source investigations"),
         say("Source identifiers, capture times, collector and hash values are preserved with each item.")),
        ("RFC 3161", say("Time-Stamp Protocol"),
         say("In Evidence mode, journal checkpoints are stamped by independent timestamp authorities.")),
        ("eIDAS, Art. 41", say("Qualified electronic time stamps (EU)"),
         say("Choose a qualified timestamp authority where a legal presumption of accuracy is needed.")),
        ("RFC 8032 · FIPS 180-4", say("Ed25519 signatures · SHA-256 hashes"),
         say("Records and the manifest are signed with Ed25519; files and records are identified by SHA-256.")),
        ("ISO 8601 · RFC 3339", say("Date and time format"),
         say("All times are written in UTC with an explicit offset.")),
        ("ISO 15836 (Dublin Core) · schema.org", say("Document metadata"),
         say("Reports carry machine-readable metadata for case-management and archiving systems.")),
    ]


def file_purpose(say, name):
    if name.startswith("media/"):
        return say("Saved file, named by its SHA-256")
    if name.startswith("anchors/"):
        return say("Timestamp answer") if not name.endswith(".json") else say("Signed checkpoint that was timestamped")
    return {
        "events.jsonl": say("Authoritative journal: one signed record per line"),
        "events.csv": say("The same records for spreadsheets (formula-safe)"),
        "report.html": say("This readable report, sealed"),
        "coverage.json": say("Observation periods, gaps and message IDs never observed"),
        "custody.json": say("Chain of custody and acquisition details"),
        "SHA256SUMS": say("SHA-256 of every file, for sha256sum -c"),
        "verify.py": say("Standalone verifier (Python 3.11+, cryptography)"),
        "README.txt": say("Instructions in the report language and in English"),
        "manifest.json": say("Signed list of every file with its SHA-256"),
        "manifest.sig": say("Ed25519 signature of manifest.json"),
        "chat.json": say("Authoritative messages, Telegram-export style"),
        "chat.html": say("Readable chat, sealed"),
        "authors.json": say("Everyone who posted, with message counts"),
        "authors.csv": say("The same list for spreadsheets"),
    }.get(name, "")


def sha256sums(hashes):
    """The format `sha256sum -c` and `shasum -a 256 -c` read."""
    return "".join(hashes[name] + "  " + name + "\n" for name in sorted(hashes)).encode("utf-8")


def custody(context):
    """Who acquired what, how and when: a structured record for case-management systems."""
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
                   "report_options": {k: options.get(k) for k in ("theme", "timeline", "raw_records", "media_previews")}},
        "integrity": {"hash": "SHA-256 (FIPS 180-4)", "signature": "Ed25519 (RFC 8032)",
                      "public_key": context["public_key"], "fingerprint": fingerprint(context["public_key"]),
                      "manifest": "manifest.json lists the SHA-256 of every file; manifest.sig signs it",
                      "report_seal": "the readable report ends with a signed seal over its own bytes"},
        "standards": [{"reference": ref, "title": title, "how": how} for ref, title, how in standards(say)],
        "custody_log": [{"at": context["created_at"], "action": "exported and sealed",
                         "by": options.get("examiner") or None, "tool": "TgWitness " + __version__}],
        "statement": "Alignment with the listed practices, not certification. Integrity is verifiable; "
                     "source authenticity and clock accuracy are not established by signatures.",
    }
    if kind == "evidence":
        digest = context["digest"]
        record["acquisition"].update(first_record_at=digest["first"], last_record_at=digest["last"],
                                     record_count=context["event_count"], head_hash=context["head_hash"],
                                     chats=len(digest["chats"]))
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
                                     accounts=[p["statement"].get("account_id") for p in meta.get("parts") or []] or None)
    return record


def readme(context, files, english):
    """README.txt in the report language, then the English instructions."""
    say = Words(context["options"].get("language", "en"))
    options, fp = context["options"], fingerprint(context["public_key"])
    evidence = context["kind"] == "evidence"
    archive = "tgwitness-evidence.zip" if evidence else "tgwitness-chat-export.zip"
    title = say("Evidence archive") if evidence else say("Chat export")
    lines = ["TgWitness · " + title, options.get("case_title") or "", "=" * 64]
    for label, key in ((say("Case ID"), "case_id"), (say("Examiner"), "examiner"), (say("Organization"), "organization")):
        if options.get(key):
            lines.append(label + ": " + options[key])
    lines += [say("Created") + ": " + utc_text(context["created_at"]), say("Report ID") + ": " + context["report_id"],
              say("Signing key fingerprint") + ": " + fp, "", say("What is in this archive"), "-" * 64]
    shown = [n for n in sorted(files) if not n.startswith(("media/", "anchors/"))]
    for name in shown:
        lines.append("  " + name.ljust(16) + file_purpose(say, name))
    for prefix in ("media/", "anchors/"):
        count = sum(1 for n in files if n.startswith(prefix))
        if count:
            lines.append("  " + prefix.ljust(16) + file_purpose(say, prefix + ("x.json" if prefix == "anchors/" else ""))
                         + " (" + str(count) + ")")
    lines += ["", say("How to verify"), "-" * 64,
              "1. " + say("Get the signer's key fingerprint from a trusted channel, not from this archive."),
              "   python verify.py " + archive + " --fingerprint " + fp,
              "2. " + say("Without Python, check the file hashes (not the signature):"),
              "   sha256sum -c SHA256SUMS            (macOS: shasum -a 256 -c SHA256SUMS)",
              "   Get-FileHash -Algorithm SHA256 <file>   (Windows PowerShell)"]
    if evidence:
        lines += ["3. " + say("Timestamps: check an RFC 3161 answer with OpenSSL and the authority's root certificate:"),
                  "   openssl ts -verify -data anchors/<checkpoint>.json -in anchors/<checkpoint>.<service>.tsr"
                  " -CAfile tsa-root.pem",
                  "   " + say("OpenTimestamps proofs: ots upgrade, then ots verify -f CHECKPOINT.json PROOF.ots"),
                  "4. " + say("The report alone:") + " python verify.py report.html --fingerprint " + fp
                  + " --evidence " + archive]
    else:
        lines += ["3. " + say("The report alone:") + " python verify.py chat.html --fingerprint " + fp
                  + " --evidence " + archive]
    lines += ["", say("Limitations"), "-" * 64] + ["- " + say(item) for item in context["limits"]]
    text = "\n".join(lines) + "\n"
    if say.language != "en":
        text += "\n" + "=" * 64 + "\nEnglish\n" + "=" * 64 + "\n"
    return (text + english).encode("utf-8")


# Page parts ---------------------------------------------------------------------------------

MARK = ('<svg viewBox="0 0 48 48" aria-hidden="true"><defs><linearGradient id="tgw-g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#1d4ed8"/></linearGradient></defs>'
        '<rect width="48" height="48" rx="13" fill="url(#tgw-g)"/><path d="M15 12h18a6 6 0 0 1 6 6v10a6 6 0 0 1-6 6H22'
        'l-5.6 4.6c-.5.4-1.4.1-1.4-.6V34a6 6 0 0 1-6-6V18a6 6 0 0 1 6-6Z" fill="#fff"/><circle cx="24" cy="23" r="5.2" '
        'fill="none" stroke="#1d4ed8" stroke-width="2.6"/><circle cx="24" cy="23" r="1.8" fill="#1d4ed8"/></svg>')
STAMP = ('<svg viewBox="0 0 160 160" aria-hidden="true"><defs><path id="tgw-ring" d="M80,80 m-61,0 a61,61 0 1,1 122,0 '
         'a61,61 0 1,1 -122,0"/></defs><circle cx="80" cy="80" r="77" class="rim"/><circle cx="80" cy="80" r="50" '
         'class="dash"/><text class="ring"><textPath href="#tgw-ring">TGWITNESS · ED25519 · SHA-256 · SEALED ·'
         '</textPath></text><circle cx="80" cy="80" r="34" class="core"/><path class="tick" d="M64 81l11 11 22-24"/>'
         '<path class="cross" d="M68 68l24 24M92 68L68 92"/></svg>')
ICON_PRINT = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16'
              'a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z"/></svg>')
ICON_THEME = ('<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/>'
              '<path d="M12 3a9 9 0 0 1 0 18z" class="fill"/></svg>')

LIGHT = ("--bg:#eef2f8;--bg2:#e7edf5;--card:#fff;--ink:#0f1b2d;--soft:#334155;--muted:#64748b;--line:#dde5ef;"
         "--accent:#2563eb;--tint:#e9f0ff;--ok:#047857;--oktint:#e2f6ec;--warn:#b45309;--warntint:#fff3df;"
         "--bad:#c62828;--badtint:#fdecec;--violet:#7c3aed;--violettint:#f1eafe;--pink:#db2777;--bubble:#fff;"
         "--chatbg:linear-gradient(160deg,#d9e7d0,#c8dcd6 40%,#cfd8e8);"
         "--shadow:0 1px 2px rgba(15,27,45,.05),0 10px 30px -12px rgba(15,27,45,.18);color-scheme:light")
DARK = ("--bg:#0a111f;--bg2:#101a2c;--card:#111b2d;--ink:#e6edf7;--soft:#c3cfdf;--muted:#8a9ab0;--line:#22314a;"
        "--accent:#60a5fa;--tint:#14294d;--ok:#34d399;--oktint:#0c2c22;--warn:#fbbf24;--warntint:#2e2410;"
        "--bad:#f87171;--badtint:#351717;--violet:#a78bfa;--violettint:#241b3f;--pink:#f472b6;--bubble:#182538;"
        "--chatbg:linear-gradient(160deg,#0e1a2b,#132235 50%,#0f1b2e);"
        "--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px -12px rgba(0,0,0,.6);color-scheme:dark")
CSS = (
    ":root{" + LIGHT + "}:root[data-theme=dark]{" + DARK + "}"
    "@media (prefers-color-scheme:dark){:root[data-theme=auto]{" + DARK + "}}"
    "*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth;scroll-padding-top:70px}"
    "body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,"
    "'Noto Sans','Helvetica Neue',Arial,sans-serif}"
    "a{color:var(--accent)}code,.mono,pre{font-family:ui-monospace,SFMono-Regular,'Cascadia Mono',Menlo,Consolas,monospace}"
    "code{font-size:.9em;overflow-wrap:anywhere}"
    ".bar{position:sticky;top:0;z-index:9;display:flex;align-items:center;gap:14px;padding:10px 22px;"
    "background:color-mix(in srgb,var(--card) 84%,transparent);backdrop-filter:saturate(1.4) blur(14px);"
    "border-bottom:1px solid var(--line)}"
    ".brand{display:flex;align-items:center;gap:10px;font-weight:750;letter-spacing:.2px;white-space:nowrap}"
    ".brand svg{width:28px;height:28px}.brand small{font-weight:500;color:var(--muted)}"
    ".bar nav{display:flex;gap:2px;margin-inline-start:auto;flex-wrap:wrap;justify-content:flex-end}"
    ".bar nav a{color:var(--soft);text-decoration:none;font-size:13px;padding:6px 10px;border-radius:8px}"
    ".bar nav a:hover{background:var(--tint);color:var(--accent)}"
    ".icon-btn{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:10px;border:1px solid var(--line);"
    "background:var(--card);color:var(--soft);cursor:pointer}.icon-btn:hover{color:var(--accent);border-color:var(--accent)}"
    ".icon-btn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linejoin:round}"
    ".icon-btn svg .fill{fill:currentColor;stroke:none}"
    "main{max-width:1120px;margin:0 auto;padding:26px 20px 64px}"
    ".hero{position:relative;overflow:hidden;border-radius:24px;padding:34px 38px;color:#eaf1ff;"
    "background:radial-gradient(900px 380px at 88% -30%,rgba(96,165,250,.42),transparent 62%),"
    "radial-gradient(600px 300px at -10% 120%,rgba(124,58,237,.28),transparent 60%),"
    "linear-gradient(135deg,#091327 0%,#122651 55%,#1b45b8 130%);box-shadow:var(--shadow);"
    "display:grid;grid-template-columns:1fr auto;gap:30px;align-items:center;"
    "-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".hero:before{content:'';position:absolute;inset:0;pointer-events:none;"
    "background-image:linear-gradient(rgba(255,255,255,.055) 1px,transparent 1px),"
    "linear-gradient(90deg,rgba(255,255,255,.055) 1px,transparent 1px);background-size:26px 26px;"
    "-webkit-mask-image:linear-gradient(90deg,transparent 10%,#000 70%);mask-image:linear-gradient(90deg,transparent 10%,#000 70%)}"
    ".hero>*{position:relative}.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;font-weight:750;opacity:.82}"
    ".hero h1{font-size:clamp(25px,3.6vw,38px);line-height:1.12;margin:10px 0 18px;letter-spacing:-.015em;overflow-wrap:anywhere}"
    ".facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px 26px;font-size:14px}"
    ".facts div{min-width:0}.facts span{display:block;opacity:.66;font-size:12px;text-transform:uppercase;letter-spacing:.06em}"
    ".facts b{font-weight:620;overflow-wrap:anywhere}"
    ".stamp{width:164px;text-align:center}.stamp svg{width:164px;height:164px;display:block}"
    ".stamp .rim{fill:rgba(255,255,255,.06);stroke:rgba(255,255,255,.6);stroke-width:2}"
    ".stamp .dash{fill:none;stroke:rgba(255,255,255,.35);stroke-width:1.5;stroke-dasharray:3 4}"
    ".stamp .ring{font:700 11px system-ui,sans-serif;letter-spacing:2.5px;fill:#fff}"
    ".stamp .core{fill:rgba(255,255,255,.14);stroke:rgba(255,255,255,.5);transition:fill .4s}"
    ".stamp .tick,.stamp .cross{fill:none;stroke:#fff;stroke-width:7;stroke-linecap:round;stroke-linejoin:round;opacity:0;"
    "transition:opacity .4s}.stamp.ok .core{fill:#10b981}.stamp.ok .tick{opacity:1}"
    ".stamp.bad .core{fill:#ef4444}.stamp.bad .cross{opacity:1}.stamp.unknown .tick{opacity:.5}"
    ".stamp-state{font-size:12px;line-height:1.35;opacity:.86;margin-top:6px}"
    ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:12px;margin:18px 0 6px}"
    ".tile{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px 13px;box-shadow:var(--shadow)}"
    ".tile i{display:block;width:26px;height:4px;border-radius:4px;margin-bottom:12px;background:var(--c,var(--accent))}"
    ".tile b{display:block;font-size:25px;line-height:1.1;letter-spacing:-.02em;font-weight:760}"
    ".tile>span{color:var(--muted);font-size:13px}"
    "section.card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:24px 26px;margin:18px 0;"
    "box-shadow:var(--shadow)}"
    "section.card>h2{display:flex;align-items:center;gap:11px;font-size:19px;margin:0 0 6px;letter-spacing:-.01em}"
    "h2 .num{display:inline-grid;place-items:center;min-width:30px;height:30px;border-radius:10px;background:var(--tint);"
    "color:var(--accent);font-size:14px;font-weight:750}"
    "h3{font-size:15px;margin:20px 0 8px}.lead{color:var(--muted);margin:0 0 16px;max-width:78ch}"
    "table{width:100%;border-collapse:collapse}"
    ".kv th{width:32%;text-align:start;font-weight:600;color:var(--soft);vertical-align:top;padding:9px 14px 9px 0;"
    "border-top:1px solid var(--line)}.kv td{padding:9px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}"
    ".grid{font-size:14px}.grid th{text-align:start;font-size:11.5px;text-transform:uppercase;letter-spacing:.07em;"
    "color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--line)}"
    ".grid td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}"
    ".grid tr:last-child td{border-bottom:0}.scroll{overflow-x:auto}"
    ".pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;font-size:12px;"
    "font-weight:650;background:var(--tint);color:var(--accent);white-space:nowrap}"
    ".pill.ok{background:var(--oktint);color:var(--ok)}.pill.warn{background:var(--warntint);color:var(--warn)}"
    ".pill.bad{background:var(--badtint);color:var(--bad)}.pill.violet{background:var(--violettint);color:var(--violet)}"
    ".pill.grey{background:var(--bg2);color:var(--muted)}"
    ".callout{border-radius:14px;padding:13px 16px;background:var(--warntint);border:1px solid "
    "color-mix(in srgb,var(--warn) 30%,transparent);margin:12px 0}"
    ".callout.ok{background:var(--oktint);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}"
    ".callout.bad{background:var(--badtint);border-color:color-mix(in srgb,var(--bad) 30%,transparent)}"
    ".callout.info{background:var(--tint);border-color:color-mix(in srgb,var(--accent) 25%,transparent)}"
    ".keycard{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;border:1px solid var(--line);"
    "border-radius:16px;padding:18px 20px;background:var(--bg2);margin:6px 0 16px}"
    ".keycard small{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}"
    ".fp{display:grid;grid-template-columns:repeat(8,auto);gap:4px 12px;justify-content:start;font-family:ui-monospace,"
    "SFMono-Regular,Menlo,Consolas,monospace;font-size:15.5px;font-weight:600;letter-spacing:.03em}"
    ".swatch{display:grid;grid-template-columns:repeat(4,22px);gap:4px;-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    ".swatch i{width:22px;height:22px;border-radius:6px}"
    ".chain{display:flex;align-items:stretch;overflow-x:auto;padding:4px 0 8px;margin:4px 0 14px}"
    ".link{flex:0 0 auto;border:1px solid var(--line);background:var(--bg2);border-radius:13px;padding:10px 14px;min-width:150px}"
    ".link b{display:block;font-size:13px}.link code{font-size:12px;color:var(--muted)}"
    ".link.head{border-color:var(--accent);background:var(--tint)}.link.more{border-style:dashed;background:transparent}"
    ".arrow{flex:0 0 30px;align-self:center;height:2px;background:linear-gradient(90deg,var(--line),var(--accent));position:relative}"
    ".arrow:after{content:'';position:absolute;inset-inline-end:-1px;top:-4px;border:5px solid transparent;"
    "border-inline-start-color:var(--accent)}"
    ".steps{counter-reset:s;list-style:none;padding:0;margin:8px 0 0}"
    ".steps>li{position:relative;padding:0 0 18px 46px}.steps>li:before{counter-increment:s;content:counter(s);position:absolute;"
    "inset-inline-start:0;top:-2px;width:31px;height:31px;border-radius:50%;display:grid;place-items:center;"
    "background:var(--accent);color:#fff;font-weight:750;font-size:14px}"
    "[dir=rtl] .steps>li{padding:0 46px 18px 0}"
    "pre.cmd{position:relative;background:#0a1222;color:#d6e2f5;border-radius:12px;padding:12px 14px;white-space:pre-wrap;"
    "overflow-wrap:anywhere;margin:8px 0;font-size:13px;direction:ltr;text-align:left;-webkit-print-color-adjust:exact;print-color-adjust:exact}"
    "pre.cmd code{display:block;padding-inline-end:120px}pre.cmd .copy{position:absolute;top:8px;right:8px;border:1px solid #2a3b57;background:#14213a;color:#b9c8df;"
    "border-radius:8px;font-size:12px;padding:4px 9px;cursor:pointer}pre.cmd .copy:hover{color:#fff}"
    ".tools{position:sticky;top:56px;z-index:4;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 0 12px;"
    "background:var(--card)}"
    ".tools input[type=search],.tools select{font:inherit;font-size:14px;padding:8px 12px;border-radius:10px;"
    "border:1px solid var(--line);background:var(--bg2);color:var(--ink)}.tools input[type=search]{flex:1 1 220px}"
    ".chip{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--soft);border-radius:999px;"
    "padding:5px 12px;font-size:13px;cursor:pointer}.chip b{font-weight:650;margin-inline-start:4px;opacity:.7}"
    ".chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}"
    ".shown{margin-inline-start:auto;color:var(--muted);font-size:13px}"
    ".rec{border:1px solid var(--line);border-inline-start:4px solid var(--c);border-radius:14px;padding:11px 16px 9px;"
    "margin:9px 0;background:var(--card);break-inside:avoid}"
    ".rec header{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;font-size:13px;color:var(--muted)}"
    ".rec .seq{font-weight:700;color:var(--muted);text-decoration:none;font-family:ui-monospace,Menlo,Consolas,monospace}"
    ".rec .k{font-weight:700;color:var(--c)}.rec .at{margin-inline-start:auto}"
    ".who{font-weight:650;margin-top:4px}.who .sub,.uname{font-weight:500;color:var(--muted)}"
    ".rec .text{white-space:pre-wrap;overflow-wrap:anywhere;margin:5px 0 3px}"
    ".rec .gone{color:var(--bad);font-size:14px;margin-top:4px}.rec .file{font-size:14px;margin-top:4px}"
    ".rec img{display:block;max-width:min(100%,420px);max-height:340px;border-radius:12px;margin:8px 0;border:1px solid var(--line)}"
    ".rec footer{display:flex;flex-wrap:wrap;gap:10px;font-size:11.5px;color:var(--muted);margin-top:4px}"
    ".cat-message{--c:var(--accent)}.cat-edited{--c:var(--warn)}.cat-deleted{--c:var(--bad)}.cat-media{--c:var(--violet)}"
    ".cat-reaction{--c:var(--pink)}.cat-member{--c:var(--ok)}.cat-system{--c:var(--muted)}"
    "details.raw summary{cursor:pointer;color:var(--muted);font-size:12px;margin-top:4px}"
    "details.raw pre{background:var(--bg2);border-radius:10px;padding:10px 12px;font-size:12px;white-space:pre-wrap;"
    "overflow-wrap:anywhere;max-height:420px;overflow:auto}"
    ".note{white-space:pre-wrap;background:var(--bg2);border-radius:12px;padding:12px 14px;margin:0}"
    ".timeline{list-style:none;margin:6px 0 0;padding:0;position:relative}"
    ".timeline:before{content:'';position:absolute;inset-inline-start:9px;top:6px;bottom:6px;width:2px;background:var(--line)}"
    ".timeline li{position:relative;padding:0 0 16px 34px}[dir=rtl] .timeline li{padding:0 34px 16px 0}"
    ".timeline li:before{content:'';position:absolute;inset-inline-start:3px;top:4px;width:14px;height:14px;border-radius:50%;"
    "background:var(--card);border:3px solid var(--accent)}.timeline li b{display:block}"
    ".timeline li span{color:var(--muted);font-size:14px}"
    ".sign td{height:40px}.drop{border:2px dashed var(--line);border-radius:16px;padding:18px;text-align:center;"
    "color:var(--muted);margin-top:14px;transition:background .2s,border-color .2s}"
    ".drop.over{border-color:var(--accent);background:var(--tint)}.drop label{color:var(--accent);cursor:pointer;font-weight:600}"
    ".drop input{position:absolute;width:1px;height:1px;opacity:0}"
    ".bars td.bar-cell{width:38%}.meter{height:8px;border-radius:5px;background:var(--bg2);overflow:hidden}"
    ".meter i{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,var(--accent),var(--violet))}"
    "footer.end{color:var(--muted);font-size:13px;text-align:center;margin:30px 0 10px;line-height:1.7}"
    "footer.end b{color:var(--soft)}"
    # Chat view.
    ".chatwall{background:var(--chatbg);border-radius:18px;padding:14px clamp(8px,2vw,22px) 18px;"
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
    ".c0{--h1:#ff885e;--h2:#e65a5a}.c1{--h1:#ffcd6a;--h2:#e8912f}.c2{--h1:#e0a2f3;--h2:#9a5bd3}.c3{--h1:#a0de7e;--h2:#3fa64a}"
    ".c4{--h1:#53edd6;--h2:#1aa6a6}.c5{--h1:#72d5fd;--h2:#2a8fd6}.c6{--h1:#ffa8a8;--h2:#e05c96}"
    ".chathead{display:flex;gap:16px;align-items:center}.chathead .ava{flex:0 0 64px;height:64px;font-size:24px}"
    ":target{outline:3px solid var(--accent);outline-offset:3px;border-radius:14px}"
    "@media (max-width:760px){.hero{grid-template-columns:1fr;padding:24px 22px}.stamp{width:120px}.stamp svg{width:120px;"
    "height:120px}.bar nav{display:none}.kv th{width:42%}.keycard{grid-template-columns:1fr}.fp{grid-template-columns:repeat(4,auto)}"
    "section.card{padding:18px 16px}.bubble{max-width:88%}}"
    "@page{size:A4;margin:16mm 14mm 18mm}"
    "@media print{body{background:#fff;font-size:12.5px}.bar,.no-print,.tools,.copy,.drop{display:none!important}"
    "main{padding:0;max-width:none}section.card,.tile{box-shadow:none;break-inside:avoid-page}"
    "section.card.long{break-inside:auto}.rec,.msg-row{break-inside:avoid}h2{break-after:avoid}"
    ":root,:root[data-theme]{" + LIGHT + "}}"
)
SCRIPT = r"""
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
const theme=$("#theme");if(theme)theme.addEventListener("click",()=>{const r=document.documentElement,
  order=["auto","light","dark"];r.dataset.theme=order[(order.indexOf(r.dataset.theme)+1)%3];});
const printer=$("#print");if(printer)printer.addEventListener("click",()=>print());
const q=$("#q");if(q){
  const chips=$$(".chip[data-cat]"),chat=$("#chat"),shown=$("#shown-n"),items=$$("[data-cat].rec,[data-cat].msg-row,[data-cat].svc-row");
  let timer;const apply=()=>{const text=q.value.trim().toLowerCase(),on=new Set(chips.filter(c=>c.getAttribute("aria-pressed")==="true")
    .map(c=>c.dataset.cat)),where=chat?chat.value:"";let n=0;
    for(const item of items){const show=(!on.size||on.has(item.dataset.cat))&&(!where||item.dataset.chat===where)
      &&(!text||item.textContent.toLowerCase().includes(text));item.hidden=!show;if(show)n++;}
    for(const d of $$(".day"))d.hidden=!!(text||on.size||where);
    if(shown)shown.textContent=new Intl.NumberFormat(lang).format(n);};
  for(const c of chips)c.addEventListener("click",()=>{c.setAttribute("aria-pressed",String(c.getAttribute("aria-pressed")!=="true"));apply();});
  q.addEventListener("input",()=>{clearTimeout(timer);timer=setTimeout(apply,180);});if(chat)chat.addEventListener("change",apply);}
async function opened(text){const seal=JSON.parse(text),s=seal.statement;
  const key=await crypto.subtle.importKey("raw",bytes(s.public_key),{name:"Ed25519"},false,["verify"]);
  return{s,fp:hex(await crypto.subtle.digest("SHA-256",bytes(s.public_key))),
    ok:await crypto.subtle.verify({name:"Ed25519"},key,bytes(seal.signature),new TextEncoder().encode(canon(s)))};}
const stamp=$("#stamp"),state=$("#seal-state"),node=$("#tgwitness-seal");
if(stamp&&node)opened(node.textContent).then(r=>{const good=r.ok&&r.fp===stamp.dataset.fp;
  stamp.classList.add(good?"ok":"bad");state.textContent=say(good?"Signature verified in this browser":"Signature does not match");})
  .catch(()=>{stamp.classList.add("unknown");state.textContent=say("Signed · check with verify.py");});
const zone=$("#drop");if(zone){const input=$("#drop-file"),out=$("#drop-result"),marker=new TextEncoder().encode(zone.dataset.open);
  const show=(kind,text)=>{out.className="callout "+kind;out.textContent=text;out.hidden=false;};
  const check=async file=>{show("info",say("Checking…"));const data=new Uint8Array(await file.arrayBuffer());let at=-1;
    outer:for(let i=data.length-marker.length;i>=0;i--){for(let j=0;j<marker.length;j++)if(data[i+j]!==marker[j])continue outer;at=i;break;}
    if(at<0)return show("bad",say("No seal found in this file."));
    const tail=new TextDecoder().decode(data.subarray(at+marker.length)),close=zone.dataset.close;
    if(!tail.endsWith(close))return show("bad",say("The seal is not at the end of the file."));
    try{const r=await opened(tail.slice(0,-close.length)),content=hex(await crypto.subtle.digest("SHA-256",data.subarray(0,at)));
      if(!r.ok)return show("bad",say("The seal signature is not valid."));
      if(content!==r.s.content_sha256)return show("bad",say("This file was changed after it was sealed."));
      show(r.fp===(stamp&&stamp.dataset.fp)?"ok":"info",say("Seal intact: every byte of this file is as signed.")+" "
        +say("Key fingerprint")+": "+r.fp.match(/.{4}/g).join(" ")+(r.fp===(stamp&&stamp.dataset.fp)?"":" · "+say("a different key than this report")));
    }catch(e){show("bad",say("This browser cannot check Ed25519 signatures. Use verify.py."));}};
  zone.addEventListener("dragover",e=>{e.preventDefault();zone.classList.add("over");});
  zone.addEventListener("dragleave",()=>zone.classList.remove("over"));
  zone.addEventListener("drop",e=>{e.preventDefault();zone.classList.remove("over");if(e.dataTransfer.files[0])check(e.dataTransfer.files[0]);});
  input.addEventListener("change",()=>{if(input.files[0])check(input.files[0]);});}
"""
SCRIPT_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode() + "'"
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data: file:; script-src " + SCRIPT_HASH
       + "; base-uri 'none'; form-action 'none'")
SCRIPT_WORDS = ("Copy", "Copied", "Signature verified in this browser", "Signature does not match",
                "Signed · check with verify.py", "Checking…", "No seal found in this file.",
                "The seal is not at the end of the file.", "The seal signature is not valid.",
                "This file was changed after it was sealed.", "Seal intact: every byte of this file is as signed.",
                "Key fingerprint", "a different key than this report",
                "This browser cannot check Ed25519 signatures. Use verify.py.")


def head(say, *, title, description, meta, linked, theme):
    """Document start: metadata for people, search tools and case-management systems."""
    tags = [("generator", "TgWitness " + __version__), ("description", description),
            ("robots", "noindex, nofollow, noarchive"), ("referrer", "no-referrer"), ("color-scheme", "light dark")]
    tags += meta
    return ('<!doctype html><html lang="' + e(say.language) + '" dir="' + say.direction + '" data-theme="' + e(theme)
            + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + e(CSP) + '"><title>' + e(title) + "</title>"
            '<link rel="schema.DC" href="http://purl.org/dc/elements/1.1/">'
            + "".join('<meta name="' + e(n) + '" content="' + e(v) + '">' for n, v in tags if v not in (None, ""))
            + '<script type="application/ld+json">' + script_json(linked) + "</script>"
            "<style>" + CSS + "</style></head><body>")


def bar(say, label, links):
    return ('<header class="bar"><div class="brand">' + MARK + '<span>TgWitness <small>· ' + e(label) + "</small></span></div>"
            "<nav>" + "".join('<a href="#' + a + '">' + e(t) + "</a>" for a, t in links) + "</nav>"
            '<button class="icon-btn" id="theme" type="button" title="' + e(say("Theme")) + '">' + ICON_THEME + "</button>"
            '<button class="icon-btn" id="print" type="button" title="' + e(say("Print or save as PDF")) + '">'
            + ICON_PRINT + "</button></header><main>")


def hero(say, eyebrow, title, facts, fp, sealed):
    stamp = ('<div class="stamp" id="stamp" data-fp="' + e(fp) + '">' + STAMP + '<div class="stamp-state" id="seal-state">'
             + e(say("Checking…")) + "</div></div>") if sealed else ""
    return ('<section class="hero" id="summary"><div><div class="eyebrow">' + e(eyebrow) + "</div><h1>" + e(title) + "</h1>"
            '<div class="facts">' + "".join("<div><span>" + e(k) + "</span><b>" + v + "</b></div>" for k, v in facts if v)
            + "</div></div>" + stamp + "</section>")


def tiles(items):
    return ('<div class="tiles">' + "".join('<div class="tile" style="--c:var(--' + c + ')"><i></i><b>' + v + "</b><span>"
                                            + e(k) + "</span></div>" for k, v, c in items) + "</div>")


def section(number, anchor, title, lead="", long=False):
    return ('<section class="card' + (" long" if long else "") + '" id="' + anchor + '"><h2><span class="num">'
            + str(number) + "</span>" + e(title) + "</h2>" + ('<p class="lead">' + e(lead) + "</p>" if lead else ""))


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


def standards_section(say, number):
    rows = [["<b>" + e(ref) + "</b><br><small>" + e(title) + "</small>", e(how)] for ref, title, how in standards(say)]
    return (section(number, "standards", say("Standards and methodology"),
                    say("This export follows these practices. Alignment, not certification."))
            + table([say("Reference"), say("How it is applied")], rows) + "</section>")


def limits_section(say, number, limits):
    return (section(number, "limits", say("Limitations"), say("Read these before relying on the material."))
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
    return (section(number, "seal", say("Seal"),
                    say("This file ends with a signed seal: the SHA-256 of every byte before it, what it describes and the "
                        "case details, signed with the key above."))
            + kv([(say("Report ID"), "<code>" + e(report_id) + "</code>"), (say("Sealed at"), when(created_at))])
            + '<div class="drop" id="drop" data-open="' + e(SEAL_OPEN.decode()) + '" data-close="' + e(SEAL_CLOSE.decode())
            + '"><p>' + e(say("Drop this report file here to check every byte in this browser. Nothing is uploaded."))
            + '</p><label>' + e(say("Choose the file")) + '<input id="drop-file" type="file" accept=".html,.htm,text/html">'
            + '</label></div><div class="callout" hidden id="drop-result" role="status"></div></section>')


def ending(say, producer):
    return ('</main><footer class="end"><b>TgWitness ' + e(producer.get("version")) + "</b> · " + e(producer.get("project"))
            + " · " + e(producer.get("homepage")) + " · " + e(producer.get("source")) + "<br>"
            + e(say("Free and open source, made to help victims of fraud and the people who investigate it.")) + "</footer>"
            '<script type="application/json" id="report-words">' + script_json({k: say(k) for k in SCRIPT_WORDS})
            + '</script><script type="module">' + SCRIPT + "</script>")


def sealed(chunks, statement, sign):
    """Yield the report, then its seal: the statement with the SHA-256 of every byte before it, signed."""
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
    """Dublin Core and TgWitness meta tags."""
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


# Evidence report ----------------------------------------------------------------------------

def record_html(event, say, titles, options, archive):
    kind, payload, chat, seq = event["kind"], event["payload"], event["chat_id"], event["seq"]
    cat = category(kind)
    parts = ['<article class="rec cat-' + cat + '" id="r' + str(seq) + '" data-cat="' + cat + '" data-chat="'
             + e("" if chat is None else chat) + '"><header><a class="seq" href="#r' + str(seq) + '">#' + str(seq) + "</a>"
             '<span class="k">' + e(kind_label(say, kind)) + "</span>"]
    if chat is not None:
        parts.append("<span>" + e(titles.get(chat) or say("Chat {id}", id=chat))
                     + (" · " + e(say("message {id}", id=event["message_id"])) if event["message_id"] is not None else "")
                     + "</span>")
    parts.append('<span class="at">' + when(event["observed_at"]) + "</span></header>")
    sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
    sender_id = payload.get("sender_id", sender.get("id"))
    if sender.get("display_name") or sender_id is not None:
        parts.append('<div class="who">' + e(sender.get("display_name") or say("User {id}", id=sender_id))
                     + (' <span class="uname">@' + e(sender["username"]) + "</span>" if sender.get("username") else "")
                     + (' <span class="sub">· id ' + e(sender_id) + "</span>" if sender_id is not None else "") + "</div>")
    if isinstance(payload.get("text"), str) and payload["text"]:
        parts.append('<div class="text">' + e(payload["text"]) + "</div>")
    if kind == "message.deleted":
        parts.append('<div class="gone">' + e(say("Telegram reported this message as deleted.")) + "</div>")
    elif kind == "message.missing_on_recheck":
        parts.append('<div class="gone">' + e(say("Telegram no longer returned this message at a later check.")) + "</div>")
    if kind == "media.saved" and isinstance(payload.get("media_sha256"), str):
        digest, mime = payload["media_sha256"], payload.get("mime_type")
        parts.append('<div class="file">' + e(payload.get("original_name") or say("Saved file")) + " · " + e(mime or "—")
                     + " · " + e(size_text(payload.get("size"))) + "<br><code>" + e(digest) + "</code></div>")
        if archive and options.get("media_previews") and mime in IMAGES and re.fullmatch("[0-9a-f]{64}", digest):
            parts.append('<img loading="lazy" alt="" src="media/' + digest + '">')
    footer = ['<span title="' + e(event["hash"]) + '">SHA-256 ' + e(short(event["hash"], 16, 6)) + "</span>"]
    if event.get("source_at"):
        footer.append("<span>" + e(say("Telegram time")) + " " + when(event["source_at"]) + "</span>")
    parts.append("<footer>" + "".join(footer) + "</footer>")
    if options.get("raw_records"):
        parts.append('<details class="raw"><summary>' + e(say("Record data")) + "</summary><pre>"
                     + e(json.dumps(payload, ensure_ascii=False, indent=2)) + "</pre></details>")
    return "".join(parts) + "</article>"


def coverage_section(say, number, coverage):
    if not coverage:
        return ""
    periods = [[when(p["from"]), when(p["to"]), e(span_text(say, p["from"], p["to"]))
                + (' <span class="pill ok">' + e(say("still observing")) + "</span>" if p.get("still_observing") else "")]
               for p in coverage["continuous"]]
    gaps = [[when(g["from"]), when(g["to"]), e(g.get("reason"))] for g in coverage["gaps"]]
    ids = [[e(c.get("title") or c["chat_id"]), num(c["observed_from"]) + " – " + num(c["observed_to"]), num(c["observed"]),
            num(c["not_observed"])] for c in coverage["unobserved_ids"]]
    out = section(number, "coverage", say("Coverage"),
                  say("Continuous means observation was on, connected and writing records at least every three minutes. "
                      "IDs not observed were never seen by this collector; that is not evidence that they were deleted."))
    out += "<h3>" + e(say("Continuous observation")) + "</h3>" + (table([say("From"), say("To"), say("Duration")], periods)
                                                                    if periods else "<p>—</p>")
    if gaps:
        out += "<h3>" + e(say("Gaps")) + "</h3>" + table([say("From"), say("To"), say("Reason")], gaps)
    if ids:
        out += "<h3>" + e(say("Message IDs per chat")) + "</h3>" + table(
            [say("Chat"), say("Observed range"), say("Observed"), say("Not observed")], ids)
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
            status = ('<span class="pill ok">' + e(say("Token valid")) + "</span> <small>" + e(signer) + "</small>" if signer
                      else '<span class="pill warn">' + e(say("Check the signature with --tsa-ca")) + "</span>")
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


def verify_section(say, number, archive_name, fp, report_name, archive):
    steps = ["<li>" + e(say("Get the signer's key fingerprint from a trusted channel, not from this archive.")) + "</li>"]
    if archive:
        steps.append("<li>" + e(say("Check the whole archive: signatures, hashes, record chain and this report's seal."))
                     + command("python verify.py " + archive_name + " --fingerprint " + fp) + "</li>")
        steps.append("<li>" + e(say("Without Python, check the file hashes (not the signature):"))
                     + command("sha256sum -c SHA256SUMS") + command("shasum -a 256 -c SHA256SUMS")
                     + command("Get-FileHash -Algorithm SHA256 " + ("events.jsonl" if report_name == "report.html"
                                                                    else "chat.json")) + "</li>")
    steps.append("<li>" + e(say("This report on its own:"))
                 + command("python verify.py " + report_name + " --fingerprint " + fp
                           + (" --evidence " + archive_name if archive else "")) + "</li>")
    return (section(number, "verify", say("How to verify"),
                    say("Anyone can repeat these checks. They show whether the material changed after it was signed."))
            + '<ol class="steps">' + "".join(steps) + "</ol></section>")


def evidence_chunks(events, coverage=None, context=None):
    """The readable journal report; sealed when the context carries the signing function."""
    context = context or {}
    options = {**ReportOptions().model_dump(), "language": "en", **(context.get("options") or {})}
    say = Words(options["language"])
    producer = context.get("producer") or {"software": "TgWitness", "version": __version__, "project": "PhishDestroy",
                                           "homepage": "https://phishdestroy.io",
                                           "source": "https://github.com/phishdestroy/TgWitness"}
    digest = context.get("digest") or Digest().result()
    anchors, files, archive = context.get("anchors", []), context.get("files", {}), context.get("archive", False)
    fp, report_id = context.get("fingerprint") or "", context.get("report_id") or "unsealed"
    created, count, head_hash = context.get("created_at") or utcnow(), context.get("event_count"), context.get("head_hash")
    case, archive_name = case_of(options), "tgwitness-evidence.zip"
    title = options.get("case_title") or say("Telegram observation journal")
    description = say("Signed record of Telegram observations made by TgWitness, with integrity and custody details.")
    sign = context.get("sign")

    def chunks():
        meta = metadata(say, title=title, description=description, created_at=created, report_id=report_id, fp=fp,
                        case=case, extra=[("tgwitness:format", "tgwitness-evidence-v1"),
                                          ("tgwitness:event-count", count), ("tgwitness:head-hash", head_hash),
                                          ("tgwitness:events-sha256", context.get("events_sha256"))])
        linked = linked_data(kind="Evidence report", title=title, description=description, created_at=created,
                             report_id=report_id, language=say.language, producer=producer, case=case, fp=fp,
                             about={"@type": "Dataset", "name": "TgWitness observation journal",
                                    "identifier": head_hash, "size": count},
                             based_on={"@type": "MediaObject", "name": "events.jsonl",
                                       "encodingFormat": "application/x-ndjson",
                                       "identifier": {"@type": "PropertyValue", "propertyID": "sha256",
                                                      "value": context.get("events_sha256")}})
        links = [("summary", say("Summary")), ("integrity", say("Integrity")), ("timestamps", say("Timestamps")),
                 ("custody", say("Custody")), ("verify", say("Verify"))]
        if options.get("timeline"):
            links.append(("records", say("Records")))
        yield (head(say, title=title + " · TgWitness", description=description, meta=meta, linked=linked,
                    theme=options.get("theme", "auto")) + bar(say, say("Evidence report"), links)).encode("utf-8")
        facts = [(say("Case ID"), e(options.get("case_id"))), (say("Examiner"), e(options.get("examiner"))),
                 (say("Organization"), e(options.get("organization"))), (say("Created"), when(created)),
                 (say("Report ID"), '<span class="mono">' + e(report_id[:8]) + "</span>")]
        categories = digest["categories"]
        yield (hero(say, say("Evidence report") + " · " + say("Signed"), title, facts, fp, sign is not None)
               + tiles([(say("Records"), num(count), "accent"), (say("Chats"), num(len(digest["chats"])), "accent"),
                        (say("Messages"), num(categories["message"]), "accent"), (say("Edits"), num(categories["edited"]), "warn"),
                        (say("Deletions"), num(categories["deleted"]), "bad"), (say("Files"), num(len(digest["media"])), "violet"),
                        (say("Timestamps"), num(len([a for a in anchors if a.get("kind") != "unreadable"])), "ok"),
                        (say("Observed"), e(span_text(say, digest["first"], digest["last"])), "pink")])).encode("utf-8")
        account = context.get("account") or {}
        account_text = " · ".join(x for x in (("@" + account["username"]) if account.get("username") else "",
                                              ("id " + str(account["id"])) if account.get("id") else "") if x)
        yield case_section(say, 1, options, [
            (say("Observing account"), e(account_text)),
            (say("Report language"), '<span data-lang="' + e(say.language) + '">' + e(say.language) + "</span>"),
            (say("Report ID"), "<code>" + e(report_id) + "</code>"), (say("Created"), when(created)),
            (say("Produced by"), e(producer.get("software")) + " " + e(producer.get("version")) + " · "
             + e(producer.get("project")))]).encode("utf-8")
        chain = ('<div class="chain"><div class="link"><b>' + e(say("Chain start")) + "</b><code>0000…0000</code></div>"
                 '<span class="arrow"></span>')
        if count and count > 1:
            chain += ('<div class="link"><b>#1</b><code>' + e(short(digest["first_hash"], 8, 4)) + "</code></div>"
                      '<span class="arrow"></span>')
        if count and count > 2:
            chain += ('<div class="link more"><b>' + e(say("Records in between: {n}", n=count - 2)) + "</b><code>SHA-256 · Ed25519"
                      '</code></div><span class="arrow"></span>')
        chain += ('<div class="link head"><b>#' + e(count) + " · " + e(say("Head")) + "</b><code>" + e(short(head_hash, 8, 4))
                  + "</code></div></div>")
        yield (section(2, "integrity", say("Integrity"),
                       say("Every record is linked to the previous one by SHA-256 and signed with Ed25519 when it is "
                           "captured. The manifest lists the SHA-256 of every file and is signed with the same key."))
               + (keycard(say, fp) if fp else "")
               + '<p class="lead">' + e(say("Compare this fingerprint with a copy kept apart from the collector, for "
                                            "example one published or given to the recipient beforehand.")) + "</p>"
               + chain
               + kv([(say("Records"), num(count)), (say("Head hash"), "<code>" + e(head_hash) + "</code>"),
                     (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"), (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                     (say("Public key"), "<code>" + e(context.get("public_key")) + "</code>"),
                     ("events.jsonl SHA-256", "<code>" + e(context.get("events_sha256")) + "</code>"
                      if context.get("events_sha256") else "")])
               + "</section>").encode("utf-8")
        yield timestamps_section(say, 3, anchors, archive_name, fp).encode("utf-8")
        yield coverage_section(say, 4, coverage).encode("utf-8")
        latest = latest_stamp(anchors)
        steps = [(say("Observed and recorded"), when(digest["first"]) + " — " + when(digest["last"])),
                 (say("Each record hashed and signed at capture"), e(say("Records: {n}", n=count))),
                 (say("Checkpoints timestamped"), (when(latest.get("time")) + " · " + e(latest["service"])) if latest
                  else e(say("none in this export"))),
                 (say("Journal verified and exported"), when(created)),
                 (say("Report sealed"), when(created) + " · " + e(options.get("examiner") or ""))]
        yield custody_section(say, 5, steps, [
            (say("Acquisition tool"), e(producer.get("software")) + " " + e(producer.get("version"))),
            (say("Acquisition method"), e(say("Telegram client observing the account; records chained by SHA-256 and "
                                              "signed with Ed25519 as they are written."))),
            (say("Observing account"), e(account_text)),
            (say("Export host"), e(platform.system() + " " + platform.release() + " · Python " + platform.python_version())),
            (say("Time standard"), "UTC · ISO 8601")]).encode("utf-8")
        yield verify_section(say, 6, archive_name, fp, "report.html", archive).encode("utf-8")
        number = 7
        if archive and files:
            yield files_section(say, number, files, ("report.html", "README.txt", "SHA256SUMS", "manifest.json",
                                                     "manifest.sig")).encode("utf-8")
            number += 1
        yield standards_section(say, number).encode("utf-8")
        yield limits_section(say, number + 1, context.get("limits") or []).encode("utf-8")
        number += 2
        if options.get("timeline"):
            titles = digest["titles"]
            chips = "".join('<button class="chip" type="button" aria-pressed="false" data-cat="' + c + '">'
                            + e(category_label(say, c)) + "<b>" + num(n) + "</b></button>"
                            for c, n in digest["categories"].items() if n)
            chats = digest["chats"]
            select = ('<select id="chat" aria-label="' + e(say("Chat")) + '"><option value="">' + e(say("All chats"))
                      + "</option>" + "".join('<option value="' + e(c) + '">' + e(titles.get(c) or c) + " (" + str(n) + ")</option>"
                                             for c, n in sorted(chats.items(), key=lambda i: -i[1])) + "</select>"
                      if len(chats) > 1 else "")
            yield (section(number, "records", say("Records"), say("Every record of the journal in order. Filters only "
                                                                  "change what is shown."), long=True)
                   + '<div class="tools"><input type="search" id="q" placeholder="' + e(say("Search text, names, IDs…"))
                   + '">' + select + chips + '<span class="shown">' + e(say("Shown")) + ': <b id="shown-n">' + num(count)
                   + "</b></span></div>").encode("utf-8")
            for event in events:
                yield record_html(event, say, titles, options, archive).encode("utf-8")
            yield b"</section>"
            number += 1
        if sign is not None:
            yield seal_section(say, number, report_id, created).encode("utf-8")
        yield ending(say, producer).encode("utf-8")

    statement = {"format": SEAL_FORMAT, "report_id": report_id, "created_at": created, "language": say.language,
                 "public_key": context.get("public_key"), "producer": producer, "case": case,
                 "subject": {"kind": "evidence", "event_count": count, "head_hash": head_hash,
                             **({"events_sha256": context["events_sha256"]} if context.get("events_sha256") else {})}}
    yield from sealed(chunks(), statement, sign)


# Chat report --------------------------------------------------------------------------------

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


def chat_rows(records, say):
    """Telegram-style rows: day separators, grouped senders, reply quotes from earlier messages."""
    quotes, previous_day, previous_sender = {}, None, object()
    for record in records:
        date, sender = record.get("date") or "", record.get("from_id")
        day = date[:10]
        if day and day != previous_day:
            yield '<div class="day"><time datetime="' + e(day) + '" data-day>' + e(day) + "</time></div>"
            previous_day, previous_sender = day, object()
        name = record.get("from") or (str(sender) if sender is not None else say("Unknown"))
        if record.get("type") == "service":
            yield ('<div class="svc-row" id="m' + e(record.get("id")) + '" data-cat="service"><span>' + e(name) + " · "
                   + e(action_text(record.get("action")) or say("Service message")) + "</span></div>")
            previous_sender = object()
            continue
        start = sender != previous_sender
        previous_sender = sender
        cat = "media" if record.get("media_type") else "edited" if record.get("edited") else "text"
        body = []
        if start:
            body.append('<div class="name">' + e(name) + (' <span class="uname">@' + e(record["from_username"]) + "</span>"
                                                          if record.get("from_username") else "") + "</div>")
        reply = record.get("reply_to_message_id")
        if reply:
            quoted = quotes.get(reply)
            body.append('<a class="quote" href="#m' + e(reply) + '"><b>' + e(quoted[0] if quoted else "#" + str(reply))
                        + "</b>" + e(quoted[1] if quoted else say("Earlier message")) + "</a>")
        if record.get("media_type"):
            body.append('<div class="media-chip">◆ ' + e(say(MEDIA_NAMES.get(record["media_type"], "Media")))
                        + ("" if record.get("file") else " · " + e(say("not included in this export"))) + "</div>")
        text = record.get("text") or ""
        if text:
            body.append('<div class="text">' + e(text).replace("\n", "<br>") + "</div>")
        meta = ('<span class="meta"><a href="#m' + e(record.get("id")) + '">#' + e(record.get("id")) + "</a> · "
                + ('<time datetime="' + e(date) + '" data-clock>' + e(date[11:16]) + "</time>" if date else "")
                + (" · " + e(say("edited")) if record.get("edited") else "") + "</span>")
        yield ('<article class="msg-row' + ("" if start else " cont") + " " + colour(sender) + '" id="m' + e(record.get("id"))
               + '" data-cat="' + cat + '"><div class="ava' + ("" if start else " blank") + '">' + e(initials(name))
               + '</div><div class="bubble">' + "".join(body) + meta + "</div></article>")
        quotes[record.get("id")] = (name, text[:90] or say(MEDIA_NAMES.get(record.get("media_type"), "Media")))
        if len(quotes) > 20000:
            quotes.pop(next(iter(quotes)))


def chat_chunks(meta, records, context):
    """The readable chat: sealed with a statement over chat.json's hash."""
    options = {**ReportOptions().model_dump(), "language": "en", **(context.get("options") or {})}
    say = Words(options["language"])
    producer, chat, stats = context["producer"], meta.get("chat") or {}, context["stats"]
    people, files, fp = context["people"], context.get("files", {}), context["fingerprint"]
    report_id, created, case = context["report_id"], context["created_at"], case_of(options)
    chat_title = chat.get("title") or say("Chat {id}", id=chat.get("id"))
    title = options.get("case_title") or chat_title
    description = say("Signed export of a Telegram chat's visible history, made by TgWitness.")
    sign = context.get("sign")

    def chunks():
        tags = metadata(say, title=title, description=description, created_at=created, report_id=report_id, fp=fp,
                        case=case, extra=[("tgwitness:format", "tgwitness-chat-export-v1"),
                                          ("tgwitness:chat-id", chat.get("id")),
                                          ("tgwitness:message-count", meta.get("message_count")),
                                          ("tgwitness:chat-json-sha256", context.get("chat_json_sha256"))])
        linked = linked_data(kind="Chat export", title=title, description=description, created_at=created,
                             report_id=report_id, language=say.language, producer=producer, case=case, fp=fp,
                             about={"@type": "Conversation", "name": chat_title, "identifier": str(chat.get("id"))},
                             based_on={"@type": "MediaObject", "name": "chat.json", "encodingFormat": "application/json",
                                       "identifier": {"@type": "PropertyValue", "propertyID": "sha256",
                                                      "value": context.get("chat_json_sha256")}})
        yield (head(say, title=title + " · TgWitness", description=description, meta=tags, linked=linked,
                    theme=options.get("theme", "auto"))
               + bar(say, say("Chat export"), [("summary", say("Summary")), ("people", say("Participants")),
                                               ("messages", say("Messages")), ("integrity", say("Integrity")),
                                               ("verify", say("Verify"))])).encode("utf-8")
        facts = [(say("Chat"), e(chat_title)), (say("Case ID"), e(options.get("case_id"))),
                 (say("Examiner"), e(options.get("examiner"))), (say("Organization"), e(options.get("organization"))),
                 (say("Created"), when(created)), (say("Report ID"), '<span class="mono">' + e(report_id[:8]) + "</span>")]
        yield (hero(say, say("Chat export") + " · " + say("Signed"), title, facts, fp, sign is not None)
               + tiles([(say("Messages"), num(meta.get("message_count")), "accent"),
                        (say("Participants"), num(len(people)), "violet"),
                        (say("With media"), num(stats["media"]), "violet"), (say("Edited"), num(stats["edited"]), "warn"),
                        (say("Service"), num(stats["service"]), "ok"),
                        (say("Period"), e(span_text(say, stats["first_at"], stats["last_at"])), "pink")])).encode("utf-8")
        account = meta.get("account") or {}
        account_text = " · ".join(x for x in (("@" + account["username"]) if account.get("username") else "",
                                              ("id " + str(account["id"])) if account.get("id") else "") if x)
        yield case_section(say, 1, options, [
            (say("Chat"), '<span class="chathead"><span class="ava ' + colour(chat.get("id")) + '">' + e(initials(chat_title))
             + "</span><span><b>" + e(chat_title) + "</b><br><small>" + e(chat.get("kind")) + " · " + e(chat.get("visibility"))
             + " · id " + e(chat.get("id")) + "</small></span></span>"),
            (say("First message"), when(stats["first_at"])), (say("Last message"), when(stats["last_at"])),
            (say("Exporting account"), e(account_text)),
            (say("Report language"), '<span data-lang="' + e(say.language) + '">' + e(say.language) + "</span>"),
            (say("Report ID"), "<code>" + e(report_id) + "</code>")]).encode("utf-8")
        top = max([p["messages"] for p in people] or [1])
        rows = [['<span class="ava ' + colour(p["user_id"]) + '" style="width:30px;height:30px;font-size:12px;display:inline-grid">'
                 + e(initials(p["name"] or p["user_id"])) + "</span> <b>" + e(p["name"] or say("Unknown")) + "</b>"
                 + (' <span class="uname">@' + e(p["username"]) + "</span>" if p.get("username") else ""),
                 "<code>" + e(p["user_id"]) + "</code>", num(p["messages"]),
                 '<div class="meter"><i style="width:' + str(max(2, round(100 * p["messages"] / top))) + '%"></i></div>',
                 when(p["first_message_at"]), when(p["last_message_at"])] for p in people[:100]]
        more = ('<p class="lead">' + e(say("… and {n} more, listed in authors.csv and authors.json.", n=len(people) - 100))
                + "</p>" if len(people) > 100 else "")
        yield (section(2, "people", say("Participants"), say("Everyone who posted in the exported history, most active first. "
                                                             "Names are the profile at export time."))
               + '<div class="bars">' + table([say("Participant"), "ID", say("Messages"), "", say("First message"),
                                                say("Last message")], rows) + "</div>" + more + "</section>").encode("utf-8")
        chips = "".join('<button class="chip" type="button" aria-pressed="false" data-cat="' + c + '">' + e(label)
                        + "<b>" + num(n) + "</b></button>" for c, label, n in (
                            ("text", say("Text"), stats["text"]), ("media", say("With media"), stats["media"]),
                            ("edited", say("Edited"), stats["edited"]), ("service", say("Service"), stats["service"])) if n)
        yield (section(3, "messages", say("Messages"), say("The visible history at export time, oldest first."), long=True)
               + '<div class="tools"><input type="search" id="q" placeholder="' + e(say("Search text, names, IDs…")) + '">'
               + chips + '<span class="shown">' + e(say("Shown")) + ': <b id="shown-n">' + num(meta.get("message_count"))
               + '</b></span></div><div class="chatwall">').encode("utf-8")
        for row in chat_rows(records(), say):
            yield row.encode("utf-8")
        yield b"</div></section>"
        parts = meta.get("parts") or []
        accounts = [["<code>" + e(p["statement"].get("account_id")) + "</code>", "<code>"
                     + e(short(fingerprint(p["statement"]["fetched_by_public_key"]), 16, 8)) + "</code>",
                     num(len(p["statement"].get("ranges") or [])), num(sum(r.get("count", 0) for r in p["statement"].get("ranges") or []))]
                    for p in parts]
        yield (section(4, "integrity", say("Integrity"),
                       say("chat.json is authoritative. The manifest lists the SHA-256 of every file and is signed with "
                           "Ed25519; this page carries its own signed seal."))
               + keycard(say, fp)
               + kv([("chat.json SHA-256", "<code>" + e(context.get("chat_json_sha256")) + "</code>"),
                     (say("Messages"), num(meta.get("message_count"))), (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"),
                     (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                     (say("Public key"), "<code>" + e(context.get("public_key")) + "</code>")])
               + (("<h3>" + e(say("Accounts that fetched the history")) + "</h3>"
                   + table([say("Account"), say("Key fingerprint"), say("Ranges"), say("Messages")], accounts)) if accounts else "")
               + "</section>").encode("utf-8")
        steps = [(say("History read through the Telegram API"), when(stats["first_at"]) + " — " + when(stats["last_at"])),
                 (say("Messages written to chat.json and hashed"), e(say("Messages: {n}", n=meta.get("message_count")))),
                 (say("Archive signed and report sealed"), when(created) + " · " + e(options.get("examiner") or ""))]
        yield custody_section(say, 5, steps, [
            (say("Acquisition tool"), e(producer.get("software")) + " " + e(producer.get("version"))),
            (say("Acquisition method"), e(say("Full visible history read through the Telegram API; a current snapshot, "
                                              "not a reconstruction of deleted or earlier edited messages."))),
            (say("Exporting account"), e(account_text)),
            (say("Export host"), e(platform.system() + " " + platform.release() + " · Python " + platform.python_version())),
            (say("Time standard"), "UTC · ISO 8601")]).encode("utf-8")
        yield verify_section(say, 6, "tgwitness-chat-export.zip", fp, "chat.html", True).encode("utf-8")
        yield files_section(say, 7, files, ("chat.html", "README.txt", "SHA256SUMS", "manifest.json",
                                            "manifest.sig")).encode("utf-8")
        yield standards_section(say, 8).encode("utf-8")
        yield limits_section(say, 9, context.get("limits") or []).encode("utf-8")
        if sign is not None:
            yield seal_section(say, 10, report_id, created).encode("utf-8")
        yield ending(say, producer).encode("utf-8")

    statement = {"format": SEAL_FORMAT, "report_id": report_id, "created_at": created, "language": say.language,
                 "public_key": context["public_key"], "producer": producer, "case": case,
                 "subject": {"kind": "chat-export", "chat_id": chat.get("id"), "chat_title": chat.get("title"),
                             "message_count": meta.get("message_count"),
                             "chat_json_sha256": context.get("chat_json_sha256")}}
    yield from sealed(chunks(), statement, sign)
