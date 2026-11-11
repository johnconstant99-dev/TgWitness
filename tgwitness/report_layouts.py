from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path


DESIGNS = frozenset(("reading_series", "ledger_margin"))
DESIGN_NAMES = {"reading_series": "Evidence Reading Series", "ledger_margin": "Ledger & Margin"}
SSR_LIMIT = 500
SSR_BYTES = 8 * 1024 * 1024
CSS = Path(__file__).with_name("report_layouts.css").read_text(encoding="utf-8")


@dataclass(frozen=True)
class Chapter:
    id: str
    title: str
    section_ids: tuple[str, ...]


def chapter_plan(design, kind="journal"):
    if design == "reading_series":
        return (
            Chapter("case", "Case & examination question", ("case", "brief")),
            Chapter("assessment", "Findings & assessment", ("examination", "assessment", "case_board")),
            Chapter("scope", "Scope & coverage", ("selection", "minimisation", "source", "coverage", "message_numbers")),
            Chapter("histories", "Change dossiers", ("histories",)),
            Chapter("activity", "Activity & observed accounts", ("analytics", "directory", "participants")),
            Chapter("journal", "Observation journal" if kind != "chat" else "Message transcript", ("journal",)),
            Chapter("artifacts", "Files, relationships & indicators", ("relations", "files", "indicators", "admin_log", "actions")),
            Chapter("assurance", "Custody, integrity & verification", ("integrity", "timestamps", "custody", "verify", "standards", "seal")),
            Chapter("limitations", "Reading this record", ("limitations",)),
        )
    if design == "ledger_margin":
        return (
            Chapter("case", "Case, question & findings", ("case", "examination", "brief", "assessment", "case_board")),
            Chapter("scope", "Scope & acquisition conditions", ("selection", "minimisation", "source")),
            Chapter("activity", "Counts, activity & basis", ("analytics",)),
            Chapter("directory", "Chats & observed accounts", ("directory", "participants")),
            Chapter("histories", "Message histories", ("histories",)),
            Chapter("relations", "Replies, threads & forwards", ("relations",)),
            Chapter("files", "Attachments & archive files", ("files",)),
            Chapter("coverage", "Coverage & absent identifiers", ("coverage", "message_numbers")),
            Chapter("actions", "Operator actions", ("actions", "admin_log")),
            Chapter("indicators", "Extracted indicators", ("indicators",)),
            Chapter("assurance", "Provenance, custody & integrity", ("integrity", "timestamps", "custody", "verify", "standards", "seal")),
            Chapter("journal", "Observation journal" if kind != "chat" else "Message transcript", ("journal",)),
            Chapter("limitations", "Reading this record", ("limitations",)),
        )
    return ()


def permitted_record(event):
    from . import report
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    sender = payload.get("sender_observation")
    sender = sender if isinstance(sender, dict) else {}
    metadata_keys = ("media_sha256", "original_name", "mime_type", "size", "reason", "declared_bytes",
                     "action", "request_seq", "status", "message_event_seq", "outgoing", "grouped_id")
    return {
        **{key: event.get(key) for key in ("seq", "kind", "chat_id", "message_id", "actor_id", "observed_at", "hash", "previous_hash", "signature")},
        **report.message_times(payload), "sender_id": payload.get("sender_id", sender.get("id")),
        "sender_profile": sender, "text": payload.get("text"), "text_withheld": bool(payload.get("text_withheld")),
        "details": report.shown_details(payload),
        "metadata": {key: payload[key] for key in metadata_keys if key in payload},
    }


def journal_directory(events, limit=SSR_LIMIT):
    chats, senders, relations, count, limited = {}, {}, [], 0, False
    for event in events:
        if count >= limit:
            limited = True
            break
        count += 1
        row = permitted_record(event)
        chat, sender = row["chat_id"], row["sender_id"]
        if type(chat) is int:
            chats[chat] = chats.get(chat, 0) + 1
        if type(sender) is int:
            item = senders.setdefault(sender, {"sender_id": sender, "profile": {}, "records": 0})
            item["records"] += 1
            if row["sender_profile"]:
                item["profile"] = row["sender_profile"]
        details = row["details"]
        if any(key in details for key in ("reply_to_message_id", "reply_to_top_id", "quote_text", "forwarded_from")):
            relations.append({key: row[key] for key in ("seq", "chat_id", "message_id", "details")})
    return {"records_examined": count, "limited": limited,
            "chats": [{"chat_id": chat, "records": total} for chat, total in chats.items()],
            "senders": list(senders.values()), "relations": relations}


def bounded_records(events, limit=SSR_LIMIT, byte_limit=SSR_BYTES):
    rows, size, limited = [], 0, False
    for event in events:
        if len(rows) >= limit:
            limited = True
            break
        length = len(json.dumps(event, ensure_ascii=False, default=str).encode("utf-8"))
        if size + length > byte_limit:
            limited = True
            break
        rows.append(event)
        size += length
    return rows, limited


FIELD_LABELS = {
    "sender_profile": "Observed sender profile", "details": "Message metadata", "metadata": "File and action metadata",
    "hash": "Record SHA-256", "previous_hash": "Previous record hash", "signature": "Record signature",
    "actor_id": "Recorded actor ID", "id": "ID", "username": "Username",
    "display_name": "Display name", "first_name": "First name", "last_name": "Last name",
    "observed_at": "Observed", "sent_at": "Sent", "edited_at": "Edited", "reply_to_message_id": "Reply to",
    "reply_to_top_id": "Reply thread", "reply_to_peer_id": "Chat of the original message", "forum_topic": "Forum topic",
    "quote_text": "Quoted text", "quote_offset": "Quote offset (UTF-16)", "quote_entities": "Quote entities",
    "forwarded_from": "Forward origin", "text_entities": "Text entities", "reactions": "Reactions",
    "buttons": "Buttons", "media_info": "Media metadata", "views": "Views", "forwards": "Forwards",
    "replies": "Replies", "auto_delete_seconds": "Auto-delete timer (seconds)", "protected": "Protected content",
    "offset": "Offset (UTF-16)", "length": "Length (UTF-16)", "href": "Literal target", "text": "Text",
    "count": "Count", "type": "Type", "kind": "Kind", "size": "Size (bytes)", "mime_type": "MIME type",
    "media_sha256": "Saved file SHA-256", "original_name": "Original file name", "reason": "Reason",
}


def _fields(value, say, depth=0):
    if value is None:
        return '<span class="muted">' + escape(say("Not supplied")) + '</span>'
    if isinstance(value, bool):
        return escape(say("Yes") if value else say("No"))
    if isinstance(value, dict) and depth < 5:
        return '<dl class="kv">' + ''.join('<dt>' + escape(say(FIELD_LABELS.get(str(key), str(key).replace('_', ' '))))
            + '</dt><dd>' + _fields(item, say, depth + 1) + '</dd>' for key, item in value.items()) + '</dl>'
    if isinstance(value, list) and depth < 5:
        if not value:
            return '<span class="muted">' + escape(say("No entries recorded")) + '</span>'
        return '<ol>' + ''.join('<li>' + _fields(item, say, depth + 1) + '</li>' for item in value) + '</ol>'
    if isinstance(value, (dict, list)):
        return '<pre>' + escape(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>'
    return '<span dir="auto">' + escape(str(value)) + '</span>'


def record_metadata_html(event, say):
    row = permitted_record(event)
    fields = {key: row[key] for key in ("actor_id", "sender_profile", "details", "metadata", "hash", "previous_hash", "signature")
              if row[key] not in ({}, None)}
    return ('<details class="record-metadata"><summary>' + escape(say("Record metadata")) + '</summary>'
            + _fields(fields, say) + '</details>')


def chat_metadata_html(record, say):
    fields = {key: value for key, value in record.items() if key not in ("raw", "text")}
    return ('<details class="record-metadata"><summary>' + escape(say("Message metadata")) + '</summary>'
            + _fields(fields, say) + '</details>')


def journal_replacements(event_factory, context, say, options, total=None, viewer_available=True):
    if not options.get("timeline") or not event_factory:
        return {}
    from . import report
    cache = []

    def sample():
        if not cache:
            rows, limited = bounded_records(event_factory(), min(SSR_LIMIT, options.get("part_size", SSR_LIMIT)))
            cache.append((rows, limited or (type(total) is int and total > len(rows))))
        return cache[0]

    def basis():
        rows, limited = sample()
        return ('<p class="inline-records-notice">' + escape(say("Based on the {n} selected records in this reading copy.", n=len(rows)))
                + (' ' + escape(say("This is a bounded reading copy, not the complete selected journal.")) if limited else '') + '</p>')

    def journal():
        rows, limited = sample()
        yield report.section(1, "records", say("Records"))
        if limited:
            yield basis()
        if viewer_available:
            yield ('<p class="no-print"><a href="#data" data-view="data">' + escape(say("Open all selected records in the viewer")) + '</a></p>')
        if context.get("archive"):
            member = "records.jsonl" if context.get("handover") else "events.jsonl"
            yield '<p><a href="' + member + '">' + escape(say("Open the signed source records")) + '</a></p>'
        if not rows:
            yield '<p>' + escape(say("No records fit this reading copy. Open the source records or the viewer.")) + '</p>'
        digest = context.get("report_digest") or context.get("digest") or {}
        yield from report.record_items(rows, say, digest.get("titles") or {}, options, context.get("archive", False))
        yield '</section>'

    def directory():
        rows, _ = sample()
        index = journal_directory(rows)
        digest = context.get("report_digest") or context.get("digest") or {}
        titles = digest.get("titles") or {}
        yield report.section(1, "observed-directory", say("Observed accounts and chats"))
        yield basis()
        yield '<p>' + escape(say("These are the account references observed in the saved records.")) + '</p>'
        if index["chats"]:
            yield report.table([say("Chat"), say("Records")], [[escape(str(titles.get(item["chat_id"]) or item["chat_id"])),
                report.num(item["records"])] for item in index["chats"]])
        for person in index["senders"]:
            yield '<details class="record-metadata"><summary>' + escape(say("User {id}", id=person["sender_id"]))
            yield ' · ' + escape(say("{n} records", n=person["records"])) + '</summary>'
            yield _fields(person["profile"], say) + '</details>'
        yield '</section>'

    def relations():
        rows, _ = sample()
        index = journal_directory(rows)
        yield report.section(1, "record-relations", say("Replies, threads & forwards"))
        yield basis()
        for item in index["relations"]:
            yield '<article class="record-relation"><h3><a href="#r' + escape(str(item["seq"])) + '">'
            yield escape(say("Record #{n}", n=item["seq"])) + '</a></h3>'
            yield report.details_html(say, item["details"]) + '</article>'
        if not index["relations"]:
            yield '<p>' + escape(say("No reply or forward metadata was recorded in this reading copy.")) + '</p>'
        yield '</section>'

    return {"journal": journal, "directory": directory, "relations": relations}


def chat_replacements(record_factory, context, meta, say, options):
    if not options.get("timeline"):
        return {"journal": None}
    from . import report

    def journal():
        rows, limited = bounded_records(record_factory(), min(SSR_LIMIT, options.get("part_size", SSR_LIMIT)))
        total = meta.get("message_count")
        limited = limited or (type(total) is int and total > len(rows))
        yield report.section(1, "messages", say("Messages"))
        if limited:
            yield '<p class="inline-records-notice">' + escape(say("This reading copy shows {n} messages. The viewer and chat.json retain the complete export.", n=len(rows))) + '</p>'
        yield '<p><a href="#data" data-view="data">' + escape(say("Open all messages in the viewer")) + '</a></p>'
        if context.get("archive", True):
            yield '<p><a href="chat.json">' + escape(say("Open the signed source records")) + '</a></p>'
        yield '<div class="chatwall">'
        yield from report.chat_rows(rows, say, bool(options.get("media_previews")),
                                    numbered=bool((context.get("message_ids") or {}).get("numbered_per_chat")), metadata=True)
        yield '</div></section>'
    return {"journal": journal}


SECTION_KEYS = {
    "case-board": "case_board",
    "brief": "brief", "case": "case", "case-assessment": "assessment", "jurisdiction-guidance": "assessment", "examination": "examination",
    "report-selection": "selection", "minimisation": "minimisation", "report-analytics": "analytics",
    "observed-directory": "directory", "changes": "histories", "record-relations": "relations",
    "actions": "actions", "indicators": "indicators", "integrity": "integrity", "timestamps": "timestamps",
    "coverage": "coverage", "custody": "custody", "verify": "verify", "files": "files",
    "standards": "standards", "limits": "limitations", "limitations": "limitations",
    "records": "journal", "messages": "journal", "source": "source", "people": "participants",
    "message-ids": "message_numbers", "ids": "message_numbers", "admin-log": "admin_log", "seal": "seal",
}


class _Blocks(HTMLParser):
    VOID = frozenset(("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"))

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.blocks, self.current, self.depth, self.attrs, self.tag = [], [], 0, {}, ""

    def _finish(self):
        if self.current:
            self.blocks.append((self.tag, self.attrs, "".join(self.current)))
        self.current, self.attrs, self.tag = [], {}, ""

    def handle_starttag(self, tag, attrs):
        if not self.depth:
            self._finish()
            self.tag, self.attrs = tag, dict(attrs)
        self.current.append(self.get_starttag_text())
        if tag not in self.VOID:
            self.depth += 1
        elif not self.depth:
            self._finish()

    def handle_startendtag(self, tag, attrs):
        if not self.depth:
            self._finish()
            self.tag, self.attrs = tag, dict(attrs)
        self.current.append(self.get_starttag_text())
        if not self.depth:
            self._finish()

    def handle_endtag(self, tag):
        self.current.append("</" + tag + ">")
        self.depth = max(0, self.depth - 1)
        if not self.depth:
            self._finish()

    def handle_data(self, data):
        if self.depth or data.strip():
            self.current.append(data)

    def handle_entityref(self, name):
        self.current.append("&" + name + ";")

    def handle_charref(self, name):
        self.current.append("&#" + name + ";")

    def handle_comment(self, data):
        self.current.append("<!--" + data + "-->")


def navigation(chapters, say, cls="layout-navigation"):
    return ('<nav class="' + cls + '" aria-label="' + escape(say("Contents")) + '"><ol>'
            + "".join('<li><a href="#chapter-' + chapter.id + '"><span>' + f"{number:02d}" + '</span>'
                      + escape(say(chapter.title)) + '</a></li>' for number, chapter in enumerate(chapters, 1))
            + '</ol></nav>')


def chapter_open(design, chapter, number, say):
    title = escape(say(chapter.title))
    if design == "ledger_margin":
        return ('<section class="ledger-margin-chapter" id="chapter-' + chapter.id + '">'
                '<aside class="ledger-margin-rail"><span>' + str(number) + '</span></aside>'
                '<div class="ledger-margin-body"><h2 class="layout-chapter-title">' + title + '</h2>')
    return ('<section class="reading-series-chapter" id="chapter-' + chapter.id + '">'
            '<header class="reading-series-chapter-head"><span>' + f"{number:02d}" + '</span>'
            '<h2 class="layout-chapter-title">' + title + '</h2></header>')


def chapter_close(design):
    return '</div></section>' if design == "ledger_margin" else '</section>'


def _children(markup):
    parser = _Blocks()
    parser.feed(markup.split('>', 1)[1].rsplit('</', 1)[0])
    parser.close()
    parser._finish()
    return parser.blocks


def _case_opening(sections, say):
    from . import report_charts
    question, examination = [], []
    question_heading = '<h3>' + escape(say("Question examined")) + '</h3>'
    for markup in sections.get("examination", ()):
        children = _children(markup)
        remaining, has_other_fields = [], False
        for tag, attrs, child in children:
            if tag == 'div' and 'examination-part' in attrs.get('class', '').split():
                if question_heading in child:
                    question.append(child.replace('class="examination-part"',
                                                  'class="examination-part layout-question"', 1))
                    continue
                has_other_fields = True
            remaining.append(child)
        if has_other_fields:
            examination.append('<section class="card" id="examination">' + ''.join(remaining) + '</section>')
    if question:
        if examination:
            sections['examination'] = examination
        else:
            sections.pop('examination', None)
        question.append('<p class="layout-authorship">' + escape(say(report_charts.REVIEW_NOTE)) + '</p>')
    case_fields = []
    for markup in sections.get('case', ()):
        case_fields.extend(child for tag, _attrs, child in _children(markup) if tag != 'h2')
    if case_fields or question:
        disclosure = ('<details class="layout-case-details"><summary>' + escape(say("Case details"))
                      + '</summary>' + ''.join(case_fields) + '</details>') if case_fields else ''
        sections['case'] = ['<section class="card layout-case" id="case">' + ''.join(question)
                            + disclosure + '</section>']


def _body(blocks, design, say, kind, replacements):
    sections, front, extras = {}, [], []
    for tag, attrs, markup in blocks:
        anchor, classes = attrs.get("id"), attrs.get("class", "").split()
        if anchor == "summary" or tag == "h1" or any(cls in classes for cls in ("hero", "tiles", "preview-cover")):
            front.append(markup)
        elif "toc" in classes:
            continue
        elif anchor in SECTION_KEYS:
            sections.setdefault(SECTION_KEYS[anchor], []).append(markup)
        elif tag == "h2":
            sections.setdefault("coverage", []).insert(0, markup)
        else:
            extras.append(markup)
    _case_opening(sections, say)
    sections.update({key: [] for key, replacement in replacements.items() if replacement is not None and key not in sections})
    for key, replacement in replacements.items():
        if replacement is None:
            sections.pop(key, None)
    chapters = [chapter for chapter in chapter_plan(design, kind) if any(key in sections for key in chapter.section_ids)]
    if extras:
        chapters.append(Chapter("additional", "Additional report details", ("additional",)))
        sections["additional"] = extras
    if design == "reading_series":
        yield '<div class="reading-series-shell"><aside class="reading-series-rail"><b>TgWitness</b>'
        yield navigation(chapters, say)
        yield '</aside><div class="reading-series-paper">'
    else:
        yield '<div class="ledger-margin-folio">'
    yield ''.join(front)
    if design == "ledger_margin":
        yield '<details class="ledger-margin-contents"><summary>' + escape(say("Contents")) + '</summary>'
        yield navigation(chapters, say)
        yield '</details>'
    for number, chapter in enumerate(chapters, 1):
        yield chapter_open(design, chapter, number, say)
        for key in chapter.section_ids:
            if key in replacements:
                if replacements[key] is not None:
                    yield from replacements[key]()
            else:
                yield from sections.get(key, ())
        yield chapter_close(design)
    yield '</div></div>' if design == "reading_series" else '</div>'


def compose(chunks, design, say, kind="journal", replacements=None):
    if design not in DESIGNS:
        yield from chunks
        return
    parser, inside, complete = _Blocks(), False, False
    for chunk in chunks:
        text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
        if complete:
            yield chunk if isinstance(chunk, bytes) else chunk.encode("utf-8")
            continue
        if not inside:
            prefix, marker, text = text.partition("<main>")
            if not marker:
                yield chunk if isinstance(chunk, bytes) else chunk.encode("utf-8")
                continue
            yield (prefix + marker).encode("utf-8")
            inside = True
        overview, marker, remainder = text.partition("</main>")
        parser.feed(overview)
        if marker:
            parser.close()
            parser._finish()
            for item in _body(parser.blocks, design, say, kind, replacements or {}):
                yield item.encode("utf-8")
            yield (marker + remainder).encode("utf-8")
            complete = True
    if inside and not complete:
        raise ValueError("Report composition requires a closed main overview")


def preview(fragment, design, say):
    return b''.join(compose([('<main>' + fragment + '</main>').encode('utf-8')], design, say, 'preview')).decode('utf-8')


def text_keys():
    import ast
    source = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    keys = [node.args[0].value for node in ast.walk(source)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "say"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)]
    return list(dict.fromkeys(keys + list(FIELD_LABELS.values()) + list(DESIGN_NAMES.values())
                             + ["Additional report details"] + [chapter.title for design in DESIGNS
                             for kind in ("journal", "chat") for chapter in chapter_plan(design, kind)]))
