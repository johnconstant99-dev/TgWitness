"""Native compositions of the approved Evidence Reading Series and Ledger & Margin.

The chapter content is supplied by the existing report renderers. This module
does not read account data, restore hidden fields, or alter the signed subject.
No browser, external fonts, network calls or HTML interpreter are required.
"""
INDEPENDENT = frozenset(("reading_series", "ledger_margin"))


def active(lay):
    return getattr(getattr(lay, "design", None), "name", None) in INDEPENDENT


def text_keys():
    import ast
    from pathlib import Path
    return list(dict.fromkeys(node.args[0].value for node in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8")))
                             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "say"
                             and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)))


def _rule(pdf, y, shade, *, x=None, width=None, weight=.3):
    x = pdf.l_margin if x is None else x
    with pdf.local_context(draw_color=shade, line_width=weight):
        pdf.line(x, y, x + (pdf.epw if width is None else width), y)


def _fill(pdf, x, y, width, height, shade):
    with pdf.local_context(fill_color=shade):
        pdf.rect(x, y, width, height, style="F")


def title_block(lay, eyebrow, title, facts, signed_note):
    pdf, style, say = lay.pdf, lay.design, lay.say
    pdf.add_page()
    pdf.start_section(str(title), level=0)
    if style.name == "reading_series":
        _rule(pdf, 21, style.accent, weight=2)
        pdf.set_y(28)
        lay.text(say("Evidence Reading Series").upper(), size=8, style="B", color=style.accent)
        lay.gap(7)
        lay.text(title, size=31 if len(str(title)) < 120 else 24, height=12,
                 family="Serif", color=style.ink)
        lay.gap(6)
        lay.text(eyebrow, size=9, color=style.muted)
        lay.gap(7)
        pairs = [(str(label), str(value)) for label, value in facts if value not in (None, "")]
        with pdf.table(col_widths=(1, 1), first_row_as_headings=False, borders_layout="NONE",
                       line_height=4.5, padding=(2, 3, 3, 0), text_align=lay.align) as table:
            for offset in range(0, len(pairs), 2):
                row = table.row()
                group = pairs[offset:offset + 2]
                if len(group) == 1:
                    group.append(("", ""))
                for label, value in lay.mirror(group):
                    row.cell((label.upper() + "\n" + value).strip(), style=lay.face(size=8.4))
    else:
        pdf.set_y(22)
        lay.text(say("Ledger & Margin").upper(), size=8, color=style.muted)
        lay.gap(3)
        lay.text(title, size=29 if len(str(title)) < 120 else 23, height=11,
                 style="B", family="Serif", color=style.ink)
        lay.gap(3)
        lay.text(eyebrow, size=8.5, color=style.muted)
        y = pdf.get_y() + 4
        _rule(pdf, y, style.ink, weight=.65)
        _rule(pdf, y + 1.2, style.ink, weight=.2)
        pdf.set_y(y + 7)
        lay.kv(facts)
    lay.gap(4)
    lay.callout(signed_note, style.accent)
    lay.gap(4)


def figures(lay, items):
    """The models use an exact count register, rather than ornamental KPI cards."""
    if not items:
        return
    pdf, style = lay.pdf, lay.design
    rows = [(str(label), "—" if value is None else str(value)) for label, value in items]
    if style.name == "reading_series":
        with pdf.table(col_widths=lay.mirror((60, 40)), first_row_as_headings=False,
                       borders_layout="HORIZONTAL_LINES", padding=1.5, line_height=4.4,
                       text_align=lay.align) as table:
            for label, value in rows:
                row = table.row()
                for text, face in lay.mirror([(label, lay.face(size=8.2, color=style.muted)),
                                              (value, lay.face(mono=True, size=8.2))]):
                    row.cell(text, style=face)
    else:
        with pdf.table(col_widths=lay.mirror((42, 58)), first_row_as_headings=False,
                       borders_layout="ALL", padding=1.4, line_height=4.4,
                       text_align=lay.align) as table:
            for label, value in rows:
                row = table.row()
                for text in lay.mirror((label, value)):
                    row.cell(text, style=lay.face(size=8.3))
    lay.gap(4)


def _body_margins(pdf):
    left, top, right = pdf.report_style.margins
    if pdf.report_style.name == "ledger_margin":
        left, right = (left, right + 31) if pdf.rtl else (left + 31, right)
    pdf.set_margins(left, top, right)
    pdf.set_x(left)


def _rail(pdf, title, number, y):
    """A real marginal column, outside the narrative's text measure."""
    style = pdf.report_style
    base_left, _, base_right = style.margins
    x = pdf.w - base_right - 25 if pdf.rtl else base_left
    pdf.set_xy(x, y)
    pdf.set_font("Serif", "", 25)
    pdf.set_text_color(*style.accent)
    pdf.cell(25, 12, str(number), align="R" if pdf.rtl else "L")
    pdf.set_xy(x, y + 14)
    pdf.set_font("Sans", "", 7)
    pdf.set_text_color(*style.muted)
    pdf.multi_cell(25, 3.7, title, new_x="LMARGIN", new_y="NEXT", align="R" if pdf.rtl else "L")
    pdf.set_xy(pdf.l_margin, y)


def section(lay, title, lead=""):
    pdf, style = lay.pdf, lay.design
    # Existing section renderers become subsections inside the model's chapters.
    if getattr(lay, "composition_chapter", False):
        lay.need(23)
        pdf.start_section(str(title), level=2)
        lay.gap(3)
        lay.text(title, size=10.2, style="B", color=style.accent)
        if lead:
            lay.text(lead, size=8.4, color=style.muted)
        lay.gap(2)
        return
    _body_margins(pdf)
    lay.number += 1
    if pdf.page_no() == 1 or pdf.get_y() > pdf.h - 67:
        # The new chapter will draw its own rail below. Do not first print the
        # previous chapter in the same margin from the page header.
        pdf.report_chapter = None
        pdf.add_page()
    else:
        lay.gap(6)
    title = str(title)
    pdf.report_chapter = (lay.number, title)
    pdf.start_section(f"{lay.number:02d}. {title}", level=1)
    y = pdf.get_y()
    _rule(pdf, y, style.ink if style.name == "reading_series" else style.line, weight=.35)
    pdf.set_y(y + 5)
    if style.name == "ledger_margin":
        _rail(pdf, title, lay.number, y + 5)
        lay.text(title, family="Serif", style="B", size=18, height=8.2)
    else:
        lay.text(f"{lay.number:02d}", family="Mono", size=9, color=style.accent)
        lay.gap(1)
        lay.text(title, family="Serif", size=22, height=9)
    if lead:
        lay.gap(2)
        lay.text(lead, size=9, color=style.muted)
    lay.gap(3)


def header(pdf, footer):
    style = pdf.report_style
    _fill(pdf, 0, 0, pdf.w, pdf.h, style.paper)
    if pdf.page_no() == 1:
        return
    pdf.set_y(7)
    pdf.set_font("Sans", "", 7)
    pdf.set_text_color(*style.muted)
    pdf.multi_cell(pdf.epw, 3.5, "TgWitness · " + footer, new_x="LMARGIN", new_y="NEXT")
    y = max(16, pdf.get_y() + 3)
    _rule(pdf, y, style.line)
    pdf.set_y(y + 5)
    chapter = getattr(pdf, "report_chapter", None)
    if style.name == "ledger_margin" and chapter:
        _rail(pdf, chapter[1], chapter[0], y + 5)
    pdf.set_x(pdf.l_margin)


def footer(pdf, text):
    style = pdf.report_style
    base_left, _, base_right = style.margins
    width = pdf.w - base_left - base_right
    _rule(pdf, pdf.h - 16, style.accent if style.name == "reading_series" else style.ink,
          x=base_left, width=width, weight=.65 if style.name == "reading_series" else .2)
    pdf.set_xy(base_left, pdf.h - 12)
    pdf.set_font("Sans", "", 6.8)
    pdf.set_text_color(*style.muted)
    pdf.multi_cell(width * .8, 3.3, text, new_x="RIGHT", new_y="TOP")
    pdf.set_font("Mono", "", 7.5)
    pdf.cell(width * .2, 5, f"{pdf.page_no():02d} / {{nb}}", align="R")


def render(lay, callbacks, default_order, kind, visible=None):
    if not active(lay):
        for key in default_order:
            callbacks[key]()
        return
    from .report_layouts import chapter_plan
    visible = visible or {}
    seen = set()
    for chapter in chapter_plan(lay.design.name, kind=kind):
        keys = [key for key in chapter.section_ids if key in callbacks and key not in seen
                and visible.get(key, True)]
        if not keys:
            continue
        section(lay, lay.say(chapter.title))
        lay.composition_chapter = True
        try:
            for key in keys:
                callbacks[key]()
                seen.add(key)
        finally:
            lay.composition_chapter = False
    # Never silently omit an established content block if the plan grows stale.
    remaining = [key for key in default_order if key not in seen and visible.get(key, True)]
    if remaining:
        raise ValueError("Native PDF chapter plan omits sections: " + ", ".join(remaining))


def indexed_events(events, total):
    """Read a bounded permitted prefix once and put every consumed event back.

    The directory is explicitly a reading aid, never a full-journal ranking.
    The transcript still receives the complete original iterator in order.
    """
    import itertools
    import json
    from .report_layouts import journal_directory, SSR_LIMIT, SSR_BYTES
    if events is None:
        return events, None
    stream, replay, sampled, size = iter(events), [], [], 0
    for event in itertools.islice(stream, SSR_LIMIT):
        replay.append(event)
        length = len(json.dumps(event, ensure_ascii=False, default=str).encode("utf-8"))
        if size + length > SSR_BYTES:
            break
        sampled.append(event)
        size += length
    index = journal_directory(sampled)
    index["limited"] = bool(index["limited"] or len(sampled) < total)
    return itertools.chain(replay, stream), index


def index_basis(lay, index):
    say = lay.say
    if index.get("limited"):
        lay.text(say("Reading index of the first {n} included records. Counts below describe this index only; the signed source and transcript remain unchanged.",
                     n=index["records_examined"]), size=8, color=lay.design.muted)
    else:
        lay.text(say("Reading index of {n} included records. Account names are saved observations, not verified identities.",
                     n=index["records_examined"]), size=8, color=lay.design.muted)


def directory(lay, data, index=None):
    say = lay.say
    chats = data.get("chats") or []
    if chats:
        lay.section(say("Chats"))
        lay.grid([say("Chat"), "ID", say("Records")],
                 [[chat.get("title") or say("Unknown"), str(chat.get("chat_id")), chat.get("records", 0)]
                  for chat in chats], (48, 30, 22))
    if index and index.get("senders"):
        lay.section(say("Observed accounts"))
        index_basis(lay, index)
        lay.grid([say("Participant"), "ID", say("Records")],
                 [[" · ".join(str(x) for x in (row["profile"].get("display_name"),
                       "@" + row["profile"]["username"] if row["profile"].get("username") else "") if x)
                   or say("Unknown"), str(row["sender_id"]), row["records"]] for row in index["senders"]], (48, 30, 22))


def relations(lay, index):
    if not index or not index.get("relations"):
        return
    from .pdf_report import details_lines
    say = lay.say
    lay.section(say("Replies, threads and forwards"))
    index_basis(lay, index)
    keys = frozenset(("reply_to_message_id", "reply_to_top_id", "reply_to_peer_id", "forum_topic",
                      "quote_text", "quote_offset", "quote_entities", "forwarded_from"))
    for row in index["relations"]:
        record_heading(lay, "#" + str(row["seq"]) + " · " + say("Chat {id}", id=row["chat_id"])
                       + " · " + say("message {id}", id=row["message_id"]))
        permitted = {key: value for key, value in row["details"].items() if key in keys}
        for line in details_lines(say, permitted, include_media=False):
            lay.text(line, size=8.5, color=lay.design.muted)


def record_heading(lay, label):
    """Model-specific record geometry while callers retain every permitted field."""
    if not active(lay):
        lay.text(label, size=7.8, style="B")
        return
    pdf, style = lay.pdf, lay.design
    lay.need(24)
    lay.gap(3)
    _rule(pdf, pdf.get_y(), style.ink, weight=.6 if style.name == "reading_series" else .25)
    lay.gap(3)
    lay.text(label, size=8.5, family="Mono", color=style.accent)
    lay.gap(2)


def message_text(lay, text):
    if active(lay):
        lay.text(text, size=10, height=5.1, family="Serif")
    else:
        lay.text(text, size=8.6)


def comparison(lay, old, new):
    """Complete texts always remain readable, even across page boundaries."""
    say, pdf, style = lay.say, lay.pdf, lay.design
    if style.name == "reading_series":
        # Paired panels are used only while both complete strings fit a row.
        # Longer texts flow vertically rather than being clipped by table cells.
        pdf.set_font("Serif", "", 9)
        widths = (pdf.epw / 2 - 5, pdf.epw / 2 - 5)
        heights = [pdf.multi_cell(width, 4.7, text or say("(no text)"), dry_run=True, output="HEIGHT")
                   for width, text in zip(widths, (old, new))]
        if max(heights) < 70:
            lay.need(max(heights) + 21)
            with pdf.table(col_widths=(1, 1), first_row_as_headings=False, line_height=4.7,
                           borders_layout="HORIZONTAL_LINES", padding=2.5, text_align=lay.align,
                           cell_fill_color=style.tint, cell_fill_mode="ALL") as table:
                heading, row = table.row(), table.row()
                for label in lay.mirror((say("Before"), say("After"))):
                    heading.cell(label, style=lay.face(bold=True, size=8))
                for text in lay.mirror((old, new)):
                    row.cell(text or say("(no text)"), style=lay.face(size=9))
            lay.gap(3)
            return
    for label, text in ((say("Before"), old), (say("After"), new)):
        lay.text(label, size=8, style="B", color=style.accent)
        lay.text(text or say("(no text)"), size=10, height=5, family="Serif")
        lay.gap(2)
