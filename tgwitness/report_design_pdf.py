from dataclasses import dataclass
from types import MappingProxyType

from .report_design import normalized


def rgb(value):
    return tuple(int(value[index:index + 2], 16) for index in (1, 3, 5))


@dataclass(frozen=True)
class Style:
    name: str
    ink: tuple
    muted: tuple
    accent: tuple
    line: tuple
    tint: tuple
    paper: tuple = (255, 255, 255)
    heading_family: str = "Sans"
    margins: tuple = (18, 16, 18)
    table_border: str = "HORIZONTAL_LINES"
    table_padding: float = 1.8
    highlight: tuple | None = None


STYLES = MappingProxyType({
    "classic": Style("classic", (20, 44, 59), (89, 104, 112), (198, 158, 91),
                     (214, 219, 218), (245, 245, 240), table_border="ALL", table_padding=1.4),
    "quire": Style("quire", rgb("#1F1B16"), rgb("#5E554B"), rgb("#8C2F1C"),
                   rgb("#D9D0C1"), rgb("#F4EFE5"), paper=rgb("#FBF8F1"),
                   heading_family="Serif", margins=(20, 18, 20)),
    "meridian": Style("meridian", rgb("#1A1E24"), rgb("#5C6570"), rgb("#0E4B64"),
                      rgb("#D4CDC1"), rgb("#F5F3EE"), margins=(12, 16, 12), table_padding=1.25),
    "atlas": Style("atlas", rgb("#16212E"), rgb("#526273"), rgb("#0B5D6B"),
                   rgb("#D6CFC1"), rgb("#F6F2E9"), margins=(16, 17, 16), table_border="ALL", table_padding=2.3),
    "ledger": Style("ledger", rgb("#17252E"), rgb("#4C606C"), rgb("#174F69"),
                    rgb("#8B9BA5"), rgb("#EDF2F5"), margins=(16, 16, 16), table_border="ALL", table_padding=1.3),
    "horizon": Style("horizon", rgb("#0F172A"), rgb("#52657C"), rgb("#036B9C"),
                     rgb("#E2E8F0"), rgb("#F4F6F9"), margins=(12, 17, 12), table_padding=1.9,
                     highlight=rgb("#0EA5E9")),
    "reading_series": Style("reading_series", rgb("#202D30"), rgb("#526266"), rgb("#176461"),
                            rgb("#C5CECA"), rgb("#F0F3EF"), paper=rgb("#FFFEFA"),
                            heading_family="Serif", margins=(20, 20, 20), table_padding=1.9),
    "ledger_margin": Style("ledger_margin", rgb("#1D1F22"), rgb("#565B62"), rgb("#0D5C63"),
                           rgb("#D6D2C6"), rgb("#F1EEE5"), paper=rgb("#FBFAF6"),
                           heading_family="Serif", margins=(15, 20, 15), table_border="ALL", table_padding=1.4),
})


def get_style(value):
    return STYLES[normalized(value)]


def color(style, value):
    return {
        (20, 44, 59): style.ink, (89, 104, 112): style.muted,
        (214, 219, 218): style.line, (245, 245, 240): style.tint,
        (198, 158, 91): style.accent,
    }.get(tuple(value), value)


def _rule(pdf, y, shade, width=None, thickness=.3):
    with pdf.local_context(draw_color=shade, line_width=thickness):
        pdf.line(pdf.l_margin, y, pdf.l_margin + (width or pdf.epw), y)


def _box(pdf, x, y, width, height, shade):
    with pdf.local_context(fill_color=shade):
        pdf.rect(x, y, width, height, style="F")


def _roman(number):
    result = ""
    for value, token in ((1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
                         (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")):
        count, number = divmod(number, value)
        result += token * count
    return result


def _title(lay, text, size, width=None):
    pdf, style = lay.pdf, lay.pdf.report_style
    size = size if len(str(text)) < 90 else size * .82 if len(str(text)) < 160 else size * .7
    pdf.set_font(style.heading_family, "B", size)
    pdf.set_text_color(*style.ink)
    pdf.multi_cell(width or pdf.epw, size * .47, str(text), align=lay.align[0],
                   new_x=lay.XPos.LMARGIN, new_y=lay.YPos.NEXT)


def _facts(lay, facts, mode):
    pdf, style = lay.pdf, lay.pdf.report_style
    facts = [(str(label), str(value)) for label, value in facts if value not in ("", None)]
    if not facts:
        return
    pdf.set_draw_color(*style.line)
    if mode in ("meridian", "atlas", "horizon"):
        columns = 3 if mode == "horizon" else 2
        with pdf.table(col_widths=[1] * columns, first_row_as_headings=False,
                       borders_layout="NONE" if mode == "atlas" else "HORIZONTAL_LINES",
                       line_height=4.3, text_align=lay.align, padding=3 if mode == "atlas" else 1.7,
                       cell_fill_color=style.tint, cell_fill_mode="ALL" if mode == "atlas" else "NONE") as table:
            for offset in range(0, len(facts), columns):
                row = table.row()
                group = facts[offset:offset + columns]
                while len(group) < columns:
                    group.append(("", ""))
                for label, value in lay.mirror(group):
                    row.cell((label.upper() + "\n" + value).strip(), style=lay.face(size=8.2))
    else:
        with pdf.table(col_widths=lay.mirror((27, 73)), first_row_as_headings=False,
                       borders_layout="ALL" if mode == "ledger" else "HORIZONTAL_LINES",
                       line_height=4.5, text_align=lay.align, padding=1.7) as table:
            for label, value in facts:
                row = table.row()
                cells = [(label.upper(), lay.face(size=7, color=style.muted)),
                         (value, lay.face(mono=mode == "ledger", size=8.4))]
                for text, face in lay.mirror(cells):
                    row.cell(text, style=face)
    lay.gap(4)


def title_block(lay, eyebrow, title, facts, signed_note, kind=None):
    pdf, style = lay.pdf, lay.pdf.report_style
    if style.name in ("reading_series", "ledger_margin"):
        from .report_composition_pdf import title_block as independent_title
        return independent_title(lay, eyebrow, title, facts, signed_note)
    pdf.add_page()
    pdf.start_section(str(title), level=0)
    name = style.name
    if name == "quire":
        with pdf.local_context(draw_color=style.line, line_width=.25):
            pdf.rect(11.5, 11.5, pdf.w - 23, pdf.h - 31)
        with pdf.local_context(draw_color=style.ink, line_width=.55):
            pdf.rect(10, 10, pdf.w - 20, pdf.h - 28)
        pdf.set_y(23)
        lay.text("TG / WITNESS", size=10, style="B")
        lay.text((kind or lay.say("Evidence dossier")).upper(), size=7.3, color=style.muted)
        _rule(pdf, 42, style.line)
        pdf.set_y(57)
        lay.text(eyebrow.upper(), size=8, color=style.accent)
        lay.gap(4)
        _title(lay, title, 34)
        lay.gap(8)
        _rule(pdf, pdf.get_y(), style.accent, width=30, thickness=.6)
        lay.gap(5)
        _facts(lay, facts, name)
    elif name == "meridian":
        _box(pdf, pdf.w - 5 if lay.rtl else 0, 0, 5, pdf.h, style.accent)
        pdf.set_y(16)
        lay.text("TG / WITNESS", size=10, style="B", color=style.accent)
        _rule(pdf, 26, style.ink, thickness=.7)
        pdf.set_y(33)
        lay.text(eyebrow.upper(), size=7.5, style="B", color=style.accent)
        lay.gap(2)
        _title(lay, title, 30)
        lay.gap(5)
        _facts(lay, facts, name)
    elif name == "atlas":
        _box(pdf, 0, 0, pdf.w, 10, style.tint)
        with pdf.local_context(draw_color=style.line, line_width=.15):
            for x in range(0, 211, 10):
                pdf.line(x, 0, x, 10)
        _rule(pdf, 19, style.accent, thickness=.7)
        _rule(pdf, 21, style.accent, thickness=.2)
        pdf.set_y(29)
        lay.text("TG / WITNESS", size=10, family="Mono", color=style.accent)
        lay.gap(7)
        lay.text(eyebrow.upper(), size=7.5, style="B", color=style.muted)
        lay.gap(2)
        _title(lay, title, 34)
        lay.gap(7)
        _facts(lay, facts, name)
    elif name == "ledger":
        pdf.set_y(18)
        lay.text("TG / WITNESS", size=11, family="Mono")
        _rule(pdf, pdf.get_y() + 3, style.ink, thickness=.65)
        pdf.set_y(pdf.get_y() + 7)
        lay.text(eyebrow.upper(), size=8, family="Mono", color=style.muted)
        lay.gap(5)
        _title(lay, title, 32)
        lay.gap(6)
        _rule(pdf, pdf.get_y(), style.ink, thickness=.65)
        lay.gap(4)
        _facts(lay, facts, name)
    else:
        size = 28 if len(str(title)) < 90 else 23 if len(str(title)) < 160 else 20
        pdf.set_font("Sans", "B", size)
        title_height = pdf.multi_cell(pdf.epw, size * .47, str(title), dry_run=True, output="HEIGHT")
        band_height = max(38, 25 + title_height)
        _box(pdf, 0, 0, pdf.w, band_height, style.ink)
        _box(pdf, 0, band_height, pdf.w, 1.1, style.highlight)
        pdf.set_y(8)
        lay.text("TG / WITNESS", size=9, style="B", color=(255, 255, 255))
        pdf.set_y(20)
        lay.text(title, size=size, height=size * .47, style="B", color=(255, 255, 255))
        pdf.set_y(band_height + 9)
        lay.text(eyebrow.upper(), size=8, style="B", color=style.muted)
        lay.gap(5)
        _facts(lay, facts, name)
    lay.callout(signed_note, style.accent)
    lay.gap(5)


def _figure_row(lay, row, *, cards=False, compact=False, ruled=False, hairlines=False):
    pdf, style = lay.pdf, lay.pdf.report_style
    row = lay.mirror(row)
    if pdf.will_page_break(28):
        pdf.add_page()
    start_y, start_page = pdf.get_y(), pdf.page_no()
    pdf.set_draw_color(*style.line)
    with pdf.table(col_widths=[1] * len(row), first_row_as_headings=False,
                   line_height=4.2 if compact else 5, text_align=lay.align,
                   borders_layout="ALL" if ruled else "NONE" if cards or hairlines else "HORIZONTAL_LINES",
                   cell_fill_color=style.tint, cell_fill_mode="ALL" if cards else "NONE",
                   padding=2.5 if cards else 1.6) as table:
        labels, values = table.row(), table.row()
        for label, value in row:
            labels.cell(label.upper(), style=lay.face(mono=ruled, size=6.8, color=style.muted))
            values.cell(value, style=lay.face(mono=ruled, size=17 if len(value) < 12 else 9,
                                             bold=not ruled, color=style.ink))
    if hairlines and start_page == pdf.page_no():
        with pdf.local_context(draw_color=style.line, line_width=.25):
            for index in range(1, len(row)):
                x = pdf.l_margin + pdf.epw * index / len(row)
                pdf.line(x, start_y, x, pdf.get_y())
    lay.gap(3 if cards else 1.5)


def figures(lay, items):
    style = lay.pdf.report_style
    if style.name in ("reading_series", "ledger_margin"):
        from .report_composition_pdf import figures as independent_figures
        return independent_figures(lay, items)
    items = [(str(label), str(value) if value is not None else "—") for label, value in items]
    if not items:
        return
    width = {"quire": 4, "meridian": 4, "atlas": 2, "ledger": 4, "horizon": 4}[style.name]
    short = [(label, value) for label, value in items if len(value) < 36]
    long = [(label, value) for label, value in items if len(value) >= 36]
    for start in range(0, len(short), width):
        _figure_row(lay, short[start:start + width], cards=style.name in ("atlas", "horizon"),
                    compact=style.name in ("meridian", "ledger"), ruled=style.name == "ledger",
                    hairlines=style.name == "quire")
    for item in long:
        _figure_row(lay, [item], compact=True, ruled=style.name == "ledger")
    lay.gap(3)
    lay.text(lay.say("Read the summary. Review the evidence. Repeat the checks."), size=7.5, color=style.muted)


def section(lay, title, lead):
    pdf, style = lay.pdf, lay.pdf.report_style
    if style.name in ("reading_series", "ledger_margin"):
        from .report_composition_pdf import section as independent_section
        return independent_section(lay, title, lead)
    lay.number += 1
    if pdf.get_y() > pdf.h - 65 or (style.name == "quire" and lay.number > 1 and pdf.get_y() > 35):
        pdf.add_page()
    else:
        lay.gap(4)
    pdf.start_section(str(lay.number) + ". " + title, level=1)
    if style.name == "quire":
        y = pdf.get_y()
        number_x = pdf.l_margin + pdf.epw - 34 if lay.rtl else pdf.l_margin
        pdf.set_xy(number_x, y)
        pdf.set_font("Serif", "", 28)
        pdf.set_text_color(*style.accent)
        pdf.cell(34, 14, _roman(lay.number), align=lay.align[0])
        pdf.set_xy(pdf.l_margin if lay.rtl else pdf.l_margin + 38, y)
        pdf.set_font("Serif", "B", 20)
        pdf.set_text_color(*style.ink)
        pdf.multi_cell(pdf.epw - 38, 8.5, title, align=lay.align[0], new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(max(pdf.get_y(), y + 14) + 2)
        _rule(pdf, pdf.get_y(), style.line)
        lay.gap(3)
    elif style.name == "meridian":
        lay.text(f"{lay.number:02d}" + "  " + title.upper(), size=10.5, style="B", color=style.ink)
        _rule(pdf, pdf.get_y() + 1, style.accent, thickness=.8)
        lay.gap(4)
    elif style.name == "atlas":
        lay.text(f"{lay.number:02d}" + "   /   " + title, size=13, family="Mono", color=style.accent)
        lay.gap(1)
        _rule(pdf, pdf.get_y(), style.line)
        lay.gap(3)
    elif style.name == "ledger":
        _rule(pdf, pdf.get_y(), style.ink, thickness=.55)
        lay.gap(3)
        lay.text(f"{lay.number:02d}" + " / " + title, size=17, height=8, style="B")
        _rule(pdf, pdf.get_y() + 1, style.line)
        lay.gap(4)
    else:
        lay.text(f"{lay.number:02d}" + "     " + title.upper(), size=12, style="B", height=6)
        _rule(pdf, pdf.get_y() + 1, style.highlight, thickness=1)
        lay.gap(4)
    if lead:
        lay.gap(1)
        lay.text(lead, size=8.8, color=style.muted)
    lay.gap(2)


def header(pdf, footer):
    style = pdf.report_style
    if style.name in ("reading_series", "ledger_margin"):
        from .report_composition_pdf import header as independent_header
        return independent_header(pdf, footer)
    if style.name == "quire":
        _box(pdf, 0, 0, pdf.w, pdf.h, style.paper)
    if pdf.page_no() <= 1:
        return
    if style.name == "meridian":
        _box(pdf, 0, 0, pdf.w, 4, style.accent)
    elif style.name == "horizon":
        _box(pdf, 0, 0, pdf.w, 4, style.ink)
        _box(pdf, 0, 4, pdf.w, .7, style.highlight)
    pdf.set_y(7)
    pdf.set_font("Mono" if style.name == "ledger" else "Sans", "", 7)
    pdf.set_text_color(*style.muted)
    pdf.multi_cell(pdf.epw, 3.5, "TG / WITNESS    ·    " + footer,
                   align="R" if pdf.rtl else "L", new_x="LMARGIN", new_y="NEXT")
    y = max(15, pdf.get_y() + 2)
    _rule(pdf, y, style.line, thickness=.5 if style.name == "ledger" else .25)
    pdf.set_xy(pdf.l_margin, y + 4)


def footer(pdf, text):
    style = pdf.report_style
    if style.name in ("reading_series", "ledger_margin"):
        from .report_composition_pdf import footer as independent_footer
        return independent_footer(pdf, text)
    _rule(pdf, pdf.h - 16, style.line, thickness=.55 if style.name == "ledger" else .25)
    pdf.set_y(-12)
    pdf.set_font("Mono" if style.name == "ledger" else "Sans", "", 7)
    pdf.set_text_color(*style.muted)
    if style.name == "quire":
        pdf.multi_cell(pdf.epw * .78, 3.5, text, new_x="RIGHT", new_y="TOP")
        pdf.cell(pdf.epw * .22, 5, f"{pdf.page_no()} / {{nb}}", align="R")
    elif style.name == "meridian":
        pdf.multi_cell(pdf.epw * .82, 3.5, text, new_x="RIGHT", new_y="TOP")
        with pdf.local_context(fill_color=style.ink, text_color=(255, 255, 255)):
            pdf.cell(pdf.epw * .18, 5, f"{pdf.page_no()} / {{nb}}", align="C", fill=True)
    elif style.name == "ledger":
        pdf.multi_cell(pdf.epw * .8, 3.5, text, new_x="RIGHT", new_y="TOP")
        pdf.cell(pdf.epw * .2, 5, f"[{pdf.page_no():03d} / {{nb}}]", align="R")
    else:
        pdf.multi_cell(pdf.epw * .8, 3.5, text, new_x="RIGHT", new_y="TOP")
        pdf.set_text_color(*style.accent)
        pdf.cell(pdf.epw * .2, 5, f"{pdf.page_no()} / {{nb}}", align="R")

