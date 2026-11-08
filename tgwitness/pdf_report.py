from . import render_data
import difflib
import hashlib
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import report, report_design_pdf, report_composition_pdf
from .store import canonical
from .verify import coverage_lines, fingerprint

FONT_DIR = Path(__file__).with_name("fonts")
SEAL_ATTRIBUTE = "2.25." + str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/phishdestroy/TgWitness#pdf-seal").int)
CONTENTS_HEX = 65536
BYTE_RANGE_PLACEHOLDER = b"[0000000000 0000000000 0000000000 0000000000]"
SIGNED_DATA, DATA = "1.2.840.113549.1.7.2", "1.2.840.113549.1.7.1"
CONTENT_TYPE, MESSAGE_DIGEST, SIGNING_TIME = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4", "1.2.840.113549.1.9.5"
SIGNING_CERTIFICATE_V2, SHA256, ECDSA_SHA256 = "1.2.840.113549.1.9.16.2.47", "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2"
INK, MUTED, LINE, FILL = (20, 44, 59), (89, 104, 112), (214, 219, 218), (245, 245, 240)
GOLD, WHITE = (198, 158, 91), (255, 255, 255)
OK, BAD, WARN = (23, 102, 58), (161, 25, 31), (138, 75, 0)
FALLBACKS = ("NotoSansArabic-Regular.ttf", "NotoSansHebrew-Regular.ttf", "NotoSansDevanagari-Regular.ttf",
             "NotoSansBengali-Regular.ttf", "NotoSansThai-Regular.ttf", "NotoSansSymbols2-Regular.ttf",
             "NotoEmoji-Regular.ttf")
CJK_FONTS = ("msyh.ttc", "malgun.ttf", "msyh.ttf", "msjh.ttc", "YuGothR.ttc", "meiryo.ttc", "simsun.ttc",
             "NotoSansCJK-Regular.ttc", "NotoSansCJKsc-Regular.otf", "NotoSansSC-Regular.ttf", "wqy-zenhei.ttc",
             "Arial Unicode.ttf", "Hiragino Sans GB.ttc")
CJK_DIRS = ("C:/Windows/Fonts", "/usr/share/fonts/opentype/noto", "/usr/share/fonts/noto-cjk",
            "/usr/share/fonts/truetype/wqy", "/usr/share/fonts/google-noto-cjk", "/Library/Fonts",
            "/System/Library/Fonts", "/System/Library/Fonts/Supplemental")
COMPLEX_SCRIPTS = re.compile("[\u0300-\u036f\u0590-\u08ff\u0900-\u0dff\u0e00-\u0fff\u1000-\u109f\u1780-\u18af"
                             "\u200c-\u200f\u202a-\u202e\u2066-\u2069\ufb1d-\ufdff\ufe70-\ufeff\U0001f3fb-\U0001f3ff]")


def available():
    try:
        import fpdf  # noqa: F401
    except ImportError:
        return False
    return True


class MissingFont(ValueError):
    pass


def cjk_candidates():
    folders = [os.environ.get("TGWITNESS_FONT_DIR")] if os.environ.get("TGWITNESS_FONT_DIR") else []
    windows = os.environ.get("WINDIR")
    folders += ([windows + "/Fonts"] if windows else []) + list(CJK_DIRS)
    seen = set()
    for folder in folders:
        for name in CJK_FONTS:
            path = Path(folder) / name
            if path.is_file() and path.resolve() not in seen:
                seen.add(path.resolve())
                yield path


def cjk_font():
    return next(cjk_candidates(), None)


def document(say, footer, design="classic"):
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    class Document(FPDF):
        def header(self):
            if self.report_style.name != "classic":
                return report_design_pdf.header(self, footer)
            if self.page_no() > 1:
                self.set_font("Sans", "B", size=7)
                self.set_text_color(*MUTED)
                self.set_y(6)
                self.multi_cell(self.epw, 3.5, "TG / WITNESS    ·    " + footer, align="R" if self.rtl else "L",
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                line_y = max(14, self.get_y() + 2)
                self.set_draw_color(*LINE)
                self.line(self.l_margin, line_y, self.l_margin + self.epw, line_y)
                with self.local_context(draw_color=GOLD, line_width=0.7):
                    self.line(self.l_margin, line_y, self.l_margin + 16, line_y)
                self.set_xy(self.l_margin, line_y + 4)

        def font_on_page(self):
            if self.page and self.current_font is not None and getattr(self, "current_font_is_set_on_page", True) is False \
                    and hasattr(self, "_set_font_for_page"):
                self._out(self._set_font_for_page(self.current_font, self.font_size_pt))

        def shape_for(self, text):
            wanted = self.can_shape and bool(COMPLEX_SCRIPTS.search(str(text or "")))
            if wanted != self.shaping:
                self.set_text_shaping(wanted)
                self.shaping = wanted

        def cell(self, w=None, h=None, text="", *args, **kwargs):
            self.font_on_page()
            self.shape_for(text)
            return super().cell(w, h, text, *args, **kwargs)

        def multi_cell(self, w, h=None, text="", *args, **kwargs):
            self.font_on_page()
            self.shape_for(text)
            return super().multi_cell(w, h, text, *args, **kwargs)

        def write(self, h=None, text="", *args, **kwargs):
            self.font_on_page()
            self.shape_for(text)
            return super().write(h, text, *args, **kwargs)

        def footer(self):
            if self.report_style.name != "classic":
                return report_design_pdf.footer(self, footer)
            self.set_draw_color(*LINE)
            self.line(self.l_margin, self.h - 16, self.l_margin + self.epw, self.h - 16)
            self.set_y(-12)
            self.set_font("Sans", size=7.5)
            self.set_text_color(*MUTED)
            self.multi_cell(self.epw * 0.8, 3.5, footer, align="L", new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(self.epw * 0.2, 5, "%d / {nb}" % self.page_no(), align="R")

        def line_text(self, text, size=9.5, style="", color=INK, height=None, align=None, family="Sans"):
            self.set_font(family, style, size)
            self.set_text_color(*report_design_pdf.color(self.report_style, color))
            self.multi_cell(0, height or size * 0.47, str(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT,
                            align=align or ("R" if self.rtl else "L"))

    pdf = Document(format="A4", unit="mm")
    pdf.report_style = report_design_pdf.get_style(design)
    pdf.rtl, pdf.say, pdf.missing = say.direction == "rtl", say, set()
    pdf.set_margins(*pdf.report_style.margins)
    pdf.set_auto_page_break(True, 20)
    pdf.add_font("Sans", "", str(FONT_DIR / "NotoSans-Regular.ttf"))
    pdf.add_font("Sans", "B", str(FONT_DIR / "NotoSans-Bold.ttf"))
    pdf.add_font("Mono", "", str(FONT_DIR / "NotoSansMono-Regular.ttf"))
    if pdf.report_style.heading_family == "Serif":
        pdf.add_font("Serif", "", str(FONT_DIR / "NotoSerif-Regular.ttf"))
        pdf.add_font("Serif", "B", str(FONT_DIR / "NotoSerif-Bold.ttf"))
    fallbacks = []
    for name in FALLBACKS:
        pdf.add_font(name[:-4], "", str(FONT_DIR / name))
        fallbacks.append(name[:-4])
    extra = cjk_font()
    cjk_coverage = set()
    if extra:
        probes = {ord(char) for char in "证證あ한"}
        for path in dict.fromkeys([extra, *cjk_candidates()]):
            try:
                family = "CJK" + str(len(fallbacks))
                pdf.add_font(family, "", str(path))
                fallbacks.append(family)
                cjk_coverage.update(pdf.fonts[family.lower()].cmap)
                if probes <= cjk_coverage:
                    break
            except Exception:
                continue
    required = {"zh": "证", "zh-Hant": "證", "ja": "あ", "ko": "한"}.get(say.language)
    if required and ord(required) not in cjk_coverage:
        raise MissingFont("A PDF in this language needs a Chinese, Japanese or Korean font on the server. "
                          "Install one (for example Noto Sans CJK) or put it in TGWITNESS_FONT_DIR; "
                          "the HTML and JSON reports are complete without it.")
    pdf.set_fallback_fonts(fallbacks, exact_match=False)
    try:
        pdf.set_text_shaping(True)
        pdf.set_text_shaping(False)
        pdf.can_shape = True
    except Exception:
        pdf.can_shape = False
    pdf.shaping = False
    pdf.set_creator("TgWitness")
    pdf.set_keywords("TgWitness; report design: " + pdf.report_style.name)
    pdf.set_lang(say.language)
    pdf.alias_nb_pages()
    return pdf


class MissingGlyphs(logging.Handler):
    def __init__(self, found):
        super().__init__(logging.WARNING)
        self.found = found
        self.thread = threading.get_ident()

    def emit(self, record):
        if record.thread != self.thread:
            return
        message = record.getMessage()
        if "missing the following glyphs" in message:
            self.found.add(message.split(":", 1)[-1].strip()[:200])


class Layout:
    def __init__(self, pdf, say, template=None):
        from fpdf.enums import TextEmphasis, XPos, YPos
        from fpdf.fonts import FontFace
        self.pdf, self.say, self.XPos, self.YPos, self.FontFace = pdf, say, XPos, YPos, FontFace
        self.plain = TextEmphasis.NONE
        self.number = 0
        self.design = pdf.report_style
        self.rtl = pdf.rtl
        self.align = "RIGHT" if pdf.rtl else "LEFT"
        self.accent = self.design.accent

    def need(self, height):
        if self.pdf.get_y() + height > self.pdf.h - self.pdf.b_margin:
            self.pdf.add_page()

    def mirror(self, items):
        items = list(items)
        return items[::-1] if self.rtl else items

    def face(self, mono=False, size=8.8, bold=False, color=INK):
        return self.FontFace(family="Mono" if mono else "Sans", emphasis="BOLD" if bold else self.plain,
                             size_pt=size, color=report_design_pdf.color(self.design, color))

    def text(self, value, **kwargs):
        self.pdf.line_text(value, **kwargs)

    def gap(self, mm=2):
        self.pdf.ln(mm)

    def title_block(self, eyebrow, title, facts, signed_note, kind=None):
        if self.design.name != "classic":
            return report_design_pdf.title_block(self, eyebrow, title, facts, signed_note, kind)
        pdf = self.pdf
        pdf.add_page()
        pdf.start_section(str(title), level=0)
        with pdf.local_context(fill_color=INK):
            pdf.rect(0, 0, pdf.w, 37, style="F")
        with pdf.local_context(fill_color=GOLD):
            pdf.rect(pdf.l_margin, 36, 28, 1, style="F")
        pdf.set_y(13)
        self.text("TG / WITNESS", size=13, style="B", color=WHITE)
        self.text((kind or self.say("Evidence dossier")).upper(), size=7.5, color=(214, 224, 228))
        pdf.set_y(48)
        self.text(eyebrow.upper(), size=8, style="B", color=MUTED)
        self.gap(4)
        title_size = 29 if len(str(title)) < 90 else 23 if len(str(title)) < 160 else 19
        self.text(title, size=title_size, style="B", height=title_size * .42)
        self.gap(7)
        pdf.set_draw_color(*LINE)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())
        self.gap(5)
        shown = [(k, v) for k, v in facts if v]
        width = pdf.epw / 2
        for row in range(0, len(shown), 2):
            y = pdf.get_y()
            heights = []
            for column, (label, value) in enumerate(shown[row:row + 2]):
                pdf.set_xy(pdf.l_margin + (1 - column if self.rtl else column) * width + (4 if self.rtl else 0), y)
                pdf.set_font("Sans", "", 7.5)
                pdf.set_text_color(*MUTED)
                pdf.multi_cell(width - 5, 4, label.upper(), new_x=self.XPos.LEFT, new_y=self.YPos.NEXT, align=self.align[0])
                pdf.set_font("Sans", "B", 9.5)
                pdf.set_text_color(*INK)
                pdf.multi_cell(width - 5, 4.6, str(value), new_x=self.XPos.LEFT, new_y=self.YPos.NEXT,
                               align=self.align[0])
                heights.append(pdf.get_y() - y)
            pdf.set_xy(pdf.l_margin, y + max(heights) + 4)
        self.gap(3)
        self.callout(signed_note, GOLD)
        self.gap(5)

    def figures(self, items):
        if self.design.name != "classic":
            return report_design_pdf.figures(self, items)
        pdf = self.pdf
        items = [(k, str(v) if v is not None else "—") for k, v in items]
        for start in range(0, len(items), 4):
            row = self.mirror(items[start:start + 4])
            with pdf.table(col_widths=[1] * len(row), first_row_as_headings=False, line_height=5,
                           borders_layout="HORIZONTAL_LINES", text_align=self.align, padding=2.5) as table:
                labels, values = table.row(), table.row()
                for label, value in row:
                    labels.cell(label.upper(), style=self.face(size=7, color=MUTED))
                    values.cell(value, style=self.face(size=16 if len(value) < 12 else 10, bold=True))
            self.gap(2)
        self.gap(4)
        self.text(self.say("Read the summary. Review the evidence. Repeat the checks."), size=8, color=MUTED)

    def section(self, title, lead=""):
        if self.design.name != "classic":
            return report_design_pdf.section(self, title, lead)
        pdf = self.pdf
        self.number += 1
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        else:
            self.gap(3)
        y = pdf.get_y()
        pdf.set_draw_color(*GOLD)
        pdf.line(pdf.l_margin, y, pdf.l_margin + pdf.epw, y)
        pdf.set_draw_color(*LINE)
        pdf.set_y(y + 3)
        pdf.start_section(str(self.number) + ". " + title, level=1)
        self.text(f"{self.number:02d}" + "   /   " + title, size=15, style="B", height=7)
        if lead:
            self.gap(1)
            self.text(lead, size=8.8, color=MUTED)
        self.gap(2)

    def heading(self, title):
        if report_composition_pdf.active(self) and title in (
                self.say("Recorded activity over time"), self.say("Observation times by weekday and hour")):
            self.need(110)
        if self.pdf.get_y() > self.pdf.h - 45:
            self.pdf.add_page()
        self.gap(2)
        self.text(title, size=10.5, style="B")
        self.gap(1)

    def kv(self, rows):
        rows = [(k, v) for k, v in rows if v not in (None, "")]
        if not rows:
            return
        if self.design.name != "classic":
            self.pdf.set_draw_color(*self.design.line)
        with self.pdf.table(col_widths=self.mirror((30, 70)), first_row_as_headings=False, line_height=4.6,
                            borders_layout=self.design.table_border, cell_fill_color=self.design.tint,
                            text_align=self.align, padding=1.6 if self.design.name == "classic" else self.design.table_padding,
                            cell_fill_mode="COLUMNS" if self.rtl else "EVEN_COLUMNS") as table:
            for key, value in rows:
                row = table.row()
                mono = isinstance(value, Mono)
                for text, style in self.mirror([(str(key), self.face(bold=True)),
                                                (str(value), self.face(mono, 8 if mono else 8.8))]):
                    row.cell(text, style=style)
        self.gap(2)

    def grid(self, columns, rows, widths=None):
        if not rows:
            return
        if self.design.name != "classic":
            self.pdf.set_draw_color(*self.design.line)
        with self.pdf.table(col_widths=self.mirror(widths) if widths else None, line_height=4.4,
                            borders_layout=self.design.table_border,
                            text_align=self.align, padding=self.design.table_padding,
                            headings_style=self.FontFace(emphasis="BOLD", size_pt=8, fill_color=self.design.tint,
                                                         color=self.design.ink if self.design.name != "classic" else None)) as table:
            head = table.row()
            for column in self.mirror(columns):
                head.cell(column)
            for values in rows:
                row = table.row()
                for value in self.mirror(values):
                    mono = isinstance(value, Mono)
                    row.cell(str(value), style=self.face(mono, 7.4 if mono else 8.2))
        self.gap(2)

    def bullets(self, items, size=8.8):
        for item in items:
            self.text("•  " + str(item), size=size)
            self.gap(0.6)

    def callout(self, text, color=WARN):
        pdf = self.pdf
        if self.design.name != "classic":
            pdf.set_font("Sans", "", 8.8)
            needed = pdf.multi_cell(pdf.epw - 3.5, 4.4, str(text), dry_run=True, output="HEIGHT")
            if pdf.will_page_break(needed):
                pdf.add_page()
            color = report_design_pdf.color(self.design, color)
        y, x = pdf.get_y(), pdf.l_margin
        pdf.set_x(x if self.rtl else x + 3.5)
        pdf.set_font("Sans", "", 8.8)
        pdf.set_text_color(*self.design.ink)
        pdf.multi_cell(pdf.epw - 3.5, 4.4, str(text), new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT,
                       align=self.align[0])
        with pdf.local_context(fill_color=color):
            pdf.rect(x + pdf.epw - 1.2 if self.rtl else x, y, 1.2, max(pdf.get_y() - y, 4.4), style="F")
        self.gap(2)

    def brief(self, summary, shows, hidden):
        say = self.say
        if self.pdf.page_no() == 1 and not report_composition_pdf.active(self):
            self.pdf.add_page()
        else:
            self.gap(4)
        self.section(say("In brief"))
        self.text(summary, size=11, height=5.8)
        self.gap(1.5)
        self.text(say("What this shows"), size=9, style="B", color=OK)
        self.bullets(shows, size=8.6)
        self.gap(1)
        self.text(say("What this does not show"), size=9, style="B", color=BAD)
        self.bullets(hidden, size=8.6)
        self.gap(2)

    def assessment_overview(self, data):
        say, assessment = self.say, report.case_assessment
        self.heading(say(assessment.OVERVIEW))
        self.grid([say("Reference"), say("Evidence"), say("Status")],
                  [(f"{number:02d}", say(item["title"]), say(assessment.STATUSES[item["status"]]))
                   for number, item in enumerate(data["checks"], 1)], widths=(14, 44, 42))

    def coverage_figure(self, coverage):
        plot = report.coverage_plot(coverage)
        if not plot:
            return
        pdf, say = self.pdf, self.say
        if pdf.get_y() > pdf.h - 70:
            pdf.add_page()
        self.heading(say("Observation timeline"))
        for index, label in enumerate(("Continuous observation", "Gaps")):
            self.text(say(label), size=7.5, color=MUTED)
            y = pdf.get_y()
            with pdf.local_context(fill_color=FILL):
                pdf.rect(pdf.l_margin, y, pdf.epw, 4, style="F")
            with pdf.local_context(fill_color=INK if index == 0 else GOLD):
                for x, width in plot["rows"][index]:
                    pdf.rect(pdf.l_margin + x * pdf.epw, y, width * pdf.epw, 4, style="F")
            pdf.set_y(y + 6)
        self.text(report.utc_text(plot["from"]) + "  —  " + report.utc_text(plot["to"]), size=7, color=MUTED, align="L")
        self.text(say("Recorded intervals only. Blank space is not proof of uninterrupted collection."), size=7.5, color=MUTED)
        self.gap(3)

    def assessment_card(self, number, item):
        pdf, say, assessment = self.pdf, self.say, report.case_assessment
        if pdf.get_y() > 145:
            pdf.add_page()
        pdf.start_section(f"{number:02d}" + " · " + say(item["title"]), level=2)
        self.gap(3)
        with pdf.local_context(draw_color=GOLD, line_width=0.6):
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 14, pdf.get_y())
        self.gap(3)
        self.text(f"{number:02d}" + "   /   " + say(item["title"]), size=13, style="B", height=6)
        self.text(say(assessment.STATUSES[item["status"]]), size=8, color=OK if item["status"] == "checked_locally" else MUTED)
        self.gap(3)
        conclusion = item["result"]
        self.text(say(conclusion["text"], **conclusion["values"]), size=10.5, style="B", height=5.2)
        self.gap(2)
        self.text(say(item["basis"]), size=8.5, color=MUTED)
        self.gap(2)
        self.kv([(say(assessment.LABELS.get(k, k)), assessment.fact_text(v, say)) for k, v in item["facts"].items()])
        self.text(say("Limits of this conclusion").upper(), size=7, style="B", color=MUTED)
        self.text(say(item["limitation"]), size=8.5)
        self.gap(2)
        self.text(say("Independent review").upper(), size=7, style="B", color=MUTED)
        self.callout(say(item["verification"]), GOLD)
        if item["references"]:
            self.text(say("Evidence references") + ': ' + ', '.join(item["references"]), size=7.3, color=MUTED)
        self.gap(5)

    def qr(self, lines, size=27):
        pdf = self.pdf
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        y, x = pdf.get_y(), pdf.l_margin
        draw_qr(pdf, qr_matrix("\n".join(lines)), x + pdf.epw - size if self.rtl else x, y, size)
        pdf.set_xy(x if self.rtl else x + size + 4, y + 1)
        pdf.set_font("Mono", "", 7.4)
        pdf.set_text_color(*INK)
        pdf.multi_cell(pdf.epw - size - 4, 3.9, "\n".join(lines), new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT,
                       align="L")
        pdf.set_y(max(pdf.get_y(), y + size) + 3)

    def blank(self, label, width=None):
        pdf = self.pdf
        pdf.set_font("Sans", "", 8.8)
        pdf.set_text_color(*MUTED)
        pdf.cell(pdf.get_string_width(label) + 3, 9, label)
        pdf.cell(width or (pdf.l_margin + pdf.epw - pdf.get_x()), 9, "", border="B", new_x=self.XPos.LMARGIN,
                 new_y=self.YPos.NEXT)
        pdf.ln(1.5)

    def command(self, text):
        pdf = self.pdf
        pdf.set_font("Mono", "", 7.6)
        pdf.set_text_color(*INK)
        with pdf.local_context(fill_color=FILL):
            pdf.multi_cell(0, 4, text, fill=True, border=0, padding=1.5, new_x=self.XPos.LMARGIN,
                           new_y=self.YPos.NEXT, align="L")
        self.gap(1.5)

    def diff(self, old, new):
        pdf, height = self.pdf, 4.6
        a, b = re.findall(r"\s+|\S+", old), re.findall(r"\s+|\S+", new)
        if report_composition_pdf.active(self) and len(a) * len(b) > 250000:
            say = self.say
            self.text(say("Inline comparison omitted for size. The complete before and after texts are shown above."),
                      size=8, color=MUTED)
            return
        pdf.set_x(pdf.l_margin)
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if op == "equal":
                pdf.set_font("Sans", "", 9)
                pdf.set_text_color(*INK)
                pdf.write(height, "".join(a[i1:i2]))
            if op in ("delete", "replace"):
                pdf.set_font("Sans", "S", 9)
                pdf.set_text_color(*BAD)
                pdf.write(height, "".join(a[i1:i2]))
            if op in ("insert", "replace"):
                pdf.set_font("Sans", "U", 9)
                pdf.set_text_color(*OK)
                pdf.write(height, "".join(b[j1:j2]))
        pdf.set_font("Sans", "", 9)
        pdf.set_text_color(*INK)
        pdf.ln(height + 1)


class Mono(str):
    pass


def message_time_line(say, item, legacy=None):
    times = report.message_times(item)
    parts = [say(label) + ": " + report.utc_text(times[key]) for key, label in
             (("sent_at", "Sent"), ("edited_at", "Edited"))
             if times[key]]
    if not parts and not any(key in item for key in ("sent_at", "edited_at")) and isinstance(legacy, str) and legacy:
        parts.append(say("Telegram time") + ": " + report.utc_text(legacy))
    return " · ".join(parts)


def details_lines(say, d, *, include_media=True):
    if not isinstance(d, dict):
        return []
    lines = []
    reply = d.get("reply_to_message_id")
    if type(reply) is int:
        lines.append(say("Reply to") + ": #" + str(reply))
    if type(d.get("reply_to_top_id")) is int:
        lines.append(say("Reply thread") + ": #" + str(d["reply_to_top_id"]))
    if type(d.get("reply_to_peer_id")) is int or isinstance(d.get("reply_to_peer_id"), str):
        lines.append(say("Chat of the original message") + ": " + str(d["reply_to_peer_id"]))
    if type(d.get("forum_topic")) is bool:
        lines.append(say("Forum topic") + ": " + say("Yes" if d["forum_topic"] else "No"))
    if isinstance(d.get("quote_text"), str) and d["quote_text"]:
        lines.append(say("Quoted text") + ": “" + d["quote_text"] + "”")
        if type(d.get("quote_offset")) is int:
            lines.append(say("Quote offset (UTF-16)") + ": " + str(d["quote_offset"]))
        lines.extend(details_lines(say, {"text_entities": d.get("quote_entities") or []}, include_media=False))
    forward = d.get("forwarded_from")
    if isinstance(forward, dict) and forward:
        who = forward.get("from_name") or (say("ID {id}", id=forward["from_id"]) if forward.get("from_id") is not None
                                           else say("a hidden sender"))
        if forward.get("from_name") and forward.get("from_id") is not None:
            who += " · " + say("ID {id}", id=forward["from_id"])
        lines.append(say("Forwarded from {name}", name=who) + (" · " + forward["post_author"] if forward.get("post_author")
                                                                 else "")
                     + (" · " + say("originally sent") + " " + report.utc_text(forward["date"]) if forward.get("date") else ""))
        if type(forward.get("channel_post")) is int:
            lines.append(say("Original message") + ": #" + str(forward["channel_post"]))
        if forward.get("saved_from_id") is not None:
            lines.append(say("Saved from chat") + ": " + str(forward["saved_from_id"]))
        if type(forward.get("saved_from_message_id")) is int:
            lines.append(say("Saved from message") + ": #" + str(forward["saved_from_message_id"]))
        if forward.get("imported") is True:
            lines.append(say("Imported message"))
    for x in d.get("text_entities") or []:
        if not isinstance(x, dict):
            continue
        if x.get("href") or x.get("user_id") is not None:
            lines.append(say("Links behind the text") + ": “" + str(x.get("text")) + "” → "
                         + (x["href"] if x.get("href") else say("user ID {id}", id=x.get("user_id")))
                         + ("   ⚠ " + say("the text shows a different address") if x.get("deceptive") else ""))
        elif x.get("type") in report.message_details.POINTING and isinstance(x.get("text"), str) and x["text"]:
            lines.append(say("Observed links and entities") + ": " + str(x["type"]) + " · “" + x["text"] + "”")
    buttons = d.get("buttons")
    if buttons and buttons.get("rows"):
        target = lambda b: b.get("url") or b.get("copy_text") or b.get("query")
        lines.append(say("Buttons") + ": " + " | ".join(str(b.get("text")) + (" → " + str(target(b)) if target(b) else "")
                                                         for row in buttons["rows"] for b in row))
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
        facts.append(say("reactions: {list}", list=report.reactions_text(d["reactions"])))
    if type(d.get("auto_delete_seconds")) is int:
        facts.append(say("auto-delete timer: {time}", time=report.seconds_text(say, d["auto_delete_seconds"])))
    if d.get("protected"):
        facts.append(say("saving and forwarding restricted"))
    if type(d.get("album_id")) is int:
        facts.append(say("Album ID") + ": " + str(d["album_id"]))
    if facts:
        lines.append(" · ".join(facts))
    media = d.get("media_info")
    if include_media and isinstance(media, dict) and media:
        description = report.media_text(say, media)
        lines.append(say(report.MEDIA_NAMES.get(media.get("kind"), "Media"))
                     + (" · " + description if description else ""))
        if isinstance(media.get("title"), str) and media["title"]:
            lines.append(say("Link preview") + ": " + media["title"]
                         + (" · " + media["site_name"] if isinstance(media.get("site_name"), str) else ""))
        for field in ("document_id", "photo_id"):
            if type(media.get(field)) is int:
                lines.append(say("Media ID") + ": " + str(media[field]))
        if type(media.get("self_destruct_seconds")) is int and not media.get("ephemeral_media"):
            lines.append(say("Self-destruct timer") + ": " + report.seconds_text(say, media["self_destruct_seconds"]))
    return lines


def changes(lay, say, changed, titles):
    for item in changed["messages"]:
        versions, gone = item.get("versions") or [], item.get("gone") or []
        first = versions[0] if versions else {}
        sender = first.get("sender") or {}
        who = " · ".join(str(x) for x in (sender.get("display_name"), "@" + sender["username"] if sender.get("username")
                                           else "", "id " + str(first.get("sender_id")) if first.get("sender_id") is not None
                                           else "") if x)
        lay.heading((titles.get(str(item["chat_id"])) or say("Chat {id}", id=item["chat_id"])) + " · "
                    + say("message {id}", id=item["message_id"]) + ("   " + who if who else ""))
        previous = None
        for number, version in enumerate(versions):
            label = (say("Original") if version["kind"] != "message.edited" else say("First saved version")) if not number \
                else say("Edit {n}", n=number) if version["kind"] == "message.edited" else say("Saved version {n}", n=number + 1)
            times = message_time_line(say, version, version.get("telegram_at"))
            lay.text(label + " · " + say("observed") + " " + report.utc_text(version["observed_at"])
                     + (" · " + times if times else "") + " · #" + str(version["seq"]), size=7.8, color=MUTED)
            if version.get("context_only"):
                lay.text(say("Context outside the report filters"), size=8, color=MUTED)
            if version.get("withheld"):
                lay.text(say("Text withheld in this extract"), size=9, color=MUTED)
            elif previous is None or previous["text"] == version["text"]:
                if previous is None and version["kind"] == "message.edited":
                    lay.text(say("The earlier version was not captured."), size=8, color=MUTED)
                lay.text(version["text"] or say("(no text)") if previous is None else say("Text unchanged"), size=9)
            else:
                if report_composition_pdf.active(lay):
                    report_composition_pdf.comparison(lay, previous["text"], version["text"])
                else:
                    lay.text(say("Before"), size=8, style="B")
                    lay.text(previous["text"] or say("(no text)"), size=9)
                    lay.text(say("After"), size=8, style="B")
                    lay.text(version["text"] or say("(no text)"), size=9)
                if not report_composition_pdf.active(lay) or lay.design.name == "ledger_margin":
                    lay.text(say("Changes"), size=8, style="B")
                    lay.diff(previous["text"], version["text"])
            if previous is None or previous.get("details") != version.get("details"):
                for line in details_lines(say, version.get("details") or {}):
                    lay.text(line, size=8, color=MUTED)
            lay.gap(1.2)
            previous = version
        for step in gone:
            deleted = step["kind"] == "message.deleted"
            if step.get("context_only"):
                lay.text(say("Context outside the report filters"), size=8, color=MUTED)
            retained = report.last_saved_before(versions, step["seq"])
            lay.text(say("Saved text before deletion") if deleted else say("Saved text before recheck"), size=8, style="B")
            lay.text(retained["text"] or say("(no text)") if retained else
                     say("No message content was saved before this observation."), size=9)
            lay.text(report.kind_label(say, step["kind"]) + " · " + say("observed") + " "
                     + report.utc_text(step["observed_at"]) + " · #" + str(step["seq"]), size=7.8, style="B", color=BAD)
            lay.text(report.timer_text(say, step["kind"]) if step.get("auto_delete") else
                     say("Telegram does not say who deleted a message or exactly when; this is when the notice was "
                         "observed.") if deleted else say("Telegram no longer returned this message at a later check."),
                     size=8.5, color=BAD)
        lay.gap(2)
    if changed["messages_changed"] > changed["listed"]:
        lay.text(say("… and {n} more changed messages, listed under Records.",
                     n=changed["messages_changed"] - changed["listed"]), size=8.5, color=MUTED)


def records(lay, say, events, titles, options):
    group, run = options.get("group_heartbeats", True), None

    def flush():
        first, last, count = run
        lay.text("#" + str(first[0]) + ("–#" + str(last[0]) if count > 1 else "") + "  "
                 + (say("Collector heartbeats: {n}", n=count) if count > 1 else say("Collector heartbeat")) + " · "
                 + report.utc_text(first[1]) + (" — " + report.utc_text(last[1]) if count > 1 else ""), size=7.8, color=MUTED)
    for event in events:
        if group and event["kind"] == "collector.heartbeat":
            at = (event["seq"], event["observed_at"])
            run = [run[0], at, run[2] + 1] if run else [at, at, 1]
            continue
        if run:
            flush()
            run = None
        payload, chat = event["payload"], event["chat_id"]
        head = ("#" + str(event["seq"]) + "  " + report.kind_label(say, event["kind"]) + " · "
                + say("Observed") + ": " + report.utc_text(event["observed_at"]))
        if chat is not None:
            head += " · " + (titles.get(chat) or titles.get(str(chat)) or say("Chat {id}", id=chat)) \
                + (" · " + say("message {id}", id=event["message_id"]) if event["message_id"] is not None else "")
        report_composition_pdf.record_heading(lay, head)
        times = message_time_line(say, payload, event.get("source_at"))
        if times:
            lay.text(times, size=7.8, color=MUTED)
        sender = payload.get("sender_observation") if isinstance(payload.get("sender_observation"), dict) else {}
        sender_id = payload.get("sender_id", sender.get("id"))
        if sender.get("display_name") or sender_id is not None:
            lay.text((sender.get("display_name") or say("User {id}", id=sender_id))
                     + (" @" + sender["username"] if sender.get("username") else "")
                     + (" · id " + str(sender_id) if sender_id is not None else ""), size=8)
        if isinstance(payload.get("text"), str) and payload["text"]:
            report_composition_pdf.message_text(lay, payload["text"])
        if payload.get("text_withheld"):
            lay.text(say("Text withheld in this extract"), size=8, color=MUTED)
        if report.CATEGORIES.get(event["kind"]) in ("message", "edited"):
            for line in details_lines(say, report.shown_details(payload)):
                lay.text(line, size=7.8, color=MUTED)
        if event.get("minimised"):
            lay.text(say("Minimised") + ": " + ", ".join(say(report.WITHHELD.get(x, x)) for x in event["minimised"]),
                     size=8, color=WARN)
        if event["kind"] == "media.saved" and isinstance(payload.get("media_sha256"), str):
            lay.text((payload.get("original_name") or say("Saved file")) + " · " + str(payload.get("mime_type") or "—")
                     + " · " + report.size_text(payload.get("size")), size=8)
            lay.text(say("File SHA-256") + ": " + payload["media_sha256"], size=6.8, color=MUTED, family="Mono")
        if event["kind"].startswith("media.") and payload.get("ephemeral_media"):
            from . import ephemeral
            lay.text(ephemeral.label(say, payload["ephemeral_media"]), size=7.8, color=MUTED)
        lay.text(say("Record hash") + " · SHA-256 " + event["hash"], size=6.8, color=MUTED, family="Mono")
        lay.gap(1)
    if run:
        flush()


def custody_steps(say, data):
    acquisition, latest = data["custody"]["acquisition"], data["custody"].get("latest_timestamped_record")
    steps = [(say("Observed and recorded"), report.utc_text(acquisition.get("first_record_at")) + " — "
              + report.utc_text(acquisition.get("last_record_at"))),
             (say("Each record hashed and signed at capture"), say("Records: {n}", n=acquisition.get("record_count")))]
    if data.get("minimisation"):
        counts = data["minimisation"]["counts"]
        steps.append((say("Extract prepared and minimised"), say("{a} shown unchanged, {b} minimised, {c} left out",
                                                                 a=counts["unchanged"], b=counts["minimised"],
                                                                 c=counts["left_out"])))
    else:
        steps.append((say("Checkpoints timestamped"), report.utc_text(latest["time"]) + " · " + latest["service"]
                      if latest else say("none in this export")))
    steps += [(say("Journal verified and exported"), report.utc_text(data["created_at"])),
              (say("Report sealed"), report.utc_text(data["created_at"]) + " · " + (data["case"].get("examiner") or ""))]
    return steps


def transfers(lay, say):
    lay.heading(say("Custody transfers"))
    lay.text(say("Fill in by hand when the printed report or the archive changes hands."), size=8.5, color=MUTED)
    with lay.pdf.table(line_height=8, borders_layout="ALL", text_align=lay.align, padding=1.4,
                       headings_style=lay.FontFace(emphasis="BOLD", size_pt=8, fill_color=FILL)) as table:
        head = table.row()
        for column in lay.mirror((say("Date and time"), say("Released by"), say("Received by"), say("Purpose"),
                                  say("Signature"))):
            head.cell(column)
        for _ in range(4):
            row = table.row()
            for _ in range(5):
                row.cell(" ")
    lay.gap(2)


def qr_matrix(text):
    import qrcode
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2)
    code.add_data(text)
    code.make(fit=True)
    return code.get_matrix()


def draw_qr(pdf, matrix, x, y, size):
    step = size / len(matrix)
    with pdf.local_context(fill_color=(0, 0, 0)):
        for row, line in enumerate(matrix):
            column = 0
            while column < len(line):
                if not line[column]:
                    column += 1
                    continue
                start = column
                while column < len(line) and line[column]:
                    column += 1
                pdf.rect(x + start * step, y + row * step, (column - start) * step, step, style="F")


def paper_lines(report_id, fp, data_name, data_sha256):
    return ["TgWitness report " + report_id, "Key SHA-256 " + fp,
            *([data_name + " SHA-256 " + data_sha256] if data_sha256 else [])]


def declaration(lay, say, case):
    lay.section(say("Examiner's declaration"), say("Completed and signed by hand by the person who collected and "
                                                   "exported this material."))
    lay.text(say("I, {name}, of {organization}, declare that I collected the material described in this report with the "
                 "tool, account and method stated in it, at the times stated in it; that I did not alter the records; and "
                 "that this report and the archive it describes are those I produced. I understand that this declaration "
                 "may be relied on in proceedings.", name=case.get("examiner") or "______________________",
                 organization=case.get("organization") or "______________________"), size=9.2)
    lay.gap(3)
    lay.blank(say("SHA-256 of the archive as handed over:"))
    lay.blank(say("Place and date:"))
    lay.blank(say("Signature:"))
    lay.section(say("For a notary or court expert"), say("Steps that let an inspection record stand on its own. Local "
                                                         "rules decide the form of the record; this list is not legal advice."))
    lay.bullets([say("Receive the archive and the key fingerprint by separate channels and write both in the record."),
                 say("Compute the archive's SHA-256 (sha256sum, or Get-FileHash on Windows) and write it in the record."),
                 say("Run verify.py with the fingerprint on a computer you trust and attach its complete output."),
                 say("Open the reports from the verified archive and check that their report ID is the one on this page."),
                 say("Name the messages relied on by chat, message number and time, as this report lists them.")])


def signatures_section(lay, say, certificate, fp, name):
    lay.section(say("Signatures of this PDF"), say(
        "This PDF is signed twice over the same bytes: with a standard PDF signature that PDF readers show, and with "
        "the Ed25519 seal of the key below. Any change to the file breaks both."))
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    lay.kv([(say("PDF signature"), "adbe.pkcs7.detached · ECDSA P-256 · SHA-256"),
            (say("Certificate"), (names[0].value if names else certificate.subject.rfc4514_string())
             + " · " + say("self-issued")),
            (say("Certificate valid"), report.utc_text(certificate.not_valid_before_utc.isoformat()) + " — "
             + report.utc_text(certificate.not_valid_after_utc.isoformat())),
            (say("Certificate SHA-256"), Mono(hashlib.sha256(cert_der).hexdigest())),
            (say("Ed25519 key fingerprint (SHA-256)"), Mono(report.grouped(fp))),
            (say("Seal"), say("Inside the PDF signature; it names the certificate's SHA-256, so the Ed25519 key vouches "
                              "for the certificate."))])
    lay.text(say("A PDF reader confirms that the document has not changed since it was signed. It shows the signer as "
                 "unknown until the reader trusts this certificate: compare the Ed25519 fingerprint with a copy kept "
                 "apart from the collector instead."), size=8.8)
    lay.gap(1)
    lay.command("python verify.py " + name + " --fingerprint " + fp)
    if lay.pdf.missing:
        lay.callout(say("Some characters of the recorded texts have no font on this server and are not shown in this "
                        "PDF. The HTML and JSON reports and the journal carry the exact text."), WARN)


class EvidencePDF:
    def __init__(self, data, context, events, certificate):
        self.data = data
        self.context = context
        self.events = events
        self.certificate = certificate

    def render(self):
        self.options = {**report.ReportOptions().model_dump(), "language": "en", **(self.context.get("options") or {})}
        self.say = report.Words(self.options["language"])
        say = self.say
        self.handover, self.case = self.data.get("minimisation"), self.data["case"]
        self.filtered = bool((self.data.get("selection") or {}).get("selection", {}).get("enabled"))
        self.report_id, self.fp = self.data["report_id"], self.data["subject"].get("fingerprint") or ""
        footer = " · ".join(x for x in ((say("Case ID") + " " + self.case["id"]) if self.case.get("id") else "",
                                        say("Report ID") + " " + self.report_id[:8]) if x)
        pdf = document(say, footer, self.options.get("design", "classic"))
        found = MissingGlyphs(pdf.missing)
        logging.getLogger("fpdf").addHandler(found)
        logging.getLogger("fontTools.subset").setLevel(logging.ERROR)
        try:
            self.lay = Layout(pdf, say)
            label = say("Handover extract") if self.handover else say("Evidence report")
            title = self.case.get("title") or (say("Handover extract") if self.handover else say("Telegram observation journal"))
            pdf.set_title(title)
            pdf.set_author(self.case.get("examiner") or self.case.get("organization") or "TgWitness")
            pdf.set_subject(label + " · " + self.report_id)
            cats, summary, self.coverage = self.data["summary"]["categories"], self.data["summary"], self.data.get("coverage") or {}
            self.lay.title_block(label + " · " + say("Signed"), title, [
                (say("Case ID"), self.case.get("id")), (say("Examiner"), self.case.get("examiner")),
                (say("Organization"), self.case.get("organization")), (say("Created"), report.utc_text(self.data["created_at"])),
                (say("Report ID"), self.report_id)],
                say("Signed PDF: a PDF signature that PDF readers show, and the Ed25519 seal of key {fp}. Check both with "
                    "verify.py; the last section explains how.", fp=report.grouped(self.fp)))
            self.records_total = (self.handover["counts"]["unchanged"] + self.handover["counts"]["minimised"]) if self.handover \
                else self.data["subject"].get("event_count")
            if self.data.get("selection"):
                self.records_total = self.data["selection"]["counts"]["selected_records"]
            self.directory_index = None
            if report_composition_pdf.active(self.lay):
                self.events, self.directory_index = report_composition_pdf.indexed_events(self.events, self.records_total or 0)
            self.lay.figures([(say("Records"), self.records_total), (say("Chats"), summary["chats"]), (say("Messages"), cats["message"]),
                         (say("Edits"), cats["edited"]), (say("Deletions"), cats["deleted"]),
                         *([(say("Missing on recheck"), cats["missing"])] if cats.get("missing") else []),
                         (say("Files"), summary["files"]),
                         (say("Timestamps"), summary["timestamps"]),
                         (say("Observation period"), report.span_text(say, summary["first_record_at"], summary["last_record_at"]))])
            data_name = "records.jsonl" if self.handover else "events.jsonl"
            self.lay.gap(5)
            self.lay.qr(paper_lines(self.report_id, self.fp, data_name, self.data["subject"].get("records_sha256" if self.handover else "events_sha256")))
            self.acquisition = self.data["custody"]["acquisition"]
            self.account = self.acquisition.get("account") or {}
            self.account_text = " · ".join(x for x in (("@" + self.account["username"]) if self.account.get("username") else "",
                                                  ("id " + str(self.account["id"])) if self.account.get("id") else "") if x)
            self.digest = {"categories": cats, "chats": [None] * summary["chats"], "media": [None] * summary["files"],
                      "first": summary["first_record_at"], "last": summary["last_record_at"]}
            self.titles = {str(c["chat_id"]): c["title"] for c in self.data["chats"] if c.get("title")}

            self.actions = self.data["actions"]

            callbacks = {
                "brief": self.render_brief,
                "selection": self.render_selection,
                "assessment": self.render_assessment,
                "case": self.render_case,
                "minimisation": self.render_minimisation,
                "histories": self.render_histories,
                "indicators": self.render_indicators,
                "actions": self.render_actions,
                "integrity": self.render_integrity,
                "timestamps": self.render_timestamps,
                "coverage": self.render_coverage,
                "custody": self.render_custody,
                "verify": self.render_verify,
                "files": self.render_files,
                "standards": self.render_standards,
                "limitations": self.render_limitations,
                "journal": self.render_journal,
                "examination": self.render_examination,
                "case_board": self.render_case_board,
                "analytics": self.render_analytics,
                "directory": self.render_directory,
                "relations": self.render_relations,
            }
            default_order = ['brief', 'selection', 'examination', 'analytics', 'assessment', 'case', 'minimisation', 'case_board', 'histories', 'indicators', 'actions', 'integrity', 'timestamps', 'coverage', 'custody', 'verify', 'files', 'standards', 'limitations', 'journal']
            if self.options.get("template") == "activity":
                default_order[2:4] = ["analytics", "examination"]
            visible = {
                "selection": bool(self.data.get("selection")), "minimisation": bool(self.handover),
                "case_board": bool((self.data.get("case_board") or {}).get("cards")),
                "examination": bool(self.data.get("examination")),
                "analytics": bool(self.data.get("analytics") or self.data.get("processors")),
                "histories": bool(self.options.get("show_changes", True) and self.data["changes"]["messages"]),
                "indicators": bool(self.options.get("show_indicators", True) and (self.data.get("indicators") or {}).get("items")),
                "actions": not self.filtered or bool(self.actions["listed"]), "timestamps": not self.handover,
                "files": bool(self.data.get("files")),
                "journal": bool(self.options.get("timeline") and self.records_total),
                "directory": bool(self.data.get("chats") or (self.directory_index or {}).get("senders")),
                "relations": bool((self.directory_index or {}).get("relations")),
            }
            report_composition_pdf.render(self.lay, callbacks, default_order, 'journal', visible)
            declaration(self.lay, say, self.case)
            self.lay.qr(paper_lines(self.report_id, self.fp, data_name, self.data["subject"].get("records_sha256" if self.handover else "events_sha256")))
            if self.certificate is not None:
                signatures_section(self.lay, say, self.certificate, self.fp, "report.pdf")
            return add_signature_field(pdf, say)
        finally:
            logging.getLogger("fpdf").removeHandler(found)

    def render_brief(self):
        say = self.say
        self.lay.brief(*report.evidence_brief(say, self.digest, self.records_total, self.data["timestamps"], self.coverage, self.account_text,
                                         self.handover, self.filtered))

    def render_selection(self):
        report.report_selection_view.pdf(self.lay, self.data.get("selection"))

    def render_assessment(self):
        report.case_assessment.pdf(self.lay, self.data.get("case_assessment") or report.case_assessment.journal(self.context, self.coverage))

    def render_case(self):
        say = self.say
        self.lay.section(say("Case"))
        self.lay.kv([(say("Case title"), self.case.get("title")), (say("Case ID"), self.case.get("id")),
                (say("Examiner"), self.case.get("examiner")), (say("Organization"), self.case.get("organization")),
                (say("Observing account"), " · ".join(x for x in (("@" + self.account["username"]) if self.account.get("username")
                                                                  else "", ("id " + str(self.account["id"])) if self.account.get("id")
                                                                  else "") if x)),
                (say("Report language"), self.data["language"]), (say("Report ID"), Mono(self.report_id)),
                (say("Created"), report.utc_text(self.data["created_at"])),
                (say("Produced by"), "TgWitness " + str((self.data.get("producer") or {}).get("version")) + " · "
                 + str((self.data.get("producer") or {}).get("project")))])
        if self.case.get("notes"):
            self.lay.heading(say("Notes"))
            self.lay.text(self.case["notes"], size=9)

    def render_minimisation(self):
        say = self.say
        if self.handover:
            self.lay.section(say("Minimisation"))
            counts, selection = self.handover["counts"], self.handover["selection"]
            self.lay.kv([(say("Purpose"), self.handover["purpose"]),
                    (say("Shown unchanged, verified in full"), counts["unchanged"]),
                    (say("Minimised, signature verified"), counts["minimised"]), (say("Left out"), counts["left_out"])])
            if isinstance(selection, dict):
                self.lay.kv([(str(k), ", ".join(map(str, v)) if isinstance(v, list) else str(v)) for k, v in selection.items()])

    def render_histories(self):
        say = self.say
        if self.options.get("show_changes", True) and self.data["changes"]["messages"]:
            self.lay.section(say("Selected message histories") if self.filtered else say("Changed and deleted messages"),
                        say("Selected changes with saved message history. Versions outside the filters are marked as context.")
                        if self.filtered else say(
                "Every saved version of each message that was edited, deleted or not found at a later check. Removed "
                "words are struck through and added words are marked; each step names its signed record."))
            changes(self.lay, say, self.data["changes"], self.titles)

    def render_indicators(self):
        say = self.say
        if self.options.get("show_indicators", True) and (self.data.get("indicators") or {}).get("items"):
            indicators_section(self.lay, say, self.data["indicators"])

    def render_actions(self):
        say = self.say
        if not self.filtered:
            self.lay.section(say("Actions by the observing account"), say(
            "Actions taken with the observing account change what others in the chat see. They are listed here so "
            "that the records around them can be read with that in mind."))
        if self.actions["listed"]:
            rows = []
            for action in self.actions["listed"]:
                request, result = action.get("request") or {}, action.get("result") or {}
                kind = request.get("action")
                detail = (action.get("preview") or {}).get("title") or "" if kind == "open" else \
                    request.get("text") or "" if kind == "send" else (action.get("button") or {}).get("text") or ""
                if kind == "open" and (action.get("preview") or {}).get("link"):
                    detail += " " + action["preview"]["link"]
                if result.get("answer"):
                    detail += " · " + say("bot answered: {answer}", answer=result["answer"])
                rows.append([report.utc_text(action["at"]), say(report.ACTION_NAMES.get(kind, "Action")),
                             self.titles.get(str(result.get("chat") or action.get("chat"))) or str(action.get("chat") or "—"),
                             detail, say(report.OUTCOMES.get(result.get("status"), ("", "no result recorded"))[1]),
                             "#" + str(action["seq"])])
            self.lay.grid([say("Time"), say("Action"), say("Chat"), say("Details"), say("Outcome"), say("Records")], rows,
                     (15, 17, 14, 33, 10, 11))
        elif not self.filtered:
            self.lay.callout(say("No action through the panel is recorded in this journal."), OK)

    def render_integrity(self):
        say = self.say
        self.lay.section(say("Integrity"), say("Every record is linked to the previous one by SHA-256 and signed with Ed25519 "
                                          "when it is captured. The manifest lists the SHA-256 of every file and is "
                                          "signed with the same key."))
        self.lay.kv([(say("Signing key fingerprint (SHA-256)"), Mono(report.grouped(self.fp))),
                (say("Records"), self.data["subject"].get("event_count") or self.records_total),
                (say("Head hash"), Mono(self.data["subject"].get("head_hash") or "")),
                (say("Independent timestamps"), "" if self.handover else report.stamps_text(say, self.data["timestamps"])),
                (say("Independent witness"), "" if self.handover else say(
                    "Not part of this archive. A witness that kept the journal head is checked with verify.py --witness.")),
                (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"), (say("Signature algorithm"), "Ed25519 (RFC 8032)"),
                (say("Public key"), Mono(self.data["subject"].get("public_key") or "")),
                ("events.jsonl SHA-256", Mono(self.data["subject"].get("events_sha256") or "")),
                ("records.jsonl SHA-256", Mono(self.data["subject"].get("records_sha256") or ""))])

    def render_timestamps(self):
        say = self.say
        if not self.handover:
            self.lay.section(say("Timestamps"), say(
                "A timestamp shows that a checkpoint, and every record before it, existed no later than the stamped "
                "time. Records after the latest stamped checkpoint rely on the collector's clock."))
            anchors = self.data["timestamps"]
            latest = report.latest_stamp(anchors)
            if latest:
                self.lay.callout(say("Latest independently timestamped record: #{n}", n=latest.get("event_count")) + " · "
                            + report.utc_text(latest.get("time")) + " · " + latest["service"], OK)
            else:
                self.lay.callout(say("No independent timestamps in this export: times come from the collector's clock. Turn "
                                "on Evidence mode to stamp checkpoints automatically."))
            rows = []
            for anchor in anchors:
                if anchor.get("kind") == "rfc3161":
                    signer = (anchor.get("signed") or {}).get("signer")
                    name = re.search(r"(?:^|,)CN=((?:\\,|[^,])+)", signer or "")
                    rows.append([anchor.get("event_count"), anchor.get("service"), "RFC 3161", report.utc_text(anchor.get("time")),
                                 say("Token valid") + " · " + (name.group(1).replace("\\,", ",") if name else signer)
                                 if report.case_assessment.verified_stamp(anchor, 2**63 - 1)
                                 else say("Checkpoint or timestamp trust not established")])
                elif anchor.get("kind") == "opentimestamps":
                    rows.append([anchor.get("event_count"), anchor.get("service"), "OpenTimestamps · Bitcoin", "—",
                                 say("Waiting for Bitcoin confirmation") if anchor.get("status") == "pending"
                                 else say("In Bitcoin; confirm with ots verify")])
            self.lay.grid([say("Records covered"), say("Service"), say("Type"), say("Stamped at"), say("Status")], rows,
                     (10, 26, 18, 17, 29))

    def render_coverage(self):
        say = self.say
        self.lay.section(say("Coverage"), (self.coverage or {}).get("meaning") or
                    say("Recorded observation intervals."))
        if self.coverage:
            self.lay.coverage_figure(self.coverage)
            self.lay.grid([say("Interval start"), say("Interval end"), say("Duration")],
                     [[report.utc_text(p["from"]), report.utc_text(p["to"]), report.span_text(say, p["from"], p["to"])]
                      for p in self.coverage.get("continuous") or []], (38, 38, 24))
            if self.coverage.get("gaps"):
                self.lay.heading(say("Gaps"))
                self.lay.grid([say("Interval start"), say("Interval end"), say("Reason")],
                         [[report.utc_text(g["from"]), report.utc_text(g["to"]), str(g.get("reason"))] for g in self.coverage["gaps"]],
                         (26, 26, 48))
            if self.coverage.get("unobserved_ids"):
                self.lay.heading(say("Message IDs per chat"))
                self.lay.grid([say("Chat"), say("Observed range"), say("Observed"), say("Not observed"), say("Numbers not observed")],
                         [[c.get("title") or c["chat_id"], str(c["observed_from"]) + " – " + str(c["observed_to"]),
                           c["observed"], c["not_observed"], ranges_line(c.get("ranges") or [], c.get("ranges_total", 0))]
                          for c in self.coverage["unobserved_ids"]], (26, 18, 12, 12, 32))
            view = report.gap_overview(say, self.coverage.get("gap_summary"))
            if view is not None:
                self.lay.heading(say("Missing message numbers"))
                self.lay.text(view["lead"], size=8, color=MUTED)
                if view["measured"]:
                    widths = (28, 18, 11, 11, 10, 11, 11) if len(view["headers"]) == 7 else (30, 20, 12, 12, 12, 14)
                    self.lay.grid(view["headers"], [[str(value) for value in row] for row in view["measured"]], widths)
                if view["listed"]:
                    self.lay.heading(say("Listed gaps"))
                    self.lay.grid(view["listed_headers"], [
                        [name, numbers, str(count), str(after), report.utc_text(after_at), str(before),
                         report.utc_text(before_at)]
                        for name, numbers, count, after, after_at, before, before_at in view["listed"]],
                        (20, 16, 8, 11, 17, 11, 17))
                if view["skipped"]:
                    self.lay.grid(view["skipped_headers"], view["skipped"], (30, 70))
                self.lay.text(view["note"], size=7.5, color=MUTED)
            self.lay.heading(say("Verifier summary"))
            for line in coverage_lines(self.coverage):
                self.lay.text(line, size=7.2, family="Mono")

    def render_custody(self):
        say = self.say
        self.lay.section(say("Chain of custody"), say("How this material was acquired, preserved and handed over. "
                                                 "custody.json carries the same record for case-management systems."))
        for step, detail in custody_steps(say, self.data):
            self.lay.text(step, size=9, style="B")
            self.lay.text(detail, size=8.5, color=MUTED)
            self.lay.gap(0.8)
        self.lay.kv([(say("Acquisition tool"), "TgWitness " + str((self.data.get("producer") or {}).get("version"))),
                (say("Program build"), Mono(report.build_text(say, self.data.get("producer") or {}))),
                (say("Acquisition method"), say("Telegram client observing the account; records chained by SHA-256 and "
                                                "signed with Ed25519 as they are written.")),
                (say("Telegram client"), "; ".join(report.client_text(say, c["client"])
                                                    for c in self.acquisition.get("clients") or []) or say("Not recorded in this journal")),
                (say("Connection route"), "; ".join(report.route_text(say, r["route"])
                                                     for r in self.acquisition.get("routes") or []) or say("Not recorded in this journal")),
                (say("Direct connections while no proxy answered: {n}", n=(self.acquisition.get("direct_fallbacks") or {}).get("count")),
                 say("Telegram saw this server's address at those times.")) if (self.acquisition.get("direct_fallbacks") or {}).get("count")
                else ("", ""),
                (say("Collector clock against Telegram"), clocks_lines(say, self.acquisition.get("clock_checks"),
                                                                       "Not recorded in this journal")),
                (say("Time standard"), "UTC · ISO 8601")])
        transfers(self.lay, say)

    def render_verify(self):
        say = self.say
        archive = "tgwitness-handover.zip" if self.handover else "tgwitness-evidence.zip"
        self.lay.section(say("Verify"), say("Get the signer's key fingerprint from a trusted channel, not from this archive."))
        self.lay.command("python verify.py " + archive + " --fingerprint " + self.fp)
        self.lay.command("python verify.py report.pdf --fingerprint " + self.fp + " --evidence " + archive)

    def render_files(self):
        say = self.say
        files = self.data.get("files") or {}
        if files:
            self.lay.section(say("Files in this archive"), say("manifest.json lists the SHA-256 of every file and is signed in "
                                                          "manifest.sig."))
            names = sorted(files)
            self.lay.grid([say("File"), say("Purpose"), "SHA-256"],
                     [[Mono(n), report.file_purpose(say, n), Mono(files[n])] for n in names[:300]], (26, 30, 44))

    def render_standards(self):
        say = self.say
        self.lay.section(say("Standards and methodology"), say("This export follows these practices. Alignment, not certification."))
        self.lay.grid([say("Reference"), say("How it is applied")],
                 [[s["reference"] + " — " + s["title"], s["how"]] for s in self.data["custody"].get("standards") or []], (34, 66))

    def render_limitations(self):
        say = self.say
        self.lay.section(say("Reading this record"), say("What the records state and what binds them."))
        self.lay.bullets([say(x) for x in self.data.get("limitations") or []])

    def render_journal(self):
        say = self.say
        parts, limit = self.data.get("parts") or [], self.options.get("part_size") or report.ReportOptions().part_size
        if self.options.get("timeline") and parts:
            self.lay.section(say("Records"), say("{n} records in {m} parts. Each part is a page of its own with its own seal; "
                                            "manifest.json lists its SHA-256.", n=self.records_total, m=len(parts)))
            self.lay.grid([say("Part"), say("Records"), say("Count"), say("Period"), "SHA-256"],
                     [[say("Part {n} of {m}", n=p["index"], m=len(parts)) + "\n" + p["file"], "#" + str(p["from"]) + " – #"
                       + str(p["to"]), p["count"], report.utc_text(p["first_at"]) + " — " + report.utc_text(p["last_at"]),
                       Mono(p.get("sha256") or "")] for p in parts], (22, 16, 8, 26, 28))
        elif self.options.get("timeline") and self.events is not None and self.records_total and self.records_total <= limit:
            self.lay.section(say("Records"), say("Records matching the report filters, in journal order.") if self.filtered else
                        say("Every record of the journal in order. Filters only change what is shown.")
                        if not self.handover else say("Every record in this extract, in journal order. Minimised records name "
                                                 "what was withheld."))
            records(self.lay, say, self.events, {**self.titles, **{int(k): v for k, v in self.titles.items() if k.lstrip("-").isdigit()}},
                    self.options)
        elif self.options.get("timeline") and self.records_total:
            self.lay.section(say("Records"))
            self.lay.callout(say("This journal has {n} records, exceeding the PDF transcript limit of {limit}. "
                            "Every record remains in the signed source files and the HTML viewer.",
                            n=self.records_total, limit=limit), WARN)

    def render_examination(self):
        report.report_charts.examination_pdf(self.lay, self.data.get("examination"))

    def render_case_board(self):
        if self.data.get("case_board"):
            from . import board_report
            board_report.pdf(self.lay, self.data["case_board"])

    def render_analytics(self):
        report.report_charts.pdf(self.lay, self.data.get("analytics"))
        report.report_charts.metrics_pdf(self.lay, self.data.get("processors"))

    def render_directory(self):
        report_composition_pdf.directory(self.lay, self.data, self.directory_index)

    def render_relations(self):
        report_composition_pdf.relations(self.lay, self.directory_index)


def evidence_pdf(data, context, events=None, certificate=None):
    return EvidencePDF(render_data.detached(data), render_data.context(context),
                      render_data.records(events), certificate).render()


def indicators_section(lay, say, found, shown=300):
    lay.section(say("Indicators"), report.ioc_lead(say))
    rows = []
    for kind, value, count, where, first, item in report.ioc_rows(say, found):
        if len(rows) >= shown:
            break
        rows.append([kind, Mono(value), count, where, " ".join(report.ref_label(r) for r in item["refs"][:6])
                     + (" …" if count > 6 else ""), report.utc_text(first)])
    lay.grid([say("Type"), say("Value"), say("Seen"), say("Where in the message"), say("Messages"), say("First seen")],
             rows, (16, 30, 7, 13, 16, 18))
    more = found["total"] - len(rows) + found.get("not_listed", 0)
    if more > 0:
        lay.text(say("… and {n} more in indicators.csv.", n=more), size=8.5, color=MUTED)


def ranges_line(ranges, total, limit=8):
    pairs = [(r["low"], r["high"]) if isinstance(r, dict) else tuple(r) for r in ranges[:limit]]
    shown = [str(low) if low == high else str(low) + "–" + str(high) for low, high in pairs]
    more = max(total, len(ranges)) - len(shown)
    return (", ".join(shown) + (" … +" + str(more) if more > 0 else "")) if shown else "—"


class ChatPDF:
    def __init__(self, meta, context, messages, certificate):
        self.meta = meta
        self.context = context
        self.messages = messages
        self.certificate = certificate

    def render(self):
        self.options = {**report.ReportOptions().model_dump(), "language": "en", **(self.context.get("options") or {})}
        self.say = report.Words(self.options["language"])
        say = self.say
        self.chat, self.stats, self.people = self.meta.get("chat") or {}, self.context["stats"], self.context["people"]
        self.ids, self.parts, self.fp = self.context.get("message_ids") or {}, self.context.get("parts") or [], self.context["fingerprint"]
        self.case, self.report_id = report.case_of(self.options), self.context["report_id"]
        self.chat_title = self.chat.get("title") or say("Chat {id}", id=self.chat.get("id"))
        footer = " · ".join(x for x in ((say("Case ID") + " " + self.case["id"]) if self.case.get("id") else "",
                                        say("Report ID") + " " + self.report_id[:8]) if x)
        pdf = document(say, footer, self.options.get("design", "classic"))
        found = MissingGlyphs(pdf.missing)
        logging.getLogger("fpdf").addHandler(found)
        logging.getLogger("fontTools.subset").setLevel(logging.ERROR)
        try:
            self.lay = Layout(pdf, say)
            title = self.case.get("title") or self.chat_title
            pdf.set_title(title)
            pdf.set_author(self.case.get("examiner") or self.case.get("organization") or "TgWitness")
            pdf.set_subject(say("Chat export") + " · " + self.report_id)
            self.lay.title_block(say("Chat export") + " · " + say("Signed"), title, [
                (say("Chat"), self.chat_title), (say("Case ID"), self.case.get("id")), (say("Examiner"), self.case.get("examiner")),
                (say("Organization"), self.case.get("organization")), (say("Created"), report.utc_text(self.context["created_at"])),
                (say("Report ID"), self.report_id)],
                say("Signed PDF: a PDF signature that PDF readers show, and the Ed25519 seal of key {fp}. Check both with "
                    "verify.py; the last section explains how.", fp=report.grouped(self.fp)))
            self.lay.figures([(say("Messages"), self.meta.get("message_count")), (say("Participants"), len(self.people)),
                         (say("With media"), self.stats["media"]), (say("Edited"), self.stats["edited"]), (say("Service"), self.stats["service"])]
                        + ([(say("Numbers absent"), self.ids["missing"])] if self.ids.get("numbered_per_chat") else [])
                        + [(say("Period"), report.span_text(say, self.stats["first_at"], self.stats["last_at"]))])
            self.lay.gap(5)
            self.lay.qr(paper_lines(self.report_id, self.fp, "chat.json", self.context.get("chat_json_sha256")))
            self.account = self.meta.get("account") or {}
            self.account_text = " · ".join(x for x in (("@" + self.account["username"]) if self.account.get("username") else "",
                                                  ("id " + str(self.account["id"])) if self.account.get("id") else "") if x)

            callbacks = {
                "brief": self.render_brief,
                "analytics": self.render_analytics,
                "assessment": self.render_assessment,
                "case": self.render_case,
                "source": self.render_source,
                "participants": self.render_participants,
                "message_numbers": self.render_message_numbers,
                "admin_log": self.render_admin_log,
                "indicators": self.render_indicators,
                "journal": self.render_journal,
                "integrity": self.render_integrity,
                "custody": self.render_custody,
                "verify": self.render_verify,
                "files": self.render_files,
                "limitations": self.render_limitations,
            }
            default_order = ['brief', 'analytics', 'assessment', 'case', 'source', 'participants', 'message_numbers', 'admin_log', 'indicators', 'journal', 'integrity', 'custody', 'verify', 'files', 'limitations']
            visible = {
                "analytics": bool(self.context.get("analytics") and report.snapshot_analytics.selected(self.options)),
                "source": bool(report.source_rows(say, self.meta, self.stats)), "message_numbers": bool(self.ids),
                "admin_log": self.context.get("admin_events") is not None,
                "indicators": bool(self.options.get("show_indicators", True) and (self.context.get("indicators") or {}).get("items")),
                "files": bool(self.context.get("files")),
            }
            report_composition_pdf.render(self.lay, callbacks, default_order, 'chat', visible)
            declaration(self.lay, say, self.case)
            self.lay.qr(paper_lines(self.report_id, self.fp, "chat.json", self.context.get("chat_json_sha256")))
            if self.certificate is not None:
                signatures_section(self.lay, say, self.certificate, self.fp, "chat.pdf")
            return add_signature_field(pdf, say)
        finally:
            logging.getLogger("fpdf").removeHandler(found)

    def render_brief(self):
        say = self.say
        self.lay.brief(*report.chat_brief(say, self.meta, self.stats, self.ids, self.account_text))

    def render_analytics(self):
        report.snapshot_analytics.pdf_section(self.lay, self.context.get("analytics"), self.options)

    def render_assessment(self):
        report.case_assessment.pdf(self.lay, report.case_assessment.snapshot(self.context, "chat", self.meta))

    def render_case(self):
        say = self.say
        self.lay.section(say("Case"))
        self.lay.kv([(say("Case title"), self.case.get("title")), (say("Case ID"), self.case.get("id")),
                (say("Examiner"), self.case.get("examiner")), (say("Organization"), self.case.get("organization")),
                (say("Chat"), self.chat_title + " · " + str(self.chat.get("kind") or "") + " · id " + str(self.chat.get("id"))),
                (say("First message"), report.utc_text(self.stats["first_at"])), (say("Last message"), report.utc_text(self.stats["last_at"])),
                (say("Exporting account"), " · ".join(x for x in (("@" + self.account["username"]) if self.account.get("username") else "",
                                                                  ("id " + str(self.account["id"])) if self.account.get("id") else "") if x)),
                (say("Report language"), say.language), (say("Report ID"), Mono(self.report_id))])
        if self.case.get("notes"):
            self.lay.heading(say("Notes"))
            self.lay.text(self.case["notes"], size=9)

    def render_source(self):
        say = self.say
        source = report.source_rows(say, self.meta, self.stats)
        if source:
            self.lay.section(say("The chat at export time"), say(
                "What Telegram said about the chat when the export began, and the exporting account's place in it. "
                "Labels such as scam and fake are Telegram's own."))
            warned = [text for _, text, tone in source if tone == "bad"]
            if warned:
                self.lay.callout(" · ".join(warned), BAD)
            self.lay.kv([(label, text) for label, text, _ in source])

    def render_participants(self):
        say = self.say
        self.lay.section(say("Participants"), say("Everyone who posted in the exported history, most active first. Names are "
                                             "the profile at export time."))
        self.lay.grid([say("Participant"), "ID", say("Messages"), say("First message"), say("Last message")],
                 [["\n".join([(p["name"] or say("Unknown")) + (" @" + p["username"] if p.get("username") else "")]
                              + report.poster_notes(say, p, self.chat)), Mono(str(p["user_id"])),
                   p["messages"], report.utc_text(p["first_message_at"]), report.utc_text(p["last_message_at"])]
                  for p in self.people[:100]], (32, 18, 10, 20, 20))

    def render_message_numbers(self):
        say = self.say
        if self.ids:
            self.lay.section(say("Message numbers"), say(
                "This export contains a selection. Absent message numbers may have been excluded by the filters. "
                "They are not evidence that a message was deleted or inaccessible."
                if self.ids.get("selection_applied") else
                "Telegram numbers the messages of a channel or supergroup 1, 2, 3… in order, service messages included. A "
                "number between the first and the last exported message that is absent belongs to a message Telegram did "
                "not return: deleted before the export, or not visible to this account. If only part of the chat was "
                "exported, numbers outside that part are absent too."))
            if self.ids.get("recheck"):
                self.lay.callout(report.recheck_text(say, self.ids["recheck"]), MUTED)
            if self.ids.get("numbered_per_chat"):
                span = self.ids["last_id"] - self.ids["first_id"] + 1 if isinstance(self.ids.get("first_id"), int) else 0
                self.lay.kv([(say("First message number"), self.ids["first_id"]), (say("Last message number"), self.ids["last_id"]),
                        (say("Numbers in this range"), span), (say("Messages present"), self.ids["present"]),
                        (say("Numbers absent"), self.ids["missing"]), (say("Runs of absent numbers"), len(self.ids["missing_ranges"]))])
                if self.ids["missing_ranges"]:
                    shown = self.ids["missing_ranges"][:200]
                    self.lay.grid([say("Message numbers"), say("Count")],
                             [[str(low) if low == high else str(low) + " – " + str(high), high - low + 1] for low, high in shown],
                             (60, 40))
                    self.lay.text(say("message-ids.json lists every absent number; verify.py recounts them from chat.json."),
                             size=8.5, color=MUTED)
            else:
                self.lay.text(say("In private chats and basic groups the numbers are shared by all of the account's chats, so "
                             "gaps say nothing about this chat."), size=9)

    def render_admin_log(self):
        say = self.say
        if self.context.get("admin_events") is not None:
            summary = self.meta.get("admin_log") or {}
            self.lay.section(say("Admin log"), say(
                "Telegram keeps a chat's admin log for about 48 hours and shows it to its admins. It names the account "
                "that deleted or edited a message, with the content: the one record of a deletion that says who did it."))
            self.lay.kv([(say("Read at"), report.utc_text(summary.get("read_at"))), (say("Events"), summary.get("events")),
                    (say("Not answered by Telegram"), summary.get("error_type") or "")])
            self.lay.grid([say("Time"), say("Account"), say("Action"), say("Message"), say("Content")],
                     [list(row) for row in report.admin_rows(say, self.context["admin_events"], 300)], (17, 13, 16, 8, 46))

    def render_indicators(self):
        say = self.say
        if self.options.get("show_indicators", True) and (self.context.get("indicators") or {}).get("items"):
            indicators_section(self.lay, say, self.context["indicators"])

    def render_journal(self):
        say = self.say
        limit = self.options.get("part_size") or report.ReportOptions().part_size
        if self.parts:
            self.lay.section(say("Messages"), say("{n} messages in {m} parts, oldest first. Each part is a page of its own "
                                             "with its own seal; manifest.json lists its SHA-256.",
                                             n=self.meta.get("message_count"), m=len(self.parts)))
            self.lay.grid([say("Part"), say("Message numbers"), say("Count"), say("Period"), "SHA-256"],
                     [[say("Part {n} of {m}", n=p["index"], m=len(self.parts)) + "\n" + p["file"], "#" + str(p["from"]) + " – #"
                       + str(p["to"]), p["count"], report.utc_text(p["first_at"]) + " — " + report.utc_text(p["last_at"]),
                       Mono(p.get("sha256") or "")] for p in self.parts], (22, 16, 8, 26, 28))
        elif self.messages is not None and (self.meta.get("message_count") or 0) <= limit:
            self.lay.section(say("Messages"), say("The visible history at export time, oldest first."))
            if self.stats.get("edited"):
                self.lay.callout(say("An edited message shows when it was last edited. A history snapshot holds only the "
                                "current text; earlier versions exist only where the observation journal recorded them."),
                            MUTED)
            transcript(self.lay, say, self.messages, bool(self.ids.get("numbered_per_chat") and not self.ids.get("selection_applied")))
        else:
            self.lay.section(say("Messages"))
            self.lay.callout(say("This chat has {n} messages, exceeding the PDF transcript limit of {limit}. "
                            "Every message remains in chat.json and the HTML viewer.",
                            n=self.meta.get("message_count") or 0, limit=limit), WARN)

    def render_integrity(self):
        say = self.say
        self.lay.section(say("Integrity"), say("chat.json is authoritative. The manifest lists the SHA-256 of every file and is "
                                          "signed with Ed25519; this page carries its own signed seal."))
        self.lay.kv([(say("Signing key fingerprint (SHA-256)"), Mono(report.grouped(self.fp))),
                ("chat.json SHA-256", Mono(self.context.get("chat_json_sha256") or "")),
                (say("Independent timestamps"), say("None: a chat export is not timestamped.")),
                (say("Independent witness"), say("None: a chat export is not witnessed.")),
                (say("Messages"), self.meta.get("message_count")), (say("Hash algorithm"), "SHA-256 (FIPS 180-4)"),
                (say("Signature algorithm"), "Ed25519 (RFC 8032)"), (say("Public key"), Mono(self.context.get("public_key") or ""))])

    def render_custody(self):
        say = self.say
        self.lay.section(say("Chain of custody"), say("How this material was acquired, preserved and handed over. "
                                                 "custody.json carries the same record for case-management systems."))
        read = report.reading(self.meta)
        for step, detail in ((say("History read through the Telegram API"),
                              report.utc_text(read["read_started_at"]) + " — " + report.utc_text(read["read_finished_at"])
                              if read["read_started_at"] else say("Time of reading not recorded in this export")),
                             (say("Period of the messages"), report.utc_text(self.stats["first_at"]) + " — "
                              + report.utc_text(self.stats["last_at"])),
                             (say("Messages written to chat.json and hashed"), say("Messages: {n}", n=self.meta.get("message_count"))),
                             (say("Archive signed and report sealed"), report.utc_text(self.context["created_at"]) + " · "
                              + (self.options.get("examiner") or ""))):
            self.lay.text(step, size=9, style="B")
            self.lay.text(detail, size=8.5, color=MUTED)
            self.lay.gap(0.8)
        self.lay.kv([(say("Acquisition tool"), "TgWitness " + str(self.context["producer"].get("version"))),
                (say("Program build"), Mono(report.build_text(say, self.context["producer"]))),
                (say("Acquisition method"), say("Full visible history read through the Telegram API; a current snapshot, "
                                                "not a reconstruction of deleted or earlier edited messages.")),
                (say("Telegram client"), report.client_text(say, self.meta["client"]) if isinstance(self.meta.get("client"), dict)
                 else say("Not recorded in this export")),
                (say("Connection route"), report.route_text(say, self.meta["route"]) if isinstance(self.meta.get("route"), dict)
                 else say("Not recorded in this export")),
                (say("Collector clock against Telegram"), clocks_lines(say, read["clock_checks"], "Not recorded in this export")),
                (say("Time standard"), "UTC · ISO 8601")])
        transfers(self.lay, say)

    def render_verify(self):
        say = self.say
        self.lay.section(say("Verify"), say("Get the signer's key fingerprint from a trusted channel, not from this archive."))
        self.lay.command("python verify.py tgwitness-chat-export.zip --fingerprint " + self.fp)

    def render_files(self):
        say = self.say
        files = self.context.get("files") or {}
        if files:
            self.lay.section(say("Files in this archive"), say("manifest.json lists the SHA-256 of every file and is signed in "
                                                          "manifest.sig."))
            self.lay.grid([say("File"), say("Purpose"), "SHA-256"],
                     [[Mono(n), report.file_purpose(say, n), Mono(files[n])] for n in sorted(files)[:300]], (26, 30, 44))

    def render_limitations(self):
        say = self.say
        self.lay.section(say("Reading this record"), say("What the records state and what binds them."))
        self.lay.bullets([say(x) for x in self.context.get("limits") or []])


def chat_pdf(meta, context, messages=None, certificate=None):
    return ChatPDF(render_data.detached(meta), render_data.context(context),
                      render_data.records(messages), certificate).render()


def clocks_lines(say, clocks, empty):
    if not clocks:
        return say(empty)
    measured = [c["offset_seconds"] for c in clocks if isinstance(c.get("offset_seconds"), (int, float))]
    lines = [say("Largest difference: {s} s", s="%.2f" % max(abs(x) for x in measured))] if len(measured) > 1 else []
    return "\n".join(lines + [report.clock_text(say, c) + " · " + report.utc_text(c.get("measured_at"))
                              for c in clocks[-10:]])


def transcript(lay, say, messages, numbered=False):
    previous = None
    for record in messages:
        gap = report.absent_before(record, previous) if numbered else None
        if gap:
            lay.text("—  " + report.absent_text(say, *gap) + "  —", size=7.8, style="B", color=BAD)
            lay.gap(0.8)
        if record.get("found_on_recheck"):
            lay.text("—  " + say("Found on recheck: missing from the history Telegram first returned") + "  —", size=7.8,
                     style="B", color=WARN)
        if type(record.get("id")) is int:
            previous = record["id"] if type(previous) is not int else max(previous, record["id"])
        if record.get("type") == "unparsed":
            lay.text("—  " + report.unparsed_text(say, record) + "  —", size=7.8, style="B", color=WARN)
            lay.gap(0.8)
            continue
        sender = record.get("from") or (str(record["from_id"]) if record.get("from_id") is not None else say("Unknown"))
        note = report.name_note(say, record)
        head = "#" + str(record.get("id")) + "  " + report.utc_text(record.get("date")) + " · " + sender \
            + (" (" + note + ")" if note else "")
        if record.get("selection"):
            head += " · " + (say("Context message") if record["selection"].get("role") == "context"
                              else say("Matches export filters"))
        if record.get("type") == "service":
            lay.text(head + " · " + (report.action_text(record.get("action")) or say("Service message")), size=7.8, color=MUTED)
            continue
        report_composition_pdf.record_heading(lay, head + (" · " + report.edited_text(say, record["edited"])
                                                           if record.get("edited") else ""))
        if record.get("text"):
            if report_composition_pdf.active(lay):
                report_composition_pdf.message_text(lay, record["text"])
            else:
                lay.text(record["text"], size=8.8)
        if record.get("media_type"):
            reason = report.FILE_STATUS.get(record.get("file_status"))
            lay.text("◆ " + say(report.MEDIA_NAMES.get(record["media_type"], "Media"))
                     + (" · " + report.media_text(say, record.get("media_info")) if record.get("media_info") else "")
                     + (" · " + say("saved in the archive") + " " + str(record.get("file_sha256")) if record.get("file")
                        else " · " + (say(reason) if reason else say("not included in this export"))), size=7.8, color=MUTED)
        for line in details_lines(say, record, include_media=False):
            lay.text(line, size=7.8, color=MUTED)
        lay.gap(0.8)


def add_signature_field(pdf, say):
    from fpdf.annotations import PDFAnnotation
    from fpdf.enums import AnnotationFlag
    from fpdf.sign import Signature
    from fpdf.syntax import PDFDate, PDFString
    value = Signature(reason=PDFString(say("Report sealed")), m=PDFDate(datetime.now(timezone.utc)))
    value.contents = "<" + "0" * CONTENTS_HEX + ">"
    pdf.pages[pdf.page].add_annotation(PDFAnnotation(
        "Widget", field_type="Sig", x=0, y=0, width=0, height=0, title="TgWitness seal", value=value,
        flags=(AnnotationFlag.PRINT, AnnotationFlag.LOCKED)))
    return indirect_signature(pdf.output())


def indirect_signature(buffer):
    data = bytes(buffer)
    contents = data.find(b"/Contents <" + b"0" * CONTENTS_HEX + b">")
    start, close = data.rfind(b"/V <<", 0, contents), data.find(b"/Type /Sig>>", contents)
    found = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data)
    head = re.compile(rb"xref\s*\n0 (\d+)\s*\n").match(data, int(found.group(1))) if found else None
    if contents < 0 or start < 0 or close < 0 or not head:
        raise ValueError("The PDF does not have the expected signature field")
    end = close + len(b"/Type /Sig>>")
    signature, count, table = data[start + 3:end], int(head.group(1)), head.end()
    trailer = data[table + 20 * count:found.start()]
    if signature.count(b"<<") != 1 or not trailer.startswith(b"trailer"):
        raise ValueError("The PDF does not have the expected signature field")
    reference = b"/V %d 0 R" % count
    shift, entries = len(reference) - (end - start), []
    for number in range(count):
        entry = data[table + 20 * number:table + 20 * number + 20]
        if entry[17:18] == b"n" and int(entry[:10]) > start:
            entry = b"%010d" % (int(entry[:10]) + shift) + entry[10:]
        entries.append(entry)
    body = data[:start] + reference + data[end:head.start()]
    entries.append(b"%010d 00000 n \n" % len(body))
    body += b"%d 0 obj\n" % count + signature + b"\nendobj\n"
    trailer = re.sub(rb"/Size \d+", b"/Size %d" % (count + 1), trailer, count=1)
    return bytearray(body + b"xref\n0 %d\n" % (count + 1) + b"".join(entries) + trailer
                     + b"startxref\n%d\n%%%%EOF\n" % len(body))


def identity(vault):
    fp = fingerprint(vault.public_key)
    saved = vault.read("document_signing")
    if saved.get("key") and saved.get("certificate"):
        certificate = x509.load_pem_x509_certificate(saved["certificate"].encode())
        named = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if named and named[0].value == fp:
            return serialization.load_pem_private_key(saved["key"].encode(), None), certificate
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TgWitness workspace " + fp[:16]),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Document signing vouched for by the Ed25519 key"),
                      x509.NameAttribute(NameOID.SERIAL_NUMBER, fp)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=365 * 20))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
                   .sign(key, hashes.SHA256()))
    vault.save("document_signing", {
        "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode(),
        "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode()})
    return key, certificate


def sign(buffer, key, certificate, seal_for):
    buffer = bytearray(buffer)
    placeholder = b"<" + b"0" * CONTENTS_HEX + b">"
    start = buffer.find(placeholder)
    if start < 0 or buffer.find(placeholder, start + 1) >= 0:
        raise ValueError("The PDF has no single signature placeholder")
    end = start + len(placeholder)
    objects = list(re.finditer(rb"(?:^|\n)\d+ 0 obj\r?\n", buffer[:start]))
    object_start = objects[-1].end() if objects else -1
    object_end = buffer.find(b"\nendobj", end)
    prefix = b"/ByteRange " + BYTE_RANGE_PLACEHOLDER
    at = buffer.find(prefix, object_start, start) if object_start >= 0 else -1
    if at < 0 or object_end < 0 or b"/Type /Sig" not in buffer[end:object_end] \
            or buffer.find(prefix, at + 1, start) >= 0:
        raise ValueError("The PDF has no byte range placeholder")
    at += len(b"/ByteRange ")
    buffer[at:at + len(BYTE_RANGE_PLACEHOLDER)] = b"[%010d %010d %010d %010d]" % (0, start, end, len(buffer) - end)
    digest = hashlib.sha256(bytes(buffer[:start]) + bytes(buffer[end:])).digest()
    der_certificate = certificate.public_bytes(serialization.Encoding.DER)
    seal = seal_for(digest.hex(), hashlib.sha256(der_certificate).hexdigest())
    value = signed_data(digest, key, certificate, der_certificate, canonical(seal)).hex().encode()
    if len(value) > CONTENTS_HEX:
        raise ValueError("The PDF signature does not fit its placeholder")
    buffer[start + 1:end - 1] = value + b"0" * (CONTENTS_HEX - len(value))
    return bytes(buffer)


def _length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, body):
    return bytes([tag]) + _length(len(body)) + body


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _set(*parts):
    return _tlv(0x31, b"".join(sorted(parts)))


def _oid(dotted):
    numbers = [int(x) for x in dotted.split(".")]
    body = bytes([40 * numbers[0] + numbers[1]])
    for number in numbers[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _int(n):
    return _tlv(0x02, n.to_bytes((n.bit_length() + 8) // 8, "big"))


def signed_data(digest, key, certificate, der_certificate, seal):
    when = datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ").encode()
    attribute = lambda kind, value: _seq(_oid(kind), _set(value))
    signed = _set(attribute(CONTENT_TYPE, _oid(DATA)), attribute(SIGNING_TIME, _tlv(0x17, when)),
                  attribute(MESSAGE_DIGEST, _tlv(0x04, digest)),
                  attribute(SIGNING_CERTIFICATE_V2, _seq(_seq(_seq(_tlv(0x04, hashlib.sha256(der_certificate).digest()))))))
    signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    unsigned = _set(attribute(SEAL_ATTRIBUTE, _tlv(0x0C, seal)))
    signer = _seq(_int(1), _seq(certificate.issuer.public_bytes(), _int(certificate.serial_number)), _seq(_oid(SHA256)),
                  b"\xa0" + signed[1:], _seq(_oid(ECDSA_SHA256)), _tlv(0x04, signature), b"\xa1" + unsigned[1:])
    body = _seq(_int(1), _set(_seq(_oid(SHA256))), _seq(_oid(DATA)), _tlv(0xA0, der_certificate), _set(signer))
    return _seq(_oid(SIGNED_DATA), _tlv(0xA0, body))


def report_pdf(data, context, vault, events=None):
    certificate = identity(vault)[1]
    return sealed_pdf(evidence_pdf(data, context, events, certificate), vault, report.seal_statement(context))


def chat_report_pdf(meta, context, vault, messages=None):
    certificate = identity(vault)[1]
    return sealed_pdf(chat_pdf(meta, context, messages, certificate), vault,
                      report.seal_statement(context, report.chat_subject(meta, context)))


def sealed_pdf(unsigned, vault, statement):
    key, certificate = identity(vault)

    def seal_for(content, certificate_sha256):
        signed = {**statement, "content_sha256": content, "content": "pdf-byte-range",
                  "document_certificate_sha256": certificate_sha256}
        return {"statement": signed, "signature": vault.sign(canonical(signed)),
                "fingerprint": fingerprint(signed["public_key"])}
    return sign(unsigned, key, certificate, seal_for)
