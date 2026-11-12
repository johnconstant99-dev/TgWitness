from types import SimpleNamespace
from unicodedata import category

from .. import pdf_report
from .style import RTL, tone

INK, MUTED, LINE, FILL, GOLD, WHITE = pdf_report.INK, pdf_report.MUTED, pdf_report.LINE, pdf_report.FILL, \
    pdf_report.GOLD, pdf_report.WHITE
COLORS = {'ok': pdf_report.OK, 'warn': pdf_report.WARN, 'bad': pdf_report.BAD, 'none': MUTED}
BARS = {'ok': pdf_report.OK, 'warn': (210, 154, 60), 'bad': pdf_report.BAD, 'none': (185, 195, 199)}
QUOTE = (251, 246, 238)
CODE = (16, 35, 46)


class Sheet:
    def __init__(self, text, footer, title):
        from fpdf.enums import XPos, YPos
        self.XPos, self.YPos = XPos, YPos
        self.pdf = pdf_report.document(SimpleNamespace(language=text.lang, direction='rtl' if text.lang in RTL else 'ltr'),
                                       footer)
        self.pdf.set_title(title)
        self.rtl = self.pdf.rtl
        self.align = 'R' if self.rtl else 'L'
        self.glyphs = set().union(*(font.cmap for font in self.pdf.fonts.values() if hasattr(font, 'cmap')))
        self.unavailable = text('expert.pdf.script')
        self.number = 0

    def shown(self, value):
        value = str(value)
        return value if all(ord(char) in self.glyphs or char.isspace() or category(char) == 'Cf' for char in value) \
            else self.unavailable

    def font(self, size=9.5, bold=False, mono=False, color=INK):
        self.pdf.set_font('Mono' if mono else 'Sans', 'B' if bold and not mono else '', size)
        self.pdf.set_text_color(*color)

    def write(self, value, size=9.5, bold=False, mono=False, color=INK, height=None, width=0, x=None, align=None):
        pdf = self.pdf
        self.font(size, bold, mono, color)
        if x is not None:
            pdf.set_x(x)
        pdf.multi_cell(width, height or size * 0.5, self.shown(value), new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT,
                       align=align or ('L' if mono else self.align))

    def measure(self, value, width, size=9.5, bold=False, mono=False, height=None):
        self.font(size, bold, mono)
        return self.pdf.multi_cell(width, height or size * 0.5, self.shown(value), dry_run=True, output='HEIGHT')

    def gap(self, mm=2):
        self.pdf.ln(mm)

    def need(self, height):
        if self.pdf.will_page_break(height):
            self.pdf.add_page()

    def hero(self, kind, title, meta, notes, badge=None):
        pdf = self.pdf
        pdf.add_page()
        left, width = pdf.l_margin, pdf.epw
        column = (width - 8) / 2
        meta = [(label, value) for label, value in meta if value]
        title_height = self.measure(title, width, 21, True, height=9)
        rows = []
        for start in range(0, len(meta), 2):
            pair = meta[start:start + 2]
            rows.append(max(self.measure(label.upper(), column, 6.6, height=3.4) +
                            self.measure(value, column, 9, True, height=4.4) for label, value in pair) + 4)
        top = 30 + title_height + (9 if badge else 0)
        band = top + 5 + sum(rows) + 6
        with pdf.local_context(fill_color=INK):
            pdf.rect(0, 0, pdf.w, band, style='F')
        with pdf.local_context(fill_color=GOLD):
            pdf.rect(0, band - 1.2, pdf.w, 1.2, style='F')
        pdf.set_y(11)
        self.font(7.5, True, color=GOLD)
        pair = [('TG / WITNESS', 'L'), (self.shown(kind.upper()), 'R')]
        for index, (label, align) in enumerate(pair[::-1] if self.rtl else pair):
            pdf.cell(width / 2, 4, label, align=align, new_x=self.XPos.RIGHT if index == 0 else self.XPos.LMARGIN,
                     new_y=self.YPos.TOP if index == 0 else self.YPos.NEXT)
        with pdf.local_context(draw_color=(60, 86, 100), line_width=0.2):
            pdf.line(left, 18, left + width, 18)
        pdf.set_y(24)
        self.write(title, 21, True, color=WHITE, height=9)
        if badge:
            self.gap(2)
            self.font(7, True, color=INK)
            label = self.shown(badge.upper())
            span = pdf.get_string_width(label) + 7
            x = left + width - span if self.rtl else left
            y = pdf.get_y()
            with pdf.local_context(fill_color=GOLD):
                pdf.rect(x, y, span, 5.6, style='F', round_corners=True, corner_radius=2.8)
            pdf.set_xy(x, y + 0.2)
            pdf.cell(span, 5.2, label, align='C', new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)
        y = top + 5
        for index, start in enumerate(range(0, len(meta), 2)):
            for slot, (label, value) in enumerate(meta[start:start + 2]):
                x = left + ((1 - slot) if self.rtl else slot) * (column + 8)
                pdf.set_xy(x, y)
                self.write(label.upper(), 6.6, color=(159, 179, 188), height=3.4, width=column, x=x)
                pdf.set_x(x)
                self.write(value, 9, True, color=WHITE, height=4.4, width=column, x=x)
            y += rows[index]
        pdf.set_y(band + 5)
        for line in notes:
            self.write(line, 8.6, color=MUTED, height=4.3)
            self.gap(0.8)
        self.gap(2)

    def section(self, title):
        pdf = self.pdf
        if pdf.get_y() > pdf.h - 60:
            pdf.add_page()
        else:
            self.gap(5)
        y = pdf.get_y()
        with pdf.local_context(draw_color=GOLD, line_width=0.5):
            pdf.line(pdf.l_margin, y, pdf.l_margin + pdf.epw, y)
        pdf.set_y(y + 3.5)
        number, _, rest = title.partition(' ')
        if number[:-1].isdigit() and number.endswith('.') and rest:
            title = f'{int(number[:-1]):02d}   /   ' + rest
        pdf.start_section(self.shown(title), level=0)
        self.write(title, 14.5, True, height=7)
        self.gap(2.5)

    def heading(self, title):
        self.need(32)
        self.gap(2.5)
        self.write(title, 10.5, True, height=5.2)
        self.gap(1.2)

    def para(self, value, size=9.5, color=INK, mono=False):
        self.write(value, size, mono=mono, color=color, height=size * 0.5)
        self.gap(1.4)

    def bullets(self, items, size=9.2, color=INK):
        for item in items:
            self.write('•  ' + item, size, color=color, height=size * 0.5)
            self.gap(0.8)

    def checklist(self, items):
        pdf = self.pdf
        for item in items:
            height = self.measure(item, pdf.epw - 6, 9.2, height=4.6)
            self.need(height + 1)
            y = pdf.get_y()
            box = pdf.l_margin + pdf.epw - 3.6 if self.rtl else pdf.l_margin
            with pdf.local_context(draw_color=INK, line_width=0.3):
                pdf.rect(box, y + 0.7, 3.4, 3.4)
            self.write(item, 9.2, height=4.6, width=pdf.epw - 6, x=pdf.l_margin + (0 if self.rtl else 6))
            self.gap(1)

    def rule(self):
        pdf = self.pdf
        self.gap(2)
        with pdf.local_context(draw_color=LINE, line_width=0.2):
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())
        self.gap(3)

    def fields(self, labels, narrow=False):
        pdf = self.pdf
        label_width = pdf.epw * (0.08 if narrow else 0.42)
        for label in labels:
            text_height = self.measure(label, label_width - 2, 8.8, height=4.4)
            height = max(9, text_height + 4)
            self.need(height)
            y = pdf.get_y()
            label_x = pdf.l_margin + pdf.epw - label_width if self.rtl else pdf.l_margin
            line_x = pdf.l_margin if self.rtl else pdf.l_margin + label_width
            pdf.set_y(y + height - text_height - 1.2)
            self.write(label, 8.8, color=MUTED, height=4.4, width=label_width - 2, x=label_x)
            with pdf.local_context(draw_color=LINE, line_width=0.2):
                pdf.line(label_x, y + height, label_x + label_width, y + height)
            with pdf.local_context(draw_color=INK, line_width=0.35):
                pdf.line(line_x, y + height, line_x + pdf.epw - label_width, y + height)
            pdf.set_y(y + height + 1)
        self.gap(2)

    def bar_block(self, lines, bar, fill=None, size=9.4, bold_first=False, padding=3.2, tints=None):
        pdf = self.pdf
        inner = pdf.epw - 2 * padding - 1.4
        heights = [self.measure(line, inner, size + (0.6 if bold_first and not index else 0),
                                bold_first and not index, height=(size + 0.6) * 0.5)
                   for index, line in enumerate(lines)]
        total = sum(heights) + 2 * padding + 1.6 * (len(lines) - 1)
        self.need(total + 2)
        y = pdf.get_y()
        if fill:
            with pdf.local_context(fill_color=fill):
                pdf.rect(pdf.l_margin, y, pdf.epw, total, style='F')
        with pdf.local_context(fill_color=bar):
            pdf.rect(pdf.l_margin + pdf.epw - 1.4 if self.rtl else pdf.l_margin, y, 1.4, total, style='F')
        pdf.set_y(y + padding)
        x = pdf.l_margin + padding + (0 if self.rtl else 1.4)
        for index, line in enumerate(lines):
            first = bold_first and not index
            tint = (tints or {}).get(index)
            self.write(line, size + (0.6 if first else 0), first or bool(tint), color=tint or INK, height=(size + 0.6) * 0.5,
                       width=inner, x=x)
            if index < len(lines) - 1:
                self.gap(1.6)
        pdf.set_y(y + total + 2.5)

    def quote(self, lines, second=False):
        for index, line in enumerate(lines):
            self.bar_block([line], GOLD if second or index else pdf_report.WARN, FILL if second or index else QUOTE)

    def code(self, lines):
        pdf = self.pdf
        for line in lines:
            self.font(7.4, mono=True, color=(227, 236, 239))
            height = pdf.multi_cell(pdf.epw, 3.9, line, dry_run=True, output='HEIGHT', padding=2.2)
            self.need(height + 1)
            with pdf.local_context(fill_color=CODE):
                pdf.multi_cell(pdf.epw, 3.9, line, fill=True, padding=2.2, new_x=self.XPos.LMARGIN,
                               new_y=self.YPos.NEXT, align='L')
            self.gap(1.6)

    def sourced(self, items):
        for label, url in items:
            if not label:
                continue
            self.need(12)
            self.write('•  ' + label, 9.2, height=4.6)
            if url:
                self.write(url, 6.8, color=(22, 92, 116), height=3.4, x=self.pdf.l_margin + (0 if self.rtl else 4.5))
            self.gap(1.4)

    def statuses(self, rows):
        pdf = self.pdf
        for label, status, shown in rows:
            self.need(8)
            y = pdf.get_y()
            kind = tone(status)
            self.font(9.2)
            pdf.cell(pdf.epw * 0.7, 6.4, self.shown(label), align=self.align)
            self.font(8.6, True, color=COLORS[kind])
            pdf.cell(pdf.epw * 0.3, 6.4, self.shown(shown), align='L' if self.rtl else 'R',
                     new_x=self.XPos.LMARGIN, new_y=self.YPos.NEXT)
            with pdf.local_context(draw_color=LINE, line_width=0.2):
                pdf.line(pdf.l_margin, y + 6.8, pdf.l_margin + pdf.epw, y + 6.8)
            pdf.set_y(y + 7.4)
        self.gap(2)

    def finding(self, title, status, shown, lines):
        self.bar_block([title, shown, *lines], BARS[tone(status)], (250, 251, 251), 9.2, True, tints={1: COLORS[tone(status)]})

    def table(self, rows, widths, mono_columns=(), size=8, muted_first=False):
        pdf = self.pdf
        widths = [pdf.epw * part for part in widths]
        for row in rows:
            heights = [self.measure(value, width - 2, size, mono=index in mono_columns, height=size * 0.5)
                       for index, (value, width) in enumerate(zip(row, widths))]
            height = max(heights) + 3
            self.need(height)
            y = pdf.get_y()
            order = list(range(len(row)))[::-1] if self.rtl else list(range(len(row)))
            x = pdf.l_margin
            for index in order:
                pdf.set_xy(x + 1, y + 1.5)
                self.write(row[index], size, mono=index in mono_columns, height=size * 0.5, width=widths[index] - 2,
                           x=x + 1, color=MUTED if index == 0 and muted_first else INK)
                x += widths[index]
            with pdf.local_context(draw_color=LINE, line_width=0.2):
                pdf.line(pdf.l_margin, y + height, pdf.l_margin + pdf.epw, y + height)
            pdf.set_y(y + height)
        self.gap(2)

    def output(self):
        return bytes(self.pdf.output())
