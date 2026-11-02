"""Native PDF styles preserve content while changing composition per document."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import pdf_report, report, report_design_pdf


FACTS = [("Case ID", "SYNTHETIC-26-014"), ("Examiner", "Example examiner"),
         ("Organization", "Fictional review laboratory"), ("Report ID", "synthetic-report")]
FIGURES = [("Records", 2518), ("Chats", 7), ("Edits", 19), ("Deletions", 577),
           ("Observation period", "01 November 2026, 09:00 UTC — 02 November 2026, 12:00 UTC")]


def cover(name):
    say = report.Words("en")
    pdf = pdf_report.document(say, "SYNTHETIC-26-014", name)
    pdf.set_creation_date(datetime(2026, 11, 2, tzinfo=timezone.utc))
    pdf.set_compression(False)
    lay = pdf_report.Layout(pdf, say)
    geometry = []
    original = pdf.multi_cell

    def record_cell(w=None, h=None, text="", *args, **kwargs):
        geometry.append((str(text), round(pdf.get_x(), 2), round(pdf.get_y(), 2),
                         round(float(w or 0), 2), round(float(h or 0), 2), pdf.font_family,
                         round(pdf.font_size_pt, 2)))
        return original(w, h, text, *args, **kwargs)

    pdf.multi_cell = record_cell
    lay.title_block("Evidence report · Signed", "A record that can be checked", FACTS, "Synthetic layout preview.")
    lay.figures(FIGURES)
    lay.section("Recorded changes", "These observations are synthetic.")
    lay.grid(["Record", "Kind", "Text"], [["1", "message.edited", "Before and after"]], (15, 30, 55))
    result = bytes(pdf.output())
    return result, tuple(geometry)


def test_every_style_changes_geometry_not_only_colors():
    constants = (pdf_report.INK, pdf_report.MUTED, pdf_report.GOLD, pdf_report.LINE, pdf_report.FILL)
    geometries = []
    for name in report_design_pdf.STYLES:
        data, geometry = cover(name)
        assert data.startswith(b"%PDF-")
        assert ("report design: " + name).encode() in data
        geometries.append(geometry)
    assert len(set(geometries)) == len(report_design_pdf.STYLES)
    assert (pdf_report.INK, pdf_report.MUTED, pdf_report.GOLD, pdf_report.LINE, pdf_report.FILL) == constants


def test_concurrent_reports_do_not_share_palette_or_layout_state():
    names = tuple(report_design_pdf.STYLES)
    expected = {name: hashlib.sha256(cover(name)[0]).hexdigest() for name in names}

    def render(name):
        return name, hashlib.sha256(cover(name)[0]).hexdigest()

    with ThreadPoolExecutor(max_workers=3) as workers:
        for name, digest in workers.map(render, names + tuple(reversed(names))):
            assert digest == expected[name]


@pytest.mark.parametrize("name", tuple(report_design_pdf.STYLES))
def test_long_rtl_titles_unicode_tables_and_page_breaks(name, caplog):
    say = report.Words("ar")
    pdf = pdf_report.document(say, "CASE-RTL · 2026", name)
    lay = pdf_report.Layout(pdf, say)
    title = ("تقرير مراجعة الرسائل والملاحظات المحفوظة " * 5)[:200]
    facts = [(say("Case ID"), "SYNTHETIC-RTL"), (say("Examiner"), "مراجع مستقل"),
             (say("Organization"), ("مختبر مستقل للمراجعة " * 8)[:160])]
    lay.title_block(say("Evidence report"), title, facts, "مراجعة محلية لسجل محفوظ دون تغيير محتواه.")
    lay.figures([(say("Records"), 2518), (say("Chats"), 7), (say("Edits"), 19)])
    for section in range(3):
        lay.section("سجل الملاحظات " + str(section), "النص محفوظ كما ورد في السجل.")
        lay.grid(["مرجع", "ملاحظة"], [[str(i), "رسالة محفوظة · Ελληνικά · Пример · हिंदी"] for i in range(24)], (20, 80))
        assert pdf.get_y() <= pdf.page_break_trigger + 2
    data = bytes(pdf.output())
    assert data.startswith(b"%PDF-") and len(pdf.pages) >= 3
    assert not any("missing the following glyphs" in row.getMessage() for row in caplog.records)
    assert "notosansarabic-regular" in pdf.fonts
    if name == "quire":
        assert "serif" in pdf.fonts and "serifB" in pdf.fonts


def test_style_records_are_immutable_and_unknown_options_use_classic():
    style = report_design_pdf.get_style("quire")
    with pytest.raises(FrozenInstanceError):
        style.ink = (0, 0, 0)
    with pytest.raises(TypeError):
        report_design_pdf.STYLES["other"] = style
    assert report_design_pdf.get_style("<unsafe>") is report_design_pdf.STYLES["classic"]
    assert report_design_pdf.get_style(None) is report_design_pdf.STYLES["classic"]


def test_empty_figures_and_sections_keep_native_output_valid():
    for name in report_design_pdf.STYLES:
        pdf = pdf_report.document(report.Words("en"), "Empty synthetic case", name)
        lay = pdf_report.Layout(pdf, report.Words("en"))
        lay.title_block("Evidence report", "No matching observations", [], "Synthetic case.")
        lay.figures([])
        lay.section("Selected data")
        lay.grid([], [])
        lay.kv([])
        assert bytes(pdf.output()).startswith(b"%PDF-")


def test_bundled_serif_fonts_are_static_regular_and_bold_with_their_license():
    from fontTools.ttLib import TTFont
    for name, weight in (("Regular", 400), ("Bold", 700)):
        with TTFont(pdf_report.FONT_DIR / ("NotoSerif-" + name + ".ttf")) as font:
            assert font["OS/2"].usWeightClass == weight
            assert "fvar" not in font
            licenses = [record.toUnicode() for record in font["name"].names if record.nameID == 13]
            assert any("SIL Open Font License" in text for text in licenses)
    assert "SIL OPEN FONT LICENSE Version 1.1" in (pdf_report.FONT_DIR / "NotoSerif-OFL.txt").read_text()


def test_missing_glyph_warnings_stay_with_the_rendering_thread():
    found = set()
    handler = pdf_report.MissingGlyphs(found)
    logger = logging.getLogger("fpdf.style-test")
    logger.addHandler(handler)
    try:
        with ThreadPoolExecutor(max_workers=1) as workers:
            workers.submit(logger.warning, "missing the following glyphs: other report").result()
        logger.warning("missing the following glyphs: current report")
        assert found == {"current report"}
    finally:
        logger.removeHandler(handler)


def test_legacy_layout_argument_cannot_replace_the_document_palette():
    pdf = pdf_report.document(report.Words("en"), "Compatibility", "quire")
    lay = pdf_report.Layout(pdf, report.Words("en"), "technical")
    assert lay.accent == report_design_pdf.STYLES["quire"].accent
    lay.title_block("Evidence report", "A single coherent design", [], "Synthetic review.")
    assert "serifB" in pdf.fonts
    assert b"report design: quire" in bytes(pdf.output())


def test_snapshot_chart_height_reservation_keeps_room_on_new_page():
    pdf = pdf_report.document(report.Words("en"), "Snapshot", "atlas")
    lay = pdf_report.Layout(pdf, report.Words("en"))
    pdf.add_page()
    pdf.set_y(pdf.page_break_trigger - 10)
    lay.need(75)
    assert pdf.page_no() == 2
    assert pdf.get_y() + 75 < pdf.page_break_trigger
    current = pdf.page_no()
    lay.need(15)
    assert pdf.page_no() == current


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

