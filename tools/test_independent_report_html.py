"""Independent compositions preserve selection, privacy, streaming bounds and seals."""
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, handover, report, report_layouts
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_report
from tools.test_report_record_metadata import record, payload
from tools.test_report_selection_exports import choices, seed


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_signed_selected_reading_copy_is_server_rendered(tmp_path, design):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        seed(store)
        options = choices() | {'design': design, 'raw_records': False,
                               'review_question': 'Which retained version changed?'}
        options['selection']['id_gaps'] = False
        output = evidence.export_file(store, vault, 'html', options)
        html = output.read_text(encoding='utf-8')
        verify_report(output, fingerprint(vault.public_key))
        assert f'data-report-design="{design}"' in html
        assert 'id="r2"' in html and 'SELECTED content' in html
        assert 'id="r4"' in html and 'id="r7"' in html
        assert 'OTHER CHAT content' not in html and 'OUTSIDE DATES' not in html
        assert 'Other author' not in html
        assert 'Which retained version changed?' in html
        assert 'class="record-metadata"' in html
        assert 'id="report-analytics"' in html
        assert 'Harbor Project' not in html and 'Synthetic prototype.' not in html
        if design == 'reading_series':
            assert 'class="reading-series-shell"' in html and 'class="reading-series-rail"' in html
            assert html.index('id="chapter-journal"') < html.index('id="chapter-assurance"')
        else:
            assert 'class="ledger-margin-folio"' in html and 'class="ledger-margin-rail"' in html
            assert html.index('id="chapter-assurance"') < html.index('id="chapter-journal"')
    finally:
        store.close()


def test_permitted_projection_never_revives_raw_fields_or_mutates_input():
    event = record(payload(details={}, sender_id=None, sender_observation={},
                           sent_at=None, edited_at=None, date='HIDDEN_LEGACY_DATE',
                           raw={'date':'HIDDEN_RAW_DATE','reply_to':{'quote_text':'HIDDEN_QUOTE'},
                                'reactions':{'recent_reactions':[{'peer_id':'HIDDEN_ID'}]}}))
    before = copy.deepcopy(event)
    projected = report_layouts.permitted_record(event)
    html = report_layouts.record_metadata_html(event, report.Words('en'))
    assert projected['details'] == {} and projected['sent_at'] is None and projected['sender_id'] is None
    assert 'HIDDEN' not in json.dumps(projected) and 'HIDDEN' not in html
    assert event == before


def test_slice_keeps_whole_text_and_stops_after_one_lookahead():
    consumed = []
    def rows():
        for number in range(20):
            consumed.append(number)
            yield record(payload(text='complete text ' * 20), seq=number + 1)
    sampled, limited = report_layouts.bounded_records(rows(), limit=3)
    assert limited and len(sampled) == 3 and consumed == [0, 1, 2, 3]
    assert all(row['payload']['text'] == 'complete text ' * 20 for row in sampled)
    sampled, limited = report_layouts.bounded_records(rows(), byte_limit=1)
    assert sampled == [] and limited


def test_composition_does_not_parse_or_join_inline_viewer_payload():
    say = report.Words('en')
    first = b'<html><body><main><section id="case"><h2>Case</h2></section>'
    tail = '<script type="application/json">' + ('never parse viewer bytes ' * 10000) + '</script>'
    fed = []
    original = report_layouts._Blocks.feed
    def feed(parser, content):
        fed.append(content)
        return original(parser, content)
    with patch.object(report_layouts._Blocks, 'feed', feed):
        chunks = list(report_layouts.compose(iter([first, ('</main>' + tail).encode(), b'</body></html>']),
                                             'reading_series', say))
    assert tail.encode() in chunks[-2]
    assert all('never parse viewer' not in content for content in fed)
    assert chunks[-1] == b'</body></html>'


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_handover_composition_does_not_restore_private_text(tmp_path, design):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        store.append('message.new', {'text':'PRIVATE_MESSAGE', 'sender_id':99,
                     'sender_observation':{'id':99,'display_name':'PRIVATE_PERSON'},
                     'raw':{'reply_to':{'quote_text':'PRIVATE_QUOTE'}}}, -1001, 1, 99)
        options = report.resolved() | {'language':'en', 'design':design, 'raw_records':False,
                                       'review_findings':'PRIVATE_FINDINGS'}
        settings = handover.Options.model_validate({'chats':[-1001], 'purpose':'Privacy check',
                                                     'text':'none', 'others':'pseudonymize'})
        archive, _ = handover.export(store, vault, settings, options)
        with zipfile.ZipFile(archive) as bundle:
            html = bundle.read('report.html')
            assert b'PRIVATE_' not in html
            standalone = tmp_path / 'handover.html'
            standalone.write_bytes(html)
            verify_report(standalone, fingerprint(vault.public_key))
    finally:
        store.close()


def test_preview_preserves_analytics_anchor_without_scripts_or_styles():
    fragment = '<section id="summary" class="hero"><h1>Actual case</h1></section><section id="report-analytics"><h2>Activity</h2></section>'
    result = report_layouts.preview(fragment, 'ledger_margin', report.Words('en'))
    assert 'id="report-analytics"' in result and 'ledger-margin-chapter' in result
    assert '<script' not in result and '<style' not in result and 'style=' not in result


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_case_board_survives_composition_in_signed_html_and_pdf(tmp_path, monkeypatch, design):
    from tgwitness import board
    from tools.test_case_board import ADMIN, bookmark
    from tgwitness.verify import verify_bundle
    from tools.test_independent_report_pdf import capture_documents

    documents = capture_documents(monkeypatch)
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        source = store.append('message.new', {'text': 'Source observation for review'}, -1001, 1)
        bookmark(board.Board(store), source, ADMIN, title='Saved observation', note='Investigator interpretation')
        options = report.resolved() | {'language': 'en', 'design': design, 'case_board': 'bookmarks'}
        archive = evidence.export_file(store, vault, 'zip', options)
        assert verify_bundle(archive, fingerprint(vault.public_key))['report_pdf']
        with zipfile.ZipFile(archive) as bundle:
            html = bundle.read('report.html').decode('utf-8')
            assert html.count('id="case-board"') == 1
            assert 'Investigator interpretation' in html
            assert 'Team notes and bookmarks' in html
            text = '\n'.join(line for document in documents for line in document.reading_lines)
            assert 'Investigator interpretation' in text and 'Team notes and bookmarks' in text
    finally:
        store.close()


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_question_precedes_disclosed_case_notes_without_duplicate_heading(design):
    say = report.Words('en')
    options = {'case_title': 'Actual title', 'case_id': 'CASE-42', 'notes': 'All notes preserved'}
    fragment = report.case_section(say, 1, options, []) + report.report_charts.examination_html(
        {'question': 'What changed?', 'method': 'Compare preserved versions'}, say)
    html = report_layouts.preview(fragment, design, say)
    assert html.count('What changed?') == 1
    assert html.index('What changed?') < html.index('All notes preserved')
    assert 'class="layout-case-details"' in html and 'CASE-42' in html and 'Actual title' in html
    assert 'Compare preserved versions' in html and 'id="examination"' in html
    case = html.split('id="case">', 1)[1].split('</section>', 1)[0]
    assert '<h2' not in case
