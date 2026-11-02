"""Independent account layouts preserve disclosure boundaries and stream large exports."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import account_report, report_layouts
from tools.check_account_reports import Document, MESSAGE


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
@pytest.mark.parametrize('language', ('en', 'ar'))
def test_account_reports_use_selected_composition_and_safe_references(design, language):
    context = {'report_language': language, 'presentation': {'design': design},
               'counts': {'messages': 2}, 'fingerprint': 'a' * 64,
               'coverage': {'inventory_complete': True, 'tasks_total': 1, 'tasks_done': 1, 'failures': 0},
               'complete_within_scope': True}
    chats = [{'id': -42, 'title': MESSAGE, 'message_count': 2}]
    rows = [{'id': 7, 'text': MESSAGE, 'date': '2026-10-12T12:00:00Z'},
            {'id': 8, 'text': 'Second observation', 'edit_date': '2026-10-12T13:00:00Z'}]
    index = b''.join(account_report.account_index(context, iter(chats))).decode()
    chat = b''.join(account_report.account_chat(context, chats[0], iter(rows))).decode()
    for html in (index, chat):
        parsed = Document(html)
        assert parsed.root['data-report-design'] == design
        assert parsed.root['dir'] == ('rtl' if language == 'ar' else 'ltr')
        assert ('reading-series-shell' if design == 'reading_series' else 'ledger-margin-folio') in html
        assert 'chapter-assurance' in parsed.ids and 'chapter-scope' in parsed.ids
        assert '&lt;img' in html and '<img' not in html
    assert 'chats/-42.html' in Document(index).links
    assert 'chats/-42.html#record-000002' in chat
    assert '2026-10-12T13:00:00Z' in chat
    assert (chat.index('id="chapter-journal"') < chat.index('id="chapter-assurance"')) == (design == 'reading_series')


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_sharing_composition_never_restores_original_private_fields(design):
    context = {'report_language': 'en', 'presentation': {'design': design},
               'policy': {'purpose': 'Review', 'sender_ids': ['SECRET_FILTER'], 'text_contains': ['SECRET_TERM'],
                          'mapping': 'SECRET_MAPPING', 'include_media': False},
               'requested_at': 'SECRET_REQUEST', 'captured_from': 'SECRET_CAPTURE',
               'options': {'transport': 'SECRET_METHOD'}, 'counts': {'messages': 1},
               'fingerprint': 'a' * 64, 'source_archive_sha256': 'b' * 64}
    rows = [{'before': 'SECRET_SOURCE', 'chat': {'title': 'Public name', 'raw': 'SECRET_CHAT'},
             'message': {'text': MESSAGE, 'sender': 'Participant 1', 'id': 'copy-1',
                         'forward': {'name': 'SECRET_FORWARD'}, 'reply': 'SECRET_REPLY',
                         'attachments': [{'outcome': 'saved', 'file': 'javascript:SECRET_URI'}]}}]
    output = b''.join(account_report.sharing_report(context, iter(rows))).decode()
    parsed = Document(output)
    assert 'SECRET' not in output
    assert 'record-000001' in parsed.ids and 'chapter-journal' in parsed.ids
    assert '<p class="message-text" dir="auto">UNCHANGED' in output
    assert 'index.html#record-000001' in output


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_transcript_does_not_materialize_message_iterator(design):
    consumed = []

    def rows():
        for n in range(200):
            consumed.append(n)
            yield {'id': n + 1, 'text': 'A complete observation ' * 100}

    stream = account_report.account_chat({'presentation': {'design': design}}, {'id': -42}, rows())
    next(stream)
    assert not consumed
    delivered = 0
    for chunk in stream:
        if b'<article class="message"' in chunk:
            delivered += 1
            assert len(consumed) == delivered, 'Message source was consumed ahead of the streamed output'
    assert delivered == 200


@pytest.mark.parametrize('design', sorted(report_layouts.DESIGNS))
def test_no_empty_activity_chapter_when_all_charts_are_off(design):
    context = {'presentation': {'design': design, 'activity_chart': False, 'hourly_chart': False,
        'participant_chart': False, 'chat_chart': False, 'composition_chart': False}}
    html = b''.join(account_report.account_chat(context, {'id': 1}, iter(()))).decode()
    assert 'chapter-activity' not in Document(html).ids


def test_legacy_null_presentation_remains_readable():
    html = b''.join(account_report.account_chat({'presentation': None}, {'id': 1}, iter(()))).decode()
    assert Document(html).root['data-template'] == 'dossier'


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
