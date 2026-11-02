"""Message times and reply context remain readable without reviving withheld fields."""
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest
from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, handover, report, report_history, viewer
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_report
from tools.check_browser import launch_browser


SENT = '2026-10-12T09:01:00Z'
EDITED = '2026-10-12T09:05:00Z'
OBSERVED = '2026-10-12T09:06:00Z'
SAY = report.Words('en')


def record(payload, *, seq=1, kind='message.new', chat=-1001, message=33):
    return {'seq': seq, 'kind': kind, 'chat_id': chat, 'message_id': message, 'actor_id': None,
            'hash': str(seq) * 64, 'observed_at': OBSERVED, 'source_at': None, 'payload': payload}


def payload(**extra):
    return {'text': 'Fictional saved text', 'sender_id': 101, 'sent_at': SENT, 'edited_at': None, **extra}


def test_journal_projection_keeps_three_independent_times_and_input_unchanged():
    event = record(payload(edited_at=EDITED), kind='message.edited')
    original = copy.deepcopy(event)
    item = viewer.journal_item(event)
    assert (item['sent_at'], item['edited_at'], item['t']) == (SENT, EDITED, OBSERVED)
    assert item['tt'] == SENT  # legacy clients can still read the original send time
    assert 'r' not in item and event == original
    html = report.record_html(event, SAY, {}, {'raw_records': False}, False)
    for label, time in (('Sent', SENT), ('Edited', EDITED)):
        assert f'{label} <time datetime="{time}"' in html
    assert f'Observed <time datetime="{OBSERVED}"' in html


def test_ordinary_record_has_no_invented_edit_time():
    item = viewer.journal_item(record(payload()))
    assert item['sent_at'] == SENT and item['edited_at'] is None
    html = report.record_html(record(payload()), SAY, {}, {}, False)
    assert 'Edited <time' not in html


def test_malformed_timestamp_text_cannot_inject_html_attributes_or_scripts():
    unsafe = '\"><script>window.__recordXss=true</script>'
    event = record(payload(sent_at=unsafe, edited_at=unsafe), kind='message.edited')
    html = report.record_html(event, SAY, {}, {}, False)
    history = report.message_histories([event], {(-1001, 33)})[(-1001, 33)]
    html += report.history_card(SAY, (-1001, 33), history, {})
    assert '&lt;script&gt;' in html and '<script>' not in html


def test_legacy_payload_date_is_preserved_without_using_raw_time():
    item = viewer.journal_item(record({'date': SENT, 'raw': {'date': 'RAW_DATE', 'edit_date': 'RAW_EDIT'}}))
    assert item['sent_at'] == item['tt'] == SENT and item['edited_at'] is None
    assert 'RAW_' not in json.dumps(item)


@pytest.mark.parametrize('missing', [None, False, '', 0])
def test_explicit_missing_time_does_not_resurrect_date_or_raw(missing):
    item = viewer.journal_item(record(payload(sent_at=missing, edited_at=missing, date='HIDDEN_LEGACY',
                                             raw={'date': 'HIDDEN_RAW', 'edit_date': 'HIDDEN_EDIT'})))
    assert item['sent_at'] is None and item['edited_at'] is None and 'tt' not in item
    assert 'HIDDEN_' not in json.dumps(item)


@pytest.mark.parametrize('fields', [{}, {'sent_at': None}, {'edited_at': None},
                                   {'sent_at': None, 'edited_at': None}])
def test_record_source_time_fallback_requires_absent_message_time_fields(fields):
    event = record({'text': 'Fictional saved text', **fields})
    event['source_at'] = SENT
    html = report.record_html(event, SAY, {}, {'raw_records': False}, False)
    if fields:
        assert 'Telegram time' not in html and SENT not in html
    else:
        assert f'Telegram time <time datetime="{SENT}"' in html
    assert f'Observed <time datetime="{OBSERVED}"' in html


@pytest.mark.parametrize('collect', [report.message_histories, report_history.collect])
def test_history_retains_send_edit_times_and_metadata_only_edit(collect):
    events = [record(payload()), record(payload(edited_at=EDITED), seq=2, kind='message.edited')]
    item = collect(events, {(-1001, 33)})[(-1001, 33)]
    assert [version['seq'] for version in item['versions']] == [1, 2]
    assert [version['sent_at'] for version in item['versions']] == [SENT, SENT]
    assert [version['edited_at'] for version in item['versions']] == [None, EDITED]
    assert [version['telegram_at'] for version in item['versions']] == [SENT, EDITED]
    html = report.history_card(SAY, (-1001, 33), item, {})
    assert f'Sent <time datetime="{SENT}"' in html and f'Edited <time datetime="{EDITED}"' in html
    assert 'Telegram time' not in html


def test_old_history_format_falls_back_only_when_new_fields_absent():
    item = report.message_histories([record(payload())], {(-1001, 33)})[(-1001, 33)]
    version = item['versions'][0]
    del version['sent_at'], version['edited_at']
    assert 'Telegram time' in report.history_card(SAY, (-1001, 33), item, {})
    version.update(sent_at=None, edited_at=None)
    assert 'Telegram time' not in report.history_card(SAY, (-1001, 33), item, {})


def test_history_preview_preserves_time_distinctions():
    item = report_history.preview([record(payload(edited_at=EDITED), kind='message.edited')],
                                  [(-1001, 33)], predicate=lambda _: True)[0]['versions'][0]
    assert (item['sent_at'], item['edited_at'], item['observed_at']) == (SENT, EDITED, OBSERVED)


def reply_payload():
    return payload(reply_to_message_id=22, raw={'reply_to': {
        'reply_to_msg_id': 22, 'reply_to_top_id': 2, 'forum_topic': False,
        'reply_to_peer_id': {'_': 'PeerChannel', 'channel_id': 789},
        'quote_text': 'quoted <script>window.__recordXss=true</script>', 'quote_offset': 0,
        'quote_entities': [{'_': 'MessageEntityTextUrl', 'offset': 0, 'length': 6,
                            'url': 'javascript:window.__recordXss=true'}]}})


def test_reply_thread_quote_and_false_flag_are_visible_and_escaped():
    source = reply_payload()
    original = copy.deepcopy(source)
    details = report.shown_details(source)
    assert details['reply_to_message_id'] == 22 and details['reply_to_top_id'] == 2
    assert details['reply_to_peer_id'] == -1000000000789
    assert details['forum_topic'] is False and details['quote_offset'] == 0
    html = report.details_html(SAY, details)
    for text in ('Reply to #22', 'Reply thread #2', 'Chat of the original message -1000000000789', 'Forum topic: No',
                 'Quote offset (UTF-16): 0', '&lt;script&gt;', 'javascript:window.__recordXss=true'):
        assert text in html
    assert '<script>' not in html and 'href="javascript:' not in html
    assert viewer.journal_item(record(source))['d'] == details
    assert source == original


@pytest.mark.parametrize('value', [None, False])
def test_reply_nulls_and_booleans_do_not_become_message_or_thread_ids(value):
    details = report.shown_details(payload(reply_to_message_id=value, raw={'reply_to': {
        'reply_to_msg_id': 999, 'reply_to_top_id': value, 'quote_offset': value,
        'reply_to_peer_id': {'_': 'PeerChannel', 'channel_id': value}}}))
    assert not set(report.REPLY_DETAILS_KEYS).intersection(details)


@pytest.mark.parametrize('details', [{}, None, [], False])
def test_explicit_projection_blocks_private_raw_reply_and_root_fallback(details):
    source = reply_payload() | {'details': details}
    event = record(source, kind='message.edited')
    assert report.shown_details(source) == {}
    assert 'd' not in viewer.journal_item(event)
    history = report.message_histories([event], {(-1001, 33)})[(-1001, 33)]
    html = report.record_html(event, SAY, {}, {'raw_records': False}, False)
    html += report.history_card(SAY, (-1001, 33), history, {})
    assert 'quoted' not in html and 'Reply to' not in html and 'window.__recordXss' not in html


def test_real_minimized_handover_never_resurrects_hidden_quote_or_sender():
    event = record(reply_payload() | {'sender_observation': {'id': 101, 'display_name': 'PRIVATE_SENDER'}})
    minimizer = handover.Minimiser(handover.Options(purpose='Review only', chats=[-1001], text='none'), None, {})
    minimized = minimizer.present(event)
    assert minimized['payload']['text_withheld'] and 'raw' not in minimized['payload']
    projected = viewer.journal_item(minimized)
    html = report.record_html(minimized, SAY, {}, {'raw_records': False}, False)
    for hidden in ('PRIVATE_SENDER', 'quoted', 'window.__recordXss'):
        assert hidden not in json.dumps(projected) and hidden not in html
    assert projected['sent_at'] == SENT and projected['a'] == 'P01'


def test_reply_only_change_is_not_deduplicated():
    events = [record(payload(reply_to_message_id=22)),
              record(payload(reply_to_message_id=23), seq=2, kind='message.snapshot')]
    for collect in (report.message_histories, report_history.collect):
        history = collect(events, {(-1001, 33)})[(-1001, 33)]
        assert len(history['versions']) == 2
        html = report.history_card(SAY, (-1001, 33), history, {})
        assert 'Reply to #22' in html and 'Reply to #23' in html


def test_signed_viewer_displays_times_cross_chat_reply_and_safe_quote(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        with patch('tgwitness.store.utcnow', return_value=OBSERVED):
            store.append('message.new', payload(text='Correct reply target'), -1000000000789, 22)
            store.append('message.new', payload(text='Other chat with same number'), -1001, 22)
            store.append('message.edited', reply_payload() | {'edited_at': EDITED}, -1001, 33)
            store.append('message.new', reply_payload() | {'details': {}, 'sent_at': None,
                         'date': 'HIDDEN_DATE', 'text': 'Approved reading copy'}, -1001, 34)
        document = evidence.export_file(store, vault, 'html', report.resolved() | {'language': 'en', 'raw_records': False})
        destination = tmp_path / 'report.html'
        destination.write_bytes(document.read_bytes())
        verify_report(destination, fingerprint(vault.public_key))
        with sync_playwright() as playwright:
            browser = launch_browser(playwright)
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(destination.as_uri())
            page.locator('.tabs [data-view=data]').click()
            expect(page.locator('#v-count')).to_contain_text('4')
            page.locator('#v-list [data-key=r3]').click()
            facts = page.locator('#v-detail .d-list').inner_text()
            for label in ('Observed', 'Sent', 'Edited', 'Reply to', 'Chat of the original message', 'Reply thread', 'Quoted text'):
                assert label in facts
            assert '9:01:00' in facts and '9:05:00' in facts and '9:06:00' in facts
            assert 'earlier text not in this export' not in facts
            expect(page.locator('#v-detail a[data-goto=r1]')).to_be_visible()
            expect(page.locator('#v-detail a[data-goto=r2]')).to_have_count(0)
            expect(page.locator('#v-detail script, #v-detail a[href^="javascript:"]')).to_have_count(0)
            assert page.evaluate('window.__recordXss') is None
            page.locator('#v-detail [data-close]').click()
            page.locator('#v-list [data-key=r4]').click()
            facts = page.locator('#v-detail .d-list').inner_text()
            assert 'Sent' not in page.locator('#v-detail .d-list dt').all_text_contents()
            assert 'Reply to' not in facts and 'Quoted text' not in facts and 'HIDDEN_DATE' not in facts
            assert not errors, errors
            browser.close()
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
