import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import evidence, report, report_selection
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle, verify_report
from tools.check_session_reservations import workspace


def seed(store):
    with patch('tgwitness.store.utcnow', return_value='2026-11-01T12:00:00Z'):
        store.append('collector.started', {'synthetic': True})
        store.append('message.new', {'text': 'SELECTED content', 'sender_id': 11}, -1001, 10)
        store.append('message.new', {'text': 'Other author', 'sender_id': 22}, -1001, 11)
        store.append('message.new', {'text': 'Neighbor after hole', 'sender_id': 11}, -1001, 15)
        store.append('message.deleted', {}, -1001, 14)
        store.append('message.new', {'text': 'OTHER CHAT content', 'sender_id': 33}, -1002, 99)
        store.append('message.edited', {'text': 'Revised selected content', 'sender_id': 11}, -1001, 10)
    with patch('tgwitness.store.utcnow', return_value='2026-11-02T12:00:00Z'):
        store.append('message.new', {'text': 'OUTSIDE DATES', 'sender_id': 11}, -1001, 12)
        store.append('collector.heartbeat', {})


def choices():
    return report.ReportOptions(selection={'enabled': True, 'chats': [-1001], 'senders': [11],
        'date_from': '2026-11-01', 'date_to': '2026-11-01', 'id_gaps': True}).model_dump() | {'language': 'en'}


def test_selected_archive_has_full_source_and_filtered_report(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        seed(store)
        options = choices()
        with store.snapshot() as snapshot:
            expected = report_selection.analyze(snapshot, report_selection.Selection(**options['selection']))
        archive = evidence.export_file(store, vault, 'zip', options)
        pin = fingerprint(vault.public_key)
        assert verify_bundle(archive, pin)['key_pinned']
        with zipfile.ZipFile(archive) as bundle:
            assert 'report.pdf' in bundle.namelist(), 'The installed PDF renderer must produce the signed PDF'
            original = bundle.read('events.jsonl')
            assert b'OTHER CHAT content' in original and len(original.splitlines()) == 9
            data = json.loads(bundle.read('report.json'))['report']
            assert data['selection']['counts'] == expected['counts']
            assert data['selection']['counts']['selected_records'] == 3
            assert data['selection']['id_gaps']['ids_total'] == 1
            assert data['selection']['id_gaps']['rows'][0]['start'] == 13
            assert data['summary']['chats'] == 1 and data['analytics']['activity_events'] == 3
            assert data['analytics']['message_observations'] == 2
            assert data['subject']['event_count'] == 9
            assert data['analytics']['source']['sha256'] == hashlib.sha256(original).hexdigest()
            assert data['custody']['acquisition']['record_count'] == 9
            assert data['custody']['export']['report_options']['selection'] == options['selection']
            assert all(item['chat_id'] == -1001 for item in data['chats'])
            viewer = b''.join(bundle.read(name) for name in bundle.namelist() if name.startswith('viewer/') and name.endswith('.html'))
            assert b'SELECTED content' in viewer and b'Other author' not in viewer
            assert b'OTHER CHAT content' not in viewer and b'OUTSIDE DATES' not in viewer
            html = bundle.read('report.html').decode()
            assert 'Selected data' in html and 'Unobserved message IDs' in html
            assert 'This report selects 3 records' in html
            for name in ('report.html', 'report.json', 'report.pdf'):
                if name not in bundle.namelist():
                    continue
                standalone = tmp_path / name
                standalone.write_bytes(bundle.read(name))
                verify_report(standalone, pin)
            manifest = json.loads(bundle.read('manifest.json'))
            assert manifest['event_count'] == 9 and manifest['report']['selected_records'] == 3
    finally:
        store.close()


def test_empty_and_gap_disabled_reports(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        seed(store)
        options = choices()
        options['selection'].update(senders=[999], id_gaps=False)
        path = evidence.export_file(store, vault, 'html', options)
        text = path.read_text(encoding='utf-8')
        assert 'No records match this selection.' in text
        assert 'id="report-selection"' in text and '<h3>Unobserved message IDs</h3>' not in text
        verify_report(path, fingerprint(vault.public_key))
        options['selection']['senders'] = [11]
        json_path = evidence.export_file(store, vault, 'json', options)
        data = json.loads(json_path.read_text(encoding='utf-8'))
        assert not data['report']['selection']['id_gaps']['enabled']
        original = copy.deepcopy(data)
        data['report']['selection']['selection']['senders'] = [999]
        json_path.write_text(json.dumps(data), encoding='utf-8')
        with pytest.raises(Exception):
            verify_report(json_path, fingerprint(vault.public_key))
        assert original['report']['selection']['selection']['senders'] == [11]
    finally:
        store.close()


def test_preview_is_scoped_read_only_and_requires_export_access():
    async def check():
        async with workspace() as (app, client):
            seed(app.state.store)
            previous = app.state.store.get_setting('report_options', None)
            result = await client.post('/api/report-preview', json=choices())
            assert result.status_code == 200, result.text
            data = result.json()
            design = await client.post('/api/report-design-preview', json=choices())
            assert design.status_code == 200, design.text
            assert design.json()['records'] == 3 and not design.json()['sampled']
            assert 'NOT SIGNED' in design.json()['html']
            assert 'Chat -1002' not in design.json()['html']
            assert data['unsigned'] and data['counts']['selected_records'] == 3
            assert data['id_gaps']['ids_total'] == 1
            assert app.state.store.get_setting('report_options', None) == previous
            invalid = choices()
            invalid['selection']['date_to'] = '2026-10-01'
            assert (await client.post('/api/report-preview', json=invalid)).status_code == 422
            assert (await client.post('/api/report-preview?ws=../other', json=choices())).status_code == 404
            from tgwitness.access import POLICY, Refused, check as check_access
            from types import SimpleNamespace
            principal = SimpleNamespace(admin=False, opens=lambda _: True, may=lambda _: True,
                                        chats=lambda _: [-1001])
            with pytest.raises(Refused):
                check_access(principal, 'default', POLICY['POST /api/report-preview'], {})
            with pytest.raises(Refused):
                check_access(principal, 'default', POLICY['POST /api/report-design-preview'], {})
            principal.chats = lambda _: None
            principal.may = lambda permission: permission == 'view'
            with pytest.raises(Refused):
                check_access(principal, 'default', POLICY['POST /api/report-preview'], {})
    asyncio.run(check())


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
