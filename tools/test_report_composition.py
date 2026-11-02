import copy
import hashlib
import json
from pathlib import Path
import sys
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import evidence, handover, report, report_charts
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle, verify_handover, verify_report


def test_chart_periods_retain_empty_intervals():
    rows = [{'period':'2026-01-01','counts':{'new':2},'total':2},
            {'period':'2026-01-31','counts':{'snapshot':3},'total':3}]
    result = report_charts.activity_bins(rows)
    assert len(result)==31 and result[15]['total']==0
    assert sum(r['total'] for r in result)==5
    compact = report_charts.activity_bins(rows,maximum=3)
    assert len(compact)==3 and sum(r['total'] for r in compact)==5
    assert sum(r['counts']['snapshot'] for r in compact)==3
    months = [{'period':'2025-12','counts':{'new':2},'total':2},
              {'period':'2026-02','counts':{'new':3},'total':3}]
    assert [r['period'] for r in report_charts.activity_bins(months)]==['2025-12','2026-01','2026-02']


@pytest.mark.parametrize('field',['review_question','review_method','review_findings','review_conclusion'])
def test_examination_fields_reject_control_characters(field):
    assert getattr(report.ReportOptions(**{field:'A\r\nB'}),field)=='A\nB'
    with pytest.raises(ValidationError):
        report.ReportOptions(**{field:'A\u202eB'})


def test_selected_material_cannot_leak_into_handover():
    analytics=report.report_analytics.Analytics()
    analytics.add({'kind':'message.new','payload':{'sender_id':913321},'seq':1,
                   'observed_at':'2026-11-01T01:00:00Z','chat_id':-1001})
    context={'kind':'evidence','options':{'review_findings':'PRIVATE FINDING'},'digest':{'analytics':analytics.result()}}
    assert report.report_material(context)['examination']['findings']=='PRIVATE FINDING'
    assert report.report_material({**context,'handover':{'counts':{}}})=={}
    assert report.report_material({**context,'kind':'handover'})=={}
    assert 'PRIVATE FINDING' not in json.dumps(report.case_of(context['options']))
    assert '913321' not in json.dumps(report.report_material(context)['analytics'])
    explicit=report.report_material({**context,'options':{'participant_labels':'ids'}})['analytics']
    assert explicit['participant_labels']=='ids' and '913321' in json.dumps(explicit)


def test_signed_composition_and_original_bytes(tmp_path):
    vault, store=Vault(tmp_path),Store(tmp_path)
    store.bind(vault)
    try:
        for kind in ('message.new','message.snapshot','message.edited','message.deleted','collector.heartbeat'):
            store.append(kind,{'text':'Original text','sender_id':913321},-1001,1,913321)
        options={**report.resolved(),'timeline':False,'review_question':'Did the recorded version change?',
                 'review_findings':'<img src=x onerror=alert(1)>\nSee records #1 and #3.',
                 'review_conclusion':'PRIVATE FINDING'}
        archive=evidence.export_file(store,vault,'zip',options)
        pin=fingerprint(vault.public_key)
        assert verify_bundle(archive,pin)['key_pinned']
        with zipfile.ZipFile(archive) as bundle:
            original=bundle.read('events.jsonl')
            payload=json.loads(bundle.read('report.json'))
            data=payload['report']
            assert data['analytics']['source']['sha256']==hashlib.sha256(original).hexdigest()
            assert data['analytics']['activity_events']==4
            assert data['analytics']['message_observations']==2
            assert data['examination']['author']=='operator'
            html=bundle.read('report.html').decode()
            assert '<img src=x' not in html and '&lt;img src=x' in html
            assert 'class="analytics-print-data"' in html
            path=tmp_path/'report.json'
            path.write_bytes(bundle.read('report.json'))
            verify_report(path,pin)
            forged=copy.deepcopy(payload)
            forged['report']['analytics']['totals']['new']=9000
            path.write_text(json.dumps(forged),encoding='utf-8')
            with pytest.raises((ValueError,InvalidSignature)):
                verify_report(path,pin)
        flags={key:False for key in ('activity_chart','hourly_chart','participant_chart','chat_chart','composition_chart')}
        without=evidence.export_file(store,vault,'zip',{**options,**flags})
        with zipfile.ZipFile(without) as bundle:
            assert bundle.read('events.jsonl')==original
            assert 'analytics' not in json.loads(bundle.read('report.json'))['report']
            assert 'id="report-analytics"' not in bundle.read('report.html').decode()
        selection=handover.Options.model_validate({'chats':[-1001], 'purpose':'Synthetic privacy check'})
        minimized,_=handover.export(store,vault,selection,options)
        assert verify_handover(minimized,pin)['key_pinned']
        with zipfile.ZipFile(minimized) as bundle:
            for name in bundle.namelist():
                assert b'PRIVATE FINDING' not in bundle.read(name), name
            assert 'analytics' not in json.loads(bundle.read('report.json'))['report']
    finally:
        store.close()


def test_hidden_histories_and_indicators_keep_the_source(tmp_path):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        store.append('message.new', {'text': 'https://example.org/original', 'sender_id': 913321}, -1001, 1)
        store.append('message.edited', {'text': 'https://example.org/revised', 'sender_id': 913321}, -1001, 1)
        original = sorted(store.events(), key=lambda row: row['seq'])
        options = {**report.resolved(), 'timeline': False, 'show_changes': False, 'show_indicators': False}
        hidden = evidence.export_file(store, vault, 'zip', options)
        with zipfile.ZipFile(hidden) as bundle:
            html = bundle.read('report.html').decode()
            assert 'id="changes"' not in html and 'id="indicators"' not in html
            assert [json.loads(line) for line in bundle.read('events.jsonl').splitlines()] == original
        shown = evidence.export_file(store, vault, 'html', {**options, 'show_changes': True, 'show_indicators': True})
        html = shown.read_text(encoding='utf-8')
        assert 'id="changes"' in html and 'id="indicators"' in html
    finally:
        store.close()


if __name__=='__main__':
    raise SystemExit(pytest.main([__file__,'-q']))
