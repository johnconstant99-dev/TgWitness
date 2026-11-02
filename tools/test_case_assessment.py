import copy
import json
from pathlib import Path
import sys
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import case_assessment as assessment, evidence, report
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, verify_bundle, verify_report


def checks(value):
    return {r['id']: r for r in value['checks']}


def test_receipt_presence_is_not_verification():
    anchor = {'kind':'rfc3161','event_count':4,'time':'2026-11-01T00:00:00Z','file':'anchors/proof.tsr',
              'checkpoint_bound':True,'signed':{'root_sha256':'a'*64}}
    context = {'event_count':10,'journal_verified':True,'anchors':[anchor]}
    good = checks(assessment.journal(context, {}))['time']
    assert good['status']=='checked_locally' and good['facts']['unanchored_tail']==6
    assert report.latest_stamp([anchor]) is anchor
    assert checks(assessment.journal(context, {}))['time']['result']['values']=={'n':4,'tail':6}
    for patch in ({'signed':None}, {'signed':True}, {'signed':{}}, {'checkpoint_bound':False},
                  {'kind':'opentimestamps'}, {'kind':'unreadable'}, {'event_count':True}, {'event_count':11}, {'time':''},
                  {'time':'not-a-date'},{'time':'2026-11-01T00:00:00'},{'signed':{'root_sha256':'not-a-root'}}):
        bad = {**anchor, **patch}
        value = checks(assessment.journal({**context, 'anchors':[bad]}, {}))['time']
        assert value['status']!='checked_locally' and value['facts']['verified_stamps']==0, patch
        assert 'unanchored_tail' not in value['facts']
    partial = checks(assessment.journal({**context,'anchors':[anchor,{**anchor,'signed':None}]}, {}))['time']
    assert partial['facts']['verified_stamps']==1 and partial['facts']['other_stamps']==1
    assert checks(assessment.journal({}, {}))['integrity']['status']=='not_checked'
    assert assessment.journal({}, {})['supporting_files_included'] is False


def test_checkpoint_belongs_to_exact_journal(tmp_path, monkeypatch):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    store.append('message.new',{'text':'Synthetic observation'},-1001,1)
    point = evidence.checkpoint(store, vault)
    monkeypatch.setattr(report,'timestamp_reply_summary',lambda *a:{'time':'2026-11-01T00:00:00Z'})
    monkeypatch.setattr(report,'timestamp_signature',lambda *a:{'signer':'Synthetic TSA','root_sha256':'a'*64})
    def describe(value, key=None, hash_at=None):
        return report.describe_anchor('checkpoint-000000000001.json',canonical(value),'checkpoint-000000000001.test.tsr',b'synthetic',
            public_key=key or vault.public_key,event_count=1,hash_at=hash_at or (lambda seq:point['statement']['head_hash']))
    assert assessment.verified_stamp(describe(point),1)
    wrong = copy.deepcopy(point)
    wrong['statement']['head_hash']='0'*64
    assert not assessment.verified_stamp(describe(wrong),1)
    assert not assessment.verified_stamp(describe(point,hash_at=lambda seq:'0'*64),1)
    other=Vault(tmp_path/'other')
    assert not assessment.verified_stamp(describe(point,key=other.public_key),1)
    monkeypatch.setattr(report,'timestamp_signature',lambda *a:(_ for _ in ()).throw(ValueError('untrusted root')))
    bad=describe(point)
    assert bad['signed'] is None and report.latest_stamp([bad]) is None
    store.close()


def test_missing_coverage_and_redaction_cannot_claim_completeness():
    context={'event_count':50,'digest':{'trust_signals':{'drand':3,'starts':2,'tdx':1}},
             'handover':{'counts':{'unchanged':2,'minimised':1,'left_out':47}}}
    rows=checks(assessment.journal(context,{'gaps':[{'reason':'offline'}], 'continuous':[],
                                           'unobserved_ids':[{'not_observed':12}]}))
    assert rows['coverage']['facts']=={'gaps':1,'periods':0,'unobserved':12,'unchanged':2,'minimised':1,'left_out':47}
    assert rows['witness']['status']=='not_checked' and rows['witness']['facts']['tdx']==1
    assert rows['time']['status']=='not_included'
    complete={'complete_within_scope':True,'coverage':{'inventory_complete':True,'tasks_done':3,'tasks_total':3,'failures':0}}
    assert checks(assessment.snapshot(complete))['scope']['facts']['complete'] is True
    for patch in ({'failures':1},{'failures':False},{'tasks_done':2},{'inventory_complete':False}):
        assert checks(assessment.snapshot({**complete,'coverage':{**complete['coverage'],**patch}}))['scope']['facts']['complete'] is False


def test_sharing_assessment_does_not_disclose_source_or_private_fields():
    context={'archive_reference':'public-copy','counts':{'messages':2}, 'source_archive_sha256':'SECRET_SOURCE',
             'captured_from':'SECRET_DATE','options':{'examiner':'SECRET_EXAMINER'},
             'policy':{'sender_ids':['SECRET_FILTER'],'identity_map':'SECRET_MAP'},
             'coverage':{'failures':'SECRET_COVERAGE','tasks_done':'SECRET_DONE','tasks_total':'SECRET_TOTAL'},'account':{'id':'SECRET_ACCOUNT'}}
    result=assessment.snapshot(context,'sharing')
    assert 'SECRET' not in json.dumps(result)
    assert result['reference']=='public-copy' and result['independent_review']=='not_performed'
    assert checks(result)['custody']['facts']['operator_fields']==0
    rendered=assessment.html(assessment.snapshot({'fingerprint':'<img src=x onerror=alert(1)>'}),report.Words('en'))
    assert '<img' not in rendered and '&lt;img' in rendered


def test_assessment_translations():
    for lang in ('ru','de'):
        say=report.Words(lang)
        for text in assessment.text_keys():
            assert say(text)!=text, (lang,text)


def test_signed_reports_and_pdf_tampering(tmp_path):
    vault, store=Vault(tmp_path),Store(tmp_path)
    store.bind(vault)
    store.append('message.new',{'text':'Synthetic case record','sender_id':44},-1001,1,44)
    options={**report.resolved(),'language':'ru','case_id':'SYNTHETIC-CASE-01','examiner':'Synthetic operator','timeline':False}
    bundle=evidence.export_file(store,vault,'zip',options)
    pin=fingerprint(vault.public_key)
    verified=verify_bundle(bundle,pin)
    assert verified['key_pinned'] and verified['report_pdf']
    output=ROOT/'test-results'/'case-assessment'
    output.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(bundle) as archive:
        manifest=json.loads(archive.read('manifest.json'))
        data=json.loads(archive.read('report.json'))
        value=data['report']['case_assessment']
        assert value==manifest['case_assessment']
        assert value['supporting_files_included'] is True
        assert checks(value)['integrity']['status']=='checked_locally'
        assert checks(value)['time']['status']=='not_included'
        for name in ('report.json','report.html','report.pdf'):
            raw=archive.read(name)
            path=tmp_path/name;path.write_bytes(raw)
            verify_report(path,pin)
            with pytest.raises(ValueError, match='fingerprint'):
                verify_report(path,'0'*64)
            (output/name).write_bytes(raw)
            if name.endswith('.pdf'):
                assert b'/Type /Catalog' in raw
                changed=raw.replace(b'/Type /Catalog',b'/Type /Cataloq',1)
            elif name.endswith('.json'):
                forged=copy.deepcopy(data)
                forged['report']['case_assessment']['independent_review']='performed'
                changed=json.dumps(forged,ensure_ascii=False).encode()
            else:
                assert assessment.TITLE not in raw.decode()
                changed=raw.replace('Основания доверия'.encode(),'Ложное заключение'.encode(),1)
            assert changed!=raw
            path.write_bytes(changed)
            with pytest.raises((ValueError, InvalidSignature)):
                verify_report(path,pin)
    store.close()


if __name__=='__main__':
    raise SystemExit(pytest.main([__file__,'-q']))
