import asyncio
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit
import zipfile

import pytest
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness import case_assessment, evidence, jurisdiction_guidance as guide, report, report_design, report_profiles, report_studio
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_bundle, verify_report


def test_default_and_disabled_guidance_preserve_the_existing_assessment():
    before = case_assessment.journal({}, {})
    assert 'jurisdiction_guidance' not in before
    assert guide.build(report.ReportOptions().jurisdiction_guidance) is None
    for choice in ({'jurisdiction': ''}, {'jurisdiction': 'IN', 'include_in_report': False}):
        assert case_assessment.journal({'options': {'jurisdiction_guidance': choice}}, {}) == before
    for value in ({'jurisdiction': 'unknown'}, {'procedure': 'notarial'}, {'verified': True}):
        with pytest.raises(ValidationError):
            report.ReportOptions(jurisdiction_guidance=value)


@pytest.mark.parametrize('profile', guide.catalog()['profiles'], ids=lambda p: p['code'])
@pytest.mark.parametrize('procedure', ['civil', 'criminal'])
def test_catalog_routes_keep_sources_local_summary_and_research_status(profile, procedure):
    criminal = procedure == 'criminal'
    value = guide.build({'jurisdiction': profile['code'], 'procedure': procedure, 'local_note': True})
    assert value['status'] in ('research_draft', 'needs_local_review')
    assert value['law'] == profile['criminal_law' if criminal else 'law']
    assert value['sources'] == profile['criminal_sources' if criminal else 'sources']
    assert value['local_summary']['text'] == profile['local_criminal' if criminal else 'local']
    assert value['sources'] and value['basis'] and value['human'] and len(value['catalog_sha256']) == 64
    assert all(urlsplit(source['url']).scheme == 'https' for source in value['sources'])
    assert not criminal or not value['tasks']  # Never inherit civil formalities.
    assert 'research draft' in guide.html(value) or 'needs local review' in guide.html(value)


def test_choices_do_not_upgrade_facts_or_claim_safeguards_were_used():
    context = {'event_count': 5, 'digest': {'trust_signals': {'tdx': 1}}}
    expected = case_assessment.journal(context, {})
    choice = {'jurisdiction': 'US', 'include_methods': True}
    actual = case_assessment.journal({**context, 'options': {'jurisdiction_guidance': choice}}, {})
    assert actual['checks'] == expected['checks']
    assert actual['independent_review'] == 'not_performed'
    data = actual['jurisdiction_guidance']
    assert len(data['safeguards']) == 7
    assert 'does not mean a measure was used or verified' in guide.html(data)
    data['name'] = '<img src=x onerror=alert(1)>'
    assert '<img' not in guide.html(data) and '&lt;img' in guide.html(data)
    assert guide.build(choice)['name'] == 'United States'


def test_next_steps_use_the_exact_export_findings_without_mutating_them():
    assessment = case_assessment.journal({'journal_verified': True, 'event_count': 211},
                                       {'gaps': [{}, {}, {}, {}], 'unobserved_ids': [{'not_observed': 1}]})
    before = json.loads(json.dumps(assessment))
    review = guide.package_review(assessment)
    rows = {row['check']: row for row in review['items']}
    assert '211 signed journal records' in rows['integrity']['finding']
    assert 'Recorded gaps: 4' in rows['coverage']['finding']
    assert 'Message numbers not observed: 1' in rows['coverage']['finding']
    assert 'cannot restore continuous observation of the past' in rows['coverage']['action']
    assert 'cannot establish an earlier time bound' in rows['time']['action']
    assert 'does not certify earlier collection' in rows['witness']['action']
    assert 'Identify the collector' in rows['custody']['action']
    assert assessment == before
    assert not review['supporting_files_included']


def test_existing_receipts_and_partial_time_bounds_get_different_actions():
    pending = case_assessment.journal({'anchors': [{'kind': 'ots'}]}, {})
    action = next(row for row in guide.package_review(pending)['items'] if row['check'] == 'time')
    assert 'Validate the existing receipts' in action['action']
    context = {'event_count': 10, 'archive': True, 'anchors': [{
        'kind': 'rfc3161', 'checkpoint_bound': True, 'signed': {'root_sha256': 'a'*64},
        'time': '2026-11-06T00:00:00Z', 'event_count': 6}]}
    partial = guide.package_review(case_assessment.journal(context, {}))
    action = next(row for row in partial['items'] if row['check'] == 'time')
    assert '4 later records' in action['finding']
    assert 'covering the later records' in action['action']
    context['event_count'] = 6
    complete = guide.package_review(case_assessment.journal(context, {}))
    action = next(row for row in complete['items'] if row['check'] == 'time')
    assert 'covering the later records' not in action['action']
    assert 'Recheck checkpoint inclusion' in action['action']


def test_present_quotes_need_verification_and_preview_does_not_invent_findings():
    assessment = case_assessment.journal({'digest': {'trust_signals': {'tdx': 2, 'drand': 3}}}, {})
    review = guide.package_review(assessment)
    witness = next(row for row in review['items'] if row['check'] == 'witness')
    assert witness['status'] == 'not_checked' and 'starts carrying TDX: 2' in witness['finding']
    assert 'Independently verify' in witness['action']
    preview = guide.build({'jurisdiction': 'BR'})
    assert preview['package_review'] is None
    assert 'design preview does not verify' in guide.html(preview)
    assert 'What this copy needs next' not in guide.html(preview)


def test_saved_settings_are_not_layout_or_implicit_sharing_context(tmp_path):
    store = Store(tmp_path)
    try:
        options = report.ReportOptions(jurisdiction_guidance={'jurisdiction': 'IN', 'procedure': 'criminal'})
        report.save(store, options)
        assert report.saved(store) == options
        assert 'jurisdiction_guidance' not in report_profiles.LAYOUT_FIELDS
        with pytest.raises(ValidationError):
            report_profiles.Profile(name='Case leak', options={'jurisdiction_guidance': {'jurisdiction': 'IN'}})
        account = report_studio.presentation(options).model_dump()
        sharing = report_studio.presentation(options, include_guidance=False).model_dump()
        assert account['jurisdiction_guidance']['jurisdiction'] == 'IN'
        assert sharing['jurisdiction_guidance']['jurisdiction'] == ''
        assert 'jurisdiction_guidance' not in case_assessment.snapshot({'options': options.model_dump()}, 'sharing')
        assert 'jurisdiction_guidance' not in case_assessment.snapshot({'presentation': sharing}, 'sharing')
        assert case_assessment.snapshot({'presentation': account})['jurisdiction_guidance']['jurisdiction'] == 'IN'
        # An explicitly selected public profile can be included in a derivative.
        assert case_assessment.snapshot({'presentation': account}, 'sharing')['jurisdiction_guidance']['jurisdiction'] == 'IN'
    finally:
        store.close()


def test_api_permissions_workspace_isolation_and_export_inheritance(monkeypatch):
    from tools.check_prepared_export_access import grant_session
    from tools.check_session_reservations import workspace
    async def run():
        async with workspace() as (app, client):
            _, reader = grant_session(app, permissions=['view'])
            response = await client.get('/api/report-guidance', headers=reader)
            assert response.status_code == 200 and len(response.json()['profiles']) == 25
            assert (await client.get('/api/report-guidance', headers={'Authorization': 'Bearer invalid'})).status_code in (401, 403)
            options = {'jurisdiction_guidance': {'jurisdiction': 'CA', 'procedure': 'criminal'}}
            assert (await client.post('/api/report-options', json=options, headers=reader)).status_code == 403
            assert (await client.post('/api/report-options', json=options)).status_code == 200
            other = (await client.post('/api/profiles', json={'label': 'Separate synthetic case'})).json()['id']
            isolated = await client.get('/profiles/'+other+'/api/report-options')
            assert isolated.json()['jurisdiction_guidance']['jurisdiction'] == ''
            async def start(values):
                return values
            monkeypatch.setattr(app.state.account_export, 'start', start)
            monkeypatch.setattr(app.state.disclosures, 'preview', lambda export_id, values, owner: values)
            account = await client.post('/api/account-export/start', json={})
            assert account.status_code == 200, account.text
            assert account.json()['report_presentation']['jurisdiction_guidance']['jurisdiction'] == 'CA'
            sharing = await client.post('/api/account-export/synthetic/disclosure/preview', json={'purpose': 'Synthetic disclosure review'})
            assert sharing.status_code == 200, sharing.text
            assert sharing.json()['report_presentation']['jurisdiction_guidance']['jurisdiction'] == ''
    asyncio.run(run())


def test_local_pdf_summary_never_silently_loses_its_script(monkeypatch):
    from tgwitness import pdf_report
    monkeypatch.setattr(pdf_report, 'cjk_font', lambda: None)
    say = report.Words('en')
    pdf = pdf_report.document(say, 'SYNTHETIC font check')
    pdf.add_page()
    lay = pdf_report.Layout(pdf, say)
    for code in ('IN', 'SA'):
        guide.pdf(lay, guide.build({'jurisdiction': code, 'local_note': True}))
    assert pdf.output().startswith(b'%PDF-')
    pdf = pdf_report.document(say, 'SYNTHETIC missing font check')
    pdf.add_page()
    with pytest.raises(pdf_report.MissingFont, match='local-language summary'):
        guide.pdf(pdf_report.Layout(pdf, say), guide.build({'jurisdiction': 'CN', 'local_note': True}))


@pytest.mark.parametrize('design', report_design.DESIGNS)
def test_signed_exports_share_guidance_across_formats_and_designs(tmp_path, design):
    import fitz
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        store.append('message.new', {'text': 'SYNTHETIC record, no real case data'}, -1001, 1)
        options = report.ReportOptions(language='en', design=design, timeline=False,
            jurisdiction_guidance={'jurisdiction': 'BR', 'local_note': True, 'include_methods': True}).model_dump()
        preview = report_studio.preview(store, options)['html']
        assert 'id="jurisdiction-guidance"' in preview and 'Código de Processo Civil' in preview
        path = evidence.export_file(store, vault, 'zip', options)
        pin = fingerprint(vault.public_key)
        verified = verify_bundle(path, pin)
        assert verified['key_pinned'] and verified['report_pdf']
        with zipfile.ZipFile(path) as archive:
            data = json.loads(archive.read('report.json'))['report']['case_assessment']
            manifest = json.loads(archive.read('manifest.json'))
            assert data == manifest['case_assessment']
            assert data['jurisdiction_guidance'] == guide.build(options['jurisdiction_guidance'], assessment=data)
            html = archive.read('report.html')
            assert b'id="jurisdiction-guidance"' in html and b'not a finding of admissibility' in html
            assert b'What this copy needs next' in html and b'1 signed journal records' in html
            with fitz.open(stream=archive.read('report.pdf'), filetype='pdf') as pdf:
                text = ' '.join(' '.join(page.get_text() for page in pdf).split()).casefold()
                assert 'jurisdiction guidance' in text and 'collector signature' in text and 'brazil' in text
                assert 'what this copy needs next' in text and 'separate trusted channel' in text
            report_path = tmp_path / 'report.html'
            report_path.write_bytes(html.replace(b'not a finding of admissibility', b'a finding of admissibility'))
            with pytest.raises((InvalidSignature, ValueError)):
                verify_report(report_path, pin)
    finally:
        store.close()
