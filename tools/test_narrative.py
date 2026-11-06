"""Every generated factual statement must retain its exact journal references."""
import json
import re
from pathlib import Path
import sys
import zipfile
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.evidence import export_file
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import verify_bundle
from tgwitness.narrative.model import build, masked
from tgwitness.narrative.text import category, parse, placeholders, render, Texts, LANGUAGES
from tgwitness.narrative.__main__ import generate
from tgwitness.narrative.render import html_report, jurisdiction
from tgwitness.narrative.diagrams import diagrams, svg


def fixture(tmp_path):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    kinds = [
        ('account.authorized', {'key_origin': 'imported', 'session_kind': 'user'}),
        ('message.new', {'text': 'synthetic'}),
        ('coverage.gap', {'reason': 'transport_disconnected'}),
        ('message.edited', {'text': 'synthetic edit'}),
        ('anchor.completed', {'status': 'pending'}),
        ('document.received', {'name': 'synthetic.pdf', 'sha256': 'a' * 64, 'signature_claimed': 'qualified',
                               'signature_objects': 0, 'pages': 9}),
        ('export.completed', {'file': 'synthetic-export.zip'})]
    try:
        for index, (kind, payload) in enumerate(kinds):
            with patch('tgwitness.store.utcnow', return_value=f'2026-10-{1 + index // 3:02d}T12:00:{index:02d}+00:00'):
                store.append(kind, payload)
        package = export_file(store, vault, 'zip', compact=True)
        return package, store.all_events()
    finally:
        store.close()


def test_model_every_fact_has_exact_references_and_no_invented_identity(tmp_path):
    package, events = fixture(tmp_path)
    model = build(events, verify_bundle(package))
    known = {(e['seq'], e['hash']) for e in events}
    for scene in model['scenes']:
        for fact in scene['facts']:
            assert fact['evidence']
            assert all((r['seq'], r['hash']) in known for r in fact['evidence'])
    assert {'authorization', 'collection', 'gaps', 'anchoring', 'external_input', 'export'} <= {s['kind'] for s in model['scenes']}
    assert not any(f['template_key'] == 'anchor.ots.confirmed' for s in model['scenes'] for f in s['facts'])
    assert 'Telegram session' in Texts('en').glossary['key_origin']


@pytest.mark.parametrize('lang,number,expected', [('ru', 21, 'one'), ('ru', 22, 'few'), ('uk', 11, 'many'),
    ('pl', 22, 'few'), ('pl', 21, 'many'), ('cs', '1.5', 'many'), ('cs', 4, 'few'), ('sk', 5, 'other'),
    ('lt', 11, 'other'), ('lt', 21, 'one'), ('lt', '1.5', 'many'), ('ja', 1, 'other')])
def test_plural_categories(lang, number, expected):
    assert category(number, lang) == expected


def test_icu_nested_parameters_and_no_payload_template_execution():
    nodes = parse('{n, plural, one{{name}: # item} other{{name}: # items}}')
    assert placeholders(nodes) == {'n', 'name'}
    assert render(nodes, {'n': 2, 'name': '{untrusted}'}, 'en') == '{untrusted}: 2 items'
    assert masked('test@example.org / +491234567890') == 't***@*** / ***90'


@pytest.mark.parametrize('lang', LANGUAGES)
def test_pdf_html_and_svg_outputs(tmp_path, lang):
    package, events = fixture(tmp_path)
    out = tmp_path / ('narrative-' + lang)
    model = generate(package, out, lang=lang)
    assert (out / 'narrative.pdf').read_bytes().startswith(b'%PDF-')
    assert len(list((out / 'diagrams').glob('*.svg'))) == 4
    assert json.loads((out / 'narrative.json').read_text(encoding='utf-8')) == model
    html = (out / 'narrative.html').read_text(encoding='utf-8')
    assert events[-1]['hash'] in html
    assert 'machine-assisted, not reviewed' == model['translation_review']
    assert Texts(lang)('limit.review') in html
    assert len(model['scenes']) == 7
    for scene in model['scenes']:
        for fact in scene['facts'] + scene['limits']:
            assert '{' not in Texts(lang).fact(fact)
    import xml.etree.ElementTree as ET
    for picture in (out / 'diagrams').glob('*.svg'):
        node = ET.fromstring(picture.read_text(encoding='utf-8'))
        assert node.find('{http://www.w3.org/2000/svg}title') is not None
        assert node.find('{http://www.w3.org/2000/svg}desc') is not None


def test_jurisdictions_change_only_the_terms_section(tmp_path):
    package, events = fixture(tmp_path)
    model = build(events, verify_bundle(package))
    model['package_sha256'] = 'a' * 64
    text = Texts('de')
    pictures = diagrams(model, text)
    rendered = [html_report(model, text, pictures, jurisdiction(code)) for code in ('DE', 'AT', 'CH')]
    assert len(set(rendered)) == 3
    stripped = [re.sub(r'<section id="jurisdiction">.*?</section>', '', h) for h in rendered]
    assert len(set(stripped)) == 1
    assert 'id="jurisdiction"' not in html_report(model, text, pictures, None)


def test_claims_do_not_become_checks_and_untrusted_markup_is_escaped(tmp_path):
    package, events = fixture(tmp_path)
    verification = verify_bundle(package)
    events[-2]['payload']['name'] = '<script>alert(1)</script>.pdf'
    model = build(events, verification)
    model['package_sha256'] = 'a' * 64
    text = Texts('en')
    pictures = diagrams(model, text)
    html = html_report(model, text, pictures, None)
    assert '<script>' not in html
    assert '&lt;script&gt;' in html
    flow = svg(pictures['flow'])
    assert '>pass<' not in flow
    assert 'recorded' in flow
    assert model['assurance']['tier'] == 'self_attested'


def test_original_signed_legacy_fixture(tmp_path):
    package = Path(__file__).parent / 'fixtures/evidence-before-fulltext.zip'
    model = generate(package, tmp_path / 'legacy')
    assert model['scenes'] and model['source']['events']


def test_catalog_policy_and_plural_edge_cases():
    from check_narrative_texts import check
    assert check() == []
    errors = check(for_release=True)
    assert any('T7' in error for error in errors)
    assert any('T13' in error for error in errors)
    assert any('native legal review absent' in error for error in errors)
    assert category('1.11', 'lv') == 'zero'
    assert category('0.1', 'lv') == 'one'
    assert category('1.21', 'lv') == 'one'


def test_golden_model_is_language_independent():
    source = Path(__file__).parent / 'fixtures/narrative-events.json'
    events = json.loads(source.read_text(encoding='utf-8'))
    result = {'fingerprint': 'synthetic-key', 'events': len(events), 'head_hash': events[-1]['hash']}
    actual = build(events, result)
    expected = json.loads(source.with_name('narrative-golden.json').read_text(encoding='utf-8'))
    assert actual == expected
    counts = []
    for lang in LANGUAGES:
        text = Texts(lang)
        counts.append(tuple(sum(len(s[key]) for s in actual['scenes']) for key in ('facts', 'limits')))
        for scene in actual['scenes']:
            for fact in scene['facts'] + scene['limits']:
                assert '{' not in text.fact(fact)
    assert len(set(counts)) == 1


def test_restart_links_signed_endpoints_without_inventing_a_cause():
    events = [dict(seq=1, hash='a' * 64, observed_at='2026-10-01T12:00:00+00:00', kind='process.stopped', payload={}),
              dict(seq=2, hash='b' * 64, observed_at='2026-10-02T12:00:00+00:00', kind='process.started', payload={})]
    scene = build(events, {})['scenes'][0]
    assert scene['kind'] == 'gaps' and scene['to_seq'] == 2
    assert scene['at_to'] == events[1]['observed_at']
    assert [r['seq'] for r in scene['facts'][0]['evidence']] == [1, 2]
    assert any(limit['template_key'] == 'limit.gap' for limit in scene['limits'])


def test_restart_preserves_the_full_recorded_time_range_after_clock_changes():
    events = [
        dict(seq=1, hash='a' * 64, observed_at='2026-10-01T12:00:00+00:00', kind='process.stopped', payload={}),
        dict(seq=2, hash='b' * 64, observed_at='2026-10-01T14:00:00+00:00', kind='connection.lost', payload={}),
        dict(seq=3, hash='c' * 64, observed_at='2026-10-01T13:00:00+00:00', kind='process.started', payload={}),
    ]
    scene = build(events, {})['scenes'][0]
    summary = scene['facts'][0]
    assert scene['at_from'] == events[0]['observed_at']
    assert scene['at_to'] == events[1]['observed_at']
    assert summary['params'] == {'n': 3, 'from': scene['at_from'], 'to': scene['at_to']}
    assert [ref['seq'] for ref in summary['evidence']] == [1, 2, 3]
    assert scene['to_seq'] == 3


def test_modified_archive_cannot_produce_a_report(tmp_path):
    package, _ = fixture(tmp_path)
    modified = tmp_path / 'modified.zip'
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(modified, 'w') as target:
        for name in source.namelist():
            data = source.read(name)
            if name == 'events.jsonl':
                data = data.replace(b'synthetic.pdf', b'fabricated.pdf')
            target.writestr(name, data)
    out = tmp_path / 'rejected'
    with pytest.raises(ValueError, match='hash mismatch'):
        generate(modified, out)
    assert list(out.iterdir()) == []


def test_anchor_attaches_only_to_covered_facts_and_preserves_numeric_values():
    events = json.loads((Path(__file__).parent / 'fixtures/narrative-events.json').read_text(encoding='utf-8'))
    checked = dict(kind='opentimestamps', status='confirmed', checkpoint='synthetic.json', service='calendar',
                   time='2026-10-03T00:00:00+00:00', event_count=6)
    model = build(events, {'anchors': [checked]})
    document = next(s for s in model['scenes'] if s['kind'] == 'external_input')
    assert all(f['anchor'] and f['anchor']['to_seq'] == 6 for f in document['facts'])
    assert next(f['params']['value'] for f in document['facts'] if f['params'].get('field') == 'signature_objects') == 0
    assert all(f['anchor'] is None for f in model['scenes'][-1]['facts'])
    model = build(events, {'anchors': [{**checked, 'status': 'pending'}]})
    assert all(f['anchor'] is None for s in model['scenes'] for f in s['facts'])
