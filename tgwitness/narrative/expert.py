from html import escape
import hashlib
import json
from pathlib import Path

from .. import __version__, verify
from ..pdf_report import BAD, INK, MUTED, OK
from ..verify import evidence_conditions
from .sheet import Sheet
from .style import heading, hero, language_name, marked, page, pill, tone

ROOT = Path(__file__).parent / 'examination'
FORMAT = 'tgwitness-examination-v1'
PROCEDURES = ('criminal', 'civil')
COMPUTED = ('integrity', 'external_time')
CONDITIONAL = ('signer', 'checkpoint', 'head_binding', 'environment')
OUTSIDE = ('authorship', 'completeness', 'truth', 'lawfulness', 'identity')
FIELDS = ('case', 'authority', 'name', 'education', 'specialty', 'experience', 'organisation', 'period', 'place')
ANSWERABLE = ('changed', 'time', 'manifest', 'key', 'coverage', 'witness')
UNANSWERABLE = ('author', 'complete', 'true', 'lawful')
STANDARDS = ('sha256', 'ed25519', 'tsp', 'ots')


def codes():
    return {path.stem for path in ROOT.glob('*.json')}


def load(code):
    if code is None or code not in codes():
        return None
    record = json.loads((ROOT / (code + '.json')).read_text(encoding='utf-8'))
    if record.get('format') != FORMAT or record.get('code') != code:
        raise ValueError('Invalid examination catalog entry: ' + code)
    return record


def route(record, procedure):
    routes = record.get('procedures') or []
    return next((item for item in routes if item.get('route') == procedure), routes[0] if routes else {})


def liability(record, procedure):
    rows = record.get('liability') or []
    return [row for row in rows if row.get('route') in (procedure, 'all')] or rows


def detail(row):
    values, status, cid = row['values'], row['status'], row['id']
    if cid == 'integrity':
        return ('expert.detail.integrity', {'records': values['records'], 'files': values['files']}) \
            if 'records' in values else ('expert.detail.integrity_plain', {})
    if cid == 'signer':
        return ('expert.detail.signer_met' if status == 'met' else 'expert.detail.signer_missing',
                {'fingerprint': values['fingerprint']})
    if cid == 'external_time':
        if status == 'met':
            return ('expert.detail.time_qualified', {'time': values['time'], 'service': values['service']}) \
                if 'service' in values else ('expert.detail.time_met', {'time': values['time']})
        if status == 'partial':
            return 'expert.detail.time_partial', {'through': values['through'], 'time': values['time']}
        if status == 'unchecked':
            return 'expert.detail.time_unchecked', {'count': values['count']}
        return 'expert.detail.time_missing', {}
    if cid in ('head_binding', 'checkpoint'):
        prefix = 'expert.detail.witness' if cid == 'head_binding' else 'expert.detail.checkpoint'
        return (prefix, {'through': values['through'], 'total': values['total']}) if 'through' in values \
            else (prefix + '_missing', {})
    if status == 'met':
        return 'expert.detail.environment_met', {'workflow': values['workflow']}
    if 'detail' in values:
        return 'expert.detail.environment_failed', {'detail': values['detail']}
    if status == 'partial':
        return 'expert.detail.environment_partial', {}
    return 'expert.detail.environment_missing', {}


def declaration(record, procedure):
    found = record.get('declaration_criminal') if procedure == 'criminal' and record.get('declaration_criminal')         else record.get('declaration')
    return found if found and found.get('route') in (None, 'all', procedure) else None


def commands(settings):
    collector = settings.get('fingerprint') or 'TRUSTED_COLLECTOR_FP'
    witness = settings.get('witness_fingerprint') or 'TRUSTED_WITNESS_FP'
    return ['python -m tgwitness.verify PACKAGE.zip --fingerprint ' + collector + ' --strict --json',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint ' + collector + ' --tsa-ca TSA-ROOT.pem --check-bitcoin --strict --plain --explain',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint ' + collector + ' --witness WITNESS.zip --witness-fingerprint '
            + witness + ' --strict --plain']


def build(result, model, settings, receipt_sha256):
    record = load(settings.get('jurisdiction'))
    procedure = settings.get('procedure') or PROCEDURES[0]
    evidence = evidence_conditions(result)
    rows = {row['id']: row for row in evidence['conditions']}
    coverage = result.get('coverage') or {}

    def finding(cid):
        return {'id': cid, 'status': rows[cid]['status'], 'detail': detail(rows[cid])}

    return {
        'format': 'tgwitness-expert-protocol-v1',
        'procedure': procedure,
        'jurisdiction': record and {**{key: record.get(key) for key in (
            'code', 'name_en', 'name_local', 'court_languages', 'local_language', 'checked_at', 'expert_term', 'statute',
            'standards', 'esignature', 'timestamp', 'open_questions')},
            'declaration': declaration(record, procedure),
            'route': route(record, procedure), 'liability': liability(record, procedure)},
        'material': {'package_sha256': model['package_sha256'],
                     'witness_package_sha256': (model.get('witness_source') or {}).get('package_sha256'),
                     'fingerprint_supplied': settings.get('fingerprint'),
                     'collector_fingerprint': result.get('fingerprint'),
                     'records': result.get('events'), 'files': result.get('files_checked'),
                     'head_hash': result.get('head_hash')},
        'tool': {'name': 'TgWitness', 'version': __version__,
                 'verifier_sha256': hashlib.sha256(Path(verify.__file__).read_bytes()).hexdigest()},
        'commands': commands(settings),
        'checks': [{'tier': row['tier'], 'status': row['status']} for row in result['assurance']['ladder']],
        'coverage': {'periods': len(coverage.get('continuous') or []), 'gaps': len(coverage.get('gaps') or []),
                     'unobserved': len(coverage.get('unobserved_ids') or [])},
        'findings': {'computed': [finding(cid) for cid in COMPUTED if cid in rows],
                     'conditional': [finding(cid) for cid in CONDITIONAL if cid in rows],
                     'outside': list(OUTSIDE)},
        'questions': {'answerable': list(ANSWERABLE), 'outside': list(UNANSWERABLE)},
        'run': {'receipt': 'narrative-run.json', 'receipt_sha256': receipt_sha256},
    }


def meta(protocol, text):
    t, local = text, protocol['jurisdiction']
    rows = []
    if local:
        rows.append((t('meta.jurisdiction'), local['name_local'] + ' · ' + local['name_en'] + ' (' + local['code'] + ')'))
    rows.append((t('meta.procedure'), t('procedure.' + protocol['procedure'])))
    if local and local.get('court_languages'):
        rows.append((t('meta.court_language'), ', '.join(language_name(code) for code in local['court_languages'])))
    rows.append((t('meta.language'), language_name(text.lang)))
    if local:
        rows.append((t('meta.checked'), local['checked_at']))
    rows.append((t('meta.package'), protocol['material']['package_sha256']))
    return rows


def sections(protocol, text):
    t, out = text, []
    local = protocol['jurisdiction']
    notes = [t('expert.draft'), t('expert.jurisdiction.research') if local else t('expert.jurisdiction.none'),
             t('advice.translation')]
    out.append(('title', t('expert.title'), {'kind': t('procedure.' + protocol['procedure']), 'badge': t('expert.badge'),
                                             'meta': meta(protocol, text), 'notes': notes}))
    native = bool(local) and text.lang == local.get('local_language')
    intro = [('fields', [t('expert.field.' + name) for name in FIELDS])]
    if local:
        basis, part = [], local['route']
        for key, label in (('appointment', 'appointment'), ('report_contents', 'contents'), ('questions', 'questions'),
                           ('rights_duties', 'duties')):
            if (part.get(key) or {}).get('basis'):
                basis.append((t('expert.basis.' + label, basis=part[key]['basis']), part[key].get('source')))
        if (local.get('statute') or {}).get('title_local'):
            basis.append((t('expert.basis.statute', title=local['statute']['title_local']), local['statute'].get('source')))
        intro.append(('heading', t('expert.basis')))
        intro.append(('sourced', basis))
        if local.get('open_questions'):
            intro.append(('open', (t('expert.open'), local['open_questions'])))
        contents = (part.get('report_contents') or {}).get('items_local' if native else 'items_en') or []
        if contents:
            intro.append(('heading', t('expert.contents')))
            intro.append(('checklist', contents))
        if local['liability']:
            intro.append(('heading', t('expert.liability')))
        for item in local['liability']:
            warning = item.get('warning_local') if native or not item.get('warning_en') else item['warning_en']
            lines = [warning] if warning else []
            if not native and item.get('warning_local') and item.get('warning_en'):
                lines.append(item['warning_local'])
            intro.append(('liability', {'lines': lines, 'norm': t('expert.liability.norm', norm=item['norm'])
                                        if item.get('norm') else None, 'source': item.get('source'),
                                        'signature': t('expert.field.signature')}))
        declaration = local.get('declaration') or {}
        text_value = declaration.get('text_local') if native or not declaration.get('text_en') else declaration.get('text_en')
        if text_value:
            intro.append(('heading', t('expert.declaration')))
            intro.append(('quote', [text_value]))
            intro.append(('sourced', [(declaration.get('basis') or '', declaration.get('source'))]))
    intro.append(('heading', t('expert.questions')))
    intro.append(('numbered', 3))
    intro.append(('muted', [t('expert.questions.see_annex')]))
    material = protocol['material']
    lines = [t('expert.material.package', sha=material['package_sha256'])]
    if material['witness_package_sha256']:
        lines.append(t('expert.material.witness', sha=material['witness_package_sha256']))
    lines.append(t('expert.material.fingerprint', fingerprint=material['fingerprint_supplied'])
                 if material['fingerprint_supplied'] else t('expert.material.no_fingerprint'))
    if material['records'] is not None and material['files'] is not None:
        lines.append(t('expert.material.records', records=material['records'], files=material['files']))
    intro.append(('heading', t('expert.material')))
    intro.append(('text', lines))
    out.append(('section', '1. ' + t('expert.section.intro'), intro))
    tool = protocol['tool']
    method = [('text', [t('expert.method.tool', version=tool['version'], sha=tool['verifier_sha256'])]),
              ('heading', t('expert.method.standards')),
              ('list', [t('expert.std.' + name) for name in STANDARDS])]
    standards = (local or {}).get('standards') or []
    if standards:
        method.append(('heading', t('expert.method.local')))
        method.append(('sourced', [(' · '.join(filter(None, (item.get('national_id'), item.get('id'), item.get('title_en')))),
                                    item.get('source')) for item in standards]))
        method.append(('muted', [t('expert.method.local_note')]))
    out.append(('section', '2. ' + t('expert.section.method'), method))
    checks = [(text.glossary[row['tier']], row['status'], text.glossary[row['status']]) for row in protocol['checks']]
    coverage = protocol['coverage']
    out.append(('section', '3. ' + t('expert.section.procedure'), [
        ('text', [t('expert.procedure.repeat')]), ('code', protocol['commands']),
        ('heading', t('expert.procedure.results')), ('statuses', checks),
        ('muted', [t('expert.procedure.coverage', periods=coverage['periods'], gaps=coverage['gaps'],
                     unobserved=coverage['unobserved'])])]))
    findings = protocol['findings']

    def described(item, conditional):
        key, values = item['detail']
        lines = [t(key, **values)]
        if conditional:
            lines.append(t('expert.condition.' + item['id']))
        elif item['id'] == 'external_time' and item['status'] in ('met', 'partial'):
            lines.append(t('expert.basis.external_time'))
        return ('finding', {'title': t('expert.cond.' + item['id']), 'status': item['status'],
                            'shown': t('expert.status.' + item['status']), 'lines': lines})

    out.append(('section', '4. ' + t('expert.section.findings'), [
        ('heading', '4.1 ' + t('expert.bucket.computed')), ('muted', [t('expert.bucket.computed.note')]),
        *[described(item, False) for item in findings['computed']],
        ('heading', '4.2 ' + t('expert.bucket.conditional')), ('muted', [t('expert.bucket.conditional.note')]),
        *[described(item, True) for item in findings['conditional']],
        ('heading', '4.3 ' + t('expert.bucket.outside')), ('muted', [t('expert.bucket.outside.note')]),
        ('list', [t('expert.outside.' + name) for name in findings['outside']])]))
    out.append(('section', t('expert.section.signature'), [
        ('fields', [t('expert.field.name'), t('expert.field.date'), t('expert.field.signature')]),
        ('muted', [t('expert.signature.cert', law=local['esignature']['law_local'])
                   if local and (local.get('esignature') or {}).get('law_local') else t('expert.signature.cert_generic'),
                   t('expert.signature.collector')])]))
    out.append(('section', t('expert.annex.questions'), [
        ('muted', [t('expert.annex.questions.note')]),
        ('answers', [(t('expert.questions.answerable'), True,
                      [(t('expert.q.' + name), t('expert.q.' + name + '.check')) for name in protocol['questions']['answerable']]),
                     (t('expert.questions.outside'), False,
                      [(t('expert.q.' + name), t('expert.q.' + name + '.reason')) for name in protocol['questions']['outside']])])]))
    out.append(('section', t('expert.annex.run'), [
        ('text', [t('expert.run.receipt', sha=protocol['run']['receipt_sha256'])]),
        ('muted', [t('expert.run.repeat')])]))
    return out


def footer(text):
    return text('expert.title')


def source_link(url, text):
    return ' <a class="src" href="' + escape(url, quote=True) + '">' + escape(text.glossary['source']) + ' ↗</a>' if url else ''


def html(protocol, text):
    e, body = escape, []
    for kind, title, blocks in sections(protocol, text):
        if kind == 'title':
            body.append(hero(blocks['kind'], title, [(label, marked(value)) for label, value in blocks['meta']],
                             blocks['notes'], blocks['badge']))
            continue
        body.append('<section class="card">' + heading(title))
        for block, value in blocks:
            if block == 'heading':
                body.append('<h3>' + e(value) + '</h3>')
            elif block in ('fields', 'numbered'):
                labels = value if block == 'fields' else [str(i) + '.' for i in range(1, value + 1)]
                body.append('<table class="form' + (' numbers' if block == 'numbered' else '') + '">'
                            + ''.join('<tr><td class="label">' + e(label) + '</td><td class="blank"></td></tr>' for label in labels)
                            + '</table>')
            elif block in ('text', 'muted'):
                body.extend('<p' + (' class="muted small"' if block == 'muted' else '') + '>' + marked(line) + '</p>' for line in value)
            elif block == 'quote':
                body.extend('<blockquote' + (' class="second"' if index else '') + '>' + e(line) + '</blockquote>'
                            for index, line in enumerate(value))
            elif block == 'code':
                body.extend('<pre class="cmd">' + e(line) + '</pre>' for line in value)
            elif block in ('list', 'checklist'):
                body.append('<ul' + (' class="check"' if block == 'checklist' else '') + '>'
                            + ''.join('<li>' + marked(line) + '</li>' for line in value) + '</ul>')
            elif block == 'sourced':
                body.append('<ul class="refs">' + ''.join('<li>' + e(label) + source_link(url, text) + '</li>'
                                                          for label, url in value if label) + '</ul>')
            elif block == 'open':
                summary, items = value
                body.append('<details class="callout" open><summary>' + e(summary) + ' (' + str(len(items)) + ')</summary><ul>'
                            + ''.join('<li>' + e(item) + '</li>' for item in items) + '</ul></details>')
            elif block == 'liability':
                body.append('<div class="box">' + ''.join('<blockquote' + (' class="second"' if index else '') + '>' + e(line)
                                                          + '</blockquote>' for index, line in enumerate(value['lines'])))
                if value['norm']:
                    body.append('<p class="small">' + e(value['norm']) + source_link(value['source'], text) + '</p>')
                body.append('<table class="form"><tr><td class="label">' + e(value['signature'])
                            + '</td><td class="blank"></td></tr></table></div>')
            elif block == 'statuses':
                body.append('<table class="status">' + ''.join('<tr><td>' + e(label) + '</td><td>' + pill(status, shown) + '</td></tr>'
                                                              for label, status, shown in value) + '</table>')
            elif block == 'finding':
                body.append('<article class="finding ' + tone(value['status']) + '"><header><h4>' + e(value['title']) + '</h4>'
                            + pill(value['status'], value['shown']) + '</header>'
                            + ''.join('<p' + (' class="muted small"' if index else '') + '>' + marked(line) + '</p>'
                                      for index, line in enumerate(value['lines'])) + '</article>')
            elif block == 'answers':
                body.append('<div class="grid2">' + ''.join(
                    '<div><h3>' + e(title) + '</h3><ul class="marks ' + ('yes' if positive else 'no') + '">'
                    + ''.join('<li>' + e(question) + '<span>' + e(note) + '</span></li>' for question, note in items) + '</ul></div>'
                    for title, positive, items in value) + '</div>')
        body.append('</section>')
    body.append('<footer>' + e(footer(text)) + '</footer>')
    return page(text.lang, text('expert.title'), ''.join(body))


def pdf(protocol, text):
    sheet = Sheet(text, footer(text), text('expert.title'))
    for kind, title, blocks in sections(protocol, text):
        if kind == 'title':
            sheet.hero(blocks['kind'], title, blocks['meta'], blocks['notes'], blocks['badge'])
            continue
        sheet.section(title)
        for block, value in blocks:
            if block == 'heading':
                sheet.heading(value)
            elif block in ('fields', 'numbered'):
                sheet.fields(value if block == 'fields' else [str(i) + '.' for i in range(1, value + 1)], block == 'numbered')
            elif block in ('text', 'muted'):
                for line in value:
                    sheet.para(line, 8.8 if block == 'muted' else 9.5, MUTED if block == 'muted' else INK)
            elif block == 'quote':
                sheet.quote(value)
            elif block == 'code':
                sheet.code(value)
            elif block == 'list':
                sheet.bullets(value)
            elif block == 'checklist':
                sheet.checklist(value)
            elif block == 'sourced':
                sheet.sourced(value)
            elif block == 'open':
                summary, items = value
                sheet.bar_block([summary + ' (' + str(len(items)) + ')', *('•  ' + item for item in items)],
                                (210, 154, 60), (253, 248, 239), 8.4, True)
            elif block == 'liability':
                sheet.rule()
                sheet.quote(value['lines'])
                if value['norm']:
                    sheet.sourced([(value['norm'], value['source'])])
                sheet.fields([value['signature']])
            elif block == 'statuses':
                sheet.statuses(value)
            elif block == 'finding':
                sheet.finding(value['title'], value['status'], value['shown'], value['lines'])
            elif block == 'answers':
                for title, positive, items in value:
                    sheet.heading(title)
                    for question, note in items:
                        sheet.bar_block([question, note], OK if positive else BAD, None, 9, True, 1.6)
    return sheet.output()


def write(protocol, out, text, outputs):
    out = Path(out)
    if 'json' in outputs:
        (out / 'expert-protocol.json').write_text(json.dumps(protocol, ensure_ascii=False, indent=2), encoding='utf-8')
    if 'html' in outputs:
        (out / 'expert-protocol.html').write_text(html(protocol, text), encoding='utf-8')
    if 'pdf' in outputs:
        (out / 'expert-protocol.pdf').write_bytes(pdf(protocol, text))
