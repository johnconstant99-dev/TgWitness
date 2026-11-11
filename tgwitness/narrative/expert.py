from html import escape
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unicodedata import category

from .. import __version__, pdf_report, verify
from ..verify import evidence_conditions

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
RTL = ('ar', 'fa', 'he', 'ur')
BLANK = '_' * 34


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
            'code', 'name_en', 'name_local', 'court_languages', 'local_language', 'checked_at', 'review', 'expert_term', 'statute',
            'standards', 'esignature', 'timestamp', 'open_questions')},
            'declaration': record.get('declaration_criminal') if procedure == 'criminal' and record.get('declaration_criminal')
            else record.get('declaration'),
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
        'translation_review': 'machine-assisted, not reviewed',
    }


def sections(protocol, text):
    t, out = text, []
    local = protocol['jurisdiction']
    head = [t('expert.draft')]
    if local:
        head.append(t('expert.jurisdiction', name=local['name_local'] + ' · ' + local['name_en'],
                      date=local['checked_at'], review=local['review']))
        head.append(t('expert.jurisdiction.research'))
        languages = local.get('court_languages') or []
        if languages and text.lang not in languages:
            head.append(t('expert.court_language', languages=', '.join(languages), lang=text.lang))
    else:
        head.append(t('expert.jurisdiction.none'))
    out.append(('title', t('expert.title'), head))
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
            intro.append(('text', [t('expert.open')]))
            intro.append(('list', local['open_questions']))
        contents = (part.get('report_contents') or {}).get('items_local' if native else 'items_en') or []
        if contents:
            intro.append(('heading', t('expert.contents')))
            intro.append(('checklist', contents))
        for item in local['liability']:
            intro.append(('heading', t('expert.liability')))
            warning = item.get('warning_local') if native or not item.get('warning_en') else item['warning_en']
            lines = [warning] if warning else []
            if not native and item.get('warning_local') and item.get('warning_en'):
                lines.append(item['warning_local'])
            intro.append(('quote', lines))
            if item.get('norm'):
                intro.append(('sourced', [(t('expert.liability.norm', norm=item['norm']), item.get('source'))]))
            intro.append(('fields', [t('expert.field.signature')]))
        declaration = local.get('declaration') or {}
        text_value = declaration.get('text_local') if native or not declaration.get('text_en') else declaration.get('text_en')
        if text_value:
            intro.append(('heading', t('expert.declaration')))
            intro.append(('quote', [text_value]))
            intro.append(('sourced', [(declaration.get('basis') or '', declaration.get('source'))]))
    intro.append(('heading', t('expert.questions')))
    intro.append(('numbered', 3))
    intro.append(('text', [t('expert.questions.see_annex')]))
    material = protocol['material']
    lines = [t('expert.material.package', sha=material['package_sha256'])]
    if material['witness_package_sha256']:
        lines.append(t('expert.material.witness', sha=material['witness_package_sha256']))
    lines.append(t('expert.material.fingerprint', fingerprint=material['fingerprint_supplied'])
                 if material['fingerprint_supplied'] else t('expert.material.no_fingerprint'))
    if material['records'] is not None and material['files'] is not None:
        lines.append(t('expert.material.records', records=material['records'], files=material['files']))
    intro.append(('heading', t('expert.material')))
    intro.append(('code', lines))
    out.append(('section', '1. ' + t('expert.section.intro'), intro))
    tool = protocol['tool']
    method = [('text', [t('expert.method.tool', version=tool['version'], sha=tool['verifier_sha256']),
                        t('expert.method.standards')]),
              ('list', [t('expert.std.' + name) for name in STANDARDS])]
    standards = (local or {}).get('standards') or []
    if standards:
        method.append(('text', [t('expert.method.local')]))
        method.append(('sourced', [(' · '.join(filter(None, (item.get('national_id'), item.get('id'), item.get('title_en')))),
                                    item.get('source')) for item in standards]))
        method.append(('text', [t('expert.method.local_note')]))
    out.append(('section', '2. ' + t('expert.section.method'), method))
    checks = [text.glossary[row['tier']] + ': ' + text.glossary[row['status']] for row in protocol['checks']]
    coverage = protocol['coverage']
    out.append(('section', '3. ' + t('expert.section.procedure'), [
        ('text', [t('expert.procedure.repeat')]), ('code', protocol['commands']),
        ('heading', t('expert.procedure.results')), ('list', checks),
        ('text', [t('expert.procedure.coverage', periods=coverage['periods'], gaps=coverage['gaps'],
                    unobserved=coverage['unobserved'])])]))
    findings = protocol['findings']

    def described(item, conditional):
        key, values = item['detail']
        lines = [t('expert.cond.' + item['id']) + ': ' + t('expert.status.' + item['status']), t(key, **values)]
        if conditional:
            lines.append(t('expert.condition.' + item['id']))
        elif item['id'] == 'external_time' and item['status'] in ('met', 'partial'):
            lines.append(t('expert.basis.external_time'))
        return lines

    out.append(('section', '4. ' + t('expert.section.findings'), [
        ('heading', '4.1 ' + t('expert.bucket.computed')), ('text', [t('expert.bucket.computed.note')]),
        *[('finding', described(item, False)) for item in findings['computed']],
        ('heading', '4.2 ' + t('expert.bucket.conditional')), ('text', [t('expert.bucket.conditional.note')]),
        *[('finding', described(item, True)) for item in findings['conditional']],
        ('heading', '4.3 ' + t('expert.bucket.outside')), ('text', [t('expert.bucket.outside.note')]),
        ('list', [t('expert.outside.' + name) for name in findings['outside']])]))
    out.append(('section', t('expert.section.signature'), [
        ('fields', [t('expert.field.name'), t('expert.field.date'), t('expert.field.signature')]),
        ('text', [t('expert.signature.cert', law=local['esignature']['law_local'])
                  if local and (local.get('esignature') or {}).get('law_local') else t('expert.signature.cert_generic'),
                  t('expert.signature.collector')])]))
    answers = [t('expert.q.' + name) + ' ' + t('expert.q.' + name + '.check') for name in protocol['questions']['answerable']]
    refused = [t('expert.q.' + name) + ' ' + t('expert.q.' + name + '.reason') for name in protocol['questions']['outside']]
    out.append(('section', t('expert.annex.questions'), [
        ('text', [t('expert.annex.questions.note')]),
        ('heading', t('expert.questions.answerable')), ('list', answers),
        ('heading', t('expert.questions.outside')), ('list', refused)]))
    out.append(('section', t('expert.annex.run'), [
        ('code', [t('expert.run.receipt', sha=protocol['run']['receipt_sha256'])]),
        ('text', [t('expert.run.repeat'), t('limit.review')])]))
    return out


def html(protocol, text):
    e = escape
    direction = 'rtl' if text.lang in RTL else 'ltr'
    out = ['<!doctype html><html lang="' + text.lang + '" dir="' + direction + '"><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'">',
           '<title>' + e(text('expert.title')) + '</title><style>body{font:16px/1.6 system-ui,sans-serif;color:#163844;'
           'max-width:960px;margin:40px auto;padding:0 24px;overflow-wrap:anywhere}h1,h2,h3{line-height:1.25}'
           'table{border-collapse:collapse;width:100%}td{padding:8px 6px;border-bottom:1px solid #ccd6d6;vertical-align:bottom}'
           'td.blank{width:55%;border-bottom:1px solid #163844}blockquote{margin:8px 0;padding:8px 14px;border-inline-start:3px solid #a3431f;'
           'background:#faf5ef}code,pre{white-space:pre-wrap;overflow-wrap:anywhere}.finding{border:1px solid #ccd6d6;padding:8px 12px;margin:8px 0}'
           '.note{color:#5b6b70}a{color:#165c74}</style><body>']
    for kind, title, blocks in sections(protocol, text):
        if kind == 'title':
            out.append('<h1>' + e(title) + '</h1>' + ''.join('<p class="note">' + e(line) + '</p>' for line in blocks))
            continue
        out.append('<section><h2>' + e(title) + '</h2>')
        for block, value in blocks:
            if block == 'heading':
                out.append('<h3>' + e(value) + '</h3>')
            elif block == 'fields':
                out.append('<table>' + ''.join('<tr><td>' + e(label) + '</td><td class="blank"></td></tr>' for label in value) + '</table>')
            elif block == 'numbered':
                out.append('<table>' + ''.join('<tr><td>' + str(i) + '.</td><td class="blank"></td></tr>' for i in range(1, value + 1)) + '</table>')
            elif block == 'text':
                out.extend('<p>' + e(line) + '</p>' for line in value)
            elif block == 'quote':
                out.extend('<blockquote>' + e(line) + '</blockquote>' for line in value)
            elif block == 'code':
                out.extend('<pre>' + e(line) + '</pre>' for line in value)
            elif block in ('list', 'checklist'):
                mark = '&#9744; ' if block == 'checklist' else ''
                out.append('<ul>' + ''.join('<li>' + mark + e(line) + '</li>' for line in value) + '</ul>')
            elif block == 'sourced':
                out.append('<ul>' + ''.join('<li>' + e(label) + (' · <a href="' + e(url, quote=True) + '">' + e(text.glossary['source'])
                                                                 + '</a>' if url else '') + '</li>' for label, url in value if label) + '</ul>')
            elif block == 'finding':
                out.append('<div class="finding"><p><strong>' + e(value[0]) + '</strong></p>'
                           + ''.join('<p>' + e(line) + '</p>' for line in value[1:]) + '</div>')
        out.append('</section>')
    out.append('</body></html>')
    return ''.join(out)


def pdf(protocol, text):
    document = pdf_report.document(SimpleNamespace(language=text.lang, direction='rtl' if text.lang in RTL else 'ltr'),
                                   text('limit.review'))
    document.set_title(text('expert.title'))
    document.add_page()
    glyphs = set().union(*(font.cmap for font in document.fonts.values() if hasattr(font, 'cmap')))
    unavailable = text('expert.pdf.script')

    def line_text(value, **style):
        shown = value if all(ord(char) in glyphs or char.isspace() or category(char) == 'Cf' for char in value) else unavailable
        document.line_text(shown, **style)

    for kind, title, blocks in sections(protocol, text):
        if kind == 'title':
            line_text(title, size=18, style='B')
            for line in blocks:
                line_text(line, size=9)
            continue
        if document.will_page_break(30):
            document.add_page()
        line_text(title, size=14, style='B')
        for block, value in blocks:
            if block == 'heading':
                line_text(value, size=11, style='B')
            elif block == 'fields':
                for label in value:
                    line_text(label + ': ' + BLANK)
            elif block == 'numbered':
                for i in range(1, value + 1):
                    line_text(str(i) + '. ' + BLANK + BLANK)
            elif block in ('text', 'quote'):
                for line in value:
                    line_text(line, style='B' if block == 'quote' else '')
            elif block == 'code':
                for line in value:
                    line_text(line, family='Mono', size=7.5)
            elif block in ('list', 'checklist'):
                for line in value:
                    line_text(('[ ] ' if block == 'checklist' else '• ') + line)
            elif block == 'sourced':
                for label, url in value:
                    if label:
                        line_text('• ' + label)
                    if url:
                        line_text(url, size=7)
            elif block == 'finding':
                line_text(value[0], style='B')
                for line in value[1:]:
                    line_text(line)
    return bytes(document.output())


def write(protocol, out, text, outputs):
    out = Path(out)
    if 'json' in outputs:
        (out / 'expert-protocol.json').write_text(json.dumps(protocol, ensure_ascii=False, indent=2), encoding='utf-8')
    if 'html' in outputs:
        (out / 'expert-protocol.html').write_text(html(protocol, text), encoding='utf-8')
    if 'pdf' in outputs:
        (out / 'expert-protocol.pdf').write_bytes(pdf(protocol, text))
