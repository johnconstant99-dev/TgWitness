from html import escape
import json
from pathlib import Path

from ..pdf_report import MUTED
from .diagrams import diagrams, svg
from .config import DIAGRAMS, OUTPUTS
from .expert import load as examination, route
from .sheet import Sheet
from .style import display_time, heading, hero, language_name, marked, page, pill, ref_label, ref_runs, time_span
from .text import Texts


def references(model):
    return sorted({(r['journal'], r['seq'], r['hash']) for s in model['scenes'] for f in s['facts']
                   for r in f['evidence']})


def ref_id(journal, seq):
    return 'ref-' + journal + '-' + str(seq)


def legacy(code):
    path = Path(__file__).parent / 'jurisdictions' / (str(code) + '.json')
    return json.loads(path.read_text(encoding='utf-8')) if code and path.is_file() else None


def jurisdiction(code, procedure='criminal'):
    if code is None:
        return None
    record, old = examination(code), legacy(code)
    if record is None and old is None:
        raise ValueError('Unsupported jurisdiction')
    if record is None:
        rows = []
        for key in ('expert_role', 'esig_regulation', 'data_access_basis', 'timestamp_recognition'):
            value = old.get(key)
            if value:
                rows.append((value['term'], value.get('basis', value.get('qes_name', '')), value['source']))
        return {'name': old['scope'], 'procedure': None, 'checked': old['checked_at'], 'rows': rows}
    part = route(record, procedure)
    appointed = next((part[key] for key in ('appointment',) if part.get(key)), {})
    esignature, timestamp = record.get('esignature') or {}, record.get('timestamp') or {}
    rows = []
    if (record.get('expert_term') or {}).get('local'):
        rows.append((record['expert_term']['local'], appointed.get('basis') or record['expert_term'].get('en', ''),
                     appointed.get('source')))
    if esignature.get('law_local'):
        rows.append((esignature.get('qualified_term_local') or esignature['law_local'], esignature['law_local'],
                     esignature.get('source')))
    if timestamp.get('basis'):
        rows.append((timestamp['basis'], timestamp.get('qualified_recognition') or '', timestamp.get('source')))
    if old and old.get('data_access_basis'):
        rows.append((old['data_access_basis']['term'], '', old['data_access_basis']['source']))
    return {'name': record['name_local'] + ' · ' + record['name_en'] + ' (' + record['code'] + ')', 'procedure': procedure,
            'checked': record['checked_at'], 'rows': rows}


def commands(model):
    return ['python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --strict --json',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --check-drand --check-bitcoin --strict --plain',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --witness WITNESS.zip --witness-fingerprint TRUSTED_WITNESS_FP --require-tier witness_anchored --strict']


def shown_fact(text, fact):
    if fact['template_key'] != 'scene.records':
        return text.fact(fact)
    params = dict(fact['params'], **{key: display_time(fact['params'][key]) for key in ('from', 'to')})
    return text.fact({**fact, 'params': params})


def fact_refs(fact):
    return ' '.join('<a href="#' + ref_id(journal, first) + '">' + escape(ref_label(journal, first, last)) + '</a>'
                    for journal, first, last in ref_runs(fact['evidence']))


def plain_refs(fact):
    return ', '.join(ref_label(journal, first, last) for journal, first, last in ref_runs(fact['evidence']))


def footer(text):
    return text('title')


def meta(model, text, local):
    scenes = model['scenes']
    period = time_span(scenes[0]['at_from'], max((s['at_to'] for s in scenes), key=display_time)) if scenes else None
    events = model['source'].get('events')
    rows = [(text('meta.package'), model['package_sha256']), (text('meta.records'), str(events) if events is not None else None),
            (text('meta.period'), period)]
    if local:
        rows.append((text('meta.jurisdiction'), local['name']))
        if local['procedure']:
            rows.append((text('meta.procedure'), text('procedure.' + local['procedure'])))
    rows.append((text('meta.language'), language_name(text.lang)))
    return rows


def notes(text):
    return [text('intro'), text('advice.translation')]


def limits(model, text):
    return [text.fact(limit) for limit in model['limits']]


def limit_key(limit):
    return limit['template_key'], json.dumps(limit['params'], sort_keys=True)


def common_limits(model):
    sets = [{limit_key(limit) for limit in scene['limits']} for scene in model['scenes']]
    shared = set.intersection(*sets) if len(sets) > 1 else set()
    return [limit for limit in (model['scenes'][0]['limits'] if sets else []) if limit_key(limit) in shared]


def own_limits(scene, shared):
    keys = {limit_key(limit) for limit in shared}
    return [limit for limit in scene['limits'] if limit_key(limit) not in keys]


def figures(pictures, keys):
    return [pictures[key] for key in keys if key in pictures and not (key == 'files' and len(pictures[key][2]) < 2)]


def checks(model, text):
    return [(text.glossary[row['tier']], row['status'], text.glossary[row['status']])
            for row in (model.get('assurance') or {}).get('ladder', [])]


def figure(picture):
    return '<figure><figcaption>' + escape(picture[0]) + '</figcaption>' + svg(picture) + '</figure>'


def html_report(model, text, pictures, local):
    e = escape
    out = [hero(language_name(text.lang), text('title'), [(label, marked(value)) for label, value in meta(model, text, local)],
                notes(text)),
           '<section class="card">' + heading('1. ' + text('heading.chronology'))]
    shared = common_limits(model)
    if shared:
        out.append('<ul class="notes-list">' + ''.join('<li>' + e(text.fact(limit)) + '</li>' for limit in shared) + '</ul>')
    out.extend(figure(picture) for picture in figures(pictures, ('timeline',)))
    for scene in model['scenes']:
        label = ref_label(scene['journal'], scene['from_seq'], scene['to_seq'])
        out.append('<article class="scene ' + e(scene['kind']) + '"><div class="when"><b>' + e(label) + '</b>'
                   + e(time_span(scene['at_from'], scene['at_to'])) + '</div><div><h3>' + e(text.glossary[scene['kind']]) + '</h3>')
        prose_count = min(7, len(scene['facts']))
        out.append('<p>' + ' '.join(e(shown_fact(text, fact)) + ' <sup>' + fact_refs(fact) + '</sup>'
                                    for fact in scene['facts'][:prose_count]) + '</p>')
        if len(scene['facts']) > prose_count:
            out.append('<table>' + ''.join('<tr><td>' + e(shown_fact(text, fact)) + '</td><td class="small">' + fact_refs(fact)
                                           + '</td></tr>' for fact in scene['facts'][prose_count:]) + '</table>')
        own = own_limits(scene, shared)
        if own:
            out.append('<ul class="notes-list">' + ''.join('<li>' + e(text.fact(limit)) + '</li>' for limit in own) + '</ul>')
        out.append('</div></article>')
    out.append('</section><section class="card">' + heading('2. ' + text('heading.assurance')))
    out.append('<table class="status">' + ''.join('<tr><td>' + e(label) + '</td><td>' + pill(status, shown) + '</td></tr>'
                                                  for label, status, shown in checks(model, text)) + '</table>')
    rows = ['<tr><td>' + e(text.glossary[scene['kind']]) + '</td><td>' + e(display_time(scene['at_from'])) + '</td><td>'
            + fact_refs(scene['facts'][0]) + '</td></tr>' for scene in model['scenes'] if scene['kind'] in ('anchoring', 'witnessing')]
    rows += ['<tr><td>' + e(anchor['kind']) + '</td><td>' + pill('pass', text.glossary['pass']) + ' ' + e(display_time(anchor['time']))
             + ' · ' + e(text.glossary[anchor['time_basis']]) + '</td><td><code>' + e(anchor['ref']) + '</code> · #'
             + str(anchor['to_seq']) + '</td></tr>' for anchor in model.get('verified_anchors', [])]
    if rows:
        out.append('<table>' + ''.join(rows) + '</table>')
    out.extend(figure(picture) for picture in figures(pictures, ('flow', 'files')))
    out.append('<p class="muted small">' + e(text('limit.recorded')) + '</p></section>')
    out.append('<section class="card">' + heading('3. ' + text('heading.limits')) + '<ul>'
               + ''.join('<li>' + e(line) + '</li>' for line in limits(model, text)) + '</ul></section>')
    out.append('<section class="card">' + heading('4. ' + text('heading.verify'))
               + ''.join('<pre class="cmd">' + e(command) + '</pre>' for command in commands(model)) + '</section>')
    if local:
        out.append('<section class="card" id="jurisdiction">' + heading('5. ' + text('heading.terms'))
                   + '<p class="muted small">' + e(text('jurisdiction.notice')) + ' ' + e(local['checked']) + '</p><table>')
        for term, basis, url in local['rows']:
            link = '<a class="src" href="' + e(url, quote=True) + '">' + e(text.glossary['source']) + ' ↗</a>' if url else ''
            out.append('<tr><td><strong>' + e(term) + '</strong></td><td>' + e(basis) + '</td><td>' + link + '</td></tr>')
        out.append('</table></section>')
    out.append('<section class="card">' + heading(text('heading.references')) + '<table class="records">')
    for journal, seq, digest in references(model):
        out.append('<tr id="' + ref_id(journal, seq) + '"><td>' + e(journal) + ' #' + str(seq) + '</td><td><code>' + digest
                   + '</code></td></tr>')
    out.append('</table></section><footer>' + e(footer(text)) + '</footer>')
    return page(text.lang, text('title'), ''.join(out))


def pdf_diagram(sheet, diagram):
    pdf = sheet.pdf
    title, height, shapes = diagram
    scale, band = pdf.epw / 1000, 650
    for top in range(0, height, band):
        sheet.need(min(band, height - top) * scale + 14)
        sheet.para(title, 8.6, MUTED)
        origin = pdf.get_y() + 3
        for shape in shapes:
            kind, *values = shape
            if not top <= values[1] < top + band:
                continue
            x, y = pdf.l_margin + values[0] * scale, origin + (values[1] - top) * scale
            color = values[-2]
            rgb = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
            if kind == 'text':
                pdf.set_xy(x, y - 2.6)
                pdf.set_font('Sans', size=6.6)
                pdf.set_text_color(*rgb)
                pdf.multi_cell(max(10, pdf.w - pdf.r_margin - x), 3.4, sheet.shown(values[2]), new_x='LMARGIN', new_y='NEXT')
            elif kind == 'rect':
                pdf.set_fill_color(*rgb)
                pdf.rect(x, y, values[2] * scale, values[3] * scale, style='F', round_corners=True, corner_radius=0.8)
            else:
                pdf.set_draw_color(*rgb)
                pdf.line(x, y, pdf.l_margin + values[2] * scale, origin + (values[3] - top) * scale)
        pdf.set_xy(pdf.l_margin, origin + min(band, height - top) * scale + 6)


def pdf_report_bytes(model, text, pictures, local):
    sheet = Sheet(text, footer(text), text('title'))
    sheet.hero(language_name(text.lang), text('title'), meta(model, text, local), notes(text))
    sheet.section('1. ' + text('heading.chronology'))
    shared = common_limits(model)
    sheet.bullets([text.fact(limit) for limit in shared], 8.2, MUTED)
    for picture in figures(pictures, ('timeline',)):
        pdf_diagram(sheet, picture)
    for scene in model['scenes']:
        sheet.need(30)
        sheet.heading(text.glossary[scene['kind']])
        sheet.para(ref_label(scene['journal'], scene['from_seq'], scene['to_seq']) + '  ·  '
                   + time_span(scene['at_from'], scene['at_to']), 7.6, MUTED, mono=True)
        for fact in scene['facts']:
            sheet.para(shown_fact(text, fact) + '  [' + plain_refs(fact) + ']', 9.2)
        sheet.bullets([text.fact(limit) for limit in own_limits(scene, shared)], 7.8, MUTED)
    sheet.section('2. ' + text('heading.assurance'))
    sheet.statuses(checks(model, text))
    for anchor in model.get('verified_anchors', []):
        sheet.para(anchor['kind'] + ' · ' + text.glossary['pass'] + ' · ' + display_time(anchor['time'])
                   + ' · ' + text.glossary[anchor['time_basis']] + ' · ' + anchor['ref'] + ' · #' + str(anchor['to_seq']), 8)
    for picture in figures(pictures, ('flow', 'files')):
        pdf_diagram(sheet, picture)
    sheet.para(text('limit.recorded'), 8.6, MUTED)
    sheet.section('3. ' + text('heading.limits'))
    sheet.bullets(limits(model, text))
    sheet.section('4. ' + text('heading.verify'))
    sheet.code(commands(model))
    if local:
        sheet.section('5. ' + text('heading.terms'))
        sheet.para(text('jurisdiction.notice') + ' ' + local['checked'], 8.6, MUTED)
        sheet.table([(term, basis, url or '') for term, basis, url in local['rows']], (0.26, 0.44, 0.30), (2,), 8)
    sheet.section(text('heading.references'))
    sheet.table([(journal + ' #' + str(seq), digest) for journal, seq, digest in references(model)], (0.2, 0.8), (1,), 7.4)
    return sheet.output()


def write(model, out, lang='en', jurisdiction_code=None, outputs=OUTPUTS, diagram_names=DIAGRAMS, procedure='criminal'):
    text = Texts(lang)
    local = jurisdiction(jurisdiction_code, procedure)
    pictures = {k: v for k, v in diagrams(model, text).items() if k in diagram_names} if (
        diagram_names and set(outputs) & {'pdf', 'html', 'svg'}) else {}
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if 'svg' in outputs:
        (out / 'diagrams').mkdir(exist_ok=True)
        for name, picture in pictures.items():
            (out / 'diagrams' / (name + '.svg')).write_text(svg(picture), encoding='utf-8')
    if 'json' in outputs:
        (out / 'narrative.json').write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding='utf-8')
    if 'html' in outputs:
        (out / 'narrative.html').write_text(html_report(model, text, pictures, local), encoding='utf-8')
    if 'pdf' in outputs:
        (out / 'narrative.pdf').write_bytes(pdf_report_bytes(model, text, pictures, local))
