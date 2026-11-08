from html import escape
import json
from pathlib import Path
from types import SimpleNamespace

from .. import pdf_report
from .diagrams import diagrams, svg
from .config import DIAGRAMS, OUTPUTS
from .text import Texts


def references(model):
    return sorted({(r['journal'], r['seq'], r['hash']) for s in model['scenes'] for f in s['facts']
                   for r in f['evidence']})


def ref_id(ref):
    return 'ref-' + ref['journal'] + '-' + str(ref['seq'])


def jurisdiction(code):
    if code is None:
        return None
    root = Path(__file__).parent / 'jurisdictions'
    if code not in {p.stem for p in root.glob('*.json')}:
        raise ValueError('Unsupported jurisdiction')
    return json.loads((root / (code + '.json')).read_text(encoding='utf-8'))


def commands(model):
    return ['python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --strict --json',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --check-drand --check-bitcoin --strict --plain',
            'python -m tgwitness.verify PACKAGE.zip --fingerprint TRUSTED_COLLECTOR_FP --witness WITNESS.zip --witness-fingerprint TRUSTED_WITNESS_FP --require-tier witness_anchored --strict']


def local_rows(local):
    if not local:
        return []
    rows = [(local['code'], local['scope'], None)]
    for key in ('expert_role', 'esig_regulation', 'data_access_basis', 'timestamp_recognition'):
        value = local.get(key)
        if value:
            rows.append((value['term'], value.get('basis', value.get('qes_name', '')), value['source']))
    return rows


def fact_refs(fact):
    return ' '.join('<a href="#' + ref_id(r) + '">' + escape(r['journal']) + ' #' + str(r['seq']) + '</a>' for r in fact['evidence'])


def html_report(model, text, pictures, local):
    e = escape
    out = ['<!doctype html><html lang="' + text.lang + '"><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'self\' data:; base-uri \'none\'">',
           '<title>' + e(text('title')) + '</title><style>body{font:17px/1.6 system-ui,sans-serif;color:#163844;max-width:1050px;margin:40px auto;padding:0 24px;overflow-wrap:anywhere}h1,h2{line-height:1.2}article{border-top:1px solid #cad6d6;padding:20px 0}.limit{color:#65523a}svg{width:100%;height:auto}code,pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:#165c74}table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #ddd;padding:6px;overflow-wrap:anywhere}footer{border-top:1px solid #ddd;margin-top:30px}</style><body>',
           '<h1>1. ' + e(text('title')) + '</h1><p>' + e(text('intro')) + '</p>',
           '<p class="limit">' + e(text('limit.review')) + '</p>',
           '<code>SHA-256 ' + e(model['package_sha256']) + '</code>',
           '<h2>2. ' + e(text('heading.chronology')) + '</h2>']
    if 'timeline' in pictures:
        out.append(svg(pictures['timeline']))
    for scene in model['scenes']:
        out.append('<article><h3>' + e(text.glossary[scene['kind']]) + '</h3>')
        prose_count = min(7, len(scene['facts']))
        out.append('<p>' + ' '.join(e(text.fact(fact)) + ' <sup>' + fact_refs(fact) + '</sup>' for fact in scene['facts'][:prose_count]) + '</p>')
        if len(scene['facts']) > prose_count:
            out.append('<table>')
            for fact in scene['facts'][prose_count:]:
                out.append('<tr><td>' + e(text.fact(fact)) + '</td><td>' + fact_refs(fact) + '</td></tr>')
            out.append('</table>')
        out.extend('<p class="limit">' + e(text.fact(limit)) + '</p>' for limit in scene['limits'])
        out.append('</article>')
    out.append('<h2>3. ' + e(text('heading.assurance')) + '</h2>')
    for key in ('ladder', 'flow', 'files'):
        if key in pictures:
            out.append(svg(pictures[key]))
    out.append('<table>')
    for row in (model.get('assurance') or {}).get('ladder', []):
        out.append('<tr><td>' + e(text.glossary[row['tier']]) + '</td><td>' + e(text.glossary[row['status']]) + '</td></tr>')
    out.append('</table><table>')
    for scene in model['scenes']:
        if scene['kind'] in ('anchoring', 'witnessing'):
            out.append('<tr><td>' + e(text.glossary[scene['kind']]) + '</td><td>' + e(scene['at_from']) + '</td><td>' + fact_refs(scene['facts'][0]) + '</td></tr>')
    for anchor in model.get('verified_anchors', []):
        out.append('<tr><td>' + e(anchor['kind']) + '</td><td>' + e(text.glossary['pass']) + ' · ' + e(anchor['time']) +
                   ' · ' + e(text.glossary[anchor['time_basis']]) + '</td><td><code>' + e(anchor['ref']) + '</code> · #' + str(anchor['to_seq']) + '</td></tr>')
    out.extend(['</table><p class="limit">' + e(text('limit.recorded')) + '</p>',
                '<h2>4. ' + e(text('heading.limits')) + '</h2>'])
    out.extend('<p class="limit">' + e(text.fact(limit)) + '</p>' for limit in model['limits'])
    out.append('<h2>5. ' + e(text('heading.verify')) + '</h2>')
    out.extend('<pre>' + e(command) + '</pre>' for command in commands(model))
    if local:
        out.extend(['<section id="jurisdiction"><h2>6. ' + e(text('heading.terms')) + '</h2>',
                    '<p class="limit">' + e(text('jurisdiction.notice')) + '</p>',
                    '<table>'])
        for index, (term, basis, url) in enumerate(local_rows(local)):
            link = '<a href="' + e(url, quote=True) + '">' + e(text.glossary['source']) + ' [' + str(index) + ']</a>' if url else ''
            out.append('<tr><td>' + e(term) + '</td><td>' + e(basis) + '</td><td>' + link + '</td></tr>')
        out.append('</table></section>')
    out.append('<h2>' + e(text('heading.references')) + '</h2><table>')
    for journal, seq, digest in references(model):
        out.append(f'<tr id="ref-{journal}-{seq}"><td>{e(journal)} #{seq}</td><td><code>{digest}</code></td></tr>')
    out.append('</table><footer>' + e(text('limit.review')) + '</footer></body></html>')
    return ''.join(out)


def pdf_diagram(pdf, diagram):
    title, height, shapes = diagram
    scale, band = pdf.epw / 1000, 650
    for top in range(0, height, band):
        drawn_height = min(band, height - top) * scale + 20
        if pdf.get_y() + drawn_height > pdf.h - pdf.b_margin:
            pdf.add_page()
        pdf.line_text(title, size=13, style='B')
        origin = pdf.get_y() + 5
        for shape in shapes:
            kind, *values = shape
            if not top <= values[1] < top + band:
                continue
            x, y = pdf.l_margin + values[0] * scale, origin + (values[1] - top) * scale
            color = values[-2]
            rgb = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
            if kind == 'text':
                pdf.set_xy(x, y)
                pdf.set_font('Sans', size=7)
                pdf.set_text_color(*rgb)
                pdf.multi_cell(max(10, pdf.w - pdf.r_margin - x), 3.5, values[2], new_x='LMARGIN', new_y='NEXT')
            elif kind == 'rect':
                pdf.set_fill_color(*rgb)
                pdf.rect(x, y, values[2] * scale, values[3] * scale, style='F')
            else:
                pdf.set_draw_color(*rgb)
                pdf.line(x, y, pdf.l_margin + values[2] * scale, origin + (values[3] - top) * scale)
        pdf.set_xy(pdf.l_margin, origin + min(band, height - top) * scale + 8)


def pdf_report_bytes(model, text, pictures, local):
    pdf = pdf_report.document(SimpleNamespace(language=text.lang, direction='ltr'), text('limit.review'))
    pdf.set_title(text('title'))
    pdf.add_page()
    pdf.line_text('1. ' + text('title'), size=20, style='B')
    pdf.line_text(text('intro'))
    pdf.line_text('SHA-256 ' + model['package_sha256'], family='Mono', size=8)
    pdf.line_text('2. ' + text('heading.chronology'), size=14, style='B')
    if 'timeline' in pictures:
        pdf_diagram(pdf, pictures['timeline'])
    for scene in model['scenes']:
        if pdf.will_page_break(25):
            pdf.add_page()
        pdf.line_text(text.glossary[scene['kind']], size=12, style='B')
        for fact in scene['facts']:
            refs = ', '.join(r['journal'] + ' #' + str(r['seq']) for r in fact['evidence'])
            pdf.line_text(text.fact(fact) + ' [' + refs + ']')
        for limit in scene['limits']:
            pdf.line_text(text.fact(limit), size=8)
    pdf.line_text('3. ' + text('heading.assurance'), size=14, style='B')
    for key in ('ladder', 'flow', 'files'):
        if key in pictures:
            pdf_diagram(pdf, pictures[key])
    for row in (model.get('assurance') or {}).get('ladder', []):
        pdf.line_text(text('assurance.state', tier=text.glossary[row['tier']], status=text.glossary[row['status']]))
    for anchor in model.get('verified_anchors', []):
        pdf.line_text(anchor['kind'] + ' · ' + text.glossary['pass'] + ' · ' + anchor['time'] +
                      ' · ' + text.glossary[anchor['time_basis']], size=8)
        pdf.line_text(anchor['ref'] + ' · #' + str(anchor['to_seq']), size=8)
    pdf.line_text('4. ' + text('heading.limits'), size=14, style='B')
    for limit in model['limits']:
        pdf.line_text(text.fact(limit))
    pdf.line_text('5. ' + text('heading.verify'), size=14, style='B')
    for command in commands(model):
        pdf.line_text(command, family='Mono', size=8)
    if local:
        pdf.line_text('6. ' + text('heading.terms'), size=14, style='B')
        pdf.line_text(text('jurisdiction.notice'))
        for term, basis, url in local_rows(local):
            pdf.line_text(term + ' · ' + basis, size=9)
            if url:
                pdf.line_text(url, size=7)
    pdf.add_page()
    pdf.line_text(text('heading.references'), size=14, style='B')
    for journal, seq, digest in references(model):
        pdf.line_text(journal + ' #' + str(seq) + ': ' + digest, family='Mono', size=7)
    return bytes(pdf.output())


def write(model, out, lang='en', jurisdiction_code=None, outputs=OUTPUTS, diagram_names=DIAGRAMS):
    text = Texts(lang)
    local = jurisdiction(jurisdiction_code)
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
