from html import escape
import hashlib

from ..verify import ASSURANCE_TIERS, parse_time

COLORS = {'pass': '#237546', 'absent': '#6b7280', 'fail': '#ae3030'}


def diagrams(model, text):
    glossary, scenes = text.glossary, model['scenes']
    result = {}
    timeline = []
    moments = [parse_time(s[k]).timestamp() for s in scenes for k in ('at_from', 'at_to')]
    earliest, span = (min(moments), max(1, max(moments) - min(moments))) if moments else (0, 1)
    for index, scene in enumerate(scenes):
        y = 40 + index * 48
        x = 270 + 680 * (parse_time(scene['at_from']).timestamp() - earliest) / span
        right = 270 + 680 * (parse_time(scene['at_to']).timestamp() - earliest) / span
        refs = f"{scene['journal']} #{scene['from_seq']}..{scene['to_seq']} | {scene['at_from']} | {scene['at_to']}"
        timeline.extend([('text', 12, y + 15, glossary[scene['kind']], '#163844', refs),
                         ('rect', x, y, max(10, right - x), 24, '#f5d6a0' if scene['kind'] == 'gaps' else '#b8d5d0', refs),
                         ('text', 270, y + 38, refs, '#374151', refs)])
        if scene['kind'] == 'gaps':
            for offset in range(0, int(max(10, right - x)), 8):
                timeline.append(('line', x + offset, y, min(x + offset + 12, max(x + 10, right)), y + 24, '#9a6521', refs))
        if scene['kind'] == 'external_input':
            timeline.extend([('line', x + 5, y - 18, x + 5, y, '#163844', refs),
                             ('line', x, y - 7, x + 5, y, '#163844', refs)])
        if scene['kind'] == 'anchoring':
            timeline.append(('line', x + 5, y - 5, x + 5, y + 28, '#237546', refs))
    timeline.append(('line', 270, 24, 960, 24, '#6b7280', ''))
    result['timeline'] = (text('timeline.title'), max(100, 50 + len(scenes) * 48), timeline)

    flow = []
    kinds = {s['kind'] for s in scenes}
    recorded_types = {f['params']['value'] for s in scenes for f in s['facts']
                      if f['template_key'] == 'record.field' and f['params']['field'] == 'event_kind'}
    has_proof = bool(model.get('verified_anchors'))
    nodes = [('Telegram', 'collection' in kinds), (glossary['collector'], True), (glossary['journal'], True),
             (glossary['checkpoint'], has_proof or any(k.startswith('checkpoint.') for k in recorded_types)),
             ('TSA / OTS / Bitcoin', has_proof), (glossary['witness'], bool(model.get('witness_source'))),
             (glossary['channel'] + ' / OTS', 'witness.posted' in recorded_types)]
    for index, (label, present) in enumerate(nodes):
        x, y = (20 + index * 195, 45) if index < 5 else (215 + (index - 5) * 300, 155)
        state = 'recorded' if present else 'absent'
        flow.extend([('rect', x, y, 175, 70, '#eef3f3', ''), ('text', x + 8, y + 23, label, '#163844', ''),
                     ('text', x + 8, y + 48, glossary[state], '#374151', '')])
        if index in (1, 2, 3, 4) and present and nodes[index - 1][1]:
            flow.append(('line', x - 20, y + 35, x, y + 35, '#6b7280', ''))
    flow.extend([('line', 492, 115, 492, 140, '#6b7280', ''),
                 ('line', 300, 140, 492, 140, '#6b7280', ''),
                 ('line', 300, 140, 300, 155, '#6b7280', ''),
                 ('line', 390, 190, 515, 190, '#6b7280', '')])
    flow.append(('text', 20, 245, glossary['collector'] + ' K: ' + model['source']['fingerprint'], '#374151', ''))
    if model.get('witness_source'):
        flow.append(('text', 20, 268, glossary['witness'] + ' W: ' + model['witness_source']['fingerprint'], '#374151', ''))
    flow.append(('text', 20, 295, text('limit.recorded'), '#374151', ''))
    result['flow'] = (text('flow.title'), 325, flow)

    ladder = []
    rows = {r['tier']: r for r in (model.get('assurance') or {}).get('ladder', [])}
    for index, tier in enumerate(ASSURANCE_TIERS):
        status = rows.get(tier, {}).get('status', 'absent')
        y = 35 + index * 48
        ladder.extend([('rect', 20 + index * 24, y, 900 - index * 24, 35, '#eef3f3', ''),
                       ('text', 32 + index * 24, y + 23, glossary[tier] + ': ' + glossary[status], COLORS[status], tier)])
    result['ladder'] = (text('ladder.title'), 340, ladder)

    files, file_count = [], 0
    for scene in scenes:
        if scene['kind'] not in ('external_input', 'export', 'analysis'):
            continue
        records = {}
        for fact in scene['facts']:
            if fact['template_key'] == 'record.field':
                for ref in fact['evidence']:
                    records.setdefault(ref['seq'], {})[fact['params']['field']] = fact['params']['value']
                    records[ref['seq']]['received_at'] = ref['observed_at']
                    if fact.get('anchor'):
                        records[ref['seq']]['anchor'] = fact['anchor']['kind'] + ' · ' + fact['anchor']['ref']
        for seq, fields in records.items():
            if not {'file', 'name', 'sha256'} & fields.keys():
                continue
            ref = scene['journal'] + ' #' + str(seq)
            values = [('file', fields.get('file', fields.get('name'))), ('sha256', fields.get('sha256')),
                      ('signature_claimed', fields.get('signature_claimed')),
                      ('signature_objects', fields.get('signature_objects', fields.get('sig_objects'))),
                      ('producer', fields.get('producer')), ('received_at', fields['received_at']), ('anchor', fields.get('anchor'))]
            top = 30 + file_count * 200
            files.append(('text', 20, top, ref, '#163844', ref))
            for index, (key, value) in enumerate(values):
                x, y = 20 + (index % 4) * 245, top + 15 + (index // 4) * 75
                label = str(value) if value is not None else glossary['absent']
                files.extend([('rect', x, y, 230, 62, '#eef3f3', ref),
                              ('text', x + 6, y + 18, glossary['observed_at' if key == 'received_at' else key], '#163844', ref),
                              ('text', x + 6, y + 43, label if len(label) < 30 else label[:27] + '…', '#374151', ref + ' | ' + label)])
                if index % 4:
                    files.append(('line', x - 15, y + 31, x, y + 31, '#6b7280', ref))
            file_count += 1
    if not files:
        files.append(('text', 20, 35, glossary['absent'], '#6b7280', ''))
    result['files'] = (text('files.title'), max(80, 30 + file_count * 200), files)
    return result


def svg(diagram):
    title, height, shapes = diagram
    identity = 'diagram-' + hashlib.sha256(title.encode()).hexdigest()[:12]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 {height}" role="img" aria-labelledby="{identity}-title {identity}-desc">',
             '<title id="' + identity + '-title">' + escape(title) + '</title><desc id="' + identity + '-desc">' + escape(title) + '</desc>',
             '<style>text{font-family:sans-serif;font-size:12px}g:focus rect,g:hover rect{stroke:#163844;stroke-width:2}</style>']
    for shape in shapes:
        kind, *values = shape
        title = '<title>' + escape(values[-1]) + '</title>' if values[-1] else ''
        if kind == 'text':
            x, y, label, color, _ = values
            limit = max(12, int((980 - x) / 7))
            if len(label) > limit:
                title = '<title>' + escape(values[-1] + ' | ' + label) + '</title>'
                label = label[:limit - 1] + '…'
            element = f'<text x="{x:.2f}" y="{y:.2f}" fill="{color}">{escape(label)}</text>'
        elif kind == 'rect':
            x, y, width, h, color, _ = values
            element = f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" height="{h}" rx="3" fill="{color}"/>'
        else:
            x, y, x2, y2, color, _ = values
            element = f'<line x1="{x:.2f}" y1="{y:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{color}"/>'
        parts.append('<g tabindex="0">' + title + element + '</g>')
    return ''.join(parts) + '</svg>'
