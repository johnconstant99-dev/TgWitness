from html import escape
import re

from ..verify import parse_time

RTL = ('ar', 'fa', 'he', 'ur')
AUTONYMS = {
    'am': 'አማርኛ', 'ar': 'العربية', 'bg': 'български', 'bn': 'বাংলা', 'ca': 'català', 'cs': 'čeština', 'da': 'dansk',
    'de': 'Deutsch', 'el': 'Ελληνικά', 'en': 'English', 'es': 'español', 'et': 'eesti', 'eu': 'euskara', 'fa': 'فارسی',
    'fi': 'suomi', 'fil': 'Filipino', 'fr': 'français', 'ga': 'Gaeilge', 'gl': 'galego', 'he': 'עברית', 'hi': 'हिन्दी',
    'hu': 'magyar', 'id': 'Bahasa Indonesia', 'it': 'italiano', 'ja': '日本語', 'ko': '한국어', 'lt': 'lietuvių',
    'lv': 'latviešu', 'ms': 'Bahasa Melayu', 'nl': 'Nederlands', 'no': 'norsk', 'pl': 'polski', 'pt': 'português',
    'ro': 'română', 'ru': 'русский', 'sk': 'slovenčina', 'sv': 'svenska', 'th': 'ไทย', 'tr': 'Türkçe', 'uk': 'українська',
    'ur': 'اردو', 'uz': 'oʻzbekcha', 'vi': 'Tiếng Việt', 'zh': '简体中文', 'zh-Hant': '繁體中文'}
TONES = {'pass': 'ok', 'met': 'ok', 'partial': 'warn', 'unchecked': 'warn', 'fail': 'bad', 'failed': 'bad'}
MARKS = {'ok': '✓', 'warn': '◐', 'bad': '✕', 'none': '–'}
HASH = re.compile(r'\b[0-9a-f]{64}\b')
CSS = (
    ':root{--ink:#142c3b;--muted:#596870;--line:#d6dbda;--fill:#f5f5f0;--gold:#c69e5b;--ok:#17663a;--warn:#8a4b00;'
    '--bad:#a1191f;--page:#eef0f2}*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}'
    'body{margin:0;background:var(--page);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;'
    'overflow-wrap:break-word}.wrap{max-width:1040px;margin:0 auto;padding:32px 24px 56px}'
    '.hero{background:var(--ink);color:#fff;border-bottom:3px solid var(--gold);padding:26px 40px 30px;border-radius:6px 6px 0 0}'
    '.eyebrow{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font:600 11px/1.4 system-ui,sans-serif;'
    'letter-spacing:.14em;text-transform:uppercase;color:var(--gold);border-bottom:1px solid rgba(255,255,255,.16);'
    'padding-bottom:14px;margin-bottom:22px}.hero h1{font:600 clamp(28px,4.2vw,42px)/1.15 Georgia,"Times New Roman",serif;'
    'margin:0;display:flex;flex-wrap:wrap;align-items:center;gap:12px 18px}.badge{font:700 11px/1 system-ui,sans-serif;'
    'letter-spacing:.12em;text-transform:uppercase;padding:7px 11px;border-radius:999px;background:var(--gold);color:var(--ink)}'
    '.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px 32px;margin:26px 0 0}'
    '.meta dt{font:600 10.5px/1.4 system-ui,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:#9fb3bc}'
    '.meta dd{margin:3px 0 0;font-weight:600;overflow-wrap:anywhere}.meta code{background:rgba(255,255,255,.08);color:#fff}'
    '.notes{background:#fff;border:1px solid var(--line);border-top:0;border-radius:0 0 6px 6px;padding:18px 40px;'
    'color:var(--muted);font-size:14.5px}.notes p{margin:4px 0}'
    '.card{background:#fff;border:1px solid var(--line);border-radius:6px;padding:30px 40px;margin-top:22px}'
    'h2{font:600 26px/1.25 Georgia,"Times New Roman",serif;margin:0 0 18px;display:flex;gap:14px;align-items:baseline}'
    'h2 .num{font:600 13px/1 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--gold);letter-spacing:.06em}'
    'h3{font-size:17px;line-height:1.35;margin:28px 0 10px}h3:first-child{margin-top:0}p{margin:10px 0}'
    'a{color:#165c74}.muted{color:var(--muted)}.small{font-size:14px}'
    '[dir=rtl] :is(p,li,dd,td,blockquote,h3,h4,summary){unicode-bidi:plaintext}'
    'code,.mono{font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}'
    'code{background:var(--fill);padding:1px 5px;border-radius:3px;overflow-wrap:anywhere}'
    'pre.cmd{background:#10232e;color:#e3ecef;padding:13px 16px 13px 36px;text-indent:-20px;border-radius:5px;'
    'white-space:pre-wrap;overflow-wrap:normal;word-break:normal;margin:10px 0;font:13px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;direction:ltr;text-align:left}'
    'table{border-collapse:collapse;width:100%}td,th{text-align:start;vertical-align:top;padding:10px 8px;'
    'border-bottom:1px solid var(--line)}th{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}'
    'table.form td{padding:16px 8px 6px;vertical-align:bottom}table.form td.label{color:var(--muted);font-size:14.5px;width:42%}'
    'table.form td.blank{border-bottom:1.5px solid var(--ink)}table.form.numbers td.label{width:6%}'
    'table.kv td:first-child{color:var(--muted);width:34%}table.records td:first-child{color:var(--muted);width:150px}'
    'ul,ol{padding-inline-start:22px}li{margin:6px 0}ul.check{list-style:none;padding:0}'
    'ul.check li{position:relative;padding-inline-start:30px}ul.check li::before{content:"";position:absolute;'
    'inset-inline-start:0;top:4px;width:15px;height:15px;border:1.5px solid var(--ink);border-radius:2px}'
    'ul.refs{list-style:none;padding:0}ul.refs li{padding:10px 0;border-bottom:1px solid var(--line);margin:0}'
    'a.src{display:inline-block;font-size:12.5px;font-weight:600;text-decoration:none;border:1px solid #b9cdd3;'
    'border-radius:999px;padding:1px 9px;margin-inline-start:6px;white-space:nowrap}'
    'blockquote{margin:12px 0;padding:13px 18px;border-inline-start:3px solid var(--warn);background:#fbf6ee;'
    'font:16px/1.55 Georgia,"Times New Roman",serif;border-radius:0 4px 4px 0}blockquote.second{border-color:var(--gold);'
    'background:var(--fill)}.box{border:1px solid var(--line);border-radius:6px;padding:18px 22px;margin:14px 0}'
    '.callout{border:1px solid #ecd2a8;background:#fdf8ef;border-radius:6px;padding:14px 20px;margin:14px 0;font-size:14.5px}'
    '.callout summary{cursor:pointer;font-weight:600;color:var(--warn)}.callout ul{margin:8px 0 0}'
    '.pill{display:inline-flex;align-items:center;gap:6px;font:600 12.5px/1.2 system-ui,sans-serif;padding:4px 11px;'
    'border-radius:999px;border:1px solid var(--line);color:var(--muted);background:#f3f5f6;white-space:nowrap}'
    '.pill.ok{color:var(--ok);background:#eaf4ee;border-color:#b7d8c3}.pill.warn{color:var(--warn);background:#fbf1e3;'
    'border-color:#ecd2a8}.pill.bad{color:var(--bad);background:#fbeaea;border-color:#efc1c1}'
    'table.status td:last-child{text-align:end;width:1%}'
    '.finding{border:1px solid var(--line);border-inline-start:4px solid #b9c3c7;border-radius:6px;padding:16px 22px;margin:12px 0}'
    '.finding.ok{border-inline-start-color:var(--ok)}.finding.warn{border-inline-start-color:#d29a3c}'
    '.finding.bad{border-inline-start-color:var(--bad)}.finding header{display:flex;justify-content:space-between;'
    'align-items:flex-start;gap:16px;flex-wrap:wrap}.finding h4{margin:0;font-size:16.5px}.finding p{margin:8px 0 0}'
    '.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}'
    'ul.marks{list-style:none;padding:0}ul.marks li{position:relative;padding-inline-start:28px}'
    'ul.marks li::before{position:absolute;inset-inline-start:0;top:0;font-weight:700}ul.marks.yes li::before{content:"✓";'
    'color:var(--ok)}ul.marks.no li::before{content:"✕";color:var(--bad)}ul.marks li span{display:block;color:var(--muted);'
    'font-size:14px}figure{margin:18px 0;border:1px solid var(--line);border-radius:6px;padding:16px 18px}'
    'figure svg{width:100%;height:auto;display:block}figcaption{font-size:13px;color:var(--muted);margin-bottom:8px;font-weight:600}'
    '.scene{display:grid;grid-template-columns:200px 1fr;gap:6px 28px;padding:22px 0;border-top:1px solid var(--line)}'
    '.scene:first-of-type{border-top:0}.scene .when{font:12.5px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;'
    'color:var(--muted);direction:ltr}.scene .when b{display:block;font:600 11px/1.4 system-ui,sans-serif;letter-spacing:.1em;'
    'text-transform:uppercase;color:var(--gold);margin-bottom:6px}.scene h3{margin:0 0 6px}'
    '.scene.gaps h3{color:var(--warn)}sup a{font-size:11.5px;text-decoration:none;border-bottom:1px dotted}'
    'ul.notes-list{list-style:none;padding:0;margin:12px 0 0;font-size:13.5px;color:var(--muted)}'
    'ul.notes-list li{margin:3px 0;padding-inline-start:18px;position:relative}ul.notes-list li::before{content:"ⓘ";'
    'position:absolute;inset-inline-start:0;font-size:12px}tr:target{background:#fdf3dc}'
    'footer{color:var(--muted);font-size:13px;margin-top:28px;text-align:center}'
    '@media (max-width:720px){.wrap{padding:16px 12px 40px}.hero,.notes,.card{padding-left:20px;padding-right:20px}'
    '.scene{grid-template-columns:1fr}table.form td.label{width:50%}}'
    '@media print{body{background:#fff;font-size:11pt}.wrap{max-width:none;padding:0}.card,.notes{border:0;padding:12px 0;'
    'margin:0}.hero{border-radius:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}pre.cmd{white-space:pre-wrap;'
    '-webkit-print-color-adjust:exact;print-color-adjust:exact}.finding,blockquote,.box,figure,.scene{break-inside:avoid}'
    'h2,h3{break-after:avoid}a.src{border:0;padding:0}}')


def tone(status):
    return TONES.get(status, 'none')


def pill(status, label):
    kind = tone(status)
    return '<span class="pill ' + kind + '"><span aria-hidden="true">' + MARKS[kind] + '</span>' + escape(label) + '</span>'


def marked(value):
    return HASH.sub(lambda match: '<code>' + match[0] + '</code>', escape(value))


def language_name(code):
    name = AUTONYMS.get(code)
    return name + ' (' + code + ')' if name and name != code else code


def display_time(value):
    try:
        moment = parse_time(value)
    except Exception:
        return value
    text = moment.strftime('%Y-%m-%d %H:%M:%S')
    if moment.microsecond:
        text += '.' + f'{moment.microsecond:06d}'[:3]
    offset = moment.utcoffset()
    return text + (' UTC' if offset is not None and not offset.total_seconds() else moment.strftime(' %z'))


def time_span(start, end):
    first, last = display_time(start), display_time(end)
    if first == last:
        return first
    return first + ' – ' + (last[11:] if first[:10] == last[:10] else last)


def runs(numbers):
    ordered, found = sorted(set(numbers)), []
    for number in ordered:
        if found and number == found[-1][1] + 1:
            found[-1][1] = number
        else:
            found.append([number, number])
    return found


def ref_runs(evidence):
    journals = {}
    for ref in evidence:
        journals.setdefault(ref['journal'], []).append(ref['seq'])
    return [(journal, first, last) for journal, seqs in journals.items() for first, last in runs(seqs)]


def ref_label(journal, first, last):
    return journal + ' #' + str(first) + ('' if first == last else '–' + str(last))


def page(lang, title, body):
    direction = 'rtl' if lang in RTL else 'ltr'
    return ('<!doctype html><html lang="' + escape(lang) + '" dir="' + direction + '"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'img-src \'self\' data:; base-uri \'none\'">'
            '<title>' + escape(title) + '</title><style>' + CSS + '</style></head><body><main class="wrap">'
            + body + '</main></body></html>')


def hero(kind, title, meta, notes, badge=None):
    out = ['<header class="hero"><div class="eyebrow"><span>TG / WITNESS</span><span>' + escape(kind) + '</span></div>',
           '<h1>' + escape(title) + ('<span class="badge">' + escape(badge) + '</span>' if badge else '') + '</h1>']
    shown = [(label, value) for label, value in meta if value]
    if shown:
        out.append('<dl class="meta">' + ''.join('<div><dt>' + escape(label) + '</dt><dd>' + value + '</dd></div>'
                                                 for label, value in shown) + '</dl>')
    out.append('</header>')
    if notes:
        out.append('<div class="notes">' + ''.join('<p>' + escape(line) + '</p>' for line in notes) + '</div>')
    return ''.join(out)


def heading(title):
    number, _, rest = title.partition(' ')
    if number[:-1].isdigit() and number.endswith('.') and rest:
        return '<h2><span class="num">' + f'{int(number[:-1]):02d}' + '</span>' + escape(rest) + '</h2>'
    return '<h2>' + escape(title) + '</h2>'
