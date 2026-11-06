import html
import json
from pathlib import Path
import re

if __package__:
    from . import build_site, site_i18n
else:
    import build_site
    import site_i18n

ROOT = Path(__file__).resolve().parents[1]


def prose_words(source):
    plain = re.sub(r'<(?:code|kbd|pre)\b[^>]*>.*?</(?:code|kbd|pre)>|<[^>]*>|'
                   r'https?://\S+|WIKISLOT\d+X|@@[A-Z_]+@@', '', source, flags=re.S)
    return re.findall(r'[A-Za-z]{3,}', html.unescape(plain))


def check(root=ROOT):
    strings, fragments, diagrams = build_site.inventory(root)
    labels = set(strings + diagrams)
    blocks = {}
    for page, fragment in fragments.items():
        for source in site_i18n.unit_texts(fragment):
            key = site_i18n.digest(source)
            item = blocks.setdefault(key, {'source': source, 'pages': []})
            item['pages'].append(page)
    results = []
    for lang in site_i18n.LANGUAGES:
        if lang == 'en':
            continue
        data = site_i18n.load(root, lang)
        missing_labels = sorted(key for key in labels if not data['strings'].get(key, '').strip())
        missing_blocks = [key for key in blocks if not data['blocks'].get(key, '').strip()]
        copied_prose = [key for key, item in blocks.items()
                        if data['blocks'].get(key) == item['source'] and len(prose_words(item['source'])) >= 12]
        negation = {'ru': 'не', 'uk': 'не', 'de': 'nicht'}.get(lang)
        repeated_negations = [key for key in blocks
                              if negation and re.search(r'\b' + negation + r'\s+' + negation + r'\b',
                                                        html.unescape(re.sub('<[^>]*>', '', data['blocks'].get(key, ''))), re.I)]
        results.append({'language': lang, 'missing_labels': missing_labels, 'missing_blocks': missing_blocks,
                        'copied_english_prose': copied_prose,
                        'repeated_negations': repeated_negations,
                        'affected_pages': sorted({page for key in missing_blocks + copied_prose + repeated_negations for page in blocks[key]['pages']})})
    failures = [item for item in results if item['missing_labels'] or item['missing_blocks'] or item['copied_english_prose'] or item['repeated_negations']]
    return {'passed': not failures, 'languages': len(results), 'pages': len(fragments), 'labels': len(labels),
            'unique_blocks': len(blocks), 'failures': failures}


if __name__ == '__main__':
    result = check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
