"""Embed the reviewed offline catalogue so verify.py remains a single-file tool."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import zlib

ROOT = Path(__file__).resolve().parents[1]
START = '# BEGIN GENERATED VERIFIER LANGUAGES\n'
END = '# END GENERATED VERIFIER LANGUAGES\n'


def embedded(catalogue):
    raw = json.dumps(catalogue, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    payload = base64.b64encode(zlib.compress(raw, 9)).decode('ascii')
    return (START + '# Source: verifier_languages.json; update with tools/sync_verifier_languages.py\n'
            + '# Catalogue SHA-256: ' + hashlib.sha256(raw).hexdigest() + '\n'
            + 'VERIFIER_LANGUAGE_DATA = (\n'
            + ''.join('    "' + payload[n:n + 112] + '"\n' for n in range(0, len(payload), 112)) + ')\n'
            + END)


def validate(catalogue):
    source = (ROOT / 'tgwitness/i18n.py').read_text(encoding='utf-8')
    import ast
    languages = next(ast.literal_eval(node.value) for node in ast.parse(source).body
                     if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'LANGUAGES' for t in node.targets))
    if tuple(catalogue) != languages:
        raise ValueError('Verifier languages must match the panel, including their order')
    for lang, entry in catalogue.items():
        if set(entry) != {'name', 'words', 'reader', 'explain'} or not entry['name']:
            raise ValueError('Invalid verifier language: ' + lang)
        for section in ('words', 'reader', 'explain'):
            if entry[section].keys() != catalogue['en'][section].keys():
                raise ValueError('Missing or extra translations: ' + lang + '/' + section)
            for key, value in entry[section].items():
                if not isinstance(value, str) or not value.strip() or '\ufffd' in value:
                    raise ValueError('Empty or damaged translation: ' + lang + '/' + key)
                placeholders = re.findall(r'\{\w+\}', catalogue['en'][section][key])
                if sorted(re.findall(r'\{\w+\}', value)) != sorted(placeholders):
                    raise ValueError('Changed placeholders: ' + lang + '/' + key)
                if any(ord(c) < 32 and c not in '\n\t' for c in value):
                    raise ValueError('Control character in translation: ' + lang + '/' + key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    catalogue = json.loads((ROOT / 'tgwitness/verifier_languages.json').read_text(encoding='utf-8'))
    validate(catalogue)
    path = ROOT / 'tgwitness/verify.py'
    source = path.read_text(encoding='utf-8')
    a, b = source.index(START), source.index(END) + len(END)
    expected = source[:a] + embedded(catalogue) + source[b:]
    if args.check:
        if source != expected:
            raise SystemExit('Embedded verifier translations are stale; run tools/sync_verifier_languages.py')
        print('Verifier catalogue complete and synchronized:', len(catalogue), 'languages')
    else:
        path.write_text(expected, encoding='utf-8')


if __name__ == '__main__':
    main()
