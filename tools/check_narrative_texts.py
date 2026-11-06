"""Validate narrative catalogs; release validation also requires external review policy."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.narrative.text import LANGUAGES, ROOT, parse, placeholders, render


def check(for_release=False):
    base = json.loads((ROOT / 'texts/en.json').read_text(encoding='utf-8'))
    glossary = json.loads((ROOT / 'texts/glossary.en.json').read_text(encoding='utf-8'))
    policy = json.loads((ROOT / 'review-policy.json').read_text(encoding='utf-8'))
    errors = []
    for lang in LANGUAGES:
        try:
            values = json.loads((ROOT / 'texts' / (lang + '.json')).read_text(encoding='utf-8'))
            words = json.loads((ROOT / 'texts' / ('glossary.' + lang + '.json')).read_text(encoding='utf-8'))
        except FileNotFoundError:
            errors.append(lang + ': missing catalog')
            continue
        if set(values) != set(base) or set(words) != set(glossary):
            errors.append(lang + ': keys differ')
            continue
        for key, template in values.items():
            try:
                tree = parse(template)
                expected = placeholders(parse(base[key]))
                if placeholders(tree) != expected:
                    raise ValueError('placeholders differ')
                if len(template) > 1.6 * len(base[key]):
                    raise ValueError('translation exceeds 1.6 times the English length')
                for count in (0, 1, 2, 5, 11, 21, 22, 101, '1.5'):
                    params = {k: count if k == 'n' else 'VALUE' for k in expected}
                    rendered = render(tree, params, lang)
                    if '{' in rendered or '}' in rendered:
                        raise ValueError('unresolved placeholders')
                for word in policy.get('forbidden_words', {}).get(lang, []):
                    if word.casefold() in template.casefold():
                        raise ValueError('forbidden evaluation: ' + word)
            except (ValueError, KeyError) as exc:
                errors.append(lang + '/' + key + ': ' + str(exc))
    if for_release:
        if policy['forbidden_words_status'] != 'approved-T7':
            errors.append('T7 forbidden-word policy has not been supplied and approved')
        if policy['custody_schema_status'] != 'integrated-T13':
            errors.append('T13 custody/spec integration has not been supplied and verified')
        for lang in ('en', 'de', 'fr', 'uk', 'ru'):
            if not policy.get('legal_native_review', {}).get(lang):
                errors.append(lang + ': native legal review absent')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--for-release', action='store_true')
    errors = check(parser.parse_args().for_release)
    for error in errors:
        print(error)
    if errors:
        raise SystemExit(1)
    print('Narrative catalogs: keys, placeholders, plural rendering, lengths and supplied word lists checked.')


if __name__ == '__main__':
    main()
