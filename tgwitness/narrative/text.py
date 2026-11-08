from decimal import Decimal
import json
from pathlib import Path
import re

LANGUAGES = ('en', 'de', 'fr', 'es', 'it', 'pt', 'nl', 'pl', 'cs', 'sk', 'uk', 'ru', 'ro', 'bg',
             'hu', 'el', 'sv', 'da', 'fi', 'no', 'lt', 'lv', 'et', 'tr', 'ja')
ROOT = Path(__file__).parent


def category(number, lang):
    number = abs(Decimal(str(number)))
    if not number.is_finite():
        raise ValueError('Plural count must be finite')
    integer, visible = int(number), max(0, -number.as_tuple().exponent)
    if lang == 'ja':
        return 'other'
    if lang in ('ru', 'uk'):
        if visible:
            return 'other'
        return 'one' if integer % 10 == 1 and integer % 100 != 11 else \
            'few' if integer % 10 in (2, 3, 4) and integer % 100 not in (12, 13, 14) else 'many'
    if lang == 'pl':
        if visible:
            return 'other'
        return 'one' if integer == 1 else 'few' if integer % 10 in (2, 3, 4) and integer % 100 not in (12, 13, 14) else 'many'
    if lang in ('cs', 'sk'):
        return 'many' if visible else 'one' if integer == 1 else 'few' if 2 <= integer <= 4 else 'other'
    if lang == 'lt':
        if number != integer:
            return 'many'
        return 'one' if integer % 10 == 1 and not 11 <= integer % 100 <= 19 else \
            'few' if 2 <= integer % 10 <= 9 and not 11 <= integer % 100 <= 19 else 'other'
    if lang == 'lv':
        fraction = int(''.join(map(str, number.as_tuple().digits[-visible:]))) if visible else 0
        if number % 10 == 0 or 11 <= number % 100 <= 19 or visible == 2 and 11 <= fraction % 100 <= 19:
            return 'zero'
        return 'one' if (number % 10 == 1 and number % 100 != 11 or
                         visible == 2 and fraction % 10 == 1 and fraction % 100 != 11 or
                         visible != 2 and fraction % 10 == 1) else 'other'
    if lang == 'ro':
        return 'one' if number == 1 and not visible else 'few' if visible or number == 0 or 1 <= number % 100 <= 19 else 'other'
    if lang in ('fr', 'pt'):
        if integer in (0, 1):
            return 'one'
    if lang in ('fr', 'pt', 'es', 'it') and not visible and integer != 0 and integer % 1000000 == 0:
        return 'many'
    if lang == 'da' and (number == 1 or number != integer and integer in (0, 1)):
        return 'one'
    return 'one' if number == 1 and (not visible or lang in ('tr', 'hu', 'no', 'bg', 'el', 'es')) else 'other'


def parse(text, depth=0):
    if depth > 12 or len(text) > 20000:
        raise ValueError('Template limit exceeded')
    nodes, position = [], 0
    while position < len(text):
        start = text.find('{', position)
        if start < 0:
            if '}' in text[position:]:
                raise ValueError('Unmatched template brace')
            nodes.append(text[position:])
            break
        nodes.append(text[position:start])
        level, end = 1, start + 1
        while end < len(text) and level:
            level += (text[end] == '{') - (text[end] == '}')
            end += 1
        if level:
            raise ValueError('Unclosed template brace')
        body = text[start + 1:end - 1]
        parts = body.split(',', 2)
        name = parts[0].strip()
        if not re.fullmatch(r'[a-z][a-z_]*', name):
            raise ValueError('Invalid placeholder')
        if len(parts) == 1:
            nodes.append((name, None))
        else:
            if len(parts) != 3 or parts[1].strip() != 'plural':
                raise ValueError('Unsupported ICU formatter; only catalog plural syntax is accepted')
            forms, rest = {}, parts[2].strip()
            while rest:
                match = re.match(r'(zero|one|two|few|many|other|=\d+)\s*\{', rest)
                if not match or match[1] in forms:
                    raise ValueError('Invalid or duplicate plural branch')
                level, end_branch = 1, match.end()
                while end_branch < len(rest) and level:
                    level += (rest[end_branch] == '{') - (rest[end_branch] == '}')
                    end_branch += 1
                if level:
                    raise ValueError('Unclosed plural branch')
                forms[match[1]] = parse(rest[match.end():end_branch - 1], depth + 1)
                rest = rest[end_branch:].strip()
            if 'other' not in forms:
                raise ValueError('ICU plural needs other')
            nodes.append((name, forms))
        position = end
    return nodes


def placeholders(nodes):
    found = set()
    for node in nodes:
        if not isinstance(node, str):
            name, forms = node
            found.add(name)
            for branch in (forms or {}).values():
                found.update(placeholders(branch))
    return found


def render(nodes, params, lang, plural=None):
    result = []
    for node in nodes:
        if isinstance(node, str):
            result.append(node.replace('#', str(plural)) if plural is not None else node)
            continue
        name, forms = node
        value = params[name]
        if forms is None:
            result.append(str(value))
        else:
            choice = forms.get('=' + str(value), forms.get(category(value, lang), forms['other']))
            result.append(render(choice, params, lang, value))
    return ''.join(result)


class Texts:
    def __init__(self, lang):
        if lang not in LANGUAGES:
            raise ValueError('Unsupported narrative language')
        self.lang = lang
        self.values = json.loads((ROOT / 'texts' / (lang + '.json')).read_text(encoding='utf-8'))
        self.glossary = json.loads((ROOT / 'texts' / ('glossary.' + lang + '.json')).read_text(encoding='utf-8'))

    def __call__(self, key, **params):
        nodes = parse(self.values[key])
        if placeholders(nodes) != set(params):
            raise ValueError('Template parameters differ: ' + key)
        return render(nodes, params, self.lang)

    def fact(self, value):
        params = dict(value['params'])
        if value['template_key'] == 'record.field':
            params['field'] = self.glossary.get(params['field'], params['field'])
            params['value'] = self.glossary.get(str(params['value']), params['value'])
        if value['template_key'] == 'assurance.state':
            params['tier'] = self.glossary.get(params['tier'], params['tier'])
            params['status'] = self.glossary.get(params['status'], params['status'])
        return self(value['template_key'], **params)
