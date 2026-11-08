import json
from pathlib import Path
import re

from ..verify import ASSURANCE_TIERS
from .text import LANGUAGES, ROOT

FORMAT = 'tgwitness-narrative-config-v1'
OUTPUTS = ('pdf', 'html', 'json', 'svg')
DIAGRAMS = ('timeline', 'flow', 'ladder', 'files')
MAX_CONFIG_BYTES = 65536
DEFAULTS = {
    'lang': 'en', 'jurisdiction': None, 'outputs': list(OUTPUTS), 'diagrams': list(DIAGRAMS),
    'max_records': 100000, 'scene_max_records': 2000,
    'fingerprint': None, 'witness': None, 'witness_fingerprint': None, 'tsa_ca': None,
    'check_drand': False, 'check_bitcoin': False,
    'require_tier': 'self_attested', 'require_pinned_signer': False,
}
PATHS = ('witness', 'tsa_ca')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate configuration key: ' + key)
        result[key] = value
    return result


def validate(values):
    if not isinstance(values, dict):
        raise ValueError('Narrative settings must be an object')
    if unknown := values.keys() - DEFAULTS.keys():
        raise ValueError('Unknown narrative setting: ' + ', '.join(sorted(unknown)))
    result = {**DEFAULTS, **values}
    if result['lang'] not in LANGUAGES:
        raise ValueError('Unsupported narrative language')
    jurisdictions = {p.stem for p in (ROOT / 'jurisdictions').glob('*.json')}
    if result['jurisdiction'] is not None and (
            not isinstance(result['jurisdiction'], str) or result['jurisdiction'] not in jurisdictions):
        raise ValueError('Unsupported narrative jurisdiction')
    for key, allowed in (('outputs', OUTPUTS), ('diagrams', DIAGRAMS)):
        value = result[key]
        if (not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v in allowed for v in value)
                or len(value) != len(set(value))):
            raise ValueError(key + ' must contain distinct supported names')
        result[key] = list(value)
    if not set(result['outputs']) & {'pdf', 'html', 'json'}:
        raise ValueError('Select pdf, html or json so the facts and limitations accompany any diagrams')
    if 'svg' in result['outputs'] and not result['diagrams']:
        raise ValueError('SVG output requires at least one diagram')
    for key, ceiling in (('max_records', 1000000), ('scene_max_records', 10000)):
        if type(result[key]) is not int or not 1 <= result[key] <= ceiling:
            raise ValueError(key + ' must be an integer from 1 to ' + str(ceiling))
    for key in ('check_drand', 'check_bitcoin', 'require_pinned_signer'):
        if type(result[key]) is not bool:
            raise ValueError(key + ' must be a boolean')
    for key in ('fingerprint', 'witness_fingerprint'):
        if result[key] is not None and (not isinstance(result[key], str) or
                not re.fullmatch(r'[0-9a-f]{64}', result[key])):
            raise ValueError(key + ' must be a lowercase 64-digit SHA-256 fingerprint')
    for key in PATHS:
        value = result[key]
        if value is not None:
            if not isinstance(value, (str, Path)) or not str(value).strip() or '\x00' in str(value):
                raise ValueError(key + ' must be a nonempty local file path')
            result[key] = str(value)
    if result['require_tier'] not in ASSURANCE_TIERS:
        raise ValueError('Unsupported minimum assurance tier')
    return result


def read_config(path):
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('Narrative configuration exceeds 64 KiB')
    value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object)
    if not isinstance(value, dict) or value.get('format') != FORMAT:
        raise ValueError('Unsupported narrative configuration format')
    if value.keys() - {'format', 'defaults', 'profiles'}:
        raise ValueError('Unknown configuration document field')
    defaults, profiles = value.get('defaults', {}), value.get('profiles', {})
    validate(defaults)
    if not isinstance(profiles, dict):
        raise ValueError('profiles must be an object')
    for name, settings in profiles.items():
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', name):
            raise ValueError('Invalid profile name')
        if not isinstance(settings, dict):
            raise ValueError('Profile settings must be an object')
        validate({**defaults, **settings})
    return value


def resolve(path=None, profile=None, overrides=None):
    selected = {}
    if path:
        document = read_config(path)
        selected.update(document.get('defaults', {}))
        if profile:
            if profile not in document.get('profiles', {}):
                raise ValueError('Unknown narrative profile: ' + profile)
            selected.update(document['profiles'][profile])
        for key in PATHS:
            if selected.get(key) is not None:
                selected[key] = str((Path(path).resolve().parent / selected[key]).resolve())
    elif profile:
        raise ValueError('--profile requires --config')
    selected.update(overrides or {})
    return validate(selected)


def example():
    return {'format': FORMAT, 'defaults': validate({}), 'profiles': {
        'ru-html': {'lang': 'ru', 'outputs': ['html', 'json', 'svg']},
        'de-proof': {'lang': 'de', 'jurisdiction': 'DE', 'require_tier': 'witness_anchored',
                     'require_pinned_signer': True, 'check_drand': True, 'check_bitcoin': True},
    }}


def write_example(path):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(example(), stream, ensure_ascii=False, indent=2)
        stream.write('\n')
