import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from ..verify import (ASSURANCE_TIERS, assurance, bounded_lines, cross_check_witness, open_archive, parse_time, safe_text,
                      verify_bundle, verify_witness)
from ..store import canonical
from .model import build, Limit
from dataclasses import asdict
from .render import write
from . import expert as examination
from .text import Texts
from .text import LANGUAGES
from .config import DIAGRAMS, OUTPUTS, resolve, validate, write_example


class RequirementsNotMet(ValueError):
    pass


def read_events(package, limit):
    with open_archive(package) as archive, archive.open('events.jsonl') as stream:
        events = []
        for line in bounded_lines(stream):
            if len(events) >= limit:
                raise ValueError(f'Narrative exceeds the configured limit of {limit} records per journal')
            events.append(json.loads(line))
    return events


def digest_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def generate(package, out, lang='en', jurisdiction=None, fingerprint=None, witness=None,
             witness_fingerprint=None, check_drand=False, check_bitcoin=False, tsa_ca=None,
             outputs=OUTPUTS, diagrams=DIAGRAMS, max_records=100000, scene_max_records=2000,
             require_tier='self_attested', require_pinned_signer=False, expert=False, procedure='criminal'):
    settings = validate(dict(lang=lang, jurisdiction=jurisdiction, fingerprint=fingerprint,
                            witness=witness, witness_fingerprint=witness_fingerprint, tsa_ca=tsa_ca,
                            check_drand=check_drand, check_bitcoin=check_bitcoin, outputs=outputs,
                            diagrams=diagrams, max_records=max_records, scene_max_records=scene_max_records,
                            require_tier=require_tier, require_pinned_signer=require_pinned_signer,
                            expert=expert, procedure=procedure))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if out.is_symlink() or any(out.iterdir()):
        raise ValueError('Narrative output must be an ordinary empty directory')
    with tempfile.TemporaryDirectory(prefix='.narrative-', dir=out) as scratch:
        scratch = Path(scratch)
        source = scratch / 'source.zip'
        shutil.copyfile(package, source)
        ca = None
        if tsa_ca:
            ca = scratch / 'tsa-ca.pem'
            shutil.copyfile(tsa_ca, ca)
        result = verify_bundle(source, fingerprint, tsa_ca=ca, check_drand=check_drand, check_bitcoin=check_bitcoin)
        if witness:
            other = scratch / 'witness.zip'
            shutil.copyfile(witness, other)
            checked = verify_witness(other, witness_fingerprint, check_drand, check_bitcoin)
            result['witness'] = cross_check_witness(checked, source, result)
        result['assurance'] = assurance(result)
        if any(row['status'] == 'fail' for row in result['assurance']['ladder']):
            raise ValueError('Contradictory evidence cannot produce a successful narrative')
        pinned = bool(fingerprint or (witness and witness_fingerprint and result['witness']['consistent']))
        if require_pinned_signer and not pinned:
            raise RequirementsNotMet('A trusted collector fingerprint or a matching pinned witness is required')
        actual_tier = result['assurance']['tier']
        if ASSURANCE_TIERS.index(actual_tier) < ASSURANCE_TIERS.index(require_tier):
            raise RequirementsNotMet(f'Required assurance tier {require_tier}; verified tier is {actual_tier}')
        model = build(read_events(source, max_records), result, max_scene_records=scene_max_records)
        if not pinned:
            model['limits'].append(asdict(Limit('assurance.state', {'tier': 'signer_pinned', 'status': 'absent'})))
        if witness:
            witness_model = build(read_events(other, max_records), checked, journal='witness',
                                  max_scene_records=scene_max_records)
            model['scenes'] += witness_model['scenes']
            model['scenes'].sort(key=lambda s: (parse_time(s['at_from']), s['journal'], s['from_seq']))
            model['witness_source'] = witness_model['source']
            model['witness_source']['package_sha256'] = digest_file(other)
        model['model_sha256'] = hashlib.sha256(canonical(model['scenes'])).hexdigest()
        model['package_sha256'] = digest_file(source)
        rendered = scratch / 'rendered'
        write(model, rendered, lang, jurisdiction, outputs=settings['outputs'], diagram_names=settings['diagrams'],
              procedure=settings['procedure'])
        public_settings = {key: value for key, value in settings.items() if key not in ('witness', 'tsa_ca')}
        receipt = {'format': 'tgwitness-narrative-run-v1', 'settings': public_settings,
                   'settings_sha256': hashlib.sha256(canonical(public_settings)).hexdigest(),
                   'package_sha256': model['package_sha256'],
                   'witness_package_sha256': model.get('witness_source', {}).get('package_sha256'),
                   'tsa_ca_sha256': digest_file(ca) if ca else None,
                   'signer_pinned': pinned, 'assurance_tier': actual_tier}
        receipt_text = json.dumps(receipt, ensure_ascii=False, indent=2)
        (rendered / 'narrative-run.json').write_text(receipt_text, encoding='utf-8')
        if settings['expert']:
            protocol = examination.build(result, model, settings, hashlib.sha256(receipt_text.encode('utf-8')).hexdigest())
            examination.write(protocol, rendered, Texts(lang), settings['outputs'])
        for file in rendered.iterdir():
            file.rename(out / file.name)
    return model


def main():
    parser = argparse.ArgumentParser(description='Build a source-linked narrative from a verified evidence journal')
    parser.add_argument('package', type=Path, nargs='?')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--config', type=Path, help='Explicit local JSON configuration file')
    parser.add_argument('--profile', help='Named profile within the configuration file')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--write-config', type=Path, help='Create an example configuration without overwriting a file')
    modes.add_argument('--print-config', action='store_true', help='Print resolved settings without reading a package')
    parser.add_argument('--lang', choices=LANGUAGES)
    parser.add_argument('--jurisdiction')
    parser.add_argument('--fingerprint')
    parser.add_argument('--witness', type=Path)
    parser.add_argument('--witness-fingerprint')
    parser.add_argument('--check-drand', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--check-bitcoin', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--tsa-ca', type=Path)
    parser.add_argument('--outputs', nargs='+', choices=OUTPUTS)
    parser.add_argument('--diagrams', nargs='+', choices=(*DIAGRAMS, 'none'))
    parser.add_argument('--max-records', type=int, help='Maximum records per journal; overflow fails without truncation')
    parser.add_argument('--scene-max-records', type=int, help='Maximum grouped records before restart cross-references')
    parser.add_argument('--require-tier', choices=ASSURANCE_TIERS)
    parser.add_argument('--require-pinned-signer', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--expert', action=argparse.BooleanOptionalAction, default=None,
                        help='Also write an expert examination protocol draft for the selected jurisdiction')
    parser.add_argument('--procedure', choices=examination.PROCEDURES, help='Procedure for the expert protocol')
    args = parser.parse_args()
    overrides = {key: value for key, value in vars(args).items() if value is not None and key not in
                 ('package', 'out', 'config', 'profile', 'write_config', 'print_config')}
    if overrides.get('jurisdiction') == 'none':
        overrides['jurisdiction'] = None
    if overrides.get('diagrams') == ['none']:
        overrides['diagrams'] = []
    try:
        if args.write_config:
            if args.package or args.out or args.config or args.profile or overrides:
                raise ValueError('--write-config cannot be combined with generation or profile settings')
            write_example(args.write_config)
            print(safe_text(args.write_config))
            return
        settings = resolve(args.config, args.profile, overrides)
    except (ValueError, OSError) as exc:
        parser.exit(2, safe_text(str(exc)) + '\n')
    if args.print_config:
        if args.package or args.out:
            parser.error('--print-config does not generate a report; omit PACKAGE and --out')
        print(json.dumps(settings, ensure_ascii=True, indent=2))
        return
    if args.package is None or args.out is None:
        parser.error('PACKAGE and --out are required to generate a report')
    try:
        generate(args.package, args.out, **settings)
    except RequirementsNotMet as exc:
        parser.exit(2, safe_text(str(exc)) + '\n')
    except Exception as exc:
        parser.exit(1, safe_text(type(exc).__name__ + ': ' + str(exc)) + '\n')
    print(safe_text(args.out))


if __name__ == '__main__':
    main()
