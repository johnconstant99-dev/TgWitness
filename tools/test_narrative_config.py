"""Profiles may select presentation and raise requirements, but cannot fabricate evidence."""
import asyncio
from datetime import date
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import AsyncMock, patch
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.narrative import __main__ as cli
from tgwitness.narrative.config import FORMAT, MAX_CONFIG_BYTES, resolve, write_example
from tgwitness.narrative.model import build
from tgwitness.narrative.render import references
from tgwitness.narrative.text import Texts
from tgwitness.store import canonical
from tgwitness.verify import verify_bundle
from test_narrative import fixture


def config_file(tmp_path, defaults=None, profiles=None):
    path = tmp_path / 'narrative-config.json'
    path.write_text(json.dumps({'format': FORMAT, 'defaults': defaults or {}, 'profiles': profiles or {}}),
                    encoding='utf-8')
    return path


def test_profile_precedence_relative_paths_and_explicit_false(tmp_path, monkeypatch):
    config = config_file(tmp_path, {'lang': 'ru', 'witness': 'witness.zip', 'tsa_ca': 'ca.pem'}, {
        'expert': {'lang': 'de', 'jurisdiction': 'DE', 'check_drand': True, 'outputs': ['html', 'json']}})
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    settings = resolve(config, 'expert', {'lang': 'uk', 'check_drand': False})
    assert settings['lang'] == 'uk' and settings['jurisdiction'] == 'DE'
    assert settings['outputs'] == ['html', 'json'] and settings['check_drand'] is False
    assert Path(settings['witness']) == tmp_path / 'witness.zip'
    assert Path(settings['tsa_ca']) == tmp_path / 'ca.pem'
    assert resolve(config, 'expert', {'witness': Path('from-cli.zip')})['witness'] == 'from-cli.zip'


@pytest.mark.parametrize('settings', [
    {'skip_verification': True}, {'hide_limits': True}, {'translation_review': 'approved'},
    {'check_bitcoin': 'false'}, {'max_records': True}, {'max_records': 0}, {'max_records': 1000001},
    {'scene_max_records': 10001}, {'outputs': ['svg']}, {'outputs': []}, {'outputs': ['json', 'json']},
    {'diagrams': []}, {'fingerprint': 'embedded'}, {'lang': '../en'}, {'jurisdiction': '../DE'},
    {'require_tier': 'approved'}, {'witness': ''},
])
def test_invalid_or_verdict_overriding_settings_are_rejected(tmp_path, settings):
    config = config_file(tmp_path, settings)
    with pytest.raises(ValueError):
        resolve(config)


def test_duplicates_oversized_and_invalid_unused_profiles_fail(tmp_path):
    config = tmp_path / 'bad.json'
    config.write_text('{"format":"' + FORMAT + '","defaults":{"lang":"de","lang":"en"}}')
    with pytest.raises(ValueError, match='Duplicate'):
        resolve(config)
    config.write_bytes(b' ' * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ValueError, match='64 KiB'):
        resolve(config)
    config = config_file(tmp_path, profiles={'unused': {'skip_verification': True}})
    with pytest.raises(ValueError, match='Unknown narrative setting'):
        resolve(config)


def test_missing_profiles_and_unknown_document_fields_fail(tmp_path):
    with pytest.raises(ValueError, match='requires --config'):
        resolve(profile='missing')
    config = config_file(tmp_path)
    with pytest.raises(ValueError, match='Unknown narrative profile'):
        resolve(config, 'missing')
    data = json.loads(config.read_text())
    data['admin_override'] = True
    config.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='Unknown configuration document field'):
        resolve(config)


def test_json_only_skips_fonts_and_diagrams_and_records_public_settings(tmp_path):
    package, _ = fixture(tmp_path)
    config = config_file(tmp_path, {'lang': 'ja', 'outputs': ['json'], 'diagrams': []})
    out = tmp_path / 'json-only'
    with patch('tgwitness.narrative.render.pdf_report_bytes', side_effect=AssertionError('PDF not requested')), \
            patch('tgwitness.narrative.render.diagrams', side_effect=AssertionError('Diagrams not requested')):
        model = cli.generate(package, out, **resolve(config))
    assert {p.name for p in out.iterdir()} == {'narrative.json', 'narrative-run.json'}
    assert json.loads((out / 'narrative.json').read_text(encoding='utf-8')) == model
    receipt = json.loads((out / 'narrative-run.json').read_text(encoding='utf-8'))
    assert receipt['settings']['lang'] == 'ja' and receipt['settings']['outputs'] == ['json']
    assert receipt['package_sha256'] == hashlib.sha256(package.read_bytes()).hexdigest()
    assert receipt['settings_sha256'] == hashlib.sha256(canonical(receipt['settings'])).hexdigest()
    assert not receipt['signer_pinned'] and receipt['assurance_tier'] == 'self_attested'
    assert 'witness' not in receipt['settings'] and 'tsa_ca' not in receipt['settings']


@pytest.mark.parametrize('selected', [[], ['timeline'], ['ladder', 'files']])
def test_optional_diagrams_cannot_hide_assurance_limits_or_references(tmp_path, selected):
    package, events = fixture(tmp_path)
    out = tmp_path / 'html'
    model = cli.generate(package, out, outputs=['html'], diagrams=selected)
    html = (out / 'narrative.html').read_text(encoding='utf-8')
    assert html.count('<svg ') == len(selected)
    assert not (out / 'diagrams').exists()
    text = Texts('en')
    assert text('heading.limits') in html and text('limit.review') in html
    assert text.glossary['self_attested'] in html and text.glossary['absent'] in html
    assert all(event['hash'] in html for event in events)
    assert all((e['seq'], e['hash']) in {(r[1], r[2]) for r in references(model)} for e in events)


def test_svg_selection_and_scene_size_preserve_all_evidence(tmp_path):
    # Grouping changes the number of scenes, not the set of cited records or their hashes.
    events = [dict(seq=n, hash=f'{n:064x}', observed_at='2026-10-01T12:00:00+00:00',
                   kind='message.new', payload={}) for n in range(1, 6)]
    default = build(events, {})
    split = build(events, {}, max_scene_records=2)
    assert len(default['scenes']) == 1 and len(split['scenes']) == 3
    assert references(default) == references(split)
    package, _ = fixture(tmp_path)
    out = tmp_path / 'svg-selection'
    cli.generate(package, out, outputs=['json', 'svg'], diagrams=['timeline', 'files'], scene_max_records=2)
    assert {p.name for p in (out / 'diagrams').iterdir()} == {'timeline.svg', 'files.svg'}


def test_limits_fail_without_silent_truncation_or_partial_report(tmp_path):
    package, events = fixture(tmp_path)
    out = tmp_path / 'too-small'
    with pytest.raises(ValueError, match='configured limit'):
        cli.generate(package, out, outputs=['json'], max_records=len(events) - 1)
    assert list(out.iterdir()) == []
    accepted = cli.generate(package, tmp_path / 'exact-limit', outputs=['json'], max_records=len(events))
    assert len(references(accepted)) == len(events)


def test_minimum_tier_pin_and_wrong_pin_are_distinct_failures(tmp_path):
    package, _ = fixture(tmp_path)
    fingerprint = verify_bundle(package)['fingerprint']
    with pytest.raises(cli.RequirementsNotMet, match='trusted collector fingerprint'):
        cli.generate(package, tmp_path / 'unpinned', outputs=['json'], require_pinned_signer=True)
    with pytest.raises(cli.RequirementsNotMet, match='verified tier is self_attested'):
        cli.generate(package, tmp_path / 'insufficient', outputs=['json'], fingerprint=fingerprint,
                     require_tier='witness_anchored', require_pinned_signer=True)
    with pytest.raises(ValueError) as wrong:
        cli.generate(package, tmp_path / 'wrong-pin', outputs=['json'], fingerprint='0' * 64)
    assert not isinstance(wrong.value, cli.RequirementsNotMet)
    for name in ('unpinned', 'insufficient', 'wrong-pin'):
        assert list((tmp_path / name).iterdir()) == []
    out = tmp_path / 'pinned'
    model = cli.generate(package, out, outputs=['json'], fingerprint=fingerprint, require_pinned_signer=True)
    assert not any(limit['params'].get('tier') == 'signer_pinned' for limit in model['limits'])
    assert json.loads((out / 'narrative-run.json').read_text())['signer_pinned']


def test_witness_fingerprint_without_matching_witness_cannot_satisfy_pin(tmp_path):
    package, _ = fixture(tmp_path)
    with pytest.raises(cli.RequirementsNotMet):
        cli.generate(package, tmp_path / 'no-witness', outputs=['json'], witness_fingerprint='a' * 64,
                     require_pinned_signer=True)


@pytest.mark.parametrize('proof', ['confirmed', 'missing', 'mismatch'])
def test_required_witness_anchored_profile_checks_actual_signed_archives(tmp_path, proof):
    from tgwitness.capture_proof import capture_head
    from tgwitness.security import Vault
    from tgwitness.store import Store
    from tgwitness.verify import OTS_MAGIC, OTS_BITCOIN, witness_challenge
    from tgwitness.witness import Witness, export
    from test_witness_freshness import BEACON, FRESH

    package, _ = fixture(tmp_path)
    store, vault = Store(tmp_path / 'collector'), Vault(tmp_path / 'collector')
    store.bind(vault)
    observer = Witness(tmp_path / 'observer', 'https://collector.invalid', 'synthetic')
    try:
        with patch('tgwitness.store.utcnow', return_value='2026-10-04T12:00:00+00:00'):
            observer._freshness = dict(FRESH)
            answer = capture_head(store, vault, {}, witness_challenge(FRESH), consistency_from=0)
            observer.store.append('witness.anchor', observer.check(answer))
        with patch('tgwitness.store.utcnow', return_value='2026-10-05T00:00:00+00:00'), \
                patch('tgwitness.witness.utc_date', return_value=date(2026, 10, 5)), \
                patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('synthetic offline calendar'))):
            seal = asyncio.run(observer.daily())
        digest = hashlib.sha256(canonical(seal)).digest()
        if proof != 'missing':
            folder = observer.store.root / 'anchors'
            folder.mkdir(exist_ok=True)
            (folder / 'daily-2026-10-04.synthetic.ots').write_bytes(
                OTS_MAGIC + b'\x01\x08' + digest + b'\x00' + OTS_BITCOIN + b'\x01\x64')
        witness_fp = observer.fingerprint
    finally:
        observer.close()
        store.close()
    export(tmp_path / 'observer', tmp_path / 'witness.zip')
    config = config_file(tmp_path, {'outputs': ['json'], 'witness': 'witness.zip', 'witness_fingerprint': witness_fp}, {
        'expert': {'require_tier': 'witness_anchored', 'require_pinned_signer': True,
                   'check_drand': True, 'check_bitcoin': True}})
    # Only external fetch results are stand-ins; archive signatures, Merkle roots and OTS paths are checked.
    commitment = bytes(32) if proof == 'mismatch' else digest
    header = bytes(36) + commitment + (1791158400).to_bytes(4, 'little') + bytes(8)
    out = tmp_path / 'witness-report'
    with patch('tgwitness.verify.drand_fetcher', return_value=lambda *_: BEACON), \
            patch('tgwitness.verify.bitcoin_fetcher', return_value=lambda height: header if height == 100 else None):
        if proof == 'confirmed':
            model = cli.generate(package, out, **resolve(config, 'expert'))
            assert model['assurance']['tier'] == 'witness_anchored'
            assert any(s['journal'] == 'witness' for s in model['scenes'])
            receipt = json.loads((out / 'narrative-run.json').read_text())
            assert receipt['signer_pinned'] and receipt['witness_package_sha256']
            assert str(tmp_path) not in (out / 'narrative-run.json').read_text()
        else:
            with pytest.raises(ValueError) as error:
                cli.generate(package, out, **resolve(config, 'expert'))
            assert isinstance(error.value, cli.RequirementsNotMet) == (proof == 'missing')
            assert list(out.iterdir()) == []


def test_profile_routes_network_flags_to_verifier_without_enabling_them_implicitly(tmp_path):
    package, _ = fixture(tmp_path)
    config = config_file(tmp_path, {'outputs': ['json']}, {'online': {'check_drand': True, 'check_bitcoin': True}})
    with patch.object(cli, 'verify_bundle', wraps=verify_bundle) as checked:
        cli.generate(package, tmp_path / 'online', **resolve(config, 'online'))
        assert checked.call_args.kwargs['check_drand'] and checked.call_args.kwargs['check_bitcoin']
    with patch.object(cli, 'verify_bundle', wraps=verify_bundle) as checked:
        with pytest.raises(cli.RequirementsNotMet):
            cli.generate(package, tmp_path / 'offline', outputs=['json'], require_tier='witness_anchored')
        assert not checked.call_args.kwargs['check_drand'] and not checked.call_args.kwargs['check_bitcoin']


def test_configuration_cannot_bypass_archive_authentication(tmp_path):
    package, _ = fixture(tmp_path)
    changed = tmp_path / 'tampered.zip'
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(changed, 'w') as target:
        for name in source.namelist():
            data = source.read(name)
            if name == 'events.jsonl':
                data = data.replace(b'synthetic.pdf', b'fabricated.pdf')
            target.writestr(name, data)
    config = config_file(tmp_path, {'outputs': ['json'], 'require_pinned_signer': False})
    out = tmp_path / 'rejected'
    with pytest.raises(ValueError, match='hash mismatch'):
        cli.generate(changed, out, **resolve(config))
    assert list(out.iterdir()) == []


def test_example_is_usable_and_never_overwrites_existing_trust_profile(tmp_path):
    config = tmp_path / 'new.json'
    write_example(config)
    original = config.read_bytes()
    assert resolve(config, 'ru-html')['lang'] == 'ru'
    assert resolve(config, 'de-proof')['require_tier'] == 'witness_anchored'
    with pytest.raises(FileExistsError):
        write_example(config)
    assert config.read_bytes() == original


def run_cli(*args):
    return subprocess.run([sys.executable, '-X', 'utf8', '-m', 'tgwitness.narrative', *map(str, args)],
                          cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
                          encoding='utf-8', timeout=90)


def test_real_cli_profile_overrides_and_exit_codes(tmp_path):
    package, _ = fixture(tmp_path)
    config = config_file(tmp_path, {'lang': 'ru', 'outputs': ['json'], 'check_drand': True}, {
        'expert': {'jurisdiction': 'DE', 'require_tier': 'witness_anchored'}})
    printed = run_cli('--config', config, '--profile', 'expert', '--lang', 'de', '--jurisdiction', 'none',
                      '--no-check-drand', '--print-config')
    assert printed.returncode == 0, printed.stderr
    resolved = json.loads(printed.stdout)
    assert resolved['lang'] == 'de' and resolved['jurisdiction'] is None and not resolved['check_drand']
    out = tmp_path / 'cli'
    failed = run_cli(package, '--config', config, '--profile', 'expert', '--out', out, '--no-check-drand')
    assert failed.returncode == 2 and 'verified tier is self_attested' in failed.stderr
    assert list(out.iterdir()) == []
    passed = run_cli(package, '--config', config, '--profile', 'expert', '--out', out,
                     '--no-check-drand', '--require-tier', 'self_attested', '--diagrams', 'none')
    assert passed.returncode == 0, passed.stderr
    assert (out / 'narrative.json').exists() and not (out / 'narrative.pdf').exists()
    wrong_pin = run_cli(package, '--outputs', 'json', '--out', tmp_path / 'wrong', '--fingerprint', '0' * 64)
    assert wrong_pin.returncode == 1


def test_real_cli_write_config_and_invalid_configuration_errors(tmp_path):
    path = tmp_path / 'created.json'
    assert run_cli('--write-config', path).returncode == 0
    assert run_cli('--write-config', path).returncode == 2
    assert run_cli('--profile', 'missing', '--print-config').returncode == 2
    assert run_cli('--config', path, '--outputs', 'svg', '--print-config').returncode == 2
