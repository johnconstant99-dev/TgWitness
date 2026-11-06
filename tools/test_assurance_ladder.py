"""Missing steps and unverified claims cannot raise the assurance of an export."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.evidence import export_file
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import assurance, verify_bundle


def complete():
    return {'events': 10, 'fingerprint': 'collector', 'anchors': [], 'witness': {
        'witness_fingerprint': 'witness', 'witness_key_pinned': True, 'export_head_witnessed': True,
        'head_not_before': '2026-10-01T00:00:00+00:00', 'head_bitcoin_block_time': '2026-10-02T00:00:00+00:00',
        'head_witnessed_at': '2026-10-01T00:00:01+00:00', 'days': [{'status': 'ok', 'bitcoin': 'confirmed'}],
        'missing_days': [], 'conflicts': [], 'anomalies': []}}


def test_all_lower_steps_must_pass_and_seal_cannot_be_inferred():
    value = complete()
    assert assurance(value)['tier'] == 'witness_anchored'
    assert assurance(value)['ladder'][-1]['status'] == 'absent'
    value['witness']['head_not_before'] = None
    assert assurance(value)['tier'] == 'witnessed'
    value['witness']['head_bitcoin_block_time'] = None
    assert assurance(value)['tier'] == 'self_attested'


@pytest.mark.parametrize('change', [{'witness_key_pinned': False}, {'export_head_witnessed': False},
                                    {'witness_fingerprint': 'collector'}])
def test_witness_requires_pin_independent_key_and_exact_head(change):
    value = complete()
    value['witness'].update(change)
    assert assurance(value)['ladder'][2]['status'] == 'absent'


def test_unconfirmed_or_partial_timestamp_does_not_count():
    for entry in [dict(kind='opentimestamps', status='bitcoin-unverified', event_count=10),
                  dict(kind='rfc3161', signature='not checked', event_count=10),
                  dict(kind='rfc3161', signature='checked against the given root', event_count=9)]:
        value = dict(events=10, anchors=[{**entry, 'time': '2026-10-01T00:00:00+00:00'}])
        assert assurance(value)['tier'] == 'self_attested'


def test_missing_days_are_absent_and_contradictions_fail():
    value = complete()
    value['witness']['missing_days'] = ['2026-10-01']
    assert assurance(value)['ladder'][4]['status'] == 'absent'
    value = complete()
    value['witness']['days'][0]['status'] = 'fail'
    assert assurance(value)['ladder'][4]['status'] == 'fail'


def test_only_checked_runtime_with_created_key_can_reach_sealed():
    value = complete()
    value['runtime_attestation'] = dict(verified=True, key_origin='created')
    assert assurance(value)['tier'] == 'sealed'
    value['runtime_attestation']['key_origin'] = 'imported'
    assert assurance(value)['tier'] == 'witness_anchored'


def test_cli_legacy_and_required_tier_exit_codes(tmp_path):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    try:
        store.append('message.new', {'text': 'synthetic'})
        path = export_file(store, vault, 'zip', compact=True)
        assert verify_bundle(path)['assurance']['tier'] == 'self_attested'
        command = [sys.executable, '-m', 'tgwitness.verify', str(path)]
        normal = subprocess.run(command + ['--json'], capture_output=True, text=True, encoding='utf-8')
        assert normal.returncode == 0, normal.stderr
        assert json.loads(normal.stdout)['result']['assurance']['tier'] == 'self_attested'
        strict = subprocess.run(command + ['--json', '--require-tier', 'witness_anchored'], capture_output=True, text=True, encoding='utf-8')
        assert strict.returncode == 2, strict.stdout + strict.stderr
        assert not json.loads(strict.stdout)['requirements_met']
        plain = subprocess.run(command + ['--plain'], capture_output=True, text=True, encoding='utf-8')
        assert plain.stdout.startswith('ASSURANCE: self_attested')
    finally:
        store.close()
