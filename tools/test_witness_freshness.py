"""Freshness needs both a signed challenge and an independently checked beacon."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.capture_proof import capture_head
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import DRAND_GENESIS, DRAND_PERIOD, post_statement, verify_witness, witness_challenge
from tgwitness.witness import Witness, drand_latest, export

BEACON = dict(round=100, signature='ab' * 48, randomness=hashlib.sha256(bytes.fromhex('ab' * 48)).hexdigest())
FRESH = dict(drand_round=100, drand_signature=BEACON['signature'],
             drand_randomness=BEACON['randomness'], nonce='01' * 16)


def archive(tmp_path, freshness=FRESH, challenge=None):
    collector = tmp_path / 'collector'
    vault = Vault(collector)
    store = Store(collector)
    store.bind(vault)
    witness = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        store.append('message.new', {'text': 'synthetic'})
        witness._freshness = freshness
        value = capture_head(store, vault, {}, challenge or witness_challenge(FRESH), consistency_from=0)
        event = witness.store.append('witness.anchor', witness.check(value))
        assert post_statement(event, witness.fingerprint).get('drand_round') == (freshness['drand_round'] if freshness else None)
    finally:
        witness.close()
        store.close()
    path = tmp_path / 'witness.zip'
    export(tmp_path / 'witness', path)
    return path


def test_deterministic_challenge_and_offline_does_not_claim_external_time(tmp_path):
    expected = hashlib.sha256(bytes.fromhex('ab' * 48 + '01' * 16)).hexdigest()[:32]
    assert witness_challenge(FRESH) == expected
    result = verify_witness(archive(tmp_path))
    assert result['freshness']['drand_bound'] == 1
    assert result['freshness']['confirmed'] == 0
    assert result['freshness']['earliest_not_before'] is None


@pytest.mark.parametrize('change', [dict(drand_randomness='00' * 32), dict(nonce='02' * 16),
                                    dict(drand_signature='ac' * 48), dict(drand_round=True)])
def test_tampered_binding_fails_even_if_witness_resigns(tmp_path, change):
    with pytest.raises(ValueError):
        verify_witness(archive(tmp_path, {**FRESH, **change}))


def test_relay_mismatch_fails_and_unavailable_is_absent(tmp_path):
    path = archive(tmp_path)
    other = dict(round=100, signature='ac' * 48, randomness=hashlib.sha256(bytes.fromhex('ac' * 48)).hexdigest())
    with patch('tgwitness.verify.drand_fetcher', return_value=lambda *_: other):
        with pytest.raises(ValueError, match='differs from'):
            verify_witness(path, check_drand=True)
    with patch('tgwitness.verify.drand_fetcher', return_value=lambda *_: BEACON):
        result = verify_witness(path, check_drand=True)
        assert result['freshness']['confirmed'] == 1
        assert result['freshness']['earliest_not_before'] is not None
    def offline(*_):
        raise OSError('offline')
    with patch('tgwitness.verify.drand_fetcher', return_value=offline):
        assert verify_witness(path, check_drand=True)['freshness']['confirmed'] == 0


def test_legacy_anchor_has_no_freshness_credit(tmp_path):
    assert verify_witness(archive(tmp_path, None))['freshness']['drand_bound'] == 0


def test_latest_rejects_future_invalid_and_network_errors():
    with patch('tgwitness.witness.request', AsyncMock(return_value=(200, {}, json.dumps(BEACON).encode()))):
        with patch('tgwitness.witness.time.time', return_value=DRAND_GENESIS + 98 * DRAND_PERIOD - 61):
            assert asyncio.run(drand_latest(None)) is None
        assert asyncio.run(drand_latest(None)) == BEACON
    with patch('tgwitness.witness.request', AsyncMock(side_effect=OSError('offline'))):
        assert asyncio.run(drand_latest(None)) is None


def test_http_fetch_binds_nonce_and_fallback_clears_previous(tmp_path):
    observer = Witness(tmp_path / 'observer', 'https://collector.invalid', 'synthetic')
    async def reply(method, url, network, headers, **kwargs):
        challenge = headers['X-TgWitness-Challenge']
        return 200, {}, json.dumps({'capture': {'statement': {'challenge': challenge}}, 'continuity': {}}).encode()
    try:
        with patch('tgwitness.witness.secrets.token_hex', return_value=FRESH['nonce']), \
                patch('tgwitness.witness.request', reply), \
                patch('tgwitness.witness.drand_latest', AsyncMock(return_value=BEACON)):
            assert asyncio.run(observer.http_fetch())['capture']['statement']['challenge'] == witness_challenge(FRESH)
            assert observer._freshness == FRESH
        with patch('tgwitness.witness.secrets.token_hex', return_value=FRESH['nonce']), \
                patch('tgwitness.witness.request', reply), \
                patch('tgwitness.witness.drand_latest', AsyncMock(return_value=None)):
            assert asyncio.run(observer.http_fetch())['capture']['statement']['challenge'] == FRESH['nonce']
            assert observer._freshness is None
    finally:
        observer.close()
