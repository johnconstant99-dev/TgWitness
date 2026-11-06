"""Daily seals bind journal prefixes, counters and prior seals; OTS is not self-certifying."""
import asyncio
from datetime import date
import hashlib
import os
from pathlib import Path
import sys
import time
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.anchoring import ots_integer, upgrade_pending_ots
from tgwitness.store import canonical
from tgwitness.verify import OTS_BITCOIN, OTS_MAGIC, OTS_PENDING, confirm_ots, daily_payload, verify_witness
from tgwitness.witness import Witness, export

CALENDAR = b'https://alice.btc.calendar.opentimestamps.org'
PENDING = b'\x00' + OTS_PENDING + ots_integer(len(CALENDAR) + 1) + ots_integer(len(CALENDAR)) + CALENDAR


def make(tmp_path, days=(1, 2), corrupt=None):
    root = tmp_path / 'witness'
    observer = Witness(root, 'https://collector.invalid', 'synthetic')
    try:
        for day in days:
            with patch('tgwitness.store.utcnow', return_value=f'2026-10-{day:02d}T12:00:00+00:00'):
                observer.store.append('witness.no_response', {'error': 'synthetic outage'})
            with patch('tgwitness.store.utcnow', return_value=f'2026-10-{day + 1:02d}T00:00:00+00:00'), \
                    patch('tgwitness.witness.utc_date', return_value=date(2026, 10, day + 1)), \
                    patch('tgwitness.anchoring.post', AsyncMock(return_value=PENDING)):
                if corrupt:
                    payload = daily_payload(observer.store.all_events(), f'2026-10-{day:02d}')
                    observer.store.append('witness.daily', {**payload, **corrupt})
                else:
                    first = asyncio.run(observer.daily())
                    assert asyncio.run(observer.daily()) == first
        events = observer.store.all_events()
    finally:
        observer.close()
    path = tmp_path / 'witness.zip'
    export(root, path)
    return path, events


def test_two_days_chain_and_pending_is_not_confirmed(tmp_path):
    path, events = make(tmp_path)
    result = verify_witness(path)
    first = next(e for e in events if e['kind'] == 'witness.daily')
    assert result['days'][1]['previous_daily_sha256'] == hashlib.sha256(canonical(first)).hexdigest()
    assert len(result['days']) == 2 and result['missing_days'] == []
    assert all(d['bitcoin'] == 'pending' and d['status'] == 'no_response_only' for d in result['days'])
    assert result['days'][0]['checks'] == {'no_response': 1}
    assert 'freshness' in result


def test_missing_middle_day_remains_visible(tmp_path):
    result = verify_witness(make(tmp_path, days=(1, 3))[0])
    assert result['missing_days'] == ['2026-10-02']


@pytest.mark.parametrize('corrupt', [{'root': '00' * 32}, {'checks': {'ok': 99}},
                                   {'previous_daily_sha256': '00' * 32}, {'to_seq': 0}])
def test_resigned_wrong_daily_fields_fail(tmp_path, corrupt):
    with pytest.raises(ValueError, match='daily root, counts, range or previous seal'):
        verify_witness(make(tmp_path, days=(1,), corrupt=corrupt)[0])


def test_empty_previous_day_does_not_claim_a_successful_check(tmp_path):
    observer = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        with patch('tgwitness.store.utcnow', return_value='2026-10-02T00:00:00+00:00'), \
                patch('tgwitness.witness.utc_date', return_value=date(2026, 10, 2)), \
                patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('offline'))):
            event = asyncio.run(observer.daily())
            assert event['payload']['from_seq'] == 1 and event['payload']['to_seq'] == 0
    finally:
        observer.close()
    path = tmp_path / 'witness.zip'
    export(tmp_path / 'witness', path)
    day = verify_witness(path)['days'][0]
    assert day['bitcoin'] == 'none' and day['status'] == 'no_response_only'


def test_bitcoin_path_must_match_external_header():
    digest = hashlib.sha256(b'synthetic seal').digest()
    commitment = hashlib.sha256(b'prefix' + digest).digest()
    proof = OTS_MAGIC + b'\x01\x08' + digest + b'\xf1\x06prefix\x08\x00' + OTS_BITCOIN + b'\x01\x64'
    header = b'\0' * 36 + commitment + (1760000000).to_bytes(4, 'little') + b'\0' * 8
    assert confirm_ots(proof, digest, lambda h: header if h == 100 else None)['status'] == 'confirmed'
    assert confirm_ots(proof, digest, lambda _: None)['status'] == 'bitcoin-unverified'
    with pytest.raises(ValueError, match='Merkle root'):
        confirm_ots(proof, digest, lambda _: b'\0' * 80)


def test_daily_upgrade_retains_original_and_stays_unconfirmed_offline(tmp_path):
    path, events = make(tmp_path, days=(1,))
    observer = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        folder = observer.store.root / 'anchors'
        for proof in folder.glob('*.ots'):
            os.utime(proof, (time.time() - 7200, time.time() - 7200))
        # Direct Bitcoin attestation is structurally valid, but is not a Bitcoin proof until independently checked.
        answer = b'\x00' + OTS_BITCOIN + b'\x01\x64'
        with patch('tgwitness.anchoring.request', AsyncMock(return_value=(200, {}, answer))):
            result = asyncio.run(upgrade_pending_ots(observer.store, observer.network,
                                {'ots_calendars': [CALENDAR.decode()]}, folder=folder))
        assert result and all(r['ok'] for r in result)
        assert list(folder.glob('*.ots.pending'))
    finally:
        observer.close()
    export(tmp_path / 'witness', path)
    assert verify_witness(path)['days'][0]['bitcoin'] == 'pending'


def test_failed_submission_retries_after_restart_without_rewriting_the_daily_seal(tmp_path):
    root = tmp_path / 'witness'
    observer = Witness(root, 'https://collector.invalid', 'synthetic')
    try:
        with patch('tgwitness.store.utcnow', return_value='2026-10-02T00:00:00+00:00'), \
                patch('tgwitness.witness.utc_date', return_value=date(2026, 10, 2)), \
                patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('offline'))):
            seal = asyncio.run(observer.daily())
        original = canonical(seal)
        assert not list((root / 'anchors').glob('*.ots'))
    finally:
        observer.close()
    observer = Witness(root, 'https://collector.invalid', 'synthetic')
    try:
        with patch('tgwitness.store.utcnow', return_value='2026-10-04T12:00:00+00:00'), \
                patch('tgwitness.anchoring.post', AsyncMock(return_value=PENDING)) as send:
            attempts = asyncio.run(observer.retry_daily_ots())
            assert [a['record'] for a in attempts] == [seal['seq']]
            assert all(call.args[1] == hashlib.sha256(original).digest() for call in send.call_args_list)
            send.reset_mock()
            assert asyncio.run(observer.retry_daily_ots()) == []
            send.assert_not_called()
        seals = [event for event in observer.store.all_events() if event['kind'] == 'witness.daily']
        assert [canonical(event) for event in seals] == [original]
        assert (root / 'anchors/daily-2026-10-01.json').read_bytes() == original
    finally:
        observer.close()
    package = tmp_path / 'witness.zip'
    export(root, package)
    day = verify_witness(package)['days'][0]
    assert day['date'] == '2026-10-01' and day['bitcoin'] == 'pending'


def test_failed_submission_retry_is_bounded_and_rotates_between_old_seals(tmp_path):
    observer = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        for day in (1, 2, 3):
            with patch('tgwitness.store.utcnow', return_value=f'2026-10-{day + 1:02d}T00:00:00+00:00'), \
                    patch('tgwitness.witness.utc_date', return_value=date(2026, 10, day + 1)), \
                    patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('offline'))):
                asyncio.run(observer.daily())
        seals = [e for e in observer.store.all_events() if e['kind'] == 'witness.daily']
        with patch('tgwitness.store.utcnow', return_value='2026-10-05T00:00:00+00:00'), \
                patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('offline'))):
            first = asyncio.run(observer.retry_daily_ots())
            second = asyncio.run(observer.retry_daily_ots())
            third = asyncio.run(observer.retry_daily_ots())
        assert [a['record'] for a in first] == [e['seq'] for e in seals[:2]]
        assert [a['record'] for a in second] == [seals[2]['seq']]
        assert [a['record'] for a in third] == [e['seq'] for e in seals[:2]]
    finally:
        observer.close()
