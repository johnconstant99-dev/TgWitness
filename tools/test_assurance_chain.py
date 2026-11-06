"""Actual signed collector/witness ZIPs through the CLI; external network boundary is mocked."""
import asyncio
from datetime import date
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.capture_proof import capture_head
from tgwitness.evidence import export_file
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import OTS_MAGIC, OTS_BITCOIN, fingerprint, main, witness_challenge
from tgwitness.witness import Witness, export
from test_witness_freshness import BEACON, FRESH


@pytest.mark.parametrize('proof,expected', [('confirmed', 0), ('missing', 2), ('mismatch', 1)])
def test_cli_requires_actual_daily_proof_for_witness_anchored(tmp_path, capsys, proof, expected):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    observer = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        with patch('tgwitness.store.utcnow', return_value='2026-10-01T12:00:00+00:00'):
            store.append('message.new', {'text': 'synthetic'})
            observer._freshness = dict(FRESH)
            answer = capture_head(store, vault, {}, witness_challenge(FRESH), consistency_from=0)
            observer.store.append('witness.anchor', observer.check(answer))
        with patch('tgwitness.store.utcnow', return_value='2026-10-02T00:00:00+00:00'), \
                patch('tgwitness.witness.utc_date', return_value=date(2026, 10, 2)), \
                patch('tgwitness.anchoring.post', AsyncMock(side_effect=OSError('synthetic offline calendar'))):
            seal = asyncio.run(observer.daily())
        digest = hashlib.sha256(canonical(seal)).digest()
        if proof != 'missing':
            folder = observer.store.root / 'anchors'
            folder.mkdir(exist_ok=True)
            (folder / 'daily-2026-10-01.synthetic.ots').write_bytes(OTS_MAGIC + b'\x01\x08' + digest + b'\x00' + OTS_BITCOIN + b'\x01\x64')
        package = export_file(store, vault, 'zip', compact=True)
        witness_fp = observer.fingerprint
    finally:
        store.close()
        observer.close()
    witnessed = tmp_path / 'witness.zip'
    export(tmp_path / 'witness', witnessed)
    # A stand-in for the authenticated fetcher's validated Bitcoin header, not a real mined block.
    commitment = digest if proof == 'confirmed' else bytes(32)
    header = bytes(36) + commitment + (1790899200).to_bytes(4, 'little') + bytes(8)
    args = ['verify', str(package), '--witness', str(witnessed), '--witness-fingerprint', witness_fp,
            '--fingerprint', fingerprint(vault.public_key), '--require-tier', 'witness_anchored', '--json']
    with patch.object(sys, 'argv', args), patch('tgwitness.verify.drand_fetcher', return_value=lambda *_: BEACON), \
            patch('tgwitness.verify.bitcoin_fetcher', return_value=lambda height: header if height == 100 else None):
        if expected:
            with pytest.raises(SystemExit) as error:
                main()
            assert error.value.code == expected
        else:
            main()
    result = json.loads(capsys.readouterr().out)
    if expected == 0:
        assert result['requirements_met'] and result['result']['assurance']['tier'] == 'witness_anchored'
        assert result['result']['witness']['head_bitcoin_block_time']
        assert 'not_after' not in result['result']['witness']['days'][0]
        assert 'head_not_after' not in result['result']['witness']
    elif expected == 1:
        assert not result['verified']
    else:
        assert result['verified'] and not result['requirements_met']
