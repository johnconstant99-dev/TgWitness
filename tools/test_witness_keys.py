"""Telegram authorization provenance is signed, compared, and never mistaken for key custody."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness.capture_proof import capture_head
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import verify_capture, verify_witness
from tgwitness.witness import Witness, export


@pytest.mark.parametrize('origin', ['created', 'imported', None])
def test_signed_authorization_history_and_unpinned_witness_change_detection(tmp_path, origin):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    observer = Witness(tmp_path / 'witness', 'https://collector.invalid', 'synthetic')
    try:
        store.append('account.authorized', {'key_origin': origin})
        first = capture_head(store, vault, {}, 'a' * 32, 0)
        assert first['capture']['statement']['keys'] == dict(count=1, origin=origin or 'unknown', authorized_seq=1)
        observer.store.append('witness.anchor', observer.check(first))
        # Simulate a missing explicit signing-key pin; authorization history must still be checked.
        observer.pinned = None
        store.append('account.authorized', {'key_origin': 'imported'})
        second = capture_head(store, vault, {}, 'b' * 32, 1)
        answer = observer.check(second)
        assert answer['status'] == 'key_changed' and answer['keys']['count'] == 2
        observer.store.append('witness.anchor', answer)
    finally:
        observer.close()
        store.close()
    path = tmp_path / 'witness.zip'
    export(tmp_path / 'witness', path)
    result = verify_witness(path)
    keys = next(iter(result['collector_keys'].values()))
    assert keys['origin'] == 'imported' and 'ключ импортирован' in keys['note']


def test_legacy_capture_without_keys_and_invalid_keys(tmp_path):
    vault = Vault(tmp_path / 'collector')
    store = Store(tmp_path / 'collector')
    store.bind(vault)
    try:
        value = capture_head(store, vault, {}, 'a' * 32, 0)
        capture = value['capture']
        assert verify_capture(capture, value['checkpoint']['statement'])['keys']['origin'] == 'unknown'
        capture['statement'].pop('keys')
        capture['signature'] = vault.sign(canonical(capture['statement']))
        assert 'keys' not in verify_capture(capture, value['checkpoint']['statement'])
        capture['statement']['keys'] = dict(count=True, origin='created', authorized_seq=0)
        capture['signature'] = vault.sign(canonical(capture['statement']))
        with pytest.raises(ValueError, match='key history'):
            verify_capture(capture, value['checkpoint']['statement'])
    finally:
        store.close()
