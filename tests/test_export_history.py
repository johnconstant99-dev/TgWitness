"""Export receipts describe exact downloaded bytes without changing evidence."""
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from tgwitness.app import create_app
from tgwitness.export_history import LIMIT, listing, prepared
from tgwitness.verify import fingerprint, verify_bundle
from test_access import issue, login
from test_collector import FakeClient


def test_receipt_hash_matches_download_and_signed_bundle_still_verifies(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers['Authorization'] = 'Bearer ' + app.state.vault.token
        app.state.store.append('message.new', {'text': 'Synthetic record'}, -1001, 1)
        response = client.get('/api/export/zip')
        assert response.status_code == 200, response.text[:200]
        digest = hashlib.sha256(response.content).hexdigest()
        assert response.headers['X-TgWitness-Export-SHA256'] == digest
        receipt = client.get('/api/exports/history').json()['exports'][0]
        assert receipt['sha256'] == digest
        assert receipt['bytes'] == len(response.content) and not receipt['encrypted']
        assert set(receipt) == {'format', 'encrypted', 'bytes', 'sha256', 'created_at'}
        path = tmp_path / 'checked-export.zip'
        path.write_bytes(response.content)
        verify_bundle(path, fingerprint(app.state.vault.public_key))
        assert not list((tmp_path / 'exports').glob('*.zip'))


def test_history_requires_whole_workspace_export_access(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app) as client:
        client.headers['Authorization'] = 'Bearer ' + app.state.vault.token
        for permissions, workspaces, expected in [
            (['view'], {'default': None}, 403),
            (['export'], {'default': [-1001]}, 403),
            (['export'], {'default': None}, 200),
        ]:
            token, _ = issue(client, permissions=permissions, workspaces=workspaces)
            browser, result = login(app, token)
            assert result.status_code == 200
            try:
                assert browser.get('/api/exports/history').status_code == expected
            finally:
                browser.close()


def test_bounded_receipts_do_not_append_or_rewrite_journal(tmp_path):
    app = create_app(tmp_path, client_factory=FakeClient)
    with TestClient(app):
        store = app.state.store
        before = store.events(limit=500)
        path = Path(tmp_path) / 'sample.bin'
        for number in range(LIMIT + 3):
            path.write_bytes(str(number).encode())
            prepared(store, path, 'csv', bool(number % 2))
        history = listing(store)
        assert len(history['exports']) == LIMIT
        assert history['exports'][0]['sha256'] == hashlib.sha256(b'22').hexdigest()
        assert store.events(limit=500) == before
        assert store.verify(app.state.vault.public_key)['events'] == len(before)
