"""Bound large reports and retain a verifiable journal when presentation exceeds the cap."""
import asyncio
import errno
import hashlib
import json
from pathlib import Path
import sys
import zipfile

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import account_report, evidence, sealed
from tgwitness.account_export import AccountExport
from tgwitness.sealed_crypto import keypair, decrypt_file
from tgwitness.sealed_package import package
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_account_export, verify_bundle
from tools.check_account_reports import Document
from tools.demo_account_export import SyntheticCollector
from tools.test_file_hash_export import ExportTransport
from tools.browser_fixtures import CapsuleClient, CHAT, config


@pytest.mark.parametrize('design', ['dossier', 'reading_series', 'ledger_margin'])
def test_paginated_chat_records_citations_and_navigation(design):
    def rows():
        for i in range(501):
            yield {'id': i + 1, 'text': 'Synthetic <text> ' + str(i), 'attachments': []}
    pages = [(name, b''.join(chunks).decode()) for name, chunks in account_report.account_chat_pages(
        {'presentation': {'design': design}}, {'id': -42, 'message_count': 501}, rows)]
    assert [n for n, _ in pages] == ['chats/-42.html', 'chats/-42-2.html', 'chats/-42-3.html']
    all_ids = []
    for index, (name, html) in enumerate(pages):
        parsed = Document(html)
        identifiers = [i for i in parsed.ids if i.startswith('record-')]
        assert len(identifiers) == (250 if index < 2 else 1)
        assert name + '#' + identifiers[0] in html
        assert '&lt;text&gt;' in html and '<text>' not in html
        if index:
            assert Path(pages[index - 1][0]).name in parsed.links
        if index < 2:
            assert Path(pages[index + 1][0]).name in parsed.links
        all_ids.extend(identifiers)
    assert all_ids == [f'record-{n:06d}' for n in range(1, 502)]


def test_page_source_byte_bound_empty_chat_and_changed_source():
    large = 'ж' * (account_report.CHAT_PAGE_DATA_BYTES // 2)
    pages = [(n, b''.join(c)) for n, c in account_report.account_chat_pages({}, {'id': 7},
        lambda: iter([{'id': i, 'text': large} for i in range(3)]))]
    assert len(pages) == 3 and all(large.encode() in body for _, body in pages)
    empty = [(n, b''.join(c)) for n, c in account_report.account_chat_pages({}, {'id': 7}, lambda: iter(()))]
    assert len(empty) == 1 and empty[0][0] == 'chats/7.html'
    assert b'rel="next"' not in empty[0][1]
    calls = 0
    def unstable():
        nonlocal calls
        calls += 1
        return iter([{'id': 1}] if calls == 1 else [])
    with pytest.raises(ValueError, match='count changed'):
        for _, chunks in account_report.account_chat_pages({}, {'id': 7}, unstable):
            b''.join(chunks)


def test_account_package_signs_all_report_pages(tmp_path):
    class Network(ExportTransport):
        async def discover(self):
            chats, tasks, gaps = await super().discover()
            tasks[0].update(cursor_start=502, newest_message_id=501)
            return chats, tasks, gaps
        async def page(self, task, cursor):
            return [({'category': 'messages', 'id': i, 'chat_id': 11, 'text': 'Synthetic',
                'date': '2026-11-04T00:00:00+00:00'}, None) for i in range(501, 0, -1)], 1, True
    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting('account', {'id': 70000})
        collector = SyntheticCollector()
        collector.store = store
        exports = AccountExport(collector, store, vault)
        exports.transport_factory = Network
        try:
            job = await exports.start({'transport': 'regular', 'include_profile': False, 'include_contacts': False})
            await exports.task
            path = exports.result_path(job['id'])
            assert verify_account_export(path, fingerprint(vault.public_key))['counts']['messages'] == 501
            with zipfile.ZipFile(path) as z:
                manifest = json.loads(z.read('manifest.json'))
                pages = [n for n in z.namelist() if n.startswith('chats/')]
                assert len(pages) == 3 and all(n in manifest['files'] for n in pages)
                assert b'chats/11.html' in z.read('index.html')
                assert b'chats/11-3.html#record-000501' in z.read('chats/11-3.html')
        finally:
            await exports.close()
            store.close()
    asyncio.run(run())


async def collect(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
            headers={'Authorization': 'Bearer ' + app.state.session.config['token']}) as client:
        assert (await client.post('/api/phone', json={'phone': '+15550001111', 'api_id': 123, 'api_hash': 'a' * 32})).status_code == 200
        assert (await client.post('/api/code', json={'code': '12345'})).status_code == 200
        assert (await client.get('/api/dialogs')).status_code == 200
        assert (await client.post('/api/collect', json={'chat_id': CHAT})).status_code == 200
        await asyncio.wait_for(asyncio.shield(app.state.session.monitor_task), 30)


@pytest.mark.parametrize('failure', ['size', 'disk', 'permission', 'core_too_large'])
def test_sealed_compact_fallback_preserves_evidence_and_refuses_other_errors(tmp_path, monkeypatch, failure):
    original = evidence.export_file
    calls = []
    def constrained(store, vault, fmt, **kwargs):
        calls.append(bool(kwargs.get('compact')))
        if failure == 'permission':
            raise PermissionError(errno.EACCES, 'Synthetic permission denied')
        if failure == 'core_too_large' or not kwargs.get('compact'):
            if failure == 'disk':
                raise OSError(errno.ENOSPC, 'Synthetic full disk')
            raise evidence.BundleSizeLimit('Synthetic report size limit')
        return original(store, vault, fmt, **kwargs)
    monkeypatch.setattr(sealed, 'export_file', constrained)
    async def run():
        key = keypair()
        cfg = config(key)
        app = sealed.create_app(tmp_path / 'data', tmp_path / 'out', cfg, CapsuleClient)
        async with app.router.lifespan_context(app):
            await collect(app)
            session = app.state.session
            assert session.revocation == 'revoked' and session.vault.read('credentials') == {}
            path = tmp_path / 'out/evidence.zip'
            if failure in ('permission', 'core_too_large'):
                assert session.phase == 'failed' and not path.exists()
                assert calls == ([False] if failure == 'permission' else [False, True, True])
                return
            assert session.phase == 'sealed', session.reason
            assert calls == [False, True]
            verified = verify_bundle(path, fingerprint(session.vault.public_key))
            assert verified['events'] > 5
            with zipfile.ZipFile(path) as z:
                events = [json.loads(line) for line in z.read('events.jsonl').splitlines()]
                assert any(e['kind'] == 'sealed.packaging' for e in events)
                assert sum(e['kind'] == 'sealed.finished' for e in events) == 1
                assert not {'report.html', 'report.pdf', 'report.json', 'events.csv'} & set(z.namelist())
                assert json.loads(z.read('manifest.json'))['packaging']['preserved_media_omitted'] is False
                saved = [e['payload']['media_sha256'] for e in events if e['kind'] == 'media.saved']
                assert saved and all(hashlib.sha256(z.read('media/' + h)).hexdigest() == h for h in saved)
            # The existing encrypted handoff accepts the compact evidence format.
            attestation = tmp_path / 'out/attestation.jsonl'
            attestation.write_text('synthetic test attestation, not a GitHub proof')
            package(cfg, path.parent, attestation)
            decoded = tmp_path / 'delivery.zip'
            decrypt_file(path.parent / 'delivery.tgwsealed', decoded, key)
            with zipfile.ZipFile(decoded) as z:
                assert z.read('evidence.zip') == path.read_bytes()
    asyncio.run(run())


def test_real_compact_writer_respects_cap_and_cleans_failed_zip(tmp_path, monkeypatch):
    vault, store = Vault(tmp_path), Store(tmp_path)
    store.bind(vault)
    try:
        for i in range(100):
            store.append('message.new', {'text': 'Synthetic ' * 200, 'sender_id': 44}, CHAT, i + 1)
        full = evidence.export_file(store, vault, 'zip')
        compact = evidence.export_file(store, vault, 'zip', compact=True)
        with zipfile.ZipFile(full) as f, zipfile.ZipFile(compact) as c:
            assert f.read('events.jsonl') == c.read('events.jsonl')
            full_bytes, compact_bytes = sum(i.file_size for i in f.infolist()), sum(i.file_size for i in c.infolist())
        assert full_bytes > compact_bytes
        original_value = evidence.tuning.value
        limit = 4 * 1024**2 + (full_bytes + compact_bytes) // 2
        monkeypatch.setattr(evidence.tuning, 'value', lambda s, name: limit / 1024**3 if name == 'export_max_gib' else original_value(s, name))
        before = set((tmp_path / 'temporary-exports').iterdir())
        with pytest.raises(evidence.BundleSizeLimit):
            evidence.export_file(store, vault, 'zip')
        assert set((tmp_path / 'temporary-exports').iterdir()) == before
        fitted = evidence.export_file(store, vault, 'zip', compact=True)
        assert verify_bundle(fitted, fingerprint(vault.public_key))['events'] == 100
    finally:
        store.close()
