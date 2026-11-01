"""Offline adversarial disclosure checks; synthetic accounts and freshly generated keys only."""
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.account_export import AccountExport
from tgwitness.disclosure import DisclosurePolicy, Disclosures, Projection, public_policy
from tgwitness.security import Vault
from tgwitness.store import Store
from tgwitness.verify import fingerprint, verify_account_disclosure, verify_account_export
from tools.demo_account_export import SyntheticCollector

AT = '2026-11-01T12:00:00+00:00'
SECRET_METADATA = 'STRUCTURED_PRIVATE_CONTACT_7711'


class SyntheticTransport:
    account_id = 70000

    def __init__(self, *_args):
        pass

    async def open(self):
        pass

    async def discover(self):
        chats = [{'id': cid, 'title': title, 'kind': kind, 'selected': True}
                 for cid, title, kind in [(101, 'RarePrivateContact', 'private'), (102, 'Meeting', 'group')]]
        tasks = [{'id': f'messages:{c["id"]}:0', 'category': 'messages', 'chat_id': c['id'],
                  'newest_message_id': 5, 'cursor_start': 6, 'own_only': False, 'telegram_range': None}
                 for c in chats]
        return chats, tasks, []

    async def page(self, task, cursor):
        cid = task['chat_id']
        rows = []
        for mid in (5, 4):
            row = dict(category='messages', chat_id=cid, id=mid, date=AT, outgoing=False,
                       text='Meeting Großmann GROSSMANN Straße STRASSE gross_alt RarePrivateContact 42 142 42.5',
                       sender={'id': 42, 'first_name': 'Großmann', 'last_name': 'Straße',
                               'usernames': [{'username': 'gross_alt', 'active': True}]}, from_id=42,
                       fwd_from={'from_name': SECRET_METADATA}, reply_to={'quote_text': SECRET_METADATA},
                       entities=[{'phone': SECRET_METADATA}], caption=SECRET_METADATA,
                       file_name=SECRET_METADATA, contact={'phone': SECRET_METADATA})
            if cid == 102:
                row.pop('from_id')
                row.pop('sender')
                row.update(text='LegacyPerson legacy_handle', **{'from': 'LegacyPerson', 'from_username': 'legacy_handle'})
            rows.append((row, None))
        return rows, min(r['id'] for r, _ in rows), True

    async def finish(self, _success):
        pass


def read_rows(path):
    with zipfile.ZipFile(path) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    return contents, [json.loads(line) for line in contents['messages.jsonl'].splitlines()]


def projection_checks():
    chat = {'id': 1, 'kind': 'private', 'title': 'RarePrivateContact'}
    row = {'id': 1, 'from_id': 42, 'sender': {'first_name': 'Großmann', 'last_name': 'Straße'},
           'text': 'Großmann GROSSMANN Straße STRASSE 42 | 142 | 42.5'}
    policy = DisclosurePolicy(purpose='Synthetic privacy check', identity_mode='pseudonymize_all')
    criteria = DisclosurePolicy(purpose='Straße STRASSE', redact_terms=['straße'])
    assert public_policy(criteria)['purpose'] == '[private criterion] [private criterion]'
    with patch('tgwitness.disclosure.source_rows', lambda _source: iter([(chat, row)])):
        projection = Projection(policy, b'synthetic-seed', None)
        result = projection.apply(chat, row)['message']['text']
        for name in ('Großmann', 'GROSSMANN', 'Straße', 'STRASSE'):
            assert name not in result, ('Hidden Unicode sender remains', name, result)
        assert result.endswith('[redacted] | 142 | 42.5'), result
        assert projection.mask_known('prefix 🧪Großmann|STRASSE!Straße tail 👁') == (
            'prefix 🧪[redacted]|[redacted]![redacted] tail 👁')
        assert projection.mask_known('StraßeGroßmann tail') == '[redacted] tail'
        assert projection.mask_known('Unrelated 🧪 trailing text 👁') == 'Unrelated 🧪 trailing text 👁'
        # Two absent sender IDs cannot substantiate the same participant identity.
        unknown = {'id': 2, 'text': ''}
        first = projection.apply(chat, unknown)['message']
        second = projection.apply(chat, {**unknown, 'id': 3})['message']
        assert first['from_id'] != second['from_id']
        assert len(projection.identity_count) == 1
        with patch('tgwitness.disclosure.MAX_MASK_TERMS', 1):
            try:
                Projection(policy, b'synthetic-seed', None)
            except ValueError as error:
                assert 'omit message text' in str(error)
            else:
                raise AssertionError('Identity term limit silently weakened masking')
            omitted = Projection(policy.model_copy(update={'text_mode': 'omit'}), b'synthetic-seed', None)
            assert omitted.apply(chat, row)['message']['text'] == '[text withheld]'

    attachment = {'outcome': 'saved', 'file': 'media/' + 'a'*64, 'sha256': 'a'*64, 'bytes': 3,
                  'filename': SECRET_METADATA, 'caption': SECRET_METADATA, 'forward': {'name': SECRET_METADATA}}
    with patch('tgwitness.disclosure.source_rows', lambda _source: iter([(chat, row)])):
        for include in (False, True):
            projected = Projection(policy.model_copy(update={'include_media': include}), b'seed', None)
            result = projected.apply(chat, {**row, 'attachments': [attachment]})
            assert SECRET_METADATA not in json.dumps(result)
            assert bool(result['message']['attachments']) is include
    # Generic group titles are not names to erase from all message content.
    group = {'id': 2, 'kind': 'group', 'title': 'Meeting'}
    with patch('tgwitness.disclosure.source_rows', lambda _source: iter([(group, row)])):
        projected = Projection(policy, b'seed', None)
        assert projected.apply(group, {**row, 'text': 'Meeting agenda'})['message']['text'] == 'Meeting agenda'
    many = [(group, {'id': n + 1, 'from_id': n + 10000,
                     'sender': {'first_name': f'PrivatePerson{n:05d}'}}) for n in range(5001)]
    with patch('tgwitness.disclosure.source_rows', lambda _source: iter(many)):
        try:
            Projection(policy, b'seed', None)
        except ValueError as error:
            assert 'Too many known identities' in str(error)
        else:
            raise AssertionError('More than 5000 identities silently truncated the mask dictionary')
        omitted = Projection(policy.model_copy(update={'text_mode': 'omit'}), b'seed', None)
        assert omitted.apply(group, {**row, 'text': 'PrivatePerson05000'})['message']['text'] == '[text withheld]'


async def manager_checks(directory):
    vault, store = Vault(directory), Store(directory)
    store.bind(vault)
    collector = SyntheticCollector()
    collector.store = store
    store.set_setting('account', {'id': SyntheticTransport.account_id})
    exports = AccountExport(collector, store, vault)
    exports.transport_factory = SyntheticTransport
    manager = Disclosures(exports, vault)
    try:
        job = await exports.start({'transport': 'regular', 'include_profile': False,
                                   'include_contacts': False, 'media_types': []})
        await asyncio.wait_for(asyncio.shield(exports.task), 15)
        assert exports.public(job['id'])['ready'], exports.public(job['id'])
        original = exports.result_path(job['id'])
        original_digest = hashlib.sha256(original.read_bytes()).hexdigest()
        trusted = fingerprint(vault.public_key)
        assert verify_account_export(original, trusted)['counts']['messages'] == 4
        with zipfile.ZipFile(original) as archive:
            assert SECRET_METADATA.encode() in b''.join(archive.read(n) for n in archive.namelist() if n.startswith('data/'))
        for mode, allowed in [('keep', []), ('pseudonymize_third_parties', [42]), ('pseudonymize_all', [42])]:
            policy = {'purpose': 'Review Großmann gross_alt RarePrivateContact LegacyPerson',
                      'identity_mode': mode, 'disclose_user_ids': allowed}
            preview = manager.preview(job['id'], policy, 'synthetic-owner')
            info = await manager.create(job['id'], preview['preview_id'], 'synthetic-owner')
            path = manager.result_path(job['id'], info['id'])
            contents, rows = read_rows(path)
            answer = verify_account_disclosure(path, trusted, source=original)
            assert answer['key_pinned'] is True
            assert answer['source_reference_checked'] and not answer['derivation_correctness_established']
            assert SECRET_METADATA.encode() not in b'\n'.join(contents.values())
            private = mode != 'keep'
            shared_purpose = json.loads(contents['manifest.json'])['policy']['purpose']
            assert ('RarePrivateContact' not in shared_purpose) is private
            if mode == 'pseudonymize_all':
                assert all(secret not in shared_purpose for secret in ('Großmann', 'gross_alt', 'LegacyPerson'))
            assert all(isinstance(row['chat']['id'], str) is private for row in rows)
            for row in rows:
                message = row['message']
                if message['from_id'] == 42:
                    assert mode != 'pseudonymize_all' and message['sender'] == 'Großmann Straße'
                if mode == 'pseudonymize_all':
                    for secret in ('Großmann', 'GROSSMANN', 'Straße', 'STRASSE', 'gross_alt',
                                   'RarePrivateContact', 'LegacyPerson', 'legacy_handle'):
                        assert secret not in message['text'], (secret, message['text'])
            if private:
                assert 'RarePrivateContact' not in json.dumps(preview['samples'])
            assert hashlib.sha256(original.read_bytes()).hexdigest() == original_digest
        # Text omission drops every alternative text/metadata copy as well.
        preview = manager.preview(job['id'], {'purpose': 'Omit text for Großmann RarePrivateContact',
                                              'text_mode': 'omit'}, 'synthetic-owner')
        info = await manager.create(job['id'], preview['preview_id'], 'synthetic-owner')
        contents, rows = read_rows(manager.result_path(job['id'], info['id']))
        assert all(row['message']['text'] == '[text withheld]' for row in rows)
        assert SECRET_METADATA.encode() not in b'\n'.join(contents.values())
        for secret in ('Großmann', 'RarePrivateContact'):
            assert secret.encode() not in b'\n'.join(contents.values())
        assert hashlib.sha256(original.read_bytes()).hexdigest() == original_digest
    finally:
        await manager.close()
        await exports.close()
        store.close()


def main():
    projection_checks()
    with tempfile.TemporaryDirectory(prefix='disclosure-privacy-') as directory:
        asyncio.run(manager_checks(Path(directory)))
    print('Disclosure privacy: Unicode/IDs/alternate names, unknown-sender separation, masking limit, '
          'all identity modes, metadata/media allowlists, text omission, signed source linkage and unchanged source PASS')


if __name__ == '__main__':
    main()
