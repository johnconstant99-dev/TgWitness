import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

import pytest
from telethon import errors
from telethon.tl import functions as f, types as t

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tgwitness import file_hashes
from tgwitness.account_export import AccountExport, AccountExportOptions, media_info
from tgwitness.account_export_transport import Transport, WrappedClient
from tgwitness.export_preflight import assess, preview
from tgwitness.security import Vault
from tgwitness.store import Store, canonical
from tgwitness.verify import fingerprint, validate_server_hashes, verify_account_export
from tools.demo_account_export import SyntheticCollector

CONTENT = b'0123456789'


def document():
    return t.Document(123, 456, b'private-reference', datetime.now(timezone.utc),
                      'application/octet-stream', len(CONTENT), 4, [])


class HashClient:
    _sender = object()
    _config = 'real-client-config'

    def __init__(self, *, gap=False, migrate=False):
        self.gap, self.migrate, self.calls, self.borrowed, self.returned = gap, migrate, [], [], []

    async def _get_dc(self, dc):
        return type(self)._config

    async def _borrow_exported_sender(self, dc):
        assert await self._get_dc(dc) == 'real-client-config'
        sender = object()
        self.borrowed.append(sender)
        return sender

    async def _return_exported_sender(self, sender):
        self.returned.append(sender)

    async def _call(self, sender, request, *args):
        self.calls.append(request)
        if isinstance(request, f.InvokeWithTakeoutRequest):
            request = request.query
        assert isinstance(request, f.upload.GetFileHashesRequest), 'Payload download is forbidden in hash-only mode'
        if self.migrate and len(self.calls)==1:
            raise errors.FileMigrateError(request, 4)
        if request.offset == 0:
            return [t.FileHash(0, 6, hashlib.sha256(CONTENT[:6]).digest())]
        if self.gap:
            return [t.FileHash(8, 6, hashlib.sha256(CONTENT[8:]).digest())]
        # Telegram pads the declared last range length, not the hashed data.
        return [t.FileHash(6, 6, hashlib.sha256(CONTENT[6:]).digest())]


def test_hashes_dc_migration_last_range_and_comparison(tmp_path):
    client = HashClient(migrate=True)
    manifest = asyncio.run(file_hashes.collect(WrappedClient(client, 999), document()))
    assert manifest['status']=='complete' and manifest['covered_bytes']==10
    assert client.borrowed == client.returned and len(client.borrowed)==1
    assert all(isinstance(r, f.InvokeWithTakeoutRequest) for r in client.calls)
    assert 'private-reference' not in json.dumps(manifest) and 'access_hash' not in json.dumps(manifest)
    path=tmp_path/'file.bin'
    path.write_bytes(CONTENT)
    assert file_hashes.compare(path, manifest)['status']=='match'
    path.write_bytes(b'x'+CONTENT[1:])
    assert file_hashes.compare(path, manifest)['mismatched_offsets']==[0]
    path.write_bytes(CONTENT+b'x')
    assert file_hashes.compare(path, manifest)['status']=='different_size_or_representation'
    assert file_hashes.compare(tmp_path/'missing',manifest)['status']=='missing'


def test_incomplete_coverage_cannot_be_promoted_to_complete(tmp_path):
    manifest=asyncio.run(file_hashes.collect(HashClient(gap=True),document()))
    assert manifest['status']=='partial' and manifest['covered_bytes']==6
    validate_server_hashes(manifest)
    path=tmp_path/'file.bin';path.write_bytes(CONTENT)
    assert file_hashes.compare(path,manifest)['status']=='incomplete_hash_coverage'
    forged=deepcopy(manifest);forged['status']='complete'
    with pytest.raises(ValueError,match='Incomplete'):
        validate_server_hashes(forged)
    bounded=asyncio.run(file_hashes.collect(HashClient(),document(),max_requests=1))
    assert bounded['status']=='partial' and bounded['request_count']==1


def test_hashes_use_media_dc_without_relying_on_migration_error():
    class Client(HashClient):
        session=SimpleNamespace(dc_id=3)
        async def _call(self,sender,request,*args):
            if sender is self._sender:
                raise errors.LocationInvalidError(request)
            return await super()._call(sender,request,*args)
    client=Client()
    result=asyncio.run(file_hashes.collect(WrappedClient(client),document()))
    assert result['status']=='complete' and client.borrowed==client.returned


def test_photo_variant_is_explicit():
    photo=t.Photo(1,2,b'private',datetime.now(timezone.utc),
        [t.PhotoSize('m',100,100,20),t.PhotoSizeProgressive('y',800,600,[40,80])],4)
    info=file_hashes.representation(photo)
    assert info['variant']=='y' and info['bytes']==80
    assert file_hashes.location(photo,info).thumb_size=='y'


def all_media_kinds():
    now = datetime.now(timezone.utc)
    result = [('photo', t.Photo(900, 2, b'private', now, [t.PhotoSize('m', 10, 10, len(CONTENT))], 4))]
    attributes = [
        ('video', [t.DocumentAttributeVideo(2, 320, 240)]),
        ('video_message', [t.DocumentAttributeVideo(2, 320, 240, round_message=True)]),
        ('voice', [t.DocumentAttributeAudio(2, voice=True)]),
        ('audio', [t.DocumentAttributeAudio(2)]),
        ('document', [t.DocumentAttributeFilename('synthetic.bin')]),
        ('animation', [t.DocumentAttributeAnimated(), t.DocumentAttributeVideo(2, 320, 240)]),
        ('sticker', [t.DocumentAttributeSticker('synthetic', t.InputStickerSetEmpty()), t.DocumentAttributeVideo(2, 320, 240)]),
    ]
    for i, (kind, attrs) in enumerate(attributes):
        result.append((kind, t.Document(901 + i, 2, b'private', now, 'application/octet-stream', len(CONTENT), 4, attrs)))
    return result


@pytest.mark.parametrize('kind,media', all_media_kinds(), ids=[kind for kind, _ in all_media_kinds()])
def test_media_policy_classification_is_independent_of_attribute_order(kind, media):
    from tgwitness.monitoring import media_kind
    from tools.browser_fixtures import telegram_message

    for reversed_order in (False, True):
        item = deepcopy(media)
        if reversed_order and isinstance(item, t.Document):
            item.attributes.reverse()
        wrapped = t.MessageMediaPhoto(photo=item) if kind == 'photo' else t.MessageMediaDocument(document=item)
        assert media_info(wrapped)['kind'] == kind
        assert media_kind(telegram_message(media=wrapped)) == ('video_note' if kind == 'video_message' else kind)


class ExportTransport:
    account_id=70000
    hash_calls=0

    def __init__(self, collector, vault, job, options):
        self.options=options

    async def open(self):
        pass

    async def discover(self):
        return ([{'id':11,'title':'Synthetic','kind':'private','selected':True,'archived':False,'left':False}],
                [{'id':'messages:11:0','category':'messages','chat_id':11,'cursor_start':3,
                  'newest_message_id':2,'own_only':False,'telegram_range':None}],[])

    async def page(self, task, cursor):
        return [({'category':'messages','id':i,'chat_id':11,'from_id':12,'outgoing':False,
                  'date':'2026-11-04T00:00:00+00:00','text':'Synthetic attachment'},document()) for i in (2,1)],1,True

    async def hashes(self, media, task):
        type(self).hash_calls += 1
        return await file_hashes.collect(HashClient(),media)

    async def download(self,*args):
        raise AssertionError('Hash-only export attempted a payload download')

    async def finish(self,success):
        pass


@pytest.mark.parametrize('action', ['download', 'hashes_only', 'exclude', 'mixed', 'budget_exhausted'])
def test_all_media_policies_preserve_messages_and_verify(tmp_path, action):
    class PolicyTransport(ExportTransport):
        async def discover(self):
            chats, tasks, gaps = await super().discover()
            tasks[0].update(cursor_start=9, newest_message_id=8)
            return chats, tasks, gaps

        async def page(self, task, cursor):
            rows = []
            for i, (kind, media) in enumerate(all_media_kinds(), 1):
                if action == 'budget_exhausted' and kind == 'document':
                    media.size = 2 * 1024**3  # Declared size only; never allocate a large payload.
                rows.append(({'category': 'messages', 'id': i, 'chat_id': 11, 'from_id': 12,
                    'outgoing': False, 'date': '2026-11-04T00:00:00+00:00', 'text': 'Synthetic ' + kind}, media))
            return rows[::-1], 1, True

        async def download(self, media, stream, progress, task):
            assert action in ('download', 'mixed'), 'Excluded, hash-only or over-budget file downloaded'
            stream.write(CONTENT)
            await progress(len(CONTENT), len(CONTENT))
            return stream

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting('account', {'id': 70000})
        collector = SyntheticCollector()
        collector.store = store
        exports = AccountExport(collector, store, vault)
        exports.transport_factory = PolicyTransport
        kinds = [kind for kind, _ in all_media_kinds()]
        options = {'transport': 'regular', 'include_profile': False, 'include_contacts': False, 'media_types': kinds}
        if action == 'mixed':
            # Explicit exclusion for GIFs/stickers must win over their video attributes.
            actions = {k: ('exclude' if k in ('animation', 'sticker') else 'download' if k == 'video' else 'hashes_only') for k in kinds}
            options.update(media_action='download', media_actions=actions)
        elif action == 'budget_exhausted':
            options.update(media_action='hashes_only', media_actions={'document': 'download'},
                           max_media_file_mib=4096, max_total_gib=1, budget_exhausted='stop_files')
        else:
            options['media_action'] = action
        try:
            job = await exports.start(options)
            await exports.task
            state = exports.public(job['id'])
            assert state['ready'] and state['counts']['messages'] == 8, state
            path = exports.result_path(job['id'])
            checked = verify_account_export(path, fingerprint(vault.public_key))
            assert checked['complete_within_scope'] == (action != 'budget_exhausted')
            with zipfile.ZipFile(path) as z:
                rows = [json.loads(line) for line in z.read('data/00000001.jsonl').splitlines()]
                for row in rows:
                    kind = row['text'].removeprefix('Synthetic ')
                    attachment, = row['attachments']
                    expected = actions[kind] if action == 'mixed' else ('download' if kind == 'document' else 'hashes_only') if action == 'budget_exhausted' else action
                    outcome = {'download': 'saved', 'hashes_only': 'hashed', 'exclude': 'excluded'}[expected]
                    if action == 'budget_exhausted' and kind == 'document':
                        assert attachment['outcome'] == 'failed' and attachment['reason'] == 'total_budget'
                    else:
                        assert attachment['outcome'] == outcome and attachment['kind'] == kind
                if action in ('hashes_only', 'exclude', 'budget_exhausted'):
                    assert not any(n.startswith('media/') for n in z.namelist())
        finally:
            await exports.close()
            store.close()
    asyncio.run(run())


def test_signed_hash_only_export_reuses_reference_and_verifies(tmp_path):
    async def run():
        vault,store=Vault(tmp_path),Store(tmp_path)
        store.bind(vault);store.set_setting('account',{'id':70000})
        collector=SyntheticCollector();collector.store=store
        exports=AccountExport(collector,store,vault);exports.transport_factory=ExportTransport
        ExportTransport.hash_calls=0
        try:
            started=await exports.start({'transport':'regular','include_profile':False,'include_contacts':False,
                'media_action':'hashes_only','media_types':['document']})
            await exports.task
            state=exports.public(started['id'])
            assert state['phase']=='done',state
            assert state['counts']['media_hashed']==2 and state['counts']['bytes_saved']==0
            assert ExportTransport.hash_calls==1
            path=exports.result_path(started['id'])
            verified=verify_account_export(path,fingerprint(vault.public_key))
            assert verified['complete_within_scope']
            with zipfile.ZipFile(path) as archive:
                assert not any(n.startswith('media/') for n in archive.namelist())
                data=[json.loads(line) for line in archive.read('data/00000001.jsonl').splitlines()]
                assert data[1]['attachments'][0]['reused']
                assert 'File hashes saved' in archive.read('chats/11.html').decode()
            before=path.read_bytes()
            await exports.resume(started['id'])
            assert path.read_bytes()==before
            # Even a correctly re-signed derivative cannot substitute an index
            # that disagrees with the immutable message-page attachment links.
            with zipfile.ZipFile(path) as archive:
                members={name:archive.read(name) for name in archive.namelist()}
            manifest=json.loads(members['manifest.json'])
            members['hashes/index.jsonl']=b'{}\n'
            manifest['files']['hashes/index.jsonl']=hashlib.sha256(members['hashes/index.jsonl']).hexdigest()
            members['SHA256SUMS']=''.join(f'{digest}  {name}\n' for name,digest in sorted(manifest['files'].items()) if name!='SHA256SUMS').encode()
            manifest['files']['SHA256SUMS']=hashlib.sha256(members['SHA256SUMS']).hexdigest()
            members['manifest.json']=canonical(manifest);members['manifest.sig']=vault.sign(canonical(manifest))
            forged=tmp_path/'wrong-index.zip'
            with zipfile.ZipFile(forged,'w') as archive:
                for name,body in members.items():archive.writestr(name,body)
            with pytest.raises(ValueError,match='File-hash index'):
                verify_account_export(forged,fingerprint(vault.public_key))
        finally:
            await exports.close();store.close()
    asyncio.run(run())


def test_additional_data_stream_return_and_unknown_length(tmp_path):
    class Client:
        async def download_file(self,media,file,progress_callback):
            raw=b'{"value":1,"auth_key":"must-not-export"}'
            file.write(raw)
            await progress_callback(len(raw),None)
            return None
    async def run():
        collector=SimpleNamespace()
        network=Transport(collector,SimpleNamespace(read=lambda _:{}),'job',{})
        network.ranged=lambda _:Client()
        (tmp_path/'media').mkdir()
        export=object.__new__(AccountExport)
        export.counts={'bytes_saved':0};export.pending_bytes=0;export.attachment_cache={};export.index=None
        options=AccountExportOptions(include_other_data=True).model_dump()
        result=await export.attachment(t.InputTakeoutFileLocation(),{'category':'other_data'},network,tmp_path,options)
        assert result['outcome']=='saved'
        assert json.loads((tmp_path/result['file']).read_bytes())=={'value':1}
        async def empty(*args):
            raise errors.RPCError(None,'TAKEOUT_FILE_EMPTY',400)
        network.download=empty
        result=await export.attachment(t.InputTakeoutFileLocation(),{'category':'other_data'},network,tmp_path,options)
        assert result['reason']=='no_additional_data'
    asyncio.run(run())


def test_download_dedup_budget_and_unique_bytes(tmp_path):
    class DownloadTransport(ExportTransport):
        downloads = 0

        async def download(self, media, stream, progress, task):
            type(self).downloads += 1
            stream.write(CONTENT)
            await progress(len(CONTENT), len(CONTENT))
            return stream

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting('account', {'id': 70000})
        collector = SyntheticCollector()
        collector.store = store
        exports = AccountExport(collector, store, vault)
        exports.transport_factory = DownloadTransport
        try:
            job = await exports.start({'transport': 'regular', 'include_profile': False, 'include_contacts': False,
                                       'media_types': ['document'], 'media_action': 'download'})
            await exports.task
            state = exports.public(job['id'])
            assert state['phase'] == 'done', state
            assert DownloadTransport.downloads == 1
            assert state['counts']['bytes_saved'] == 2 * len(CONTENT)
            assert state['counts']['unique_media_bytes'] == len(CONTENT)
            verified = verify_account_export(exports.result_path(job['id']), fingerprint(vault.public_key))
            assert verified['counts']['unique_media_bytes'] == len(CONTENT)
            exports.recover(json.loads((exports.directory(job['id']) / 'job.json').read_bytes())['statement'])
            assert exports.counts['unique_media_bytes'] == len(CONTENT)
        finally:
            await exports.close()
            store.close()
    asyncio.run(run())


def test_single_chat_hash_policy_and_signed_bundle(tmp_path):
    from tgwitness.collector import Collector
    from tgwitness.chat_export import build_bundle
    from tgwitness.monitoring import Capture
    from tgwitness.verify import verify_chat_export
    from tools.browser_fixtures import telegram_message

    async def run():
        vault, store = Vault(tmp_path), Store(tmp_path)
        store.bind(vault)
        store.set_setting('account', {'id': 70000})
        store.set_setting('capture', Capture(media_action='hashes_only', include_avatars=False).model_dump())
        collector = Collector(store, vault)
        collector.client = HashClient()
        message = telegram_message(media=t.MessageMediaDocument(document=document()))
        try:
            first = await collector.export_attachment(message, tmp_path)
            again = await collector.export_attachment(message, tmp_path)
            assert first == again and first['file_status'] == 'hashes_only'
            assert len(collector.client.calls) == 2  # Two ranges, only one acquisition.
            scratch = tmp_path / 'messages.jsonl'
            scratch.write_bytes(canonical({'id': 9, 'date': '2026-11-04T00:00:00+00:00', 'text': 'Synthetic',
                'from_id': 44, 'media_type': 'MessageMediaDocument', **first}) + b'\n')
            path = tmp_path / 'chat.zip'
            build_bundle(scratch, {'chat': {'id': -1000000000123, 'title': 'Synthetic'}, 'message_count': 1}, vault, path)
            assert verify_chat_export(path, fingerprint(vault.public_key))['message_count'] == 1
            with zipfile.ZipFile(path) as z:
                assert len([n for n in z.namelist() if n.startswith('hashes/')]) == 1
                assert not any(n.startswith('media/') for n in z.namelist())
        finally:
            store.close()
    asyncio.run(run())


def test_preflight_unknown_totals_and_static_errors():
    options=AccountExportOptions(transport='regular',include_other_data=True).model_dump()
    result=assess(options,10*1024**3)
    assert result['can_start'] and result['fit']=='unknown' and result['estimated_seconds'] is None
    assert any(i['code']=='takeout_required' for i in result['issues'])
    assert not assess(options,1024)['can_start']


def test_preflight_is_bounded_and_downloads_nothing(tmp_path):
    class Client:
        calls=0
        async def iter_dialogs(self,**kwargs):
            for i in range(30):
                yield SimpleNamespace(entity=t.User(i+1,first_name='Synthetic'),folder_id=None)
        async def get_messages(self,entity,limit):
            self.calls+=1
            return [SimpleNamespace(date=datetime.now(timezone.utc),from_id=t.PeerUser(9),message='Synthetic',
                       out=False,media=t.MessageMediaDocument(document=document())) for _ in range(limit)]
    async def run():
        collector=SyntheticCollector();collector.client=Client()
        async def restore():pass
        collector.restore=restore
        exports=object.__new__(AccountExport);exports.collector=collector;exports.root=tmp_path
        result=await preview(exports,{'media_action':'hashes_only','include_profile':False,'include_contacts':False})
        sample=result['sample']
        assert sample['sampled_chats']==12 and sample['messages_examined']==300
        assert sample['known_download_bytes']==0 and sample['known_hash_source_bytes']==10
        assert sample['duplicate_references']==299 and sample['message_file_payload_downloaded_bytes']==0
        assert collector.export_claim is None and result['fit']=='unknown'
    asyncio.run(run())
