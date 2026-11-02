import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import threading
import time
import zipfile
import pytest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check_prepared_export_access import grant_session
from tools.check_session_reservations import workspace
from tgwitness import evidence, handover, report
from tgwitness.access import Principal
from tgwitness.board import Board, notifications
from tgwitness.verify import fingerprint, verify_handover, verify_selection
from tgwitness.store import canonical


def test_http_permissions_and_export_isolation(tmp_path):
    async def run():
        async with workspace() as (app, client):
            store, vault = app.state.store, app.state.vault
            a = store.append('message.new', {'text': 'Visible source', 'sender_id': 11}, -1001, 1)
            b = store.append('message.new', {'text': 'HIDDEN SOURCE', 'sender_id': 22}, -1002, 1)
            service = Board(store)
            hidden = service.append('bookmark', {'target': {'event_hash': b['hash']}, 'note': 'PRIVATE TEAM NOTE'}, Principal(True, 'Admin'))
            _, scoped = grant_session(app, {'default': [-1001]}, ['view','export','board.read','board.write'])
            _, readonly = grant_session(app, {'default': [-1001]}, ['view','board.read'])
            _, exporter = grant_session(app, permissions=['view','export'])
            saved = await client.post('/api/board/bookmark', headers=scoped, json={'target': {'event_hash': a['hash']}, 'note': 'Allowed note'})
            assert saved.status_code == 200, saved.text
            assert saved.json()['access_label'] == 'Synthetic reviewer' and saved.json()['access_id'] != 'admin'
            card_id = saved.json()['payload']['id']
            assert (await client.post('/api/board/comment', headers=scoped, json={'parent_id': card_id, 'text':'Invalid mention', 'mentions':[{}]})).status_code == 422
            assert (await client.get('/api/board?from=2026-11-02', headers=scoped)).status_code == 422
            assert (await client.get('/api/board?from=2026-11-03T00:00:00Z&to=2026-11-02T00:00:00Z', headers=scoped)).status_code == 422
            participants = await client.get('/api/board/card/'+card_id+'/participants', headers=scoped)
            assert participants.status_code == 200 and saved.json()['access_id'] in {row['id'] for row in participants.json()}
            assert (await client.post('/api/board/bookmark', headers=readonly, json={'target': {'event_hash': a['hash']}})).status_code == 403
            assert (await client.get('/api/board', headers=exporter)).status_code == 403
            assert (await client.get('/api/board/card/'+hidden['payload']['id'], headers=scoped)).status_code == 404
            assert (await client.post('/api/board/slice', headers=scoped, json={'query': {'chat_ids': [-1001,-1002]}})).status_code == 403
            assert (await client.post('/api/board/bookmark', headers=scoped, json={'target': {'event_hash': a['hash']}, 'access_id': 'admin'})).status_code == 422
            feed = await client.get('/api/board', headers=scoped)
            assert len(feed.json()['cards']) == 1 and 'PRIVATE TEAM NOTE' not in feed.text
            assert 'HIDDEN SOURCE' not in (await client.get('/api/board/export', headers=scoped)).text
            response = await client.get('/api/export/zip', headers=exporter)
            assert response.status_code == 200, response.text[:200]
            path = tmp_path / 'no-board.zip'
            path.write_bytes(response.content)
            with zipfile.ZipFile(path) as archive:
                assert 'case-board.json' not in archive.namelist() and 'annotations.jsonl' not in archive.namelist()
                assert b'PRIVATE TEAM NOTE' not in archive.read('report.json')
            created = await client.post('/api/board/slice', headers=scoped, json={'query': {'chat_id': -1001}})
            ident = created.json()['payload']['id']
            selection = await client.get('/api/board/slice/'+ident+'/export', headers=scoped)
            assert selection.status_code == 200
            selection_path = tmp_path / 'selection.json'
            selection_path.write_bytes(selection.content)
            archive = evidence.export_file(store,vault,'zip',report.resolved())
            checked = verify_selection(selection_path,fingerprint(vault.public_key),archive)
            assert checked['selection_signed'] and checked['items_checked'] == 1
            incomplete = selection.json()['statement']
            incomplete['items'] = []
            selection_path.write_bytes(canonical({'statement': incomplete, 'signature': vault.sign(canonical(incomplete))}))
            with pytest.raises(ValueError, match='complete|omits|query'):
                verify_selection(selection_path, fingerprint(vault.public_key), archive)
            records = await client.get('/api/events?slice_id='+ident, headers=scoped)
            assert records.status_code == 200 and len(records.json()['events']) == 1
            assert (await client.get('/api/events?slice_id='+ident, headers=exporter)).status_code == 403
            who = app.state.access.resolve(scoped['Authorization'].split()[1], '127.0.0.1')
            live, _ = notifications(store, 0, who, 'default')
            assert hidden['payload']['id'] not in str(live)
            group = {'current':'team'}
            app.state.access.group_of = lambda workspace: group['current']
            app.state.access.grant(saved.json()['access_id'])['groups'] = ['team']
            assert (await client.get('/api/board/card/'+hidden['payload']['id'], headers=scoped)).status_code == 200
            original_read = Board.read
            def changing_read(service, db, principal):
                result = original_read(service, db, principal)
                group['current'] = 'another-team'
                return result
            with patch.object(Board, 'read', changing_read):
                raced = await client.get('/api/board', headers=scoped)
                assert raced.status_code == 403 and 'PRIVATE TEAM NOTE' not in raced.text
            assert (await client.get('/api/board/card/'+hidden['payload']['id'], headers=scoped)).status_code == 404
    asyncio.run(run())


def test_handover_board_opt_in_and_pseudonyms(tmp_path):
    from tgwitness.security import Vault
    from tgwitness.store import Store
    store, vault = Store(tmp_path), Vault(tmp_path)
    store.bind(vault)
    try:
        service, admin = Board(store), Principal(True, 'Admin')
        event = store.append('message.new', {'text':'Contact alex@example.com', 'sender_id':11, 'sender_observation':{'username':'alex','display_name':'Alex'}}, -1001,1)
        other = store.append('message.new', {'text':'PRIVATE CHAT', 'sender_id':22}, -1002,1)
        saved = service.append('bookmark', {'target':{'event_hash':event['hash']}, 'note':'Main administrator reviewed alex@example.com', 'labels':['alex@example.com','Main administrator']},admin)
        service.append('comment', {'parent_id':saved['payload']['id'],'text':'Main administrator: contact alex@example.com'},admin)
        service.append('bookmark', {'target':{'event_hash':other['hash']}, 'note':'PRIVATE NOTE'},admin)
        service.append('slice', {'query':{'chat_id':-1001,'search':'alex@example.com'}},admin)
        for mode in ('off','comments'):
            options = handover.Options(purpose='Synthetic handover', chats=[-1001], case_board=mode, mask_contacts=True)
            archive, _ = handover.export(store,vault,options)
            verify_handover(archive,fingerprint(vault.public_key))
            with zipfile.ZipFile(archive) as incoming:
                assert 'annotations.jsonl' not in incoming.namelist()
                if mode == 'off':
                    assert 'case-board.json' not in incoming.namelist()
                else:
                    text = incoming.read('case-board.json').decode()
                    assert 'R01' in text and '[e-mail]' in text
                    assert all(value not in text for value in ('Main administrator','alex@example.com','PRIVATE NOTE','PRIVATE CHAT'))
                    assert json.loads(incoming.read('report.json'))['report']['case_board']['mode'] == 'comments'
    finally:
        store.close()


def test_slice_write_and_session_resolution_finish_concurrently():
    async def run():
        async with workspace() as (app, client):
            store, access = app.state.store, app.state.access
            store.append('message.new', {'text': 'Synthetic concurrent observation'}, -1001, 1)
            session, _ = access.login(app.state.vault.token, '127.0.0.1', 'Synthetic administrator')
            assert session != app.state.vault.token
            entered, attempted = threading.Event(), threading.Event()
            active, result, timeouts = threading.local(), {}, []
            original_transaction = store.transaction

            class BoundedLock:
                def __init__(self, lock, name):
                    self.lock, self.name = lock, name

                def __enter__(self):
                    reader = threading.current_thread() is concurrent
                    acquired = False
                    if reader and self.name == 'access':
                        acquired = self.lock.acquire(blocking=False)
                        attempted.set()
                    if not acquired and not self.lock.acquire(timeout=5):
                        timeouts.append(self.name)
                        raise TimeoutError('Concurrent Case Board operation blocked on ' + self.name)
                    if self.name == 'store' and getattr(active, 'transaction', False) and not entered.is_set():
                        entered.set()
                        if not attempted.wait(5):
                            self.lock.release()
                            raise TimeoutError('Concurrent session resolver did not attempt its access check')
                    return self

                def __exit__(self, *args):
                    self.lock.release()

            @contextmanager
            def scheduled_transaction():
                previous = getattr(active, 'transaction', False)
                active.transaction = True
                try:
                    with original_transaction():
                        yield
                finally:
                    active.transaction = previous

            def resolve_session():
                try:
                    if not entered.wait(5):
                        raise TimeoutError('Case Board write did not enter its transaction')
                    result['principal'] = access.resolve(session, '127.0.0.1')
                except Exception as exc:
                    result['error'] = exc

            concurrent = threading.Thread(target=resolve_session, name='case-board-session-reader')
            with patch.object(access, 'lock', BoundedLock(access.lock, 'access')), \
                    patch.object(store, 'lock', BoundedLock(store.lock, 'store')), \
                    patch.object(store, 'transaction', scheduled_transaction):
                concurrent.start()
                try:
                    response = await asyncio.wait_for(client.post('/api/board/slice',
                        headers={'Authorization': 'Bearer ' + session}, json={'query': {'chat_id': -1001}}), 15)
                finally:
                    await asyncio.to_thread(concurrent.join, 6)
                    assert not concurrent.is_alive(), 'Bounded concurrent resolver did not finish'
            assert not timeouts and 'error' not in result, (timeouts, result)
            assert attempted.is_set() and result['principal'].admin
            assert response.status_code == 200, response.text
            saved = Board(store).read(store.db, result['principal'])['items']
            assert len(saved) == 1 and saved[0]['kind'] == 'board.slice'
    asyncio.run(run())


@pytest.mark.parametrize('checkpoint', ['transaction', 'append'])
@pytest.mark.parametrize('credential', ['admin-session', 'grant-session'])
@pytest.mark.parametrize('invalidation', ['revocation', 'expiry'])
def test_board_write_rechecks_current_access(checkpoint, credential, invalidation):
    async def run():
        async with workspace() as (app, client):
            store, access = app.state.store, app.state.access
            store.append('message.new', {'text': 'Synthetic authorization observation'}, -1001, 1)
            if credential == 'admin-session':
                token, principal = access.login(app.state.vault.token, '127.0.0.1', 'Synthetic administrator')
                headers = {'Authorization': 'Bearer ' + token}
                grant = None
            else:
                grant, headers = grant_session(app, {'default': [-1001]}, ['view', 'board.read', 'board.write'])
                token = headers['Authorization'].split(' ', 1)[1]
                principal = access.resolve(token, '127.0.0.1')
            invalidated = False
            original_transaction, original_append = store.transaction, Board.append

            def invalidate():
                nonlocal invalidated
                if invalidated:
                    return
                invalidated = True
                if invalidation == 'revocation':
                    if grant:
                        access.revoke(grant['id'])
                    else:
                        access.end(principal.session_id, 'Synthetic revocation during Case Board write')
                elif grant:
                    grant['expires_at'] = time.time() - 1
                else:
                    next(item for item in access.sessions.values() if item['id'] == principal.session_id)['expires'] = time.time() - 1

            @contextmanager
            def changing_transaction():
                with original_transaction():
                    invalidate()
                    yield

            def changing_append(service, *args, **kwargs):
                invalidate()
                return original_append(service, *args, **kwargs)

            changing = patch.object(store, 'transaction', changing_transaction) if checkpoint == 'transaction' else \
                patch.object(Board, 'append', changing_append)
            with changing:
                response = await client.post('/api/board/slice', headers=headers, json={'query': {'chat_id': -1001}})
            assert invalidated and response.status_code == 403, response.text
            assert not Board(store).state(store.db)['items']
    asyncio.run(run())


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
