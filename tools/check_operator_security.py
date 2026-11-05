import asyncio
import json
import logging
from pathlib import Path
import re
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tgwitness.access import AccessControl, Console, GrantSettings
from tgwitness.app import create_app
from tgwitness import report
from tgwitness.evidence import export_file
from tgwitness.live_stream import StreamSlots
from tgwitness.operator_privacy import hide_addresses, private_log
from tgwitness.request_security import RequestSecurity
from tools.check_codeql_boundaries import local_client


async def boundary_checks():
    seen, clock = [], [0.0]
    async def app(scope, receive, send):
        seen.append(scope['client'][0])
        status = 401 if scope['path'].endswith('/bad') else 200
        await send({'type': 'http.response.start', 'status': status, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})
    guard = RequestSecurity(app, trusted='127.0.0.1/32', header='x-forwarded-for', allowed='', clock=lambda: clock[0])
    async def request(path='/api/status', peer='203.0.113.9', headers=(), target=guard):
        sent = []
        async def send(message):
            sent.append(message)
        async def receive():
            return {'type': 'http.request', 'body': b''}
        await target({'type': 'http', 'path': path, 'headers': list(headers), 'client': (peer, 123)}, receive, send)
        return sent[0]
    await request(headers=[(b'x-forwarded-for', b'198.51.100.4')])
    assert seen[-1] == '203.0.113.9'
    await request(peer='127.0.0.1', headers=[(b'x-forwarded-for', b'192.0.2.9, 198.51.100.4')])
    assert seen[-1] == '198.51.100.4'
    cf = RequestSecurity(app, trusted='127.0.0.1', header='cf-connecting-ip', allowed='', clock=lambda: clock[0])
    await request(peer='127.0.0.1', headers=[(b'cf-connecting-ip', b'2001:db8::12')], target=cf)
    assert seen[-1] == '2001:db8::12'
    assert (await request(peer='127.0.0.1', headers=[(b'cf-connecting-ip', b'192.0.2.1,192.0.2.2')], target=cf))['status'] == 400
    strict = RequestSecurity(app, trusted='127.0.0.1', allowed='127.0.0.1', header='x-forwarded-for')
    assert (await request(peer='127.0.0.1', headers=[(b'x-forwarded-for', b'invalid')], target=strict))['status'] == 400
    assert (await request(peer='127.0.0.1', headers=[(b'x-forwarded-for', b'192.0.2.1'), (b'x-forwarded-for', b'192.0.2.2')], target=strict))['status'] == 400
    assert (await request(peer='127.0.0.1', target=strict))['status'] == 200
    restricted = RequestSecurity(app, trusted='', allowed='198.51.100.0/24')
    assert (await request(target=restricted))['status'] == 403
    assert (await request(peer='198.51.100.9', target=restricted))['status'] == 200
    for _ in range(10):
        assert (await request('/api/bad'))['status'] == 401
    reply = await request()
    assert reply['status'] == 429 and dict(reply['headers'])[b'retry-after'] == b'1'
    clock[0] += 1
    assert (await request('/api/bad'))['status'] == 401
    assert dict((await request())['headers'])[b'retry-after'] == b'2'
    clock[0] += 61
    for _ in range(600):
        assert (await request())['status'] == 200
    assert (await request())['status'] == 429
    assert (await request(peer='203.0.113.10'))['status'] == 200
    v6 = RequestSecurity(app, trusted='', allowed='', clock=lambda: clock[0])
    for index in range(10):
        assert (await request('/api/bad', peer='2001:db8:1:2::' + format(index + 1, 'x'), target=v6))['status'] == 401
    assert (await request(peer='2001:db8:1:2:ffff::9', target=v6))['status'] == 429
    assert (await request(peer='2001:db8:1:3::1', target=v6))['status'] == 200
    for _ in range(10):
        assert (await request('/api/bad', peer='::ffff:192.0.2.40', target=v6))['status'] == 401
    assert (await request(peer='192.0.2.40', target=v6))['status'] == 429
    for _ in range(10):
        assert (await request('/api/bad', peer='64:ff9b::c000:22a', target=v6))['status'] == 401
    assert (await request(peer='64:ff9b::c000:22b', target=v6))['status'] == 200
    mapped = RequestSecurity(app, trusted='', allowed='192.0.2.0/24')
    assert (await request(peer='::ffff:192.0.2.40', target=mapped))['status'] == 200
    slots = StreamSlots(limit=3, per_token=2)
    assert slots.acquire('a') and slots.acquire('a') and not slots.acquire('a')
    assert slots.acquire('b') and not slots.acquire('c')
    slots.release('a')
    assert slots.acquire('c')
    slots.release('a'); slots.release('b'); slots.release('c')
    assert slots.active == 0 and not slots.owners


def disclosure_checks():
    with tempfile.TemporaryDirectory(prefix='operator-security-') as tmp:
        app = create_app(Path(tmp), demo=False)
        with local_client(app) as http:
            access, vault, store = app.state.access, app.state.vault, app.state.store
            marker = 'PRIVATE_PROXY_HOST.invalid'
            app.state.collector.route_status = lambda: {'current': {'host': marker, 'port': 2053}, 'pool': {'source': marker}}
            app.state.collector.last_error = 'Connection to ' + marker + ' failed'
            root_headers = {'Authorization': 'Bearer ' + vault.token}
            assert http.get('/api/status', headers=root_headers).status_code == 200
            for permissions, chats, visible in [(['view'], None, False), (['view', 'export'], None, False),
                                                (['view', 'account'], None, True), (['view', 'account'], [123], False)]:
                token, _ = access.issue(GrantSettings(label='Synthetic reviewer', permissions=permissions, workspaces={'default': chats}))
                session, _ = access.login(token, '127.0.0.1', 'PrivateBrowser/999.1234 <script>unexpected()</script>')
                headers = {'Authorization': 'Bearer ' + session}
                for path in ('/api/status', '/api/profiles'):
                    response = http.get(path, headers=headers)
                    assert response.status_code == 200, (path, response.content)
                    assert (marker.encode() in response.content) is visible, (permissions, path)
                journal = http.get('/api/events', headers=headers, params={
                    'kind': 'access.session_started,access.granted', 'include_count': 'true', 'limit': 500}).json()
                assert journal['events'] == [] and journal['matched'] == 0, permissions
                listed = http.get('/api/events', headers=headers, params={'limit': 500}).json()['events']
                assert not any(event['kind'].startswith('access.') for event in listed), permissions
                if not visible:
                    data = json.loads(http.get('/api/status', headers=headers).content)
                    assert 'network' not in data['collector'] and 'version' not in data and 'run_id' not in data
                    assert data['health']['state']
                    health_reply = http.get('/api/health', headers=headers)
                    assert marker.encode() not in health_reply.content
                assert http.get('/api/access', headers=headers).status_code == 403
                assert http.post('/api/access/token', headers=headers, json={}).status_code == 403
                for path in ('/api/replica', '/api/alerts', '/api/parameters'):
                    assert http.get(path, headers=headers).status_code == 403
            started = http.get('/api/events', headers=root_headers,
                               params={'kind': 'access.session_started', 'limit': 50}).json()['events']
            assert started and not any('address' in event['payload'] for event in started)
            for bad in ('../other', 'missing', 'default&ws=default', ''):
                assert http.get('/api/access?ws=' + bad, headers=root_headers).status_code == 404
            assert http.get('/api/access?ws=default', headers=root_headers).status_code == 200
            child = http.post('/api/profiles', headers=root_headers, json={'label': 'Synthetic second workspace'}).json()['id']
            child_url = '/profiles/' + child + '/api/status'
            assert http.get(child_url + '?ws=' + child, headers=root_headers).status_code == 200
            assert http.get(child_url + '?ws=default', headers=root_headers).status_code == 404
            before = app.state.collector.policy_state()
            assert before['outside_enabled'] is False
            denied = http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': True})
            assert denied.status_code == 400, (denied.status_code, denied.content)
            assert app.state.collector.policy_state() == before
            accepted = http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': False})
            assert accepted.status_code == 200, accepted.content
            proxy = {'kind': 'socks5', 'host': '127.0.0.1', 'port': 1080}
            assert http.post('/api/network', headers=root_headers, json=proxy).status_code == 200
            assert http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': True}).status_code == 200
            assert http.post('/api/network', headers=root_headers, json={'kind': 'mtproxy_auto'}).status_code == 400
            assert app.state.collector.network_config().kind == 'socks5'
            assert 'PrivateBrowser' not in json.dumps(vault.read('access'))
            assert 'PrivateBrowser' not in json.dumps(access.state())
            probe_settings = GrantSettings(label='Address probe', ips=['203.0.113.128/25'], workspaces={'default': None})
            probe, probe_grant = access.issue(probe_settings)
            access.change(probe_grant['id'], probe_settings)
            access.login(probe, '203.0.113.201', None)
            assert any(s['address'] == '203.0.113.201' for s in access.state()['sessions'])
            policy = [event['payload'] for event in http.get('/api/events', headers=root_headers, params={
                'kind': 'access.granted,access.changed', 'limit': 50}).json()['events']
                if event['payload'].get('label') == 'Address probe']
            assert len(policy) == 2 and all(p['ip_restrictions'] == 1 and 'ips' not in p for p in policy)
            archive = export_file(store, vault, 'zip')
            with zipfile.ZipFile(archive) as exported:
                assert b'PrivateBrowser' not in exported.read('events.jsonl')
                assert b'203.0.113.201' not in exported.read('events.jsonl')
                assert b'203.0.113.128' not in exported.read('events.jsonl')
                assert b'PrivateBrowser' not in exported.read('report.html')
            raw = vault.read('access')
            raw['sessions'][0]['agent'] = 'OldPrivateBrowser/123'
            vault.save('access', raw)
            restarted = AccessControl(vault, store)
            assert 'OldPrivateBrowser' not in json.dumps(vault.read('access'))
            old_key = vault.token
            active, _ = restarted.login(old_key, '127.0.0.1', 'Secret browser')
            new_key, count = restarted.rotate_token()
            assert count > 0 and new_key != old_key
            assert restarted.resolve(old_key, '127.0.0.1') is None
            assert restarted.resolve(active, '127.0.0.1') is None
            assert restarted.resolve(new_key, '127.0.0.1').admin
            assert not AccessControl(vault, store).sessions
            assert (Path(tmp) / 'panel-token.txt').read_text() == new_key
            assert new_key not in json.dumps(list(store.events(limit=200)))
            attack = '<img src=x onerror="window.attack=1"><script>unexpected()</script>'
            store.append('synthetic.operator_check', {'agent': attack})
            path = export_file(store, vault, 'html', {**report.resolved(), 'language': 'en', 'raw_records': True})
            output = path.read_text(encoding='utf-8')
            blocks = re.findall(r'<script type="application/json" class="tgw-file" data-file="viewer/records-[^"]+">(.*?)</script>', output)
            assert blocks and attack not in output
            records = [record for block in blocks for record in json.loads(block)]
            assert any(record.get('r', {}).get('payload', {}).get('agent') == attack for record in records)
    console = Console()
    original = 'connected 203.0.113.19:443 [2001:db8::7]:443 ::1 at 12:34:56'
    record = logging.LogRecord('synthetic', logging.INFO, '', 0, original, (), None)
    console.emit(record)
    rendered = console.after(0)[0]['text']
    assert '203.0.113.19' not in rendered and '2001:db8' not in rendered and '::1' not in rendered
    assert '12:34:56' in rendered and record.getMessage() == original
    assert hide_addresses('version 0.7.1') == 'version 0.7.1'
    for raw, sensitive in [('tg://proxy?server=203.0.113.1&secret=SYNTHETIC_SECRET', 'SYNTHETIC_SECRET'),
                           ('socks5://person:password123@localhost:1080', 'password123'),
                           ('Authorization: Bearer SYNTHETIC_TOKEN', 'SYNTHETIC_TOKEN'),
                           ('{"phone_code": "12345"}', '12345')]:
        assert sensitive not in private_log(raw)


def admin_record_checks():
    from tgwitness.live_stream import notifications
    from tgwitness.network import NetworkConfig
    with tempfile.TemporaryDirectory(prefix='operator-admin-records-') as tmp:
        app = create_app(Path(tmp), demo=False)
        with local_client(app) as http:
            store, vault, collector = app.state.store, app.state.vault, app.state.collector
            admin = {'Authorization': 'Bearer ' + vault.token}
            other = http.post('/api/profiles', headers=admin, json={'label': 'Synthetic covert workspace'}).json()['id']

            def session(label, permissions, workspaces):
                token = http.post('/api/access/grants', headers=admin, json={
                    'label': label, 'permissions': permissions, 'workspaces': workspaces}).json()['token']
                return {'Authorization': 'Bearer ' + http.post('/api/access/login', json={'token': token}).json()['session']}

            colleague = session('Synthetic colleague', ['view', 'export', 'board.read', 'board.write'], {'default': None})
            limited = session('Synthetic limited', ['view', 'export'], {'default': [123]})
            listed = http.get('/api/events', headers=colleague, params={'kind': 'profile.created', 'limit': 50}).json()
            assert listed['events'] == [] and b'Synthetic covert workspace' not in http.get(
                '/api/events', headers=colleague, params={'limit': 500}).content
            assert http.get('/api/events', headers=admin, params={'kind': 'profile.created', 'limit': 50}).json()['events']
            streamed = {row['kind'] for row in notifications(store, 0, None, limit=500, hide_admin=True)}
            assert not any(kind.startswith(('access.', 'profile.')) for kind in streamed)
            assert any(row['kind'].startswith('access.') for row in notifications(store, 0, None, limit=500))

            record = store.events(kind='access.session_started', limit=1)[0]
            refused = http.post('/api/board/bookmark', headers=colleague, json={'target': {'event_hash': record['hash']}, 'title': 'probe'})
            assert refused.status_code == 403, refused.content
            card = http.post('/api/board/bookmark', headers=admin, json={'target': {'event_hash': record['hash']}, 'title': 'admin note'}).json()
            detail = http.get('/api/board/card/' + card['payload']['id'], headers=colleague).json()
            assert detail['target']['payload'] == {} and detail['target']['kind'] == 'access.session_started'
            targeted = [item for item in http.get('/api/board', headers=colleague).json()['cards'] if item.get('target')]
            assert targeted and all(item['preview']['payload'] == {} for item in targeted)
            assert http.get('/api/board/card/' + card['payload']['id'], headers=admin).json()['target']['payload']

            mcp = http.post('/api/mcp/connections', headers=admin, json={
                'name': 'Synthetic MCP', 'workspaces': {'default': None}, 'expires_in_seconds': 3600}).json()['token']
            journal = http.post('/api/archive/query', headers={'Authorization': 'Bearer ' + mcp},
                                json={'tool': 'get_journal_event', 'event_seq': record['seq']})
            assert journal.status_code == 403, journal.content

            vault.save('outside_proxy', NetworkConfig(kind='socks5', host='203.0.113.77', port=1080).model_dump())
            store.set_setting('route_policy', {'exposure': 'hide', 'outside_enabled': True})
            assert http.get('/api/analysis/provider', headers=admin).json()['route_host'] == '203.0.113.77'
            provider = http.get('/api/analysis/provider', headers=limited)
            assert provider.status_code == 200 and b'203.0.113.77' not in provider.content, provider.content

            for value in ('123.0', '0x7b'):
                assert http.get('/api/chats/' + value + '/messages', headers=limited).status_code == 403
            assert http.post('/profiles/' + other + '/api/preferences', headers=colleague, json={}).status_code == 403
            assert http.post('/api/preferences', headers=colleague, json={}).status_code == 200

            result = store.root / 'synthetic-chat-export.zip'
            result.write_bytes(b'PK synthetic')
            collector.export_state, collector.export_path = {'id': 'synthetic-export', 'chat_id': 123, 'phase': 'done', 'ready': True}, result
            assert http.get('/api/chat-export/synthetic-export/download', headers=limited).status_code == 404
            assert http.post('/api/chat-export/synthetic-export/cancel', headers=limited).status_code == 403
            assert http.get('/api/chat-export/synthetic-export', headers=limited).json() == {'phase': 'unknown'}
            assert http.get('/api/chat-export/synthetic-export/download', headers=admin).content == b'PK synthetic'


if __name__ == '__main__':
    asyncio.run(boundary_checks())
    disclosure_checks()
    admin_record_checks()
    print('Operator security passed: proxy trust, API backoff, IP allowlist, stream limits, scoped status, UA minimization, key rotation and escaped reports.')
