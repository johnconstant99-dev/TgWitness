"""Synthetic regressions for panel disclosure, proxy trust, limits and key replacement."""
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
    # Malformed trusted metadata must never inherit an allowlisted local proxy IP.
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
            for bad in ('../other', 'missing', 'default&ws=default', ''):
                assert http.get('/api/access?ws=' + bad, headers=root_headers).status_code == 404
            assert http.get('/api/access?ws=default', headers=root_headers).status_code == 200
            child = http.post('/api/profiles', headers=root_headers, json={'label': 'Synthetic second workspace'}).json()['id']
            child_url = '/profiles/' + child + '/api/status'
            assert http.get(child_url + '?ws=' + child, headers=root_headers).status_code == 200
            assert http.get(child_url + '?ws=default', headers=root_headers).status_code == 404
            # A refused route policy cannot partly overwrite the saved settings.
            before = app.state.collector.policy_state()
            assert before['outside_enabled'] is False
            denied = http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': True})
            assert denied.status_code == 400, (denied.status_code, denied.content)
            assert app.state.collector.policy_state() == before
            accepted = http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': False})
            assert accepted.status_code == 200, accepted.content
            # A later Telegram-route change cannot remove the only outside route.
            proxy = {'kind': 'socks5', 'host': '127.0.0.1', 'port': 1080}
            assert http.post('/api/network', headers=root_headers, json=proxy).status_code == 200
            assert http.post('/api/network/policy', headers=root_headers, json={'exposure': 'hide', 'outside_enabled': True}).status_code == 200
            assert http.post('/api/network', headers=root_headers, json={'kind': 'mtproxy_auto'}).status_code == 400
            assert app.state.collector.network_config().kind == 'socks5'
            assert 'PrivateBrowser' not in json.dumps(vault.read('access'))
            assert 'PrivateBrowser' not in json.dumps(access.state())
            archive = export_file(store, vault, 'zip')
            with zipfile.ZipFile(archive) as exported:
                assert b'PrivateBrowser' not in exported.read('events.jsonl')
                assert b'PrivateBrowser' not in exported.read('report.html')
            # Old fingerprints are removed from mutable session data on restart.
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
            # HTML reports render hostile raw strings as text, even in raw-record details.
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


if __name__ == '__main__':
    asyncio.run(boundary_checks())
    disclosure_checks()
    print('Operator security passed: proxy trust, API backoff, IP allowlist, stream limits, scoped status, UA minimization, key rotation and escaped reports.')
