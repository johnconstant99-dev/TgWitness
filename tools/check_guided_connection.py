import base64
import asyncio
import hashlib
import io
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from tools.check_browser import FakeClient
from tgwitness.app import create_app
from tgwitness.guided_connection import probe
from tgwitness.network import NetworkConfig
from tgwitness.portable_routes import binary_data, runtime_config, wireguard_profile


KEY = base64.b64encode(bytes(range(32))).decode()
PROFILE = f"""[Interface]
PrivateKey = {KEY}
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1
[Peer]
PublicKey = {KEY}
Endpoint = vpn.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""
CHECK = {"telegram_connected": True, "latency_ms": 25, "checked_at": 1700000000,
         "exit_ip": "203.0.113.10", "country": "DE", "warp": "on"}


class Profiles(unittest.IsolatedAsyncioTestCase):
    async def test_data_only_profile_and_pinned_endpoint(self):
        profile = wireguard_profile(PROFILE)
        route = NetworkConfig(kind="socks5", host="127.0.0.1", port=40001, username="local", password="private")
        with patch('tgwitness.netclient.resolve', AsyncMock(return_value=['1.1.1.1'])):
            config = await runtime_config(profile, route)
        self.assertIn('Endpoint = 1.1.1.1:51820', config)
        self.assertIn('BindAddress = 127.0.0.1:40001', config)
        for replacement in ('PostUp = touch /tmp/file', 'WGConfig = /etc/passwd',
                            'TunnelDomains = example.org', 'PrivateKey = $SECRET'):
            text = PROFILE.replace('PrivateKey = ' + KEY, replacement)
            with self.assertRaises(ValueError):
                wireguard_profile(text)
        for extra in ('\n[Socks5]\nBindAddress = 0.0.0.0:80', '\n[DEFAULT]\nSecret = x',
                      '\n[Peer]\nEndpoint = evil:80'):
            with self.assertRaises(ValueError):
                wireguard_profile(PROFILE + extra)
        with self.assertRaises(ValueError):
            wireguard_profile(PROFILE.replace('0.0.0.0/0, ::/0', '10.0.0.0/8'))
        with patch('tgwitness.netclient.resolve', AsyncMock(return_value=['169.254.169.254'])):
            with self.assertRaises(Exception):
                await runtime_config(profile, route)

    async def test_archive_digest_and_paths(self):
        with self.assertRaises(ValueError):
            binary_data('wgcf', b'evil', '0' * 64, False)
        for name, kind in [('wireproxy', tarfile.REGTYPE), ('../wireproxy', tarfile.REGTYPE),
                           ('wireproxy', tarfile.SYMTYPE)]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w:gz') as archive:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = 4 if kind == tarfile.REGTYPE else 0
                archive.addfile(info, io.BytesIO(b'test') if info.size else None)
            content = data.getvalue()
            if name == 'wireproxy' and kind == tarfile.REGTYPE:
                self.assertEqual(binary_data('wireproxy', content, hashlib.sha256(content).hexdigest(), False), b'test')
            else:
                with self.assertRaises(ValueError):
                    binary_data('wireproxy', content, hashlib.sha256(content).hexdigest(), False)

    async def test_probe_does_not_load_account_session(self):
        from types import SimpleNamespace
        made = []
        def factory(session, *args, **kwargs):
            self.assertIsNone(session.auth_key)
            self.assertFalse(kwargs['receive_updates'])
            client = SimpleNamespace(connect=AsyncMock(), disconnect=AsyncMock())
            made.append(client)
            return client
        c = SimpleNamespace(client_factory=factory)
        with patch('tgwitness.netclient.request', AsyncMock(return_value=(200, {}, b'ip=1.1.1.1\nloc=US\nwarp=off\n'))):
            result = await probe(c, NetworkConfig(kind='direct'), 'direct')
            self.assertTrue(result['telegram_connected'])
            self.assertEqual(result['exit_ip'], '1.1.1.1')
            with self.assertRaises(ValueError):
                await probe(c, NetworkConfig(kind='direct'), 'warp')
        for client in made:
            client.disconnect.assert_awaited_once()


class API(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.app = create_app(Path(self.folder.name), client_factory=FakeClient)
        self.client = TestClient(self.app).__enter__()
        self.headers = {'Authorization': 'Bearer ' + self.app.state.vault.token}
        self.probe = patch('tgwitness.guided_connection.probe', AsyncMock(return_value=CHECK)).start()

    def tearDown(self):
        patch.stopall()
        self.client.__exit__(None, None, None)
        self.folder.cleanup()

    def post(self, path, body):
        return self.client.post('/api/connection/' + path, json=body, headers=self.headers)

    def wait_job(self):
        for _ in range(300):
            result = self.client.get('/api/connection', headers=self.headers).json()['job']
            if result['state'] not in ('preparing', 'applying'):
                return result
            time.sleep(.01)
        self.fail('Connection job did not finish')

    def prepare(self, **body):
        r = self.post('prepare', {'mode': 'direct', **body})
        self.assertEqual(r.status_code, 200, r.text)
        job = self.wait_job()
        self.assertEqual(job['state'], 'ready', job)
        return job['plan']

    def test_checked_apply_and_no_implicit_collection(self):
        original = self.app.state.collector.network_config().kind
        plan = self.prepare()
        self.assertEqual(self.app.state.collector.network_config().kind, original)
        self.assertEqual(self.post('apply', {'plan': plan}).status_code, 200)
        job = self.wait_job()
        self.assertTrue(job['rows'][0]['applied'], job)
        self.assertEqual(self.app.state.collector.network_config().kind, 'direct')
        self.assertFalse(self.app.state.collector.running)
        self.assertEqual(self.post('apply', {'plan': plan}).status_code, 409)

    def test_changed_and_expired_plan_refused(self):
        plan = self.prepare()
        self.app.state.store.set_setting('route_policy', {'exposure':'fallback','outside_enabled':True})
        self.post('apply', {'plan': plan})
        self.assertEqual(self.wait_job()['state'], 'failed')
        self.assertNotEqual(self.app.state.collector.network_config().kind, 'direct')
        plan = self.prepare()
        self.app.state.connection.plan['expires'] = 0
        self.post('apply', {'plan': plan})
        self.assertEqual(self.wait_job()['state'], 'failed')

    def test_failed_recheck_preserves_route_and_credentials(self):
        plan = self.prepare()
        before = self.app.state.vault.read('network')
        self.probe.side_effect = TimeoutError()
        self.post('apply', {'plan': plan})
        job = self.wait_job()
        self.assertFalse(job['rows'][0]['applied'])
        self.assertEqual(self.app.state.vault.read('network'), before)

    def test_scope_validation_and_permissions(self):
        self.assertEqual(self.post('preview', {'mode':'direct','account':'../other'}).status_code, 400)
        self.assertEqual(self.post('preview', {'mode':'direct','scope':'group','group':'missing'}).status_code, 400)
        self.assertEqual(self.post('preview', {'mode':'vpn','wireguard':PROFILE,'scope':'all'}).status_code, 422)
        self.assertEqual(self.client.get('/api/connection').status_code, 401)
        from tgwitness.access import GrantSettings
        token, _ = self.app.state.access.issue(GrantSettings(label='Reviewer', workspaces={'default':None}))
        login = self.client.post('/api/access/login', json={'token':token}).json()
        viewer = {'Authorization':'Bearer ' + login['session']}
        self.assertEqual(self.client.get('/api/connection', headers=viewer).status_code, 403)
        self.assertEqual(self.client.post('/api/connection/prepare', json={'mode':'direct'}, headers=viewer).status_code, 403)

    def test_all_accounts_keep_custom_and_apply_individually(self):
        added = self.client.post('/api/profiles', json={'label':'Second account'}, headers=self.headers)
        self.assertEqual(added.status_code, 200, added.text)
        entries = self.app.state.profiles.entries
        identifier = next(i for i in entries if i != 'default')
        child = entries[identifier]['app']
        child.state.vault.save('network', NetworkConfig(kind='direct').model_dump())
        preview = self.post('preview', {'mode':'direct','scope':'all'}).json()
        self.assertEqual({r['id'] for r in preview['rows'] if r['skipped']}, {identifier})
        plan = self.prepare(scope='all')
        self.post('apply', {'plan':plan})
        job = self.wait_job()
        self.assertEqual(len(job['rows']), 1)
        self.assertEqual(job['rows'][0]['id'], 'default')
        self.assertTrue(job['rows'][0]['applied'])
        self.assertFalse(child.state.collector.running)

    def test_switch_failure_restores_old_policy(self):
        plan = self.prepare()
        c = self.app.state.collector
        before = c.route_policy()
        with patch.object(c, 'set_network', AsyncMock(side_effect=ValueError('synthetic save failure'))):
            self.post('apply', {'plan':plan})
            job = self.wait_job()
        self.assertFalse(job['rows'][0]['applied'])
        self.assertEqual(c.route_policy(), before)
        self.assertEqual(c.network_config().kind, 'mtproxy_auto')

    def test_cancel_pending_probe_without_changing_route(self):
        async def waiting(*args):
            await asyncio.Event().wait()
        self.probe.side_effect = waiting
        self.assertEqual(self.post('prepare', {'mode':'direct'}).status_code, 200)
        self.assertEqual(self.post('cancel', {}).status_code, 200)
        self.assertEqual(self.wait_job()['state'], 'idle')
        self.assertEqual(self.app.state.collector.network_config().kind, 'mtproxy_auto')

    def test_warp_group_uses_separate_saved_credentials(self):
        from tgwitness.portable_routes import PortableRoutes
        self.client.post('/api/profiles', json={'label':'Second account'}, headers=self.headers)
        generated=[]
        async def local_fixture(*args):
            index=len(generated)+1
            route=NetworkConfig(kind='socks5',host='127.0.0.1',port=40000+index,
                                username='fixture',password='per-account-'+str(index),local_proxy=True)
            saved={'id':str(index)*32,'mode':'warp','profile':PROFILE,'network':route.model_dump()}
            generated.append(saved)
            return saved
        with patch.object(PortableRoutes,'prepare',AsyncMock(side_effect=local_fixture)), \
                patch.object(PortableRoutes,'restore',AsyncMock()):
            plan=self.prepare(mode='warp',scope='all',accept_setup=True)
            self.post('apply', {'plan':plan})
            result=self.wait_job()
        self.assertEqual(len(generated), 2)
        self.assertTrue(all(row['applied'] for row in result['rows']), result)
        routes=[e['app'].state.vault.read('portable_route') for e in self.app.state.profiles.entries.values()]
        self.assertEqual(len({r['network']['password'] for r in routes}),2)
        for entry in self.app.state.profiles.entries.values():
            vault=entry['app'].state.vault
            self.assertNotIn(KEY.encode(), (vault.root/'portable_route.enc').read_bytes())

    def test_failed_check_does_not_stop_reused_selected_tunnel(self):
        portable = self.app.state.connection.portable
        route = NetworkConfig(kind='socks5',host='127.0.0.1',port=40001,local_proxy=True)
        saved = {'id':'a'*32,'mode':'warp','profile':PROFILE,'network':route.model_dump()}
        self.app.state.vault.save('network',route.model_dump())
        self.app.state.vault.save('portable_route',saved)
        self.probe.side_effect = ValueError('synthetic probe failure')
        with patch.object(portable,'prepare',AsyncMock(return_value=saved)), \
                patch.object(portable,'restore',AsyncMock()), patch.object(portable,'stop',AsyncMock()) as stop:
            self.post('prepare', {'mode':'warp'})
            self.assertEqual(self.wait_job()['state'],'failed')
            stop.assert_not_awaited()
        self.assertEqual(portable.selected(),saved)


if __name__ == '__main__':
    unittest.main()
