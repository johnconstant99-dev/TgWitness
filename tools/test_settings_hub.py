import asyncio
import json
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from check_browser import RunningApp, launch_browser, check_layout
from tgwitness import settings_hub
from tgwitness.guided_connection import ConnectionDraft, GuidedConnection
from tgwitness.monitoring import duration_allowed, capture_settings
from tgwitness.network import parse_proxy_url


def test_proxy_urls():
    config = parse_proxy_url('https://user:p%40ss@example.com:444')
    assert config.tls and config.port == 444 and config.password == 'p@ss'
    assert config.client_options()['connection'].__name__ == 'HTTPSConnection'
    assert parse_proxy_url('socks5://[::1]:1080').host == '::1'
    assert parse_proxy_url('tg://proxy?server=example.com&port=443&secret='+'ab'*16).kind == 'mtproxy'
    for value in ('https://example.com/path', 'file:///etc/passwd', 'socks5://host:99999', 'http://host/#fragment'):
        with pytest.raises(ValueError):
            parse_proxy_url(value)


def test_auto_never_falls_through_to_direct(monkeypatch):
    from tgwitness import guided_connection
    attempts = []
    async def fail(c, route, mode, **kwargs):
        attempts.append(mode)
        raise ValueError('offline')
    async def warp(*args):
        attempts.append('warp')
        raise ValueError('offline')
    monkeypatch.setattr(guided_connection, 'probe', fail)
    portable = SimpleNamespace(prepare=warp)
    manager = object.__new__(GuidedConnection)
    for allow in (False, True):
        attempts.clear()
        with pytest.raises(ValueError):
            asyncio.run(manager.automatic_route(None, portable, ConnectionDraft(mode='auto', allow_direct=allow), lambda _:None))
        assert attempts == (['mtproxy','warp','direct'] if allow else ['mtproxy','warp'])


def test_short_video_rule():
    rule = settings_hub.file_policy('short_media')['types']['video']
    assert duration_allowed(SimpleNamespace(file=SimpleNamespace(duration=60)), rule)
    assert not duration_allowed(SimpleNamespace(file=SimpleNamespace(duration=61)), rule)
    assert not duration_allowed(SimpleNamespace(file=SimpleNamespace()), rule)


def test_export_honors_goal_file_limits():
    from tgwitness.account_export import AccountExport, AccountExportOptions
    from telethon.tl import types
    export=object.__new__(AccountExport)
    video=SimpleNamespace(document=SimpleNamespace(size=1000,id=1,attributes=[types.DocumentAttributeVideo(
        duration=61,w=320,h=240)]))
    options=AccountExportOptions(media_rules={'video':{'max_mb':20,'max_seconds':60}}).model_dump()
    result=asyncio.run(export.attachment(video,{'category':'messages'},None,None,options))
    assert result['reason']=='duration_limit'
    video.document.attributes[0].duration=20
    video.document.size=21*1024**2
    result=asyncio.run(export.attachment(video,{'category':'messages'},None,None,options))
    assert result['reason']=='per_file_limit'


def test_https_proxy_verifies_tls_and_keeps_credentials_inside(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from tgwitness import https_proxy, alerts
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
        .not_valid_after(now+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
        .sign(key,hashes.SHA256()))
    pem, private = tmp_path/'cert.pem', tmp_path/'key.pem'
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_tls.load_cert_chain(pem,private)
    real_context = ssl.create_default_context
    async def exercise():
        seen = []
        async def proxy(reader, writer):
            try:
                seen.append(await reader.readuntil(b'\r\n\r\n'))
                assert writer.get_extra_info('ssl_object') is not None
                writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n'); await writer.drain()
                writer.write(await reader.readexactly(4)); await writer.drain()
            finally:
                writer.close()
        async with await asyncio.start_server(proxy,'127.0.0.1',0,ssl=server_tls) as server:
            port=server.sockets[0].getsockname()[1]
            route=parse_proxy_url(f'https://user:secret@localhost:{port}')
            with pytest.raises(ssl.SSLCertVerificationError):
                await https_proxy.tunnel(route,'149.154.167.51',443,address='127.0.0.1')
            assert not seen, 'Proxy credentials must not be sent before TLS verification'
            monkeypatch.setattr(https_proxy.ssl,'create_default_context',lambda:real_context(cafile=str(pem)))
            reader,writer=await https_proxy.tunnel(route,'149.154.167.51',443,address='127.0.0.1')
            writer.write(b'ping');await writer.drain();assert await reader.readexactly(4)==b'ping'
            writer.close();await writer.wait_closed()
            assert seen[0].startswith(b'CONNECT 149.154.167.51:443 HTTP/1.1\r\n')
            assert b'Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=' in seen[0]
            assert alerts.proxy_url(route,'127.0.0.1').startswith('https://user:secret@localhost:')
            wrong=route.model_copy(update={'tls_server_name':'wrong.invalid'})
            with pytest.raises(ssl.SSLCertVerificationError):
                await https_proxy.tunnel(wrong,'149.154.167.51',443,address='127.0.0.1')
    asyncio.run(exercise())


def test_server_state(tmp_path):
    with RunningApp(tmp_path) as server:
        token = requests.post(server.url+'/api/access/login',json={'token':server.app.state.vault.token}).json()['session']
        headers = {'Authorization':'Bearer '+token}
        def get(path):
            r=requests.get(server.url+'/api/'+path,headers=headers);assert r.ok,r.text;return r.json()
        def post(path,body,status=200):
            r=requests.post(server.url+'/api/'+path,json=body,headers=headers);assert r.status_code==status,r.text;return r.json()
        assert get('settings')['wizard']['step'] == 1
        post('preferences',{'language':'ru','timezone':'Europe/Moscow','theme':'dark','level':'expert'})
        assert get('preferences')['saved']['language']=='ru'
        assert get('status')['collector']['has_session'] is False
        post('first-run',{'step':3,'goal':'watch'})
        assert get('settings')['wizard']['goal']=='watch'
        post('first-run',{'step':5},409)
        from tgwitness.guided_connection import revision
        server.app.state.store.set_setting('connection_check',{'telegram_connected':True,'checked_at':time.time(),'revision':'stale'})
        post('first-run',{'step':5},409)
        server.app.state.store.set_setting('connection_check',{'telegram_connected':True,'checked_at':time.time(),'revision':revision(server.app.state.collector)})
        server.app.state.store.set_setting('connection_strategy',{'mode':'auto','allow_direct':False})
        post('first-run',{'step':5})
        post('first-run',{'step':5,'route':'warp'},409)
        post('first-run',{'step':5,'unchecked':True})
        post('first-run',{'step':6,'unchecked':True},409)
        plan=post('settings/goal/preview',{'goal':'copy'})
        post('settings/goal',{'goal':'copy','revision':'stale'},409)
        result=post('settings/goal',{'goal':'copy','revision':plan['revision']})
        assert result['values']['files']=='photos' and result['values']['outside'] is False
        assert capture_settings(server.app.state.store)['types']['video']['enabled'] is False
        post('settings/edit',{'key':'notifications','value':True,'revision':result['revision']},409)
        result=post('settings/edit',{'key':'notifications','value':True,'allow_outside':True,'revision':result['revision']})
        assert result['needs_notification_destination']
        assert any(f['modified'] for f in result['fields'] if f['key']=='notifications')
        post('settings/edit',{'key':'outside','value':False,'revision':result['revision']},409)
        result=post('settings/edit',{'key':'outside','value':False,'disable_dependents':True,'revision':result['revision']})
        assert not result['values']['notifications']
        post('first-run/skip',{})
        assert get('settings')['wizard']['skipped']
        from tgwitness.access import GrantSettings
        issued,_=server.app.state.access.issue(GrantSettings(label='Viewer',permissions=['view'],workspaces={'default':None}))
        session=requests.post(server.url+'/api/access/login',json={'token':issued}).json()['session']
        viewer={'Authorization':'Bearer '+session}
        assert requests.post(server.url+'/api/preferences',headers=viewer,json={'language':'en','timezone':'UTC','level':'simple','theme':'system'}).ok
        assert get('preferences')['saved']['language']=='ru'
        for path in ('settings','connection'):
            assert requests.get(server.url+'/api/'+path,headers=viewer).status_code==403
        assert requests.post(server.url+'/api/settings/goal',headers=viewer,json={'goal':'evidence','revision':result['revision']}).status_code==403
        store=server.app.state.store
        store.set_setting('replica',{'enabled':True,'endpoint':'https://storage.invalid','bucket':'synthetic'})
        store.set_setting('route_policy',{'exposure':'hide','outside_enabled':True})
        current=get('settings')
        post('settings/edit',{'key':'outside','value':False,'revision':current['revision']},409)
        current=post('settings/edit',{'key':'outside','value':False,'disable_dependents':True,'revision':current['revision']})
        assert not current['values']['replica'] and not current['values']['outside']


def test_migration_and_chat_selection(tmp_path):
    from tools.browser_fixtures import ScopeClient, saved_session, CHAT
    with RunningApp(tmp_path, client_factory=ScopeClient) as server:
        s, v=server.app.state.store,server.app.state.vault
        v.save('credentials',{'api_id':123,'api_hash':'a'*32,'session':saved_session()})
        v.save('network',{'kind':'direct'})
        s.set_setting('route_policy',{'exposure':'tunnel','outside_enabled':False})
        s.set_setting('resume',True)
        headers={'Authorization':'Bearer '+v.token}
        before=capture_settings(s)
        result=requests.get(server.url+'/api/settings',headers=headers).json()
        assert result['wizard']['completed'] and result['values']['continuous']
        assert capture_settings(s)==before, 'Reading Settings must preserve legacy configuration'
        def select(body):
            return requests.post(server.url+'/api/settings/scope',headers=headers,json=body)
        r=select({'scope':'selected','chat_ids':[CHAT]});assert r.ok,r.text
        assert [row['chat_id'] for row in s.targets() if row['enabled']]==[CHAT]
        r=select({'scope':'folder','folder_id':2});assert r.ok,r.text
        assert s.get_setting('scope')['folder_id']==2
        assert select({'scope':'folder','folder_id':999}).status_code==400
        assert select({'scope':'selected','chat_ids':[999]}).status_code==400


def test_browser(tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    errors=[]
    from tools.browser_fixtures import QRClient
    from tgwitness import guided_connection
    from tgwitness.portable_routes import PortableRoutes
    async def failed_probe(*args, **kwargs):
        raise ValueError('No public proxy answers. Try WARP or your own proxy.')
    monkeypatch.setattr(guided_connection, 'probe', failed_probe)
    monkeypatch.setattr(PortableRoutes, 'prepare', failed_probe)
    with RunningApp(tmp_path, client_factory=QRClient) as server, sync_playwright() as p:
        exports=[]
        async def fake_export(options):
            exports.append(options)
            return {'id':'synthetic'}
        monkeypatch.setattr(server.app.state.account_export,'start',fake_export)
        browser=launch_browser(p)
        page=browser.new_page(viewport={'width':1280,'height':900},locale='ru-RU',reduced_motion='reduce')
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(server.url)
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        expect(page.locator('#view-first-run')).to_be_visible(timeout=20000)
        expect(page.locator('#view-first-run h1')).to_contain_text('Язык')
        page.locator('#first-run-next').click()
        page.locator('[data-answer="expert"]').click()
        expect(page.locator('[data-answer="expert"]')).to_be_enabled()
        page.reload()
        expect(page.locator('[data-answer="expert"]')).to_have_attribute('aria-pressed','true',timeout=20000)
        page.locator('#first-run-next').click()
        page.locator('[data-answer="copy"]').click()
        expect(page.locator('[data-answer="copy"]')).to_be_enabled()
        page.locator('#first-run-next').click()
        expect(page.locator('#first-run-next')).to_be_disabled()
        expect(page.locator('#hub-connection-result')).to_have_class('connection-result failed',timeout=15000)
        check_layout(page)
        page.set_viewport_size({'width':390,'height':844})
        output=ROOT/'test-results'/'settings-onboarding'
        output.mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(output/'first-run-mobile.png'),full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), page.evaluate("""[...document.querySelectorAll('body *')].filter(e=>e.checkVisibility()&&e.getBoundingClientRect().right>innerWidth+1).map(e=>[e.tagName,e.id,e.className,e.getBoundingClientRect().right]).slice(0,25)""")
        check_layout(page)
        page.screenshot(path=str(tmp_path/'first-run-mobile.png'),full_page=True)
        page.get_by_text('Продолжить без проверки',exact=True).click()
        page.locator('#first-run-next').click()
        expect(page.locator('#start-qr')).to_be_visible()
        expect(page.locator('#first-run-next')).to_be_disabled()
        page.locator('#start-qr').click()
        expect(page.locator('#qr-image')).to_be_visible()
        c=server.app.state.collector.login_client
        c.loop.call_soon_threadsafe(c.scan.set)
        expect(page.locator('#first-run-next')).to_be_enabled(timeout=10000)
        page.locator('#first-run-next').click()
        expect(page.locator('.wizard-chats')).to_have_count(0)
        page.locator('#first-run-next').click()
        expect(page.locator('.setup-summary')).to_be_visible()
        page.screenshot(path=str(output/'summary-mobile-ru.png'),full_page=True)
        page.locator('#first-run-next').click()
        expect(page.locator('#view-evidence')).to_be_visible(timeout=15000)
        assert len(exports)==1 and exports[0].media_types==['photo']
        headers={'Authorization':'Bearer '+page.evaluate("sessionStorage.getItem('tgwitness-token')")}
        assert requests.post(server.url+'/api/first-run/finish',headers=headers,json={'step':7,'goal':'copy','unchecked':True}).ok
        assert len(exports)==1, 'A repeated finish must not start another export'
        page.goto(server.url+'/settings')
        expect(page.locator('#view-settings')).to_be_visible()
        page.locator('.hub-search').fill('drand')
        expect(page.locator('.hub-results button')).not_to_have_count(0)
        page.locator('.hub-search').fill('')
        page.set_viewport_size({'width':1280,'height':900})
        page.screenshot(path=str(output/'settings-desktop-ru.png'),full_page=True)
        token=page.evaluate("sessionStorage.getItem('tgwitness-token')")
        page.locator('.sidebar select.language-select').select_option('en')
        expect(page.locator('#view-settings h1')).to_have_text('Settings',timeout=15000)
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')")==token
        assert server.app.state.store.get_setting('ui_preferences:admin')['language']=='en'
        page.locator('select.level-pick').select_option('simple')
        expect(page.locator('html')).to_have_attribute('data-ui-level','simple')
        assert sorted(page.locator('.sidebar .nav:visible').evaluate_all('(els)=>els.map(e=>e.dataset.view)'))==['chats','evidence','observations','settings','start']
        page.locator('.hub-search').fill('Proof of live recording')
        page.locator('.hub-results button').first.click()
        expect(page.locator('[data-setting="drand"]')).to_be_visible()
        page.locator('select.level-pick').select_option('standard')
        expect(page.locator('.setting-help')).to_have_count(2)
        page.locator('select.level-pick').select_option('simple')
        page.goto(server.url+'/settings')
        expect(page.locator('#view-settings h1')).to_have_text('Settings',timeout=15000)
        expect(page.locator('#view-settings')).to_be_visible()
        expect(page.locator('select.level-pick')).to_have_value('simple')
        page.screenshot(path=str(output/'settings-simple-desktop.png'),full_page=True)
        page.locator('[data-section="notifications"]').click()
        page.get_by_role('button',name='Notification destinations',exact=True).click()
        expect(page.locator('#view-settings #alerts-form')).to_be_visible()
        expect(page.locator('#alerts-enabled')).not_to_be_checked()
        page.get_by_role('button',name='Off-site copy',exact=True).click()
        expect(page.locator('#view-settings #replica-form')).to_be_visible()
        expect(page.locator('#replica-enabled')).not_to_be_checked()
        with page.expect_response(lambda response: response.url == server.url+'/api/preferences'
                and response.request.method == 'POST'
                and response.request.post_data_json.get('language') == 'ru') as language_saved:
            page.goto(server.url+'/settings?lang=ru')
        assert language_saved.value.ok, language_saved.value.status
        assert language_saved.value.json()['saved']['language'] == 'ru'
        expect(page.locator('#view-settings h1')).to_have_text('Настройки')
        expect(page.locator('html')).to_have_attribute('data-ui-level','simple')
        assert server.app.state.store.get_setting('ui_preferences:admin')['language']=='ru'
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')")==token
        page.goto(server.url+'/settings')
        expect(page.locator('#view-settings h1')).to_have_text('Настройки')
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')")==token
        browser.close()
    assert not errors,errors


@pytest.mark.parametrize('outcome', ['late', 'network'])
def test_settings_bootstrap_failure_preserves_session(tmp_path, outcome):
    from playwright.sync_api import sync_playwright, expect
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        headers={'Authorization':'Bearer '+server.app.state.vault.token}
        response=requests.post(server.url+'/api/profiles',headers=headers,json={'label':'Second'})
        assert response.ok,response.text
        child=response.json()['id']
        for app in (server.app, server.app.state.profiles.entries[child]['app']):
            app.state.store.set_setting('first_run',{'skipped':True})
            app.state.store.set_setting('ui_preferences:admin',{'language':'en','timezone':'UTC','theme':'system','level':'expert'})
        browser=launch_browser(p)
        page=browser.new_page(locale='en-US')
        page.add_init_script("""(()=>{
          const original=window.fetch.bind(window);let held=false;
          window.fetch=async(...args)=>{const response=await original(...args);
            if(!held&&String(args[0])==='/api/settings'){held=true;await new Promise((resolve,reject)=>{window.releaseOldSettings=resolve;window.failOldSettings=()=>reject(new TypeError('Synthetic interrupted settings fetch'));});}
            return response;
          };
        })();""")
        page.goto(server.url)
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        page.wait_for_function('()=>typeof window.releaseOldSettings==="function"')
        token=page.evaluate('state.token')
        if outcome == 'late':
            page.locator('#profile-select').select_option(child)
            page.wait_for_function('id=>state.profile===id&&!document.querySelector("#workspace").inert',arg=child)
            page.evaluate('window.releaseOldSettings()')
        else:
            page.evaluate('window.failOldSettings()')
            expect(page.locator('#toast')).to_contain_text('Synthetic interrupted settings fetch')
        expect(page.locator('#unlock-form button')).to_be_enabled()
        assert page.evaluate('state.token')==token
        assert page.evaluate('sessionStorage.getItem("tgwitness-token")')==token
        expect(page.locator('#workspace')).to_be_visible()
        assert page.evaluate('async()=>{await json("status");return true;}')
        browser.close()


def test_first_run_import_and_settings_account_actions(tmp_path):
    from playwright.sync_api import sync_playwright, expect
    from tools.browser_fixtures import saved_session, sqlite_fixture
    from tools.check_browser import answer_panel_dialog

    def upload(name, payload):
        return {'name': name, 'mimeType': 'application/octet-stream', 'buffer': payload}

    metadata = json.dumps({'session_file': '', 'app_id': 123, 'app_hash': 'a' * 32,
                           'device': 'Synthetic import laptop', 'sdk': 'Windows 11'}).encode()
    pair = [upload('research.json', metadata), upload('research.session', sqlite_fixture())]
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        store = server.app.state.store
        store.set_setting('first_run', {'step': 5, 'goal': 'copy', 'unchecked': True})
        store.set_setting('ui_preferences:admin', {'language': 'en', 'timezone': 'UTC', 'theme': 'system', 'level': 'expert'})
        key = server.app.state.vault.public_key
        browser = launch_browser(p)
        page = browser.new_page(viewport={'width': 1280, 'height': 1000}, locale='en-US', reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(server.url)
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        expect(page.locator('#view-first-run #credentials-form')).to_be_visible()
        page.locator('.other-sign-in > summary').click()
        page.locator('[data-auth-method="files"]').click()
        page.locator('#session-file').set_input_files([pair[0]])
        expect(page.locator('#import-result')).to_have_attribute('data-state', 'missing_session')
        expect(page.locator('#auth-continue')).to_be_disabled()
        expect(page.locator('#first-run-next')).to_be_disabled()
        assert not server.app.state.collector.status()['has_session']
        page.locator('#session-file').set_input_files(pair)
        expect(page.locator('#import-result')).to_have_attribute('data-state', 'ready')
        expect(page.locator('#auth-continue')).to_be_enabled()
        page.locator('#auth-continue').click()
        expect(page.locator('#view-first-run #authorized-account')).to_contain_text('ID 44')
        expect(page.locator('#first-run-next')).to_be_enabled()
        assert server.app.state.vault.public_key == key

        page.evaluate('()=>navigate("settings")')
        page.locator('[data-section="telegram"]').click()
        expect(page.locator('#view-settings #authorized-account')).to_contain_text('ID 44')
        page.locator('#change-account').click()
        page.locator('.other-sign-in').evaluate('el=>el.open=true')
        page.locator('[data-auth-method="files"]').click()
        page.locator('#session-file').set_input_files(pair)
        expect(page.locator('#import-result')).to_have_attribute('data-state', 'ready')
        page.locator('#auth-continue').click()
        expect(page.locator('#view-settings #authorized-account')).to_contain_text('ID 44')
        assert page.evaluate('state.profile') == 'default'
        assert len(server.app.state.profiles.entries) == 1
        assert server.app.state.vault.public_key == key

        page.locator('.other-sign-in').evaluate('el=>el.open=false')
        page.locator('#account-add-another').click()
        expect(page.locator('[data-auth-method="files"]')).to_be_visible()
        expect(page.locator('#view-settings #session-file')).to_be_visible()
        page.locator('#api-details').evaluate('el=>el.open=true')
        page.locator('#api-id').fill('')
        page.locator('#api-hash').fill('')
        other = json.dumps({'app_id': 456, 'app_hash': 'b' * 32, 'session': saved_session(b'n')}).encode()
        page.locator('#session-file').set_input_files(upload('second-account.json', other))
        expect(page.locator('#import-result')).to_have_attribute('data-state', 'ready')
        page.locator('#auth-continue').click()
        expect(page.locator('dialog.panel-dialog input')).to_have_value('second-account')
        answer_panel_dialog(page, text='Second imported account')
        expect(page.locator('#view-connection #authorized-account')).to_contain_text('ID 456')
        assert page.evaluate('state.profile') != 'default'
        assert len(server.app.state.profiles.entries) == 2
        assert store.get_setting('account')['id'] == 44
        assert server.app.state.vault.public_key == key
        assert not errors, errors
        browser.close()


@pytest.mark.parametrize('workspace', ['default', 'child'])
def test_unfinished_setup_keeps_explicit_workspace_link(tmp_path, workspace):
    from playwright.sync_api import sync_playwright, expect
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        profile = 'default'
        if workspace == 'child':
            response = requests.post(server.url + '/api/profiles',
                headers={'Authorization': 'Bearer ' + server.app.state.vault.token}, json={'label': 'Fresh child'})
            assert response.ok, response.text
            profile = response.json()['id']
        app = server.app if profile == 'default' else server.app.state.profiles.entries[profile]['app']
        app.state.store.set_setting('ui_preferences:admin',
            {'language': 'en', 'timezone': 'UTC', 'theme': 'system', 'level': 'expert'})
        browser = launch_browser(p)
        page = browser.new_page(locale='en-US', reduced_motion='reduce')
        page.add_init_script('sessionStorage.setItem("tgwitness-profile", "default")')
        page.goto(server.url + '/exports?ws=' + profile)
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        expect(page.locator('#view-evidence')).to_be_visible()
        expect(page.locator('#unlock-form button')).to_be_enabled()
        expect(page).to_have_url(server.url + '/exports?ws=' + profile)
        expect(page.locator('#view-first-run')).to_be_hidden()
        assert page.evaluate('state.profile') == profile
        assert app.state.store.get_setting('first_run', None) is None
        browser.close()


@pytest.mark.parametrize('held_path', ['/api/preferences', '/api/settings'])
def test_unfinished_setup_bootstrap_respects_new_navigation(tmp_path, held_path):
    from playwright.sync_api import sync_playwright, expect
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        server.app.state.store.set_setting('ui_preferences:admin',
            {'language': 'en', 'timezone': 'UTC', 'theme': 'system', 'level': 'expert'})
        browser = launch_browser(p)
        page = browser.new_page(locale='en-US', reduced_motion='reduce')
        page.add_init_script("""(() => {
          const original=window.fetch.bind(window);let held=false;
          window.fetch=async(...args)=>{const response=await original(...args);
            if(!held&&String(args[0])===HELD_PATH){held=true;await new Promise(resolve=>{window.releaseSetupBootstrap=resolve;});}
            return response;
          };
        })();""".replace('HELD_PATH', json.dumps(held_path)))
        page.goto(server.url)
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        page.wait_for_function('()=>typeof window.releaseSetupBootstrap==="function"')
        page.locator('.sidebar [data-view="evidence"]').click()
        expect(page.locator('#view-evidence')).to_be_visible()
        page.evaluate('window.releaseSetupBootstrap()')
        expect(page.locator('#unlock-form button')).to_be_enabled()
        expect(page).to_have_url(server.url + '/exports?ws=default')
        expect(page.locator('#view-evidence')).to_be_visible()
        expect(page.locator('#view-first-run')).to_be_hidden()
        assert server.app.state.store.get_setting('first_run', None) is None
        browser.close()


@pytest.mark.parametrize('change', ['goal', 'outside'])
def test_settings_consent_belongs_to_its_workspace(tmp_path, change):
    from playwright.sync_api import sync_playwright, expect
    from tools.check_browser import answer_panel_dialog

    with RunningApp(tmp_path) as server, sync_playwright() as p:
        response = requests.post(server.url + '/api/profiles',
            headers={'Authorization': 'Bearer ' + server.app.state.vault.token}, json={'label': 'Second'})
        assert response.ok, response.text
        child = response.json()['id']
        apps = (server.app, server.app.state.profiles.entries[child]['app'])
        for app in apps:
            app.state.store.set_setting('first_run', {'skipped': True})
            app.state.store.set_setting('ui_preferences:admin',
                {'language': 'en', 'timezone': 'UTC', 'theme': 'system', 'level': 'expert'})
            app.state.store.set_setting('route_policy', {'exposure': 'tunnel', 'outside_enabled': False})
        before = [settings_hub.state(app) for app in apps]
        assert before[0]['revision'] == before[1]['revision']
        assert not before[0]['values']['outside'] and not before[0]['values']['notifications']
        assert settings_hub.preview(apps[0], settings_hub.GoalChange(goal='copy'))['diff']

        browser = launch_browser(p)
        page = browser.new_page(locale='en-US', reduced_motion='reduce')
        mutations, errors = [], []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: mutations.append(request.url)
            if request.method == 'POST' and request.url.endswith(('/api/settings/goal', '/api/settings/edit')) else None)
        page.goto(server.url + '/settings?ws=default')
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        expect(page.locator('#view-settings h1')).to_have_text('Settings')
        expect(page.locator('#unlock-form button')).to_be_enabled()
        page.locator('[data-section="goal"]' if change == 'goal' else '[data-section="notifications"]').click()
        control = page.locator('[data-answer="copy"]' if change == 'goal' else '[data-setting="notifications"] input')
        event = 'onclick' if change == 'goal' else 'onchange'
        control.evaluate("""(el, event) => {
          const original = el[event];
          el[event] = (...args) => (window.pendingSettingsChange = original.apply(el, args));
        }""", event)
        control.click()
        dialog = page.locator('dialog.panel-dialog[open]')
        expect(dialog).to_contain_text('Change goal?' if change == 'goal'
            else 'This feature needs external requests. Allow them?')
        page.evaluate('id => switchProfile(id)', child)
        assert page.evaluate('state.profile') == child
        expect(page).to_have_url(server.url + '/settings?ws=' + child)
        answer_panel_dialog(page)
        page.evaluate('async () => { await window.pendingSettingsChange; }')
        assert not mutations, f'An old confirmation sent a settings mutation: {mutations}'
        for app, original in zip(apps, before, strict=True):
            current = settings_hub.state(app)
            assert current['revision'] == original['revision']
            assert current['goal'] == original['goal']
            assert current['values'] == original['values']
        assert not errors, errors
        browser.close()


@pytest.mark.parametrize('destination', ['settings', 'workspace'])
def test_live_setup_check_stops_after_navigation(tmp_path, destination):
    from playwright.sync_api import sync_playwright, expect
    from tools.browser_fixtures import ScopeClient, saved_session, CHAT

    with RunningApp(tmp_path, client_factory=ScopeClient) as server, sync_playwright() as p:
        store, vault = server.app.state.store, server.app.state.vault
        vault.save('credentials', {'api_id': 123, 'api_hash': 'a' * 32, 'session': saved_session()})
        vault.save('network', {'kind': 'direct'})
        store.set_setting('route_policy', {'exposure': 'tunnel', 'outside_enabled': False})
        store.set_setting('goal_preset', {'goal': 'watch'})
        store.set_setting('first_run', {'step': 7, 'goal': 'watch', 'unchecked': True,
            'scope': 'selected', 'chat_ids': [CHAT], 'account_kind': 'dedicated', 'route': 'direct'})
        prefs = {'language': 'en', 'timezone': 'UTC', 'theme': 'system', 'level': 'expert'}
        store.set_setting('ui_preferences:admin', prefs)
        response = requests.post(server.url + '/api/profiles',
            headers={'Authorization': 'Bearer ' + vault.token}, json={'label': 'Second'})
        assert response.ok, response.text
        child = response.json()['id']
        child_store = server.app.state.profiles.entries[child]['app'].state.store
        child_store.set_setting('first_run', {'skipped': True})
        child_store.set_setting('ui_preferences:admin', prefs)
        browser = launch_browser(p)
        page = browser.new_page(locale='en-US', reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.add_init_script("""(() => {
          const original=window.fetch.bind(window); let held=false;
          window.fetch=async(...args)=>{
            const response=await original(...args);
            if(!held&&String(args[0])==='/api/status'&&document.querySelector('.first-run-live')){
              held=true; await new Promise(resolve=>{window.releaseLiveStatus=resolve;});
              window.liveStatusReleased=true;
            }
            return response;
          };
        })();""")
        page.goto(server.url + '/first-run/7?ws=default')
        page.locator('#panel-token').fill(vault.token)
        page.locator('#unlock-form button').click()
        expect(page.locator('#first-run-next')).to_be_enabled()
        page.locator('#first-run-next').click()
        expect(page.locator('.first-run-live')).to_be_visible()
        page.wait_for_function('()=>typeof window.releaseLiveStatus==="function"')
        if destination == 'workspace':
            page.evaluate('id=>switchProfile(id)', child)
        page.evaluate('()=>navigate("settings")')
        expect(page.locator('#view-settings')).to_be_visible()
        page.evaluate('window.releaseLiveStatus()')
        page.wait_for_function('()=>window.liveStatusReleased')
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        expect(page.locator('#view-first-run')).to_be_hidden()
        assert page.evaluate('state.profile') == (child if destination == 'workspace' else 'default')
        assert child_store.get_setting('first_run') == {'skipped': True}
        assert not errors, errors
        browser.close()


def test_late_bootstrap_does_not_restore_an_older_wizard_step(tmp_path):
    from playwright.sync_api import sync_playwright, expect
    with RunningApp(tmp_path) as server, sync_playwright() as p:
        store = server.app.state.store
        store.set_setting('first_run', {'step':2,'goal':'copy'})
        browser = launch_browser(p)
        page = browser.new_page(locale='en-US', reduced_motion='reduce')
        page.add_init_script("""(() => {
          const original=window.fetch.bind(window);let reads=0;
          window.fetch=async(...args)=>{
            const response=await original(...args);
            if(String(args[0])==='/api/settings'&&++reads===2){
              await new Promise(resolve=>{window.releaseOldSettings=resolve;});
              const parse=response.json.bind(response);
              response.json=async()=>{const data=await parse();window.oldSettingsParsed=true;return data;};
            }
            return response;
          };
        })();""")
        page.goto(server.url+'/first-run/2?ws=default')
        page.locator('#panel-token').fill(server.app.state.vault.token)
        page.locator('#unlock-form button').click()
        page.wait_for_function('()=>typeof window.releaseOldSettings==="function"')
        page.locator('#first-run-next').click()
        expect(page.locator('[data-answer="copy"]')).to_be_visible()
        page.locator('[data-answer="copy"]').click()
        expect(page.locator('[data-answer="copy"]')).to_be_enabled()
        page.evaluate('window.releaseOldSettings()')
        page.wait_for_function('()=>window.oldSettingsParsed===true')
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        expect(page.locator('[data-answer="copy"]')).to_be_visible()
        assert store.get_setting('first_run')['step']==3
        browser.close()


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-q']))
