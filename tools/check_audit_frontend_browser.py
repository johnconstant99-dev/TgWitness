from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import (RunningApp, hold_api_response, launch_browser,
                           release_api_response, unlock)
from browser_fixtures import CHAT, saved_session
from tgwitness.group_settings import save_values


def accept(page):
    dialog = page.locator('dialog.panel-dialog[open]')
    expect(dialog).to_be_visible()
    dialog.locator('button[type=submit]').click()
    expect(dialog).to_have_count(0)


def switch(page, profile, view):
    page.evaluate("""async ({profile,view})=>{
      if(state.profile!==profile)await switchProfile(profile);
      await navigate(view);
    }""", {"profile": profile, "view": view})


def confirmations(page, server, child):
    stores = [server.app.state.store, server.app.state.profiles.entries[child]['app'].state.store]
    for store in stores:
        store.set_target(CHAT, 'Synthetic shared source', 'supergroup', True)
    switch(page, child, 'sources')
    switch(page, 'default', 'sources')
    page.locator('#sources-tab-chats').click()
    mutations = []
    def record(request):
        if request.method == 'POST' and request.url.endswith(('/targets/batch', '/scope')):
            mutations.append(request.url)
    page.on('request', record)
    page.locator('.source-row-menu summary').first.click()
    page.locator('[data-source-action=pause]').first.click()
    expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
    page.go_back()
    page.wait_for_function("id=>state.profile===id&&!$('workspace').inert", arg=child)
    accept(page)
    switch(page, 'default', 'sources')
    page.locator('#sources-tab-chats').click()
    page.locator('[data-source-action=select]').first.check()
    page.locator('#target-bulk-action').select_option('pause')
    page.locator('#target-bulk-apply').click()
    expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
    page.evaluate('id=>switchProfile(id)', child)
    accept(page)
    page.wait_for_timeout(150)
    assert not mutations, mutations
    assert all(store.targets()[0]['enabled'] for store in stores)
    page.remove_listener('request', record)

    calls = []
    child_app = server.app.state.profiles.entries[child]['app']
    collector = child_app.state.collector
    credentials = child_app.state.vault.read('credentials')
    previous = (collector.running, collector.phase, collector.authorization_required)
    child_app.state.vault.save('credentials', {'api_id': 123, 'api_hash': 'b' * 32, 'session': saved_session()})
    page.route('**/api/collector/*', lambda route: (
        calls.append(route.request.url.rsplit('/', 1)[-1]), route.fulfill(json={'ok': True})))
    def running(value=True):
        collector.running = value
        collector.phase = 'observing' if value else 'offline'
        collector.authorization_required = False
        page.evaluate('()=>refreshStatus()')
    try:
        running()
        page.locator('#collector-toggle').click()
        expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
        running(False)
        with page.expect_request('**/api/collector/stop'):
            accept(page)
        expect(page.locator('#collector-toggle')).to_be_enabled()
        expect(page.locator('#collector-toggle')).not_to_have_attribute('aria-busy', 'true')
        assert calls == ['stop'], calls
        running()
        page.locator('#collector-toggle').click()
        expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
        page.evaluate("()=>switchProfile('default')")
        accept(page)
        page.wait_for_timeout(150)
        assert calls == ['stop'], calls
    finally:
        page.unroute('**/api/collector/*')
        collector.running, collector.phase, collector.authorization_required = previous
        child_app.state.vault.save('credentials', credentials)


def connection_and_reports(page):
    switch(page, 'default', 'connection')
    page.locator('#connect-toggle').click()
    page.locator('[data-connect-mode=proxy]').click()
    page.locator('#connect-host').fill('old-proxy.example.invalid')
    page.locator('#connect-port').fill('1080')
    hold_api_response(page, '/api/connection/preview')
    page.locator('#connect-preview').click()
    expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
    page.locator('#connect-host').fill('new-proxy.example.invalid')
    release_api_response(page)
    expect(page.locator('#connect-preview')).to_be_enabled()
    expect(page.locator('#connect-prepare')).to_be_hidden()
    page.locator('#connect-preview').click()
    expect(page.locator('#connect-prepare')).to_be_visible()
    submitted = []
    page.route('**/api/connection/prepare', lambda route: (
        submitted.append(route.request.post_data_json), route.fulfill(json={'state': 'preparing'})))
    page.locator('#connect-prepare').click()
    expect(page.locator('#connect-prepare')).to_be_hidden()
    assert submitted[0]['proxy']['host'] == 'new-proxy.example.invalid', submitted
    page.unroute('**/api/connection/prepare')

    page.evaluate("()=>navigate('evidence')")
    page.locator('#exports-tab-settings').click()
    expect(page.locator('#report-fields')).to_be_enabled()
    baseline = page.locator('#report-case-title').input_value()
    marker = 'SYNTHETIC DISCARDED TITLE 12345'
    page.locator('#report-case-title').fill(marker)
    page.wait_for_function("s=>$('report-preview-frame').getAttribute('srcdoc')?.includes(s)", arg=marker)
    page.locator('#report-form .form-draft-bar .quiet').click()
    expect(page.locator('#report-case-title')).to_have_value(baseline)
    expect(page.locator('#report-form')).to_have_attribute('data-dirty', 'false')
    page.wait_for_function("s=>{const html=$('report-preview-frame').getAttribute('srcdoc');return html&&!html.includes(s);}", arg=marker)
    assert page.locator('.studio-stage').evaluate("el=>parseFloat(getComputedStyle(el).borderTopWidth)") > 0
    page.evaluate("()=>renderExportState({phase:'done',ready:true,captured:3,title:'Synthetic completed chat'})")
    assert not page.evaluate("$('chat-export-download').hidden")
    assert '3' in page.evaluate("$('chat-export-progress').textContent")
    path = '/api/chat-export/synthetic-old'
    page.route('**' + path, lambda route: route.fulfill(json={'phase': 'done', 'ready': True, 'captured': 999}))
    hold_api_response(page, path)
    page.evaluate("()=>{state.exportId='synthetic-old';window.auditPoll=pollExport(state.exportId);}")
    expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
    page.evaluate("()=>{state.exportId='synthetic-new';renderExportState({phase:'running',captured:7});}")
    release_api_response(page)
    page.evaluate('window.auditPoll')
    assert page.evaluate('state.exportId') == 'synthetic-new'
    assert '999' not in page.evaluate("$('chat-export-progress').textContent")
    page.unroute('**' + path)
    page.evaluate('()=>{state.exportId=null;renderExportState(null);}')


def settings_and_setup(page, server, child):
    switch(page, 'default', 'settings')
    page.locator('[data-section=protection]').click()
    checkbox = page.locator('[data-setting=timestamps] input')
    checkbox.check()
    expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
    page.locator('dialog.panel-dialog[open] button[type=button]').click()
    expect(checkbox).not_to_be_checked()
    values = page.evaluate("()=>json('settings').then(r=>r.values)")
    assert not values['timestamps'] and not values['outside']
    checkbox.check()
    accept(page)
    expect(checkbox).to_be_enabled()
    expect(checkbox).to_be_checked()
    assert page.evaluate("()=>json('settings').then(r=>r.values.timestamps)")
    page.route('**/api/settings/edit', lambda route: route.fulfill(status=503, json={'detail': 'Synthetic failed save'}))
    checkbox.uncheck()
    expect(checkbox).to_be_enabled()
    expect(checkbox).to_be_checked()
    assert page.evaluate("()=>json('settings').then(r=>r.values.timestamps)")
    page.unroute('**/api/settings/edit')

    switch(page, 'default', 'witness')
    page.evaluate("()=>selectExtra('setup')")
    page.locator('input[name=setup-goal][value=evidence]').check()
    page.locator('input[name=setup-size][value=large]').check()
    page.locator('input[name=setup-files][value=all]').check()
    switch(page, child, 'witness')
    page.evaluate("()=>selectExtra('setup')")
    saved = page.evaluate("()=>json('setup')")
    assert page.locator('input[name=setup-goal]:checked').count() == 0
    for key in ('size', 'files', 'place'):
        expect(page.locator(f'input[name=setup-{key}]:checked')).to_have_value(saved['current'][key])
    page.locator('input[name=setup-goal][value=personal]').check()
    page.locator('#setup-form button[type=submit]').click()
    expect(page.locator('#setup-status')).to_contain_text('A personal record')
    assert page.evaluate("()=>json('setup').then(r=>r.saved.goal)") == 'personal'

    child_app = server.app.state.profiles.entries[child]['app']
    child_store = child_app.state.store
    child_store.set_setting('first_run', {'step': 5, 'completed': False, 'skipped': False,
        'goal': 'watch', 'unchecked': True, 'account_kind': 'dedicated'})
    credentials = child_app.state.vault.read('credentials')
    child_app.state.vault.save('credentials', {'api_id': 123, 'api_hash': 'b' * 32, 'session': saved_session()})
    child_app.state.collector.authorization_required = True
    child_app.state.collector.phase = 'authorization_required'
    page.evaluate("""async()=>{
      await refreshStatus();
      await navigate('first-run');await settingsHub.load(5);
    }""")
    wizard = page.locator('#view-first-run')
    expect(wizard.get_by_text('Telegram is connected.', exact=True)).to_have_count(0)
    expect(wizard.locator('#first-run-next')).to_be_disabled()
    expect(wizard.locator('.auth-card')).to_be_visible()
    child_app.state.collector.authorization_required = False
    child_app.state.collector.phase = 'offline'
    page.evaluate('async()=>{await refreshStatus();settingsHub.status();}')
    expect(wizard.get_by_text('Telegram is connected.', exact=True)).to_be_visible()
    expect(wizard.locator('#first-run-next')).to_be_enabled()
    child_app.state.collector.authorization_required = True
    child_app.state.collector.phase = 'authorization_required'
    page.evaluate('async()=>{await refreshStatus();settingsHub.status();}')
    expect(wizard.locator('.auth-card')).to_be_visible()
    expect(wizard.locator('#first-run-next')).to_be_disabled()
    child_app.state.vault.save('credentials', credentials)
    child_app.state.collector.authorization_required = False
    child_app.state.collector.phase = 'offline'
    child_store.set_setting('first_run', {'completed': False, 'skipped': True})


def delayed_downloads(page, child):
    switch(page, 'default', 'analysis')
    page.evaluate("async()=>{await json('analysis/provider',{enabled:true,model:'synthetic-test'},{root:true});await refreshStatus();await navigate('analysis');}")
    page.locator(f'#ask-chats input[value="{CHAT}"]').check()
    page.locator('#ask-question').fill('Find the synthetic archived observation.')
    hold_api_response(page, '/api/analysis/preview')
    page.locator('#ask-form button[type=submit]').click()
    expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
    expect(page.locator('#ask-context-export')).to_be_visible()
    expect(page.locator('#ask-context-export')).to_be_disabled()
    expect(page.locator('#ask-generate')).to_be_disabled()
    release_api_response(page)
    expect(page.locator('#ask-context-export')).to_be_enabled()
    expect(page.locator('#ask-sources')).to_contain_text('Synthetic archived observation.')
    selected = page.locator('#ask-sources input[type=checkbox]')
    for item in selected.all():
        item.uncheck()
    expect(page.locator('#ask-context-export')).to_be_disabled()
    expect(page.locator('#ask-generate')).to_be_disabled()
    selected.first.check()
    expect(page.locator('#ask-context-export')).to_be_enabled()
    page.evaluate("""()=>{
      window.auditFetch=window.fetch;window.auditDownloads=[];window.auditSaveBlob=window.saveBlob;
      window.saveBlob=(blob,name)=>auditDownloads.push(name);
      window.fetch=async(...args)=>{
        if(!String(args[0]).includes('/analysis/context-export'))return auditFetch(...args);
        const stream=new ReadableStream({start(controller){
          window.auditRelease=()=>{controller.enqueue(new TextEncoder().encode('synthetic export'));controller.close();};
        }});
        document.documentElement.dataset.auditDownload='headers';
        return new Response(stream,{headers:{'Content-Type':'application/zip'}});
      };
    }""")
    page.locator('#ask-context-export').click()
    expect(page.locator('html')).to_have_attribute('data-audit-download', 'headers')
    page.evaluate('id=>switchProfile(id)', child)
    page.evaluate('()=>auditRelease()')
    page.wait_for_timeout(150)
    assert page.evaluate('auditDownloads') == []
    page.evaluate('()=>{window.fetch=auditFetch;window.saveBlob=auditSaveBlob;}')
    page.evaluate("()=>{window.fetch=async(...args)=>String(args[0]).includes('/analysis/synthetic-download')?new Response('synthetic complete'):auditFetch(...args);}")
    with page.expect_download() as result:
        assert page.evaluate("()=>download('analysis/synthetic-download','synthetic-analysis.json',false,true)")
    assert result.value.suggested_filename == 'synthetic-analysis.json'
    page.evaluate('()=>{window.fetch=auditFetch;}')

    switch(page, 'default', 'analysis')
    report = {'id': 'synthetic-report', 'title': 'Synthetic reviewed report', 'created_at': '2026-01-01T00:00:00Z',
        'model_summary': [], 'chronology': [], 'entities': [],
        'coverage': {'workspace_events_visible': True, 'events': []}, 'template': 'synthetic',
        'generation': {'provider': 'offline-fixture', 'model': 'synthetic', 'at': '2026-01-01T00:00:00Z'},
        'analyst_revisions': []}
    page.route('**/api/analysis/reports?workspace_id=default', lambda route: route.fulfill(json={'reports': [report]}))
    page.route('**/api/analysis/reports/synthetic-report?workspace_id=default', lambda route: route.fulfill(json=report))
    page.locator('#ask-refresh-reports').click()
    page.locator('#ask-reports button').click()
    expect(page.locator('#report-download')).to_be_visible()
    page.evaluate("""()=>{
      window.auditDownloads=[];window.saveBlob=(blob,name)=>auditDownloads.push(name);
      delete document.documentElement.dataset.auditDownload;
      window.fetch=async(...args)=>{
        if(!String(args[0]).includes('/analysis/reports/synthetic-report/download'))return auditFetch(...args);
        const stream=new ReadableStream({start(controller){
          window.auditRelease=()=>{controller.enqueue(new TextEncoder().encode('{}'));controller.close();};
        }});
        document.documentElement.dataset.auditDownload='headers';
        return new Response(stream,{headers:{'Content-Type':'application/json'}});
      };
    }""")
    page.locator('#report-download').click()
    expect(page.locator('html')).to_have_attribute('data-audit-download', 'headers')
    page.evaluate('id=>switchProfile(id)', child)
    page.evaluate('()=>auditRelease()')
    page.wait_for_timeout(150)
    assert page.evaluate('auditDownloads') == []
    page.evaluate('()=>{window.fetch=auditFetch;window.saveBlob=auditSaveBlob;}')
    page.unroute('**/api/analysis/reports?workspace_id=default')
    page.unroute('**/api/analysis/reports/synthetic-report?workspace_id=default')


def outage_retry(page, server, child):
    logout = []
    page.on('request', lambda request: logout.append(request.url) if request.url.endswith('/api/access/logout') else None)
    for outcome in (503, 429, 'network'):
        switch(page, 'default', 'settings')
        token = page.evaluate('state.token')
        path = f'**/profiles/{child}/api/status'
        def outage(route):
            if outcome == 'network':
                route.abort('failed')
            else:
                route.fulfill(status=outcome, json={'detail': 'Synthetic temporary outage'})
        page.route(path, outage)
        page.evaluate('async id=>{try{await switchProfile(id);}catch{}}', child)
        expect(page.locator('#workspace')).to_be_hidden()
        expect(page.locator('#bootstrap-retry')).to_be_visible()
        assert page.evaluate("sessionStorage.getItem('tgwitness-token')") == token
        assert server.app.state.access.resolve(token, '127.0.0.1') is not None
        assert not logout, logout
        page.unroute(path, outage)
        page.locator('#bootstrap-retry').click()
        expect(page.locator('#workspace')).to_be_visible()
        page.wait_for_function('id=>state.profile===id&&state.status!==null', arg=child)
        assert page.evaluate('state.token') == token


def group_adoption(page, server, child):
    switch(page, 'default', 'accounts')
    group = page.evaluate("()=>json('profile-groups',{label:'Synthetic route group'},{root:true}).then(r=>r.groups.at(-1).id)")
    registry = server.app.state.profiles
    route_value = {'mode': 'direct', 'allow_direct': False}
    save_values(registry, group, {'route': route_value})
    page.evaluate('()=>loadProfiles()')
    select = page.locator(f'.account-card[data-profile="{child}"] .fleet-card-group')
    requests = []
    def record(request):
        if request.url.endswith('/settings/adopt'):
            requests.append(request.post_data_json)
    page.on('request', record)
    select.select_option(group)
    expect(select).to_be_enabled()
    expect(page.locator('dialog.panel-dialog[open]')).to_have_count(0)
    assert not requests, requests
    select.select_option('')
    expect(select).to_be_enabled()
    save_values(registry, group, {'route': route_value, 'parameter:snapshot_max': 777})
    select.select_option(group)
    expect(page.locator('dialog.panel-dialog[open]')).to_contain_text('1 setting of this account differs')
    expect(page.locator('dialog.panel-dialog[open]')).not_to_contain_text('Connection route')
    accept(page)
    expect(page.locator('#toast')).to_contain_text('Own route preserved')
    assert requests == [{'profiles': [child], 'keys': ['parameter:snapshot_max']}], requests
    child_store = registry.entries[child]['app'].state.store
    assert child_store.get_setting('parameters')['snapshot_max'] == 777
    assert child_store.get_setting('connection_strategy', {}).get('mode') != 'direct'
    page.remove_listener('request', record)


def presentation(page):
    switch(page, 'default', 'accounts')
    page.locator('#fleet-import-open').click()
    page.locator('#fleet-files').focus()
    assert page.locator('#fleet-drop').evaluate("el=>getComputedStyle(el).outlineStyle") != 'none'
    page.evaluate("async()=>{await navigate('connection');connectionSettings(true);$('proxy-pool').open=true;$('pool-sources').open=true;}")
    page.locator('#pool-files').focus()
    assert page.locator('#pool-drop').evaluate("el=>getComputedStyle(el).outlineStyle") != 'none'
    page.evaluate("()=>navigate('settings')")
    page.evaluate("document.documentElement.dir='rtl'")
    assert page.locator('.hub-arrow').first.evaluate("el=>getComputedStyle(el).transform") == 'matrix(-1, 0, 0, 1, 0, 0)'
    page.evaluate("document.documentElement.dir='ltr'")


def pending_action_owners(page, server, child):
    for app in (server.app, server.app.state.profiles.entries[child]['app']):
        app.state.vault.save('credentials', {'api_id': 123, 'api_hash': 'b' * 32, 'session': saved_session()})
        app.state.store.set_setting('account', {'id': 44, 'username': 'synthetic_fixture'})
    mutations = []
    paths = ('auth/logout', 'network/policy', 'alerts')

    def intercept(route):
        if route.request.method != 'POST':
            if route.request.url.endswith('/alerts'):
                response = route.fetch()
                result = response.json()
                result['destinations'] = ['Synthetic disabled destination']
                route.fulfill(response=response, json=result)
                return
            route.continue_()
            return
        mutations.append(route.request.url)
        if route.request.url.endswith('/network/policy'):
            route.fulfill(json={'exposure': 'tunnel', 'outside_enabled': False, 'outside_proxy': None,
                'outside_route': 'none', 'direct_fallback': False})
        elif route.request.url.endswith('/alerts'):
            route.fulfill(json={'settings': {'enabled': False, 'destinations': [], 'batch_seconds': 30, 'kinds': []},
                'has_destinations': False})
        else:
            route.fulfill(json={'ok': True, 'telegram_session_ended': True})

    for path in paths:
        page.route('**/api/' + path, intercept)

    def open_action(action):
        if action == 'policy':
            page.locator('#policy-form').evaluate("form=>form.requestSubmit(form.querySelector('button[type=submit]'))")
        elif action == 'logout':
            page.locator('#sign-out').click()
        else:
            page.evaluate('()=>loadAlerts()')
            page.locator('#alerts-clear').evaluate('button=>button.click()')
        expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()

    for action in ('policy', 'logout', 'alerts'):
        view = 'witness' if action == 'alerts' else 'connection'
        switch(page, child, view)
        switch(page, 'default', view)
        mutations.clear()
        open_action(action)
        page.go_back()
        page.wait_for_function("id=>state.profile===id&&!$('workspace').inert", arg=child)
        accept(page)
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        assert not mutations, 'A stale confirmation issued a workspace mutation'

    switch(page, 'default', 'connection')
    open_action('policy')
    with page.expect_response(lambda response: response.url.endswith('/api/network/policy') and response.request.method == 'POST'):
        accept(page)
    assert mutations == [server.url + '/api/network/policy'], mutations
    mutations.clear()
    open_action('logout')
    old_session = page.evaluate('state.token')
    replacement, _ = server.app.state.access.login(server.app.state.vault.token, '127.0.0.1', 'Synthetic replacement')
    page.evaluate('token=>{state.token=token}', replacement)
    accept(page)
    page.evaluate('()=>new Promise(requestAnimationFrame)')
    assert not mutations, 'An old confirmation survived a panel-session change'
    page.evaluate('token=>{state.token=token}', old_session)
    for path in paths:
        page.unroute('**/api/' + path, intercept)

    profile_mutations = []
    def capture_profile(route):
        if route.request.method in ('PATCH', 'DELETE'):
            profile_mutations.append(route.request.method)
            route.fulfill(json={'ok': True})
        else:
            route.continue_()
    page.route('**/api/profiles/*', capture_profile)
    for action in ('rename', 'delete'):
        switch(page, 'default', 'accounts')
        row = page.locator(f'.account-card[data-profile="{child}"]')
        row.locator(f'[data-action="{action}"]').click()
        dialog = page.locator('dialog.panel-dialog[open]')
        expect(dialog).to_be_visible()
        label = page.evaluate('id=>state.profiles.find(p=>p.id===id).label', child)
        dialog.locator('input').fill(label if action == 'delete' else 'Synthetic unaccepted rename')
        page.evaluate('id=>switchProfile(id)', child)
        accept(page)
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        assert not profile_mutations, 'A stale prompt or typed confirmation mutated a workspace'
    page.unroute('**/api/profiles/*', capture_profile)


def group_confirmation_owners(page, server):
    switch(page, 'default', 'accounts')
    groups = {}
    for label, count in (('Synthetic owner Alpha', 2), ('Synthetic owner Beta', 1)):
        group = page.evaluate("label=>json('profile-groups',{label},{root:true}).then(r=>r.groups.find(g=>g.label===label).id)", label)
        members = []
        for number in range(count):
            member = page.evaluate("value=>json('profiles',value,{root:true}).then(r=>r.id)",
                {'label': label + ' ' + str(number), 'group': group})
            server.app.state.profiles.entries[member]['app'].state.vault.save('credentials',
                {'api_id': 123, 'api_hash': 'b' * 32, 'session': saved_session(bytes([number + 1]))})
            server.app.state.profiles.entries[member]['app'].state.store.set_target(CHAT, 'Synthetic selected source', 'supergroup', True)
            members.append(member)
        groups[label] = (group, members)
    alpha, members = groups['Synthetic owner Alpha']
    beta, _ = groups['Synthetic owner Beta']
    exports, collections = [], []

    def capture_export(route):
        exports.append(route.request.url)
        route.fulfill(status=409, json={'detail': 'Synthetic export capture'})

    def capture_collection(route):
        collections.append(route.request.url)
        route.fulfill(json={'ok': True})

    page.route('**/api/profile-groups/*/export', capture_export)
    page.route('**/api/collector/*', capture_collection)
    page.evaluate('window.showSaveFilePicker=undefined')
    def open_group(group):
        page.evaluate('id=>window.TgWitnessOpenGroup(id)', group)
        expect(page.locator('#view-group h1')).to_contain_text('Alpha' if group == alpha else 'Beta')
    def action(name):
        page.locator('#view-group .group-actions').get_by_role('button', name=name, exact=True).click()

    for name in ('Export group', 'Start all'):
        open_group(beta)
        open_group(alpha)
        action(name)
        expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
        page.go_back()
        expect(page.locator('#view-group h1')).to_contain_text('Beta')
        accept(page)
        page.evaluate('()=>new Promise(requestAnimationFrame)')
        assert not exports and not collections, 'A group action survived navigation to another group'

    open_group(alpha)
    action('Export group')
    with page.expect_response('**/api/profile-groups/' + alpha + '/export'):
        accept(page)
    assert exports == [server.url + '/api/profile-groups/' + alpha + '/export'], exports
    exports.clear()
    page.evaluate("""()=>{window.showSaveFilePicker=()=>new Promise(resolve=>{
      window.finishGroupPicker=()=>resolve({createWritable:async()=>({write:async()=>{},close:async()=>{},abort:async()=>{}})});
    });}""")
    action('Export group')
    accept(page)
    page.wait_for_function('()=>typeof window.finishGroupPicker==="function"')
    open_group(beta)
    page.evaluate('()=>finishGroupPicker()')
    page.evaluate('()=>new Promise(requestAnimationFrame)')
    assert not exports, 'The group export resumed after its save-picker owner changed'
    page.evaluate('window.showSaveFilePicker=undefined')

    open_group(alpha)
    hold_api_response(page, '/api/collector/start')
    action('Start all')
    accept(page)
    expect(page.locator('html')).to_have_attribute('data-acceptance-held', 'true')
    assert len(collections) == 1
    open_group(beta)
    release_api_response(page)
    page.evaluate('()=>new Promise(requestAnimationFrame)')
    assert len(collections) == 1, 'Remaining group members ran after the group changed'
    collections.clear()
    open_group(alpha)
    action('Start all')
    accept(page)
    expect(page.locator('#toast')).to_contain_text('2 workspaces started.')
    assert {url.split('/profiles/')[1].split('/')[0] for url in collections} == set(members)
    page.unroute('**/api/profile-groups/*/export', capture_export)
    page.unroute('**/api/collector/*', capture_collection)


def main():
    with tempfile.TemporaryDirectory(prefix='audit-frontend-check-') as folder, RunningApp(Path(folder)) as server, sync_playwright() as p:
        store = server.app.state.store
        store.set_target(CHAT, 'Synthetic shared source', 'supergroup', True)
        store.append('message.new', {'text': 'Synthetic archived observation.'}, chat_id=CHAT, message_id=1)
        browser = launch_browser(p)
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.set_default_timeout(20000)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        unlock(page, server)
        child = page.evaluate("async()=>{const p=await json('profiles',{label:'Synthetic second workspace'},{root:true});await loadProfiles();return p.id;}")
        confirmations(page, server, child)
        print('ok  confirmation ownership', flush=True)
        connection_and_reports(page)
        print('ok  connection and report drafts', flush=True)
        settings_and_setup(page, server, child)
        print('ok  settings and setup', flush=True)
        delayed_downloads(page, child)
        print('ok  delayed analysis downloads', flush=True)
        outage_retry(page, server, child)
        print('ok  transient failure recovery', flush=True)
        group_adoption(page, server, child)
        print('ok  group route adoption', flush=True)
        presentation(page)
        pending_action_owners(page, server, child)
        group_confirmation_owners(page, server)
        print('ok  pending workspace, session and group confirmations', flush=True)
        assert not errors, errors
        browser.close()
    print('Audit frontend browser regressions passed')


if __name__ == '__main__':
    main()
