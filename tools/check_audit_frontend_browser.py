"""Audit regressions: async ownership, restored drafts and recoverable panel failures.

All accounts, records, responses and download bodies are synthetic. No Telegram,
provider, tunnel or cloud request is made by these scenarios.
"""
from pathlib import Path
import tempfile

from playwright.sync_api import expect, sync_playwright

from check_browser import (RunningApp, hold_api_response, launch_browser,
                           release_api_response, unlock)
from browser_fixtures import CHAT
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
    # Exercise the separate bulk confirmation path as well.
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
    page.route('**/api/collector/*', lambda route: (
        calls.append(route.request.url.rsplit('/', 1)[-1]), route.fulfill(json={'ok': True})))
    def running():
        page.evaluate("""()=>{
          Object.assign(state.status.collector,{has_session:true,running:true,connected:true,authorization_required:false});
          renderStatus();
        }""")
    running()
    page.locator('#collector-toggle').click()
    expect(page.locator('dialog.panel-dialog[open]')).to_be_visible()
    page.evaluate('()=>{state.status.collector.running=false;renderStatus();}')
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
    page.unroute('**/api/collector/*')


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
    # A former job's completed response cannot replace the current job.
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
    # The new workspace's own edit can still be applied after resetting the controller.
    page.locator('input[name=setup-goal][value=personal]').check()
    page.locator('#setup-form button[type=submit]').click()
    expect(page.locator('#setup-status')).to_contain_text('A personal record')
    assert page.evaluate("()=>json('setup').then(r=>r.saved.goal)") == 'personal'

    child_store = server.app.state.profiles.entries[child]['app'].state.store
    child_store.set_setting('first_run', {'step': 5, 'completed': False, 'skipped': False,
        'goal': 'watch', 'unchecked': True, 'account_kind': 'dedicated'})
    page.evaluate("""async()=>{
      Object.assign(state.status.collector,{has_session:true,authorization_required:true,running:false,phase:'authorization_required'});
      await navigate('first-run');await settingsHub.load(5);
    }""")
    wizard = page.locator('#view-first-run')
    expect(wizard.get_by_text('Telegram is connected.', exact=True)).to_have_count(0)
    expect(wizard.locator('#first-run-next')).to_be_disabled()
    expect(wizard.locator('.auth-card')).to_be_visible()
    # Authorisation can change without the presence of the saved session changing.
    page.evaluate('()=>{state.status.collector.authorization_required=false;settingsHub.status();}')
    expect(wizard.get_by_text('Telegram is connected.', exact=True)).to_be_visible()
    expect(wizard.locator('#first-run-next')).to_be_enabled()
    page.evaluate('()=>{state.status.collector.authorization_required=true;settingsHub.status();}')
    expect(wizard.locator('.auth-card')).to_be_visible()
    expect(wizard.locator('#first-run-next')).to_be_disabled()
    child_store.set_setting('first_run', {'completed': False, 'skipped': True})


def delayed_downloads(page, child):
    switch(page, 'default', 'analysis')
    page.evaluate("async()=>{await json('analysis/provider',{enabled:true,model:'synthetic-test'},{root:true});await refreshStatus();await navigate('analysis');}")
    page.locator(f'#ask-chats input[value="{CHAT}"]').check()
    page.locator('#ask-question').fill('Find the synthetic archived observation.')
    page.locator('#ask-form button[type=submit]').click()
    expect(page.locator('#ask-context-export')).to_be_visible()
    # Return response headers immediately and release its body only after switching.
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
    # A normal download still completes through the same guarded body reader.
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
        assert not errors, errors
        browser.close()
    print('Audit frontend browser regressions passed')


if __name__ == '__main__':
    main()
