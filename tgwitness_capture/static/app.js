(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', status = null, dirty = false, busy = false, revision = 0;
  const flags = ['screenshots', 'pages', 'database', 'video'];
  const labels={'service.started':'Recorder started','service.stopped':'Recorder stopped',
    'capture.saved':'Artifact saved','capture.partial':'Artifact partially saved',
    'capture.failed':'Capture failed','capture.requested':'Snapshot requested',
    'capture.settings_changed':'Capture settings changed','capture.target_selected':'Browser tab selected',
    'capture.heartbeat':'Recorder heartbeat','export.created':'Export prepared',
    'video.started':'Video started','video.segment':'Video segment saved',
    'video.stopped':'Video stopped','video.interrupted':'Video interrupted'};
  function date(value) {return value ? new Intl.DateTimeFormat('en-GB',{dateStyle:'medium',timeStyle:'medium',timeZone:'UTC'}).format(new Date(value)) + ' UTC' : 'none yet';}
  async function api(path, body) {
    const expected=revision;
    const response = await fetch('/api/' + path, {method:body === undefined ? 'GET' : 'POST',
      headers:{Authorization:'Bearer ' + token, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      body:body === undefined ? undefined : JSON.stringify(body), cache:'no-store'});
    if(expected !== revision) throw new Error('Panel disconnected; request result hidden.');
    if (!response.ok) { let detail='Request failed'; try {detail=(await response.json()).detail || detail;} catch {} throw new Error(typeof detail === 'string' ? detail : 'Check request parameters'); }
    return response;
  }
  function render(data) {
    status=data;
    $('login').hidden=true; $('workspace').hidden=false;
    $('kind').textContent=data.kind === 'browser' ? 'Browser recorder' : 'AyuGram recorder';
    $('badge').textContent=!data.settings.enabled ? 'Capture paused' : data.last_error ? 'Capture error' : 'Capture running';
    $('badge').className='badge' + (!data.settings.enabled ? '' : data.last_error ? ' error' : ' active');
    $('browser-options').hidden=data.kind !== 'browser'; $('database-options').hidden=data.kind !== 'ayugram';
    $('coverage').textContent=data.kind === 'browser' ? 'Background capture checks the selected tab’s text and URL and saves periodic snapshots. Changes between observations may be missed.' : 'The database is copied at intervals. Changes that do not persist between snapshots may be missed.';
    if (!dirty) for (const key of flags) $(key).checked=data.settings[key];
    $('video').disabled=!data.video_available;
    $('video-help').textContent=data.video_available ? 'Video is recorded only while capture is running. Last segment: ' + (data.last_video_segment || 'none yet') : 'Video unavailable: configure a screen source and FFmpeg on the server.';
    $('toggle').textContent=data.settings.enabled ? 'Pause capture' : 'Start capture';
    $('snapshot').disabled=!data.settings.enabled; $('export').disabled=data.settings.enabled;
    $('select-target').disabled=data.settings.enabled; $('refresh-targets').disabled=data.settings.enabled;
    $('observer').textContent=data.observer_id; $('fingerprint').textContent=data.fingerprint;
    $('boundary').textContent='#' + data.seq + ' · ' + data.head_hash; $('route').textContent=data.route_label;
    $('last-success').textContent='Last saved snapshot: ' + date(data.last_success) + (data.last_error ? ' · ' + data.last_error : '');
  }
  async function refresh() {
    if (!token || busy) return;
    const expected=revision;
    const [data, events]=await Promise.all([(await api('status')).json(), (await api('events')).json()]);
    if(expected !== revision) return;
    render(data); $('events').replaceChildren();
    for (const event of events.reverse()) {
      const row=document.createElement('li'), time=document.createElement('time');
      row.textContent='#' + event.seq + ' · ' + (labels[event.kind] || event.kind); row.dataset.kind=event.kind;
      time.textContent=date(event.observed_at); time.title=event.observed_at; row.append(time); $('events').append(row);
    }
  }
  async function action(fn) {
    if (busy) return; busy=true; $('notice').textContent='';
    try {await fn();} catch(error) {$('notice').textContent=error.message;}
    finally {busy=false; if(token) await refresh().catch(error=>{$('notice').textContent=error.message;});}
  }
  function selection() {return Object.fromEntries(flags.map(key=>[key,$(key).checked]));}
  function download(blob,name) {
    const url=URL.createObjectURL(blob), a=document.createElement('a');
    a.href=url; a.download=name; document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),30000);
  }
  $('login-form').addEventListener('submit',event=>{event.preventDefault(); action(async()=>{token=$('token').value.trim(); $('token').value=''; revision++; render(await (await api('status')).json());});});
  $('logout').addEventListener('click',()=>{token=''; revision++; status=null; dirty=false; $('workspace').hidden=true; $('login').hidden=false; $('events').replaceChildren(); $('notice').textContent='Panel disconnected. Recorder capture state has not changed.';});
  for (const key of flags) $(key).addEventListener('change',()=>{dirty=true;});
  $('save').addEventListener('click',()=>action(async()=>{render(await (await api('settings',selection())).json()); dirty=false;}));
  $('toggle').addEventListener('click',()=>action(async()=>{
    const patch=status.settings.enabled ? {enabled:false} : {...selection(), enabled:true};
    const data=await (await api('settings',patch)).json(); dirty=false; render(data);
  }));
  $('snapshot').addEventListener('click',()=>action(async()=>{await api('snapshot',{});}));
  $('refresh-targets').addEventListener('click',()=>action(async()=>{
    const items=await (await api('targets')).json(); $('targets').replaceChildren();
    for (const item of items) {const option=document.createElement('option'); option.value=item.target_id; option.textContent=item.url; $('targets').append(option);}
  }));
  $('select-target').addEventListener('click',()=>action(async()=>{render(await (await api('target',{target_id:$('targets').value})).json());}));
  $('checkpoint').addEventListener('click',()=>action(async()=>{download(await (await api('checkpoint')).blob(),'capture-checkpoint.json');}));
  $('export').addEventListener('click',()=>action(async()=>{download(await (await api('export',{})).blob(),'capture-' + status.kind + '.zip');}));
  setInterval(()=>refresh().catch(error=>{$('notice').textContent=error.message;}),4000);
})();
