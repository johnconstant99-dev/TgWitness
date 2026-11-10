(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const locales = window.TGW_OFFICIAL_LOCALES || {}, browser = navigator.language.split('-')[0];
  const english = new Map([...document.querySelectorAll('[data-t]')].map(el => [el,el.textContent]));
  let lang = locales[browser] ? browser : 'en', token = '', status = null, busy = false, refreshing = false, screenUrl = null, revision = 0, clientState = 'loading';
  const access = new URLSearchParams(location.hash.slice(1)).get('access');
  if(access && /^[A-Za-z0-9_-]{43}$/.test(access)) {token=access; history.replaceState(null,'',location.pathname+location.search);}
  const text = en => lang === 'en' ? en : locales[lang]?.[en] ?? en;
  function translate() {document.documentElement.lang=lang; $('language').value=lang; for(const [el,en] of english) el.textContent=text(en); if(status) render(status);}
  $('language').addEventListener('change',()=>{lang=$('language').value; translate();}); translate();
  async function api(path,body) {
    const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
    if(!response.ok) {let detail=text('Operation refused'); try{const data=await response.json(); if(typeof data.detail==='string') detail=data.detail;}catch{} throw new Error(detail);}
    return response;
  }
  function render(data) {
    status=data; const o=data.official; if(!o) throw new Error('This recorder does not provide the official client');
    for(const button of document.querySelectorAll('#workspace button')) button.disabled=false;
    $('login').hidden=true; $('workspace').hidden=false;
    const names={created:text('Not started'),login:text('Login without recording'),ready:text('Ready to record'),observing:text('Recording'),paused:text('Paused'),stopped:text('Stopped'),finishing:text('Finishing'),finished:text('Finished')};
    $('badge').textContent=names[o.phase]+(o.reason?':'+o.reason:''); $('badge').className='badge'+(data.settings.enabled?' active':o.reason?' error':'');
    $('selected').textContent=(o.selected_chat||text('No chat selected'))+' · '+o.steps+' '+text('steps');
    $('route').textContent=(o.options.egress==='direct'?text('Direct connection · Telegram sees the runner or host public IP'):o.options.egress+' · '+o.options.proxy_server+' · '+text('No direct fallback'))+' · '+(o.exit_ip||text('IP not checked yet'));
    $('plan-section').hidden=o.phase!=='created'; $('client-section').hidden=['created','finished'].includes(o.phase);
    $('toggle').textContent=data.settings.enabled?text('Pause recording'):text('Start recording');
    $('toggle').disabled=!o.selected_chat||!['ready','paused','observing'].includes(o.phase); $('stop').disabled=['created','finished'].includes(o.phase);
    for(const id of ['older','newer','snapshot']) $(id).disabled=!data.settings.enabled;
    const canChoose=!busy&&clientState==='ready'&&!o.source_locked&&['login','ready','paused'].includes(o.phase);
    $('chats-refresh').disabled=!canChoose; $('chats').disabled=!canChoose;
    $('chat-select').disabled=!canChoose||!$('chats').value;
    $('selection').disabled=!o.source;
    $('finish').disabled=['created','finished','finishing'].includes(o.phase); $('export').disabled=data.settings.enabled;
    $('video-help').textContent=data.video_available?text('Video available, closed segments enter the signed journal.'):text('Video unavailable. A profile requiring video cannot start.');
    $('fingerprint').textContent=data.fingerprint; $('boundary').textContent='#'+data.seq+' · '+data.head_hash;
    $('finish-result').textContent=o.phase==='finished'?(o.logout_confirmed?text('Telegram logout confirmed, browser context closed.'):text('Logout unconfirmed. Revoke this session from a trusted Telegram device.')):'';
    if(busy) for(const button of document.querySelectorAll('#workspace button:not(#stop)')) button.disabled=true;
  }
  async function refresh() {
    if(!token||refreshing||busy) return; refreshing=true; const expected=revision;
    try {
      const data=await (await api('status')).json(); if(expected!==revision) return; render(data); const o=status.official;
      if(!['created','finished','finishing'].includes(o.phase)) {
        const login=await (await api('official/login')).json(); if(expected!==revision)return;
        clientState=login.state; render(data); $('login-state').textContent=text('Client state:')+login.state;
        $('password-form').hidden=login.state!=='password'||o.phase!=='login';
        const blob=await (await api('official/screen')).blob(); if(expected!==revision)return; if(screenUrl) URL.revokeObjectURL(screenUrl); screenUrl=URL.createObjectURL(blob); $('screen').src=screenUrl;
      }
      const events=await (await api('events')).json(); if(expected!==revision)return; $('events').replaceChildren();
      for(const event of events.slice(-12).reverse()){const row=document.createElement('li'); row.textContent='#'+event.seq+' · '+event.kind+' · '+event.observed_at; $('events').append(row);}
    } catch(error) {if(expected===revision){clientState='loading';if(status)render(status);}throw error;} finally {refreshing=false;}
  }
  async function action(fn) {if(busy)return; busy=true; revision++; if(status)render(status); $('notice').textContent=''; try{await fn();}catch(e){$('notice').textContent=e.message;}finally{if(token){try{status=await(await api('status')).json();}catch(e){$('notice').textContent=e.message;}} busy=false; if(status)render(status); await refresh().catch(e=>{$('notice').textContent=e.message;});}}
  function download(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
  $('login-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{token=$('token').value.trim();$('token').value='';render(await(await api('status')).json());const p=status.official.options; for(const [id,key] of Object.entries({mode:'mode',minutes:'session_minutes',minpause:'min_pause_seconds',maxpause:'max_pause_seconds',pixels:'scroll_pixels',steps:'max_steps'})) $(id).value=p[key];});});
  $('plan-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{await api('official/plan',{mode:$('mode').value,session_minutes:Number($('minutes').value),min_pause_seconds:Number($('minpause').value),max_pause_seconds:Number($('maxpause').value),scroll_pixels:Number($('pixels').value),max_steps:Number($('steps').value)});await api('official/open',{});});});
  $('password-form').addEventListener('submit',e=>{e.preventDefault();const password=$('password').value;$('password').value='';action(()=>api('official/password',{password}));});
  $('chats-refresh').addEventListener('click',()=>action(async()=>{const chats=await(await api('official/chats')).json();$('chats').replaceChildren(...chats.map(c=>new Option(c.title,c.handle)));}));
  $('chat-select').addEventListener('click',()=>action(()=>api('official/chat',{handle:$('chats').value})));
  $('chats').addEventListener('change',()=>{if(status)render(status);});
  $('toggle').addEventListener('click',()=>action(()=>api('settings',{enabled:!status.settings.enabled,screenshots:true,pages:true,database:false,video:status.video_available})));
  for(const direction of ['older','newer']) $(direction).addEventListener('click',()=>action(()=>api('official/scroll',{direction})));
  $('snapshot').addEventListener('click',()=>action(()=>api('snapshot',{})));
  $('finish').addEventListener('click',()=>action(()=>api('official/finish',{})));
  $('stop').addEventListener('click',()=>{api('official/stop',{}).then(()=>refresh()).catch(e=>{$('notice').textContent=e.message;});});
  $('selection').addEventListener('click',()=>download(new Blob([JSON.stringify({format:'tgwitness-official-selection-v1',options:status.official.options,source:status.official.source},null,2)],{type:'application/json'}),'official-settings.json'));
  $('checkpoint').addEventListener('click',()=>action(async()=>download(await(await api('checkpoint')).blob(),'official-checkpoint.json')));
  $('export').addEventListener('click',()=>action(async()=>download(await(await api('export',{})).blob(),'official-evidence.zip')));
  setInterval(()=>refresh().catch(e=>{$('notice').textContent=e.message;}),2500);
  if(token) refresh().catch(e=>{$('notice').textContent=e.message;});
})();
