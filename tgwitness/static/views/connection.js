// A route is a draft until its server-side check and explicit application finish.
export function createConnectionView({root, tr, json, state, refreshStatus, askConfirm}) {
  const get = id => root.querySelector('#' + id);
  const el = (tag, text, cls) => { const n = document.createElement(tag); if(text)n.textContent=text; if(cls)n.className=cls; return n; };
  let generation=0, timer=null, data=null, draft=null, plan=null, mode='warp', visible=false;
  const labels = {direct:tr('Direct'),vpn:tr('VPN'),proxy:tr('My proxy'),mtproxy:tr('Public MTProto'),warp:tr('WARP')};
  const routeName=value=>({mtproxy_auto:tr('Public MTProto'),socks5:tr('SOCKS5 proxy'),http:tr('HTTP proxy')}[value]||labels[value]||value);
  const notes = {
    direct:tr('Connect from this machine. Telegram and external services can see its public IP address.'),
    vpn:tr('Import a WireGuard profile. TgWitness runs it inside its own folder and routes this account through it. Other applications keep their routes.'),
    proxy:tr('Use your own SOCKS5, HTTP CONNECT or MTProxy server. The credentials stay in this installation.'),
    mtproxy:tr('Choose working servers from the public pool. This carries Telegram traffic only. External requests are switched off; configure a separate proxy under Advanced if needed.'),
    warp:tr('Run a local WARP tunnel for this account. TgWitness manages it inside its data folder using wgcf and wireproxy, an unofficial integration. No system VPN or driver is installed.'),
  };
  function status(text, error=false){get('connect-progress').textContent=text;get('connect-progress').classList.toggle('error',error);}
  function invalidate(){draft=null;plan=null;status('');get('connect-prepare').hidden=true;get('connect-apply').hidden=true;get('connect-continue').hidden=true;get('connect-review').replaceChildren();}
  function choose(value){
    mode=value;invalidate();
    for(const button of root.querySelectorAll('[data-connect-mode]')){
      const selected=button.dataset.connectMode===mode;button.setAttribute('aria-pressed',String(selected));
      button.classList.toggle('selected',selected);
    }
    get('connect-note').textContent=notes[mode];
    get('connect-proxy-fields').hidden=mode!=='proxy';get('connect-vpn-fields').hidden=mode!=='vpn';
    get('connect-setup-fields').hidden=!['warp','vpn'].includes(mode);
    get('connect-warp-note').hidden=mode!=='warp';
    get('connect-outside').disabled=mode==='mtproxy';
    get('connect-step').textContent=tr('1. Choose a route');
  }
  function readDraft(){
    const body={mode,scope:get('connect-scope').value,account:state.profile,group:get('connect-group').value||null,
      keep_custom:get('connect-keep').checked,outside_enabled:mode!=='mtproxy'&&get('connect-outside').checked,
      accept_setup:['warp','vpn'].includes(mode)&&get('connect-consent').checked};
    if(mode==='vpn')body.wireguard=get('connect-wireguard').value.trim();
    if(mode==='proxy')body.proxy={kind:get('connect-proxy-kind').value,host:get('connect-host').value.trim(),
      port:Number(get('connect-port').value),username:get('connect-user').value,password:get('connect-password').value,
      secret:get('connect-secret').value};
    return body;
  }
  function proof(check){
    if(!check)return tr('Not checked yet');
    return [check.telegram_connected?tr('Telegram connected'):tr('Not connected'),check.exit_ip||tr('Exit address unavailable'),
      check.country,check.warp?('WARP: '+check.warp):'',check.latency_ms+' ms',
      new Date(check.checked_at*1000).toLocaleString()].filter(Boolean).join(' · ');
  }
  function rows(items){
    const table=el('table',null,'connect-table'),head=el('tr');
    for(const label of [tr('Account'),tr('Change'),tr('Result')])head.append(el('th',label));
    const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody');
    for(const row of items||[]){
      const r=el('tr'),name=data?.accounts.find(x=>x.id===row.id)?.label||row.id;
      r.append(el('td',row.label||name));
      r.append(el('td',row.before?routeName(row.before)+' → '+(row.skipped?tr('Keep current'):labels[row.after]):
        row.applied?tr('Applied'):tr('Not applied')));
      r.append(el('td',row.error|| (row.skipped?tr('Own route preserved'):row.check?proof(row.check):
        row.running?tr('Observation will pause briefly'):tr('Ready to check'))));body.append(r);
    }
    table.append(body);get('connect-review').replaceChildren(table);
  }
  function setBusy(busy){
    get('connect-fields').disabled=busy;get('connect-preview').disabled=busy;
    get('connect-prepare').disabled=busy;get('connect-apply').disabled=busy;
  }
  function showJob(job){
    const busy=['preparing','applying'].includes(job.state);setBusy(busy);
    get('connect-apply').hidden=job.state!=='ready';get('connect-prepare').hidden=true;
    get('connect-cancel').hidden=!['preparing','ready'].includes(job.state);
    get('connect-continue').hidden=job.state!=='applied'||job.rows.some(row=>!row.applied||row.error);
    if(job.state==='ready'){
      plan=job.plan;get('connect-step').textContent=tr('3. Review and apply');rows(job.rows);
      status(tr('Connection checked. Review the accounts below, then apply. This preview expires in 10 minutes.'));
    }else if(job.state==='applied'){
      plan=null;rows(job.rows);status(job.rows.some(x=>!x.applied||x.error)?
        tr('Some accounts need attention. Review each result below.'):tr('Connection updated. You can continue to sign in or choose sources.'));
    }else if(job.state!=='idle')status((job.account?job.account+' · ':'')+tr(job.error||job.stage),job.state==='failed');
    if(busy)get('connect-step').textContent=job.state==='preparing'?tr('2. Prepare and check'):tr('Applying connection');
    return busy;
  }
  async function load(){
    if(!visible||!state.me?.admin||state.status?.demo)return;
    const stamp=generation;
    try{
      const result=await json('connection',undefined,{root:true});
      const current=state.profile==='default'?result:await json('connection');
      if(stamp!==generation||!visible)return;
      data=result;
      const group=get('connect-group'),selected=group.value;
      group.replaceChildren(...result.groups.map(g=>{const o=el('option',g.label);o.value=g.id;return o;}));group.value=selected||result.groups[0]?.id||'';
      get('connect-current').textContent=routeName(current.current.mode)+
        (current.current.managed?' · '+tr(current.current.process_running?'Local tunnel running':'Local tunnel stopped'):'');
      get('connect-toggle').textContent=tr('Connection route')+' · '+routeName(current.current.mode);
      get('connect-check-result').textContent=proof(current.current.check);
      get('connect-stop').hidden=!current.current.managed||!current.current.process_running;
      get('connect-start').hidden=!current.current.managed||current.current.process_running;
      for(const button of root.querySelectorAll('[data-connect-mode="warp"],[data-connect-mode="vpn"]'))button.disabled=!result.supported;
      if(showJob(result.job))timer=setTimeout(load,1200);
      else if(result.job.state==='applied')await refreshStatus();
    }catch(error){if(stamp===generation&&visible){status(error.message,true);timer=setTimeout(load,5000);}}
  }
  async function action(button, fn){
    const stamp=generation;button.disabled=true;
    try{await fn(stamp);}catch(error){if(stamp===generation)status(error.message,true);}
    finally{if(stamp===generation)button.disabled=false;}
  }
  for(const b of root.querySelectorAll('[data-connect-mode]'))b.addEventListener('click',()=>choose(b.dataset.connectMode));
  get('connect-fields').addEventListener('input',invalidate);
  get('connect-scope').addEventListener('change',()=>{
    get('connect-group-wrap').hidden=get('connect-scope').value!=='group';
    get('connect-keep-wrap').hidden=get('connect-scope').value==='account';
  });
  get('connect-proxy-kind').addEventListener('change',()=>{
    const mt=get('connect-proxy-kind').value==='mtproxy';get('connect-secret-wrap').hidden=!mt;get('connect-login-fields').hidden=mt;
    get('connect-user').value='';get('connect-password').value='';get('connect-secret').value='';
  });
  get('connect-proxy-url').addEventListener('change',()=>{
    try{
      const u=new URL(get('connect-proxy-url').value),kind={ 'socks5:':'socks5','socks5h:':'socks5','http:':'http'}[u.protocol];
      if(!kind||!u.hostname||!u.port||u.search||u.hash||(u.pathname&&u.pathname!=='/'))throw new Error(tr('Enter a SOCKS5 or HTTP proxy URL with a port.'));
      get('connect-proxy-kind').value=kind;get('connect-host').value=u.hostname.replace(/^\[|\]$/g,'');get('connect-port').value=u.port;
      get('connect-user').value=decodeURIComponent(u.username);get('connect-password').value=decodeURIComponent(u.password);
      get('connect-secret').value='';get('connect-secret-wrap').hidden=true;get('connect-login-fields').hidden=false;
      get('connect-proxy-url').value='';invalidate();
    }catch{status(tr('Enter a SOCKS5 or HTTP proxy URL with a port.'),true);}
  });
  get('connect-preview').addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    const body=readDraft(),preview=await json('connection/preview',body,{root:true});
    if(stamp!==generation)return;draft=body;rows(preview.rows);get('connect-prepare').hidden=false;
    get('connect-step').textContent=tr('2. Prepare and check');
    status(tr('Review this selection. Preparing checks the new route while the saved connection keeps working.'));
  }));
  get('connect-prepare').addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    if(!draft)return;await json('connection/prepare',draft,{root:true});
    if(stamp!==generation)return;draft=null;get('connect-wireguard').value='';get('connect-password').value='';get('connect-secret').value='';await load();
  }));
  get('connect-apply').addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    if(!plan)return;
    if(!await askConfirm(tr('Apply the checked routes? Active observation pauses during the switch and resumes if the connection succeeds. History downloads remain paused. External requests will use this route or be disabled for MTProto.'),{confirmText:tr('Apply connection')}))return;
    if(stamp!==generation)return;await json('connection/apply',{plan},{root:true});if(stamp===generation)await load();
  }));
  get('connect-check').addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    status(tr('Checking the current connection…'));const check=await json('connection/check',{});
    if(stamp===generation){get('connect-check-result').textContent=proof(check);status(tr('Current connection checked.'));}
  }));
  get('connect-cancel').addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    await json('connection/cancel',{},{root:true});if(stamp===generation){invalidate();await load();status(tr('Connection draft discarded. Saved settings were not changed.'));}
  }));
  get('connect-continue').addEventListener('click',()=>{
    get('connect-details').open=false;
    document.getElementById('account-heading')?.scrollIntoView({block:'center',behavior:'smooth'});
  });
  for(const control of ['start','stop'])get('connect-'+control).addEventListener('click',e=>action(e.currentTarget,async stamp=>{
    if(control==='stop'&&!await askConfirm(tr('Stop this tunnel and pause observation? This account stays offline until you start the tunnel again.'),{confirmText:tr('Stop tunnel')}))return;
    if(stamp!==generation)return;await json('connection/'+control,{});if(stamp===generation){await load();await refreshStatus();}
  }));
  choose('warp');
  return {
    enter(){visible=true;root.hidden=!state.me?.admin||!!state.status?.demo;clearTimeout(timer);if(!root.hidden)return load();},
    leave(){visible=false;generation++;clearTimeout(timer);},
    reset(){generation++;clearTimeout(timer);data=null;invalidate();get('connect-current').textContent=tr('Current connection');
      get('connect-check-result').textContent=tr('Not checked yet');status('');
      for(const input of root.querySelectorAll('input[type=password],textarea'))input.value='';},
  };
}
