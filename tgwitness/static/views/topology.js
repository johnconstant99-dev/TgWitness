const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SVGNS='http://www.w3.org/2000/svg';
const ROWS=40;
const ROUTE={direct:'Direct',mtproxy_auto:'MTProxy · auto',mtproxy:'MTProxy',socks5:'SOCKS5',http:'HTTP proxy',warp:'WARP',vpn:'WireGuard',none:'No route'};
const MODES=[['computer','monitor','Computer'],['docker','archive','Docker'],['server','layers','Cloud VM'],['tdx','shield','Confidential VM']];
const SERVICES=[
  ['github','braces','GitHub','MTProxy lists',/(^|\.)github\.com$|githubusercontent\.com$|\.github\.io$/],
  ['dns','link','1.1.1.1','DNS via proxy',/^1\.1\.1\.1$|^1\.0\.0\.1$/],
  ['cloudflare','shield','Cloudflare','route check · WARP',/(^|\.)cloudflare\.com$|cloudflareclient\.com$|trycloudflare\.com$|argotunnel\.com$|cloudflare-gateway\.com$/],
  ['time','clock','TSA · OTS','timestamps',/^(freetsa\.org|timestamp\.sectigo\.com|[ab]\.pool\.opentimestamps\.org|a\.pool\.eternitywall\.com|ots\.btc\.catallaxy\.com)$/],
  ['drand','activity','drand','time beacon',/^(api[23]?\.drand\.sh|drand\.cloudflare\.com)$/],
  ['storage','archive','S3','encrypted copy',/^downloads\.rclone\.org$/],
  ['bot','message','Bot API','operator bot',/^api\.telegram\.org$/],
  ['notify','bell','Alerts','webhooks · ntfy',/^(ntfy\.sh|discord\.com|hooks\.slack\.com)$/],
  ['geo','search','Geo lookup','proxy country',/^(api\.country\.is|ipwho\.is)$/],
  ['ai','sparkle','AI','archive analysis',/^$/],
];
const THREATS=[
  ['people','operator','People','Phishing for the panel key or a login code, approved QR logins and shared screenshots. The most likely way in.'],
  ['key','panel','Panel key','One key controls every account in this installation.'],
  ['host','host','Host access','Root on a running host can read the decrypted vault and plaintext media.'],
  ['proxy','route','Public proxies','Proxy operators see the server address and timing, not MTProto content.'],
  ['edge','entry','TLS edge','Cloudflare or a reverse proxy decrypts panel traffic.'],
  ['outside','out','Outside services','S3, webhooks and AI receive what you configure.'],
];
const PURPOSE={proxy_catalog:'MTProxy list',proxy_sources:'proxy search',guided_connection:'route check',portable_routes:'WARP helper',anchoring:'timestamp',replica:'encrypted copy',storage:'media storage',capture_connections:'recorder',assurance:'host record',tdx:'TDX collateral',cloud:'deployment',cloud_wizard:'deployment',cloud_attestation:'attestation',alerts:'alert',operator_bot:'operator bot',webhooks:'webhook',ai:'analysis',source_check:'source check',witness:'witness',verify:'verification',mcp_server:'MCP',dns:'DNS via proxy',telegram:'Telegram transport'};
const PLANE='<svg class="tp-plane" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.6 11.3 20.4 4.4c.8-.3 1.6.4 1.4 1.3l-3 14.2c-.2.9-1.2 1.3-2 .8l-4.6-3.4-2.4 2.3c-.3.3-.8.1-.8-.3l.2-3.6 7.6-6.9c.3-.3-.1-.6-.4-.4L7 13.4l-4.3-1.3c-.8-.3-.8-1.4-.1-1.8Z"/></svg>';
const f=n=>Number(n).toFixed(1);
const M=p=>`M${f(p[0])} ${f(p[1])}`;
const L=p=>`L${f(p[0])} ${f(p[1])}`;
const hc=(a,b)=>{const m=(b[0]-a[0])/2;return `C${f(a[0]+m)} ${f(a[1])} ${f(b[0]-m)} ${f(b[1])} ${f(b[0])} ${f(b[1])}`;};
const vc=(a,b)=>{const m=(b[1]-a[1])/2;return `C${f(a[0])} ${f(a[1]+m)} ${f(b[0])} ${f(b[1]-m)} ${f(b[0])} ${f(b[1])}`;};
const bus=(a,y,b)=>{const r=10,d=Math.sign(b[0]-a[0]);if(Math.abs(b[0]-a[0])<2*r)return M(a)+L([a[0],y])+L([b[0],y])+L(b);
  return M(a)+L([a[0],y-r])+`Q${f(a[0])} ${f(y)} ${f(a[0]+d*r)} ${f(y)}`+L([b[0]-d*r,y])+`Q${f(b[0])} ${f(y)} ${f(b[0])} ${f(y+r)}`+L(b);};
const split=key=>{const i=key.indexOf(':');return i<0?[key,'']:[key.slice(0,i),key.slice(i+1)];};

export function createTopology({root,json,tr,getState,options,openSettings,toast}){
  const t=value=>esc(tr(value));
  const icon=(name,cls='icon')=>`<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const motion=matchMedia('(prefers-reduced-motion: reduce)');
  const listeners=new AbortController();
  const layers={traffic:true,ports:true,threats:false};
  const events=new Map();
  let data=null,visible=false,timer=null,clock=null,request=null,generation=0,received=0,failed=false,first=true;
  let selected=null,reveal=false,lastEvent=0,prev=new Map(),pipes=new Map(),particles=[],frame=0,gframe=0,polled=0,demo=null;
  const find=name=>root.querySelector(`[data-tp="${name}"]`);
  const put=(name,html)=>{const el=find(name);if(!el||el._html===html)return false;el.innerHTML=html;el._html=html;return true;};
  const clock12=value=>{const d=value?new Date(typeof value==='number'?value*1000:value):null;return d&&!isNaN(d)?d.toLocaleTimeString([],{hour12:false}):'—';};
  const local=host=>/^(127\.|::1$|localhost$)/.test(host||'');
  const literal=host=>/^[0-9.]+$|:/.test(host||'');
  const tgHost=host=>(data?.telegram?.datacenters||[]).some(dc=>dc.address===host);
  const named=host=>SERVICES.some(item=>item[4].test(host||''));
  const addr=(point,secret=false)=>{
    if(!point)return '—';
    const host=point.host||'',port=point.port?':'+point.port:'';
    return reveal||!secret&&(point.telegram_network||local(host)||tgHost(host)||!literal(host)&&named(host))?(host.includes(':')?'['+host+']':host)+port:'•••'+port;
  };

  root.innerHTML=`<div class="tp">
    <header class="tp-head">
      <div class="tp-title"><h1>${t('Network topology')}</h1><span class="tp-live" data-tp="live"></span></div>
      <div class="tp-tools" role="group" aria-label="${t('Layers')}">
        ${[['traffic','activity','Traffic'],['ports','link','Ports'],['threats','alert','Threats']].map(([id,g,l])=>`<button type="button" class="tp-tool" data-tp-layer="${id}" aria-pressed="${layers[id]}">${icon(g)}<span>${t(l)}</span></button>`).join('')}
        <button type="button" class="tp-tool" data-tp-action="reveal" aria-pressed="false">${icon('eye')}<span>${t('Addresses')}</span></button>
        <button type="button" class="tp-tool tp-tool-icon" data-tp-action="refresh" aria-label="${t('Refresh')}" title="${t('Refresh')}">${icon('refresh')}</button>
      </div>
    </header>
    <div class="tp-modes" data-tp="modes" role="list" aria-label="${t('Placement')}"></div>
    <div class="tp-kpis" data-tp="kpis"></div>
    <div class="tp-error" data-tp="error" role="status" hidden></div>
    <section class="tp-stage" data-tp="stage" aria-label="${t('Network topology')}">
      <svg class="tp-wires" data-tp="wires" aria-hidden="true"></svg>
      <div class="tp-grid">
        <div class="tp-left">
          <div class="tp-col-you"><div class="tp-colhead">${t('You')}</div><div data-tp="you"></div></div>
          <div class="tp-col-entry"><div class="tp-colhead">${t('Entry')}</div><div data-tp="entry"></div></div>
        </div>
        <div class="tp-hostcol"><div class="tp-colhead" data-tp="hosthead"></div><div data-tp="host"></div></div>
        <div class="tp-routecol"><div class="tp-colhead">${t('Route')}</div><div class="tp-hops" data-tp="hops"></div></div>
        <div class="tp-gatecol"><div class="tp-colhead">${t('Filter')}</div><div class="tp-gatebox" data-tp="gate"></div></div>
        <div class="tp-tgcol"><div class="tp-colhead">Telegram</div><div class="tp-tgbox" data-tp="tg"></div></div>
        <div class="tp-outrow" data-tp="out"></div>
      </div>
      <svg class="tp-fx" data-tp="fx" aria-hidden="true"></svg>
      <div class="tp-pins" data-tp="pins"></div>
      <aside class="tp-card" data-tp="card" hidden></aside>
      <footer class="tp-legend" data-tp="legend"></footer>
    </section>
    <div class="tp-bottom">
      <section class="tp-term"><header><span>${t('Live requests')}</span><b data-tp="total"></b></header><div class="tp-term-body" data-tp="log" tabindex="0" aria-label="${t('Live requests')}"></div></section>
      <section class="tp-ports"><header><span>${t('Port map')}</span></header><div class="tp-ports-body" data-tp="ports"></div></section>
    </div>
  </div>`;
  const stage=find('stage'),wires=find('wires'),fx=find('fx'),card=find('card');

  const mode=()=>['computer','docker','server','tdx'].includes(data.host.kind)?data.host.kind:'computer';
  const remote=()=>data.host.place==='server'||!!data.host.provider;
  const shown=()=>data.accounts.slice(0,ROWS);
  const acc=id=>data.accounts.find(a=>a.id===id);
  const routeOf=a=>{const r=a.route||{};return r.managed==='warp'||r.managed==='vpn'?r.managed:r.fallback?'direct':r.kind||'none';};
  const hopKey=a=>{const k=routeOf(a),r=a.route||{};if(k==='direct'||k==='none')return null;if(k==='warp'||k==='vpn')return k+':'+a.id;if(!r.gateway)return 'wait:'+a.id;return k+':'+r.gateway.host+':'+r.gateway.port;};
  const target=a=>a.socket?.peer?.telegram_network?a.socket.peer:a.telegram?.endpoint;
  const check=a=>{if(a.state!=='connected')return null;if(target(a)?.telegram_network)return 'ok';if(routeOf(a)==='direct'&&a.socket?.peer&&!local(a.socket.peer.host))return 'bad';return 'unknown';};
  const dcUp=()=>new Set([...data.accounts.filter(a=>a.state==='connected').map(a=>a.telegram?.dc),...data.accounts.flatMap(a=>(a.media||[]).filter(x=>x.connected).map(x=>x.dc))]);
  const layoutOf=()=>{const w=stage.clientWidth||root.clientWidth||1200;return w>=1120?'wide':w>=820?'mid':'narrow';};
  const svcOn=id=>{
    const s=data.accounts.map(a=>a.services||{}),any=k=>s.some(x=>x[k]?.enabled),auto=data.accounts.some(a=>a.route?.kind==='mtproxy_auto'),p=data.pool||{};
    return {github:auto&&!p.operator_catalog||!!p.github_search||any('source_check'),dns:data.accounts.some(a=>a.outside?.enabled&&['socks5','http'].includes(a.outside.route)),
      cloudflare:data.accounts.some(a=>a.route?.managed==='warp'||a.route?.check)||any('gateway_log'),time:any('timestamps'),drand:any('drand'),storage:any('replica')||any('storage'),
      bot:any('operator_bot'),notify:any('alerts')||any('webhooks')||data.ingress.deployment?.tunnel==='quick',geo:auto&&!!p.countries&&!p.operator_catalog,ai:any('analysis')}[id];
  };
  function entries(){
    const i=data.ingress,tunnel=i.via==='cloudflare'||i.published?.kind==='quick'||!!i.deployment?.tunnel||data.host.provider==='phala',domain=i.via==='reverse_proxy'||i.published?.kind==='domain';
    const list=[['cloudflare','shield','Cloudflare Tunnel',i.via==='cloudflare'?'on':tunnel?'ready':'off'],['domain','link','HTTPS domain',i.via==='reverse_proxy'?'on':domain?'ready':'off'],
      ['ssh','lock','SSH tunnel',i.via==='loopback'&&remote()?'on':'off'],['local','monitor','This computer',i.via==='loopback'&&!remote()?'on':'off']];
    if(i.via==='network')list.push(['open','alert','Open port','warn']);
    return list;
  }
  const mainKind=()=>data.host.container||data.host.provider==='phala'?'container':data.host.provider?'systemd service':'process';
  const mainTitle=()=>data.host.provider==='phala'?'collector':data.host.provider&&!data.host.container?'tgwitness.service':'tgwitness';
  const hostTitle=()=>({computer:'This computer',docker:remote()?'Server · Docker':'Docker host',server:'Cloud VM',tdx:'Confidential VM · Intel TDX'}[mode()]);
  function sidecars(){
    const h=data.host,i=data.ingress,s=data.accounts.map(a=>a.services||{}),ent=entries();
    const kind=h.provider==='phala'||h.container?'container':h.provider?'systemd service':'process';
    const rec=k=>s.map(x=>x['recorder_'+k]).find(x=>x?.configured||x?.enabled);
    const list=[{id:'tunnel',glyph:'shield',label:'cloudflared',kind,on:ent[0][3]!=='off',sub:'outbound only'}];
    if(i.deployment?.tunnel==='quick')list.push({id:'beacon',glyph:'bell',label:'address beacon',kind,on:true,sub:'ntfy'});
    if(ent[1][3]!=='off')list.push({id:'caddy',glyph:'link',label:'Caddy',kind:'container',on:true,sub:'HTTPS'});
    list.push({id:'witness',glyph:'fingerprint',label:'witness',kind:'reads checkpoints',on:s.some(x=>x.witness?.enabled)});
    for(const [id,glyph,label] of [['trusted','lock','Trusted Live'],['browser','monitor','browser recorder'],['ayugram','message','AyuGram recorder']]){
      const r=rec(id);list.push({id,glyph,label,kind:'recorder',on:!!r,port:r?.endpoints?.[0]?.port});
    }
    return list;
  }
  function hops(){
    const map=new Map();
    for(const a of shown()){const k=hopKey(a);if(!k)continue;const h=map.get(k)||{key:k,accounts:[]};h.accounts.push(a);map.set(k,h);}
    return [...map.values()];
  }
  const svcUse=(a,id)=>{const s=a.services||{};return {github:!!s.source_check?.enabled||a.route?.kind==='mtproxy_auto',dns:!!a.outside?.enabled,cloudflare:!!a.route?.check||a.route?.managed==='warp'||!!s.gateway_log?.enabled,
    time:!!s.timestamps?.enabled,drand:!!s.drand?.enabled,storage:!!s.replica?.enabled||!!s.storage?.enabled,bot:!!s.operator_bot?.enabled,notify:!!s.alerts?.enabled||!!s.webhooks?.enabled,geo:a.route?.kind==='mtproxy_auto',ai:!!s.analysis?.enabled}[id];};
  function related(key){
    if(!selected||selected===key)return true;
    const [k,id]=split(selected),[k2,id2]=split(key);
    if(k==='host'||k==='threat'||k2==='threat')return true;
    if(k==='acc'){const a=acc(id);return !a||key==='hop:'+hopKey(a)||key==='dc:'+a.telegram?.dc||key==='gate'||key==='vault'||(a.media||[]).some(x=>key==='dc:'+x.dc)||k2==='svc'&&svcUse(a,id2);}
    if(k==='dc')return k2==='acc'&&String(acc(id2)?.telegram?.dc)===id||key==='gate';
    if(k==='hop')return k2==='acc'&&hopKey(acc(id2)||{})===id||key==='gate';
    if(k==='gate')return ['acc','dc','hop'].includes(k2);
    if(k==='svc'||k==='out')return key==='out'||k2==='svc'&&(k==='out'||id2===id)||k2==='acc'&&k==='svc'&&svcUse(acc(id2)||{},id);
    if(k==='vault')return k2==='acc';
    if(['entry','operator','panel','car','door'].includes(k))return ['entry','operator','panel','car','door'].includes(k2);
    return false;
  }
  const dimOf=key=>selected&&!related(key)?' tp-dim':'';

  function youHTML(){
    return `<button type="button" class="tp-op" data-tp-node="operator" aria-label="${t('You')}"><span class="tp-op-orb" data-tp-anchor="operator">${icon('users')}</span><strong>${t('You')}</strong><small>${esc(tr('Sessions: {n}',{n:(data.ingress.sessions||[]).length}))}</small></button>`;
  }
  function entryHTML(){
    return `<div class="tp-entries">${entries().map(([id,g,label,st])=>`<button type="button" class="tp-entry tp-${st}" data-tp-node="entry:${id}" data-tp-anchor="entry:${id}">${icon(g)}<span>${t(label)}</span></button>`).join('')}</div>`;
  }
  function accHTML(a,ix){
    const up=a.state==='connected',r=routeOf(a);
    return `<button type="button" class="tp-acc ${up?'tp-on':'tp-off'} tp-s-${esc(a.state)}" data-tp-node="acc:${esc(a.id)}" data-tp-anchor="acc:${esc(a.id)}" aria-label="${esc(a.label)}">
      <span class="tp-acc-ix">${String(ix+1).padStart(2,'0')}</span>${icon('lock','icon tp-acc-lock')}<span class="tp-acc-name">${esc(a.label)}</span>
      <span class="tp-acc-route tp-r-${esc(r)}">${t(ROUTE[r]||r)}</span>${a.telegram?.dc?`<span class="tp-acc-dc">DC${esc(a.telegram.dc)}</span>`:''}
      <span class="tp-acc-ctr" data-tp-count="${esc(a.id)}"></span>${a.socket?.local?`<span class="tp-acc-port">:${esc(a.socket.local.port)}</span>`:''}</button>`;
  }
  function hostHTML(){
    const h=data.host,m=mode(),i=data.ingress,l=i.listener,loop=!!l&&local(l.host),ssh=i.deployment?.ssh,list=shown(),more=data.accounts.length-list.length;
    const external=data.accounts.some(a=>a.storage?.key_mode==='external');
    return `<section class="tp-host tp-host-${m}">
      <div class="tp-host-head" data-tp-node="host" data-tp-anchor="hosthead" role="button" tabindex="0" aria-label="${t(hostTitle())}">
        <span class="tp-host-ic">${icon({computer:'monitor',docker:'archive',server:'layers',tdx:'shield'}[m])}</span>
        <span class="tp-host-tx"><strong>${t(hostTitle())}</strong><small>${esc([h.provider,h.os,h.machine].filter(Boolean).join(' · '))}</small></span>
        ${h.tdx?`<span class="tp-chip tp-chip-tdx">${icon('shield')}Intel TDX</span>`:''}
      </div>
      <div class="tp-walls">
        <button type="button" class="tp-chip ${loop?'tp-chip-ok':'tp-chip-warn'}" data-tp-node="door" data-tp-anchor="door">${icon(loop?'lock':'alert')}<span>${t(loop?'Panel port: loopback only':'Panel port is exposed')}</span></button>
        ${ssh==='disabled'?`<button type="button" class="tp-chip tp-chip-ok" data-tp-node="door">${icon('lock')}<span>${t('SSH off')}</span></button>`:ssh==='debug'?`<button type="button" class="tp-chip tp-chip-warn" data-tp-node="door">${icon('alert')}<span>${t('SSH on')}</span></button>`:''}
      </div>
      <div class="tp-cars">${sidecars().map(c=>`<button type="button" class="tp-car ${c.on?'tp-on':'tp-off'}" data-tp-node="car:${c.id}" data-tp-anchor="car:${c.id}">${icon(c.glyph)}<b>${t(c.label)}</b><small>${t(c.on?c.sub||c.kind:'not connected')}${c.on&&c.port&&layers.ports?' · :'+esc(c.port):''}</small></button>`).join('')}</div>
      <div class="tp-proc" data-tp-anchor="proc">
        <div class="tp-proc-head">${icon(mainKind()==='container'?'archive':'settings')}<b>${esc(mainTitle())}</b><span class="tp-tag">${t(mainKind())}</span></div>
        <button type="button" class="tp-panel" data-tp-node="panel" data-tp-anchor="panel">${icon('shield')}<span>${t('Panel')}</span>${l?`<code class="tp-port">${esc(addr(l))}</code>`:''}</button>
        <div class="tp-accs" data-tp="accs">${list.map((a,ix)=>accHTML(a,ix)).join('')||`<p class="tp-empty">${t('No accounts yet.')}</p>`}${more>0?`<div class="tp-more">${esc(tr('+{n} more',{n:more}))}</div>`:''}</div>
        <button type="button" class="tp-vault" data-tp-node="vault">${icon('lock')}<span>${t('Encrypted vault per account')}</span><em>${t(external?'external master key':'local key')}</em></button>
      </div>
    </section>`;
  }
  function hopsHTML(){
    return hops().map(h=>{
      const a=h.accounts[0],k=routeOf(a),up=h.accounts.some(x=>x.state==='connected'),r=a.route||{};
      const sub=k==='warp'||k==='vpn'?(layers.ports&&r.helper?.port?'127.0.0.1:'+r.helper.port:r.check?.country||tr('local tunnel')):h.key.startsWith('wait:')?tr('waiting'):layers.ports?addr(r.gateway,true):tr(r.source||'proxy');
      return `<button type="button" class="tp-hop tp-hop-${esc(k)} ${up?'tp-on':'tp-off'}" data-tp-node="hop:${esc(h.key)}" data-tp-anchor="hop:${esc(h.key)}" data-tp-hop="${esc(h.accounts.map(x=>x.id).join(' '))}"><b>${t(ROUTE[k]||k)}${h.accounts.length>1?' ×'+h.accounts.length:''}</b><small>${esc(sub)}</small></button>`;
    }).join('');
  }
  function gateHTML(){
    const nets=data.telegram.networks||[],v4=nets.filter(n=>!n.includes(':')),v6=nets.length-v4.length;
    return `<div class="tp-gate" data-tp-node="gate" data-tp-anchor="gate" role="button" tabindex="0" aria-label="${t('Telegram only')}"><span class="tp-gate-title">${t('Telegram only')}</span><span class="tp-cidrs">${v4.map(n=>`<span>${esc(n)}</span>`).join('')}</span>${v6?`<span class="tp-gate-more">${esc(tr('+{n} IPv6',{n:v6}))}</span>`:''}</div>`;
  }
  function tgHTML(){
    const up=dcUp();
    return `<div class="tp-tg-head"><span class="tp-plane-wrap">${PLANE}</span><span><b>Telegram</b><small>MTProto${layers.ports?' · :443':''}</small></span></div><div class="tp-dcs">${data.telegram.datacenters.map(dc=>{
      const on=up.has(dc.id),n=data.accounts.filter(a=>a.telegram?.dc===dc.id&&a.state==='connected').length;
      return `<button type="button" class="tp-dc ${on?'tp-on':'tp-off'}" data-tp-node="dc:${dc.id}" aria-label="DC${dc.id}"><span class="tp-orb" data-tp-anchor="dc:${dc.id}">DC${dc.id}</span><span class="tp-dc-tx"><strong>${t(dc.city||'')}</strong><code>${esc(dc.address)}</code></span>${n?`<em>×${n}</em>`:''}</button>`;
    }).join('')}</div>`;
  }
  function outHTML(){
    const a=data.accounts,on=a.filter(x=>x.outside?.enabled).length,unlisted=[...events.values()].some(e=>e._node==='other'),priv=!!data.policy?.private_destinations;
    return `<div class="tp-out-head" data-tp-node="out" data-tp-anchor="outbus" role="button" tabindex="0" aria-label="${t('HTTPS out')}"><span class="tp-colhead">${t('HTTPS out')}</span><span class="tp-out-sub">${t('A separate channel, not through the Telegram route')}</span>
      <span class="tp-chip ${on?'tp-chip-out':'tp-chip-off'}">${esc(tr('Allowed for {n} of {total} accounts',{n:on,total:a.length}))}</span><span class="tp-chip ${priv?'tp-chip-warn':'tp-chip-ok'}">${t(priv?'Private networks allowed':'Private networks refused')}</span></div>
      <div class="tp-svcs">${SERVICES.map(([id,g,label,why])=>`<button type="button" class="tp-svc ${svcOn(id)?'tp-on':'tp-off'}" data-tp-node="svc:${id}" data-tp-anchor="svc:${id}">${icon(g)}<b>${esc(label)}</b><small>${t(why)}</small></button>`).join('')}${unlisted?`<button type="button" class="tp-svc tp-alarm" data-tp-node="svc:other" data-tp-anchor="svc:other">${icon('alert')}<b>${t('Unlisted host')}</b><small>${t('review')}</small></button>`:''}</div>`;
  }
  function legendHTML(){
    return `<span class="tp-k tp-k-tx">${t('to Telegram')}</span><span class="tp-k tp-k-rx">${t('from Telegram')}</span><span class="tp-k tp-k-out">${t('HTTPS out')}</span><span class="tp-k tp-k-in">${t('panel access')}</span><span class="tp-k tp-k-off">${t('not connected')}</span><span class="tp-note">${t(data?.demo?'Demo data. Motion shows direction only.':'Dots are counted calls, updates and requests. Moving dashes mark an open connection.')}</span>`;
  }
  function renderModes(){
    const m=mode();
    put('modes',MODES.map(([id,g,l])=>`<div class="tp-mode${id===m?' tp-mode-on':''}" role="listitem"${id===m?' aria-current="true"':''}>${icon(g)}<span>${t(l)}</span>${id===m?icon('check','icon tp-mode-check'):''}</div>`).join(''));
  }
  function renderKpis(){
    const a=data.accounts,up=a.filter(x=>x.state==='connected'),ok=up.filter(x=>check(x)==='ok').length,bad=up.some(x=>check(x)==='bad');
    const l=data.ingress.listener,loop=!!l&&local(l.host),out=a.filter(x=>x.outside?.enabled).length,tr2=data.traffic||{};
    put('kpis',[['users','Accounts online',`${up.length}/${a.length}`,up.length?'ok':'off',''],['activity','Telegram pipes',String(up.length),up.length?'tx':'off','to and from Telegram'],
      ['shield','In Telegram ranges',`${ok}/${up.length}`,bad?'bad':up.length&&ok===up.length?'ok':up.length?'warn':'off','checked per connection'],
      ['lock','Panel port',l?':'+l.port:'—',loop?'ok':'warn',loop?'loopback only':'network'],['link','HTTPS out',`${out}/${a.length}`,out?'out':'off','accounts allowed'],
      ['search','Observed requests',tr2.available?String(tr2.total??0):'—','in','this process']]
      .map(([g,l2,v,tone,sub])=>`<div class="tp-kpi tp-t-${tone}">${icon(g)}<b>${esc(v)}</b><span>${t(l2)}</span>${sub?`<small>${t(sub)}</small>`:''}</div>`).join(''));
  }
  function counts(){
    for(const a of shown()){
      const el=root.querySelector(`[data-tp-count="${CSS.escape(a.id)}"]`);if(!el)continue;
      const act=a.activity||{},up=a.state==='connected';
      const value=up&&act.available?`↑${act.calls} ↓${act.ok}`:up?'':tr(a.state==='unavailable'?'unavailable':a.authorized?'disconnected':'no session');
      if(el.textContent!==value)el.textContent=value;
    }
  }
  function dims(){for(const el of root.querySelectorAll('[data-tp-node]'))el.classList.toggle('tp-dim',!!selected&&!related(el.dataset.tpNode));}

  function placeHops(box){
    const col=find('hops'),S=stage.getBoundingClientRect(),C=col.getBoundingClientRect(),top=C.top-S.top;
    const direct=shown().filter(a=>!hopKey(a)).map(a=>box('acc:'+a.id)).filter(Boolean).map(b=>b.cy-top);
    const items=[...col.querySelectorAll('[data-tp-hop]')].map(el=>{
      const ys=el.dataset.tpHop.split(' ').map(id=>box('acc:'+id)).filter(Boolean).map(b=>b.cy-top);
      return {el,y:ys.length?ys.reduce((s,v)=>s+v,0)/ys.length:24,h:el.offsetHeight||38};
    }).sort((p,q)=>p.y-q.y);
    const placed=[];
    for(const it of items){
      const clash=y=>placed.some(p=>Math.abs(p-y)<it.h+8)||direct.some(d=>Math.abs(d-y)<it.h/2+7);
      let y=it.y;
      for(let k=1;k<90&&clash(y);k++)y=it.y+(k%2?1:-1)*Math.ceil(k/2)*6;
      y=Math.max(it.h/2,Math.min(Math.max(C.height,it.h)-it.h/2,y));
      placed.push(y);it.el.style.top=Math.round(y-it.h/2)+'px';
    }
  }
  const mark=(x,y,state,dim)=>`<g class="tp-check tp-${state}${dim}" transform="translate(${f(x)} ${f(y)})"><circle r="7"/><path d="${state==='ok'?'M-3.2 .2l2.1 2.2 4.1-4.4':state==='bad'?'M-2.6 -2.6l5.2 5.2M2.6 -2.6l-5.2 5.2':'M-1.9 -2a2 2 0 1 1 2.7 1.9c-.6.2-.8.6-.8 1.1M0 3.2v.2'}"/></g>`;
  function geometry(){
    gframe=0;
    if(!data||!visible)return;
    const S=stage.getBoundingClientRect();if(!S.width||!S.height)return;
    const lay=stage.dataset.layout,anchors=new Map();
    for(const el of root.querySelectorAll('[data-tp-anchor]'))if(el.getClientRects().length)anchors.set(el.dataset.tpAnchor,el);
    const box=key=>{const el=anchors.get(key);if(!el)return null;const r=el.getBoundingClientRect(),x=r.left-S.left,y=r.top-S.top;return {x,y,w:r.width,h:r.height,cx:x+r.width/2,cy:y+r.height/2};};
    if(lay==='wide')placeHops(box);
    const aura=[],base=[],flows=[],marks=[],flowing=layers.traffic&&!motion.matches;
    const op=box('operator'),pan=box('panel'),g=box('gate'),proc=box('proc');
    for(const [id,,,st] of entries()){
      const e=box('entry:'+id),d=dimOf('entry:'+id);if(!op||!e)continue;
      const active=st==='on'||st==='warn',key=active?' data-pipe="in"':'';
      if(lay==='narrow'){
        if(st==='off'||!pan)continue;
        const p0=[op.x+op.w,op.cy],p1=[e.x,e.cy],e1=[e.cx,e.y+e.h];
        base.push(`<path d="${M(p0)+hc(p0,p1)+L([e.cx,e.cy])+L(e1)+vc(e1,[pan.x+Math.min(pan.w*.3,90),pan.y])}" class="tp-pipe tp-in tp-${st}${d}"${key}/>`);
        continue;
      }
      const p0=[op.x+op.w,op.cy],p1=[e.x,e.cy];
      if(st==='off'||!pan){base.push(`<path d="${M(p0)+hc(p0,p1)}" class="tp-pipe tp-in tp-off${d}"/>`);continue;}
      const car=id==='cloudflare'?box('car:tunnel'):id==='domain'?box('car:caddy'):null,e1=[e.x+e.w,e.cy];
      let path=M(p0)+hc(p0,p1)+L(e1);
      if(car){const c0=[car.x,car.cy],c1=[car.cx,car.y+car.h];path+=hc(e1,c0)+L(c1)+vc(c1,[pan.x+Math.min(pan.w*.3,90),pan.y]);}
      else path+=hc(e1,[pan.x,pan.cy]);
      base.push(`<path d="${path}" class="tp-pipe tp-in tp-${st}${d}"${key}/>`);
      if(active&&flowing)flows.push(`<path d="${path}" class="tp-flow tp-flow-in${d}"/>`);
    }
    if(lay!=='narrow'&&g){
      for(const a of shown()){
        const r=box('acc:'+a.id);if(!r)continue;
        const up=a.state==='connected',k=lay==='wide'?hopKey(a):null,hb=k?box('hop:'+k):null,d=dimOf('acc:'+a.id),y=r.cy,x0=r.x+r.w;
        const line=(off,to)=>{let p=M([x0,y+off]);
          if(hb){const hy=hb.cy+off;p+=hc([x0,y+off],[hb.x,hy])+L([hb.x+hb.w,hy])+hc([hb.x+hb.w,hy],[g.x,y+off]);}else p+=L([g.x,y+off]);
          p+=L([g.x+g.w,y+off]);if(to)p+=hc([g.x+g.w,y+off],[to.x,to.cy+off*1.6]);return p;};
        const dc=box('dc:'+a.telegram?.dc),tx=line(-2.4,dc),rx=line(2.4,dc);
        if(up&&dc)aura.push(`<path d="${tx}" class="tp-aura${d}"/>`);
        const pick=selected==='acc:'+a.id?' tp-pick':'';
        base.push(`<path d="${tx}" class="tp-pipe tp-tx ${up?'tp-on':'tp-off'}${d}${pick}" data-pipe="tx:${esc(a.id)}"/><path d="${rx}" class="tp-pipe tp-rx ${up?'tp-on':'tp-off'}${d}${pick}" data-pipe="rx:${esc(a.id)}"/>`);
        if(up&&dc&&flowing)flows.push(`<path d="${tx}" class="tp-flow tp-flow-tx${d}"/><path d="${rx}" class="tp-flow tp-flow-rx${d}"/>`);
        for(const m of a.media||[]){const to=box('dc:'+m.dc);if(to&&m.connected&&m.dc!==a.telegram?.dc)base.push(`<path d="${line(6,to)}" class="tp-pipe tp-media${d}"/>`);}
        const st=check(a);if(st)marks.push(mark(g.cx,y,st,d));
      }
    }
    if(lay==='narrow'&&g&&proc){
      const by=new Map();for(const a of shown())if(a.telegram?.dc)by.set(a.telegram.dc,[...(by.get(a.telegram.dc)||[]),a]);
      const keys=[...by.keys()].sort((p,q)=>p-q);
      keys.forEach((dc,i)=>{
        const list=by.get(dc),db=box('dc:'+dc);if(!db)return;
        const online=list.filter(a=>a.state==='connected'),d=selected&&!related('dc:'+dc)&&!list.some(a=>selected==='acc:'+a.id)?' tp-dim':'';
        const x0=proc.x+proc.w*(i+1)/(keys.length+1),y0=proc.y+proc.h,x1=db.cx;
        const path=M([x0,y0])+vc([x0,y0],[x1,g.y])+L([x1,g.y+g.h])+vc([x1,g.y+g.h],[x1,db.y]);
        base.push(`<path d="${path}" class="tp-pipe tp-trunk ${online.length?'tp-on':'tp-off'}${d}" data-pipe="trunk:${dc}"/>`);
        if(online.length&&flowing)flows.push(`<path d="${path}" class="tp-flow tp-flow-tx${d}"/>`);
        if(online.length)marks.push(mark(x1,g.y+g.h,online.some(a=>check(a)==='bad')?'bad':online.every(a=>check(a)==='ok')?'ok':'unknown',d));
      });
    }
    const ob=box('outbus');
    if(lay!=='narrow'&&proc&&ob){
      const y=ob.y-14,p0=[proc.cx,proc.y+proc.h];
      for(const id of [...SERVICES.map(s=>s[0]),'other']){
        const s=box('svc:'+id);if(!s)continue;
        const on=id==='other'||!!svcOn(id),d=dimOf('svc:'+id);
        base.push(`<path d="${bus(p0,y,[s.cx,s.y])}" class="tp-pipe tp-out ${id==='other'?'tp-bad':on?'tp-on':'tp-off'}${d}" data-pipe="svc:${id}"/>`);
      }
    }
    const W=Math.round(S.width),H=Math.round(S.height);
    const html=`<defs><filter id="tp-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs><g>${aura.join('')}</g><g>${base.join('')}</g><g>${flows.join('')}</g><g data-tp="dots" filter="url(#tp-glow)"></g>`;
    if(wires._html!==html||wires._size!==W+'x'+H){
      wires.setAttribute('viewBox',`0 0 ${W} ${H}`);wires.innerHTML=html;wires._html=html;wires._size=W+'x'+H;
      pipes=new Map([...wires.querySelectorAll('[data-pipe]')].map(el=>[el.dataset.pipe,{el,len:el.getTotalLength()}]));
      for(const p of particles)p.dots=null;
    }
    const marked=marks.join('');
    if(fx._html!==marked||fx._size!==W+'x'+H){fx.setAttribute('viewBox',`0 0 ${W} ${H}`);fx.innerHTML=marked;fx._html=marked;fx._size=W+'x'+H;}
    placePins(box);
  }
  function placePins(box){
    const el=find('pins');
    if(!layers.threats){put('pins','');return;}
    put('pins',THREATS.map(([id,,label],i)=>`<button type="button" class="tp-pin${i<3?' tp-pin-hot':''}" data-tp-node="threat:${id}" aria-label="${t(label)}" title="${t(label)}">${i+1}</button>`).join(''));
    const firstHop=hops().find(h=>!h.key.startsWith('warp:')&&!h.key.startsWith('vpn:'));
    const at={operator:[box('operator'),b=>[b.x+b.w-2,b.y+2]],panel:[box('panel'),b=>[b.x+b.w-10,b.y]],host:[box('hosthead'),b=>[b.x+b.w-6,b.y+6]],
      route:[(firstHop&&box('hop:'+firstHop.key))||box('gate'),b=>[b.x+b.w-6,b.y]],entry:[box('entry:cloudflare'),b=>[b.x+b.w-6,b.y]],out:[box('outbus'),b=>[b.x+Math.min(b.w-14,240),b.y+4]]};
    [...el.children].forEach((pin,i)=>{const [b,pos]=at[THREATS[i][1]];pin.hidden=!b;if(!b)return;const [x,y]=pos(b);pin.style.left=Math.round(x)+'px';pin.style.top=Math.round(y)+'px';});
  }
  const schedule=()=>{if(!gframe)gframe=requestAnimationFrame(geometry);};

  function emit(key,count,cls,spread,back=false){
    if(!layers.traffic||motion.matches||document.hidden||!visible||!pipes.has(key))return;
    if(selected){const [k,id]=split(key);if((k==='tx'||k==='rx')&&!related('acc:'+id)||k==='svc'&&!related('svc:'+id)||k==='trunk'&&!related('dc:'+id)||k==='in'&&!related('panel'))return;}
    const now=performance.now(),n=Math.min(count,8);
    for(let i=0;i<n;i++)particles.push({key,cls,back,start:now+spread*i/Math.max(1,n)+Math.random()*140,dur:0,dots:null});
    if(particles.length>320)particles.splice(0,particles.length-320).forEach(p=>p.dots?.forEach(d=>d.remove()));
    if(!frame)frame=requestAnimationFrame(tick);
  }
  function tick(now){
    frame=0;const layer=wires.querySelector('[data-tp="dots"]');if(!layer||!visible)return;
    const alive=[];
    for(const p of particles){
      const pipe=pipes.get(p.key);if(!pipe){p.dots?.forEach(d=>d.remove());continue;}
      p.dur||=Math.max(900,Math.min(3200,pipe.len*3.2));
      const k=(now-p.start)/p.dur;
      if(k<0){alive.push(p);continue;}
      if(k>=1){p.dots?.forEach(d=>d.remove());continue;}
      if(!p.dots||!p.dots[0].isConnected){p.dots=[0,1,2].map(i=>{const c=document.createElementNS(SVGNS,'circle');c.setAttribute('r',String(3.2-i*.8));c.setAttribute('class','tp-dot '+p.cls);c.setAttribute('opacity',String(1-i*.3));layer.append(c);return c;});}
      p.dots.forEach((dot,i)=>{const q=Math.max(0,k-i*.016),at=pipe.el.getPointAtLength((p.back?1-q:q)*pipe.len);dot.setAttribute('cx',at.x.toFixed(1));dot.setAttribute('cy',at.y.toFixed(1));});
      alive.push(p);
    }
    particles=alive;
    if(particles.length&&visible)frame=requestAnimationFrame(tick);
  }
  function hit(id){const el=root.querySelector(`[data-tp-node="svc:${CSS.escape(id)}"]`);if(!el||motion.matches)return;el.classList.remove('tp-hit');void el.offsetWidth;el.classList.add('tp-hit');}
  function classify(e){
    const host=e.destination?.host||'',comp=e.component||'';
    if(e.destination?.telegram_network||comp==='telegram')return 'telegram';
    if(e.destination?.loopback)return 'local';
    for(const a of data.accounts){const s=a.services||{};
      if([...(s.replica?.endpoints||[]),...(s.storage?.endpoints||[])].some(p=>p.host===host))return 'storage';
      if((s.webhooks?.endpoints||[]).some(p=>p.host===host))return 'notify';
      if((s.analysis?.endpoints||[]).some(p=>p.host===host))return 'ai';
      if([...(s.timestamps?.endpoints||[]),...(s.calendars?.endpoints||[])].some(p=>p.host===host))return 'time';}
    const hitService=SERVICES.find(item=>item[4].test(host));if(hitService)return hitService[0];
    if(['proxy_catalog','guided_connection'].includes(comp)&&literal(host))return 'probe';
    if(['alerts','webhooks'].includes(comp))return 'notify';if(['replica','storage'].includes(comp))return 'storage';if(comp==='ai')return 'ai';
    if(['cloud','cloud_wizard','cloud_attestation','tdx','assurance','verify','capture_connections','mcp_server','witness','source_check'].includes(comp))return 'known';
    return 'other';
  }
  function merge(list){
    const fresh=[];
    for(const e of list||[]){if(typeof e?.id!=='number'||events.has(e.id))continue;e._node=classify(e);events.set(e.id,e);fresh.push(e);lastEvent=Math.max(lastEvent,e.id);}
    while(events.size>300)events.delete(events.keys().next().value);
    return fresh;
  }
  function animate(fresh){
    if(first||data.demo)return;
    const spread=Math.max(1200,Math.min(4800,performance.now()-polled)),narrow=stage.dataset.layout==='narrow';
    for(const a of shown()){
      const old=prev.get(a.id),act=a.activity||{},was=old?.activity||{};
      if(!old||!act.available||!was.available||old.run_id!==a.run_id||act.since!==was.since)continue;
      const tx=Math.max(0,act.calls-was.calls),rx=Math.max(0,act.ok-was.ok)+(act.last_update_at&&act.last_update_at!==was.last_update_at?1:0);
      if(tx)emit(narrow?'trunk:'+a.telegram?.dc:'tx:'+a.id,tx,'tp-c-tx',spread);
      if(rx)emit(narrow?'trunk:'+a.telegram?.dc:'rx:'+a.id,rx,'tp-c-rx',spread,true);
    }
    emit('in',1,'tp-c-in',0);
    for(const e of fresh.slice(-30)){
      const bad=e.outcome==='failed'||e._node==='other',cls=bad?'tp-c-bad':e.kind==='http_result'?'tp-c-rx':'tp-c-out';
      if(e._node==='telegram'&&e.workspace){const a=acc(e.workspace);if(a)emit(narrow?'trunk:'+a.telegram?.dc:'tx:'+a.id,1,'tp-c-tx',spread);}
      else if(e._node==='other'||SERVICES.some(([id])=>id===e._node)){emit('svc:'+e._node,1,cls,spread,e.kind==='http_result');hit(e._node);}
    }
  }
  function demoMotion(){
    clearInterval(demo);demo=null;
    if(!data?.demo||!visible||motion.matches||!layers.traffic)return;
    demo=setInterval(()=>{
      if(document.hidden||!data)return;
      const narrow=stage.dataset.layout==='narrow';
      for(const a of shown().filter(x=>x.state==='connected')){
        if(Math.random()>.4)continue;
        const n=1+Math.floor(Math.random()*2);
        if(narrow)emit('trunk:'+a.telegram?.dc,n,Math.random()<.5?'tp-c-tx':'tp-c-rx',800,Math.random()<.5);
        else{emit('tx:'+a.id,n,'tp-c-tx',800);if(Math.random()<.8)emit('rx:'+a.id,n,'tp-c-rx',900,true);}
      }
      if(Math.random()<.3){const on=SERVICES.filter(([id])=>svcOn(id));if(on.length){const [id]=on[Math.floor(Math.random()*on.length)];emit('svc:'+id,1,'tp-c-out',400);hit(id);}}
      if(Math.random()<.25)emit('in',1,'tp-c-in',0);
    },900);
  }

  function renderLog(){
    const tr2=data.traffic||{};
    find('total').textContent=tr2.available?String(tr2.total??0):'';
    if(!tr2.available){put('log',`<p class="tp-empty">${t('Request observer is not available in this build.')}</p>`);return;}
    const label=id=>acc(id)?.label,all=[...events.values()],answered=new Set(all.map(e=>e.parent).filter(Boolean));
    const why=e=>e.component==='proxy_catalog'&&e.kind==='connect_attempt'?'proxy check':e.component==='anchoring'?(e._node==='drand'?'time beacon':e._node==='cloudflare'?'Gateway DNS log':'timestamp'):PURPOSE[e.component]||e.component||'';
    put('log',all.filter(e=>!(e.kind==='http_request'&&answered.has(e.id))).slice(-90).reverse().map(e=>{
      const bad=e.outcome==='failed'||e._node==='other',tone=bad?'bad':e._node==='telegram'?'tx':e._node==='local'?'in':'out';
      const res=e.status?String(e.status):e.error?e.error:e.kind==='dns_lookup'?'dns':e.kind==='connect_attempt'?'connect':'…';
      return `<div class="tp-line tp-l-${tone}"><time>${esc(clock12(e.at))}</time><span class="tp-l-who">${esc(label(e.workspace)||tr('system'))}</span><span class="tp-l-dst">→ ${esc(addr(e.destination))}</span><span class="tp-l-why">${esc(tr(why(e)))}</span><span class="tp-l-res">${esc(res)}${e.duration_ms!=null?' · '+esc(e.duration_ms)+'ms':''}</span></div>`;
    }).join('')||`<p class="tp-empty">${t('Waiting for requests…')}</p>`);
  }
  function renderPorts(){
    const rows=[],l=data.ingress.listener;
    if(l)rows.push(['in',':'+l.port,tr('Panel'),tr(local(l.host)?'listens on loopback':'listens on the network')]);
    for(const c of sidecars())if(c.on&&c.port)rows.push(['car',':'+c.port,tr(c.label),tr('recorder endpoint')]);
    for(const a of data.accounts){
      if(a.route?.helper?.port)rows.push(['tun',':'+a.route.helper.port,'wireproxy · '+a.label,tr('listens on loopback')]);
      if(a.socket?.local)rows.push(['tg',':'+a.socket.local.port,a.label,'→ '+addr(a.socket.peer,!a.socket.peer?.telegram_network&&!local(a.socket.peer?.host))+(a.telegram?.dc?' · DC'+a.telegram.dc:'')]);
      for(const m of a.media||[])if(m.socket?.local)rows.push(['tg',':'+m.socket.local.port,a.label+' · '+tr('media'),'→ '+addr(m.socket.peer,!m.socket.peer?.telegram_network)+' · DC'+m.dc]);
    }
    put('ports',rows.map(([kind,port,who,dir])=>`<div class="tp-prow tp-p-${kind}"><b>${esc(port)}</b><span>${esc(who)}</span><em>${esc(dir)}</em></div>`).join('')||`<p class="tp-empty">${t('No open sockets right now.')}</p>`);
  }
  function renderCard(){
    if(!selected){card.hidden=true;return;}
    const [k,id]=split(selected),rows=[],kv=(a,b)=>rows.push(`<div><dt>${t(a)}</dt><dd>${esc(b??'—')}</dd></div>`),note=text=>rows.push(`<p>${t(text)}</p>`);
    let title='',sub='';
    if(k==='acc'){const a=acc(id);if(!a){selected=null;return renderCard();}
      const r=a.route||{},act=a.activity||{},st=check(a);title=a.label;sub=tr(a.state);
      kv('Route',tr(ROUTE[routeOf(a)]||routeOf(a)));if(r.gateway)kv('Next hop',addr(r.gateway,true));if(r.helper)kv('Local tunnel','wireproxy 127.0.0.1:'+r.helper.port);
      kv('Socket',a.socket?.local?':'+a.socket.local.port+' → '+addr(a.socket.peer,!a.socket.peer?.telegram_network&&!local(a.socket.peer?.host)):'—');
      kv('Telegram',a.telegram?.endpoint?'DC'+a.telegram.dc+' · '+addr(a.telegram.endpoint):'—');kv('Telegram range',target(a)?.telegram_network||'—');
      kv('IP protection',tr({hide:'hidden · no direct fallback',fallback:'direct as last resort',tunnel:'tunnel mode'}[r.exposure]||'—'));
      kv('HTTPS out',a.outside?.enabled?tr(ROUTE[a.outside.route]||a.outside.route):tr('off'));
      if(act.available)kv('Calls / responses',act.calls+' / '+act.ok);
      kv('Vault',tr(a.storage?.key_mode==='external'?'external master key':'local key'));
      if(st==='bad')note('This direct socket is outside the published Telegram networks.');
      else if(st&&routeOf(a)!=='direct')note("Through a proxy the session target is checked. The proxy's onward connection is not observed.");
      rows.push(`<button type="button" class="tp-btn" data-tp-action="open">${icon('settings')}${t('Connection settings')}</button>`);}
    else if(k==='dc'){const dc=data.telegram.datacenters.find(x=>String(x.id)===id);title='DC'+id;sub=tr(dc?.city||'');
      kv('Address',dc?(dc.address+':'+dc.port):'—');kv('Range',dc?.network);kv('Accounts',data.accounts.filter(a=>String(a.telegram?.dc)===id).map(a=>a.label).join(', ')||'—');}
    else if(k==='hop'){const h=hops().find(x=>x.key===id),a=h?.accounts[0];if(!a){selected=null;return renderCard();}
      title=tr(ROUTE[routeOf(a)]||routeOf(a));sub=tr('Accounts: {n}',{n:h.accounts.length});
      kv('Endpoint',a.route.gateway?addr(a.route.gateway,true):'127.0.0.1:'+(a.route.helper?.port??'—'));if(a.route.source)kv('List',a.route.source);
      if(a.route.check?.exit_ip)kv('Exit',addr({host:a.route.check.exit_ip},true)+' '+(a.route.check.country||''));
      const pool=a.route.pool||data.pool?.state;if(pool)kv('Pool',tr('{healthy} of {listed} healthy',{healthy:pool.healthy,listed:pool.listed}));
      note(routeOf(a)==='warp'||routeOf(a)==='vpn'?'A local WireGuard helper carries this account.':'MTProxy carries Telegram traffic only. Its operator sees the server address and timing, not message content.');}
    else if(k==='svc'){const s=SERVICES.find(x=>x[0]===id);title=s?.[2]||tr('Unlisted host');sub=s?tr(s[3]):'';
      kv('Status',tr(id==='other'?'review':svcOn(id)?'in use':'off'));
      [...events.values()].filter(e=>e._node===id).slice(-5).reverse().forEach(e=>kv(clock12(e.at),addr(e.destination)+' · '+(e.status||e.error||e.kind)));}
    else if(k==='gate'){const up=data.accounts.filter(a=>a.state==='connected');title=tr('Telegram only');sub=tr('account connections');
      kv('Verified now',up.filter(a=>check(a)==='ok').length+' / '+up.length);
      note('Each connected account socket is compared with the published Telegram networks. This is a check, not a host firewall.');
      (data.telegram.networks||[]).forEach(n=>rows.push(`<code>${esc(n)}</code>`));}
    else if(['entry','operator','panel','door'].includes(k)){const i=data.ingress;title=tr('Panel access');
      sub=tr({loopback:'loopback · this machine or SSH',cloudflare:'via Cloudflare',reverse_proxy:'via reverse proxy',network:'open network port'}[i.via]||'');
      kv('Listener',i.listener?addr(i.listener):'—');kv('Published',i.published?.kind==='quick'?'trycloudflare.com':i.published?.kind==='domain'?(reveal?i.published.host:tr('your domain')):'—');
      kv('Key',tr(i.token_source==='environment'?'bearer · TGWITNESS_TOKEN':'bearer · panel-token.txt'));kv('Scoped grants',i.grants);kv('IP allowlist',i.allowed_networks||tr('off'));
      if(i.deployment?.ssh)kv('SSH',tr(i.deployment.ssh==='disabled'?'off':'on'));
      (i.sessions||[]).forEach(s=>kv(s.admin?'admin':s.label,(reveal?s.address:'•••')+' · '+clock12(s.last_seen_at)));}
    else if(k==='car'){const c=sidecars().find(x=>x.id===id);title=tr(c?.label||id);sub=tr(c?.kind||'');kv('Status',tr(c?.on?'on':'not connected'));if(c?.port)kv('Port',':'+c.port);
      if(id==='tunnel')note('cloudflared opens an outbound connection to Cloudflare. No inbound port is needed for the panel.');
      if(id==='witness')note('A separate witness reads signed checkpoints with a read-only token and keeps its own key.');}
    else if(k==='host'){const h=data.host;title=tr(hostTitle());sub=tr(mainKind());kv('System',[h.os,h.machine].filter(Boolean).join(' · '));kv('TgWitness',h.version);
      kv('Started',clock12(h.started_at));kv('Container',tr(h.container?'yes':'no'));kv('Provider',h.provider||'—');kv('TDX quote',tr(h.tdx?'yes':'no'));
      note('All accounts run in this one process. Each account has its own directory, signing key and encrypted vault.');}
    else if(k==='vault'){title=tr('Encrypted vault per account');sub=tr('session · API keys · signing key');
      data.accounts.forEach(a=>kv(a.label,tr(a.storage?.key_mode==='external'?'external master key':'local key')+(reveal&&a.storage?.vault?' · '+a.storage.vault:'')));
      note('The journal and media are signed for integrity. The application does not encrypt them.');}
    else if(k==='out'){title=tr('HTTPS out');sub=tr('per-account route');data.accounts.forEach(a=>kv(a.label,a.outside?.enabled?tr(ROUTE[a.outside.route]||a.outside.route):tr('off')));
      kv('Private hosts',tr(data.policy?.private_destinations?'allowed':'refused'));note('MTProxy cannot carry these requests. They use Direct, SOCKS5 or HTTP, or stay off.');}
    else if(k==='threat'){const th=THREATS.find(x=>x[0]===id);if(!th){selected=null;return renderCard();}title=tr(th[2]);rows.push(`<p>${t(th[3])}</p>`);}
    card.hidden=false;
    const html=`<header><div><strong>${esc(title)}</strong><span>${esc(sub)}</span></div><button type="button" class="tp-x" data-tp-action="close" aria-label="${t('Close')}">${icon('x')}</button></header><dl>${rows.join('')}</dl>`;
    if(card._html!==html){card.innerHTML=html;card._html=html;}
  }
  function live(){
    const age=received?Math.floor((Date.now()-received)/1000):0,stale=failed||age>15;
    root.classList.toggle('tp-stale',!!data&&stale);
    const el=find('live');if(el)el.textContent=!data?tr('connecting…'):data.demo?tr('demo data'):stale?tr('stale'):tr('live · {n}s',{n:age});
  }
  function renderAll(){
    if(!data)return;
    stage.dataset.layout=layoutOf();
    root.classList.toggle('tp-noports',!layers.ports);root.classList.toggle('tp-threats',layers.threats);root.classList.toggle('tp-demo',!!data.demo);
    put('you',youHTML());put('entry',entryHTML());put('hosthead',t(remote()?'Server':'Computer'));
    if(put('host',hostHTML())){const rows=Math.min(shown().length,ROWS);find('accs')?.style.setProperty('--tp-rh',(rows<=8?36:rows<=14?31:rows<=24?27:23)+'px');}
    put('hops',hopsHTML());put('gate',gateHTML());put('tg',tgHTML());put('out',outHTML());put('legend',legendHTML());
    counts();renderModes();renderKpis();renderLog();renderPorts();renderCard();dims();live();schedule();
  }
  async function load(){
    if(!visible||document.hidden)return;
    clearTimeout(timer);request?.abort();const serial=++generation,controller=new AbortController();request=controller;
    const parent=options()?.signal,abort=()=>controller.abort();parent?.addEventListener('abort',abort,{once:true});
    const deadline=setTimeout(()=>controller.abort('timeout'),15000);if(parent?.aborted)controller.abort();
    try{
      const result=await json('topology?after='+lastEvent,undefined,{root:true,signal:controller.signal});
      if(serial!==generation||!visible||controller.signal.aborted)return;
      if(result.schema!=='tgwitness-topology-v1'||!Array.isArray(result.accounts))throw new Error(tr('Topology data is unavailable.'));
      const wasDemo=!!data?.demo;data=result;received=Date.now();failed=false;find('error').hidden=true;
      const fresh=merge(result.traffic?.events);renderAll();
      requestAnimationFrame(()=>{if(serial===generation)animate(fresh);prev=new Map(result.accounts.map(a=>[a.id,a]));polled=performance.now();first=false;});
      if(!!data.demo!==wasDemo||data.demo&&!demo)demoMotion();
    }catch(error){
      if(serial!==generation||!visible||controller.signal.aborted&&controller.signal.reason!=='timeout')return;
      failed=true;const e=find('error');e.hidden=false;e.textContent=tr('Refresh failed. Showing the last snapshot.');live();
    }finally{
      clearTimeout(deadline);parent?.removeEventListener('abort',abort);
      if(serial===generation){request=null;if(visible&&!document.hidden)timer=setTimeout(load,3000);}
    }
  }
  function choose(key){selected=!key||selected===key?null:key;renderCard();dims();if(card._html&&!card.hidden)card.scrollTop=0;wires._html=null;schedule();}
  function clearDots(){particles.forEach(p=>p.dots?.forEach(d=>d.remove()));particles=[];}
  root.addEventListener('click',event=>{
    if(!data)return;
    const node=event.target.closest('[data-tp-node]');if(node&&!event.target.closest('[data-tp-action]')){choose(node.dataset.tpNode);return;}
    const layer=event.target.closest('[data-tp-layer]');
    if(layer){const id=layer.dataset.tpLayer;layers[id]=!layers[id];layer.setAttribute('aria-pressed',String(layers[id]));if(id==='traffic'&&!layers[id])clearDots();
      if(id==='threats'&&!layers[id]&&selected?.startsWith('threat:'))selected=null;wires._html=null;renderAll();demoMotion();return;}
    const button=event.target.closest('[data-tp-action]');if(!button)return;
    const action=button.dataset.tpAction;
    if(action==='refresh')void load();
    else if(action==='close')choose(null);
    else if(action==='reveal'){reveal=!reveal;button.setAttribute('aria-pressed',String(reveal));renderAll();}
    else if(action==='open'){const [,id]=split(selected||'');Promise.resolve(openSettings?.(id,'connection')).catch(error=>toast(error.message,true));}
  },{signal:listeners.signal});
  root.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&selected){choose(null);return;}
    if(event.key!=='Enter'&&event.key!==' ')return;
    const node=event.target.closest?.('[data-tp-node]');if(!node||!data||node.tagName==='BUTTON')return;event.preventDefault();choose(node.dataset.tpNode);
  },{signal:listeners.signal});
  document.addEventListener('visibilitychange',()=>{if(!visible)return;if(document.hidden){clearTimeout(timer);request?.abort();generation++;clearDots();}else void load();},{signal:listeners.signal});
  motion.addEventListener('change',()=>{if(motion.matches)clearDots();wires._html=null;schedule();demoMotion();},{signal:listeners.signal});
  const resize=new ResizeObserver(()=>{if(!visible||!data)return;if(layoutOf()!==stage.dataset.layout){wires._html=null;renderAll();}else schedule();});
  resize.observe(stage);
  function leave(){visible=false;generation++;request?.abort();request=null;clearTimeout(timer);clearInterval(clock);clearInterval(demo);demo=null;cancelAnimationFrame(frame);cancelAnimationFrame(gframe);frame=0;gframe=0;clearDots();}
  return {
    async enter(){leave();if(getState().view!=='topology'||!getState().me?.admin)return;visible=true;first=!data;clock=setInterval(live,1000);live();if(data){wires._html=null;renderAll();demoMotion();}await load();},
    leave,
    resetSession(){leave();data=null;selected=null;reveal=false;lastEvent=0;first=true;prev.clear();events.clear();
      for(const n of ['modes','kpis','log','ports','you','entry','hosthead','host','hops','gate','tg','out','legend','pins'])put(n,'');
      wires.replaceChildren();wires._html=null;fx.replaceChildren();fx._html=null;card.hidden=true;card._html='';find('error').hidden=true;root.classList.remove('tp-stale','tp-demo');
      root.querySelector('[data-tp-action="reveal"]').setAttribute('aria-pressed','false');live();},
    destroy(){leave();resize.disconnect();listeners.abort();},
  };
}
