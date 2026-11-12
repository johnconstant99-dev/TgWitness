import {createGroupSettings} from './group-settings.js?v=1';
import {accountState} from '../components/account-state.js';

export function createSettingsHub(ctx) {
  const {root, wizardRoot, state, json, tr, node, toast, navigate, askConfirm, $, refreshStatus} = ctx;
  const rank = {simple:0, standard:1, expert:2};
  const goals = [['copy','📥','Just download','Save chats and files once. Nothing keeps running in the background. The archive is signed, and verify.py checks every file in it.'],['watch','👁','Follow chats','Keep new messages and their changes, with independent timestamps from a third party that the recipient checks. Needs requests outside Telegram.'],['evidence','⚖','Evidence for a case','Record continuously with independent timestamps from a third party that the recipient checks. Needs requests outside Telegram.']];
  const goalLevels = {copy:'simple',watch:'standard',evidence:'standard'};
  const routes = [['auto','✨','Automatic','Try WARP, then public proxies.'],['warp','🛡','Cloudflare WARP','Connect through a local tunnel.'],['proxy','🔌','My proxy','Paste one proxy address.'],['direct','🌐','Direct','Telegram will see this server’s address.']];
  const levels = [['simple','🙂','Simple','Only the essentials.'],['standard','⚙','Standard','Common settings and explanations.'],['expert','🛠','Expert','All fields, limits and technical details.']];
  const navLevels = {'system-map':'expert',topology:'expert',start:'simple',chats:'simple',observations:'simple',evidence:'simple',settings:'simple',
    board:'standard',accounts:'simple',access:'standard',sources:'standard',connection:'expert',witness:'expert',analysis:'expert',
    parameters:'expert','system-log':'expert',integrations:'expert',sealed:'expert'};
  let data=null, prefs=null, draft=null, section=null, generation=0, connectionBusy=false, checkTimer=null, statusTimer=null;
  let dialogs=null, moved=[], query='', reveal=new Set(), editing=false;
  let autoTried=false, routeDirty=false, checkFailure=null;
  let live=null, liveTimer=null, visited=0, recordedStep=null, shownSession=null, methodShown=false;
  let shownStep=null, shownStage=null, levelChosen=false, moreOpen=false;
  let groupScope=null;
  let preferencesQueue=Promise.resolve(), draftQueue=Promise.resolve(), preferencesSequence=0, draftSequence=0, checkSequence=0;
  const owner=()=>({generation,profile:state.profile,token:state.token,revision:state.workspaceRevision});
  const signedIn=()=>{const account=accountState(state.status||{});return account.hasSession&&!account.needsSignIn;};
  const current=who=>who.generation===generation&&who.profile===state.profile&&who.token===state.token&&who.revision===state.workspaceRevision;
  function requireOwner(who){
    if(!current(who))throw ctx.staleView();
  }
  async function request(who,path,body){
    requireOwner(who);
    const result=await json(path,body,{profile:who.profile,token:who.token});
    requireOwner(who);return result;
  }
  async function confirm(who,message){
    requireOwner(who);const accepted=await askConfirm(message);requireOwner(who);return accepted;
  }
  async function refresh(who){requireOwner(who);await refreshStatus();requireOwner(who);}
  const label=(value)=>tr({copy:'Just download',watch:'Follow chats',evidence:'Evidence',photos:'Photos up to 20 MB',
    short_media:'Photos and videos up to 60 seconds / 20 MB',all:'All files up to 1 GB',custom:'Custom file limits',
    auto:'Automatic',hide:'No, hide it',simple:'Simple',standard:'Standard',expert:'Expert',
    account:'All chats',selected:'Choose chats',folder:'Telegram folder',warp:'Cloudflare WARP',proxy:'My proxy',direct:'Direct',
    mtproxy_auto:'Automatic',mtproxy:'My proxy',socks5:'My proxy',http:'My proxy',vpn:'VPN'}[value]||String(value));
  const describe=value=>typeof value==='boolean'?tr(value?'On':'Off'):label(value);
  const sharedNames={goal:'Goal',monitoring:'What to record',recheck:'Recheck schedule',alert_rules:'Notification rules',
    reports:'Report settings',route:'Connection route'};
  const groupView=createGroupSettings({json,tr,trn:ctx.trn,node,toast,askConfirm,button,message,cards,label,describe,goals,run,root,
    fields:()=>data?.fields||[],openConnection:ctx.openConnection,back:async()=>{groupScope=null;data=await request(owner(),'settings');render();}});
  function button(text, fn, style='secondary') { const el=node('button',style,tr(text));el.type='button';el.onclick=()=>run(fn,el);return el; }
  async function run(fn, control) { if(control)control.disabled=true;try{return await fn();}catch(e){if(e.name!=='StaleView')toast(e.message,true);}finally{if(control?.isConnected)control.disabled=false;} }
  function message(text, cls='hint') { return node('p',cls,tr(text)); }
  function title(box,text){box.append(node('h2','',tr(text)));}
  function select(text, choices, value, fn) {
    const wrap=node('label','hub-label',tr(text)), el=node('select');
    for(const [key,name] of choices)el.append(new Option(tr(name),key));el.value=value;el.onchange=()=>run(()=>fn(el.value));wrap.append(el);return wrap;
  }
  function cards(box, entries, value, fn) {
    const group=node('div','answer-cards');group.setAttribute('role','group');
    for(const [key,emoji,name,note] of entries){
      const b=button('',()=>fn(key),'answer-card');b.dataset.answer=key;b.setAttribute('aria-pressed',String(key===value));
      b.append(node('span','answer-icon',emoji),node('strong','',tr(name)),node('span','hint',tr(note)));group.append(b);
    }box.append(group);
  }
  function restoreMoved(){for(const [el,marker] of moved){marker.replaceWith(el);}moved=[];}
  function move(el, host){if(!el)return;const marker=document.createComment('settings-form');el.before(marker);host.append(el);moved.push([el,marker]);}
  function lastLevel(){try{const value=localStorage.getItem('tgwitness-ui-level');return ['simple','standard','expert'].includes(value)?value:'simple';}catch{return 'simple';}}
  function applyPresentation() {
    if(!prefs)return;
    ctx.catalog();
    document.documentElement.dataset.uiLevel=prefs.level;
    try{localStorage.setItem('tgwitness-ui-level',prefs.level);}catch{}
    for(const b of document.querySelectorAll('.sidebar .nav[data-view]'))b.dataset.level=navLevels[b.dataset.view]||'expert';
    for(const [view,simple,full] of [['start','Home','Home'],['observations','Journal','Journal'],['evidence','Exports','Exports']]){
      const b=document.querySelector('.sidebar [data-view="'+view+'"]');
      const text=[...b.childNodes].find(n=>n.nodeType===3&&n.textContent.trim());if(text)text.textContent=' '+tr(prefs.level==='simple'?simple:full)+' ';
    }
    for(const control of document.querySelectorAll('[data-ui-level]'))control.value=prefs.level;
    ctx.applyPreferences(prefs);
  }
  function savePreferences(patch,who=owner()){
    requireOwner(who);
    prefs={...prefs,...patch};const body={...prefs}, sequence=++preferencesSequence;
    preferencesQueue=preferencesQueue.catch(()=>{}).then(async()=>{
      const result=await request(who,'preferences',body);
      if(sequence===preferencesSequence){prefs=result.saved;applyPresentation();}
    });return preferencesQueue;
  }
  async function bootstrap({openFirstRun=true}={}) {
    const who=owner(), initialRoute=location.href, draftVersion=draftSequence, preferenceVersion=preferencesSequence;
    const demo=state.status?.demo||window.TGW_ONLINE_DEMO;
    for(const control of document.querySelectorAll('[data-ui-level]'))control.hidden=!!demo;
    if(demo){$('hub-route-status').hidden=true;return;}
    const loaded=await request(who,'preferences');
    if(preferenceVersion===preferencesSequence)prefs=loaded.saved||{language:ctx.language,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC',theme:'system',level:lastLevel(),...(prefs||{})};
    const requestedLanguage=new URL(location.href).searchParams.get('lang');
    if(requestedLanguage===ctx.language&&prefs.language!==requestedLanguage)await savePreferences({language:requestedLanguage},who);
    else if(!loaded.saved)await savePreferences({},who);else applyPresentation();
    requireOwner(who);
    if(prefs.language!==ctx.language){await ctx.changeLanguage(prefs.language);return;}
    if(!state.me?.admin||state.status?.demo)return;
    const loadedSettings=await request(who,'settings');
    if(draftVersion!==draftSequence){scheduleStatus();return;}
    data=loadedSettings;draft={...data.wizard};
    if(openFirstRun&&location.href===initialRoute&&!draft.completed&&!draft.skipped)await navigate('first-run');
    requireOwner(who);
    scheduleStatus();
  }
  async function load(wanted=null){
    const who=owner();
    if(state.status?.demo){root.replaceChildren(message('Demo workspace. Connect accounts in your live installation.'));return;}
    if(!state.me?.admin){root.replaceChildren(message('Only the workspace administrator can change collection settings.'));return;}
    if(!prefs){const result=await request(who,'preferences');prefs=result.saved||{language:ctx.language,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC',theme:'system',level:lastLevel(),...(prefs||{})};applyPresentation();}
    data=await request(who,'settings');draft={...data.wizard};
    visited=Math.max(visited,draft.step);
    if(state.view==='first-run'&&wanted&&wanted!==draft.step&&wanted<=visited&&!live){
      recordedStep=wanted;
      try{await saveDraft({step:wanted},who);}catch(error){if(error.name==='StaleView')throw error;toast(error.message,true);recordedStep=null;}
    }
    if(state.view==='first-run')await renderWizard(who);else render();
    requireOwner(who);
    updateIndicator(data.connection);
  }
  function saveDraft(patch={},who=owner()){
    requireOwner(who);
    draft={...draft,...patch};const body=draftBody(), sequence=++draftSequence;
    draftQueue=draftQueue.catch(()=>{}).then(async()=>{
      let result;
      try{result=await request(who,'first-run',body);}catch(error){
        if(current(who)&&sequence===draftSequence&&data?.wizard)draft={...data.wizard};
        throw error;
      }
      data=result;if(sequence===draftSequence)draft={...result.wizard};
    });return draftQueue;
  }
  async function applyGoal(goal,{first=false,keep=false}={},who=owner()){
    const plan=await request(who,'settings/goal/preview',{goal,keep_manual:keep});
    const text=plan.diff.map(row=>tr(data.fields.find(f=>f.key===row.key)?.label||row.key)+': '+describe(row.before)+' → '+describe(row.after)).join('\n');
    if(!first&&!await confirm(who,tr('Change goal?')+'\n\n'+(text||tr('The settings already match.'))))return false;
    data=await request(who,'settings/goal',{goal,revision:plan.revision,keep_manual:keep});
    await refresh(who);return true;
  }
  async function edit(key,value,who=owner()){
    requireOwner(who);const revision=data.revision,values={...data.values};
    try{
      let allow_outside=false,disable_dependents=false;
      if(['timestamps','drand','notifications','replica'].includes(key)&&value&&!values.outside){
        allow_outside=await confirm(who,tr('This feature needs external requests. Allow them?'));if(!allow_outside)return;
      }
      if(key==='outside'&&!value&&(values.timestamps||values.drand||values.notifications||values.replica)){
        disable_dependents=await confirm(who,tr('Turn off the dependent features too?'));if(!disable_dependents)return;
      }
      data=await request(who,'settings/edit',{key,value,allow_outside,disable_dependents,revision});await refresh(who);
    }finally{if(current(who)&&state.view==='settings')render();}
  }
  function preferencesForm(box,{language=true}={}){
    if(language)box.append(select('Language',Object.entries(ctx.languages),prefs.language,async value=>{const who=owner();await savePreferences({language:value},who);requireOwner(who);await ctx.changeLanguage(value);}));
    box.append(select('Theme',[['system','System theme'],['light','Light theme'],['dark','Dark theme']],prefs.theme,value=>savePreferences({theme:value})));
    const zones=[...new Set([prefs.timezone,Intl.DateTimeFormat().resolvedOptions().timeZone,'UTC',...(Intl.supportedValuesOf?.('timeZone')||[])])];
    box.append(select('Time zone',zones.map(x=>[x,x]),prefs.timezone,value=>savePreferences({timezone:value})));
  }
  function fieldRow(f){
    const row=node('div','hub-field');row.dataset.level=f.level;row.dataset.setting=f.key;
    const heading=node('div');heading.append(node('strong','',tr(f.label)));
    const explanations={timestamps:'Independent services confirm when records existed.',drand:'Adds a public randomness beacon to records so their recording time can be checked.',outside:'Timestamps, notifications and off-site copies contact services outside Telegram.',files:'Files larger than the selected limit are recorded without downloading their contents.'};
    if(prefs.level==='standard'&&explanations[f.key]){
      const help=node('details','setting-help');help.append(node('summary','', '?'),message(explanations[f.key]));
      help.querySelector('summary').setAttribute('aria-label',tr('Explain this setting'));heading.append(help);
    }
    const mark=inheritMark(f.key);
    if(mark)heading.append(mark);else if(f.modified)heading.append(node('span','modified-tag',tr('Changed by you')));
    row.append(heading);
    if(f.type==='bool'){
      const control=node('input');control.type='checkbox';control.checked=f.value;control.setAttribute('aria-label',tr(f.label));
      control.onchange=()=>run(()=>edit(f.key,control.checked),control);row.append(control);
    }else{
      const values=f.key==='files'?[...(f.value==='custom'?['custom']:[]),'photos','short_media','all']:['hide','auto'];
      const field=select(f.label,values.map(v=>[v,label(v)]),f.value,v=>edit(f.key,v));
      if(f.value==='custom')field.querySelector('option').disabled=true;row.append(field);
    }
    if(f.modified&&!mark)row.append(button('Restore goal value',async()=>{
      const who=owner(),plan=await request(who,'settings/goal/preview',{goal:data.goal});await edit(f.key,plan.values[f.key],who);
    },'text-link'));
    return row;
  }
  const inherited=key=>data?.inheritance?.keys?.[key];
  async function adoptGroup(keys,who=owner()){
    requireOwner(who);
    await json('profile-groups/'+encodeURIComponent(data.inheritance.group.id)+'/settings/adopt',{profiles:[who.profile],keys},{root:true,token:who.token});
    data=await request(who,'settings');render();await refresh(who);
  }
  function revertKey(key){
    const item=inherited(key);
    if(key==='route')return ctx.openConnection({scope:'account',mode:item.group_value.mode});
    if(data.fields.some(f=>f.key===key))return edit(key,item.group_value);
    return adoptGroup([key]);
  }
  function inheritMark(key){
    const item=inherited(key);if(!item)return null;
    const box=node('span','inherit-mark '+item.source);box.dataset.inherit=item.source;
    box.append(node('span','inherit-source',item.source==='group'?'🔗 '+tr('From the group'):'✏️ '+tr('Own value')));
    if(item.source==='own')box.append(button('Return to the group value',()=>revertKey(key),'text-link'));
    return box;
  }
  function sharedName(key){return key.startsWith('parameter:')?data.parameters.find(p=>p.key===key)?.label||key:sharedNames[key]||key;}
  async function openGroup(id){await groupView.load(id);groupScope=id;section=null;query='';render();}
  function openSection(name){section=name;query='';render();root.querySelector('h2')?.focus();}
  function render(){
    restoreMoved();if(!data||!prefs)return;
    if(groupScope&&groupView.data){groupView.render(root);return;}
    root.replaceChildren();
    const header=node('div','hub-heading');header.append(node('div','eyebrow',tr('One place for every answer')),node('h1','',tr('Settings')));root.append(header);
    const inheritance=data.inheritance;
    if(inheritance){
      const note=node('div','notice hub-group-note');
      note.append(node('span','',tr('This account is in the group {name}.',{name:inheritance.group.label})+' '+
        tr('🔗 marks a value from the group; ✏️ marks this account’s own value.')),
        button('Group settings',()=>openGroup(inheritance.group.id),'text-link'));
      root.append(note);
    }
    const search=node('input','hub-search');search.type='search';search.placeholder=tr('Search all settings, including hidden ones');search.setAttribute('aria-label',search.placeholder);search.value=query;
    search.oninput=()=>{query=search.value;renderResults(results);};root.append(search);
    const results=node('div','hub-results');root.append(results);renderResults(results);
    const overview=node('div','hub-grid');overview.hidden=!!query||!!section;root.append(overview);
    const summaries=[['appearance','Language, time and appearance',ctx.languages[prefs.language]+' · '+prefs.timezone],['level','Interface level',label(prefs.level)],
      ['goal','Goal',data.goal?label(data.goal):tr('Choose a goal')],['connection','Connection',label(data.connection.mode)],
      ['telegram','Telegram account',signedIn()?tr('Connected'):tr('Not connected')],
      ['chats','Which chats?',label(data.wizard.scope||'account')],['collection','Collection and files',label(data.values.files)],
      ['protection','Record protection',tr(data.values.timestamps?'On':'Off')],['notifications','Notifications and off-site copy',tr(data.values.notifications?'On':'Off')]];
    if(inheritance){
      const keys=Object.values(inheritance.keys),own=keys.filter(k=>k.source==='own').length;
      summaries.push(['group','Shared with the group',inheritance.group.label+' · '+(own?ctx.trn('{n} own value','{n} own values',own):tr('follows the group'))]);
    }
    for(const [id,name,summary] of summaries){const b=button('',()=>openSection(id),'hub-summary');b.dataset.section=id;
      b.append(node('strong','',tr(name)),node('span','hint',summary),node('span','hub-arrow','→'));overview.append(b);}
    const detail=node('section','hub-detail');detail.hidden=!section;root.append(detail);
    if(section){
      detail.append(button('Back to settings',async()=>{data=await request(owner(),'settings');section=null;render();},'text-link'));
      title(detail,summaries.find(s=>s[0]===section)?.[1]||'Settings');
      if(section==='appearance')preferencesForm(detail);
      if(section==='level')cards(detail,levels,prefs.level,async level=>{await savePreferences({level});render();});
      if(section==='group'&&inheritance){
        const keys=Object.keys(inheritance.keys).filter(k=>k!=='goal'&&!data.fields.some(f=>f.key===k));
        detail.append(message(keys.length?'Settings the group shares besides those in the other sections:':'The group shares only settings shown in the other sections.'));
        for(const key of keys){
          const row=node('div','hub-field');row.dataset.setting=key;const heading=node('div');
          heading.append(node('strong','',tr(sharedName(key))),inheritMark(key));row.append(heading);detail.append(row);
        }
        detail.append(button('Group settings',()=>openGroup(inheritance.group.id)));
      }
      if(section==='goal'){
        const goalMark=inheritMark('goal');if(goalMark)detail.append(goalMark);
        const keep=node('input');keep.type='checkbox';const keepLabel=node('label','check-label');keepLabel.append(keep,document.createTextNode(tr('Keep my manual changes')));detail.append(keepLabel);
        cards(detail,goals,data.goal,async goal=>{await applyGoal(goal,{keep:keep.checked});render();});
      }
      if(section==='connection')connectionForm(detail,false);
      if(section==='telegram')move(ctx.authCard(),detail);
      if(section==='chats'){detail.append(message('Choose all chats, individual chats or a Telegram folder.'));
        detail.append(button('Choose chats',async()=>{await saveDraft({step:6,unchecked:true});await navigate('first-run');}));}
      const fields=data.fields.filter(f=>f.section===section&&f.key!=='ip');
      const hidden=fields.filter(f=>rank[f.level]>rank[prefs.level]&&!reveal.has(section));
      for(const f of fields.filter(f=>!hidden.includes(f)))detail.append(fieldRow(f));
      if(hidden.length)detail.append(button(tr('Show {n} more settings',{n:hidden.length}),()=>{reveal.add(section);render();},'text-link'));
      if(section==='notifications'){
        if(data.needs_notification_destination)detail.append(message('Notifications are enabled. Add a destination to receive them.','notice warning'));
        detail.append(button('Notification destinations',()=>openForm('alerts-form')),button('Off-site copy',()=>openForm('replica-form')));
      }
      if(section==='protection')detail.append(button('Advanced protection settings',()=>openForm('evidence-form')));
      if(data.collection_problem&&section==='collection')detail.append(message('Collection could not start. Check the connection and selected chats.','notice warning'));
      if(data.outside_problem&&['connection','protection','notifications'].includes(section))detail.append(message('External services need a working SOCKS5 or WARP route.','notice warning'));
    }
    const more=node('details','hub-more');more.hidden=!!section;more.append(node('summary','',tr('More settings and expert tools')));
    for(const [view,text] of [['sources','Recording rules'],['parameters','Parameters'],['access','Access'],['integrations','Integrations / MCP'],['system-log','System log'],['sealed','GitHub Actions']]){
      const b=button(text,()=>openAdvanced(view));b.dataset.level=navLevels[view];more.append(b);
    }root.append(more,button('Open first setup',async()=>{await saveDraft({step:1});await navigate('first-run');},'text-link'));
    if(data.recommendations.length)root.append(message('Recommended: an off-site copy, a witness bot and a code check.','notice'));
  }
  function renderResults(box){
    box.replaceChildren();root.querySelector('.hub-grid')?.toggleAttribute('hidden',!!query||!!section);
    if(!query.trim())return;
    const q=query.trim().toLocaleLowerCase();
    const all=[...data.fields,...data.parameters,...[...ctx.catalog()].map(f=>({...f,label:tr(f.label)}))];
    const matches=all.filter(f=>(tr(f.label)+' '+f.key).toLocaleLowerCase().includes(q));
    if(!matches.length)box.append(message('No settings found.'));
    for(const f of matches.slice(0,80)){
      const hidden=rank[f.level]>rank[prefs.level];
      const b=button(tr(f.label)+(hidden?' · '+tr('Show hidden setting'):''),async()=>{
        if(['alerts-form','replica-form','evidence-form'].includes(f.form))await openForm(f.form,f.id);
        else if(f.view)await openAdvanced(f.view,f.extra,f.id);
        else if(f.key.startsWith('parameter:'))await openAdvanced('parameters',null,'parameter-'+f.key.slice(10));
        else{reveal.add(f.section);openSection(f.section);root.querySelector('[data-setting="'+f.key+'"]')?.scrollIntoView({block:'center'});}
      });b.dataset.level=f.level;box.append(b);
    }
  }
  async function openForm(id, focus){
    const who=owner();
    section=id==='evidence-form'?'protection':'notifications';query='';render();
    const detail=root.querySelector('.hub-detail');
    const form=$(id);move(form,detail);await ctx.loadSettingsForm(id);
    requireOwner(who);
    const control=focus?$(focus):form;
    for(let p=control.parentElement;p&&p!==detail;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;
    control.scrollIntoView({block:'center'});if(focus)control.focus();
  }
  async function openAdvanced(view, extra, id){
    const who=owner();
    restoreMoved();await navigate(view);
    requireOwner(who);
    const page=$('view-'+view);
    if(page&&!page.querySelector('.hub-back-link'))page.prepend(button('Back to settings',()=>navigate('settings'),'text-link hub-back-link'));
    if(extra)await ctx.openExtra(extra);
    requireOwner(who);
    if(id){const el=$(id);if(el){for(let p=el.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;el.scrollIntoView({block:'center'});el.focus();}}
  }
  function connectionForm(box, first){
    const routeDraft=first?draft:(editing?draft:{...data.wizard,route:data.connection.strategy?.mode|| (data.connection.managed?'warp':data.connection.mode==='direct'?'direct':data.connection.mode==='mtproxy_auto'?'auto':'proxy'),allow_direct:data.connection.strategy?.allow_direct??data.connection.policy.exposure!=='hide'});
    if(!first){draft=routeDraft;editing=true;}
    const options=first?node('details','wizard-options'):null, routeBox=node('div');
    if(options){options.append(node('summary','',tr('Connection settings')),routeBox);options.open=prefs.level==='expert'||draft.route!=='auto'||!!draft.unchecked||!!checkFailure;}
    else box.append(routeBox);
    function updateRoutes(){routeBox.replaceChildren();cards(routeBox,routes,draft.route,async mode=>{
      const who=owner();
      if(connectionBusy)return;
      draft.route=mode;draft.unchecked=false;routeDirty=true;checkFailure=null;
      if(mode==='direct')draft.allow_direct=true;
      if(first)await saveDraft({step:4},who);requireOwner(who);updateRoutes();
      if(mode==='auto'||mode==='direct')await checkConnection(false,who);
    });
      const protection=select('Can Telegram see this server’s address?',[['hide','No, hide it'],['allow','Only if nothing else works']],draft.allow_direct?'allow':'hide',async v=>{
        draft.allow_direct=v==='allow';draft.unchecked=false;routeDirty=true;if(!draft.allow_direct&&draft.route==='direct')draft.route='auto';
        if(first)await saveDraft({step:4});updateRoutes();updateNext();
      });routeBox.append(protection);
      if(!first&&data.fields.find(f=>f.key==='ip')?.modified){
        routeBox.append(message('Changed by you','modified-tag'),button('Restore goal value',async()=>{
          const who=owner(),plan=await request(who,'settings/goal/preview',{goal:data.goal});editing=false;await edit('ip',plan.values.ip,who);
        },'text-link'));
      }
      if(draft.route==='proxy'){
        const input=node('input');input.type='password';input.id='hub-proxy';input.autocomplete='off';input.placeholder='tg://proxy, socks5://, http(s)://';input.setAttribute('aria-label',tr('Proxy address'));routeBox.append(input);
        input.oninput=()=>{routeDirty=true;updateNext();};
      }
      if(['auto','warp'].includes(draft.route))routeBox.append(message('Auto and WARP can download verified helpers and register this server with Cloudflare.'));
      routeBox.append(button(draft.route==='warp'?'Enable WARP':'Check connection',()=>checkConnection(draft.route==='warp')));
    }
    updateRoutes();
    const status=node('div','connection-result');status.id='hub-connection-result';status.setAttribute('role','status');box.append(status);
    if(options)box.append(options);
    if(connectionBusy){status.className='connection-result checking';status.textContent=tr('Checking connection…');}
    else if(checkFailure&&!fresh(data.connection))connectionFailed(checkFailure);
    else paintConnection(data.connection);
    if(first){const bypass=node('label','check-label');const check=node('input');check.type='checkbox';check.checked=!!draft.unchecked;
      check.onchange=()=>run(async()=>{const who=owner();draft.unchecked=check.checked;
        if(check.checked&&connectionBusy){checkSequence++;clearTimeout(checkTimer);await request(who,'connection/cancel',{});connectionBusy=false;}
        await saveDraft({step:4},who);updateNext();});
      bypass.append(check,document.createTextNode(tr('Continue without checking')));options.append(bypass);}
  }
  function openOptions(){const options=wizardRoot.querySelector('.wizard-options');if(options)options.open=true;}
  async function checkConnection(acceptSetup=false,who=owner()){
    requireOwner(who);
    if(connectionBusy)return;connectionBusy=true;checkFailure=null;updateNext();
    const profile=who.profile,attempt=++checkSequence;
    const currentAttempt=()=>current(who)&&checkSequence===attempt;
    const result=$('hub-connection-result');if(result){result.className='connection-result checking';result.textContent=tr('Checking connection…');}
    try{
      await request(who,'connection/prepare',{mode:draft.route,scope:'account',account:profile,
        allow_direct:draft.allow_direct,outside_enabled:data.values.outside,
        accept_setup:acceptSetup||draft.route==='auto',...(draft.route==='proxy'?{proxy_url:$('hub-proxy').value}:{})});
      const poll=async()=>{
        if(!currentAttempt())return;
        const current=await request(who,'connection');
        if(!currentAttempt())return;
        if(current.job.state==='ready'){await request(who,'connection/apply',{plan:current.job.plan});}
        else if(current.job.state==='applied'){
          if(current.job.rows.some(r=>!r.applied))throw new Error(current.job.rows.find(r=>!r.applied).error);
          connectionBusy=false;routeDirty=false;data.connection=current.current;draft.unchecked=false;
        if(state.view==='first-run')await saveDraft({unchecked:false},who);
        else{data=await request(who,'settings');}
          requireOwner(who);paintConnection(current.current);updateIndicator(current.current);updateNext();await refresh(who);return;
        }else if(['failed','expired'].includes(current.job.state))throw new Error(current.job.error||current.job.stage);
        if(currentAttempt())checkTimer=setTimeout(()=>poll().catch(e=>{if(currentAttempt())connectionFailed(e);}),800);
      };
      const safePoll=async()=>{try{await poll();}catch(e){if(currentAttempt())connectionFailed(e);}};
      if(currentAttempt())checkTimer=setTimeout(safePoll,600);
    }catch(e){if(currentAttempt())connectionFailed(e);}
  }
  function connectionFailed(error){connectionBusy=false;checkFailure=error;const box=$('hub-connection-result');if(box){openOptions();box.className='connection-result failed';box.replaceChildren(message('Connection failed. Try WARP or your own proxy.'));
    const details=node('details');details.append(node('summary','',tr('Technical details')),message(error.message));box.append(details);
    box.append(button('Try WARP',async()=>{draft.route='warp';if(state.view==='first-run')await renderWizard();else render();}),
      button('My proxy',async()=>{draft.route='proxy';if(state.view==='first-run')await renderWizard();else render();}),button('Check again',checkConnection));}updateNext();}
  function fresh(connection){return connection?.check?.telegram_connected&&connection.check.current!==false&&Date.now()/1000-connection.check.checked_at<300;}
  function draftChecked(){return !routeDirty&&fresh(data.connection)&&data.connection.strategy?.mode===draft.route&&!!data.connection.strategy?.allow_direct===draft.allow_direct;}
  function paintConnection(connection){const box=$('hub-connection-result');if(!box)return;box.replaceChildren();
    const ok=fresh(connection);box.className='connection-result '+(ok?'working':'unchecked');
    box.append(message(ok?tr('Working · {n} ms',{n:connection.check.latency_ms}):'Connection has not been verified.'));
    if(!ok){
      if(connection?.pool?.listed&&connection.pool.healthy===0&&connection.pool.probed_at){openOptions();box.className='connection-result failed';box.prepend(message('No public proxy answers. Try WARP or your own proxy.'));}
      box.append(button('Try WARP',async()=>{draft.route='warp';if(state.view==='first-run')await renderWizard();else render();}),button('Check again',checkConnection));
    }
  }
  function updateIndicator(connection){
    const el=$('hub-route-status');if(!el)return;
    const ok=fresh(connection)&&(!state.status.collector.running||state.status.collector.connected!==false);
    el.classList.toggle('route-offline',!ok);el.textContent=ok?label(connection.mode)+' · '+connection.check.latency_ms+' '+tr('ms'):tr('No connection');
    el.onclick=()=>run(async()=>{section='connection';await navigate('settings');});
    const warning=$('hub-proxy-warning');
    warning.hidden=ok||!connection?.pool?.listed||connection.pool.healthy!==0||!connection.pool.probed_at;
    if(!warning.hidden){warning.replaceChildren(message('No public proxy answers. Try WARP or your own proxy.'));
      warning.append(button('Switch to WARP',async()=>{const who=owner();section='connection';await navigate('settings');requireOwner(who);draft.route='warp';editing=true;render();}),
        button('Check again',async()=>{const who=owner();section='connection';await navigate('settings');requireOwner(who);await checkConnection(false,who);}));}
  }
  function scheduleStatus(who=owner()){clearTimeout(statusTimer);statusTimer=setTimeout(async()=>{
    if(!current(who)||!state.token||!state.me?.admin||state.status?.demo)return;
    try{const result=await request(who,'connection');if(data)data.connection=result.current;updateIndicator(result.current);}catch{}
    if(current(who))scheduleStatus(who);
  },15000);}
  function wizardTop(page){
    const top=node('div','wizard-top'), brand=node('div','wizard-brand'), mark=node('img'), language=node('select','wizard-language');
    mark.src='/mark.svg';mark.alt='';mark.width=30;mark.height=30;
    brand.append(mark,node('span','',tr('First setup')));
    for(const [key,name] of Object.entries(ctx.languages))language.append(new Option(name,key));
    language.value=prefs.language;language.setAttribute('aria-label',tr('Language'));
    language.onchange=()=>run(async()=>{const who=owner();await savePreferences({language:language.value},who);requireOwner(who);await ctx.changeLanguage(language.value);},language);
    top.append(brand,language);page.append(top);
  }
  function wizardStages(page){
    const names=[tr('Goal'),tr('Connection'),tr('Telegram'),tr('Chats'),tr('Start')], targets=[1,4,5,6,7];
    const stage=live?names.length:Math.max(0,draft.step-3), last=names.length-1, list=node('ol','wizard-stepper');
    list.setAttribute('aria-label',tr('Setup progress'));
    list.style.setProperty('--from',String(Math.min(shownStage??stage,last)/last));list.style.setProperty('--to',String(Math.min(stage,last)/last));
    names.forEach((name,i)=>{
      const item=node('li','wizard-stage'+(i<stage?' done':i===stage?' current':'')), dot=node('span','wizard-dot',i<stage?'✓':String(i+1)), text=node('span','wizard-stage-name',name);
      dot.setAttribute('aria-hidden','true');item.style.setProperty('--i',String(i));
      if(i===stage)item.setAttribute('aria-current','step');
      if(i<stage&&!live){const jump=button('',async()=>{draft.step=targets[i];await saveDraft();await renderWizard();},'wizard-stage-link');jump.append(dot,text);item.append(jump);}
      else item.append(dot,text);
      list.append(item);
    });
    if(shownStage!==stage)list.classList.add('wizard-moved');
    shownStage=stage;page.append(list);
  }
  async function renderWizard(who=owner()){
    requireOwner(who);
    const focused=wizardRoot.contains(document.activeElement)?document.activeElement.closest('[data-answer]')?.dataset.answer:null;
    restoreMoved();wizardRoot.replaceChildren();if(!draft||!prefs)return;
    const page=node('div','first-run-shell'+(shownStep===null?' wizard-enter':''));wizardRoot.append(page);
    wizardTop(page);wizardStages(page);
    if(live){renderLive(page);return;}
    visited=Math.max(visited,draft.step);
    if(recordedStep!==draft.step){ctx.record?.({replace:recordedStep===null});recordedStep=draft.step;}
    const choosing=draft.step<4, screen=choosing?1:draft.step;
    const direction=shownStep===null?'enter':(shownStep<4?1:shownStep)===screen?'none':draft.step>shownStep?'forward':'back';
    shownStep=draft.step;
    const pane=node('div','wizard-pane');pane.dataset.direction=direction;page.append(pane);
    const names=['What do you want to do?','What do you want to do?','What do you want to do?','How should we connect?','Connect Telegram','Which chats?','Review your choices'];
    const heading=node('h1','',tr(names[draft.step-1]));heading.tabIndex=-1;pane.append(heading);
    if(choosing)pane.append(message('Save a copy of your Telegram account, or keep a record of conversations as they change.','wizard-lead'));
    const body=node('div','first-run-body');pane.append(body);
    if(choosing){
      cards(body,goals,draft.goal,async goal=>{
        draft.goal=goal;await saveDraft();
        if(!levelChosen&&!draft.completed&&prefs.level!==goalLevels[goal])await savePreferences({level:goalLevels[goal]});
        await renderWizard();
      });
      body.querySelector('[data-answer="copy"]')?.append(node('span','answer-badge',tr('Easiest')));
      const more=node('details','wizard-more'), moreBody=node('div','wizard-more-body');
      more.append(node('summary','',tr('More options')),moreBody);more.open=moreOpen;more.ontoggle=()=>{moreOpen=more.open;};
      moreBody.append(node('h2','',tr('Interface level')));
      cards(moreBody,levels,prefs.level,async level=>{levelChosen=true;await savePreferences({level});await renderWizard();});
      preferencesForm(moreBody,{language:false});
      body.append(more);
    }
    if(draft.step===4)connectionForm(body,true);
    if(draft.step===5){
      shownSession=signedIn();
      accountQuestion(body);
      if(shownSession)body.append(message('Telegram is connected.','notice success'));
      move(ctx.authCard(),body);
      if(!shownSession&&!methodShown){methodShown=true;ctx.authMethod(draft.account_kind==='main'?'qr':'files');}
    }
    if(draft.step===6){
      const main=draft.goal!=='copy'&&draft.account_kind==='main';
      if(main&&draft.scope!=='selected')draft.scope='selected';
      cards(body,[['account','✦','All chats','Includes new chats in continuous collection.'],['selected','☑','Choose chats','Only the chats you select.'],['folder','▤','Telegram folder','Use a folder from Telegram.']],draft.scope,async scope=>{
        draft.scope=scope;await saveDraft();await renderWizard();});
      if(main){
        for(const key of ['account','folder']){const card=body.querySelector('[data-answer="'+key+'"]');card.disabled=true;card.title=tr('Only on a separate account.');}
        body.append(message('Only chosen chats can be recorded on a main account.','notice warning'));
      }
      if(!dialogs){const loading=message('Loading chats…');body.append(loading);try{dialogs=await request(who,'dialogs');loading.remove();}catch(e){loading.remove();if(e.name==='StaleView')throw e;body.append(message(e.message,'notice warning'));}}
      requireOwner(who);
      if(dialogs){
        if(draft.scope==='folder')body.append(select('Telegram folder',[['','Choose a folder'],...dialogs.folders.map(f=>[String(f.id),f.title])],String(draft.folder_id??''),async id=>{draft.folder_id=id===''?null:Number(id);await saveDraft();updateNext();}));
        if(draft.scope==='selected'){
          const filter=node('input');filter.type='search';filter.placeholder=tr('Search chats');body.append(filter);
          const list=node('div','wizard-chats');body.append(list);
          for(const chat of dialogs.dialogs){const row=node('label','check-label'), check=node('input');check.type='checkbox';check.checked=draft.chat_ids.includes(chat.chat_id);
            check.onchange=()=>run(async()=>{draft.chat_ids=check.checked?[...new Set([...draft.chat_ids,chat.chat_id])]:draft.chat_ids.filter(id=>id!==chat.chat_id);await saveDraft();updateNext();});
            row.dataset.title=chat.title.toLocaleLowerCase();row.append(check,document.createTextNode(chat.title));list.append(row);}
          filter.oninput=()=>{for(const row of list.children)row.hidden=!row.dataset.title.includes(filter.value.toLocaleLowerCase());};
        }
        body.append(message(tr('{n} chats loaded. File size and duration are estimates.',{n:dialogs.dialogs.length})));
        if(dialogs.may_be_truncated)body.append(message('The chat list is limited. Increase the chat list limit in Settings.','notice warning'));
        if(draft.completed)body.append(button('Save chat selection',async()=>{const action=owner();data=await request(action,'settings/scope',draftBody());await navigate('settings');requireOwner(action);toast(tr('Settings saved.'));},'primary'));
        body.append(button('Estimate size and time',async()=>{const estimate=await request(owner(),'first-run/estimate',draftBody());
          estimateBox.textContent=estimate.available?tr('About {size} MB · {min}–{max} minutes. Based on a sample; actual results may differ.',estimate):tr('An estimate is not available yet.');}));
        const estimateBox=message('The estimate uses a small sample of the selected chats.');body.append(estimateBox);
      }
    }
    if(draft.step===7){
      const summary=node('dl','setup-summary');for(const [key,value,go,more] of [['Goal',label(draft.goal),1,false],['Which chats?',label(draft.scope),6,false],['Telegram account',tr('Connected'),5,false],['Connection',label(draft.route),4,false],['Interface level',label(prefs.level),1,true],['Language',ctx.languages[prefs.language]||prefs.language,1,false],['Time zone',prefs.timezone,1,true]]){
        summary.append(node('dt','',tr(key)));const dd=node('dd','',value);dd.append(button('Edit',async()=>{draft.step=go;if(more)moreOpen=true;await saveDraft();await renderWizard();},'text-link'));summary.append(dd);
      }body.append(summary);
      if(draft.unchecked)body.append(message('Connection was not checked. Starting can fail.','notice warning'));
      if(data.needs_notification_destination)body.append(message('Add a notification destination later in Settings.'));
    }
    page.append(message('Everything can be changed later in Settings.','setup-reassurance'));
    const footer=node('div','wizard-actions');page.append(footer);
    const back=button('Back',async()=>{draft.step=draft.step===4?1:draft.step-1;await saveDraft();await renderWizard();});back.disabled=choosing;footer.append(back);
    const next=button(draft.step===7?(draft.goal==='copy'?'Start export':'Start'):'Next',async()=>{
      const action=owner();
      if(draft.step===7){
        const result=await request(action,'first-run/finish',draftBody());data=result;draft={...result.wizard};await refresh(action);
        if(result.action==='export'){await navigate('evidence');return;}
        if(state.view!=='first-run')return;
        live={started:Date.now(),done:false};await renderWizard(action);watchLive(action);return;
      }
      if(choosing){
        if(data.goal!==draft.goal&&!await applyGoal(draft.goal,{first:!data.goal},action))return;
        await saveDraft({step:4},action);await renderWizard(action);return;
      }
      await saveDraft({step:draft.step+1},action);await renderWizard(action);
    },'primary');next.id='first-run-next';footer.append(next);
    page.append(button('Skip, I’ll set it up myself',async()=>{data=await request(owner(),'first-run/skip',{});await navigate('settings');},'text-link setup-skip'));
    updateNext();
    const restore=direction==='none'&&focused?page.querySelector('[data-answer="'+focused+'"]'):null;
    if(restore)restore.focus({preventScroll:true});else heading.focus({preventScroll:true});
    if(direction!=='none'&&page.getBoundingClientRect().top<0)page.scrollIntoView({block:'start'});
    if(draft.step===4&&draft.route==='auto'&&!autoTried&&!fresh(data.connection)){
      autoTried=true;void checkConnection(false,who);
    }
  }
  function accountQuestion(box){
    box.append(node('h2','',tr('Is this a separate account or your main one?')));
    cards(box,[['dedicated','🧪','A separate account','Recommended. Made for recording: it joins only the chats you want to keep, and losing it costs nothing.'],
      ['main','👤','My main account','Not recommended: the account you use every day.']],draft.account_kind,async kind=>{
      draft.account_kind=kind;if(kind==='main'&&draft.scope!=='selected')draft.scope='selected';
      await saveDraft();await renderWizard();
    });
    const why=node('details','setting-help-block');why.append(node('summary','',tr('Why a separate account?')),
      message('Recording sees everything the account sees, including private chats of other people. A separate account keeps your own chats out of the journal and does not risk your main account.'));
    box.append(why);
    if(draft.account_kind==='main'){
      box.append(message('Telegram can restrict, freeze or ban an account that works through an unofficial API client, and a main account is hard to replace. Your own private chats can also end up in the journal and in exports. Only chosen chats can be recorded on a main account; the whole account and folders stay off. The protection scale counts a main account as a penalty.','notice warning'));
      box.append(message('For an account you cannot lose, use Official Web or Trusted Live under Independent capture: they record through the official Telegram client and make no API calls of their own.'));
    }
  }
  function liveParts(){const h=state.status?.health||{};return ['connection','intake','sources','media'].map(name=>({name,...(h[name]||{state:'unknown'})}));}
  function renderLive(page){
    const heading=node('h1','',tr(live.done?'Setup is applied.':'Checking that recording works…'));heading.tabIndex=-1;page.append(heading);
    const list=node('div','first-run-live'+(live.shown?'':' wizard-appear'));list.setAttribute('aria-live','polite');
    liveParts().forEach((part,i)=>{
      const row=node('div','first-run-check');row.dataset.state=part.state;row.style.setProperty('--i',String(i));
      row.append(ctx.stateBadge(part.state),node('strong','',ctx.healthNames[part.name]),node('span','hint',ctx.healthLines(part.name,part)[0]||''));
      list.append(row);
    });
    live.shown=true;page.append(list);
    if(live.done){
      page.append(node('h2','wizard-done'+(live.celebrated?'':' wizard-appear'),tr('Done! What next:')));live.celebrated=true;
      const actions=node('div','first-run-next-actions');
      for(const [view,text,style] of [['chats','Open chats','primary'],['observations','Open the journal','secondary'],['evidence','How to export','secondary']])
        actions.append(button(text,async()=>{live=null;clearTimeout(liveTimer);await navigate(view);},style));
      page.append(actions);
    }
  }
  function watchLive(who=owner()){
    clearTimeout(liveTimer);
    const session=live;
    const active=()=>current(who)&&session&&live===session&&state.view==='first-run';
    const tick=async()=>{
      if(!active())return;
      try{await refresh(who);}catch{}
      if(!active())return;
      const ready=liveParts().every(part=>['working','off'].includes(part.state));
      if(ready&&Date.now()-live.started>4000||Date.now()-live.started>120000)live.done=true;
      await renderWizard(who);
      if(active()&&!live.done)liveTimer=setTimeout(tick,2000);
    };
    liveTimer=setTimeout(tick,1500);
  }
  function draftBody(){const {step,goal,route,allow_direct,unchecked,scope,chat_ids,folder_id,account_kind}=draft;return {step,goal,route,allow_direct,unchecked,scope,chat_ids,folder_id,account_kind:account_kind||null};}
  function updateNext(){const next=$('first-run-next');if(!next||!draft)return;
    next.disabled=connectionBusy||draft.step===4&&!draftChecked()&&!draft.unchecked||
      draft.step===5&&(!signedIn()||draft.goal!=='copy'&&!draft.account_kind)||
      draft.step===6&&(draft.scope==='selected'&&!draft.chat_ids.length||draft.scope==='folder'&&draft.folder_id===null);
  }
  for(const select of document.querySelectorAll('[data-ui-level]'))select.onchange=()=>run(async()=>{await savePreferences({level:select.value});if(state.view==='settings')render();});
  return {bootstrap,load,render,savePreferences,
    async openGroup(id){if(!data)data=await request(owner(),'settings');await openGroup(id);},
    get step(){return draft&&!live?draft.step:null;},
    leave(){restoreMoved();clearTimeout(liveTimer);live=null;recordedStep=null;groupScope=null;shownStep=shownStage=null;},
    status(){
      updateNext();if(data)updateIndicator(data.connection);
      const session=signedIn();
      if(state.view==='first-run'&&draft?.step===5&&!live&&shownSession!==null&&session!==shownSession)void renderWizard();
      shownSession=session;
    },
    reset(){generation++;checkSequence++;clearTimeout(checkTimer);clearTimeout(statusTimer);clearTimeout(liveTimer);restoreMoved();data=prefs=draft=dialogs=null;live=null;groupScope=null;groupView.reset();visited=0;recordedStep=shownSession=shownStep=shownStage=null;levelChosen=moreOpen=methodShown=false;connectionBusy=false;editing=false;autoTried=routeDirty=false;checkFailure=null;preferencesQueue=draftQueue=Promise.resolve();},
    async refreshPreferences(patch){if(prefs)await savePreferences(patch);},
  };
}
