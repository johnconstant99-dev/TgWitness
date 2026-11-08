export function createGroupView(ctx){
  const {root,json,tr,trn,node,toast}=ctx;
  let groupId=null,data=null,serial=0,working=false;
  function owner(){
    const {profile,token,workspaceRevision}=ctx.getState(),id=groupId,version=serial;
    return {id,token,current:()=>{const state=ctx.getState();return groupId===id&&serial===version&&state.groupId===id&&
      state.view==='group'&&state.profile===profile&&state.token===token&&state.workspaceRevision===workspaceRevision;}};
  }
  const goals={copy:['📥','Just download'],watch:['👁','Follow chats'],evidence:['⚖','Evidence']};
  const routes={auto:'Automatic',mtproxy_auto:'Automatic',warp:'Cloudflare WARP',proxy:'My proxy',mtproxy:'My proxy',
    socks5:'My proxy',http:'My proxy',direct:'Direct',vpn:'VPN'};
  const profile=id=>(ctx.getState().profiles||[]).find(p=>p.id===id);
  const usable=id=>{const p=profile(id);return !!p&&!p.error_type&&!!p.collector?.has_session&&!ctx.accountState(p).needsSignIn;};
  function button(text,fn,cls='secondary small'){const b=node('button',cls,tr(text));b.type='button';b.addEventListener('click',()=>run(b,fn));return b;}
  async function run(control,fn){
    if(control)control.disabled=true;
    try{await fn();}catch(error){if(error.name!=='StaleView')toast(error.message,true);}
    finally{if(control?.isConnected)control.disabled=false;}
  }
  async function load(id){
    if(id!==groupId){groupId=id;data=null;root.replaceChildren(node('p','hint',tr('Loading…')));}
    const request=++serial,result=await json('profile-groups/'+encodeURIComponent(id)+'/overview',undefined,{root:true});
    if(request!==serial||groupId!==id)return;
    data=result;render();
  }
  function problems(id){
    const p=profile(id);if(!p)return [];
    if(p.error_type)return [{part:null,text:tr('Unavailable: {error}',{error:p.error_type})}];
    const found=['connection','intake','sources','media'].filter(part=>ctx.needsLook(p.health?.[part]?.state))
      .map(part=>({part,text:ctx.healthPartNames[part]+': '+(ctx.collectorLines(part,p.health[part]).find(Boolean)||'')}));
    if(ctx.accountState(p).needsSignIn&&!found.some(f=>f.part==='connection'))
      found.unshift({part:'connection',text:tr('Telegram signed this account out. Sign in again to resume observation.')});
    return found;
  }
  async function inWorkspace(id){
    if(ctx.getState().profile!==id&&await ctx.switchProfile(id)===false)return false;
    return ctx.getState().profile===id&&!!ctx.getState().token;
  }
  async function fix(id,part){
    if(!await inWorkspace(id))return;
    if(!part||part==='connection')await ctx.navigate('connection');else ctx.diagnose(part);
  }
  async function runAll(action){
    if(working)return;
    const consent=owner();
    const due=data.members.map(m=>profile(m.id)).filter(p=>p&&!p.error_type&&p.collector&&
      (action==='stop'?p.collector.running:!p.collector.running&&ctx.accountState(p).canStart)).map(p=>({id:p.id,label:p.label}));
    if(!due.length)return;
    const text=action==='stop'?tr('Pause {n} workspaces? New messages, edits and deletions will not be collected while paused. Missed activity can only be recovered partly.',{n:due.length}):
      tr('Resume {n} workspaces? They will connect to Telegram and collect their selected sources. Telegram request limits still apply.',{n:due.length});
    if(!(await window.TgWitnessDialogs.confirm(text+'\n\n'+due.map(p=>p.label).join('\n'))))return;
    if(!consent.current())return;
    working=true;render();const done=[],failed=[];
    try{
      for(const p of due){
        if(!consent.current())return;
        try{await json('collector/'+action,{},{profile:p.id,token:consent.token});if(!consent.current())return;done.push(p.label);}
        catch(error){if(error.name==='StaleView')return;failed.push(p.label+': '+error.message);}
      }
      await ctx.loadProfiles();
      if(!consent.current())return;
      toast([action==='start'?trn('{n} workspace started.','{n} workspaces started.',done.length):
        trn('{n} workspace paused.','{n} workspaces paused.',done.length),...failed].join(' · '),!!failed.length);
    }finally{working=false;if(data&&ctx.getState().view==='group')render();}
  }
  function header(){
    const g=data.group,box=node('header','group-head'),title=node('div','group-title');
    title.append(node('div','eyebrow',tr('Group')),node('h1','',g.label));
    const goal=goals[g.goal];
    title.append(node('p','group-goal',goal?goal[0]+' '+tr('Goal')+': '+tr(goal[1]):tr('No goal yet: choose one in the group settings.')));
    const attention=node('div','group-attention'),troubled=data.members.filter(m=>problems(m.id).length);
    attention.dataset.count=String(troubled.length);
    if(!troubled.length)attention.append(node('span','group-ok','✓ '+tr('Nothing needs attention.')));
    else{
      attention.append(node('strong','',tr('Needs attention')+': '+troubled.length));
      for(const m of troubled){const link=node('button','text-link',m.label);link.type='button';
        link.addEventListener('click',()=>{const card=root.querySelector('#group-account-'+CSS.escape(m.id));card?.scrollIntoView({block:'center'});card?.focus({preventScroll:true});});
        attention.append(link);}
    }
    box.append(title,attention);return box;
  }
  function actions(){
    const box=node('div','group-actions'),members=data.members.map(m=>profile(m.id)).filter(Boolean),collect=ctx.may('collect');
    const start=button('Start all',()=>runAll('start')),pause=button('Pause all',()=>runAll('stop'));
    start.disabled=working||!collect||!members.some(p=>!p.error_type&&p.collector&&!p.collector.running&&ctx.accountState(p).canStart);
    pause.disabled=working||!collect||!members.some(p=>p.collector?.running);
    const route=button('Change the group route',()=>ctx.openConnection({scope:'group',group:groupId})),goal=button('Apply a goal',()=>ctx.openGroupSettings(groupId));
    const settings=button('Group settings',()=>ctx.openGroupSettings(groupId),'quiet small');
    const save=button('Export group',async()=>{
      const consent=owner(),label=data.group.label;
      if(!(await window.TgWitnessDialogs.confirm(tr('Export the records of every account in the group {name}?',{name:label}),{confirmText:tr('Prepare export')})))return;
      if(!consent.current())return;
      if(await ctx.exportGroup(consent.id,label,consent)!==false&&consent.current())toast(tr('Group export saved: each account’s signed export and a signed list of them.'));
    });
    save.title=tr('Each account’s signed export in one ZIP, with a manifest signed by the main workspace.');
    for(const b of [route,goal,settings])b.disabled=working||!data.members.length;
    save.disabled=working||!data.members.length||!ctx.may('export')||data.members.some(m=>!m.available);
    box.append(start,pause,route,goal,save,settings);return box;
  }
  function card(m){
    const p=profile(m.id),box=node('article','card padded group-account');box.id='group-account-'+m.id;box.tabIndex=-1;box.dataset.profile=m.id;
    const head=node('div','group-account-head'),who=node('div','group-account-who'),name=node('div');
    name.append(node('h3','',m.label),node('p','account-id',m.username?'@'+m.username:tr(m.available?'No account connected':'Unavailable')));
    who.append(ctx.avatarNode(m.account_id??null,m.username||m.label,'',m.id),name);head.append(who);
    if(p?.health&&!p.error_type)head.append(ctx.stateBadge(p.health.state,'account-badge'));
    box.append(head);
    if(m.account_kind)box.append(node('span','group-kind '+m.account_kind,tr(m.account_kind==='main'?'Main account':'Dedicated account')));
    if(m.available&&p){
      const facts=node('dl','account-meta');
      const pair=(k,v,field)=>{const item=node('div','account-value');item.dataset.field=field;item.append(node('dt','',tr(k)),node('dd','',v));facts.append(item);};
      pair('Observation',ctx.accountPhaseLabel(p),'observation');
      pair('Connection route',tr(routes[m.route.mode]||m.route.mode)+' · '+(m.route.latency_ms!==null?tr('{n} ms',{n:m.route.latency_ms}):tr('not checked')),'route');
      pair('Last message',m.last_message?ctx.fmtTime(m.last_message.at):tr('none yet'),'last');
      box.append(facts);
    }
    const found=problems(m.id);
    if(found.length){
      const list=node('ul','group-problems');
      for(const f of found){const li=node('li');li.append(node('span','',f.text),button('Fix',()=>fix(m.id,f.part),'text-link'));list.append(li);}
      box.append(list);
    }
    const row=node('div','account-actions'),open=button('Open',async()=>{if(await inWorkspace(m.id))await ctx.navigate('chats');});
    open.disabled=!p||!!p.error_type;row.append(open);box.append(row);
    return box;
  }
  function chats(){
    const box=node('section','group-chats card padded'),total=data.members.length;
    box.append(node('h2','',tr('Chats several accounts see')),
      node('p','hint',tr('Several accounts can export one chat together: each fetches part of it and the archive is signed once. Channels and supergroups only.')));
    if(!data.chats.length){box.append(node('p','hint group-chats-empty',tr('No chat is seen by more than one account of this group yet.')));return box;}
    const list=node('ul','group-chat-list');
    for(const c of data.chats){
      const li=node('li','group-chat'),text=node('div','group-chat-text'),cover=c.coverage;
      const coverage=!c.recorded_by.length?tr('none of them records it'):!cover.observed?tr('No workspace observation in the last {days} days',{days:data.window_days}):
        cover.interruptions?trn('Workspace observation: {n} interruption in the available period','Workspace observation: {n} interruptions in the available period',cover.interruptions)+' ('+ctx.fmtDuration(cover.seconds_unobserved)+')':
        tr('Workspace observation: no interruptions in the available period');
      const paused=c.recorded_by.length&&!c.recorded_by.some(id=>profile(id)?.collector?.running);
      text.append(node('strong','',c.title||String(c.chat_id)),
        node('span','group-chat-meta',tr('{n} of {total} accounts see it',{n:c.seen_by.length,total})+' · '+coverage+(paused?' · '+tr('recording paused'):'')));
      const ready=c.seen_by.filter(usable),lead=c.recorded_by.find(usable)||ready[0],together=c.chat_id<-1000000000000&&ready.length>1;
      const open=button('Open chat',()=>ctx.openChat(lead,c.chat_id),'quiet small');
      const share=button('Export chat',()=>ctx.exportTogether(lead,c.chat_id,together?ready:[lead]),'secondary small');
      if(together)share.textContent=trn('Export with {n} account','Export with {n} accounts',ready.length);
      open.disabled=!lead;share.disabled=!lead||!ctx.may('export');
      const buttons=node('div','group-chat-actions');buttons.append(open,share);li.append(text,buttons);list.append(li);
    }
    box.append(list);
    if(data.chats_total>data.chats.length)box.append(node('p','hint',tr('Showing {n} of {total}.',{n:data.chats.length,total:data.chats_total})));
    return box;
  }
  const stamp=()=>JSON.stringify((data?.members||[]).map(m=>{const p=profile(m.id);
    return p&&[p.error_type,p.health?.state,p.collector?.running,p.collector?.phase,p.collector?.has_session,
      ...['connection','intake','sources','media'].map(part=>p.health?.[part]?.state+':'+p.health?.[part]?.reason)];}));
  let shown='';
  function render(){
    if(!data)return;
    shown=stamp();
    const back=button('All accounts and groups',()=>ctx.navigate('accounts'),'text-link group-back');
    const grid=node('div','group-accounts');
    if(!data.members.length)grid.append(node('p','hint',tr('No workspaces in this group yet. Move one here or import accounts into it.')));
    for(const m of data.members)grid.append(card(m));
    const focus=document.activeElement&&root.contains(document.activeElement)?document.activeElement.id:null;
    root.replaceChildren(back,header(),actions(),node('h2','group-section',tr('Accounts')),grid,chats());
    if(focus)root.querySelector('#'+CSS.escape(focus))?.focus({preventScroll:true});
  }
  return {load,
    status(){if(data&&!working&&stamp()!==shown)render();},
    reset(){serial++;groupId=null;data=null;working=false;root.replaceChildren();}};
}
