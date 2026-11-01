import {accountState} from "../components/account-state.js";

export function createAccounts(context) {
  const {root,tr,getState,getSession,json,loadProfiles,refreshStatus,toast,switchProfile,navigate,diagnose}=context;
  const find=id=>root.querySelector('#'+id), listeners=new AbortController(), selected=new Set();
  let session=getSession(), page=0, working=false, visible=[];
  const make=(tag,cls='',text='')=>{const n=root.ownerDocument.createElement(tag);n.className=cls;n.textContent=text;return n;};
  const on=(node,event,fn)=>node.addEventListener(event,fn,{signal:listeners.signal});
  const profiles=()=>getState().profiles||[];
  const allowed=()=>!!getState().me?.admin&&!getState().status?.demo;
  const empty=p=>accountState(p).kind==='empty';
  const issues=p=>['connection','intake','sources','media'].filter(key=>['failed','degraded','unknown'].includes(p.health?.[key]?.state));
  const problem=p=>!!p.error_type||accountState(p).needsSignIn||issues(p).length>0;
  const collecting=p=>accountState(p).kind==='collecting';
  const eligible=(p,action)=>!p.error_type&&!!p.collector&&(action==='stop'?p.collector.running:
    accountState(p).canStart);
  for(const [value,label] of [['sign_in','Sign-in required'],['paused','Paused']]){
    if(![...find('accounts-filter').options].some(option=>option.value===value))find('accounts-filter').add(new Option(tr(label),value));
  }
  function resetSession(){
    session=getSession();selected.clear();working=false;page=0;
    find('accounts-result').hidden=true;find('accounts-result').textContent='';
    find('accounts-search').value='';find('accounts-filter').value='all';find('accounts-sort').value='attention';
    find('accounts-overview').replaceChildren();find('accounts-selected').textContent=tr('{n} selected',{n:0});
  }
  function summary(){
    const list=profiles(), facts=[['workspaces',tr('Workspaces'),list.length,'all'],['collecting',tr('Collecting'),list.filter(collecting).length,'collecting'],
      ['sign_in',tr('Sign-in required'),list.filter(p=>accountState(p).needsSignIn).length,'sign_in'],
      ['empty',tr('Not connected'),list.filter(empty).length,'empty'],
      ['paused',tr('Paused'),list.filter(p=>accountState(p).kind==='paused').length,'paused'],
      ['problems',tr('Needs attention'),list.filter(problem).length,'attention']];
    const box=find('accounts-overview');
    for(const [id,label,value,filter] of facts){
      let item=box.querySelector('[data-count="'+id+'"]');
      if(!item){item=make('button','accounts-total');item.type='button';item.dataset.count=id;item.append(make('strong'),make('span','',label));box.append(item);
        on(item,'click',()=>{find('accounts-search').value='';find('accounts-filter').value=filter;page=0;updateStatus();});}
      item.firstElementChild.textContent=value.toLocaleString();
      item.setAttribute('aria-pressed',String(find('accounts-filter').value===filter));
    }
  }
  async function openWorkspace(id,target){
    if(!getState().me?.admin)return;
    if(getState().profile!==id)await switchProfile(id);
    if(getState().profile!==id||!getState().token)return;
    if(target==='connection')await navigate('connection');else diagnose(target);
  }
  function decorate(card){
    const id=card.dataset.profile;
    let label=card.querySelector('.account-select');
    if(!label){label=make('label','account-select');const check=make('input');check.type='checkbox';
      on(check,'change',()=>{check.checked?selected.add(id):selected.delete(id);controls();});label.append(check);card.prepend(label);}
    const p=card.profileData,account=accountState(p);card.dataset.accountState=account.kind;
    label.firstElementChild.checked=selected.has(id);label.firstElementChild.disabled=working||!allowed()||!!p.error_type;
    label.firstElementChild.setAttribute('aria-label',tr('Select {name}',{name:p.label}));
    let connection=card.querySelector('[data-action="connect"]');
    if(connection){connection.hidden=!empty(p)&&!account.needsSignIn;connection.disabled=working||!allowed();
      connection.textContent=tr(account.needsSignIn?'Sign in again':'Connect');}
    const toggle=card.querySelector('[data-action="toggle"]');
    if(toggle){toggle.disabled=working||!allowed()||!eligible(p,p.collector?.running?'stop':'start');
      toggle.hidden=account.needsSignIn||account.kind==='empty';}
    let attention=card.querySelector('.account-problems');
    if(!attention){attention=make('div','account-problems');card.append(attention);}
    const found=issues(p), prior=new Map([...attention.children].map(n=>[n.dataset.part,n]));
    if(account.needsSignIn&&!found.includes('connection'))found.unshift('connection');
    const names={connection:tr('Connection'),intake:tr('Event intake'),sources:tr('Sources'),media:tr('Media queue')};
    for(const part of found){let button=prior.get(part);if(!button){button=make('button','text-link',names[part]);button.type='button';button.dataset.part=part;
      on(button,'click',()=>openWorkspace(id,part).catch(error=>toast(error.message,true)));attention.append(button);}
      button.textContent=tr(part==='connection'&&account.needsSignIn?'Sign in again':names[part]);
      button.hidden=part==='connection'&&account.needsSignIn&&!!connection;
      button.title=tr(part==='connection'&&account.needsSignIn?'Sign in to this account again':'Open {part} diagnostics',{part:names[part]});}
    for(const [part,button] of prior)if(!found.includes(part))button.remove();
    attention.hidden=!found.length;
  }
  function controls(){
    const chosen=profiles().filter(p=>selected.has(p.id)), count=selected.size;
    find('accounts-selected').textContent=tr('{n} selected',{n:count});
    find('accounts-pause').disabled=working||!allowed()||!chosen.some(p=>eligible(p,'stop'));
    find('accounts-resume').disabled=working||!allowed()||!chosen.some(p=>eligible(p,'start'));
    find('accounts-clear').disabled=working||!count;
    const pick=find('accounts-select-page'), selectable=visible.filter(p=>!p.error_type);
    pick.disabled=working||!allowed()||!selectable.length;pick.checked=!!selectable.length&&selectable.every(p=>selected.has(p.id));
    pick.indeterminate=!pick.checked&&selectable.some(p=>selected.has(p.id));
  }
  function updateStatus(){
    if(getState().view!=='accounts')return;
    if(session!==getSession())resetSession();
    const list=profiles(), known=new Set(list.map(p=>p.id));for(const id of selected)if(!known.has(id))selected.delete(id);
    summary();
    const query=find('accounts-search').value.trim().toLowerCase(),filter=find('accounts-filter').value,sort=find('accounts-sort').value;
    const filtered=list.filter(p=>(!query||[p.label,p.collector?.account?.username,p.collector?.account?.id].join(' ').toLowerCase().includes(query))&&
      (filter==='all'||filter==='attention'&&problem(p)||filter==='collecting'&&collecting(p)||filter==='offline'&&!collecting(p)||filter==='empty'&&empty(p)||
        filter==='sign_in'&&accountState(p).needsSignIn||filter==='paused'&&accountState(p).kind==='paused'));
    filtered.sort((a,b)=>(sort==='attention'?Number(problem(b))-Number(problem(a)):sort==='events'?(b.stats?.total||0)-(a.stats?.total||0):sort==='pending'?(b.collector?.media_pending||0)-(a.collector?.media_pending||0):0)||a.label.localeCompare(b.label));
    page=Math.min(page,Math.max(0,Math.ceil(filtered.length/10)-1));visible=filtered.slice(page*10,page*10+10);
    const shown=new Set(visible.map(p=>p.id)),cards=new Map([...root.querySelectorAll('.account-card')].map(n=>[n.dataset.profile,n])),box=find('accounts-list');
    for(const card of cards.values()){decorate(card);card.hidden=!shown.has(card.dataset.profile);}
    // Move only when ordering changes; ordinary status polls retain focus and controls.
    let cursor=box.firstElementChild;
    for(const p of [...filtered,...list.filter(p=>!filtered.includes(p))]){const card=cards.get(p.id);if(!card)continue;
      if(card!==cursor)box.insertBefore(card,cursor);cursor=card.nextElementSibling;}
    find('accounts-empty').hidden=!!filtered.length;
    find('accounts-page').textContent=filtered.length?tr('{first}–{last} of {total}',{first:page*10+1,last:Math.min((page+1)*10,filtered.length),total:filtered.length}):tr('0 workspaces');
    find('accounts-prev').disabled=page===0;find('accounts-next').disabled=(page+1)*10>=filtered.length;controls();
  }
  async function run(action){
    if(working||!allowed())return;
    const chosen=profiles().filter(p=>selected.has(p.id)&&eligible(p,action));if(!chosen.length)return;
    const text=action==='stop'?tr('Pause {n} workspaces? New messages, edits and deletions will not be collected while paused. Missed activity can only be recovered partly.',{n:chosen.length}):
      tr('Resume {n} workspaces? They will connect to Telegram and collect their selected sources. Telegram request limits still apply.',{n:chosen.length});
    if(!window.confirm(text+'\n\n'+chosen.map(p=>p.label).join('\n')))return;
    const started=getSession();working=true;updateStatus();const done=[],failed=[];
    try{
      for(const p of chosen){
        if(started!==getSession()||!allowed())return;
        const current=profiles().find(value=>value.id===p.id);if(!current||!eligible(current,action))continue;
        try{await json('collector/'+action,{},{profile:p.id});if(started!==getSession())return;done.push(p.label);selected.delete(p.id);}
        catch(error){if(started!==getSession()||error.name==='StaleView')return;failed.push(p.label+': '+error.message);}
      }
      if(started!==getSession())return;
      const result=find('accounts-result');result.hidden=false;
      result.textContent=tr('{n} workspaces updated.',{n:done.length})+(failed.length?' '+tr('Not changed: {list}',{list:failed.join('; ')}):'');
      await loadProfiles();if(started===getSession())await refreshStatus();
    }finally{if(started===getSession()){working=false;updateStatus();}}
  }
  for(const id of ['accounts-search','accounts-filter','accounts-sort'])on(find(id),id==='accounts-search'?'input':'change',()=>{page=0;updateStatus();});
  on(find('accounts-prev'),'click',()=>{page--;updateStatus();});on(find('accounts-next'),'click',()=>{page++;updateStatus();});
  on(find('accounts-select-page'),'change',event=>{for(const p of visible)if(!p.error_type)event.target.checked?selected.add(p.id):selected.delete(p.id);updateStatus();});
  on(find('accounts-clear'),'click',()=>{selected.clear();updateStatus();});
  on(find('accounts-pause'),'click',()=>run('stop').catch(error=>toast(error.message,true)));
  on(find('accounts-resume'),'click',()=>run('start').catch(error=>toast(error.message,true)));
  on(find('fleet-group-new'),'click',()=>{find('accounts-groups').open=true;});
  return {ownsRows:true,updateStatus,enter:updateStatus,resetSession,leave(){},destroy(){listeners.abort();resetSession();}};
}
