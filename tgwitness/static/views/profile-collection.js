export function createProfileCollection({json,tr,owner,active,canCollect,formatTime,attachment,record,onComplete}){
  const node=(tag,text='',cls='')=>{const el=document.createElement(tag);el.textContent=String(text??'');el.className=cls;return el;};
  const button=(text,work,cls='secondary')=>{const el=node('button',tr(text),cls);el.type='button';el.addEventListener('click',work);return el;};
  const stages={participants:'Participants',profile:'Profile',avatars:'Profile photos',gifts:'Gifts',links:'Links'};
  const phases={idle:'Ready',running:'Collecting',paused:'Paused',complete:'Completed',partial:'Incomplete',cancelled:'Cancelled'};
  const reasons={telegram_wait:'Telegram asked us to wait. Collection resumes automatically.',retry_wait:'Waiting before another attempt.',
    waiting_for_account:'Another task is using this account.',account_changed:'This collection belongs to another Telegram account.',
    authorization_required:'Connect a Telegram account first.',source_paused:'Resume the selected chats to continue.',operator:'Paused by you.',cancelled:'Cancelled'};
  let host=null,key=null,timer=null,serial=0,statusRequest=0,working=false,readError=false,completed=null,last=null,selectedPerson=null,selectedTab='profile';
  let scope=null,options=null,status=null,actions=null,error=null,start=null;
  const current=(expected,ticket)=>host?.isConnected&&active()&&owner()===expected&&key===expected&&ticket===serial;
  const chat=()=>Number(owner().split(':').at(-1));
  function reset(){clearTimeout(timer);serial++;statusRequest++;host=null;key=null;working=false;readError=false;selectedPerson=null;selectedTab='profile';last=null;completed=null;}
  function mount(root){
    reset();host=node('section','','profile-collection');root.append(host);key=owner();
    if(!canCollect()){host.hidden=true;return;}
    const heading=node('div','','profile-collection-heading');heading.append(node('strong',tr('People profiles')));host.append(heading);
    const form=node('div','','profile-collection-form');scope=node('select');scope.id='profiling-scope';scope.setAttribute('aria-label',tr('Chats'));
    scope.append(new Option(tr('This chat'),'chat'),new Option(tr('Selected chats'),'all'));form.append(scope);
    options=node('div','','profile-collection-options');
    for(const [name,title] of [['participants','Participants'],['avatars','Profile photos'],['gifts','Gifts'],['links','Links']]){
      const label=node('label','','check-label'),input=node('input');input.type='checkbox';input.checked=true;input.dataset.profilingOption=name;
      label.append(input,document.createTextNode(tr(title)));options.append(label);
    }
    start=button('Start',()=>run('start'),'primary');start.id='profiling-start';form.append(start);host.append(form,options);
    status=node('div','','profile-collection-status');status.setAttribute('aria-live','polite');
    actions=node('div','','profile-collection-actions');error=node('div','','notice warning');error.hidden=true;
    host.append(status,actions,error);void refresh();
  }
  function body(userId){
    const all=!userId&&scope.value==='all';
    return {all_chats:all,chat_ids:all?[]:[chat()],user_id:userId||null,
      ...Object.fromEntries([...options.querySelectorAll('input')].map(input=>[input.dataset.profilingOption,input.checked]))};
  }
  async function run(action,userId){
    if(working||!canCollect())return;
    const expected=key,ticket=serial;working=true;statusRequest++;clearTimeout(timer);readError=false;error.hidden=true;render(last);
    try{const data=await json('profiling/'+action,action==='start'?body(userId):{});if(!current(expected,ticket))return;last=data;render(data);}
    catch(problem){if(current(expected,ticket)){error.replaceChildren(node('span',problem.message),button('Retry',()=>run(action,userId),'quiet small'));error.hidden=false;}}
    finally{if(current(expected,ticket)){working=false;render(last);schedule();}}
  }
  function render(data){
    if(!status?.isConnected)return;
    const state=data?.phase||'idle',occupied=['running','paused'].includes(state);
    start.disabled=working||occupied;scope.disabled=working||occupied;for(const input of options.querySelectorAll('input'))input.disabled=working||occupied;
    status.replaceChildren();actions.replaceChildren();if(!data||state==='idle')return;
    const counts=data.counts,done=(counts.complete||0)+(counts.partial||0),summary=node('div','','profile-collection-summary');
    summary.append(node('span',tr(phases[state]||state),'profile-phase '+state),node('strong',`${done.toLocaleString()} / ${(counts.total||0).toLocaleString()}`),node('span',tr('People'),'hint'));status.append(summary);
    const progress=node('progress');progress.max=Math.max(1,counts.total||0);progress.setAttribute('aria-label',tr('People'));if(data.discovery_complete||state!=='running')progress.value=done;status.append(progress);
    const numbers=node('div','','profile-collection-counts');
    for(const [title,value] of [['Completed',counts.complete||0],['Incomplete',counts.partial||0],['Profile photos',counts.avatars||0],['Gifts',counts.gifts||0]])numbers.append(node('span',`${tr(title)}: ${Number(value).toLocaleString()}`));status.append(numbers);
    if(data.current_stage)status.append(node('p',tr(stages[data.current_stage]||data.current_stage)+(data.current_user?' · ID '+data.current_user:''),'hint'));
    if(data.reason){let text=tr(reasons[data.reason]||'Collection could not start. Check the connection and selected chats.');if(state==='running'&&data.wait_until>Date.now()/1000)text+=' '+formatTime(new Date(data.wait_until*1000).toISOString());status.append(node('p',text,'hint'));}
    const sources=node('details','','profile-collection-sources');sources.append(node('summary',tr('Sources')+' · '+data.sources.length));
    for(const source of data.sources){const row=node('div','','profile-source');row.append(node('span',source.title),node('small',`${source.position}${source.total!==null?' / '+source.total:''} · ${tr(source.phase==='pending'?'Collecting':source.phase==='partial'?'Unavailable':source.phase==='known_users'?'Observed':'Completed')}`));
      if(source.error)row.append(node('p',tr(source.error==='ChatAdminRequiredError'?'Telegram does not allow this account to do this.':'Unavailable'),'hint'));sources.append(row);}
    status.append(sources);
    const available=state==='running'?[['pause','Pause'],['cancel','Cancel']]:state==='paused'?[['resume','Resume'],['cancel','Cancel']]:state==='partial'?[['retry','Retry unavailable profiles']]:[];
    for(const [action,title] of available){const control=button(title,()=>run(action));control.dataset.profilingAction=action;control.disabled=working;actions.append(control);}
  }
  function schedule(){clearTimeout(timer);if(host?.isConnected&&active())timer=setTimeout(refresh,2500);}
  async function refresh(){
    if(!host?.isConnected||!active()||!canCollect()||working)return;
    const expected=key,ticket=serial,request=++statusRequest;
    try{const data=await json('profiling');if(!current(expected,ticket)||request!==statusRequest)return;last=data;if(readError){error.hidden=true;readError=false;}render(data);
      const done=data.id+':'+data.phase;if(['complete','partial'].includes(data.phase)&&completed!==done){const previous=completed;completed=done;if(previous!==null)onComplete?.();}else if(data.phase==='running')completed=data.id+':running';
    }catch(problem){if(current(expected,ticket)&&request===statusRequest&&!working){readError=true;error.replaceChildren(node('span',problem.message),button('Retry',refresh,'quiet small'));error.hidden=false;}}
    finally{if(current(expected,ticket)&&request===statusRequest)schedule();}
  }
  function profile(root,person,valid){
    if(selectedPerson!==person.user_id){selectedPerson=person.user_id;selectedTab='profile';}
    const box=node('section','','profile-card'),heading=node('div','','profile-card-heading'),identity=node('div');
    identity.append(node('h3',person.profile.display_name||'ID '+person.user_id),node('p',`ID ${person.user_id}${person.profile.username?' · @'+person.profile.username:''}`,'hint'));
    heading.append(identity);if(canCollect())heading.append(button('Refresh profile',()=>run('start',person.user_id),'quiet'));
    const tabs=node('div','','profile-tabs');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label',tr('Profile'));
    const content=node('div','','profile-card-content');content.setAttribute('role','tabpanel');box.append(heading,tabs,content);root.append(box);let load=0;
    function overview(){
      const p=person.profile;if(p.about)content.append(node('div',p.about,'profile-bio'));
      const facts=node('dl','','profile-facts'),fields=[['Username',(p.usernames||[]).map(name=>'@'+name).join(', ')],['First name',p.first_name],['Last name',p.last_name],
        ['Birthday',p.birthday?[p.birthday.day,p.birthday.month,p.birthday.year].filter(v=>v!==null&&v!==undefined).join('.'):''],
        ['Channel',p.personal_channel_id],['Messages',person.messages],['Last message',person.last_message_at?formatTime(person.last_message_at):''],['Observed',p.observed_at?formatTime(p.observed_at):'']];
      for(const [title,value] of fields)if(value!==null&&value!==undefined&&value!=='')facts.append(node('dt',tr(title)),node('dd',value));content.append(facts);
      if(p.business?.title||p.business?.description)content.append(node('h4',p.business.title),node('p',p.business.description));if(p.bot_description)content.append(node('p',p.bot_description));
      const flags=Object.entries(p.flags||{}).filter(([,value])=>value===true);if(flags.length){const badges=node('div','','profile-badges');for(const [name] of flags)badges.append(node('span',tr(name),'badge'));content.append(badges);}
    }
    const safeLink=(text,url)=>{try{const parsed=new URL(url);if(!['https:','http:'].includes(parsed.protocol))return node('span',text);const link=node('a',text);link.href=parsed.href;link.target='_blank';link.rel='noopener noreferrer';return link;}catch{return node('span',text);}};
    function card(item,category){
      const card=node('article','','profile-asset');if(item.media_sha256)card.append(attachment(item));
      if(category==='avatar'){card.append(node('strong',tr('Profile photo')));if(item.uploaded_at)card.append(node('small',tr('Source time')+': '+formatTime(item.uploaded_at)));if(!item.media_sha256)card.append(node('p',tr('Attachment not collected'),'hint'));}
      else if(category==='gift'){
        card.append(node('strong',item.title||'🎁 #'+item.gift_id));if(item.number)card.append(node('span','#'+item.number));if(item.received_at)card.append(node('small',tr('Received')+': '+formatTime(item.received_at)));
        if(item.sender_id)card.append(node('small',tr('Sender')+': '+item.sender_id));if(item.message)card.append(node('p',item.message));
        for(const attribute of item.attributes||[])if(attribute.name)card.append(node('span',attribute.name+(attribute.rarity_permille!==undefined?' · '+attribute.rarity_permille/10+'%':''),'badge'));
        if(item.slug)card.append(safeLink(tr('Open Telegram link'),'https://t.me/nft/'+encodeURIComponent(item.slug)));
      }else{
        card.append(node('small',tr(item.relation==='personal_channel'?'Channel':'Bio'),'hint'));const url=item.url||(item.username?'https://t.me/'+encodeURIComponent(item.username):null);
        card.append(url?safeLink(item.title||url,url):node('strong',item.title||String(item.channel_id||'')));
        if(item.about){const description=node('details');description.append(node('summary',tr('Description')),node('p',item.about));card.append(description);}if(item.participants!==null&&item.participants!==undefined)card.append(node('small',tr('Participants')+': '+item.participants));
      }
      card.append(node('small',tr('Observed')+': '+formatTime(item.observed_at)),button('#'+item.event_seq,()=>record(item.event_seq),'text-link'));return card;
    }
    async function assets(category,ticket){
      const grid=node('div','','profile-assets'),notice=node('p',tr('Loading…'),'hint'),more=button('Load more',()=>fetchPage(),'secondary');more.hidden=true;content.append(notice,grid,more);let offset=0,before=null,pending=false;
      async function fetchPage(){
        if(pending)return;pending=true;more.disabled=true;
        try{const query=new URLSearchParams({category,offset:String(offset),limit:'48'});if(before)query.set('before',before);const data=await json(`chats/${encodeURIComponent(chat())}/people/${person.user_id}/assets?${query}`);
          if(!valid()||ticket!==load||!content.isConnected)return;notice.textContent=data.total?tr('{n} saved records').replace('{n}',data.total):tr('No data');
          for(const item of data.items)grid.append(card(item,category));before=data.before;offset=data.next_offset;more.hidden=offset===null;
        }catch(problem){if(valid()&&ticket===load){notice.textContent=problem.message;more.textContent=tr('Retry');more.hidden=false;}}
        finally{pending=false;if(valid()&&ticket===load)more.disabled=false;}
      }
      await fetchPage();
    }
    function select(name){selectedTab=name;const ticket=++load;content.replaceChildren();for(const tab of tabs.children){tab.setAttribute('aria-selected',String(tab.dataset.profileTab===name));tab.tabIndex=tab.dataset.profileTab===name?0:-1;}if(name==='profile')overview();else void assets(name,ticket);}
    for(const [name,title] of [['profile','Profile'],['avatar','Profile photos'],['gift','Gifts'],['link','Links']]){const tab=button(title,()=>select(name),'profile-tab');tab.dataset.profileTab=name;tab.setAttribute('role','tab');tabs.append(tab);}
    tabs.addEventListener('keydown',event=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();const buttons=[...tabs.children],index=buttons.indexOf(document.activeElement),next=event.key==='Home'?0:event.key==='End'?buttons.length-1:(index+(event.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;buttons[next].click();buttons[next].focus();});select(selectedTab);
  }
  return {mount,refresh,profile,reset};
}
