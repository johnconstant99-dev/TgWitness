export function createPeopleTimeline({root, json, tr, owner, active, record, formatTime}) {
  const node=(tag,text='',cls='')=>{const el=document.createElement(tag);el.textContent=text;el.className=cls;return el;};
  let bound=null, request=0, offset=0, person=null, days=7, mode='all', pending=false, lastLoad=0;
  const current=(key,ticket)=>active()&&owner()===key&&bound===key&&ticket===request;
  const labels={online:'Online observed',offline:'Offline observed',unknown:'Unknown',recently:'Recently',last_week:'Within a week',last_month:'Within a month',
    joined:'Joined',left:'Left',removed:'Removed',banned:'Banned',restricted:'Restricted',admin:'Administrator',member:'Member',absent:'No longer present',
    quiet:'No recent messages observed',recent:'Recent messages observed',never_posted:'No saved messages',
    no_recorded_gap:'No recorded collection gap in this period; visibility may still be incomplete.',interrupted:'Collection was interrupted or settings changed in this period.',unknown_coverage:'Coverage is unconfirmed for this period.'};
  const label=value=>tr(labels[value]||value||'Unknown');
  function button(text,work,cls='secondary'){const b=node('button',tr(text),cls);b.type='button';b.addEventListener('click',work);return b;}
  function guard(work){return async()=>{const key=owner();try{await work();}catch(error){const status=root.querySelector('.people-timeline-status');if(active()&&key===owner()&&status)status.textContent=error.message;}};}
  function mount(){
    root.replaceChildren();const box=node('section','','people-timeline padded'),heading=node('div','','people-timeline-toolbar');
    box.append(node('h3',tr('Participant timeline')),
      node('p',tr('Observed profiles, membership and activity. Online status is account-wide and does not show which chat a person reads.'),'hint'));
    const filter=node('select');filter.setAttribute('aria-label',tr('Filter participants'));filter.id='people-timeline-filter';
    for(const [key,text] of [['all','All observed users'],['quiet','No recent messages observed'],['departed','Left, removed or banned'],['deleted','Account marked deleted'],['never_posted','No saved messages']])filter.append(new Option(tr(text),key));
    filter.value=mode;filter.addEventListener('change',()=>{mode=filter.value;offset=0;person=null;load(true);});
    const field=node('label',tr('Silence threshold, days')),input=node('input');input.type='number';input.min='1';input.max='365';input.value=String(days);input.id='people-timeline-days';field.append(input);
    input.addEventListener('change',()=>{if(!input.reportValidity())return;days=input.valueAsNumber;offset=0;load(true);});
    heading.append(filter,field,button('Refresh',guard(()=>load(true))));box.append(heading,node('p','','hint people-timeline-status'),node('div','','people-timeline-content'));root.append(box);
  }
  function summary(data){
    const status=root.querySelector('.people-timeline-status');status.textContent=label(data.coverage==='unknown'?'unknown_coverage':data.coverage);
  }
  async function load(force=false){
    if(!active())return;
    const key=owner();if(bound!==key||!root.querySelector('.people-timeline')){bound=key;request++;offset=0;person=null;pending=false;lastLoad=0;mount();}
    if(!force&&(pending||person!==null||Date.now()-lastLoad<15000))return;
    const ticket=++request,chat=key.split(':').at(-1);pending=true;
    lastLoad=Date.now();
    try{
      const query=person?`people/${person}?quiet_days=${days}`:`people?offset=${offset}&limit=100&quiet_days=${days}&mode=${mode}`;
      const data=await json(`chats/${encodeURIComponent(chat)}/${query}`);if(!current(key,ticket))return;
      summary(data);const content=root.querySelector('.people-timeline-content');content.replaceChildren();
      if(person)detail(content,data,key,ticket);else list(content,data);
    }catch(error){if(current(key,ticket))root.querySelector('.people-timeline-status').textContent=error.message;}
    finally{if(current(key,ticket))pending=false;}
  }
  function list(content,data){
    content.append(node('p',tr('Observed users: {count}').replace('{count}',data.total),'hint'));
    const table=node('table','','people-table'),head=node('tr');
    for(const title of ['Person','Messages','Last message','Observed status','Membership'])head.append(node('th',tr(title)));
    const thead=node('thead');thead.append(head);table.append(thead);const body=node('tbody');
    for(const item of data.people){const row=node('tr'),who=node('td'),name=item.profile.display_name||`ID ${item.user_id}`;
      const open=button(name,()=>{person=item.user_id;load(true);},'text-link');open.dataset.personId=String(item.user_id);who.append(open,node('small',` ID ${item.user_id}`));
      if(item.profile.flags?.deleted)who.append(node('p',tr('Account marked deleted'),'bad'));
      row.append(who,node('td',String(item.messages)),node('td',item.last_message_at?formatTime(item.last_message_at):'—'),
        node('td',label(item.status.state)),node('td',label(item.membership.state)));
      if(item.activity==='quiet')row.children[2].append(node('p',label('quiet'),'hint'));body.append(row);
    }
    table.append(body);const scroll=node('div','','people-timeline-table');scroll.append(table);content.append(scroll);
    if(!data.people.length)content.append(node('p',tr('No matching observed users.'),'hint'));
    const pages=node('div','','people-timeline-toolbar');
    if(offset)pages.append(button('Previous',()=>{offset=Math.max(0,offset-100);load(true);}));
    if(offset+data.people.length<data.total)pages.append(button('Next',()=>{offset+=100;load(true);}));content.append(pages);
  }
  function detail(content,data,key,ticket){
    const p=data.person;content.append(button('Back to participants',()=>{person=null;load(true);}),node('h4',p.profile.display_name||`ID ${p.user_id}`),
      node('p',`ID ${p.user_id} · ${label(p.status.state)} · ${label(p.membership.state)}`));
    if(p.profile.flags?.deleted)content.append(node('p',tr('Telegram marked this account deleted. The cause and exact deletion time are unknown.'),'hint'));
    content.append(node('p',`${label(p.activity)} · ${tr('Last message')}: ${p.last_message_at?formatTime(p.last_message_at):'—'}`,'hint'));
    if(data.last_message_gap_days!=null)content.append(node('p',tr('Gap between the two latest saved message times: {days} days. Historical imports do not mean a return today.').replace('{days}',data.last_message_gap_days.toFixed(1)),'hint'));
    const events=node('ol','','people-timeline-events');content.append(events);
    function append(items){for(const item of items){const li=node('li'),title={message:item.data.edited?'Message edited':'Message observed',profile:'Profile observed',status:'Status observed',membership:'Membership observed',refresh_requested:'Profile refresh requested',profile_unavailable:'Profile unavailable'}[item.category]||item.category;
      li.append(node('strong',tr(title)),node('small',`${tr('Observed')}: ${formatTime(item.observed_at)}`));
      if(item.source_at)li.append(node('small',`${tr('Source time')}: ${formatTime(item.source_at)}`));
      if(item.category==='status'||item.category==='membership')li.append(node('p',label(item.data.state)));
      if(item.category==='message')li.append(node('p',`#${item.data.message_id} · ${item.data.sent_at?formatTime(item.data.sent_at):tr('Unknown')}`));
      for(const [field,change] of Object.entries(item.data.profile_changes||{}))li.append(node('p',`${field}: ${JSON.stringify(change.before)} → ${JSON.stringify(change.after)}`));
      if(item.data.actor_id)li.append(node('p',`${tr('Actor ID')}: ${item.data.actor_id}`));
      li.append(button(`#${item.event_seq}`,guard(()=>record(item.event_seq)),'text-link'));events.append(li);
    }}append(data.events);
    let before=data.next_before;
    if(before){const more=button('Load earlier observations',guard(async()=>{
      more.disabled=true;try{const chat=key.split(':').at(-1),value=await json(`chats/${encodeURIComponent(chat)}/people/${p.user_id}?before=${before}&quiet_days=${days}`);
        if(!current(key,ticket))return;append(value.events);before=value.next_before;if(!before)more.remove();
      }finally{if(more.isConnected)more.disabled=false;}
    }));content.append(more);}
  }
  return {load,reset(){bound=null;request++;pending=false;lastLoad=0;}};
}
