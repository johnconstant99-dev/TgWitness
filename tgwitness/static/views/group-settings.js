// A group's shared settings (group_settings.py): every member takes each value unless it keeps its own.
// A change is previewed first; accounts with their own value keep it unless ticked in the preview.
export function createGroupSettings(ctx) {
  const {json, tr, trn, node, toast, askConfirm, button, message, cards, label, describe, goals, openConnection, back} = ctx;
  // Collecting now or paused stays with each account: Accounts starts or pauses a whole group.
  const fields=()=>ctx.fields().filter(f=>f.key!=='continuous');
  let data=null, groupId=null;
  const who=m=>m.username?'@'+m.username:m.label;
  const OTHER=[['monitoring','What to record'],['recheck','Recheck schedule'],['alert_rules','Notification rules'],
    ['reports','Report settings'],['parameters','Parameters'],['route','Connection route']];
  const keysOf=item=>item==='parameters'?data.keys.filter(k=>k.category==='parameters').map(k=>k.key):[item];
  const nameOf=key=>tr(data.keys.find(k=>k.key===key)?.label||key);
  const available=()=>data.members.filter(m=>m.available);
  const hubShared=()=>fields().every(f=>f.key in data.values);
  function valueText(key,value){
    if(value===undefined||value===null)return tr('Not shared');
    if(key==='route')return label(value.mode);
    return typeof value==='object'?tr('Shared'):describe(value);
  }
  async function load(id){groupId=id;data=await json('profile-groups/'+encodeURIComponent(id)+'/settings',undefined,{root:true});return data;}
  function coverage(keys){
    if(!keys.some(k=>k in data.values))return tr('Not shared: each account keeps its own value.');
    const members=available(),owners=members.filter(m=>keys.some(k=>m.own.includes(k)));
    const text=tr('{n} of {total} accounts follow the group',{n:members.length-owners.length,total:data.members.length});
    return owners.length?text+' · '+tr('own value: {list}',{list:owners.map(who).join(', ')}):text;
  }
  // Lines for the preview: one per setting, Parameters counted together.
  function changeLines(plan){
    const keys=Object.keys(plan.after),params=keys.filter(k=>k.startsWith('parameter:'));
    const lines=keys.filter(k=>!k.startsWith('parameter:')).map(k=>nameOf(k)+': '+valueText(k,plan.before[k])+' → '+valueText(k,plan.after[k]));
    if(params.length)lines.push(tr('Parameters')+': '+trn('{n} value changes','{n} values change',params.length));
    return lines;
  }
  function ownText(own){
    const entries=Object.entries(own),params=entries.filter(([k])=>k.startsWith('parameter:'));
    const parts=entries.filter(([k])=>!k.startsWith('parameter:')).map(([k,v])=>nameOf(k)+' '+valueText(k,v));
    if(params.length)parts.push(tr('Parameters')+' '+trn('{n} value differs','{n} values differ',params.length));
    return parts.join(', ');
  }
  async function change(values,flags={}){
    const plan=await json('profile-groups/'+encodeURIComponent(groupId)+'/settings/preview',{values,...flags},{root:true});
    if(!Object.keys(plan.after).length){toast(tr('The group already shares these values.'));return false;}
    // An account differs either by its own choice (kept unless ticked) or because the group did not share
    // this setting until now (ticked: by default an account takes what its group shares).
    const owners=plan.members.filter(r=>r.status==='own'),missing=plan.members.filter(r=>r.status==='unavailable');
    const applies=plan.follow+owners.filter(r=>r.new.length).length;
    const text=[changeLines(plan).join('\n'),tr('Applies to {n} of {total} accounts.',{n:applies,total:plan.total})];
    if(missing.length)text.push(tr('Unavailable now, they keep their current values: {list}',{list:missing.map(who).join(', ')}));
    const choices=owners.map(r=>({value:r.id,checked:r.new.length>0,
      label:who(r)+' · '+tr(r.new.length?'current value':'own value')+': '+ownText(r.own)}));
    const overwrite=await window.TgWitnessDialogs.choose(text.join('\n\n'),{title:tr('Change the group setting?'),choices,
      choicesLabel:tr('These accounts have a different value. Ticked ones take the group value:'),confirmText:tr('Apply')});
    if(overwrite===null)return false;
    data=await json('profile-groups/'+encodeURIComponent(groupId)+'/settings',{values,...flags,overwrite,revision:plan.revision},{root:true});
    const parts=[trn('Applied to {n} account.','Applied to {n} accounts.',data.applied.length)];
    if(data.kept.length)parts.push(trn('{n} account kept its own value.','{n} accounts kept their own value.',data.kept.length));
    for(const f of data.failed)parts.push(f.label+': '+tr(f.error));
    toast(parts.join(' '),!!data.failed.length);
    return true;
  }
  // The same consent a single account asks for when a feature depends on another.
  async function editHub(key,value){
    const v=data.values,flags={};
    if(['timestamps','drand','notifications','replica'].includes(key)&&value&&!v.outside){
      if(!await askConfirm(tr('This feature needs external requests. Allow them?')))return;flags.allow_outside=true;
    }
    if(key==='outside'&&!value&&(v.timestamps||v.drand||v.notifications||v.replica)){
      if(!await askConfirm(tr('Turn off the dependent features too?')))return;flags.disable_dependents=true;
    }
    await change({[key]:value},flags);
  }
  function hubRow(f){
    const row=node('div','hub-field group-field');row.dataset.setting=f.key;
    const heading=node('div');heading.append(node('strong','',tr(f.label)),node('span','hint',coverage([f.key])));row.append(heading);
    const value=data.values[f.key],disabled=!hubShared();
    if(f.type==='bool'){
      const control=node('input');control.type='checkbox';control.checked=!!value;control.disabled=disabled;control.setAttribute('aria-label',tr(f.label));
      control.onchange=()=>ctx.run(async()=>{try{await editHub(f.key,control.checked);}finally{render(ctx.root);}});row.append(control);
    }else{
      const wrap=node('label','hub-label',tr(f.label)),control=node('select');
      for(const v of f.key==='files'?['photos','short_media','all']:['hide','auto'])control.append(new Option(label(v),v));
      control.value=value??'';control.disabled=disabled;control.onchange=()=>ctx.run(async()=>{try{await editHub(f.key,control.value);}finally{render(ctx.root);}});
      wrap.append(control);row.append(wrap);
    }
    return row;
  }
  function otherRow([item,title]){
    const keys=keysOf(item),shared=keys.some(k=>k in data.values);
    const row=node('div','hub-field group-field');row.dataset.setting=item;
    const heading=node('div');heading.append(node('strong','',tr(title)),node('span','hint',coverage(keys)));
    if(item==='route'&&shared)heading.append(node('span','hint',tr('Group route')+': '+valueText('route',data.values.route)));
    row.append(heading);
    const actions=node('div','group-field-actions');
    if(item==='route'){
      actions.append(button('Change the group route',()=>openConnection({scope:'group',group:groupId,mode:data.values.route?.mode})));
    }else{
      const source=node('select');source.setAttribute('aria-label',tr('Take the value of'));
      for(const m of available())source.append(new Option(tr('Take the value of {name}',{name:who(m)}),m.id));
      actions.append(source,button(shared?'Share this value instead':'Share this value',async()=>{
        const member=available().find(m=>m.id===source.value);if(!member)return;
        if(await change(Object.fromEntries(keys.map(k=>[k,member.values[k]]))))render(ctx.root);
      }));
    }
    if(shared)actions.append(button('Stop sharing',async()=>{
      if(await change(Object.fromEntries(keys.filter(k=>k in data.values).map(k=>[k,null]))))render(ctx.root);
    },'text-link'));
    row.append(actions);return row;
  }
  function render(root){
    root.replaceChildren();if(!data)return;
    const header=node('div','hub-heading');
    header.append(button('Back to account settings',back,'text-link'),node('div','eyebrow',tr('Group')),
      node('h1','',tr('Shared settings: {name}',{name:data.group.label})));
    header.querySelector('h1').tabIndex=-1;root.append(header);
    root.append(message('Accounts in the group take these values. An account with its own value keeps it until you return it to the group value.'));
    const list=node('ul','group-members');
    for(const m of data.members)list.append(node('li','',who(m)+' · '+(!m.available?tr('Unavailable'):m.own.length?
      trn('{n} own value','{n} own values',m.own.length):tr('follows the group'))));
    if(!data.members.length)list.append(node('li','hint',tr('No accounts in this group yet.')));
    root.append(list);
    const goal=node('section','hub-detail group-section');goal.append(node('h2','',tr('Goal')),node('p','hint',coverage(['goal'])));
    cards(goal,goals,data.values.goal,async g=>{if(await change({goal:g}))render(root);});
    root.append(goal);
    const hub=node('section','hub-detail group-section');hub.append(node('h2','',tr('Collection, protection and notifications')),
      message('Starting and pausing collection stays with each account; Accounts starts or pauses the whole group.'));
    if(!hubShared())hub.append(message('Choose a goal for the group first; its settings come together.','notice'));
    for(const f of fields())hub.append(hubRow(f));
    root.append(hub);
    const other=node('section','hub-detail group-section');other.append(node('h2','',tr('More shared settings')),
      message('Share the value one account already has. Notification destinations, proxies and sign-in stay with each account.'));
    for(const item of OTHER)other.append(otherRow(item));
    root.append(other);
    header.querySelector('h1').focus({preventScroll:true});
  }
  return {load,render,change,get id(){return groupId;},get data(){return data;},reset(){data=null;groupId=null;}};
}
