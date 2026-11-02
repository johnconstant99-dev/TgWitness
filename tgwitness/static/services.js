(() => {
  'use strict';
  const iconURL=new URL('./services-icons.svg',document.currentScript.src).href;
  const marks=new Set('telegram discord ntfy gmail matrix signal whatsapp mattermost rocketdotchat zulip pushbullet pagerduty ifttt homeassistant nextcloud synology mastodon googlechat streamlabs googledrive dropbox mega cloudflare backblaze rclone hetzner digitalocean vultr github protondrive box minio wasabi'.split(' '));
  const aliases={tgram:'telegram',email:'gmail','google mail':'gmail','google drive':'googledrive','microsoft teams':'teams'};
  const owner=()=>state.workspaceRevision+':'+state.profile;
  let bound=null, catalog=null, selected=null, storageDirty=false, botDirty=false, mode='backup', loading=null;
  function brand(name){
    const key=aliases[name.toLowerCase()]||name.toLowerCase().replace(/[^a-z0-9]/g,''),el=node('span','service-brand');
    el.dataset.service=key;el.title=name;el.setAttribute('aria-hidden','true');
    if(marks.has(key)){const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'),use=document.createElementNS(svg.namespaceURI,'use');use.setAttribute('href',iconURL+'#'+key);svg.append(use);el.append(svg);}
    else el.textContent=name.slice(0,1).toUpperCase();return el;
  }
  panelQueries('[data-service-icons]').forEach(row=>row.dataset.serviceIcons.split(',').forEach(name=>row.append(brand(name))));
  function clear(){bound=null;storageDirty=botDirty=false;selected=null;loading=null;show('service-setup',false);$('service-setup').replaceChildren();$('storage-form').reset();$('operator-bot-form').reset();$('services-search').value='';}
  function list(){
    if(!catalog)return;
    const query=$('services-search').value.toLowerCase().trim(),box=$('services-catalog');box.replaceChildren();
    const popular=['Telegram','Discord','Slack','NTFY','Email','Matrix','Gotify','Pushover'];
    const rows=catalog.services.filter(s=>(s.name+' '+s.protocols.join(' ')).toLowerCase().includes(query)).sort((a,b)=>{
      const rank=x=>popular.indexOf(x)<0?100:popular.indexOf(x);return rank(a.name)-rank(b.name)||a.name.localeCompare(b.name);});
    $('services-count').textContent=tr('{shown} of {total} services',{shown:rows.length,total:catalog.count});
    for(const item of rows){const button=node('button','service-choice');button.type='button';button.setAttribute('aria-pressed',String(selected===item.name));button.append(brand(item.name),node('strong','',item.name));button.addEventListener('click',()=>choose(item));box.append(button);}
    if(!rows.length)box.append(node('p','hint',tr('No matching service. Try another name.')));
  }
  function choose(item){
    selected=item.name;list();const box=$('service-setup');box.replaceChildren();show('service-setup',true);
    const heading=node('h3');heading.append(brand(item.name),node('span','',item.name));box.append(heading);
    const select=node('select');select.setAttribute('aria-label',tr('Connection format'));
    item.templates.forEach(t=>select.append(new Option(t,t)));box.append(select);
    const fields=node('div','service-fields');box.append(fields);
    function inputs(){fields.replaceChildren();for(const key of new Set((select.value.match(/\{[^}]+\}/g)||[]).map(t=>t.slice(1,-1)))){
      const spec=item.tokens[key]||{},label=node('label','',String(spec.name||key));let input;
      if(key==='schema'){input=node('select');for(const p of item.protocols)input.append(new Option(p,p));input.value=item.secure_protocols[0]||item.protocols[0];}
      else {input=node('input');input.type=spec.private?'password':'text';input.autocomplete=spec.private?'new-password':'off';input.spellcheck=false;if(spec.default!=null)input.value=String(spec.default);}
      input.dataset.token=key;label.append(input);fields.append(label);
    }}select.addEventListener('change',inputs);inputs();
    const actions=node('div','service-actions'),add=node('button','secondary',tr('Add destination'));add.type='button';actions.append(add);
    if(item.documentation?.startsWith('https://')){const link=node('a','text-link',tr('Setup instructions'));link.href=item.documentation;link.target='_blank';link.rel='noopener noreferrer';actions.append(link);}box.append(actions);
    add.addEventListener('click',e=>busy(e.currentTarget,async()=>{
      const revision=owner(),values={};for(const input of fields.querySelectorAll('[data-token]')){let value=input.value.trim(),key=input.dataset.token;
        if(!value){input.focus();throw new Error(tr('Fill in: {field}',{field:input.parentElement.firstChild.textContent}));}
        if(key==='schema'&&!item.protocols.includes(value))throw new Error(tr('Choose a connection format.'));
        if(key==='host'&&!/^[a-zA-Z0-9.\-\[\]:]+$/.test(value))throw new Error(tr('Enter a hostname without a path.'));
        values[key]=['schema','host','port'].includes(key)?value:key==='targets'?value.split(/[,\s]+/).map(encodeURIComponent).join('/'):encodeURIComponent(value);
      }
      const url=select.value.replace(/\{([^}]+)\}/g,(_,key)=>values[key]);
      $('alerts-enabled').checked=true;await saveAlerts(null,[url]);if(revision!==owner())return;
      show('service-setup',false);box.replaceChildren();selected=null;list();toast(tr('Destination saved. Use Send test to check delivery.'));
    }));
  }
  $('services-search').addEventListener('input',list);
  function storageMode(value){mode=value;panelQueries('[data-storage-mode]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.storageMode===value)));
    show('storage-form',value==='offload');show('storage-lock-help',value==='evidence');
    if(state.extra==='storage')$('storage-s3-slot').append($('replica-form'));else $('storage-s3-home').after($('replica-form'));
    $('replica-form').hidden=state.extra==='storage'&&value==='offload';
    if(value==='evidence')$('replica-form').querySelector('details').open=true;
  }
  panelQueries('[data-storage-mode]').forEach(button=>button.addEventListener('click',()=>storageMode(button.dataset.storageMode)));
  const presets={wasabi:['https://s3.us-east-1.wasabisys.com','us-east-1','Enable Object Lock when creating a bucket. Choose its real endpoint and retention period.'],aws:['https://s3.us-east-1.amazonaws.com','us-east-1','Choose your bucket region. Object Lock requires a versioned bucket.'],b2:['','us-west-004','Copy the S3 endpoint and region from your Backblaze bucket.'],r2:['','auto','Use https://ACCOUNT_ID.r2.cloudflarestorage.com. Retention support differs from S3 Object Lock; check the result.'],minio:['','us-east-1','Enter your own HTTPS S3 endpoint. Enable versioning and Object Lock on the bucket if needed.']};
  $('replica-provider').addEventListener('change',()=>{const p=presets[$('replica-provider').value];if(!p)return;$('replica-endpoint').value=p[0];$('replica-region').value=p[1];$('replica-provider-hint').textContent=tr(p[2]);state.replicaDirty=true;});
  function renderStorage(data){
    if(!storageDirty){const s=data.settings;$('storage-backend').value=s.backend;$('storage-purpose').value=s.purpose;$('storage-age').value=s.older_than_days;$('storage-folder').value=s.remote_path;$('storage-compress').checked=s.compress;$('storage-enabled').checked=s.enabled;$('storage-interval').value=s.interval_minutes;$('storage-batch').value=s.batch_files;}
    show('storage-rclone',$('storage-backend').value==='rclone');$('storage-config').placeholder=data.has_config?tr('Saved securely. Leave empty to keep.'):'[mycloud]\ntype = mega\nuser = …\npass = …';
    $('storage-install').textContent=tr(data.rclone_installed?'Reinstall verified rclone':'Install verified rclone in this workspace');
    const stats=$('storage-stats');stats.replaceChildren();for(const [value,label] of [[data.copied_files,'Verified copies'],[data.remote_files,'Files stored remotely'],[data.last?.freed_bytes||0,'Bytes freed in last pass']]){const item=node('div');item.append(node('strong','',String(value)),node('small','',tr(label)));stats.append(item);}
    $('storage-status').textContent=data.busy?tr('Storage operation in progress…'):data.last?.error?tr(data.last.error):data.last?.at?tr('Last pass: {time}',{time:fmtFull(data.last.at)}):tr('Ready to configure.');
    for(const id of ['storage-copy','storage-test','storage-restore','storage-install'])$(id).disabled=data.busy||!!state.status?.demo;
  }
  async function load(){
    if(state.view!=='witness'||!state.token)return;
    if(bound!==owner()){clear();bound=owner();}
    if(loading)return loading;
    const expected=owner();loading=(async()=>{
      if(state.extra==='alerts'&&!catalog){try{catalog=await json('services/notifications');if(owner()!==expected)return;list();}catch(e){$('services-count').textContent=e.message;}}
      if(!state.me?.admin||state.status?.demo)return;
      if(state.extra==='storage'){try{const data=await json('storage');if(owner()===expected)renderStorage(data);}catch(e){if(owner()===expected)$('storage-status').textContent=e.message;}}
      if(state.extra==='alerts'){try{const data=await json('operator-bot');if(owner()!==expected)return;if(!botDirty){const s=data.settings;$('operator-bot-enabled').checked=s.enabled;$('operator-bot-chat').value=s.chat_id;$('operator-bot-users').value=s.user_ids.join(', ');$('operator-bot-commands').value=s.commands;}$('operator-bot-status').textContent=data.last?.error?tr('Bot connection unavailable: {error}',{error:data.last.error}):data.has_token?tr('Bot token saved. Only listed users can send commands.'):tr('Create your own bot with BotFather.');}catch(e){if(owner()===expected)$('operator-bot-status').textContent=e.message;}}
    })().finally(()=>{loading=null;});return loading;
  }
  $('storage-form').addEventListener('input',()=>{storageDirty=true;});$('storage-backend').addEventListener('change',()=>show('storage-rclone',$('storage-backend').value==='rclone'));
  $('storage-form').addEventListener('submit',event=>{event.preventDefault();busy(event.submitter,async()=>{
    const expected=owner();
    const offload=$('storage-purpose').value==='offload';if(offload&&!(await askConfirm(tr('Remove local files only after a complete remote download matches the uploaded bytes? Keep the recovery file. Restore files before a full evidence export.'),{danger:true})))return;
    if(expected!==owner())return;
    const data=await json('storage',{enabled:$('storage-enabled').checked,backend:$('storage-backend').value,purpose:$('storage-purpose').value,compress:$('storage-compress').checked,older_than_days:Number($('storage-age').value),interval_minutes:Number($('storage-interval').value),batch_files:Number($('storage-batch').value),remote_path:$('storage-folder').value.trim(),rclone_config:$('storage-config').value,confirm_offload:offload});
    $('storage-config').value='';storageDirty=false;renderStorage(data);toast(tr('Storage settings saved.'));
  });});
  for(const [id,endpoint,message] of [['storage-install','install','Verified helper installed.'],['storage-test','test','Upload and full download verified.'],['storage-copy','copy','Storage copy started.'],['storage-restore','restore','Restoring files. Keep this workspace running.']])$(id).addEventListener('click',event=>busy(event.currentTarget,async()=>{await json('storage/'+endpoint,{});toast(tr(message));await load();}));
  $('storage-recovery').addEventListener('click',event=>busy(event.currentTarget,async()=>{await download('storage/recovery','tgwitness-storage-recovery.json');}));
  $('storage-recovery-import').addEventListener('change',event=>busy(null,async()=>{
    const input=event.currentTarget,file=input.files[0],expected=owner();if(!file)return;
    try{
      if(file.size>7*1024*1024)throw new Error(tr('This recovery file is too large for the panel. Use the recovery command.'));
      let recovery;try{recovery=JSON.parse(await file.text());}catch{throw new Error(tr('Choose a valid TgWitness storage recovery JSON file.'));}
      if(expected!==owner())return;
      if(!(await askConfirm(tr('Import storage recovery information into this workspace? Its signature must match this workspace. Cloud credentials are kept separately.'))))return;
      if(expected!==owner())return;
      await json('storage/recovery',{recovery});toast(tr('Recovery information verified. Configure the same cloud destination, then choose Restore all files.'));await load();
    }finally{input.value='';}
  }));
  $('operator-bot-form').addEventListener('input',()=>{botDirty=true;});
  $('operator-bot-form').addEventListener('submit',event=>{event.preventDefault();busy(event.submitter,async()=>{await json('operator-bot',{enabled:$('operator-bot-enabled').checked,token:$('operator-bot-token').value.trim(),chat_id:$('operator-bot-chat').value.trim(),user_ids:$('operator-bot-users').value.split(/[,\s]+/).filter(Boolean).map(Number),commands:$('operator-bot-commands').value});$('operator-bot-token').value='';botDirty=false;await load();toast(tr('Operator bot saved.'));});});
  $('operator-bot-test').addEventListener('click',event=>busy(event.currentTarget,async()=>{await json('operator-bot/test',{});toast(tr('Status sent to your bot.'));}));
  $('cloud-choose-phala').addEventListener('click',()=>{showCloudHost('phala');$('cloud-phala-token').focus();$('cloud-setup').scrollIntoView({block:'start'});});
  window.addEventListener('tgwitness:lock',clear);
  window.TgWitnessServices={load,clear,select(){storageMode(mode);load();},brand};
})();
