const $=id=>document.getElementById(id);
const node=(tag,cls='',text='')=>{const n=document.createElement(tag);n.className=cls;n.textContent=text;return n;};
let session=sessionStorage.getItem('tgwitness-showcase-session')||'',selection='',cursor=null,messageId=null,ticket=0,revision=0,refreshTicket=0,paged=false;
const snapshots=new Map();
const challenge=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
const date=value=>value?new Date(value).toLocaleString(undefined,{dateStyle:'medium',timeStyle:'medium',timeZone:'UTC'})+' UTC':'Not yet observed';
function notice(text,error=false){$('notice').textContent=text;$('notice').classList.toggle('error',error);}
function clear(){revision++;ticket++;session='';sessionStorage.removeItem('tgwitness-showcase-session');snapshots.clear();selection='';cursor=null;messageId=null;$('login').hidden=false;$('content').hidden=true;$('sign-out').hidden=true;$('feed').replaceChildren();$('collectors').replaceChildren();$('channel').replaceChildren();$('totals').replaceChildren();$('title').textContent='Real records. Visible changes.';}
async function api(path,body){const response=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(session?{Authorization:'Bearer '+session}:{})},body:body?JSON.stringify(body):undefined,cache:'no-store',referrerPolicy:'no-referrer'});if(!response.ok){if([401,403].includes(response.status))clear();const error=await response.json().catch(()=>({}));throw Error(typeof error.detail==='string'?error.detail:'The request could not be completed.');}return response.json();}
function download(value,name){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'})),link=node('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function restoreSession(){
  const me=await api('access/me');
  if(!me.showcase){clear();throw Error('Use a showcase access link. This page does not open administrator or reviewer access.');}
  await refresh();
}
async function exchangeAccessToken(token){
  const result=await api('access/login',{token});
  if(!result.me.showcase){await fetch('/api/access/logout',{method:'POST',headers:{Authorization:'Bearer '+result.session}});throw Error('Use a showcase access link. This page does not open administrator or reviewer access.');}
  session=result.session;sessionStorage.setItem('tgwitness-showcase-session',session);$('token').value='';await restoreSession();
}
$('login').addEventListener('submit',async e=>{e.preventDefault();e.submitter.disabled=true;try{await exchangeAccessToken($('token').value.trim());}catch(error){notice(error.message,true);}finally{e.submitter.disabled=false;}});
$('sign-out').addEventListener('click',async()=>{try{await api('access/logout',{});}catch{}clear();notice('Showcase access closed.');});
function collectorCard(value,index,previous){const s=value.statement,card=node('article','card collector'),head=node('header'),status=node('span','pill',s.health.running?(s.health.connected?'Collecting':'Waiting for connection'):'Paused');if(s.health.running&&s.health.connected)status.classList.add('live');head.append(node('h3','','Collector '+(index+1)),status);card.append(head,node('p','muted','Last heartbeat · '+date(s.health.last_heartbeat)));
  const settings=s.settings_now;card.append(node('p','',Object.entries(settings.monitoring).filter(([,v])=>v).map(([k])=>k).join(' · ')),node('p','muted','Heartbeat: '+settings.heartbeat_seconds+'s · checkpoints: '+settings.checkpoint_minutes+' min'));
  const details=node('details');details.append(node('summary','','Fingerprint & signed checkpoint'),node('p','','Signing key · SHA-256'),node('code','',value.fingerprint),node('p','','Journal head · #'+s.checkpoint.statement.event_count),node('code','',s.checkpoint.statement.head_hash),node('p','muted','Checkpoint covers this collector’s journal. Visible counts cover only the selected channels.'));
  const button=node('button','','Download signed snapshot');button.addEventListener('click',()=>download({format:'tgwitness-showcase-pair-v1',current:value,previous:previous||null},'showcase-'+s.workspace_id+'-'+s.checkpoint.statement.event_count+'.json'));details.append(button);card.append(details);return card;}
async function refresh(){const current=revision,mine=++refreshTicket,nonce=challenge(),prior=new Map(snapshots);notice('Loading saved observations…');const result=await api('showcase?challenge='+nonce);if(current!==revision||mine!==refreshTicket)return;
  for(let i=0;i<result.workspaces.length;i++){const pid=result.workspaces[i].statement.workspace_id,old=prior.get(pid);if(old)result.workspaces[i]=await api('showcase/'+encodeURIComponent(pid)+'?challenge='+nonce+'&from_count='+old.statement.checkpoint.statement.event_count);}
  if(current!==revision||mine!==refreshTicket)return;
  if(result.workspaces.some(value=>value.statement.challenge!==nonce))throw Error('Collector returned a stale response. Refresh to request a new snapshot.');
  $('title').textContent=result.label;$('login').hidden=true;$('content').hidden=false;$('sign-out').hidden=false;$('collectors').replaceChildren();$('totals').replaceChildren();$('channel').replaceChildren();let totals={};let synthetic=false;
  snapshots.clear();for(const [i,value] of result.workspaces.entries()){const s=value.statement;snapshots.set(s.workspace_id,value);synthetic ||= s.synthetic;for(const [k,n] of Object.entries(s.counts))totals[k]=(totals[k]||0)+n;$('collectors').append(collectorCard(value,i,prior.get(s.workspace_id)));for(const channel of s.channels){const option=node('option','',channel.title+' · Collector '+(i+1));option.value=s.workspace_id+':'+channel.chat_id;option.title='Public profile observed '+date(channel.public_observed_at);$('channel').append(option);}}
  for(const [label,keys] of [['New messages',['message.new']],['Saved edits',['message.edited']],['Deletion observations',['message.deleted']],['History observations',['message.snapshot','message.recovered']]]){const box=node('div','total');box.append(node('strong','',keys.reduce((a,k)=>a+(totals[k]||0),0).toLocaleString()),node('span','',label));$('totals').append(box);}
  $('synthetic').hidden=!synthetic;$('updated').textContent='Updated '+date(new Date().toISOString());notice(result.unavailable?.length?result.unavailable.length+' collector(s) unavailable. Totals cover the available selection.':'');if([...$('channel').options].some(o=>o.value===selection))$('channel').value=selection;else {selection=$('channel').value;messageId=null;cursor=null;}
  if(selection){await feed(false);}else{$('feed').replaceChildren(node('p','empty','No public channels are currently available in this access.'));$('older').hidden=true;}
}
function eventCard(item){const card=node('article','event '+item.kind.split('.')[1]),head=node('header');const labels={'message.new':'Message captured','message.edited':'Edited version saved','message.deleted':'Deletion observed','message.snapshot':'History snapshot','message.recovered':'Content recovered','message.missing_on_recheck':'Missing on recheck'};head.append(node('strong','',labels[item.kind]||item.kind),node('time','',date(item.observed_at)));card.append(head);const shown=item.retained||item;
  if(item.retained)card.append(node('p','caption','Text retained from '+date(item.retained.observed_at)));
  card.append(node('p','message-text',shown.text??'No text was captured.'));
  const meta=node('div','metadata');if(shown.author)meta.append(node('span','redacted','Author · Redacted'));if(shown.profile)meta.append(node('span','redacted','Profile available · Redacted'));if(shown.attachment_present)meta.append(node('span','','Attachment present · not shared'));card.append(meta);
  const details=node('details');details.append(node('summary','','Record #'+item.seq+' · Message '+(item.message_id??'unknown')),node('p','','Original record hash'),node('code','',item.source_hash));if(shown.source_at)details.append(node('p','','Telegram timestamp · '+date(shown.source_at)));if(item.retained)details.append(node('p','','Retained text source hash'),node('code','',item.retained.source_hash));card.append(details);
  if(item.message_id&&messageId===null){const versions=node('button','','Saved versions & observations');versions.addEventListener('click',()=>{messageId=item.message_id;cursor=null;feed(false).catch(e=>notice(e.message,true));});card.append(versions);}return card;}
async function feed(append){
  const mine=++ticket;selection=$('channel').value;if(!selection)return;paged=append;
  const [pid,cid]=selection.split(':'),q=new URLSearchParams({kind:messageId?'all':$('filter').value,limit:'30'});
  if(append&&cursor)q.set('before',cursor);if(messageId)q.set('message_id',messageId);
  $('feed-status').textContent='Loading…';$('older').disabled=true;
  if(!append){$('feed').replaceChildren();$('older').hidden=true;}
  try{
    const value=await api('showcase/'+encodeURIComponent(pid)+'/chats/'+encodeURIComponent(cid)+'?'+q);
    if(mine!==ticket)return;const s=value.statement;
    for(const item of s.items)$('feed').append(eventCard(item));
    if(!append&&!s.items.length)$('feed').append(node('p','empty','No observations match this selection.'));
    cursor=s.next_before;$('older').hidden=!cursor;$('latest').hidden=messageId===null;
    $('feed-status').textContent=(messageId?'Saved observations for message '+messageId+'. ':'')+'Public profile observed '+date(s.channel.public_observed_at);
  }catch(error){if(mine===ticket)$('feed-status').textContent='Could not load these observations. Refresh to retry.';throw error;}
  finally{if(mine===ticket)$('older').disabled=false;}
}
for(const id of ['channel','filter'])$(id).addEventListener('change',()=>{messageId=null;cursor=null;feed(false).catch(e=>notice(e.message,true));});
$('older').addEventListener('click',()=>feed(true).catch(e=>notice(e.message,true)));
$('latest').addEventListener('click',()=>{messageId=null;cursor=null;feed(false).catch(e=>notice(e.message,true));});
$('refresh').addEventListener('click',()=>refresh().catch(e=>notice(e.message,true)));
const fragment=new URLSearchParams(location.hash.slice(1)),token=fragment.get('access');if(location.hash)history.replaceState(null,'',location.pathname);
if(token)exchangeAccessToken(token).catch(e=>notice(e.message,true));else if(session)restoreSession().catch(e=>notice(e.message,true));
setInterval(()=>{if(session&&!document.hidden&&!messageId&&!paged)refresh().catch(e=>notice(e.message,true));},60000);
