export function createCaseBoard(ctx){
  const {root,state,json,tr,trn,node,toast,may,openEvidence,openSlice,download}=ctx;
  const n=(tag,cls='',text='')=>node(tag,cls,text), t=value=>tr(value);
  let data=null,selected=null,revision=0,request=0,liveCursor=0,unread=0,offset=0,anchor=null,dialog=null,timer=null;
  const drafts=new Map();let threadTicket=0;
  const key=()=>state.workspaceRevision+':'+state.profile;
  const valid=(stamp,rev)=>stamp===key()&&rev===revision&&!!state.me;
  const btn=(text,fn,cls='quiet small')=>{const b=n('button',cls,t(text));b.type='button';b.addEventListener('click',async event=>{
    event.stopPropagation();if(b.disabled)return;b.disabled=true;try{await fn(event);}catch(error){if(!['AbortError','StaleView'].includes(error.name))toast(error.message,true);}finally{b.disabled=false;}});return b;};
  const field=(form,label,type='text',value='')=>{const wrap=n('label','board-field',t(label)),input=n(type==='textarea'?'textarea':'input');
    if(type!=='textarea')input.type=type;input.value=value;wrap.append(input);form.append(wrap);return input;};
  const select=(form,label,options)=>{const wrap=n('label','board-field',t(label)),input=n('select');for(const [value,text] of options)input.add(new Option(t(text),value));wrap.append(input);form.append(wrap);return input;};
  const time=value=>value?new Date(value).toLocaleString(undefined,{timeZone:'UTC',dateStyle:'medium',timeStyle:'short'})+' UTC':'—';
  const source=chat=>state.status?.targets?.find(item=>item.chat_id===chat)?.title||String(chat??t('Unknown chat'));
  const preview=value=>window.TgWitnessPrivacy?.render(value||'',{className:'board-evidence-text',tr})||n('p','board-evidence-text',value||'');
  const typeLabel=kind=>t({'board.bookmark':'Bookmark','board.highlight':'Highlight','board.slice':'Range slice','board.collection':'Collection'}[kind]||kind);
  const heading=n('div','page-heading board-heading'),intro=n('div');
  intro.append(n('span','eyebrow',t('INVESTIGATION')),n('h1','',t('Case Board')),n('p','page-description',t('Connect the observations. Keep your reasoning separate.')));
  const topActions=n('div','board-actions');topActions.append(btn('Slice by time',()=>sliceDialog()),btn('Presentation',()=>present()),btn('Export board',()=>download('board/export','case-board.json')));
  heading.append(intro,topActions);
  const privacy=n('p','board-private',t('Private to this case. Nothing here is sent to Telegram.'));
  const admin=n('p','board-admin',t('Posting as Main administrator. Create named access for each investigator.'));admin.hidden=true;
  const layout=n('div','board-layout'),left=n('aside','board-sidebar'),main=n('section','board-main'),right=n('aside','board-thread');
  left.setAttribute('aria-label',t('Collections and filters'));right.setAttribute('aria-label',t('Card discussion'));right.hidden=true;
  const collectionHead=n('div','board-side-heading');collectionHead.append(n('h2','',t('Collections')),btn('New',()=>collectionDialog()));
  const collections=n('div','board-collections'),filters=n('form','board-filters');filters.addEventListener('submit',event=>{event.preventDefault();void load();});
  left.append(collectionHead,collections,filters);
  const search=field(filters,'Search notes and quotes','search');search.placeholder=t('Search this case…');search.maxLength=200;
  const author=select(filters,'Investigator',[['','Everyone']]),chat=select(filters,'Chat',[['','All chats']]);
  const label=field(filters,'Label'),status=select(filters,'Status',[['','All states'],['open','Open'],['review','Under review'],['confirmed','Confirmed'],['dismissed','Dismissed']]);
  const kind=select(filters,'Card type',[['','All types'],['bookmark','Bookmark'],['highlight','Highlight'],['slice','Range slice']]);
  const since=field(filters,'From (UTC)','datetime-local'),until=field(filters,'Until (UTC)','datetime-local');
  const onlyComments=field(filters,'Only with comments','checkbox');
  const order=select(filters,'Feed order',[['bottom','New at the bottom'],['top','New at the top']]);
  filters.append(btn('Apply filters',()=>load(),'secondary'));
  let collection='';
  const stats=n('div','board-feed-heading'),count=n('span'),live=n('span','board-live',t('Signed team notes'));
  stats.append(count,live);const feed=n('div','board-feed');feed.setAttribute('aria-label',t('Case feed'));
  const more=btn('Load more',()=>load(true),'secondary board-more');more.hidden=true;
  main.append(stats,feed,more);layout.append(left,main,right);root.append(heading,privacy,admin,layout);
  search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(()=>load().catch(error=>toast(error.message,true)),350);});
  order.addEventListener('change',()=>render());

  function reset(){revision++;request++;threadTicket++;drafts.clear();data=null;selected=null;liveCursor=0;unread=0;anchor=null;collection='';offset=0;feed.replaceChildren();right.replaceChildren();right.hidden=true;collections.replaceChildren();closeDialog();badge();}
  function badge(){const el=document.getElementById('board-unread');if(el){el.hidden=!unread;el.textContent=String(unread);}}
  async function load(append=false){
    if(!may('board.read')){reset();return;}
    const stamp=key(),rev=revision,ticket=++request;
    const params=new URLSearchParams({limit:'50',offset:String(append?offset:0),order:'newest'});
    for(const [key,value] of Object.entries({collection,author:author.value,chat:chat.value,label:label.value,state:status.value,kind:kind.value,q:search.value,
      from:since.value?since.value+':00Z':'',to:until.value?until.value+':00Z':'',comments:onlyComments.checked?'true':''}))if(value)params.set(key,value);
    live.textContent=t('Loading…');const result=await json('board?'+params);
    if(!valid(stamp,rev)||ticket!==request)return;
    if(append&&data)result.cards=[...data.cards,...result.cards];data=result;offset=result.next_offset;
    liveCursor=Math.max(liveCursor,result.cursor);unread=0;badge();render();
    if(selected){const id=selected.card.id;await choose(id,true);}
  }
  function options(input,items){const old=input.value;input.replaceChildren(...items.map(([value,label])=>new Option(label,value)));if([...input.options].some(option=>option.value===old))input.value=old;}
  function render(){
    if(!data)return;admin.hidden=!state.me?.admin;
    topActions.children[0].hidden=!may('board.write');topActions.children[2].hidden=!may('export');
    collectionHead.lastElementChild.hidden=!may('board.manage');
    count.textContent=trn('{n} cards','{n} cards',data.total);live.textContent=t('Signed team notes');
    if(Object.values(data.limits).some(value=>value.exceeded))live.textContent=t('Soft limit reached. Existing cards remain available.');
    options(author,[['',t('Everyone')],...data.authors.map(item=>[item.id,item.label])]);
    options(chat,[['',t('All chats')],...(state.status?.targets||[]).map(item=>[String(item.chat_id),item.title])]);
    collections.replaceChildren();
    for(const item of [{id:'',title:t('All cards')},{id:'inbox',title:t('Inbox')},...data.collections]){
      const line=n('div','board-collection-line'),b=btn(item.title,()=>{collection=item.id;selected=null;right.hidden=true;return load();},'board-collection');
      b.setAttribute('aria-pressed',String(collection===item.id));line.append(b);
      if(item.annotation_hash&&may('board.manage'))line.append(btn('Edit',()=>collectionDialog(item)));
      collections.append(line);
    }
    feed.replaceChildren();let day='';
    const cards=order.value==='bottom'?[...data.cards].reverse():data.cards;
    for(const card of cards){const next=card.at.slice(0,10);if(next!==day){feed.append(n('div','board-day',next+' · UTC'));day=next;}feed.append(cardNode(card));}
    if(!cards.length){const empty=n('div','board-empty');empty.append(n('div','board-empty-symbol','⌑'),n('h2','',t('Build a trail of reasoning')),
      n('p','',t('Bookmark a record, highlight a passage or save every action in a time range. Your team can discuss each card here.')));feed.append(empty);}
    more.hidden=offset===null;
  }
  function cardNode(card,presentation=false){
    const article=n('article','board-card board-'+card.kind.split('.')[1]);article.dataset.cardId=card.id;
    const head=n('div','board-card-head'),avatar=n('span','board-avatar',(card.access_label||'?').slice(0,2).toUpperCase()),person=n('div');
    person.append(n('strong','',card.access_label),n('small','',time(card.at)));head.append(avatar,person,n('span','board-kind',typeLabel(card.kind)));article.append(head);
    article.append(n('h3','',card.title||typeLabel(card.kind)));
    if(card.target){const meta=n('div','board-target');meta.append(n('span','',source(card.target.chat_id)),n('code','','#'+card.target.seq+' · '+card.target.kind));article.append(meta);}
    if(card.kind==='board.highlight'){
      const quote=n('blockquote','board-quote board-color-'+card.color);quote.append(preview(card.range.quote));article.append(quote,n('small','board-version',t('Highlight is tied to this saved version.')));
    }else if(card.preview?.payload){article.append(preview(card.preview.payload.text||card.preview.payload.caption||t('Open the observation for its complete contents.')));}
    if(card.kind==='board.slice'){
      const summary=n('div','board-slice-summary');summary.append(n('strong','',String(card.snapshot.record_count)),n('span','',t('observed records at bookmark')));article.append(summary);
      if(card.snapshot.timeline?.bins){const values=card.snapshot.timeline.bins,max=Math.max(1,...values),svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 480 64');svg.classList.add('board-mini-timeline');svg.setAttribute('role','img');svg.setAttribute('aria-label',t('Activity by observation time'));
        values.forEach((count,index)=>{const rect=document.createElementNS(svg.namespaceURI,'rect');rect.setAttribute('x',String(index*20));rect.setAttribute('y',String(62-count/max*58));rect.setAttribute('width','15');rect.setAttribute('height',String(Math.max(1,count/max*58)));rect.setAttribute('rx','2');const title=document.createElementNS(svg.namespaceURI,'title');title.textContent=String(count);rect.append(title);svg.append(rect);});article.append(svg);}
      const bars=n('div','board-kind-counts');for(const [kind,count] of Object.entries(card.snapshot.counts||{})){const row=n('div');row.append(n('span','',kind),n('b','',String(count)));bars.append(row);}article.append(bars);
      article.append(n('p','board-range',[(card.query.chat_ids||[card.query.chat_id]).map(source).join(' · '),card.query.from?time(card.query.from):'',card.query.to?time(card.query.to):''].filter(Boolean).join(' / ')));
    }
    if(data?.thumbnails&&!presentation)for(const media of card.preview_media||[])article.append(ctx.media(media));
    if(card.note)article.append(n('p','board-note',card.note));
    const tags=n('div','board-tags');for(const label of card.labels||[])tags.append(n('span','board-tag',label));
    tags.append(n('span','board-state board-state-'+card.state,t({open:'Open',review:'Under review',confirmed:'Confirmed',dismissed:'Dismissed'}[card.state])));article.append(tags);
    if(card.dangling)article.append(n('p','board-warning',t('Dangling reference: the source observation is missing.')));
    if(!presentation){const actions=n('div','board-card-actions');actions.append(btn('Open',()=>openCard(card)),btn('Comment',()=>choose(card.id)),btn('Copy ref',()=>navigator.clipboard.writeText(card.target?'tgw://'+(state.status?.fingerprint||'').slice(0,8)+'/'+card.target.seq:'Case Board '+card.id)));
      if(may('board.write'))actions.append(btn('Edit',()=>editDialog(card)),btn('Move',()=>moveDialog(card)),btn('Status',()=>statusDialog(card)),btn('Remove',()=>removeCard(card)));
      actions.append(n('span','board-comment-count',trn('{n} comments','{n} comments',card.comment_count||0)));article.append(actions);}
    return article;
  }
  async function openCard(card){
    if(card.kind==='board.slice'){await openSlice(card);return;}
    const stamp=key(),rev=revision,detail=await json('board/card/'+card.id);if(!valid(stamp,rev))return;
    if(!detail.target){toast(t('Dangling reference: the source observation is missing.'),true);return;}
    await openEvidence(detail.target,card.range);
  }
  async function choose(id,refresh=false){
    const stamp=key(),rev=revision,ticket=++threadTicket;selected={card:{id}};right.hidden=false;if(!refresh)right.replaceChildren(n('p','',t('Loading…')));
    const [detail,participants]=await Promise.all([json('board/card/'+id),json('board/card/'+id+'/participants')]);if(!valid(stamp,rev)||selected?.card.id!==id||ticket!==threadTicket||state.view!=='board')return;
    const oldText=right.querySelector('.board-comment-form textarea'),focused=oldText===document.activeElement,caret=oldText?[oldText.selectionStart,oldText.selectionEnd]:null;
    const draft=drafts.get(id)||{text:'',parent:id,mentions:[]};drafts.set(id,draft);
    selected=detail;right.replaceChildren();const header=n('div','board-thread-heading');header.append(n('h2','',t('Discussion')),btn('Close',()=>{selected=null;right.hidden=true;}));right.append(header,cardNode({...detail.card,preview:detail.target},true));
    const thread=n('div','board-comments');let replyTo=draft.parent;
    for(const comment of detail.thread){const item=n('article','board-comment');item.append(n('strong','',comment.access_label),n('small','',time(comment.at)));
      if(comment.parent_id!==id)item.append(n('small','',t('Reply in thread')));
      item.append(n('p','',comment.removed?t('Comment removed; history retained.'):comment.text));
      if(may('board.write')&&!comment.removed)item.append(btn('Reply',()=>{replyTo=comment.id;draft.parent=replyTo;replyLabel.textContent=tr('Reply to {name}',{name:comment.access_label});text.focus();}));thread.append(item);}
    right.append(thread);
    const replyLabel=n('p','hint',t('Add a team comment')),form=n('form','board-comment-form'),text=field(form,'Comment','textarea');text.required=true;text.maxLength=20000;
    text.value=draft.text;text.addEventListener('input',()=>{draft.text=text.value;});
    if(replyTo!==id)replyLabel.textContent=t('Reply in thread');
    const mentions=new Set(draft.mentions);
    const mention=select(form,'Mention investigator',[['','No mention'],...participants.map(item=>[item.id,item.label])]);
    mention.addEventListener('change',()=>{const person=participants.find(item=>item.id===mention.value);if(!person)return;mentions.add(person.id);text.value+=(text.value&&!text.value.endsWith(' ')?' ':'')+'@'+person.label+' ';draft.text=text.value;draft.mentions=[...mentions];mention.value='';text.focus();});
    form.prepend(replyLabel);form.append(btn('Post comment',async()=>{if(!text.reportValidity())return;const saved=await post('comment',{parent_id:replyTo,text:text.value,mentions:[...mentions]});if(saved){drafts.delete(id);await choose(id);}},'primary'));
    form.addEventListener('submit',event=>event.preventDefault());if(may('board.write'))right.append(form);
    if(focused&&may('board.write')){text.focus({preventScroll:true});if(caret)text.setSelectionRange(...caret);}
    if(detail.status_history.length){right.append(n('h3','',t('Status history')));for(const item of detail.status_history)right.append(n('p','board-status-history',item.access_label+' · '+item.state+' · '+time(item.at)+(item.reason?' — '+item.reason:'')));}
    if(detail.related.length){right.append(n('h3','',t('Related cards')));for(const related of detail.related)right.append(btn(related.slice(0,8),()=>choose(related)));}
    if(detail.card.kind==='board.slice'){
      right.append(btn('Explore slice',()=>sliceRecords(id)));
      if(may('export'))right.append(btn('JSON excerpt',()=>download('board/slice/'+id+'/export','board-slice.json')),btn('CSV excerpt',()=>download('board/slice/'+id+'/export?format=csv','board-slice.csv')));
    }
  }
  function closeDialog(){if(dialog){dialog.close();dialog.remove();dialog=null;}}
  function modal(title){closeDialog();dialog=n('dialog','board-dialog');const own=dialog,head=n('div','board-dialog-heading');head.append(n('h2','',t(title)),btn('Close',closeDialog));
    const body=n('div');dialog.append(head,body);dialog.setAttribute('aria-label',t(title));dialog.addEventListener('close',()=>{own.remove();if(dialog===own)dialog=null;},{once:true});document.body.append(dialog);dialog.showModal();return body;}
  async function post(action,payload){const stamp=key(),rev=revision;const saved=await json('board/'+action,payload);if(!valid(stamp,rev))return null;
    liveCursor=Math.max(liveCursor,saved.seq);toast(t('Added to Case Board. Nothing was sent to Telegram.'));if(state.view==='board')await load();return saved;}
  async function bookmark(event){if(!may('board.write'))return;await post('bookmark',{target:{event_hash:event.hash,seq:event.seq}});}
  async function bookmarkOptions(event){const stamp=key(),rev=revision,result=await json('board?limit=1');if(!valid(stamp,rev))return;
    const body=modal('Bookmark options'),title=field(body,'Title'),note=field(body,'Note','textarea'),labels=field(body,'Labels, separated by commas'),collection=select(body,'Collection',[['','Inbox'],...result.collections.map(item=>[item.id,item.title])]);
    body.append(btn('Add to board',async()=>{const saved=await post('bookmark',{target:{event_hash:event.hash,seq:event.seq},title:title.value,note:note.value,labels:labels.value.split(',').map(value=>value.trim()).filter(Boolean)});
      if(saved&&collection.value)await post('move',{card_id:saved.payload.id,collection_id:collection.value});if(saved)closeDialog();},'primary'));}
  async function editDialog(card){const body=modal('Edit card'),title=field(body,'Title','text',card.title||''),note=field(body,'Note','textarea',card.note||''),labels=field(body,'Labels, separated by commas','text',(card.labels||[]).join(', '));
    body.append(n('p','hint',t('Saving appends a signed revision. The previous version remains in the annotations history.')),
      btn('Save revision',async()=>{const payload={id:card.id,supersedes:card.annotation_hash,title:title.value,note:note.value,labels:labels.value.split(',').map(x=>x.trim()).filter(Boolean)};
        if(card.target)payload.target=card.target;if(card.range){payload.range=card.range;payload.color=card.color;}if(card.query)payload.query=card.query;
        await post(card.kind.split('.')[1],payload);closeDialog();},'primary'));}
  async function highlight(event,range){const body=modal('Highlight → board');body.append(preview(range.quote));
    const color=select(body,'Highlight color',[['amber','Amber'],['blue','Blue'],['green','Green'],['rose','Rose']]),note=field(body,'Note','textarea'),labels=field(body,'Labels, separated by commas');
    body.append(btn('Add to board',async()=>{const saved=await post('highlight',{target:{event_hash:event.hash,seq:event.seq},range:{...range,version:event.hash},color:color.value,note:note.value,labels:labels.value.split(',').map(x=>x.trim()).filter(Boolean)});if(saved)closeDialog();},'primary'));
  }
  async function sliceDialog(initial={}){
    const body=modal('Save a range slice');body.append(n('p','hint',t('Includes every observed action by default. Times below are observation times in UTC.')));
    const title=field(body,'Title'),chats=field(body,'Chat IDs, separated by commas','text',(initial.chat_ids||[initial.chat_id??state.chat??state.source]).filter(Boolean).join(','));
    const from=field(body,'From (UTC)','datetime-local',initial.from?initial.from.slice(0,16):''),to=field(body,'Until (UTC)','datetime-local',initial.to?initial.to.slice(0,16):'');
    const start=field(body,'First message ID','number',initial.from_message_id||''),end=field(body,'Last message ID','number',initial.to_message_id||'');
    const actors=field(body,'Actor IDs, separated by commas','text',(initial.actors||[]).join(','));
    body.append(n('p','hint',t('Actor means an actor explicitly recorded in the observation. An editor, deleter or reactor is not inferred from the message author.')));
    const kinds=field(body,'Event kinds (all, or comma separated)','text',Array.isArray(initial.kinds)?initial.kinds.join(','):'all');
    const kindChoices=n('fieldset','board-kind-options');kindChoices.append(n('legend','',t('Include actions')));body.insertBefore(kindChoices,kinds.parentElement);
    const allKinds=field(kindChoices,'All observed actions','checkbox'),checks=[];
    for(const [value,label] of [['message.*','Messages, edits and deletions'],['reaction.snapshot','Reactions'],['membership.*,service.*','Membership and service actions'],['interaction.*,button.pressed','Buttons and own actions'],['media.*','Media'],['chat.*,consensus.*','Chat changes and corroboration']]){
      const check=field(kindChoices,label,'checkbox');checks.push([check,value]);check.addEventListener('change',()=>{kinds.value=checks.filter(([input])=>input.checked).map(([,value])=>value).join(',');kinds.dispatchEvent(new Event('input',{bubbles:true}));});}
    const syncKinds=()=>{allKinds.checked=kinds.value.trim()==='all';for(const [check,value]of checks){check.disabled=allKinds.checked;check.checked=allKinds.checked||value.split(',').every(kind=>kinds.value.split(',').map(v=>v.trim()).includes(kind));}};
    allKinds.addEventListener('change',()=>{kinds.value=allKinds.checked?'all':checks.map(([,value])=>value).join(',');kinds.dispatchEvent(new Event('input',{bubbles:true}));});kinds.addEventListener('input',syncKinds);syncKinds();
    const search=field(body,'Search in saved payload','text',initial.search||''),hideSystem=field(body,'Hide routine system records','checkbox');hideSystem.checked=!!initial.hide_system;
    const unscoped=field(body,'Include unknown-chat deletion notices separately','checkbox');unscoped.checked=!!initial.include_unscoped;unscoped.disabled=!!state.status?.chats_limited;
    const note=field(body,'Note','textarea'),summary=n('div','board-preview-summary');summary.role='status';body.append(summary);
    const query=()=>({chat_ids:chats.value.split(',').map(x=>x.trim()).filter(Boolean).map(Number).filter(x=>Number.isSafeInteger(x)&&x!==0),
      ...(from.value?{from:from.value+':00Z'}:{}),...(to.value?{to:to.value+':00Z'}:{}),
      ...(start.value?{from_message_id:Number(start.value)}:{}),...(end.value?{to_message_id:Number(end.value)}:{}),
      actors:actors.value?actors.value.split(',').map(x=>Number(x.trim())):[],kinds:kinds.value.trim()==='all'?'all':kinds.value.split(',').map(x=>x.trim()),include_unscoped:unscoped.checked,search:search.value,hide_system:hideSystem.checked});
    let checked='';const add=btn('Add to board',async()=>{const q=query();if(JSON.stringify(q)!==checked)throw new Error(t('Preview the current slice before adding it.'));
      const saved=await post('slice',{title:title.value,note:note.value,query:q});if(saved)closeDialog();},'primary');add.disabled=true;
    body.append(btn('Preview all actions',async()=>{const q=query(),stamp=key(),rev=revision,container=dialog,result=await json('board/slice-preview',q);if(!valid(stamp,rev)||container!==dialog)return;
      summary.replaceChildren(n('strong','',trn('{n} records','{n} records',result.record_count)));for(const [kind,count] of Object.entries(result.counts))summary.append(n('span','board-tag',kind+' · '+count));checked=JSON.stringify(q);add.disabled=false;},'secondary'),add);
    body.addEventListener('input',()=>{add.disabled=true;});
  }
  async function collectionDialog(item=null){const body=modal(item?'Edit collection':'New collection'),title=field(body,'Title','text',item?.title||''),description=field(body,'Description','textarea',item?.description||''),chats=field(body,'Chat IDs (empty means whole workspace)','text',(item?.chat_ids||[]).join(',')),order=field(body,'Order','number',item?.order||0);
    body.append(btn('Save collection',async()=>{await post('collection',{...(item?{id:item.id,supersedes:item.annotation_hash}:{}),title:title.value,description:description.value,chat_ids:chats.value?chats.value.split(',').map(Number):[],card_ids:[],order:Number(order.value)});closeDialog();},'primary'));}
  async function moveDialog(card){if(!data)data=await json('board');const body=modal('Move card'),choice=select(body,'Collection',[['','Inbox'],...data.collections.map(item=>[item.id,item.title])]);choice.value=card.collection_id||'';
    body.append(btn('Move',async()=>{await post('move',{card_id:card.id,collection_id:choice.value||null});closeDialog();},'primary'));}
  async function statusDialog(card){const body=modal('Change status'),options=[['open','Open'],['review','Under review']];if(may('board.manage'))options.push(['confirmed','Confirmed'],['dismissed','Dismissed']);
    const value=select(body,'Status',options),reason=field(body,'Reason','textarea');value.value=card.state;body.append(n('p','hint',t('A team status is an opinion, not a verification result.')),
      btn('Save status',async()=>{await post('status',{card_id:card.id,state:value.value,reason:reason.value});closeDialog();},'primary'));}
  async function removeCard(card){const body=modal('Remove card');body.append(n('p','',t('The card will be hidden from the feed. Its signed history remains.')),btn('Remove',async()=>{await post('remove',{card_id:card.id});selected=null;right.hidden=true;closeDialog();},'danger'));}
  async function sliceRecords(id){const body=modal('Slice records'),stamp=key(),rev=revision,container=dialog;let next=0;const table=n('table','board-record-table'),head=n('tr');
    for(const title of ['Observed / Telegram time','Kind','Actor','Target','Summary','Record'])head.append(n('th','',t(title)));const thead=n('thead'),tbody=n('tbody');thead.append(head);table.append(thead,tbody);
    const summary=n('p','hint'),wrap=n('div','board-record-scroll');wrap.append(table);body.append(summary,wrap);
    const more=btn('Load more',page,'secondary');body.append(more);
    async function page(){const result=await json('board/slice/'+id+'/records?limit=100&offset='+next);if(!valid(stamp,rev)||dialog!==container)return;
      summary.textContent=tr('Slice recomputed: +{added} / −{removed} records since bookmark.',result.diff);next=result.next_offset;more.hidden=next===null;
      for(const item of result.records){const e=item.event,row=n('tr',item.added_since_bookmark?'board-record-added':'');
        row.append(n('td','',time(e.observed_at)+' / '+time(e.source_at)),n('td','',e.kind),n('td','',String(e.actor_id??'—')),n('td','',source(e.chat_id)+' / '+String(e.message_id??'—')));
        const summary=n('td');summary.append(preview(String(e.payload.text||e.payload.caption||e.payload.service_action||e.payload.reason||'').slice(0,300)));row.append(summary);
        const link=n('td');link.append(btn('#'+e.seq,()=>{closeDialog();return openEvidence(e);}));row.append(link);tbody.append(row);
        if(item.reaction_delta){const line=n('tr'),cell=n('td');cell.colSpan=6;cell.textContent=t('Reaction counts changed between observations; actor lists may be incomplete.')+' '+time(item.reaction_delta.from)+' → '+time(item.reaction_delta.to)+' · '+JSON.stringify(item.reaction_delta.count_changes);
          if(item.reaction_delta.recent_actor_observations.length)cell.append(n('pre','board-source-json',JSON.stringify(item.reaction_delta.recent_actor_observations,null,2)));line.append(cell);tbody.append(line);}
      }}await page();}
  async function present(){if(!data?.cards.length)return;const body=modal('Presentation'),own=dialog,stamp=key(),rev=revision,profile=state.profile,token=state.token;dialog.classList.add('board-presentation');
    const stage=n('div'),tabs=n('div','board-actions'),controls=n('div','board-presentation-controls');let index=0,mode='card',drawTicket=0,items=[],nextOffset=0;
    const counter=n('span'),previous=btn('Previous',async()=>{index=Math.max(0,index-1);await draw();}),next=btn('Next',async()=>{index=Math.min(items.length-1,index+1);await draw();});
    for(const [value,label] of [['card','Card'],['context','Source context'],['comments','Team comments']])tabs.append(btn(label,async()=>{mode=value;await draw();},'secondary small'));
    controls.append(previous,counter,next);body.append(tabs,stage,controls);stage.append(n('p','',t('Loading…')));
    do{const result=await json('board?'+new URLSearchParams({collection,limit:'200',offset:String(nextOffset),order:'oldest'}));if(!valid(stamp,rev)||dialog!==own)return;items.push(...result.cards);nextOffset=result.next_offset;}while(nextOffset!==null);
    async function draw(){const ticket=++drawTicket;if(!items.length)return;const card=items[index];counter.textContent=(index+1)+' / '+items.length;previous.disabled=index===0;next.disabled=index===items.length-1;
      const detail=await json('board/card/'+card.id);if(!valid(stamp,rev)||dialog!==own||ticket!==drawTicket)return;
      if(mode==='card')stage.replaceChildren(cardNode({...card,preview:detail.target},true));
      else if(mode==='context'){const context=n('div','board-card');context.append(n('h3','',t('Source context')),n('p','hint',t('Team interpretation is separate from this saved observation.')));
        const current=()=>valid(stamp,rev)&&state.token===token&&dialog===own&&ticket===drawTicket&&state.view==='board'&&mode==='context';
        if(detail.target){const event=detail.target,reveal=event.chat_id!=null&&event.message_id!=null?
            ()=>json('privacy/reveal',{chat_id:event.chat_id,message_id:event.message_id},{profile,token}):null;
          context.append(preview(event.payload.text||event.payload.caption||''),n('p','hint','#'+event.seq+' · '+time(event.observed_at)),
            window.TgWitnessPrivacy.renderRecord(event,{className:'board-source-json',tr,current,reveal}));}
        else context.append(window.TgWitnessPrivacy.renderRecord(card.query,{className:'board-source-json',tr,current}));stage.replaceChildren(context);}
      else{const comments=n('div','board-card');comments.append(n('h3','',t('Team comments')));for(const item of detail.thread.filter(item=>!item.removed))comments.append(n('strong','',item.access_label+' · '+time(item.at)),n('p','board-note',item.text));if(!detail.thread.length)comments.append(n('p','hint',t('No comments yet.')));stage.replaceChildren(comments);}
    }
    dialog.addEventListener('keydown',event=>{if(event.key==='ArrowRight')next.click();if(event.key==='ArrowLeft')previous.click();});await draw();}
  function attach(element,event,content=null){
    if(!may('board.write'))return;const actions=element.querySelector('.bubble-meta,.event-open')||element;
    actions.append(btn('To board',()=>bookmark(event),'text-link board-save'));const more=btn('⋯',()=>bookmarkOptions(event),'text-link board-save');more.setAttribute('aria-label',t('Bookmark options'));more.title=t('Bookmark options');actions.append(more);element.tabIndex=element.tabIndex<0?0:element.tabIndex;
    element.addEventListener('keydown',e=>{if(e.key.toLowerCase()==='b'&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!e.target.closest('input,textarea,select')){e.preventDefault();void bookmark(event).catch(error=>toast(error.message,true));}});
    element.addEventListener('click',e=>{if(!e.shiftKey||e.target.closest('button,a,input'))return;e.preventDefault();e.stopPropagation();
      if(anchor&&anchor.chat_id===event.chat_id&&event.message_id&&anchor.message_id){void sliceDialog({chat_id:event.chat_id,from_message_id:Math.min(anchor.message_id,event.message_id),to_message_id:Math.max(anchor.message_id,event.message_id)});anchor=null;}
      else{anchor=event;toast(t('Range start selected. Shift-click the second record.'));}},{capture:true});
    if(content)content.addEventListener('mouseup',()=>{const selection=window.getSelection();if(!selection?.rangeCount||selection.isCollapsed)return;
      const range=selection.getRangeAt(0);if(!content.contains(range.startContainer)||!content.contains(range.endContainer))return;
      const prefix=range.cloneRange();prefix.selectNodeContents(content);prefix.setEnd(range.startContainer,range.startOffset);
      const quote=range.toString(),start=Array.from(prefix.toString()).length,length=Array.from(quote).length;
      if(Array.from(event.payload?.text||'').slice(start,start+length).join('')!==quote)return;
      const old=element.querySelector('.board-highlight-action');old?.remove();const action=btn('Highlight → board',()=>highlight(event,{field:'text',start,length,quote}),'secondary small board-highlight-action');actions.append(action);
    });
  }
  return {load,reset,cursor:()=>liveCursor,attach,bookmark,sliceDialog,explore:sliceRecords,
    live(notes){liveCursor=Math.max(liveCursor,...notes.map(item=>item.seq));if(state.view==='board'){clearTimeout(timer);timer=setTimeout(()=>load().catch(error=>toast(error.message,true)),180);}else{unread+=notes.length;badge();}},
    leave(){request++;threadTicket++;closeDialog();}};
}
