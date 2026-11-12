export function createReportSelection({root,tr,json,getOwner,ready,options,active}) {
  const find=id=>root.querySelector('#'+id), kinds=[...root.querySelectorAll('[data-report-kind]')];
  const make=(tag,text='',cls='')=>{const el=document.createElement(tag);el.textContent=String(text??'');if(cls)el.className=cls;return el;};
  const mask=text=>window.TgWitnessPrivacy?.preview(String(text??''))??tr('Message preview unavailable');
  let catalog={chats:[],senders:[]}, response=null, request=0, revision=0, pending=false, controller=null, stamp=null;
  const count=value=>Number(value||0).toLocaleString();
  const fields={chats:find('report-selection-chats'),senders:find('report-selection-senders')};
  const containers={chats:find('report-chat-catalog'),senders:find('report-sender-catalog')};
  const searches={chats:root.querySelector('[data-report-search=chats]'),senders:root.querySelector('[data-report-search=senders]')};
  function ids(field){
    const chunks=field.value.split(/[\s,;]+/).filter(Boolean);
    const valid=chunks.every(value=>/^-?[1-9]\d*$/.test(value)&&Number.isSafeInteger(Number(value)));
    field.setCustomValidity(valid?'':tr('Enter whole Telegram IDs separated by commas.'));
    return valid?[...new Set(chunks.map(Number))]:[];
  }
  function read(){
    const enabled=find('report-selection-chosen').checked,from=find('report-selection-from').value,to=find('report-selection-to').value;
    if(!enabled){
      for(const field of [fields.chats,fields.senders,find('report-selection-to'),kinds[0]])field.setCustomValidity('');
      return {enabled:false,chats:[],senders:[],date_from:'',date_to:'',kinds:kinds.map(input=>input.dataset.reportKind),id_gaps:find('report-selection-gaps').checked};
    }
    find('report-selection-to').setCustomValidity(from&&to&&from>to?tr('The end date must not be earlier than the start date.'): '');
    const selected=kinds.filter(input=>input.checked).map(input=>input.dataset.reportKind);
    kinds[0].setCustomValidity(selected.length?'':tr('Choose at least one record type.'));
    return {enabled,chats:ids(fields.chats),senders:ids(fields.senders),
      date_from:from,date_to:to,kinds:selected,id_gaps:find('report-selection-gaps').checked};
  }
  function controls(){
    find('report-selection-options').disabled=!find('report-selection-chosen').checked;
    find('report-selection-options').hidden=!find('report-selection-chosen').checked;
    find('report-preview-run').disabled=pending;
    find('report-load-catalog').disabled=pending;
  }
  function renderCatalog(key){
    const selected=new Set(ids(fields[key])), query=searches[key].value.trim().toLowerCase();
    const all=new Map((catalog[key]||[]).map(row=>[Number(row.id),row]));
    for(const id of selected)if(!all.has(id))all.set(id,{id,count:null});
    const rows=[...all.values()].filter(row=>String(row.id).includes(query)||String(row.title||'').toLowerCase().includes(query));
    const nodes=rows.map(row=>{
      const label=make('label','','report-catalog-row'),input=make('input');input.type='checkbox';input.checked=selected.has(Number(row.id));
      input.dataset.reportChoice=key;input.dataset.id=String(row.id);
      const title=key==='chats'&&row.title?mask(row.title):tr(key==='chats'?'Chat {id}':'Account {id}',{id:row.id});
      const info=make('span','','report-catalog-label');info.append(make('strong',title),make('small',String(row.id)));
      label.append(input,info,make('span',row.count===null?'—':count(row.count),'report-catalog-number'));
      input.addEventListener('change',()=>{
        const current=new Set(ids(fields[key]));if(input.checked)current.add(Number(row.id));else current.delete(Number(row.id));
        fields[key].value=[...current].join(', ');fields[key].dispatchEvent(new Event('input',{bubbles:true}));
      });return label;
    });
    const empty=catalog[key+'_status']==='too_many_groups'?tr('Too many choices to list. Enter the Telegram IDs below.')
      :response?tr('No matches.'):tr('Load the workspace to see available choices.');
    containers[key].replaceChildren(...(nodes.length?nodes:[make('p',empty,'hint')]));
    if(nodes.length&&catalog[key+'_status']==='too_many_groups')containers[key].prepend(make('p',empty,'hint'));
    find(key==='chats'?'report-chat-count':'report-sender-count').textContent=selected.size
      ?tr('{n} selected',{n:count(selected.size)}):tr(key==='chats'?'All chats included':'All authors included');
  }
  function changed(event){
    if(event?.target?.matches('[data-report-search]'))return;
    revision++;controls();read();
    if(event?.target===fields.chats||event?.target===fields.senders||event?.target?.name==='report-selection-mode'){
      renderCatalog('chats');renderCatalog('senders');
    }
    if(response||pending){find('report-preview-stale').hidden=false;find('report-preview-result').dataset.stale='true';}
  }
  function table(headings,rows,cls=''){
    const scroll=make('div','','report-preview-scroll'),el=make('table','',cls),head=make('thead'),trHead=make('tr');
    for(const heading of headings){const cell=make('th',heading);cell.scope='col';trHead.append(cell);}head.append(trHead);
    const body=make('tbody');for(const row of rows){const line=make('tr');for(const item of row){const cell=make('td');if(item instanceof Node)cell.append(item);else cell.textContent=String(item??'—');line.append(cell);}body.append(line);}
    el.append(head,body);scroll.append(el);return scroll;
  }
  function chart(title,rows){
    const block=make('section','','report-preview-chart');block.append(make('h4',tr(title)));
    const maximum=Math.max(1,...rows.map(row=>Number(row.value||0)));
    for(const row of rows){
      const line=make('div','','report-preview-bar'),track=make('span','','report-preview-track'),fill=make('span');
      fill.style.width=(100*Number(row.value||0)/maximum)+'%';track.append(fill);track.setAttribute('aria-hidden','true');
      line.append(make('span',row.label),track,make('b',count(row.value)));block.append(line);
    }
    if(!rows.length)block.append(make('p',tr('No observations in this selection.'),'hint'));
    return block;
  }
  function rowLabel(row){return tr(row.label||'Unknown',row.label_values||{});}
  const kindLabel=kind=>({
    'message.new':tr('New message'),'message.snapshot':tr('History observation'),'message.recovered':tr('Recovered message'),
    'message.edited':tr('Edit'),'message.deleted':tr('Deletion notice'),'message.missing_on_recheck':tr('Missing on recheck')
  }[kind]||String(kind||''));
  function message(row){
    if(!row)return make('span',tr('Not available'));
    const block=make('div','','report-preview-message');
    block.append(make('small','#'+row.seq+' · '+tr('Message {id}',{id:row.message_id??'—'})+' · '+String(row.observed_at||'')),make('p',mask(row.text)));
    return block;
  }
  function changeVersion(row,label){
    const block=make('div','','report-change-version');
    if(label)block.append(make('strong',label));
    block.append(make('small','#'+row.seq+' · '+kindLabel(row.kind)+' · '+String(row.observed_at||'')));
    if(row.context_only)block.append(make('span',tr('Context outside the selected filters'),'report-change-context'));
    block.append(make('p',row.withheld?tr('Message text was not retained.'):row.text?mask(row.text):tr('(no text)')));
    if(row.text_truncated)block.append(make('span',tr('Text shortened in this preview.'),'hint'));
    return block;
  }
  function renderChanges(changes){
    const section=make('section','','report-preview-changes');
    section.append(make('h4',tr('Changes and deleted messages')),
      make('p',tr('Selected changes with saved message history. Versions outside the filters are marked as context.'),'hint'));
    for(const row of changes.messages||[]){
      const card=make('article','','report-change-card'),versions=row.versions||[],latest=versions.at(-1),previous=versions.at(-2);
      card.append(make('h5',tr('Chat {id}',{id:row.chat_id})+' · '+tr('Message {id}',{id:row.message_id})));
      if(previous&&latest?.kind==='message.edited'){
        const pair=make('div','','report-change-pair');pair.append(changeVersion(previous,tr('Before')),changeVersion(latest,tr('After')));card.append(pair);
      }else if(latest)card.append(changeVersion(latest,tr('Saved version')));
      const earlier=versions.slice(0,previous&&latest?.kind==='message.edited'?-2:-1);
      if(earlier.length){const detail=make('details');detail.append(make('summary',tr('Earlier saved versions')));
        for(const version of earlier)detail.append(changeVersion(version));card.append(detail);}
      for(const gone of row.gone||[]){
        const notice=make('div','','report-change-gone');
        notice.append(make('strong',kindLabel(gone.kind)),make('small','#'+gone.seq+' · '+String(gone.observed_at||'')));
        if(gone.context_only)notice.append(make('span',tr('Context outside the selected filters'),'report-change-context'));
        const retained=versions.find(version=>version.seq===gone.previous_version_seq);
        if(retained)notice.append(changeVersion(retained,tr('Last saved content before this observation')));
        else notice.append(make('p',tr(gone.previous_version_seq==null?'No message content was saved before this observation.'
          :'The saved version is outside this preview. Open the report for the full context.')));
        card.append(notice);
      }
      if(row.versions_truncated||row.gone_truncated)card.append(make('p',tr('Preview shortened. Open the report for the full saved history.'),'hint'));
      section.append(card);
    }
    if(!changes.messages?.length)section.append(make('p',tr('No edits or deletion observations match these choices.'),'hint'));
    if(changes.truncated)section.append(make('p',tr('Showing {shown} of {total} changed messages.',{
      shown:count(changes.listed??changes.messages?.length),total:count(changes.total??changes.messages_changed)}),'hint'));
    return section;
  }
  function render(data){
    const target=find('report-preview-result'),source=data.source||{},counts=data.counts||{},stats=make('dl','','report-preview-counts');
    for(const [name,value] of [[tr('Selected records'),counts.selected_records],[tr('Message observations'),counts.message_observations],
      [tr('Observed message senders'),counts.participants],[tr('Chats'),counts.chats]]){const entry=make('div');entry.append(make('dt',name),make('dd',count(value)));stats.append(entry);}
    const provenance=make('p',tr('Calculated from {n} journal records, through record #{last}.',{n:count(source.records),last:source.last_seq??'—'}),'hint');
    target.replaceChildren(stats,provenance);
    const anchor=make('details'),summary=make('summary',tr('Journal head'));anchor.append(summary,make('code',source.journal_head||'—'));target.append(anchor);
    if(!counts.selected_records)target.append(make('p',tr('No records match these choices. Change the filters and build the preview again.'),'report-preview-empty'));
    const analytics=data.analytics||{},grid=make('div','','report-preview-charts');
    if(analytics.activity){
      const rows=analytics.activity.rows||[];
      grid.append(chart('Activity over time',rows.slice(-36).map(row=>({label:row.period,value:row.total}))));
      if(rows.length>36)grid.append(make('p',tr('Showing the latest {n} recorded periods. The report includes the complete selected period.',{n:36}),'hint'));
    }
    if(analytics.participants){const block=chart('Participant activity',(analytics.participants.rows||[]).map(row=>({label:rowLabel(row),value:row.total})));
      block.append(make('p',tr('Sender counts use new messages, history observations and recovered messages.'),'hint'));grid.append(block);}
    if(analytics.chats)grid.append(chart('Activity by chat',(analytics.chats.rows||[]).map(row=>({label:rowLabel(row),value:row.total}))));
    if(analytics.hourly){
      const block=make('section','','report-preview-chart report-preview-hours');block.append(make('h4',tr('Activity by weekday and hour')));
      const days=[tr('Monday'),tr('Tuesday'),tr('Wednesday'),tr('Thursday'),tr('Friday'),tr('Saturday'),tr('Sunday')],rows=analytics.hourly.rows||[];
      const maximum=Math.max(1,...rows.flat());
      block.append(table([tr('UTC'),...Array.from({length:24},(_,hour)=>String(hour).padStart(2,'0'))],rows.map((row,day)=>[
        days[day],...row.map(value=>{const cell=make('span',count(value),'report-heat-cell');cell.style.backgroundColor='rgb(36 126 140 / '+(.05+.45*Number(value)/maximum)+')';return cell;})
      ]),'report-heat-table'));grid.append(block);
    }
    if(grid.children.length){target.append(make('p',tr('Activity uses observation times in UTC. Counts are recorded observations, not unique messages.'),'hint'),grid);}
    for(const key of ['activity','participants','chats'])if(analytics[key]?.status&&analytics[key].status!=='available')
      target.append(make('p',tr('A chart could not be grouped within the report limits. No approximate counts are shown.'),'hint'));
    if(data.changes)target.append(renderChanges(data.changes));
    target.append(make('h4',tr('Selected message samples')));
    const messages=data.messages||{},rows=messages.rows||[];
    target.append(table([tr('Record'),tr('Chat'),tr('Type'),tr('Observed at (UTC)'),tr('Message preview')],rows.map(row=>[
      '#'+row.seq,String(row.chat_id??'—'),kindLabel(row.kind),String(row.observed_at||'—'),message(row)
    ]),'report-message-table'));
    target.append(make('p',tr('Showing {shown} of {total} selected records. Possible secrets are masked in this preview.',{shown:count(rows.length),total:count(messages.total)}),'hint'));
    const gaps=data.id_gaps||{};
    if(gaps.enabled){
      target.append(make('h4',tr('Missing message IDs')),make('p',tr('{ranges} ranges, {ids} message IDs not observed.',{ranges:count(gaps.ranges_total),ids:count(gaps.ids_total)}),'hint'));
      target.append(table([tr('Chat'),tr('Missing IDs'),tr('Before the gap'),tr('After the gap')],(gaps.rows||[]).map(row=>[
        String(row.chat_id),String(row.start)+' – '+String(row.end)+' ('+count(row.count)+')',message(row.before),message(row.after)
      ]),'report-gap-table'));
      if(gaps.truncated)target.append(make('p',tr('Preview shortened. The saved report lists the available gap details.'),'hint'));
      target.append(make('p',tr('Missing numbers are gaps in the observed IDs; deletions are recorded as separate notices. Neighboring records are context and may be outside the chosen authors, event types or dates.'),'hint'));
    }
  }
  async function preview(reveal=true){
    if(!ready()||pending)return;
    const body=options();if(!root.reportValidity())return;
    const mine=++request,owner=getOwner(),version=revision;
    controller?.abort();controller=new AbortController();pending=true;controls();
    find('report-preview-status').textContent=tr('Reading the selected journal records…');
    find('report-preview-retry').hidden=true;
    const current=()=>mine===request&&owner===getOwner()&&active();
    try{
      const data=await json('report-preview',body,{signal:controller.signal});
      if(!current())return;
      if(version!==revision){find('report-preview-status').textContent=tr('Choices changed while the preview was running. Build it again.');find('report-preview-stale').hidden=false;return;}
      response=data;stamp=JSON.stringify(body);catalog=data.catalog||{chats:[],senders:[]};
      renderCatalog('chats');renderCatalog('senders');render(data);
      find('report-preview-stale').hidden=true;delete find('report-preview-result').dataset.stale;
      find('report-preview-status').textContent=tr('Preview ready. Save your choices before downloading the report.');
      if(reveal){find('report-preview').scrollIntoView({block:'start',behavior:'instant'});find('report-preview-title').focus({preventScroll:true});}
    }catch(error){
      if(!current()||['AbortError','StaleView'].includes(error.name))return;
      find('report-preview-status').textContent=tr('Could not build the preview.')+' '+error.message;find('report-preview-retry').hidden=false;
    }finally{if(mine===request&&owner===getOwner()){pending=false;controls();}}
  }
  for(const key of ['chats','senders'])searches[key].addEventListener('input',()=>renderCatalog(key));
  root.querySelectorAll('[data-report-step]').forEach(button=>button.addEventListener('click',()=>{
    const section=find(button.dataset.reportStep);section.scrollIntoView({block:'start',behavior:'instant'});section.querySelector('[tabindex="-1"]')?.focus({preventScroll:true});
  }));
  find('report-preview-run').addEventListener('click',()=>preview());find('report-preview-retry').addEventListener('click',()=>preview());
  find('report-load-catalog').addEventListener('click',()=>preview(false));
  function leave(){request++;controller?.abort();controller=null;pending=false;controls();}
  function reset(){
    leave();revision++;response=null;stamp=null;catalog={chats:[],senders:[]};
    for(const field of Object.values(searches))field.value='';
    for(const field of [fields.chats,fields.senders,find('report-selection-to'),kinds[0]])field.setCustomValidity('');
    find('report-preview-result').replaceChildren();delete find('report-preview-result').dataset.stale;
    find('report-preview-status').textContent='';find('report-preview-stale').hidden=find('report-preview-retry').hidden=true;
    for(const box of Object.values(containers))box.replaceChildren();find('report-chat-count').textContent=find('report-sender-count').textContent='';
  }
  return {read,changed,preview,leave,reset,
    load(selection={}){
      selection=selection||{};find('report-selection-all').checked=!selection.enabled;find('report-selection-chosen').checked=!!selection.enabled;
      fields.chats.value=(selection.chats||[]).join(', ');fields.senders.value=(selection.senders||[]).join(', ');
      for(const [id,key] of [['report-selection-from','date_from'],['report-selection-to','date_to']])find(id).value=selection[key]||'';
      const set=new Set(selection.kinds||kinds.map(input=>input.dataset.reportKind));for(const input of kinds)input.checked=set.has(input.dataset.reportKind);
      find('report-selection-gaps').checked=selection.id_gaps!==false;controls();renderCatalog('chats');renderCatalog('senders');
      if(stamp&&stamp!==JSON.stringify(options())){find('report-preview-stale').hidden=false;find('report-preview-result').dataset.stale='true';}
    }
  };
}
