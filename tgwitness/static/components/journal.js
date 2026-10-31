const TYPES=[["messages","Messages"],["message.edited","Edits"],["message.deleted","Deletions"],
  ["reaction.snapshot","Reactions"],["membership","Membership"],["media","Attachments"],["actions","Actions"],["coverage","Collection"]];

export function groupEvents(events){
  const groups=[];
  for(let i=0;i<events.length;){
    const event=events[i],ref=event.payload?.message_event;
    if(event.kind==="media.saved"&&Number.isSafeInteger(ref)&&event.chat_id!==null&&event.message_id!==null){
      let end=i;
      while(end<events.length&&events[end].kind==="media.saved"&&events[end].payload?.message_event===ref
        &&events[end].chat_id===event.chat_id&&events[end].message_id===event.message_id)end++;
      const original=events[end];
      if(original?.seq===ref&&original.chat_id===event.chat_id&&original.message_id===event.message_id
        &&["message.new","message.snapshot","message.recovered"].includes(original.kind)){
        groups.push({event:original,related:events.slice(i,end)});i=end+1;continue;
      }
    }
    groups.push({event,related:[]});i++;
  }
  return groups;
}

export function signedRecordPreview(value,{node,tr}){
  const details=node("details","detail-block journal-json"),pre=node("pre"),code=node("code");
  details.append(node("summary","",tr("Original signed record")),pre);pre.append(code);
  let rendered=false;
  details.addEventListener("toggle",()=>{
    if(!details.open||rendered)return;rendered=true;
    const raw=JSON.stringify(value,null,2),limit=120000,text=raw.slice(0,limit);
    const pattern=/"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;
    let offset=0,tokens=0;
    for(const match of text.matchAll(pattern)){
      if(++tokens>3000)break;
      code.append(document.createTextNode(text.slice(offset,match.index)));
      const kind=match[0][0]==='"'?(text[match.index+match[0].length]===":"?"key":"string"):
        /^(true|false|null)$/.test(match[0])?"literal":"number";
      code.append(node("span","json-"+kind,match[0]));offset=match.index+match[0].length;
    }
    code.append(document.createTextNode(text.slice(offset)));
    if(raw.length>limit)details.append(node("p","hint",tr("Preview limited to {n} characters. Export the signed ZIP for the complete record.",{n:limit.toLocaleString()})));
  });
  return details;
}

export function createJournal(context){
  const {get: $,state,node,icon,tr}=context,root=$("journal-filters"),search=$("event-search"),nativeSource=$("source-filter");
  let searchTimer=null,sourceQuery="",sourceFocus=0,selectedSeq=null,pageBusy=false,pageTicket=0;
  const expanded=new Set();
  const selected=()=>new Set((state.filter||"").split(",").filter(Boolean));
  const button=(label,cls="quiet")=>{const b=node("button",cls,tr(label));b.type="button";return b;};
  const inspector=$("detail-drawer"),wide=matchMedia("(min-width: 1280px)");let inspected=null;
  function positionInspector(){
    const active=inspected!==null&&!inspector.hidden&&state.drawerSeq===inspected.seq;
    const docked=active&&state.view==="observations"&&wide.matches;
    inspector.classList.toggle("journal-inspector",active);inspector.dataset.docked=String(docked);
    inspector.setAttribute("aria-modal",String(!docked));document.body.classList.toggle("journal-docked",docked);
    if(active)context.showBackdrop(!docked);
  }
  function closeInspector(){
    inspected=null;inspector.classList.remove("journal-inspector");delete inspector.dataset.docked;
    inspector.setAttribute("aria-modal","true");document.body.classList.remove("journal-docked");
  }
  function openInspector(event){
    inspected=event;
    const bar=node("nav","journal-record-nav");bar.setAttribute("aria-label",tr("Record navigation"));
    const index=state.events.findIndex(item=>item.seq===event.seq);
    for(const [label,offset,id] of [["Previous record",-1,"journal-previous-record"],["Next record",1,"journal-next-record"]]){
      const b=button(label,"quiet small"),next=index>=0?state.events[index+offset]:null;b.id=id;b.disabled=!next;
      b.addEventListener("click",()=>context.openDetail(next));bar.append(b);
    }
    if(event.chat_id!==null&&event.chat_id!==undefined){
      const open=button("Open in chat","secondary small");open.id="journal-open-chat";
      open.addEventListener("click",async()=>{
        if(open.disabled)return;open.disabled=true;
        try{await context.openChat(event);}catch(error){if(error.name!=="AbortError"&&error.name!=="StaleView")context.error(error.message);}
        finally{if(open.isConnected)open.disabled=false;}
      });bar.append(open);
    }
    $("detail-content").prepend(bar);inspector.scrollTop=0;positionInspector();
    const row=$("events-body").querySelector('[data-seq="'+event.seq+'"]');
    if(row?.hidden){
      const toggle=[...$("events-body").querySelectorAll(".journal-related")].find(control=>control.getAttribute("aria-controls")?.split(" ").includes(row.id));
      if(toggle?.getAttribute("aria-expanded")==="false")toggle.click();
    }
    if(row&&!row.hidden){selectRow(row);row.scrollIntoView({block:"nearest"});}
  }
  wide.addEventListener("change",positionInspector);
  const types=node("div","journal-type-filters");types.role="group";types.setAttribute("aria-label",tr("Event types"));
  const all=button("All events","filter");all.dataset.filter="";types.append(all);
  all.addEventListener("click",()=>{state.filter="";change();});
  for(const [value,label] of TYPES){
    const b=button(label,"filter");b.dataset.filter=value;
    b.addEventListener("click",()=>{const values=selected();values.has(value)?values.delete(value):values.add(value);state.filter=[...values].join(",");change();});
    types.append(b);
  }
  const controls=node("div","journal-controls"),searchWrap=node("div","search-wrap");
  searchWrap.append(icon("search"),search);
  const source=button("All sources","secondary journal-source-toggle");source.id="journal-source-toggle";
  source.setAttribute("aria-haspopup","dialog");source.setAttribute("aria-expanded","false");
  nativeSource.hidden=true;nativeSource.tabIndex=-1;
  controls.append(searchWrap,source,nativeSource);
  const dates=node("div","journal-date-filters");dates.role="group";dates.setAttribute("aria-label",tr("Observed period"));
  const ranges=[["","Any time",null],["1h","1 hour",3600000],["24h","24 hours",86400000],["7d","7 days",604800000],["custom","Custom",null]];
  const custom=node("form","journal-custom-dates");custom.hidden=true;
  const from=node("input"),until=node("input");from.type=until.type="datetime-local";
  from.id="journal-since";until.id="journal-until";
  for(const [input,label] of [[from,"From (UTC)"],[until,"Until (UTC)"]]){const l=node("label","",tr(label));l.append(input);custom.append(l);}
  const apply=button("Apply dates","secondary");apply.type="submit";custom.append(apply);
  const error=node("p","field-error");error.id="journal-filter-error";error.role="status";error.hidden=true;
  for(const [value,label,duration] of ranges){
    const b=button(label,"filter");b.dataset.range=value;
    b.addEventListener("click",()=>{
      if(value==="custom"){custom.hidden=!custom.hidden;if(!custom.hidden)from.focus();return;}
      state.eventSince=duration?new Date(Date.now()-duration).toISOString():"";state.eventUntil="";custom.hidden=true;change();
    });dates.append(b);
  }
  custom.addEventListener("submit",event=>{
    event.preventDefault();error.hidden=true;
    const a=from.value?new Date(from.value+"Z"):null,b=until.value?new Date(until.value+"Z"):null;
    if(a&&Number.isNaN(a.getTime())||b&&Number.isNaN(b.getTime())||a&&b&&a>b){
      error.textContent=tr("Choose a valid start before the end.");error.hidden=false;return;
    }
    state.eventSince=a?.toISOString()||"";state.eventUntil=b?.toISOString()||"";change();
  });
  const chips=node("div","journal-active-filters");chips.id="journal-active-filters";chips.setAttribute("aria-label",tr("Active filters"));
  const systemLine=node("div","journal-system-row"),systemLabel=node("label"),system=node("input");
  system.type="checkbox";system.id="journal-system";
  systemLabel.append(system,node("span","",tr("Show system records")));
  systemLine.append(systemLabel,node("small","",tr("Routine records stay in the signed journal.")));
  system.addEventListener("change",()=>{state.eventSystem=system.checked;change();});
  const more=node('details','journal-more-filters'),moreTitle=node('summary','',tr('Filters'));
  const compact=matchMedia('(max-width: 767px)');more.open=!compact.matches;
  compact.addEventListener('change',()=>{more.open=!compact.matches;});
  more.append(moreTitle,dates,custom,systemLine);
  root.replaceChildren(types,controls,more,error,chips);
  const older=$("load-more"),footer=older.closest(".table-footer"),shown=$("shown-count"),range=node("span","journal-window-range");
  const pager=node("div","journal-pager"),newer=button("Newer records","quiet"),latest=button("Latest","quiet");
  newer.id="journal-newer";latest.id="journal-latest";older.textContent=tr("Older records");older.hidden=false;
  range.id="journal-window-range";pager.append(newer,older,latest);
  const windowStatus=node("span","journal-window-status");windowStatus.role="status";footer.replaceChildren(shown,range,pager,windowStatus);
  for(const [control,direction] of [[older,"older"],[newer,"newer"],[latest,"latest"]])control.addEventListener("click",async()=>{
    if(pageBusy)return;const ticket=++pageTicket;pageBusy=true;syncPage();windowStatus.textContent=tr("Loading records…");
    try{await context.page(direction);if(ticket===pageTicket)$("events-body").closest(".table-wrap").scrollTop=0;}
    catch(error){if(!["AbortError","StaleView"].includes(error.name))context.error(error.message);}
    finally{if(ticket===pageTicket){pageBusy=false;windowStatus.textContent="";syncPage();}}
  });
  const visibleRows=()=>[...$("events-body").querySelectorAll(".event-row")].filter(row=>!row.hidden);
  function selectRow(row,focus=false){
    selectedSeq=row?Number(row.dataset.seq):null;
    for(const item of visibleRows()){const active=item===row;item.tabIndex=active?0:-1;item.classList.toggle("journal-selected",active);}
    if(focus&&row){row.focus();row.scrollIntoView({block:"nearest"});}
  }
  function restoreSelection(){const rows=visibleRows();selectRow(rows.find(row=>Number(row.dataset.seq)===selectedSeq)||rows[0]||null);}
  $("events-body").addEventListener("focusin",event=>{const row=event.target.closest(".event-row");if(row)selectRow(row);});
  $("events-body").addEventListener("keydown",event=>{
    if(event.ctrlKey||event.metaKey||event.altKey||event.shiftKey||event.isComposing)return;
    const row=event.target.closest(".event-row");if(!row)return;
    if(["ArrowDown","ArrowUp"].includes(event.key)){
      event.preventDefault();const rows=visibleRows(),index=rows.indexOf(row),next=Math.max(0,Math.min(rows.length-1,index+(event.key==="ArrowDown"?1:-1)));
      selectRow(rows[next],true);
    }else if(event.key==="Escape"&&$("detail-drawer").hidden){event.preventDefault();$("refresh").focus();}
  });

  const picker=node("dialog","journal-source-picker");picker.setAttribute("aria-label",tr("Choose a source"));
  const heading=node("div","journal-picker-heading"),sourceSearch=node("input"),close=button("Close","quiet small");
  sourceSearch.type="search";sourceSearch.id="journal-source-search";sourceSearch.placeholder=tr("Find a source or chat ID…");
  sourceSearch.setAttribute("aria-label",tr("Find a source"));heading.append(sourceSearch,close);
  const options=node("div","journal-source-options");options.role="listbox";
  const sourceHint=node("p","hint");picker.append(heading,options,sourceHint);document.body.append(picker);
  function closeSource(focus=false){if(picker.open)picker.close();source.setAttribute("aria-expanded","false");if(focus&&source.isConnected)source.focus();}
  function positionSource(){
    const box=source.getBoundingClientRect();picker.style.width=Math.min(360,innerWidth-24)+"px";
    picker.style.maxHeight=Math.max(140,innerHeight-24)+"px";
    const height=picker.getBoundingClientRect().height;
    picker.style.left=Math.max(12,Math.min(box.left,innerWidth-picker.offsetWidth-12))+"px";
    picker.style.top=(box.bottom+height+8<=innerHeight?box.bottom+6:Math.max(12,box.top-height-6))+"px";
  }
  function sourceOptions(){
    const query=sourceQuery.trim().toLocaleLowerCase(),targets=(state.status?.targets||[]).filter(t=>
      (t.title+" "+t.chat_id).toLocaleLowerCase().includes(query));
    options.replaceChildren();
    const choices=[...(!query?[{chat_id:"",title:tr("All sources")}]:[]),...targets.slice(0,100)];
    for(const item of choices){
      const b=button("","journal-source-option");b.role="option";b.dataset.source=String(item.chat_id);
      b.setAttribute("aria-selected",String(String(item.chat_id)===String(state.source)));
      b.append(node("strong","",item.title),node("small","",String(item.chat_id)));
      b.addEventListener("click",()=>{state.source=String(item.chat_id);nativeSource.value=state.source;closeSource(true);change();});options.append(b);
    }
    sourceHint.textContent=targets.length>100?tr("Showing the first 100 sources. Narrow the search."):
      !choices.length?tr("No sources match this search."):"";
    sourceHint.hidden=!sourceHint.textContent;sourceFocus=0;if(picker.open)positionSource();
  }
  source.addEventListener("click",()=>{
    if(picker.open){closeSource();return;}
    sourceQuery="";sourceSearch.value="";sourceOptions();picker.show();source.setAttribute("aria-expanded","true");positionSource();sourceSearch.focus();
  });
  sourceSearch.addEventListener("input",()=>{sourceQuery=sourceSearch.value;sourceOptions();});
  close.addEventListener("click",()=>closeSource(true));
  picker.addEventListener("keydown",event=>{
    if(event.key==="Escape"){event.preventDefault();closeSource(true);}
    if(["ArrowUp","ArrowDown"].includes(event.key)){
      const items=[...options.querySelectorAll("button")];if(!items.length)return;event.preventDefault();
      const index=items.indexOf(document.activeElement);sourceFocus=index<0?0:(index+(event.key==="ArrowDown"?1:-1)+items.length)%items.length;
      items[sourceFocus].focus();
    }
  });
  document.addEventListener("pointerdown",event=>{if(picker.open&&!picker.contains(event.target)&&!source.contains(event.target))closeSource();});
  window.addEventListener("resize",()=>closeSource());
  search.addEventListener("input",()=>{
    state.search=search.value;context.invalidate();clearTimeout(searchTimer);
    searchTimer=setTimeout(()=>change(),300);
  });
  nativeSource.addEventListener("change",()=>{state.source=nativeSource.value;change();});
  function change(){
    clearTimeout(searchTimer);error.hidden=true;pageTicket++;pageBusy=false;windowStatus.textContent="";context.invalidate();sync();
    context.changed().catch(error=>{if(error.name!=="AbortError"&&error.name!=="StaleView")context.error(error.message);});
  }
  function chip(text,remove){const b=button("","journal-filter-chip");b.append(node("span","",text),icon("x"));b.title=tr("Remove filter");b.addEventListener("click",()=>{remove();change();});chips.append(b);}
  function sync(){
    system.checked=!!state.eventSystem;
    const values=selected();
    for(const b of types.children){const on=b.dataset.filter?values.has(b.dataset.filter):!values.size;b.classList.toggle("active",on);b.setAttribute("aria-pressed",String(on));}
    if(document.activeElement!==search)search.value=state.search;
    const title=state.source?(state.status?.targets||[]).find(t=>String(t.chat_id)===state.source)?.title||state.source:tr("All sources");
    source.replaceChildren(node("span","",title),icon("chevron"));source.title=title;
    const age=state.eventSince?Date.now()-Date.parse(state.eventSince):null;
    const range=!state.eventSince&&!state.eventUntil?"":!state.eventUntil&&ranges.find(([, ,duration])=>duration&&Math.abs(age-duration)<120000)?.[0]||"custom";
    for(const b of dates.children){b.classList.toggle("active",b.dataset.range===range);b.setAttribute("aria-pressed",String(b.dataset.range===range));}
    if(document.activeElement!==from)from.value=state.eventSince?.slice(0,16)||"";
    if(document.activeElement!==until)until.value=state.eventUntil?.slice(0,16)||"";
    chips.replaceChildren();
    for(const value of values)chip(tr(TYPES.find(([key])=>key===value)?.[1]||value),()=>{values.delete(value);state.filter=[...values].join(",");});
    if(state.source)chip(title,()=>{state.source="";nativeSource.value="";});
    if(state.search)chip(tr("Search: {query}",{query:state.search}),()=>{state.search="";search.value="";});
    if(state.eventSince||state.eventUntil)chip(range==="custom"?tr("Custom period"):tr(ranges.find(([key])=>key===range)?.[1]||"Custom period"),()=>{state.eventSince=state.eventUntil="";custom.hidden=true;});
    if(chips.childElementCount){const clear=button("Clear filters","quiet small");clear.addEventListener("click",()=>{state.filter=state.source=state.search=state.eventSince=state.eventUntil="";search.value="";nativeSource.value="";change();});chips.append(clear);}
    chips.hidden=!chips.childElementCount;
  }
  function leave(){clearTimeout(searchTimer);closeSource();closeInspector();}
  function renderRows(events,makeRow){
    const body=$("events-body"),groups=groupEvents(events),present=new Set(groups.map(group=>group.event.seq));
    for(const key of expanded)if(!present.has(key))expanded.delete(key);
    body.replaceChildren();
    for(const group of groups){
      const row=makeRow(group.event);body.append(row);
      if(!group.related.length)continue;
      row.classList.add("journal-bundle");
      const toggle=button("","quiet small journal-related"),children=[];
      toggle.append(icon("chevron"),node("span","",group.related.length===1?tr("Attachment record"):tr("{n} attachment records",{n:group.related.length})));
      row.querySelector(".event-summary > div").append(toggle);
      for(const event of group.related){
        const child=makeRow(event);child.classList.add("journal-related-row");child.id="journal-related-"+event.seq;
        children.push(child);body.append(child);
      }
      const syncGroup=()=>{const open=expanded.has(group.event.seq);toggle.setAttribute("aria-expanded",String(open));children.forEach(child=>child.hidden=!open);};
      toggle.setAttribute("aria-controls",children.map(child=>child.id).join(" "));
      toggle.addEventListener("click",event=>{event.stopPropagation();expanded.has(group.event.seq)?expanded.delete(group.event.seq):expanded.add(group.event.seq);syncGroup();restoreSelection();});
      syncGroup();
    }
    restoreSelection();
  }
  function syncPage(){
    shown.textContent=Number.isFinite(state.eventMatched)?tr("{shown} of {total} matching records",{shown:state.events.length,total:state.eventMatched.toLocaleString()}):
      tr("{shown} records in this window",{shown:state.events.length});
    range.textContent=state.events.length?"#"+state.events[0].seq+" – #"+state.events.at(-1).seq:"";
    older.disabled=pageBusy||state.cursor===null;newer.disabled=pageBusy||state.eventAfter===null;
    latest.disabled=pageBusy;latest.hidden=state.eventBefore===null;
    $("events-body").closest(".table-wrap").setAttribute("aria-busy",String(pageBusy));
  }
  window.addEventListener("tgwitness:lock",leave);
  sync();syncPage();return {sync,leave,renderRows,syncPage,openDetail:openInspector,closeDetail:closeInspector,
    signedRecord:value=>signedRecordPreview(value,{node,tr}),
    canRefresh:()=>!root.contains(document.activeElement)&&!picker.contains(document.activeElement)&&!$("events-body").contains(document.activeElement),
    reset(){leave();expanded.clear();selectedSeq=null;pageTicket++;pageBusy=false;}};
}
