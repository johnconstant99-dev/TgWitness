(() => {
  "use strict";
  let config=null, plan=null, report=null, workspace=null, generation=0;
  let loaded=false,loading=null,providerPending=null,capabilityKey="";
  let providerEpoch=0,editRevision=0,saving=null;
  const edits=new Map();
  const numberFields={context:"context_chars",output:"output_tokens",timeout:"timeout_seconds",budget:"daily_requests","input-price":"input_per_million","output-price":"output_per_million"};
  const call=(path,body,options={})=>json("analysis/"+path,body,{root:true,...options});
  const scoped=path=>path+(path.includes("?")?"&":"?")+"workspace_id="+encodeURIComponent(workspace);
  function resetResults(){generation++;loaded=false;loading=null;plan=null;report=null;window.TgWitnessMedia?.clear();$("ask-consent").checked=false;["ask-preview","ask-answer","ask-report"].forEach(id=>show(id,false));["ask-sources","ask-claims","ask-report-content","ask-reports","ask-transmission"].forEach(id=>$(id).replaceChildren());}
  function clear(){
    resetResults();workspace=null;config=null;providerPending=null;capabilityKey="";providerEpoch++;edits.clear();saving=null;
    $("ai-settings").open=false;$("ai-settings-form").reset();$("ai-settings-form").inert=true;
    $("ai-settings-form").querySelector('button[type="submit"]').disabled=true;$("ai-test").disabled=true;
    for(const id of ["ai-status","ai-key-state","ai-test-result","ask-provider-status","ask-workspace","ask-usage"])$(id).textContent="";
    $("ask-form").reset();$("ask-report-form").reset();$("ask-chats").replaceChildren();$("ask-coverage").replaceChildren();
  }
  function capabilities(status=state.status){return {enabled:!!status?.analysis?.enabled&&!status?.demo,media:!!status?.analysis?.media_available&&!status?.demo};}
  function current(turn){return turn===generation&&workspace===state.profile&&!!state.me;}
  function syncStatus(status=state.status){
    if(workspace!==state.profile){clear();workspace=state.profile;}
    const flags=capabilities(status),key=workspace+":"+flags.enabled+":"+flags.media;
    if(key!==capabilityKey){resetResults();capabilityKey=key;}
    show("ai-settings",!!state.me?.admin&&!status?.demo);show("ask-form",flags.enabled);
    show("analysis-description",flags.enabled);$("analysis-help").closest("p").hidden=!flags.enabled;
    if($("ask-provider-status"))show("ask-provider-status",flags.enabled);
    $("ask-reports").closest("section").hidden=!flags.enabled;
    show("media-analysis-section",flags.media);
    return flags;
  }
  window.addEventListener("tgwitness:lock",clear);
  function providerMode(){if(!config)return;$("ai-endpoint").readOnly=$("ai-provider").value==="ollama";if($("ai-endpoint").readOnly)$("ai-endpoint").value=config.local_endpoint;}
  function providerCurrent(epoch){return epoch===providerEpoch&&workspace===state.profile&&!!state.me;}
  function providerControls(){
    const editable=!!config&&workspace===state.profile&&!!state.me?.admin&&!state.status?.demo;
    $("ai-settings-form").inert=!editable;
    $("ai-settings-form").querySelector('button[type="submit"]').disabled=!editable||!!providerPending||!!saving;
    $("ai-test").disabled=!editable||!config.enabled||!!providerPending||!!saving;
  }
  function settings(data,submitted=null){
    config=data;
    const values={"ai-enabled":data.enabled,"ai-provider":data.provider,"ai-model":data.model,"ai-endpoint":data.endpoint,
      "ai-key":"","ai-clear-key":false,"ai-currency":data.currency};
    for(const [id,key] of Object.entries(numberFields))values["ai-"+id]=data[key]??"";
    for(const [id,value] of Object.entries(values)){
      const edited=edits.get(id);
      if(edited!==undefined&&(submitted===null||edited>submitted))continue;
      const field=$(id);if(field.type==="checkbox")field.checked=value;else field.value=value??"";
      edits.delete(id);
    }
    $("ai-key-state").textContent=data.has_key?tr("A key is stored. Leave blank to keep it."):tr("No API key stored.");
    $("ai-status").textContent=(data.enabled?tr("AI enabled"):tr("AI disabled"))+" · "+data.provider+" · "+data.endpoint+" · "+tr("Workspace route")+": "+data.route;
    if($("ask-provider-status"))$("ask-provider-status").textContent=$("ai-status").textContent;
    providerMode();providerControls();
  }
  $("ai-provider").addEventListener("change",providerMode);
  for(const event of ["input","change"])$("ai-settings-form").addEventListener(event,event=>{
    if(!event.target.matches("input,select"))return;
    edits.set(event.target.id,++editRevision);
    if(event.target.id==="ai-provider")edits.set("ai-endpoint",editRevision);
  });
  $("ai-settings-form").addEventListener("submit",event=>{
    event.preventDefault();
    if(!config||workspace!==state.profile||!state.me?.admin||state.status?.demo||providerPending||saving)return;
    const marker={},epoch=providerEpoch,submitted=editRevision;
    saving=marker;providerControls();
    busy(null,async()=>{
      try{
        const body={enabled:$("ai-enabled").checked,provider:$("ai-provider").value,endpoint:$("ai-endpoint").value,model:$("ai-model").value,clear_key:$("ai-clear-key").checked};
        if($("ai-key").value)body.api_key=$("ai-key").value;
        for(const [id,key] of Object.entries(numberFields))body[key]=$("ai-"+id).value===""?null:Number($("ai-"+id).value);
        body.currency=$("ai-currency").value;
        const data=await call(scoped("provider"),body);if(!providerCurrent(epoch))return;
        settings(data,submitted);resetResults();await refreshStatus();
        if(providerCurrent(epoch))toast(tr("Provider settings saved."));
      }finally{if(saving===marker){saving=null;providerControls();}}
    });
  });
  async function loadProvider(force=false){
    if(config&&!force||saving)return config;
    if(providerPending)return providerPending;
    const epoch=providerEpoch;
    const pending=(async()=>{const data=await call(scoped("provider"));if(!providerCurrent(epoch))return null;settings(data);return data;})();
    providerPending=pending;providerControls();
    try{return await pending;}finally{if(providerPending===pending){providerPending=null;if(providerCurrent(epoch))providerControls();}}
  }
  async function loadSettings(){
    syncStatus();if(!state.me?.admin||state.status?.demo||saving)return;
    const epoch=providerEpoch;
    $("ai-status").textContent=tr("Loading…");
    try{await loadProvider(true);}catch(error){if(providerCurrent(epoch))$("ai-status").textContent=error.message;}
  }
  $("ai-settings").addEventListener("toggle",()=>{if($("ai-settings").open)loadSettings();});
  $("ai-test").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(!config?.enabled)return;const turn=generation;await call(scoped("provider/test"),{});if(current(turn))$("ai-test-result").textContent=tr("Connection checked with synthetic text. No messages were read.");}));
  function citation(ref,label){const button=node("button","text-link",label||"#"+ref.event_seq);button.type="button";button.title=tr("Open journal record #{seq}",{seq:ref.event_seq});button.addEventListener("click",()=>busy(button,()=>openRecord(ref.event_seq)));return button;}
  function coverage(data,target){
    target.replaceChildren(node("p","hint",tr("Only saved observations are available. Gaps may exist; absence from the archive does not prove absence in Telegram.")));
    if(!data.workspace_events_visible)target.append(node("p","hint",tr("This access cannot read workspace-wide coverage events.")));
    for(const event of data.events){const line=node("p","hint",event.kind+" · "+fmtFull(event.observed_at)+" ");line.append(citation(event.source));target.append(line);}
  }
  function transmission(){
    if(!plan)return;
    const ids=new Set([...$("ask-sources").querySelectorAll("input:checked")].map(el=>el.value));
    const messages=structuredClone(plan.transmission),data=JSON.parse(messages[1].content);data.observations=data.observations.filter(s=>ids.has(s.id));messages[1].content=JSON.stringify(data,null,2);
    $("ask-transmission").textContent=JSON.stringify(messages,null,2);$("ask-consent").checked=false;
  }
  function sources(data){
    const provider=data.provider;
    if(provider&&$("ask-provider-status"))$("ask-provider-status").textContent=(provider.enabled?tr("AI enabled"):tr("AI disabled"))+" · "+provider.provider+" · "+provider.model+" · "+provider.endpoint;
    const box=$("ask-sources");box.replaceChildren();
    if(data.not_found)box.append(viewState("empty",tr("Not found in the available archive"),tr("Try a different phrase, chat or observation period.")));
    for(const source of data.sources){
      const row=node("article","analysis-source"),label=node("label","check-label"),check=node("input");check.type="checkbox";check.value=source.id;check.checked=true;
      label.append(check,node("span","",source.id+" · "+source.kind+" · "+fmtFull(source.observed_at)));row.append(label,node("blockquote","",source.text||tr("Metadata-only observation")));
      const links=node("div","route-actions");links.append(citation(source.source,tr("Compare with source")));
      const context=node("button","quiet",tr("Open chat context")),contextBox=node("div");context.type="button";context.addEventListener("click",()=>busy(context,async()=>{const result=await call("context",{tool:"get_message_context",workspace,chat_id:source.source.chat_id,message_id:source.source.message_id});contextBox.replaceChildren();for(const item of result.items){const p=node("p","",item.kind+" · "+item.text+" ");p.append(citation(item.source));contextBox.append(p);}if(result.next_before)contextBox.append(node("p","hint",tr("The context is bounded. Open the source for more detail.")));}));links.append(context);row.append(links,contextBox);
      if(source.text_truncated)row.append(node("small","hint",tr("Excerpt shortened. Open the source to read the saved text.")));
      check.addEventListener("change",transmission);box.append(row);
    }
    if(data.partial)box.append(node("p","notice",tr("The result is bounded. Narrow the search to inspect additional sources.")));
    coverage(data.coverage,$("ask-coverage"));show("ask-preview",true);$("ask-generate").disabled=!data.sources.length||!(provider?.enabled??config?.enabled);transmission();
  }
  $("ask-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
    if(!capabilities().enabled)return;
    const turn=++generation;show("ask-answer",false);plan=null;$("ask-sources").replaceChildren(viewState("loading",tr("Loading…")));show("ask-preview",true);
    const chats=[...$("ask-chats").querySelectorAll("input:checked")].map(el=>Number(el.value));
    const body={workspace,chats,since:new Date($("ask-since").value).toISOString(),until:new Date($("ask-until").value).toISOString(),question:$("ask-question").value,query:$("ask-query").value,message_id:$("ask-message").value?Number($("ask-message").value):null};
    try{const result=await call("preview",body);if(turn!==generation)return;plan=result;sources(result);}
    catch(error){if(turn===generation)$("ask-sources").replaceChildren(viewState("error",tr("Could not load data"),error.message));throw error;}
  });});
  function claims(items,box){
    box.replaceChildren();
    if(!items.length)box.append(viewState("empty",tr("Not found in the available archive"),tr("The selected sources do not support an answer.")));
    for(const item of items){const row=node("article","analysis-source");row.append(node("small","hint",tr("Model inference")),node("p","",item.text));for(const ref of item.citations){row.append(node("blockquote","",ref.quote),citation(ref.source,ref.id+" · #"+ref.source.event_seq));}box.append(row);}
  }
  $("ask-generate").addEventListener("click",event=>busy(event.currentTarget,async()=>{
    if(!plan||!capabilities().enabled)return;if(!$("ask-consent").checked)throw new Error(tr("Review and approve the selected data first."));
    const turn=generation,result=await call("generate",{plan_id:plan.plan_id,source_ids:[...$("ask-sources").querySelectorAll("input:checked")].map(el=>el.value),consent:true});
    if(turn!==generation)return;claims(result.claims,$("ask-claims"));show("ask-answer",true);$("ask-generate").dataset.complete="true";
    const meta=result.generation,usage=[];if(meta.tokens.input_tokens!==undefined)usage.push(tr("Input tokens: {n}",{n:meta.tokens.input_tokens}));if(meta.tokens.output_tokens!==undefined)usage.push(tr("Output tokens: {n}",{n:meta.tokens.output_tokens}));if(meta.cost)usage.push(meta.cost.amount.toFixed(4)+" "+meta.cost.currency);
    $("ask-usage").textContent=meta.provider+" · "+meta.model+" · "+usage.join(" · ");
  }));
  async function reports(){if(!capabilities().enabled)return;const turn=generation,data=await call(scoped("reports"));if(!current(turn))return;const box=$("ask-reports");box.replaceChildren();for(const row of data.reports){const button=node("button","text-link",row.title+" · "+fmtFull(row.created_at));button.type="button";button.addEventListener("click",()=>busy(button,async()=>{const turn=generation,data=await call(scoped("reports/"+row.id));if(current(turn))renderReport(data);}));box.append(button);}if(!data.reports.length)box.append(viewState("empty",tr("No analytical reports"),tr("Save a reviewed answer to create a separate report.")));}
  function renderReport(data){
    report=data;show("ask-report",true);const box=$("ask-report-content");box.replaceChildren();
    const summary=node("div");claims(data.model_summary,summary);box.append(node("h3","",tr("Model inference")),summary);
    const history=node("details");history.append(node("summary","",tr("Observed facts · chronology")));for(const event of data.chronology){const row=node("p","",fmtFull(event.observed_at)+" · "+event.kind+" · "+event.quote+" ");row.append(citation(event.source));history.append(row);}box.append(history);
    const entities=node("details");entities.append(node("summary","",tr("Observed links and entities")));for(const entry of data.entities){const row=node("p","",entry.value+" ");row.append(citation(entry.source));entities.append(row);}box.append(entities);
    const gaps=node("div");coverage(data.coverage,gaps);box.append(gaps);
    box.append(node("p","hint",data.template+" · "+data.generation.provider+" · "+data.generation.model+" · "+fmtFull(data.generation.at)));
    for(const revision of data.analyst_revisions){box.append(node("h3","",tr("Analyst note")+" · "+fmtFull(revision.at)),node("p","",revision.revised_summary),node("p","",revision.analyst_note));}
    const latest=data.analyst_revisions.at(-1);$("report-title").value=data.title;$("report-summary").value=latest?.revised_summary||"";$("report-note").value=latest?.analyst_note||"";$("report-download").hidden=!may("export");
  }
  $("ask-save-report").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(plan&&capabilities().enabled){const turn=generation,data=await call("reports",{plan_id:plan.plan_id});if(current(turn)){renderReport(data);await reports();}}}));
  $("ask-refresh-reports").addEventListener("click",event=>busy(event.currentTarget,reports));
  $("ask-report-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{if(report&&capabilities().enabled){const turn=generation,data=await call(scoped("reports/"+report.id),{title:$("report-title").value,revised_summary:$("report-summary").value,analyst_note:$("report-note").value},{method:"PATCH"});if(current(turn)){renderReport(data);await reports();}}});});
  $("report-download").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(!report)return;const response=await api("analysis/"+scoped("reports/"+report.id+"/download"),undefined,{root:true});const url=URL.createObjectURL(await response.blob()),link=node("a");link.href=url;link.download="tgwitness-analysis.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
  async function load(){
    const flags=syncStatus();if(!flags.enabled&&!flags.media||loaded)return;if(loading)return loading;
    const turn=generation;
    const pending=(async()=>{
      if(flags.enabled){
        $("ask-workspace").textContent=tr("Workspace")+": "+(state.profiles.find(p=>p.id===workspace)?.label||workspace);
        $("ask-form").querySelector('button[type="submit"]').disabled=false;
        const date=value=>{const d=new Date(value);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);};$("ask-since").value=date(Date.now()-86400000);$("ask-until").value=date(Date.now()+60000);
        const [,data]=await Promise.all([loadProvider(),json("chats")]);if(!current(turn))return;
        const box=$("ask-chats");box.replaceChildren();for(const chat of data.chats){const label=node("label","check-label"),input=node("input");input.type="checkbox";input.value=chat.chat_id;input.checked=chat.chat_id===state.chat;label.append(input,node("span","",chat.title||String(chat.chat_id)));box.append(label);}await reports();
      }
      if(current(turn)&&flags.media)await window.TgWitnessMedia?.load();
      if(current(turn))loaded=true;
    })();
    loading=pending;
    try{await pending;}catch(error){if(current(turn)){$("ai-status").textContent=error.message;loaded=false;}}
    finally{if(loading===pending)loading=null;}
  }
  async function focusChat(id){
    if(!syncStatus().enabled||state.view!=='analysis')return false;
    const turn=generation;await load();
    if(!current(turn)||!loaded||state.view!=='analysis'||!capabilities().enabled)return false;
    const choices=[...$("ask-chats").querySelectorAll('input[type="checkbox"]')];
    if(!choices.some(input=>input.value===String(id)))return false;
    for(const input of choices)input.checked=input.value===String(id);
    $("ask-question").focus({preventScroll:true});return true;
  }
  window.TgWitnessAnalysis={clear,syncStatus,loadSettings,load,focusChat};
})();
