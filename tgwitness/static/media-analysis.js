(() => {
  "use strict";
  let selected=null,offset=0,next=null,available=false,generation=0,loadSerial=0;
  const enabled=()=>!!state.me&&!!state.status?.analysis?.media_available&&!state.status?.demo;
  const current=(turn,workspace)=>turn===generation&&workspace===state.profile&&enabled();
  const scoped=path=>path+(path.includes("?")?"&":"?")+"workspace_id="+encodeURIComponent(state.profile);
  const call=(path,body)=>json("analysis/"+scoped(path),body,{root:true});
  function clear(){generation++;loadSerial++;selected=null;offset=0;next=null;available=false;$("media-analysis-target").textContent=tr("No attachment selected.");$("media-start").disabled=true;$("media-jobs").replaceChildren();$("media-result").replaceChildren();}
  window.addEventListener("tgwitness:lock",clear);
  async function load(){
    if(!enabled())return;
    const turn=generation,workspace=state.profile,serial=++loadSerial;
    const data=await call("media?"+new URLSearchParams({query:$("media-search").value,kind:$("media-filter").value,offset}));
    if(!current(turn,workspace)||serial!==loadSerial)return;
    available=data.available;next=data.next_offset;$("media-next").disabled=next===null;$("media-previous").disabled=offset===0;$("media-start").disabled=!available||!selected;
    $("media-worker-status").textContent=available?tr("Local worker · one CPU · 2 GiB RAM · no network"):tr("Local worker is not configured. See the media processing setup guide.");
    const box=$("media-jobs");box.replaceChildren();
    for(const job of data.jobs){
      const statuses={queued:tr("Queued"),running:tr("Running"),completed:tr("Completed"),failed:tr("Failed"),cancelled:tr("Cancelled"),interrupted:tr("Interrupted")};
      const row=node("article","analysis-source"),info=node("p","",job.request.engine+" · "+(statuses[job.status]||job.status)+" · #"+job.source.event_seq);row.append(info);
      if(job.error)row.append(node("p","hint",tr(job.error)));if(job.excerpt)row.append(node("p","",job.excerpt));
      const actions=node("div","route-actions");
      if(job.status==="completed"){const view=node("button","text-link",tr("Open recognized text"));view.type="button";view.addEventListener("click",()=>busy(view,async()=>{
        const turn=generation,workspace=state.profile,result=(await call("media/"+job.id)).result;if(!current(turn,workspace))return;const box=$("media-result");box.replaceChildren(node("h3","",tr("Machine recognition")),node("p","hint",result.engine+" · "+result.engine_version+" · "+result.language),node("pre","analysis-data",result.text));
        for(const segment of result.segments)box.append(node("p","",segment.start.toFixed(1)+"–"+segment.end.toFixed(1)+" · "+segment.text));
        const source=node("button","text-link",tr("Compare with source"));source.type="button";source.addEventListener("click",()=>openRecord(result.source.event_seq));box.append(source,node("p","detail-hash","SHA-256 · "+result.media_sha256));
      }));actions.append(view);}
      const action=["queued","running"].includes(job.status)?"cancel":["failed","interrupted","cancelled"].includes(job.status)?"retry":null;
      if(action){const button=node("button",action==="cancel"?"quiet":"secondary",action==="cancel"?tr("Cancel"):tr("Retry"));button.type="button";button.addEventListener("click",()=>busy(button,async()=>{await call("media/"+job.id+"/"+action,{});await load();}));actions.append(button);}
      row.append(actions);box.append(row);
    }
    if(!data.jobs.length)box.append(viewState("empty",tr("No matching recognition results"),tr("Start with a saved attachment, or change the recognition filter.")));
  }
  $("media-analysis-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{if(!selected||!enabled()||!available)return;await call("media",{...selected,engine:$("media-engine").value,language:$("media-language").value});await load();});});
  $("media-search-form").addEventListener("submit",event=>{event.preventDefault();offset=0;busy(event.submitter,load);});
  $("media-next").addEventListener("click",event=>busy(event.currentTarget,async()=>{offset=next??offset;await load();}));
  $("media-previous").addEventListener("click",event=>busy(event.currentTarget,async()=>{offset=Math.max(0,offset-20);await load();}));
  $("media-refresh").addEventListener("click",event=>busy(event.currentTarget,load));
  window.TgWitnessMedia={clear,load,select:record=>{if(!enabled()||record.workspace!==state.profile)return;closeDetail();navigate("analysis");selected=record;$("media-analysis-target").textContent=tr("Selected source")+" #"+record.event_seq+" · "+record.digest;$("media-start").disabled=!available;$("media-analysis-section").scrollIntoView({block:"start"});}};
})();
