(() => {
  "use strict";
  let secret="",revision=0;
  function clear(){revision++;secret="";$("webhook-secret").value="";show("webhook-created",false);}
  window.addEventListener("tgwitness:lock",clear);
  async function refresh(){
    if(state.status?.demo)return;
    const data=await json("integrations/webhooks"),box=$("webhook-list");box.replaceChildren();
    $("webhook-status").textContent=tr("Pending deliveries: {n}",{n:data.pending})+(data.last_error?" · "+tr(data.last_error):"");
    for(const hook of data.connections){
      const row=node("div","target-row"),info=node("div");info.append(node("h3","",hook.name),node("p","",hook.url),node("p","",hook.events.join(", ")+" · "+(hook.include_text?tr("Text excerpts included"):tr("Metadata only"))));
      const actions=node("div","route-actions"),test=node("button","secondary",tr("Send synthetic test")),remove=node("button","danger",tr("Remove"));test.type=remove.type="button";
      test.addEventListener("click",()=>busy(test,async()=>{await json("integrations/webhooks/"+hook.id+"/test",{});toast(tr("Synthetic test queued. Refresh to see delivery status."));await refresh();}));
      remove.addEventListener("click",()=>busy(remove,async()=>{await api("integrations/webhooks/"+hook.id,undefined,{method:"DELETE"});clear();await refresh();}));
      actions.append(test,remove);row.append(info,actions);box.append(row);
    }
    if(!data.connections.length)box.append(viewState("empty",tr("No webhook destinations"),tr("Add a receiver to deliver structured notifications.")));
    const statuses={delivered:tr("Delivered"),retrying:tr("Retrying"),exhausted:tr("Retries exhausted")};
    const history=$("webhook-history");history.replaceChildren();for(const item of [...data.history].reverse()){history.append(node("p","hint",fmtFull(item.timestamp)+" · "+(statuses[item.status]||item.status)+" · "+item.attempt+" · "+item.event_id.slice(0,12)+(item.error?" · "+tr(item.error):"")));}
  }
  $("webhook-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
    const expected=revision;
    const result=await json("integrations/webhooks",{name:$("webhook-name").value,url:$("webhook-url").value,events:[...$("webhook-form").querySelectorAll('[name="hook-event"]:checked')].map(el=>el.value),chats:[...$("webhook-chats").querySelectorAll("input:checked")].map(el=>Number(el.value)),include_text:$("webhook-text").checked});
    if(expected!==revision)return;secret=result.secret;$("webhook-secret").value=secret;show("webhook-created",true);await refresh();
  });});
  $("webhook-copy").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(secret){await navigator.clipboard.writeText(secret);toast(tr("Signing secret copied. Store it only in the receiver's protected configuration."));}}));
  $("webhook-forget").addEventListener("click",clear);$("webhook-refresh").addEventListener("click",event=>busy(event.currentTarget,refresh));
  window.TgWitnessWebhooks={clear,load:async()=>{
    $("webhook-form").querySelector('button[type="submit"]').disabled=!!state.status?.demo;
    $("webhook-workspace").textContent=tr("Workspace")+": "+(state.profiles.find(p=>p.id===state.profile)?.label||state.profile);
    const box=$("webhook-chats");box.replaceChildren();const data=await json("chats");for(const chat of data.chats){const label=node("label","check-label"),input=node("input");input.type="checkbox";input.value=chat.chat_id;label.append(input,node("span","",chat.title||String(chat.chat_id)));box.append(label);}await refresh();
  }};
})();
