(() => {
  "use strict";
  let secret = "", configuration = null, revision=0;
  function clear() { revision++;secret="";$("mcp-token").value="";show("mcp-created",false);configuration=null; }
  window.addEventListener("tgwitness:lock",clear);
  function mode(){show("mcp-local",$("mcp-mode").value==="stdio");show("mcp-remote",$("mcp-mode").value==="http");}
  $("mcp-mode").addEventListener("change",mode);
  async function scope(){
    const box=$("mcp-scope");box.replaceChildren();
    for(const profile of state.profiles){
      if(profile.error_type)continue;
      const group=node("details","access-group"),summary=node("summary","",profile.label),choices=node("div","access-chats");
      group.append(summary,choices);box.append(group);
      group.addEventListener("toggle",async()=>{
        if(!group.open||group.dataset.loaded)return;
        group.dataset.loaded="true";choices.replaceChildren(viewState("loading",tr("Loading…")));
        try{
          const result=await json("chats",undefined,{profile:profile.id});choices.replaceChildren();
          const add=(value,label)=>{const row=node("label","check-label"),check=node("input");check.type="checkbox";check.dataset.workspace=profile.id;check.value=value;row.append(check,node("span","",label));choices.append(row);};
          add("all",tr("All chats in this workspace, including future chats"));
          result.chats.forEach(chat=>add(String(chat.chat_id),chat.title||String(chat.chat_id)));
        }catch(error){group.dataset.loaded="";choices.replaceChildren(viewState("error",tr("Could not load data"),error.message));}
      });
    }
  }
  async function refresh(){
    const box=$("mcp-list");
    if(state.status?.demo){box.replaceChildren(viewState("unavailable",tr("Available in your own workspace"),tr("Create an archive connection in your local TgWitness installation.")));return;}
    const result=await json("integrations/mcp",undefined,{root:true});box.replaceChildren();
    for(const entry of result.connections){
      const row=node("div","target-row"),info=node("div"),status=entry.revoked_at?tr("Revoked"):entry.expires_at*1000<=Date.now()?tr("Expired"):tr("Active");
      info.append(node("h3","",entry.name),node("p","",status+" · "+tr("Expires {time}",{time:formatTime(entry.expires_at*1000)})),
        node("p","",entry.last_used_at?tr("Last used {time}",{time:formatTime(entry.last_used_at*1000)}):tr("Not used yet")));
      const scopes=Object.entries(entry.workspaces).map(([id,chats])=>(state.profiles.find(p=>p.id===id)?.label||id)+": "+(chats?chats.join(", "):tr("All chats")));
      info.append(node("p","",scopes.join(" · ")));
      const details=node("details"),summary=node("summary","",tr("Allowed tools"));details.append(summary,node("code","",entry.tools.join(", ")));info.append(details);
      const revoke=node("button","danger",tr("Revoke"));revoke.type="button";revoke.disabled=!!entry.revoked_at;
      revoke.addEventListener("click",()=>busy(revoke,async()=>{await api("integrations/mcp/"+encodeURIComponent(entry.id),undefined,{method:"DELETE",root:true});clear();await refresh();}));
      row.append(info,revoke);box.append(row);
    }
    if(!result.connections.length)box.append(viewState("empty",tr("No archive connections"),tr("Create a connection above to grant read-only access.")));
  }
  function config(){
    const prompt="${input:tgwitness-archive-token}";
    const server=$("mcp-mode").value==="stdio"?{type:"stdio",command:$("mcp-command").value.trim()||"python",
      args:["-m","tgwitness.mcp_server","--api-url",location.origin],env:{TGWITNESS_ARCHIVE_TOKEN:prompt}}:
      {type:"http",url:$("mcp-url").value.trim(),headers:{Authorization:"Bearer "+prompt}};
    if(server.type==="http"){
      const url=new URL(server.url);
      if(url.username||url.password||url.search||url.hash||!(url.protocol==="https:"||url.protocol==="http:"&&["127.0.0.1","localhost","[::1]"].includes(url.hostname)))throw new Error(tr("Use HTTPS for a remote MCP server."));
    }
    return {inputs:[{type:"promptString",id:"tgwitness-archive-token",description:"TgWitness archive access token",password:true}],servers:{tgwitness:server}};
  }
  $("mcp-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
    const workspaces={};$("mcp-scope").querySelectorAll("input:checked").forEach(input=>{
      const id=input.dataset.workspace;if(input.value==="all")workspaces[id]=null;
      else if(workspaces[id]!==null)(workspaces[id]??=[]).push(Number(input.value));
    });
    if(!Object.keys(workspaces).length)throw new Error(tr("Choose at least one workspace and chat."));
    const next=config();
    const expected=revision;
    const result=await json("integrations/mcp",{name:$("mcp-name").value.trim(),workspaces,expires_at:Date.now()/1000+Number($("mcp-duration").value)*3600},{root:true});
    if(expected!==revision)return;
    secret=result.token;configuration=next;$("mcp-token").value=secret;$("mcp-check-result").textContent="";show("mcp-created",true);await refresh();
  });});
  $("mcp-copy-token").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(secret){await navigator.clipboard.writeText(secret);toast(tr("Archive token copied. It grants access to the selected chats."));}}));
  $("mcp-hide-token").addEventListener("click",clear);
  $("mcp-download").addEventListener("click",()=>{
    if(!configuration)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(configuration,null,2)+"\n"],{type:"application/json"})),link=node("a");
    link.href=url;link.download="mcp.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  $("mcp-check").addEventListener("click",event=>busy(event.currentTarget,async()=>{
    if(!secret||!configuration)return;
    const server=configuration.servers.tgwitness;
    const result=await json("integrations/mcp/check",{token:secret,transport:server.type,url:server.type==="http"?server.url:null},{root:true});
    $("mcp-check-result").textContent=tr("Protocol and access checked. No messages were read.")+" · "+result.tools.length;
  }));
  $("mcp-refresh").addEventListener("click",event=>busy(event.currentTarget,refresh));
  window.TgWitnessIntegrations={clear,load:async()=>{
    try{mode();$("mcp-form").querySelector('button[type="submit"]').disabled=!!state.status?.demo;await scope();await refresh();await window.TgWitnessWebhooks?.load();}
    catch(error){$("mcp-list").replaceChildren(viewState("error",tr("Could not load data"),error.message,tr("Retry"),refresh));}
  }};
})();
