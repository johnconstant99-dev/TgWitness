(() => {
  "use strict";
  const ENV="TGWITNESS_MCP_TOKEN", PLACEHOLDER="<PASTE_TOKEN_HERE>";
  const toolLabels={list_workspaces:tr("List workspaces"),list_chats:tr("List chats"),search_messages:tr("Search messages"),
    get_message_versions:tr("Message versions"),get_message_context:tr("Message context"),get_journal_event:tr("Journal records"),get_capture_status:tr("Capture status")};
  let secret="", issuedId=null, configuration=null, revision=0, owner=null, runtime=null, creating=false, timer=null, refreshing=null, checkActive=0;
  const groups=new Map(), connectionRows=new Map();
  const ownerKey=()=>state.workspaceRevision+":"+state.profile;
  const current=expected=>expected===revision&&owner===ownerKey()&&state.view==="integrations"&&!!state.token;
  function forget(){
    secret="";issuedId=null;configuration=null;checkActive=0;$("mcp-token").value="";$("mcp-config").textContent="";$("mcp-check-result").replaceChildren();show("mcp-created",false);
  }
  function clear(reset=false){
    revision++;clearTimeout(timer);timer=null;refreshing=null;creating=false;forget();
    if(reset){owner=null;runtime=null;groups.clear();connectionRows.clear();$("mcp-form").reset();$("mcp-scope").replaceChildren();$("mcp-tools").replaceChildren();$("mcp-list").replaceChildren();}
    if(reset){customExpiry.hidden=true;customMinutes.required=false;customMinutes.setCustomValidity("");}
    controls();
  }
  window.addEventListener("tgwitness:lock",()=>clear(true));
  $("mcp-form").before($("mcp-form-status"));
  const customExpiry=node("div"),customLabel=node("label","",tr("Custom duration (minutes)")),customMinutes=node("input");
  customExpiry.id="mcp-custom-expiry";customExpiry.hidden=true;customMinutes.id="mcp-custom-minutes";
  Object.assign(customMinutes,{type:"number",min:"1",max:String(90*24*60),step:"1",value:"60"});
  customLabel.htmlFor=customMinutes.id;customExpiry.append(customLabel,customMinutes,node("p","hint",tr("1 minute to 90 days. Starts when the server creates the connection.")));
  $("mcp-duration").append(new Option(tr("Custom duration"),"custom"));$("mcp-duration").after(customExpiry);
  function durationSeconds(){
    const seconds=$("mcp-duration").value==="custom"?Number(customMinutes.value)*60:Number($("mcp-duration").value)*3600;
    const valid=Number.isInteger(seconds)&&seconds>=60&&seconds<=Number(runtime?.max_days||90)*86400;
    customMinutes.setCustomValidity(valid?"":tr("Access must expire between one minute and 90 days from now."));
    return valid?seconds:null;
  }
  $("mcp-duration").addEventListener("change",()=>{customExpiry.hidden=$("mcp-duration").value!=="custom";customMinutes.required=!customExpiry.hidden;durationSeconds();});
  customMinutes.addEventListener("input",durationSeconds);

  function controls(){
    show("mcp-form",!!runtime?.available&&!state.status?.demo);
    $("mcp-fields").disabled=!runtime?.available||creating||!!state.status?.demo||owner!==ownerKey();
  }
  async function loadChats(profile,group,choices){
    if(group.dataset.loaded||group.dataset.loading===String(revision))return;
    const expected=revision;group.dataset.loading=String(expected);choices.replaceChildren(viewState("loading",tr("Loading…")));
    try{
      const result=await json("chats",undefined,{profile:profile.id});
      if(!current(expected)||!group.isConnected)return;
      choices.replaceChildren();group.dataset.loaded="true";
      const add=(value,label)=>{const row=node("label","check-label"),check=node("input");check.type="checkbox";check.dataset.workspace=profile.id;check.value=value;
        check.addEventListener("change",()=>{if(value==="all")choices.querySelectorAll('input:not([value="all"])').forEach(input=>{input.disabled=check.checked;});});
        row.append(check,node("span","",label));choices.append(row);};
      add("all",tr("All chats in this workspace, including future chats"));
      result.chats.forEach(chat=>add(String(chat.chat_id),chat.title||String(chat.chat_id)));
      if(!result.chats.length)choices.append(node("p","hint",tr("No saved chats yet. All chats includes future observations.")));
    }catch(error){
      if(!current(expected)||error instanceof StaleView)return;
      choices.replaceChildren(viewState("error",tr("Could not load data"),error.message,tr("Retry"),()=>loadChats(profile,group,choices)));
    }finally{if(group.dataset.loading===String(expected))delete group.dataset.loading;}
  }
  function scope(){
    const box=$("mcp-scope"),ids=new Set();
    for(const profile of state.profiles){
      if(profile.error_type)continue;ids.add(profile.id);
      let group=groups.get(profile.id);
      if(!group){
        group=node("details","access-group");const summary=node("summary"),choices=node("div","access-chats");group.append(summary,choices);box.append(group);groups.set(profile.id,group);
        group.addEventListener("toggle",()=>{if(group.open)loadChats(profile,group,choices);});
      }
      group.firstElementChild.textContent=profile.label;
      if(group.open&&!group.dataset.loaded)loadChats(profile,group,group.lastElementChild);
    }
    for(const [id,group] of groups)if(!ids.has(id)){group.remove();groups.delete(id);}
  }
  function renderTools(tools){
    const box=$("mcp-tools"),previous=[...box.querySelectorAll("input:checked")].map(input=>input.value),initialized=!!box.childElementCount;
    if(JSON.stringify([...box.querySelectorAll("input")].map(input=>input.value))===JSON.stringify(tools))return;
    box.replaceChildren();
    for(const name of tools){const label=node("label","check-label"),check=node("input"),text=node("span");check.type="checkbox";check.value=name;check.checked=initialized?previous.includes(name):true;
      check.addEventListener("change",()=>{$("mcp-preset").value="custom";});text.append(node("span","",toolLabels[name]||name),node("code","",name));label.append(check,text);box.append(label);}
  }
  $("mcp-preset").addEventListener("change",()=>{
    const value=$("mcp-preset").value;if(value==="custom")return;
    const overview=new Set(["list_workspaces","list_chats","get_capture_status"]);
    $("mcp-tools").querySelectorAll("input").forEach(input=>input.checked=value==="all"||overview.has(input.value));
  });
  function renderConnections(connections){
    const box=$("mcp-list"),keep=new Set(connections.map(entry=>entry.id));
    for(const [id,item] of connectionRows)if(!keep.has(id)){item.row.remove();connectionRows.delete(id);}
    if(connections.length)box.querySelector(":scope > .ui-state")?.remove();
    const text=(element,value)=>{if(element.textContent!==value)element.textContent=value;};
    connections.forEach((entry,index)=>{
      let item=connectionRows.get(entry.id);
      if(!item){
        const row=node("div","target-row mcp-connection"),info=node("div"),actions=node("div","route-actions"),details=node("details");
        row.dataset.connection=entry.id;details.dataset.connection=entry.id;
        item={row,details,entry};
        for(const key of ["name","status","rate","last","scope","uses","address","tool","tools"])
          item[key]=node(key==="name"?"h3":key==="tools"?"code":"p",key==="tools"?"mcp-tool-names":"");
        details.append(node("summary","",tr("Connection details")),item.uses,item.address,item.tool,node("p","",tr("Allowed tools")),item.tools);
        info.append(item.name,item.status,item.rate,item.last,item.scope,details);
        item.rotate=node("button","secondary",tr("Rotate token"));item.revoke=node("button","danger",tr("Revoke"));
        item.rotate.type=item.revoke.type="button";actions.append(item.rotate,item.revoke);row.append(info,actions);
        item.rotate.addEventListener("click",()=>{
          const entry=item.entry;
          if(!window.confirm(tr("Replace the token for {name}? The old token stops working immediately.",{name:entry.name})))return;
          const expected=revision;busy(item.rotate,async()=>{const result=await json("mcp/connections/"+encodeURIComponent(entry.id)+"/rotate",{},{root:true});if(!current(expected))return;issued(result);await afterMutation(expected);});
        });
        item.revoke.addEventListener("click",()=>{
          const entry=item.entry;
          if(!window.confirm(tr("Revoke {name}? Its next request will be refused.",{name:entry.name})))return;
          const expected=revision;busy(item.revoke,async()=>{await api("mcp/connections/"+encodeURIComponent(entry.id),undefined,{method:"DELETE",root:true});if(!current(expected))return;if(issuedId===entry.id)forget();await afterMutation(expected);});
        });
        connectionRows.set(entry.id,item);
      }
      item.entry=entry;
      const expired=entry.expires_at*1000<=Date.now(),status=entry.revoked_at?tr("Revoked"):expired?tr("Expired"):tr("Active");
      text(item.name,entry.name);text(item.status,status+" · "+tr("Expires {time}",{time:formatTime(entry.expires_at*1000)}));
      text(item.rate,tr("Last minute: {n} / {limit} requests",{n:entry.requests_last_minute||0,limit:entry.rate_limit_per_minute||60}));
      text(item.last,entry.last_used_at?tr("Last used {time}",{time:formatTime(entry.last_used_at*1000)}):tr("Not used yet"));
      const scopes=Object.entries(entry.workspaces).map(([id,chats])=>(state.profiles.find(profile=>profile.id===id)?.label||id)+": "+(chats?chats.join(", "):tr("All chats")));
      text(item.scope,scopes.join(" · "));text(item.uses,tr("Requests: {n}",{n:entry.uses||0}));
      text(item.address,tr("Last address: {address}",{address:entry.last_address||tr("Not used yet")}));
      text(item.tool,tr("Last tool: {tool}",{tool:entry.last_tool||tr("Not used yet")}));text(item.tools,entry.tools.join(", "));
      item.rotate.disabled=!!entry.revoked_at||expired||!runtime?.available||item.rotate.hasAttribute("aria-busy");
      item.revoke.disabled=!!entry.revoked_at||item.revoke.hasAttribute("aria-busy");
      if(box.children[index]!==item.row)box.insertBefore(item.row,box.children[index]||null);
    });
    if(!connections.length&&!box.childElementCount)box.append(viewState("empty",tr("No archive connections"),tr("Create a connection above to grant read-only access.")));
  }
  function schedule(){
    clearTimeout(timer);timer=null;
    if(state.view==="integrations"&&state.token&&!state.status?.demo)timer=setTimeout(()=>{if(!document.hidden)refresh();else schedule();},15000);
  }
  async function afterMutation(expected){if(refreshing)await refreshing;if(current(expected))await refresh();}
  async function refresh(){
    if(refreshing)return refreshing;
    if(state.status?.demo){runtime=null;controls();show("mcp-unavailable",false);$("mcp-list").replaceChildren(viewState("unavailable",tr("Available in your own workspace"),tr("Create an archive connection in your local TgWitness installation.")));return;}
    const expected=revision;
    const task=(async()=>{
      try{
        const result=await json("mcp",undefined,{root:true});if(!current(expected))return;
        runtime=result;controls();scope();renderTools(result.tools);renderConnections(result.connections);
        $("mcp-form-status").textContent="";show("mcp-unavailable",!result.available);
        $("mcp-problem").textContent=result.problem?tr(result.problem):"";$("mcp-install-command").textContent=result.install_command||"";$("mcp-copy-install").disabled=!result.install_command;
        for(const option of $("mcp-duration").options)option.disabled=Number(option.value)>Number(result.max_days||90)*24;
      }catch(error){
        if(!current(expected)||error instanceof StaleView)return;
        if(runtime)runtime={...runtime,available:false};controls();
        const retry=node("button","quiet",tr("Retry"));retry.type="button";retry.addEventListener("click",refresh);
        $("mcp-form-status").replaceChildren(node("span","",tr("Could not load data")+": "+error.message),retry);
      }finally{if(expected===revision){refreshing=null;schedule();}}
    })();refreshing=task;return task;
  }
  function endpoint(){
    let url;try{url=new URL($("mcp-url").value.trim());}catch{throw new Error(tr("Use HTTPS for a remote MCP server."));}
    if(url.username||url.password||url.search||url.hash||!(url.protocol==="https:"||url.protocol==="http:"&&["127.0.0.1","localhost","[::1]"].includes(url.hostname)))throw new Error(tr("Use HTTPS for a remote MCP server."));
    return url.href;
  }
  function config(){
    const url=endpoint(),client=$("mcp-client").value,type=$("mcp-mode").value;
    const local={command:$("mcp-command").value.trim()||"python",args:["-m","tgwitness.mcp_server","--url",url]};
    const prompt="${input:tgwitness-token}",env=client==="cursor"?"${env:"+ENV+"}":client==="claude-code"?"${"+ENV+"}":PLACEHOLDER;
    let data,where,reference;
    if(client==="vscode"){
      data={inputs:[{type:"promptString",id:"tgwitness-token",description:"TgWitness MCP token",password:true}],servers:{tgwitness:type==="http"?{type:"http",url,headers:{Authorization:"Bearer "+prompt}}:{type:"stdio",...local,env:{[ENV]:prompt}}}};
      where=tr("Save as .vscode/mcp.json. Start tgwitness with MCP: List Servers and paste the token when prompted. Use a Local harness session.");
      reference="https://code.visualstudio.com/docs/agents/reference/mcp-configuration";
    }else if(client==="cursor"||client==="claude-code"){
      data={mcpServers:{tgwitness:type==="http"?{...(client==="claude-code"?{type:"http"}:{}),url,headers:{Authorization:"Bearer "+env}}:{...local,env:{[ENV]:env}}}};
      where=client==="cursor"?tr("Save as .cursor/mcp.json. Set TGWITNESS_MCP_TOKEN to the saved token before starting Cursor."):tr("Save as .mcp.json. Set TGWITNESS_MCP_TOKEN to the saved token before starting Claude Code.");
      reference=client==="cursor"?"https://prod.cursor.com/docs/mcp":"https://code.claude.com/docs/en/mcp";
    }else if(client==="claude-desktop"){
      data={mcpServers:{tgwitness:{...local,env:{[ENV]:PLACEHOLDER}}}};
      where=tr("Claude Desktop: Settings → Developer → Edit Config. Replace <PASTE_TOKEN_HERE> with the saved token, then restart the client.");reference="https://modelcontextprotocol.io/docs/develop/connect-local-servers";
    }else if(client==="windsurf"){
      data={mcpServers:{tgwitness:type==="http"?{serverUrl:url,headers:{Authorization:"Bearer "+PLACEHOLDER}}:{...local,env:{[ENV]:PLACEHOLDER}}}};
      where=tr("Windsurf: MCP settings → View raw config. Replace <PASTE_TOKEN_HERE> with the saved token, then refresh the servers.");reference="https://docs.windsurf.com/windsurf/cascade/mcp";
    }else{
      data=type==="http"?{url,headers:{Authorization:"Bearer "+PLACEHOLDER}}:{...local,env:{[ENV]:PLACEHOLDER}};
      where=tr("Use these connection settings in your MCP client. Replace <PASTE_TOKEN_HERE> with the saved token.");reference="https://modelcontextprotocol.io/docs/develop/connect-local-servers";
    }
    return {data,where,reference,url,type};
  }
  function syncConfig(){
    const desktop=$("mcp-client").value==="claude-desktop";if(desktop)$("mcp-mode").value="stdio";$("mcp-mode").disabled=desktop;show("mcp-local",$("mcp-mode").value==="stdio");
    $("mcp-check-result").replaceChildren();configuration=null;
    try{
      const next=config();configuration=next;$("mcp-config").textContent=JSON.stringify(next.data,null,2);$("mcp-config-where").textContent=next.where;$("mcp-client-help").href=next.reference;
      const temporary=new URL(next.url).hostname.endsWith(".trycloudflare.com");show("mcp-url-warning",temporary);
      $("mcp-url-warning").textContent=temporary?tr("This temporary tunnel address changes when the tunnel restarts. Use a stable HTTPS address for a lasting connection."):"";
    }catch(error){$("mcp-config").textContent="";$("mcp-config-where").textContent=error.message;show("mcp-url-warning",false);}
    for(const id of ["mcp-copy-config","mcp-download","mcp-check"])$(id).disabled=!configuration||!secret;
    if(checkActive)$("mcp-check").disabled=true;
  }
  for(const id of ["mcp-client","mcp-mode","mcp-command","mcp-url"])$(id).addEventListener(id==="mcp-command"||id==="mcp-url"?"input":"change",syncConfig);
  function issued(result){
    secret=result.token;issuedId=result.connection.id;$("mcp-token").value=secret;$("mcp-created-name").textContent=result.connection.name;
    if(!$("mcp-url").value)$("mcp-url").value=new URL(runtime?.endpoint||"/mcp",location.origin).href;
    show("mcp-created",true);syncConfig();$("mcp-created").scrollIntoView({block:"start",behavior:"instant"});$("mcp-copy-token").focus({preventScroll:true});
  }
  $("mcp-form").addEventListener("submit",event=>{event.preventDefault();if(creating||$("mcp-fields").disabled)return;
    const workspaces={};$("mcp-scope").querySelectorAll("input:checked").forEach(input=>{
      const id=input.dataset.workspace;if(input.value==="all")workspaces[id]=null;else if(workspaces[id]!==null)(workspaces[id]??=[]).push(Number(input.value));
    });
    const tools=[...$("mcp-tools").querySelectorAll("input:checked")].map(input=>input.value),expected=revision;
    busy(event.submitter,async()=>{
      if(!Object.keys(workspaces).length)throw new Error(tr("Choose at least one workspace and chat."));
      if(!tools.length)throw new Error(tr("Choose at least one tool."));
      const duration=durationSeconds();if(duration===null){customMinutes.reportValidity();return;}
      if(secret&&!window.confirm(tr("Replace the token shown here? Save it first; it cannot be retrieved later.")))return;
      creating=true;controls();
      try{const result=await json("mcp/connections",{name:$("mcp-name").value.trim(),workspaces,tools,expires_in_seconds:duration},{root:true});
        if(!current(expected))return;issued(result);await afterMutation(expected);
      }finally{if(expected===revision){creating=false;controls();}}
    });
  });
  $("mcp-copy-token").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(secret){await navigator.clipboard.writeText(secret);toast(tr("Archive token copied. It grants access to the selected chats."));}}));
  $("mcp-hide-token").addEventListener("click",()=>{
    forget();$("mcp-form").reset();customExpiry.hidden=true;customMinutes.required=false;customMinutes.setCustomValidity("");groups.clear();$("mcp-scope").replaceChildren();$("mcp-tools").replaceChildren();
    scope();renderTools(runtime?.tools||[]);$("mcp-name").focus();
  });
  $("mcp-copy-install").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(runtime?.install_command){await navigator.clipboard.writeText(runtime.install_command);toast(tr("Copied"));}}));
  $("mcp-copy-config").addEventListener("click",event=>busy(event.currentTarget,async()=>{if(configuration){await navigator.clipboard.writeText(JSON.stringify(configuration.data,null,2)+"\n");toast(tr("Configuration copied."));}}));
  $("mcp-download").addEventListener("click",()=>{
    if(!configuration||!secret)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(configuration.data,null,2)+"\n"],{type:"application/json"})),link=node("a");
    link.href=url;link.download="mcp.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  let checking=0;
  $("mcp-check").addEventListener("click",event=>{let request=0;busy(event.currentTarget,async()=>{
    if(!secret||!configuration)return;
    const expected=revision,token=secret,next=configuration;request=++checking;checkActive=request;$("mcp-check-result").replaceChildren(node("span","",tr("Checking…")));
    try{
      const result=await json("mcp/check",{token,transport:next.type,url:next.url},{root:true});
      if(!current(expected)||secret!==token||configuration!==next||request!==checking)return;
      const box=$("mcp-check-result"),details=node("details");details.append(node("summary","",tr("Allowed tools")),node("code","mcp-tool-names",result.tools.join(", ")));
      box.replaceChildren(node("span","",tr("Protocol and access checked. No messages were read.")),node("span","hint",tr("MCP {version} · {n} tools · {ms} ms",{version:result.protocol_version,n:result.tools.length,ms:Math.round(result.latency_ms)})),details);
      if(next.type==="stdio")box.append(node("span","hint",tr("The server-side relay passed. Your client device still needs TgWitness with MCP support.")));
    }catch(error){if(!current(expected)||secret!==token||configuration!==next||request!==checking||error instanceof StaleView)return;$("mcp-check-result").textContent=error.message;}
  }).finally(()=>{if(checkActive===request)checkActive=0;$("mcp-check").disabled=!!checkActive||!secret||!configuration;});});
  for(const id of ["mcp-refresh","mcp-recheck"])$(id).addEventListener("click",event=>busy(event.currentTarget,refresh));
  window.TgWitnessIntegrations={clear,refresh,load:async()=>{
    if(owner!==ownerKey()){clear(true);owner=ownerKey();$("mcp-url").value="";$("mcp-command").value="python";$("mcp-client").value="vscode";$("mcp-mode").value="http";}
    const expected=revision;controls();scope();
    await Promise.all([refresh(),window.TgWitnessWebhooks?.load().catch(error=>{
      if(current(expected)&&!(error instanceof StaleView))$("webhook-list").replaceChildren(viewState("error",tr("Could not load data"),error.message));
    })]);
  }};
})();
