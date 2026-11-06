(() => {
  let inspection=null, pending=null, inspectionSerial=0, editing=false, intent='auto';
  const missing="No session — only application settings. Add a .session or TData file, or sign in by phone or QR.";
  const context=()=>({profile:state.profile,revision:state.workspaceRevision,selection:accountImportRevision});
  const current=c=>c.profile===state.profile&&c.revision===state.workspaceRevision&&c.selection===accountImportRevision&&!!state.token;
  const occupied=()=>!!state.status?.collector?.account;
  const adding=()=>occupied()&&(intent==='add'||intent==='auto'&&accountSignedIn());
  function selected(){
    const files=[...$("session-file").files];
    return files.length?files:$("session-string").value.trim()?
      [new File([$("session-string").value.trim()],"session.txt",{type:"text/plain"})]:[];
  }
  function controls(){
    if(authMethod!=="files")return;
    const allowed=!!inspection?.result.can_connect&&current(inspection.owner);
    if(!$("auth-continue").hasAttribute("aria-busy"))$("auth-continue").disabled=!allowed;
    $("auth-continue").textContent=tr(adding()?"Create workspace and connect":"Connect account");
    if(!$("import-account").hasAttribute("aria-busy"))$("import-account").disabled=!!pending||!selected().length;
  }
  function render(result){
    const box=$("import-result");box.className="import-check "+result.state;
    box.dataset.state=result.state;box.setAttribute("role","status");box.setAttribute("aria-live","polite");
    box.replaceChildren();box.hidden=result.state==="empty";
    if(box.hidden){controls();return;}
    const icons={ready:"✓",missing_session:"!",invalid:"!",incomplete:"!",checking:"…"};
    const head=node("div","import-check-head"),mark=node("span","import-check-mark",icons[result.state]||"!");
    mark.setAttribute("aria-hidden","true");
    const titles={ready:"Session found",missing_session:"No login session",invalid:"File cannot be used",incomplete:"More information needed",checking:"Checking your files…"};
    head.append(mark,node("strong","",tr(titles[result.state]||"File cannot be used")));box.append(head);
    if(result.message)box.append(node("p","",tr(result.message)));
    if(result.formats?.length)box.append(node("p","hint",result.formats.map(format=>tr(format)).join(" + ")));
    const profile=result.client_profile;
    if(profile){
      const details=node("dl","import-check-details");
      for(const [label,value] of [["Device",profile.device_model],["Platform",profile.system_version],
        ["App version",profile.app_version],["Language",profile.lang_code]]){
        if(!value)continue;const item=node("div");item.append(node("dt","",tr(label)),node("dd","",value));details.append(item);
      }
      box.append(details);
    }
    if(result.state==="missing_session"){
      const actions=node("div","import-check-actions");
      for(const [label,method] of [["Sign in by phone","phone"],["Sign in with QR","qr"]]){
        const button=node("button","quiet small",tr(label));button.type="button";
        button.addEventListener("click",()=>setAuthMethod(method));actions.append(button);
      }
      box.append(actions);
    }
    if(result.state==="invalid"){
      const retry=node("button","quiet small",tr("Check again"));retry.type="button";
      retry.addEventListener("click",()=>inspect());box.append(retry);
    }
    controls();
  }
  async function encode(files){
    const encoded=[];
    for(const file of files){
      const bytes=new Uint8Array(await file.arrayBuffer()),parts=[];
      for(let i=0;i<bytes.length;i+=32768)parts.push(String.fromCharCode(...bytes.subarray(i,i+32768)));
      encoded.push({name:file.name,content:btoa(parts.join(""))});
    }
    return encoded;
  }
  async function inspect(){
    const owner=context(),ticket=++inspectionSerial,files=selected(),passcode=$("tdata-passcode").value;
    inspection=null;
    if(!files.length){pending=null;render({state:"empty",can_connect:false});return null;}
    if(files.length>4||files.some(file=>!file.size)||files.reduce((n,file)=>n+file.size,0)>8*1024**2){
      pending=null;render({state:"invalid",can_connect:false,message:"Select 1–4 nonempty account files totaling at most 8 MiB."});return null;
    }
    render({state:"checking",can_connect:false,message:"No sign-in takes place during this check."});
    const work=(async()=>{
      try{
        if(files.every(file=>/\.json$/i.test(file.name))){
          const objects=await Promise.all(files.map(file=>file.text().then(text=>JSON.parse(text.replace(/^\uFEFF/,"")))));
          if(objects.every(value=>value&&typeof value==="object"&&!Array.isArray(value)&&
            !["string_session","session_string","session_str","session","auth_key","auth_key_hex"].some(key=>value[key])))
            if(current(owner)&&ticket===inspectionSerial)render({state:"missing_session",can_connect:false,message:missing});
        }
        const filesEncoded=await encode(files);
        if(!current(owner)||ticket!==inspectionSerial)return null;
        const result=await json("auth/import/preview",{files:filesEncoded,passcode},{profile:owner.profile});
        if(!current(owner)||ticket!==inspectionSerial)return null;
        const enteredId=$("api-id").value.trim();
        if(result.can_connect&&result.api_id&&enteredId&&Number(enteredId)!==result.api_id){
          result.state="incomplete";result.can_connect=false;
          result.message="The API ID entered above differs from the JSON. Clear the manual API settings or choose matching files.";
        }
        inspection={owner,result,files:filesEncoded,passcode,name:files[0].name.replace(/\.[^.]+$/,"").slice(0,80)||tr("Imported account")};
        render(result);return inspection;
      }catch(error){
        if(!current(owner)||ticket!==inspectionSerial||error instanceof StaleView)return null;
        const message=error instanceof SyntaxError?"Invalid account JSON. Choose an unmodified JSON file or the session file itself.":error.message;
        render({state:"invalid",can_connect:false,message});return null;
      }finally{if(ticket===inspectionSerial){pending=null;controls();}}
    })();
    pending=work;controls();return work;
  }
  async function checked(){
    const item=pending?await pending:inspection&&current(inspection.owner)?inspection:await inspect();
    if(!item?.result.can_connect)throw new Error(tr(item?.result.message||"Choose a valid session before connecting."));
    return item;
  }
  async function read(){
    const item=await checked();
    const result=await json("auth/import",{files:item.files,passcode:item.passcode,new_session:$("import-new-session").checked},{profile:item.owner.profile});
    if(!current(item.owner))return;
    if(!result.has_authorization)throw new Error(tr(missing));
    $("session-string").value=result.session;importExpectedId=result.expected_user_id||null;
    importClientProfile=result.client_profile||null;
    importFormats=result.formats||[];importTwoFactor=result.two_factor_password||"";
    if(result.api_id)$("api-id").value=result.api_id;
    if(result.api_hash)$("api-hash").value=result.api_hash;
    $("tdata-passcode").value="";renderApiState();render(item.result);return result;
  }
  async function connectNew(){
    const item=await checked();
    if(!state.me?.admin)throw new Error(tr("Ask the installation administrator to add another workspace."));
    const account=state.status.collector.account,who=account.username?"@"+account.username:"ID "+account.id;
    const name=await askText(tr("{who} stays in this workspace. The imported account gets its own journal, sources and signing key.",{who}),
      {title:tr("Add another account"),label:tr("New workspace name"),value:item.name,maxLength:80,confirmText:tr("Create workspace and connect")});
    if(!name?.trim()||!current(item.owner))return;
    const credentials=apiCredentials();if(!credentials)return;
    authProgress(tr("Creating the workspace and checking the session with Telegram…"));
    try{
      const result=await json("profiles/import",{files:item.files,passcode:item.passcode,label:name.trim(),new_session:$("import-new-session").checked,
        ...(credentials.api_id?{api_id:credentials.api_id,api_hash:credentials.api_hash.toLowerCase()}: {})},{root:true});
      if(!current(item.owner))return;
      await switchProfile(result.profile.id);await navigate("connection");
      if(result.step==="password")setAuthStep("password");
      else if(result.step==="retry"){
        setAuthStep("credentials");setAuthMethod("files");$("import-new-session").checked=true;
        toast(tr("The independent login was saved. Import the same donor again to resume.")+" "+(result.error||""),true);
      }else toast(tr("Account connected in its new workspace."));
    }finally{authProgress("");}
  }
  function clear(){inspectionSerial++;inspection=null;pending=null;editing=false;intent='auto';render({state:"empty",can_connect:false});}
  function beginAdd(){editing=true;intent='add';setAuthStep("credentials");setAuthMethod("files");renderAccount();$("session-file").focus();}
  async function removeWorkspace(){
    const profile=state.profile,revision=state.workspaceRevision,p=state.profiles.find(entry=>entry.id===profile);
    if(!p||profile==="default")return;
    if(!(await askTyped(tr("Delete \"{name}\" permanently? This stops its collector and erases its session, journal, sources and signing key. This cannot be undone.",{name:p.label}),p.label,
      {title:tr("Delete workspace"),confirmText:tr("Delete workspace")})))return;
    if(profile!==state.profile||revision!==state.workspaceRevision)throw new StaleView();
    await api("profiles/"+encodeURIComponent(profile),undefined,{root:true,method:"DELETE"});
    await switchProfile("default");toast(tr("Workspace deleted."));
  }
  function renderAccount(){
    if(!state.status)return;
    const account=state.status?.collector?.account,connected=accountSignedIn();
    if(!$("account-add-another")){
      const add=node("button","secondary",tr("Add another account"));add.id="account-add-another";add.type="button";
      add.addEventListener("click",beginAdd);$("account-manage").before(add);
      const remove=node("button","quiet danger-text",tr("Delete workspace"));remove.id="account-delete-workspace";remove.type="button";
      remove.addEventListener("click",()=>busy(remove,removeWorkspace));$("account-manage").querySelector(".account-manage-row").append(remove);
    }
    $("account-add-another").hidden=!state.me?.admin||!connected;
    $("account-delete-workspace").hidden=!state.me?.admin||state.profile==="default";
    const heading=$("account-heading");
    if(account&&connected){
      const who=account.username?"@"+account.username:"ID "+account.id;
      if(heading.isConnected)heading.textContent=tr(editing?(adding()&&authMethod==="files"?"Add another account":"Sign in again"):"Connected: {who}",{who});
      $("change-account").textContent=tr("Sign in again");
      $("sign-out").textContent=tr("Sign out of Telegram");
      $("authorized-account").textContent=(account.username?"@"+account.username+" · ":"")+"ID "+account.id;
    }
    let note=$("import-new-workspace");
    if(!note){note=node("p","hint",tr("Another account gets a separate workspace."));note.id="import-new-workspace";$("import-details").prepend(note);}
    note.hidden=!adding();controls();
  }
  for(const id of ["tdata-passcode","session-string"]){
    $(id).addEventListener("input",()=>{if(authMethod==="files")inspect();});
  }
  for(const id of ["api-id","api-hash"])$(id).addEventListener("change",()=>{if(authMethod==="files"&&selected().length)inspect();});
  window.TgWitnessAccountImport={inspect,read,connectNew,occupied,adding,clear,renderAccount,beginAdd,
    syncControls:controls,edit(){editing=true;intent='renew';},isEditing:()=>editing,methodChanged(){
      if(authMethod==="files")inspect();
      else{inspectionSerial++;inspection=null;pending=null;render({state:"empty",can_connect:false});$("auth-continue").disabled=false;}
      renderAccount();
    }};
})();
