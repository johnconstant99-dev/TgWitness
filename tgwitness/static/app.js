"use strict";
// Classic addons share this adapter; each screen keeps its own root while detached.
const panelRoots=new Map([...document.querySelectorAll('.view')].map(root=>[root.id.slice(5),root]));
const $ = id => {
  const attached=document.getElementById(id);if(attached)return attached;
  for(const root of panelRoots.values()){
    if(root.id===id)return root;
    const found=root.querySelector('#'+CSS.escape(id));if(found)return found;
  }
  return null;
};
const viewQuery=(view,selector)=>panelRoots.get(view)?.querySelector(selector);
const viewQueries=(view,selector)=>[...panelRoots.get(view)?.querySelectorAll(selector)||[]];
function panelQueries(selector){
  const found=new Set(document.querySelectorAll(selector));
  for(const root of panelRoots.values())if(!root.isConnected)for(const item of root.querySelectorAll(selector))found.add(item);
  return [...found];
}
const state = {token: sessionStorage.getItem("tgwitness-token") || "",
  view:({account:"connection",sources:"sources",exports:"evidence",journal:"observations",sealed:"sealed"}[location.hash.slice(1)]||"connection"), status: null,
  events: [], dialogs: [], filter: "", source: "", search: "", eventSince:"",eventUntil:"",eventSystem:false,
  eventBefore:null,eventAfter:null,eventMatched:null,cursor: null, request: 0, drawerSeq: null,
  profile: sessionStorage.getItem("tgwitness-profile") || "default", profiles: [], demoToken: "", monitoringDirty: false,
  captureDirty: false, workspaceRevision: 0, verification: null, opened:false, connectionSettings:false,
  chat: null, chats: [], chatsLoading: false, chatsError: false, chatMessages: [], chatNextBefore: null, chatNextAfter: null, chatInfo: null, chatFilter: "all", chatView: "messages", chatAuthor: null,
  scope: null, scopeDirty: false, dossier: null, notifications: [], witnessToken: null, parameters: null, parametersDirty: false,
  me: null, access: null, accessEdit: null, accessChats: {}, consoleAfter: 0,
  accountExportJobs: [], accountExportDefaults: null, accountExportCapabilities: null,
  accountExportDraftProfile: null, accountExportDirty: false,
  accountDisclosureJob: null, accountDisclosurePreview: null, accountDisclosureDirty: false,
  accountDisclosures: {}, exportTask: 'journal', workflow: null};
let accountState;
const accountStateReady=import('./components/account-state.js?v=1').then(module=>{accountState=module.accountState;});
let disclosurePreview;
const disclosurePreviewReady=import('./views/disclosure-preview.js?v=1').then(({createDisclosurePreview})=>{
  disclosurePreview=createDisclosurePreview({root:$('view-evidence'),tr,formatTime:accountExportTime});
});
let viewHost=null;
const viewContexts=new Map();
const viewOptions=view=>({signal:viewContexts.get(view)?.signal});
const viewReady=Promise.all([
  import('./core/view-host.js?v=1'),
  new Promise(resolve=>document.readyState==='complete'?resolve():document.addEventListener('DOMContentLoaded',resolve,{once:true})),
]).then(([{createViewHost}])=>{
  viewHost=createViewHost({getSession:()=>({workspace:state.profile,revision:state.workspaceRevision}),onError:error=>toast(error.message,true)});
  for(const [name,root] of panelRoots){
    let top=0,scrolls=[];
    viewHost.register(name,root,{
      async enter(context){
        viewContexts.set(name,context);
        if(context.params.load!==false)await loadPanelView(name);
        if(!context.current())return;
        for(const [element,scroll] of scrolls)if(root.contains(element))element.scrollTop=scroll;
        if(context.params.restore!==false)window.scrollTo({top,behavior:'instant'});
      },
      updateStatus:()=>renderViewStatus(name),
      leave(){
        top=window.scrollY;scrolls=[root,...root.querySelectorAll('*')].filter(element=>element.scrollTop).map(element=>[element,element.scrollTop]);
        if(name==='connection')window.TgWitnessProxies?.stop?.();
        if(name==='integrations'){window.TgWitnessIntegrations?.clear();window.TgWitnessWebhooks?.clear();}
        if(name==='sealed')window.TgWitnessCaptureStory?.pause?.();
        if(name==='parameters')parametersView?.leave();
        if(name==='evidence')exportsView?.leave();
        if(name==='system-log')systemLogView?.leave();
        if(name==='observations')window.TgWitnessJournal?.leave();
      },
      resetSession(){top=0;scrolls=[];viewContexts.delete(name);resetViewContent(name);},
    });
  }
});
function resetViewContent(view){
  const root=panelRoots.get(view);for(const form of root.querySelectorAll('form'))form.reset();
  for(const field of root.querySelectorAll('input,textarea'))if(!field.form){field.value=field.defaultValue;field.checked=field.defaultChecked;}
  if(view==='connection'){networkLoadedFor=null;policyOutsideDirty=false;policyFormDirty=false;state.policy=null;}
  if(view==='sources'){state.scope=null;state.scopeDirty=false;state.recheckDirty=false;}
  if(view==='parameters')parametersView?.resetSession();
  if(view==='evidence'){exportsView?.resetSession();resetAccountExport();}
  if(view==='accounts')accountsView?.resetSession();
  if(view==='witness'){state.evidenceDirty=false;state.replicaDirty=false;state.alertsDirty=false;state.githubDirty=false;}
  if(view==='chats')chatListView?.resetSession();
  if(view==='sealed')window.TgWitnessCapture?.reset();
  if(view==='system-log')systemLogView?.resetSession();
  if(view==='access'){accessView?.resetSession();accessFormVersion++;adminLimitsVersion++;accessFormReady=false;adminLimitsReady=false;adminLimitsDirty=false;accessLoadSerial++;
    state.access=null;state.accessEdit=null;state.accessChats={};state.consoleAfter=0;show('access-new',false);}
  if(view==='observations')window.TgWitnessJournal?.reset();
  const clear={observations:['events-body'],chats:['chats-list','chat-feed','chat-people','chat-about'],accounts:['accounts-list','fleet-groups'],
    access:['access-list','access-sessions-list','access-token'],'system-log':['access-console'],
    connection:['profiles-list'],witness:['witness-list','github-result','cloud-health','alerts-saved','evidence-status','replica-status'],
    integrations:['webhook-list','webhook-history','webhook-chats']}[view]||[];
  for(const id of clear)$(id)?.replaceChildren();
}
async function loadPanelView(view){
  if(view==='start')renderWorkflowControls();
  else if(view==='sources'){await sourcesReady;sourcesView.enter();renderTargets();await loadScope();}
  else if(view==='witness')await loadExtras();
  else if(view==='parameters')await loadParameters();
  else if(view==='accounts'){renderAccounts();await loadProfiles();}
  else if(view==='chats')await refreshChats(true);
  else if(view==='observations')await refreshEvents();
  else if(view==='access')await loadAccess();
  else if(view==='system-log')await loadConsole();
  else if(view==='evidence'){
    renderChatExportTools();
    await Promise.all([loadReportSettings(),loadExports(),loadAccountExport().catch(accountExportError)]);
  }
  else if(view==='integrations')await window.TgWitnessIntegrations?.load();
  else if(view==='analysis')await window.TgWitnessAnalysis?.load();
  else if(view==='connection'){await loadProfiles();if(!state.status.demo)await loadPolicy();}
}
let routerTask=null;
function routeSnapshot(){return {view:state.drawerSeq!==null?"observations":state.view,workspace:state.profile,
  chatId:state.view==="chats"?state.chat:null,seq:state.drawerSeq,kind:state.filter,source:state.source,q:state.search,
  since:state.eventSince,until:state.eventUntil,system:state.eventSystem,before:state.eventBefore,extra:state.extra||null,section:state.parameterSection||null};}
function ensureRouter(){
  if(!routerTask)routerTask=import("./router.js?v=4").then(({createRouter})=>{
    window.TgWitnessRouter=createRouter({snapshot:routeSnapshot,ready:()=>!!state.me&&!$("workspace").hidden,
      error:message=>toast(tr(message),true),apply:applyRouteToPanel});return window.TgWitnessRouter;
  });
  return routerTask;
}
async function applyRouteToPanel(route,current){
  if(!state.profiles.some(profile=>profile.id===route.workspace&&!profile.error_type))throw new Error(tr("Unknown workspace."));
  if(state.profile!==route.workspace)await switchProfile(route.workspace,{history:false});
  if(!current())return;
  closeDetail({history:false});
  state.filter=route.kind;state.source=route.source;state.search=route.q;state.eventSince=route.since;state.eventUntil=route.until;
  state.eventSystem=!!route.system;
  state.eventBefore=route.before??null;
  $("event-search").value=state.search;fillSourceSelect("source-filter",state.source,true);
  viewQueries("observations","[data-filter]").forEach(button=>button.classList.toggle("active",button.dataset.filter===state.filter));
  navigate(route.view,{history:false,load:false});
  const view=state.view;
  if(view==="chats"){await refreshChats();if(current()&&route.chatId!==null)await openChat(route.chatId,{history:false});}
  else if(view==="observations"){await refreshEvents();if(current()&&route.seq)await openRecord(route.seq,{history:false});}
  else if(view==="sources"){await sourcesReady;sourcesView.enter();renderTargets();await loadScope();}
  else if(view==="parameters"){
    await loadParameters();if(current()){state.parameterSection=route.section;if(route.section)parametersView?.selectSection(route.section,{record:false});}
  }else if(view==="accounts")await loadProfiles();
  else if(view==="connection"){await loadProfiles();if(current()&&!state.status.demo)await loadPolicy();}
  else if(view==="access")await loadAccess();
  else if(view==="system-log")await loadConsole();
  else if(view==="integrations")await window.TgWitnessIntegrations?.load();
  else if(view==="analysis")await window.TgWitnessAnalysis?.load();
  else if(view==="evidence"){
    renderChatExportTools();
    await Promise.all([loadReportSettings(),loadExports(),loadAccountExport().catch(accountExportError)]);
  }
  else if(view==="witness"){await loadExtras();if(current())selectExtra(route.extra,{history:false});}
}

const permissionLabels={
  view:[tr("Read"),tr("Chats, journal, messages, attachments and settings. Always included.")],
  export:[tr("Exports"),tr("Download signed exports, chat exports and people profiles.")],
  sources:[tr("Sources"),tr("Choose chats, the observation scope, rechecks and history snapshots.")],
  collect:[tr("Observation"),tr("Start and pause observation.")],
  interact:[tr("Act in Telegram"),tr("Send messages, press buttons and open links as the account.")],
  settings:[tr("Settings"),tr("Attachments, monitoring, evidence mode, off-site copy, notifications, parameters and witnesses.")],
  account:[tr("Account"),tr("Connect or sign out the Telegram account and change its connection route.")]};
const sessionEndReasons={"signed out":tr("signed out"),"replaced by a newer session":tr("replaced by a newer session"),
  "ended by the administrator":tr("ended by the administrator"),"access revoked":tr("access revoked"),
  "access changed":tr("access changed"),"access expired":tr("access expired")};

const labels = {
  "interaction.preview": [tr("Telegram link preview saved"), "link", "system"],
  "interaction.requested": [tr("Panel action requested"), "play", "system"],
  "interaction.result": [tr("Panel action result"), "receipt", "system"],
  "message.new": [tr("Message captured"), "message", ""], "message.edited": [tr("Message edited"), "edit", "edit"],
  "message.deleted": [tr("Deletion observed"), "trash", "delete"], "message.snapshot": [tr("History snapshot"), "layers", ""],
  "message.recovered": [tr("Missed message recovered"), "refresh", ""],
  "message.missing_on_recheck": [tr("Not found at recheck"), "question", "delete"],
  "recheck.completed": [tr("Recheck completed"), "refresh", "system"],
  "replica.completed": [tr("Off-site copy"), "export", "system"], "replica.changed": [tr("Off-site copy settings changed"), "settings", "system"],
  "alerts.changed": [tr("Notification settings changed"), "settings", "system"],
  "source.checked": [tr("Code checked against GitHub"), "shield", "system"],
  "anchor.completed": [tr("Checkpoint timestamped"), "clock", "system"], "evidence.changed": [tr("Evidence mode changed"), "settings", "system"],
  "storage.low": [tr("Disk almost full"), "alert", "coverage"], "storage.ok": [tr("Disk space available again"), "refresh", "system"],
  "reaction.snapshot": [tr("Reactions observed"), "heart", "reaction"], "membership.service": [tr("Membership service event"), "users", "member"],
  "membership.update": [tr("Participant update"), "users", "member"], "coverage.gap": [tr("Coverage gap"), "alert", "coverage"],
  "connection.restored": [tr("Connection restored"), "link", "system"], "deletion.unscoped": [tr("Unscoped deletion notice"), "question", "coverage"],
  "collector.heartbeat": [tr("Collector heartbeat"), "activity", "system"], "process.started": [tr("Collector process started"), "play", "system"],
  "process.stopped": [tr("Collector process stopped"), "stop", "coverage"], "observation.started": [tr("Observation started"), "play", "system"],
  "observation.stopped": [tr("Observation paused"), "pause", "coverage"], "media.saved": [tr("Attachment preserved"), "clip", ""],
  "media.skipped": [tr("Attachment not collected"), "clip", "coverage"], "media.failed": [tr("Attachment unavailable"), "alert", "coverage"],
  "collector.error": [tr("Collection error"), "alert", "coverage"], "demo.created": [tr("Synthetic demo created"), "sparkle", "system"],
  "media.retry": [tr("Attachment retry scheduled"), "refresh", "coverage"],
  "media.recovered": [tr("Interrupted media jobs recovered"), "refresh", "system"],
  "source.access_unconfirmed": [tr("Source access unconfirmed"), "question", "coverage"],
  "monitoring.changed": [tr("Monitoring settings changed"), "settings", "coverage"],
  "account.authorized": [tr("Account connected"), "account", "system"],
  "account.signed_out": [tr("Signed out of Telegram"), "account", "system"], "target.changed": [tr("Source selection changed"), "sources", "system"],
  "capture.changed": [tr("Attachment settings changed"), "settings", "coverage"], "clock.discontinuity": [tr("Clock change detected"), "clock", "coverage"],
  "connection.retry": [tr("Reconnecting to Telegram"), "refresh", "system"], "connection.retry_failed": [tr("Reconnect attempt failed"), "alert", "coverage"],
  "telegram.backoff": [tr("Telegram rate limit"), "clock", "coverage"], "export.failed": [tr("Export failed"), "alert", "coverage"],
  "network.changed": [tr("Connection route changed"), "link", "system"], "network.probe": [tr("Connection test"), "link", "system"],
  "network.route_assigned": [tr("Proxy assigned"), "link", "system"], "network.route_rotated": [tr("Proxy replaced"), "refresh", "coverage"],
  "network.route_unavailable": [tr("No working proxy"), "alert", "coverage"],
  "network.route_fallback": [tr("Connected directly without a proxy"), "alert", "coverage"],
  "network.policy_changed": [tr("IP protection changed"), "shield", "system"],
  "profile.created": [tr("Workspace created"), "plus", "system"], "profile.unavailable": [tr("Workspace unavailable"), "alert", "coverage"],
  "snapshot.started": [tr("History snapshot started"), "layers", "system"], "snapshot.completed": [tr("History snapshot completed"), "layers", "system"],
  "snapshot.interrupted": [tr("History snapshot interrupted"), "alert", "coverage"],
  "scope.changed": [tr("Observation scope changed"), "settings", "coverage"],
  "scope.applied": [tr("Sources updated by the scope"), "sources", "system"],
  "source.discovered": [tr("New chat under observation"), "plus", "system"],
  "target.removed": [tr("Source removed"), "trash", "system"], "target.priority": [tr("Source priority changed"), "star", "system"],
  "recheck.changed": [tr("Recheck settings changed"), "settings", "system"],
  "dossier.changed": [tr("People profiles switched"), "users", "system"],
  "parameters.changed": [tr("Parameters changed"), "settings", "system"],
  "source.profile": [tr("Chat profile saved"), "account", "system"],
  "witness.token_created": [tr("Witness token created"), "eye", "system"], "witness.token_revoked": [tr("Witness token revoked"), "eye", "system"],
  "witness.seen": [tr("Witness began checking"), "eye", "system"],
  "access.granted": [tr("Access issued"), "lock", "system"], "access.changed": [tr("Access changed"), "lock", "system"],
  "access.revoked": [tr("Access revoked"), "lock", "system"], "access.session_started": [tr("Signed in to the panel"), "account", "system"],
  "access.session_ended": [tr("Panel session ended"), "account", "system"],
  "access.admin_changed": [tr("Administrator session limits changed"), "settings", "system"],
};
function node(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; }
function placeChildren(parent,children){
  const keep=new Set(children);for(const child of [...parent.childNodes])if(!keep.has(child))child.remove();
  children.forEach((child,index)=>{if(parent.childNodes[index]!==child)parent.insertBefore(child,parent.childNodes[index]||null);});
}
function syncOptions(select,choices,fallback=""){
  const selected=select.value,existing=new Map([...select.options].map(option=>[option.value,option]));
  placeChildren(select,choices.map(([value,label])=>{const option=existing.get(value)||new Option(label,value);
    if(option.textContent!==label)option.textContent=label;return option;}));
  select.value=choices.some(([value])=>value===selected)?selected:fallback;
}
function viewState(kind,title,text="",label="",action=null){
  const box=node("div","ui-state");box.dataset.state=kind;
  box.setAttribute("role",kind==="error"?"alert":"status");
  box.append(icon(kind==="loading"?"refresh":kind==="error"?"help":"journal"),node("h3","",title));
  if(text)box.append(node("p","",text));
  if(action){const b=node("button","secondary",label);b.type="button";b.addEventListener("click",()=>busy(b,()=>action(b)));box.append(b);}
  return box;
}
function unitField(input,unit){
  const box=node("div","field-unit");box.append(input,node("span","unit",unit));return box;
}
function clearFieldError(input){
  if(!input?.id)return;
  const id=input.id+"-field-error";$(id)?.remove();
  input.removeAttribute("aria-invalid");
  const ids=(input.getAttribute("aria-describedby")||"").split(/\s+/).filter(x=>x&&x!==id);
  if(ids.length)input.setAttribute("aria-describedby",ids.join(" "));else input.removeAttribute("aria-describedby");
}
function showFieldError(input,message){
  if(!input?.id)return;
  for(let parent=input.parentElement;parent;parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;
  clearFieldError(input);
  const error=node("span","field-error",message);error.id=input.id+"-field-error";
  input.setAttribute("aria-invalid","true");input.setAttribute("aria-describedby",[input.getAttribute("aria-describedby"),error.id].filter(Boolean).join(" "));
  (input.closest(".field-unit")||input).after(error);
}
document.addEventListener("invalid",event=>{
  const input=event.target;if(!input.id||!input.validationMessage)return;
  showFieldError(input,input.validationMessage);
},true);
document.addEventListener("input",event=>{if(event.target.hasAttribute("aria-invalid"))clearFieldError(event.target);});
for(const [id,unit] of [["max-media",tr("MiB")],["recheck-priority",tr("min")],["recheck-other",tr("min")]]){
  const input=$(id);if(input){const placeholder=node("span");input.replaceWith(placeholder);placeholder.replaceWith(unitField(input,unit));}
}
const patternButton=$("chat-pattern");
function chatPattern(value){$("chat-feed").dataset.pattern=value;patternButton.setAttribute("aria-pressed",String(value==="dots"));}
try{chatPattern(localStorage.getItem("tgwitness-chat-pattern")==="dots"?"dots":"plain");}catch{chatPattern("plain");}
patternButton.addEventListener("click",()=>{
  const value=patternButton.getAttribute("aria-pressed")==="true"?"plain":"dots";chatPattern(value);
  try{localStorage.setItem("tgwitness-chat-pattern",value);}catch{}
});
const tooltip=node("div","ui-tooltip");tooltip.id="ui-tooltip";tooltip.role="tooltip";tooltip.hidden=true;document.body.append(tooltip);
let tooltipTarget=null;
function hideTooltip(){
  if(tooltipTarget){const ids=(tooltipTarget.getAttribute("aria-describedby")||"").split(/\s+/).filter(id=>id&&id!==tooltip.id);if(ids.length)tooltipTarget.setAttribute("aria-describedby",ids.join(" "));else tooltipTarget.removeAttribute("aria-describedby");}
  tooltip.hidden=true;tooltipTarget=null;
}
function showTooltip(event){
  const target=event.target.closest?.("button[title],summary[title]");if(!target?.title||target.disabled)return;
  hideTooltip();tooltipTarget=target;tooltip.textContent=target.title;tooltip.hidden=false;
  if(!target.textContent.trim()&&!target.getAttribute("aria-label"))target.setAttribute("aria-label",target.title);
  target.setAttribute("aria-describedby",[target.getAttribute("aria-describedby"),tooltip.id].filter(Boolean).join(" "));
  const rect=target.getBoundingClientRect();tooltip.style.left=Math.max(8,Math.min(rect.left,innerWidth-tooltip.offsetWidth-8))+"px";
  tooltip.style.top=(rect.bottom+tooltip.offsetHeight+8<innerHeight?rect.bottom+6:Math.max(8,rect.top-tooltip.offsetHeight-6))+"px";
}
document.addEventListener("pointerover",showTooltip);document.addEventListener("focusin",showTooltip);
document.addEventListener("pointerout",event=>{if(tooltipTarget&&!tooltipTarget.contains(event.relatedTarget))hideTooltip();});
document.addEventListener("focusout",hideTooltip);document.addEventListener("keydown",event=>{if(event.key==="Escape")hideTooltip();});
document.addEventListener("scroll",hideTooltip,true);
function icon(name) {
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg"),use=document.createElementNS(svg.namespaceURI,"use");
  svg.setAttribute("class","icon");svg.setAttribute("aria-hidden","true");use.setAttribute("href","#i-"+name);svg.append(use);return svg;
}
function show(id, visible) { const n = $(id); clearTimeout(n.leaveTimer); n.classList.remove("leaving"); n.hidden = !visible; }

function leave(id) {
  const n = $(id); if (n.hidden || n.classList.contains("leaving")) return;
  if (window.tgwReducedMotion?.() ?? matchMedia("(prefers-reduced-motion: reduce)").matches) { n.hidden = true; return; }
  n.classList.add("leaving"); n.leaveTimer = setTimeout(() => { n.classList.remove("leaving"); n.hidden = true; }, 180);
}

function replay(n, name, ms) { n.classList.remove(name); void n.offsetWidth; n.classList.add(name); clearTimeout(n.replayTimer); n.replayTimer = setTimeout(() => n.classList.remove(name), ms); }

const termLabels={offline:tr("offline"),ready:tr("ready"),credentials:tr("credentials"),session:tr("session"),
  login_required:tr("login required"),authorization_required:tr("authorization required"),password_required:tr("password required"),qr_required:tr("QR required"),
  observing:tr("observing"),paused:tr("paused"),reconnecting:tr("reconnecting"),collector_error:tr("collector error"),
  storage_error:tr("storage error"),supergroup:tr("supergroup"),channel:tr("channel"),group:tr("group"),
  private:tr("private chat"),bot:tr("bot"),discovered:tr("added automatically"),
  visible_in_dialogs:tr("visible in dialogs"),access_unconfirmed:tr("access unconfirmed"),public_username:tr("public username"),
  private_or_unlisted:tr("private or unlisted"),creator:tr("creator"),administrator:tr("administrator"),
  member_or_unknown:tr("member or unknown"),unknown:tr("unknown"),messages:tr("messages"),edits:tr("edits"),
  deletions:tr("deletions"),reactions:tr("reactions"),membership:tr("membership")};
const termText=value=>termLabels[value]??String(value??"").replaceAll("_"," ");
let panelTime;
const timeReady=import("./core/time.js?v=1").then(({createTimeFormatter})=>{
  let zone="UTC";try{zone=localStorage.getItem("tgwitness-time-zone")||"UTC";}catch{}
  panelTime=createTimeFormatter({locale:LANG,translate:tr,zone});
  const label=node("label","language-pick time-zone-pick"),select=node("select");
  select.id="time-zone";select.setAttribute("aria-label",tr("Display time"));
  select.append(new Option(tr("UTC"),"UTC"),new Option(tr("Local time"),"local"));select.value=panelTime.zone;
  label.append(node("span","",tr("Time")),select);document.querySelector(".sidebar .preferences").prepend(label);
  select.addEventListener("change",()=>{
    panelTime.setZone(select.value);try{localStorage.setItem("tgwitness-time-zone",panelTime.zone);}catch{}
    if(state.view==="chats"&&state.chat!==null){const feed=$("chat-feed"),top=feed.scrollTop;renderChatFeed();feed.scrollTop=top;}
    updateTimes();window.dispatchEvent(new CustomEvent("tgwitness:time-zone",{detail:{zone:panelTime.zone}}));
  });
});
const shellReady=import("./components/shell.js?v=3").then(({createResponsiveShell})=>createResponsiveShell({node,icon,tr}));
let connectionNotice=null;
const connectionReady=import('./components/connection-notice.js').then(({createConnectionNotice})=>{
  connectionNotice=createConnectionNotice({host:document.querySelector('.topbar').parentElement,tr,retry:()=>refreshStatus(),
    active:()=>!!state.me&&!$("workspace").hidden});
  const notice=$("panel-connection-notice");document.querySelector('.topbar').after(notice);
});
let formControls=null;
const formsReady=import('./components/forms.js').then(({createFormControls})=>{
  formControls=createFormControls({roots:[...panelRoots.values()],tr,getSession:()=>state.workspaceRevision+':'+state.profile,toast,
    forms:[['report-form',value=>reportDirty=value],['evidence-form',value=>state.evidenceDirty=value],
      ['replica-form',value=>state.replicaDirty=value],['alerts-form',value=>state.alertsDirty=value],
      ['github-form',value=>state.githubDirty=value]].map(([id,setDirty])=>({form:$(id),setDirty}))});
});
function fmtTime(value,options){return panelTime?.fmtTime(value,options)??tr("Not supplied");}
function formatTime(value){return fmtTime(value);}
function timeNode(value,cls="",mode="relative"){
  const result=node("time",cls,fmtTime(value,{mode}));
  if(value!==null&&value!==undefined&&value!==""){
    result.dataset.timestamp=String(value);result.dataset.timeMode=mode;result.title=fmtTime(value);
    const instant=new Date(value);if(Number.isFinite(instant.getTime()))result.dateTime=instant.toISOString();
  }
  return result;
}
function updateTimes(){
  for(const item of document.querySelectorAll("[data-timestamp]")){
    const value=item.dateTime||item.dataset.timestamp;
    item.textContent=fmtTime(value,{mode:item.dataset.timeMode||"absolute"});item.title=fmtTime(value);
  }
}
setInterval(()=>{if(!document.hidden)updateTimes();},30000);
function sourceTitle(id) { return state.status?.targets.find(x => x.chat_id === id)?.title || (id === null ? tr("Collector / account") : String(id)); }
let toastTimer;
let networkLoadedFor=null;
let qrPending=null,importExpectedId=null,accountImportRevision=0,authMethod="phone";
let accessStarted=false;
class StaleView extends Error {constructor(){super("");this.name="StaleView";}}
function toast(message, error=false) { if(!message)return;const n = $("toast"); n.textContent = message; n.classList.toggle("error", error); show("toast", true); clearTimeout(toastTimer); toastTimer = setTimeout(() => leave("toast"), error ? 9000 : 5000); }
async function api(path, body, options={}) {
  const revision=state.workspaceRevision;
  const {root=false,profile=state.profile,token=state.token,allowStale=false,...fetchOptions}=options;
  const prefix=root||profile==="default" ? "/api/" : "/profiles/"+encodeURIComponent(profile)+"/api/";
  const deadline=path==='status'?AbortSignal.timeout(15000):null;
  const requestSignal=deadline?(fetchOptions.signal?AbortSignal.any([deadline,fetchOptions.signal]):deadline):fetchOptions.signal;
  let response;try{response = await fetch(prefix + path, {method: body === undefined ? "GET" : "POST",
    headers: {Authorization: "Bearer " + token, ...(body !== undefined ? {"Content-Type":"application/json"} : {})},
    ...(body !== undefined ? {body: JSON.stringify(body)} : {}), ...fetchOptions,...(requestSignal?{signal:requestSignal}:{})});
  }catch(error){if(fetchOptions.signal?.aborted)throw new StaleView();
    if(revision===state.workspaceRevision&&token===state.token)connectionNotice?.fail();
    if(deadline?.aborted)throw new Error(tr("Panel status timed out. Try again."));throw error;}
  if(fetchOptions.signal?.aborted){await response.body?.cancel();throw new StaleView();}
  if(!allowStale&&revision!==state.workspaceRevision){await response.body?.cancel();throw new StaleView();}
  if(revision===state.workspaceRevision&&token===state.token){
    if(response.ok&&path==='status')connectionNotice?.clear();else if(response.status>=500)connectionNotice?.fail();
  }
  if (!response.ok) {
    const result = await response.json().catch(() => ({detail: tr("Request failed")}));
    let detail = result.detail || tr("Request failed");const parameter=detail?.parameter;
    if (Array.isArray(detail)) detail = detail.map(x => x.field + ": " + x.message).join("; ");
    if (typeof detail === "object") detail = tr(detail.message) + (detail.retry_after ? " " + tr("Retry after {n} seconds.", {n: detail.retry_after}) : "");
    if(!allowStale&&revision!==state.workspaceRevision)throw new StaleView();
    if (response.status === 401 && revision===state.workspaceRevision && token===state.token && !$("workspace").hidden) lock();
    if(fetchOptions.signal?.aborted)throw new StaleView();
    const error=new Error(tr(detail));error.status=response.status;if(parameter)error.parameter=parameter;throw error;
  }
  return response;
}
async function json(path, body, options) {
  const revision=state.workspaceRevision;let result;
  try{result=await (await api(path, body, options)).json();}
  catch(error){if(options?.signal?.aborted)throw new StaleView();throw error;}
  if(options?.signal?.aborted)throw new StaleView();
  if(!options?.allowStale&&revision!==state.workspaceRevision)throw new StaleView();
  return result;
}
async function busy(button, work) {
  if (button?.disabled) return;
  clearTimeout(toastTimer);show("toast",false);
  if (button) {button.disabled = true;button.setAttribute("aria-busy","true");}
  const form=button?.closest("form");form?.querySelector(".form-error")?.remove();
  try { return await work(); } catch (e) {
    if(e instanceof StaleView)return;
    toast(e.message, true);
    if(form){const message=node("p","form-error",e.message);message.setAttribute("role","alert");form.append(message);}
    if(e.field&&form?.contains($(e.field))){showFieldError($(e.field),e.message);$(e.field).focus();}
  }
  finally { if (button) {button.disabled=false;button.removeAttribute("aria-busy");
    if(button.id==="chat-send"||button.id==="chat-preview-button")renderComposer();} }
}
function lock() {
  state.workflow=null;state.exportTask='journal';
  window.TgWitnessRouter?.invalidate();
  viewHost?.resetSession();formControls?.reset();connectionNotice?.clear();state.permissionsStamp=null;
  state.events=[];state.chats=[];state.chatsLoading=false;state.chatsError=false;state.chatMessages=[];state.chatInfo=null;state.chat=null;state.parameters=null;
  sourcesView?.resetSession();
  parametersView?.resetSession();
  resetChatExportTools();
  resetReportSettings();
  window.dispatchEvent(new Event("tgwitness:lock"));
  $("quick-dialog").close();
  $("workspace").inert=false;
  resetInteractions();
  cancelQR();
  state.workspaceRevision++;state.monitoringDirty=false;state.captureDirty=false;state.parametersDirty=false;clearVerification();

  if(state.token.startsWith("tgws_"))fetch("/api/access/logout",{method:"POST",headers:{Authorization:"Bearer "+state.token}}).catch(()=>{});
  state.me=null;state.access=null;state.accessEdit=null;state.accessChats={};state.consoleAfter=0;$("access-console").textContent="";
  $("access-token").textContent="";show("access-new",false);
  state.token=""; sessionStorage.removeItem("tgwitness-token"); closeDetail({history:false});
  $("export-dialog").close("cancel");stopExportPoll();clearTimeout(multiPoll);multiPoll=null;state.multiChecked=false;
  clearSecrets();resetWitnessSetup();selectExtra(null);
  $("panel-token").value=""; show("workspace",false); show("gate",true);
}
async function unlock() {
  accessStarted=true;
  await Promise.all([timeReady,shellReady,viewReady,formsReady,connectionReady,chatListReady,accountStateReady,disclosurePreviewReady]);
  const router=await ensureRouter(),requested=router.parse();
  state.me = await json("access/me",undefined,{root:true});
  await loadProfiles();
  if(state.profiles.some(profile=>profile.id===requested.workspace&&!profile.error_type))state.profile=requested.workspace;
  if(!state.profiles.some(p=>p.id===state.profile && !p.error_type))
    state.profile=state.profiles.find(p=>!p.error_type)?.id||"default";
  state.status = await json("status");
  applyAccess();
  if(!state.opened&&!requested.explicit){
    state.view=state.status.demo?"chats":viewAllowed('start')?'start':'chats';
  }
  if(!viewAllowed(state.view))state.view="chats";
  state.opened=true;
  sessionStorage.setItem("tgwitness-token", state.token);
  show("gate",false); show("workspace",true); $("panel-token").value="";
  navigate(state.view,{history:false});

  renderStatus(); setAuthStep(accountSignedIn() ? "authorized" : "credentials");
  loadNotifications().catch(()=>{});
  await router.start();
}
$("unlock-form").addEventListener("submit", async event => {
  event.preventDefault(); $("login-error").textContent="";
  const button = event.submitter; button.disabled=true;
  try {

    const entered=$("panel-token").value.trim();
    state.token=(await json("access/login",{token:entered},{root:true,token:""})).session;
    await unlock();
  } catch (e) { state.token="";$("login-error").textContent=e.message; } finally { button.disabled=false; }
});
function may(permission){return !!state.me&&(state.me.admin||state.me.permissions.includes(permission));}

function viewAllowed(view){
  const limited=!!state.status?.chats_limited;
  return {start:!!state.me&&!limited,sources:may("sources")&&!limited,evidence:may("export")&&!limited,sealed:may("export")&&!limited,witness:may("settings")&&!limited,
    parameters:may("settings")&&!limited,connection:may("account")&&!limited,accounts:!!state.me?.admin,
    access:!!state.me?.admin,"system-log":!!state.me?.admin,integrations:!!state.me?.admin,
    analysis:!!(state.status?.analysis?.enabled||state.status?.analysis?.media_available)}[view]??true;
}
function applyAccess(){
  const stamp=JSON.stringify([state.workspaceRevision,state.me,state.status?.chats_limited,state.status?.demo,state.status?.analysis]);
  if(stamp===state.permissionsStamp)return;state.permissionsStamp=stamp;
  window.TgWitnessAnalysis?.syncStatus?.(state.status);
  const analysisTitle=tr(state.status?.analysis?.enabled?"Ask the archive":"Machine recognition");
  const analysisNav=document.querySelector('.sidebar [data-view="analysis"]');
  const analysisText=[...analysisNav.childNodes].find(n=>n.nodeType===Node.TEXT_NODE&&n.textContent.trim());
  if(analysisText)analysisText.textContent=" "+analysisTitle;
  $("view-analysis").querySelector("h1").textContent=analysisTitle;
  document.querySelectorAll(".sidebar .nav[data-view]").forEach(n=>n.hidden=!viewAllowed(n.dataset.view));
  $('nav-more').hidden=![...$('nav-more').querySelectorAll('[data-view]')].some(button=>!button.hidden);
  document.querySelectorAll(".nav-section").forEach(heading=>{
    let next=heading.nextElementSibling,visible=false;
    while(next&&!next.classList.contains("nav-section")){visible=visible||!next.hidden;next=next.nextElementSibling;}
    heading.hidden=!visible;
  });
  panelQueries("[data-open]").forEach(n=>n.hidden=!viewAllowed(n.dataset.open));
  $("collector-toggle").hidden=!may("collect")||!!state.status?.chats_limited;
  $("manage-profiles").hidden=!state.me?.admin;
  if(state.view==="analysis"&&!viewAllowed("analysis")&&!$("workspace").hidden)navigate("chats");
  panelQueries("[data-export]").forEach(n=>n.hidden=!viewAllowed("evidence"));
  show("account-export-card",!!state.me?.admin&&viewAllowed("evidence"));
  renderWorkflowControls();

  const limited=!!state.status?.chats_limited;
  $("chats-manage").hidden=!viewAllowed("sources");
  viewQuery("chats",".chat-open").hidden=!may("interact")||limited;
  $("chat-load-history").hidden=$("chat-history-limit").hidden=!may("sources");
  $("chat-export-start").hidden=!may("export");
  $("chat-compose").hidden=!may("interact");
  $("workspace").dataset.access=state.me?.admin?"admin":"issued";
}
$("lock-panel").addEventListener("click",lock);
$("top-lock").addEventListener("click",lock);
$("entry-lock").addEventListener("click",lock);
$("entry-return").addEventListener("click",()=>navigate("observations"));
function connectionSettings(open){
  state.connectionSettings=open;$("workspace").dataset.connectionSettings=String(open);
  $("entry-settings").setAttribute("aria-expanded",String(open));
  show("connection-options",open);$("connection-options").open=open;
  if(open)window.TgWitnessProxies?.load();
  else window.TgWitnessProxies?.stop?.();
  $("api-details").open=open;
}
$("entry-settings").addEventListener("click",()=>connectionSettings(!state.connectionSettings));
$("route-open").addEventListener("click",()=>{
  connectionSettings(true);$("network-details").open=true;$("connection-options").scrollIntoView({block:"start"});
});
$("open-demo").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  state.token=state.demoToken;state.profile="default";await unlock();
}));
function syncLive(){
  if(!state.token||!state.status||state.status.demo||window.TGW_ONLINE_DEMO||!["observations","chats"].includes(state.view)){
    window.TgWitnessLive?.stop();return;
  }
  window.TgWitnessLive?.start({key:state.workspaceRevision+":"+state.profile,head:state.status.stats.head?.seq,api,tr,accessEnded:lock,
    hosts:[viewQuery(state.view,state.view==='chats'?'.chat-toolbar':'.journal .card-heading')].filter(Boolean),
    canRefresh:()=>{
      if(state.drawerSeq!==null||window.getSelection()?.toString()||document.hidden)return false;
      if(state.view==="chats"){const feed=$("chat-feed");return state.chatNextAfter===null&&feed.scrollHeight-feed.scrollTop-feed.clientHeight<80;}
      return state.eventBefore===null&&state.events.length<=200&&window.scrollY<120&&window.TgWitnessJournal?.canRefresh()!==false;
    },
    refresh:async({force=false}={})=>{await refreshStatus();if(state.view==="chats"){
      const result=force&&state.chatView==='messages'?await loadChatMessages('latest'):await refreshChats(true);
      if(result===false)throw new Error('Chat refresh failed');
    }else if(state.view==="observations")await refreshEvents();}
  });
}
function navigate(view,options={}) {
  if(!viewAllowed(view))view="chats";
  if(view!==state.view)window.TgWitnessJournal?.leave();
  if(view!==state.view&&state.drawerSeq!==null)closeDetail({history:false});
  if(view!=="connection")window.TgWitnessProxies?.stop?.();
  state.view=view;
  if(view==='start')state.workflow=null;
  const advanced=document.querySelector('#nav-more [data-view="'+CSS.escape(view)+'"]');
  if(advanced)$('nav-more').open=true;
  $("workspace").dataset.currentView=view;
  const entered=viewHost.activate(view,{params:{load:options.load,restore:options.restore}}).catch(error=>{
    if(!(error instanceof StaleView)&&error.name!=='AbortError')toast(error.message,true);
  });
  syncLive();
  document.querySelectorAll("[data-view]").forEach(n=>{
    const selected=n.dataset.view===(view==="sealed"?"evidence":view);
    n.classList.toggle("active",selected);
    if(selected)n.setAttribute("aria-current","page");else n.removeAttribute("aria-current");
  });
  $("view-label").textContent=tr({start:"Start here",chats:"Chats",observations:"Journal",sources:"Sources",evidence:"Exports",sealed:"Exports",witness:"Extras",parameters:"Parameters",connection:"Account",accounts:"Accounts",access:"Access","system-log":"System log",integrations:"Integrations",analysis:state.status?.analysis?.enabled?"Ask the archive":"Machine recognition"}[view]);
  show("entry-header",view==="connection");
  if(view==="connection")connectionSettings(false);
  if(state.status){renderSetup();renderWorkflowControls();}
  if(options.history!==false)window.TgWitnessRouter?.record();
  return entered;
}
$("manage-profiles").addEventListener("click",()=>{
  navigate("connection");connectionSettings(true);$("profiles-details").open=true;$("profiles-details").scrollIntoView({block:"start"});
});
document.querySelectorAll("[data-view],[data-open]").forEach(button=>button.addEventListener("click",()=>{
  const view=button.dataset.view || button.dataset.open;
  if(view==="witness")selectExtra(null);
  navigate(view);
}));

function accountSignedIn(){
  const info=accountState?.(state.status);
  return !!info?.hasSession&&!info.needsSignIn;
}
function selectExportTask(task){
  state.exportTask=task==='account'&&state.me?.admin&&viewAllowed('evidence')?'account':'journal';
  if(state.view!=='evidence')return;
  show('export-account-panel',state.exportTask==='account');
  show('export-journal-panel',state.exportTask==='journal');
  show('verify-journal',state.exportTask==='journal');
  show('verification-result',state.exportTask==='journal');
  show('verification-details',state.exportTask==='journal');
  viewQueries('evidence','.export-task-choices [data-export-task]').forEach(button=>
    button.setAttribute('aria-pressed',String(button.dataset.exportTask===state.exportTask)));
  renderExportJobLink();
}
function renderExportJobLink(){
  if(state.view!=='evidence')return;
  const jobs=state.accountExportJobs||[],canUse=!!state.me?.admin&&viewAllowed('evidence');
  show('exports-job-link',canUse&&state.exportTask!=='account'&&jobs.length>0);
  const active=jobs.filter(job=>['preparing','running','waiting','packaging'].includes(job.phase)&&job.active!==false).length;
  const attention=jobs.filter(job=>['failed','partial','paused'].includes(job.phase)).length;
  $('exports-job-summary').textContent=tr('Account exports: {total} · in progress: {active} · ready: {ready} · review: {attention}',
    {total:jobs.length,active,ready:jobs.filter(job=>job.ready).length,attention});
}
function renderWorkflowControls(){
  if(!state.status||!accountState)return;
  const info=accountState(state.status),canExport=!!state.me?.admin&&viewAllowed('evidence');
  if(state.view==='start'){
  show('workflow-account-card',canExport);
  show('workflow-investigation-card',viewAllowed('sources')&&viewAllowed('connection')&&may('collect'));
  $('workflow-status-title').textContent=state.status.demo?tr('Demo workspace'):tr(info.label);
  $('workflow-status-title').closest('.workflow-status').dataset.state=info.kind;
  $('workflow-status-copy').textContent=tr('{records} saved records · {sources} selected sources',
    {records:state.status.stats.total.toLocaleString(),sources:state.status.targets.filter(target=>target.enabled).length});
  const investigate=viewQuery('start','[data-workflow="investigation"]');
  investigate.textContent=tr(state.status.collector.running?'Open investigation':'Set up observation');
  }
  if(state.view==='connection'){
  const pending=state.workflow?.profile===state.profile&&state.workflow.kind==='account';
  show('workflow-handoff',pending);
  $('workflow-handoff-copy').textContent=tr(accountSignedIn()?
    'Your account is connected. Continue to choose what to export.':
    'Sign in to choose what to export. Continuous observation is not required.');
  show('workflow-continue',pending&&accountSignedIn());
  const sourceAction=viewQuery('connection','#authorized-state [data-open="sources"]');
  sourceAction.hidden=pending||!viewAllowed('sources');
  viewQuery('connection','#authorized-state .muted').textContent=tr(pending?
    'Continue to export your account, then choose chats, dates and files.':'Choose the groups and channels to observe.');
  }
  if(state.view==='evidence'){
  show('export-task-account',canExport);
  selectExportTask(state.exportTask);
  $('account-export-configure').textContent=tr(!state.status.demo&&!accountSignedIn()?
    info.needsSignIn?'Sign in again':'Connect account →':'Configure account export');
  }
}
async function openAccountWorkflow(){
  if(!state.me?.admin||!viewAllowed('evidence'))return;
  const workflow=state.workflow={profile:state.profile,kind:'account'},revision=state.workspaceRevision;
  const current=()=>state.workflow===workflow&&revision===state.workspaceRevision&&state.me?.admin&&viewAllowed('evidence');
  if(!state.status.demo&&!accountSignedIn()){
    await navigate('connection');if(current()&&state.view==='connection')setAuthStep('credentials');return;
  }
  selectExportTask('account');await navigate('evidence');
  if(current()&&state.view==='evidence'){exportsView?.select('downloads');$('account-export-configure').click();}
}
panelQueries('[data-workflow]').forEach(button=>button.addEventListener('click',()=>busy(button,async()=>{
  if(button.dataset.workflow==='account'){await openAccountWorkflow();return;}
  state.workflow=null;
  if(!viewAllowed('sources')||!viewAllowed('connection')||!may('collect'))return;
  await navigate(!accountSignedIn()&&!state.status.demo?'connection':hasSources(state.status)?'chats':'sources');
  if(state.view==='connection')setAuthStep('credentials');
})));
$('workflow-continue').addEventListener('click',e=>busy(e.currentTarget,openAccountWorkflow));
$('collector-sign-in').addEventListener('click',()=>{navigate('connection');setAuthStep('credentials');});
viewQueries('evidence','[data-export-task]').forEach(button=>button.addEventListener('click',()=>{
  selectExportTask(button.dataset.exportTask);exportsView?.select('downloads');
}));

const quickDialog=$("quick-dialog"),quickSearch=$("quick-search"),quickResults=$("quick-results");
const quickCatalogHint=node('p','hint');quickCatalogHint.hidden=true;quickCatalogHint.setAttribute('role','status');quickResults.after(quickCatalogHint);
let quickIndex=0,quickCatalog=[],quickCatalogKey='',quickCatalogPending=null;
const quickSession=()=>state.workspaceRevision+':'+state.profile;
function cancelQuickCatalog(){
  const pending=quickCatalogPending;quickCatalogPending=null;
  pending?.abort();quickCatalogHint.hidden=true;
}
async function loadQuickCatalog(){
  if(!quickDialog.open||!viewAllowed('parameters'))return;
  const session=quickSession();if(quickCatalogKey===session||quickCatalogPending)return;
  quickCatalog=[];quickCatalogHint.hidden=true;const controller=new AbortController();quickCatalogPending=controller;
  try{const parameters=await parametersReady,data=state.parameters||await json('parameters',undefined,{signal:controller.signal});
    if(controller.signal.aborted||session!==quickSession()||!quickDialog.open||!viewAllowed('parameters'))return;
    quickCatalog=parameters.searchEntries(data);quickCatalogKey=session;
    const selected=quickResults.children[quickIndex]?.id;renderQuick();
    const kept=[...quickResults.children].findIndex(option=>option.id===selected);if(kept>=0)selectQuick(kept);
  }catch(error){if(!controller.signal.aborted&&session===quickSession()&&quickDialog.open&&!(error instanceof StaleView)){
    quickCatalogHint.textContent=tr('Parameter search is unavailable. Open Parameters to retry.');quickCatalogHint.hidden=false;
  }}finally{if(quickCatalogPending===controller)quickCatalogPending=null;}
}
// Native close events are queued; an older one must not cancel a reopened palette.
quickDialog.addEventListener('close',()=>{if(!quickDialog.open)cancelQuickCatalog();});
window.addEventListener('tgwitness:lock',()=>{quickCatalog=[];quickCatalogKey='';cancelQuickCatalog();quickResults.replaceChildren();});
$("quick-shortcut").textContent=/Mac|iPhone|iPad/.test(navigator.platform)?"⌘ K":"Ctrl K";
function selectQuick(index){
  const options=[...quickResults.children];
  if(!options.length){quickSearch.removeAttribute("aria-activedescendant");return;}
  quickIndex=(index+options.length)%options.length;
  options.forEach((option,i)=>option.setAttribute("aria-selected",String(i===quickIndex)));
  quickSearch.setAttribute("aria-activedescendant",options[quickIndex].id);
  options[quickIndex].scrollIntoView({block:"nearest"});
}
function renderQuick(){
  quickResults.replaceChildren();
  const query=quickSearch.value.trim().toLocaleLowerCase();
  for(const nav of document.querySelectorAll(".sidebar .nav")){
    if(nav.hidden)continue;
    const title=[...nav.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join("").trim();
    const keywords=nav.dataset.view==="witness"?tr("bot Telegram proof GitHub witness"):
      nav.dataset.view==="connection"?tr("proxy MTProxy SOCKS5 HTTP connection route"):"";
    if(!(`${title} ${nav.dataset.view} ${keywords}`).toLocaleLowerCase().includes(query))continue;
    const option=node("div","quick-option");
    option.id="quick-option-"+nav.dataset.view;option.setAttribute("role","option");
    option.dataset.destination=nav.dataset.view;
    option.append(nav.querySelector("svg").cloneNode(true),node("span","quick-label",title));
    if(nav.dataset.view===state.view)option.append(node("small","",tr("Current section")));
    option.append(icon("chevron"));
    option.addEventListener("click",()=>openQuickDestination(nav.dataset.view));
    quickResults.append(option);
  }
  if(query){
    const option=(key,title,subtitle,action)=>{
      const item=node("div","quick-option");item.id="quick-option-"+key;item.setAttribute("role","option");item.dataset.action=key;
      item.append(node("span","quick-label",title),node("small","",subtitle),icon("chevron"));
      item.addEventListener("click",()=>{quickDialog.close();busy(null,action);});quickResults.append(item);
    };
    for(const profile of state.profiles.filter(p=>!p.error_type&&(p.label+" "+p.id).toLowerCase().includes(query)).slice(0,8))
      option("workspace-"+profile.id,profile.label,tr("Accounts"),()=>switchProfile(profile.id));
    for(const chat of (state.status?.targets||[]).filter(c=>(c.title+" "+c.chat_id).toLowerCase().includes(query)).slice(0,12))
      option("chat-"+chat.chat_id,chat.title,String(chat.chat_id),async()=>{navigate("chats");await refreshChats();await openChat(chat.chat_id);});
    const text=quickSearch.value.trim().slice(0,200);
    if(viewAllowed('parameters')&&quickCatalogKey===quickSession())for(const item of quickCatalog.filter(item=>item.search.includes(query)).slice(0,12))
      option('parameter-'+item.key,item.label,item.groupLabel+' · '+item.key,async()=>{
        const session=quickSession();await navigate('parameters',{history:false});
        if(session===quickSession()&&state.view==='parameters'&&viewAllowed('parameters')&&!(await parametersReady).focusParameter(item.key)){
          window.TgWitnessRouter?.record();toast(tr('Parameter is unavailable in this workspace.'),true);
        }
      });
    const record=/^#([1-9]\d*)$/.exec(text),seq=record?Number(record[1]):null;
    if(Number.isSafeInteger(seq))option('record-'+seq,tr('Open record #{seq}',{seq}),tr('Journal'),async()=>{
      const session=quickSession();await navigate('observations');if(session===quickSession()&&state.view==='observations')await openRecord(seq);
    });
    option("journal",tr("Search journal"),text,async()=>{state.search=text;state.cursor=state.eventBefore=state.eventAfter=null;$("event-search").value=text;navigate("observations");await refreshEvents();});

    if(/^(@[a-z0-9_]{3,}|(?:https?:\/\/)?t\.me\/\S+)$/i.test(text)&&may("interact"))
      option("telegram",tr("Open Telegram link"),text,()=>{navigate("chats");$("chat-link").value=text;viewQuery("chats",".chat-open").open=true;$("chat-link").focus();});
  }
  show("quick-empty",!quickResults.children.length);selectQuick(0);
}
function openQuickDestination(view){
  quickDialog.close();
  if($("workspace").hidden||$("workspace").inert)return;
  if(view==="witness")selectExtra(null);
  navigate(view);

  const heading=$("view-"+view).querySelector("h1,h2,input,button");
  if(heading){if(/^H[12]$/.test(heading.tagName))heading.tabIndex=-1;heading.focus({preventScroll:true});}
}
function toggleQuick(){
  if(quickDialog.open){quickDialog.close();return;}
  if($("workspace").hidden||$("workspace").inert||document.querySelector("dialog[open]")||!$("detail-drawer").hidden)return;
  // Retire the previous request before reopening, even if its close event is still queued.
  closeNotifications();cancelQuickCatalog();quickSearch.value="";
  quickDialog.showModal();renderQuick();quickSearch.focus();void loadQuickCatalog();
}
document.querySelectorAll("[data-quick-open]").forEach(button=>button.addEventListener("click",toggleQuick));
$("quick-close").addEventListener("click",()=>quickDialog.close());
quickDialog.addEventListener("keydown",event=>{
  if(event.key!=="Tab")return;
  const first=$("quick-close"),last=quickSearch;
  if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
});
quickSearch.addEventListener("input",renderQuick);
quickSearch.addEventListener("keydown",event=>{
  if(event.isComposing)return;
  if(event.key==="ArrowDown"||event.key==="ArrowUp"){
    event.preventDefault();selectQuick(quickIndex+(event.key==="ArrowDown"?1:-1));
  }else if(event.key==="Enter"){
    event.preventDefault();const option=quickResults.children[quickIndex];
    if(option)option.click();
  }
});
quickDialog.addEventListener("click",event=>{
  if(event.target!==quickDialog)return;
  const r=quickDialog.getBoundingClientRect();
  if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)quickDialog.close();
});
document.addEventListener("keydown",event=>{
  if(event.key.toLowerCase()==="k"&&(event.ctrlKey||event.metaKey)&&!event.altKey&&!event.shiftKey&&!event.isComposing
      &&!$("workspace").hidden&&!$("workspace").inert){event.preventDefault();if(!event.repeat)toggleQuick();}
});

// ---- Health: what each part does now, apart from whether it is switched on (health.py) ----
// [label, icon]: the state is always written and drawn, colour only adds to it.
const healthStates={off:[tr("Off"),"pause"],configured:[tr("Configured"),"settings"],running:[tr("In progress"),"refresh"],
  working:[tr("Working"),"check"],degraded:[tr("Degraded"),"alert"],failed:[tr("Error"),"x"],unknown:[tr("State unknown"),"question"]};
const healthKnown=value=>Object.hasOwn(healthStates,value)?value:"unknown";
const healthWorst=values=>["failed","degraded","unknown","running","configured","working","off"].find(v=>values.includes(v))||"unknown";
const needsLook=value=>["failed","degraded","unknown"].includes(value);
const when=value=>value?fmtFull(value):tr("none yet");
function stateBadge(value,cls="health-badge"){
  const key=healthKnown(value),badge=node("span",cls+" state-"+key);
  badge.append(icon(healthStates[key][1]),node("span","",healthStates[key][0]));return badge;
}
// Where a part's problem can be looked into; opening it changes no setting and contacts nobody.
const healthDiagnostics={connection:{view:"connection"},intake:{view:"observations",filter:"coverage"},
  sources:{view:"sources"},media:{view:"sources",target:"capture-form"},
  timestamps:{view:"witness",extra:"evidence",target:"evidence-status"},
  replica:{view:"witness",extra:"evidence",target:"replica-status"},server:{view:"witness",extra:"cloud",target:"cloud-health"}};
function openDiagnostics(name){
  const d=healthDiagnostics[name];if(!d||!viewAllowed(d.view))return;
  if(d.view==="witness")selectExtra(null);
  navigate(d.view);
  if(d.extra)$("extras-open-"+d.extra).click();
  if(d.filter)document.querySelector('[data-filter="'+d.filter+'"]')?.click();
  if(d.target==="capture-form"){
    sourcesReady.then(view=>{view.showTab("recording");$("capture-form").scrollIntoView({block:"start"});});
    return;
  }
  if(d.target)$(d.target).scrollIntoView({block:"start"});
}
function healthRow(name,title,item,lines){
  const row=node("div","health-row"),head=node("div","health-row-head");
  head.append(node("strong","",title),stateBadge(item.state));row.append(head);
  lines.filter(Boolean).forEach((line,i)=>row.append(node("p",i?"hint":"",line)));
  const d=healthDiagnostics[name];
  if(needsLook(item.state)&&d&&viewAllowed(d.view)&&d.view!==state.view){
    const button=node("button","text-link",tr("Diagnostics"));button.type="button";
    button.addEventListener("click",()=>openDiagnostics(name));row.append(button);
  }
  return row;
}
const healthPartNames={connection:tr("Telegram connection"),intake:tr("Event intake"),sources:tr("Sources"),media:tr("Attachment queue")};
function collectorLines(name,p){
  const c=p.counts||{};
  if(name==="connection"){
    if(p.reason==="connected")return [tr("Connected to Telegram.")];
    if(p.reason==="reconnecting")return [tr("Connection lost; reconnecting (attempt {n}).",{n:p.attempts}),
      p.next_reconnect_at&&tr("Next attempt: {time}",{time:fmtFull(p.next_reconnect_at)}),p.error&&tr("Last error: {error}",{error:p.error})];
    if(p.reason==="telegram_pause")return [tr("Telegram asked to pause requests until {time}.",{time:fmtFull(p.telegram_pause_until)})];
    if(p.reason==="signed_out")return [tr("Telegram signed this account out. Sign in again to resume observation.")];
    if(p.reason==="collector_error")return [tr("Observation stopped after an error: {error}",{error:p.error||"?"})];
    if(p.reason==="storage_error")return [tr("Observation stopped: the journal could not be written.")];
    if(p.reason==="resume_failed")return [tr("Observation did not resume after the restart: {error}",{error:p.error||"?"})];
    if(p.reason==="paused")return [tr("Observation is paused.")];
    return [tr("No Telegram account is connected.")];
  }
  if(name==="intake"){
    const facts=[tr("Collector heartbeat: {time}",{time:when(p.last_heartbeat)}),tr("Last event received: {time}",{time:when(p.last_event_at)})];
    if(p.reason==="live")return [tr("Events arrive. A quiet chat without new messages is not a fault."),...facts];
    if(p.reason==="no_heartbeat")return [tr("No collector heartbeat yet."),...facts];
    if(p.reason==="stale")return [tr("No collector heartbeat for longer than expected; the collector may not be responding."),...facts];
    if(p.reason==="disconnected")return [tr("No events can arrive while the connection is down."),...facts];
    return [tr("Observation is paused.")];
  }
  if(name==="sources"){
    const counts=c.checked?tr("Visible: {visible} · added automatically: {added} · not found: {unconfirmed}",c):"";
    if(p.reason==="visible")return [tr("All checked sources are visible in the account's dialogs."),counts];
    if(p.reason==="some_unconfirmed")return [tr("Some sources were not found among the account's chats; the others continue."),counts];
    if(p.reason==="none_visible")return [tr("None of the sources was found among the account's chats."),counts];
    if(p.reason==="not_checked")return [tr("Sources are checked when observation starts.")];
    return [tr("No source is selected.")];
  }
  const facts=[tr("Waiting: {pending} · retrying: {retry} · not saved: {failed}",c),
    p.oldest_pending_at&&tr("Oldest pending attachment")+": "+fmtFull(p.oldest_pending_at),
    p.disk_free_bytes!=null&&tr("Free disk")+": "+humanSize(p.disk_free_bytes)];
  if(p.reason==="ok")return [tr("Attachments are being saved."),...facts];
  if(p.reason==="disk_low")return [tr("Disk almost full: downloads are paused until space is free."),...facts];
  if(p.reason==="paused")return [tr("Downloads continue when observation resumes."),...facts];
  if(p.reason==="failed_items")return [tr("Some attachments could not be saved; their messages are recorded."),...facts];
  if(p.reason==="queue_waiting")return [tr("Attachments have been waiting for more than an hour."),...facts];
  return [tr("Attachment downloads are off."),...facts];
}
let healthUI=null;
const healthReady=import("./components/health.js?v=1").then(({createHealthBar})=>{
  healthUI=createHealthBar({node,icon,tr,stateNames:healthStates,partNames:healthPartNames,lines:collectorLines,
    actionContext:{getState:()=>state,getSession:()=>state.workspaceRevision+':'+state.profile,may,json,refreshStatus,toast,getSources:()=>sourcesReady,navigate},
    diagnose:openDiagnostics,canDiagnose:name=>viewAllowed(healthDiagnostics[name]?.view),workspace:$("workspace")});
  if(state.status)renderCollectorHealth(state.status.health);
  return healthUI;
});
healthReady.catch(error=>toast(error.message,true));
function renderCollectorHealth(h){
  healthUI?.update(h,{profile:state.profile,demo:state.status?.demo});
  if(!h)return;
  const names=["connection","intake","sources","media"],states=state.profile+":"+names.map(name=>h[name]?.state).join(",");
  if(state.healthStates&&state.healthStates!==states&&state.healthStates.split(":")[0]===state.profile)
    $("health-announce").textContent=names.map(name=>healthPartNames[name]+" — "+healthStates[healthKnown(h[name]?.state)][0]).join(" · ");
  state.healthStates=states;
}

let collectionUI=null;
const collectionReady=import("./components/collection.js?v=2").then(({createCollectionControl})=>{
  collectionUI=createCollectionControl({node,tr,status:()=>state.status,workspace:$("workspace")});collectionUI.update();return collectionUI;
});
collectionReady.catch(error=>toast(error.message,true));
function renderStatus() {
  const s=state.status,c=s.collector;
  $("workspace").dataset.demo=String(!!s.demo);
  $("workspace").dataset.onlineDemo=String(!!window.TGW_ONLINE_DEMO);
  show("demo-banner",s.demo);
  $("app-version").textContent=s.version?"TgWitness "+s.version:"";
  $("status-chip").textContent=tr(s.demo ? "Demo workspace" : accountState(s).needsSignIn?'Sign in again':c.running ? (c.connected?"Observing":"Reconnecting") :
    c.has_session ? "Observation off" : ({code_required:"Waiting for code",password_required:"Waiting for 2FA",qr_pending:"Waiting for QR"}[c.phase]||"Account not connected"));
  $("status-chip").classList.toggle("live",!s.demo && c.running && c.connected);
  $("status-chip").classList.toggle("warn",!s.demo && (!c.running || !c.connected));
  $("collector-toggle").textContent=tr(c.running ? "Pause observation" : "Start observation");
  $("collector-toggle").disabled=s.demo||(!c.running&&!accountState(s).canStart);
  $("collector-toggle").title=tr(s.demo?"Demo uses fictional observations":accountState(s).needsSignIn?'Sign in again':!c.has_session?"Connect an account first":
    !hasSources(s)?"Select at least one source first":"");
  $("nav-count").textContent=s.stats.total.toLocaleString();
  renderCollectorHealth(s.health);collectionUI?.update();
  const signIn=accountState(s).needsSignIn;
  show("collector-error",!!c.last_error||signIn);
  show('collector-sign-in',signIn&&viewAllowed('connection'));
  $("collector-error-copy").textContent=signIn?
    tr('Telegram no longer accepts this session. Sign in to the same account; saved records and sources stay in this workspace.'):
    c.last_error ? tr("Collector reported {error}. Review coverage events before relying on completeness.",{error:c.last_error}) : "";
  renderSetup();
  renderWorkflowControls();
  viewHost?.updateStatus(s);
}
function renderViewStatus(view){
  const s=state.status;if(!s||viewHost?.active!==view)return;
  const c=s.collector,counts=s.stats.counts;
  if(view==='start')renderWorkflowControls();
  else if(view==='observations'){
    $("stat-messages").textContent=((counts["message.new"]||0)+(counts["message.snapshot"]||0)).toLocaleString();
    $("stat-edits").textContent=(counts["message.edited"]||0).toLocaleString();
    $("stat-deletes").textContent=(counts["message.deleted"]||0).toLocaleString();
    $("stat-sources").textContent=s.targets.filter(x=>x.enabled).length;
    $("sources-footnote").textContent=tr(s.demo ? "Synthetic sources" : c.running ? "Observation enabled" : "Observation paused");
    $("event-total").textContent=s.stats.total.toLocaleString();
    fillSourceSelect("source-filter",state.source,true);
    window.TgWitnessJournal?.sync();
  }else if(view==='chats'){
    renderComposer();renderChatStatus();renderMulti();renderChatsList();
  }else if(view==='evidence'){
    $("fingerprint").textContent=s.fingerprint;$("export-profile-id").textContent=state.profile;
    renderVerification();renderChatExportTools();
  }else if(view==='parameters'){
    parametersView?.updateStatus();
  }else if(view==='sources'){
    sourcesView?.updateStatus(s);renderHistory();renderRecheck();renderTargets();
  }else if(view==='connection'){
  show("entry-settings",!s.demo);
  show("entry-demo",s.demo);show("entry-return",s.demo||c.has_session);
  $("entry-return").textContent=tr(s.demo?"View sample messages →":"Back to journal");
  const account=c.account;
  show("account-summary",!!account);
  const identity=account ? (account.username ? "@"+account.username+" · " : "") + "ID "+account.id : "";
  $("account-summary").textContent=account ? tr(accountState(s).needsSignIn?'Sign in again for account: {who}':"Connected account: {who}",{who:identity}) : "";
  show("authorized-account",!!account);$("authorized-account").textContent=identity;
  const avatarKey=account?state.profile+":"+account.id:"";
  if(state.accountAvatar!==avatarKey){
    state.accountAvatar=avatarKey;
    const fresh=account?avatarNode(account.id,account.username||"Account","xl"):node("span","avatar xl");
    fresh.id="authorized-avatar";fresh.hidden=!account;$("authorized-avatar").replaceWith(fresh);
    show("authorized-mark",!account);
  }
  renderConnection();
  }else if(view==='analysis'||view==='integrations')window.TgWitnessAnalysis?.syncStatus?.(s);
}

function hasSources(s){return s.targets.some(t=>t.enabled)||(s.scope?.mode||"selected")!=="selected";}
function renderSetup(){
  const s=state.status,c=s.collector;
  show("setup-card",['chats','observations','sources'].includes(state.view)&&!s.demo&&!c.running&&viewAllowed("connection")&&viewAllowed("sources")&&may("collect"));
  const stage=!accountSignedIn()?0:!hasSources(s)?1:2;
  const steps=[
    [tr("GET STARTED · STEP 1 OF 3"),tr("Connect your Telegram account"),tr("Use your phone number, scan a QR code, or import account files."),tr("Connect account →")],
    [tr("ACCOUNT CONNECTED · STEP 2 OF 3"),tr("Choose the groups you want to observe"),tr("Open Sources to see your groups and channels, then add the ones to include. Observation is still off."),tr("Choose sources →")],
    [tr("SOURCES SELECTED · STEP 3 OF 3"),tr("Ready to start observation"),tr("New activity from enabled sources will be saved using your monitoring settings."),tr("Start observation")],
  ][stage];
  if(accountState(s).needsSignIn){steps[1]=tr('Sign in again');steps[2]=tr('Telegram no longer accepts this session. Sign in to the same account; saved records and sources stay in this workspace.');steps[3]=tr('Sign in again');}
  ["setup-stage","setup-title","setup-description","setup-action"].forEach((id,i)=>$(id).textContent=steps[i]);
  ["setup-account","setup-sources","setup-observe"].forEach((id,i)=>{
    const item=$(id);item.classList.toggle("complete",i<stage);item.classList.toggle("current",i===stage);
    if(i===stage)item.setAttribute("aria-current","step");else item.removeAttribute("aria-current");
    item.querySelector("span").textContent=i<stage?"✓":String(i+1);
  });
}
function nextSetupStep(){
  if(!accountSignedIn()){navigate("connection");setAuthStep('credentials');}
  else if(!hasSources(state.status))navigate("sources");
  else $("collector-toggle").click();
}
$("setup-action").addEventListener("click",nextSetupStep);
$("empty-action").addEventListener("click",()=>{
  if(state.filter||state.source||state.search||state.eventSince||state.eventUntil){
    state.filter=state.source=state.search=state.eventSince=state.eventUntil="";$("event-search").value="";$("source-filter").value="";
    state.cursor=state.eventBefore=state.eventAfter=null;
    viewQueries("observations","[data-filter]").forEach(n=>n.classList.toggle("active",n.dataset.filter===""));
    window.TgWitnessRouter?.record();
    busy($("empty-action"),()=>refreshEvents());
  }else nextSetupStep();
});
function fillSourceSelect(id,value,all=false) {
  const n=$(id); n.replaceChildren();
  if (all) n.append(new Option(tr("All sources"),""));
  state.status.targets.filter(t=>all || t.enabled).forEach(t=>n.append(new Option(t.title,String(t.chat_id))));
  if ([...n.options].some(o=>o.value===String(value))) n.value=String(value);
}
let statusRequest=0,profilesRequest=0;
const workspaceOptionsReady=import("./components/workspaces.js?v=2");
async function refreshStatus() {
  const request=++statusRequest,revision=state.workspaceRevision,result=await json("status");
  if(revision!==state.workspaceRevision||request!==statusRequest)return;
  state.status=result;applyAccess();renderStatus();
  if(!viewAllowed(state.view))navigate("chats");
}
async function loadProfiles(){
  const request=++profilesRequest,result=await json("profiles",undefined,{root:true});
  const {updateWorkspaceOptions}=await workspaceOptionsReady;
  if(request!==profilesRequest)return;
  state.profiles=result.profiles;

  for(const profile of state.profiles)if(profile.id==="default"&&profile.label==="Main account")profile.label=tr("Main account");
  const select=$("profile-select");updateWorkspaceOptions(select,state.profiles,state.profile,tr);
  const list=$("profiles-list"),showList=state.view==='connection',oldRows=new Map([...list.children].map(row=>[row.dataset.profile,row])),rows=[];
  for(const profile of state.profiles){
    if(!showList)continue;
    const row=node("div","target-row"),info=node("div");
    info.append(node("h3","",profile.label),node("p","",profile.error_type==="DeletionPending"?tr("Deletion incomplete"):profile.error_type?tr("Unavailable: {error}",{error:profile.error_type}):
      termText(profile.collector?.phase||"offline")+" · "+trn("{n} journal event","{n} journal events",profile.stats?.total||0)));
    const button=node("button","secondary",tr(profile.id===state.profile?"Current workspace":"Open workspace"));
    button.disabled=!!profile.error_type||profile.id===state.profile;
    button.addEventListener("click",()=>busy(button,()=>switchProfile(profile.id)));
    row.dataset.profile=profile.id;row.append(info,button);
    const existing=oldRows.get(profile.id);
    if(existing){if(existing.firstElementChild.outerHTML!==info.outerHTML)existing.firstElementChild.replaceWith(info);
      const control=existing.lastElementChild;control.textContent=button.textContent;if(!control.hasAttribute('aria-busy'))control.disabled=button.disabled;rows.push(existing);
    }else rows.push(row);
  }
  if(showList)placeChildren(list,rows);
  select.value=state.profile;
  $("nav-accounts").textContent=String(state.profiles.length);
  if(state.view==='accounts')await window.TgWitnessFleet?.load();
  if(request!==profilesRequest)return;
  renderAccounts();
}
function accountPhaseLabel(p){
  if(p.error_type==="DeletionPending")return tr("Deletion incomplete");
  if(p.error_type)return tr("Unavailable")+" · "+p.error_type;
  return tr(accountState(p).label);
}
function accountIdentity(p){
  const a=p.collector&&p.collector.account;
  if(!a)return tr(p.collector&&p.collector.has_session?"Signed in":"No account connected");
  return (a.username?"@"+a.username+" · ":"")+"ID "+a.id;
}
let accountsView=null;
const accountsReady=import("./views/accounts.js?v=30").then(({createAccounts})=>{
  accountsView=createAccounts({root:$("view-accounts"),tr,getState:()=>state,getSession:()=>state.workspaceRevision+":"+state.profile,
    json,loadProfiles,refreshStatus,toast,switchProfile,navigate,diagnose:openDiagnostics});
  window.TgWitnessAccounts=accountsView;
  if(state.view==='accounts')renderAccounts();
  return accountsView;
}).catch(error=>toast(error.message,true));
function renderAccounts(){
  if(state.view!=='accounts')return;
  const grid=$("accounts-list"),s=state.status;if(!grid||!s)return;
  window.TgWitnessFleet?.beforeRender?.();
  const cards=new Map(viewQueries('accounts','.account-card[data-profile]').map(card=>[card.dataset.profile,card]));
  const list=state.profiles||[];
  $("accounts-limit").textContent=trn("{n} workspace. Add as many as you need — each uses its own Telegram account.",
    "{n} workspaces. Add as many as you need — each uses its own Telegram account.",list.length);
  $("account-add-form").querySelector("button").disabled=s.demo;
  for(const value of list){
    const existing=cards.get(value.id),p=existing?Object.assign(existing.profileData,value):value;
    const c=p.collector,current=p.id===state.profile,down=!!p.error_type||!c;
    const card=node("div","card padded account-card"+(current?" current":""));card.dataset.profile=p.id;card.profileData=p;
    const head=node("div","account-head"),who=node("div","account-who"),account=c&&c.account;
    const title=node("div");title.append(node("h2","",p.label));
    // The badge sums up every part (health.py); the observation phase alone is listed below it.
    const badge=s.demo?node("span","account-badge sample",tr("Sample data")):!down&&p.health?stateBadge(p.health.state,"account-badge"):
      node("span","account-badge "+(c&&c.running?"on":down?"down":"off"),accountPhaseLabel(p));
    title.append(node("p","account-id",s.demo?tr("Demo workspace"):accountIdentity(p)));
    who.append(avatarNode(account?account.id:null,account&&account.username?account.username:p.label,"lg",p.id),title);
    head.append(who,badge);card.append(head);
    if(!down){
      const meta=node("dl","account-meta");
      const pair=(k,v,field)=>{const item=node("div","account-value");item.dataset.field=field;item.append(node("dt","",k),node("dd","",v));meta.append(item);};
      pair(tr("Observation"),s.demo?tr("Sample data"):accountPhaseLabel(p),"observation");
      const attention=!s.demo&&p.health?Object.keys(healthPartNames).filter(name=>needsLook(p.health[name]?.state)):[];
      if(attention.length)pair(tr("Needs attention"),attention.map(name=>healthPartNames[name]+" — "+healthStates[healthKnown(p.health[name].state)][0]).join(" · "),"attention");
      pair(tr("Sources"),tr("{n} active",{n:p.sources_enabled||0})+(p.sources_total?" / "+p.sources_total:""),"sources");
      pair(tr("Journal"),p.stats?trn("{n} event","{n} events",p.stats.total):tr("Unavailable"),"events");
      pair(tr("Pending media"),String(c.media_pending||0),"pending");
      pair(tr("Last update"),c.last_update_at?fmtTime(c.last_update_at):"—","updated");
      card.append(meta);
    } else if(p.error_type){
      card.append(node("p","access-warning",p.error_type==="DeletionPending"?
        tr("Deletion is incomplete. Close programs using this workspace's files, then retry Delete. Observation remains stopped."):
        tr("This workspace could not start. Its data directory is preserved for inspection.")));
    }
    const actions=node("div","account-actions");
    const open=node("button","secondary",tr(current?"Current":"Open"));open.dataset.action='open';open.disabled=down||current;
    open.addEventListener("click",()=>busy(open,()=>switchProfile(p.id)));
    actions.append(open);
    if(!down&&(!c.has_session||accountState(p).needsSignIn)){
      const connect=node("button","secondary",tr(accountState(p).needsSignIn?"Sign in again":"Connect"));connect.type="button";connect.dataset.action="connect";connect.disabled=state.status.demo;
      connect.addEventListener("click",()=>busy(connect,async()=>{if(state.profile!==p.id)await switchProfile(p.id);if(state.profile===p.id&&state.token)await navigate("connection");}));
      actions.prepend(connect);
    }
    if(!down){
      const toggle=node("button","quiet",tr(c.running?"Pause":"Start"));toggle.dataset.action='toggle';toggle.disabled=state.status.demo||(!c.running&&!accountState(p).canStart);
      toggle.addEventListener("click",()=>busy(toggle,async()=>{
        const running=!!p.collector?.running;
        if(running&&!(await collectionReady).confirmPause(p.label))return;
        await json("collector/"+(running?"stop":"start"),{},{profile:p.id});
        toast(tr(running?"Paused collection for {name}.":"Started collection for {name}.",{name:p.label}));
        await loadProfiles();if(p.id===state.profile)await refreshStatus();
      }));
      actions.append(toggle);
    }
    const rename=node("button","quiet",tr("Rename"));rename.dataset.action='rename';rename.disabled=state.status.demo;
    rename.addEventListener("click",()=>busy(rename,async()=>{
      const label=(window.prompt(tr("New name for this workspace:"),p.label)||"").trim();
      if(!label||label===p.label)return;
      await api("profiles/"+encodeURIComponent(p.id),{label},{root:true,method:"PATCH"});
      toast(tr("Renamed workspace."));await loadProfiles();
    }));
    actions.append(rename);
    if(p.id!=="default"){
      const del=node("button","danger",tr("Delete"));del.dataset.action='delete';del.disabled=state.status.demo;
      del.addEventListener("click",()=>busy(del,async()=>{
        if(!window.confirm(tr("Delete \"{name}\" permanently? This stops its collector and erases its session, journal, sources and signing key. This cannot be undone.",{name:p.label})))return;
        const revision=state.workspaceRevision;
        try{
          await api("profiles/"+encodeURIComponent(p.id),undefined,{root:true,method:"DELETE"});
        }catch(error){
          if(error instanceof StaleView||revision!==state.workspaceRevision)throw error;
          await loadProfiles().catch(()=>{});
          if(revision===state.workspaceRevision&&state.profile===p.id&&state.profiles.some(item=>item.id===p.id&&item.error_type)){
            await switchProfile("default").catch(()=>{});
          }
          throw error;
        }
        if(state.profile===p.id){await switchProfile("default");}
        toast(tr("Workspace deleted."));await loadProfiles();
      }));
      actions.append(del);
    }
    card.append(actions);
    if(!existing){grid.append(card);continue;}
    existing.className=card.className;
    for(const selector of ['.account-head','.account-meta','.access-warning']){
      const old=existing.querySelector(':scope > '+selector),fresh=card.querySelector(':scope > '+selector);
      if(!fresh)old?.remove();else if(!old)existing.insertBefore(fresh,existing.querySelector('.account-actions'));
      else if(old.outerHTML!==fresh.outerHTML)old.replaceWith(fresh);
    }
    const retained=existing.querySelector('.account-actions'),buttons=new Map([...retained.children].map(button=>[button.dataset.action,button]));
    placeChildren(retained,[...actions.children].map(button=>{const old=buttons.get(button.dataset.action);if(!old)return button;
      if(old.textContent!==button.textContent)old.textContent=button.textContent;
      if(!old.hasAttribute('aria-busy'))old.disabled=button.disabled;return old;}));
  }
  for(const [id,card] of cards)if(!list.some(profile=>profile.id===id))card.remove();
  window.TgWitnessFleet?.decorate();accountsView?.updateStatus();
}
async function switchProfile(id,options={}){
  if(id!==state.profile&&(state.accountExportDirty||state.accountDisclosureDirty)&&
      !options.discardConfirmed&&!window.confirm(tr("Discard unsaved settings in this workspace and switch accounts?"))){
    $("profile-select").value=state.profile;return false;
  }
  formControls?.reset();connectionNotice?.clear();
  if(options.history!==false)window.TgWitnessRouter?.invalidate();
  parametersView?.resetSession();
  resetChatExportTools();
  resetReportSettings();
  window.TgWitnessIntegrations?.clear(true);
  window.TgWitnessLive?.stop();window.TgWitnessReview?.clear();
  window.TgWitnessProxies?.clear?.();
  window.TgWitnessAnalysis?.clear();
  quickDialog.close();
  const revision=++state.workspaceRevision;
  viewHost?.resetSession();state.permissionsStamp=null;
  $("workspace").inert=true;
  try{
  resetInteractions();
  closeDetail({history:false});$("export-dialog").close("cancel");stopExportPoll();state.exportId=null;
  clearTimeout(multiPoll);multiPoll=null;state.multiChecked=false;
  await cancelQR();
  if(revision!==state.workspaceRevision)return;
  state.request++;clearVerification();
  state.workflow=null;state.exportTask="journal";
  state.profile=id;state.monitoringDirty=false;state.captureDirty=false;sessionStorage.setItem("tgwitness-profile",id);
  state.events=[];state.dialogs=[];state.cursor=null;state.filter="";state.source="";state.search="";state.eventSince="";state.eventUntil="";state.eventSystem=false;
  state.eventBefore=state.eventAfter=state.eventMatched=null;
  state.chat=null;state.chats=[];state.chatsLoading=false;state.chatsError=false;state.chatMessages=[];state.chatNextBefore=null;state.chatNextAfter=null;state.chatInfo=null;state.chatFilter="all";state.chatView="messages";state.chatAuthor=null;
  state.scope=null;state.scopeDirty=false;state.dossier=null;state.notifications=[];resetWitnessSetup();
  closeNotifications();renderNotifications();renderExportState(null);
  state.evidenceDirty=false;state.replicaDirty=false;state.alertsDirty=false;
  state.parameters=null;state.parametersDirty=false;state.recheckDirty=false;
  sourcesView?.resetSession();
  $("load-dialogs").textContent=tr("Load chats");
  $("event-search").value="";$("dialog-search").value="";show("available-card",false);
  viewQueries("observations","[data-filter]").forEach(n=>n.classList.toggle("active",n.dataset.filter===""));
  clearSecrets();$("api-id").value="";networkLoadedFor=null;
  $("network-result").textContent="";
  await refreshStatus();await loadProfiles();
  if(revision!==state.workspaceRevision)return;
  await navigate(state.view,{history:false});
  await loadNotifications().catch(()=>{});
  if(revision!==state.workspaceRevision)return;
  setAuthStep(accountSignedIn()?"authorized":"credentials");
  syncLive();
  if(options.history!==false)window.TgWitnessRouter?.record();
  toast(tr("Switched workspace. Other collectors keep their current state."));
  }catch(error){if(revision===state.workspaceRevision&&!(error instanceof StaleView))lock();throw error;}
  finally{if(revision===state.workspaceRevision)$("workspace").inert=false;}
}
$("profile-select").addEventListener("change",()=>busy(null,()=>switchProfile($("profile-select").value)));
$("profile-create-form").addEventListener("submit",event=>{
  event.preventDefault();busy(event.submitter,async()=>{
    const profile=await json("profiles",{label:$("profile-label").value.trim()},{root:true});
    $("profile-label").value="";await switchProfile(profile.id);navigate("connection");
  });
});
$("account-add-form").addEventListener("submit",event=>{
  event.preventDefault();busy(event.submitter,async()=>{
    const profile=await json("profiles",{label:$("account-add-label").value.trim(),group:$("account-add-group").value||null},{root:true});
    $("account-add-label").value="";await switchProfile(profile.id);navigate("connection");
    toast(tr("Workspace created. Connect a Telegram account to start."));
  });
});
$("accounts-refresh").addEventListener("click",e=>busy(e.currentTarget,async()=>{await loadProfiles();}));
function excerpt(e) {
  const p=e.payload;
  if (p.text) return p.text;
  if (e.kind==="message.deleted") return tr("Earlier captured versions remain available. Deletion actor not supplied.");
  if (e.kind==="message.missing_on_recheck") return tr("Telegram no longer returns this message; no deletion notice was received.");
  if (e.kind==="replica.completed") return p.error?tr("Stopped: {error}",{error:p.error}):tr("{n} encrypted object(s), {size}",{n:p.objects,size:humanSize(p.bytes)});
  if (e.kind==="alerts.changed") return p.enabled?tr("On · {n} destination(s)",{n:p.destinations}):tr("Off");
  if (e.kind==="replica.changed") return p.enabled?tr("On · {bucket} · every {n} min",{bucket:p.bucket,n:p.interval_minutes}):tr("Off");
  if (e.kind==="anchor.completed") return tr("{ok} of {total} services answered for the checkpoint of {n} records",{ok:p.results.filter(r=>r.ok).length,total:p.results.length,n:p.checkpoint.event_count});
  if (e.kind==="source.checked") return (p.matches?tr("Matches"):tr("Differs"))+" · "+p.repository.replace("https://github.com/","")+" @ "+p.commit.slice(0,12);
  if (e.kind==="evidence.changed") return p.enabled?tr("On · every {n} min · {services} services",{n:p.interval_minutes,services:p.tsa_urls.length+p.ots_calendars.length}):tr("Off");
  if (e.kind==="storage.low") return tr("Photo & file downloads paused at {size} free; queued files are kept.",{size:humanSize(p.free_bytes)});
  if (e.kind==="storage.ok") return tr("Photo & file downloads resumed · {size} free",{size:humanSize(p.free_bytes)});
  if (e.kind==="recheck.completed") return tr("{chats} chat(s) · {recovered} recovered · {edited} edited · {missing} not found",{chats:p.chats.length,recovered:p.recovered,edited:p.edited,missing:p.missing});
  if (e.kind==="reaction.snapshot") return p.counts ? Object.entries(p.counts).map(([k,v])=>k+" "+v).join("  ·  ") : tr("Reaction snapshot received · actor list may be incomplete");
  const failure=p.error_type ? " · "+p.error_type : "";
  switch (e.kind) {
    case "interaction.preview": return [p.title,p.link].filter(Boolean).join(" · ");
    case "interaction.requested": return [p.request?.action,p.button?.text,p.request?.text].filter(Boolean).join(" · ");
    case "interaction.result": return [p.status,p.answer?.message,p.answer?.url,p.error_type].filter(Boolean).join(" · ");
    case "account.authorized": return tr("Telegram account ID {id}",{id:p.account_id});
    case "account.signed_out": return tr("Telegram account ID {id}",{id:p.account_id})+(p.telegram_session_ended?"":" · "+tr("Telegram did not confirm the end of the session"))+failure;
    case "media.skipped": {
      const type=/^attachment type not collected by policy: (\w+)$/.exec(p.reason||"")?.[1];
      if(type)return tr("Not collected by the attachment settings: {type}",{type:Object.fromEntries(mediaTypes)[type]||termText(type)});
      if(p.reason==="media download disabled")return tr("Attachment downloads off");
      if(p.reason==="above the size limit of the attachment settings")return tr("Larger than the size limit");
      if(p.reason==="authorized account identity unavailable")return tr("Telegram account not identified yet");
      return String(p.reason||"").startsWith("metadata-only")?tr("No file to download"):p.reason||"";
    }
    case "media.failed": return p.reason==="download failed"?tr("Download failed")+failure:tr({above_limit:"Larger than the size limit",
      unknown_size_or_above_limit:"Size unknown or above the limit",download_unavailable:"Telegram did not provide the file",
      download_size_differs_from_observed_attachment:"The downloaded size differs from the observed attachment",
      queue_descriptor_differs_from_signed_observation:"The queued file differs from the signed observation",
      existing_content_addressed_file_is_corrupt:"The saved copy of this file is damaged"}[p.reason]||p.reason||p.meaning||"");
    case "target.changed": return (p.title||tr("Source"))+" · "+tr(p.enabled?"observed":"paused");
    case "capture.changed": return p.download_media ? tr("Attachments on · up to {n} MiB per file",{n:mediaLimit(p)}) : tr("Attachment downloads off");
    case "connection.retry": return tr("Attempt {n}",{n:p.attempt});
    case "connection.retry_failed": return tr("Attempt {n}",{n:p.attempt})+failure;
    case "telegram.backoff": return tr("Telegram asked to wait {n} s",{n:p.retry_after_seconds});
    case "export.failed": return (p.format||"export").toUpperCase()+failure;
    case "network.changed": return tr({direct:"Direct connection",socks5:"SOCKS5 proxy",http:"HTTP proxy",mtproxy:"MTProxy",mtproxy_auto:"Automatic MTProxy"}[p.kind]||p.kind);
    case "network.route_assigned": return (p.returned_from_direct?tr("Back on a proxy after a direct connection")+" · ":"")+(p.source||"");
    case "network.route_rotated": return tr({connect_failed:"The proxy stopped answering",repeated_disconnect:"The proxy kept dropping the connection",
      planned:"Planned switch to another proxy"}[p.reason]||p.reason)+(p.source?" · "+p.source:"")+failure;
    case "network.route_unavailable": return (p.fallback_to_direct?tr("Telegram is contacted directly, as the IP protection allows"):
      tr("Telegram is not contacted until a listed proxy answers"))+failure;
    case "network.route_fallback": return tr("Telegram sees this server's address until a listed proxy answers");
    case "network.policy_changed": return exposureNames[p.exposure]||p.exposure;
    case "network.probe": return p.connected ? tr("Telegram transport connected") : tr("Connection failed")+failure;
    case "profile.created": return p.label||p.id;
    case "profile.unavailable": return p.profile_id+failure;
    case "snapshot.started": return tr("Up to {n} recent messages",{n:p.limit});
    case "snapshot.completed": return tr("{captured} of {requested} messages saved",{captured:p.captured,requested:p.requested});
    case "snapshot.interrupted": return tr("{captured} of {requested} messages saved",{captured:p.captured,requested:p.requested})+failure;
    case "scope.changed": return scopeName(p.after?.mode)+(p.after?.mode!=="selected"&&p.acknowledged?" · "+tr("warning confirmed"):"");
    case "scope.applied": return tr("{added} added · {paused} paused · {resumed} resumed",{added:(p.added||[]).length,paused:(p.paused||[]).length,resumed:(p.resumed||[]).length});
    case "source.discovered": return (p.title||"")+" · "+termText(p.kind);
    case "target.removed": return p.title||"";
    case "target.priority": return (p.title||"")+" · "+tr(p.priority?"priority":"regular");
    case "recheck.changed": return tr("Priority chats every {a} min · others every {b} min (0 = off)",{a:p.recheck_minutes,b:p.recheck_other_minutes});
    case "dossier.changed": return tr(p.enabled?"On":"Off");
    case "source.profile": return [p.title||"",p.bot?tr("bot"):"",String(p.bot?.description||p.about||"").slice(0,120)].filter(Boolean).join(" · ");
    case "parameters.changed": return Object.keys(p.after||{}).map(key=>parameterLabel(key)+": "+parameterValue(p.after[key])).join(" · ");
    case "witness.token_created": return p.label||"";
    case "access.granted": case "access.changed": return (p.label||"")+" · "+(p.permissions||[]).map(x=>permissionLabels[x]?.[0]||x).join(", ");
    case "access.revoked": return p.label||"";
    case "access.session_started": return (p.label==="Main administrator"?tr("Main administrator"):p.label||"")+" · "+(p.address||"");
    case "access.session_ended": return (p.label==="Main administrator"?tr("Main administrator"):p.label||"")+" · "+(sessionEndReasons[p.reason]||p.reason||"");
    case "witness.seen": return (p.label||"")+" · "+String(p.witness_fingerprint||"").slice(0,16);
  }
  if (p.reason) return p.reason;
  if (p.service_action) return p.service_action;
  if (p.action) return p.action._ || tr("Telegram service action");
  if (p.coverage) return tr(p.coverage);
  if (p.meaning) return p.meaning;
  return tr("Open the source record for observation details");
}
let previouslyFocused;
function eventRow(e) {
    const label=labels[e.kind] || [e.kind,"activity","system"];
    const row=node("tr","event-row"); row.tabIndex=0; row.setAttribute("role","button"); row.setAttribute("aria-label",tr("Open {label} event {seq}",{label:label[0],seq:e.seq}));
    const cell=node("td"), summary=node("div","event-summary"), text=node("div");
    const title=node("div","event-title",label[0]); title.append(node("span","",e.message_id ? "#"+e.message_id : "#"+e.seq));
    const mobileMeta=node("div","event-mobile-meta",sourceTitle(e.chat_id)+" · ");
    mobileMeta.append(timeNode(e.observed_at));text.append(title,node("div","event-excerpt",excerpt(e)),mobileMeta);
    const mark=node("span","event-icon "+label[2]); mark.append(icon(label[1]));
    summary.append(mark,text); cell.append(summary);
    const source=node("td"); source.append(node("span","source-title",sourceTitle(e.chat_id)),node("span","source-id",e.chat_id || tr("system")));
    const time=node("td");time.append(timeNode(e.observed_at,"event-time"));
    const open=node("td","event-open"); open.append(icon("chevron"));
    row.append(cell,source,time,open);
    row.addEventListener("click",()=>openDetail(e));
    row.addEventListener("keydown",event=>{ if(event.target===row&&(event.key==="Enter"||event.key===" ")){event.preventDefault();openDetail(e);} });
    row.dataset.seq=String(e.seq);
    return row;
}
function renderEvents() {
  if(state.view!=='observations')return;
  window.TgWitnessJournal.renderRows(state.events,eventRow);
  show("empty-events",state.events.length===0);
  const filtered=state.filter||state.source||state.search||state.eventSince||state.eventUntil,c=state.status.collector;
  $("empty-copy").textContent=tr(filtered ? "No events match these filters. Try another source, event type, or search." :
    !c.has_session?"Connect an account to start your journal.":!hasSources(state.status)?
    "Your account is connected. Choose which groups and channels to observe.":c.running?
    "Observation is on. New activity will appear here when Telegram delivers it.":"Your sources are ready. Start observation to save new activity.");
  $("empty-action").textContent=tr(filtered?"Clear filters":!c.has_session?"Connect account →":
    !hasSources(state.status)?"Choose sources →":"Start observation");
  show("empty-action",!!filtered||(!state.status.demo&&!c.running));
  window.TgWitnessJournal.syncPage();
}
async function refreshEvents(direction=false) {
  if(state.view!=='observations')return;
  await journalReady;
  window.TgWitnessJournal.sync();
  const request=++state.request,params=new URLSearchParams({limit:"200",include_count:"true"});
  const after=direction==="newer"?state.eventAfter:null;
  const before=direction==="latest"?null:direction===true||direction==="older"?state.cursor:state.eventBefore;
  if(direction==="newer"&&after===null||[true,"older"].includes(direction)&&before===null)return;
  if(state.filter)params.set("kind",state.filter);
  if(state.source)params.set("chat_id",state.source);
  if(state.search)params.set("search",state.search);
  if(state.eventSince)params.set("since",state.eventSince);
  if(state.eventUntil)params.set("until",state.eventUntil);
  if(!state.eventSystem)params.set("hide_system","true");
  if(after!==null)params.set("after",after);else if(before!==null)params.set("before",before);
  const result=await json("events?"+params,undefined,viewOptions('observations'));
  if(request!==state.request)return;
  state.events=result.events.slice(0,200);state.cursor=result.next_before??null;state.eventAfter=result.next_after??null;
  state.eventMatched=result.count_exact?result.matched:null;
  state.eventBefore=after!==null?(state.eventAfter!==null&&result.events.length?result.events[0].seq+1:null):before;
  renderEvents();
  if(direction)window.TgWitnessRouter?.record({seq:null,before:state.eventBefore});
}
const journalReady=import('./components/journal.js?v=4').then(({createJournal})=>{
  window.TgWitnessJournal=createJournal({get:$,state,node,icon,tr,invalidate:()=>{state.request++;},error:message=>toast(message,true),
    changed:async()=>{state.cursor=state.eventBefore=state.eventAfter=state.eventMatched=null;closeDetail({history:false});window.TgWitnessRouter?.record({seq:null});await refreshEvents();},
    page:direction=>{closeDetail({history:false});return refreshEvents(direction);},openDetail,showBackdrop:visible=>show("drawer-backdrop",visible),
    openChat:async event=>{
      const revision=state.workspaceRevision;closeDetail({history:false});await navigate("chats",{load:false});
      if(revision!==state.workspaceRevision||state.view!=="chats")return;
      await refreshChats();if(revision!==state.workspaceRevision||state.view!=="chats")return;
      if(await openChat(event.chat_id)){
        const message=$("msg-"+event.message_id);
        if(message){message.scrollIntoView({block:"center"});replay(message,"flash",1500);}
      }
    }});
  return window.TgWitnessJournal;
});
$("refresh").addEventListener("click",e=>busy(e.currentTarget,async()=>{await refreshStatus();await refreshEvents();}));
$("collector-toggle").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await json("collector/"+(state.status.collector.running ? "stop" : "start"),{});
  await refreshStatus();await refreshEvents();
}));
function detailBlock(label,text,cls="") {
  const n=node("div","detail-block "+cls); n.append(node("small","",label),node("div","message-text",text||tr("(No text in this version)"))); return n;
}
async function openDetail(e,options={}) {
  const detailView=state.view,detailRevision=state.workspaceRevision;await journalReady;
  if(state.view!==detailView||state.workspaceRevision!==detailRevision||$("workspace").hidden)return;
  if($("detail-drawer").hidden)previouslyFocused=document.activeElement;
  state.drawerSeq=e.seq;
  if(options.history!==false)window.TgWitnessRouter?.record({view:"observations",seq:e.seq});
  const label=labels[e.kind]?.[0]||e.kind;
  const content=$("detail-content");content.replaceChildren();
  const h=node("h2","",label);h.id="detail-title";content.append(h);
  const meta=node("div","detail-meta");
  const sender=e.payload.sender_id ?? e.actor_id;
  for(const [label,value] of [
    [tr("Source"),sourceTitle(e.chat_id)],[tr("Record"),tr("Event #{seq}",{seq:e.seq})+(e.message_id ? " / "+tr("Message #{id}",{id:e.message_id}) : "")],
    [tr("Observed at (collector clock)"),formatTime(e.observed_at)],[tr("Source time"),formatTime(e.source_at)],
    [tr("Message sender / supplied actor"),sender ?? tr("Not supplied")],
    [tr("Action attribution"),tr(e.kind==="message.edited" ? "Editor not supplied" : e.kind==="message.deleted" ? "Deleter not supplied" : "See raw record and visibility notes")],
  ]) { const box=node("div");box.append(node("small","",label),node("strong","",String(value)));meta.append(box); }
  content.append(meta);
  const copies=node("div","review-tabs");
  for(const [label,value] of [["SHA-256",e.hash],["Message ID",e.message_id],["Sender ID",sender],
    ["Link to this record",window.TgWitnessRouter?.href({view:"observations",seq:e.seq})||location.origin+"/?"+new URLSearchParams({event:e.seq,workspace:state.profile})+"#journal"]]){
    if(value===null||value===undefined)continue;
    const copy=node("button","quiet small",tr(label));copy.type="button";copy.title=String(value);
    copy.addEventListener("click",()=>busy(copy,async()=>{await navigator.clipboard.writeText(String(value));toast(tr("Copied"));}));copies.append(copy);
  }
  content.append(copies);
  const versions=node("div");content.append(versions);
  if("text" in e.payload)versions.append(detailBlock(tr("Captured version"),e.payload.text));
  content.append(node("p","detail-caption",excerpt(e)));
  if(e.payload.media_sha256) {
    content.append(window.TgWitnessReview.attachment(e.payload,{api,download,busy,tr}));
    if(state.status?.analysis?.media_available){
      const recognize=node("button","quiet",tr("Recognize attachment"));recognize.type="button";
      recognize.addEventListener("click",()=>window.TgWitnessMedia?.select({workspace:state.profile,chat_id:e.chat_id,event_seq:e.seq,digest:e.payload.media_sha256}));content.append(recognize);
    }
  }
  content.append(window.TgWitnessJournal.signedRecord(e));
  content.append(node("p","detail-hash","SHA-256 · "+e.hash));
  const lineage=node("div","lineage");content.append(lineage);
  show("drawer-backdrop",true);show("detail-drawer",true);$("close-detail").focus();
  window.TgWitnessJournal.openDetail(e);
  if(e.chat_id!==null && e.message_id!==null) {
    try {
      const result=await json("events?"+new URLSearchParams({chat_id:e.chat_id,message_id:e.message_id,limit:"500"}));
      if(state.drawerSeq!==e.seq)return;
      const previous=result.events.find(x=>x.seq<e.seq && ["message.new","message.edited","message.snapshot","message.recovered"].includes(x.kind));
      if(e.kind==="message.edited") {
        versions.replaceChildren();
        if(previous)versions.append(window.TgWitnessReview.compare(previous.payload,e.payload,tr));
        else versions.append(detailBlock(tr("Previous content unavailable"),tr("No earlier content version was found in the loaded records."),"before"),
          detailBlock(tr("Newly observed version"),e.payload.text,"after"));
      } else if(e.kind==="message.deleted") {
        versions.append(previous ? detailBlock(tr("Last captured content before this notice"),previous.payload.text)
          : detailBlock(tr("Content unavailable"),tr("The journal has no earlier content version in the loaded records. This notice cannot recover it.")));
      }
      lineage.append(node("h3","",tr("Message observation history")));
      result.events.forEach(other=>{
        const b=node("button","",(other.seq===e.seq ? "● " : "")+"#"+other.seq+" · "+(labels[other.kind]?.[0]||other.kind)+" · "+formatTime(other.observed_at));
        b.addEventListener("click",()=>openDetail(other));lineage.append(b);
      });
      if(result.next_before)lineage.append(node("p","hint",tr("Showing the latest 500 observations for this message. The complete history is in the evidence export.")));
    } catch(error) {if(state.drawerSeq===e.seq)lineage.append(node("p","hint",error.message));}
  }
}
function closeDetail(options={}){const opened=state.drawerSeq!==null;state.drawerSeq=null;window.TgWitnessJournal?.closeDetail();leave("detail-drawer");leave("drawer-backdrop");$("detail-content").replaceChildren();if(opened&&previouslyFocused?.isConnected)previouslyFocused.focus();previouslyFocused=null;if(opened&&options.history!==false)window.TgWitnessRouter?.record({seq:null},{replace:true});}
$("close-detail").addEventListener("click",closeDetail);$("drawer-backdrop").addEventListener("click",closeDetail);
document.addEventListener("keydown",e=>{
  if($("detail-drawer").hidden)return;
  if(document.querySelector("dialog[open]"))return;
  if(e.key==="Escape")closeDetail();
  if(!e.defaultPrevented&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!e.shiftKey&&!e.isComposing&&!e.target.closest("input,textarea,select,[contenteditable='true'],audio,video")
    &&!window.getSelection()?.toString()&&["ArrowUp","ArrowDown","j","k"].includes(e.key)){
    const index=state.events.findIndex(item=>item.seq===state.drawerSeq),step=["ArrowDown","j"].includes(e.key)?1:-1;
    if(index>=0&&state.events[index+step]){e.preventDefault();openDetail(state.events[index+step]);}
  }
  if(e.key==="Tab"&&$("detail-drawer").getAttribute("aria-modal")==="true"){
    const nodes=[...$("detail-drawer").querySelectorAll("button,summary,a,audio,video,[tabindex='0']")].filter(n=>!n.disabled&&n.getClientRects().length);
    const first=nodes[0],last=nodes.at(-1);
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  }
});
// Sources view boundary: the host supplies session, data and actions explicitly.
let sourcesView=null;
const sourcesReady=import("./views/sources.js").then(({createSources})=>{
  sourcesView=createSources({root:$("view-sources"),tr,getState:()=>state,
    getSession:()=>state.workspaceRevision+":"+state.profile,may,json,refreshStatus,toast,termText,scopeName,icon,loadScope,formatTime,
    setDialogs:result=>{state.dialogs=result.dialogs;if(state.scope)state.scope.folders=result.folders||[];},
    renderScope,focusObservation:()=>$("collector-toggle").focus({preventScroll:true}),
    confirm:message=>window.confirm(message),
    scopeExclusions:(ids,excluded)=>{if(state.scopeDirty)state.scopeExclude=excluded?
      [...new Set([...state.scopeExclude,...ids])]:state.scopeExclude.filter(id=>!ids.includes(id));},
    setDirty:dirty=>{state.monitoringDirty=dirty.monitoring;state.captureDirty=dirty.capture;state.recheckDirty=dirty.recheck;},
    saved:result=>{for(const name of ["monitoring","capture","recheck"])state.status[name]=result[name];}});
  if(state.view==="sources"&&!$("workspace").hidden)sourcesView.enter();
  return sourcesView;
}).catch(error=>{toast(error.message,true);throw error;});
function renderTargets() { sourcesView?.renderTargets(); }
const mediaLimit=c=>Math.max(0,...Object.values(c?.types||{}).filter(r=>r.enabled).map(r=>r.max_mb))||c?.max_media_mb;
function renderHistory(){
  const s=state.status,h=s?.history||{phase:"none"},phase=h.phase;
  const active=phase==="running",paused=phase==="paused",exists=phase!=="none";
  show("history-card",may("sources")&&!s?.chats_limited);
  show("history-start",!active&&!paused);show("history-pause",active);
  show("history-resume",paused);show("history-cancel",active||paused);
  show("history-report",exists&&may("export"));
  $("history-start").disabled=!!s?.demo||!s?.collector.running||!s?.targets.some(x=>x.enabled);
  $("history-resume").disabled=!!s?.demo||!s?.collector.running;
  const labels={running:tr("Loading history"),paused:tr("History paused"),complete:tr("History reading finished"),
    incomplete:tr("History finished with gaps"),cancelled:tr("History run ended")};
  const counts=h.sources_by_phase||{},finished=(counts.complete||0)+(counts.failed||0)+(counts.skipped||0);
  $("history-progress").textContent=exists?(labels[phase]||phase)+" · "+tr("{messages} messages · {done} of {total} sources",{
    messages:h.captured,done:finished,total:h.sources_total})+(h.reason?" · "+tr(h.reason):""):
    tr("{n} enabled sources. Start observation before loading history.",{n:s?.targets.filter(x=>x.enabled).length||0});
  $("history-media").textContent=exists?tr("Attachments: {done} saved, {pending} pending, {failed} failed. Unavailable messages: {missing}.",{
    done:h.media?.done||0,pending:h.media_pending||0,failed:h.media?.failed||0,missing:h.unavailable||0}):"";
  const list=$("history-sources");list.replaceChildren();
  const phases={queued:tr("Queued"),reading:tr("Reading history"),complete:tr("History reading finished"),
    failed:tr("Failed"),skipped:tr("Skipped")};
  for(const source of h.sources||[]){
    list.append(node("li","",source.title+" · "+(phases[source.phase]||source.phase)+" · "+source.captured+
      (source.error?" · "+tr(source.error):"")));
  }
  if(h.sources_total>50)list.append(node("li","hint",tr("The signed report lists every source.")));
}
for(const action of ["start","pause","resume","cancel"]){
  $("history-"+action).addEventListener("click",e=>busy(e.currentTarget,async()=>{
    await json("history/"+action,{});await refreshStatus();await refreshEvents();
  }));
}
$("history-report").addEventListener("click",e=>busy(e.currentTarget,()=>download("history/report","tgwitness-history-report.json")));

function resetChatExportTools(){
  for(const id of ["snapshot-source","chat-export-source"])$(id).replaceChildren();
  $("export-chat-tools").open=false;
  $("chat-export-progress").textContent="";
  show("chat-export-download",false);show("chat-export-cancel",false);
}
function renderChatExportTools(){
  const s=state.status;if(!s||state.view!=="evidence")return;
  show("snapshot-form",may("sources"));show("chat-export-form",may("export"));
  fillSourceSelect("snapshot-source",$("snapshot-source").value);
  fillSourceSelect("chat-export-source",$("chat-export-source").value,true);
  $("chat-export-source").options[0].textContent=tr("Choose a chat");
  $("snapshot-form").querySelector("button").disabled=s.demo||!may("sources")||!s.collector.has_session||!s.targets.some(t=>t.enabled);
  renderRecheck();syncExport(s);
}
$("snapshot-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  toast(tr("Capturing visible history. This may take a minute."));
  const limit=Number($("snapshot-limit").value),most=state.status?.parameters?.snapshot_max||500;
  if(!Number.isInteger(limit)||limit<1||limit>most)throw new Error(tr("Enter 1 to {n} messages. The largest snapshot is set in Parameters.",{n:most}));
  const r=await json("snapshot",{chat_id:Number($("snapshot-source").value),limit});
  toast(tr("Saved {n} history observations.",{n:r.captured}));await refreshStatus();await refreshEvents();
});});
let exportPoll=null;
function stopExportPoll(){if(exportPoll){clearTimeout(exportPoll);exportPoll=null;}}
function renderExportState(x){
  if(state.view!=='sources')return;
  const prog=$("chat-export-progress");
  const running=!!x&&x.phase==="running",done=!!x&&x.phase==="done"&&x.ready;
  show("chat-export-cancel",running);show("chat-export-download",done);
  const percent=running&&x.total?Math.min(99,Math.floor((x.captured||0)*100/x.total)):null;
  if(!x||x.phase==="unknown"){prog.textContent="";return;}
  const counts={title:x.title||tr("chat"),captured:(x.captured||0).toLocaleString(),total:(x.total||0).toLocaleString(),percent};
  if(running)prog.textContent=tr("Exporting {title}: ",counts)+tr(x.total?"{captured} of {total} messages ({percent}%)":"{captured} messages read",counts)+
    (x.eta_seconds!==null&&x.eta_seconds!==undefined?" · "+tr("{time} left",{time:fmtDuration(x.eta_seconds)}):"")+"…";
  else if(x.phase==="done")prog.textContent=tr("Done: {captured} messages. Download the signed bundle.",counts);
  else if(x.phase==="failed")prog.textContent=tr("Export failed")+(x.error?" ("+x.error+")":"")+". "+tr("Try again.");
  else if(x.phase==="cancelled")prog.textContent=tr("Export cancelled.");
}
async function pollExport(id){
  stopExportPoll();
  try{
    const x=await json("chat-export/"+encodeURIComponent(id));
    renderExportState(x);
    if(x.phase==="running")exportPoll=setTimeout(()=>pollExport(id),1500);
    else state.exportId=x.phase==="done"?id:null;
  }catch(e){if(e instanceof StaleView)return;renderExportState({phase:"failed",error:e.message});state.exportId=null;}
}
function syncExport(s){
  const btn=$("chat-export-form").querySelector("button[type=submit]"),x=s.collector.chat_export;
  btn.disabled=s.demo||!s.collector.has_session||!s.targets.length||!!(x&&x.phase==="running");
  if(state.exportId||exportPoll)return;
  if(!x){renderExportState(null);return;}
  if(x.phase==="running"){state.exportId=x.id;renderExportState(x);pollExport(x.id);}
  else if(x.phase==="done"){state.exportId=x.id;renderExportState(x);}
  else renderExportState(x);
}
$("chat-export-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const chat_id=Number($("chat-export-source").value);
  if(!chat_id)throw new Error(tr("Select a source to export."));
  const x=await json("chat-export/start",{chat_id});
  state.exportId=x.id;renderExportState(x);
  toast(tr("Full chat export started. Large chats can take a while."));pollExport(x.id);
});});
$("chat-export-cancel").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  if(!state.exportId)return;
  await json("chat-export/"+encodeURIComponent(state.exportId)+"/cancel",{});
  stopExportPoll();state.exportId=null;renderExportState({phase:"cancelled"});
}));
function saveExport(button){return busy(button,async()=>{
  if(!state.exportId)throw new Error(tr("No finished export to download."));
  const revision=state.workspaceRevision;
  if(await download("chat-export/"+encodeURIComponent(state.exportId)+"/download","tgwitness-chat-export.zip",true)===false)return;
  if(revision!==state.workspaceRevision)return;
  toast(tr("Signed chat export downloaded."));
  show("chat-export-download",false);state.exportId=null;
  $("chat-export-progress").textContent=tr("Downloaded. Export another chat if needed.");
});}
$("chat-export-download").addEventListener("click",e=>saveExport(e.currentTarget));
// A Telegram account snapshot is a durable job, separate from the signed observation journal.
const accountExportKinds=["private","bot","group","supergroup","channel"];
const accountExportMedia=["photo","video","video_message","voice","audio","document","sticker","animation"];
const accountExportFallback={purpose:"",chat_kinds:accountExportKinds,from_utc:null,to_utc:null,chat_ids:[],
  report_language:'en',
  sender_ids:[],text_contains:[],own_messages_only:false,
  include_archived:true,media_types:accountExportMedia,max_media_file_mib:512,max_total_gib:16,
  include_profile:true,include_contacts:true,include_profile_photos:false,include_stories:false,
  include_session_metadata:false,include_other_data:false,transport:"takeout"};
let accountExportRead=null,accountExportRequest=0;
for(const id of ['account-export-language','account-disclosure-language']){
  for(const [code,name] of Object.entries(PANEL_LANGUAGES)){
    const option=new Option(name,code);option.lang=code;option.defaultSelected=code==='en';$(id).append(option);
  }
}
function resetAccountExport(){
  accountExportRequest++;accountExportRead=null;disclosurePreview?.clear();
  $("account-export-dialog")?.close();$("account-disclosure-dialog")?.close();
  state.accountExportJobs=[];state.accountExportDefaults=null;state.accountExportCapabilities=null;
  state.accountExportDraftProfile=null;state.accountExportDirty=false;
  state.accountDisclosureJob=null;state.accountDisclosurePreview=null;state.accountDisclosureDirty=false;
  state.accountDisclosures={};
  $("account-export-jobs")?.replaceChildren();
  $('exports-account-error').textContent='';$('exports-account-error').hidden=true;
  if($("account-export-status"))$("account-export-status").textContent="";
}
function accountExportError(error){
  if(error instanceof StaleView)return;
  $("account-export-status").textContent=tr("Account export could not be refreshed: {error}",{error:error.message});
  if(state.view==='evidence'&&state.me?.admin){$('exports-account-error').textContent=$('account-export-status').textContent;$('exports-account-error').hidden=false;}
}
function accountExportDefaults(options){
  const saved={...accountExportFallback,...options};
  $("account-export-purpose").value=saved.purpose||"";
  $('account-export-language').value=saved.report_language||'en';
  for(const input of $("account-export-kinds").querySelectorAll('input[type="checkbox"]'))
    input.checked=saved.chat_kinds.includes(input.value);
  for(const input of $("account-export-media").querySelectorAll('input[type="checkbox"]'))
    input.checked=saved.media_types.includes(input.value);
  $("account-export-archived").checked=!!saved.include_archived;
  $("account-export-own").checked=!!saved.own_messages_only;
  $("account-export-ids").value=(saved.chat_ids||[]).join(", ");
  $("account-export-senders").value=(saved.sender_ids||[]).join(", ");
  $("account-export-phrases").value=(saved.text_contains||[]).join("\n");
  $("account-export-from").value=saved.from_utc?String(saved.from_utc).slice(0,10):"";
  $("account-export-through").value=saved.to_utc?
    new Date(Date.parse(saved.to_utc)-86400000).toISOString().slice(0,10):"";
  $("account-export-file-limit").value=String(saved.max_media_file_mib);
  $("account-export-total-limit").value=String(saved.max_total_gib);
  for(const key of ["profile","contacts","profile-photos","stories","session-metadata","other-data"]){
    const field="include_"+key.replaceAll("-","_");$("account-export-"+key).checked=!!saved[field];
  }
  $("account-export-transport").value=saved.transport;
  state.accountExportDraftProfile=state.profile;state.accountExportDirty=false;
  renderAccountExportPreview();
}
function invalidExportField(field,message){const error=new Error(message);error.field=field;return error;}
function accountExportOptions(){
  const purpose=$("account-export-purpose").value.trim();
  const kinds=[...$("account-export-kinds").querySelectorAll("input:checked")].map(n=>n.value);
  if(!kinds.length)throw invalidExportField('account-export-kinds',tr("Choose at least one chat type."));
  const ids=$("account-export-ids").value.trim().split(/[\s,;]+/).filter(Boolean);
  const chat_ids=[...new Set(ids.map(value=>{
    const id=Number(value);
    if(!Number.isSafeInteger(id)||id===0)throw invalidExportField('account-export-ids',tr("Enter valid numeric chat IDs, separated by commas or lines."));
    return id;
  }))];
  const sender_ids=[...new Set($("account-export-senders").value.trim().split(/[\s,;]+/).filter(Boolean).map(value=>{
    const id=Number(value);
    if(!Number.isSafeInteger(id)||id===0)throw invalidExportField('account-export-senders',tr("Enter valid numeric sender IDs, separated by commas or spaces."));
    return id;
  }))];
  if(sender_ids.length>10000)throw invalidExportField('account-export-senders',tr("Select no more than 10,000 sender IDs."));
  const text_contains=[...new Set($("account-export-phrases").value.split(/\r?\n/).map(value=>value.trim()).filter(Boolean))];
  if(text_contains.length>100||text_contains.some(value=>value.length>200))
    throw invalidExportField('account-export-phrases',tr("Use no more than 100 literal phrases, each up to 200 characters."));
  const from=$("account-export-from").value,through=$("account-export-through").value;
  const from_utc=from?from+"T00:00:00Z":null;
  const to_utc=through?new Date(Date.parse(through+"T00:00:00Z")+86400000).toISOString():null;
  if(from_utc&&to_utc&&Date.parse(from_utc)>=Date.parse(to_utc))
    throw invalidExportField('account-export-through',tr("The through date must be on or after the from date."));
  const max_media_file_mib=Number($("account-export-file-limit").value);
  const max_total_gib=Number($("account-export-total-limit").value);
  if(!Number.isInteger(max_media_file_mib)||max_media_file_mib<1||max_media_file_mib>4096||
      !Number.isInteger(max_total_gib)||max_total_gib<1||max_total_gib>1024)
    throw new Error(tr("Enter a per-file limit of 1–4,096 MiB and a media budget of 1–1,024 GiB."));
  return {purpose,report_language:$('account-export-language').value,chat_kinds:kinds,from_utc,to_utc,chat_ids,sender_ids,text_contains,
    own_messages_only:$("account-export-own").checked,
    include_archived:$("account-export-archived").checked,
    media_types:[...$("account-export-media").querySelectorAll("input:checked")].map(n=>n.value),
    max_media_file_mib,max_total_gib,include_profile:$("account-export-profile").checked,
    include_contacts:$("account-export-contacts").checked,
    include_profile_photos:$("account-export-profile-photos").checked,
    include_stories:$("account-export-stories").checked,
    include_session_metadata:$("account-export-session-metadata").checked,
    include_other_data:$("account-export-other-data").checked,transport:$("account-export-transport").value};
}
function renderAccountExportPreview(){
  const box=$("account-export-preview");
  try{
    const x=accountExportOptions(),all=!x.chat_ids.length;
    const extras=[['include_profile',tr('Account profile')],['include_contacts',tr('Contacts')],
      ['include_profile_photos',tr('Profile photos')],['include_stories',tr('Stories')],
      ['include_session_metadata',tr('Session metadata')],['include_other_data',tr('Other available data')]];
    const other=extras.filter(([key])=>x[key]).map(([,label])=>label).join(', ')||tr('none');
    const transport=tr(x.transport==='regular'?'Regular session':'Telegram Takeout session');
    $('account-export-advanced-summary').textContent=other+' · '+transport;
    box.textContent=tr(all?"All accessible chats of {n} selected types, including Saved Messages when private chats are selected.":
      "{n} selected chat IDs of the chosen types.",{n:all?x.chat_kinds.length:x.chat_ids.length})+" "+
      tr(x.from_utc||x.to_utc?"Selected UTC dates apply to each chat.":"Full visible history, without a date limit.")+" "+
      tr("Media: {n} types, up to {file} MiB per file and {total} GiB downloaded media budget.",
        {n:x.media_types.length,file:x.max_media_file_mib,total:x.max_total_gib})+" "+
      tr("Sender filter: {senders}; literal phrases: {phrases}.",
        {senders:x.sender_ids.length||tr("all"),phrases:x.text_contains.length||tr("none")})+
      ' '+tr(x.own_messages_only?'Only messages sent by this account.':'Messages from all matching senders.')+
      ' '+tr(x.include_archived?'Archived chats included.':'Archived chats excluded.')+
      ' '+tr('Other account data: {data}. Connection method: {method}.',{data:other,method:transport})+
      ' '+tr('Report language: {language}.',{language:PANEL_LANGUAGES[x.report_language]||x.report_language})+
      (x.purpose?" "+tr("Purpose: {purpose}",{purpose:x.purpose}):" "+tr("Enter a collection purpose before starting."));
  }catch(error){box.textContent=error.message;$('account-export-advanced-summary').textContent=tr('Review export settings.');}
}
function accountExportPhase(phase){return tr({preparing:"Discovering chats",running:"Reading Telegram",waiting:"Waiting for Telegram",
  paused:"Paused — can resume",packaging:"Signing archive",done:"Finished",partial:"Partial — review omissions",
  failed:"Stopped with an error"}[phase]||phase||"Unknown");}
function accountExportTime(value){
  if(!value)return "";
  const date=new Date(accountExportEpochMs(value));
  return Number.isNaN(date.valueOf())?String(value):fmtTime(date);
}
window.addEventListener("tgwitness:time-zone",()=>{if(state.view==="evidence")renderAccountExportJobs();});
function accountExportEpochMs(value){return typeof value==="number"&&value<1e12?value*1000:value;}
function accountExportIds(value,label){
  const values=String(value||"").trim().split(/[\s,;]+/).filter(Boolean);
  const ids=[...new Set(values.map(raw=>{
    const id=Number(raw);
    if(!Number.isSafeInteger(id)||id===0)throw new Error(tr("Enter valid numeric {label} IDs, separated by commas or spaces.",{label}));
    return id;
  }))];
  if(ids.length>10000)throw new Error(tr("Select no more than 10,000 {label} IDs.",{label}));
  return ids;
}
function accountExportPhrases(value){
  const phrases=[...new Set(String(value||"").split(/\r?\n/).map(x=>x.trim()).filter(Boolean))];
  if(phrases.length>100||phrases.some(x=>x.length>200))
    throw new Error(tr("Use no more than 100 literal phrases, each up to 200 characters."));
  return phrases;
}
function accountExportDates(prefix){
  const from=$(prefix+"-from").value,through=$(prefix+"-through").value;
  const from_utc=from?from+"T00:00:00Z":null;
  const to_utc=through?new Date(Date.parse(through+"T00:00:00Z")+86400000).toISOString():null;
  if(from_utc&&to_utc&&Date.parse(from_utc)>=Date.parse(to_utc))
    throw new Error(tr("The through date must be on or after the from date."));
  return {from_utc,to_utc};
}
function renderAccountExportJobs(){
  const box=$("account-export-jobs"),focused=document.activeElement,
    action=focused?.dataset?.accountExportAction,jobId=focused?.dataset?.jobId;
  box.replaceChildren();
  const jobs=state.accountExportJobs;
  renderExportJobLink();
  if(!jobs.length){box.append(node("p","account-export-empty",tr("No account exports yet. Configure one to save the history this account can currently read.")));return;}
  const addAction=(parent,job,label,kind,work,cls="secondary")=>{
    const b=node("button",cls,label);b.type="button";b.dataset.accountExportAction=kind;b.dataset.jobId=job.id;
    b.addEventListener("click",()=>busy(b,work));parent.append(b);
  };
  for(const job of jobs){
    const phase=job.phase||"unknown",counts=job.counts||{},coverage=job.coverage||{};
    const card=node("article","account-export-job"),head=node("div","account-export-job-head");
    head.append(node("strong","",tr("Account export {id}",{id:String(job.id||"").slice(0,10)})),
      node("span","account-export-state "+phase,accountExportPhase(phase)));
    card.append(head);
    const when=accountExportTime(job.created_at);
    if(when)card.append(node("p","account-export-job-sub",tr("Started {time}",{time:when})));
    if(Number.isFinite(coverage.tasks_total)&&coverage.tasks_total>0){
      const bar=node("progress");bar.max=coverage.tasks_total;bar.value=Math.min(coverage.tasks_total,coverage.tasks_done||0);
      bar.setAttribute("aria-label",tr("Export tasks completed"));card.append(bar);
    }else if(["preparing","running","waiting","packaging"].includes(phase)&&job.active!==false){
      const bar=node("progress");bar.setAttribute("aria-label",tr("Export in progress"));card.append(bar);
    }
    const facts=node("div","account-export-metrics");
    const metric=(label,value)=>{if(Number.isFinite(value)){const item=node("span");item.append(label+": ",node("b","",value.toLocaleString()));facts.append(item);}};
    metric(tr("chats discovered"),counts.chats_discovered);
    metric(tr("chats selected"),counts.chats_selected);
    metric(tr("chats finished"),counts.chats_done);
    metric(tr("messages saved"),counts.messages_exported);
    metric(tr("media saved"),counts.media_saved);
    metric(tr("media skipped"),counts.media_skipped);
    if(Number.isFinite(counts.bytes_saved))metric(tr("bytes saved"),counts.bytes_saved);
    if(facts.childNodes.length)card.append(facts);
    const current=job.current_chat;
    if(current)card.append(node("p","account-export-job-note",tr("Current chat: {name}",
      {name:typeof current==="object"?(current.title||current.id||current.chat_id||tr("Unknown")):current})));
    if(job.wait_until)card.append(node("p","account-export-job-note warning",tr("Telegram asked this job to wait until {time}.",
      {time:accountExportTime(job.wait_until)})));
    else if(job.delay_seconds)card.append(node("p","account-export-job-note warning",tr("Telegram delay: {n} seconds.",{n:job.delay_seconds})));
    if(coverage.inventory_complete===false)card.append(node("p","account-export-job-note warning",
      tr("Chat inventory is still being read or was interrupted; this is not a complete account inventory.")));
    if(coverage.scope)card.append(node("p","account-export-job-note",tr("Coverage: {scope}",{scope:tr(coverage.scope)})));
    if(coverage.failures)card.append(node("p","account-export-job-note warning",
      tr("Coverage issues: {n}.",{n:Array.isArray(coverage.failures)?coverage.failures.length:coverage.failures})));
    const omissions=Array.isArray(job.omissions)?job.omissions:[];
    if(omissions.length){
      const details=node("details","account-export-omissions"),summary=node("summary","",tr("Omissions and unavailable data ({n})",{n:omissions.length}));
      const list=node("ul");for(const item of omissions.slice(0,100)){
        const description=typeof item==="string"?item:[item.section||item.chat_id||item.kind,item.reason||item.error||item.status].filter(Boolean).join(": ");
        list.append(node("li","",description||tr("Not available")));
      }
      if(omissions.length>100)list.append(node("li","",tr("More omissions are recorded in the signed archive.")));
      details.append(summary,list);card.append(details);
    }
    if(job.error)card.append(node("p","account-export-job-note error",tr("Job error: {error}",{error:job.error})));
    const actions=node("div","account-export-job-actions"),
      active=["preparing","running","waiting","packaging"].includes(phase)&&job.active!==false,
      waitPending=phase==="waiting"&&job.wait_until&&
        new Date(accountExportEpochMs(job.wait_until)).valueOf()>Date.now();
    if(active)addAction(actions,job,tr("Pause"),"pause",()=>accountExportAction(job,"pause"),"quiet");
    if(!job.ready&&(["paused","failed"].includes(phase)||(phase==="waiting"&&!active&&!waitPending)))
      addAction(actions,job,tr("Resume"),"resume",()=>accountExportAction(job,"resume"));
    if(job.ready)addAction(actions,job,tr("Download signed archive"),"download",()=>accountExportDownload(job),"primary");
    if(job.ready)addAction(actions,job,tr("Prepare a sharing copy"),"disclosure",()=>openAccountDisclosure(job));
    if(!active)addAction(actions,job,tr("Delete job"),"delete",()=>accountExportDelete(job),"quiet");
    card.append(actions);
    const saved=state.accountDisclosures[job.id]||[];
    const persisted=Array.isArray(job.disclosures)?job.disclosures:[];
    const disclosures=[...persisted,...saved.filter(local=>!persisted.some(item=>item.id===local.id))];
    if(disclosures.length){
      const derivatives=node("div","account-disclosure-list");
      derivatives.append(node("strong","",tr("Signed sharing copies")));
      for(const item of disclosures){
        const row=node("div","account-disclosure-item"),label=node("span","",tr("Disclosure {id}",{id:String(item.id||"").slice(0,10)}));
        row.append(label);
        if(item.ready){const button=node("button","quiet",tr("Download sharing copy"));button.type="button";
          button.dataset.accountExportAction="disclosure-download";button.dataset.jobId=job.id;
          button.addEventListener("click",()=>busy(button,()=>accountDisclosureDownload(job,item)));
          row.append(button);
        }else row.append(node("span","hint",tr("Preparing signed derivative")));
        derivatives.append(row);
      }
      card.append(derivatives);
    }
    box.append(card);
  }
  if(action&&jobId){const replacement=[...box.querySelectorAll("[data-account-export-action]")].find(n=>
    n.dataset.accountExportAction===action&&n.dataset.jobId===jobId);replacement?.focus({preventScroll:true});}
}
async function loadAccountExport(silent=false){
  if(!state.me?.admin||!viewAllowed("evidence"))return;
  if(silent&&accountExportRead?.revision===state.workspaceRevision&&accountExportRead.profile===state.profile)
    return accountExportRead.promise;
  const revision=state.workspaceRevision,profile=state.profile,request=++accountExportRequest;
  const pending=(async()=>{
    const result=await json("account-export");
    if(revision!==state.workspaceRevision||profile!==state.profile||request!==accountExportRequest)return;
    state.accountExportJobs=Array.isArray(result.jobs)?result.jobs:[];
    $('exports-account-error').textContent='';$('exports-account-error').hidden=true;
    state.accountExportDefaults=result.defaults||accountExportFallback;
    state.accountExportCapabilities=result.capabilities||{};
    if(state.accountExportDraftProfile!==profile&&!state.accountExportDirty)accountExportDefaults(state.accountExportDefaults);
    $("account-export-start").disabled=state.accountExportCapabilities.can_start===false||
      state.accountExportJobs.some(job=>["preparing","running","waiting","packaging"].includes(job.phase));
    $("account-export-status").textContent=state.status?.demo?
      tr("Demo account export uses fictional data only."):"";
    renderAccountExportJobs();
  })();
  accountExportRead={revision,profile,promise:pending};
  try{await pending;}finally{if(accountExportRead?.promise===pending)accountExportRead=null;}
}
async function accountExportAction(job,verb){
  await json("account-export/"+encodeURIComponent(job.id)+"/"+verb,{});
  await loadAccountExport();
}
async function accountExportDownload(job){
  if(!job.ready)throw new Error(tr("This account archive is not ready to download."));
  const name="tgwitness-account-export-"+String(job.id).replace(/[^a-zA-Z0-9_-]/g,"")+".zip";
  if(await download("account-export/"+encodeURIComponent(job.id)+"/download",name,true))
    toast(tr("Signed account archive saved. You can download it again from this job."));
}
async function accountExportDelete(job){
  if(!window.confirm(tr("Delete this account export job, its archive and its disclosures? This cannot be undone.")))return;
  await api("account-export/"+encodeURIComponent(job.id),undefined,{method:"DELETE"});
  delete state.accountDisclosures[job.id];
  await loadAccountExport();toast(tr("Account export job deleted."));
}
$("account-export-configure").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const profile=state.profile,revision=state.workspaceRevision,context=viewContexts.get('evidence');
  const current=()=>profile===state.profile&&revision===state.workspaceRevision&&state.me?.admin&&
    viewAllowed('evidence')&&state.view==='evidence'&&context?.current();
  if(!current())return;
  if(!state.status.demo&&!accountSignedIn()){
    state.workflow={profile:state.profile,kind:'account'};
    await navigate('connection');
    if(profile===state.profile&&revision===state.workspaceRevision&&state.view==='connection')setAuthStep('credentials');return;
  }
  await loadAccountExport();if(!current())return;$('account-export-dialog').showModal();
  $("account-export-dialog-title").focus?.();
}));
$("account-export-refresh").addEventListener("click",e=>busy(e.currentTarget,()=>loadAccountExport()));
$("account-export-close").addEventListener("click",()=>$("account-export-dialog").close());
$("account-export-dismiss").addEventListener("click",()=>$("account-export-dialog").close());
$("account-export-form").addEventListener("input",()=>{state.accountExportDirty=true;renderAccountExportPreview();});
$("account-export-form").addEventListener("change",()=>{state.accountExportDirty=true;renderAccountExportPreview();});
$("account-export-minimize").addEventListener("click",()=>{
  for(const input of $("account-export-media").querySelectorAll("input"))input.checked=false;
  for(const input of $("account-export-sections").querySelectorAll("input"))input.checked=false;
  state.accountExportDirty=true;renderAccountExportPreview();
});
$("account-export-form").addEventListener("submit",event=>{
  event.preventDefault();busy(event.submitter,async()=>{
    const options=accountExportOptions(),profile=state.profile,revision=state.workspaceRevision;
    if(!options.purpose){$("account-export-purpose").focus();throw new Error(tr("Enter a collection purpose."));}
    const job=await json("account-export/start",options);
    if(revision!==state.workspaceRevision||profile!==state.profile)return;
    state.accountExportDirty=false;$("account-export-dialog").close();
    await loadAccountExport();
    toast(tr("Account export started. Progress and omissions appear here; you can leave this page and return."));
    if(job?.id&&!state.accountExportJobs.some(x=>x.id===job.id)){
      state.accountExportJobs.unshift(job);renderAccountExportJobs();
    }
  });
});
let accountDisclosurePolicyRevision=0;
function accountDisclosurePolicy(){
  const purpose=$("account-disclosure-purpose").value.trim();
  if(!purpose)throw new Error(tr("Enter a disclosure purpose."));
  const identity_mode=$("account-disclosure-identities").value;
  return {purpose,report_language:$('account-disclosure-language').value,...accountExportDates("account-disclosure"),
    sender_ids:accountExportIds($("account-disclosure-senders").value,"sender"),
    text_contains:accountExportPhrases($("account-disclosure-phrases").value),
    redact_terms:accountExportPhrases($("account-disclosure-redact-terms").value),
    identity_mode,
    disclose_user_ids:identity_mode==="pseudonymize_third_parties"?
      accountExportIds($("account-disclosure-disclose-ids").value,"disclosed user"):[],
    text_mode:$("account-disclosure-text-mode").value,
    include_media:$("account-disclosure-media").checked,
    include_contacts:false,include_profile:false,include_profile_photos:false,
    include_stories:false,include_session_metadata:false,include_other_data:false};
}
function accountDisclosureInvalidate(){
  accountDisclosurePolicyRevision++;
  state.accountDisclosurePreview=null;state.accountDisclosureDirty=true;
  $("account-disclosure-create").disabled=true;
  disclosurePreview?.clear();
  $("account-disclosure-status").textContent=tr("Settings changed. Preview again before creating a signed derivative.");
}
function openAccountDisclosure(job){
  if(!job.ready)throw new Error(tr("Finish the source archive before preparing a disclosure."));
  if(state.accountDisclosureJob!==job.id){
    if(state.accountDisclosureDirty&&!window.confirm(tr("Discard the unfinished disclosure settings?")))return;
    $("account-disclosure-form").reset();
    state.accountDisclosureJob=job.id;state.accountDisclosureDirty=false;
    accountDisclosureInvalidate();state.accountDisclosureDirty=false;
    $("account-disclosure-status").textContent=tr("Preview is required after every change to these settings.");
  }
  $("account-disclosure-disclose-ids").disabled=$("account-disclosure-identities").value!=="pseudonymize_third_parties";
  $("account-disclosure-dialog").showModal();
  $("account-disclosure-purpose").focus();
}
function renderAccountDisclosurePreview(result){
  disclosurePreview.render(result);
}
async function previewAccountDisclosure(){
  const jobId=state.accountDisclosureJob,profile=state.profile,revision=state.workspaceRevision;
  const policyRevision=accountDisclosurePolicyRevision,policy=accountDisclosurePolicy();
  $("account-disclosure-status").textContent=tr("Preparing transformed preview…");
  const result=await json("account-export/"+encodeURIComponent(jobId)+"/disclosure/preview",policy);
  if(profile!==state.profile||revision!==state.workspaceRevision||jobId!==state.accountDisclosureJob||
      policyRevision!==accountDisclosurePolicyRevision)return;
  if(!result?.preview_id)throw new Error(tr("Disclosure preview did not return an approval ID."));
  state.accountDisclosurePreview={id:result.preview_id,jobId,profile,revision,policyRevision,expires_at:result.expires_at};
  renderAccountDisclosurePreview(result);
  $("account-disclosure-status").textContent=tr("Review the transformed sample and remaining privacy warnings, then confirm creation.");
  $("account-disclosure-create").disabled=false;
}
async function createAccountDisclosure(){
  const approved=state.accountDisclosurePreview;
  if(!approved||approved.jobId!==state.accountDisclosureJob||approved.profile!==state.profile||
      approved.revision!==state.workspaceRevision||approved.policyRevision!==accountDisclosurePolicyRevision)
    throw new Error(tr("Preview the current disclosure settings before creating a file."));
  if(approved.expires_at&&Date.now()>=new Date(accountExportEpochMs(approved.expires_at)).valueOf()){
    accountDisclosureInvalidate();throw new Error(tr("The disclosure preview expired. Preview the settings again."));
  }
  if(!window.confirm(tr("Create a signed derivative from this preview? Personal information may still remain; review the file before sharing.")))return;
  const jobId=approved.jobId,profile=approved.profile,revision=approved.revision;
  const result=await json("account-export/"+encodeURIComponent(jobId)+"/disclosure",{preview_id:approved.id});
  if(profile!==state.profile||revision!==state.workspaceRevision||jobId!==state.accountDisclosureJob)return;
  if(!result?.id)throw new Error(tr("Disclosure creation did not return a derivative ID."));
  (state.accountDisclosures[jobId]??=[]).unshift(result);
  state.accountDisclosureDirty=false;state.accountDisclosurePreview=null;
  $("account-disclosure-create").disabled=true;$("account-disclosure-dialog").close();
  await loadAccountExport();
  toast(tr("Signed minimized disclosure created. Review the downloaded file before sharing."));
}
async function accountDisclosureDownload(job,item){
  if(!item.ready)throw new Error(tr("This disclosure is still being prepared."));
  const safeId=String(item.id).replace(/[^a-zA-Z0-9_-]/g,"");
  const path="account-export/"+encodeURIComponent(job.id)+"/disclosures/"+encodeURIComponent(item.id)+"/download";
  if(await download(path,"tgwitness-disclosure-"+safeId+".zip",true))
    toast(tr("Signed disclosure saved. Review it before sharing."));
}
$("account-disclosure-form").addEventListener("input",accountDisclosureInvalidate);
$("account-disclosure-form").addEventListener("change",accountDisclosureInvalidate);
$("account-disclosure-identities").addEventListener("change",()=>{
  $("account-disclosure-disclose-ids").disabled=$("account-disclosure-identities").value!=="pseudonymize_third_parties";
});
$("account-disclosure-close").addEventListener("click",()=>$("account-disclosure-dialog").close());
$("account-disclosure-dismiss").addEventListener("click",()=>$("account-disclosure-dialog").close());
$("account-disclosure-check").addEventListener("click",event=>busy(event.currentTarget,previewAccountDisclosure));
$("account-disclosure-form").addEventListener("submit",event=>{
  event.preventDefault();busy(event.submitter,createAccountDisclosure);
});
let exportsView=null;
const exportsReady=import('./views/exports.js').then(({createExports})=>{
  exportsView=createExports({root:$("view-evidence"),tr,json,getSession:()=>state.workspaceRevision+":"+state.profile,fmtTime,toast});
  return exportsView;
});
async function loadExports(){return (await exportsReady).enter(viewOptions('evidence'));}
async function download(path,filename,stream=false,root=false,body=undefined,progress=()=>{}){
  const profile=state.profile;
  let handle=null,writer=null,reader=null;
  if(stream&&typeof window.showSaveFilePicker==="function"){
    try{handle=await window.showSaveFilePicker({suggestedName:filename});}
    catch(error){if(error.name==="AbortError"){progress({phase:"cancelled"});return false;}throw error;}
  }
  const response=await api(path,body,root?{root:true,allowStale:true}:{profile,allowStale:true});
  const expected=Number(response.headers.get("Content-Length")||0);
  const limit=(state.status?.parameters?.browser_buffer_mib||128)*1024*1024;
  try{
    if(!handle&&expected>limit)throw new Error(tr("This browser cannot stream this large export to a file. Use the streaming download command in the local setup guide."));
    reader=response.body.getReader();
    if(handle)writer=await handle.createWritable();
    let total=0;const chunks=[];
    while(true){
      const {value,done}=await reader.read();if(done)break;
      total+=value.byteLength;
      if(writer)await writer.write(value);
      else{if(total>limit)throw new Error(tr("Browser download limit reached. Use the streaming download command."));chunks.push(value);}
      progress({phase:"saving",total,expected});
      if(stream){const size=(total/1024**2).toFixed(1)+" MiB"+(expected?" / "+(expected/1024**2).toFixed(1)+" MiB":"");toast(tr("Saving export: {size}",{size}));}
    }
    if(expected&&total!==expected)throw new Error(tr("Download was interrupted. Retry the export."));
    if(writer){await writer.close();writer=null;}
    else saveBlob(new Blob(chunks,{type:response.headers.get("Content-Type")||"application/octet-stream"}),filename);
    progress({phase:"done",total,expected});return true;
  }catch(error){
    if(reader)await reader.cancel().catch(()=>{});else await response.body.cancel().catch(()=>{});
    if(writer)await writer.abort().catch(()=>{});
    throw error;
  }
}
function saveBlob(blob,filename){
  const url=URL.createObjectURL(blob),a=node("a");a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
}
panelQueries("[data-export]").forEach(b=>b.addEventListener("click",()=>busy(b,async()=>{
  const fmt=b.dataset.export,password=$("export-password").value;
  const encrypt=!!b.closest("#view-evidence")&&$("export-encrypt-on").checked;
  if(encrypt&&password.length<12){$("export-password").focus();throw new Error(tr("Enter a password of at least 12 characters, or untick encryption."));}
  const progress=(await exportsReady).begin();
  try{
    const saved=await download("export/"+fmt,encrypt?"tgwitness-evidence-"+fmt+"-encrypted.zip":"tgwitness-evidence."+fmt,true,false,encrypt?{password}:undefined,progress);
    if(saved)toast(tr(encrypt?"Encrypted export saved. Open it in 7-Zip or WinRAR with the password; the signed file inside is unchanged.":"Evidence export saved."));
  }catch(error){progress({phase:"failed",error:error.message});throw error;}
})));
// Report settings: language, case details and contents of the sealed report in every export.
const REPORT_FIELDS={"report-language":"language","report-theme":"theme","report-case-title":"case_title",
  "report-case-id":"case_id","report-examiner":"examiner","report-organization":"organization","report-notes":"notes"};
const REPORT_CHECKS={"report-timeline":"timeline","report-raw":"raw_records","report-media":"media_previews"};
let reportOwner=null,reportReady=false,reportDirty=false,reportRequest=0,reportLoading=null,reportSaving=false;
const reportKey=()=>state.workspaceRevision+":"+state.profile;
function resetReportSettings(){
  reportOwner=null;reportReady=false;reportDirty=false;reportRequest++;reportLoading=null;reportSaving=false;
  $("report-form").reset();$("report-fields").disabled=true;$("report-status").replaceChildren();
  $("report-form").querySelectorAll(".form-error").forEach(el=>el.remove());
}
function reportControls(){
  $("report-fields").disabled=!reportReady||reportOwner!==reportKey()||reportSaving||!!window.TGW_ONLINE_DEMO;
  syncReportParts();
}
async function loadReportSettings(){
  if(!state.status)return;
  const owner=reportKey();
  if(reportOwner!==owner){resetReportSettings();reportOwner=owner;}
  if(reportSaving||reportReady&&reportDirty)return;
  if(reportLoading)return reportLoading;
  const request=++reportRequest,current=()=>reportOwner===owner&&reportKey()===owner&&request===reportRequest;
  reportReady=false;reportControls();$("report-status").textContent=tr("Loading…");
  const pending=(async()=>{
    try{
      const options=await json("report-options",undefined,viewOptions('evidence'));if(!current()||state.view!=='evidence')return;
      const select=$("report-language");
      if(!select.options.length){
        select.append(new Option(tr("Same as the panel"),"auto"));
        for(const [code,name] of Object.entries(PANEL_LANGUAGES)){const o=new Option(name,code);o.lang=code;select.append(o);}
      }
      for(const [id,key] of Object.entries(REPORT_FIELDS))$(id).value=options[key];
      for(const [id,key] of Object.entries(REPORT_CHECKS))$(id).checked=options[key];
      reportReady=true;reportDirty=false;formControls?.loaded("report-form");$("report-status").textContent=window.TGW_ONLINE_DEMO?tr("Sample data"):"";
    }catch(error){
      if(!current()||error instanceof StaleView||error.name==='AbortError')return;
      const retry=node("button","text-link",tr("Retry"));retry.type="button";
      retry.addEventListener("click",()=>loadReportSettings());
      $("report-status").replaceChildren(node("span","",tr("Could not load data")+": "+error.message+" "),retry);
    }finally{if(current())reportControls();}
  })();
  reportLoading=pending;
  try{await pending;}finally{if(reportLoading===pending)reportLoading=null;}
}
function syncReportParts(){$("report-raw").disabled=$("report-media").disabled=!$("report-timeline").checked;}
$("report-timeline").addEventListener("change",syncReportParts);
$("report-form").addEventListener("input",()=>{if(reportReady){reportDirty=true;$("report-status").replaceChildren();}});
$("report-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  if(!reportReady||reportOwner!==reportKey()||reportSaving||window.TGW_ONLINE_DEMO)return;
  const owner=reportOwner,draft=formControls?.capture("report-form");
  const body={};
  for(const [id,key] of Object.entries(REPORT_FIELDS))body[key]=$(id).value;
  for(const [id,key] of Object.entries(REPORT_CHECKS))body[key]=$(id).checked;
  reportSaving=true;reportControls();
  try{
    await json("report-options",body);if(reportOwner!==owner||reportKey()!==owner)return;
    reportDirty=formControls?.changed(draft)||false;formControls?.accepted(draft,reportDirty);$("report-status").textContent=tr(reportDirty?"Saved. New edits have not been saved.":"Saved. The next export uses these settings.");toast(tr("Report settings saved."));
  }finally{if(reportOwner===owner&&reportKey()===owner){reportSaving=false;reportControls();}}
});});
panelQueries("[data-go-reports]").forEach(link=>link.addEventListener("click",event=>{
  event.preventDefault();navigate("evidence");exportsReady.then(view=>{view.select("settings");$("report-form").scrollIntoView({block:"start"});});
}));
$("export-encrypt-on").addEventListener("change",()=>{
  const on=$("export-encrypt-on").checked;show("export-password-field",on);if(on)$("export-password").focus();else $("export-password").value="";
});
$("save-checkpoint").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const checkpoint=await json("checkpoint");saveBlob(new Blob([JSON.stringify(checkpoint,null,2)],{type:"application/json"}),"tgwitness-checkpoint.json");
  toast(tr("Checkpoint downloaded. Retain it outside the collector."));
}));
$("save-run-receipt").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const receipt=await json("run-receipt");saveBlob(new Blob([JSON.stringify(receipt,null,2)],{type:"application/json"}),"tgwitness-run-receipt.json");
  toast(tr("Signed acquisition process receipt downloaded."));
}));
$("save-anchor-request").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await download("anchor-request","tgwitness-timestamp-request.zip");
  toast(tr("Timestamp request prepared. No external timestamp authority has been contacted."));
}));
async function loadEvidence(){
  if(!state.status)return;
  if(state.status.demo){renderEvidence(null);return;}
  const profile=state.profile,e=await json("evidence");
  if(profile===state.profile)renderEvidence(e);
}
const hostOf=url=>{try{return new URL(url).hostname;}catch{return url;}};
// A state with its reason first, then the facts behind it (health.py).
function renderHealthDetail(box,item,lead,facts){
  const head=node("p","health-lead");head.append(stateBadge(item.state),node("span","",lead));
  box.replaceChildren(head,...facts.filter(Boolean).map(text=>node("p","",text)));
}
function timestampsLead(h){
  switch(h.reason){
    case "disabled":return tr("Off — checkpoints stay on this machine only.");
    case "route":return tr(h.route_problem);
    case "sending":return tr("Sending the checkpoint hash to timestamp services…");
    case "loop_error":return tr("The timestamp pass stopped with an error: {error}",{error:h.error});
    case "first_pending":return tr("On — the first checkpoint will be anchored within a minute.");
    case "no_checkpoint":return tr("No checkpoint to timestamp yet.");
    case "stale":return tr("No timestamp pass for longer than the interval; the current state is unknown.");
    case "up_to_date":return tr("Every service has already answered for the latest checkpoint.");
    case "no_answer":return tr("No timestamp service answered for the latest checkpoint.");
    case "partial":return tr("Some timestamp services did not answer for the latest checkpoint.");
    case "unverified":return tr("Only OpenTimestamps proofs were received; no RFC 3161 timestamp was verified.");
    default:return tr("The latest checkpoint is timestamped.");
  }
}
// An answer that arrived is not yet a verified timestamp; an OpenTimestamps proof waits for Bitcoin.
function timestampsFacts(e,h){
  if(!e.settings.enabled)return [];
  const c=h.counts,l=e.last,facts=[];
  if(l?.checkpoint)facts.push(tr("Latest checkpoint ({n} records): verified timestamps {verified} · OpenTimestamps proofs awaiting confirmation {pending} · answers rejected by the checks {rejected} · no answer {unreachable}",
    {n:l.checkpoint.event_count.toLocaleString(),verified:c.verified+c.covered_verified,
     pending:c.ots_pending+c.ots_bitcoin_unverified+c.covered-c.covered_verified,rejected:c.rejected,unreachable:c.unreachable}));
  const tsa=(l?.results||[]).filter(r=>r.ok&&r.kind==="rfc3161").map(r=>hostOf(r.service)+(r.time?" ("+fmtFull(r.time)+")":""));
  if(tsa.length)facts.push(tr("Timestamped by {list}. ",{list:tsa.join(", ")}).trim());
  const attempts=[h.last_attempt_at,h.last_pass_at].filter(Boolean).sort();
  facts.push(tr("Last attempt: {time}",{time:when(attempts.at(-1))}));
  facts.push(tr("Last verified timestamp: {time}",{time:when(h.last_verified_at)}));
  if(h.last_failure)facts.push(tr("Last failure, {time}: {list}",{time:fmtFull(h.last_failure.at),
    list:h.last_failure.errors.map(r=>hostOf(r.service)+" — "+r.error).join("; ")}));
  if(h.next_attempt_at)facts.push(tr("Next attempt: {time}",{time:fmtFull(h.next_attempt_at)}));
  return facts;
}
function renderEvidence(e){
  if(state.view!=='witness')return;
  const form=$("evidence-form"),status=$("evidence-status");
  form.querySelectorAll("input,select,textarea,button").forEach(n=>n.disabled=!e);
  state.timestampsHealth=e?.health||null;renderEvidenceBadge();
  if(!e){status.textContent=tr("Evidence mode works in a real workspace, not in the demo.");return;}
  if(state.evidenceProfile!==state.profile){state.evidenceDirty=false;state.evidenceProfile=state.profile;}
  if(!state.evidenceDirty){
    $("evidence-enabled").checked=e.settings.enabled;$("evidence-interval").value=String(e.settings.interval_minutes);
    $("evidence-tsa").value=e.settings.tsa_urls.join("\n");$("evidence-ots").value=e.settings.ots_calendars.join("\n");formControls?.loaded("evidence-form");
  }
  $("evidence-anchor").disabled=!e.settings.enabled||e.busy;
  renderHealthDetail(status,e.health,timestampsLead(e.health),timestampsFacts(e,e.health));
}
$("evidence-form").addEventListener("input",()=>{state.evidenceDirty=true;});
$("evidence-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const draft=formControls?.capture("evidence-form");
  const lines=id=>$(id).value.split("\n").map(v=>v.trim()).filter(Boolean);
  const e=await json("evidence",{enabled:$("evidence-enabled").checked,interval_minutes:Number($("evidence-interval").value),
    tsa_urls:lines("evidence-tsa"),ots_calendars:lines("evidence-ots")});
  state.evidenceDirty=formControls?.changed(draft)||false;renderEvidence(e);formControls?.accepted(draft,state.evidenceDirty);
  toast(tr(e.settings.enabled?"Evidence mode is on. The current checkpoint is being timestamped.":"Evidence mode is off."));
});});
$("evidence-anchor").addEventListener("click",ev=>busy(ev.currentTarget,async()=>{
  renderEvidence(await json("evidence/anchor",{}));toast(tr("A fresh checkpoint is being timestamped."));
}));
async function loadReplica(){
  if(!state.status)return;
  if(state.status.demo){renderReplica(null);return;}
  const profile=state.profile,r=await json("replica");
  if(profile===state.profile)renderReplica(r);
}
function replicaLead(r,h){
  switch(h.reason){
    case "disabled":return tr(r.has_credentials?"Off.":"Off — enter your storage details to keep a copy away from this machine.");
    case "route":return tr(h.route_problem);
    case "copying":return tr("Copying…");
    case "loop_error":case "error":return tr("Stopped: {error} — retried on the next pass.",{error:h.error});
    case "first_pending":return tr("The first copy starts within a minute.");
    case "stale":return tr("No copy pass for longer than the interval; the current state is unknown.");
    default:return tr("The last copy pass finished without errors.");
  }
}
function replicaFacts(r,h){
  const s=r.settings,l=r.last;if(!s.enabled)return [];
  return [tr("Copies to {bucket}/{location}. ",{bucket:s.bucket,location:r.location}).trim(),
    l&&tr("Last pass {time}: {n} object(s), {size}; journal copied up to record {seq}.",{time:fmtFull(l.at),n:l.objects,
      size:humanSize(l.bytes),seq:(l.journal_seq||0).toLocaleString()}),
    tr("Last successful copy: {time}",{time:when(h.last_success_at)}),
    h.lag_records!=null&&tr("Journal records not yet copied: {lag} of {head}.",{lag:h.lag_records.toLocaleString(),head:(h.head_seq||0).toLocaleString()}),
    h.next_attempt_at&&tr("Next attempt: {time}",{time:fmtFull(h.next_attempt_at)}),
    l?.object_lock&&lockText(l.object_lock)];
}

function lockText(lock){
  if(lock.verified===true)return tr("Object Lock confirmed on an uploaded object: {mode} until {until}.",{mode:lock.object.mode,until:fmtFull(lock.object.retain_until)});
  if(lock.verified===false)return tr("Object Lock is NOT applied by this storage: uploaded objects can be deleted or overwritten. Enable Object Lock on the bucket or use another provider.");
  return lock.bucket_enabled?tr("Object Lock is enabled on the bucket; no retention was requested."):tr("Object Lock is not enabled on this bucket.");
}
function renderReplica(r){
  if(state.view!=='witness')return;
  const form=$("replica-form"),status=$("replica-status");
  form.querySelectorAll("input,select,button").forEach(n=>n.disabled=!r);
  state.replicaHealth=r?.health||null;renderEvidenceBadge();
  if(!r){status.textContent=tr("The off-site copy works in a real workspace, not in the demo.");return;}
  if(state.replicaProfile!==state.profile){state.replicaDirty=false;state.replicaProfile=state.profile;}
  const s=r.settings;
  if(!state.replicaDirty){
    $("replica-enabled").checked=s.enabled;$("replica-endpoint").value=s.endpoint;$("replica-region").value=s.region;
    $("replica-bucket").value=s.bucket;$("replica-prefix").value=s.prefix;$("replica-path-style").checked=s.path_style;
    $("replica-interval").value=String(s.interval_minutes);$("replica-retention").value=String(s.retention_days);
    $("replica-mode").value=s.retention_mode;formControls?.loaded("replica-form");
  }
  for(const id of ["replica-access","replica-secret"])$(id).placeholder=r.has_credentials?tr("Saved — leave empty to keep"):"";
  $("replica-test").disabled=!r.has_credentials;$("replica-sync").disabled=!s.enabled||r.busy;$("replica-key").disabled=!r.has_key;
  renderHealthDetail(status,r.health,replicaLead(r,r.health),replicaFacts(r,r.health));
}
$("replica-form").addEventListener("input",()=>{state.replicaDirty=true;});
$("replica-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const draft=formControls?.capture("replica-form");
  const r=await json("replica",{enabled:$("replica-enabled").checked,endpoint:$("replica-endpoint").value.trim(),
    region:$("replica-region").value.trim()||"us-east-1",bucket:$("replica-bucket").value.trim(),prefix:$("replica-prefix").value.trim()||"tgwitness",
    path_style:$("replica-path-style").checked,interval_minutes:Number($("replica-interval").value),
    retention_days:Number($("replica-retention").value||0),retention_mode:$("replica-mode").value,
    access_key:$("replica-access").value.trim(),secret_key:$("replica-secret").value.trim()});
  formControls?.clearSubmitted(draft,["replica-access","replica-secret"]);
  state.replicaDirty=formControls?.changed(draft)||false;renderReplica(r);formControls?.accepted(draft,state.replicaDirty);
  toast(tr(r.settings.enabled?"Off-site copy is on. Download the encryption key and keep it apart.":"Off-site copy settings saved."));
});});
$("replica-test").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const r=await json("replica/test",{});
  toast(tr("The storage accepted an encrypted test object.")+(r.object_lock?" "+lockText(r.object_lock):""),r.object_lock?.verified===false);
}));
$("replica-sync").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  renderReplica(await json("replica/sync",{}));toast(tr("Copying now."));
}));
$("replica-key").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  if(await download("replica/key","tgwitness-replica-key.json"))toast(tr("Encryption key saved. Keep it apart from this computer."));
}));
async function loadAlerts(){
  if(!state.status)return;
  if(state.status.demo){renderAlerts(null);return;}
  const profile=state.profile,a=await json("alerts");
  if(profile===state.profile)renderAlerts(a);
}
function alertsText(a){
  const s=a.settings,l=a.last;
  if(!s.enabled)return tr(a.destinations.length?"Off.":"Off — add a destination to receive alerts.");
  if(a.route_problem)return tr(a.route_problem);
  if(!l)return tr("On. Nothing has needed a notification yet.");
  return tr("Last notification {time}.",{time:fmtFull(l.at)})+(l.error?" "+tr("Not delivered: {error} — retried within a minute.",{error:l.error}):"");
}
function renderAlerts(a){
  if(state.view!=='witness')return;
  const form=$("alerts-form"),status=$("alerts-status");
  form.querySelectorAll("input,select,textarea,button").forEach(n=>n.disabled=!a);
  extraBadge("alerts",!!a?.settings.enabled,"On","Off");
  if(!a){status.textContent=tr("Notifications work in a real workspace, not in the demo.");return;}
  if(state.alertsProfile!==state.profile){state.alertsDirty=false;state.alertsProfile=state.profile;}
  const s=a.settings;
  if(!state.alertsDirty){
    $("alerts-enabled").checked=s.enabled;$("alerts-problems").checked=s.problems;$("alerts-changes").checked=s.changes;
    $("alerts-text").checked=!!s.include_text;
    $("alerts-daily").checked=s.daily;$("alerts-hour").value=String(s.daily_hour);formControls?.loaded("alerts-form");
  }
  $("alerts-urls").placeholder=a.destinations.length?tr("Leave empty to keep the saved destinations"):"matrixs://user:password@matrix.example.org/#room";
  $("alerts-saved").textContent=a.destinations.length?tr("Saved: {list}",{list:a.destinations.join(" · ")}):"";
  $("alerts-test").disabled=$("alerts-clear").disabled=!a.destinations.length;
  status.textContent=alertsText(a);
}
for(let h=0;h<24;h++)$("alerts-hour").append(new Option(String(h).padStart(2,"0")+":00",String(h)));
$("alerts-form").addEventListener("input",()=>{state.alertsDirty=true;});
async function saveAlerts(urls,add=[]){
  const draft=formControls?.capture("alerts-form");
  const a=await json("alerts",{enabled:$("alerts-enabled").checked,problems:$("alerts-problems").checked,changes:$("alerts-changes").checked,
    daily:$("alerts-daily").checked,daily_hour:Number($("alerts-hour").value),language:LANG,include_text:$("alerts-text").checked,urls,add_urls:add});
  formControls?.clearSubmitted(draft,["alerts-urls"]);state.alertsDirty=formControls?.changed(draft)||false;renderAlerts(a);formControls?.accepted(draft,state.alertsDirty);return a;
}
$("alerts-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const lines=$("alerts-urls").value.split("\n").map(v=>v.trim()).filter(Boolean);
  const a=await saveAlerts(lines.length?lines:null);
  toast(tr(a.settings.enabled?"Notifications are on.":"Notification settings saved."));
});});
$("alerts-test").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await json("alerts/test",{});toast(tr("Test notification delivered."));
}));
$("alerts-clear").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  if(!window.confirm(tr("Remove every saved destination and turn notifications off?")))return;
  $("alerts-enabled").checked=false;await saveAlerts([]);toast(tr("Destinations removed. Notifications are off."));
}));

const ALERT_SERVICES={
  tgram:{fields:[["token","Bot token from @BotFather","123456789:AA…"],
    ["chat","Chat ID · optional: empty sends to whoever last pressed Start in the bot","-1001234567890",true]],
    hint:"Open the bot in Telegram and press Start, or add it to your group or channel, before adding it here.",
    url:v=>/^\d+:[\w-]+$/.test(v.token)&&"tgram://"+v.token+"/"+(v.chat?encodeURIComponent(v.chat):"")},
  discord:{fields:[["webhook","Webhook URL: channel settings → Integrations → Webhooks","https://discord.com/api/webhooks/…"]],
    url:v=>{const m=/\/webhooks\/(\d+)\/([\w-]+)/.exec(v.webhook);return m&&"discord://"+m[1]+"/"+m[2];}},
  slack:{fields:[["webhook","Incoming webhook URL","https://hooks.slack.com/services/…"]],
    url:v=>{const m=/hooks\.slack\.com\/services\/(\w+)\/(\w+)\/(\w+)/.exec(v.webhook);return m&&"slack://"+m.slice(1).join("/");}},
  ntfy:{fields:[["topic","Topic: a long name nobody can guess","tgwitness-7f3k2q9x"],["server","Own ntfy server · optional","ntfy.example.org",true]],
    hint:"Subscribe to the same topic in the ntfy app on your phone.",
    url:v=>/^[\w-]+$/.test(v.topic)&&"ntfys://"+(v.server?v.server.replace(/^https?:\/\//,"").replace(/\/+$/,"")+"/":"")+v.topic},
  mailto:{fields:[["address","Your email address","you@gmail.com"],["password","App password, not the account password",""],
    ["to","Send to · optional, yourself by default","",true]],
    hint:"Gmail, Outlook, Yahoo, Fastmail and similar mailboxes are set up automatically; for others use an Apprise address.",
    url:v=>{const at=v.address.lastIndexOf("@");return at>0&&"mailto://"+encodeURIComponent(v.address.slice(0,at))+":"+
      encodeURIComponent(v.password)+"@"+v.address.slice(at+1)+(v.to?"?to="+encodeURIComponent(v.to):"");}},
};
function renderAlertService(){
  const service=ALERT_SERVICES[$("alerts-service").value],box=$("alerts-service-fields");
  box.replaceChildren();show("alerts-service-fields",!!service);show("alerts-service-add",!!service);
  if(!service)return;
  for(const [key,label,placeholder,optional] of service.fields){
    const input=node("input");input.id="alerts-field-"+key;input.dataset.key=key;input.placeholder=placeholder;
    input.spellcheck=false;input.autocomplete="off";input.required=!optional;
    if(key==="token"||key==="password")input.type="password";
    const name=node("label",null,tr(label));name.htmlFor=input.id;box.append(name,input);
  }
  if(service.hint)box.append(node("p","hint",tr(service.hint)));
}
$("alerts-service").addEventListener("change",renderAlertService);
$("alerts-service-add").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const service=ALERT_SERVICES[$("alerts-service").value],values={};
  for(const input of $("alerts-service-fields").querySelectorAll("input")){
    values[input.dataset.key]=input.value.trim();
    if(input.required&&!values[input.dataset.key]){input.focus();throw new Error(tr("Fill in: {field}",{field:input.labels[0].textContent}));}
  }
  const url=service.url(values);
  if(!url)throw new Error(tr("This does not look like what the service gives you. Check it and try again."));
  const lines=$("alerts-urls").value.split("\n").map(v=>v.trim()).filter(Boolean);
  $("alerts-enabled").checked=true;await saveAlerts(lines.length?lines:null,[url]);
  $("alerts-service").value="";renderAlertService();
  try{await json("alerts/test",{});toast(tr("Destination added and notifications are on. A test notification was sent."));}
  catch(err){if(err instanceof StaleView)return;toast(tr("Destination added, but the test notification failed: {error}",{error:err.message}),true);}
}));

const scopeName=mode=>tr({selected:"Chosen chats",folder:"Telegram folder",account:"Whole account"}[mode]||"Chosen chats");
const scopeTypes=["channels","groups","private","bots"];

const wideWarning=()=>tr("Folder and whole-account modes record private chats and messages of third parties. Use them only on a dedicated account, for a lawful purpose, and keep the data protected.");
async function loadScope(){
  if(!state.status)return;
  if(state.status.demo){
    state.scope={settings:state.status.scope,recheck:state.status.recheck,folders:[],warning:wideWarning()};
    if(state.view==="sources")renderScope();return;
  }
  const revision=state.workspaceRevision,profile=state.profile,r=await json("scope");
  if(revision!==state.workspaceRevision||profile!==state.profile)return;
  state.scope={...r,folders:r.folders.length?r.folders:(state.scope?.folders||[])};
  if(state.view==="sources")renderScope();
}
function scopeDraft(){
  const mode=viewQuery("sources","[name=scope-mode]:checked")?.value||"selected",folder=$("scope-folder").value;
  return {mode,folder_id:mode==="folder"&&folder!==""?Number(folder):null,
    types:Object.fromEntries(scopeTypes.map(k=>[k,$("scope-"+k).checked])),exclude:state.scopeExclude||[],own_actions:$("scope-own").checked,
    new_chats:{profile:$("scope-new-profile").checked,history:Math.max(0,Math.min(1000,Math.floor(Number($("scope-new-history").value)||0)))}};
}

$("scope-investigation").addEventListener("click",()=>{
  viewQueries("sources","[name=scope-mode]").forEach(r=>{r.checked=r.value==="account";});
  for(const k of scopeTypes)$("scope-"+k).checked=true;
  $("scope-own").checked=true;$("scope-new-profile").checked=true;
  if(Number($("scope-new-history").value)<200)$("scope-new-history").value="200";
  state.scopeDirty=true;renderScope();$("scope-form").querySelector("button[type=submit]").focus();
});
function chatTitle(id){
  return state.status?.targets.find(t=>t.chat_id===id)?.title||state.dialogs.find(d=>d.chat_id===id)?.title||tr("Chat {id}",{id});
}
function renderScope(){
  const form=$("scope-form"),sc=state.scope,demo=!!state.status?.demo;
  form.querySelectorAll("input,select,button").forEach(n=>n.disabled=demo||!sc);
  if(!sc){$("scope-unsaved").textContent=demo?tr("The scope can be changed in a real workspace, not in the demo."):"";return;}
  const saved=sc.settings,select=$("scope-folder");
  if(!state.scopeDirty){
    form.querySelectorAll("[name=scope-mode]").forEach(r=>{r.checked=r.value===saved.mode;});
    for(const k of scopeTypes)$("scope-"+k).checked=saved.types[k];
    $("scope-own").checked=saved.own_actions;state.scopeExclude=[...saved.exclude];
    $("scope-new-profile").checked=!!saved.new_chats?.profile;$("scope-new-history").value=String(saved.new_chats?.history||0);
  }
  const chosen=state.scopeDirty?select.value:String(saved.folder_id??"");
  select.replaceChildren(new Option(tr("Choose a folder"),""));
  for(const f of sc.folders)select.append(new Option(f.title||tr("Folder {id}",{id:f.id}),String(f.id)));
  if(saved.folder_id!==null&&!sc.folders.some(f=>f.id===saved.folder_id))select.append(new Option(tr("Folder {id}",{id:saved.folder_id}),String(saved.folder_id)));
  select.value=chosen;
  $("scope-folder-hint").textContent=tr(sc.folders.length?"Chats added to this folder in Telegram are picked up within an hour; new chats that match its rules at once.":
    "Press Refresh chat list above to list this account's folders.");
  const draft=scopeDraft();
  show("scope-folder-field",draft.mode==="folder");show("scope-types",draft.mode!=="selected");show("scope-new",draft.mode!=="selected");
  const box=$("scope-exclude");box.replaceChildren();
  if(state.scopeExclude.length){
    box.append(node("strong","",tr("Excluded chats")));
    for(const id of state.scopeExclude){
      const chip=node("span","exclude-chip",chatTitle(id)),undo=node("button","text-link",tr("Allow again"));undo.type="button";undo.disabled=demo;
      undo.addEventListener("click",()=>{state.scopeExclude=state.scopeExclude.filter(x=>x!==id);state.scopeDirty=true;renderScope();});
      chip.append(undo);box.append(chip);
    }
  }
  show("scope-warning",draft.mode!=="selected");$("scope-warning").textContent=wideWarning();
  $("scope-unsaved").textContent=state.scopeDirty?tr("Unsaved changes — press Save scope to apply."):tr("Saved: {mode}.",{mode:scopeName(saved.mode)});
}
$("scope-form").addEventListener("change",()=>{state.scopeDirty=true;renderScope();});
$("scope-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const draft=scopeDraft(),saved=state.scope.settings,revision=state.workspaceRevision,profile=state.profile;
  if(draft.mode==="folder"&&draft.folder_id===null)throw new Error(tr("Choose a Telegram folder. Load chats first if the list is empty."));
  const widening=draft.mode!=="selected"&&(draft.mode!==saved.mode||draft.folder_id!==saved.folder_id);
  if(widening&&!window.confirm(wideWarning()+"\n\n"+tr("Continue only with a dedicated account. Your confirmation is recorded in the signed journal.")))return;
  const r=await json("scope",{...draft,acknowledged:widening},{profile});
  if(revision!==state.workspaceRevision)return;
  state.scopeDirty=JSON.stringify(draft)!==JSON.stringify(scopeDraft());
  state.scope={...r,folders:r.folders.length?r.folders:state.scope.folders};
  await refreshStatus();
  if(revision!==state.workspaceRevision||profile!==state.profile)return;
  if(state.view==="sources")renderScope();
  toast(tr(draft.mode==="selected"?"Scope saved: only chosen chats are recorded.":"Scope saved and recorded in the signed journal. New chats are added as they appear."));
});});
function renderRecheck(){
  const most=state.status?.parameters?.snapshot_max||500;
  $("snapshot-limit").max=String(most);
  $("snapshot-limit-hint").textContent=tr("1 to {n} messages; the largest snapshot is set in Parameters.",{n:most});
}

const parameterItems=()=>(state.parameters?.groups||[]).flatMap(g=>g.items);
function parameterLabel(key){const item=parameterItems().find(i=>i.key===key);return item?tr(item.label):key.replaceAll("_"," ");}
function parameterValue(value){
  if(Array.isArray(value))return trn("{n} line","{n} lines",value.length);
  return typeof value==="boolean"?tr(value?"On":"Off"):Number(value).toLocaleString();
}
let parametersView=null;
const parametersReady=import("./views/parameters.js").then(({createParameters})=>{
  parametersView=createParameters({root:$("view-parameters"),tr,getState:()=>state,
    getSession:()=>state.workspaceRevision+":"+state.profile,may,json,refreshStatus,toast,
    headerOffset:()=>{const header=document.querySelector(".topbar");return header&&["sticky","fixed"].includes(getComputedStyle(header).position)?header.getBoundingClientRect().height:0;},
    sectionHref:id=>window.TgWitnessRouter?.href({view:"parameters",section:id})||"#parameters-group-"+id,
    sectionChanged:id=>{state.parameterSection=id;window.TgWitnessRouter?.record();},
    setDirty:value=>state.parametersDirty=value,saved:value=>{state.parameters=value;quickCatalogKey='';}});
  return parametersView;
}).catch(error=>{toast(error.message,true);throw error;});
async function loadParameters(){if(state.view==="parameters")return (await parametersReady).enter(viewContexts.get("parameters")||{});}

function selectExtra(name,options={}){
  state.extra=name;
  show("extras-overview",!name);
  for(const key of ["alerts","evidence","cloud","bot","github"]){
    show("extras-"+key,key===name);
    $("extras-open-"+key).setAttribute("aria-expanded",String(key===name));
  }
  if(state.view==="witness"&&options.history!==false)window.TgWitnessRouter?.record();
}
document.querySelectorAll("[data-extra]").forEach(button=>button.addEventListener("click",()=>{
  const name=button.dataset.extra;selectExtra(name);
  const heading=$("extras-"+name+"-title");heading.focus({preventScroll:true});heading.scrollIntoView({block:"start"});
}));
document.querySelectorAll("[data-extra-close]").forEach(button=>button.addEventListener("click",()=>{
  const opener=$("extras-open-"+button.dataset.extraClose);selectExtra(null);opener.focus();
}));

document.querySelectorAll("[data-go-extra]").forEach(link=>link.addEventListener("click",event=>{
  event.preventDefault();navigate("witness",{history:false});$("extras-open-"+link.dataset.goExtra).click();
}));
function extraBadge(name,on,onText,offText){
  const badge=$("extra-"+name+"-badge");badge.textContent=tr(on?onText:offText);badge.classList.toggle("on",on);
}
// A card badge from what the parts do (health.py), not from their switches.
function stateExtraBadge(name,value){
  const key=healthKnown(value),badge=$("extra-"+name+"-badge");
  badge.className="extra-badge state-"+key;badge.replaceChildren(icon(healthStates[key][1]),node("span","",healthStates[key][0]));
}
function renderEvidenceBadge(){
  const t=state.timestampsHealth,r=state.replicaHealth,line=$("extra-evidence-status");
  stateExtraBadge("evidence",healthWorst([t?.state||"off",r?.state||"off"]));
  show("extra-evidence-status",!!(t||r));
  line.textContent=t||r?tr("Timestamps")+": "+healthStates[healthKnown(t?.state||"off")][0]+" · "+
    tr("Off-site copy")+": "+healthStates[healthKnown(r?.state||"off")][0]:"";
}

async function loadAssurance(){
  if(state.assurance===undefined&&state.status){
    // The statement exists only in high-assurance mode; elsewhere the request would only log a 404
    const r=state.status.assurance?await fetch("/api/assurance").catch(()=>null):null;
    state.assurance=r?.ok?(await r.json()).statement:null;
  }
  const s=state.assurance,on=!!s;
  if(state.view!=='witness')return;
  show("alerts-host",on);show("cloud-active",on);
  if(!on){$("extra-cloud-badge").className="extra-badge";extraBadge("cloud",false,"","Off");renderServerHealth(null);return;}
  $("cloud-active").textContent=tr("This collector runs on a sealed {provider} server, signing key {fingerprint}. An opened SSH port or a login there is recorded in the journal and sent as a problem notification.",
    {provider:CLOUD[s.host?.mode]?.[0]||s.host?.mode||"",fingerprint:s.fingerprint});
  const profile=state.profile,h=await json("health");
  if(profile===state.profile)renderServerHealth(h.server);
}
// Deployment and the protection checks are separate: a running server is not a sealed one.
function renderServerHealth(s){
  if(state.view!=='witness')return;
  const box=$("cloud-health");box.replaceChildren();
  show("cloud-health",!!s);if(!s)return;
  const d=s.deployment,c=s.checks;
  stateExtraBadge("cloud",healthWorst([d.state,c.state]));
  box.append(healthRow("server",tr("Deployment"),d,[d.reason==="deployed"?tr("Deployed in high-assurance mode: {mode}.",{mode:CLOUD[d.mode]?.[0]||d.mode}):
    d.reason==="provider_unavailable"?tr("The provider's metadata service did not answer: {error}",{error:d.error}):tr("This server has no deployment description.")]));
  const lead={passed:tr("All protection checks passed."),attention:tr("Some protection checks need attention."),
    partly_unknown:tr("Some values could not be measured.")}[c.reason]||tr("No recent host measurement.");
  const names={ssh_port:tr("Port 22"),ssh_processes:tr("SSH server processes"),sessions:tr("Logged-in sessions"),new_logins:tr("New login records since start")};
  const value=i=>i.result==="unknown"?tr("could not be measured"):i.name==="ssh_port"?tr(i.value?"accepts connections":"not listening"):i.value?String(i.value):tr("none");
  const row=healthRow("server",tr("Protection checks"),c,[lead,c.measured_at&&tr("Measured: {time}",{time:fmtFull(c.measured_at)})]);
  const list=node("ul","health-checks");
  for(const i of c.items){
    const item=node("li","check-"+i.result);
    item.append(icon(i.result==="pass"?"check":i.result==="attention"?"alert":"question"),node("span","",names[i.name]+": "+value(i)));list.append(item);
  }
  row.append(list,node("p","hint",tr("A running SSH process or an open port is not proof of a login.")),
    node("p","hint",tr("Measured by the collector on its own host; compare with the provider's records.")));
  box.append(row);
}
async function loadExtras(){
  await Promise.all([loadWitness(),loadAlerts(),loadEvidence(),loadReplica(),loadAssurance(),loadSourceCheck()]);
}

async function loadSourceCheck(){
  if(!state.status)return;
  const profile=state.profile,r=await json("source-check");
  if(profile===state.profile)renderSourceCheck(r);
}
function renderSourceCheck(r){
  if(state.view!=='witness')return;
  const l=r.last,box=$("github-result"),badge=$("extra-github-badge"),good=!!l&&r.current&&l.matches;
  $("github-form").querySelectorAll("input,button").forEach(n=>n.disabled=!!state.status?.demo);
  badge.textContent=tr(!l?"Not checked":!r.current?"Check again":l.matches?"Matches":"Differs");
  badge.classList.toggle("on",good);badge.classList.toggle("warn",!!l&&!good);
  if(l&&!state.githubDirty){$("github-repository").value=l.repository.replace("https://","");$("github-ref").value=l.ref;formControls?.loaded("github-form");}
  $("github-running").textContent=tr("Running: version {version}, {n} program files, source hash {hash}.",
    {version:r.version,n:r.files,hash:r.source_tree_sha256.slice(0,16)+"…"});
  box.replaceChildren();show("github-result",!!l);
  if(!l)return;
  const vars={repository:l.repository.replace("https://github.com/",""),commit:l.commit.slice(0,12),ref:l.ref,n:l.matches?l.files:l.differences};
  box.className="github-result "+(good?"ok":"warn");
  box.append(node("p","github-verdict",l.matches?tr("The code matches {repository} at {commit} ({ref}): all {n} program files are identical.",vars)
    :tr("The code differs from {repository} at {commit} ({ref}): {n} file(s) are not the same.",vars)));
  box.append(node("p","hint",r.current?tr("Checked {time} and saved in the signed journal.",{time:fmtFull(l.checked_at)})
    :tr("The program has changed since this check of {time}. Check again to cover the running code.",{time:fmtFull(l.checked_at)})));
  for(const [key,label] of [["changed","Changed"],["extra","Only here"],["missing","Only on GitHub"]]){
    if(!l[key].length)continue;
    const p=node("p","github-files");p.append(node("strong","",tr(label)+": "),node("code","",l[key].join(", ")));box.append(p);
  }
  const link=node("a","text-link",tr("Open the commit on GitHub ↗"));
  link.href=l.repository+"/commit/"+l.commit;link.target="_blank";link.rel="noopener noreferrer";box.append(link);
}
$("github-form").addEventListener("input",()=>{state.githubDirty=true;});
$("github-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const draft=formControls?.capture("github-form");
  const r=await json("source-check",{repository:$("github-repository").value.trim(),ref:$("github-ref").value.trim()});
  state.githubDirty=formControls?.changed(draft)||false;renderSourceCheck(r);formControls?.accepted(draft,state.githubDirty);
  toast(tr(r.last.matches?"The code matches the commit. The check is saved in the signed journal."
    :"The code differs from the commit. The check is saved in the signed journal."),!r.last.matches);
});});

const CLOUD={hetzner:["Hetzner Cloud","cpx22","nbg1"],digitalocean:["DigitalOcean","s-1vcpu-2gb","fra1"],
  linode:["Akamai Cloud (Linode)","g6-standard-1","eu-central"],vultr:["Vultr","vc2-1c-2gb","fra"],
  aws:["Amazon EC2","t3.small","eu-central-1"],generic:["Any server (self-attested)","",""]};
for(const [key,[title]] of Object.entries(CLOUD))$("cloud-provider").append(new Option(key==="generic"?tr("Any server (self-attested)"):title,key));
const shellWord=v=>/^[\w@%+=:,./-]+$/.test(v)?v:"'"+v.replaceAll("'","'\\''")+"'";
function renderCloud(){
  const provider=$("cloud-provider").value,[,type,location]=CLOUD[provider],generic=provider==="generic";
  const v=id=>$(id).value.trim(),name=v("cloud-name")||"tgwitness-1";
  $("cloud-type").placeholder=type;$("cloud-location").placeholder=location;
  $("cloud-type").disabled=$("cloud-location").disabled=generic;
  const target=["--provider",provider,"--name",name,
    ...(generic?[]:["--server-type",v("cloud-type")||type,...(v("cloud-location")?["--location",v("cloud-location")]:[])]),
    "--ref",v("cloud-ref")||"RELEASE_TAG","--zone",v("cloud-zone")||"example.org",
    "--cloudflare-account",v("cloud-account")||"CLOUDFLARE_ACCOUNT_ID","--panel-host",v("cloud-panel")||"panel.example.org",
    ...(v("cloud-witness")?["--witness-host",v("cloud-witness")]:[])];
  const run=(command,args)=>"python -m tgwitness.cloud "+command+" "+args.map(shellWord).join(" ");
  $("cloud-commands").textContent=[
    "# "+tr("1. Preview: prints the installer and every API call, creates nothing"),run("plan",target),"",
    "# "+tr("2. Create: Cloudflare Tunnel, a firewall without inbound rules and the server; waits for the collector key"),
    run("deploy",[...target,...(generic?[]:["--provider-token-file",provider+"-token.txt"]),"--cloudflare-token-file","cloudflare-token.txt"]),"",
    "# "+tr("3. Check at any time, also by someone else with read-only tokens"),
    run("verify",["--record","deployments/"+name+"/deployment.json",...(generic?[]:["--provider-token-file",provider+"-readonly.txt"]),
      "--fingerprint","COLLECTOR_FINGERPRINT"])].join("\n");
}
$("cloud-form").addEventListener("input",renderCloud);
$("cloud-form").addEventListener("submit",e=>e.preventDefault());
renderCloud();
$("cloud-copy").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await navigator.clipboard.writeText($("cloud-commands").textContent);toast(tr("Commands copied."));
}));
async function loadWitness(){
  if(!state.status)return;
  const profile=state.profile,r=state.status.demo?{tokens:[]}:await json("witness");
  if(profile===state.profile)renderWitness(r);
}
function collectorAddress(){return location.origin+(state.profile==="default"?"":"/profiles/"+encodeURIComponent(state.profile));}
function renderWitness(r){
  if(state.view!=='witness')return;
  const list=$("witness-list"),demo=!!state.status?.demo;list.replaceChildren();
  const witnessed=r.tokens.some(token=>token.last_poll&&!token.overdue);
  extraBadge("bot",witnessed,"On",r.tokens.some(token=>token.overdue)?"Check again":"Not checked");
  $("witness-form").querySelectorAll("input,button").forEach(n=>n.disabled=demo);
  $("witness-setup-form").querySelector('[type="submit"]').disabled=demo;
  $("witness-token-download").disabled=demo||!state.witnessToken;
  if(!$("witness-address").value)$("witness-address").value=collectorAddress();
  renderWitnessVolume();
  $("witness-start-command").textContent=["python -m tgwitness.witness run --config witness.json --check-config",
    "python -m tgwitness.witness run --config witness.json",
    "python -m tgwitness.witness fingerprint --config witness.json"].join("\n");
  if(!r.tokens.length)list.append(node("p","hint",tr(demo?"Witnesses work in a real workspace, not in the demo.":"No witness yet. Create a read-only token for each witness.")));
  for(const t of r.tokens){
    const row=node("div","target-row"),info=node("div"),poll=t.last_poll;
    info.append(node("h3","",t.label),node("p","",tr("Created {time}",{time:fmtFull(t.created_at)})));
    info.append(node("p",t.overdue?"access-warning":"",poll?tr("Last check {time}",{time:fmtFull(poll.at)})+(poll.witness?" · "+tr("witness key {key}…",{key:poll.witness.slice(0,16)}):"")+
      (poll.interval_minutes?" · "+tr("every {n} min",{n:poll.interval_minutes}):"")+(t.overdue?" · "+tr("overdue: the witness has not checked in time"):""):tr("Not used yet")));
    const revoke=node("button","danger",tr("Revoke"));revoke.type="button";revoke.disabled=demo;
    revoke.addEventListener("click",()=>busy(revoke,async()=>{
      if(!window.confirm(tr("Revoke the token of \"{name}\"? That witness can no longer check this journal.",{name:t.label})))return;
      const result=await api("witness/tokens/"+encodeURIComponent(t.id),undefined,{method:"DELETE"}).then(x=>x.json());
      resetWitnessSetup();renderWitness(result);
    }));
    row.append(info,revoke);list.append(row);
  }
  const token=state.witnessToken||"<witness token>",address=collectorAddress(),local=state.profile==="default"?"http://tgwitness:8787":"http://tgwitness:8787/profiles/"+state.profile;
  const env=["TGWITNESS_WITNESS_TOKEN="+token,"TGWITNESS_WITNESS_BOT_TOKEN=<bot token from @BotFather>","TGWITNESS_WITNESS_CHANNEL=@your_witness_channel",
    "TGWITNESS_WITNESS_COLLECTOR_FINGERPRINT="+state.status.fingerprint];
  $("witness-docker").textContent=["# .env next to compose.yaml",...env,"TGWITNESS_WITNESS_COLLECTOR="+local,"","docker compose --profile witness up -d",
    "docker compose logs witness    # prints the witness key fingerprint: keep a copy elsewhere"].join("\n");
  $("witness-options").textContent=["# .env (Docker) or the environment",
    "TGWITNESS_WITNESS_INTERVAL=10          # minutes between checks, 1-1440",
    "TGWITNESS_WITNESS_TIMEOUT=30           # seconds to wait for the collector and the Bot API",
    "TGWITNESS_WITNESS_POST=all             # all | changes (new head or a problem) | problems",
    "TGWITNESS_WITNESS_TITLE=TgWitness witness","",
    "# or a JSON file: python -m tgwitness.witness run --config witness.json",
    JSON.stringify({collector:address,token_file:"witness-token.txt",bot_token_file:"bot-token.txt",channel:"@your_witness_channel",
      collector_fingerprint:state.status.fingerprint,interval:10,timeout:30,post:"all",title:"TgWitness witness",
      texts:{ok:"journal head",no_response:"no answer from the collector",records:"records"}},null,2)].join("\n");
  $("witness-remote").textContent=["# .env next to compose.witness.yaml on the witness server",...env,"TGWITNESS_WITNESS_COLLECTOR="+address,"",
    "docker compose -f compose.witness.yaml up -d","","# or without Docker, from a TgWitness checkout:",
    "python -m tgwitness.witness run --collector "+address+" --token-file witness-token.txt --bot-token-file bot-token.txt --channel @your_witness_channel"].join("\n");
  $("witness-verify").textContent=["# on the witness side","python -m tgwitness.witness export --out witness.zip","",
    "# anywhere: the collector's signed ZIP, the witness journal and the channel (Telegram Desktop export, result.json)",
    "python verify.py tgwitness-evidence.zip --witness witness.zip --witness-fingerprint <witness key> --channel result.json"].join("\n");
}
$("witness-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const r=await json("witness/tokens",{label:$("witness-label").value.trim()});
  $("witness-label").value="";state.witnessToken=r.token;$("witness-token").textContent=r.token;show("witness-new",true);renderWitness(r);
});});
$("witness-copy").addEventListener("click",e=>busy(e.currentTarget,async()=>{await navigator.clipboard.writeText($("witness-token").textContent);toast(tr("Token copied."));}));
$("witness-refresh").addEventListener("click",e=>busy(e.currentTarget,loadWitness));

function resetWitnessSetup(){
  state.witnessToken=null;show("witness-new",false);$("witness-token-download").disabled=true;
  for(const id of ["witness-token","witness-docker","witness-remote","witness-options","witness-setup-result"])$(id).textContent="";
  $("witness-setup-form").reset();$("witness-address").value="";
  $("witness-launch").open=false;
  viewQueries("witness","#extras-bot details").forEach(detail=>detail.open=false);
}
function renderWitnessVolume(){
  const interval=Number($("witness-interval").value),policy=$("witness-policy").value;
  $("witness-volume").textContent=policy==="all"&&interval>=1&&interval<=1440?
    tr("About {n} channel posts per day for this workspace. Each check is a signed observation, including failures.",{n:Math.ceil(1440/interval)}):
    tr("This policy leaves checks unpublished. Use every check for a regular external evidence trail.");
}
for(const id of ["witness-interval","witness-policy"])$(id).addEventListener("input",renderWitnessVolume);
$("witness-token-download").addEventListener("click",()=>{
  if(state.witnessToken)saveBlob(new Blob([state.witnessToken+"\n"],{type:"text/plain"}),"witness-token.txt");
});
$("witness-setup-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const address=$("witness-address").value.trim(),channel=$("witness-channel").value.trim();
  const validAddress=value=>{try{const u=new URL(value);return ["https:","http:"].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{return false;}};
  if(!validAddress(address)||!validAddress($("witness-bot-api").value.trim()))throw new Error(tr("Use HTTP(S) addresses without credentials, query or fragment."));
  if(!/^@[A-Za-z0-9_]{5,32}$|^-?\d{1,20}$/.test(channel))throw new Error(tr("Use a Telegram @channel or numeric chat ID."));
  const proxy=$("witness-proxy").value.trim();
  if(proxy){let u;try{u=new URL(proxy);}catch{throw new Error(tr("Use an HTTP or SOCKS5 proxy for the witness, not an MTProxy link."));}
    if(!["http:","socks5:","socks5h:"].includes(u.protocol)||!u.hostname||u.search||u.hash||(!u.port&&u.protocol!=="http:")||u.pathname&&u.pathname!=="/")
      throw new Error(tr("Use an HTTP or SOCKS5 proxy for the witness, not an MTProxy link."));}
  const pin=state.status.fingerprint;
  if(!/^[0-9a-f]{64}$/.test(pin))throw new Error(tr("Refresh the workspace to obtain its signing-key fingerprint."));
  const config={collector:address.replace(/\/$/,""),collector_fingerprint:pin,token_file:"witness-token.txt",
    bot_token_file:"bot-token.txt",channel,interval:Number($("witness-interval").value),timeout:30,
    post:$("witness-policy").value,bot_api:$("witness-bot-api").value.trim(),data_dir:"witness-data"};
  if(proxy)config.proxy=proxy;
  saveBlob(new Blob([JSON.stringify(config,null,2)+"\n"],{type:"application/json"}),"witness.json");
  $("witness-setup-result").textContent=tr("Configuration saved. Step 3 shows how to start your witness.");
  $("witness-launch").open=true;
});});

let noticeUI=null,noticeRequest=0;
async function noticeNavigate(view){
  if(!viewAllowed(view))return false;
  if(typeof selectView==="function")await selectView(view);else navigate(view);
  return state.view===view;
}
async function noticeAction(item,kind){
  const revision=state.workspaceRevision,action=kind==="record"?{type:"record"}:item.action||
    {type:item.level==="change"?"chat":"record",chat_id:item.chat_id};
  if(action.type==="chat"&&Number.isSafeInteger(action.chat_id)){
    if(!await noticeNavigate("chats"))return openRecord(item.seq);
    await refreshChats();
    if(revision!==state.workspaceRevision)return;
    if(state.chats.some(chat=>chat.chat_id===action.chat_id))return openChat(action.chat_id);
  }else if(action.type==="diagnostics"){
    const destination=healthDiagnostics[action.part]||{accounts:{view:"accounts"},exports:{view:"evidence"}}[action.part];
    if(destination&&await noticeNavigate(destination.view)){
      if(revision!==state.workspaceRevision)return;
      if(destination.extra)selectExtra(destination.extra);
      if(destination.filter)document.querySelector('[data-filter="'+destination.filter+'"]')?.click();
      const target=destination.target?$(destination.target):$("view-"+destination.view)?.querySelector("h1,h2");
      if(target){target.tabIndex=-1;target.focus({preventScroll:true});target.scrollIntoView({block:"start"});}
      return;
    }
  }
  if(revision===state.workspaceRevision)return openRecord(item.seq);
}
const noticesReady=import("./components/notifications.js?v=1").then(({createNotifications})=>{
  noticeUI=createNotifications({workspace:$("workspace"),panel:$("notify-panel"),toggle:$("notify-toggle"),badge:$("notify-count"),list:$("notify-list"),
    readAll:$("notify-read"),rules:$("notify-rules"),closeButton:$("notify-close"),
    filters:[...document.querySelectorAll("[data-notice-filter]")],summary:$("notify-summary"),status:$("notify-status"),
    tr,trn,formatTime:fmtFull,items:()=>state.notifications,
    context:()=>({profile:state.profile,fingerprint:state.status?.fingerprint,revision:state.workspaceRevision,
      active:!!state.token&&!!state.status&&!$("workspace").hidden&&!$("workspace").inert}),
    refresh:loadNotifications,action:noticeAction,canRules:()=>viewAllowed("witness")&&may("settings"),
    openRules:async()=>{if(await noticeNavigate("witness")){selectExtra("alerts");$("extras-alerts-title").focus({preventScroll:true});$("extras-alerts").scrollIntoView({block:"start"});}},
    error:error=>{if(!(error instanceof StaleView))toast(error.message,true);}});
});
noticesReady.catch(()=>{$("notify-toggle").disabled=false;$("notify-toggle").addEventListener("click",()=>toast(tr("Notifications could not load. Reload the page to retry."),true));});
async function loadNotifications(){
  if(!state.status||!state.token||$("workspace").hidden)return;
  const profile=state.profile,revision=state.workspaceRevision,ticket=++noticeRequest,r=await json("notifications");
  if(profile!==state.profile||revision!==state.workspaceRevision||ticket!==noticeRequest)return;
  state.notifications=r.items;renderNotifications();
}
function renderNotifications(){
  if(noticeUI)noticeUI.render();else noticesReady.then(()=>noticeUI.render()).catch(()=>{});
}
function closeNotifications(){if(noticeUI)noticeUI.close();else{$("notify-panel").hidden=true;$("notify-toggle").setAttribute("aria-expanded","false");}}
async function openRecord(seq,options={}){
  const context=viewContexts.get(state.view),r=await json("events?"+new URLSearchParams({before:String(seq+1),limit:"1"}),undefined,{signal:context?.signal});
  if(context&&!context.current())return;
  if(r.events[0]?.seq===seq)await openDetail(r.events[0],options);
  else toast(tr("Record is unavailable to this access."),true);
}
function clearVerification(){state.verification=null;$("verification-result").textContent="";}
function renderVerification(){
  const v=state.verification;if(!v)return;
  if(v.profile!==state.profile||v.fingerprint!==state.status.fingerprint){clearVerification();return;}
  const head=state.status.stats.head;
  const newer=head&&(head.seq>v.events||(head.seq===v.events&&head.hash!==v.head_hash));
  $("verification-result").textContent=tr("Verified {n} event signatures and chain links through event #{n}. ",{n:v.events})+
    (newer?tr("The journal has changed since this check; verify again to check newer records. "):"")+
    tr("Attachments are checked when exporting a signed ZIP. Signer identity still requires an independently trusted fingerprint.");
}
$("verify-journal").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const profile=state.profile,revision=state.workspaceRevision;clearVerification();
  const r=await json("verify",{},{profile});
  if(revision!==state.workspaceRevision)return;
  state.verification={...r,profile};renderVerification();
  toast(tr("Journal integrity check passed."));
}));
function setAuthStep(step){
  const demo=!!state.status?.demo;
  show("demo-account-state",demo);
  if(demo)step="demo";
  for(const s of ["credentials","code","password"])show(s+"-form",step===s);
  show("authorized-state",step==="authorized");
  show("qr-state",step==="qr");
  show("auth-back",["code","password"].includes(step));
  $("account-heading").textContent=tr(demo?"Connect your account":step==="authorized"?"Your account":step==="credentials"?(accountState?.(state.status).needsSignIn?"Sign in again":"Add account"):"Sign in");
  const focus=step==="credentials"&&authMethod==="phone"?"phone":["code","password"].includes(step)?step:null;
  if(focus)$(focus).focus();
}
function setAuthMethod(method){
  if(method!==authMethod){
    accountImportRevision++;importExpectedId=null;
    for(const id of ["session-string","session-file","tdata-passcode","auth-key","auth-dc","auth-user-id"])$(id).value="";
    $("import-result").textContent="";
  }
  authMethod=method;
  viewQueries("connection","[data-auth-method]").forEach(button=>{
    const selected=button.dataset.authMethod===method;
    button.classList.toggle("active",selected);button.setAttribute("aria-pressed",String(selected));
  });
  show("import-details",method==="files");show("auth-continue",method!=="qr");show("start-qr",method==="qr");
  show("phone-fields",method==="phone");$("phone").required=method==="phone";
  show("qr-intro",method==="qr");
  show("auth-key-fields",method==="key");
  $("auth-continue").textContent=tr(method==="files"||method==="key"?"Connect account":"Continue");
  $("method-description").textContent=tr({phone:"Receive a login code in Telegram. Enter your 2FA password if asked.",
    qr:"Use Telegram on a device where you are already signed in.",
    files:"Choose one session format. Add its JSON file if supplied.",
    key:"Already have an Auth Key? Paste it with the supplied DC ID."}[method]);
  authProgress("");
  renderSelectedFiles();
  $("login-note").textContent="";
  $("credentials-form").querySelector(".form-error")?.remove();
  renderApiState();
}
function renderApiState(){
  const c=state.status?.collector;
  const entered=$("api-id").value&&$("api-hash").value;
  $("api-state").textContent=tr(entered?"Entered":
    c?.has_api_credentials&&!c.builtin_api?"Saved":"Built-in");
}
function apiCredentials(){
  const id=$("api-id"),hash=$("api-hash");

  if(!id.value&&!hash.value){id.required=hash.required=false;return {};}
  id.required=hash.required=true;
  if(!id.checkValidity()||!hash.checkValidity()||Number(id.value)<1||Number(id.value)>2147483647){
    show("api-details",true);$("api-details").open=true;
    $("api-required").firstChild.textContent=tr("Enter both API ID and API hash, or clear both fields to use the built-in pool.")+" ";
    if(!id.checkValidity()){id.reportValidity();}else if(Number(id.value)<1||Number(id.value)>2147483647){
      $("api-pair-result").textContent=tr("API ID must be between 1 and 2147483647.");id.focus();
    }else hash.reportValidity();
    return null;
  }
  return {api_id:Number(id.value),api_hash:hash.value.trim()};
}
async function loginRequest(path,body,options){
  const controls=[...$("credentials-form").querySelectorAll("input,textarea,button")].map(n=>[n,n.disabled]);
  controls.forEach(([n])=>n.disabled=true);
  authProgress(tr(path==="auth/phone/start"||path==="auth/phone"?"Requesting your Telegram login code…":
    path==="auth/qr/start"?"Generating your Telegram QR code…":"Connecting to Telegram and checking the account…"));
  try{return await json(path,body,options);}
  finally{controls.forEach(([n,disabled])=>n.disabled=disabled);authProgress("");}
}
function authProgress(message){
  $("auth-progress").textContent=message;show("auth-progress",!!message);
}
viewQueries("connection","[data-auth-method]").forEach(button=>button.addEventListener("click",()=>setAuthMethod(button.dataset.authMethod)));
$("api-id").addEventListener("paste",event=>{
  const text=event.clipboardData?.getData("text")||"";
  if(!text.includes(":"))return;
  event.preventDefault();
  const match=text.trim().match(/^([0-9]{1,10})\s*:\s*([a-fA-F0-9]{32})$/);
  const valid=match&&Number(match[1])>0&&Number(match[1])<=2147483647;
  $("api-pair-result").classList.toggle("error",!valid);
  if(!valid){$("api-pair-result").textContent=tr("Paste one pair: a positive API ID, a colon, and a 32-character hexadecimal API hash. Existing fields were kept.");return;}
  accountImportRevision++;
  $("api-id").value=String(Number(match[1]));$("api-hash").value=match[2];
  $("api-pair-result").textContent=tr("Both fields filled. Telegram will validate the credentials when you sign in.");
  renderApiState();
});
for(const id of ["api-id","api-hash"])$(id).addEventListener("input",()=>{accountImportRevision++;$("api-pair-result").textContent="";authProgress("");renderApiState();});
function clearSecrets(){
  clearTimeout(toastTimer);show("toast",false);
  cancelQR();importExpectedId=null;accountImportRevision++;$("import-result").textContent="";
  for(const name of ["api-id","api-hash","session-string","session-file","phone","code","password",
                    "tdata-passcode","auth-key","auth-dc","auth-user-id","network-username","network-password","network-secret","network-link"])$(name).value="";
  $("network-link-result").textContent="";
  $("api-id").required=$("api-hash").required=false;$("api-details").open=false;
  $("api-pair-result").textContent="";setAuthMethod("phone");
}
function routeFields(){
  const kind=$("network-kind").value;
  const endpoint=kind!=="direct"&&kind!=="mtproxy_auto";
  show("network-endpoint",endpoint);show("network-login",kind!=="mtproxy");show("network-mtproxy",kind==="mtproxy");
  $("network-host").required=endpoint;$("network-secret").required=kind==="mtproxy";
  $("network-link").closest(".proxy-link").hidden=kind!=="mtproxy";
  viewQuery("connection",".proxy-catalog").hidden=kind!=="mtproxy";
  $("network-auto-help").hidden=kind!=="mtproxy_auto";
  window.TgWitnessProxies?.sync?.();
  if(kind==="mtproxy"&&$("network-details").open)loadProxyCatalog();
}
function renderConnection(){
  if(state.view!=='connection')return;
  renderApiState();
  const c=state.status.collector,r=c.network||{kind:"mtproxy_auto"},p=state.status.protection||{};
  const route=tr({direct:"Direct connection",socks5:"SOCKS5 proxy",http:"HTTP CONNECT proxy",mtproxy:"MTProxy · experimental",
    mtproxy_auto:"Automatic MTProxy"}[r.kind]);
  const auto=r.kind==="mtproxy_auto",now=auto&&r.current,pool=(auto&&r.pool)||{};
  $("route-summary").textContent=route;
  $("route-line-text").textContent=tr("Connection: {route}",{route:r.kind==="direct"||(auto&&!now)?route:route+" · "+(now||r).host+":"+(now||r).port});
  show("route-line",!state.status.demo);show("network-running",!state.status.demo&&c.running);
  const fallback=r.fallback_to_direct?tr("Connected directly now: no listed proxy answers. A proxy is used again as soon as one does."):
    auto&&r.exposure==="fallback"?tr("Direct connection after {n} minutes without a working proxy.",{n:state.status.parameters?.proxy_fallback_minutes??10}):
    auto&&r.exposure==="tunnel"?tr("Direct connection while no proxy works."):tr("Direct fallback disabled.");
  $("route-detail").textContent=r.kind==="direct"?tr("Telegram client connects directly. Other applications have their own network settings."):
    auto?(now?now.host+":"+now.port+" · "+now.source+" · ":"")+tr("{healthy} of {listed} listed proxies answer; a failing proxy is replaced by the next working one.",
      {healthy:pool.healthy||0,listed:pool.listed||0})+" "+fallback:
    r.host+":"+r.port+" · "+(r.has_credentials?tr("Credentials stored in encrypted vault.")+" ":"")+tr("Direct fallback disabled.");
  if(networkLoadedFor!==state.profile){
    $("network-kind").value=r.kind;$("network-host").value=r.host||"";$("network-port").value=String(r.port||1080);
    networkLoadedFor=state.profile;routeFields();
  }
  $("network-form").querySelector('[type="submit"]').disabled=state.status.demo||c.running;
  $("network-test").disabled=state.status.demo;$("sign-out").disabled=state.status.demo;
  if(state.status.demo)$("proxy-catalog-refresh").disabled=true;
  $("proxy-catalog-apply").disabled=state.status.demo||c.running||!$("proxy-catalog-select").value;
  const summary=$("protection-summary");summary.replaceChildren();
  for(const [title,value] of [[tr("Account & proxy secrets"),tr("Encrypted in the vault")],
    [tr("Vault key"),tr(p.vault_key_mode==="external"?"External master key; separate workspace keys":"Stored in the data directory")],
    [tr("Messages & attachments"),tr("Not encrypted by TgWitness")],[tr("Evidence signatures"),tr("Ed25519 · integrity verification")]]){
    const row=node("div");row.append(node("strong","",title),node("span","muted",value));summary.append(row);
  }
}
$("network-kind").addEventListener("change",routeFields);
$("network-details").addEventListener("toggle",()=>{if($("network-details").open&&$("network-kind").value==="mtproxy")loadProxyCatalog();});
async function loadProxyCatalog(refresh=false){
  const profile=state.profile,revision=state.workspaceRevision,select=$("proxy-catalog-select"),previous=select.value;
  try{
    const r=await json(refresh?"network/catalog/refresh":"network/catalog",refresh?{}:undefined);
    if(profile!==state.profile||revision!==state.workspaceRevision)return;
    select.replaceChildren();
    for(const row of r.proxies)select.add(new Option(row.host+":"+row.port+" · "+row.label,row.id));
    if(r.proxies.some(row=>row.id===previous))select.value=previous;
    select.disabled=!r.proxies.length;
    let description=r.mode==="operator"?tr("This installation uses its operator's catalog. Public subscriptions are disabled."):
      tr("{n} compatible public proxies. A ready-made list is included; update it when you need fresh addresses.",{n:r.proxies.length});
    if(!r.proxies.length)description=tr("No compatible proxies in the list. Enter your own proxy below.");
    if(r.refresh){
      description=r.throttled?tr("The list was refreshed recently. Wait one minute before another download."):
        r.refresh.updated.length===0?tr("Sources are unavailable or contain no compatible proxies. Your previous list is still available."):
        r.refresh.retained.length?tr("Some sources updated. Previous entries were kept for unavailable sources."):
        tr("Public lists updated. Your current connection route has not changed.");
    }
    $("proxy-catalog-status").textContent=description;
    $("proxy-catalog-refresh").textContent=tr(r.mode==="operator"?"Reload operator catalog":"Update public lists");
    $("proxy-catalog-refresh").disabled=state.status.demo;
    const sources=$("proxy-catalog-sources");sources.replaceChildren();
    for(const source of r.sources||[]){
      const row=node("p"),link=node("a","",source.label);link.href=source.homepage;link.target="_blank";link.rel="noopener noreferrer";
      row.append(link,node("span","hint",source.fetched_at?tr("Saved {date} · {n} compatible",{date:formatTime(source.fetched_at),n:source.compatible}):tr("No saved list yet")));sources.append(row);
    }
    $("proxy-catalog-download").textContent=r.mode!=="operator"&&r.download_route==="none"?
      tr(r.download_problem)+" "+tr("Until then the pool uses the lists it already has."):
      tr(r.mode==="operator"?"The local operator catalog is reloaded without contacting public list providers.":
      r.download_route==="proxy"?"Updates download lists over HTTPS through the operator's download proxy. Telegram account credentials are never sent.":
      "Updates download lists directly over HTTPS from this server. Telegram account credentials are never sent. The operator can configure a separate download proxy.");
    $("proxy-catalog-apply").disabled=!r.proxies.length||state.status.demo||state.status.collector.running;
  }catch(error){
    if(profile!==state.profile||revision!==state.workspaceRevision)return;
    if(refresh&&select.options.length){
      $("proxy-catalog-status").textContent=tr("Could not update the public lists. Your saved list is still available; check the download connection settings.");
      return;
    }
    select.replaceChildren();select.disabled=true;$("proxy-catalog-apply").disabled=true;
    $("proxy-catalog-status").textContent=tr("Public proxy catalog is unavailable. Custom routes still work.");
  }
}
$("proxy-catalog-refresh").addEventListener("click",e=>busy(e.currentTarget,()=>loadProxyCatalog(true)));
async function routeSaved(){
  clearSecrets();networkLoadedFor=null;await refreshStatus();setAuthStep(accountSignedIn()?"authorized":"credentials");
  $("network-result").textContent=tr("Route saved. Pending login cancelled. Start observation when ready.");
  toast(tr("Telegram connection route saved."));
}
$("proxy-catalog-apply").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const id=$("proxy-catalog-select").value;if(!id)return;
  await json("network/catalog/"+encodeURIComponent(id),{});await routeSaved();
}));
$("network-import").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const r=await json("network/parse-link",{link:$("network-link").value.trim()});
  $("network-kind").value="mtproxy";$("network-host").value=r.host;$("network-port").value=String(r.port);
  $("network-secret").value=r.secret;$("network-username").value="";$("network-password").value="";
  $("network-link").value="";routeFields();
  $("network-link-result").textContent=tr("Fields filled. Review the endpoint, then save the route. No connection has been made.");
}));

const exposureNames={hide:tr("Hide this server's address"),fallback:tr("Direct connection as a last resort"),
  tunnel:tr("Server behind a tunnel or VPN")};
let policyOutsideDirty=false,policyFormDirty=false;
function renderPolicy(p){
  if(state.view!=='connection')return;
  state.policy=p;policyOutsideDirty=false;policyFormDirty=false;
  $("policy-summary").textContent=exposureNames[p.exposure];
  viewQueries("connection",'input[name="exposure"]').forEach(n=>n.checked=n.value===p.exposure);
  $("outside-enabled").checked=p.outside_enabled;
  const proxy=p.outside_proxy;
  $("outside-kind").value=proxy?.kind||"";$("outside-host").value=proxy?.host||"";
  $("outside-port").value=String(proxy?.port||1080);$("outside-username").value="";$("outside-password").value="";
  outsideFields();
  $("policy-status").textContent=(p.direct_fallback?tr("Connected to Telegram directly now: no listed proxy answers.")+" ":"")+
    (p.outside_route==="none"?tr(p.outside_problem):p.outside_route==="direct"?
      tr("Requests outside Telegram go directly from this server."):
      tr("Requests outside Telegram go through {proxy}.",{proxy:(proxy?proxy.host+":"+proxy.port:tr("this workspace's proxy"))}));

  $("network-kind").querySelector('[value="direct"]').disabled=p.exposure!=="tunnel"&&$("network-kind").value!=="direct";
}
function outsideFields(){
  const none=!$("outside-kind").value;
  for(const id of ["outside-host","outside-port","outside-username","outside-password"]){
    $(id).disabled=none||!$("outside-enabled").checked;$(id).parentElement.hidden=$(id).disabled;
  }
  $("outside-kind").disabled=!$("outside-enabled").checked;
  $("outside-kind").parentElement.hidden=!$("outside-enabled").checked;
}
async function loadPolicy(){
  const profile=state.profile,p=await json("network/policy",undefined,viewOptions('connection'));
  if(profile===state.profile){if(policyFormDirty)state.policy=p;else renderPolicy(p);}
}
for(const event of ['input','change'])$("policy-form").addEventListener(event,()=>{policyFormDirty=true;});
for(const id of ["outside-kind","outside-host","outside-port","outside-username","outside-password"])
  $(id).addEventListener("input",()=>{policyOutsideDirty=true;outsideFields();});
$("outside-enabled").addEventListener("change",outsideFields);
$("policy-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const kind=$("outside-kind").value,body={exposure:viewQuery("connection",'input[name="exposure"]:checked')?.value||"hide",
    outside_enabled:$("outside-enabled").checked,outside_proxy:null,remove_outside_proxy:false};
  if(policyOutsideDirty&&kind)body.outside_proxy={kind,host:$("outside-host").value.trim(),port:Number($("outside-port").value),
    username:$("outside-username").value,password:$("outside-password").value};
  else if(!kind&&state.policy?.outside_proxy)body.remove_outside_proxy=true;
  renderPolicy(await json("network/policy",body));await refreshStatus();
  toast(tr("IP protection saved."));
});});
$("network-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const kind=$("network-kind").value,body={kind};
  if(kind!=="direct"&&kind!=="mtproxy_auto")Object.assign(body,{host:$("network-host").value.trim(),port:Number($("network-port").value)});
  if(kind==="socks5"||kind==="http")Object.assign(body,{username:$("network-username").value,password:$("network-password").value});
  if(kind==="mtproxy")body.secret=$("network-secret").value.trim();
  await json("network",body);
  await routeSaved();
});});
$("network-test").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  $("network-result").textContent=tr("Testing the configured Telegram route…");
  try{await json("network/test",{});$("network-result").textContent=tr("Telegram transport connected. This does not test capture completeness.");}
  catch(error){if(error instanceof StaleView)throw error;$("network-result").textContent=tr("Connection test failed. No direct fallback was attempted.");throw error;}
}));
function renderSelectedFiles(){
  const files=[...$("session-file").files];
  $("file-picker-title").textContent=tr(files.length?"Change selected files":"Choose account files");
  $("file-picker-caption").textContent=files.length?tr("{n} selected · {size} KiB",{n:files.length,size:Math.ceil(files.reduce((sum,f)=>sum+f.size,0)/1024)}):tr("One account · up to 4 files · 8 MiB total");
  $("selected-files").textContent=files.map(f=>f.name).join(" · ");show("selected-files",!!files.length);
}
$("session-file").addEventListener("change",()=>{
  accountImportRevision++;
  authProgress("");
  $("session-string").value="";importExpectedId=null;
  $("import-result").textContent="";
  renderSelectedFiles();
});
async function loadAccountFiles(){
  const input=$("session-file"),files=[...input.files];
  if(!files.length||files.length>4||files.reduce((sum,file)=>sum+file.size,0)>8*1024**2)
    throw new Error(tr("Select 1–4 account files totaling at most 8 MiB."));
  const profile=state.profile,revision=state.workspaceRevision,selection=accountImportRevision,passcode=$("tdata-passcode").value;
  let converted=false;
  authProgress(tr("Reading account files…"));
  try{
    const encoded=[];
    for(const file of files){
      const bytes=new Uint8Array(await file.arrayBuffer()),parts=[];
      for(let i=0;i<bytes.length;i+=32768)parts.push(String.fromCharCode(...bytes.subarray(i,i+32768)));
      encoded.push({name:file.name,content:btoa(parts.join(""))});
    }
    if(revision!==state.workspaceRevision||selection!==accountImportRevision||!state.token)return;
    const result=await json("auth/import",{files:encoded,passcode},{profile});
    if(revision!==state.workspaceRevision||selection!==accountImportRevision||!state.token)return;

    $("session-string").value=result.session||"";importExpectedId=result.expected_user_id||null;
    if(result.api_id)$("api-id").value=result.api_id;
    if(result.api_hash)$("api-hash").value=result.api_hash;
    $("import-result").textContent=tr("{formats} loaded.",{formats:result.formats.join(" + ")})+" "+tr(result.has_authorization?
      "Ready to connect.":"API metadata only. Use phone or QR login, or add a session file.");
    converted=true;renderApiState();return result;
  }catch(error){
    if(revision===state.workspaceRevision&&selection===accountImportRevision&&/passcode/i.test(error.message)){
      viewQuery("connection",".import-advanced").open=true;$("tdata-passcode").focus();
    }
    throw error;
  }finally{if(revision===state.workspaceRevision&&selection===accountImportRevision){if(converted)input.value="";renderSelectedFiles();$("tdata-passcode").value="";authProgress("");}}
}
async function loadAuthKey(){
  const key=$("auth-key").value.trim(),dc=Number($("auth-dc").value),user=$("auth-user-id").value.trim();
  if(!/^[a-fA-F0-9]{512}$/.test(key)){
    $("auth-key").focus();throw new Error(tr("Paste the full Auth Key: 512 hexadecimal characters. A shortened key containing … cannot be used."));
  }
  if(!Number.isInteger(dc)||dc<1||dc>5){$("auth-dc").focus();throw new Error(tr("Choose the DC ID supplied with this Auth Key (1–5)."));}
  if(user&&(!/^[0-9]+$/.test(user)||!Number.isSafeInteger(Number(user))||Number(user)<1)){
    $("auth-user-id").focus();throw new Error(tr("User ID must be a positive whole number within the supported numeric range."));
  }
  const profile=state.profile,revision=state.workspaceRevision,selection=accountImportRevision;
  const record={auth_key:key,dc_id:dc,...(user?{user_id:Number(user)}:{})};
  authProgress(tr("Reading your authorization key…"));
  try{
    const result=await json("auth/import",{files:[{name:"auth-key.json",content:btoa(JSON.stringify(record))}]},{profile});
    if(revision!==state.workspaceRevision||selection!==accountImportRevision||!state.token)return;
    $("session-string").value=result.session||"";importExpectedId=result.expected_user_id||null;
    return result;
  }finally{if(revision===state.workspaceRevision&&selection===accountImportRevision)authProgress("");}
}
for(const id of ["auth-key","auth-dc","auth-user-id"])$(id).addEventListener("input",()=>{
  accountImportRevision++;importExpectedId=null;$("session-string").value="";authProgress("");
});
$("import-account").addEventListener("click",e=>busy(e.currentTarget,loadAccountFiles));
$("session-string").addEventListener("input",()=>{accountImportRevision++;importExpectedId=null;$("import-result").textContent="";});
$("credentials-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  if(state.status.demo){toast(tr("Demo workspace. Connect accounts in your live installation."),true);return;}
  if(authMethod==="qr"){await beginQR();return;}
  const method=authMethod,profile=state.profile,revision=state.workspaceRevision;
  if(method==="phone"){
    $("phone").value=$("phone").value.replace(/[\s().-]/g,"");
    if(!$("phone").reportValidity())return;
  }else if(method==="key"){
    if(!await loadAuthKey())return;
  }else{
    if($("session-file").files.length){
      const imported=await loadAccountFiles();if(!imported)return;
    }
    if(!$("session-string").value.trim()){
      if($("api-id").value&&$("api-hash").value){
        setAuthMethod("phone");$("login-note").textContent=tr("API credentials loaded. Enter your phone number or choose QR code.");$("phone").focus();return;
      }
      throw new Error(tr("Choose a Telethon/Pyrogram .session file, a TData .zip, or a JSON containing authorization. You can also paste a Telethon StringSession under Passcode or session text."));
    }
  }
  const credentials=apiCredentials();if(!credentials)return;
  const selection=accountImportRevision;
  await cancelQR();
  if(revision!==state.workspaceRevision||method!==authMethod||selection!==accountImportRevision)return;
  const body=method==="phone"?{...credentials,phone:$("phone").value}:
    {...credentials,session:$("session-string").value.trim(),expected_user_id:importExpectedId};
  let r;
  if(method==="phone"&&state.status.collector.has_api_credentials===undefined){

    await loginRequest("auth/configure",credentials,{profile});
    if(revision!==state.workspaceRevision)return;
    r=await loginRequest("auth/phone",{phone:body.phone},{profile});
  }else r=await loginRequest(method==="phone"?"auth/phone/start":"auth/configure",body,{profile});
  if(revision!==state.workspaceRevision)return;
  if(r.step==="authorized")clearSecrets();
  setAuthStep(r.step);
  await refreshStatus();
});});
async function cancelQR(){
  const pending=qrPending;qrPending=null;
  if(pending)clearTimeout(pending.timer);
  $("qr-image").removeAttribute("src");show("qr-state",false);
  if(pending&&state.token){try{await json("auth/qr/"+encodeURIComponent(pending.id)+"/cancel",{},{profile:pending.profile});}catch(_){} }
}
async function beginQR(){
  if(state.status.demo){toast(tr("Demo workspace. Connect accounts in your live installation."),true);return;}
  const credentials=apiCredentials();if(!credentials)return;
  await cancelQR();
  const profile=state.profile,revision=state.workspaceRevision,token=state.token;
  const result=await loginRequest("auth/qr/start",credentials,{profile,token});
  if(revision!==state.workspaceRevision||!state.token){
    await json("auth/qr/"+encodeURIComponent(result.id)+"/cancel",{},{profile,token});
    return;
  }
  const pending=qrPending={id:result.id,profile,revision,timer:null};
  clearTimeout(toastTimer);show("toast",false);
  $("qr-image").src=result.image;show("qr-image",true);show("qr-retry",false);
  $("qr-status").textContent=tr("Waiting for confirmation · expires {time}",{time:formatTime(result.expires)});setAuthStep("qr");
  async function poll(){
    if(qrPending!==pending||revision!==state.workspaceRevision)return;
    try{
      const r=await json("auth/qr/"+encodeURIComponent(pending.id),undefined,{profile});
      if(qrPending!==pending||revision!==state.workspaceRevision)return;
      if(r.step==="qr"){pending.timer=setTimeout(poll,1500);return;}
      $("qr-image").removeAttribute("src");show("qr-image",false);
      if(r.step==="authorized"){
        qrPending=null;clearSecrets();setAuthStep("authorized");await refreshStatus();toast(tr("Telegram account connected."));
      }else if(r.step==="password"){
        setAuthStep("password");toast(tr("Telegram requires your two-step verification password."));
      }else{
        $("qr-status").textContent=tr(r.error||"QR login was cancelled. Generate another code when ready.");show("qr-retry",true);
      }
    }catch(error){
      if(qrPending===pending){$("qr-status").textContent=error.message;pending.timer=setTimeout(poll,3000);}
    }
  }
  pending.timer=setTimeout(poll,500);
}
$("start-qr").addEventListener("click",e=>busy(e.currentTarget,beginQR));
$("qr-retry").addEventListener("click",e=>busy(e.currentTarget,beginQR));
$("qr-cancel").addEventListener("click",e=>busy(e.currentTarget,async()=>{await cancelQR();setAuthStep("credentials");}));
for(const [form,field] of [["code","code"],["password","password"]]){
  $(form+"-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
    const profile=state.profile,revision=state.workspaceRevision;
    const r=await json("auth/"+form,{[field]:$(field).value},{profile});if(revision!==state.workspaceRevision)return;
    $(field).value="";if(r.step==="authorized")clearSecrets();setAuthStep(r.step);await refreshStatus();
  });});
}
$("auth-back").addEventListener("click",()=>{clearSecrets();setAuthStep("credentials");});
$("change-account").addEventListener("click",()=>{if(state.status.collector.running){toast(tr("Pause observation before changing accounts."),true);return;}clearSecrets();setAuthStep("credentials");});
$("sign-out").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  if(state.status.collector.running){toast(tr("Pause observation before signing out."),true);return;}
  if(!window.confirm(tr("Sign out of this Telegram account? TgWitness ends the session in Telegram and forgets it on this computer. The journal, sources and signing key stay; only the same account can connect to this workspace again.")))return;
  const r=await json("auth/logout",{});
  clearSecrets();await refreshStatus();setAuthStep("credentials");
  toast(tr(r.telegram_session_ended?"Signed out. Telegram ended the session.":
    "Signed out here. Telegram did not confirm: end the session in Telegram under Settings → Devices."),!r.telegram_session_ended);
}));

const avatarCache=new Map();
function avatarClass(id){let h=0;for(const ch of String(id??"?"))h=(h*31+ch.charCodeAt(0))>>>0;return "av"+(h%8);}
function initials(name){

  const words=String(name||"").replace(/^@/,"").split(/\s+/).filter(w=>/^\p{L}/u.test(w));
  return words.length?(words[0][0]+(words[1]?.[0]||"")).toUpperCase():"?";
}
function loadAvatar(id,profile=state.profile){
  if(id===null||id===undefined||typeof id!=="number"||state.status?.demo)return Promise.resolve(null);
  const key=profile+":"+id;
  // 204: no photo now; asked again after ten minutes instead of on every list render
  if(!avatarCache.has(key))avatarCache.set(key,api("avatar/"+id,undefined,{profile})
    .then(r=>r.status===204?(setTimeout(()=>avatarCache.delete(key),600000),null):r.blob())
    .then(b=>b&&URL.createObjectURL(new Blob([b],{type:"image/jpeg"})))
    .catch(()=>{setTimeout(()=>avatarCache.delete(key),60000);return null;}));
  return avatarCache.get(key);
}
function avatarNode(id,name,size="",profile=state.profile){
  const n=node("span","avatar "+size+" "+avatarClass(id??name),initials(name));n.setAttribute("aria-hidden","true");
  loadAvatar(id,profile).then(url=>{if(url){const img=node("img");img.alt="";img.src=url;n.replaceChildren(img);}});
  return n;
}
const fmtDay=value=>panelTime?.day(value)??tr("Unknown date");
const fmtFull=value=>fmtTime(value);
const fmtShort=value=>value?fmtTime(value,{mode:"relative"}):"";
function humanSize(n){if(n===null||n===undefined)return "";const u=["B","KB","MB","GB"];let i=0;while(n>=1024&&i<3){n/=1024;i++;}return n.toFixed(i?1:0)+" "+u[i];}
const serviceLabels={MessageActionChatAddUser:tr("added a member"),MessageActionChatDeleteUser:tr("removed a member or left"),
  MessageActionChatJoinedByLink:tr("joined via invite link"),MessageActionChatJoinedByRequest:tr("joined after a join request"),
  MessageActionPinMessage:tr("pinned a message"),MessageActionChatEditTitle:tr("changed the chat name"),
  MessageActionChatEditPhoto:tr("changed the chat photo"),MessageActionChatCreate:tr("created the group"),MessageActionChannelCreate:tr("created the channel")};
function serviceText(action){return serviceLabels[action]||String(action||"service event").replace(/^MessageAction/,"").replace(/([a-z])([A-Z])/g,"$1 $2").toLowerCase();}
function senderName(m){
  const s=m.sender,title=state.chatInfo?.title;
  if(!s||s.id===state.chat)return title||tr("Channel");
  return s.name||(s.username?"@"+s.username:tr("Unknown"));
}
function recheckText(c){
  if(!c.recheck_minutes)return " "+tr("Rechecks are off.");
  if(!c.recheck)return " "+tr("Telegram is asked again every {n} min for anything missed.",{n:c.recheck_minutes});
  return " "+tr("Last recheck {time}: {recovered} recovered, {missing} not found.",{time:fmtTime(c.recheck.at),recovered:c.recheck.recovered,missing:c.recheck.missing});
}
function recordingMode(s){
  const m=s.monitoring||{},on=["messages","edits","deletions","reactions","membership"].filter(k=>m[k]);
  return on.length===5?tr("Everything"):on.join()==="messages,edits,deletions"?tr("Messages, edits & deletions"):
    on.length?tr("Custom: {list}",{list:on.map(termText).join(", ")}):tr("Nothing selected");
}
function modeSummary(s){
  const free=s.collector?.disk_free_bytes,files=s.capture?.download_media?tr("photos & files up to {n} MB each",{n:mediaLimit(s.capture)})
    +(free?" · "+tr("{size} free on disk",{size:humanSize(free)}):""):tr("photos & files not saved");
  return tr("Mode: {mode}",{mode:recordingMode(s)})+" · "+files;
}
async function openRecordingSettings(){
  await navigate("sources");sourcesView?.showTab('recording');$("capture-form").scrollIntoView({block:"start"});
}
const exportRunning=()=>multiRunning()||state.status?.collector.chat_export?.phase==="running";
let chatListRequest=0;
async function refreshChats(refresh=false){
  if(!state.status||state.view!=='chats')return;
  void resumeMulti();
  const revision=state.workspaceRevision,request=++chatListRequest;
  const current=()=>request===chatListRequest&&revision===state.workspaceRevision&&state.view==='chats';
  state.chatsLoading=true;state.chatsError=false;renderChatsList();
  if(state.chat===null)renderChatEmpty();
  let result;
  try{result=await json("chats",undefined,viewOptions('chats'));}
  catch(error){
    if(!current()||error instanceof StaleView||error.name==='AbortError')return;
    state.chatsLoading=false;state.chatsError=true;renderChatsList();
    if(state.chat===null)renderChatEmpty();
    throw error;
  }
  if(!current())return;
  state.chats=result.chats;state.chatsLoading=false;state.chatsError=false;
  if(state.chat!==null&&!state.chats.some(c=>c.chat_id===state.chat))beginChat(null);
  if(state.chat===null&&state.chats.length){beginChat((state.chats.find(c=>c.enabled)||state.chats[0]).chat_id);refresh=false;}
  renderChatsList();
  if(state.chat===null){renderChatEmpty();return;}
  return await loadChatMessages(refresh?"refresh":"open");
}
let chatListView=null;
const chatListReady=import('./views/chat-list.js?v=13').then(({createChatList})=>{
  chatListView=createChatList({root:panelRoots.get('chats'),tr,node,icon,avatarNode,timeNode,getState:()=>state,
    getSession:()=>state.workspaceRevision+':'+state.profile,may,json,refreshStatus,openChat,toast,viewState,reload:()=>refreshChats()});
  return chatListView;
});
function renderChatsList(){chatListView?.render();}
$("chat-back").addEventListener("click",()=>{
  viewQuery("chats",".chats-shell").dataset.panel="list";
  $("chat-search").focus({preventScroll:true});
});
document.querySelectorAll("[data-demo-filter]").forEach(button=>button.addEventListener("click",()=>busy(button,async()=>{
  if(!state.status?.demo)return;
  const revision=state.workspaceRevision;
  state.chatFilter=button.dataset.demoFilter;state.chatView="messages";state.chatAuthor=null;
  viewQuery("chats",".chats-shell").dataset.panel="chat";
  if(state.view!=="chats")navigate("chats");
  await refreshChats();
  if(revision!==state.workspaceRevision||state.view!=="chats")return;
  const version=$("chat-feed").querySelector("button.pill-edited");
  if(state.chatFilter==="edited"&&version&&!version.closest(".bubble").querySelector(".versions"))version.click();
  $("chat-feed").scrollTop=0;
})));
function beginChat(id){
  $("export-dialog").close("cancel");
  chatGeneration++;chatReady=false;state.chat=id;state.chatInfo=null;state.chatMessages=[];
  state.chatNextBefore=null;state.chatNextAfter=null;state.chatAuthor=null;state.chatProfile=null;
  state.chatView="messages";
  renderComposer();renderChat();renderChatsList();
}
async function openChat(id,options={}){
  viewQuery("chats",".chats-shell").dataset.panel="chat";
  beginChat(id);if(options.history!==false)window.TgWitnessRouter?.record({view:"chats",chatId:id,seq:null});const loaded=await loadChatMessages("open");
  if(loaded)loadChatProfile().catch(()=>{});
  return loaded;
}
function fmtDuration(seconds){
  if(seconds===null||seconds===undefined)return tr("unknown");
  if(seconds<60)return tr("under a minute");
  if(seconds<3600)return tr("~{n} min",{n:Math.round(seconds/60)});
  return tr("~{h} h {m} min",{h:Math.floor(seconds/3600),m:Math.round(seconds%3600/60)});
}
async function loadChatMessages(mode){
  const id=state.chat,revision=state.workspaceRevision,generation=chatGeneration,feed=$("chat-feed");
  const atBottom=feed.scrollHeight-feed.scrollTop-feed.clientHeight<80;
  if(mode==='refresh'&&(chatPagePending?.generation===generation||state.chatNextAfter!==null||(state.chatView==='messages'&&!atBottom))){renderChat();return true;}
  if((mode==='older'&&state.chatNextBefore===null)||(mode==='newer'&&state.chatNextAfter===null))return true;
  const request=++chatPageRequest,params=new URLSearchParams({limit:String(mode==='refresh'?Math.min(200,Math.max(60,state.chatMessages.length)):60)});
  if(mode==="older")params.set("before_id",String(state.chatNextBefore));
  if(mode==="newer")params.set("after_id",String(state.chatNextAfter));
  chatPagePending={request,generation};
  let result;
  try {result=await json("chats/"+encodeURIComponent(id)+"/messages?"+params,undefined,viewOptions('chats'));}
  catch(error){
    if(error instanceof StaleView||error.name==='AbortError'||request!==chatPageRequest||state.view!=='chats'||revision!==state.workspaceRevision||id!==state.chat||generation!==chatGeneration)return;
    feed.querySelector(".refresh-notice")?.remove();
    const notice=viewState("error",tr("Could not load data"),tr("Saved content remains available. Try loading again."),tr("Retry"),()=>loadChatMessages(mode));
    if(state.chatMessages.length){notice.classList.add("refresh-notice");feed.prepend(notice);}else feed.replaceChildren(notice);
    return false;
  }
  finally{if(chatPagePending?.request===request)chatPagePending=null;}
  if(request!==chatPageRequest||state.view!=='chats'||revision!==state.workspaceRevision||id!==state.chat||generation!==chatGeneration)return;
  const known=state.chatMessages.reduce((last,m)=>Math.max(last,m.message_id),0);
  const bounds=feed.getBoundingClientRect(),visible=[...feed.querySelectorAll('.msg,.chat-service[id]')].find(row=>{const r=row.getBoundingClientRect();return r.bottom>bounds.top&&r.top<bounds.bottom;});
  const anchor=visible?{id:visible.id,offset:visible.getBoundingClientRect().top-bounds.top}:null,top=feed.scrollTop;
  const reset=mode==='open'||mode==='latest'||(mode==='refresh'&&result.messages.length&&result.messages[0].message_id>known);
  const previousBefore=state.chatNextBefore,previousAfter=state.chatNextAfter;
  const merged=new Map((reset?[]:state.chatMessages).map(m=>[m.message_id,m]));
  result.messages.forEach(m=>merged.set(m.message_id,m));
  const ordered=[...merged.values()].sort((a,b)=>a.message_id-b.message_id);
  state.chatMessages=mode==='older'?ordered.slice(0,200):ordered.slice(-200);
  const first=state.chatMessages[0]?.message_id,last=state.chatMessages.at(-1)?.message_id;
  if(reset){state.chatNextBefore=result.next_before;state.chatNextAfter=result.next_after??null;}
  else if(mode==='older'){state.chatNextBefore=result.next_before;state.chatNextAfter=ordered.length>200?last:previousAfter;}
  else if(mode==='newer'){state.chatNextBefore=ordered.length>200?first:previousBefore;state.chatNextAfter=result.next_after??null;}
  else{state.chatNextBefore=ordered.length>200?first:first===result.messages[0]?.message_id?result.next_before:previousBefore;state.chatNextAfter=result.next_after??null;}
  chatReady=true;renderChat();

  if(mode==="open")replay(feed,"entering",900);
  else if(mode==="refresh")state.chatMessages.forEach(m=>{if(m.message_id>known)$("msg-"+m.message_id)?.classList.add("fresh");});
  if(mode==="open"||mode==='latest'||(mode==="refresh"&&atBottom))feed.scrollTop=feed.scrollHeight;
  else{const kept=anchor&&feed.querySelector('#'+CSS.escape(anchor.id));
    if(kept)feed.scrollTop+=kept.getBoundingClientRect().top-feed.getBoundingClientRect().top-anchor.offset;else feed.scrollTop=top;}
  return true;
}
function renderChatEmpty(){
  viewQuery("chats",".chats-shell").dataset.panel="chat";
  const box=$("chat-empty"),s=state.status;show("chat-main",false);show("chat-empty",true);box.replaceChildren();
  if(!s)return;
  if(!state.chats.length&&state.chatsLoading){box.append(viewState('loading',tr('Loading…')));return;}
  if(!state.chats.length&&state.chatsError){box.append(viewState('error',tr('Could not load data'),'',tr('Retry'),()=>refreshChats()));return;}
  const add=(title,text,label,view)=>{box.append(node("h2","",title),node("p","",text));
    if(label){const b=node("button","primary",label);b.type="button";b.addEventListener("click",()=>navigate(view));box.append(b);}};
  if(!s.demo&&!s.collector.has_session)add(tr("Connect a Telegram account"),tr("TgWitness reads chats through an account you control. Connect it with a phone number, QR code or session file."),tr("Connect account"),"connection");
  else if(!state.chats.length)add(tr("Choose chats to watch"),tr("Pick the groups and channels to investigate. Their messages, edits and deletions will appear here."),tr("Choose chats"),"sources");
  else add(tr("Select a chat"),tr("Pick a chat on the left to see its messages."));
}
function renderChat(){
  if(state.view!=='chats')return;
  const info=state.chats.find(c=>c.chat_id===state.chat);state.chatInfo=info||null;
  if(!info){renderChatEmpty();return;}
  show("chat-empty",false);show("chat-main",true);
  const title=info.title||tr("Chat {id}",{id:info.chat_id}),avatar=avatarNode(info.chat_id,title,"lg");avatar.id="chat-avatar";
  $("chat-avatar").replaceWith(avatar);$("chat-name").textContent=title;
  const kind={supergroup:tr("Group"),megagroup:tr("Group"),group:tr("Group"),chat:tr("Group"),channel:tr("Channel"),broadcast:tr("Channel"),bot:tr("Bot"),user:tr("Private chat"),private:tr("Private chat")}[info.kind]||termText(info.kind);
  $("chat-sub").textContent=[kind,tr("{n} saved",{n:(info.messages||0).toLocaleString()}),info.deleted?tr("{n} deleted",{n:info.deleted}):"",
    info.missing?tr("{n} not found",{n:info.missing}):"",info.edited?tr("{n} edited",{n:info.edited}):""].filter(Boolean).join(" · ");
  renderChatStatus();renderMulti();renderChatFeed();renderComposer();
}
function renderChatStatus(){
  if(state.view!=='chats')return;
  const box=$("chat-status"),s=state.status,info=state.chatInfo;if(!info||!s||$("chat-main").hidden)return;
  const current=s.collector,key=JSON.stringify([state.workspaceRevision,chatGeneration,info.enabled,s.demo,s.chats_limited,state.me?.permissions,
    current.has_session,current.running,current.connected,current.storage_low,current.storage_low&&current.disk_free_bytes,
    modeSummary(s),recheckText(current),state.chatFilter,state.chatView,state.chatAuthor,state.chatProfile,s.analysis?.enabled,exportRunning()]);
  if(box.renderKey===key)return;box.renderKey=key;
  const focusedFilter=box.contains(document.activeElement)?document.activeElement.dataset.chatFilter:null;
  const focusedView=box.contains(document.activeElement)?document.activeElement.dataset.chatView:null;
  const c=s.collector;box.replaceChildren();
  const state_=node("div","chat-state"),say=(cls,text,description=text)=>{state_.className="chat-state "+cls;const t=node("span","",text);t.title=description;state_.append(t);};
  state_.setAttribute('role','status');
  const action=(cls,label,work)=>{const b=node("button",cls+" small",label);b.type="button";b.addEventListener("click",()=>busy(b,work));state_.append(b);return b;};
  if(s.demo)say("info",tr("Demo with fictional messages. Deleted messages are red; edited ones keep every saved version."));
  else if(!info.enabled){say("warn",tr("Chat paused"),tr("This chat is paused — nothing in it is being saved."));if(viewAllowed("sources"))action("text-link",tr("Choose chats"),async()=>navigate("sources"));}
  else if(!c.has_session){say("warn",tr("Account not connected"));if(viewAllowed("connection"))action("text-link",tr("Connect account"),async()=>navigate("connection"));}
  else if(!c.running){say("warn",tr("Observation off"),tr("Observation is off — new messages, edits and deletions are not being saved."));
    if(may("collect")&&!s.chats_limited)action("text-link",tr("Start observation"),async()=>{await json("collector/start",{});await refreshStatus();toast(tr("Observation started. New messages, edits and deletions will appear here."));});}
  else if(c.storage_low)say("warn",tr("Files paused: low disk space"),tr("Observing, but the disk is almost full ({size} free): photos & files are paused until space is freed. Messages are still saved.",{size:humanSize(c.disk_free_bytes)}));
  else say(c.connected?"ok":"warn",c.connected?tr("Observing"):tr("Reconnecting to Telegram"),c.connected?tr("Observing — new messages, edits and deletions are saved as they happen.")+recheckText(c):tr("Reconnecting to Telegram — missed changes are requested again once connected."));
  const mode=node("div","chat-mode-chips");
  for(const [name,label] of [['mode',tr("Mode: {mode}",{mode:recordingMode(s)})],['files',s.capture?.download_media?tr("Files ≤ {n} MB",{n:mediaLimit(s.capture)}):tr("Files off")]]){
    const allowed=!s.demo&&viewAllowed('sources'),chip=node(allowed?'button':'span','chat-setting-chip',label);chip.dataset.recording=name;chip.title=modeSummary(s);
    if(allowed){chip.type='button';chip.setAttribute('aria-label',label+' · '+tr('Recording settings'));chip.addEventListener('click',()=>busy(chip,openRecordingSettings));}mode.append(chip);
  }
  const filters=node("div","chat-filters");filters.setAttribute("role","group");filters.setAttribute("aria-label",tr("Show messages"));
  for(const [key,label] of [["all",tr("All")],["deleted",tr("Deleted")],["edited",tr("Edited")],["media",tr("Media")]]){
    const f=node("button","filter"+(state.chatFilter===key?" active":""),label);f.type="button";
    f.dataset.chatFilter=key;
    f.setAttribute("aria-pressed",String(state.chatFilter===key));
    f.addEventListener("click",()=>{state.chatFilter=key;renderChatStatus();renderChatFeed();});filters.append(f);
  }
  const tabs=node('div','chat-view-tabs');tabs.setAttribute('role','group');tabs.setAttribute('aria-label',tr('Chat views'));
  const views=[['messages',tr('Messages')],['people',tr('People')],['profile',tr('Profile')]];
  if(s.analysis?.enabled&&!s.demo&&viewAllowed('analysis'))views.push(['ai',tr('AI context')]);
  for(const [name,label] of views){const tab=node('button','filter'+(state.chatView===name?' active':''),label);tab.type='button';tab.dataset.chatView=name;
    tab.setAttribute('aria-pressed',String(state.chatView===name));tab.addEventListener('click',()=>{
      if(name==='ai'){busy(tab,async()=>{const chat=state.chat,revision=state.workspaceRevision;await navigate('analysis');
        if(revision===state.workspaceRevision)await window.TgWitnessAnalysis?.focusChat(chat);});return;}
      state.chatView=name;renderChatStatus();renderChatFeed();renderComposer();});tabs.append(tab);}
  const toolbar=node("div","chat-filter-row");toolbar.append(filters);toolbar.hidden=state.chatView!=='messages';
  if(!s.demo){box.append(state_,mode);}
  else {
    const hint=node("span","visually-hidden",tr("Demo with fictional messages. Deleted messages are red; edited ones keep every saved version."));
    box.append(hint);
  }
  box.append(tabs,toolbar);
  if(state.chatAuthor!==null&&state.chatView==='messages'){
    const who=state.chatMessages.find(m=>m.sender?.id===state.chatAuthor),chip=node("div","chat-author-chip");
    const author=who?senderName(who):"ID "+state.chatAuthor;chip.append(node("span","",tr("Showing only messages from {name}",{name:author})));
    const clear=node("button","text-link",tr("Show everyone"));clear.type="button";
    clear.addEventListener("click",()=>{state.chatAuthor=null;renderChatStatus();renderChatFeed();});chip.append(clear);box.append(chip);
  }
  const blocked=s.demo||!c.has_session||!info.enabled;
  $("chat-load-history").disabled=blocked;$("chat-history-limit").disabled=blocked;
  $("chat-export-start").disabled=s.demo||!c.has_session||exportRunning();
  if(focusedFilter)box.querySelector('[data-chat-filter="'+focusedFilter+'"]')?.focus({preventScroll:true});
  if(focusedView)box.querySelector('[data-chat-view="'+focusedView+'"]')?.focus({preventScroll:true});
}
function renderChatFeed(){
  if(state.view!=='chats')return;
  const feed=$("chat-feed"),s=state.status,info=state.chatInfo;
  if(state.chatView==="people"){
    const generation=chatGeneration;
    if(!feed.querySelector(".people"))feed.replaceChildren(viewState("loading",tr("Loading…")));
    renderPeople(feed).catch(error=>{
      if(error instanceof StaleView||state.chatView!=="people"||generation!==chatGeneration)return;
      const notice=viewState("error",tr("Could not load data"),"",tr("Retry"),()=>renderChatFeed());
      if(feed.querySelector(".people")){feed.querySelector(".refresh-notice")?.remove();notice.classList.add("refresh-notice");feed.prepend(notice);}
      else feed.replaceChildren(notice);
    });return;
  }
  if(state.chatView==='profile'){
    const key=JSON.stringify([state.chat,state.chatProfile,s.demo,s.collector.has_session,may('sources')]);
    if(feed.firstElementChild?.profileKey!==key){const profile=profileNode(true);profile.profileKey=key;feed.replaceChildren(profile);}return;
  }
  const expanded=new Map([...feed.querySelectorAll(".msg")].map(row=>[row.id,{
    versions:!!row.querySelector(".versions"),author:!!row.querySelector(".sender-details[open]")
  }]));
  const active=document.activeElement,focusRow=feed.contains(active)?active.closest(".msg")?.id:null;
  const focusSelector=active.matches("button.pill-edited")?"button.pill-edited":
    active.matches(".sender-details > summary")?".sender-details > summary":null;
  const oldRows=new Map([...feed.querySelectorAll('.msg')].map(row=>[row.id,row])),days=new Map([...feed.querySelectorAll('.chat-day')].map(day=>[day.dataset.day,day])),next=[],replaced=new Set();
  if(!chatReady){feed.replaceChildren(viewState("loading",tr("Loading…")));return;}
  const shown=state.chatMessages.filter(m=>(state.chatFilter==="all"||(state.chatFilter==="deleted"?m.deleted||m.missing:state.chatFilter==='media'?m.has_media||m.media.length:m.edited))
    &&(state.chatAuthor===null||m.sender?.id===state.chatAuthor));
  if(shown.some(m=>m.has_media&&!m.media.length)){
    const key=JSON.stringify([s.demo,may('sources'),s.capture?.download_media]);let notice=feed.querySelector('.chat-media-notice');
    if(!notice||notice.renderKey!==key){notice=node('aside','chat-media-notice');notice.setAttribute('role','note');notice.renderKey=key;
      notice.append(icon('clip'),node('span','',tr('Some attachment files have not been saved.')));
      if(!s.demo&&viewAllowed('sources')){const settings=node('button','text-link',tr('File saving settings'));settings.type='button';
        settings.title=tr('Applies to future captures. Earlier files may no longer be available.');settings.addEventListener('click',()=>busy(settings,openRecordingSettings));notice.append(settings);}}
    next.push(notice);
  }
  if(state.chatNextBefore){let older=feed.querySelector('.chat-older');if(!older){older=node("button","quiet chat-older",tr("Show older messages"));older.type="button";
    older.addEventListener("click",()=>busy(older,()=>loadChatMessages("older")));}next.push(older);}
  const newer=()=>{
    if(state.chatNextAfter===null)return;
    let controls=feed.querySelector('.chat-newer');if(!controls){controls=node('div','chat-newer');
      for(const [mode,label] of [['newer',tr('Show newer messages')],['latest',tr('Back to latest')]]){const button=node('button','quiet',label);button.type='button';button.dataset.chatPage=mode;
        button.addEventListener('click',()=>busy(button,()=>loadChatMessages(mode)));controls.append(button);}}
    next.push(controls);
  };
  if(!shown.length){
    const filtered=state.chatFilter!=="all"||state.chatAuthor!==null;
    const empty=filtered?viewState("filtered-empty",tr("No messages match these filters"),tr(state.chatNextBefore?"Older messages are not loaded yet — use “Show older messages”.":"Try another filter or show all saved messages."),tr("Clear filters"),()=>{state.chatFilter="all";state.chatAuthor=null;renderChatStatus();renderChatFeed();}):
      viewState("empty",tr("No messages saved for this chat yet"),tr(s.demo?"This demo chat has no messages.":"Load recent messages from Telegram to see the conversation. Keep observation on to catch new messages, edits and deletions."),tr("Load last 100 messages"),!s.demo&&s.collector.has_session&&info.enabled?b=>loadHistory(b,100):null);
    empty.classList.add("chat-feed-empty");
    next.push(empty);newer();placeChildren(feed,next);return;
  }
  const byId=new Map(state.chatMessages.map(m=>[m.message_id,m]));
  let lastDay=null,lastSender=null,lastTime=0;
  for(const m of shown){
    const when=m.sent_at||m.versions[0]?.observed_at||m.deleted_observed_at,day=panelTime.dayKey(when);
    if(day!==lastDay){const chip=days.get(day)||node("div","chat-day"),label=fmtDay(when);chip.dataset.day=day;
      if(chip.textContent!==label)chip.textContent=label;chip.title=label;next.push(chip);lastDay=day;lastSender=null;}
    if(m.service_action){const service=node("div","chat-service",senderName(m)+" "+serviceText(m.service_action)+" · ");service.id='msg-'+m.message_id;service.append(timeNode(when));next.push(service);lastSender=null;continue;}
    const sid=m.sender?.id??null,t=when?new Date(when).getTime():0,grouped=sid!==null&&sid===lastSender&&t>=lastTime&&t-lastTime<300000;
    lastSender=sid;lastTime=t;
    const old=oldRows.get('msg-'+m.message_id),key=JSON.stringify([chatGeneration,m,grouped,m.reply_to&&byId.get(m.reply_to),may('interact'),s.demo,s.collector.has_session]);
    if(old?.renderKey===key)next.push(old);else{const row=messageRow(m,grouped,byId);row.renderKey=key;next.push(row);replaced.add(row.id);}
  }
  newer();placeChildren(feed,next);
  for(const row of feed.querySelectorAll(".msg")){
    if(!replaced.has(row.id))continue;
    const previous=expanded.get(row.id);if(!previous)continue;
    if(previous.versions)row.querySelector("button.pill-edited")?.click();
    if(previous.author&&row.querySelector(".sender-details"))row.querySelector(".sender-details").open=true;
  }
  if(focusRow&&focusSelector)$(focusRow)?.querySelector(focusSelector)?.focus({preventScroll:true});
}
function messageRow(m,grouped,byId){
  const row=node("div","msg"+(grouped?" grouped":"")+(m.deleted?" deleted":m.missing?" missing":""));row.id="msg-"+m.message_id;
  const name=senderName(m),bubble=node("div","bubble");
  row.append(grouped?node("span","avatar-spacer"):avatarNode(m.sender?.id,name));
  if(!grouped){const head=node("div","bubble-head"),details=node("details","sender-details"),summary=node("summary"),facts=node("div","sender-facts");
    summary.title=m.sender?.username?'@'+m.sender.username:tr("Author details");summary.setAttribute('aria-label',tr('Author details')+': '+name);summary.append(node("span","sender",name));
    if(m.sender?.username)facts.append(node("span","","@"+m.sender.username));
    if(m.sender?.id!==null&&m.sender?.id!==undefined)facts.append(node("span","","ID "+m.sender.id));
    if(!facts.children.length)facts.append(node("span","",tr("No saved author details")));
    details.append(summary,facts);head.append(details);bubble.append(head);}
  if(m.reply_to){
    const target=byId.get(m.reply_to),quote=node(target?'button':'div',target?'reply-quote':'reply-unavailable');
    if(target){quote.type='button';quote.append(node('b','',senderName(target)),node('span','',target.text||tr('[attachment]')));
      quote.addEventListener('click',()=>{let el=$('msg-'+m.reply_to);if(!el){state.chatFilter='all';state.chatAuthor=null;renderChatStatus();renderChatFeed();el=$('msg-'+m.reply_to);}if(!el)return;
        el.scrollIntoView({block:'center',behavior:'smooth'});el.classList.add('flash');setTimeout(()=>el.classList.remove('flash'),1600);});}
    else quote.textContent=tr('Reply to #{id} · outside this loaded window',{id:m.reply_to});
    bubble.append(quote);
  }
  if(m.captured){if(m.text)bubble.append(node("div","bubble-text",m.text));if(m.buttons)bubble.append(buttonsNode(m.buttons,m));}
  else bubble.append(node("div","bubble-text muted-text",tr(m.deleted?"Deleted before TgWitness could save it — only the deletion notice was recorded.":"Content was not saved.")));
  m.media.forEach(media=>bubble.append(mediaNode(media)));
  if(m.has_media&&!m.media.length){const missing=node('span','media-missing');missing.title=tr('Attachment file not saved');missing.setAttribute('role','img');missing.setAttribute('aria-label',missing.title);missing.append(icon('clip'));bubble.append(missing);}
  const meta=node("div","bubble-meta");
  if(m.deleted){const d=node("span","pill pill-deleted",tr("Deleted"));d.title=tr("Deletion seen {time}. Telegram does not report who deleted it or exactly when.",{time:fmtFull(m.deleted_observed_at)});meta.append(d);}
  else if(m.missing){const d=node("span","pill pill-missing",tr("Not found at recheck"));d.title=tr("Telegram no longer returned this message at {time} and no deletion notice was received: deleted while notices were missed, removed by an auto-delete timer, or no longer visible to this account.",{time:fmtFull(m.missing_observed_at)});meta.append(d);}
  if(m.versions.length>1){const e=node("button","pill pill-edited",tr("Edited · {n} versions",{n:m.versions.length}));e.type="button";e.title=tr("Show every saved version");
    e.setAttribute("aria-expanded","false");
    e.addEventListener("click",()=>{const open=bubble.querySelector(".versions");e.setAttribute("aria-expanded",String(!open));if(open){open.remove();return;}bubble.insertBefore(versionsNode(m),meta);});meta.append(e);}
  else if(m.edited){const e=node("span","pill pill-edited",tr("Edited"));e.title=tr("Telegram marks this message as edited; the earlier text was not saved.");meta.append(e);}
  if(!m.origins.includes("live")&&m.origins.includes("history")){const o=node("span","origin",tr("from history"));o.title=tr("Loaded from chat history, not seen live");meta.append(o);}
  meta.append(timeNode(m.sent_at||m.versions[0]?.observed_at,"time"));
  if(!state.status?.demo&&state.status?.collector.has_session&&!m.deleted&&!m.missing&&may("interact")){const reply=node("button","text-link",tr("Reply"));reply.type="button";
    const generation=chatGeneration,revision=state.workspaceRevision;
    reply.addEventListener("click",()=>{if(!chatReady||generation!==chatGeneration||revision!==state.workspaceRevision)return;
      composeReply=m.message_id;renderComposer();$("chat-message").focus();});meta.append(reply);}
  bubble.append(meta);row.append(bubble);return row;
}
let peopleRequest=0;
async function renderPeople(feed){
  const id=state.chat,generation=chatGeneration,request=++peopleRequest,result=await json("chats/"+encodeURIComponent(id)+"/authors",undefined,viewOptions('chats'));
  if(request!==peopleRequest||state.view!=='chats'||id!==state.chat||generation!==chatGeneration||state.chatView!=="people")return;
  const old=feed.querySelector('.people'),profiled=(state.status.dossiers||[]).includes(id),key=JSON.stringify([result,profiled]);
  if(old?.renderKey===key&&old.chat===id){feed.querySelector('.refresh-notice')?.remove();return;}
  const box=node("div","people");
  box.chat=id;box.profiled=profiled;box.renderKey=key;
  box.append(node("h3","",trn("{n} person with saved messages","{n} people with saved messages",result.authors.length)),
    node("p","hint",tr("Counted from messages saved in this workspace. Load history or export the chat for the full list. Names are the profile seen when the message was saved.")));
  if(result.deleted_without_author)box.append(node("p","hint",tr("{n} deleted message(s) were never saved, so their author is unknown.",{n:result.deleted_without_author})));
  const keepBar=old?.chat===id&&old.profiled===profiled?old.querySelector('.dossier-bar'):null;
  if(!keepBar)box.append(dossierBar(id,profiled));
  const table=node("table","people-table"),head=node("tr");
  [tr("Person"),tr("Messages"),tr("Deleted"),tr("Edited"),tr("First"),tr("Last")].forEach((h,i)=>head.append(node("th",i>0&&i<4?"num":"",h)));
  const thead=node("thead");thead.append(head);table.append(thead);
  const body=node("tbody");
  for(const p of result.authors){
    const row=node("tr"),who=node("td"),name=p.id===id?(state.chatInfo?.title||tr("Channel")):p.name||(p.username?"@"+p.username:p.id!==null?tr("User {id}",{id:p.id}):tr("Unknown"));
    const card=node("div","person");card.append(avatarNode(typeof p.id==="number"?p.id:null,name));
    const text=node("div");text.append(node("b","",name),node("small","",[p.username?"@"+p.username:"",p.id!==null?"ID "+p.id:""].filter(Boolean).join(" · ")));
    card.append(text);who.append(card);
    row.append(who,node("td","num",String(p.messages)),node("td","num"+(p.deleted||p.missing?" bad":""),String(p.deleted)+(p.missing?" +"+tr("{n} not found",{n:p.missing}):"")),
      node("td","num",String(p.edited)),Object.assign(node("td"),{title:fmtTime(p.first_message_at)}),Object.assign(node("td"),{title:fmtTime(p.last_message_at)}));
    row.children[row.children.length-2].append(timeNode(p.first_message_at));row.lastElementChild.append(timeNode(p.last_message_at));
    if(p.id!==null){row.tabIndex=0;row.title=tr(profiled&&p.id!==id?"Open this person's profile":"Show this person's messages");
      const open=profiled&&p.id!==id?()=>openDossier(p.id).catch(e=>toast(e.message,true)):
        ()=>{state.chatAuthor=p.id;state.chatFilter="all";state.chatView='messages';renderChatStatus();renderChatFeed();renderComposer();};
      row.addEventListener("click",open);row.addEventListener("keydown",e=>{if(e.key==="Enter")open();});}
    body.append(row);
  }
  table.append(body);box.append(table);
  if(keepBar){placeChildren(old,[...box.children].filter(child=>child!==table).concat(keepBar,table));old.renderKey=key;feed.querySelector('.refresh-notice')?.remove();}
  else feed.replaceChildren(box);
}

function dossierBar(chat,profiled){
  const bar=node("div","dossier-bar"),demo=!!state.status.demo;
  const action=(cls,label,work)=>{const b=node("button",cls+" small",label);b.type="button";b.disabled=demo;b.addEventListener("click",()=>busy(b,work));return b;};
  if(!profiled){
    bar.append(node("p","",tr("People profiles are off for this chat. A profile shows name and username history, Telegram flags, avatar hashes, activity, who replies to whom, other observed chats and mentioned wallets, phones, usernames and links — built only from records already saved, each fact pointing to its record.")),
      action("secondary",tr("Turn on profiles"),async()=>{
        if(!window.confirm(tr("Profiles are personal data about third parties. Turn them on only when you have a lawful reason, and delete them when no longer needed. Continue?")))return;
        await json("chats/"+encodeURIComponent(chat)+"/dossier",{enabled:true});await refreshStatus();renderChatFeed();
      }));
    return bar;
  }
  const password=node("input");password.type="password";password.autocomplete="new-password";password.maxLength=256;
  password.placeholder=tr("Password for an encrypted copy (12+ characters)");password.setAttribute("aria-label",tr("Password for an encrypted copy"));password.disabled=demo;
  bar.append(node("p","",tr("Profiles are on. Click a person to open their profile. The export is a separate signed file; it is deleted with the chat.")),
    action("secondary",tr("Export profiles"),async()=>{
      if(await download("chats/"+encodeURIComponent(chat)+"/dossier/export","tgwitness-dossier-"+chat+".json"))toast(tr("Signed profiles saved."));
    }),
    password,
    action("quiet",tr("Export encrypted"),async()=>{
      if(password.value.length<12){password.focus();throw new Error(tr("Enter a password of at least 12 characters."));}
      if(await download("chats/"+encodeURIComponent(chat)+"/dossier/export","tgwitness-dossier-"+chat+"-encrypted.zip",false,false,{password:password.value}))
        toast(tr("Encrypted profiles saved. Open the ZIP with 7-Zip or WinRAR and this password."));
      password.value="";
    }),
    action("quiet",tr("Turn off and delete"),async()=>{
      if(!window.confirm(tr("Turn off profiles for this chat and delete the saved profile file?")))return;
      await json("chats/"+encodeURIComponent(chat)+"/dossier",{enabled:false});state.dossier=null;await refreshStatus();renderChatFeed();
    }));
  return bar;
}
async function dossierData(chat){
  if(state.dossier?.chat===chat&&Date.now()-state.dossier.at<60000)return state.dossier.value;
  const value=await json("chats/"+encodeURIComponent(chat)+"/dossier");
  state.dossier={chat,at:Date.now(),value};return value;
}
function refButtons(records){
  const span=node("span","refs");
  for(const seq of records.slice(0,6)){const b=node("button","text-link ref","#"+seq);b.type="button";b.title=tr("Open journal record #{seq}",{seq});
    b.addEventListener("click",()=>openRecord(seq).catch(e=>toast(e.message,true)));span.append(b);}
  if(records.length>6)span.append(node("small","",tr("+{n} more",{n:records.length-6})));
  return span;
}
function factSection(title,items,describe=item=>String(item.value)){
  const section=node("section","dossier-section");section.append(node("h3","",title));
  if(!items.length){section.append(node("p","hint",tr("Nothing saved.")));return section;}
  const list=node("ul");
  for(const item of items){
    const li=node("li");li.append(node("span","fact",describe(item)),node("small","",trn("{n} time","{n} times",item.count??1)+" · "+fmtFull(item.first_at)),refButtons(item.records||[]));
    list.append(li);
  }
  section.append(list);return section;
}
async function openDossier(personId){
  const generation=chatGeneration,revision=state.workspaceRevision,context=viewContexts.get('chats');
  const value=await dossierData(state.chat),statement=value.statement;
  if(generation!==chatGeneration||revision!==state.workspaceRevision||state.view!=='chats'||context?.signal.aborted)return;
  const person=statement.people.find(p=>p.id===personId);
  if(!person)throw new Error(tr("No profile for this person: they have no saved message in this chat."));
  const nameOf=id=>{const other=statement.people.find(p=>p.id===id);return other?.names.at(-1)?.value||tr("User {id}",{id});};
  previouslyFocused=document.activeElement;state.drawerSeq="dossier";window.TgWitnessJournal?.closeDetail();
  const content=$("detail-content");content.replaceChildren();
  const head=node("div","dossier-head"),h=node("h2","",nameOf(person.id));h.id="detail-title";
  head.append(avatarNode(person.id,nameOf(person.id),"lg"),h);content.append(head);
  content.append(node("p","detail-caption","ID "+person.id+(person.usernames.length?" · "+person.usernames.map(u=>u.value).join(", "):"")));
  const flags=node("div","dossier-flags");
  for(const [flag,info] of Object.entries(person.flags))if(info.value){const chip=node("span","pill"+(["scam","fake"].includes(flag)?" pill-deleted":""),flag);
    chip.title=tr("Seen since record #{seq}",{seq:info.since_record});flags.append(chip);}
  if(flags.children.length)content.append(flags);
  content.append(factSection(tr("Names"),person.names),factSection(tr("Usernames"),person.usernames));
  const a=person.activity,activity=node("section","dossier-section");activity.append(node("h3","",tr("Activity")));
  const facts=node("dl","dossier-facts"),pair=(k,v)=>facts.append(node("dt","",k),node("dd","",v));
  pair(tr("Saved messages"),String(a.messages));pair(tr("Edited"),a.edited+" ("+Math.round(a.edited_share*100)+"%)");
  pair(tr("Deleted"),a.deleted+" ("+Math.round(a.deleted_share*100)+"%)"+(a.missing?" · "+tr("{n} not found",{n:a.missing}):""));
  pair(tr("First message"),a.first_message?fmtFull(a.first_message.at)+" · #"+a.first_message.record:"—");
  pair(tr("Last message"),a.last_message?fmtFull(a.last_message.at)+" · #"+a.last_message.record:"—");
  activity.append(facts);
  const peak=Math.max(1,...a.hours_utc),hours=node("div","hour-bars");hours.setAttribute("aria-label",tr("Messages by hour, UTC"));
  a.hours_utc.forEach((n,hour)=>{const bar=node("span");bar.style.height=Math.round(n/peak*100)+"%";bar.title=String(hour).padStart(2,"0")+":00 UTC · "+n;hours.append(bar);});
  activity.append(node("small","hint",tr("Messages by hour, UTC")),hours);
  if(a.deleted_records.length){activity.append(node("small","",tr("Deletion notices:")),refButtons(a.deleted_records));}
  content.append(activity);
  const avatar=person.avatar,pictures=node("section","dossier-section");pictures.append(node("h3","",tr("Avatar")));
  if(avatar.cached)pictures.append(node("p","mono","SHA-256 "+avatar.cached.sha256),node("p","mono","pHash "+(avatar.cached.phash||"—")),
    node("p","hint",tr("From the local avatar cache, saved {time}; not a journal record.",{time:fmtFull(avatar.cached.cached_at)})));
  else pictures.append(node("p","hint",tr("No avatar in the local cache. Avatars are cached when the panel shows them.")));
  if(avatar.similar.length)pictures.append(node("p","",tr("Similar avatars: {list}",{list:avatar.similar.map(s=>(s.in_this_chat?nameOf(s.id):"ID "+s.id)+" ("+s.distance+")").join(", ")})));
  if(avatar.photo_ids.length)pictures.append(factSection(tr("Profile photo IDs seen"),avatar.photo_ids));
  if(avatar.history?.length){
    const history=node("details","avatar-history"),entries=node("div");let shown=0;
    history.append(node("summary","",tr("Saved versions, oldest first")+" · "+avatar.history.length),entries);
    const more=node("button","quiet small",tr("Load more"));more.type="button";
    const fill=()=>{
      for(const saved of avatar.history.slice(shown,shown+20)){
        const row=node("div","avatar-history-item");row.append(node("p","hint",tr("First")+" · "+fmtFull(saved.first_at)+" / "+tr("Last")+" · "+fmtFull(saved.last_at)),
          window.TgWitnessReview.attachment(saved,{api,download,busy,tr}),refButtons(saved.records||[]));entries.append(row);
      }
      shown+=20;more.hidden=shown>=avatar.history.length;
    };
    history.addEventListener("toggle",()=>{if(history.open&&!shown)fill();});more.addEventListener("click",fill);history.append(more);pictures.append(history);
  }
  if(avatar.history_similar?.length){
    for(const similar of avatar.history_similar.slice(0,20)){
      const line=node("p","",tr("Similar avatars: {list}",{list:nameOf(similar.id)+" ("+similar.distance+")"}));
      line.append(refButtons(similar.records||[]),refButtons(similar.other_records||[]));pictures.append(line);
    }
  }
  content.append(pictures);
  const r=person.relations,links=node("section","dossier-section");links.append(node("h3","",tr("Connections")));
  const linkList=node("ul");
  for(const x of r.replies_to){const li=node("li");li.append(node("span","fact",tr("Replies to {name}: {n}",{name:nameOf(x.id),n:x.count})),refButtons(x.records));linkList.append(li);}
  for(const x of r.replied_by)linkList.append(node("li","",tr("Replied to by {name}: {n}",{name:nameOf(x.id),n:x.count})));
  for(const x of r.other_chats)linkList.append(node("li","",tr("Also in {chat}: {n} saved messages",{chat:x.title||tr("Chat {id}",{id:x.chat_id}),n:x.messages})));
  if(!linkList.children.length)linkList.append(node("li","hint",tr("No replies or other observed chats.")));
  links.append(linkList);content.append(links);
  const m=person.mentions;
  content.append(factSection(tr("Wallets mentioned"),m.wallets,item=>item.value+(item.detail?" · "+item.detail:"")),
    factSection(tr("Phone numbers mentioned"),m.phones),factSection(tr("Usernames mentioned"),m.usernames),factSection(tr("Links"),m.links),
    factSection(tr("Matches of your patterns"),m.patterns||[],item=>item.value+(item.detail?" · "+item.detail:"")));
  const show_=node("button","secondary",tr("Show this person's messages"));show_.type="button";
  show_.addEventListener("click",()=>{closeDetail();state.chatAuthor=person.id;state.chatFilter="all";state.chatView='messages';renderChatStatus();renderChatFeed();renderComposer();});
  const limits=node("details","detail-block");limits.append(node("summary","",tr("What a profile can and cannot show")));
  const ul=node("ul");statement.limitations.forEach(x=>ul.append(node("li","",x)));limits.append(ul);
  content.append(show_,limits,node("p","detail-hash",tr("Built {time} from {n} journal records · signed with this workspace's key",{time:fmtFull(statement.built_at),n:Object.keys(statement.record_hashes).length})));
  show("drawer-backdrop",true);show("detail-drawer",true);$("close-detail").focus();
}
function versionsNode(m){
  const box=node("div","versions");box.append(node("div","versions-title",tr("Saved versions, oldest first")));
  m.versions.forEach((v,i)=>{const item=node("div","version"+(i===m.versions.length-1?" current":""));
    item.append(node("small","",(i===0?tr("First saved"):tr("Edit {n}",{n:i}))+" · "+tr("saved {time}",{time:fmtFull(v.observed_at)})));
    item.append(i?window.TgWitnessReview.compare(m.versions[i-1],v,tr):node("div","",v.text||tr("(no text)")));
    if(v.buttons)item.append(buttonsNode(v.buttons));
    const record=node("button","text-link",tr("Journal record #{n}",{n:v.seq}));record.type="button";
    record.addEventListener("click",()=>busy(record,()=>openRecord(v.seq)));item.append(record);box.append(item);});
  return box;
}

const buttonKinds={url:tr("link"),web_app:tr("web app"),login_url:tr("login link"),callback:tr("callback"),copy:tr("copies text"),
  switch_inline:tr("inline query"),request_phone:tr("asks for the phone number"),request_location:tr("asks for the location"),
  request_chat:tr("asks to choose a chat"),request_poll:tr("asks for a poll"),user_profile:tr("opens a profile"),game:tr("game"),
  buy:tr("payment"),text:tr("sends its text")};
function buttonsNode(keyboard,message=null){
  const box=node("div","msg-buttons"+(keyboard.inline?" inline":" reply"));
  box.setAttribute("aria-label",tr(keyboard.inline?"Buttons under the message":"Reply keyboard"));
  const chat=state.chat,profile=state.profile,revision=state.workspaceRevision,generation=chatGeneration;
  for(const [rowIndex,row] of keyboard.rows.entries()){
    const line=node("div","msg-button-row");
    for(const [column,b] of row.entries()){
      const item=node("div","msg-button"),target=b.url||b.copy_text||b.query||(b.user_id?"ID "+b.user_id:"");
      item.append(node("span","label",b.text||"—"),node("small","kind",buttonKinds[b.type]||b.type));
      if(target)item.append(node("code","target",target));
      if(message&&!message.deleted&&!message.missing&&["callback","text"].includes(b.type)&&!state.status?.demo){
        const press=node("button","secondary small",tr("Press button"));press.type="button";
        press.disabled=!state.status?.collector.has_session||!state.chatInfo?.enabled;
        press.addEventListener("click",()=>busy(press,async()=>{
          if(!chatReady||generation!==chatGeneration||revision!==state.workspaceRevision||chat!==state.chat)return;
          await panelAction({action:"press",chat_id:chat,message_id:message.message_id,
            keyboard_event:message.versions.at(-1).seq,row:rowIndex,column},{profile,revision});
        }));item.append(press);
      }
      line.append(item);
    }
    box.append(line);
  }
  return box;
}


let composeContext=null,composeReply=null,linkPreview=null,actionBusy=false;
let chatGeneration=0,chatReady=false,composeDestination=null,chatPageRequest=0,chatPagePending=null;
const pendingActions=new Map();
function resetInteractions(){
  composeContext=null;composeReply=null;linkPreview=null;
  chatGeneration++;chatReady=false;composeDestination=null;
  $("chat-message").value="";$("chat-link").value="";$("chat-link-preview").replaceChildren();
  $("chat-search").value="";
  viewQuery("chats",".chats-shell").dataset.panel="chat";
  show("interaction-result",false);show("chat-reply",false);
}
function renderComposer(){
  if(state.view!=='chats')return;
  const context=state.workspaceRevision+":"+chatGeneration+":"+state.profile+":"+state.chat;
  if(composeContext!==context){$("chat-message").value="";composeReply=null;composeContext=context;show("interaction-result",false);}
  const s=state.status,enabled=!!(chatReady&&s&&!s.demo&&s.collector.has_session&&state.chatInfo?.enabled);
  show("chat-compose",!!(state.chatView==='messages'&&s&&!s.demo&&s.collector.has_session&&may('interact')));
  composeDestination=enabled?{chat:state.chat,profile:state.profile,revision:state.workspaceRevision,generation:chatGeneration}:null;
  $("chat-send").disabled=!enabled||actionBusy;$("chat-message").disabled=!enabled||actionBusy;
  $("chat-message").placeholder=tr("Write a message…");
  const account=s?.collector.account;
  const identity=account?(account.username?"@"+account.username:"ID "+account.id):tr("No account connected");
  $("chat-compose-account").textContent=tr("Sending as {account}",{account:identity});
  show("chat-reply",composeReply!==null);$("chat-reply-label").textContent=tr("Reply to message #{id}",{id:composeReply});
  $("chat-preview-button").disabled=!s||s.demo||!s.collector.has_session||actionBusy;
}
function actionResult(result){
  const box=$("interaction-result");box.replaceChildren();show("interaction-result",true);
  const labels={succeeded:tr("Action completed and recorded."),approval_pending:tr("Join request sent. Waiting for administrator approval."),
    rejected:tr("Telegram did not accept the action."),unknown:tr("The result is unknown. Check the chat before attempting a new action.")};
  box.append(node("strong","",labels[result.status]||result.status));
  if(result.error_type)box.append(node("span","",result.error_type));
  if(result.retry_after)box.append(node("p","",tr("Retry after {n} seconds.",{n:result.retry_after})));
  if(result.answer?.message)box.append(node("p","bubble-text",result.answer.message));
  if(result.answer?.url)box.append(node("code","target",result.answer.url));
  const seq=result.result_event||result.request_event;
  if(seq){const record=node("button","text-link",tr("Journal record #{n}",{n:seq}));record.type="button";
    record.addEventListener("click",()=>busy(record,()=>openRecord(seq)));box.append(record);}
}
async function panelAction(body,{profile=state.profile,revision=state.workspaceRevision}={}){
  if(actionBusy||profile!==state.profile||revision!==state.workspaceRevision)return null;
  if(body.action!=="open"&&(!chatReady||body.chat_id!==state.chat))return null;
  actionBusy=true;renderComposer();
  const key=profile+":"+JSON.stringify(body);
  if(!pendingActions.has(key))pendingActions.set(key,Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,"0")).join(""));
  try{
    const result=await json("interactions",{...body,request_id:pendingActions.get(key)},{profile});
    if(revision!==state.workspaceRevision)return result;
    if(result.status==="succeeded"&&body.action==="send"&&body.chat_id===state.chat){$("chat-message").value="";composeReply=null;}

    if(body.action==="open"||body.chat_id===state.chat)actionResult(result);
    let refreshFailed=false;
    try{
      await refreshStatus();
      if(revision!==state.workspaceRevision)return result;
      refreshFailed=(await refreshChats(true))===false;

      if(!refreshFailed&&result.status!=="unknown")pendingActions.delete(key);
    }catch{refreshFailed=true;}
    if(refreshFailed&&revision===state.workspaceRevision&&(body.action==="open"||body.chat_id===state.chat)){
      actionResult(result);$("interaction-result").append(node("p","hint",tr("The receipt is saved. Chat refresh failed; refresh the view to see the latest messages.")));
    }
    return result;
  }finally{actionBusy=false;renderComposer();}
}
$("chat-compose").addEventListener("submit",e=>{e.preventDefault();const dest=composeDestination;
  if(!dest||!chatReady||dest.generation!==chatGeneration||dest.chat!==state.chat||dest.revision!==state.workspaceRevision)return;
  busy($("chat-send"),()=>panelAction({action:"send",chat_id:dest.chat,text:$("chat-message").value,reply_to:composeReply},dest));});
$("chat-reply-cancel").addEventListener("click",()=>{composeReply=null;renderComposer();});
$("chat-link").addEventListener("input",()=>{linkPreview=null;$("chat-link-preview").replaceChildren();});
$("chat-open-form").addEventListener("submit",e=>{e.preventDefault();busy($("chat-preview-button"),async()=>{
  const profile=state.profile,revision=state.workspaceRevision;linkPreview=null;$("chat-link-preview").replaceChildren();
  const preview=await json("interactions/preview",{link:$("chat-link").value},{profile});
  if(revision!==state.workspaceRevision||$("chat-link").value.trim()!==preview.link)return;linkPreview=preview;
  const box=$("chat-link-preview"),open=node("button","primary",tr("Join / open and observe"));open.type="button";
  box.append(node("strong","",preview.title),node("code","target",preview.link));
  if(preview.about)box.append(node("p","",preview.about));
  if(preview.participants_count!==null)box.append(node("p","hint",tr("Members")+": "+preview.participants_count));
  box.append(
    node("p","hint",tr("The preview is saved. Opening a bot sends /start; joining adds the chat to your sources.")),open);
  open.addEventListener("click",()=>busy(open,async()=>{
    if(revision!==state.workspaceRevision||linkPreview!==preview)return;
    const result=await panelAction({action:"open",preview_id:preview.preview_id},{profile,revision});
    if(!result||revision!==state.workspaceRevision)return;
    if(["succeeded","approval_pending"].includes(result.status)){linkPreview=null;open.remove();}
    if(result.chat_id){
      let refreshFailed=false;
      try{refreshFailed=(await openChat(result.chat_id))===false;}catch{refreshFailed=true;}
      if(revision===state.workspaceRevision&&state.chat===result.chat_id){
        actionResult(result);
        if(refreshFailed)$("interaction-result").append(node("p","hint",tr("The receipt is saved. Chat refresh failed; refresh the view to see the latest messages.")));
      }
    }
  }));
});});

async function loadChatProfile(){
  const id=state.chat,revision=state.workspaceRevision,generation=chatGeneration;if(id===null||id===undefined)return;
  let r;
  try{r=await json("chats/"+encodeURIComponent(id)+"/profile",undefined,viewOptions('chats'));}
  catch(error){if(id===state.chat&&revision===state.workspaceRevision&&generation===chatGeneration&&!(error instanceof StaleView)){
    state.chatProfile={chat:id,error:true};if(state.chatView==='profile')renderChatFeed();}throw error;}
  if(id!==state.chat||revision!==state.workspaceRevision||generation!==chatGeneration)return;
  state.chatProfile={chat:id,...r};renderChatStatus();if(state.chatView==='profile')renderChatFeed();
}
function profileNode(standalone=false){
  const s=state.status,saved=state.chatProfile?.chat===state.chat?state.chatProfile:null,data=saved?.profile;
  const box=node(standalone?'section':'details',"chat-profile"+(standalone?' chat-profile-view':'')),summary=node(standalone?'header':'summary');
  if(!standalone){box.open=!!state.chatProfileOpen;box.addEventListener("toggle",()=>{state.chatProfileOpen=box.open;});}
  summary.append(node("strong","",tr("Profile")),node("span","",data?tr("saved {time}",{time:fmtFull(saved.observed_at)}):saved&&!saved.error?tr("not saved yet"):''));
  box.append(summary);
  if(data){
    const facts=node("dl","dossier-facts"),add=(label,value)=>{if(value===null||value===undefined||value==="")return;facts.append(node("dt","",label),node("dd","",String(value)));};
    add(tr("Description"),data.bot?.description||data.about);
    if(data.bot)add(tr("About"),data.about);
    add(tr("Username"),data.username?"@"+data.username:"");
    add(tr("Members"),typeof data.participants==="number"?data.participants.toLocaleString():"");
    add(tr("Invite link"),data.invite_link);
    add(tr("Linked chat"),data.linked_chat_id);
    if(facts.childNodes.length)box.append(facts);
    if(data.bot?.commands?.length){
      const list=node("ul","bot-commands");data.bot.commands.forEach(c=>list.append(node("li","","/"+c.command+(c.description?" — "+c.description:""))));
      box.append(node("h4","",tr("Bot commands")),list);
    }
    const record=node("button","text-link",tr("Open record #{seq}",{seq:saved.seq}));record.type="button";
    record.addEventListener("click",()=>openRecord(saved.seq).catch(e=>toast(e.message,true)));box.append(record);
  }
  if(!data){const empty=!saved?viewState('loading',tr('Loading…')):saved.error?viewState('error',tr('Could not load data'),'',tr('Retry'),()=>loadChatProfile().catch(()=>{})):
    viewState("unavailable",tr("Profile not saved yet"),tr("Save a profile snapshot to view the details available to this account."));empty.classList.add("compact");box.append(empty);}
  const save=node("button","secondary small",tr("Save profile now"));save.type="button";save.disabled=!s||s.demo||!s.collector.has_session;
  save.hidden=!may("sources");
  save.addEventListener("click",()=>busy(save,async()=>{
    const id=state.chat,r=await json("chats/"+encodeURIComponent(id)+"/profile",{});
    if(id!==state.chat)return;
    state.chatProfile={chat:id,...r};state.chatProfileOpen=true;renderChatStatus();if(state.chatView==='profile')renderChatFeed();toast(tr("Profile saved in the signed journal."));
  }));
  box.append(save);return box;
}
function mediaNode(media){
  return window.TgWitnessReview.attachment(media,{api,download,busy,tr});
}
async function loadHistory(button,limit){
  await busy(button,async()=>{
    toast(tr("Loading the last {n} messages from Telegram…",{n:limit}));
    const r=await json("snapshot",{chat_id:state.chat,limit});
    toast(tr("Loaded {n} messages.",{n:r.captured}));await refreshStatus();await refreshChats();
  });
}
$("chats-manage").addEventListener("click",()=>navigate("sources"));
$("chat-load-history").addEventListener("click",e=>loadHistory(e.currentTarget,Number($("chat-history-limit").value)));

let multiPoll=null,multiRequest=0,multiDiscovery=null;
const multiRunning=()=>state.multi?.phase==="running";
const multiCurrent=(revision,token,request)=>revision===state.workspaceRevision&&token===state.token&&
  !!token&&!$("workspace").hidden&&request===multiRequest;
const multiRetryable=error=>!(error instanceof StaleView)&&
  (!error.status||[408,429].includes(error.status)||error.status>=500);
const multiRetryDelay=attempt=>Math.min(30000,1500*2**Math.min(attempt+1,5));
async function openExportDialog(){
  const chat=state.chat,profile=state.profile,revision=state.workspaceRevision,generation=chatGeneration;
  toast(tr("Asking Telegram how big this chat is…"));
  const [scale]=await Promise.all([json("chats/"+encodeURIComponent(state.chat)+"/scale"),loadProfiles()]);
  if(revision!==state.workspaceRevision||generation!==chatGeneration)return;
  show("toast",false);
  const info=state.chatInfo,basic=info?.kind==="group",facts=$("export-dialog-facts"),list=$("export-dialog-accounts");
  facts.replaceChildren();list.replaceChildren();
  facts.append(node("p","export-fact",tr("{title}: {n} messages in Telegram right now.",{title:info?.title||tr("This chat"),n:scale.total.toLocaleString()})));
  if(scale.missing_ids)facts.append(node("p","export-fact",tr("The newest message is #{last}, so about {n} message numbers no longer exist — deleted earlier, they cannot be exported.",
    {last:scale.last_message_id.toLocaleString(),n:scale.missing_ids.toLocaleString()})));
  if(basic)facts.append(node("p","export-fact warn",tr("This is an ordinary group: message numbers differ between accounts, so only this account can download it.")));
  function estimate(){
    const n=list.querySelectorAll("input:checked").length||1;
    $("export-dialog-estimate").textContent=trn("Estimated time with {n} account: {time}","Estimated time with {n} accounts: {time}",n,{time:fmtDuration(Math.round(scale.estimate_seconds/n))})+
      (scale.total>3000?" — "+tr("each account fetches 100 messages per request, 1 s apart"):"")+". "+tr("Telegram may ask an account to pause for longer.");
  }
  for(const p of state.profiles){
    const c=p.collector,lead=p.id===state.profile,connected=!!c?.has_session&&!p.error_type,account=c?.account;
    const row=node("label","export-account"),box=node("input"),who=node("span","export-account-who"),text=node("span");
    box.type="checkbox";box.value=p.id;box.checked=lead;box.disabled=lead||!connected||basic;box.addEventListener("change",estimate);
    text.append(node("b","",p.label),node("small","",lead?tr("starts the export and signs the archive"):!connected?tr("no Telegram account connected"):
      basic?tr("not possible for ordinary groups"):account?(account.username?"@"+account.username+" · ":"")+"ID "+account.id:""));
    who.append(avatarNode(account?account.id:null,account&&account.username?account.username:p.label,"",p.id),text);
    row.append(box,who);list.append(row);
  }
  show("export-select-all",!basic&&state.profiles.length>1);
  $("export-select-all").onclick=()=>{list.querySelectorAll("input:not(:disabled)").forEach(b=>{b.checked=true;});estimate();};
  estimate();
  const dialog=$("export-dialog");
  $("export-dialog-cancel").onclick=()=>dialog.close("cancel");
  dialog.returnValue="";dialog.showModal();
  const choice=await new Promise(resolve=>dialog.addEventListener("close",()=>resolve(dialog.returnValue),{once:true}));
  if(choice!=="start"||revision!==state.workspaceRevision||generation!==chatGeneration)return;
  const profiles=[...list.querySelectorAll("input:checked")].map(b=>b.value);
  const x=await json("multi-export/start",{chat_id:chat,lead:profile,profiles},{root:true});
  state.multi=x;state.multiHidden=null;renderMulti();pollMulti(x.id);
  toast(trn("Export started with {n} account. Observation keeps running.","Export started with {n} accounts. Observation keeps running.",profiles.length));
}
function renderMulti(){
  if(state.view!=='chats')return;
  const x=state.multi,box=$("export-box"),known=x&&!["none","unknown"].includes(x.phase);
  const running=known&&x.phase==="running",mine=known&&x.chat_id===state.chat&&x.lead===state.profile;
  const percent=known&&x.total?Math.min(running?99:100,Math.floor(x.captured*100/x.total)):null;
  $("chat-export-label").textContent=running?tr("Exporting")+(percent!==null?" "+percent+"%":"…"):tr("Export chat");
  show("chat-export-get",!!(mine&&x.phase==="done"&&x.ready));
  if(!mine||(!running&&state.multiHidden===x.id)){show("export-box",false);return;}
  box.replaceChildren();show("export-box",true);
  const head=node("div","export-head");
  const counts={title:x.title||tr("chat"),captured:x.captured.toLocaleString(),total:(x.total||0).toLocaleString(),percent};
  head.append(node("b","",running?tr("Exporting {title}: ",counts)+tr(x.total?"{captured} of {total} messages ({percent}%)":"{captured} messages",counts)+
    (x.eta_seconds?" · "+tr("{time} left",{time:fmtDuration(x.eta_seconds)}):""):x.phase==="done"?tr(x.ready?"Export ready: {captured} messages, signed.":"Export saved: {captured} messages, signed.",counts):
    x.phase==="failed"?tr("Export failed: {error}",{error:x.error||tr("unknown error")}):tr("Export cancelled.")));
  const action=(cls,label,work)=>{const b=node("button",cls+" small",label);b.type="button";b.addEventListener("click",()=>work(b));head.append(b);};
  if(running)action("quiet",tr("Cancel"),b=>busy(b,async()=>{await json("multi-export/"+encodeURIComponent(x.id)+"/cancel",{},{root:true});await pollMulti(x.id);}));
  if(x.phase==="done"&&x.ready)action("primary",tr("Save signed export"),b=>saveMulti(b));
  if(!running)action("quiet",tr("Hide"),()=>{state.multiHidden=x.id;renderMulti();});
  box.append(head);
  if(x.phase==="done")box.append(node("p","hint",tr("The messages are in the archive (chat.json, chat.html, authors.csv). This chat view shows what observation and “Load history” saved in the journal.")));
  if(running&&percent!==null){const bar=node("progress","export-bar");bar.max=100;bar.value=percent;bar.setAttribute("aria-label",tr("Export progress"));box.append(bar);}
  const workers=node("ul","export-workers");
  for(const w of x.workers){
    const wait=w.state==="waiting"&&w.wait_until?tr("Telegram asked to pause {n} s",{n:Math.max(0,Math.round(w.wait_until-Date.now()/1000))}):null;
    const label=wait||tr({pending:"starting",running:"downloading",done:"finished",skipped:"skipped",failed:"stopped — its share goes to the others"}[w.state]||w.state);
    const li=node("li","export-worker "+w.state);
    li.append(node("b","",w.label),node("span","",label+(w.error?" ("+w.error+")":"")),node("span","num",trn("{n} message","{n} messages",w.captured)));
    workers.append(li);
  }
  box.append(workers);
}
async function pollMulti(id,attempt=0){
  if(!state.token||$("workspace").hidden||(state.multi?.id&&state.multi.id!==id))return;
  clearTimeout(multiPoll);multiPoll=null;
  const revision=state.workspaceRevision,token=state.token,request=++multiRequest;
  const current=()=>multiCurrent(revision,token,request);
  state.multiChecked=true;
  try{
    const before=state.multi?.phase,x=await json("multi-export/"+encodeURIComponent(id),undefined,{root:true});
    if(!current())return;
    state.multi=x;renderMulti();
    if(x.phase==="running")multiPoll=setTimeout(()=>{if(current())pollMulti(id);},1500);
    else if(before==="running"&&x.phase==="done")toast(tr("Chat export finished: {n} messages. Save the signed archive.",{n:x.captured.toLocaleString()}));
    else if(before==="running"&&x.phase==="failed")toast(tr("Chat export failed: {error}",{error:x.error||tr("unknown error")}),true);
  }catch(e){
    if(!current()||e instanceof StaleView)return;
    if(multiRetryable(e))multiPoll=setTimeout(()=>{if(current())pollMulti(id,attempt+1);},multiRetryDelay(attempt));
    else if([403,404].includes(e.status)){state.multi=null;renderMulti();}
    if(!attempt)toast(e.message,true);
  }
}
async function resumeMulti(attempt=0){
  if(state.multiChecked||!state.token||!may("export")||$("workspace").hidden)return;
  if(multiDiscovery&&multiCurrent(multiDiscovery.revision,multiDiscovery.token,multiDiscovery.request))return multiDiscovery.promise;
  clearTimeout(multiPoll);multiPoll=null;
  const request={revision:state.workspaceRevision,token:state.token,request:++multiRequest};
  const current=()=>multiCurrent(request.revision,request.token,request.request);
  multiDiscovery=request;
  request.promise=(async()=>{
    try{
      const x=await json("multi-export/current",undefined,{root:true});
      if(!current())return;
      state.multiChecked=true;
      state.multi=x&&["running","done"].includes(x.phase)?x:null;renderMulti();
      if(state.multi?.phase==="running")pollMulti(x.id);
    }catch(e){
      if(!current()||e instanceof StaleView)return;
      if(multiRetryable(e))multiPoll=setTimeout(()=>{if(current())resumeMulti(attempt+1);},multiRetryDelay(attempt));
      else{state.multiChecked=true;state.multi=null;renderMulti();}
      if(!attempt)toast(e.message,true);
    }finally{if(multiDiscovery===request)multiDiscovery=null;}
  })();
  return request.promise;
}
function saveMulti(button){return busy(button,async()=>{
  const x=state.multi;if(!x?.ready)throw new Error(tr("No finished export to save."));
  if(await download("multi-export/"+encodeURIComponent(x.id)+"/download","tgwitness-chat-export.zip",true,true)===false)return;
  state.multi={...x,ready:false};renderMulti();toast(tr("Signed chat export saved."));
});}
$("chat-export-start").addEventListener("click",e=>busy(e.currentTarget,openExportDialog));
$("chat-export-get").addEventListener("click",e=>saveMulti(e.currentTarget));

function localInput(unix){
  if(!unix)return "";const d=new Date(unix*1000);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);
}
function workspaceName(id){return state.profiles.find(p=>p.id===id)?.label||id;}
function accessScope(g){
  if(g.all_workspaces)return tr("All workspaces");
  return Object.entries(g.workspaces).map(([id,chats])=>chats===null?tr("{workspace}: every chat",{workspace:workspaceName(id)}):
    trn("{workspace}: {n} chat","{workspace}: {n} chats",chats.length,{workspace:workspaceName(id)})).join("; ");
}
function accessLimits(g){
  const parts=[trn("{n} parallel session","{n} parallel sessions",g.max_sessions)+" · "+
    (g.on_limit==="refuse"?tr("new sign-ins refused at the limit"):tr("the oldest session ends at the limit"))];
  parts.push(g.max_uses?tr("sign-ins: {used} of {max}",{used:g.uses,max:g.max_uses}):trn("{n} sign-in","{n} sign-ins",g.uses));
  if(g.expires_at)parts.push(tr("valid until {time}",{time:formatTime(g.expires_at)}));
  if(g.ips.length)parts.push(tr("addresses: {list}",{list:g.ips.join(", ")}));
  if(g.bind_first_ip)parts.push(g.bound_ip?tr("bound to {address}",{address:g.bound_ip}):tr("binds to the first sign-in address"));
  return parts.join(" · ");
}
function renderPermissions(selected){
  const box=$("access-permissions");box.replaceChildren();
  for(const [key,[name,about]] of Object.entries(permissionLabels)){
    const label=node("label","check-label access-permission"),input=document.createElement("input"),text=node("span");
    input.type="checkbox";input.value=key;input.checked=key==="view"||selected.includes(key);input.disabled=key==="view";
    text.append(node("strong","",name),node("small","",about));label.append(input,text);box.append(label);
  }
}
async function fillAccessChats(id,box,chosen){
  if(!state.accessChats[id])state.accessChats[id]=(await json("chats",undefined,{profile:id})).chats;
  box.replaceChildren();
  if(!state.accessChats[id].length){box.append(node("p","hint",tr("This workspace has no chats yet. Choose its sources first.")));return;}
  for(const chat of state.accessChats[id]){
    const label=node("label","check-label"),input=document.createElement("input");
    input.type="checkbox";input.value=String(chat.chat_id);input.checked=chosen.includes(chat.chat_id);
    label.append(input,document.createTextNode(" "+(chat.title||String(chat.chat_id))));box.append(label);
  }
}
function renderAccessWorkspaces(selected){
  const box=$("access-workspaces");box.replaceChildren();
  for(const profile of state.profiles){
    const id=profile.id,chosen=Object.hasOwn(selected,id)?selected[id]:undefined;
    const row=node("div","access-workspace"),pick=node("label","check-label"),check=document.createElement("input");
    check.type="checkbox";check.dataset.workspace=id;check.checked=chosen!==undefined;
    pick.append(check,document.createTextNode(" "+profile.label));
    const mode=document.createElement("select");mode.dataset.mode=id;
    mode.setAttribute("aria-label",tr("Chats of {workspace}",{workspace:profile.label}));
    mode.append(new Option(tr("Every chat"),"all"),new Option(tr("Chosen chats"),"chosen"));
    mode.value=Array.isArray(chosen)?"chosen":"all";
    const chats=node("div","access-chats");chats.dataset.chats=id;
    const sync=async()=>{
      check.disabled=mode.disabled=$("access-all").checked;mode.hidden=!check.checked;
      chats.hidden=!(check.checked&&mode.value==="chosen");
      if(!chats.hidden&&!chats.childElementCount)await fillAccessChats(id,chats,Array.isArray(chosen)?chosen:[]);
    };
    for(const input of [check,mode])input.addEventListener("change",()=>sync().catch(e=>toast(e.message,true)));
    row.append(pick,mode,chats);box.append(row);
    sync().catch(e=>toast(e.message,true));
  }
}
function renderAccessForm(g){
  accessFormVersion++;
  $("access-form-mode").textContent=g?tr("Edit access"):tr("New access");
  $("access-submit").textContent=g?tr("Save access"):tr("Create access");
  show("access-cancel",!!g);
  $("access-label").value=g?.label||"";$("access-all").checked=!!g?.all_workspaces;
  renderPermissions(g?.permissions||["view"]);
  $("access-sessions").value=g?.max_sessions??1;$("access-on-limit").value=g?.on_limit||"refuse";
  $("access-uses").value=g?.max_uses??"";$("access-expires").value=localInput(g?.expires_unix);
  $("access-idle").value=g?.session_minutes??720;
  $("access-ips").value=(g?.ips||[]).join("\n");$("access-bind").checked=!!g?.bind_first_ip;
  renderAccessWorkspaces(g?g.workspaces:{[state.profile]:null});accessView?.syncForm();
}
function accessSettings(){
  const workspaces={},box=$("access-workspaces");
  if(!$("access-all").checked)for(const check of box.querySelectorAll("[data-workspace]:checked")){
    const id=check.dataset.workspace;
    workspaces[id]=box.querySelector(`[data-mode="${id}"]`).value==="all"?null:
      [...box.querySelectorAll(`[data-chats="${id}"] input:checked`)].map(x=>Number(x.value));
  }
  const expires=$("access-expires").value,uses=$("access-uses").value;
  return {label:$("access-label").value.trim(),all_workspaces:$("access-all").checked,workspaces,
    permissions:[...$("access-permissions").querySelectorAll("input:checked")].map(x=>x.value),
    ips:$("access-ips").value.split(/\s+/).filter(Boolean),bind_first_ip:$("access-bind").checked,
    max_uses:uses?Number(uses):null,expires_at:expires?new Date(expires).getTime()/1000:null,
    max_sessions:Number($("access-sessions").value),on_limit:$("access-on-limit").value,
    session_minutes:Number($("access-idle").value)};
}
function sessionOwner(s){return s.admin?tr("Main administrator"):s.label;}
function renderAccess(){
  const a=state.access;if(!a)return;
  const list=$("access-list"),grants=new Map([...list.children].map(row=>[row.dataset.id,row])),grantRows=[];
  if(!a.grants.length)grantRows.push(list.querySelector('p.hint')||node("p","hint",tr("No access issued yet. Only the panel token opens this panel.")));
  for(const value of a.grants){
    const old=grants.get(value.id),g=old?Object.assign(old.record,value):value;
    const row=node("div","access-row"),info=node("div"),actions=node("div","access-actions");
    row.dataset.id=g.id;row.record=g;
    const condition=g.expired?tr("expired"):g.used_up?tr("used up"):trn("{n} open session","{n} open sessions",g.sessions);
    const last=g.last_login_at?" · "+tr("last sign-in {time} from {address}",{time:formatTime(g.last_login_at),address:g.last_address}):"";
    info.append(node("h3","",g.label+" · "+condition),node("p","",accessScope(g)),
      node("p","",g.permissions.map(p=>permissionLabels[p]?.[0]||p).join(", ")),node("p","hint",accessLimits(g)+last));
    const edit=node("button","secondary",tr("Edit")),revoke=node("button","quiet",tr("Revoke"));
    edit.addEventListener("click",()=>{state.accessEdit=g;show("access-new",false);renderAccessForm(g);$("access-form").scrollIntoView({block:"start"});});
    revoke.addEventListener("click",()=>busy(revoke,async()=>{
      if(!window.confirm(tr("Revoke the access of \"{name}\"? Its open sessions end at once.",{name:g.label})))return;
      accessLoadSerial++;
      state.access=await json("access/grants/"+encodeURIComponent(g.id),undefined,{root:true,method:"DELETE"});
      if(state.accessEdit?.id===g.id){state.accessEdit=null;renderAccessForm(null);}
      renderAccess();
    }));
    actions.append(edit,revoke);row.append(info,actions);
    if(old){if(old.firstElementChild.outerHTML!==info.outerHTML)old.firstElementChild.replaceWith(info);grantRows.push(old);}else grantRows.push(row);
  }
  placeChildren(list,grantRows);
  const sessions=$("access-sessions-list"),existing=new Map([...sessions.children].map(row=>[row.dataset.id,row])),sessionRows=[];
  if(!a.sessions.length)sessionRows.push(sessions.querySelector('p.hint')||node("p","hint",tr("No open sessions.")));
  for(const value of a.sessions){
    const old=existing.get(value.id),s=old?Object.assign(old.record,value):value;
    const row=node("div","access-row"),info=node("div"),end=node("button","quiet",tr("End session"));
    row.dataset.id=s.id;row.record=s;
    info.append(node("h3","",sessionOwner(s)+(s.current?" · "+tr("this browser"):"")),
      node("p","",[s.address,tr("since {time}",{time:formatTime(s.started_at)}),
        tr("last activity {time}",{time:formatTime(s.last_seen_at)}),trn("{n} request","{n} requests",s.requests)].join(" · ")),
      node("p","hint",s.agent.slice(0,120)));
    end.addEventListener("click",()=>busy(end,async()=>{
      if(!window.confirm(tr("End this session? Its open panel will be locked.")))return;
      accessLoadSerial++;
      state.access=await json("access/sessions/"+encodeURIComponent(s.id),undefined,{root:true,method:"DELETE"});renderAccess();
    }));
    row.append(info,end);if(old){if(old.firstElementChild.outerHTML!==info.outerHTML)old.firstElementChild.replaceWith(info);sessionRows.push(old);}else sessionRows.push(row);
  }
  placeChildren(sessions,sessionRows);
}
let accessView=null,systemLogView=null;
const accessReady=import("./views/access.js").then(({createAccessView})=>{
  accessView=createAccessView({root:$("view-access"),tr,navigate,localInput,getState:()=>state});return accessView;
});
const systemLogReady=import("./views/system-log.js").then(({createSystemLog})=>{
  systemLogView=createSystemLog({root:$("view-system-log"),tr,json,getState:()=>state,getSession:()=>state.workspaceRevision+":"+state.profile,
    options:()=>viewOptions('system-log'),formatTime:fmtTime,toast});return systemLogView;
});
accessReady.catch(error=>toast(error.message,true));systemLogReady.catch(error=>toast(error.message,true));
async function loadConsole(){return (await systemLogReady).load();}
let accessFormVersion=0,adminLimitsVersion=0;
let accessFormReady=false,adminLimitsReady=false,adminLimitsDirty=false,accessLoadSerial=0;
async function loadAccess(quiet=false){
  if(!state.me?.admin)return;
  // Build a complete new-access form before the request yields; later responses only update saved data.
  if(!accessFormReady){renderAccessForm(state.accessEdit);accessFormReady=true;}
  if(!adminLimitsReady)$("access-admin-form").inert=true;
  const view=await accessReady;if(state.view!=='access'||!state.me?.admin)return;view.enter();
  const serial=++accessLoadSerial,result=await json("access",undefined,{root:true,...viewOptions('access')});
  if(serial!==accessLoadSerial||state.view!=='access')return;
  state.access=result;
  if(!adminLimitsDirty){
    $("admin-sessions").value=state.access.admin.max_sessions;$("admin-on-limit").value=state.access.admin.on_limit;
    $("admin-idle").value=state.access.admin.session_minutes;
  }
  adminLimitsReady=true;$("access-admin-form").inert=false;
  renderAccess();
}
$("access-refresh").addEventListener("click",e=>busy(e.currentTarget,()=>loadAccess()));
$("access-all").addEventListener("change",()=>$("access-workspaces").querySelectorAll("input,select")
  .forEach(n=>n.disabled=$("access-all").checked));
$("access-cancel").addEventListener("click",()=>{state.accessEdit=null;renderAccessForm(null);});
for(const event of ['input','change']){
  $("access-admin-form").addEventListener(event,()=>{adminLimitsDirty=true;adminLimitsVersion++;});
  $("access-form").addEventListener(event,()=>{accessFormVersion++;});
}
$("access-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  accessLoadSerial++;
  const settings=accessSettings(),edit=state.accessEdit,version=accessFormVersion;
  if(edit){
    state.access=await json("access/grants/"+encodeURIComponent(edit.id),settings,{root:true,method:"PATCH"});
    toast(tr("Access saved. Its open sessions follow the new settings."));
  }else{
    const result=await json("access/grants",settings,{root:true});state.access=result;
    $("access-token").textContent=result.token;show("access-new",true);toast(tr("Access created. Copy its token now."));
  }
  if(version===accessFormVersion&&state.accessEdit===edit){state.accessEdit=null;renderAccessForm(null);}renderAccess();
});});
$("access-copy").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await navigator.clipboard.writeText($("access-token").textContent);toast(tr("Token copied."));
}));
$("access-admin-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  if(!adminLimitsReady)return;
  accessLoadSerial++;const version=adminLimitsVersion;
  state.access=await json("access/admin",{max_sessions:Number($("admin-sessions").value),on_limit:$("admin-on-limit").value,
    session_minutes:Number($("admin-idle").value)},{root:true});
  if(version===adminLimitsVersion)adminLimitsDirty=false;renderAccess();toast(tr("Limits saved."));
});});
let notifyTick=0,pollRevision=null;
async function pollWorkspace(){
  if(!state.token||document.hidden||$("workspace").hidden||$("workspace").inert||pollRevision===state.workspaceRevision)return;
  const revision=state.workspaceRevision;pollRevision=revision;
  try{
    const head=state.status?.stats.head?.seq;
    await refreshStatus();
    if(!window.TgWitnessLive?.active()&&state.view==="observations" && state.drawerSeq===null && state.eventBefore===null && state.events.length<=200&&window.TgWitnessJournal?.canRefresh()!==false
        && state.status.stats.head?.seq!==head) await refreshEvents();
    if(!window.TgWitnessLive?.active()&&state.view==="chats" && state.status.stats.head?.seq!==head) await refreshChats(true);
    if(state.view==="accounts") await loadProfiles();
    if(state.view==="witness") await loadExtras();
    if(state.view==="access") await loadAccess(true);
    if(state.view==="system-log") await loadConsole();
    if(state.view==="evidence") await loadAccountExport(true).catch(accountExportError);
    if(++notifyTick%3===0) await loadNotifications();
  }catch(e){if(revision===state.workspaceRevision&&!(e instanceof StaleView))$("status-chip").textContent=tr("Panel connection unavailable");}
  finally{if(pollRevision===revision)pollRevision=null;}
}
setInterval(pollWorkspace,5000);
async function bootstrap(){
  await Promise.all([timeReady,shellReady,viewReady,chatListReady]);
  await ensureRouter();
  const revision=state.workspaceRevision;
  try{
    const response=await fetch("/api/demo-access",{cache:"no-store",credentials:"omit"});
    const entry=response.ok?await response.json():{};

    if(accessStarted||revision!==state.workspaceRevision)return;
    if(entry.available){
      state.demoToken=entry.token;state.token=entry.token;state.profile="default";
      show("unlock-form",false);show("open-demo",true);
      $("gate-description").textContent=tr("Explore fictional messages, saved edits, deletion notices and verifiable exports. No Telegram account is connected.");
      $("gate-help").textContent=tr("For your own groups, run Start.cmd or python start.py using a separate data directory. Demo data cannot be converted into a real investigation.");
    }
  }catch(error){                                                                     }
  if(!accessStarted&&revision===state.workspaceRevision&&state.token)
    await unlock().catch(error=>{if(!(error instanceof StaleView)){lock();$("login-error").textContent=error.message;}});
}
bootstrap();
